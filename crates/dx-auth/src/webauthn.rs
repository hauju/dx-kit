//! Minimal WebAuthn Relying Party — SeggWat is its own RP.
//!
//! FerrisKey's webauthn endpoints derive their RP ID from the FerrisKey
//! deployment's `WEBAPP_URL`, which pins passkeys to the IdP's origin, and
//! enrolling requires a FerrisKey user JWT that email-OTP accounts can never
//! obtain. So the dashboard runs the ceremonies itself: options + verification
//! here, credentials in our `user_passkeys` table, challenges parked in
//! tower-sessions by the handlers.
//!
//! Scope is deliberately small:
//! * Attestation policy is **none** (`attestation: "none"` is requested and
//!   attestation statements are not verified — same trust model as accepting
//!   any authenticator, which is what a consumer login wants).
//! * Supported algorithms: ES256 (-7), EdDSA (-8), RS256 (-257) — the set
//!   every real-world authenticator falls into.
//! * User verification is **required** in both ceremonies: a passkey login is
//!   single-factor, so the authenticator must have checked the user
//!   (biometric / PIN / screen lock).
//!
//! All signature verification is `ring` (already in-tree via rustls) — no
//! openssl. CBOR via `ciborium`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::Value as Cbor;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

// Authenticator data flag bits (WebAuthn §6.1).
const FLAG_UP: u8 = 0x01; // user present
const FLAG_UV: u8 = 0x04; // user verified
const FLAG_BS: u8 = 0x10; // backup state
const FLAG_AT: u8 = 0x40; // attested credential data present

#[derive(Debug, thiserror::Error)]
pub enum WebauthnError {
    #[error("malformed credential payload: {0}")]
    Malformed(&'static str),
    #[error("ceremony validation failed: {0}")]
    Invalid(&'static str),
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(i64),
    #[error("signature verification failed")]
    BadSignature,
}

type WebauthnResult<T> = std::result::Result<T, WebauthnError>;

/// The relying party identity all ceremonies are checked against.
#[derive(Debug, Clone)]
pub struct RelyingParty {
    /// RP ID — the registrable domain (`seggwat.com`, or `localhost` in dev).
    pub rp_id: String,
    /// Exact expected origin (`https://seggwat.com`, `http://localhost:8080`).
    pub origin: String,
}

impl RelyingParty {
    /// Derive RP ID + origin from the dashboard's `BASE_URL`.
    pub fn from_base_url(base_url: &str) -> WebauthnResult<Self> {
        let parsed = url::Url::parse(base_url)
            .map_err(|_| WebauthnError::Malformed("BASE_URL is not a valid URL"))?;
        let host = parsed
            .host_str()
            .ok_or(WebauthnError::Malformed("BASE_URL has no host"))?
            .to_string();
        Ok(RelyingParty {
            rp_id: host,
            origin: parsed.origin().ascii_serialization(),
        })
    }
}

/// A fresh 32-byte challenge, base64url (the wire encoding throughout).
pub fn generate_challenge() -> WebauthnResult<String> {
    crypto::generate_url_safe_token(32)
        .map_err(|_| WebauthnError::Invalid("OS RNG failed generating challenge"))
}

/// `PublicKeyCredentialCreationOptions` for registering a new passkey.
///
/// `exclude_credential_ids` should be the user's existing credential ids so
/// the authenticator refuses to double-register.
pub fn registration_options(
    rp: &RelyingParty,
    challenge: &str,
    user_id: &[u8],
    user_name: &str,
    user_display_name: &str,
    exclude_credential_ids: &[String],
) -> Value {
    json!({
        "rp": { "id": rp.rp_id, "name": "SeggWat" },
        "user": {
            "id": URL_SAFE_NO_PAD.encode(user_id),
            "name": user_name,
            "displayName": user_display_name,
        },
        "challenge": challenge,
        "pubKeyCredParams": [
            { "type": "public-key", "alg": -7 },
            { "type": "public-key", "alg": -8 },
            { "type": "public-key", "alg": -257 },
        ],
        "timeout": 60_000,
        "excludeCredentials": exclude_credential_ids.iter().map(|id| {
            json!({ "type": "public-key", "id": id })
        }).collect::<Vec<_>>(),
        "authenticatorSelection": {
            "residentKey": "preferred",
            "userVerification": "required",
        },
        "attestation": "none",
    })
}

/// `PublicKeyCredentialRequestOptions` for authenticating with a passkey.
pub fn request_options(
    rp: &RelyingParty,
    challenge: &str,
    allow_credentials: &[(String, Vec<String>)],
) -> Value {
    json!({
        "challenge": challenge,
        "timeout": 60_000,
        "rpId": rp.rp_id,
        "allowCredentials": allow_credentials.iter().map(|(id, transports)| {
            json!({ "type": "public-key", "id": id, "transports": transports })
        }).collect::<Vec<_>>(),
        "userVerification": "required",
    })
}

/// Outcome of a verified registration ceremony — what the caller persists.
#[derive(Debug)]
pub struct RegisteredPasskey {
    /// base64url credential id.
    pub credential_id: String,
    /// COSE public key, re-encoded CBOR.
    pub public_key_cose: Vec<u8>,
    pub sign_count: i64,
    pub transports: Vec<String>,
    pub backed_up: bool,
}

/// Verify a `navigator.credentials.create()` response (the JSON shape emitted
/// by `webauthn_helpers::browser_create_passkey`).
pub fn verify_registration(
    rp: &RelyingParty,
    expected_challenge: &str,
    credential: &Value,
) -> WebauthnResult<RegisteredPasskey> {
    let response = credential
        .get("response")
        .ok_or(WebauthnError::Malformed("missing response"))?;

    let client_data = b64_field(response, "clientDataJSON")?;
    check_client_data(&client_data, "webauthn.create", expected_challenge, rp)?;

    let attestation_object = b64_field(response, "attestationObject")?;
    let auth_data = attestation_auth_data(&attestation_object)?;
    let parsed = parse_auth_data(&auth_data, rp, true)?;

    if parsed.flags & FLAG_UV == 0 {
        return Err(WebauthnError::Invalid("user verification missing"));
    }
    let attested = parsed
        .attested
        .ok_or(WebauthnError::Malformed("no attested credential data"))?;

    // Sanity: the COSE key must parse to a supported algorithm now, not at
    // first login.
    parse_cose_key(&attested.public_key_cose)?;

    // The top-level `rawId` must match the attested credential id.
    let raw_id = credential
        .get("rawId")
        .and_then(Value::as_str)
        .ok_or(WebauthnError::Malformed("missing rawId"))?;
    if raw_id != attested.credential_id {
        return Err(WebauthnError::Invalid("rawId does not match attested id"));
    }

    let transports = response
        .get("transports")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    Ok(RegisteredPasskey {
        credential_id: attested.credential_id,
        public_key_cose: attested.public_key_cose,
        sign_count: parsed.sign_count,
        transports,
        backed_up: parsed.flags & FLAG_BS != 0,
    })
}

/// Outcome of a verified authentication ceremony.
#[derive(Debug)]
pub struct AuthenticatedPasskey {
    /// The signature counter to **persist** — never less than the stored value.
    pub sign_count: i64,
    pub backed_up: bool,
}

/// Verify a `navigator.credentials.get()` assertion against a stored COSE key
/// (the JSON shape emitted by `webauthn_helpers::browser_get_passkey`).
///
/// `stored_sign_count` feeds clone detection: a counter that fails to advance
/// on an authenticator that implements counters means a cloned key.
pub fn verify_authentication(
    rp: &RelyingParty,
    expected_challenge: &str,
    credential: &Value,
    public_key_cose: &[u8],
    stored_sign_count: i64,
) -> WebauthnResult<AuthenticatedPasskey> {
    let response = credential
        .get("response")
        .ok_or(WebauthnError::Malformed("missing response"))?;

    let client_data = b64_field(response, "clientDataJSON")?;
    check_client_data(&client_data, "webauthn.get", expected_challenge, rp)?;

    let auth_data = b64_field(response, "authenticatorData")?;
    // Assertions never carry attested credential data — don't parse it. An
    // attacker can set the AT flag anyway, and the CBOR decode it triggers runs
    // *before* the signature check, so parsing it here is an unauthenticated
    // memory-amplification vector. `want_attested: false` stops after signCount.
    let parsed = parse_auth_data(&auth_data, rp, false)?;
    if parsed.flags & FLAG_UV == 0 {
        return Err(WebauthnError::Invalid("user verification missing"));
    }

    // signCount clone detection: only meaningful when the authenticator
    // implements a counter (many platform authenticators always report 0).
    if parsed.sign_count > 0 && stored_sign_count > 0 && parsed.sign_count <= stored_sign_count {
        return Err(WebauthnError::Invalid("signature counter did not advance"));
    }

    let signature = b64_field(response, "signature")?;
    let mut message = auth_data.clone();
    message.extend_from_slice(&Sha256::digest(&client_data));

    verify_signature(public_key_cose, &message, &signature)?;

    Ok(AuthenticatedPasskey {
        // Persist the *max* so a counter never regresses: an assertion reporting
        // 0 against a stored non-zero must not reset the stored value, or it
        // would silently disarm clone detection for that credential forever.
        sign_count: parsed.sign_count.max(stored_sign_count),
        backed_up: parsed.flags & FLAG_BS != 0,
    })
}

// ── Internals ────────────────────────────────────────────────────────

fn b64_field(response: &Value, key: &'static str) -> WebauthnResult<Vec<u8>> {
    let s = response
        .get(key)
        .and_then(Value::as_str)
        .ok_or(WebauthnError::Malformed("missing base64 field"))?;
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| WebauthnError::Malformed(key))
}

/// Validate collectedClientData: ceremony type, challenge echo, exact origin.
fn check_client_data(
    client_data: &[u8],
    expected_type: &str,
    expected_challenge: &str,
    rp: &RelyingParty,
) -> WebauthnResult<()> {
    let parsed: Value = serde_json::from_slice(client_data)
        .map_err(|_| WebauthnError::Malformed("clientDataJSON is not JSON"))?;

    if parsed.get("type").and_then(Value::as_str) != Some(expected_type) {
        return Err(WebauthnError::Invalid("wrong ceremony type"));
    }
    // The browser re-encodes the challenge bytes as base64url-no-pad, which
    // round-trips to the exact string we minted.
    if parsed.get("challenge").and_then(Value::as_str) != Some(expected_challenge) {
        return Err(WebauthnError::Invalid("challenge mismatch"));
    }
    if parsed.get("origin").and_then(Value::as_str) != Some(rp.origin.as_str()) {
        return Err(WebauthnError::Invalid("origin mismatch"));
    }
    Ok(())
}

struct AttestedCredential {
    credential_id: String,
    public_key_cose: Vec<u8>,
}

struct ParsedAuthData {
    flags: u8,
    sign_count: i64,
    attested: Option<AttestedCredential>,
}

/// Parse authenticatorData (WebAuthn §6.1): rpIdHash ‖ flags ‖ signCount
/// [‖ attestedCredentialData when the AT flag is set].
///
/// `want_attested` gates the (attacker-influenced) CBOR decode of attested
/// credential data: `true` on registration, where we need the new key; `false`
/// on authentication, where an assertion has none and parsing it would be a
/// pre-signature-check DoS vector.
fn parse_auth_data(
    auth_data: &[u8],
    rp: &RelyingParty,
    want_attested: bool,
) -> WebauthnResult<ParsedAuthData> {
    if auth_data.len() < 37 {
        return Err(WebauthnError::Malformed("authenticatorData too short"));
    }
    let rp_id_hash = &auth_data[..32];
    if rp_id_hash != Sha256::digest(rp.rp_id.as_bytes()).as_slice() {
        return Err(WebauthnError::Invalid("rpIdHash mismatch"));
    }
    let flags = auth_data[32];
    if flags & FLAG_UP == 0 {
        return Err(WebauthnError::Invalid("user presence missing"));
    }
    let sign_count = u32::from_be_bytes(
        auth_data[33..37]
            .try_into()
            .expect("slice length checked above"),
    ) as i64;

    let attested = if want_attested && flags & FLAG_AT != 0 {
        // 16-byte AAGUID ‖ u16 credIdLen ‖ credId ‖ COSE key (CBOR).
        if auth_data.len() < 55 {
            return Err(WebauthnError::Malformed("attested data too short"));
        }
        let cred_id_len =
            u16::from_be_bytes(auth_data[53..55].try_into().expect("length checked")) as usize;
        // WebAuthn §6.5.2 caps a credential id at 1023 bytes. Reject longer so a
        // self-registered credential can't smuggle a huge id into storage.
        if cred_id_len > 1023 {
            return Err(WebauthnError::Malformed("credential id too long"));
        }
        let cred_id_end = 55 + cred_id_len;
        if auth_data.len() < cred_id_end {
            return Err(WebauthnError::Malformed("credential id truncated"));
        }
        let credential_id = URL_SAFE_NO_PAD.encode(&auth_data[55..cred_id_end]);

        // Read exactly one CBOR item (extensions may trail when the ED flag is
        // set) and re-encode it as the canonical stored key bytes.
        let mut reader = &auth_data[cred_id_end..];
        let key: Cbor = ciborium::de::from_reader(&mut reader)
            .map_err(|_| WebauthnError::Malformed("COSE key is not valid CBOR"))?;
        let mut public_key_cose = Vec::new();
        ciborium::ser::into_writer(&key, &mut public_key_cose)
            .map_err(|_| WebauthnError::Malformed("COSE key re-encode failed"))?;

        Some(AttestedCredential {
            credential_id,
            public_key_cose,
        })
    } else {
        None
    };

    Ok(ParsedAuthData {
        flags,
        sign_count,
        attested,
    })
}

/// Pull `authData` out of the registration attestationObject. The `fmt` /
/// `attStmt` members are deliberately ignored (attestation policy "none").
fn attestation_auth_data(attestation_object: &[u8]) -> WebauthnResult<Vec<u8>> {
    let parsed: Cbor = ciborium::de::from_reader(attestation_object)
        .map_err(|_| WebauthnError::Malformed("attestationObject is not valid CBOR"))?;
    let map = parsed
        .as_map()
        .ok_or(WebauthnError::Malformed("attestationObject is not a map"))?;
    for (k, v) in map {
        if k.as_text() == Some("authData") {
            return v
                .as_bytes()
                .cloned()
                .ok_or(WebauthnError::Malformed("authData is not bytes"));
        }
    }
    Err(WebauthnError::Malformed(
        "attestationObject missing authData",
    ))
}

enum CoseKey {
    /// ES256: uncompressed P-256 point (0x04 ‖ x ‖ y).
    Es256(Vec<u8>),
    /// EdDSA: raw Ed25519 public key.
    Ed25519(Vec<u8>),
    /// RS256: (n, e).
    Rs256(Vec<u8>, Vec<u8>),
}

/// Parse a COSE_Key (RFC 9052 §7) into one of the supported algorithms.
fn parse_cose_key(cose: &[u8]) -> WebauthnResult<CoseKey> {
    let parsed: Cbor = ciborium::de::from_reader(cose)
        .map_err(|_| WebauthnError::Malformed("COSE key is not valid CBOR"))?;
    let map = parsed
        .as_map()
        .ok_or(WebauthnError::Malformed("COSE key is not a map"))?;

    let get = |label: i64| -> Option<&Cbor> {
        map.iter()
            .find(|(k, _)| k.as_integer() == Some(label.into()))
            .map(|(_, v)| v)
    };
    let get_bytes = |label: i64, what: &'static str| -> WebauthnResult<Vec<u8>> {
        get(label)
            .and_then(Cbor::as_bytes)
            .cloned()
            .ok_or(WebauthnError::Malformed(what))
    };

    let alg: i64 = get(3)
        .and_then(Cbor::as_integer)
        .and_then(|i| i.try_into().ok())
        .ok_or(WebauthnError::Malformed("COSE key missing alg"))?;

    match alg {
        -7 => {
            // EC2, P-256. -2 = x, -3 = y.
            let x = get_bytes(-2, "ES256 key missing x")?;
            let y = get_bytes(-3, "ES256 key missing y")?;
            if x.len() != 32 || y.len() != 32 {
                return Err(WebauthnError::Malformed("ES256 coordinate length"));
            }
            let mut point = Vec::with_capacity(65);
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            Ok(CoseKey::Es256(point))
        }
        -8 => {
            // OKP, Ed25519. -2 = x.
            let x = get_bytes(-2, "Ed25519 key missing x")?;
            if x.len() != 32 {
                return Err(WebauthnError::Malformed("Ed25519 key length"));
            }
            Ok(CoseKey::Ed25519(x))
        }
        -257 => {
            // RSA. -1 = n, -2 = e.
            let n = get_bytes(-1, "RS256 key missing n")?;
            let e = get_bytes(-2, "RS256 key missing e")?;
            Ok(CoseKey::Rs256(n, e))
        }
        other => Err(WebauthnError::UnsupportedAlgorithm(other)),
    }
}

fn verify_signature(cose: &[u8], message: &[u8], signature: &[u8]) -> WebauthnResult<()> {
    use ring::signature;
    match parse_cose_key(cose)? {
        CoseKey::Es256(point) => {
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &point)
                .verify(message, signature)
                .map_err(|_| WebauthnError::BadSignature)
        }
        CoseKey::Ed25519(key) => signature::UnparsedPublicKey::new(&signature::ED25519, &key)
            .verify(message, signature)
            .map_err(|_| WebauthnError::BadSignature),
        CoseKey::Rs256(n, e) => signature::RsaPublicKeyComponents { n: &n, e: &e }
            .verify(&signature::RSA_PKCS1_2048_8192_SHA256, message, signature)
            .map_err(|_| WebauthnError::BadSignature),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair};

    fn rp() -> RelyingParty {
        RelyingParty {
            rp_id: "localhost".to_string(),
            origin: "http://localhost:8080".to_string(),
        }
    }

    fn client_data(ceremony: &str, challenge: &str, origin: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "type": ceremony,
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": false,
        }))
        .unwrap()
    }

    /// authenticatorData with the given flags/counter, optionally carrying
    /// attested credential data (AT flag added automatically).
    fn auth_data(
        rp_id: &str,
        mut flags: u8,
        counter: u32,
        attested: Option<(&[u8], &[u8])>, // (cred_id, cose_key)
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        if attested.is_some() {
            flags |= FLAG_AT;
        }
        out.push(flags);
        out.extend_from_slice(&counter.to_be_bytes());
        if let Some((cred_id, cose_key)) = attested {
            out.extend_from_slice(&[0u8; 16]); // AAGUID
            out.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
            out.extend_from_slice(cred_id);
            out.extend_from_slice(cose_key);
        }
        out
    }

    fn cose_es256(public_point: &[u8]) -> Vec<u8> {
        // Uncompressed point: 0x04 ‖ x(32) ‖ y(32).
        assert_eq!(public_point.len(), 65);
        let map = Cbor::Map(vec![
            (Cbor::Integer(1.into()), Cbor::Integer(2.into())), // kty: EC2
            (Cbor::Integer(3.into()), Cbor::Integer((-7).into())), // alg: ES256
            (Cbor::Integer((-1).into()), Cbor::Integer(1.into())), // crv: P-256
            (
                Cbor::Integer((-2).into()),
                Cbor::Bytes(public_point[1..33].to_vec()),
            ),
            (
                Cbor::Integer((-3).into()),
                Cbor::Bytes(public_point[33..65].to_vec()),
            ),
        ]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&map, &mut out).unwrap();
        out
    }

    fn cose_ed25519(public_key: &[u8]) -> Vec<u8> {
        let map = Cbor::Map(vec![
            (Cbor::Integer(1.into()), Cbor::Integer(1.into())), // kty: OKP
            (Cbor::Integer(3.into()), Cbor::Integer((-8).into())), // alg: EdDSA
            (Cbor::Integer((-1).into()), Cbor::Integer(6.into())), // crv: Ed25519
            (Cbor::Integer((-2).into()), Cbor::Bytes(public_key.to_vec())),
        ]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&map, &mut out).unwrap();
        out
    }

    fn attestation_object(auth_data: &[u8]) -> Vec<u8> {
        let map = Cbor::Map(vec![
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
            (
                Cbor::Text("authData".into()),
                Cbor::Bytes(auth_data.to_vec()),
            ),
        ]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&map, &mut out).unwrap();
        out
    }

    fn registration_credential(
        challenge: &str,
        origin: &str,
        cred_id: &[u8],
        cose_key: &[u8],
        flags: u8,
    ) -> Value {
        let ad = auth_data("localhost", flags, 0, Some((cred_id, cose_key)));
        json!({
            "id": URL_SAFE_NO_PAD.encode(cred_id),
            "rawId": URL_SAFE_NO_PAD.encode(cred_id),
            "type": "public-key",
            "response": {
                "attestationObject": URL_SAFE_NO_PAD.encode(attestation_object(&ad)),
                "clientDataJSON": URL_SAFE_NO_PAD.encode(client_data("webauthn.create", challenge, origin)),
                "transports": ["internal", "hybrid"],
            },
        })
    }

    #[test]
    fn registration_roundtrip_es256() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let cose = cose_es256(key.public_key().as_ref());

        let challenge = generate_challenge().unwrap();
        let cred = registration_credential(
            &challenge,
            "http://localhost:8080",
            b"cred-id-1",
            &cose,
            FLAG_UP | FLAG_UV | FLAG_BS,
        );

        let reg = verify_registration(&rp(), &challenge, &cred).expect("registration verifies");
        assert_eq!(reg.credential_id, URL_SAFE_NO_PAD.encode(b"cred-id-1"));
        assert_eq!(reg.public_key_cose, cose);
        assert!(reg.backed_up);
        assert_eq!(reg.transports, vec!["internal", "hybrid"]);
    }

    #[test]
    fn registration_rejects_wrong_origin_challenge_type_and_missing_uv() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let cose = cose_es256(key.public_key().as_ref());
        let challenge = generate_challenge().unwrap();

        let wrong_origin = registration_credential(
            &challenge,
            "https://evil.example",
            b"c",
            &cose,
            FLAG_UP | FLAG_UV,
        );
        assert!(verify_registration(&rp(), &challenge, &wrong_origin).is_err());

        let good = registration_credential(
            &challenge,
            "http://localhost:8080",
            b"c",
            &cose,
            FLAG_UP | FLAG_UV,
        );
        assert!(verify_registration(&rp(), "other-challenge", &good).is_err());

        let no_uv =
            registration_credential(&challenge, "http://localhost:8080", b"c", &cose, FLAG_UP);
        assert!(verify_registration(&rp(), &challenge, &no_uv).is_err());
    }

    fn assertion(
        challenge: &str,
        origin: &str,
        flags: u8,
        counter: u32,
        sign: impl FnOnce(&[u8]) -> Vec<u8>,
    ) -> Value {
        let ad = auth_data("localhost", flags, counter, None);
        let cd = client_data("webauthn.get", challenge, origin);
        let mut message = ad.clone();
        message.extend_from_slice(&Sha256::digest(&cd));
        let sig = sign(&message);
        json!({
            "id": "x", "rawId": "x", "type": "public-key",
            "response": {
                "authenticatorData": URL_SAFE_NO_PAD.encode(&ad),
                "clientDataJSON": URL_SAFE_NO_PAD.encode(&cd),
                "signature": URL_SAFE_NO_PAD.encode(&sig),
                "userHandle": null,
            },
        })
    }

    #[test]
    fn authentication_verifies_es256_and_ed25519() {
        let rng = SystemRandom::new();

        // ES256
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let cose = cose_es256(key.public_key().as_ref());
        let challenge = generate_challenge().unwrap();
        let cred = assertion(
            &challenge,
            "http://localhost:8080",
            FLAG_UP | FLAG_UV,
            5,
            |m| key.sign(&rng, m).unwrap().as_ref().to_vec(),
        );
        let out =
            verify_authentication(&rp(), &challenge, &cred, &cose, 4).expect("es256 verifies");
        assert_eq!(out.sign_count, 5);

        // Ed25519
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let cose = cose_ed25519(key.public_key().as_ref());
        let challenge = generate_challenge().unwrap();
        let cred = assertion(
            &challenge,
            "http://localhost:8080",
            FLAG_UP | FLAG_UV,
            0,
            |m| key.sign(m).as_ref().to_vec(),
        );
        verify_authentication(&rp(), &challenge, &cred, &cose, 0).expect("ed25519 verifies");
    }

    #[test]
    fn authentication_ignores_attested_data_on_assertion() {
        // An attacker sets the AT flag on an assertion and appends a bogus
        // "attested credential data" blob that is NOT valid CBOR. The verifier
        // must ignore it (not decode it — that would be a pre-signature DoS) and
        // still verify the signature over the full authenticatorData.
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let cose = cose_es256(key.public_key().as_ref());
        let challenge = generate_challenge().unwrap();

        let junk = vec![0xFFu8; 128]; // 0xFF is CBOR "break" — decode would error
        let ad = auth_data("localhost", FLAG_UP | FLAG_UV, 3, Some((b"cred", &junk)));
        let cd = client_data("webauthn.get", &challenge, "http://localhost:8080");
        let mut message = ad.clone();
        message.extend_from_slice(&Sha256::digest(&cd));
        let sig = key.sign(&rng, &message).unwrap().as_ref().to_vec();
        let cred = json!({
            "id": "x", "rawId": "x", "type": "public-key",
            "response": {
                "authenticatorData": URL_SAFE_NO_PAD.encode(&ad),
                "clientDataJSON": URL_SAFE_NO_PAD.encode(&cd),
                "signature": URL_SAFE_NO_PAD.encode(&sig),
                "userHandle": null,
            },
        });
        verify_authentication(&rp(), &challenge, &cred, &cose, 0)
            .expect("AT flag + junk attested data is ignored on an assertion");
    }

    #[test]
    fn authentication_never_regresses_stored_counter() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let cose = cose_es256(key.public_key().as_ref());

        // Authenticator reports 0 (no counter) but we already stored 5 — the
        // persisted value must stay 5, else clone detection is disarmed forever.
        let challenge = generate_challenge().unwrap();
        let cred = assertion(
            &challenge,
            "http://localhost:8080",
            FLAG_UP | FLAG_UV,
            0,
            |m| key.sign(&rng, m).unwrap().as_ref().to_vec(),
        );
        let out = verify_authentication(&rp(), &challenge, &cred, &cose, 5)
            .expect("zero counter accepted");
        assert_eq!(out.sign_count, 5, "stored counter must not regress to 0");

        // A genuine advance persists the higher value.
        let challenge = generate_challenge().unwrap();
        let cred = assertion(
            &challenge,
            "http://localhost:8080",
            FLAG_UP | FLAG_UV,
            9,
            |m| key.sign(&rng, m).unwrap().as_ref().to_vec(),
        );
        let out =
            verify_authentication(&rp(), &challenge, &cred, &cose, 5).expect("advance verifies");
        assert_eq!(out.sign_count, 9);
    }

    #[test]
    fn authentication_rejects_tampered_sig_counter_regression_and_wrong_rp() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let cose = cose_es256(key.public_key().as_ref());
        let challenge = generate_challenge().unwrap();

        // Tampered signature.
        let cred = assertion(
            &challenge,
            "http://localhost:8080",
            FLAG_UP | FLAG_UV,
            5,
            |m| {
                let mut s = key.sign(&rng, m).unwrap().as_ref().to_vec();
                s[10] ^= 0xff;
                s
            },
        );
        assert!(matches!(
            verify_authentication(&rp(), &challenge, &cred, &cose, 4),
            Err(WebauthnError::BadSignature)
        ));

        // Counter regression (stored 5, asserted 5 — must advance).
        let cred = assertion(
            &challenge,
            "http://localhost:8080",
            FLAG_UP | FLAG_UV,
            5,
            |m| key.sign(&rng, m).unwrap().as_ref().to_vec(),
        );
        assert!(verify_authentication(&rp(), &challenge, &cred, &cose, 5).is_err());

        // Signed for a different RP ID.
        let other = RelyingParty {
            rp_id: "seggwat.com".to_string(),
            origin: "http://localhost:8080".to_string(),
        };
        let cred = assertion(
            &challenge,
            "http://localhost:8080",
            FLAG_UP | FLAG_UV,
            6,
            |m| key.sign(&rng, m).unwrap().as_ref().to_vec(),
        );
        assert!(verify_authentication(&other, &challenge, &cred, &cose, 5).is_err());
    }

    #[test]
    fn relying_party_from_base_url() {
        let rp = RelyingParty::from_base_url("http://localhost:8080").unwrap();
        assert_eq!(rp.rp_id, "localhost");
        assert_eq!(rp.origin, "http://localhost:8080");

        let rp = RelyingParty::from_base_url("https://seggwat.com").unwrap();
        assert_eq!(rp.rp_id, "seggwat.com");
        assert_eq!(rp.origin, "https://seggwat.com");
    }
}
