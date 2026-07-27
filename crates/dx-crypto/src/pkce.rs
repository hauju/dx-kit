//! PKCE (Proof Key for Code Exchange, RFC 7636) helpers for OAuth flows.
//!
//! The client sends `code_challenge = BASE64URL-NO-PAD(SHA256(code_verifier))`
//! on the authorize request, and the server verifies the later `code_verifier`
//! against it at the token endpoint. Only the `S256` method is supported —
//! `plain` must be rejected by the caller.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

/// Compute the S256 code challenge for a PKCE code verifier (RFC 7636 §4.2):
/// `BASE64URL-NO-PAD(SHA256(ASCII(verifier)))`.
///
/// # Example
/// ```
/// use dx_crypto::pkce_s256_challenge;
///
/// // RFC 7636 Appendix B test vector
/// let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// assert_eq!(
///     pkce_s256_challenge(verifier),
///     "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
/// );
/// ```
pub fn pkce_s256_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Constant-time check that `verifier` hashes to the stored S256 `challenge`.
///
/// The comparison runs in time proportional to the challenge length regardless
/// of where the first mismatching byte is, so a caller cannot learn the stored
/// challenge one byte at a time by measuring how long verification took.
///
/// # Example
/// ```
/// use dx_crypto::verify_pkce_s256;
///
/// let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/// let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
/// assert!(verify_pkce_s256(verifier, challenge));
/// assert!(!verify_pkce_s256("wrong-verifier", challenge));
/// ```
pub fn verify_pkce_s256(verifier: &str, challenge: &str) -> bool {
    let computed = pkce_s256_challenge(verifier);
    let a = computed.as_bytes();
    let b = challenge.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Deprecated alias for [`verify_pkce_s256`], kept so existing call sites keep
/// compiling. Prefer [`verify_pkce_s256`] — it is otherwise identical.
#[deprecated(since = "0.1.0", note = "renamed to `verify_pkce_s256`")]
pub fn pkce_s256_matches(code_verifier: &str, code_challenge: &str) -> bool {
    verify_pkce_s256(code_verifier, code_challenge)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector_rfc7636() {
        // RFC 7636 Appendix B test vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(pkce_s256_challenge(verifier), challenge);
        assert!(verify_pkce_s256(verifier, challenge));
    }

    #[test]
    fn rejects_wrong_verifier() {
        assert!(!verify_pkce_s256(
            "wrong-verifier",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
    }

    #[test]
    fn rejects_tampered_challenge() {
        assert!(!verify_pkce_s256(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "tampered"
        ));
    }

    #[test]
    fn rejects_length_mismatch_without_panicking() {
        assert!(!verify_pkce_s256("anything", ""));
    }
}
