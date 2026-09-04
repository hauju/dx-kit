//! Self-owned login flow. Two factors, both owned here — there is no external
//! identity provider and no password anywhere.
//!
//! * **Email OTP** — the universal baseline, for sign-in *and* sign-up. We mint
//!   the code, mail it, and hold it in the session (see `otp`). A verified code
//!   for an unknown address *creates* the account: registration is not a
//!   separate step, but it is gated by the registration allowlist and, when
//!   configured, the captcha.
//! * **Passkey** — this app is its own WebAuthn Relying Party (see
//!   `crate::webauthn`): credentials live in the app's store and ceremonies are
//!   verified here. `start_session` hands request options to a browser whose
//!   account has credentials; `verify_passkey_handler` checks the assertion and
//!   finalizes. Enrollment lives in `passkey_enroll`.
//!
//! The flow is: email → passkey if the account has one → OTP otherwise, with
//! OTP always reachable as the fallback when a passkey ceremony is cancelled or
//! fails.

use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::config::AuthConfig;
use crate::error::{AuthError, AuthResult};
use crate::handlers::otp::{
    CUSTOM_OTP_CODE_KEY, CUSTOM_OTP_LAST_SENT_AT_KEY, CUSTOM_OTP_PURPOSE_KEY,
    CUSTOM_OTP_RESEND_COUNT_KEY, MAX_RESEND_COUNT, RESEND_COOLDOWN_SECONDS, captcha_cfg,
    clear_otp_state, generate_and_send_otp, verify_captcha_token, verify_otp_guarded,
};
use crate::handlers::shared::{self, determine_post_login_redirect, registration_allowed};
use crate::session::LoggedInData;
use crate::state::AuthState;
use crate::types::{AuthUser, NewAuthUser};

// ── Session keys for temporary login state ──────────────────────────

const LOGIN_EMAIL_KEY: &str = "login.email";

/// Set when login starts for an address with no account. The account is created
/// only once an OTP verifies, so a bot cannot mint rows by POSTing addresses.
const DEFERRED_NEW_USER_KEY: &str = "login.deferred_new_user";

/// Kill-switch for the passkey *login* path. Enrollment
/// (`/auth/passkey/enroll/*`) stays available either way, so flipping this off
/// during an incident degrades to OTP rather than locking anyone out.
const PASSKEY_LOGIN_ENABLED: bool = true;

// Passkey login ceremony state.
const PASSKEY_CHALLENGE_KEY: &str = "passkey.challenge";
const PASSKEY_USER_ID_KEY: &str = "passkey.user_id";

// ── Request / Response types ────────────────────────────────────────

#[derive(Deserialize)]
pub struct StartSessionRequest {
    pub email: String,
    #[serde(default)]
    pub redirect_url: Option<String>,
}

#[derive(Serialize)]
pub struct StartSessionResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_options: Option<serde_json::Value>,
    pub otp_sent: bool,
    pub is_new_user: bool,
    pub has_passkeys: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub captcha_required: Option<bool>,
    /// Captcha server base URL + site key, returned only when a new-user
    /// registration needs the widget. Both values are public by design.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub captcha_server_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub captcha_site_key: Option<String>,
}

impl StartSessionResponse {
    fn otp_sent(is_new_user: bool, has_passkeys: bool) -> Self {
        Self {
            public_key_options: None,
            otp_sent: true,
            is_new_user,
            has_passkeys,
            captcha_required: None,
            captcha_server_url: None,
            captcha_site_key: None,
        }
    }
}

#[derive(Deserialize)]
pub struct VerifyPasskeyRequest {
    pub credential_assertion_data: serde_json::Value,
}

#[derive(Deserialize)]
pub struct VerifyOtpRequest {
    pub code: String,
}

#[derive(Deserialize)]
pub struct VerifyCaptchaRequest {
    /// The bollwark widget's opaque token.
    #[serde(default)]
    pub captcha_token: Option<String>,
}

#[derive(Serialize)]
pub struct CaptchaVerifyResponse {
    pub success: bool,
    pub otp_sent: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<i64>,
    /// `Some(true)` after a successful login when the account has no passkeys
    /// yet — the client may show the one-time enrollment prompt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offer_passkey: Option<bool>,
}

impl VerifyResponse {
    fn failed(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            redirect_url: None,
            error: Some(msg.into()),
            retry_after_seconds: None,
            offer_passkey: None,
        }
    }

    fn logged_in(result: FinalizeResult) -> Self {
        Self {
            success: true,
            redirect_url: Some(result.redirect_url),
            error: None,
            retry_after_seconds: None,
            offer_passkey: result.offer_passkey.then_some(true),
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// The WebAuthn Relying Party identity, derived from this app's own `base_url`.
fn relying_party(auth_config: &AuthConfig) -> AuthResult<crate::webauthn::RelyingParty> {
    crate::webauthn::RelyingParty::from_base_url(&auth_config.base_url)
        .map_err(|e| AuthError::ServerStateError(format!("BASE_URL invalid for WebAuthn: {e}")))
}

/// The WebAuthn `user.id` (userHandle) for an account, as the browser returns
/// it: base64url of the bytes `passkey_enroll` registered (the user id's text).
///
/// The bytes here **must** match what enrollment registers, or the
/// conditional-UI cross-check below rejects every resident credential.
fn user_handle(user_id: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(user_id.as_bytes())
}

/// Drop credential state left over from an earlier attempt in this session.
/// Without it, an OTP, a `deferred_new_user` flag or a passkey challenge issued
/// for one address survive into a `/session/start` for a different one.
///
/// Deliberately keeps the resend throttle: it is an abuse control, and
/// restarting the flow must not reset it.
async fn reset_pending_login_state(session: &tower_sessions::Session) -> AuthResult<()> {
    clear_otp_state(session).await;
    session.remove::<bool>(DEFERRED_NEW_USER_KEY).await?;
    session.remove::<String>(PASSKEY_CHALLENGE_KEY).await?;
    session.remove::<String>(PASSKEY_USER_ID_KEY).await?;
    Ok(())
}

/// Shared resend guard: a hard cap plus a cooldown. Every endpoint that can
/// trigger an email must go through this, or it becomes an unauthenticated mail
/// cannon aimed at an arbitrary address — the per-IP governor on the auth router
/// is the only other bound, and it does not know about the recipient.
async fn resend_throttle_error(
    session: &tower_sessions::Session,
) -> AuthResult<Option<VerifyResponse>> {
    let resend_count = session
        .get::<u32>(CUSTOM_OTP_RESEND_COUNT_KEY)
        .await?
        .unwrap_or(0);
    if resend_count >= MAX_RESEND_COUNT {
        return Ok(Some(VerifyResponse::failed(
            "Maximum resend attempts reached. Please start a new login.",
        )));
    }

    if let Some(last_sent_at) = session.get::<i64>(CUSTOM_OTP_LAST_SENT_AT_KEY).await? {
        let elapsed = chrono::Utc::now().timestamp() - last_sent_at;
        if elapsed < RESEND_COOLDOWN_SECONDS {
            let retry_after = RESEND_COOLDOWN_SECONDS - elapsed;
            return Ok(Some(VerifyResponse {
                retry_after_seconds: Some(retry_after),
                ..VerifyResponse::failed(format!(
                    "Please wait {retry_after} seconds before requesting a new code."
                ))
            }));
        }
    }

    Ok(None)
}

/// Resolve the account for an address whose ownership was just proven, creating
/// it on first sign-in.
///
/// **Email is the identity here.** There is no directory to reconcile against,
/// so the lookup is by address and `sub` is never rewritten after creation.
/// `shared::lookup_or_create_user` is deliberately not used: it keys on the
/// IdP's `sub` and migrates by email, which with a self-issued `sub` would
/// rewrite the column on every login.
pub(super) async fn resolve_or_create_account(
    auth_state: &AuthState,
    auth_config: &AuthConfig,
    email: &str,
) -> AuthResult<AuthUser> {
    if let Some(user) = auth_state.user_store.get_user_by_email(email).await? {
        return Ok(user);
    }

    // Re-check the allowlist at the point of creation, independent of the
    // start-of-flow check: this is the only step that provisions an account,
    // so it must not rely on an upstream gate.
    if !registration_allowed(auth_state, auth_config, email).await? {
        warn!("Blocked account creation for '{email}' (not permitted to register)");
        return Err(AuthError::Unauthorized(
            "Registration is not open for this address".to_string(),
        ));
    }

    // No identity provider to issue a subject, so mint one: opaque, unique,
    // and stable for the account's life.
    let sub = crypto::generate_url_safe_token(16)
        .map_err(|e| AuthError::ServerStateError(format!("Failed to generate subject: {e}")))?;
    let user = auth_state
        .user_store
        .create_user(NewAuthUser {
            sub,
            email: email.to_string(),
        })
        .await
        .map_err(|e| {
            warn!("Error creating user: {:?}", e);
            AuthError::ServerStateError("Failed to create user".to_string())
        })?;
    info!("Created account {} for a first sign-in", user.id);

    if let Err(e) = auth_state
        .user_store
        .create_personal_organization(&user.id, email)
        .await
    {
        warn!("Failed to create personal organization: {:?}", e);
    }

    Ok(user)
}

/// Send an email OTP and shape the start-session response around it.
async fn send_otp_session(
    auth_state: &AuthState,
    session: &tower_sessions::Session,
    email: &str,
    is_new_user: bool,
) -> AuthResult<Json<StartSessionResponse>> {
    generate_and_send_otp(auth_state, session, email, "login").await?;
    Ok(Json(StartSessionResponse::otp_sent(is_new_user, false)))
}

// ── POST /auth/session/start ────────────────────────────────────────

pub async fn start_session(
    Extension(auth_state): Extension<AuthState>,
    Extension(auth_config): Extension<AuthConfig>,
    session: tower_sessions::Session,
    Json(req): Json<StartSessionRequest>,
) -> AuthResult<Json<StartSessionResponse>> {
    let email = req.email.trim().to_lowercase();

    if !shared::is_valid_email(&email) {
        return Err(AuthError::BadRequest("Invalid email address".to_string()));
    }

    if let Some(ref url) = req.redirect_url
        && shared::is_safe_redirect_url(url)
    {
        session
            .insert(shared::LOGIN_REDIRECT_URL_SESSION_KEY, url)
            .await?;
    }

    // A new attempt must not inherit the previous one's credentials.
    reset_pending_login_state(&session).await?;
    session.insert(LOGIN_EMAIL_KEY, &email).await?;

    let Some(user) = auth_state.user_store.get_user_by_email(&email).await? else {
        // ── Unknown address: this is a registration. ──
        if !registration_allowed(&auth_state, &auth_config, &email).await? {
            info!("Registration refused for '{email}' (not permitted to register)");
            return Err(AuthError::Unauthorized(
                "Registration is not open for this address".to_string(),
            ));
        }

        // Flag it so `passkey_fallback_to_otp` refuses to send a code (there
        // is no passkey to fall back from, and that endpoint bypasses the
        // captcha) and `verify_captcha_handler` knows there is one pending.
        session.insert(DEFERRED_NEW_USER_KEY, true).await?;

        return if let Some(cfg) = captcha_cfg() {
            // Gate registration behind the widget; the OTP is sent only once
            // the token verifies at /auth/session/captcha/verify.
            info!("No account for '{email}', requiring captcha before OTP");
            Ok(Json(StartSessionResponse {
                public_key_options: None,
                otp_sent: false,
                is_new_user: true,
                has_passkeys: false,
                captcha_required: Some(true),
                captcha_server_url: Some(cfg.server_url),
                captcha_site_key: Some(cfg.site_key),
            }))
        } else {
            // No captcha deployment: the registration allowlist is the whole
            // gate. It is closed by default and re-checked at account creation.
            warn!(
                "No captcha configured; registration for '{email}' is gated by the allowlist alone"
            );
            send_otp_session(&auth_state, &session, &email, true).await
        };
    };

    let passkeys = auth_state
        .passkey_store
        .list_passkeys(&user.id)
        .await
        .unwrap_or_else(|e| {
            warn!("list_passkeys failed for {}: {:?}", user.id, e);
            Vec::new()
        });

    if PASSKEY_LOGIN_ENABLED && !passkeys.is_empty() {
        let rp = relying_party(&auth_config)?;
        let challenge = crate::webauthn::generate_challenge()
            .map_err(|e| AuthError::ServerStateError(e.to_string()))?;
        let allow: Vec<(String, Vec<String>)> = passkeys
            .iter()
            .map(|p| (p.credential_id.clone(), p.transports.clone()))
            .collect();
        let options = crate::webauthn::request_options(&rp, &challenge, &allow);

        session.insert(PASSKEY_CHALLENGE_KEY, &challenge).await?;
        session.insert(PASSKEY_USER_ID_KEY, &user.id).await?;

        info!("Passkey login challenge issued for user {}", user.id);
        return Ok(Json(StartSessionResponse {
            public_key_options: Some(options),
            otp_sent: false,
            is_new_user: false,
            has_passkeys: true,
            captcha_required: None,
            captcha_server_url: None,
            captcha_site_key: None,
        }));
    }

    // Existing account with no passkey: OTP is the only factor. No captcha —
    // it gates account *creation*, and this address already has one.
    send_otp_session(&auth_state, &session, &email, false).await
}

// ── POST /auth/session/passkey/conditional/options ──────────────────

/// Discoverable-credential request options for the conditional-UI (autofill)
/// flow: no email is known yet, so `allowCredentials` is empty and the browser
/// offers whatever resident keys it holds for this RP. The challenge is parked
/// in the session **without** a user binding — `verify_passkey_handler`
/// resolves the account from the asserted credential instead.
pub async fn passkey_conditional_options(
    Extension(auth_config): Extension<AuthConfig>,
    session: tower_sessions::Session,
) -> AuthResult<Json<serde_json::Value>> {
    if !PASSKEY_LOGIN_ENABLED {
        return Err(AuthError::BadRequest(
            "Passkey login is disabled".to_string(),
        ));
    }
    let rp = relying_party(&auth_config)?;
    let challenge = crate::webauthn::generate_challenge()
        .map_err(|e| AuthError::ServerStateError(e.to_string()))?;
    let options = crate::webauthn::request_options(&rp, &challenge, &[]);

    session.insert(PASSKEY_CHALLENGE_KEY, &challenge).await?;
    session.remove::<String>(PASSKEY_USER_ID_KEY).await?;

    Ok(Json(serde_json::json!({ "options": options })))
}

// ── POST /auth/session/passkey/verify ───────────────────────────────

pub async fn verify_passkey_handler(
    Extension(auth_state): Extension<AuthState>,
    Extension(auth_config): Extension<AuthConfig>,
    session: tower_sessions::Session,
    Json(req): Json<VerifyPasskeyRequest>,
) -> AuthResult<Json<VerifyResponse>> {
    const FAILED: &str = "Passkey verification failed. Please try again.";

    // Kill-switch parity: `start_session` / `conditional_options` won't hand out
    // a challenge when passkeys are disabled, but a session may already hold one
    // — so honour the flag here too, otherwise flipping it off mid-incident
    // still authenticates held challenges.
    if !PASSKEY_LOGIN_ENABLED {
        return Err(AuthError::BadRequest(
            "Passkey login is disabled".to_string(),
        ));
    }

    let challenge = session
        .get::<String>(PASSKEY_CHALLENGE_KEY)
        .await?
        .ok_or_else(|| AuthError::BadRequest("No passkey challenge in progress".to_string()))?;
    // Present on the email-bound flow; absent on the conditional-UI (autofill)
    // flow, where the credential itself names the account.
    let expected_user_id = session.get::<String>(PASSKEY_USER_ID_KEY).await?;

    // The assertion's rawId names the credential; on the email-bound flow it
    // must belong to the user whose email started this login.
    let raw_id = req
        .credential_assertion_data
        .get("rawId")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AuthError::BadRequest("Malformed passkey assertion".to_string()))?;

    let Some(passkey) = auth_state
        .passkey_store
        .find_passkey_by_credential_id(raw_id)
        .await?
    else {
        warn!("Passkey assertion for unknown credential id");
        return Ok(Json(VerifyResponse::failed(FAILED)));
    };
    if let Some(expected) = &expected_user_id
        && passkey.user_id != *expected
    {
        warn!(
            "Passkey assertion user mismatch: credential belongs to {}, session expects {}",
            passkey.user_id, expected
        );
        return Ok(Json(VerifyResponse::failed(FAILED)));
    }
    // Conditional flow: the resident key carries our user id as its userHandle
    // (set at registration) — cross-check it against the store.
    if expected_user_id.is_none()
        && let Some(handle) = req
            .credential_assertion_data
            .get("response")
            .and_then(|r| r.get("userHandle"))
            .and_then(serde_json::Value::as_str)
        && handle != user_handle(&passkey.user_id)
    {
        warn!("Passkey userHandle does not match the credential's owner");
        return Ok(Json(VerifyResponse::failed(FAILED)));
    }

    let rp = relying_party(&auth_config)?;
    let outcome = match crate::webauthn::verify_authentication(
        &rp,
        &challenge,
        &req.credential_assertion_data,
        &passkey.public_key_cose,
        passkey.sign_count,
    ) {
        Ok(outcome) => outcome,
        Err(e) => {
            // Keep the challenge so the user can retry the same ceremony; it is
            // burned on success below and superseded by any new
            // /auth/session/start.
            warn!("Passkey verification failed: {:?}", e);
            return Ok(Json(VerifyResponse::failed(FAILED)));
        }
    };

    // Burn the challenge and record the authentication.
    session.remove::<String>(PASSKEY_CHALLENGE_KEY).await?;
    session.remove::<String>(PASSKEY_USER_ID_KEY).await?;
    if let Err(e) = auth_state
        .passkey_store
        .touch_passkey(
            &passkey.credential_id,
            outcome.sign_count,
            outcome.backed_up,
        )
        .await
    {
        warn!("touch_passkey failed: {:?}", e);
    }

    // The verified credential names its owner; on the email-bound flow that
    // owner was already checked against the session's binding above.
    let user = auth_state
        .user_store
        .get_user_by_id(&passkey.user_id)
        .await?
        .ok_or_else(|| AuthError::ServerStateError("Passkey owner no longer exists".to_string()))?;

    let result = finalize_login(&auth_state, &auth_config, &session, &user).await?;
    Ok(Json(VerifyResponse::logged_in(result)))
}

// ── POST /auth/session/otp/verify ───────────────────────────────────

pub async fn verify_otp_handler(
    Extension(auth_state): Extension<AuthState>,
    Extension(auth_config): Extension<AuthConfig>,
    session: tower_sessions::Session,
    Json(req): Json<VerifyOtpRequest>,
) -> AuthResult<Json<VerifyResponse>> {
    let code = req.code.trim().to_string();
    if code.is_empty() {
        return Err(AuthError::BadRequest(
            "Verification code is required".to_string(),
        ));
    }

    match verify_otp_guarded(&session, &code).await? {
        // `email` is the address the code was mailed to, not `login.email` —
        // the latter is rewritten by every /session/start and proves nothing.
        // A verified code is proof of address ownership, which is the whole
        // basis for an account here, so this creates the user if the address
        // has none.
        Ok(email) => {
            let user = resolve_or_create_account(&auth_state, &auth_config, &email).await?;
            let result = finalize_login(&auth_state, &auth_config, &session, &user).await?;
            Ok(Json(VerifyResponse::logged_in(result)))
        }
        Err(msg) => {
            warn!("OTP verification failed: {}", msg);
            Ok(Json(VerifyResponse::failed(msg)))
        }
    }
}

// ── POST /auth/session/otp/resend ───────────────────────────────────

pub async fn resend_otp_handler(
    Extension(auth_state): Extension<AuthState>,
    session: tower_sessions::Session,
) -> AuthResult<Json<VerifyResponse>> {
    let email = session
        .get::<String>(LOGIN_EMAIL_KEY)
        .await?
        .ok_or_else(|| AuthError::BadRequest("No login session in progress".to_string()))?;

    // Resending means re-sending something already issued. Without this guard the
    // new-user path — which deliberately withholds the OTP until the registration
    // challenge is solved — is skippable by calling resend instead.
    if session.get::<String>(CUSTOM_OTP_CODE_KEY).await?.is_none() {
        return Err(AuthError::BadRequest(
            "No verification code in progress".to_string(),
        ));
    }

    if let Some(err) = resend_throttle_error(&session).await? {
        warn!(email = %email, "OTP resend throttled");
        return Ok(Json(err));
    }

    let purpose = session
        .get::<String>(CUSTOM_OTP_PURPOSE_KEY)
        .await?
        .unwrap_or_else(|| "login".to_string());

    generate_and_send_otp(&auth_state, &session, &email, &purpose).await?;

    Ok(Json(VerifyResponse {
        success: true,
        redirect_url: None,
        error: None,
        retry_after_seconds: Some(RESEND_COOLDOWN_SECONDS),
        offer_passkey: None,
    }))
}

// ── POST /auth/session/passkey-fallback-otp ──────────────────────────

/// When the client-side passkey ceremony fails (cancelled, wrong device, no
/// credential on this machine) the client asks us to switch to email OTP.
pub async fn passkey_fallback_to_otp(
    Extension(auth_state): Extension<AuthState>,
    session: tower_sessions::Session,
) -> AuthResult<Json<StartSessionResponse>> {
    let email = session
        .get::<String>(LOGIN_EMAIL_KEY)
        .await?
        .ok_or_else(|| AuthError::BadRequest("No login session in progress".to_string()))?;

    // A new-user session never had a passkey to fall back *from*, and its OTP is
    // gated behind the registration captcha (`/captcha/verify` is the only
    // sanctioned OTP send for new users). Refuse here so this endpoint cannot be
    // used to mint an account-creating OTP without solving the captcha.
    if session
        .get::<bool>(DEFERRED_NEW_USER_KEY)
        .await?
        .unwrap_or(false)
    {
        return Err(AuthError::BadRequest(
            "Please complete verification to receive a code.".to_string(),
        ));
    }

    // This endpoint calls `generate_and_send_otp` directly, so it needs the same
    // throttle as `/otp/resend`.
    if let Some(err) = resend_throttle_error(&session).await? {
        return Err(AuthError::BadRequest(err.error.unwrap_or_else(|| {
            "Please wait before requesting a code.".to_string()
        })));
    }

    info!("Passkey fallback to OTP for {}", email);

    session.remove::<String>(PASSKEY_CHALLENGE_KEY).await?;
    session.remove::<String>(PASSKEY_USER_ID_KEY).await?;

    generate_and_send_otp(&auth_state, &session, &email, "login").await?;

    Ok(Json(StartSessionResponse::otp_sent(false, true)))
}

// ── POST /auth/session/captcha/verify ────────────────────────────────

pub async fn verify_captcha_handler(
    Extension(auth_state): Extension<AuthState>,
    session: tower_sessions::Session,
    Json(req): Json<VerifyCaptchaRequest>,
) -> AuthResult<Json<CaptchaVerifyResponse>> {
    let is_deferred = session
        .get::<bool>(DEFERRED_NEW_USER_KEY)
        .await?
        .unwrap_or(false);
    if !is_deferred {
        return Err(AuthError::BadRequest(
            "No pending registration session".to_string(),
        ));
    }

    // The proof is the widget token, verified server-to-server. Fail-closed —
    // a missing token, a rejection, and an unreachable captcha server all
    // block registration. Only reached when start_session asked for a captcha,
    // so an unconfigured captcha here means the page is out of step.
    let Some(cfg) = captcha_cfg() else {
        return Err(AuthError::BadRequest(
            "No captcha is configured for this deployment".to_string(),
        ));
    };

    let rejected = |msg: &str| {
        Ok(Json(CaptchaVerifyResponse {
            success: false,
            otp_sent: false,
            error: Some(msg.to_string()),
        }))
    };
    let Some(token) = req.captcha_token.as_deref().filter(|t| !t.is_empty()) else {
        return rejected("Verification token missing. Please try again.");
    };
    match verify_captcha_token(&cfg, token).await {
        Ok(true) => {}
        Ok(false) => return rejected("Verification failed. Please try again."),
        Err(_) => return rejected("Verification unavailable. Please try again in a moment."),
    }

    let email = session
        .get::<String>(LOGIN_EMAIL_KEY)
        .await?
        .ok_or_else(|| AuthError::ServerStateError("Missing login email".to_string()))?;

    generate_and_send_otp(&auth_state, &session, &email, "login").await?;

    info!("Captcha verified, OTP sent to new user: {}", email);

    Ok(Json(CaptchaVerifyResponse {
        success: true,
        otp_sent: true,
        error: None,
    }))
}

// ── Finalize login ──────────────────────────────────────────────────

struct FinalizeResult {
    redirect_url: String,
    /// Account has no passkeys — the client may show the enrollment prompt.
    offer_passkey: bool,
}

async fn finalize_login(
    auth_state: &AuthState,
    auth_config: &AuthConfig,
    session: &tower_sessions::Session,
    user: &AuthUser,
) -> AuthResult<FinalizeResult> {
    info!("Login successful for user {}", user.id);

    let username = user
        .display_name
        .as_ref()
        .filter(|n| !n.is_empty())
        .cloned()
        .unwrap_or_else(|| user.email.split('@').next().unwrap_or("user").to_string());

    // New session id at the privilege boundary: a pre-login session id that an
    // attacker planted must not become an authenticated one.
    session.cycle_id().await?;

    let data = LoggedInData {
        id: user.id.clone(),
        sub: user.sub.clone(),
        email: user.email.clone(),
        username,
        avatar_url: None,
        id_token: "local_login".to_string(),
    };
    crate::session::login(session, &data).await?;

    if let Err(e) = auth_state.user_store.record_login(&data.id).await {
        warn!(user_id = %data.id, "Failed to record last login: {e:?}");
    }

    // Clean up temporary login state, throttle counters included: the login
    // succeeded, so the next attempt from this session starts fresh.
    session.remove::<String>(LOGIN_EMAIL_KEY).await?;
    reset_pending_login_state(session).await?;
    session.remove::<i64>(CUSTOM_OTP_LAST_SENT_AT_KEY).await?;
    session.remove::<u32>(CUSTOM_OTP_RESEND_COUNT_KEY).await?;

    let redirect_url =
        determine_post_login_redirect(auth_state, auth_config, session, user).await?;
    let offer_passkey = PASSKEY_LOGIN_ENABLED
        && auth_state
            .passkey_store
            .list_passkeys(&user.id)
            .await
            .map(|list| list.is_empty())
            .unwrap_or(false);

    Ok(FinalizeResult {
        redirect_url,
        offer_passkey,
    })
}

#[cfg(test)]
mod tests {
    use super::resolve_or_create_account;
    use crate::config::AuthConfig;
    use crate::error::{AuthError, AuthResult};
    use crate::state::AuthState;
    use crate::traits::{
        AuthEmailSender, AuthPasskeyStore, AuthUserStore, NewPasskey, StoredPasskey,
    };
    use crate::types::{AuthTosAcceptance, AuthUser, NewAuthUser};
    use std::sync::{Arc, Mutex};

    /// A store holding at most one user, that records the rows it is asked to
    /// create.
    #[derive(Default)]
    struct OneUserStore {
        user: Option<AuthUser>,
        created: Mutex<Vec<NewAuthUser>>,
    }

    #[async_trait::async_trait]
    impl AuthUserStore for OneUserStore {
        async fn get_user_by_sub(&self, sub: &str) -> AuthResult<Option<AuthUser>> {
            Ok(self.user.clone().filter(|u| u.sub == sub))
        }
        async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<AuthUser>> {
            Ok(self.user.clone().filter(|u| u.email == email))
        }
        async fn get_user_by_id(&self, id: &str) -> AuthResult<Option<AuthUser>> {
            Ok(self.user.clone().filter(|u| u.id == id))
        }
        async fn create_user(&self, user: NewAuthUser) -> AuthResult<AuthUser> {
            self.created.lock().unwrap().push(user.clone());
            Ok(AuthUser {
                id: "new".to_string(),
                sub: user.sub,
                email: user.email,
                display_name: None,
                tos_acceptance: None,
            })
        }
        async fn update_user_sub(&self, _: &str, _: &str) -> AuthResult<()> {
            panic!("the self-owned flow must never rewrite a sub");
        }
        async fn create_personal_organization(&self, _: &str, _: &str) -> AuthResult<()> {
            Ok(())
        }
        async fn update_tos_acceptance(&self, _: &str, _: AuthTosAcceptance) -> AuthResult<()> {
            Ok(())
        }
        async fn determine_post_login_redirect(&self, _: &str, d: &str) -> AuthResult<String> {
            Ok(d.to_string())
        }
        async fn has_any_users(&self) -> AuthResult<bool> {
            Ok(self.user.is_some())
        }
    }

    struct NoMail;

    #[async_trait::async_trait]
    impl AuthEmailSender for NoMail {
        async fn send_verification_code(&self, _: &str, _: &str, _: u32) -> AuthResult<()> {
            Ok(())
        }
    }

    struct NoPasskeys;

    #[async_trait::async_trait]
    impl AuthPasskeyStore for NoPasskeys {
        async fn list_passkeys(&self, _: &str) -> AuthResult<Vec<StoredPasskey>> {
            Ok(Vec::new())
        }
        async fn find_passkey_by_credential_id(
            &self,
            _: &str,
        ) -> AuthResult<Option<StoredPasskey>> {
            Ok(None)
        }
        async fn insert_passkey(&self, _: &str, _: NewPasskey) -> AuthResult<()> {
            Ok(())
        }
        async fn touch_passkey(&self, _: &str, _: i64, _: bool) -> AuthResult<()> {
            Ok(())
        }
        async fn delete_passkey(&self, _: &str, _: &str) -> AuthResult<bool> {
            Ok(false)
        }
    }

    fn state(store: Arc<OneUserStore>) -> AuthState {
        AuthState::local(store, Arc::new(NoMail), Arc::new(NoPasskeys))
    }

    fn existing() -> AuthUser {
        AuthUser {
            id: "existing-id".to_string(),
            sub: "existing-sub".to_string(),
            email: "me@example.com".to_string(),
            display_name: None,
            tos_acceptance: None,
        }
    }

    #[tokio::test]
    async fn an_existing_account_keeps_its_sub() {
        let store = Arc::new(OneUserStore {
            user: Some(existing()),
            ..Default::default()
        });

        let user = resolve_or_create_account(
            &state(store.clone()),
            &AuthConfig::default(),
            "me@example.com",
        )
        .await
        .unwrap();

        assert_eq!(user.id, "existing-id");
        assert_eq!(user.sub, "existing-sub");
        assert!(store.created.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_first_sign_in_creates_the_account_with_a_minted_sub() {
        // No users yet and no allowlist: the bootstrap rule admits the first one.
        let store = Arc::new(OneUserStore::default());

        let user = resolve_or_create_account(
            &state(store.clone()),
            &AuthConfig::default(),
            "first@example.com",
        )
        .await
        .unwrap();

        assert_eq!(user.email, "first@example.com");
        assert!(
            !user.sub.is_empty(),
            "sub must be issued, not left for the store"
        );
        let created = store.created.lock().unwrap();
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].sub, user.sub);
    }

    #[tokio::test]
    async fn registration_is_refused_outside_the_allowlist() {
        let store = Arc::new(OneUserStore {
            user: Some(existing()),
            ..Default::default()
        });
        let config = AuthConfig {
            allowed_registration_emails: vec!["ops@example.com".to_string()],
            ..Default::default()
        };

        let result =
            resolve_or_create_account(&state(store.clone()), &config, "stranger@example.com").await;

        assert!(matches!(result, Err(AuthError::Unauthorized(_))));
        assert!(store.created.lock().unwrap().is_empty());
    }
}
