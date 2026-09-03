//! Custom login flow handlers backed by FerrisKey.
//!
//! Three concrete paths share this state machine:
//!
//! * **Passkey** — `start_session` bootstraps a FerrisKey flow, fetches
//!   `passkey-request-options`, and hands them to the browser. The browser
//!   POSTs the assertion back to `verify_passkey`, which proxies it to
//!   `passkey-authenticate`. On `Success` we exchange the OIDC `code` for
//!   tokens and finalize.
//! * **Password** — `verify_password` calls `/login-actions/authenticate`
//!   with the captured FerrisKey session and the same code-exchange wraps
//!   things up.
//! * **Email OTP** — fully on our side. We mint and email the code, store it
//!   in tower-sessions, and on success either *create* the FerrisKey user
//!   (deferred new-user path, gated by captcha) or *update* email_verified.
//!   No FerrisKey flow is involved on this path — we look the user up by
//!   email and use that record's `id` as the OIDC subject.

use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tracing::{info, warn};

use crate::config::AuthConfig;
use crate::error::{AuthError, AuthResult};
use crate::ferriskey;
use crate::ferriskey::{
    AuthenticateResponse, AuthenticationStatus, FerrisKeyFlow, FerrisKeyUser, OidcTokenResponse,
};
use crate::handlers::shared;
use crate::handlers::shared::{AuthUserInfo, determine_post_login_redirect, lookup_or_create_user};
use crate::session::LoggedInData;
use crate::state::AuthState;
use crate::types::AuthTosAcceptance;

// ── Session keys for temporary login state ──────────────────────────

const FLOW_KEY: &str = "ferriskey.flow";
const FERRISKEY_USER_ID_KEY: &str = "ferriskey.user_id";
const LOGIN_EMAIL_KEY: &str = "login.email";

// TOS acceptance
pub const TOS_VERSION: &str = "1.0";
pub(crate) const TOS_PENDING_REDIRECT_KEY: &str = "tos.pending_redirect";

// Custom OTP session keys (our own email OTP, not FerrisKey)
const CUSTOM_OTP_CODE_KEY: &str = "custom_otp.code";
// The address the code was actually mailed to. An OTP proves ownership of this
// address and of nothing else, so verification resolves the user from *this*
// key — never from `login.email`, which any later /session/start overwrites.
const CUSTOM_OTP_EMAIL_KEY: &str = "custom_otp.email";
const CUSTOM_OTP_EXPIRES_AT_KEY: &str = "custom_otp.expires_at";
const CUSTOM_OTP_PURPOSE_KEY: &str = "custom_otp.purpose";
const CUSTOM_OTP_ATTEMPTS_KEY: &str = "custom_otp.attempts";
const MAX_OTP_ATTEMPTS: u32 = 5;

// OTP resend throttle
const CUSTOM_OTP_LAST_SENT_AT_KEY: &str = "custom_otp.last_sent_at";
const CUSTOM_OTP_RESEND_COUNT_KEY: &str = "custom_otp.resend_count";
const RESEND_COOLDOWN_SECONDS: i64 = 30;
const MAX_RESEND_COUNT: u32 = 5;

// Deferred user creation: set when a new user starts login but hasn't verified OTP yet.
// The FerrisKey user is only created after OTP is verified, preventing bot-created accounts.
const DEFERRED_NEW_USER_KEY: &str = "ferriskey.deferred_new_user";

const PASSWORD_ATTEMPTS_KEY: &str = "password.attempts";
const MAX_PASSWORD_ATTEMPTS: u32 = 5;

// ── Per-session attempt-counter serialisation ───────────────────────
//
// tower-sessions hands every request its own copy of the session record and
// writes it back when the response completes. Two concurrent requests carrying
// the same cookie therefore both read `attempts = n` and both write `n + 1`,
// so a burst of parallel guesses meets the cap once instead of per request.
// Holding a per-session lock across the read, the compare and an explicit
// `save` closes that window in-process. Replicas do not share the lock, so
// the same cookie serviced by N replicas at once can overshoot by at most N
// passes — bounded by the deployment, not by the attacker's request count.
//
// Striped rather than per-id so the table never grows: unrelated sessions
// that share a stripe only wait on each other for the few store round-trips
// the guarded section performs.

const SESSION_LOCK_STRIPES: usize = 64;
static SESSION_LOCKS: [tokio::sync::Mutex<()>; SESSION_LOCK_STRIPES] =
    [const { tokio::sync::Mutex::const_new(()) }; SESSION_LOCK_STRIPES];

/// Lock the stripe for this session.
///
/// Must be taken before the handler's first read of the session: tower-sessions
/// loads the record lazily and then keeps that copy for the rest of the
/// request, so a read before the lock is a read of stale state.
async fn lock_session(session: &tower_sessions::Session) -> tokio::sync::MutexGuard<'static, ()> {
    let stripe = session
        .id()
        .map(|id| (id.0.unsigned_abs() % SESSION_LOCK_STRIPES as u128) as usize)
        .unwrap_or(0);
    SESSION_LOCKS[stripe].lock().await
}

/// Write the session back to the store now, rather than when the response
/// completes, so the next request for this cookie loads what this one wrote.
/// A request with no session has nothing to race over, and saving would only
/// mint an empty record per request.
async fn persist_now(session: &tower_sessions::Session) -> AuthResult<()> {
    if session.id().is_some() {
        session.save().await?;
    }
    Ok(())
}

// ── Bollwark captcha (optional, env-configured) ─────────────────────
//
// When all three vars are set, new-user registration is gated by the bollwark
// widget instead of the built-in image CAPTCHA: the login page pre-solves the
// widget invisibly inside the email form and forwards its token, which we
// verify server-to-server. Absent or partial config falls back to the image
// CAPTCHA, so local dev needs no captcha deployment.

struct CaptchaCfg {
    server_url: String,
    site_key: String,
    secret_key: String,
}

fn captcha_cfg() -> Option<CaptchaCfg> {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    Some(CaptchaCfg {
        server_url: env("CAPTCHA_URL")?,
        site_key: env("CAPTCHA_SITE_KEY")?,
        secret_key: env("CAPTCHA_SECRET_KEY")?,
    })
}

/// Pooled client for the verify call; the timeout caps how long an unreachable
/// captcha server can stall a registration submit.
fn captcha_client() -> &'static reqwest::Client {
    use std::sync::OnceLock;
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("captcha verify client")
    })
}

/// Forward the widget token to bollwark's `POST /v1/verify`.
///
/// Returns `Ok(true)` on a verified pass, `Ok(false)` on an explicit
/// rejection, and `Err` when the captcha server is unreachable. Registration
/// is fail-closed: the caller blocks on both `false` and `Err`.
async fn verify_captcha_token(cfg: &CaptchaCfg, token: &str) -> AuthResult<bool> {
    let resp = captcha_client()
        .post(format!(
            "{}/v1/verify",
            cfg.server_url.trim_end_matches('/')
        ))
        .bearer_auth(&cfg.secret_key)
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .map_err(|e| {
            warn!(error = ?e, "captcha verify request failed");
            AuthError::ServerStateError("captcha verify request failed".to_string())
        })?;

    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    let success = body
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !status.is_success() || !success {
        warn!(status = %status, "captcha verify rejected");
        return Ok(false);
    }
    Ok(true)
}

// ── Request / Response types ────────────────────────────────────────

#[derive(Deserialize)]
pub struct StartSessionRequest {
    pub email: String,
    #[serde(default)]
    pub redirect_url: Option<String>,
}

#[derive(Serialize)]
pub struct StartSessionResponse {
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_options: Option<serde_json::Value>,
    pub otp_sent: bool,
    pub is_new_user: bool,
    pub has_passkeys: bool,
    pub has_password: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs_tos_acceptance: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub captcha_required: Option<bool>,
    /// Set (with `captcha_site_key`) when registration is gated by the
    /// bollwark widget. The login page uses them to mount the widget; both
    /// values are public by design.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub captcha_server_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub captcha_site_key: Option<String>,
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
    pub needs_tos_acceptance: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<i64>,
}

#[derive(Deserialize)]
pub struct VerifyPasswordRequest {
    pub password: String,
}

// ── FerrisKey config helpers ─────────────────────────────────────────

struct FkConfig<'a> {
    base: &'a str,
    realm: &'a str,
    client_id: &'a str,
    client_secret: &'a str,
    base_url: &'a str,
}

impl<'a> FkConfig<'a> {
    fn from(auth_config: &'a AuthConfig) -> AuthResult<Self> {
        let client_secret = auth_config
            .ferriskey_client_secret
            .as_deref()
            .ok_or_else(|| {
                AuthError::ServerStateError("FERRISKEY_CLIENT_SECRET not configured".to_string())
            })?;
        Ok(FkConfig {
            base: &auth_config.ferriskey_url,
            realm: &auth_config.ferriskey_realm,
            client_id: &auth_config.ferriskey_client_id,
            client_secret,
            base_url: &auth_config.base_url,
        })
    }
}

/// Get a service-account access token (client_credentials grant) for
/// user-management calls.
async fn service_token(fk: &FkConfig<'_>) -> AuthResult<String> {
    let resp =
        ferriskey::service_account_token(fk.base, fk.realm, fk.client_id, fk.client_secret).await?;
    Ok(resp.access_token)
}

// ── OTP / CAPTCHA helpers ───────────────────────────────────────────

async fn generate_and_send_otp(
    auth_state: &AuthState,
    session: &tower_sessions::Session,
    email: &str,
    purpose: &str,
) -> AuthResult<()> {
    let code = crypto::generate_numeric_otp(6)
        .map_err(|e| AuthError::ServerStateError(format!("Failed to generate OTP: {}", e)))?;

    let expires_at = chrono::Utc::now().timestamp() + 600;
    session.insert(CUSTOM_OTP_CODE_KEY, &code).await?;
    session.insert(CUSTOM_OTP_EMAIL_KEY, email).await?;
    session
        .insert(CUSTOM_OTP_EXPIRES_AT_KEY, expires_at)
        .await?;
    session.insert(CUSTOM_OTP_PURPOSE_KEY, purpose).await?;
    session.insert(CUSTOM_OTP_ATTEMPTS_KEY, 0u32).await?;

    auth_state
        .email_sender
        .send_verification_code(email, &code, 10)
        .await
        .map_err(|e| {
            AuthError::ServerStateError(format!("Failed to send verification email: {}", e))
        })?;

    session
        .insert(CUSTOM_OTP_LAST_SENT_AT_KEY, chrono::Utc::now().timestamp())
        .await?;

    let count = session
        .get::<u32>(CUSTOM_OTP_RESEND_COUNT_KEY)
        .await
        .unwrap_or(None)
        .unwrap_or(0);
    session
        .insert(CUSTOM_OTP_RESEND_COUNT_KEY, count + 1)
        .await?;

    info!(to = %email, purpose = %purpose, "Sent OTP verification code");
    Ok(())
}

/// Wipe the in-flight OTP record. Every field goes together: a code that
/// outlives the address it was bound to is exactly the state that let one
/// address's OTP be verified against another address's account.
async fn clear_otp_state(session: &tower_sessions::Session) {
    let _ = session.remove::<String>(CUSTOM_OTP_CODE_KEY).await;
    let _ = session.remove::<String>(CUSTOM_OTP_EMAIL_KEY).await;
    let _ = session.remove::<i64>(CUSTOM_OTP_EXPIRES_AT_KEY).await;
    let _ = session.remove::<String>(CUSTOM_OTP_PURPOSE_KEY).await;
    let _ = session.remove::<u32>(CUSTOM_OTP_ATTEMPTS_KEY).await;
}

/// Drop credential state left over from an earlier attempt in this session.
/// Without it, an OTP and a `deferred_new_user` flag issued for one address
/// survive into a `/session/start` for a different address.
///
/// Deliberately keeps the resend throttle and the password-attempt counter:
/// those are abuse controls, and restarting the flow must not reset them.
pub(super) async fn reset_pending_login_state(session: &tower_sessions::Session) {
    clear_otp_state(session).await;
    let _ = session.remove::<bool>(DEFERRED_NEW_USER_KEY).await;
}

/// Verify a submitted code against the in-flight OTP and return the address the
/// code was mailed to. Callers must resolve the user from the returned email —
/// it is the only address this OTP proves anything about.
async fn verify_otp_from_session(
    session: &tower_sessions::Session,
    submitted_code: &str,
) -> std::result::Result<String, String> {
    let stored_code = session
        .get::<String>(CUSTOM_OTP_CODE_KEY)
        .await
        .map_err(|_| "Session error".to_string())?
        .ok_or_else(|| "No verification code in progress".to_string())?;

    let bound_email = session
        .get::<String>(CUSTOM_OTP_EMAIL_KEY)
        .await
        .map_err(|_| "Session error".to_string())?
        .ok_or_else(|| "No verification code in progress".to_string())?;

    let expires_at = session
        .get::<i64>(CUSTOM_OTP_EXPIRES_AT_KEY)
        .await
        .map_err(|_| "Session error".to_string())?
        .ok_or_else(|| "No verification code in progress".to_string())?;

    if chrono::Utc::now().timestamp() > expires_at {
        clear_otp_state(session).await;
        return Err("Verification code has expired. Please request a new one.".to_string());
    }

    let attempts = session
        .get::<u32>(CUSTOM_OTP_ATTEMPTS_KEY)
        .await
        .map_err(|_| "Session error".to_string())?
        .unwrap_or(0);

    if attempts >= MAX_OTP_ATTEMPTS {
        clear_otp_state(session).await;
        return Err(
            "Too many failed attempts. Please request a new verification code.".to_string(),
        );
    }

    if submitted_code
        .as_bytes()
        .ct_eq(stored_code.as_bytes())
        .unwrap_u8()
        != 1
    {
        let _ = session.insert(CUSTOM_OTP_ATTEMPTS_KEY, attempts + 1).await;
        return Err("Invalid verification code. Please try again.".to_string());
    }

    clear_otp_state(session).await;

    Ok(bound_email)
}

/// [`verify_otp_from_session`] under the session lock, with the attempt
/// counter persisted before the lock is released. See [`SESSION_LOCKS`].
async fn verify_otp_guarded(
    session: &tower_sessions::Session,
    submitted_code: &str,
) -> AuthResult<std::result::Result<String, String>> {
    let _guard = lock_session(session).await;
    let outcome = verify_otp_from_session(session, submitted_code).await;
    persist_now(session).await?;
    Ok(outcome)
}

// ── Flow plumbing ────────────────────────────────────────────────────

pub(super) async fn store_flow(
    session: &tower_sessions::Session,
    flow: &FerrisKeyFlow,
) -> AuthResult<()> {
    session.insert(FLOW_KEY, flow).await?;
    Ok(())
}

pub(super) async fn load_flow(session: &tower_sessions::Session) -> AuthResult<FerrisKeyFlow> {
    session
        .get::<FerrisKeyFlow>(FLOW_KEY)
        .await?
        .ok_or_else(|| AuthError::BadRequest("No login flow in progress".to_string()))
}

/// Pull `code` and `state` out of the OIDC redirect URL returned in
/// `AuthenticateResponse.url` on success. Validates `state` against the flow.
fn parse_oidc_redirect(url: &str, expected_state: &str) -> AuthResult<String> {
    let parsed = url::Url::parse(url).map_err(|e| {
        AuthError::ServerStateError(format!("FerrisKey returned invalid redirect URL: {e}"))
    })?;
    let mut code: Option<String> = None;
    let mut state: Option<String> = None;
    for (k, v) in parsed.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            _ => {}
        }
    }
    let state = state
        .ok_or_else(|| AuthError::ServerStateError("Missing state in redirect URL".to_string()))?;
    if state != expected_state {
        return Err(AuthError::Unauthorized(
            "Login flow state mismatch — please retry".to_string(),
        ));
    }
    code.ok_or_else(|| AuthError::ServerStateError("Missing code in redirect URL".to_string()))
}

/// Exchange the success `url` for tokens and decode the id_token.
async fn exchange_and_resolve(
    fk: &FkConfig<'_>,
    jwks: &crate::jwt::JwksCache,
    flow: &FerrisKeyFlow,
    redirect_url: &str,
) -> AuthResult<AuthUserInfo> {
    let code = parse_oidc_redirect(redirect_url, &flow.state)?;
    let code_verifier = flow.code_verifier.as_deref().ok_or_else(|| {
        AuthError::ServerStateError("Login flow missing PKCE verifier — please retry".to_string())
    })?;
    let tokens: OidcTokenResponse = ferriskey::exchange_code(
        fk.base,
        fk.realm,
        fk.client_id,
        fk.client_secret,
        &code,
        code_verifier,
        fk.base_url,
    )
    .await?;

    let id_token = tokens
        .id_token
        .ok_or_else(|| AuthError::ServerStateError("FerrisKey returned no id_token".to_string()))?;
    resolve_id_token(jwks, flow, &id_token).await
}

/// Validate an id_token against JWKS and bind it to `flow` through the nonce.
///
/// The nonce is what ties the token to this login attempt, so when the flow
/// carries one the claim must be present and equal — a token minted for some
/// other flow, or one that lost its nonce, is refused. In SSO mode the
/// id_token arrives from the browser, so this is the only binding there is.
pub(super) async fn resolve_id_token(
    jwks: &crate::jwt::JwksCache,
    flow: &FerrisKeyFlow,
    id_token: &str,
) -> AuthResult<AuthUserInfo> {
    let claims = jwks.validate_token(id_token).await.map_err(|e| {
        AuthError::ServerStateError(format!("Failed to validate FerrisKey id_token: {e}"))
    })?;

    if let Some(expected_nonce) = flow.nonce.as_deref() {
        let matches = claims.nonce.as_deref().is_some_and(|returned| {
            returned
                .as_bytes()
                .ct_eq(expected_nonce.as_bytes())
                .unwrap_u8()
                == 1
        });
        if !matches {
            warn!("FerrisKey id_token nonce missing or mismatched — possible token replay");
            return Err(AuthError::Unauthorized(
                "Login flow nonce mismatch — please retry".to_string(),
            ));
        }
    }

    // Accounts are keyed by address as well as by sub, so an id_token that
    // carries no email is refused rather than resolved to an empty one.
    let email = claims.email.filter(|e| !e.is_empty()).ok_or_else(|| {
        AuthError::ServerStateError("FerrisKey id_token has no email claim".to_string())
    })?;

    Ok(AuthUserInfo {
        sub: claims.sub,
        nickname: None,
        name: None,
        email,
        email_verified: claims.email_verified.unwrap_or(false),
        picture: None,
        preferred_username: None,
    })
}

// ── Registration gate ───────────────────────────────────────────────

/// Whether a not-yet-registered `email` may create an account.
///
/// Registration is the one place an unauthenticated caller can cross into the
/// trust boundary, so it is closed by default. An operator opens it with an
/// allowlist of exact addresses and/or domains; when neither is configured,
/// registration is permitted only while no user exists yet (first-run
/// bootstrap) and refused afterwards, so a fresh deployment is usable without
/// configuration but does not stay open to the internet.
async fn registration_allowed(
    auth_state: &AuthState,
    auth_config: &AuthConfig,
    email: &str,
) -> AuthResult<bool> {
    let emails = &auth_config.allowed_registration_emails;
    let domains = &auth_config.allowed_registration_domains;

    // Only the no-allowlist bootstrap path needs to know whether users exist,
    // so avoid the query when an allowlist is configured.
    let has_users = if emails.is_empty() && domains.is_empty() {
        auth_state.user_store.has_any_users().await?
    } else {
        false
    };

    Ok(registration_permitted(emails, domains, email, has_users))
}

/// Pure allowlist decision, split out so it can be unit-tested without a store.
///
/// `email` is assumed already trimmed and lowercased (as `start_session` does).
/// `has_users` is consulted only when both allowlists are empty.
fn registration_permitted(
    emails: &[String],
    domains: &[String],
    email: &str,
    has_users: bool,
) -> bool {
    if emails.is_empty() && domains.is_empty() {
        // No allowlist configured: allow the very first account, then close.
        return !has_users;
    }

    if emails.iter().any(|allowed| allowed == email) {
        return true;
    }

    matches!(
        email.rsplit('@').next(),
        Some(domain) if domains.iter().any(|allowed| allowed == domain)
    )
}

// ── POST /auth/session/start ────────────────────────────────────────

pub async fn start_session(
    Extension(auth_state): Extension<AuthState>,
    Extension(auth_config): Extension<AuthConfig>,
    session: tower_sessions::Session,
    Json(req): Json<StartSessionRequest>,
) -> AuthResult<Json<StartSessionResponse>> {
    let fk = FkConfig::from(&auth_config)?;
    let email = req.email.trim().to_lowercase();

    info!("start_session: email={}", email);

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
    reset_pending_login_state(&session).await;
    session.insert(LOGIN_EMAIL_KEY, &email).await?;

    let svc_token = service_token(&fk).await?;
    let user_lookup = ferriskey::find_user_by_email(fk.base, fk.realm, &svc_token, &email).await?;

    if let Some(user) = user_lookup {
        if !user.enabled {
            warn!("Login attempted for disabled FerrisKey user {}", user.id);
            return Err(AuthError::Unauthorized(
                "This account is disabled".to_string(),
            ));
        }

        let credentials = ferriskey::list_user_credentials(fk.base, fk.realm, &svc_token, &user.id)
            .await
            .map_err(|e| {
                warn!("list_user_credentials failed for {}: {:?}", user.id, e);
                AuthError::ServerStateError("Unable to inspect user credentials".to_string())
            })?;
        let has_passkeys = ferriskey::has_passkey(&credentials);
        let has_password = ferriskey::has_password(&credentials);

        session.insert(FERRISKEY_USER_ID_KEY, &user.id).await?;

        let flow = ferriskey::start_auth_flow(fk.base, fk.realm, fk.client_id, fk.base_url).await?;
        store_flow(&session, &flow).await?;

        if has_passkeys {
            match ferriskey::passkey_request_options(fk.base, fk.realm, &flow, &email).await {
                Ok(options) => {
                    info!("Passkey flow ready for user {}", user.id);
                    return Ok(Json(StartSessionResponse {
                        session_id: String::new(),
                        public_key_options: Some(options),
                        otp_sent: false,
                        is_new_user: false,
                        has_passkeys,
                        has_password: false,
                        needs_tos_acceptance: None,
                        redirect_url: None,
                        captcha_required: None,
                        captcha_server_url: None,
                        captcha_site_key: None,
                    }));
                }
                Err(e) => {
                    warn!("passkey_request_options failed: {:?}", e);
                    return Err(AuthError::ServerStateError(
                        "Unable to start passkey authentication".to_string(),
                    ));
                }
            }
        }

        if has_password {
            // No OTP yet — frontend will collect the password and POST it to
            // /auth/session/password/verify, which uses the same FerrisKey flow.
            info!("Password flow ready for user {}", user.id);
            return Ok(Json(StartSessionResponse {
                session_id: String::new(),
                public_key_options: None,
                otp_sent: false,
                is_new_user: false,
                has_passkeys: false,
                has_password: true,
                needs_tos_acceptance: None,
                redirect_url: None,
                captcha_required: None,
                captcha_server_url: None,
                captcha_site_key: None,
            }));
        }

        if credentials.is_empty() {
            // App-created email-OTP accounts have no FerrisKey credentials yet.
            // Allow OTP only in this narrow case; accounts with any FerrisKey
            // credential must use FerrisKey-backed authentication.
            session.remove::<FerrisKeyFlow>(FLOW_KEY).await?;
            return send_otp_session(&auth_state, &session, &email, false).await;
        }

        warn!(
            "Existing FerrisKey user {} has credentials, but none are supported by this login screen",
            user.id
        );
        Err(AuthError::Unauthorized(
            "This account has no supported login method".to_string(),
        ))
    } else {
        // ── New user: check the registration allowlist, then gate with a
        //    CAPTCHA before sending an OTP ──
        if !registration_allowed(&auth_state, &auth_config, &email).await? {
            info!(
                "Registration refused for '{}' (not permitted to register)",
                email
            );
            return Err(AuthError::Unauthorized(
                "Registration is not open for this address".to_string(),
            ));
        }
        session.insert(DEFERRED_NEW_USER_KEY, true).await?;

        // Bollwark configured: the widget in the email form has been
        // pre-solving already; tell the page to forward its token. No
        // server-side state to stash — the token is the whole proof.
        if let Some(cfg) = captcha_cfg() {
            info!(
                "User '{}' not found in FerrisKey, requiring captcha before OTP",
                email
            );
            return Ok(Json(StartSessionResponse {
                session_id: String::new(),
                public_key_options: None,
                otp_sent: false,
                is_new_user: true,
                has_passkeys: false,
                has_password: false,
                needs_tos_acceptance: None,
                redirect_url: None,
                captcha_required: Some(true),
                captcha_server_url: Some(cfg.server_url),
                captcha_site_key: Some(cfg.site_key),
            }));
        }

        // No captcha deployment: the registration allowlist is the whole gate.
        // It is closed by default and re-checked at account creation, so an
        // internal deployment stays usable without a captcha server, while a
        // public one is expected to set CAPTCHA_URL.
        warn!(
            "No captcha configured; registration for '{}' is gated by the allowlist alone",
            email
        );
        send_otp_session(&auth_state, &session, &email, true).await
    }
}

/// Send an app-managed email OTP for a new user or an existing account with no
/// FerrisKey credentials. Do not call this as fallback for accounts that have
/// any FerrisKey credential; that would bypass the IdP's configured factors.
async fn send_otp_session(
    auth_state: &AuthState,
    session: &tower_sessions::Session,
    email: &str,
    is_new_user: bool,
) -> AuthResult<Json<StartSessionResponse>> {
    generate_and_send_otp(auth_state, session, email, "login").await?;

    info!("OTP session created (no FerrisKey flow): email={}", email);

    Ok(Json(StartSessionResponse {
        session_id: String::new(),
        public_key_options: None,
        otp_sent: true,
        is_new_user,
        has_passkeys: false,
        has_password: false,
        needs_tos_acceptance: None,
        redirect_url: None,
        captcha_required: None,
        captcha_server_url: None,
        captcha_site_key: None,
    }))
}

// ── POST /auth/session/passkey/verify ───────────────────────────────

pub async fn verify_passkey_handler(
    Extension(auth_state): Extension<AuthState>,
    Extension(auth_config): Extension<AuthConfig>,
    session: tower_sessions::Session,
    Json(req): Json<VerifyPasskeyRequest>,
) -> AuthResult<Json<VerifyResponse>> {
    let fk = FkConfig::from(&auth_config)?;
    let flow = load_flow(&session).await?;

    match ferriskey::passkey_authenticate(fk.base, fk.realm, &flow, &req.credential_assertion_data)
        .await
    {
        Ok(resp) => handle_oidc_outcome(&auth_state, &auth_config, &session, &flow, resp).await,
        Err(e) => {
            warn!("Passkey verification failed: {:?}", e);
            Ok(Json(VerifyResponse {
                success: false,
                redirect_url: None,
                needs_tos_acceptance: None,
                error: Some("Passkey verification failed. Please try again.".to_string()),
                retry_after_seconds: None,
            }))
        }
    }
}

// ── POST /auth/session/password/verify ──────────────────────────────

pub async fn verify_password_handler(
    Extension(auth_state): Extension<AuthState>,
    Extension(auth_config): Extension<AuthConfig>,
    session: tower_sessions::Session,
    Json(req): Json<VerifyPasswordRequest>,
) -> AuthResult<Json<VerifyResponse>> {
    let fk = FkConfig::from(&auth_config)?;

    let password = req.password.trim().to_string();
    if password.is_empty() {
        return Err(AuthError::BadRequest("Password is required".to_string()));
    }

    // The attempt is counted before it is made, under the session lock, so
    // parallel submissions each consume a slot instead of all reading the same
    // count. A non-failed outcome below hands the slot back.
    {
        let _guard = lock_session(&session).await;
        let attempts = session
            .get::<u32>(PASSWORD_ATTEMPTS_KEY)
            .await?
            .unwrap_or(0);
        if attempts >= MAX_PASSWORD_ATTEMPTS {
            return Ok(Json(VerifyResponse {
                success: false,
                redirect_url: None,
                needs_tos_acceptance: None,
                error: Some(
                    "Too many failed password attempts. Please start a new login.".to_string(),
                ),
                retry_after_seconds: None,
            }));
        }
        session.insert(PASSWORD_ATTEMPTS_KEY, attempts + 1).await?;
        persist_now(&session).await?;
    }

    let flow = load_flow(&session).await?;

    let email = session
        .get::<String>(LOGIN_EMAIL_KEY)
        .await?
        .ok_or_else(|| AuthError::BadRequest("No login session in progress".to_string()))?;

    match ferriskey::authenticate_password(
        fk.base,
        fk.realm,
        fk.client_id,
        &flow,
        &email,
        &password,
    )
    .await
    {
        Ok(resp) => {
            if resp.status != AuthenticationStatus::Failed {
                session.remove::<u32>(PASSWORD_ATTEMPTS_KEY).await?;
            }
            handle_oidc_outcome(&auth_state, &auth_config, &session, &flow, resp).await
        }
        Err(e) => {
            warn!("Password verification failed: {:?}", e);
            Ok(Json(VerifyResponse {
                success: false,
                redirect_url: None,
                needs_tos_acceptance: None,
                error: Some("Invalid password. Please try again.".to_string()),
                retry_after_seconds: None,
            }))
        }
    }
}

/// Branch on `AuthenticateResponse.status` after a password or passkey step.
async fn handle_oidc_outcome(
    auth_state: &AuthState,
    auth_config: &AuthConfig,
    session: &tower_sessions::Session,
    flow: &FerrisKeyFlow,
    resp: AuthenticateResponse,
) -> AuthResult<Json<VerifyResponse>> {
    match resp.status {
        AuthenticationStatus::Success => {
            let url = resp.url.ok_or_else(|| {
                AuthError::ServerStateError(
                    "FerrisKey returned Success without a redirect URL".to_string(),
                )
            })?;
            let fk = FkConfig::from(auth_config)?;
            let info = exchange_and_resolve(&fk, &auth_state.jwks_cache, flow, &url).await?;
            let result = finalize_login(auth_state, auth_config, session, &info).await?;
            Ok(Json(VerifyResponse {
                success: true,
                redirect_url: result.redirect_url,
                needs_tos_acceptance: if result.needs_tos_acceptance {
                    Some(true)
                } else {
                    None
                },
                error: None,
                retry_after_seconds: None,
            }))
        }
        AuthenticationStatus::RequiresOtpChallenge | AuthenticationStatus::RequiresActions => {
            // TOTP / required-action step-ups aren't wired into the dashboard
            // UI. Surface a clear message instead of silently failing.
            let label = match resp.status {
                AuthenticationStatus::RequiresOtpChallenge => "TOTP",
                _ => "additional setup",
            };
            warn!(
                "FerrisKey returned {:?} — UI does not yet support {} step-up",
                resp.status, label
            );
            Ok(Json(VerifyResponse {
                success: false,
                redirect_url: None,
                needs_tos_acceptance: None,
                error: Some(format!(
                    "Your account requires {label}, which isn't supported by this login screen yet."
                )),
                retry_after_seconds: None,
            }))
        }
        AuthenticationStatus::Failed => Ok(Json(VerifyResponse {
            success: false,
            redirect_url: None,
            needs_tos_acceptance: None,
            error: Some(
                resp.message
                    .unwrap_or_else(|| "Authentication failed".to_string()),
            ),
            retry_after_seconds: None,
        })),
    }
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
        Ok(email) => {
            let fk = FkConfig::from(&auth_config)?;
            let svc_token = service_token(&fk).await?;
            let is_deferred = session
                .get::<bool>(DEFERRED_NEW_USER_KEY)
                .await?
                .unwrap_or(false);

            let user: FerrisKeyUser = if is_deferred {
                // Re-check the allowlist at the point of creation, independent of
                // the start-of-flow check: this is the only step that actually
                // provisions an account, so it must not rely on an upstream gate.
                if !registration_allowed(&auth_state, &auth_config, &email).await? {
                    warn!(
                        "Blocked account creation for '{}' (not permitted to register)",
                        email
                    );
                    return Err(AuthError::Unauthorized(
                        "Registration is not open for this address".to_string(),
                    ));
                }
                // `create_user` answers an HTTP 409 by returning the existing
                // account, so even a deferred registration can resolve to a real
                // user. Hold it to the same rule as the branch below: email-OTP
                // is a login method only for accounts with no FerrisKey credential.
                let user = ferriskey::create_user(fk.base, fk.realm, &svc_token, &email).await?;
                let credentials =
                    ferriskey::list_user_credentials(fk.base, fk.realm, &svc_token, &user.id)
                        .await
                        .map_err(|e| {
                            warn!("list_user_credentials failed for {}: {:?}", user.id, e);
                            AuthError::ServerStateError(
                                "Unable to inspect user credentials".to_string(),
                            )
                        })?;
                if !credentials.is_empty() {
                    return Err(AuthError::Unauthorized(
                        "Email code login is not available for this account".to_string(),
                    ));
                }
                session.remove::<bool>(DEFERRED_NEW_USER_KEY).await?;
                user
            } else {
                let user = ferriskey::find_user_by_email(fk.base, fk.realm, &svc_token, &email)
                    .await?
                    .ok_or_else(|| {
                        AuthError::ServerStateError(format!(
                            "OTP-verified user '{email}' not found in FerrisKey"
                        ))
                    })?;
                let credentials =
                    ferriskey::list_user_credentials(fk.base, fk.realm, &svc_token, &user.id)
                        .await
                        .map_err(|e| {
                            warn!("list_user_credentials failed for {}: {:?}", user.id, e);
                            AuthError::ServerStateError(
                                "Unable to inspect user credentials".to_string(),
                            )
                        })?;
                if !credentials.is_empty() {
                    return Err(AuthError::Unauthorized(
                        "Email code login is not available for this account".to_string(),
                    ));
                }
                if !user.email_verified {
                    ferriskey::set_email_verified(fk.base, fk.realm, &svc_token, &user.id, &email)
                        .await?;
                }
                user
            };

            if !user.enabled {
                warn!(
                    "OTP login attempted for disabled FerrisKey user {}",
                    user.id
                );
                return Err(AuthError::Unauthorized(
                    "This account is disabled".to_string(),
                ));
            }

            let info = AuthUserInfo {
                sub: user.id.clone(),
                nickname: None,
                name: if user.firstname.is_empty() {
                    None
                } else {
                    Some(user.firstname.clone())
                },
                email: email.clone(),
                // Proven by the code just verified.
                email_verified: true,
                picture: None,
                preferred_username: Some(email.clone()),
            };

            let result = finalize_login(&auth_state, &auth_config, &session, &info).await?;
            Ok(Json(VerifyResponse {
                success: true,
                redirect_url: result.redirect_url,
                needs_tos_acceptance: if result.needs_tos_acceptance {
                    Some(true)
                } else {
                    None
                },
                error: None,
                retry_after_seconds: None,
            }))
        }
        Err(msg) => {
            warn!("OTP verification failed: {}", msg);
            Ok(Json(VerifyResponse {
                success: false,
                redirect_url: None,
                needs_tos_acceptance: None,
                error: Some(msg),
                retry_after_seconds: None,
            }))
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

    let resend_count = session
        .get::<u32>(CUSTOM_OTP_RESEND_COUNT_KEY)
        .await?
        .unwrap_or(0);
    if resend_count >= MAX_RESEND_COUNT {
        warn!(email = %email, "OTP resend limit reached ({}/{})", resend_count, MAX_RESEND_COUNT);
        return Ok(Json(VerifyResponse {
            success: false,
            redirect_url: None,
            needs_tos_acceptance: None,
            error: Some("Maximum resend attempts reached. Please start a new login.".to_string()),
            retry_after_seconds: None,
        }));
    }

    if let Some(last_sent_at) = session.get::<i64>(CUSTOM_OTP_LAST_SENT_AT_KEY).await? {
        let elapsed = chrono::Utc::now().timestamp() - last_sent_at;
        if elapsed < RESEND_COOLDOWN_SECONDS {
            let retry_after = RESEND_COOLDOWN_SECONDS - elapsed;
            warn!(email = %email, retry_after, "OTP resend cooldown active");
            return Ok(Json(VerifyResponse {
                success: false,
                redirect_url: None,
                needs_tos_acceptance: None,
                error: Some(format!(
                    "Please wait {} seconds before requesting a new code.",
                    retry_after
                )),
                retry_after_seconds: Some(retry_after),
            }));
        }
    }

    let purpose = session
        .get::<String>(CUSTOM_OTP_PURPOSE_KEY)
        .await?
        .unwrap_or_else(|| "login".to_string());

    generate_and_send_otp(&auth_state, &session, &email, &purpose).await?;

    Ok(Json(VerifyResponse {
        success: true,
        redirect_url: None,
        needs_tos_acceptance: None,
        error: None,
        retry_after_seconds: Some(RESEND_COOLDOWN_SECONDS),
    }))
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

    let Some(token) = req.captcha_token.as_deref().filter(|t| !t.is_empty()) else {
        return Ok(Json(CaptchaVerifyResponse {
            success: false,
            otp_sent: false,
            error: Some("Verification token missing. Please try again.".to_string()),
        }));
    };
    if !verify_captcha_token(&cfg, token).await? {
        return Ok(Json(CaptchaVerifyResponse {
            success: false,
            otp_sent: false,
            error: Some("Verification failed. Please try again.".to_string()),
        }));
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

pub(super) struct FinalizeResult {
    pub(super) redirect_url: Option<String>,
    pub(super) needs_tos_acceptance: bool,
}

pub(super) async fn finalize_login(
    auth_state: &AuthState,
    auth_config: &AuthConfig,
    session: &tower_sessions::Session,
    info: &AuthUserInfo,
) -> AuthResult<FinalizeResult> {
    let user = lookup_or_create_user(auth_state, info).await?;

    info!("FerrisKey login successful for user {}", user.id);

    let username = user
        .display_name
        .as_ref()
        .filter(|n| !n.is_empty())
        .cloned()
        .unwrap_or_else(|| info.email.split('@').next().unwrap_or("user").to_string());

    session.cycle_id().await?;

    let data = LoggedInData {
        id: user.id.to_string(),
        sub: user.sub.clone(),
        email: user.email.clone(),
        username,
        avatar_url: None,
        id_token: "ferriskey_login".to_string(),
    };
    crate::session::login(session, &data).await?;

    if let Err(e) = auth_state.user_store.record_login(&data.id).await {
        tracing::warn!(user_id = %data.id, "Failed to record last_login_at: {e:?}");
    }

    // Clean up temporary session keys
    session.remove::<FerrisKeyFlow>(FLOW_KEY).await?;
    session.remove::<String>(LOGIN_EMAIL_KEY).await?;
    session.remove::<String>(FERRISKEY_USER_ID_KEY).await?;
    session.remove::<String>(CUSTOM_OTP_CODE_KEY).await?;
    session.remove::<String>(CUSTOM_OTP_EMAIL_KEY).await?;
    session.remove::<i64>(CUSTOM_OTP_EXPIRES_AT_KEY).await?;
    session.remove::<String>(CUSTOM_OTP_PURPOSE_KEY).await?;
    session.remove::<u32>(CUSTOM_OTP_ATTEMPTS_KEY).await?;
    session.remove::<i64>(CUSTOM_OTP_LAST_SENT_AT_KEY).await?;
    session.remove::<u32>(CUSTOM_OTP_RESEND_COUNT_KEY).await?;
    session.remove::<bool>(DEFERRED_NEW_USER_KEY).await?;
    session.remove::<u32>(PASSWORD_ATTEMPTS_KEY).await?;

    let needs_tos = match &user.tos_acceptance {
        Some(ta) => ta.latest_version != TOS_VERSION || !ta.accepted,
        None => true,
    };

    if needs_tos {
        let redirect_url =
            determine_post_login_redirect(auth_state, auth_config, session, &user).await?;
        session
            .insert(TOS_PENDING_REDIRECT_KEY, &redirect_url)
            .await?;
        Ok(FinalizeResult {
            redirect_url: None,
            needs_tos_acceptance: true,
        })
    } else {
        let redirect_url =
            determine_post_login_redirect(auth_state, auth_config, session, &user).await?;
        Ok(FinalizeResult {
            redirect_url: Some(redirect_url),
            needs_tos_acceptance: false,
        })
    }
}

// ── POST /auth/session/accept-tos ───────────────────────────────────

pub async fn accept_tos_handler(
    Extension(auth_state): Extension<AuthState>,
    user_session: crate::session::UserSession,
    session: tower_sessions::Session,
) -> AuthResult<Json<VerifyResponse>> {
    let user_data = user_session.data()?;

    auth_state
        .user_store
        .update_tos_acceptance(
            &user_data.id,
            AuthTosAcceptance {
                latest_version: TOS_VERSION.to_string(),
                accepted: true,
            },
        )
        .await
        .map_err(|e| {
            warn!("Failed to update TOS acceptance: {:?}", e);
            AuthError::ServerStateError("Failed to save TOS acceptance".to_string())
        })?;

    let redirect_url = session
        .remove::<String>(TOS_PENDING_REDIRECT_KEY)
        .await?
        .unwrap_or_else(|| "/dashboard".to_string());

    info!(
        "TOS v{} accepted by user {}, redirecting to {}",
        TOS_VERSION, user_data.id, redirect_url
    );

    Ok(Json(VerifyResponse {
        success: true,
        redirect_url: Some(redirect_url),
        needs_tos_acceptance: None,
        error: None,
        retry_after_seconds: None,
    }))
}

#[cfg(test)]
mod tests {
    use super::{
        CUSTOM_OTP_ATTEMPTS_KEY, CUSTOM_OTP_CODE_KEY, CUSTOM_OTP_EMAIL_KEY,
        CUSTOM_OTP_EXPIRES_AT_KEY, MAX_OTP_ATTEMPTS, registration_permitted, verify_otp_guarded,
    };
    use std::sync::Arc;
    use tower_sessions::session::{Id, Record};
    use tower_sessions::{MemoryStore, Session, SessionStore, session_store};

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// A store whose loads take long enough that every request in a burst
    /// reads the record before any of them writes it back — the interleaving
    /// production hits when parallel requests carry one cookie.
    #[derive(Debug, Default)]
    struct SlowStore(MemoryStore);

    #[async_trait::async_trait]
    impl SessionStore for SlowStore {
        async fn save(&self, record: &Record) -> session_store::Result<()> {
            self.0.save(record).await
        }
        async fn load(&self, id: &Id) -> session_store::Result<Option<Record>> {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            self.0.load(id).await
        }
        async fn delete(&self, id: &Id) -> session_store::Result<()> {
            self.0.delete(id).await
        }
    }

    #[tokio::test]
    async fn parallel_otp_guesses_cannot_exceed_the_attempt_cap() {
        let store = Arc::new(SlowStore::default());

        let seed = Session::new(None, store.clone(), None);
        seed.insert(CUSTOM_OTP_CODE_KEY, "123456").await.unwrap();
        seed.insert(CUSTOM_OTP_EMAIL_KEY, "a@example.com")
            .await
            .unwrap();
        seed.insert(
            CUSTOM_OTP_EXPIRES_AT_KEY,
            chrono::Utc::now().timestamp() + 600,
        )
        .await
        .unwrap();
        seed.insert(CUSTOM_OTP_ATTEMPTS_KEY, 0u32).await.unwrap();
        seed.save().await.unwrap();
        let id = seed.id().unwrap();

        // Twenty requests in flight at once, each with its own handle on the
        // same cookie — the shape tower-sessions gives concurrent requests.
        let tasks: Vec<_> = (0..20)
            .map(|_| {
                let session = Session::new(Some(id), store.clone(), None);
                tokio::spawn(async move { verify_otp_guarded(&session, "000000").await.unwrap() })
            })
            .collect();

        let mut evaluated = 0;
        for task in tasks {
            match task.await.unwrap() {
                Err(msg) if msg.starts_with("Invalid verification code") => evaluated += 1,
                Err(_) => {} // cap reached, or the code already cleared by it
                Ok(email) => panic!("wrong code accepted for {email}"),
            }
        }
        assert_eq!(evaluated, MAX_OTP_ATTEMPTS as usize);
    }

    #[test]
    fn no_allowlist_permits_only_the_first_account() {
        // Fresh deployment (no users yet): the first registration is allowed.
        assert!(registration_permitted(&[], &[], "first@example.com", false));
        // Once a user exists, registration closes.
        assert!(!registration_permitted(
            &[],
            &[],
            "second@example.com",
            true
        ));
    }

    #[test]
    fn email_allowlist_is_exact_match() {
        let emails = v(&["ops@example.com"]);
        assert!(registration_permitted(
            &emails,
            &[],
            "ops@example.com",
            true
        ));
        // A different address is refused even though a user already exists is irrelevant here.
        assert!(!registration_permitted(
            &emails,
            &[],
            "intruder@example.com",
            false
        ));
        // No substring or suffix matching.
        assert!(!registration_permitted(
            &emails,
            &[],
            "notops@example.com",
            false
        ));
    }

    #[test]
    fn domain_allowlist_matches_the_part_after_the_at() {
        let domains = v(&["example.com"]);
        assert!(registration_permitted(
            &[],
            &domains,
            "anyone@example.com",
            true
        ));
        assert!(!registration_permitted(
            &[],
            &domains,
            "anyone@evil.com",
            false
        ));
        // A domain that is only a suffix of the address's domain must not match.
        assert!(!registration_permitted(
            &[],
            &domains,
            "anyone@notexample.com",
            false
        ));
    }

    #[test]
    fn a_configured_allowlist_ignores_the_bootstrap_rule() {
        // With an allowlist set, has_users is not consulted: a non-listed address
        // is refused even on a brand-new instance with no users.
        let emails = v(&["ops@example.com"]);
        assert!(!registration_permitted(
            &emails,
            &[],
            "someone@example.com",
            false
        ));
    }

    #[test]
    fn email_and_domain_allowlists_combine() {
        let emails = v(&["contractor@other.com"]);
        let domains = v(&["example.com"]);
        assert!(registration_permitted(
            &emails,
            &domains,
            "staff@example.com",
            true
        ));
        assert!(registration_permitted(
            &emails,
            &domains,
            "contractor@other.com",
            true
        ));
        assert!(!registration_permitted(
            &emails,
            &domains,
            "stranger@other.com",
            true
        ));
    }
}
