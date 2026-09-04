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
use crate::handlers::otp::{
    CUSTOM_OTP_ATTEMPTS_KEY, CUSTOM_OTP_CODE_KEY, CUSTOM_OTP_EMAIL_KEY, CUSTOM_OTP_EXPIRES_AT_KEY,
    CUSTOM_OTP_LAST_SENT_AT_KEY, CUSTOM_OTP_PURPOSE_KEY, CUSTOM_OTP_RESEND_COUNT_KEY,
    MAX_RESEND_COUNT, RESEND_COOLDOWN_SECONDS, captcha_cfg, clear_otp_state, generate_and_send_otp,
    lock_session, persist_now, verify_captcha_token, verify_otp_guarded,
};
use crate::handlers::shared;
use crate::handlers::shared::registration_allowed;
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

// Deferred user creation: set when a new user starts login but hasn't verified OTP yet.
// The FerrisKey user is only created after OTP is verified, preventing bot-created accounts.
const DEFERRED_NEW_USER_KEY: &str = "ferriskey.deferred_new_user";

const PASSWORD_ATTEMPTS_KEY: &str = "password.attempts";
const MAX_PASSWORD_ATTEMPTS: u32 = 5;

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
