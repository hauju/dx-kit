//! Auth route builder.

#[cfg(feature = "local-login")]
use axum::extract::DefaultBodyLimit;
use axum::{
    Extension, Router,
    routing::{get, post},
};

use crate::config::AuthConfig;
use crate::csrf::csrf_origin_check;
use crate::handlers;
use crate::rate_limit::{self, AuthRateLimiter, rate_limit_middleware};
use crate::session;
use crate::state::AuthState;

/// Builds a Router with all authentication routes.
///
/// Routes included:
/// - `POST /auth/logout` — Logout handler
/// - `POST /auth/session/start` — Start a session (auto-detects passkey or OTP)
/// - `POST /auth/session/passkey/verify` — Verify passkey assertion
/// - `POST /auth/session/otp/verify` — Verify email OTP
/// - `POST /auth/session/otp/resend` — Resend OTP code
/// - `POST /auth/session/captcha/verify` — Verify the captcha for new user registration
/// - `POST /auth/session/accept-tos` — Accept Terms of Service
/// - `GET /auth/sso/start` — Browser-redirect login (only with `sso_enabled`)
/// - `GET /auth/callback` — OIDC redirect target (only with `sso_enabled`)
/// - `POST /auth/sso/complete` — Finish a browser-redirect login (only with `sso_enabled`)
///
/// Security middleware included:
/// - **Rate limiting:** 20 requests/minute per IP (via `governor`)
/// - **CSRF:** Origin/Referer validation on POST requests against `base_url`
///
/// `AuthConfig` and `AuthState` are added as `Extension`s for handler access.
pub fn auth_router(auth_config: AuthConfig, auth_state: AuthState) -> Router {
    let rate_limiter = AuthRateLimiter::new(rate_limit::AUTH_REQUESTS_PER_MINUTE);

    let router = Router::new()
        // Logout (POST to prevent forced-logout via cross-site image/link tags)
        .route("/auth/logout", post(session::logout))
        // Session API v2 (custom login: auto-detect passkey/OTP)
        .route("/auth/session/start", post(handlers::start_session))
        .route(
            "/auth/session/passkey/verify",
            post(handlers::verify_passkey_handler),
        )
        .route(
            "/auth/session/otp/verify",
            post(handlers::verify_otp_handler),
        )
        .route(
            "/auth/session/otp/resend",
            post(handlers::resend_otp_handler),
        )
        .route(
            "/auth/session/password/verify",
            post(handlers::verify_password_handler),
        )
        .route(
            "/auth/session/captcha/verify",
            post(handlers::verify_captcha_handler),
        )
        .route(
            "/auth/session/accept-tos",
            post(handlers::accept_tos_handler),
        );

    // Passkey enrollment, for apps that are their own Relying Party. Both are
    // session-authenticated: you enroll a passkey onto an account you are
    // already logged into, so there is no unauthenticated entry point here.
    #[cfg(feature = "passkey-rp")]
    let router = router
        .route(
            "/auth/passkey/enroll/options",
            post(handlers::passkey_enroll_options),
        )
        .route(
            "/auth/passkey/enroll/verify",
            post(handlers::passkey_enroll_verify),
        );

    // Development-only login bypass (see handlers::dev_login). Compiled out of
    // release builds; also requires DEV_LOGIN=true at runtime.
    #[cfg(debug_assertions)]
    let router = router.route("/auth/dev-login", post(handlers::dev_login_handler));

    // Browser-redirect login against FerrisKey's hosted page (see
    // handlers::sso). Off by default: nothing is mounted unless the app opts in.
    let router = if auth_config.sso_enabled {
        router
            .route("/auth/sso/start", get(handlers::sso_start))
            .route("/auth/callback", get(handlers::sso_callback))
            .route("/auth/sso/complete", post(handlers::sso_complete))
    } else {
        router
    };

    router
        // NOTE: axum applies the LAST `.layer()` outermost, so these run in the
        // reverse of the order written — CSRF first, then rate limiting.
        //
        // That ordering is deliberate: a cross-origin POST is rejected before it
        // can consume any of the per-IP quota or reach the database-backed
        // counter, so junk traffic can't exhaust a real user's budget.
        //
        // 2nd: rate limiting — 20 requests/minute per IP across auth endpoints.
        .layer(axum::middleware::from_fn(rate_limit_middleware))
        .layer(Extension(rate_limiter))
        // 1st: CSRF — validate Origin/Referer on POST requests.
        .layer(axum::middleware::from_fn(csrf_origin_check))
        // AuthConfig and AuthState available to all handlers via Extension
        .layer(Extension(auth_config))
        .layer(Extension(auth_state))
}

/// Every auth request body is small — an email, a six-digit code, or one
/// WebAuthn credential. This bounds the attacker-controlled CBOR that the
/// enrollment path decodes, which is the only place we parse a nested binary
/// format from an unauthenticated caller.
#[cfg(feature = "local-login")]
const AUTH_BODY_LIMIT: usize = 64 * 1024;

/// Builds a Router for the self-owned login flow — no identity provider, no
/// passwords. Mount this *instead of* [`auth_router`]: both own the same
/// `/auth/session/*` paths.
///
/// Routes included:
/// - `POST /auth/session/start` — email in; passkey options or an emailed OTP out
/// - `POST /auth/session/otp/verify` — verify the code; creates the account if new
/// - `POST /auth/session/otp/resend` — throttled resend
/// - `POST /auth/session/passkey/verify` — verify a WebAuthn assertion
/// - `POST /auth/session/passkey/conditional/options` — autofill (discoverable) options
/// - `POST /auth/session/passkey-fallback-otp` — cancelled ceremony falls back to OTP
/// - `POST /auth/session/captcha/verify` — registration gate, only when configured
/// - `POST /auth/passkey/enroll/options|verify` — enroll a passkey while logged in
/// - `POST /auth/logout`
/// - `POST /auth/dev-login` — debug builds only
///
/// Security middleware is the same as [`auth_router`] plus a 64 KiB body limit.
#[cfg(feature = "local-login")]
pub fn local_auth_router(auth_config: AuthConfig, auth_state: AuthState) -> Router {
    use handlers::local_login as local;

    let rate_limiter = AuthRateLimiter::new(rate_limit::AUTH_REQUESTS_PER_MINUTE);

    let router = Router::new()
        .route("/auth/logout", post(session::logout))
        .route("/auth/session/start", post(local::start_session))
        .route("/auth/session/otp/verify", post(local::verify_otp_handler))
        .route("/auth/session/otp/resend", post(local::resend_otp_handler))
        .route(
            "/auth/session/passkey/verify",
            post(local::verify_passkey_handler),
        )
        .route(
            "/auth/session/passkey/conditional/options",
            post(local::passkey_conditional_options),
        )
        .route(
            "/auth/session/passkey-fallback-otp",
            post(local::passkey_fallback_to_otp),
        )
        .route(
            "/auth/session/captcha/verify",
            post(local::verify_captcha_handler),
        )
        .route(
            "/auth/passkey/enroll/options",
            post(handlers::passkey_enroll_options),
        )
        .route(
            "/auth/passkey/enroll/verify",
            post(handlers::passkey_enroll_verify),
        );

    #[cfg(debug_assertions)]
    let router = router.route("/auth/dev-login", post(handlers::dev_login_handler));

    router
        // Same ordering as `auth_router`: CSRF runs first, then rate limiting.
        .layer(axum::middleware::from_fn(rate_limit_middleware))
        .layer(Extension(rate_limiter))
        .layer(axum::middleware::from_fn(csrf_origin_check))
        .layer(DefaultBodyLimit::max(AUTH_BODY_LIMIT))
        .layer(Extension(auth_config))
        .layer(Extension(auth_state))
}
