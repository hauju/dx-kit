//! Browser-redirect login ("SSO mode") against FerrisKey's hosted login page.
//!
//! `GET /auth/sso/start` mints the OIDC request (state, nonce, PKCE) into the
//! session and sends the browser to FerrisKey. FerrisKey comes back to
//! `GET /auth/callback?code&state`, which serves a small page that redeems the
//! code **from the browser** and posts the id_token to
//! `POST /auth/sso/complete`; that handler validates it and opens the session.
//!
//! The browser does the exchange because FerrisKey sets its SSO cookie
//! (`FERRISKEY_IDENTITY`) only on the token endpoint's response: a server-side
//! exchange would leave the cookie on our reqwest client and the next app in
//! the realm would prompt again. The client is therefore a public one (no
//! secret), and the id_token is accepted only with our audience and the nonce
//! minted for this session.

use axum::extract::Query;
use axum::http::header;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use super::session_auth::{
    VerifyResponse, finalize_login, load_flow, reset_pending_login_state, resolve_id_token,
    store_flow,
};
use super::shared;
use crate::config::AuthConfig;
use crate::error::{AuthError, AuthResult};
use crate::ferriskey::{self, FerrisKeyFlow};
use crate::state::AuthState;

const START_PATH: &str = "/auth/sso/start";
const COMPLETE_PATH: &str = "/auth/sso/complete";

#[derive(Deserialize)]
pub struct SsoStartQuery {
    #[serde(default)]
    pub next: Option<String>,
}

/// `GET /auth/sso/start?next=` — send the browser to FerrisKey.
pub async fn sso_start(
    Extension(auth_config): Extension<AuthConfig>,
    session: tower_sessions::Session,
    Query(query): Query<SsoStartQuery>,
) -> AuthResult<Response> {
    reset_pending_login_state(&session).await;
    if let Some(next) = query.next.filter(|n| shared::is_safe_redirect_url(n)) {
        session
            .insert(shared::LOGIN_REDIRECT_URL_SESSION_KEY, &next)
            .await?;
    }
    let flow = ferriskey::new_flow();
    store_flow(&session, &flow).await?;
    let url = ferriskey::authorize_url(
        &auth_config.ferriskey_url,
        &auth_config.ferriskey_realm,
        &auth_config.ferriskey_client_id,
        &auth_config.base_url,
        &flow,
    )?;
    Ok(Redirect::to(&url).into_response())
}

#[derive(Deserialize)]
pub struct SsoCallbackQuery {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
}

/// `GET /auth/callback?code&state` — FerrisKey's redirect target. Checks the
/// state against the flow and serves the page that redeems the code.
pub async fn sso_callback(
    Extension(auth_config): Extension<AuthConfig>,
    session: tower_sessions::Session,
    Query(query): Query<SsoCallbackQuery>,
) -> AuthResult<Response> {
    let flow = load_flow(&session).await?;
    let code = validate_callback(&flow, &query)?;
    let code_verifier = flow.code_verifier.ok_or_else(|| {
        AuthError::ServerStateError("Login flow missing PKCE verifier — please retry".to_string())
    })?;
    let page = render_callback_page(&CallbackConfig {
        token_url: ferriskey::token_url(&auth_config.ferriskey_url, &auth_config.ferriskey_realm),
        client_id: auth_config.ferriskey_client_id.clone(),
        redirect_uri: ferriskey::redirect_uri(&auth_config.base_url),
        code,
        code_verifier,
        complete_url: COMPLETE_PATH.to_string(),
        restart_url: START_PATH.to_string(),
    });
    // The page carries a one-time code and the PKCE verifier.
    Ok(([(header::CACHE_CONTROL, "no-store")], Html(page)).into_response())
}

fn validate_callback(flow: &FerrisKeyFlow, query: &SsoCallbackQuery) -> AuthResult<String> {
    let state = query
        .state
        .as_deref()
        .ok_or_else(|| AuthError::BadRequest("Missing state".to_string()))?;
    if state.as_bytes().ct_eq(flow.state.as_bytes()).unwrap_u8() != 1 {
        return Err(AuthError::Unauthorized(
            "Login flow state mismatch — please retry".to_string(),
        ));
    }
    query
        .code
        .clone()
        .filter(|c| !c.is_empty())
        .ok_or_else(|| AuthError::BadRequest("Missing code".to_string()))
}

#[derive(Serialize)]
struct CallbackConfig {
    token_url: String,
    client_id: String,
    redirect_uri: String,
    code: String,
    code_verifier: String,
    complete_url: String,
    restart_url: String,
}

/// The values reach the script as JSON in a `<script type="application/json">`
/// block, with `<` escaped so no value can close the block early.
fn render_callback_page(cfg: &CallbackConfig) -> String {
    let config = serde_json::to_string(cfg)
        .expect("CallbackConfig is plain strings")
        .replace('<', "\\u003c");
    include_str!("sso_callback.html").replacen("__SSO_CONFIG__", &config, 1)
}

#[derive(Deserialize)]
pub struct SsoCompleteRequest {
    pub id_token: String,
}

/// `POST /auth/sso/complete` — accept the id_token the browser redeemed and
/// open the session.
pub async fn sso_complete(
    Extension(auth_state): Extension<AuthState>,
    Extension(auth_config): Extension<AuthConfig>,
    session: tower_sessions::Session,
    Json(req): Json<SsoCompleteRequest>,
) -> AuthResult<Json<VerifyResponse>> {
    let flow = load_flow(&session).await?;
    let info = resolve_id_token(&auth_state.jwks_cache, &flow, &req.id_token).await?;
    let result = finalize_login(&auth_state, &auth_config, &session, &info).await?;
    let redirect_url = if result.needs_tos_acceptance {
        tos_redirect_url(&auth_config.login_page_url)
    } else {
        result
            .redirect_url
            .unwrap_or_else(|| auth_config.default_post_login_url.clone())
    };
    Ok(Json(VerifyResponse {
        success: true,
        redirect_url: Some(redirect_url),
        needs_tos_acceptance: None,
        error: None,
        retry_after_seconds: None,
    }))
}

/// Where to send a user who still has to accept the terms: the login page
/// opens on its TOS step when `redirect_url` contains `accept_tos=true`, and
/// `POST /auth/session/accept-tos` then releases the pending redirect.
fn tos_redirect_url(login_page_url: &str) -> String {
    let target: String = url::form_urlencoded::byte_serialize(b"/?accept_tos=true").collect();
    format!("{login_page_url}?redirect_url={target}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow() -> FerrisKeyFlow {
        FerrisKeyFlow {
            state: "abc".to_string(),
            ..Default::default()
        }
    }

    fn query(code: Option<&str>, state: Option<&str>) -> SsoCallbackQuery {
        SsoCallbackQuery {
            code: code.map(str::to_string),
            state: state.map(str::to_string),
        }
    }

    #[test]
    fn callback_without_state_is_a_bad_request() {
        assert!(matches!(
            validate_callback(&flow(), &query(Some("c"), None)),
            Err(AuthError::BadRequest(_))
        ));
    }

    #[test]
    fn callback_with_foreign_state_is_unauthorized() {
        assert!(matches!(
            validate_callback(&flow(), &query(Some("c"), Some("xyz"))),
            Err(AuthError::Unauthorized(_))
        ));
    }

    #[test]
    fn callback_without_code_is_a_bad_request() {
        assert!(matches!(
            validate_callback(&flow(), &query(None, Some("abc"))),
            Err(AuthError::BadRequest(_))
        ));
        assert!(matches!(
            validate_callback(&flow(), &query(Some(""), Some("abc"))),
            Err(AuthError::BadRequest(_))
        ));
    }

    #[test]
    fn callback_with_matching_state_yields_the_code() {
        assert_eq!(
            validate_callback(&flow(), &query(Some("c0de"), Some("abc"))).unwrap(),
            "c0de"
        );
    }

    #[test]
    fn callback_page_cannot_be_broken_out_of_by_the_code() {
        let page = render_callback_page(&CallbackConfig {
            token_url: "https://idp.example/realms/r/protocol/openid-connect/token".to_string(),
            client_id: "app".to_string(),
            redirect_uri: "https://app.example/auth/callback".to_string(),
            code: "x</script><script>alert(1)</script>".to_string(),
            code_verifier: "v".to_string(),
            complete_url: "/auth/sso/complete".to_string(),
            restart_url: "/auth/sso/start".to_string(),
        });
        assert!(page.contains(r#"id="sso-config">{"#));
        assert!(page.contains("\\u003c/script>\\u003cscript>alert(1)"));
        assert!(!page.contains("</script><script>"));
        assert!(!page.contains("__SSO_CONFIG__"));
    }

    #[test]
    fn tos_redirect_opens_the_login_page_on_its_tos_step() {
        assert_eq!(
            tos_redirect_url("/login"),
            "/login?redirect_url=%2F%3Faccept_tos%3Dtrue"
        );
    }
}
