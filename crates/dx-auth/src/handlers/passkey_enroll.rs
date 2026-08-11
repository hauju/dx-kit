//! Passkey enrollment for an already-authenticated user (profile page).
//!
//! SeggWat is its own WebAuthn Relying Party, so enrolling needs nothing but
//! the dashboard session — unlike FerrisKey's webauthn endpoints, which
//! require a FerrisKey user JWT that email-OTP accounts can never obtain.
//!
//! * `POST /auth/passkey/enroll/options` — mint a challenge (parked in the
//!   tower-session) and return `PublicKeyCredentialCreationOptions`.
//! * `POST /auth/passkey/enroll/verify` — verify the attestation response and
//!   persist the credential.

use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::config::AuthConfig;
use crate::error::{AuthError, AuthResult};
use crate::session::UserSession;
use crate::state::AuthState;
use crate::traits::NewPasskey;
use crate::webauthn;

const ENROLL_CHALLENGE_KEY: &str = "passkey.enroll_challenge";

/// Hard cap per user — bounds sprawl, not a product limit anyone should hit.
const MAX_PASSKEYS_PER_USER: usize = 10;

#[derive(Serialize)]
pub struct EnrollOptionsResponse {
    pub options: serde_json::Value,
}

#[derive(Deserialize)]
pub struct EnrollVerifyRequest {
    pub credential: serde_json::Value,
    /// Optional user-facing label (defaults to empty; the UI shows a fallback).
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Serialize)]
pub struct EnrollVerifyResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ── POST /auth/passkey/enroll/options ────────────────────────────────

pub async fn passkey_enroll_options(
    Extension(auth_state): Extension<AuthState>,
    Extension(auth_config): Extension<AuthConfig>,
    user_session: UserSession,
    session: tower_sessions::Session,
) -> AuthResult<Json<EnrollOptionsResponse>> {
    let user = user_session.data()?;

    let existing = auth_state.passkey_store.list_passkeys(&user.id).await?;
    if existing.len() >= MAX_PASSKEYS_PER_USER {
        return Err(AuthError::BadRequest(
            "Maximum number of passkeys reached. Delete one first.".to_string(),
        ));
    }

    let rp = webauthn::RelyingParty::from_base_url(&auth_config.base_url)
        .map_err(|e| AuthError::ServerStateError(format!("BASE_URL invalid for WebAuthn: {e}")))?;
    let challenge =
        webauthn::generate_challenge().map_err(|e| AuthError::ServerStateError(e.to_string()))?;

    let exclude: Vec<String> = existing.into_iter().map(|p| p.credential_id).collect();
    let options = webauthn::registration_options(
        &rp,
        &challenge,
        user.id.as_bytes(),
        &user.email,
        &user.username,
        &exclude,
    );

    session.insert(ENROLL_CHALLENGE_KEY, &challenge).await?;

    Ok(Json(EnrollOptionsResponse { options }))
}

// ── POST /auth/passkey/enroll/verify ─────────────────────────────────

pub async fn passkey_enroll_verify(
    Extension(auth_state): Extension<AuthState>,
    Extension(auth_config): Extension<AuthConfig>,
    user_session: UserSession,
    session: tower_sessions::Session,
    Json(req): Json<EnrollVerifyRequest>,
) -> AuthResult<Json<EnrollVerifyResponse>> {
    let user = user_session.data()?;

    // Single-use: burn the challenge up front.
    let challenge = session
        .remove::<String>(ENROLL_CHALLENGE_KEY)
        .await?
        .ok_or_else(|| AuthError::BadRequest("No passkey enrollment in progress".to_string()))?;

    let rp = webauthn::RelyingParty::from_base_url(&auth_config.base_url)
        .map_err(|e| AuthError::ServerStateError(format!("BASE_URL invalid for WebAuthn: {e}")))?;

    let registered = match webauthn::verify_registration(&rp, &challenge, &req.credential) {
        Ok(r) => r,
        Err(e) => {
            warn!("Passkey enrollment verification failed: {:?}", e);
            return Ok(Json(EnrollVerifyResponse {
                success: false,
                error: Some("Passkey could not be verified. Please try again.".to_string()),
            }));
        }
    };

    let name = req
        .name
        .unwrap_or_default()
        .trim()
        .chars()
        .take(64)
        .collect::<String>();

    auth_state
        .passkey_store
        .insert_passkey(
            &user.id,
            NewPasskey {
                credential_id: registered.credential_id,
                public_key_cose: registered.public_key_cose,
                sign_count: registered.sign_count,
                transports: registered.transports,
                name,
                backed_up: registered.backed_up,
            },
        )
        .await?;

    info!("Passkey enrolled for user {}", user.id);
    Ok(Json(EnrollVerifyResponse {
        success: true,
        error: None,
    }))
}
