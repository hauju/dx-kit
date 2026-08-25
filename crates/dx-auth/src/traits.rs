//! Trait abstractions for auth operations.
//!
//! These traits decouple the auth crate from the host application (database, email, business logic).
//! The host app provides concrete implementations that wrap `AppState`.

use crate::error::AuthResult;
use crate::types::{AuthTosAcceptance, AuthUser, NewAuthUser};

/// User lookup, creation, migration, TOS, and post-login redirect.
///
/// Implemented by the host app to bridge its `User` type ↔ `AuthUser`.
#[async_trait::async_trait]
pub trait AuthUserStore: Send + Sync + 'static {
    /// Find a user by their OIDC subject identifier.
    async fn get_user_by_sub(&self, sub: &str) -> AuthResult<Option<AuthUser>>;

    /// Find a user by email address.
    async fn get_user_by_email(&self, email: &str) -> AuthResult<Option<AuthUser>>;

    /// Create a new user and return the created user (with generated ID).
    async fn create_user(&self, user: NewAuthUser) -> AuthResult<AuthUser>;

    /// Update a user's OIDC subject (IdP migration).
    async fn update_user_sub(&self, user_id: &str, new_sub: &str) -> AuthResult<()>;

    /// Create a personal organization for a newly registered user.
    async fn create_personal_organization(&self, user_id: &str, email: &str) -> AuthResult<()>;

    /// Update a user's TOS acceptance status.
    async fn update_tos_acceptance(&self, user_id: &str, tos: AuthTosAcceptance) -> AuthResult<()>;

    /// Determine the post-login redirect URL based on org/subscription state.
    ///
    /// `default_url` is the fallback if no special redirect is needed.
    async fn determine_post_login_redirect(
        &self,
        user_id: &str,
        default_url: &str,
    ) -> AuthResult<String>;

    /// Record that the given user has just successfully logged in.
    /// Default implementation is a no-op so older `AuthUserStore` impls
    /// keep compiling; the dashboard may override it to bump
    /// `users.last_login_at`. Errors here are logged but should never
    /// fail the login flow.
    async fn record_login(&self, _user_id: &str) -> AuthResult<()> {
        Ok(())
    }

    /// Whether any user account exists yet.
    ///
    /// Consulted only to permit first-run registration when no allowlist is
    /// configured. The default returns `true` (i.e. "users exist, so keep
    /// registration closed") so an impl that does not override it fails safe.
    async fn has_any_users(&self) -> AuthResult<bool> {
        Ok(true)
    }
}

/// A stored WebAuthn credential, as the login and enrollment handlers need it.
#[cfg(feature = "passkey-rp")]
#[derive(Debug, Clone)]
pub struct StoredPasskey {
    /// Store row id, used for delete.
    pub id: String,
    /// Owning user id (`AuthUser.id`).
    pub user_id: String,
    /// base64url credential id chosen by the authenticator.
    pub credential_id: String,
    /// COSE public key bytes captured at registration.
    pub public_key_cose: Vec<u8>,
    pub sign_count: i64,
    pub transports: Vec<String>,
    pub name: String,
}

/// A freshly verified registration to persist.
#[cfg(feature = "passkey-rp")]
#[derive(Debug, Clone)]
pub struct NewPasskey {
    pub credential_id: String,
    pub public_key_cose: Vec<u8>,
    pub sign_count: i64,
    pub transports: Vec<String>,
    pub name: String,
    pub backed_up: bool,
}

/// Passkey (WebAuthn credential) persistence, for apps that act as their own
/// Relying Party.
///
/// The alternative is proxying passkeys through the identity provider, but
/// FerrisKey derives its RP ID from the IdP deployment's own origin — which
/// pins credentials to that origin — and its enrollment endpoints require a
/// FerrisKey user JWT that email-OTP accounts can never obtain. Apps that need
/// passkeys for OTP-created accounts therefore run the ceremonies themselves,
/// and the credentials live in their own database behind this trait.
#[cfg(feature = "passkey-rp")]
#[async_trait::async_trait]
pub trait AuthPasskeyStore: Send + Sync + 'static {
    /// All passkeys registered by a user.
    async fn list_passkeys(&self, user_id: &str) -> AuthResult<Vec<StoredPasskey>>;

    /// Look up a passkey by its authenticator credential id. The login path's
    /// entry point: an assertion identifies itself by credential id alone.
    async fn find_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> AuthResult<Option<StoredPasskey>>;

    /// Persist a newly registered passkey for a user.
    async fn insert_passkey(&self, user_id: &str, passkey: NewPasskey) -> AuthResult<()>;

    /// Record a successful authentication: signature counter, backup state and
    /// last-used time. The counter must be written back for the no-regress
    /// check on the next assertion to mean anything.
    async fn touch_passkey(
        &self,
        credential_id: &str,
        sign_count: i64,
        backed_up: bool,
    ) -> AuthResult<()>;

    /// Delete one of the user's passkeys. Scoped by `user_id` so a caller
    /// cannot delete someone else's credential by guessing a row id. Returns
    /// whether a row was actually deleted.
    async fn delete_passkey(&self, user_id: &str, passkey_id: &str) -> AuthResult<bool>;
}

/// Sends verification emails (OTP codes).
///
/// Implemented by the dashboard to wrap SMTP/email service.
#[async_trait::async_trait]
pub trait AuthEmailSender: Send + Sync + 'static {
    /// Send a verification code email to the given address.
    async fn send_verification_code(
        &self,
        to_email: &str,
        code: &str,
        expires_in_minutes: u32,
    ) -> AuthResult<()>;
}

/// Backs auth rate limiting with shared storage so the quota holds across
/// replicas.
///
/// Optional: when no store is supplied on [`crate::AuthState`], the router falls
/// back to an in-process limiter, which is correct for a single instance but
/// allows N× the quota across N replicas.
///
/// Kept as a trait (rather than taking a database handle) so this crate stays
/// independent of the host application's storage layer.
#[async_trait::async_trait]
pub trait AuthRateLimitStore: Send + Sync + 'static {
    /// Record a request against `key` and report whether it is within quota.
    ///
    /// The quota itself belongs to the implementation. Implementations should
    /// decide deliberately whether to fail open or closed when their backing
    /// store is unavailable, and document the choice.
    async fn check(&self, key: &str) -> bool;
}
