//! Authentication crate.
//!
//! Drives a custom login UI against FerrisKey's REST API. Owns OIDC code
//! exchange, password / passkey verification, and our own email-OTP fallback.
//!
//! With the `local-login` feature the crate can also run without an identity
//! provider at all: email OTP plus passkeys verified by the app's own WebAuthn
//! Relying Party (`local_auth_router`, `LocalLoginPage`).
//!
//! The application provides trait implementations via `AuthUserStore`
//! and `AuthEmailSender` to bridge auth ↔ business logic.

mod config;
mod error;
pub mod types;

pub use config::AuthConfig;
pub use error::{AuthError, AuthResult};
pub use types::UserDataRefreshTrigger;

#[cfg(feature = "server")]
pub mod traits;

#[cfg(feature = "server")]
pub mod state;

#[cfg(feature = "server")]
pub use state::AuthState;

#[cfg(feature = "server")]
pub use traits::{AuthEmailSender, AuthRateLimitStore, AuthUserStore};

#[cfg(feature = "passkey-rp")]
pub use traits::{AuthPasskeyStore, NewPasskey, StoredPasskey};

#[cfg(feature = "server")]
pub mod jwt;

#[cfg(feature = "server")]
pub use jwt::JwksCache;

#[cfg(feature = "server")]
pub mod ferriskey;

#[cfg(feature = "server")]
pub mod session;

#[cfg(feature = "server")]
pub mod handlers;

#[cfg(feature = "server")]
pub mod csrf;

#[cfg(feature = "server")]
pub mod rate_limit;

/// WebAuthn Relying Party — ceremony options, and registration/assertion
/// verification against the app's own credential store.
///
/// Standalone by construction: this module imports nothing from the rest of the
/// crate, so it can be reasoned about (and tested) as pure protocol code.
#[cfg(feature = "passkey-rp")]
pub mod webauthn;
#[cfg(feature = "server")]
pub use rate_limit::AUTH_REQUESTS_PER_MINUTE;

#[cfg(feature = "server")]
mod router;

#[cfg(feature = "server")]
pub use router::auth_router;

#[cfg(feature = "local-login")]
pub use router::local_auth_router;

#[cfg(feature = "server")]
pub use session::{LoggedInData, UserSession, login};

#[cfg(feature = "web")]
pub mod webauthn_helpers;

#[cfg(any(feature = "web", feature = "server"))]
mod hydration;

#[cfg(any(feature = "web", feature = "server"))]
pub use hydration::use_hydrated;

#[cfg(any(feature = "web", feature = "server"))]
mod login_page;

#[cfg(any(feature = "web", feature = "server"))]
pub use login_page::LoginPage;

/// The login page for the self-owned flow (`local-login`). Compiled for the
/// wasm client (`web`) and, for SSR, the server that mounts the local router.
#[cfg(any(feature = "web", feature = "local-login"))]
mod local_login_page;

#[cfg(any(feature = "web", feature = "local-login"))]
pub use local_login_page::LocalLoginPage;
