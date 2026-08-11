//! Auth state: trait-object holders for user store and email sender.

use crate::jwt::JwksCache;
use crate::traits::{AuthEmailSender, AuthRateLimitStore, AuthUserStore};
use std::sync::Arc;

/// Replaces `Extension<AppState>` in auth handlers.
///
/// Holds trait objects so the auth crate stays independent of
/// dashboard-specific types (`Database`, `AppState`, etc.).
///
/// `jwks_cache` is shared (Arc) so the JWKS cache persists across
/// logins instead of being rebuilt — and refetched — on every flow.
#[derive(Clone)]
pub struct AuthState {
    pub user_store: Arc<dyn AuthUserStore>,
    pub email_sender: Arc<dyn AuthEmailSender>,
    pub jwks_cache: Arc<JwksCache>,
    /// Optional shared store for rate limiting. `None` falls back to the
    /// in-process limiter, which under-counts across replicas — see
    /// [`AuthRateLimitStore`].
    pub rate_limit_store: Option<Arc<dyn AuthRateLimitStore>>,
    /// WebAuthn credentials, when this app is its own Relying Party.
    ///
    /// Required rather than optional: the field only exists under the
    /// `passkey-rp` feature, so enabling the feature without wiring a store
    /// would mount enrollment routes with nothing behind them. Apps that leave
    /// the feature off never see this field, which is why adding it is not a
    /// breaking change for them.
    #[cfg(feature = "passkey-rp")]
    pub passkey_store: Arc<dyn crate::traits::AuthPasskeyStore>,
}
