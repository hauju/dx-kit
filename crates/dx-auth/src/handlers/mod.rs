//! HTTP handlers for authentication flows.

mod session_auth;
mod shared;

#[cfg(debug_assertions)]
mod dev_login;

#[cfg(feature = "passkey-rp")]
mod passkey_enroll;

#[cfg(feature = "passkey-rp")]
pub use passkey_enroll::{passkey_enroll_options, passkey_enroll_verify};

pub use session_auth::*;
pub use shared::{
    AuthUserInfo, determine_post_login_redirect, is_valid_email, lookup_or_create_user,
};

#[cfg(debug_assertions)]
pub use dev_login::dev_login_handler;
