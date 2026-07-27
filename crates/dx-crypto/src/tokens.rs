//! Token generation utilities
//!
//! Provides high-level functions for generating the token types used throughout
//! the apps:
//!
//! - **API keys**: prefixed tokens for API authentication
//! - **Invitation tokens**: URL-safe tokens for email invitations
//! - **CSRF tokens**: protection against cross-site request forgery

use crate::{Result, random::generate_url_safe_token};

/// Default token length in bytes (256-bit security)
const DEFAULT_TOKEN_BYTES: usize = 32;

/// Prefix applied by [`generate_api_key`]. Projects that want their own brand of
/// key call [`generate_prefixed_api_key`] instead.
pub const DEFAULT_API_KEY_PREFIX: &str = "oat_";

/// Random characters kept, unhashed, after the prefix for indexed lookup.
///
/// Eight URL-safe base64 characters is ~48 bits — enough to make the lookup
/// selective while the full 256-bit secret stays hashed.
pub const API_KEY_PREFIX_RANDOM_CHARS: usize = 8;

/// Length of the indexed lookup prefix for a [`DEFAULT_API_KEY_PREFIX`] key:
/// `oat_` plus [`API_KEY_PREFIX_RANDOM_CHARS`].
pub const API_KEY_PREFIX_LEN: usize = DEFAULT_API_KEY_PREFIX.len() + API_KEY_PREFIX_RANDOM_CHARS;

/// Derive the indexed lookup prefix from a presented `oat_` API key.
///
/// Returns `None` for anything that isn't a well-formed `oat_` token, so callers
/// can reject malformed credentials before touching the database.
///
/// # Example
/// ```
/// use dx_crypto::{generate_api_key, api_key_prefix};
///
/// let key = generate_api_key().unwrap();
/// let prefix = api_key_prefix(&key).unwrap();
/// assert!(key.starts_with(&prefix));
/// assert_eq!(prefix.len(), 12);
/// ```
pub fn api_key_prefix(token: &str) -> Option<String> {
    prefixed_api_key_prefix(token, DEFAULT_API_KEY_PREFIX)
}

/// Derive the indexed lookup prefix from a key carrying a custom `prefix`.
///
/// The returned prefix is `prefix` plus [`API_KEY_PREFIX_RANDOM_CHARS`] random
/// characters. Returns `None` if `token` doesn't start with `prefix` or is too
/// short to carry the full lookup prefix.
///
/// # Example
/// ```
/// use dx_crypto::{generate_prefixed_api_key, prefixed_api_key_prefix};
///
/// let key = generate_prefixed_api_key("ipk_").unwrap();
/// let prefix = prefixed_api_key_prefix(&key, "ipk_").unwrap();
/// assert_eq!(prefix.len(), 12);
/// assert!(key.starts_with(&prefix));
/// // A key minted under a different prefix is rejected.
/// assert!(prefixed_api_key_prefix(&key, "oat_").is_none());
/// ```
pub fn prefixed_api_key_prefix(token: &str, prefix: &str) -> Option<String> {
    let len = prefix.len() + API_KEY_PREFIX_RANDOM_CHARS;
    if !token.starts_with(prefix) || token.len() < len {
        return None;
    }
    // API keys are prefix + URL-safe base64 (ASCII), so byte-slicing on a char
    // boundary is safe as long as the caller's prefix is ASCII too.
    token.get(..len).map(str::to_string)
}

/// Generate an API key of the form `oat_<43 url-safe chars>`.
///
/// The prefix makes keys easy to spot and rotate in logs, while the random
/// portion provides 256 bits of entropy.
///
/// # Errors
/// Returns an error if random byte generation fails
///
/// # Example
/// ```
/// use dx_crypto::generate_api_key;
///
/// let key = generate_api_key().unwrap();
/// assert!(key.starts_with("oat_"));
/// assert_eq!(key.len(), 47); // "oat_" (4) + base64(32 bytes) (43)
/// ```
pub fn generate_api_key() -> Result<String> {
    generate_prefixed_api_key(DEFAULT_API_KEY_PREFIX)
}

/// Generate an API key carrying a project-specific `prefix`.
///
/// Use an ASCII prefix ending in `_` (e.g. `"ipk_"`, `"sgw_"`) so
/// [`prefixed_api_key_prefix`] can slice it back off safely.
///
/// # Errors
/// Returns an error if random byte generation fails
///
/// # Example
/// ```
/// use dx_crypto::generate_prefixed_api_key;
///
/// let key = generate_prefixed_api_key("ipk_").unwrap();
/// assert!(key.starts_with("ipk_"));
/// assert_eq!(key.len(), 47);
/// ```
pub fn generate_prefixed_api_key(prefix: &str) -> Result<String> {
    let token = generate_url_safe_token(DEFAULT_TOKEN_BYTES)?;
    Ok(format!("{prefix}{token}"))
}

/// Generate a secure invitation token for email-based invitations.
///
/// Returns a URL-safe base64-encoded token suitable for embedding in invitation
/// links.
///
/// # Errors
/// Returns an error if random byte generation fails
///
/// # Example
/// ```
/// use dx_crypto::generate_invitation_token;
///
/// let token = generate_invitation_token().unwrap();
/// let invite_url = format!("https://example.com/invite?token={}", token);
/// ```
pub fn generate_invitation_token() -> Result<String> {
    generate_url_safe_token(DEFAULT_TOKEN_BYTES)
}

/// Generate a CSRF token for OAuth state parameter protection.
///
/// Used to prevent cross-site request forgery in OAuth flows by ensuring the
/// callback came from our original redirect.
///
/// # Errors
/// Returns an error if random byte generation fails
///
/// # Example
/// ```
/// use dx_crypto::generate_csrf_token;
///
/// let state = generate_csrf_token().unwrap();
/// // Store in session, then include in OAuth redirect URL
/// let auth_url = format!("https://auth.example.com/authorize?state={}", state);
/// ```
pub fn generate_csrf_token() -> Result<String> {
    generate_url_safe_token(DEFAULT_TOKEN_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_api_key_format() {
        let key = generate_api_key().unwrap();
        assert!(key.starts_with("oat_"), "API key should have oat_ prefix");
        assert_eq!(
            key.len(),
            47,
            "API key should be 47 characters (4 prefix + 43 base64)"
        );
    }

    #[test]
    fn test_generate_api_key_uniqueness() {
        let key1 = generate_api_key().unwrap();
        let key2 = generate_api_key().unwrap();
        assert_ne!(key1, key2, "API keys should be unique");
    }

    #[test]
    fn test_generate_invitation_token_length() {
        let token = generate_invitation_token().unwrap();
        assert_eq!(token.len(), 43, "Token should be 43 characters");
    }

    #[test]
    fn test_generate_invitation_token_url_safe() {
        let token = generate_invitation_token().unwrap();
        // URL-safe base64 only contains alphanumeric, -, and _
        assert!(
            token
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
            "Token should be URL-safe"
        );
    }

    #[test]
    fn test_generate_csrf_token_length() {
        let token = generate_csrf_token().unwrap();
        assert_eq!(token.len(), 43, "CSRF token should be 43 characters");
    }

    #[test]
    fn test_generate_csrf_token_uniqueness() {
        let token1 = generate_csrf_token().unwrap();
        let token2 = generate_csrf_token().unwrap();
        assert_ne!(token1, token2, "CSRF tokens should be unique");
    }

    #[test]
    fn test_api_key_prefix_roundtrip() {
        let key = generate_api_key().unwrap();
        let prefix = api_key_prefix(&key).unwrap();
        assert_eq!(prefix.len(), API_KEY_PREFIX_LEN);
        assert!(key.starts_with(&prefix));
        assert!(prefix.starts_with("oat_"));
    }

    #[test]
    fn test_api_key_prefix_rejects_malformed() {
        assert!(api_key_prefix("not-an-oat-key").is_none());
        assert!(api_key_prefix("oat_short").is_none());
        assert!(api_key_prefix("").is_none());
    }

    #[test]
    fn test_custom_prefix_roundtrip() {
        let key = generate_prefixed_api_key("ipk_").unwrap();
        assert!(key.starts_with("ipk_"));
        let prefix = prefixed_api_key_prefix(&key, "ipk_").unwrap();
        assert_eq!(prefix.len(), 12);
        assert!(key.starts_with(&prefix));
    }

    #[test]
    fn test_custom_prefix_rejects_foreign_key() {
        let key = generate_prefixed_api_key("ipk_").unwrap();
        assert!(prefixed_api_key_prefix(&key, "oat_").is_none());
        assert!(api_key_prefix(&key).is_none());
    }

    #[test]
    fn test_prefix_of_differing_lengths() {
        let key = generate_prefixed_api_key("sgwt_").unwrap();
        let prefix = prefixed_api_key_prefix(&key, "sgwt_").unwrap();
        assert_eq!(prefix.len(), 5 + API_KEY_PREFIX_RANDOM_CHARS);
    }
}
