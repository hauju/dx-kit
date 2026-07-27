//! SHA-256 lookup hashes.
//!
//! These are deterministic (unsalted) hashes — intended for values that are
//! already high-entropy random tokens, where a fast hash enables an indexed
//! lookup. Do **not** use these for low-entropy secrets like passwords; use
//! [`crate::hash_secret`] (Argon2) for those.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

/// Deterministic lookup hash for an API key.
///
/// API keys are 256-bit random tokens, so a plain SHA-256 (no salt) is
/// sufficient — there's no low-entropy input to protect, and determinism is
/// required so the hash can be stored under a unique index and looked up in one
/// query. Returns the digest as URL-safe base64 (no padding).
///
/// # Example
/// ```
/// use dx_crypto::{generate_api_key, hash_api_key};
///
/// let key = generate_api_key().unwrap();
/// // Same input always yields the same digest — that's what makes it indexable.
/// assert_eq!(hash_api_key(&key), hash_api_key(&key));
/// assert_eq!(hash_api_key(&key).len(), 43);
/// ```
pub fn hash_api_key(key: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(key.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_api_key_is_deterministic() {
        let key = "oat_test_key_value";
        assert_eq!(hash_api_key(key), hash_api_key(key));
    }

    #[test]
    fn hash_api_key_differs_per_input() {
        assert_ne!(hash_api_key("oat_a"), hash_api_key("oat_b"));
    }

    #[test]
    fn hash_api_key_is_url_safe() {
        let hash = hash_api_key("oat_whatever");
        // SHA-256 → 32 bytes → 43 url-safe base64 chars (no padding).
        assert_eq!(hash.len(), 43);
        assert!(
            hash.chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        );
    }
}
