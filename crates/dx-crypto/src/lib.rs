//! Cryptographic utilities shared across the dx SaaS apps.
//!
//! - **random**: secure random bytes, URL-safe tokens, and numeric OTPs from OS entropy
//! - **hashing**: Argon2 hashing for low-entropy secrets (passwords)
//! - **sha256**: deterministic SHA-256 lookup hashes for high-entropy tokens
//! - **tokens**: API keys, invitation tokens, CSRF tokens
//! - **pkce**: RFC 7636 `S256` challenge/verify for OAuth
//! - **encryption**: AES-256-GCM for secrets at rest
//!
//! # Choosing a hash
//!
//! Use [`hash_secret`] (Argon2, salted, slow) for anything a human chose. Use
//! [`sha256::hash_api_key`] (unsalted, fast, deterministic) only for values that
//! are already 256-bit random — it is deterministic on purpose so the digest can
//! sit under a unique index and be looked up in one query.

pub mod encryption;
mod error;
mod hashing;
pub mod pkce;
mod random;
pub mod sha256;
mod tokens;

pub use error::{Error, Result};
pub use hashing::{hash_secret, verify_secret};
#[allow(deprecated)]
pub use pkce::pkce_s256_matches;
pub use pkce::{pkce_s256_challenge, verify_pkce_s256};
pub use random::{generate_numeric_otp, generate_random_bytes, generate_url_safe_token};
pub use sha256::hash_api_key;
pub use tokens::{
    API_KEY_PREFIX_LEN, API_KEY_PREFIX_RANDOM_CHARS, DEFAULT_API_KEY_PREFIX, api_key_prefix,
    generate_api_key, generate_csrf_token, generate_invitation_token, generate_prefixed_api_key,
    prefixed_api_key_prefix,
};
