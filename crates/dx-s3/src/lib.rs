//! S3-compatible object storage without an SDK.
//!
//! One [`S3Client`] per bucket, built from an [`S3Config`]. It speaks
//! Signature V4 directly over the same `reqwest` + rustls stack the rest of
//! the kit uses, so an app carries no second HTTP client and no AWS crate
//! tree. Works against AWS, RustFS, MinIO, Cloudflare R2, Contabo, Hetzner
//! and anything else that implements the S3 API.
//!
//! ```no_run
//! use std::time::Duration;
//! use dx_s3::{PutOptions, S3Client, S3Config, content_disposition_inline};
//!
//! # async fn run() -> dx_s3::Result<()> {
//! let client = S3Client::new(
//!     S3Config::new("us-east-1", "media", "rustfsadmin", "rustfsadmin")
//!         .with_endpoint("http://localhost:9000")
//!         .with_force_path_style(true)
//!         .with_path_prefix("blog"),
//! )?;
//! client.verify_connection().await?;
//!
//! client
//!     .put(
//!         "covers/1.png",
//!         png_bytes(),
//!         PutOptions::content_type("image/png")
//!             .with_cache_control("public, max-age=31536000, immutable")
//!             .with_content_disposition(content_disposition_inline("Titelbild.png")),
//!     )
//!     .await?;
//!
//! let url = client.public_url("covers/1.png");
//! let signed = client.presign_get("covers/1.png", Duration::from_secs(600))?;
//! let listing = client.list("covers/").await?;
//! client.delete("covers/1.png").await?;
//! # let _ = (url, signed, listing);
//! # Ok(()) }
//! # fn png_bytes() -> Vec<u8> { Vec::new() }
//! ```
//!
//! Keys are relative to `path_prefix` in both directions; the prefix is a
//! deployment detail the app never sees. Errors are classified by cause
//! ([`Error::NotFound`], [`Error::AccessDenied`], …) rather than by
//! operation, and every request is retried on transport errors and 5xx.
//!
//! Not covered: multipart and streaming uploads (bodies are in memory),
//! STS session tokens, bucket management.

mod client;
mod config;
pub mod error;
mod signer;
mod types;
mod xml;

pub use bytes::Bytes;
pub use client::S3Client;
pub use config::S3Config;
pub use error::{Error, Result};
pub use secrecy::SecretString;
pub use types::{
    ListedObject, ObjectMeta, PutOptions, content_disposition_attachment,
    content_disposition_inline,
};
