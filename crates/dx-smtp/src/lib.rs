//! SMTP email transport via [lettre].
//!
//! Two ways to send:
//!
//! - [`SmtpClientImpl`] / [`AsyncSmtpClientImpl`] — build once from one
//!   [`SmtpConfig`], pool connections, retry transient failures with backoff.
//!   Use these for the app's own sender.
//! - [`send_email_with`] — one config per message (per-tenant custom senders),
//!   fresh transport, single bounded attempt, no retry.
//!
//! [lettre]: https://docs.rs/lettre

mod client;
pub mod error;
mod types;

pub use client::{
    AsyncSmtpClient, AsyncSmtpClientImpl, SmtpClient, SmtpClientImpl, send_email_with,
};
pub use lettre::message::Mailbox;
pub use types::{Email, EmailAttachment, EmailBuilder, SmtpConfig, SmtpSecurity};
