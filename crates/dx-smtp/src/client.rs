use std::future::Future;
use std::time::Duration;

use lettre::message::header::{HeaderName, HeaderValue};
use lettre::message::{Attachment, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, SmtpTransport, Tokio1Executor, Transport,
};
use secrecy::ExposeSecret;

use crate::error::{Error, Result};
use crate::types::{Email, SmtpConfig, SmtpSecurity};

const MAX_RETRIES: u32 = 3;
const INITIAL_BACKOFF_MS: u64 = 1000;

/// Per-send transport timeout. A relay that hangs must not stall a shared email
/// job queue, so every connect+send is bounded.
const SEND_TIMEOUT: Duration = Duration::from_secs(20);

const FALLBACK_TEXT: &str = "If this message isn't displaying correctly, please enable HTML in your email settings or try a different email client.";

/// Builds a lettre `Message` from an `Email` and sender address.
fn build_message(email: Email, from: &str) -> Result<Message> {
    let mut multipart = MultiPart::mixed().multipart(MultiPart::alternative_plain_html(
        FALLBACK_TEXT.to_string(),
        email.body,
    ));

    for attachment in email.attachments {
        let attachment = Attachment::new(attachment.filename)
            .body(attachment.data, attachment.content_type.parse()?);
        multipart = multipart.singlepart(attachment);
    }

    let from = from.parse()?;
    let mut builder = Message::builder()
        .from(from)
        .to(email.to)
        .subject(email.subject);

    // Bulk mail carries a one-click unsubscribe so it lands under the
    // Gmail/Yahoo bulk-sender rules; transactional mail leaves it off.
    if let Some(value) = email.list_unsubscribe {
        builder = builder
            .raw_header(HeaderValue::new(
                HeaderName::new_from_ascii_str("List-Unsubscribe"),
                value,
            ))
            .raw_header(HeaderValue::new(
                HeaderName::new_from_ascii_str("List-Unsubscribe-Post"),
                "List-Unsubscribe=One-Click".to_string(),
            ));
    }

    Ok(builder.multipart(multipart)?)
}

/// Returns true if the error is a transport-level error worth retrying.
fn is_retryable(err: &Error) -> bool {
    matches!(err, Error::SmtpTransportError(_)) && !err.is_permanent()
}

fn credentials(config: &SmtpConfig) -> Credentials {
    Credentials::new(
        config.user.expose_secret().to_string(),
        config.password.expose_secret().to_string(),
    )
}

fn build_sync_transport(config: &SmtpConfig) -> Result<SmtpTransport> {
    let transport = match config.security {
        SmtpSecurity::None => {
            tracing::warn!(host = %config.host, "SMTP transport is plaintext (no TLS, no auth)");
            SmtpTransport::builder_dangerous(&config.host)
                .port(config.port)
                .timeout(Some(SEND_TIMEOUT))
                .build()
        }
        SmtpSecurity::Tls => SmtpTransport::relay(&config.host)?
            .port(config.port)
            .credentials(credentials(config))
            .timeout(Some(SEND_TIMEOUT))
            .build(),
        SmtpSecurity::StartTls => SmtpTransport::starttls_relay(&config.host)?
            .port(config.port)
            .credentials(credentials(config))
            .timeout(Some(SEND_TIMEOUT))
            .build(),
    };
    Ok(transport)
}

fn build_async_transport(config: &SmtpConfig) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
    type T = AsyncSmtpTransport<Tokio1Executor>;
    let transport = match config.security {
        SmtpSecurity::None => {
            tracing::warn!(host = %config.host, "SMTP transport is plaintext (no TLS, no auth)");
            T::builder_dangerous(&config.host)
                .port(config.port)
                .timeout(Some(SEND_TIMEOUT))
                .build()
        }
        SmtpSecurity::Tls => T::relay(&config.host)?
            .port(config.port)
            .credentials(credentials(config))
            .timeout(Some(SEND_TIMEOUT))
            .build(),
        SmtpSecurity::StartTls => T::starttls_relay(&config.host)?
            .port(config.port)
            .credentials(credentials(config))
            .timeout(Some(SEND_TIMEOUT))
            .build(),
    };
    Ok(transport)
}

fn log_retry(attempt: u32, backoff: u64) {
    tracing::warn!(
        attempt = attempt + 1,
        max = MAX_RETRIES,
        backoff_ms = backoff,
        "SMTP send failed, retrying"
    );
}

// ============================================================================
// Sync Client
// ============================================================================

pub trait SmtpClient {
    fn send_email(&self, email: Email) -> Result<()>;
}

/// Synchronous SMTP client implementation using lettre.
///
/// The inner `SmtpTransport` is built once and pools connections, so a client
/// should be constructed once and shared rather than rebuilt per send.
pub struct SmtpClientImpl {
    transport: SmtpTransport,
    from: String,
}

impl SmtpClientImpl {
    /// Builds the pooled transport described by `config`.
    ///
    /// # Errors
    /// Returns an error if the relay hostname is unusable.
    pub fn new(config: SmtpConfig) -> Result<Self> {
        let transport = build_sync_transport(&config)?;
        Ok(SmtpClientImpl {
            transport,
            from: config.from,
        })
    }
}

impl SmtpClient for SmtpClientImpl {
    fn send_email(&self, email: Email) -> Result<()> {
        let message = build_message(email, &self.from)?;

        let mut last_err = None;
        for attempt in 0..MAX_RETRIES {
            match self.transport.send(&message) {
                Ok(_) => return Ok(()),
                Err(e) => {
                    let err = Error::SmtpTransportError(e);
                    if !is_retryable(&err) || attempt + 1 == MAX_RETRIES {
                        return Err(err);
                    }
                    let backoff = INITIAL_BACKOFF_MS * 2u64.pow(attempt);
                    log_retry(attempt, backoff);
                    std::thread::sleep(Duration::from_millis(backoff));
                    last_err = Some(err);
                }
            }
        }

        Err(last_err.expect("retry loop always records an error before exhausting attempts"))
    }
}

// ============================================================================
// Async Client
// ============================================================================

pub trait AsyncSmtpClient {
    fn send_email(&self, email: Email) -> impl Future<Output = Result<()>> + Send;
}

/// Asynchronous SMTP client implementation using lettre with Tokio.
///
/// The inner `AsyncSmtpTransport` is built once and pools connections, so a
/// client should be constructed once and shared rather than rebuilt per send.
pub struct AsyncSmtpClientImpl {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: String,
}

impl AsyncSmtpClientImpl {
    /// Builds the pooled transport described by `config`.
    ///
    /// # Errors
    /// Returns an error if the relay hostname is unusable.
    pub fn new(config: SmtpConfig) -> Result<Self> {
        let transport = build_async_transport(&config)?;
        Ok(AsyncSmtpClientImpl {
            transport,
            from: config.from,
        })
    }
}

impl AsyncSmtpClient for AsyncSmtpClientImpl {
    async fn send_email(&self, email: Email) -> Result<()> {
        let message = build_message(email, &self.from)?;

        let mut last_err = None;
        for attempt in 0..MAX_RETRIES {
            match self.transport.send(message.clone()).await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    let err = Error::SmtpTransportError(e);
                    if !is_retryable(&err) || attempt + 1 == MAX_RETRIES {
                        return Err(err);
                    }
                    let backoff = INITIAL_BACKOFF_MS * 2u64.pow(attempt);
                    log_retry(attempt, backoff);
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                    last_err = Some(err);
                }
            }
        }

        Err(last_err.expect("retry loop always records an error before exhausting attempts"))
    }
}

/// Send one email using an explicit [`SmtpConfig`] — the per-tenant custom
/// sender path, where the config differs per message and pooling would not help.
///
/// Builds a fresh transport per call and makes a **single** attempt bounded by
/// [`SEND_TIMEOUT`]; there is no retry, so a caller draining a shared queue
/// stays responsive and can apply its own backoff policy. Use
/// [`AsyncSmtpClientImpl`] instead when one config serves every message.
pub async fn send_email_with(config: &SmtpConfig, email: Email) -> Result<()> {
    let message = build_message(email, &config.from)?;
    let transport = build_async_transport(config)?;
    transport.send(message).await?;
    Ok(())
}
