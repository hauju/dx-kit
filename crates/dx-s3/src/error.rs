pub type Result<T> = core::result::Result<T, Error>;

/// Errors are classified by cause, not by the operation that hit them, so a
/// caller can match `NotFound` to answer 404, `AccessDenied` to alert, and use
/// [`Error::is_transient`] to decide whether a retry is worth it.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The object does not exist. Only produced by operations that address
    /// one object (`get`, `head`, `copy` source); `delete` is idempotent and
    /// never returns this.
    #[error("object not found: {key}")]
    NotFound { key: String },

    /// The credentials or the bucket policy rejected the request (401/403).
    #[error("access denied ({status}): {message}")]
    AccessDenied { status: u16, message: String },

    /// Any other non-2xx response, with the `<Code>` and `<Message>` from the
    /// XML error body when S3 sent one.
    #[error("S3 returned {status}{}: {message}", code.as_deref().map(|c| format!(" {c}")).unwrap_or_default())]
    Status {
        status: u16,
        code: Option<String>,
        message: String,
    },

    /// A batch delete succeeded for some keys and failed for others. Keys are
    /// the caller's keys (without the path prefix), paired with S3's error code.
    #[error("{} object(s) could not be deleted", failed.len())]
    DeleteFailed { failed: Vec<(String, String)> },

    /// Connection, TLS, timeout, or body-read failure.
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),

    #[error("invalid S3 config: {0}")]
    InvalidConfig(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// S3 answered 2xx with a body this crate could not parse.
    #[error("could not parse S3 response: {0}")]
    Xml(String),
}

impl Error {
    /// Whether retrying the same request later has a reasonable chance of
    /// succeeding: transport failures, 5xx, 429 (`SlowDown`) and 503.
    ///
    /// The client already retries these up to three times per call, so a
    /// `true` here means three attempts failed.
    pub fn is_transient(&self) -> bool {
        match self {
            Error::Transport(_) => true,
            Error::Status { status, .. } => *status >= 500 || *status == 429,
            _ => false,
        }
    }
}
