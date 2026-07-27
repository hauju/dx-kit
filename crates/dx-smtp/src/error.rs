pub type Result<T> = core::result::Result<T, Error>;

#[derive(thiserror::Error)]
pub enum Error {
    #[error("LettreError: {0}")]
    LettreError(#[from] lettre::error::Error),

    #[error("SmtpTransportError: {0}")]
    SmtpTransportError(#[from] lettre::transport::smtp::Error),

    #[error("SmtpAddressError: {0}")]
    SmtpAddressError(#[from] lettre::address::AddressError),

    #[error("LettreContentTypeError: {0}")]
    LettreContentTypeError(#[from] lettre::message::header::ContentTypeErr),
}

impl Error {
    /// Whether this send failure is permanent (a 5xx SMTP reply or an invalid
    /// recipient address) — i.e. retrying won't help and the recipient should be
    /// suppressed. Transient failures (4xx, connection/TLS) return `false`.
    pub fn is_permanent(&self) -> bool {
        match self {
            Error::SmtpTransportError(e) => e.is_permanent(),
            Error::SmtpAddressError(_) => true,
            _ => false,
        }
    }
}

impl core::fmt::Debug for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self)
    }
}
