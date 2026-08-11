use lettre::message::Mailbox;
use secrecy::SecretString;

/// How the SMTP connection is secured.
///
/// Replaces the older `insecure: bool` flag, which could only distinguish
/// "plaintext" from "implicit TLS" and left STARTTLS relays unreachable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SmtpSecurity {
    /// Implicit TLS (SMTPS), conventionally port 465.
    #[default]
    Tls,
    /// Upgrade a plaintext connection with STARTTLS, conventionally port 587.
    StartTls,
    /// No encryption and no authentication — for local dev relays like Mailpit
    /// on port 1025. Never select this against a real relay.
    None,
}

impl SmtpSecurity {
    /// Whether this mode skips TLS and authentication entirely.
    pub fn is_plaintext(self) -> bool {
        matches!(self, SmtpSecurity::None)
    }
}

/// Represents an email message.
#[derive(Debug, Clone)]
pub struct Email {
    /// Recipient email address
    pub to: Mailbox,
    /// Email subject
    pub subject: String,
    /// Email body (HTML)
    pub body: String,
    /// Attachments
    pub attachments: Vec<EmailAttachment>,
    /// Value for the `List-Unsubscribe` header (e.g. `<https://…/unsubscribe/…>`).
    /// When set, the bulk-sender `List-Unsubscribe` + one-click
    /// `List-Unsubscribe-Post` headers are emitted. Required for bulk mail
    /// (Gmail/Yahoo); transactional 1:1 mail leaves this `None`.
    pub list_unsubscribe: Option<String>,
}

impl Email {
    /// Starts building an email to `to`.
    pub fn builder(to: Mailbox) -> EmailBuilder {
        EmailBuilder::new(to)
    }
}

/// Builder for [`Email`].
pub struct EmailBuilder {
    to: Mailbox,
    subject: Option<String>,
    body: Option<String>,
    attachments: Vec<EmailAttachment>,
    list_unsubscribe: Option<String>,
}

impl EmailBuilder {
    /// Creates a new builder for a message to `to`.
    pub fn new(to: Mailbox) -> Self {
        Self {
            to,
            subject: None,
            body: None,
            attachments: Vec::new(),
            list_unsubscribe: None,
        }
    }

    /// Sets the subject line.
    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Sets the HTML body.
    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Adds a single attachment.
    pub fn attachment(mut self, attachment: EmailAttachment) -> Self {
        self.attachments.push(attachment);
        self
    }

    /// Adds several attachments at once.
    pub fn attachments(mut self, attachments: Vec<EmailAttachment>) -> Self {
        self.attachments.extend(attachments);
        self
    }

    /// Sets the `List-Unsubscribe` header value (e.g.
    /// `<https://example.com/unsubscribe/abc>`). Marks the message as bulk mail
    /// with a one-click unsubscribe; leave unset for transactional mail.
    pub fn list_unsubscribe(mut self, value: impl Into<String>) -> Self {
        self.list_unsubscribe = Some(value.into());
        self
    }

    /// Builds the `Email` instance.
    ///
    /// # Panics
    /// Panics if subject or body were never set. Use [`EmailBuilder::try_build`]
    /// to get an `Option` instead.
    pub fn build(self) -> Email {
        Email {
            to: self.to,
            subject: self.subject.expect("subject is required"),
            body: self.body.expect("body is required"),
            attachments: self.attachments,
            list_unsubscribe: self.list_unsubscribe,
        }
    }

    /// Builds the `Email`, returning `None` if subject or body are missing.
    pub fn try_build(self) -> Option<Email> {
        Some(Email {
            to: self.to,
            subject: self.subject?,
            body: self.body?,
            attachments: self.attachments,
            list_unsubscribe: self.list_unsubscribe,
        })
    }
}

/// A file attached to an [`Email`].
#[derive(Debug, Clone)]
pub struct EmailAttachment {
    /// Filename of the attachment
    pub filename: String,
    /// Content type of the attachment
    /// e.g. "application/pdf"
    pub content_type: String,
    /// data
    pub data: Vec<u8>,
}

/// SMTP configuration for sending emails.
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    /// Sender email address. May be a bare address (`a@b.com`) or a display
    /// form (`Name <a@b.com>`).
    pub from: String,
    /// SMTP host
    pub host: String,
    /// SMTP port
    pub port: u16,
    /// SMTP username
    pub user: SecretString,
    /// SMTP password
    pub password: SecretString,
    /// Transport security. Defaults to implicit TLS.
    pub security: SmtpSecurity,
}
