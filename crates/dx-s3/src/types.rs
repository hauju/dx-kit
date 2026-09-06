use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

/// Headers stored with an object on [`put`](crate::S3Client::put). All
/// optional; S3 defaults the content type to `binary/octet-stream`.
#[derive(Clone, Debug, Default)]
pub struct PutOptions {
    pub content_type: Option<String>,
    pub cache_control: Option<String>,
    /// Build with [`content_disposition_inline`] or
    /// [`content_disposition_attachment`] so non-ASCII filenames are encoded
    /// rather than rejected.
    pub content_disposition: Option<String>,
}

impl PutOptions {
    pub fn content_type(content_type: impl Into<String>) -> Self {
        Self {
            content_type: Some(content_type.into()),
            ..Self::default()
        }
    }

    pub fn with_cache_control(mut self, value: impl Into<String>) -> Self {
        self.cache_control = Some(value.into());
        self
    }

    pub fn with_content_disposition(mut self, value: impl Into<String>) -> Self {
        self.content_disposition = Some(value.into());
        self
    }
}

/// What `HEAD` reports about one object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectMeta {
    pub size: u64,
    pub content_type: Option<String>,
    /// Without the surrounding quotes.
    pub etag: Option<String>,
}

/// One entry of a listing. `key` is relative to the configured path prefix,
/// like every key the client accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedObject {
    pub key: String,
    pub size: u64,
    pub etag: Option<String>,
}

/// `inline; filename="…"; filename*=UTF-8''…` for `filename`.
pub fn content_disposition_inline(filename: &str) -> String {
    content_disposition("inline", filename)
}

/// `attachment; filename="…"; filename*=UTF-8''…` for `filename`.
pub fn content_disposition_attachment(filename: &str) -> String {
    content_disposition("attachment", filename)
}

/// RFC 6266: an ASCII `filename` every client understands plus the RFC 5987
/// `filename*` that carries the exact name. Without the second form a name
/// like `Größe.png` either fails signing or arrives as mojibake.
fn content_disposition(kind: &str, filename: &str) -> String {
    const ATTR_CHAR: &AsciiSet = &NON_ALPHANUMERIC
        .remove(b'!')
        .remove(b'#')
        .remove(b'$')
        .remove(b'&')
        .remove(b'+')
        .remove(b'-')
        .remove(b'.')
        .remove(b'^')
        .remove(b'_')
        .remove(b'`')
        .remove(b'|')
        .remove(b'~');

    let ascii: String = filename
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .map(|c| match c {
            '"' | '\\' | '/' => '_',
            c if c.is_ascii_graphic() || c == ' ' => c,
            _ => '_',
        })
        .collect();
    let ascii = if ascii.is_empty() { "file" } else { &ascii };
    let encoded = utf8_percent_encode(filename, ATTR_CHAR);
    format!("{kind}; filename=\"{ascii}\"; filename*=UTF-8''{encoded}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disposition_is_ascii_with_an_exact_encoded_name() {
        assert_eq!(
            content_disposition_inline("Größe  \"1\".png"),
            "inline; filename=\"Gr__e _1_.png\"; filename*=UTF-8''Gr%C3%B6%C3%9Fe%20%20%221%22.png"
        );
        assert_eq!(
            content_disposition_attachment("report.pdf"),
            "attachment; filename=\"report.pdf\"; filename*=UTF-8''report.pdf"
        );
        assert!(content_disposition_inline("").starts_with("inline; filename=\"file\""));
        assert!(content_disposition_inline("日本").is_ascii());
    }
}
