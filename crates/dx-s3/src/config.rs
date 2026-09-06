use std::time::Duration;

use secrecy::SecretString;
use url::Url;

use crate::error::{Error, Result};

/// Connection settings for one bucket.
///
/// Keys handed to the client are always relative to `path_prefix`: the prefix
/// is applied on the way in and stripped on the way out (`list`), so an app
/// never sees it. That is what lets several apps share one bucket safely.
///
/// `Debug` redacts the secret key.
#[derive(Clone, Debug)]
pub struct S3Config {
    /// `None` for AWS; the base URL of the service otherwise (RustFS, MinIO,
    /// R2, Contabo, Hetzner, …). A path component is kept: `https://h/s3`.
    pub endpoint: Option<String>,
    pub region: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: SecretString,
    /// Prefix under which every key of this app lives, without slashes on
    /// either end. `None` or empty means the bucket root.
    pub path_prefix: Option<String>,
    /// `https://host/bucket/key` instead of `https://bucket.host/key`.
    /// Required by RustFS and MinIO, and by any endpoint whose TLS
    /// certificate does not cover `*.host`.
    pub force_path_style: bool,
    /// Base for [`S3Client::public_url`](crate::S3Client::public_url) when
    /// public reads go somewhere other than the API endpoint: a CDN, or
    /// Contabo's `https://eu2.contabostorage.com/<tenant>:<bucket>`. Points
    /// at the bucket root; the prefixed key is appended.
    pub public_url_base: Option<String>,
    /// TCP connect timeout. Default 10 s.
    pub connect_timeout: Duration,
    /// Inactivity timeout between reads of a response. Bounds a stalled
    /// connection without capping the total transfer time, so a slow 200 MB
    /// upload still completes. Default 30 s.
    pub read_timeout: Duration,
}

impl S3Config {
    pub fn new(
        region: impl Into<String>,
        bucket: impl Into<String>,
        access_key: impl Into<String>,
        secret_key: impl Into<SecretString>,
    ) -> Self {
        Self {
            endpoint: None,
            region: region.into(),
            bucket: bucket.into(),
            access_key: access_key.into(),
            secret_key: secret_key.into(),
            path_prefix: None,
            force_path_style: false,
            public_url_base: None,
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(30),
        }
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    pub fn with_path_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.path_prefix = Some(prefix.into());
        self
    }

    pub fn with_force_path_style(mut self, force: bool) -> Self {
        self.force_path_style = force;
        self
    }

    pub fn with_public_url_base(mut self, base: impl Into<String>) -> Self {
        self.public_url_base = Some(base.into());
        self
    }

    /// The configured prefix without surrounding slashes, or `None`.
    pub(crate) fn prefix(&self) -> Option<&str> {
        self.path_prefix
            .as_deref()
            .map(|p| p.trim_matches('/'))
            .filter(|p| !p.is_empty())
    }

    /// The key as stored in the bucket: `path_prefix` plus `key`.
    pub fn full_key(&self, key: &str) -> String {
        match self.prefix() {
            Some(prefix) => format!("{prefix}/{key}"),
            None => key.to_string(),
        }
    }

    /// Inverse of [`full_key`](Self::full_key) for keys read back from S3.
    pub(crate) fn strip_prefix(&self, full_key: String) -> String {
        match self.prefix() {
            Some(prefix) => full_key
                .strip_prefix(prefix)
                .and_then(|k| k.strip_prefix('/'))
                .map(str::to_string)
                .unwrap_or(full_key),
            None => full_key,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("region", &self.region),
            ("bucket", &self.bucket),
            ("access_key", &self.access_key),
        ] {
            if value.trim().is_empty() {
                return Err(Error::InvalidConfig(format!("{name} is empty")));
            }
        }
        if !self.access_key.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(Error::InvalidConfig(
                "access_key must be printable ASCII".into(),
            ));
        }
        if secrecy::ExposeSecret::expose_secret(&self.secret_key).is_empty() {
            return Err(Error::InvalidConfig("secret_key is empty".into()));
        }
        if let Some(base) = &self.public_url_base
            && base.trim_end_matches('/').is_empty()
        {
            return Err(Error::InvalidConfig("public_url_base is empty".into()));
        }
        Ok(())
    }

    /// `(api_base, public_base)`: the bucket root for signed requests, with a
    /// trailing slash, and the bucket root for public URLs, without one.
    pub(crate) fn resolve_bases(&self) -> Result<(String, String)> {
        let api = match &self.endpoint {
            Some(endpoint) => {
                let parsed = Url::parse(endpoint).map_err(|e| {
                    Error::InvalidConfig(format!("endpoint {endpoint:?} is not a URL: {e}"))
                })?;
                if !matches!(parsed.scheme(), "http" | "https") {
                    return Err(Error::InvalidConfig(format!(
                        "endpoint {endpoint:?} must be http or https"
                    )));
                }
                let host = parsed.host_str().ok_or_else(|| {
                    Error::InvalidConfig(format!("endpoint {endpoint:?} has no host"))
                })?;
                let port = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
                let path = parsed.path().trim_end_matches('/');
                let scheme = parsed.scheme();
                if self.force_path_style {
                    format!("{scheme}://{host}{port}{path}/{}/", self.bucket)
                } else {
                    format!("{scheme}://{}.{host}{port}{path}/", self.bucket)
                }
            }
            None if self.force_path_style => {
                format!("https://s3.{}.amazonaws.com/{}/", self.region, self.bucket)
            }
            None => format!("https://{}.s3.{}.amazonaws.com/", self.bucket, self.region),
        };
        let public = match &self.public_url_base {
            Some(base) => base.trim_end_matches('/').to_string(),
            None => api.trim_end_matches('/').to_string(),
        };
        Ok((api, public))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> S3Config {
        S3Config::new("eu-central-1", "media", "AKIA", "secret")
    }

    #[test]
    fn debug_redacts_the_secret() {
        let s = format!("{:?}", config());
        assert!(s.contains("AKIA"));
        assert!(!s.contains("secret\""));
        assert!(s.contains("REDACTED"));
    }

    #[test]
    fn full_key_round_trips_through_the_prefix() {
        let c = config().with_path_prefix("/uploads/");
        assert_eq!(c.full_key("a/b.png"), "uploads/a/b.png");
        assert_eq!(c.strip_prefix("uploads/a/b.png".into()), "a/b.png");
        assert_eq!(c.strip_prefix("other/x".into()), "other/x");
        assert_eq!(c.full_key(""), "uploads/");

        let c = config().with_path_prefix("");
        assert_eq!(c.full_key("a.png"), "a.png");
        assert_eq!(config().full_key("a.png"), "a.png");
    }

    #[test]
    fn aws_virtual_host_and_path_style() {
        let (api, public) = config().resolve_bases().unwrap();
        assert_eq!(api, "https://media.s3.eu-central-1.amazonaws.com/");
        assert_eq!(public, "https://media.s3.eu-central-1.amazonaws.com");

        let (api, _) = config()
            .with_force_path_style(true)
            .resolve_bases()
            .unwrap();
        assert_eq!(api, "https://s3.eu-central-1.amazonaws.com/media/");
    }

    #[test]
    fn custom_endpoint_keeps_port_and_path_and_puts_the_bucket_in_the_host() {
        let (api, _) = config()
            .with_endpoint("http://localhost:9100/")
            .with_force_path_style(true)
            .resolve_bases()
            .unwrap();
        assert_eq!(api, "http://localhost:9100/media/");

        let (api, public) = config()
            .with_endpoint("https://acct.r2.cloudflarestorage.com")
            .resolve_bases()
            .unwrap();
        assert_eq!(api, "https://media.acct.r2.cloudflarestorage.com/");
        assert_eq!(public, "https://media.acct.r2.cloudflarestorage.com");

        let (api, _) = config()
            .with_endpoint("https://gateway.example/s3/")
            .with_force_path_style(true)
            .resolve_bases()
            .unwrap();
        assert_eq!(api, "https://gateway.example/s3/media/");
    }

    #[test]
    fn public_url_base_overrides_the_endpoint() {
        let (_, public) = config()
            .with_endpoint("https://eu2.contabostorage.com")
            .with_force_path_style(true)
            .with_public_url_base("https://eu2.contabostorage.com/tenant:media/")
            .resolve_bases()
            .unwrap();
        assert_eq!(public, "https://eu2.contabostorage.com/tenant:media");
    }

    #[test]
    fn invalid_config_is_rejected() {
        assert!(matches!(
            S3Config::new("r", "", "k", "s").validate(),
            Err(Error::InvalidConfig(m)) if m == "bucket is empty"
        ));
        assert!(matches!(
            S3Config::new("r", "b", "k", "").validate(),
            Err(Error::InvalidConfig(_))
        ));
        assert!(matches!(
            S3Config::new("r", "b", "kë", "s").validate(),
            Err(Error::InvalidConfig(_))
        ));
        assert!(matches!(
            config().with_endpoint("localhost:9000").resolve_bases(),
            Err(Error::InvalidConfig(_))
        ));
        assert!(matches!(
            config().with_endpoint("ftp://x").resolve_bases(),
            Err(Error::InvalidConfig(_))
        ));
        assert!(config().validate().is_ok());
    }
}
