use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64::Engine;
use bytes::Bytes;
use reqwest::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE, HeaderMap, HeaderValue};
use reqwest::{Method, Response, StatusCode};
use secrecy::ExposeSecret;
use url::Url;

use crate::config::S3Config;
use crate::error::{Error, Result};
use crate::signer::{self, Credentials};
use crate::types::{ListedObject, ObjectMeta, PutOptions};
use crate::xml;

const MAX_ATTEMPTS: u32 = 3;
const BACKOFF: Duration = Duration::from_millis(200);
/// AWS refuses presigned URLs valid for longer than a week.
const MAX_PRESIGN: Duration = Duration::from_secs(7 * 24 * 3600);
/// `DeleteObjects` takes at most 1000 keys per request.
const DELETE_BATCH: usize = 1000;

struct Inner {
    http: reqwest::Client,
    config: S3Config,
    /// Bucket root for signed requests, with a trailing slash.
    api_base: String,
    /// Bucket root for public URLs, without one.
    public_base: String,
}

/// One bucket. Cheap to clone and share; holds a pooled HTTP client.
///
/// Every request is signed with SigV4 and retried up to three times on
/// transport errors, 5xx and 429, with 200 ms / 400 ms backoff. All
/// operations here are idempotent, so that is safe.
#[derive(Clone)]
pub struct S3Client {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for S3Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Client")
            .field("bucket", &self.inner.config.bucket)
            .field("api_base", &self.inner.api_base)
            .finish_non_exhaustive()
    }
}

impl S3Client {
    /// Validates the config and builds the HTTP client. Does no I/O; call
    /// [`verify_connection`](Self::verify_connection) at startup to fail fast
    /// on wrong credentials or a missing bucket.
    pub fn new(config: S3Config) -> Result<Self> {
        config.validate()?;
        let (api_base, public_base) = config.resolve_bases()?;
        let http = reqwest::Client::builder()
            .connect_timeout(config.connect_timeout)
            .read_timeout(config.read_timeout)
            .build()?;
        Ok(Self {
            inner: Arc::new(Inner {
                http,
                config,
                api_base,
                public_base,
            }),
        })
    }

    pub fn config(&self) -> &S3Config {
        &self.inner.config
    }

    pub fn bucket(&self) -> &str {
        &self.inner.config.bucket
    }

    /// The URL an anonymous reader fetches `key` from — `public_url_base` if
    /// set, else the API endpoint. Says nothing about whether the bucket
    /// policy actually allows the read.
    pub fn public_url(&self, key: &str) -> String {
        format!(
            "{}/{}",
            self.inner.public_base,
            signer::encode_key(&self.inner.config.full_key(key))
        )
    }

    /// `HEAD` on the bucket. Fails on bad credentials (403), a missing
    /// bucket (404) and a wrong region (301). Needs `s3:ListBucket`.
    pub async fn verify_connection(&self) -> Result<()> {
        let url = self.bucket_url(&[])?;
        let resp = self
            .send(Method::HEAD, url, HeaderMap::new(), Bytes::new())
            .await?;
        ensure_success(resp, None).await?;
        tracing::info!(bucket = self.bucket(), "S3 bucket reachable");
        Ok(())
    }

    /// Store `body` at `key`, replacing whatever was there.
    pub async fn put(&self, key: &str, body: impl Into<Bytes>, options: PutOptions) -> Result<()> {
        let url = self.object_url(key)?;
        let mut headers = HeaderMap::new();
        for (name, value) in [
            (CONTENT_TYPE, &options.content_type),
            (CACHE_CONTROL, &options.cache_control),
            (CONTENT_DISPOSITION, &options.content_disposition),
        ] {
            if let Some(value) = value {
                headers.insert(name.clone(), header_value(name.as_str(), value)?);
            }
        }
        let resp = self.send(Method::PUT, url, headers, body.into()).await?;
        ensure_success(resp, None).await?;
        tracing::debug!(key, "stored object");
        Ok(())
    }

    /// Fetch the whole object. [`Error::NotFound`] if it does not exist.
    pub async fn get(&self, key: &str) -> Result<Bytes> {
        let url = self.object_url(key)?;
        let resp = self
            .send(Method::GET, url, HeaderMap::new(), Bytes::new())
            .await?;
        let resp = ensure_success(resp, Some(key)).await?;
        Ok(resp.bytes().await?)
    }

    /// Size, content type and ETag without the body. [`Error::NotFound`] if
    /// the object does not exist.
    pub async fn head(&self, key: &str) -> Result<ObjectMeta> {
        let url = self.object_url(key)?;
        let resp = self
            .send(Method::HEAD, url, HeaderMap::new(), Bytes::new())
            .await?;
        let resp = ensure_success(resp, Some(key)).await?;
        let header = |name: &str| {
            resp.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        Ok(ObjectMeta {
            size: header("content-length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            content_type: header("content-type"),
            etag: header("etag").map(|e| e.trim_matches('"').to_string()),
        })
    }

    /// `Ok(false)` only for a definite 404. Any other failure is an error,
    /// never a silent "no" — a guard that must not overwrite existing data
    /// can rely on it.
    pub async fn exists(&self, key: &str) -> Result<bool> {
        match self.head(key).await {
            Ok(_) => Ok(true),
            Err(Error::NotFound { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Delete one object. Succeeds when the object was already gone; fails
    /// on 403, 5xx and a missing bucket.
    pub async fn delete(&self, key: &str) -> Result<()> {
        let url = self.object_url(key)?;
        let resp = self
            .send(Method::DELETE, url, HeaderMap::new(), Bytes::new())
            .await?;
        ensure_success(resp, None).await?;
        tracing::debug!(key, "deleted object");
        Ok(())
    }

    /// Delete up to any number of objects, 1000 per request. Keys that do
    /// not exist count as deleted. Stops at the first batch with failures
    /// and reports them as [`Error::DeleteFailed`].
    pub async fn delete_many<K: AsRef<str>>(&self, keys: &[K]) -> Result<()> {
        for chunk in keys.chunks(DELETE_BATCH) {
            let full: Vec<String> = chunk
                .iter()
                .map(|k| {
                    validate_key(k.as_ref())?;
                    Ok(self.inner.config.full_key(k.as_ref()))
                })
                .collect::<Result<_>>()?;
            let body = xml::delete_request(&full);

            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/xml"));
            // S3 and MinIO require Content-MD5 on DeleteObjects.
            let md5 = base64::engine::general_purpose::STANDARD.encode(md5::compute(&body).0);
            headers.insert("content-md5", header_value("content-md5", &md5)?);

            let url = self.bucket_url(&[("delete", String::new())])?;
            let resp = self
                .send(Method::POST, url, headers, Bytes::from(body))
                .await?;
            let resp = ensure_success(resp, None).await?;
            let failed = xml::delete_errors(&resp.text().await?);
            if !failed.is_empty() {
                return Err(Error::DeleteFailed {
                    failed: failed
                        .into_iter()
                        .map(|(k, code)| (self.inner.config.strip_prefix(k), code))
                        .collect(),
                });
            }
            tracing::debug!(count = chunk.len(), "deleted objects");
        }
        Ok(())
    }

    /// Every object whose key starts with `prefix` (`""` for all of them),
    /// across as many pages as it takes. Prefix semantics are S3's:
    /// `"demos/ab"` also matches `demos/abc/…`; end it with `/` for a
    /// directory.
    pub async fn list(&self, prefix: &str) -> Result<Vec<ListedObject>> {
        self.list_paged(prefix, 1000).await
    }

    #[doc(hidden)]
    pub async fn list_paged(&self, prefix: &str, page_size: u16) -> Result<Vec<ListedObject>> {
        if prefix.starts_with('/') {
            return Err(Error::InvalidArgument(
                "prefix must not start with '/'".into(),
            ));
        }
        let full_prefix = self.inner.config.full_key(prefix);
        let mut objects = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut params = vec![
                ("list-type", "2".to_string()),
                ("max-keys", page_size.to_string()),
            ];
            if !full_prefix.is_empty() {
                params.push(("prefix", full_prefix.clone()));
            }
            if let Some(t) = &token {
                params.push(("continuation-token", t.clone()));
            }
            let url = self.bucket_url(&params)?;
            let resp = self
                .send(Method::GET, url, HeaderMap::new(), Bytes::new())
                .await?;
            let resp = ensure_success(resp, None).await?;
            let page = xml::parse_list(&resp.text().await?)?;
            objects.extend(page.objects.into_iter().map(|o| ListedObject {
                key: self.inner.config.strip_prefix(o.key),
                ..o
            }));
            match page.next {
                Some(next) => token = Some(next),
                None => return Ok(objects),
            }
        }
    }

    /// Server-side copy within the bucket. [`Error::NotFound`] for a
    /// missing source. Objects above 5 GB need multipart copy, which this
    /// crate does not do.
    pub async fn copy(&self, src_key: &str, dst_key: &str) -> Result<()> {
        validate_key(src_key)?;
        let url = self.object_url(dst_key)?;
        let source = format!(
            "/{}/{}",
            self.inner.config.bucket,
            signer::encode_key(&self.inner.config.full_key(src_key))
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-copy-source",
            header_value("x-amz-copy-source", &source)?,
        );
        let resp = self.send(Method::PUT, url, headers, Bytes::new()).await?;
        let resp = ensure_success(resp, Some(src_key)).await?;
        // A copy that fails after the 200 header is sent comes back as an
        // <Error> body with a 200 status.
        let body = resp.text().await?;
        if let (Some(code), message) = xml::parse_error(&body) {
            return Err(Error::Status {
                status: 200,
                code: Some(code),
                message: message.unwrap_or_default(),
            });
        }
        tracing::debug!(src_key, dst_key, "copied object");
        Ok(())
    }

    /// [`list`](Self::list) then [`delete_many`](Self::delete_many).
    /// Returns how many objects were deleted.
    pub async fn delete_prefix(&self, prefix: &str) -> Result<usize> {
        let keys: Vec<String> = self
            .list(prefix)
            .await?
            .into_iter()
            .map(|o| o.key)
            .collect();
        self.delete_many(&keys).await?;
        Ok(keys.len())
    }

    /// Server-side copy of every object under `src_prefix` to the same
    /// relative key under `dst_prefix`. Returns how many were copied.
    pub async fn copy_prefix(&self, src_prefix: &str, dst_prefix: &str) -> Result<usize> {
        let objects = self.list(src_prefix).await?;
        for object in &objects {
            let rest = &object.key[src_prefix.len()..];
            self.copy(&object.key, &format!("{dst_prefix}{rest}"))
                .await?;
        }
        Ok(objects.len())
    }

    /// A URL that lets anyone `GET` the object until `expires` (1 s to 7 d)
    /// has passed. Pure computation, no request.
    pub fn presign_get(&self, key: &str, expires: Duration) -> Result<String> {
        self.presign("GET", key, expires)
    }

    /// A URL that lets anyone `PUT` a body to `key` until `expires` (1 s to
    /// 7 d) has passed — for direct browser uploads. Only the host is
    /// signed, so the uploader chooses the content type.
    pub fn presign_put(&self, key: &str, expires: Duration) -> Result<String> {
        self.presign("PUT", key, expires)
    }

    fn presign(&self, method: &str, key: &str, expires: Duration) -> Result<String> {
        if expires < Duration::from_secs(1) || expires > MAX_PRESIGN {
            return Err(Error::InvalidArgument(format!(
                "presign expiry must be between 1 second and 7 days, got {expires:?}"
            )));
        }
        let url = self.object_url(key)?;
        Ok(signer::presign(
            method,
            &url,
            expires,
            &self.creds(),
            SystemTime::now(),
        ))
    }

    fn creds(&self) -> Credentials<'_> {
        let config = &self.inner.config;
        Credentials {
            access_key: &config.access_key,
            secret_key: config.secret_key.expose_secret(),
            region: &config.region,
        }
    }

    fn object_url(&self, key: &str) -> Result<Url> {
        validate_key(key)?;
        let raw = format!(
            "{}{}",
            self.inner.api_base,
            signer::encode_key(&self.inner.config.full_key(key))
        );
        Url::parse(&raw).map_err(|e| Error::InvalidArgument(format!("key {key:?}: {e}")))
    }

    /// The bucket itself (`/bucket` or `/`), with an already-canonical query.
    fn bucket_url(&self, params: &[(&str, String)]) -> Result<Url> {
        let mut raw = self.inner.api_base.trim_end_matches('/').to_string();
        if !params.is_empty() {
            raw.push('?');
            raw.push_str(&signer::encode_query(params));
        }
        Url::parse(&raw).map_err(|e| Error::InvalidConfig(format!("bucket URL: {e}")))
    }

    /// Sign and send, retrying transport errors, 5xx and 429. Each attempt
    /// is signed afresh so the timestamp stays current.
    async fn send(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<Response> {
        let payload_hash = signer::sha256_hex(&body);
        let creds = self.creds();
        let mut attempt = 1;
        loop {
            let mut signed = headers.clone();
            signer::sign_headers(
                method.as_str(),
                &url,
                &mut signed,
                &payload_hash,
                &creds,
                SystemTime::now(),
            );
            let mut req = self
                .inner
                .http
                .request(method.clone(), url.clone())
                .headers(signed);
            if !body.is_empty() {
                req = req.body(body.clone());
            }

            let result = req.send().await;
            let retryable = match &result {
                Err(_) => true,
                Ok(resp) => {
                    resp.status().is_server_error()
                        || resp.status() == StatusCode::TOO_MANY_REQUESTS
                }
            };
            if retryable && attempt < MAX_ATTEMPTS {
                let outcome = match &result {
                    Ok(resp) => resp.status().to_string(),
                    Err(e) => e.to_string(),
                };
                tracing::warn!(%method, attempt, outcome, "S3 request failed, retrying");
                tokio::time::sleep(BACKOFF * 2u32.pow(attempt - 1)).await;
                attempt += 1;
                continue;
            }
            return Ok(result?);
        }
    }
}

/// Non-empty, no leading slash. Everything else is S3's business.
fn validate_key(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(Error::InvalidArgument("key is empty".into()));
    }
    if key.starts_with('/') {
        return Err(Error::InvalidArgument(format!(
            "key {key:?} must not start with '/'"
        )));
    }
    Ok(())
}

/// Header values must be visible ASCII: the signer canonicalises bytes, and
/// S3 does not document how it treats anything else, so a non-ASCII value
/// would fail with an opaque `SignatureDoesNotMatch` instead of here.
fn header_value(name: &str, value: &str) -> Result<HeaderValue> {
    if !value.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return Err(Error::InvalidArgument(format!(
            "{name} must be printable ASCII; use content_disposition_inline() for filenames"
        )));
    }
    HeaderValue::from_str(value)
        .map_err(|_| Error::InvalidArgument(format!("{name} is not a valid header value")))
}

/// 2xx passes through; anything else becomes an error, with `key` turning a
/// 404 into [`Error::NotFound`].
async fn ensure_success(resp: Response, key: Option<&str>) -> Result<Response> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let body = resp.text().await.unwrap_or_default();
    let (code, message) = xml::parse_error(&body);
    Err(match (status.as_u16(), key) {
        (404, Some(key)) => Error::NotFound {
            key: key.to_string(),
        },
        (401 | 403, _) => Error::AccessDenied {
            status: status.as_u16(),
            message: describe(code, message, &body),
        },
        (status, _) => Error::Status {
            status,
            message: describe(code.clone(), message, &body),
            code,
        },
    })
}

fn describe(code: Option<String>, message: Option<String>, body: &str) -> String {
    match (code, message) {
        (_, Some(message)) => message,
        (Some(code), None) => code,
        (None, None) => body.chars().take(200).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> S3Client {
        S3Client::new(
            S3Config::new("us-east-1", "media", "AKIA", "secret")
                .with_endpoint("http://localhost:9100")
                .with_force_path_style(true)
                .with_path_prefix("app"),
        )
        .unwrap()
    }

    #[test]
    fn urls_are_prefixed_and_encoded() {
        let c = client();
        assert_eq!(
            c.object_url("a b/ü.png").unwrap().as_str(),
            "http://localhost:9100/media/app/a%20b/%C3%BC.png"
        );
        assert_eq!(
            c.public_url("a b/ü.png"),
            "http://localhost:9100/media/app/a%20b/%C3%BC.png"
        );
        assert_eq!(
            c.bucket_url(&[]).unwrap().as_str(),
            "http://localhost:9100/media"
        );
        assert_eq!(
            c.bucket_url(&[("list-type", "2".into()), ("prefix", "app/".into())])
                .unwrap()
                .as_str(),
            "http://localhost:9100/media?list-type=2&prefix=app%2F"
        );
        assert!(matches!(c.object_url(""), Err(Error::InvalidArgument(_))));
        assert!(matches!(c.object_url("/x"), Err(Error::InvalidArgument(_))));
    }

    #[test]
    fn public_url_base_wins() {
        let c = S3Client::new(
            S3Config::new("us-east-1", "media", "AKIA", "secret")
                .with_endpoint("https://eu2.contabostorage.com")
                .with_force_path_style(true)
                .with_public_url_base("https://eu2.contabostorage.com/tenant:media"),
        )
        .unwrap();
        assert_eq!(
            c.public_url("x.png"),
            "https://eu2.contabostorage.com/tenant:media/x.png"
        );
    }

    #[test]
    fn presign_bounds() {
        let c = client();
        assert!(matches!(
            c.presign_get("k", Duration::ZERO),
            Err(Error::InvalidArgument(_))
        ));
        assert!(matches!(
            c.presign_get("k", MAX_PRESIGN + Duration::from_secs(1)),
            Err(Error::InvalidArgument(_))
        ));
        let url = c.presign_put("a b.png", Duration::from_secs(60)).unwrap();
        assert!(url.starts_with("http://localhost:9100/media/app/a%20b.png?X-Amz-Algorithm="));
        assert!(url.contains("&X-Amz-Expires=60&"));
    }

    #[test]
    fn non_ascii_header_values_are_rejected_up_front() {
        assert!(matches!(
            header_value("content-disposition", "inline; filename=\"ü.png\""),
            Err(Error::InvalidArgument(_))
        ));
        assert!(header_value("cache-control", "public, max-age=60").is_ok());
    }

    #[test]
    fn debug_shows_no_secret() {
        let s = format!("{:?}", client());
        assert!(s.contains("media"));
        assert!(!s.contains("secret"));
    }

    #[test]
    fn client_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<S3Client>();
    }
}
