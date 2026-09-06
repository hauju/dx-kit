//! AWS Signature Version 4 for S3: header signing for the requests this crate
//! sends, and query-string signing for the presigned URLs it hands out.
//!
//! Deliberately small. No STS session tokens, no chunked/streaming payload
//! signing: every body is either empty or fully in memory, so the payload
//! hash is a plain SHA-256 over the bytes. Correctness is pinned by the
//! worked examples in the S3 API reference (`tests` below), not by trust.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::header::{AUTHORIZATION, HOST, HeaderMap, HeaderName, HeaderValue};
use sha2::{Digest, Sha256};
use url::Url;

const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const SERVICE: &str = "s3";
const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// SigV4 "URI-encode": everything except the unreserved set `A-Za-z0-9-._~`.
/// Used for query components.
pub(crate) const QUERY: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// The same set with `/` kept, for object keys: each segment is encoded, the
/// separators are not.
pub(crate) const PATH: &AsciiSet = &QUERY.remove(b'/');

pub(crate) struct Credentials<'a> {
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub region: &'a str,
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Percent-encode an object key for use in a path (segments encoded, `/`
/// kept). This is the canonical URI form SigV4 expects, so the request path
/// and the signed path are the same bytes.
pub(crate) fn encode_key(key: &str) -> String {
    utf8_percent_encode(key, PATH).to_string()
}

/// Encode and canonically order query parameters. The result is used both
/// in the request URL and in the canonical request, which is what keeps the
/// two in agreement.
pub(crate) fn encode_query(params: &[(&str, String)]) -> String {
    let mut encoded: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| {
            (
                utf8_percent_encode(k, QUERY).to_string(),
                utf8_percent_encode(v, QUERY).to_string(),
            )
        })
        .collect();
    // Sorted by encoded name, then encoded value — SigV4 orders the encoded
    // forms, not the raw ones.
    encoded.sort();
    encoded
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Sign `headers` in place for a request to `url`. Inserts `host`,
/// `x-amz-date`, `x-amz-content-sha256` and `authorization`. Every header
/// already present is included in the signature, so set content headers
/// before calling this and never after.
///
/// `url.query()` is signed verbatim; build it with [`encode_query`] so it is
/// already canonical.
pub(crate) fn sign_headers(
    method: &str,
    url: &Url,
    headers: &mut HeaderMap,
    payload_hash: &str,
    creds: &Credentials<'_>,
    now: SystemTime,
) {
    let (amz_date, date_stamp) = amz_dates(now);
    let host = host_with_port(url);

    headers.insert(HOST, ascii_header(&host));
    headers.insert(
        HeaderName::from_static("x-amz-date"),
        ascii_header(&amz_date),
    );
    headers.insert(
        HeaderName::from_static("x-amz-content-sha256"),
        ascii_header(payload_hash),
    );

    let (canonical_headers, signed_headers) = canonical_headers(headers);
    let canonical_request = format!(
        "{method}\n{}\n{}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
        canonical_path(url),
        url.query().unwrap_or(""),
    );

    let scope = credential_scope(&date_stamp, creds.region);
    let signature = signature(&canonical_request, &scope, &amz_date, &date_stamp, creds);
    let auth = format!(
        "{ALGORITHM} Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        creds.access_key
    );
    headers.insert(AUTHORIZATION, ascii_header(&auth));
}

/// Build a presigned URL for `method` on `url` (which must carry no query),
/// valid for `expires`. Only the `host` header is signed, so whoever uses
/// the URL needs to send nothing else.
pub(crate) fn presign(
    method: &str,
    url: &Url,
    expires: Duration,
    creds: &Credentials<'_>,
    now: SystemTime,
) -> String {
    let (amz_date, date_stamp) = amz_dates(now);
    let host = host_with_port(url);
    let scope = credential_scope(&date_stamp, creds.region);

    let query = encode_query(&[
        ("X-Amz-Algorithm", ALGORITHM.to_string()),
        ("X-Amz-Credential", format!("{}/{scope}", creds.access_key)),
        ("X-Amz-Date", amz_date.clone()),
        ("X-Amz-Expires", expires.as_secs().to_string()),
        ("X-Amz-SignedHeaders", "host".to_string()),
    ]);

    let path = canonical_path(url);
    let canonical_request =
        format!("{method}\n{path}\n{query}\nhost:{host}\n\nhost\n{UNSIGNED_PAYLOAD}");
    let signature = signature(&canonical_request, &scope, &amz_date, &date_stamp, creds);

    format!(
        "{}://{host}{path}?{query}&X-Amz-Signature={signature}",
        url.scheme()
    )
}

fn credential_scope(date_stamp: &str, region: &str) -> String {
    format!("{date_stamp}/{region}/{SERVICE}/aws4_request")
}

fn signature(
    canonical_request: &str,
    scope: &str,
    amz_date: &str,
    date_stamp: &str,
    creds: &Credentials<'_>,
) -> String {
    let string_to_sign = format!(
        "{ALGORITHM}\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let k_date = hmac(
        format!("AWS4{}", creds.secret_key).as_bytes(),
        date_stamp.as_bytes(),
    );
    let k_region = hmac(&k_date, creds.region.as_bytes());
    let k_service = hmac(&k_region, SERVICE.as_bytes());
    let k_signing = hmac(&k_service, b"aws4_request");
    hex::encode(hmac(&k_signing, string_to_sign.as_bytes()))
}

fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    // HMAC accepts keys of any length; the only error path is unreachable.
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// All inputs are ASCII by construction (hosts, dates, hex, and an access key
/// the config validated), so this cannot fail in practice.
fn ascii_header(value: &str) -> HeaderValue {
    HeaderValue::from_str(value).expect("signer only produces ASCII header values")
}

fn host_with_port(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

/// The canonical URI is the percent-encoded path as sent. `Url` has already
/// removed dot segments while parsing, so `a/../b` is signed and requested as
/// `b`; the two agree, which is all the signature needs.
fn canonical_path(url: &Url) -> &str {
    let path = url.path();
    if path.is_empty() { "/" } else { path }
}

/// Lowercase names sorted, values trimmed with runs of whitespace collapsed,
/// repeated headers joined with commas.
fn canonical_headers(headers: &HeaderMap) -> (String, String) {
    let mut names: Vec<&str> = headers.keys().map(|n| n.as_str()).collect();
    names.sort_unstable();

    let mut canonical = String::new();
    for name in &names {
        let values: Vec<String> = headers
            .get_all(*name)
            .iter()
            .map(|v| {
                String::from_utf8_lossy(v.as_bytes())
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect();
        canonical.push_str(name);
        canonical.push(':');
        canonical.push_str(&values.join(","));
        canonical.push('\n');
    }
    (canonical, names.join(";"))
}

/// `(YYYYMMDD'T'HHMMSS'Z', YYYYMMDD)` for `now`, without a date-time crate.
fn amz_dates(now: SystemTime) -> (String, String) {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    let date_stamp = format!("{y:04}{m:02}{d:02}");
    let amz_date = format!(
        "{date_stamp}T{:02}{:02}{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    );
    (amz_date, date_stamp)
}

/// Days since 1970-01-01 → proleptic Gregorian `(year, month, day)`.
/// Howard Hinnant's `civil_from_days`.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Credentials and timestamp used by every worked example in the S3 API
    /// reference ("Signature Calculations for the Authorization Header").
    const CREDS: Credentials<'static> = Credentials {
        access_key: "AKIAIOSFODNN7EXAMPLE",
        secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        region: "us-east-1",
    };

    fn example_time() -> SystemTime {
        // 2013-05-24T00:00:00Z
        UNIX_EPOCH + Duration::from_secs(1_369_353_600)
    }

    fn signature_of(headers: &HeaderMap) -> String {
        headers[AUTHORIZATION]
            .to_str()
            .unwrap()
            .rsplit("Signature=")
            .next()
            .unwrap()
            .to_string()
    }

    #[test]
    fn get_object_matches_aws_example() {
        let url = Url::parse("https://examplebucket.s3.amazonaws.com/test.txt").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("range", HeaderValue::from_static("bytes=0-9"));
        sign_headers(
            "GET",
            &url,
            &mut headers,
            &sha256_hex(b""),
            &CREDS,
            example_time(),
        );
        assert_eq!(
            signature_of(&headers),
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
        assert!(
            headers[AUTHORIZATION]
                .to_str()
                .unwrap()
                .contains("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,")
        );
    }

    #[test]
    fn put_object_matches_aws_example() {
        let url = Url::parse("https://examplebucket.s3.amazonaws.com/test%24file.text").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "date",
            HeaderValue::from_static("Fri, 24 May 2013 00:00:00 GMT"),
        );
        headers.insert(
            "x-amz-storage-class",
            HeaderValue::from_static("REDUCED_REDUNDANCY"),
        );
        let body = b"Welcome to Amazon S3.";
        sign_headers(
            "PUT",
            &url,
            &mut headers,
            &sha256_hex(body),
            &CREDS,
            example_time(),
        );
        assert_eq!(
            signature_of(&headers),
            "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
        );
    }

    #[test]
    fn list_objects_matches_aws_example() {
        let query = encode_query(&[("prefix", "J".into()), ("max-keys", "2".into())]);
        assert_eq!(query, "max-keys=2&prefix=J");
        let url = Url::parse(&format!("https://examplebucket.s3.amazonaws.com/?{query}")).unwrap();
        let mut headers = HeaderMap::new();
        sign_headers(
            "GET",
            &url,
            &mut headers,
            &sha256_hex(b""),
            &CREDS,
            example_time(),
        );
        // Pinned from this implementation once the three vectors above
        // matched the reference; guards the query-string path against drift.
        assert_eq!(
            signature_of(&headers),
            "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
        );
    }

    #[test]
    fn presigned_get_matches_aws_example() {
        let url = Url::parse("https://examplebucket.s3.amazonaws.com/test.txt").unwrap();
        let signed = presign(
            "GET",
            &url,
            Duration::from_secs(86_400),
            &CREDS,
            example_time(),
        );
        assert_eq!(
            signed,
            "https://examplebucket.s3.amazonaws.com/test.txt\
             ?X-Amz-Algorithm=AWS4-HMAC-SHA256\
             &X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request\
             &X-Amz-Date=20130524T000000Z\
             &X-Amz-Expires=86400\
             &X-Amz-SignedHeaders=host\
             &X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
        );
    }

    #[test]
    fn non_default_port_is_part_of_the_host() {
        let url = Url::parse("http://localhost:9100/bucket/key").unwrap();
        assert_eq!(host_with_port(&url), "localhost:9100");
        let url = Url::parse("https://example.com:443/bucket/key").unwrap();
        assert_eq!(host_with_port(&url), "example.com");
    }

    #[test]
    fn repeated_headers_are_comma_joined_and_whitespace_collapsed() {
        let mut headers = HeaderMap::new();
        headers.append("x-test", HeaderValue::from_static("  a   b "));
        headers.append("x-test", HeaderValue::from_static("c"));
        headers.insert("host", HeaderValue::from_static("h"));
        let (canonical, signed) = canonical_headers(&headers);
        assert_eq!(canonical, "host:h\nx-test:a b,c\n");
        assert_eq!(signed, "host;x-test");
    }

    #[test]
    fn encode_key_keeps_slashes_and_encodes_everything_else() {
        assert_eq!(encode_key("a b/ü+c?.png"), "a%20b/%C3%BC%2Bc%3F.png");
        assert_eq!(encode_key("plain/key.txt"), "plain/key.txt");
    }

    #[test]
    fn encode_query_sorts_encoded_forms() {
        let q = encode_query(&[
            ("continuation-token", "a/b=c".into()),
            ("list-type", "2".into()),
            ("delete", String::new()),
        ]);
        assert_eq!(q, "continuation-token=a%2Fb%3Dc&delete=&list-type=2");
    }

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(15_849), (2013, 5, 24));
        assert_eq!(civil_from_days(20_089), (2025, 1, 1));
        let (amz, stamp) = amz_dates(UNIX_EPOCH + Duration::from_secs(1_369_353_600 + 45_296));
        assert_eq!(amz, "20130524T123456Z");
        assert_eq!(stamp, "20130524");
    }
}
