# dx-s3

S3-compatible object storage without an SDK. One `S3Client` per bucket,
speaking Signature V4 directly over the same `reqwest` + rustls stack the
rest of the kit uses. Works against AWS, RustFS, MinIO, Cloudflare R2,
Contabo, Hetzner and anything else that implements the S3 API.

```toml
[dependencies]
dx-s3 = { git = "https://github.com/hauju/dx-kit.git", tag = "dx-s3-v0.1.0" }
```

No features. Bodies are in memory; multipart and streaming uploads are not
covered, nor are STS session tokens or bucket management.

## Use

```rust
use std::time::Duration;
use dx_s3::{PutOptions, S3Client, S3Config, content_disposition_inline};

let client = S3Client::new(
    S3Config::new("us-east-1", "media", "rustfsadmin", "rustfsadmin")
        .with_endpoint("http://localhost:9000")   // omit for AWS
        .with_force_path_style(true)              // RustFS, MinIO
        .with_path_prefix("blog"),                // this app's corner of the bucket
)?;
client.verify_connection().await?;                // fails on 403 / 404 / wrong region

client.put(
    "covers/1.png",
    bytes,
    PutOptions::content_type("image/png")
        .with_cache_control("public, max-age=31536000, immutable")
        .with_content_disposition(content_disposition_inline("Titelbild.png")),
).await?;

client.public_url("covers/1.png");                        // for <img src>
client.presign_get("covers/1.png", Duration::from_secs(600))?;
client.presign_put("uploads/direct.bin", Duration::from_secs(300))?; // browser → S3
client.get("covers/1.png").await?;                        // Bytes, or Error::NotFound
client.head("covers/1.png").await?;                       // size, content type, etag
client.exists("covers/1.png").await?;                     // Ok(false) only on a real 404
client.list("covers/").await?;                            // all pages, keys without the prefix
client.copy("covers/1.png", "covers/2.png").await?;       // server-side
client.delete("covers/1.png").await?;                     // idempotent
client.delete_many(&["a", "b"]).await?;                   // 1000 per request
client.delete_prefix("covers/").await?;                   // list + delete_many
client.copy_prefix("demos/1/", "demos/2/").await?;
```

Keys are relative to `path_prefix` in both directions: applied on every
request, stripped from every listing. The app never sees the prefix, which
is what makes sharing one bucket between apps safe.

## Config

| field | meaning |
|---|---|
| `endpoint` | `None` for AWS, else the service base URL (a path component is kept) |
| `region`, `bucket`, `access_key`, `secret_key` | the usual; `secret_key` is a `SecretString`, `Debug` redacts it |
| `path_prefix` | this app's prefix in the bucket |
| `force_path_style` | `host/bucket/key` instead of `bucket.host/key` — RustFS, MinIO, endpoints without a wildcard cert |
| `public_url_base` | bucket root for public reads when it differs from the API endpoint: a CDN, or Contabo's `https://eu2.contabostorage.com/<tenant>:<bucket>` |
| `connect_timeout`, `read_timeout` | 10 s and 30 s; the read timeout is per read, so long uploads are not capped |

Env-var loading stays in the app; the switch that decides whether uploads
are offered at all is an app decision.

## Errors

Classified by cause, not by operation:

- `NotFound { key }` — `get`, `head`, `copy` source. `exists` turns it into `Ok(false)`.
- `AccessDenied { status, message }` — 401/403, including `verify_connection` with wrong keys.
- `Status { status, code, message }` — any other non-2xx, with S3's `<Code>` when it sent one.
- `DeleteFailed { failed }` — a batch delete that S3 partly refused.
- `Transport` — connection, TLS, timeout.
- `InvalidConfig`, `InvalidArgument` — caught before any request goes out.

`Error::is_transient()` is true for transport errors, 5xx and 429. Every
request is already retried three times on those with 200 ms / 400 ms backoff;
all operations are idempotent, so that is safe.

## Why not rust-s3 or aws-sdk-s3

Four app copies were reviewed before this crate was written. Three wrapped
`rust-s3` with `default-features = false` to get rustls, which silently
drops its `fail-on-err` feature: every non-2xx comes back as `Ok`, and each
copy compensated in some places and not others. The template copy's
`file_exists` returned `true` for every key, `delete` never reported a
403, and `verify_connection` passed with wrong credentials. `rust-s3` also
pulls a second `reqwest` major, a second HTTP client for IMDS, an INI
parser and `sysinfo`. `aws-sdk-s3` is ~80 crates.

The fourth copy signed requests itself in ~250 lines. That signer, with its
SigV4 pitfalls fixed, is what this crate is built on; it adds `hmac`,
`sha2`, `md5` and `roxmltree` to a stack the app already has. Correctness
is pinned by the worked examples from the S3 API reference in
`src/signer.rs`.

Bugs fixed on the way in, all live in at least one app: non-ASCII filenames
failing the signature (`content_disposition_inline` emits the RFC 5987
form); `force_path_style` ignored for AWS; `public_url` not encoding keys;
the bucket missing from virtual-host URLs on custom endpoints; no timeouts;
no retries; secrets in `Debug` output.

## Testing

Unit tests need nothing. The integration tests run against any live
endpoint and clean up after themselves:

```sh
S3_ENDPOINT=http://localhost:9000 S3_BUCKET=dx-s3-test \
S3_ACCESS_KEY=rustfsadmin S3_SECRET_KEY=rustfsadmin \
cargo test -p dx-s3 --test rustfs_integration -- --ignored
```
