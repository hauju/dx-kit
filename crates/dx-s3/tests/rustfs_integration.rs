//! Integration tests against a live S3-compatible endpoint (RustFS, MinIO, …).
//!
//! Prerequisites: a reachable bucket and these env vars —
//! `S3_ENDPOINT`, `S3_BUCKET`, `S3_ACCESS_KEY`, `S3_SECRET_KEY`
//! (`S3_REGION` defaults to `us-east-1`; path-style addressing is assumed).
//!
//! ```sh
//! S3_ENDPOINT=http://localhost:9000 S3_BUCKET=dx-s3-test \
//! S3_ACCESS_KEY=rustfsadmin S3_SECRET_KEY=rustfsadmin \
//! cargo test -p dx-s3 --test rustfs_integration -- --ignored
//! ```
//!
//! Every test works under its own random prefix and cleans up after itself.

use std::time::Duration;

use dx_s3::{Error, PutOptions, S3Client, S3Config, content_disposition_inline};

fn config() -> S3Config {
    let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"));
    S3Config::new(
        std::env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".into()),
        var("S3_BUCKET"),
        var("S3_ACCESS_KEY"),
        var("S3_SECRET_KEY"),
    )
    .with_endpoint(var("S3_ENDPOINT"))
    .with_force_path_style(true)
}

/// A client scoped to a fresh prefix, so tests never see each other's keys.
fn scoped_client() -> S3Client {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    S3Client::new(config().with_path_prefix(format!("dx-s3-test/{nonce}"))).unwrap()
}

#[tokio::test]
#[ignore = "requires a live S3 endpoint (see module docs)"]
async fn verify_connection_succeeds_and_rejects_bad_credentials() {
    scoped_client().verify_connection().await.unwrap();

    let mut bad = config();
    bad.access_key = "wrong".into();
    bad.secret_key = "wrong".into();
    let bad = S3Client::new(bad).unwrap();
    assert!(matches!(
        bad.verify_connection().await,
        Err(Error::AccessDenied { .. })
    ));

    let mut missing = config();
    missing.bucket = "dx-s3-no-such-bucket".into();
    let missing = S3Client::new(missing).unwrap();
    assert!(matches!(
        missing.verify_connection().await,
        Err(Error::Status { status: 404, .. } | Error::AccessDenied { .. })
    ));
}

#[tokio::test]
#[ignore = "requires a live S3 endpoint (see module docs)"]
async fn put_get_head_exists_delete_round_trip() {
    let client = scoped_client();
    let key = "dir with space/Größe ü+#?.png";
    let body = b"\x89PNG not really".to_vec();

    assert!(!client.exists(key).await.unwrap());
    assert!(matches!(
        client.get(key).await,
        Err(Error::NotFound { key: k }) if k == key
    ));

    client
        .put(
            key,
            body.clone(),
            PutOptions::content_type("image/png")
                .with_cache_control("public, max-age=60")
                .with_content_disposition(content_disposition_inline("Größe.png")),
        )
        .await
        .unwrap();

    assert!(client.exists(key).await.unwrap());
    let meta = client.head(key).await.unwrap();
    assert_eq!(meta.size, body.len() as u64);
    assert_eq!(meta.content_type.as_deref(), Some("image/png"));
    assert!(meta.etag.is_some());
    assert_eq!(client.get(key).await.unwrap().as_ref(), body.as_slice());

    // The public URL points at the object we just wrote.
    let url = client.public_url(key);
    let resp = reqwest::get(&url).await.unwrap();
    assert!(
        resp.status().is_success() || resp.status() == 403,
        "public_url {url} answered {}",
        resp.status()
    );

    client.delete(key).await.unwrap();
    assert!(!client.exists(key).await.unwrap());
    // Idempotent.
    client.delete(key).await.unwrap();
}

#[tokio::test]
#[ignore = "requires a live S3 endpoint (see module docs)"]
async fn list_paginates_and_strips_the_prefix() {
    let client = scoped_client();
    let keys: Vec<String> = (0..5).map(|i| format!("pages/{i}.txt")).collect();
    for key in &keys {
        client.put(key, "x", PutOptions::default()).await.unwrap();
    }
    client
        .put("other/1.txt", "x", PutOptions::default())
        .await
        .unwrap();

    let mut listed: Vec<String> = client
        .list_paged("pages/", 2)
        .await
        .unwrap()
        .into_iter()
        .map(|o| o.key)
        .collect();
    listed.sort();
    assert_eq!(listed, keys);

    let all = client.list("").await.unwrap();
    assert_eq!(all.len(), 6);
    assert!(all.iter().all(|o| o.size == 1));

    assert_eq!(client.delete_prefix("pages/").await.unwrap(), 5);
    assert_eq!(client.list("pages/").await.unwrap().len(), 0);
    assert_eq!(client.delete_prefix("").await.unwrap(), 1);
}

#[tokio::test]
#[ignore = "requires a live S3 endpoint (see module docs)"]
async fn delete_many_tolerates_missing_keys() {
    let client = scoped_client();
    client
        .put("a.txt", "a", PutOptions::default())
        .await
        .unwrap();
    client
        .delete_many(&["a.txt", "never-existed.txt"])
        .await
        .unwrap();
    assert!(!client.exists("a.txt").await.unwrap());
    client.delete_many::<&str>(&[]).await.unwrap();
}

#[tokio::test]
#[ignore = "requires a live S3 endpoint (see module docs)"]
async fn copy_and_copy_prefix_are_server_side() {
    let client = scoped_client();
    client
        .put(
            "src/a b.txt",
            "hello",
            PutOptions::content_type("text/plain"),
        )
        .await
        .unwrap();
    client
        .put("src/nested/c.txt", "world", PutOptions::default())
        .await
        .unwrap();

    client.copy("src/a b.txt", "dst/a b.txt").await.unwrap();
    assert_eq!(client.get("dst/a b.txt").await.unwrap().as_ref(), b"hello");
    assert_eq!(
        client
            .head("dst/a b.txt")
            .await
            .unwrap()
            .content_type
            .as_deref(),
        Some("text/plain")
    );

    assert!(matches!(
        client.copy("src/missing.txt", "dst/x").await,
        Err(Error::NotFound { .. })
    ));

    assert_eq!(client.copy_prefix("src/", "copy/").await.unwrap(), 2);
    let mut copied: Vec<String> = client
        .list("copy/")
        .await
        .unwrap()
        .into_iter()
        .map(|o| o.key)
        .collect();
    copied.sort();
    assert_eq!(copied, ["copy/a b.txt", "copy/nested/c.txt"]);

    client.delete_prefix("").await.unwrap();
}

#[tokio::test]
#[ignore = "requires a live S3 endpoint (see module docs)"]
async fn presigned_urls_work_without_credentials() {
    let client = scoped_client();
    let http = reqwest::Client::new();

    let put_url = client
        .presign_put("direct/upload ü.bin", Duration::from_secs(120))
        .unwrap();
    let resp = http
        .put(&put_url)
        .header("content-type", "application/octet-stream")
        .body("uploaded by the browser")
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "presigned PUT: {}",
        resp.status()
    );

    let get_url = client
        .presign_get("direct/upload ü.bin", Duration::from_secs(120))
        .unwrap();
    let resp = http.get(&get_url).send().await.unwrap();
    assert!(
        resp.status().is_success(),
        "presigned GET: {}",
        resp.status()
    );
    assert_eq!(resp.text().await.unwrap(), "uploaded by the browser");

    // Tampering with the key invalidates the signature.
    let resp = http
        .get(get_url.replace("upload", "other"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    client.delete("direct/upload ü.bin").await.unwrap();
}
