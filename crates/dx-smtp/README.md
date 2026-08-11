# dx-smtp

SMTP email transport over [lettre]. Pooled sync and async clients with retry,
backoff and timeouts, plus a one-shot sender for per-tenant relay credentials.

```toml
[dependencies]
dx-smtp = { git = "https://github.com/hauju/dx-kit.git", tag = "dx-smtp-v0.1.0" }
```

Optional `serde` feature derives `Serialize`/`Deserialize` on `SmtpSecurity` so
it can be persisted in per-tenant settings.

## Two ways to send

**The app's own sender** — build once, share it. The transport pools
connections and retries transient failures up to 3 attempts, backing off 1s then
2s.

```rust
use dx_smtp::{AsyncSmtpClient, AsyncSmtpClientImpl, Email, SmtpConfig, SmtpSecurity};
use secrecy::SecretString;

let client = AsyncSmtpClientImpl::new(SmtpConfig {
    from: "Acme <noreply@acme.test>".to_string(),
    host: "smtp.acme.test".to_string(),
    port: 587,
    user: SecretString::from("apikey"),
    password: SecretString::from(std::env::var("SMTP_PASSWORD")?),
    security: SmtpSecurity::StartTls,
})?;

client
    .send_email(
        Email::builder("user@example.com".parse()?)
            .subject("Welcome")
            .body("<p>Hello</p>")
            .build(),
    )
    .await?;
```

`SmtpClientImpl` is the blocking equivalent. Both take the config by value and
return `Result<Self>` — a hostname the relay builder can't use fails at
construction, not on the first send.

**A relay you were handed at request time** — `send_email_with(&config, email)`
builds a fresh transport, makes one bounded attempt, and does not retry. That is
deliberate: one customer's hung relay must not stall a shared queue.

## Transport security

`SmtpSecurity` is explicit, never inferred from the hostname:

| variant | conventional port | |
|---|---|---|
| `Tls` (default) | 465 | implicit TLS / SMTPS |
| `StartTls` | 587 | plaintext connection upgraded via STARTTLS |
| `None` | 1025 | no encryption, no auth — local dev relays like Mailpit only |

Picking plaintext by matching `host == "localhost"` is the bug this replaces: a
production relay reachable under that name would silently drop TLS. The
configured port is always passed through to the relay builder rather than
falling back to lettre's default.

Built on rustls with `webpki-roots`, so there's no OpenSSL in the build.

## Bulk mail and failure handling

`Email::builder(..).list_unsubscribe("<https://acme.test/u/abc>")` emits the
`List-Unsubscribe` and one-click `List-Unsubscribe-Post` headers required by the
Gmail/Yahoo bulk-sender rules. Leave it unset for transactional 1:1 mail.

`Error::is_permanent()` separates a 5xx reply or an invalid recipient address
(suppress the recipient) from a 4xx or a connection/TLS failure (try again
later). Every send is bounded by a 20s timeout.

## Tests

The unit tests need nothing. The integration suite in `tests/` is `#[ignore]`d
and expects a [Mailpit] instance on `localhost:1025`:

```
docker run -p 1025:1025 -p 8025:8025 axllent/mailpit
cargo test -p dx-smtp -- --ignored
```

[lettre]: https://docs.rs/lettre
[Mailpit]: https://mailpit.axllent.org

## License

MIT — see [LICENSE](../../LICENSE).
