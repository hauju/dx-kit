# dx-kit

Small, dependency-light Rust crates for SaaS backends — the pieces that every
app ends up re-implementing. Extracted from several apps that each carried their
own copy, so a fix lands once instead of once per app.

| crate | what it is |
|---|---|
| [`dx-crypto`](crates/dx-crypto) | secure random, Argon2 hashing, SHA-256 lookup hashes, API-key / CSRF / invitation tokens, PKCE `S256`, AES-256-GCM at rest |
| [`dx-smtp`](crates/dx-smtp) | Lettre-backed SMTP — pooled sync/async clients with retry and timeouts, plus a one-shot per-tenant sender |

Both are storage-agnostic: no database dependency, no ORM types in any public
signature. Planned: billing, object storage, and auth crates.

## Using it

Depend on a tag, not a branch — the tag *is* the version:

```toml
[dependencies]
dx-crypto = { git = "https://github.com/hauju/dx-kit.git", tag = "dx-crypto-v0.1.0" }
dx-smtp   = { git = "https://github.com/hauju/dx-kit.git", tag = "dx-smtp-v0.1.0" }
```

If your app already has hundreds of `crypto::` / `smtp::` call sites, rename at
the dependency instead of touching them all:

```toml
crypto = { package = "dx-crypto", git = "https://github.com/hauju/dx-kit.git", tag = "dx-crypto-v0.1.0" }
```

### Developing the kit from inside an app

Point the git dependency at your local checkout with a gitignored
`.cargo/config.toml` in the consuming app:

```toml
[patch."https://github.com/hauju/dx-kit.git"]
dx-crypto = { path = "../../dx-kit/crates/dx-crypto" }
dx-smtp   = { path = "../../dx-kit/crates/dx-smtp" }
```

Edit in place, and cut a tag when the change settles. Because the patch lives in
an untracked file, CI still builds against the pinned tag.

### Releasing

Tag per crate so consumers can move independently:

```
git tag dx-crypto-v0.2.0 && git push origin dx-crypto-v0.2.0
```

Bump `version` in the crate's `Cargo.toml` in the same commit as the change, so
the tag and the manifest agree.

## Design notes

Where the source copies disagreed, the kit takes the safer option rather than
the most common one.

### dx-crypto

- **rand 0.9.** Argon2 salting uses argon2's own `rand_core` re-export, so the
  module does not care which `rand` major version the crate is on.
- **One PKCE implementation.** `verify_pkce_s256` compares in constant time;
  `pkce_s256_challenge` builds the challenge. `pkce_s256_matches` remains as a
  `#[deprecated]` alias for existing call sites.
- **Custom API-key prefixes.** `generate_api_key` mints `oat_` keys;
  `generate_prefixed_api_key("ipk_")` and `prefixed_api_key_prefix` let a
  project use its own prefix without forking the crate. `API_KEY_PREFIX_LEN`
  is 12.
- **`hash_api_key`** is a SHA-256 lookup hash for high-volume credential
  lookups, with docs on when to reach for it over Argon2.
- **AES-GCM nonce handling** validates the nonce length on decrypt instead of
  panicking on short input.

### dx-smtp

- **`SmtpSecurity` instead of `insecure: bool`.** Transport security is an
  explicit enum (`Tls`, `StartTls`, `None`) with no domain types from any app.
- **No magic hostnames.** Plaintext transport is only ever selected by
  `SmtpSecurity::None`, never inferred from the host — so a production relay
  that happens to be reachable as `localhost` cannot silently drop TLS.
- **Implicit TLS and STARTTLS both supported**, and the configured port is
  passed through to the relay builder rather than falling back to lettre's
  default.
- **Pooling + retry.** Clients build the transport once and retry transient
  failures with exponential backoff.
- **Timeouts, `List-Unsubscribe`, and `Error::is_permanent`.** Every send is
  bounded by 20s; bulk mail can carry one-click unsubscribe headers for the
  Gmail/Yahoo bulk-sender rules; callers can tell a 5xx from a 4xx to decide
  whether to suppress a recipient.
- **`send_email_with`** is the per-tenant path: fresh transport, single bounded
  attempt, no retry, so one hung customer relay cannot stall a shared queue.

## Coming from your own copy?

If you are replacing a hand-rolled copy of either crate, these are the
signatures most likely to differ:

- `SmtpConfig { insecure: true }` → `SmtpConfig { security: SmtpSecurity::None }`.
- `SmtpClientImpl::new(config)` returns `Result<Self>`, not a bare `Self`.
- `SmtpSecurity` lives in `dx_smtp`; enable the `serde` feature to keep it
  serializable in persisted settings.
- `pkce_s256_challenge` and `hash_api_key` are exported from the `dx_crypto`
  root, not from submodules.

## License

MIT — see [LICENSE](LICENSE).
