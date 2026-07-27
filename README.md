# dx-kit

Shared crates for the dx SaaS apps — seggwat, stepshots, infrapage, and
`dx-saas-template`. Extracted from the four copies that had drifted apart, so a
fix lands once instead of four times.

| crate | what it is |
|---|---|
| [`dx-crypto`](crates/dx-crypto) | secure random, Argon2 hashing, SHA-256 lookup hashes, API-key / CSRF / invitation tokens, PKCE `S256`, AES-256-GCM at rest |
| [`dx-smtp`](crates/dx-smtp) | Lettre-backed SMTP — pooled sync/async clients with retry and timeouts, plus a one-shot per-tenant sender |

Still to extract: `polar`, `storage`, `auth`.

## Using it

Depend on a tag, not a branch — the tag *is* the version:

```toml
[dependencies]
dx-crypto = { git = "ssh://git@github.com/hauju/dx-kit.git", tag = "dx-crypto-v0.1.0" }
dx-smtp   = { git = "ssh://git@github.com/hauju/dx-kit.git", tag = "dx-smtp-v0.1.0" }
```

If an app already has hundreds of `crypto::` / `smtp::` call sites, rename at the
dependency instead of touching them all:

```toml
crypto = { package = "dx-crypto", git = "ssh://git@github.com/hauju/dx-kit.git", tag = "dx-crypto-v0.1.0" }
```

### Developing the kit from inside an app

Point the git dependency at your local checkout with a gitignored
`.cargo/config.toml` in the consuming app:

```toml
[patch."ssh://git@github.com/hauju/dx-kit.git"]
dx-crypto = { path = "../../dx-kit/crates/dx-crypto" }
dx-smtp   = { path = "../../dx-kit/crates/dx-smtp" }
```

Edit in place, and cut a tag when the change settles. Because the patch lives in
an untracked file, CI still builds against the pinned tag.

### Releasing

Tag per crate so the four apps can move independently:

```
git tag dx-crypto-v0.2.0 && git push origin dx-crypto-v0.2.0
```

Bump `version` in the crate's `Cargo.toml` in the same commit as the change, so
the tag and the manifest agree.

## What changed during extraction

Each crate is the **union** of the four copies, not a straight copy of any one
of them. The notable reconciliations:

### dx-crypto

- **rand 0.9** everywhere (seggwat was already there; the others were on 0.8).
  Argon2 salting now uses argon2's own `rand_core` re-export, so the module no
  longer cares which `rand` major version the crate is on.
- **One PKCE implementation.** There were three: `pkce_s256_matches` (template,
  non-constant-time), `verify_pkce_s256` (stepshots, constant-time), and
  `pkce_s256_challenge` (infrapage). Kept the constant-time comparison and the
  challenge builder; `pkce_s256_matches` survives as a `#[deprecated]` alias so
  existing call sites still compile.
- **Custom API-key prefixes.** `generate_api_key` still mints `oat_` keys, so
  existing keys keep validating. `generate_prefixed_api_key("ipk_")` and
  `prefixed_api_key_prefix` let a project use its own brand without forking the
  crate. `API_KEY_PREFIX_LEN` keeps its old value of 12.
- **`hash_api_key`** (was infrapage's `sha256.rs`) is now available everywhere,
  with docs on when to reach for it over Argon2.
- **AES-GCM nonce handling** takes seggwat's version, which validates the nonce
  length on decrypt instead of panicking on a short input.

### dx-smtp

- **`SmtpSecurity` replaces `insecure: bool`** and no longer lives in
  `seggwat-core` — that dependency was the only thing keeping this crate from
  being shared. It gained a `None` variant, which is what `insecure: true`
  used to mean.
- **No more magic hostnames.** infrapage and seggwat branched on
  `host == "mailpit" || host == "localhost"` to pick a plaintext transport. That
  is now an explicit `SmtpSecurity::None`, so a production relay that happens to
  be reachable as `localhost` can't silently drop TLS.
- **STARTTLS works.** The template could only do implicit TLS; port-587 relays
  needed seggwat's `starttls_relay` branch. Both are supported, and the
  configured port is now actually passed to the relay builder rather than
  falling back to lettre's default.
- **Pooling + retry, from the template.** seggwat and infrapage rebuilt the
  transport on every send and never retried. The clients now build once and
  retry transient failures with exponential backoff.
- **Timeouts, `List-Unsubscribe`, and `Error::is_permanent`**, from seggwat.
  Every send is bounded by 20s; bulk mail can carry one-click unsubscribe
  headers for the Gmail/Yahoo bulk-sender rules; callers can tell a 5xx from a
  4xx to decide whether to suppress a recipient.
- **`send_email_with`** is the per-tenant path: fresh transport, single bounded
  attempt, no retry, so one hung customer relay can't stall a shared queue.

## Migration notes

Adopting these is not a drop-in for every app — the reconciliations above change
some signatures:

- `SmtpConfig { insecure: true }` → `SmtpConfig { security: SmtpSecurity::None }`
  (template, stepshots).
- `SmtpClientImpl::new(config)` now returns `Result<Self>` for seggwat and
  infrapage, which previously got a bare `Self`.
- seggwat's `smtp::SmtpSecurity` re-export from `seggwat-core` should be deleted
  and the domain type re-pointed at `dx_smtp::SmtpSecurity` (enable the `serde`
  feature to keep it serializable).
- infrapage's `crypto::sha256::pkce_s256_challenge` moved to
  `dx_crypto::pkce_s256_challenge`; `hash_api_key` stays put.
