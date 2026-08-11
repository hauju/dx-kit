# dx-kit

Small, dependency-light Rust crates for SaaS backends — the pieces that every
app ends up re-implementing. Extracted from several apps that each carried their
own copy, so a fix lands once instead of once per app.

| crate | what it is |
|---|---|
| [`dx-crypto`](crates/dx-crypto) | secure random, Argon2 hashing, SHA-256 lookup hashes, API-key / CSRF / invitation tokens, PKCE `S256`, AES-256-GCM at rest |
| [`dx-smtp`](crates/dx-smtp) | Lettre-backed SMTP — pooled sync/async clients with retry and timeouts, plus a one-shot per-tenant sender |
| [`dx-auth`](crates/dx-auth) | FerrisKey OIDC, custom login UI (passkey / password / email-OTP), sessions, CSRF, rate limiting, and an optional self-owned WebAuthn Relying Party |

All are storage-agnostic: no database dependency, no ORM types in any public
signature. `dx-auth` reaches storage through the `AuthUserStore`,
`AuthEmailSender` and `AuthRateLimitStore` traits, which the host app
implements. Planned: billing and object storage.

## Using it

Depend on a tag, not a branch — the tag *is* the version:

```toml
[dependencies]
dx-crypto = { git = "https://github.com/hauju/dx-kit.git", tag = "dx-crypto-v0.1.0" }
dx-smtp   = { git = "https://github.com/hauju/dx-kit.git", tag = "dx-smtp-v0.1.0" }
dx-auth   = { git = "https://github.com/hauju/dx-kit.git", tag = "dx-auth-v0.2.0" }
```

`dx-auth` has no default features. Enable `server`, `web`, or both — apps
normally propagate both. Add `passkey-rp` to act as your own WebAuthn Relying
Party (see the design note below); it implies `server`.

CI checks each combination a real app ships, not just `--all-features`: an
optional feature is a configuration someone builds, and a misplaced `cfg` breaks
only that one.

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

### dx-auth

Reconciled from the six copies closest to `dx-saas-template`. The template copy
(byte-identical in mcpi) was the baseline and won almost everywhere; measured
drift was 0 for mcpi and 79–137 changed lines for dx-seo, mistral, dx-ideas,
cadence and dx-blog. Each decision:

- **`AuthRateLimitStore` is in, and it is why this extraction is worth doing.**
  Only 3 of 12 app copies had it; the other 9 fall back to an in-process
  limiter that allows N× the quota across N replicas. It stays a trait so the
  crate keeps no storage dependency, and `AuthState.rate_limit_store` is
  `Option` so an app can adopt the crate before wiring a backend.
- **`AUTH_REQUESTS_PER_MINUTE` as a named constant**, not the literal `20` five
  of the six copies inlined.
- **The layer-ordering comment is kept verbatim.** Axum applies the last
  `.layer()` outermost, so CSRF runs before rate limiting — deliberately, so a
  cross-origin POST is rejected before it can consume a real user's quota. That
  reasoning existed in one copy and is the kind of thing a reader silently
  "fixes" if it is not written down.
- **Hydration gating comes from dx-blog**, the one copy that had it. SSR paints
  the login form fully styled before the WASM bundle lands; a `<form>` whose
  `onsubmit` has not attached still does the browser's *native* submit on Enter,
  a GET that reloads the page and discards the typed email. `use_hydrated`
  plus a `disabled` `<fieldset>` closes that. cadence had a weaker inline
  version gating only the submit button, which does not stop implicit
  submission — the merge replaced it.
- **`handlers/dev_login.rs` is in**, `#[cfg(debug_assertions)]` and additionally
  gated on `DEV_LOGIN=true` at runtime. Four of the six copies had dropped it.
- **CAPTCHA stays an optional feature.** It is inert unless `CAPTCHA_*` is
  configured, because a shared crate must not require an external service to be
  usable.

#### The `passkey-rp` feature (v0.2.0)

Makes the app its own WebAuthn Relying Party: it runs the ceremonies and stores
credentials itself instead of proxying passkeys through the identity provider.

Needed because FerrisKey derives its RP ID from the IdP deployment's own origin,
which pins credentials there, and its enrollment endpoints require a FerrisKey
user JWT that email-OTP accounts can never obtain. An app whose accounts are
created by OTP therefore cannot offer passkeys at all through the IdP.

- **Additive, not an alternative.** seggwat runs its own RP *alongside* FerrisKey
  login — it has both `ferriskey/` and `webauthn.rs`. Enabling the feature does
  not commit you to dropping the IdP.
- **Scope is the RP core, not the login flow.** `webauthn.rs` imports nothing
  from the rest of the crate — options, registration and assertion verification
  are pure protocol code, which is why it can be shared without dragging session
  handling along. `session_auth.rs` differs by ~1,200 lines between the FerrisKey
  and self-owned architectures and is deliberately **not** part of this feature.
- **Off costs nothing.** `AuthState.passkey_store` and the two enroll routes only
  exist under the feature, so apps that leave it off compile unchanged and never
  link `ring` or `ciborium`.
- **Reconciled from seggwat and dx-admin**, whose copies were 842 lines apart by
  2 — a `seggwat_crypto::` vs `crypto::` rename. `passkey_enroll.rs` and
  `webauthn_helpers.rs` were byte-identical. dx-admin's trait docs won (they
  explain the sign-counter no-regress check and the `user_id` scoping that stops
  one user deleting another's credential); the browser globals were normalised
  from `window.__seggwat_*` to `window.__auth_*`, which dx-admin had inherited
  verbatim.
- **Brings the crate's only protocol tests** — 7 in `webauthn.rs`, covering RP-ID
  derivation and the verification paths.

The login page's hydration-stall notice expects a `.hydration-stall` CSS class
in the host app's stylesheet — a delayed reveal, since if the bundle never
arrives there is no Rust running to notice. Without the class the notice simply
shows immediately; nothing breaks.

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
