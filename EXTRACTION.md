# Crate extraction — status and plan

Working notes for pulling the crates duplicated across seggwat, stepshots,
infrapage, and `dx-saas-template` into this repo. Read [README.md](README.md)
first for how to *use* the kit; this file is about the migration itself.

Last updated: 2026-07-28.

---

## Where things stand

| phase | crates | status |
|---|---|---|
| 1 | `dx-crypto`, `dx-smtp` | **done** — extracted, merged, tested, committed locally |
| 2 | `polar` | not started |
| 3 | `storage` | not started |
| 4 | `auth` | not started |

Phase 1 is committed on `main` (`8d6be31`). CI workflow is written but has never
run. 40 unit tests + 15 doctests pass; `cargo clippy --workspace --all-targets
--all-features -- -D warnings` and `cargo fmt --all --check` are clean.

### Open items blocking progress

1. **No git remote.** The repo is local-only. `hauju/dx-kit` does not exist on
   GitHub yet — needs creating, then `git remote add origin`, then push.
2. **No tags.** Cut `dx-crypto-v0.1.0` and `dx-smtp-v0.1.0` once the remote
   exists. Nothing can depend on the kit until then.
3. **No app migrated.** All four still build against their own copies. Nothing
   has been deleted from any app — this repo is purely additive so far.

### Suggested next step

Wire **stepshots** against a local path patch and get it building. It's the
cheapest first migration: its `smtp` copy was 3 lines off the template and its
`crypto` copy 99. Proves the whole loop before touching a remote.

---

## Decisions already made

**Distribution: git dependencies pinned by tag**, against this single repo. Not
crates.io (code is private, and the APIs are still moving), not a workspace with
path deps (four separate app repos, CI would break), not a private registry
(overkill for one dev). The tag is the version; apps upgrade independently.

**Local development uses `[patch]`**, via a gitignored `.cargo/config.toml` in
the consuming app — see README. CI still builds against the pinned tag because
the patch file is untracked.

**Crates are the union of all four copies**, never a straight copy of one. The
template is generally the most refined, but seggwat carried real improvements
the template lacked. Every reconciliation is documented in the README.

**Migration is one-way.** Once an app adopts a kit crate, its local copy under
`crates/` gets deleted. No period of keeping both in sync.

**Naming: `dx-` prefix, `dx_` in code.** Apps with many call sites can rename at
the dependency (`crypto = { package = "dx-crypto", ... }`) to avoid touching
them — see README.

---

## The database constraint

The apps do not share a database. seggwat, stepshots and infrapage are on
**MongoDB**; `dx-saas-template` is on **sqlx/Postgres**, and newer projects will
be Postgres too.

This turned out to cost nothing, because the crates were already DB-free. Audited
2026-07-28 across all four copies:

- No shared crate depends on `mongodb`, `bson`, `sqlx`, `sea-orm`, or `diesel`.
- No `ObjectId`, `bson`, `_id`, or `rename = "_id"` anywhere in their sources.
- `AuthUser.id` is `String` in all four; every auth trait method takes `&str`
  for IDs.
- `auth` contains no timestamp type at all — `AuthTosAcceptance` is
  `{ latest_version: String, accepted: bool }`.
- No shared crate ships migrations, SQL, or schema.
- `storage` is S3-compatible object storage (`reqwest` + `hmac` SigV4), not a
  database. `polar` is a REST client plus `standardwebhooks` verification with
  no persistence.

### Rules that follow

**`dx-auth` must never gain a DB dependency — not even behind a feature flag.**
A `#[cfg(feature = "mongo")]` inside it forks the crate internally and makes
every Postgres app carry dead code and a resolver hazard. The
`AuthUserStore` / `AuthEmailSender` / `AuthRateLimitStore` traits are the seam;
keep the DB on the app side of it.

**Keep `id: String`.** It is permissive on purpose — Mongo's
`ObjectId::to_hex()` and Postgres' `Uuid::to_string()` both round-trip cleanly.
Making `dx-auth` generic over `Id: FromStr + Display` infects every signature
and every trait impl to buy nothing. ID validation belongs in the app's store
impl.

**Any shared Mongo code goes in a separate `dx-auth-mongo` crate**, depending on
`dx-auth`, never a feature of it — so the Postgres side never links it. Three
apps are about to write near-identical Mongo `AuthRateLimitStore` TTL-index
counters, which is the obvious first candidate. Decide after the trait side is
extracted and the three implementations can be compared side by side.

---

## Measured drift (2026-07-28)

Changed lines vs the `dx-saas-template` copy, `diff -ru`, ignoring `target/`.
Re-measure before starting a phase; the apps are still moving.

| crate | LOC | seggwat | stepshots | infrapage |
|---|---|---|---|---|
| `crypto` | ~800 | 202 | 99 | 88 |
| `smtp` | ~330 | 252 | 3 | 166 |
| `polar` | ~2.1k | 814 | 208 | 417 |
| `storage` | 0.6–1.5k | 733 | 172 | *(absent)* |
| `auth` | ~4.5k | 1659 | 143 | 568 |

Lineage, from doc comments and missing features: seggwat → stepshots →
infrapage → generalized into the template. stepshots' `auth/traits.rs` still
says *"decouple the auth crate from `seggwat-app`"*. seggwat is the oldest copy
and the furthest behind, but also carries the most unique improvements.

Toolchain is aligned across all four, which is what makes any of this feasible:
edition 2024, dioxus 0.7.9, axum 0.8, sqlx 0.8 (template only).

---

## Remaining phases

### Phase 2 — `polar`

Identical file layout in all four (`client.rs`, `config.rs`, `error.rs`,
`lib.rs`, `types.rs`, `webhook.rs`). No DB, no persistence.

**Blocking change: product IDs are baked into `PolarConfig` as named struct
fields.** Template has `solo_monthly_product_id` / `solo_yearly_product_id`;
infrapage renamed both to `pro_*` and added `claim_product_id` for a one-time
purchase. Every new plan forces a fork. Replace with a map keyed by plan slug
before extracting, or the crate cannot be shared.

Check during extraction: whether webhook idempotency/dedupe is handled inside
the crate (it should not be — that's app-side persistence).

### Phase 3 — `storage`

S3-compatible object storage. Template and stepshots share the same five
modules; **seggwat has an extra `signer.rs`** (presigned URLs) — fold it in as a
cargo feature or just include it, it has no extra deps beyond `hmac`.
infrapage has no storage crate at all.

### Phase 4 — `auth`

The big one, ~4.5k LOC, and the only crate touching user data. Do it last, once
the workflow is boring.

Divergence is genuine, not cosmetic:

- seggwat has `middleware.rs` the others lack.
- seggwat lacks `csrf.rs` and `rate_limit.rs` the others have.
- Template alone has `handlers/dev_login.rs` and the `AuthRateLimitStore` trait
  (the fallback in-process limiter allows N× quota across N replicas).
- stepshots is missing `AuthRateLimitStore` entirely.

Payoff is real — seggwat gains CSRF and the distributed rate limiter it is
currently missing. Cost is real too; budget it separately from phases 2–3.

---

## Gotchas found in phase 1

Worth expecting again in later phases:

- **Doc-test crate paths.** Copied files carry `use crypto::` / `use
  seggwat_crypto::` in their `# Example` blocks. They compile as doctests and
  fail loudly — grep and rewrite to `dx_*` when moving files.
- **Field names drift silently.** `EmailAttachment.data` vs `.content` — an
  easy thing to get wrong when reconstructing a merged file from memory rather
  than from the source. Diff the merged file against its origin before trusting
  it.
- **`#[deprecated]` aliases warn through `pub use`.** Needs `#[allow(deprecated)]`
  on the re-export in `lib.rs`, or clippy `-D warnings` fails CI.
- **rustfmt reorders `use` statements** after a scripted rename. Run
  `cargo fmt --all` before checking.
- **Merging can surface real bugs.** Phase 1 found two in smtp: plaintext
  transport selected by matching `host == "localhost"`, and the configured port
  never passed to the relay builder (so port-587 STARTTLS was unreachable).
  Expect the same when reconciling `auth`, and treat each one as a finding to
  report rather than a silent fix.
