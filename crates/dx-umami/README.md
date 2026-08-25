# dx-umami

Self-hosted [Umami](https://umami.is) analytics, the way the dx apps run it:
a same-origin proxy for the tracker plus a thin client bridge. Extracted from
four apps (stepshots, infrapage, bollwark, seggwat) that each carried their own
copy.

```toml
[dependencies]
dx-umami = { git = "https://github.com/hauju/dx-kit.git", tag = "dx-umami-v0.1.0" }
```

## Why a proxy at all

`umami.*` hostnames are on the standard ad-block filter lists (EasyPrivacy,
uBlock's built-ins), so a cross-origin tracker tag is never fetched for a large
share of visitors — and the failure is invisible: the page works, the numbers
are quietly wrong. Serving the script from your own origin at `/stats.js`
sidesteps that.

**Both routes are required.** The tracker derives its collect endpoint from its
own `src` — `https://example.com/stats.js` posts to
`https://example.com/api/send`. Proxying the script without the collect
endpoint is worse than not proxying: the script loads and every event 404s.

The forwarder passes `X-Forwarded-For` upstream. Umami derives country and the
daily visitor hash from the client IP; a proxy that drops it hands Umami the
*server's* address for every visitor, collapsing unique visitors and putting
the whole audience in one country. (Three of the four original app copies had
this bug.)

## Server (feature `server`)

```rust
// unit-state router:
router.merge(dx_umami::proxy::routes());
// or mount the handlers yourself:
router
    .route("/stats.js", get(dx_umami::proxy::script))
    .route("/api/send", post(dx_umami::proxy::collect));
```

`UMAMI_HOST` is the switch (e.g. `https://umami.example.com`). Unset, both
routes 404 and the tag fails harmlessly — which is also what keeps local
development out of the production statistics. The script is cached in-process
for an hour and served stale on upstream failure.

## Client bridge (target-gated, no feature)

Compiles to no-ops off wasm, so shared code calls it unconditionally.

```rust
// The app keeps its own typed event enum; the bridge takes name + props.
dx_umami::track("checkout_completed", Some(HashMap::from([
    ("user_id".into(), PropValue::Str(dx_umami::hash_id(&user.id))),
    ("revenue".into(), PropValue::Num(29.0)), // must be a JS number for Umami's revenue report
    ("currency".into(), PropValue::Str("EUR".into())),
])));

// Tie the session to a (hashed!) user id — unlocks per-user
// Sessions/Retention/Journeys reports. Retries until the tracker loads.
dx_umami::identify(&dx_umami::hash_id(&user.id), &[("plan", "pro")]);

// For apps that learn the website id at runtime; apps with a compile-time id
// can render the <script defer src="/stats.js" data-website-id=…> tag directly.
dx_umami::mount_script(&website_id);
```
