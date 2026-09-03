# dx-auth

Authentication for a Dioxus fullstack app: a custom login UI driven against
FerrisKey's REST API, with sessions, CSRF, and rate limiting on the Axum side.

Login is OTP-first with auto-detection — the user types an email, and the crate
decides whether to challenge a passkey, ask for a password, or mail a one-time
code. FerrisKey is the identity provider; the login screen is yours.

```toml
[dependencies]
dx-auth = { git = "https://github.com/hauju/dx-kit.git", tag = "dx-auth-v0.5.0", features = ["server"] }
```

No default features. Enable `server` (Axum handlers, FerrisKey client, session
and rate-limit machinery), `web` (WASM passkey helpers), or both — a fullstack
app normally propagates both, and that union is what CI gates on.

## Storage stays in your app

The crate has no database dependency. It reaches storage through three traits:

| trait | what you implement |
|---|---|
| `AuthUserStore` | look up / create a user, update their `sub`, record TOS acceptance and logins, decide the post-login redirect |
| `AuthEmailSender` | deliver the OTP code (pair it with [`dx-smtp`](../dx-smtp)) |
| `AuthRateLimitStore` | a shared counter for rate limiting — see below |

`AuthUser.id` is a `String` on purpose: Mongo's `ObjectId::to_hex()` and
Postgres' `Uuid::to_string()` both round-trip through it, so the crate never
needs to know which one you run. ID validation belongs in your store impl.

## Wiring it up

```rust
use dx_auth::{auth_router, AuthConfig, AuthState, JwksCache};
use std::sync::Arc;

let config = AuthConfig {
    login_page_url: "/login".into(),
    default_post_login_url: "/dashboard".into(),
    ferriskey_url: std::env::var("FERRISKEY_URL")?,
    ferriskey_realm: "myapp".into(),
    ferriskey_client_id: "myapp-dashboard".into(),
    ferriskey_client_secret: std::env::var("FERRISKEY_CLIENT_SECRET").ok(),
    base_url: "https://app.example.com".into(),
    trust_proxy_headers: true, // only behind a proxy you control
    ..Default::default()
};

let state = AuthState {
    user_store: Arc::new(MyUserStore::new(db.clone())),
    email_sender: Arc::new(MyEmailSender::new(smtp.clone())),
    jwks_cache: Arc::new(JwksCache::new(
        &config.ferriskey_url,
        config.ferriskey_issuer_url.as_deref().unwrap_or(&config.ferriskey_url),
        &config.ferriskey_realm,
        &config.ferriskey_client_id,
    )),
    rate_limit_store: Some(Arc::new(MyRateLimitStore::new(db.clone()))),
};

let app = my_router
    .merge(auth_router(config, state))
    .layer(session_manager_layer); // tower-sessions, provided by your app
```

The router needs a `tower_sessions::Session` in the request extensions — mount
your `SessionManagerLayer` outside it, or every request fails with
`AuthError::AuthSessionLayerNotFound`.

On the UI side, render `LoginPage { redirect_url }` (pass `embed: true` to drop
the built-in page wrapper and card), and read the session back in server
functions with the `UserSession` extractor:

```rust
let user = user_session.data()?; // Err(AuthError::UserNotLoggedIn) if anonymous
```

`UserDataRefreshTrigger` is a context signal the login flow bumps on success, so
the shell can re-fetch user data instead of reloading the page — provide it via
`use_context_provider` above the page.

The login markup is Tailwind + DaisyUI (`card`, `base-200`, `loading-spinner`),
so it inherits the host app's DaisyUI theme rather than shipping its own CSS.

## Routes

`auth_router` mounts:

```
POST /auth/logout
POST /auth/session/start                 email → passkey | password | OTP
POST /auth/session/passkey/verify
POST /auth/session/password/verify
POST /auth/session/otp/verify
POST /auth/session/otp/resend
POST /auth/session/captcha/verify        new-user registration (bollwark)
POST /auth/session/accept-tos
POST /auth/dev-login                     debug builds only
GET  /auth/sso/start?next=               SSO mode only, see below
GET  /auth/callback
POST /auth/sso/complete
```

## SSO mode (browser redirect)

Apps sharing one FerrisKey realm can share one login. Set `sso_enabled: true`
and link the login page to `GET /auth/sso/start?next=/dashboard`. The browser
is sent to FerrisKey's hosted login page instead of the custom `LoginPage` and
comes back to `GET /auth/callback`, which serves a small page that redeems the
code **from the browser** and posts the id_token to `POST /auth/sso/complete`.
The app validates it (JWKS, audience, nonce) and opens the session like any
other login.

The exchange runs in the browser on purpose: FerrisKey sets its SSO cookie
(`FERRISKEY_IDENTITY`) on the token endpoint's response and nowhere else, so a
server-side exchange never gets it into the browser. With the cookie in place,
the next app's `/auth/sso/start` comes back with a code and no prompt — for as
long as the client's `access_token_lifetime`, which is what the cookie carries.
The PKCE verifier and the token response pass through the browser, as for any
public (SPA) client; the app only ever accepts an id_token with its own
audience and the nonce it minted for that session.

FerrisKey client checklist, one per app, all in the shared realm:

- **public** client with PKCE required — no secret is used in this mode
- redirect URI `{base_url}/auth/callback` (exact match)
- CORS for the browser's token request: on FerrisKey 0.7.x this is the
  server-wide `ALLOWED_ORIGINS` env of the API container (comma-separated; add
  `{base_url}`'s origin). Newer FerrisKey has per-client web origins instead,
  where `+` derives the origin from the redirect URI
- post-logout redirect URI `{base_url}{login_page_url}` (exact match; the
  root URL or a trailing slash won't do)
- `access_token_lifetime` = the silent-SSO window you want (realm default 300 s)
- users' emails marked verified, or an existing account cannot be re-bound to
  its new `sub` (see the security notes)
- no roles, scopes or mappers: the app reads `sub`, `email` and
  `email_verified` from the default `openid email profile` scope

`ferriskey_url` must be reachable from the browser. Logout redirects through
FerrisKey's end-session endpoint so the identity cookie is cleared; that only
works for a **top-level** `POST /auth/logout` (a form submit) — a `fetch`
follows the redirect without credentials and the cookie survives. Other apps'
local sessions are not ended; they expire on their own.

Set the tower-sessions cookie to `SameSite=Lax`. The login returns from
FerrisKey by a top-level redirect, and `Strict` withholds the cookie on any
cross-site navigation — which includes `localhost` against a hosted IdP — so
the callback finds no flow. dx-auth's origin check still covers the POSTs.

Two things to know when testing:

- **Silent SSO cannot be observed from `localhost`.** FerrisKey's identity
  cookie is `SameSite=Lax`, and browsers discard a Lax cookie delivered by a
  cross-site request; `localhost` → `auth.example` is cross-site, while
  `app.example` → `auth.example` is not. Logging in works locally, the
  no-prompt second login only shows on the deployed host.
- **A FerrisKey console session in the same browser breaks the flow** (0.7.x):
  the hosted login page restarts the OAuth request with its own random `state`
  and drops the nonce and PKCE challenge, so the callback answers
  `Login flow state mismatch`. Log out of the console and retry. The same
  happens after the page's 10-minute session refresh.

## Security notes

**Middleware order is load-bearing.** Axum applies the last `.layer()`
outermost, so CSRF origin checking runs *before* rate limiting. That is
deliberate: a cross-origin POST is rejected before it can consume a real user's
per-IP quota or reach the shared counter. If you re-layer the router, keep that
order.

**Rate limiting is 20 req/min per IP** (`AUTH_REQUESTS_PER_MINUTE`) across all
auth endpoints. `rate_limit_store: None` falls back to an in-process limiter,
which is fine for a single instance and wrong for several — N replicas allow N×
the quota. Wire a shared store before you scale out. The field is `Option` so
adopting the crate and wiring the backend can be separate commits.

**OTP and password attempt caps are enforced under a per-session lock,** with
the counter written back before the lock is released. Without that, parallel
requests carrying one cookie each read the same count and the cap is met once
per burst, not per request. The lock is in-process, so N replicas serving the
same cookie at once can overshoot by at most N passes — a bound set by your
deployment, not by the attacker.

**An id_token's email may only claim an existing account when the IdP marks it
`email_verified`.** An unverified match is refused with 401 rather than migrated
or duplicated, so a FerrisKey user whose address was never verified cannot log
into a local account that happens to share it. Email-OTP logins count as
verified by construction.

**`trust_proxy_headers` defaults to `false`.** Only turn it on behind a reverse
proxy you control; otherwise a client can spoof `X-Forwarded-For` and get a
fresh quota per request.

**Logout is `POST`,** so a cross-site `<img>` or link can't force it.

**`/auth/dev-login` is compiled out of release builds** (`#[cfg(debug_assertions)]`)
*and* additionally requires `DEV_LOGIN=true` at runtime.

**A captcha guards new-user registration**, using bollwark: set `CAPTCHA_URL`,
`CAPTCHA_SITE_KEY` and `CAPTCHA_SECRET_KEY` and the login page mounts the widget
in the email form, pre-solving while the user types; the token is verified
server-to-server and fails closed on a missing token, a rejection, or an
unreachable captcha server. With those vars unset there is no captcha and the
registration allowlist is the only gate — fine for an internal deployment,
not for a public one.

**reqwest is built on rustls**, not native-tls, to keep OpenSSL out of slim
runtime images.

## Hydration

With SSR the browser paints the login form fully styled long before the WASM
bundle lands. Until it does, no handler is attached — and a `<form>` whose
`onsubmit` hasn't attached still performs the browser's *native* submit on
Enter: a GET that reloads the page and discards the typed email.

`use_hydrated()` reports which side of that line the page is on; `LoginPage`
uses it to keep the controls in a `disabled` `<fieldset>` until interactive.
Gating only the submit button is not enough — it doesn't stop implicit
submission.

If the bundle takes too long, the page reveals a stall notice styled by a
`.hydration-stall` class your stylesheet is expected to define (a delayed
reveal, since if the bundle never arrives there is no Rust running to notice).
Without the class the notice just appears immediately; nothing breaks.

## Not in this crate yet

**A self-owned WebAuthn Relying Party.** Passkeys here are verified through
FerrisKey. Running your own RP instead — needed when FerrisKey's RP ID doesn't
match your origin, or when email-OTP accounts can't obtain the user JWT its
enrollment requires — is planned behind a `passkey-rp` feature. It is the seam
between "FerrisKey is the IdP" and "this app is its own IdP", and it wants
designing rather than bolting on.

## License

MIT — see [LICENSE](../../LICENSE).
