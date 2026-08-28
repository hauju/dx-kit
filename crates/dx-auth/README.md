# dx-auth

Authentication for a Dioxus fullstack app: a custom login UI driven against
FerrisKey's REST API, with sessions, CSRF, and rate limiting on the Axum side.

Login is OTP-first with auto-detection — the user types an email, and the crate
decides whether to challenge a passkey, ask for a password, or mail a one-time
code. FerrisKey is the identity provider; the login screen is yours.

```toml
[dependencies]
dx-auth = { git = "https://github.com/hauju/dx-kit.git", tag = "dx-auth-v0.4.1", features = ["server"] }
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

`auth_router` mounts, all `POST`:

```
/auth/logout
/auth/session/start                 email → passkey | password | OTP
/auth/session/passkey/verify
/auth/session/password/verify
/auth/session/otp/verify
/auth/session/otp/resend
/auth/session/captcha/verify        new-user registration (bollwark)
/auth/session/accept-tos
/auth/dev-login                     debug builds only
```

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
