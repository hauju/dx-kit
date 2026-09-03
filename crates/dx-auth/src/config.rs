/// Configuration for auth routes, redirects, and FerrisKey integration.
///
/// Replaces all reads from `AppState.config.*` and `AppState.secrets.*`
/// that the auth crate previously needed.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// URL for the login page (e.g. "/login")
    pub login_page_url: String,
    /// Default redirect after login (e.g. "/org/redirect" or "/dashboard")
    pub default_post_login_url: String,
    /// Dev login page URL (e.g. "/dev/login")
    pub dev_login_url: String,

    // ── FerrisKey configuration ─────────────────────────────────────
    /// FerrisKey base API URL (e.g. "http://localhost:3333")
    pub ferriskey_url: String,
    /// FerrisKey public issuer base URL. If unset, derived from
    /// `ferriskey_url` by stripping a trailing `/api`.
    pub ferriskey_issuer_url: Option<String>,
    /// FerrisKey realm name (e.g. "myapp")
    pub ferriskey_realm: String,
    /// FerrisKey OIDC client ID (e.g. "myapp-dashboard")
    pub ferriskey_client_id: String,
    /// FerrisKey OIDC client secret. Required for authorization-code
    /// exchange and the client-credentials grant used for service-account
    /// calls (user lookup/create).
    pub ferriskey_client_secret: Option<String>,

    // ── Application URLs ───────────────────────────────────────────
    /// Base URL where the dashboard is deployed (e.g. "https://example.com")
    pub base_url: String,
    /// Whether auth rate limiting may trust X-Forwarded-For, X-Real-IP, and
    /// Forwarded headers from an upstream reverse proxy.
    pub trust_proxy_headers: bool,

    // ── SSO (browser-redirect login) ──────────────────────────────
    /// Mount the browser-redirect login routes (`GET /auth/sso/start`,
    /// `GET /auth/callback`, `POST /auth/sso/complete`) and end the FerrisKey
    /// session on logout. The browser is sent to FerrisKey's hosted login page
    /// and completes the code exchange itself, which is what puts FerrisKey's
    /// `FERRISKEY_IDENTITY` cookie in the browser: the next app in the same
    /// realm then logs in without a prompt.
    ///
    /// Requires `ferriskey_client_id` to be a **public** FerrisKey client (no
    /// secret is used), `ferriskey_url` to be reachable from the browser, and
    /// on the client: `{base_url}/auth/callback` as a redirect URI, web origin
    /// `+`, and `{base_url}{login_page_url}` as a post-logout redirect URI.
    pub sso_enabled: bool,

    // ── Registration allowlist ─────────────────────────────────────
    /// Exact, lowercased email addresses permitted to self-register.
    /// Empty means no address allowlist (see [`crate::AuthConfig`] docs on the
    /// bootstrap behaviour when both allowlists are empty).
    pub allowed_registration_emails: Vec<String>,
    /// Lowercased email domains (the part after `@`) permitted to self-register.
    /// Empty means no domain allowlist.
    pub allowed_registration_domains: Vec<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            login_page_url: "/login".to_string(),
            default_post_login_url: "/dashboard".to_string(),
            dev_login_url: "/dev/login".to_string(),
            ferriskey_url: String::new(),
            ferriskey_issuer_url: None,
            ferriskey_realm: String::new(),
            ferriskey_client_id: String::new(),
            ferriskey_client_secret: None,
            base_url: "http://localhost:8080".to_string(),
            trust_proxy_headers: false,
            sso_enabled: false,
            allowed_registration_emails: Vec::new(),
            allowed_registration_domains: Vec::new(),
        }
    }
}
