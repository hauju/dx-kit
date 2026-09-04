//! Shared helpers for OIDC and Session API login flows.

use crate::config::AuthConfig;
use crate::error::{AuthError, AuthResult};
use crate::state::AuthState;
use crate::types::{AuthUser, NewAuthUser};
use tracing::{info, warn};

/// Session key for storing the post-login redirect URL.
pub(crate) const LOGIN_REDIRECT_URL_SESSION_KEY: &str = "login.redirect.url";

/// User info extracted from OIDC userinfo or FerrisKey session.
#[derive(serde::Deserialize)]
#[allow(dead_code)]
pub struct AuthUserInfo {
    pub sub: String,
    pub nickname: Option<String>,
    pub name: Option<String>,
    pub email: String,
    /// Whether ownership of `email` has been proven — by our own OTP, or by
    /// the IdP's `email_verified` claim. Gates the by-email account migration
    /// in [`lookup_or_create_user`]: an unverified address must not be able to
    /// claim an existing account.
    #[serde(default)]
    pub email_verified: bool,
    pub picture: Option<String>,
    pub preferred_username: Option<String>,
}

/// Validate redirect URL to prevent open redirect attacks.
/// Only allows relative paths starting with `/` (no protocol-relative `//`).
///
/// Browsers normalize `\` to `/` while parsing an authority, so `/\evil.com`
/// reaches the same off-site host that `//evil.com` would — reject both forms.
pub(crate) fn is_safe_redirect_url(url: &str) -> bool {
    let mut chars = url.chars();
    chars.next() == Some('/') && !matches!(chars.next(), Some('/' | '\\'))
}

/// Quick email-format check. Returns `true` for plausibly-deliverable addresses.
///
/// Catches the common garbage we've seen hit downstream mailers: missing/multiple
/// `@`, empty or over-long parts, consecutive dots, leading/trailing dots, and
/// domains with no TLD. This is intentionally a shape check — not an RFC 5321
/// parser — just enough to reject input before we spend cycles on CAPTCHA, OTP
/// generation, and SMTP.
pub fn is_valid_email(email: &str) -> bool {
    if email.len() < 3 || email.len() > 320 {
        return false;
    }

    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };

    // Exactly one '@'
    if domain.contains('@') {
        return false;
    }

    if local.is_empty() || local.len() > 64 {
        return false;
    }
    if domain.is_empty() || domain.len() > 255 {
        return false;
    }

    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return false;
    }
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return false;
    }

    // Domain must have a TLD
    if !domain.contains('.') {
        return false;
    }

    // Rough character sanity — local part allows RFC-5322 atext + dot;
    // domain is limited to LDH (letters, digits, hyphen, dot).
    let local_ok = local
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b".!#$%&'*+/=?^_`{|}~-.".contains(&b));
    if !local_ok {
        return false;
    }

    let domain_ok = domain
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
    if !domain_ok {
        return false;
    }

    // No label may start/end with hyphen or be empty
    domain
        .split('.')
        .all(|label| !label.is_empty() && !label.starts_with('-') && !label.ends_with('-'))
}

/// Look up user by sub or email, migrate sub if needed, create if new.
/// Shared between OIDC callback and Session API login flows.
pub async fn lookup_or_create_user(
    auth_state: &AuthState,
    info: &AuthUserInfo,
) -> AuthResult<AuthUser> {
    // First try by OIDC subject ID (already migrated users)
    let user_by_sub = auth_state
        .user_store
        .get_user_by_sub(&info.sub)
        .await
        .map_err(|e| {
            warn!("Error fetching user by OIDC sub: {:?}", e);
            AuthError::ServerStateError("Failed to fetch user".to_string())
        })?;

    if let Some(user) = user_by_sub {
        info!("Existing user logged in (matched by sub)");
        return Ok(user);
    }

    // Try to find by email (IdP migration case, e.g. Auth0/Zitadel -> FerrisKey)
    let user_by_email = auth_state
        .user_store
        .get_user_by_email(&info.email)
        .await
        .map_err(|e| {
            warn!("Error fetching user by email: {:?}", e);
            AuthError::ServerStateError("Failed to fetch user".to_string())
        })?;

    if let Some(existing_user) = user_by_email {
        // Matching by address hands this login the existing account, so the
        // address has to be proven. Refused outright rather than treated as a
        // new user: a second account under the same address would only
        // collide in the host's store.
        if !info.email_verified {
            warn!(
                "Refusing to migrate user {} to sub {}: email not verified by the IdP",
                existing_user.id, info.sub
            );
            return Err(AuthError::Unauthorized(
                "This email address has not been verified".to_string(),
            ));
        }

        info!(
            "Migrating user {} from old IdP to FerrisKey (updating sub)",
            existing_user.id
        );

        auth_state
            .user_store
            .update_user_sub(&existing_user.id, &info.sub)
            .await
            .map_err(|e| {
                warn!("Error updating user sub: {:?}", e);
                AuthError::ServerStateError("Failed to migrate user".to_string())
            })?;

        info!("Successfully migrated user sub to FerrisKey");

        return Ok(AuthUser {
            sub: info.sub.clone(),
            ..existing_user
        });
    }

    // Completely new user - create them
    info!("User not found, creating new user...");

    let user = auth_state
        .user_store
        .create_user(NewAuthUser {
            sub: info.sub.clone(),
            email: info.email.clone(),
        })
        .await
        .map_err(|e| {
            warn!("Error creating user: {:?}", e);
            AuthError::ServerStateError("Failed to create user".to_string())
        })?;

    info!("New user created successfully");

    // Create a personal organization for the new user
    if let Err(e) = auth_state
        .user_store
        .create_personal_organization(&user.id, &info.email)
        .await
    {
        warn!("Failed to create personal organization: {:?}", e);
    } else {
        info!("Created personal organization for new user");
    }

    Ok(user)
}

/// Check subscriptions and determine redirect URL after login.
/// Shared between OIDC callback and Session API login flows.
pub async fn determine_post_login_redirect(
    auth_state: &AuthState,
    auth_config: &AuthConfig,
    session: &tower_sessions::Session,
    user: &AuthUser,
) -> AuthResult<String> {
    // Check for a stored redirect URL in the session first
    let session_redirect = session
        .remove::<String>(LOGIN_REDIRECT_URL_SESSION_KEY)
        .await?
        .filter(|url| is_safe_redirect_url(url));

    // Delegate to the trait impl for org/subscription logic
    let redirect = auth_state
        .user_store
        .determine_post_login_redirect(&user.id, &auth_config.default_post_login_url)
        .await?;

    // Session redirect takes priority if the trait returned the default
    if redirect == auth_config.default_post_login_url
        && let Some(url) = session_redirect
    {
        return Ok(url);
    }

    Ok(redirect)
}

// ── Registration gate ───────────────────────────────────────────────

/// Whether a not-yet-registered `email` may create an account.
///
/// Registration is the one place an unauthenticated caller can cross into the
/// trust boundary, so it is closed by default. An operator opens it with an
/// allowlist of exact addresses and/or domains; when neither is configured,
/// registration is permitted only while no user exists yet (first-run
/// bootstrap) and refused afterwards, so a fresh deployment is usable without
/// configuration but does not stay open to the internet.
pub(super) async fn registration_allowed(
    auth_state: &AuthState,
    auth_config: &AuthConfig,
    email: &str,
) -> AuthResult<bool> {
    let emails = &auth_config.allowed_registration_emails;
    let domains = &auth_config.allowed_registration_domains;

    // Only the no-allowlist bootstrap path needs to know whether users exist,
    // so avoid the query when an allowlist is configured.
    let has_users = if emails.is_empty() && domains.is_empty() {
        auth_state.user_store.has_any_users().await?
    } else {
        false
    };

    Ok(registration_permitted(emails, domains, email, has_users))
}

/// Pure allowlist decision, split out so it can be unit-tested without a store.
///
/// `email` is assumed already trimmed and lowercased (as `start_session` does).
/// `has_users` is consulted only when both allowlists are empty.
fn registration_permitted(
    emails: &[String],
    domains: &[String],
    email: &str,
    has_users: bool,
) -> bool {
    if emails.is_empty() && domains.is_empty() {
        // No allowlist configured: allow the very first account, then close.
        return !has_users;
    }

    if emails.iter().any(|allowed| allowed == email) {
        return true;
    }

    matches!(
        email.rsplit('@').next(),
        Some(domain) if domains.iter().any(|allowed| allowed == domain)
    )
}

#[cfg(test)]
mod tests {
    use super::{
        AuthUserInfo, is_safe_redirect_url, is_valid_email, lookup_or_create_user,
        registration_permitted,
    };
    use crate::error::{AuthError, AuthResult};
    use crate::state::AuthState;
    use crate::traits::{AuthEmailSender, AuthUserStore};
    use crate::types::{AuthTosAcceptance, AuthUser, NewAuthUser};
    use std::sync::{Arc, Mutex};

    /// A store holding one user, reachable by sub and/or by email, that records
    /// the writes the login path makes.
    #[derive(Default)]
    struct OneUserStore {
        by_sub: Option<AuthUser>,
        by_email: Option<AuthUser>,
        sub_updates: Mutex<Vec<(String, String)>>,
        created: Mutex<Vec<NewAuthUser>>,
    }

    #[async_trait::async_trait]
    impl AuthUserStore for OneUserStore {
        async fn get_user_by_sub(&self, _sub: &str) -> AuthResult<Option<AuthUser>> {
            Ok(self.by_sub.clone())
        }
        async fn get_user_by_email(&self, _email: &str) -> AuthResult<Option<AuthUser>> {
            Ok(self.by_email.clone())
        }
        #[cfg(feature = "local-login")]
        async fn get_user_by_id(&self, _id: &str) -> AuthResult<Option<AuthUser>> {
            Ok(None)
        }
        async fn create_user(&self, user: NewAuthUser) -> AuthResult<AuthUser> {
            self.created.lock().unwrap().push(user.clone());
            Ok(AuthUser {
                id: "new".to_string(),
                sub: user.sub,
                email: user.email,
                display_name: None,
                tos_acceptance: None,
            })
        }
        async fn update_user_sub(&self, user_id: &str, new_sub: &str) -> AuthResult<()> {
            self.sub_updates
                .lock()
                .unwrap()
                .push((user_id.to_string(), new_sub.to_string()));
            Ok(())
        }
        async fn create_personal_organization(&self, _: &str, _: &str) -> AuthResult<()> {
            Ok(())
        }
        async fn update_tos_acceptance(&self, _: &str, _: AuthTosAcceptance) -> AuthResult<()> {
            Ok(())
        }
        async fn determine_post_login_redirect(&self, _: &str, d: &str) -> AuthResult<String> {
            Ok(d.to_string())
        }
    }

    struct NoMail;

    #[async_trait::async_trait]
    impl AuthEmailSender for NoMail {
        async fn send_verification_code(&self, _: &str, _: &str, _: u32) -> AuthResult<()> {
            Ok(())
        }
    }

    #[cfg(feature = "passkey-rp")]
    struct NoPasskeys;

    #[cfg(feature = "passkey-rp")]
    #[async_trait::async_trait]
    impl crate::traits::AuthPasskeyStore for NoPasskeys {
        async fn list_passkeys(&self, _: &str) -> AuthResult<Vec<crate::traits::StoredPasskey>> {
            Ok(Vec::new())
        }
        async fn find_passkey_by_credential_id(
            &self,
            _: &str,
        ) -> AuthResult<Option<crate::traits::StoredPasskey>> {
            Ok(None)
        }
        async fn insert_passkey(&self, _: &str, _: crate::traits::NewPasskey) -> AuthResult<()> {
            Ok(())
        }
        async fn touch_passkey(&self, _: &str, _: i64, _: bool) -> AuthResult<()> {
            Ok(())
        }
        async fn delete_passkey(&self, _: &str, _: &str) -> AuthResult<bool> {
            Ok(false)
        }
    }

    fn state(store: Arc<OneUserStore>) -> AuthState {
        AuthState {
            user_store: store,
            email_sender: Arc::new(NoMail),
            jwks_cache: Arc::new(crate::jwt::JwksCache::new(
                "http://localhost:3333",
                "http://localhost:3333",
                "realm",
                "client",
            )),
            rate_limit_store: None,
            #[cfg(feature = "passkey-rp")]
            passkey_store: Arc::new(NoPasskeys),
        }
    }

    fn victim() -> AuthUser {
        AuthUser {
            id: "victim-id".to_string(),
            sub: "old-idp|victim".to_string(),
            email: "victim@example.com".to_string(),
            display_name: None,
            tos_acceptance: None,
        }
    }

    fn login_as(sub: &str, email_verified: bool) -> AuthUserInfo {
        AuthUserInfo {
            sub: sub.to_string(),
            nickname: None,
            name: None,
            email: "victim@example.com".to_string(),
            email_verified,
            picture: None,
            preferred_username: None,
        }
    }

    #[tokio::test]
    async fn unverified_email_cannot_claim_an_existing_account() {
        // An IdP identity whose email merely *matches* an existing account —
        // and which the IdP has not verified — must not become that account.
        let store = Arc::new(OneUserStore {
            by_email: Some(victim()),
            ..Default::default()
        });

        let result =
            lookup_or_create_user(&state(store.clone()), &login_as("attacker", false)).await;

        assert!(matches!(result, Err(AuthError::Unauthorized(_))));
        assert!(store.sub_updates.lock().unwrap().is_empty());
        assert!(store.created.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn verified_email_migrates_the_existing_account() {
        let store = Arc::new(OneUserStore {
            by_email: Some(victim()),
            ..Default::default()
        });

        let user = lookup_or_create_user(&state(store.clone()), &login_as("fk|victim", true))
            .await
            .unwrap();

        assert_eq!(user.id, "victim-id");
        assert_eq!(user.sub, "fk|victim");
        assert_eq!(
            *store.sub_updates.lock().unwrap(),
            vec![("victim-id".to_string(), "fk|victim".to_string())]
        );
    }

    #[tokio::test]
    async fn sub_match_needs_no_email_verification() {
        // Once the account is keyed by this sub, the email claim is not consulted.
        let store = Arc::new(OneUserStore {
            by_sub: Some(victim()),
            ..Default::default()
        });

        let user = lookup_or_create_user(&state(store.clone()), &login_as("old-idp|victim", false))
            .await
            .unwrap();

        assert_eq!(user.id, "victim-id");
        assert!(store.sub_updates.lock().unwrap().is_empty());
    }

    #[test]
    fn accepts_normal_emails() {
        assert!(is_valid_email("user@example.com"));
        assert!(is_valid_email("a.b.c@sub.example.co.uk"));
        assert!(is_valid_email("user+tag@example.com"));
    }

    #[test]
    fn rejects_consecutive_dots() {
        // The real-world address that triggered this check.
        assert!(!is_valid_email("q.u.i.n.t.on..kellam@gmail.com"));
        assert!(!is_valid_email("a..b@example.com"));
        assert!(!is_valid_email("a@example..com"));
    }

    #[test]
    fn rejects_malformed() {
        assert!(!is_valid_email(""));
        assert!(!is_valid_email("no-at-sign"));
        assert!(!is_valid_email("two@at@signs.com"));
        assert!(!is_valid_email(".leading@example.com"));
        assert!(!is_valid_email("trailing.@example.com"));
        assert!(!is_valid_email("user@nodotdomain"));
        assert!(!is_valid_email("user@-bad.com"));
        assert!(!is_valid_email("user@bad-.com"));
    }

    #[test]
    fn redirect_url_allows_only_relative_paths() {
        assert!(is_safe_redirect_url("/"));
        assert!(is_safe_redirect_url("/dashboard"));
        assert!(is_safe_redirect_url("/demos/abc?tab=1"));

        assert!(!is_safe_redirect_url(""));
        assert!(!is_safe_redirect_url("//evil.com"));
        assert!(!is_safe_redirect_url("https://evil.com"));
        assert!(!is_safe_redirect_url("dashboard"));
        // Browsers read `\` as `/` in the authority, so these are off-site too.
        assert!(!is_safe_redirect_url("/\\evil.com"));
        assert!(!is_safe_redirect_url("/\\/evil.com"));
    }

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn no_allowlist_permits_only_the_first_account() {
        // Fresh deployment (no users yet): the first registration is allowed.
        assert!(registration_permitted(&[], &[], "first@example.com", false));
        // Once a user exists, registration closes.
        assert!(!registration_permitted(
            &[],
            &[],
            "second@example.com",
            true
        ));
    }

    #[test]
    fn email_allowlist_is_exact_match() {
        let emails = v(&["ops@example.com"]);
        assert!(registration_permitted(
            &emails,
            &[],
            "ops@example.com",
            true
        ));
        // A different address is refused even though a user already exists is irrelevant here.
        assert!(!registration_permitted(
            &emails,
            &[],
            "intruder@example.com",
            false
        ));
        // No substring or suffix matching.
        assert!(!registration_permitted(
            &emails,
            &[],
            "notops@example.com",
            false
        ));
    }

    #[test]
    fn domain_allowlist_matches_the_part_after_the_at() {
        let domains = v(&["example.com"]);
        assert!(registration_permitted(
            &[],
            &domains,
            "anyone@example.com",
            true
        ));
        assert!(!registration_permitted(
            &[],
            &domains,
            "anyone@evil.com",
            false
        ));
        // A domain that is only a suffix of the address's domain must not match.
        assert!(!registration_permitted(
            &[],
            &domains,
            "anyone@notexample.com",
            false
        ));
    }

    #[test]
    fn a_configured_allowlist_ignores_the_bootstrap_rule() {
        // With an allowlist set, has_users is not consulted: a non-listed address
        // is refused even on a brand-new instance with no users.
        let emails = v(&["ops@example.com"]);
        assert!(!registration_permitted(
            &emails,
            &[],
            "someone@example.com",
            false
        ));
    }

    #[test]
    fn email_and_domain_allowlists_combine() {
        let emails = v(&["contractor@other.com"]);
        let domains = v(&["example.com"]);
        assert!(registration_permitted(
            &emails,
            &domains,
            "staff@example.com",
            true
        ));
        assert!(registration_permitted(
            &emails,
            &domains,
            "contractor@other.com",
            true
        ));
        assert!(!registration_permitted(
            &emails,
            &domains,
            "stranger@other.com",
            true
        ));
    }
}
