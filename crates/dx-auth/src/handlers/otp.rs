//! Email-OTP machinery shared by both login back-ends.
//!
//! The FerrisKey flow (`session_auth`) and the self-owned flow (`local_login`)
//! mint, mail and verify the code the same way; only what they do with a
//! verified address differs. Keeping the code here means the attempt cap, the
//! recipient binding and the session lock are fixed once.

use subtle::ConstantTimeEq;
use tracing::{info, warn};

use crate::error::{AuthError, AuthResult};
use crate::state::AuthState;

// ── Session keys ─────────────────────────────────────────────────────

pub(super) const CUSTOM_OTP_CODE_KEY: &str = "custom_otp.code";
/// The address the code was actually mailed to. An OTP proves ownership of this
/// address and of nothing else, so verification resolves the user from *this*
/// key — never from `login.email`, which any later /session/start overwrites.
pub(super) const CUSTOM_OTP_EMAIL_KEY: &str = "custom_otp.email";
pub(super) const CUSTOM_OTP_EXPIRES_AT_KEY: &str = "custom_otp.expires_at";
pub(super) const CUSTOM_OTP_PURPOSE_KEY: &str = "custom_otp.purpose";
pub(super) const CUSTOM_OTP_ATTEMPTS_KEY: &str = "custom_otp.attempts";
pub(super) const MAX_OTP_ATTEMPTS: u32 = 5;

// OTP resend throttle
pub(super) const CUSTOM_OTP_LAST_SENT_AT_KEY: &str = "custom_otp.last_sent_at";
pub(super) const CUSTOM_OTP_RESEND_COUNT_KEY: &str = "custom_otp.resend_count";
pub(super) const RESEND_COOLDOWN_SECONDS: i64 = 30;
pub(super) const MAX_RESEND_COUNT: u32 = 5;

// ── Per-session attempt-counter serialisation ───────────────────────
//
// tower-sessions hands every request its own copy of the session record and
// writes it back when the response completes. Two concurrent requests carrying
// the same cookie therefore both read `attempts = n` and both write `n + 1`,
// so a burst of parallel guesses meets the cap once instead of per request.
// Holding a per-session lock across the read, the compare and an explicit
// `save` closes that window in-process. Replicas do not share the lock, so
// the same cookie serviced by N replicas at once can overshoot by at most N
// passes — bounded by the deployment, not by the attacker's request count.
//
// Striped rather than per-id so the table never grows: unrelated sessions
// that share a stripe only wait on each other for the few store round-trips
// the guarded section performs.

const SESSION_LOCK_STRIPES: usize = 64;
static SESSION_LOCKS: [tokio::sync::Mutex<()>; SESSION_LOCK_STRIPES] =
    [const { tokio::sync::Mutex::const_new(()) }; SESSION_LOCK_STRIPES];

/// Lock the stripe for this session.
///
/// Must be taken before the handler's first read of the session: tower-sessions
/// loads the record lazily and then keeps that copy for the rest of the
/// request, so a read before the lock is a read of stale state.
pub(super) async fn lock_session(
    session: &tower_sessions::Session,
) -> tokio::sync::MutexGuard<'static, ()> {
    let stripe = session
        .id()
        .map(|id| (id.0.unsigned_abs() % SESSION_LOCK_STRIPES as u128) as usize)
        .unwrap_or(0);
    SESSION_LOCKS[stripe].lock().await
}

/// Write the session back to the store now, rather than when the response
/// completes, so the next request for this cookie loads what this one wrote.
/// A request with no session has nothing to race over, and saving would only
/// mint an empty record per request.
pub(super) async fn persist_now(session: &tower_sessions::Session) -> AuthResult<()> {
    if session.id().is_some() {
        session.save().await?;
    }
    Ok(())
}

// ── Bollwark captcha (optional, env-configured) ─────────────────────
//
// When all three vars are set, new-user registration is gated by the bollwark
// widget: the login page pre-solves the widget invisibly inside the email form
// and forwards its token, which we verify server-to-server. Absent or partial
// config means registration is gated by the allowlist alone, so local dev
// needs no captcha deployment.

pub(super) struct CaptchaCfg {
    pub(super) server_url: String,
    pub(super) site_key: String,
    secret_key: String,
}

pub(super) fn captcha_cfg() -> Option<CaptchaCfg> {
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    Some(CaptchaCfg {
        server_url: env("CAPTCHA_URL")?,
        site_key: env("CAPTCHA_SITE_KEY")?,
        secret_key: env("CAPTCHA_SECRET_KEY")?,
    })
}

/// Pooled client for the verify call; the timeout caps how long an unreachable
/// captcha server can stall a registration submit.
fn captcha_client() -> &'static reqwest::Client {
    use std::sync::OnceLock;
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("captcha verify client")
    })
}

/// Forward the widget token to bollwark's `POST /v1/verify`.
///
/// Returns `Ok(true)` on a verified pass, `Ok(false)` on an explicit
/// rejection, and `Err` when the captcha server is unreachable. Registration
/// is fail-closed: the caller blocks on both `false` and `Err`.
pub(super) async fn verify_captcha_token(cfg: &CaptchaCfg, token: &str) -> AuthResult<bool> {
    let resp = captcha_client()
        .post(format!(
            "{}/v1/verify",
            cfg.server_url.trim_end_matches('/')
        ))
        .bearer_auth(&cfg.secret_key)
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .map_err(|e| {
            warn!(error = ?e, "captcha verify request failed");
            AuthError::ServerStateError("captcha verify request failed".to_string())
        })?;

    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    let success = body
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !status.is_success() || !success {
        warn!(status = %status, "captcha verify rejected");
        return Ok(false);
    }
    Ok(true)
}

// ── Mint, mail, verify ──────────────────────────────────────────────

pub(super) async fn generate_and_send_otp(
    auth_state: &AuthState,
    session: &tower_sessions::Session,
    email: &str,
    purpose: &str,
) -> AuthResult<()> {
    let code = crypto::generate_numeric_otp(6)
        .map_err(|e| AuthError::ServerStateError(format!("Failed to generate OTP: {}", e)))?;

    let expires_at = chrono::Utc::now().timestamp() + 600;
    session.insert(CUSTOM_OTP_CODE_KEY, &code).await?;
    session.insert(CUSTOM_OTP_EMAIL_KEY, email).await?;
    session
        .insert(CUSTOM_OTP_EXPIRES_AT_KEY, expires_at)
        .await?;
    session.insert(CUSTOM_OTP_PURPOSE_KEY, purpose).await?;
    session.insert(CUSTOM_OTP_ATTEMPTS_KEY, 0u32).await?;

    auth_state
        .email_sender
        .send_verification_code(email, &code, 10)
        .await
        .map_err(|e| {
            AuthError::ServerStateError(format!("Failed to send verification email: {}", e))
        })?;

    session
        .insert(CUSTOM_OTP_LAST_SENT_AT_KEY, chrono::Utc::now().timestamp())
        .await?;

    let count = session
        .get::<u32>(CUSTOM_OTP_RESEND_COUNT_KEY)
        .await
        .unwrap_or(None)
        .unwrap_or(0);
    session
        .insert(CUSTOM_OTP_RESEND_COUNT_KEY, count + 1)
        .await?;

    info!(to = %email, purpose = %purpose, "Sent OTP verification code");
    Ok(())
}

/// Wipe the in-flight OTP record. Every field goes together: a code that
/// outlives the address it was bound to is exactly the state that let one
/// address's OTP be verified against another address's account.
pub(super) async fn clear_otp_state(session: &tower_sessions::Session) {
    let _ = session.remove::<String>(CUSTOM_OTP_CODE_KEY).await;
    let _ = session.remove::<String>(CUSTOM_OTP_EMAIL_KEY).await;
    let _ = session.remove::<i64>(CUSTOM_OTP_EXPIRES_AT_KEY).await;
    let _ = session.remove::<String>(CUSTOM_OTP_PURPOSE_KEY).await;
    let _ = session.remove::<u32>(CUSTOM_OTP_ATTEMPTS_KEY).await;
}

/// Verify a submitted code against the in-flight OTP and return the address the
/// code was mailed to. Callers must resolve the user from the returned email —
/// it is the only address this OTP proves anything about.
async fn verify_otp_from_session(
    session: &tower_sessions::Session,
    submitted_code: &str,
) -> std::result::Result<String, String> {
    let stored_code = session
        .get::<String>(CUSTOM_OTP_CODE_KEY)
        .await
        .map_err(|_| "Session error".to_string())?
        .ok_or_else(|| "No verification code in progress".to_string())?;

    let bound_email = session
        .get::<String>(CUSTOM_OTP_EMAIL_KEY)
        .await
        .map_err(|_| "Session error".to_string())?
        .ok_or_else(|| "No verification code in progress".to_string())?;

    let expires_at = session
        .get::<i64>(CUSTOM_OTP_EXPIRES_AT_KEY)
        .await
        .map_err(|_| "Session error".to_string())?
        .ok_or_else(|| "No verification code in progress".to_string())?;

    if chrono::Utc::now().timestamp() > expires_at {
        clear_otp_state(session).await;
        return Err("Verification code has expired. Please request a new one.".to_string());
    }

    let attempts = session
        .get::<u32>(CUSTOM_OTP_ATTEMPTS_KEY)
        .await
        .map_err(|_| "Session error".to_string())?
        .unwrap_or(0);

    if attempts >= MAX_OTP_ATTEMPTS {
        clear_otp_state(session).await;
        return Err(
            "Too many failed attempts. Please request a new verification code.".to_string(),
        );
    }

    if submitted_code
        .as_bytes()
        .ct_eq(stored_code.as_bytes())
        .unwrap_u8()
        != 1
    {
        let _ = session.insert(CUSTOM_OTP_ATTEMPTS_KEY, attempts + 1).await;
        return Err("Invalid verification code. Please try again.".to_string());
    }

    clear_otp_state(session).await;

    Ok(bound_email)
}

/// [`verify_otp_from_session`] under the session lock, with the attempt
/// counter persisted before the lock is released. See [`SESSION_LOCKS`].
pub(super) async fn verify_otp_guarded(
    session: &tower_sessions::Session,
    submitted_code: &str,
) -> AuthResult<std::result::Result<String, String>> {
    let _guard = lock_session(session).await;
    let outcome = verify_otp_from_session(session, submitted_code).await;
    persist_now(session).await?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::{
        CUSTOM_OTP_ATTEMPTS_KEY, CUSTOM_OTP_CODE_KEY, CUSTOM_OTP_EMAIL_KEY,
        CUSTOM_OTP_EXPIRES_AT_KEY, MAX_OTP_ATTEMPTS, verify_otp_guarded,
    };
    use std::sync::Arc;
    use tower_sessions::session::{Id, Record};
    use tower_sessions::{MemoryStore, Session, SessionStore, session_store};

    /// A store whose loads take long enough that every request in a burst
    /// reads the record before any of them writes it back — the interleaving
    /// production hits when parallel requests carry one cookie.
    #[derive(Debug, Default)]
    struct SlowStore(MemoryStore);

    #[async_trait::async_trait]
    impl SessionStore for SlowStore {
        async fn save(&self, record: &Record) -> session_store::Result<()> {
            self.0.save(record).await
        }
        async fn load(&self, id: &Id) -> session_store::Result<Option<Record>> {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            self.0.load(id).await
        }
        async fn delete(&self, id: &Id) -> session_store::Result<()> {
            self.0.delete(id).await
        }
    }

    #[tokio::test]
    async fn parallel_otp_guesses_cannot_exceed_the_attempt_cap() {
        let store = Arc::new(SlowStore::default());

        let seed = Session::new(None, store.clone(), None);
        seed.insert(CUSTOM_OTP_CODE_KEY, "123456").await.unwrap();
        seed.insert(CUSTOM_OTP_EMAIL_KEY, "a@example.com")
            .await
            .unwrap();
        seed.insert(
            CUSTOM_OTP_EXPIRES_AT_KEY,
            chrono::Utc::now().timestamp() + 600,
        )
        .await
        .unwrap();
        seed.insert(CUSTOM_OTP_ATTEMPTS_KEY, 0u32).await.unwrap();
        seed.save().await.unwrap();
        let id = seed.id().unwrap();

        // Twenty requests in flight at once, each with its own handle on the
        // same cookie — the shape tower-sessions gives concurrent requests.
        let tasks: Vec<_> = (0..20)
            .map(|_| {
                let session = Session::new(Some(id), store.clone(), None);
                tokio::spawn(async move { verify_otp_guarded(&session, "000000").await.unwrap() })
            })
            .collect();

        let mut evaluated = 0;
        for task in tasks {
            match task.await.unwrap() {
                Err(msg) if msg.starts_with("Invalid verification code") => evaluated += 1,
                Err(_) => {} // cap reached, or the code already cleared by it
                Ok(email) => panic!("wrong code accepted for {email}"),
            }
        }
        assert_eq!(evaluated, MAX_OTP_ATTEMPTS as usize);
    }
}
