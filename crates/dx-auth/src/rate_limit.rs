//! IP-based rate limiting middleware for auth endpoints.
//!
//! Uses `governor` for per-IP keyed rate limiting.
//! By default the key is the socket peer IP. Reverse-proxy headers are only
//! trusted when `AuthConfig::trust_proxy_headers` is enabled.

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;

use axum::{
    Extension,
    extract::{ConnectInfo, Request},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use governor::{Quota, RateLimiter, state::keyed::DefaultKeyedStateStore};

use crate::config::AuthConfig;
use crate::state::AuthState;

/// Requests allowed per IP per minute across all auth endpoints.
///
/// Shared by both backends so the in-process fallback and the
/// [`crate::AuthRateLimitStore`] path enforce the same number.
pub const AUTH_REQUESTS_PER_MINUTE: u32 = 20;

/// Keyed rate limiter: one bucket per IP string.
type KeyedLimiter =
    RateLimiter<String, DefaultKeyedStateStore<String>, governor::clock::DefaultClock>;

/// Wrapper so we can put it in an `Extension`.
#[derive(Clone)]
pub struct AuthRateLimiter {
    inner: Arc<KeyedLimiter>,
}

/// How often idle per-IP buckets are reclaimed. Governor's keyed store never shrinks on its own,
/// so without this every client IP the process has ever seen occupies an entry until restart.
const KEY_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

impl AuthRateLimiter {
    /// Create a new rate limiter allowing `per_minute` requests per IP per minute.
    pub fn new(per_minute: u32) -> Self {
        let quota = Quota::per_minute(NonZeroU32::new(per_minute).expect("per_minute must be > 0"));
        let inner = Arc::new(RateLimiter::keyed(quota));

        // The task holds a Weak, so it stops on its own once the limiter is dropped.
        let weak = Arc::downgrade(&inner);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(KEY_SWEEP_INTERVAL);
            loop {
                ticker.tick().await;
                match weak.upgrade() {
                    Some(limiter) => limiter.retain_recent(),
                    None => return,
                }
            }
        });

        Self { inner }
    }
}

/// Extract the client IP address from common reverse-proxy headers.
///
/// Checks (in order): `X-Forwarded-For`, `X-Real-IP`, `Forwarded`. In the list-valued headers,
/// always the **last** entry — the one appended by the trusted proxy directly in front of us.
/// Everything before it arrived inside the client's own request; taking the first entry would
/// let a client mint a fresh rate-limit bucket per request with `X-Forwarded-For: <random>`,
/// which on these routes means unlimited OTP and CAPTCHA attempts.
fn forwarded_client_ip(headers: &axum::http::HeaderMap) -> Option<IpAddr> {
    // X-Forwarded-For: client, proxy1, proxy2 — the rightmost is what our proxy appended.
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok())
        && let Some(last) = xff.split(',').next_back()
        && let Some(ip) = parse_ip(last)
    {
        return Some(ip);
    }

    // X-Real-IP: single IP, set (not appended) by the proxy itself.
    if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok())
        && let Some(ip) = parse_ip(real_ip)
    {
        return Some(ip);
    }

    // Forwarded: for=192.0.2.60;proto=http, for=203.0.113.43 — elements are comma-separated,
    // one per hop in order, so the trustworthy element is again the last.
    if let Some(fwd) = headers.get("forwarded").and_then(|v| v.to_str().ok())
        && let Some(element) = fwd.split(',').next_back()
    {
        for part in element.split(';') {
            let part = part.trim();
            if let Some(ip) = part.strip_prefix("for=")
                && let Some(ip) = parse_ip(ip)
            {
                return Some(ip);
            }
        }
    }

    None
}

fn parse_ip(raw: &str) -> Option<IpAddr> {
    let candidate = raw.trim().trim_matches('"');
    if candidate.is_empty() || candidate.eq_ignore_ascii_case("unknown") {
        return None;
    }

    if let Ok(addr) = candidate.parse::<IpAddr>() {
        return Some(addr);
    }

    if let Ok(addr) = candidate.parse::<SocketAddr>() {
        return Some(addr.ip());
    }

    if let Some(stripped) = candidate.strip_prefix('[')
        && let Some((ip, _)) = stripped.split_once(']')
    {
        return ip.parse::<IpAddr>().ok();
    }

    // Common IPv4 host:port form in Forwarded headers.
    if let Some((host, _port)) = candidate.rsplit_once(':')
        && !host.contains(':')
    {
        return host.parse::<IpAddr>().ok();
    }

    None
}

fn rate_limit_key(
    headers: &axum::http::HeaderMap,
    peer_addr: Option<SocketAddr>,
    trust_proxy_headers: bool,
) -> String {
    if trust_proxy_headers && let Some(ip) = forwarded_client_ip(headers) {
        return format!("forwarded:{ip}");
    }

    if let Some(addr) = peer_addr {
        return format!("peer:{}", addr.ip());
    }

    "peer:unknown".to_string()
}

/// Axum middleware that enforces per-IP rate limiting.
///
/// Returns `429 Too Many Requests` when the limit is exceeded.
pub async fn rate_limit_middleware(
    Extension(limiter): Extension<AuthRateLimiter>,
    Extension(config): Extension<AuthConfig>,
    Extension(state): Extension<AuthState>,
    request: Request,
    next: Next,
) -> Response {
    let key = rate_limit_key(
        request.headers(),
        request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| *addr),
        config.trust_proxy_headers,
    );

    // Prefer the shared store when the host app supplies one, so the quota is
    // enforced once across every replica rather than once per process.
    let allowed = match &state.rate_limit_store {
        Some(store) => store.check(&key).await,
        None => limiter.inner.check_key(&key).is_ok(),
    };

    if allowed {
        next.run(request).await
    } else {
        tracing::warn!(rate_limit_key = %key, "Auth rate limit exceeded");
        (
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests. Please try again later.",
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn ignores_forwarded_headers_unless_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.1".parse().unwrap());
        let peer = "203.0.113.7:12345".parse().unwrap();

        assert_eq!(
            rate_limit_key(&headers, Some(peer), false),
            "peer:203.0.113.7"
        );
        assert_eq!(
            rate_limit_key(&headers, Some(peer), true),
            "forwarded:198.51.100.1"
        );
    }

    #[test]
    fn parses_forwarded_header_ipv4_port() {
        let mut headers = HeaderMap::new();
        headers.insert("forwarded", "for=\"198.51.100.9:443\"".parse().unwrap());

        assert_eq!(
            forwarded_client_ip(&headers),
            Some("198.51.100.9".parse().unwrap())
        );
    }

    #[test]
    fn a_client_cannot_choose_its_ip_by_prepending_hops() {
        // The proxy appends the address it saw; whatever the client put in front of it must
        // not become the rate-limit identity — that would be unlimited OTP attempts.
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "1.2.3.4, 198.51.100.9".parse().unwrap());
        assert_eq!(
            forwarded_client_ip(&headers),
            Some("198.51.100.9".parse().unwrap())
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            "forwarded",
            "for=1.2.3.4, for=198.51.100.9".parse().unwrap(),
        );
        assert_eq!(
            forwarded_client_ip(&headers),
            Some("198.51.100.9".parse().unwrap())
        );
    }
}
