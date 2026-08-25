//! First-party proxy for the self-hosted Umami tracker.
//!
//! The tracker is served from *this* origin at `/stats.js`, and its events are
//! forwarded from `/api/send`, rather than the browser talking to the Umami
//! host directly — that hostname sits on the standard ad-blocking filter
//! lists, so a cross-origin tag is simply never fetched for a large share of
//! visitors.
//!
//! **Both routes are required.** Umami's tracker derives its collect endpoint
//! from its own `src` — `https://example.com/stats.js` becomes
//! `https://example.com/api/send`. Proxying the script without also proxying
//! the collect endpoint is worse than not proxying at all: the script loads
//! fine and then every event 404s.
//!
//! `UMAMI_HOST` is the switch. Unset, both routes 404 and the tag on the page
//! fails harmlessly — which is also what keeps local development out of the
//! production statistics.

use std::net::SocketAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use axum::{
    Router,
    extract::{ConnectInfo, Request},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};

/// The upstream script changes only on an Umami upgrade, so re-fetching it per
/// visitor would add a round trip to every cold page load for nothing.
const CACHE_TTL: Duration = Duration::from_secs(60 * 60);

/// Generous for a tracker beacon, which runs a few hundred bytes.
const MAX_EVENT_BYTES: usize = 64 * 1024;

static SCRIPT_CACHE: RwLock<Option<(String, Instant)>> = RwLock::new(None);

/// `GET /stats.js` + `POST /api/send`, for `Router::merge`. Apps with a typed
/// router state can mount [`script`] and [`collect`] themselves instead.
pub fn routes() -> Router {
    Router::new()
        .route("/stats.js", get(script))
        .route("/api/send", post(collect))
}

fn host() -> Option<String> {
    std::env::var("UMAMI_HOST")
        .ok()
        .map(|h| h.trim_end_matches('/').to_string())
        .filter(|h| !h.is_empty())
}

/// Serve the tracker from this origin, cached in process.
pub async fn script() -> Response {
    let Some(host) = host() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    if let Some(cached) = SCRIPT_CACHE
        .read()
        .ok()
        .and_then(|c| c.clone())
        .filter(|(_, at)| at.elapsed() < CACHE_TTL)
        .map(|(body, _)| body)
    {
        return js(cached);
    }

    match fetch_script(&host).await {
        Ok(body) => {
            if let Ok(mut cache) = SCRIPT_CACHE.write() {
                *cache = Some((body.clone(), Instant::now()));
            }
            js(body)
        }
        // Serve a stale copy rather than nothing: analytics being briefly wrong
        // beats an error in the console of every page on the site.
        Err(e) => match SCRIPT_CACHE.read().ok().and_then(|c| c.clone()) {
            Some((body, _)) => {
                tracing::warn!(error = %e, "umami script refresh failed; serving stale copy");
                js(body)
            }
            None => {
                tracing::warn!(error = %e, "umami script unavailable");
                StatusCode::BAD_GATEWAY.into_response()
            }
        },
    }
}

async fn fetch_script(host: &str) -> Result<String, reqwest::Error> {
    reqwest::get(format!("{host}/script.js"))
        .await?
        .error_for_status()?
        .text()
        .await
}

/// Forward one event upstream.
///
/// The client IP is passed on deliberately. Umami derives both the country and
/// the daily visitor hash from it, and a proxy that dropped it would hand
/// Umami *this server's* address for every visitor on earth — collapsing
/// unique visitors to roughly "distinct user agents" and putting the entire
/// audience in one country. Umami stores the hash, never the address.
pub async fn collect(incoming: Request) -> Response {
    let Some(host) = host() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    // Read `ConnectInfo` out of the extensions rather than extracting it: a
    // server mounted with `into_make_service` attaches none, and `ConnectInfo`
    // as a required extractor 500s every beacon. Behind a reverse proxy the
    // peer is unused anyway — `X-Forwarded-For` is already set.
    let peer = incoming
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(p)| *p);
    let headers = incoming.headers().clone();

    // A beacon is a few hundred bytes. The cap is what stops this route being
    // a way to make the server buffer arbitrary uploads.
    let body = match axum::body::to_bytes(incoming.into_body(), MAX_EVENT_BYTES).await {
        Ok(body) => body,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };

    let client = reqwest::Client::new();
    let mut request = client
        .post(format!("{host}/api/send"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(body);

    if let Some(ip) = forwarded_for(&headers, peer) {
        request = request.header("x-forwarded-for", ip);
    }

    // Umami parses the browser and OS out of this; without it every visit is
    // recorded as an unknown client.
    if let Some(ua) = headers.get(header::USER_AGENT) {
        request = request.header(header::USER_AGENT, ua);
    }

    match request.send().await {
        Ok(upstream) => {
            let status =
                StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            match upstream.text().await {
                Ok(body) => (status, body).into_response(),
                Err(_) => status.into_response(),
            }
        }
        Err(e) => {
            // Never surface this to the page. A failed beacon must not become
            // a console error on every page of the site.
            tracing::warn!(error = %e, "umami event forward failed");
            StatusCode::NO_CONTENT.into_response()
        }
    }
}

/// Preserve an existing `X-Forwarded-For` (the reverse proxy sets one in
/// production) and otherwise start the chain at the peer. Taken on trust
/// because the only thing a spoofed value can distort is the spoofer's own
/// page-view row — unlike a rate limiter, where the same header would need to
/// sit behind a trust flag.
fn forwarded_for(headers: &HeaderMap, peer: Option<SocketAddr>) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())
        .or_else(|| peer.map(|p| p.ip().to_string()))
}

fn js(body: String) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/javascript"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> Option<SocketAddr> {
        Some("198.51.100.7:44321".parse().unwrap())
    }

    #[test]
    fn the_peer_is_used_when_no_proxy_set_a_header() {
        assert_eq!(
            forwarded_for(&HeaderMap::new(), peer()).as_deref(),
            Some("198.51.100.7")
        );
    }

    #[test]
    fn an_existing_chain_survives_intact() {
        // Umami reads the leftmost entry; rebuilding the chain here would
        // replace the real visitor with the proxy's address.
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.9, 10.0.0.1".parse().unwrap());
        assert_eq!(
            forwarded_for(&headers, peer()).as_deref(),
            Some("203.0.113.9, 10.0.0.1")
        );
    }

    /// The configuration these apps run under locally: no proxy header and no
    /// `ConnectInfo`. Must forward the event without an address rather than
    /// refuse it — this is the case that 500'd every beacon.
    #[test]
    fn no_header_and_no_peer_is_not_an_error() {
        assert_eq!(forwarded_for(&HeaderMap::new(), None), None);
    }
}
