//! Self-hosted [Umami](https://umami.is) analytics, the way the dx apps run it.
//!
//! Three pieces, extracted from four apps that each carried their own copy:
//!
//! - **[`proxy`]** (feature `server`): serves the tracker from *this* origin at
//!   `/stats.js` and forwards its beacons from `/api/send`. `umami.*` hostnames
//!   sit on the standard ad-blocking filter lists (EasyPrivacy and uBlock's
//!   built-ins both carry them), so a cross-origin tag is simply never fetched
//!   for a large share of visitors — and the failure is invisible: the page
//!   works, the numbers are just quietly wrong.
//! - **Client bridge** ([`track`], [`identify`], [`mount_script`]): thin
//!   wrappers over `window.umami`. Compiled to no-ops on non-wasm targets, so
//!   shared code can call them unconditionally.
//! - **[`hash_id`]**: privacy hashing for IDs that ride along as event
//!   properties.
//!
//! The app keeps its own typed event enum and calls
//! `dx_umami::track(event.name(), event.properties())` — event vocabulary is
//! product-specific and does not belong in a kit crate.

use std::collections::HashMap;

#[cfg(feature = "server")]
pub mod proxy;

/// Hash an ID for privacy (first 8 chars of SHA-256 hex).
///
/// Enough to correlate events within analytics, useless for recovering the
/// original ID.
pub fn hash_id(id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(id.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..4])
}

/// Event property value.
///
/// Umami's revenue report only registers a `revenue` property when it arrives
/// as a JS number, so string-only properties don't suffice.
#[derive(Debug, Clone, PartialEq)]
pub enum PropValue {
    Str(String),
    Num(f64),
}

/// Track an event via `window.umami.track(name, properties)` — fire and forget.
///
/// No-op when the tracker isn't loaded (blocked, not yet fetched, or
/// `UMAMI_HOST` unset) and on non-wasm targets.
#[cfg(target_family = "wasm")]
pub fn track(name: &str, props: Option<HashMap<String, PropValue>>) {
    use js_sys::wasm_bindgen::JsValue;

    let Some(window) = web_sys::window() else {
        return;
    };

    let umami = match js_sys::Reflect::get(&window, &JsValue::from_str("umami")) {
        Ok(u) if !u.is_undefined() && !u.is_null() => u,
        _ => return,
    };

    let track_fn = match js_sys::Reflect::get(&umami, &JsValue::from_str("track")) {
        Ok(f) if f.is_function() => js_sys::Function::from(f),
        _ => return,
    };

    let event_name = JsValue::from_str(name);

    let _result = if let Some(props) = props {
        let js_props = js_sys::Object::new();
        for (key, value) in props {
            let js_value = match value {
                PropValue::Str(s) => JsValue::from_str(&s),
                PropValue::Num(n) => JsValue::from_f64(n),
            };
            let _ = js_sys::Reflect::set(&js_props, &JsValue::from_str(&key), &js_value);
        }
        track_fn.call2(&umami, &event_name, &js_props)
    } else {
        track_fn.call1(&umami, &event_name)
    };
}

/// No-op on non-wasm targets.
#[cfg(not(target_family = "wasm"))]
pub fn track(_name: &str, _props: Option<HashMap<String, PropValue>>) {}

/// Identify the current session to Umami with a distinct ID.
///
/// Ties the session to the ID so the Sessions/Retention/Journeys reports work
/// per-user. Pass a [`hash_id`]-ed value, never a raw user ID. `data` becomes
/// the session's data properties (e.g. `[("plan", "pro")]`).
///
/// The tracker loads async, so unlike [`track`] this retries until
/// `window.umami` exists (up to ~10s) — an identify that races the script tag
/// and silently loses would defeat the point.
#[cfg(target_family = "wasm")]
pub fn identify(distinct_id: &str, data: &[(&str, &str)]) {
    let _ = js_sys::eval(&identify_js(distinct_id, data));
}

/// No-op on non-wasm targets.
#[cfg(not(target_family = "wasm"))]
pub fn identify(_distinct_id: &str, _data: &[(&str, &str)]) {}

/// Mount the proxied tracker script tag (`/stats.js`) once.
///
/// For apps that only learn the website ID at runtime (fetched from a server
/// fn); apps with a compile-time ID can render the `<script>` tag directly
/// instead. Idempotent — guarded by the element ID.
#[cfg(target_family = "wasm")]
pub fn mount_script(website_id: &str) {
    let _ = js_sys::eval(&mount_script_js(website_id));
}

/// No-op on non-wasm targets.
#[cfg(not(target_family = "wasm"))]
pub fn mount_script(_website_id: &str) {}

/// Build the identify snippet. Values go through serde_json so arbitrary
/// strings can't break out of the JS literal.
#[cfg_attr(not(target_family = "wasm"), allow(dead_code))]
fn identify_js(distinct_id: &str, data: &[(&str, &str)]) -> String {
    let id = serde_json::Value::String(distinct_id.to_string());
    let data = serde_json::Value::Object(
        data.iter()
            .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
            .collect(),
    );
    format!(
        r#"(function() {{
    var tries = 0;
    function go() {{
        if (window.umami && window.umami.identify) {{
            window.umami.identify({id}, {data});
        }} else if (++tries < 50) {{
            setTimeout(go, 200);
        }}
    }}
    go();
}})();"#
    )
}

/// Build the script-mount snippet.
#[cfg_attr(not(target_family = "wasm"), allow(dead_code))]
fn mount_script_js(website_id: &str) -> String {
    let id = serde_json::Value::String(website_id.to_string());
    format!(
        r#"if (!document.getElementById('dx-umami')) {{
    var s = document.createElement('script');
    s.id = 'dx-umami';
    s.src = '/stats.js';
    s.defer = true;
    s.setAttribute('data-website-id', {id});
    document.head.appendChild(s);
}}"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_id_is_8_hex_chars_and_deterministic() {
        let hashed = hash_id("some-id-12345");
        assert_eq!(hashed.len(), 8);
        assert!(hashed.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(hashed, hash_id("some-id-12345"));
        assert_ne!(hashed, hash_id("some-other-id"));
    }

    #[test]
    fn identify_js_escapes_hostile_values() {
        let js = identify_js("abc123", &[("plan", r#"pro"); alert(1); //"#)]);
        assert!(js.contains(r#""abc123""#));
        // The double quote inside the value must arrive escaped, so it cannot
        // terminate the JSON string literal it sits in.
        assert!(js.contains(r#"pro\"); alert(1); //"#));
        assert!(!js.contains(r#"pro"); alert"#));
        assert!(js.contains(r#"{"plan":"#));
    }

    #[test]
    fn mount_script_js_quotes_the_website_id() {
        let js = mount_script_js("4e3483fa-2b7e-42b6-ba78-544bbec8f190");
        assert!(js.contains(r#""4e3483fa-2b7e-42b6-ba78-544bbec8f190""#));
        assert!(js.contains("'/stats.js'"));
    }
}
