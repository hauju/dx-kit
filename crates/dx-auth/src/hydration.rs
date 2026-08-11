//! Knowing whether the page is interactive yet.
//!
//! With SSR the browser paints a fully-styled page long before the WASM bundle
//! arrives. Until it does, nothing is wired up: `oninput` doesn't fire,
//! `onsubmit` doesn't run, and a form that looks ready silently drops whatever
//! the user does. Worse, a `<form>` whose `onsubmit` handler hasn't attached yet
//! still performs the browser's *native* submit on Enter — a GET to the current
//! URL that reloads the page and throws away what was typed.
//!
//! [`use_hydrated`] reports which side of that line the page is on, so a
//! component can render itself as visibly not-ready instead of deceptively
//! ready.

use dioxus::prelude::*;

/// `false` while the page is server-rendered and on the first client render,
/// flipping to `true` once the WASM bundle has hydrated and event handlers are
/// live.
///
/// The first client render must match the server's, or hydration mismatches;
/// that's why this starts `false` on both sides and is only flipped by an
/// effect, which runs after hydration completes. The resulting re-render is the
/// signal that the page became interactive.
pub fn use_hydrated() -> Signal<bool> {
    let mut hydrated = use_signal(|| false);
    use_effect(move || hydrated.set(true));
    hydrated
}
