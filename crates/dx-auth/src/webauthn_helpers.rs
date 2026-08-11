//! Shared WebAuthn browser helpers (WASM only).
//!
//! Provides async functions that invoke `navigator.credentials.create()` / `.get()`
//! via `js_sys::eval` and poll `window.__auth_*` globals for the result.
//! Used by both the login page and the profile passkey management UI.

/// Call `navigator.credentials.get()` with the given request options JSON.
/// Returns the assertion data as a JSON `Value`, or an error string.
///
/// Includes a guard: if `navigator.credentials` is unavailable (non-secure context),
/// returns an error immediately instead of crashing.
pub async fn browser_get_passkey(request_options_json: &str) -> Result<serde_json::Value, String> {
    let js_code = format!(
        r#"
        (async function() {{
            try {{
                if (!navigator.credentials || !navigator.credentials.get) {{
                    window.__auth_passkey_result = null;
                    window.__auth_passkey_error = 'Passkeys are not supported in this browser or context.';
                    return;
                }}
                const raw = {request_options_json};
                // FerrisKey returns the unwrapped W3C PublicKeyCredentialRequestOptions
                // shape directly; tolerate a `publicKey` wrapper for forward compat.
                const options = raw.publicKey || raw;

                function b64urlToBuffer(b64url) {{
                    const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
                    const pad = b64.length % 4;
                    const padded = pad ? b64 + '='.repeat(4 - pad) : b64;
                    const binary = atob(padded);
                    const bytes = new Uint8Array(binary.length);
                    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
                    return bytes.buffer;
                }}

                function bufferToB64url(buffer) {{
                    const bytes = new Uint8Array(buffer);
                    let binary = '';
                    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
                    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
                }}

                if (options.challenge) {{
                    options.challenge = b64urlToBuffer(options.challenge);
                }}
                if (options.allowCredentials) {{
                    options.allowCredentials = options.allowCredentials.map(cred => ({{
                        ...cred,
                        id: b64urlToBuffer(cred.id)
                    }}));
                }}

                const credential = await navigator.credentials.get({{ publicKey: options }});

                const result = {{
                    id: credential.id,
                    rawId: bufferToB64url(credential.rawId),
                    type: credential.type,
                    response: {{
                        authenticatorData: bufferToB64url(credential.response.authenticatorData),
                        clientDataJSON: bufferToB64url(credential.response.clientDataJSON),
                        signature: bufferToB64url(credential.response.signature),
                        userHandle: credential.response.userHandle
                            ? bufferToB64url(credential.response.userHandle)
                            : null
                    }}
                }};

                window.__auth_passkey_result = JSON.stringify(result);
                window.__auth_passkey_error = null;
            }} catch (e) {{
                window.__auth_passkey_result = null;
                window.__auth_passkey_error = e.name === 'NotAllowedError'
                    ? 'Authentication was cancelled or timed out.'
                    : ('Passkey error: ' + e.message);
            }}
        }})();
        "#
    );

    let _ = js_sys::eval(&js_code);
    poll_passkey_result("__auth_passkey_result", "__auth_passkey_error", 600).await
}

/// Conditional-UI (autofill) passkey request: `mediation: "conditional"` keeps
/// the ceremony pending in the background while the email field shows stored
/// passkeys in its autofill dropdown. Resolves only when the user picks one.
///
/// Abortable via [`abort_conditional_passkey`] — REQUIRED before starting a
/// modal WebAuthn request, since browsers reject concurrent ceremonies.
pub async fn browser_get_passkey_conditional(
    request_options_json: &str,
) -> Result<serde_json::Value, String> {
    let js_code = format!(
        r#"
        (async function() {{
            try {{
                if (!window.PublicKeyCredential || !PublicKeyCredential.isConditionalMediationAvailable) {{
                    window.__auth_cond_result = null;
                    window.__auth_cond_error = 'conditional-unsupported';
                    return;
                }}
                const available = await PublicKeyCredential.isConditionalMediationAvailable();
                if (!available) {{
                    window.__auth_cond_result = null;
                    window.__auth_cond_error = 'conditional-unsupported';
                    return;
                }}

                if (window.__auth_cond_abort) window.__auth_cond_abort.abort();
                const controller = new AbortController();
                window.__auth_cond_abort = controller;
                window.__auth_cond_pending = true;

                const raw = {request_options_json};
                const options = raw.publicKey || raw;

                function b64urlToBuffer(b64url) {{
                    const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
                    const pad = b64.length % 4;
                    const padded = pad ? b64 + '='.repeat(4 - pad) : b64;
                    const binary = atob(padded);
                    const bytes = new Uint8Array(binary.length);
                    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
                    return bytes.buffer;
                }}

                function bufferToB64url(buffer) {{
                    const bytes = new Uint8Array(buffer);
                    let binary = '';
                    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
                    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
                }}

                if (options.challenge) {{
                    options.challenge = b64urlToBuffer(options.challenge);
                }}
                // Discoverable flow: allowCredentials stays empty.
                options.allowCredentials = [];

                const credential = await navigator.credentials.get({{
                    publicKey: options,
                    mediation: 'conditional',
                    signal: controller.signal,
                }});

                const result = {{
                    id: credential.id,
                    rawId: bufferToB64url(credential.rawId),
                    type: credential.type,
                    response: {{
                        authenticatorData: bufferToB64url(credential.response.authenticatorData),
                        clientDataJSON: bufferToB64url(credential.response.clientDataJSON),
                        signature: bufferToB64url(credential.response.signature),
                        userHandle: credential.response.userHandle
                            ? bufferToB64url(credential.response.userHandle)
                            : null
                    }}
                }};

                window.__auth_cond_result = JSON.stringify(result);
                window.__auth_cond_error = null;
            }} catch (e) {{
                window.__auth_cond_result = null;
                window.__auth_cond_error = e.name === 'AbortError'
                    ? 'conditional-aborted'
                    : (e.name === 'NotAllowedError'
                        ? 'Authentication was cancelled or timed out.'
                        : ('Passkey error: ' + e.message));
            }} finally {{
                window.__auth_cond_pending = false;
            }}
        }})();
        "#
    );

    let _ = js_sys::eval(&js_code);
    poll_passkey_result("__auth_cond_result", "__auth_cond_error", 3000).await
}

/// Abort a pending conditional ceremony and **wait until the browser has
/// actually released it** (no-op when none is pending). `abort()` settles the
/// request asynchronously — a modal `navigator.credentials.get()` issued
/// before that lands is rejected with "A request is already pending", so
/// callers must await this before starting one.
pub async fn abort_conditional_passkey() {
    let _ = js_sys::eval(
        "if (window.__auth_cond_abort) { window.__auth_cond_abort.abort(); window.__auth_cond_abort = undefined; }",
    );
    // Poll the pending flag for up to ~2s; the AbortError handler clears it.
    for _ in 0..40 {
        let pending = js_sys::eval("!!window.__auth_cond_pending")
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !pending {
            return;
        }
        gloo_timers::future::TimeoutFuture::new(50).await;
    }
}

/// Call `navigator.credentials.create()` with the given creation options JSON.
/// Returns the credential data as a JSON `Value`, or an error string.
///
/// Includes a guard: if `navigator.credentials` is unavailable (non-secure context),
/// returns an error immediately instead of crashing.
pub async fn browser_create_passkey(
    creation_options_json: &str,
) -> Result<serde_json::Value, String> {
    let js_code = format!(
        r#"
        (async function() {{
            try {{
                if (!navigator.credentials || !navigator.credentials.create) {{
                    window.__auth_passkey_reg_result = null;
                    window.__auth_passkey_reg_error = 'Passkeys are not supported in this browser or context.';
                    return;
                }}
                const raw = {creation_options_json};
                const options = raw.publicKey || raw;

                function b64urlToBuffer(b64url) {{
                    const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
                    const pad = b64.length % 4;
                    const padded = pad ? b64 + '='.repeat(4 - pad) : b64;
                    const binary = atob(padded);
                    const bytes = new Uint8Array(binary.length);
                    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
                    return bytes.buffer;
                }}

                function bufferToB64url(buffer) {{
                    const bytes = new Uint8Array(buffer);
                    let binary = '';
                    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
                    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
                }}

                if (options.challenge) {{
                    options.challenge = b64urlToBuffer(options.challenge);
                }}
                if (options.user && options.user.id) {{
                    if (typeof options.user.id === 'string') {{
                        options.user.id = b64urlToBuffer(options.user.id);
                    }}
                }}
                if (options.excludeCredentials) {{
                    options.excludeCredentials = options.excludeCredentials.map(cred => ({{
                        ...cred,
                        id: b64urlToBuffer(cred.id)
                    }}));
                }}

                const credential = await navigator.credentials.create({{ publicKey: options }});

                const result = {{
                    id: credential.id,
                    rawId: bufferToB64url(credential.rawId),
                    type: credential.type,
                    response: {{
                        attestationObject: bufferToB64url(credential.response.attestationObject),
                        clientDataJSON: bufferToB64url(credential.response.clientDataJSON),
                        transports: (credential.response.getTransports && credential.response.getTransports()) || []
                    }}
                }};

                window.__auth_passkey_reg_result = JSON.stringify(result);
                window.__auth_passkey_reg_error = null;
            }} catch (e) {{
                window.__auth_passkey_reg_result = null;
                window.__auth_passkey_reg_error = e.name === 'NotAllowedError'
                    ? 'Passkey creation was cancelled or timed out.'
                    : ('Passkey creation error: ' + e.message);
            }}
        }})().catch(function(e) {{
            window.__auth_passkey_reg_result = null;
            window.__auth_passkey_reg_error = 'Passkey creation error: ' + e.message;
        }});
        "#
    );

    if let Err(e) = js_sys::eval(&js_code) {
        let msg = e
            .as_string()
            .unwrap_or_else(|| format!("JS eval error: {:?}", e));
        return Err(format!("Passkey setup failed: {}", msg));
    }

    poll_passkey_result("__auth_passkey_reg_result", "__auth_passkey_reg_error", 600).await
}

/// Generic WASM POST helper that sends JSON (same-origin, session cookie
/// included) and deserializes the JSON response.
pub(crate) async fn wasm_post_json<R: for<'de> serde::Deserialize<'de>>(
    url: &str,
    body: Option<serde_json::Value>,
) -> Result<R, String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{Headers, Request, RequestCredentials, RequestInit, Response, window};

    let opts = RequestInit::new();
    opts.set_method("POST");
    opts.set_credentials(RequestCredentials::SameOrigin);

    let headers = Headers::new().map_err(|_| "Failed to create headers".to_string())?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|_| "Failed to set header".to_string())?;
    opts.set_headers(&headers);

    if let Some(b) = body {
        opts.set_body(&wasm_bindgen::JsValue::from_str(&b.to_string()));
    }

    let request = Request::new_with_str_and_init(url, &opts)
        .map_err(|_| "Failed to create request".to_string())?;

    let window = window().ok_or("No window".to_string())?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|_| "Network error".to_string())?;

    let resp: Response = resp_value
        .dyn_into()
        .map_err(|_| "Invalid response".to_string())?;

    if !resp.ok() {
        let text = JsFuture::from(
            resp.text()
                .map_err(|_| "Failed to read response".to_string())?,
        )
        .await
        .map_err(|_| "Failed to read response text".to_string())?;
        let msg = text
            .as_string()
            .unwrap_or_else(|| "Request failed".to_string());
        return Err(msg);
    }

    let json = JsFuture::from(
        resp.json()
            .map_err(|_| "Failed to parse response".to_string())?,
    )
    .await
    .map_err(|_| "Failed to parse JSON".to_string())?;

    serde_wasm_bindgen::from_value(json).map_err(|e| format!("Deserialization error: {}", e))
}

/// Full passkey enrollment flow for a logged-in user: fetch creation options
/// from the server, run the browser ceremony, submit the attestation.
///
/// Returns a user-facing error string on failure (cancelled, unsupported,
/// rejected by the server).
pub async fn enroll_passkey() -> Result<(), String> {
    #[derive(serde::Deserialize)]
    struct OptionsResp {
        options: serde_json::Value,
    }
    #[derive(serde::Deserialize)]
    struct VerifyResp {
        success: bool,
        error: Option<String>,
    }

    let opts: OptionsResp = wasm_post_json("/auth/passkey/enroll/options", None).await?;
    let credential = browser_create_passkey(&opts.options.to_string()).await?;
    let resp: VerifyResp = wasm_post_json(
        "/auth/passkey/enroll/verify",
        Some(serde_json::json!({ "credential": credential })),
    )
    .await?;
    if resp.success {
        Ok(())
    } else {
        Err(resp
            .error
            .unwrap_or_else(|| "Passkey enrollment failed".to_string()))
    }
}

/// Check if `navigator.credentials` is available in the current browser context.
pub fn is_webauthn_available() -> bool {
    js_sys::eval("!!(navigator.credentials && navigator.credentials.create)")
        .ok()
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// Poll window globals for a WebAuthn result. Each iteration is 200ms, so
/// `max_iterations` of 600 ≈ 2 minutes (modal ceremonies) and 3000 ≈ 10
/// minutes (conditional/autofill ceremonies that idle until the user picks).
async fn poll_passkey_result(
    result_key: &str,
    error_key: &str,
    max_iterations: u32,
) -> Result<serde_json::Value, String> {
    let read_result = format!("window.{result_key}");
    let read_error = format!("window.{error_key}");
    let cleanup = format!("window.{result_key} = undefined; window.{error_key} = undefined;");

    for _ in 0..max_iterations {
        gloo_timers::future::TimeoutFuture::new(200).await;

        let result = js_sys::eval(&read_result).ok().and_then(|v| v.as_string());
        let error = js_sys::eval(&read_error).ok().and_then(|v| v.as_string());

        if let Some(err) = error {
            let _ = js_sys::eval(&cleanup);
            return Err(err);
        }

        if let Some(result_json) = result {
            let _ = js_sys::eval(&cleanup);
            return serde_json::from_str(&result_json)
                .map_err(|_| "Failed to parse passkey response".to_string());
        }
    }

    let _ = js_sys::eval(&cleanup);
    Err("Passkey operation timed out".to_string())
}
