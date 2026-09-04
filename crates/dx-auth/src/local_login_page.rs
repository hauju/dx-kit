//! The login page for the self-owned flow (`local_auth_router`).
//!
//! Compiled for BOTH targets on purpose. The server renders it to produce the
//! SSR markup and the client hydrates that same tree; gating it to `web` would
//! leave the server emitting different HTML, and hydration then walks onto
//! nodes that do not exist. The wasm-only calls inside are individually cfg'd.
//!
//! Styling is Tailwind + DaisyUI, so it inherits the host theme. A few hooks
//! are left for the host stylesheet to define (all optional — the page renders
//! without them): `.auth-bg`, `.auth-card`, the `animate-scale-in`,
//! `animate-step-in`, `animate-alert-in` and `animate-pulse-glow` utilities,
//! and `.hydration-stall` (see the crate README on hydration).

use crate::types::UserDataRefreshTrigger;
use dioxus::prelude::*;

/// Multi-step login page for the self-owned flow: email OTP with auto-passkey
/// detection, passkey autofill (conditional UI), and a one-time passkey
/// enrollment offer after an OTP login.
///
/// Flow: Email → (PasskeyChallenge | OtpCodeInput) → Verifying → OfferPasskey? → Success
// Several signals are only written from `web`-gated effects; on a server-only
// build they read as needlessly mutable.
#[cfg_attr(not(feature = "web"), allow(unused_mut, unused_variables))]
#[component]
pub fn LocalLoginPage(
    redirect_url: String,
    #[props(default)] on_success: EventHandler<String>,
    /// Bollwark captcha widget: `(server_url, site_key)`. When set, new-user
    /// registration is gated by the widget pre-solving invisibly inside the
    /// email form. Pass the same values the server reads from `CAPTCHA_URL` /
    /// `CAPTCHA_SITE_KEY`; both are public by design. Leave unset only where
    /// the registration allowlist is gate enough — the server must be
    /// unconfigured too, or it will ask for a widget this page cannot mount.
    #[props(default)]
    captcha_config: Option<(String, String)>,
    /// Product name for the heading. `None` renders a neutral "Sign in" — the
    /// auth crate is shared across apps and must not name any one of them.
    #[props(default)]
    app_name: Option<String>,
    /// Logo URL. `None` renders no image at all, rather than a broken one.
    #[props(default)]
    logo_src: Option<String>,
) -> Element {
    // Login state machine
    let mut step = use_signal(|| LoginStep::EmailInput);
    let mut email = use_signal(String::new);
    let mut otp_code = use_signal(String::new);
    let mut error_msg = use_signal(|| None::<String>);
    let mut success_msg = use_signal(|| None::<String>);
    // Field-level validation for the email step. Kept separate from `error_msg`
    // (the banner) so a bad-email hint renders inline under the input instead of
    // as a loud top-of-card alert that shoves the form down.
    let mut email_error = use_signal(|| None::<String>);

    // Whether the WASM bundle has hydrated the page yet. SSR paints this form
    // fully styled well before the bundle lands, so without this the controls
    // look live while every handler is still unattached.
    let hydrated = crate::use_hydrated();

    // Whether this browser can do WebAuthn — gates the "Sign in with a passkey"
    // affordance. Set post-hydration (SSR can't know), so SSR and the client's
    // first render match and the button fades in once support is confirmed.
    let mut webauthn_available = use_signal(|| false);
    #[cfg(feature = "web")]
    use_effect(move || {
        webauthn_available.set(crate::webauthn_helpers::is_webauthn_available());
    });
    let mut is_loading = use_signal(|| false);
    let is_new_user = use_signal(|| false);

    // Store passkey options for the WebAuthn browser API
    let passkey_options = use_signal(|| None::<String>);

    // Ceremony generation counter — bumped by every ceremony start and by any
    // action that abandons one (Back, switching method), so late-resolving
    // ceremonies can't act on a flow the user has left.
    let mut passkey_attempt = use_signal(|| 0u32);

    // Trigger for App to re-fetch user data after login (avoids full page reload)
    let mut user_refresh: Signal<UserDataRefreshTrigger> = use_context();

    // Fire on_success callback immediately when step transitions to Success.
    // This lets the parent component navigate without waiting for the
    // resource chain (trigger → server fetch → auth state update → effect).
    use_effect(move || {
        if let LoginStep::Success { redirect_url } = step() {
            on_success.call(redirect_url);
        }
    });

    // Pre-solve the bollwark widget invisibly while the user is on the
    // email-entry step. The widget is mounted inside the email <form> (see the
    // EmailInput render branch) so it captures real interaction (keystrokes,
    // mouse, dwell time) and writes its token into a hidden `captcha-token`
    // input by the time the user submits. `invisible` mode renders no chrome
    // for the common low-risk tier (it auto-solves silently); an escalated
    // tier auto-renders a checkbox.
    #[cfg(feature = "web")]
    let has_captcha = captcha_config.is_some();
    #[cfg(feature = "web")]
    use_effect(use_reactive!(|step| {
        if !matches!(step(), LoginStep::EmailInput) || !has_captcha {
            return;
        }

        // Mount: script tag and `data-sitekey` container can land in either
        // order, so poll briefly for both, then ask the (idempotent) autoInit.
        let _ = js_sys::eval(
            r#"(function() {
                let tries = 0;
                const id = setInterval(() => {
                    tries++;
                    const hasRuntime = window.Bollwark && window.Bollwark.scan;
                    const hasContainer = document.querySelector('#bollwark-container[data-sitekey]');
                    if (hasRuntime && hasContainer) {
                        window.Bollwark.scan();
                        clearInterval(id);
                    } else if (tries > 100) {
                        clearInterval(id);
                        console.warn('[dx-auth] captcha widget failed to mount within 5s');
                    }
                }, 50);
            })();"#,
        );
    }));

    // Conditional-UI passkeys: while the email step is showing, park a
    // discoverable WebAuthn request behind the field so stored passkeys
    // appear in its autofill dropdown — one tap signs in without typing the
    // email or seeing a modal. Silently does nothing when unsupported. The
    // ceremony is aborted on email submit (browsers reject concurrent
    // WebAuthn requests) and restarts if the user comes back to this step.
    let mut conditional_running = use_signal(|| false);
    let mut conditional_disabled = use_signal(|| false);
    #[cfg(feature = "web")]
    use_effect(use_reactive!(|step| {
        // `use_reactive!` closures don't take `mut` params — rebind.
        let mut step = step;
        // `is_loading` covers the email-submit window: the submit aborts the
        // parked ceremony, which flips `conditional_running` back to false
        // while the step is still EmailInput — without the guard this effect
        // would instantly park a NEW ceremony and the modal request from the
        // in-flight /start would hit "a request is already pending".
        if !matches!(step(), LoginStep::EmailInput)
            || conditional_running()
            || conditional_disabled()
            || is_loading()
        {
            return;
        }
        conditional_running.set(true);
        // Same generation guard as the modal ceremony: this task can resolve up
        // to 10 minutes after the user picked an autofill entry, long after
        // they may have submitted the email or moved to OTP. Snapshot the
        // counter and refuse to touch `step` (or trust the verify) once it has
        // moved on — else a late autofill pick could yank a live OTP step away
        // or log the session in on a stale challenge.
        let attempt = *passkey_attempt.peek();
        let stale = move || *passkey_attempt.peek() != attempt;
        spawn(async move {
            let outcome: Result<(), String> = async {
                let opts: OptionsResp =
                    wasm_post_json("/auth/session/passkey/conditional/options", None).await?;
                let assertion = crate::webauthn_helpers::browser_get_passkey_conditional(
                    &opts.options.to_string(),
                )
                .await?;
                if stale() {
                    return Ok(());
                }
                // The user picked a passkey from the dropdown — verify it.
                step.set(LoginStep::Verifying);
                let resp: VerifyResp = wasm_post_json(
                    "/auth/session/passkey/verify",
                    Some(serde_json::json!({ "credential_assertion_data": assertion })),
                )
                .await?;
                if stale() {
                    return Ok(());
                }
                if resp.success {
                    proceed_after_login(&resp, step, user_refresh, is_loading);
                    Ok(())
                } else {
                    step.set(LoginStep::EmailInput);
                    Err(resp
                        .error
                        .unwrap_or_else(|| "Passkey verification failed".to_string()))
                }
            }
            .await;
            conditional_running.set(false);
            if let Err(e) = outcome {
                // This ceremony is a background pre-warm the user never asked
                // for — its failures must stay silent. Painting them on the
                // form produces a blocking banner on an untouched page (e.g. a
                // rate-limit 429 on the auto-fired options fetch). We only
                // disable further attempts and let the normal email flow drive.
                if e != "conditional-aborted" {
                    // Aborted is expected on email submit / step change (the
                    // effect re-arms next time the email step shows); anything
                    // else — unsupported, network, 429 — means stop retrying.
                    conditional_disabled.set(true);
                }
            }
        });
    }));

    // ── Handlers ────────────────────────────────────────────────────

    // Submit email → POST to /auth/session/start
    let redirect_url_clone = redirect_url.clone();
    let on_email_submit = move |evt: FormEvent| {
        evt.prevent_default();
        let email_val = email().trim().to_lowercase();
        if email_val.is_empty() || !email_val.contains('@') {
            email_error.set(Some("Please enter a valid email address.".to_string()));
            return;
        }
        email_error.set(None);
        error_msg.set(None);
        success_msg.set(None);
        // Invalidate any parked conditional ceremony: from here the flow is
        // email-bound, so a late autofill pick must not complete a login or
        // rewrite the step behind our back.
        passkey_attempt += 1;
        // Stay on EmailInput (don't switch to a Detecting step) so the
        // pre-solving captcha widget — and the dwell time + behavior signals it
        // has been accumulating while the user typed — survives the
        // /auth/session/start round-trip. Remounting it would reset both and
        // trip the verify-time bot score. is_loading drives the spinner instead.
        is_loading.set(true);

        #[cfg(feature = "web")]
        start_session_flow(
            email_val,
            redirect_url_clone.clone(),
            step,
            error_msg,
            is_new_user,
            is_loading,
            passkey_options,
            user_refresh,
            passkey_attempt,
        );
    };

    // Verify OTP code
    let on_otp_verify = move |evt: FormEvent| {
        evt.prevent_default();
        spawn(async move {
            let code = otp_code().trim().to_string();
            if code.is_empty() {
                error_msg.set(Some("Please enter the verification code.".to_string()));
                success_msg.set(None);
                return;
            }
            is_loading.set(true);
            error_msg.set(None);
            success_msg.set(None);
            step.set(LoginStep::Verifying);

            #[cfg(feature = "web")]
            {
                let result: std::result::Result<VerifyResp, String> = wasm_post_json(
                    "/auth/session/otp/verify",
                    Some(serde_json::json!({ "code": code })),
                )
                .await;
                match result {
                    Ok(resp) => {
                        if resp.success {
                            proceed_after_login(&resp, step, user_refresh, is_loading);
                        } else {
                            let msg = resp
                                .error
                                .unwrap_or_else(|| "Verification failed".to_string());
                            error_msg.set(Some(msg));
                            step.set(LoginStep::OtpCodeInput);
                            is_loading.set(false);
                        }
                    }
                    Err(e) => {
                        error_msg.set(Some(e));
                        step.set(LoginStep::OtpCodeInput);
                        is_loading.set(false);
                    }
                }
            }

            #[cfg(not(feature = "web"))]
            {
                is_loading.set(false);
            }
        });
    };

    // Resend OTP
    let on_resend_otp = move |_| {
        spawn(async move {
            is_loading.set(true);
            error_msg.set(None);
            success_msg.set(None);

            #[cfg(feature = "web")]
            {
                let result: std::result::Result<VerifyResp, String> =
                    wasm_post_json("/auth/session/otp/resend", None).await;
                match result {
                    Ok(resp) => {
                        if resp.success {
                            success_msg
                                .set(Some("A new code has been sent to your email.".to_string()));
                        } else {
                            let msg = resp
                                .error
                                .unwrap_or_else(|| "Failed to resend code".to_string());
                            error_msg.set(Some(msg));
                        }
                    }
                    Err(e) => {
                        error_msg.set(Some(e));
                    }
                }
                is_loading.set(false);
            }

            #[cfg(not(feature = "web"))]
            {
                is_loading.set(false);
            }
        });
    };

    // "Use email code instead" — passkey fallback to OTP
    let on_use_email_code = move |_| {
        spawn(async move {
            // Abandoning the passkey ceremony — invalidate it so a late
            // resolution can't yank the user out of the OTP form.
            passkey_attempt += 1;
            is_loading.set(true);
            error_msg.set(None);
            success_msg.set(None);

            #[cfg(feature = "web")]
            {
                let result: std::result::Result<StartSessionResp, String> =
                    wasm_post_json("/auth/session/passkey-fallback-otp", None).await;
                match result {
                    Ok(_resp) => {
                        success_msg.set(Some("Verification code sent to your email.".to_string()));
                        otp_code.set(String::new());
                        step.set(LoginStep::OtpCodeInput);
                        is_loading.set(false);
                    }
                    Err(e) => {
                        error_msg.set(Some(e));
                        step.set(LoginStep::EmailInput);
                        is_loading.set(false);
                    }
                }
            }

            #[cfg(not(feature = "web"))]
            {
                is_loading.set(false);
            }
        });
    };

    // Back to the email form from the passkey steps — e.g. wrong account, or
    // the user wants a different sign-in. Invalidates any pending ceremony.
    let on_passkey_back = move |_| {
        passkey_attempt += 1;
        error_msg.set(None);
        success_msg.set(None);
        is_loading.set(false);
        step.set(LoginStep::EmailInput);
    };

    // Re-run the passkey ceremony after a server-side rejection. The stored
    // request options (and the server challenge) are still valid.
    let on_passkey_retry = move |_| {
        #[cfg(feature = "web")]
        {
            error_msg.set(None);
            step.set(LoginStep::PasskeyChallenge);
            trigger_passkey_auth(
                passkey_options,
                step,
                error_msg,
                is_loading,
                user_refresh,
                passkey_attempt,
            );
        }
    };

    // Post-login enrollment offer: run the enrollment ceremony, then continue
    // to the redirect. Failures stay on the offer step with the error shown.
    let on_offer_add = move |_| {
        spawn(async move {
            #[cfg(feature = "web")]
            {
                is_loading.set(true);
                error_msg.set(None);
                match crate::webauthn_helpers::enroll_passkey().await {
                    Ok(()) => {
                        is_loading.set(false);
                        if let LoginStep::OfferPasskey { redirect_url } = step() {
                            step.set(LoginStep::Success { redirect_url });
                            user_refresh.write().0 += 1;
                        }
                    }
                    Err(e) => {
                        error_msg.set(Some(e));
                        is_loading.set(false);
                    }
                }
            }
        });
    };

    let on_offer_skip = move |_| {
        #[cfg(feature = "web")]
        dismiss_passkey_prompt();
        error_msg.set(None);
        if let LoginStep::OfferPasskey { redirect_url } = step() {
            step.set(LoginStep::Success { redirect_url });
            user_refresh.write().0 += 1;
        }
    };

    let on_back = move |_| {
        error_msg.set(None);
        success_msg.set(None);
        email_error.set(None);
        otp_code.set(String::new());
        step.set(LoginStep::EmailInput);
    };

    // Explicit "Sign in with a passkey" — a discoverable modal ceremony that
    // needs no email: the resident key names the account. Mirrors the
    // conditional pre-warm but user-initiated (immediate mediation), so it
    // aborts the parked conditional request first to avoid a concurrent-
    // ceremony rejection, and carries the same generation guard.
    let on_passkey_button = move |_| {
        #[cfg(feature = "web")]
        spawn(async move {
            error_msg.set(None);
            email_error.set(None);
            passkey_attempt += 1;
            crate::webauthn_helpers::abort_conditional_passkey().await;
            step.set(LoginStep::PasskeyChallenge);
            let attempt = *passkey_attempt.peek();
            let stale = move || *passkey_attempt.peek() != attempt;
            let outcome: Result<(), String> = async {
                let opts: OptionsResp =
                    wasm_post_json("/auth/session/passkey/conditional/options", None).await?;
                let assertion =
                    crate::webauthn_helpers::browser_get_passkey(&opts.options.to_string()).await?;
                if stale() {
                    return Ok(());
                }
                step.set(LoginStep::Verifying);
                let resp: VerifyResp = wasm_post_json(
                    "/auth/session/passkey/verify",
                    Some(serde_json::json!({ "credential_assertion_data": assertion })),
                )
                .await?;
                if stale() {
                    return Ok(());
                }
                if resp.success {
                    proceed_after_login(&resp, step, user_refresh, is_loading);
                    Ok(())
                } else {
                    Err(resp
                        .error
                        .unwrap_or_else(|| "Passkey verification failed".to_string()))
                }
            }
            .await;
            if let Err(e) = outcome {
                if stale() {
                    return;
                }
                // Cancel / no-passkey-on-device / unsupported → quietly return
                // to the email form; only surface an unexpected failure.
                if !(e.contains("cancelled") || e.contains("timed out")) {
                    error_msg.set(Some(e));
                }
                step.set(LoginStep::EmailInput);
            }
        });
    };

    // ── Render ──────────────────────────────────────────────────────

    // Stable per-step key so the step wrapper remounts on a step change and
    // replays its entrance animation (but not on unrelated re-renders).
    let step_key = match step() {
        LoginStep::EmailInput => "email",
        LoginStep::PasskeyChallenge => "passkey",
        LoginStep::PasskeyRetry => "passkey-retry",
        LoginStep::OfferPasskey { .. } => "offer",
        LoginStep::OtpCodeInput => "otp",
        LoginStep::Verifying => "verifying",
        LoginStep::Success { .. } => "success",
    };

    let step_content = rsx!(
        div { key: "{step_key}", class: "animate-step-in",
            match step() {
                LoginStep::EmailInput => rsx!(
                    form {
                        onsubmit: on_email_submit,
                        // Suppress the browser's native validation bubble
                        // so our own inline `email_error` renders instead.
                        novalidate: true,
                        class: "space-y-4",
                        fieldset {
                            class: "fieldset",
                            label { class: "fieldset-label", "Email address" }
                            input {
                                r#type: "email",
                                class: if email_error().is_some() {
                                    "input input-bordered w-full input-error"
                                } else {
                                    "input input-bordered w-full"
                                },
                                placeholder: "you@example.com",
                                required: true,
                                autofocus: true,
                                // "webauthn" makes stored passkeys show
                                // up in this field's autofill dropdown
                                // (conditional-UI ceremony above).
                                autocomplete: "username webauthn",
                                value: "{email}",
                                oninput: move |e| {
                                    email.set(e.value());
                                    email_error.set(None);
                                },
                            }
                            // Field-level validation, inline — never the
                            // top-of-card banner (that's for auth errors).
                            if let Some(err) = email_error() {
                                p { class: "text-xs text-error mt-1.5 animate-alert-in", "{err}" }
                            }
                        }

                        // Pre-solve the bollwark widget invisibly while the
                        // user types. The widget injects its hidden
                        // `captcha-token` input into the closest <form> (this
                        // one), so the proof-of-work token is ready by submit
                        // time and the new-user flow can forward it without an
                        // extra screen. `invisible` mode renders no chrome for
                        // low-risk visitors; an escalated tier auto-renders a
                        // checkbox the user clicks before continuing.
                        if let Some((server_url, site_key)) = captcha_config.clone() {
                            document::Script {
                                src: "{server_url}/v1/widget.js",
                                defer: true,
                            }
                            div {
                                id: "bollwark-container",
                                class: "flex justify-center",
                                "data-sitekey": "{site_key}",
                                "data-server-url": "{server_url}",
                                "data-mode": "invisible",
                            }
                        }

                        button {
                            r#type: "submit",
                            class: "btn btn-primary w-full transition-transform duration-150 hover:-translate-y-0.5 active:translate-y-0",
                            disabled: is_loading(),
                            if is_loading() {
                                span { class: "loading loading-spinner loading-sm" }
                            }
                            "Continue"
                        }

                        // Passkey affordance — makes the modern path
                        // visible instead of only discoverable via the
                        // field's autofill. Shown once WebAuthn support
                        // is confirmed (post-hydration).
                        if webauthn_available() {
                            div { class: "divider text-xs text-base-content/40 my-1", "or" }
                            button {
                                r#type: "button",
                                class: "btn btn-outline w-full gap-2 transition-transform duration-150 hover:-translate-y-0.5 active:translate-y-0",
                                onclick: on_passkey_button,
                                disabled: is_loading(),
                                {icon_fingerprint("h-5 w-5")}
                                "Sign in with a passkey"
                            }
                        }

                        p { class: "text-xs text-base-content/40 text-center mt-3",
                            "No account yet? We'll create one for you."
                        }
                    }
                ),

                LoginStep::PasskeyChallenge => rsx!(
                    div { class: "text-center space-y-4 py-4",
                        div { class: "mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-primary/10 text-primary animate-pulse-glow",
                            {icon_fingerprint("h-8 w-8")}
                        }
                        p { class: "font-medium", "Waiting for authentication..." }
                        p { class: "text-sm text-base-content/50",
                            "Follow the prompt from your browser or device."
                        }
                        div { class: "flex justify-center gap-2 mt-4",
                            button {
                                class: "btn btn-ghost btn-sm",
                                onclick: on_passkey_back,
                                disabled: is_loading(),
                                "Back"
                            }
                            button {
                                class: "btn btn-ghost btn-sm",
                                onclick: on_use_email_code,
                                disabled: is_loading(),
                                "Use email code instead"
                            }
                        }
                    }
                ),

                LoginStep::PasskeyRetry => rsx!(
                    div { class: "text-center space-y-4 py-4",
                        div { class: "mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-base-content/5 text-base-content/50",
                            {icon_fingerprint("h-8 w-8")}
                        }
                        p { class: "font-medium", "Passkey sign-in didn't work" }
                        p { class: "text-sm text-base-content/50",
                            "You can try again or use another way to sign in."
                        }
                        div { class: "flex flex-col gap-2",
                            button {
                                class: "btn btn-primary",
                                onclick: on_passkey_retry,
                                disabled: is_loading(),
                                "Try again"
                            }
                            button {
                                class: "btn btn-ghost btn-sm",
                                onclick: on_use_email_code,
                                disabled: is_loading(),
                                "Use email code instead"
                            }
                            button {
                                class: "btn btn-ghost btn-sm",
                                onclick: on_passkey_back,
                                disabled: is_loading(),
                                "Back"
                            }
                        }
                    }
                ),

                LoginStep::OfferPasskey { .. } => rsx!(
                    div { class: "text-center space-y-4 py-4",
                        div { class: "mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-primary/10 text-primary",
                            {icon_fingerprint("h-8 w-8")}
                        }
                        p { class: "font-medium", "Skip the email code next time" }
                        p { class: "text-sm text-base-content/50",
                            "Add a passkey to sign in with your fingerprint, face, or screen lock."
                        }
                        div { class: "flex flex-col gap-2",
                            button {
                                class: "btn btn-primary",
                                onclick: on_offer_add,
                                disabled: is_loading(),
                                if is_loading() {
                                    span { class: "loading loading-spinner loading-sm" }
                                }
                                "Add passkey"
                            }
                            button {
                                class: "btn btn-ghost btn-sm",
                                onclick: on_offer_skip,
                                disabled: is_loading(),
                                "Not now"
                            }
                        }
                    }
                ),

                LoginStep::OtpCodeInput => rsx!(
                    div { class: "space-y-4",
                        div { class: "text-center",
                            if is_new_user() {
                                div { class: "badge badge-success badge-outline mb-2",
                                    "Account created"
                                }
                            }
                            p { class: "text-sm text-base-content/70",
                                "We sent a verification code to"
                            }
                            p { class: "font-medium text-sm", "{email}" }
                        }

                        form {
                            onsubmit: on_otp_verify,
                            class: "space-y-4",
                            fieldset {
                                class: "fieldset",
                                label { class: "fieldset-label", "Verification code" }
                                input {
                                    r#type: "text",
                                    class: "input input-bordered w-full text-center text-xl tracking-widest",
                                    placeholder: "000000",
                                    maxlength: "8",
                                    autofocus: true,
                                    autocomplete: "one-time-code",
                                    inputmode: "numeric",
                                    value: "{otp_code}",
                                    oninput: move |e| otp_code.set(e.value()),
                                }
                            }
                            button {
                                r#type: "submit",
                                class: "btn btn-primary w-full",
                                disabled: is_loading(),
                                if is_loading() {
                                    span { class: "loading loading-spinner loading-sm" }
                                }
                                "Verify"
                            }
                        }

                        div { class: "flex justify-between items-center text-sm",
                            button {
                                class: "btn btn-ghost btn-sm text-base-content/50",
                                onclick: on_back,
                                "Back"
                            }
                            button {
                                class: "btn btn-ghost btn-sm text-primary",
                                onclick: on_resend_otp,
                                disabled: is_loading(),
                                "Resend code"
                            }
                        }
                    }
                ),

                LoginStep::Verifying => rsx!(
                    div { class: "text-center space-y-4 py-4",
                        span { class: "loading loading-spinner loading-lg text-primary" }
                        p { class: "text-base-content/70", "Verifying..." }
                    }
                ),

                LoginStep::Success { redirect_url: _ } => rsx!(
                    div { class: "text-center space-y-4 py-4",
                        div { class: "text-success text-4xl mb-2",
                            svg {
                                xmlns: "http://www.w3.org/2000/svg",
                                class: "h-12 w-12 mx-auto",
                                fill: "none",
                                "viewBox": "0 0 24 24",
                                "stroke-width": "2",
                                stroke: "currentColor",
                                path {
                                    "stroke-linecap": "round",
                                    "stroke-linejoin": "round",
                                    d: "M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
                                }
                            }
                        }
                        p { class: "font-medium", "Login successful!" }
                        p { class: "text-sm text-base-content/50", "Redirecting..." }
                        span { class: "loading loading-spinner loading-sm" }
                    }
                ),
            }
        }
    );

    let inner = rsx!(
        // Success display — soft tinted, animated in (no solid block).
        if let Some(msg) = success_msg() {
            div { class: "animate-alert-in flex items-start gap-2.5 rounded-xl border border-success/25 bg-success/10 px-4 py-3 text-sm text-success mb-4",
                svg {
                    xmlns: "http://www.w3.org/2000/svg",
                    class: "stroke-current shrink-0 h-5 w-5 mt-px",
                    fill: "none",
                    "viewBox": "0 0 24 24",
                    path {
                        "stroke-linecap": "round",
                        "stroke-linejoin": "round",
                        "stroke-width": "2",
                        d: "M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
                    }
                }
                span { "{msg}" }
            }
        }

        // Error display — reserved for auth/server errors (field
        // validation renders inline under its input instead).
        if let Some(err) = error_msg() {
            div { class: "animate-alert-in flex items-start gap-2.5 rounded-xl border border-error/25 bg-error/10 px-4 py-3 text-sm text-error mb-4",
                svg {
                    xmlns: "http://www.w3.org/2000/svg",
                    class: "stroke-current shrink-0 h-5 w-5 mt-px",
                    fill: "none",
                    "viewBox": "0 0 24 24",
                    path {
                        "stroke-linecap": "round",
                        "stroke-linejoin": "round",
                        "stroke-width": "2",
                        d: "M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z",
                    }
                }
                span { "{err}" }
            }
        }

        // Step content — keyed wrapper animates each step swap. Its own block:
        // Dioxus only honours `key` on the first node of a block.
        {step_content}
    );

    rsx!(
        div { class: "auth-bg min-h-screen flex flex-col items-center justify-center bg-base-200 p-4",
            div { class: "auth-card card w-full max-w-md bg-base-100 animate-scale-in",
                div { class: "card-body p-7 sm:p-9",
                    // Logo / header
                    div { class: "text-center mb-7",
                        if let Some(src) = logo_src.clone() {
                            img {
                                src,
                                alt: app_name.clone().unwrap_or_default(),
                                class: "h-16 mx-auto mb-4",
                            }
                        }
                        h1 { class: "text-2xl font-bold tracking-tight",
                            match app_name.clone() {
                                Some(name) => format!("Welcome to {name}"),
                                None => "Sign in".to_string(),
                            }
                        }
                        p { class: "text-sm text-base-content/60 mt-1.5",
                            "Sign in or create an account"
                        }
                    }

                    // Gate the whole form on hydration. A disabled <fieldset>
                    // disables every control inside it, and — the sharper bug —
                    // with the submit button disabled the browser skips implicit
                    // (Enter-key) submission, which pre-hydration would do a
                    // native GET that reloads the page and discards the email.
                    // `display: contents` keeps it out of the layout.
                    fieldset { class: "contents", disabled: !hydrated(), {inner} }
                    if !hydrated() {
                        div {
                            class: "flex items-center justify-center gap-2 mt-4 text-xs text-base-content/50",
                            "aria-live": "polite",
                            span { class: "loading loading-spinner loading-xs" }
                            "Starting up…"
                        }
                        div { class: "hydration-stall text-center text-xs text-warning mt-2",
                            "Still loading — if this doesn't clear, try reloading the page."
                        }
                    }

                    // Trust footer
                    div { class: "mt-6 flex items-center justify-center gap-1.5 text-xs text-base-content/40",
                        {icon_lock("h-3.5 w-3.5")}
                        span { "Secured with passkeys & encryption" }
                    }
                }
            }
        }
    )
}

// ── Inline icons (kept local to avoid an icon-crate dep in the auth crate) ──

fn icon_fingerprint(class: &str) -> Element {
    rsx! {
        svg {
            xmlns: "http://www.w3.org/2000/svg",
            class: "{class}",
            fill: "none",
            "viewBox": "0 0 24 24",
            "stroke-width": "1.5",
            stroke: "currentColor",
            path {
                "stroke-linecap": "round",
                "stroke-linejoin": "round",
                d: "M7.864 4.243A7.5 7.5 0 0119.5 10.5c0 2.92-.556 5.709-1.568 8.268M5.742 6.364A7.465 7.465 0 004.5 10.5a7.464 7.464 0 01-1.15 3.993m1.989 3.559A11.209 11.209 0 008.25 10.5a3.75 3.75 0 117.5 0c0 .527-.021 1.049-.064 1.565M12 10.5a14.94 14.94 0 01-3.6 9.75m6.633-4.596a18.666 18.666 0 01-2.485 5.33",
            }
        }
    }
}

fn icon_lock(class: &str) -> Element {
    rsx! {
        svg {
            xmlns: "http://www.w3.org/2000/svg",
            class: "{class}",
            fill: "none",
            "viewBox": "0 0 24 24",
            "stroke-width": "1.5",
            stroke: "currentColor",
            path {
                "stroke-linecap": "round",
                "stroke-linejoin": "round",
                d: "M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z",
            }
        }
    }
}

// ── Login step state machine ────────────────────────────────────────

#[derive(Clone, PartialEq)]
#[cfg_attr(not(feature = "web"), allow(dead_code))]
enum LoginStep {
    EmailInput,
    PasskeyChallenge,
    /// A passkey assertion was rejected server-side — no ceremony is pending;
    /// offer an explicit retry instead of a lying spinner.
    PasskeyRetry,
    /// Post-login one-time prompt: account has no passkeys, offer enrollment.
    OfferPasskey {
        redirect_url: String,
    },
    OtpCodeInput,
    Verifying,
    Success {
        redirect_url: String,
    },
}

// ── WASM HTTP helpers ───────────────────────────────────────────────

#[cfg(feature = "web")]
use crate::webauthn_helpers::wasm_post_json;

#[cfg(feature = "web")]
#[derive(serde::Deserialize)]
struct StartSessionResp {
    public_key_options: Option<serde_json::Value>,
    otp_sent: bool,
    is_new_user: bool,
    #[allow(dead_code)]
    has_passkeys: bool,
    captcha_required: Option<bool>,
    // The widget config comes from the `captcha_config` prop (the widget is
    // mounted pre-emptively on the email step), so these response fields are
    // not read client-side; the server still returns them.
    #[allow(dead_code)]
    captcha_server_url: Option<String>,
    #[allow(dead_code)]
    captcha_site_key: Option<String>,
}

#[cfg(feature = "web")]
#[derive(serde::Deserialize)]
struct CaptchaVerifyResp {
    success: bool,
    #[allow(dead_code)]
    otp_sent: bool,
    error: Option<String>,
}

#[cfg(feature = "web")]
#[derive(serde::Deserialize)]
struct VerifyResp {
    success: bool,
    redirect_url: Option<String>,
    error: Option<String>,
    #[serde(default)]
    offer_passkey: Option<bool>,
}

/// `/auth/session/passkey/conditional/options` response.
#[cfg(feature = "web")]
#[derive(serde::Deserialize)]
struct OptionsResp {
    options: serde_json::Value,
}

/// Reads the bollwark widget's hidden `captcha-token` input from the DOM
/// verbatim. The value is an opaque token — it is forwarded as-is to the
/// server (which forwards it to `/v1/verify`) and never parsed. Returns
/// `None` when the widget hasn't produced a token yet.
#[cfg(feature = "web")]
fn read_captcha_token_from_dom() -> Option<String> {
    let raw = js_sys::eval(
        r#"(() => {
            const el = document.querySelector('input[name="captcha-token"]');
            return el ? el.value : "";
        })()"#,
    )
    .ok()?
    .as_string()?;
    if raw.is_empty() {
        return None;
    }
    Some(raw)
}

/// Complete the new-user captcha flow from the email step. The widget has been
/// pre-solving invisibly inside the email form; poll for its token (up to
/// ~12s), forward it to the server, and on success advance to OTP entry. The
/// step stays on EmailInput so a rejection or timeout lets the user simply
/// resubmit while the widget keeps solving.
#[cfg(feature = "web")]
async fn complete_captcha_flow(
    mut step: Signal<LoginStep>,
    mut error_msg: Signal<Option<String>>,
    mut is_loading: Signal<bool>,
) {
    // Poll for the solved token (~60 tries × 200ms ≈ 12s). It is normally
    // already present by the time the user finishes typing and submitting.
    let mut token = None;
    for _ in 0..60 {
        if let Some(t) = read_captcha_token_from_dom() {
            token = Some(t);
            break;
        }
        gloo_timers::future::TimeoutFuture::new(200).await;
    }

    let Some(token) = token else {
        error_msg.set(Some(
            "Verification is still loading. Please wait a moment and try again.".to_string(),
        ));
        is_loading.set(false);
        return;
    };

    let result: std::result::Result<CaptchaVerifyResp, String> = wasm_post_json(
        "/auth/session/captcha/verify",
        Some(serde_json::json!({ "captcha_token": token })),
    )
    .await;
    match result {
        Ok(resp) if resp.success => {
            error_msg.set(None);
            step.set(LoginStep::OtpCodeInput);
            is_loading.set(false);
        }
        Ok(resp) => {
            error_msg.set(Some(
                resp.error
                    .unwrap_or_else(|| "Verification failed".to_string()),
            ));
            reset_captcha_widget();
            is_loading.set(false);
        }
        Err(e) => {
            error_msg.set(Some(e));
            reset_captcha_widget();
            is_loading.set(false);
        }
    }
}

/// Clear the stale captcha token and reset the widget so it produces a fresh
/// puzzle (and auto-solves it) for the next submit attempt.
#[cfg(feature = "web")]
fn reset_captcha_widget() {
    let _ = js_sys::eval(
        r#"(function() {
            const el = document.querySelector('input[name="captcha-token"]');
            if (el) el.value = "";
            const a = window.Bollwark && window.Bollwark._instances;
            if (a) a.forEach((w) => w.reset());
        })();"#,
    );
}

/// Post-login continuation shared by the OTP and passkey verifiers: the
/// one-time passkey-enrollment offer (server says the account has none, device
/// supports WebAuthn, not dismissed before), else straight to the redirect.
#[cfg(feature = "web")]
fn proceed_after_login(
    resp: &VerifyResp,
    mut step: Signal<LoginStep>,
    mut user_refresh: Signal<UserDataRefreshTrigger>,
    mut is_loading: Signal<bool>,
) {
    if let Some(url) = resp.redirect_url.clone() {
        if resp.offer_passkey == Some(true)
            && crate::webauthn_helpers::is_webauthn_available()
            && !passkey_prompt_dismissed()
        {
            step.set(LoginStep::OfferPasskey { redirect_url: url });
            is_loading.set(false);
        } else {
            step.set(LoginStep::Success { redirect_url: url });
            user_refresh.write().0 += 1;
        }
    }
}

/// Whether this device has dismissed the enrollment prompt before. Reads
/// localStorage via eval (no web-sys Storage feature needed); storage errors
/// (private mode) count as dismissed so the prompt can never nag.
#[cfg(feature = "web")]
fn passkey_prompt_dismissed() -> bool {
    js_sys::eval(
        "(function(){try{return localStorage.getItem('auth_passkey_prompt_dismissed')==='1'}catch(e){return true}})()",
    )
    .ok()
    .and_then(|v| v.as_bool())
    .unwrap_or(true)
}

#[cfg(feature = "web")]
fn dismiss_passkey_prompt() {
    let _ =
        js_sys::eval("try{localStorage.setItem('auth_passkey_prompt_dismissed','1')}catch(e){}");
}

/// Start session flow: POST to /auth/session/start, then auto-trigger passkey or show OTP.
#[cfg(feature = "web")]
#[allow(clippy::too_many_arguments)]
fn start_session_flow(
    email_val: String,
    redirect_url: String,
    mut step: Signal<LoginStep>,
    mut error_msg: Signal<Option<String>>,
    mut is_new_user: Signal<bool>,
    mut is_loading: Signal<bool>,
    mut passkey_options: Signal<Option<String>>,
    user_refresh: Signal<UserDataRefreshTrigger>,
    passkey_attempt: Signal<u32>,
) {
    spawn(async move {
        is_loading.set(true);

        // A pending conditional ceremony blocks any modal WebAuthn request —
        // abort it and wait for the browser to release it before the
        // email-bound flow (which may start one).
        crate::webauthn_helpers::abort_conditional_passkey().await;

        let mut body = serde_json::json!({ "email": email_val });
        if !redirect_url.is_empty() {
            body["redirect_url"] = serde_json::Value::String(redirect_url);
        }

        let result: std::result::Result<StartSessionResp, String> =
            wasm_post_json("/auth/session/start", Some(body)).await;

        match result {
            Ok(resp) => {
                is_new_user.set(resp.is_new_user);

                if resp.captcha_required == Some(true) {
                    // New user → the captcha widget on the email step has been
                    // pre-solving invisibly while the user typed. We never left
                    // EmailInput, so that same widget (with real dwell + behavior
                    // signals) is still mounted — read its token, forward it, and
                    // advance to OTP. is_loading keeps the form disabled meanwhile.
                    complete_captcha_flow(step, error_msg, is_loading).await;
                } else if let Some(pk_opts) = resp.public_key_options {
                    // Server detected passkeys → auto-trigger WebAuthn
                    passkey_options.set(Some(pk_opts.to_string()));
                    step.set(LoginStep::PasskeyChallenge);
                    is_loading.set(false);

                    trigger_passkey_auth(
                        passkey_options,
                        step,
                        error_msg,
                        is_loading,
                        user_refresh,
                        passkey_attempt,
                    );
                } else if resp.otp_sent {
                    // OTP flow: either an existing account with no passkey, or a
                    // registration whose captcha (when configured) already passed.
                    step.set(LoginStep::OtpCodeInput);
                    is_loading.set(false);
                } else {
                    error_msg.set(Some("Unexpected response from server".to_string()));
                    step.set(LoginStep::EmailInput);
                    is_loading.set(false);
                }
            }
            Err(e) => {
                error_msg.set(Some(e));
                step.set(LoginStep::EmailInput);
                is_loading.set(false);
            }
        }
    });
}

/// Trigger the WebAuthn browser API to get a passkey assertion, then verify it.
/// On failure/cancel, lands on the retry step; the user chooses OTP from there.
#[cfg(feature = "web")]
fn trigger_passkey_auth(
    passkey_options: Signal<Option<String>>,
    mut step: Signal<LoginStep>,
    mut error_msg: Signal<Option<String>>,
    mut is_loading: Signal<bool>,
    user_refresh: Signal<UserDataRefreshTrigger>,
    mut passkey_attempt: Signal<u32>,
) {
    spawn(async move {
        let Some(options_json) = passkey_options() else {
            error_msg.set(Some("No passkey challenge available".to_string()));
            step.set(LoginStep::EmailInput);
            return;
        };

        // Generation guard: bump on every ceremony start; anything else that
        // bumps it (Back, switching to OTP) invalidates this run so a
        // late-resolving ceremony can't act on an abandoned flow — e.g. fire a
        // verify POST or flip the step after the user went back to the email
        // form.
        passkey_attempt += 1;
        let attempt = *passkey_attempt.peek();
        let stale = move || *passkey_attempt.peek() != attempt;

        match crate::webauthn_helpers::browser_get_passkey(&options_json).await {
            Ok(assertion_data) => {
                if stale() {
                    return;
                }
                step.set(LoginStep::Verifying);
                let verify_result: std::result::Result<VerifyResp, String> = wasm_post_json(
                    "/auth/session/passkey/verify",
                    Some(serde_json::json!({ "credential_assertion_data": assertion_data })),
                )
                .await;
                if stale() {
                    return;
                }
                match verify_result {
                    Ok(resp) => {
                        if resp.success {
                            proceed_after_login(&resp, step, user_refresh, is_loading);
                        } else {
                            let msg = resp
                                .error
                                .unwrap_or_else(|| "Verification failed".to_string());
                            error_msg.set(Some(msg));
                            step.set(LoginStep::PasskeyRetry);
                            is_loading.set(false);
                        }
                    }
                    Err(e) => {
                        error_msg.set(Some(e));
                        step.set(LoginStep::PasskeyRetry);
                        is_loading.set(false);
                    }
                }
            }
            Err(e) => {
                if stale() {
                    return;
                }
                // Ceremony failed browser-side (cancelled, timed out, not
                // available). Land on the retry step and let the user choose —
                // no auto-sent OTP email: a cancel used to silently fire one
                // per attempt, which reads as spam from a login page.
                if e.contains("cancelled") || e.contains("timed out") {
                    error_msg.set(None);
                } else {
                    error_msg.set(Some(e));
                }
                step.set(LoginStep::PasskeyRetry);
                is_loading.set(false);
            }
        }
    });
}
