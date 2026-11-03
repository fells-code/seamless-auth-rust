//! Cross-site state changes against cookie-authenticated routes (#24).

use serde_json::json;

use super::*;
use crate::SameSite;

fn access() -> String {
    signed_cookie("seamless-access", json!({ "sub": "u1", "token": "t" }))
}

/// A body-less POST to a cookie-authenticated route, as an HTML form on another
/// site can send it.
fn form_post() -> Call {
    call("POST", "/recovery-codes").cookie(&access())
}

async fn started() -> FakeApi {
    let api = FakeApi::start().await;
    api.on(
        "POST",
        "/recovery-codes",
        respond(200, json!({ "recoveryCodes": ["a"] })),
    );
    api
}

#[tokio::test]
async fn a_same_site_form_post_under_lax_cookies_is_refused() {
    let api = started().await;
    let adapter = api.adapter(|b| b.same_site(SameSite::Lax));

    let r = form_post()
        .header("sec-fetch-site", "same-site")
        .header("origin", "https://evil.example.com")
        .to(&adapter)
        .await;

    assert_eq!(r.status, 415, "{}", r.text);
    assert!(api.calls_to("POST", "/recovery-codes").is_empty());
}

#[tokio::test]
async fn a_form_post_without_fetch_metadata_is_refused() {
    let api = started().await;
    let adapter = api.adapter(|b| b.same_site(SameSite::Lax));

    let r = form_post()
        .header("origin", "https://evil.example")
        .to(&adapter)
        .await;

    assert_eq!(r.status, 415, "{}", r.text);
    assert!(api.calls_to("POST", "/recovery-codes").is_empty());
}

#[tokio::test]
async fn the_origin_check_runs_whatever_the_same_site_setting() {
    let api = started().await;
    for same_site in [SameSite::Lax, SameSite::Strict] {
        let adapter = api.adapter(|b| {
            b.same_site(same_site)
                .allowed_origins(["https://app.example.com"])
        });

        let r = form_post()
            .header("sec-fetch-site", "cross-site")
            .header("content-type", "application/json")
            .to(&adapter)
            .await;
        assert_eq!(r.status, 403, "{same_site:?} cross-site: {}", r.text);

        let r = form_post()
            .header("sec-fetch-site", "same-site")
            .header("origin", "https://evil.example.com")
            .header("content-type", "application/json")
            .to(&adapter)
            .await;
        assert_eq!(r.status, 403, "{same_site:?} same-site: {}", r.text);

        let r = form_post()
            .header("origin", "https://evil.example.com")
            .header("content-type", "application/json")
            .to(&adapter)
            .await;
        assert_eq!(r.status, 403, "{same_site:?} no fetch metadata: {}", r.text);
    }
    assert!(api.calls_to("POST", "/recovery-codes").is_empty());
}

#[tokio::test]
async fn an_empty_configured_allowlist_is_strict() {
    let api = started().await;
    let adapter = api.adapter(|b| b.allowed_origins(Vec::<String>::new()));

    let r = form_post()
        .header("sec-fetch-site", "same-site")
        .header("origin", "https://evil.example.com")
        .header("content-type", "application/json")
        .to(&adapter)
        .await;
    assert_eq!(r.status, 403, "same-site: {}", r.text);

    let r = form_post()
        .header("origin", "https://evil.example.com")
        .header("content-type", "application/json")
        .to(&adapter)
        .await;
    assert_eq!(r.status, 403, "no fetch metadata: {}", r.text);

    assert!(api.calls_to("POST", "/recovery-codes").is_empty());
}

#[tokio::test]
async fn a_body_less_unsafe_request_passes_with_json_or_the_transport_header() {
    let api = started().await;
    let adapter = api.adapter(|b| b);

    let r = form_post()
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json")
        .to(&adapter)
        .await;
    assert_eq!(r.status, 200, "json: {}", r.text);

    let r = form_post()
        .header("sec-fetch-site", "same-origin")
        .header("x-seamless-auth-transport", "cookie")
        .to(&adapter)
        .await;
    assert_eq!(r.status, 200, "transport header: {}", r.text);

    let r = form_post()
        .header("sec-fetch-site", "same-origin")
        .to(&adapter)
        .await;
    assert_eq!(r.status, 415, "neither: {}", r.text);
}

/// What the JS client sends today: body-less, with no content type and no
/// transport header.
fn session_call(method: &str, path: &str) -> Call {
    let refresh = signed_cookie(
        "seamless-refresh",
        json!({ "sub": "u1", "refreshToken": "r1" }),
    );
    call(method, path).cookie(&format!("{}; {refresh}", access()))
}

#[tokio::test]
async fn refresh_and_logout_are_exempt_from_the_content_type_gate() {
    let api = started().await;
    api.on("POST", "/refresh", respond(200, api.session("u1")));
    api.on(
        "DELETE",
        "/logout",
        respond(200, json!({ "message": "ok" })),
    );
    api.on(
        "DELETE",
        "/logout/all",
        respond(200, json!({ "message": "ok" })),
    );
    let adapter = api.adapter(|b| b.same_site(SameSite::Lax));

    let r = session_call("POST", "/refresh").to(&adapter).await;
    assert_eq!(r.status, 200, "refresh: {}", r.text);
    let r = session_call("DELETE", "/logout").to(&adapter).await;
    assert_eq!(r.status, 204, "logout: {}", r.text);
    let r = session_call("DELETE", "/logout/all").to(&adapter).await;
    assert_eq!(r.status, 204, "logout/all: {}", r.text);
}

#[tokio::test]
async fn refresh_and_logout_still_get_the_origin_check() {
    let api = started().await;
    for same_site in [SameSite::None, SameSite::Lax, SameSite::Strict] {
        let adapter = api.adapter(|b| b.same_site(same_site));
        for (method, path) in [
            ("POST", "/refresh"),
            ("DELETE", "/logout"),
            ("DELETE", "/logout/all"),
        ] {
            let r = session_call(method, path)
                .header("sec-fetch-site", "cross-site")
                .to(&adapter)
                .await;
            assert_eq!(r.status, 403, "{same_site:?} {method} {path}: {}", r.text);
            assert_eq!(r.body, json!({ "error": "cross_site_request_blocked" }));
            assert!(
                r.cookies.is_empty(),
                "{same_site:?} {method} {path} touched cookies: {:?}",
                r.cookies
            );
        }
    }
    assert!(api.calls_to("POST", "/refresh").is_empty());
    assert!(api.calls_to("DELETE", "/logout").is_empty());
    assert!(api.calls_to("DELETE", "/logout/all").is_empty());
}

#[tokio::test]
async fn other_body_less_auth_routes_get_the_content_type_gate() {
    let api = started().await;
    let adapter = api.adapter(|b| b);

    for (method, path) in [("POST", "/recovery-codes"), ("POST", "/totp/enroll/start")] {
        let r = session_call(method, path)
            .header("sec-fetch-site", "same-origin")
            .to(&adapter)
            .await;
        assert_eq!(r.status, 415, "{method} {path}: {}", r.text);
        assert_eq!(r.body, json!({ "error": "unsupported_media_type" }));
    }
}
