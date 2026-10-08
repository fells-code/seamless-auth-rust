use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::http::HeaderValue;
use axum::response::Response;
use serde_json::{Value, json};

use super::*;
use crate::Delivery;
use crate::adapter::is_json_content_type;
use crate::jwt::{str_claim, verify_hs256};
use crate::service_token::{DELIVERY_SUBJECT, PROXY_SUBJECT};

fn pre_auth() -> String {
    signed_cookie(
        "seamless-ephemeral",
        json!({ "sub": "u1", "token": "pre-auth" }),
    )
}

fn access() -> String {
    signed_cookie("seamless-access", json!({ "sub": "u1", "token": "t" }))
}

#[tokio::test]
async fn login_stores_the_pre_auth_token_and_picks_the_body() {
    let api = FakeApi::start().await;
    api.on(
        "POST",
        "/login",
        respond(
            200,
            json!({
                "message": "Success", "identifierType": "email", "loginMethods": ["email_otp"],
                "sub": "u1", "ttl": 300, "token": api.token("u1", "ephemeral"),
            }),
        ),
    );

    let r = call("POST", "/login")
        .body(r#"{"identifier":"a@b.test"}"#)
        .to(&api.adapter(|b| b))
        .await;

    assert_eq!(r.status, 200);
    assert!(
        r.body.get("token").is_none() && r.body.get("sub").is_none(),
        "body passed more than the pick: {}",
        r.body
    );
    assert_eq!(r.body["identifierType"], "email");
    let cookie = &r.cookies["seamless-ephemeral"];
    assert_eq!(attribute(cookie, "Max-Age"), Some("300"));
    assert_eq!(attribute(cookie, "Path"), Some("/"));
    assert_eq!(attribute(cookie, "SameSite"), Some("None"));
    assert!(
        flag(cookie, "HttpOnly") && flag(cookie, "Secure"),
        "{cookie}"
    );
}

#[tokio::test]
async fn a_session_route_sets_cookies_and_strips_tokens() {
    let api = FakeApi::start().await;
    api.on(
        "POST",
        "/totp/verify-login",
        respond(200, api.session("u1")),
    );

    let r = call("POST", "/totp/verify-login")
        .body(r#"{"code":"123456"}"#)
        .cookie(&pre_auth())
        .to(&api.adapter(|b| b))
        .await;

    assert_eq!(r.status, 200, "{}", r.text);
    let recorded = &api.calls_to("POST", "/totp/verify-login")[0];
    assert_eq!(recorded.header("authorization"), "Bearer pre-auth");
    assert_eq!(recorded.body, r#"{"code":"123456"}"#);
    assert_eq!(recorded.header("content-type"), "application/json");
    assert!(
        r.body.get("token").is_none(),
        "access token in a cookie-transport body"
    );
    assert!(
        r.body.get("refreshToken").is_none(),
        "refresh token in a cookie-transport body"
    );
    assert_eq!(
        attribute(&r.cookies["seamless-access"], "Max-Age"),
        Some("900")
    );
    assert_eq!(
        attribute(&r.cookies["seamless-refresh"], "Max-Age"),
        Some("3600")
    );

    let claims = verify_hs256(&r.cookie_value("seamless-access"), TEST_SECRET).unwrap();
    assert_eq!(str_claim(&claims, "sessionId"), "s-1");
    assert_eq!(str_claim(&claims, "sub"), "u1");
    assert_eq!(str_claim(&claims, "kind"), "access");
}

#[tokio::test]
async fn a_session_that_does_not_verify_is_refused() {
    let api = FakeApi::start().await;
    let mut forged = api.session("u1");
    forged["sub"] = json!("someone-else");
    api.on("POST", "/totp/verify-login", respond(200, forged));

    let r = call("POST", "/totp/verify-login")
        .body("{}")
        .cookie(&pre_auth())
        .to(&api.adapter(|b| b))
        .await;

    assert_eq!(r.status, 502);
    assert!(r.cookies.is_empty());
}

#[tokio::test]
async fn a_session_signed_by_another_key_is_refused() {
    let api = FakeApi::start().await;
    let mut forged = api.session("u1");
    // HS256 under the cookie secret: an algorithm-confusion attempt.
    forged["token"] = json!(
        sign_hs256(
            json!({ "sub": "u1", "typ": "access", "iss": api.url, "aud": api.url })
                .as_object()
                .unwrap()
                .clone(),
            TEST_SECRET,
            std::time::Duration::from_secs(60),
            Some("k1"),
        )
        .unwrap()
    );
    api.on("POST", "/totp/verify-login", respond(200, forged));

    let r = call("POST", "/totp/verify-login")
        .body("{}")
        .cookie(&pre_auth())
        .to(&api.adapter(|b| b))
        .await;

    assert_eq!(r.status, 502);
    assert!(r.cookies.is_empty());
}

#[tokio::test]
async fn an_issued_session_must_carry_the_expected_token_type() {
    let api = FakeApi::start().await;

    // A session route answering with an ephemeral token.
    let mut wrong = api.session("u1");
    wrong["token"] = json!(api.token("u1", "ephemeral"));
    api.on("POST", "/totp/verify-login", respond(200, wrong));
    let r = call("POST", "/totp/verify-login")
        .body("{}")
        .cookie(&pre_auth())
        .to(&api.adapter(|b| b))
        .await;
    assert_eq!(r.status, 502, "session from an ephemeral token");
    assert!(r.cookies.is_empty());

    // The pre-auth route answering with an access token.
    api.on(
        "POST",
        "/login",
        respond(
            200,
            json!({ "message": "ok", "sub": "u1", "ttl": 300, "token": api.token("u1", "access") }),
        ),
    );
    let r = call("POST", "/login")
        .body("{}")
        .to(&api.adapter(|b| b))
        .await;
    assert_eq!(r.status, 502, "pre-auth from an access token");
    assert!(r.cookies.is_empty());
}

#[tokio::test]
async fn bearer_transport_returns_the_whole_body_and_no_cookies() {
    let api = FakeApi::start().await;
    let session = api.session("u1");
    api.on("POST", "/totp/verify-login", respond(200, session.clone()));

    let r = call("POST", "/totp/verify-login")
        .body("{}")
        .header("x-seamless-auth-transport", "bearer")
        .header("authorization", "Bearer client-token")
        .to(&api.adapter(|b| b))
        .await;

    assert_eq!(r.status, 200);
    assert_eq!(r.body["token"], session["token"]);
    assert_eq!(r.body["refreshToken"], "refresh-u1");
    assert!(r.cookies.is_empty(), "bearer transport set cookies");
    assert_eq!(
        api.calls_to("POST", "/totp/verify-login")[0].header("authorization"),
        "Bearer client-token"
    );
}

#[tokio::test]
async fn a_missing_access_cookie_is_restored_from_the_refresh_cookie_once() {
    let api = FakeApi::start().await;
    let refreshes = Arc::new(AtomicUsize::new(0));
    let session = api.session("u1");
    let counter = refreshes.clone();
    api.on(
        "POST",
        "/refresh",
        Arc::new(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            json_reply(200, session.clone())
        }),
    );
    api.on(
        "GET",
        "/users/me",
        respond(200, json!({ "user": { "id": "u1" } })),
    );
    let adapter = api.adapter(|b| b);
    let refresh = signed_cookie(
        "seamless-refresh",
        json!({ "sub": "u1", "refreshToken": "r1" }),
    );

    let (a, b, c) = tokio::join!(
        call("GET", "/users/me").cookie(&refresh).to(&adapter),
        call("GET", "/users/me").cookie(&refresh).to(&adapter),
        call("GET", "/users/me").cookie(&refresh).to(&adapter),
    );

    for r in [&a, &b, &c] {
        assert_eq!(r.status, 200, "{}", r.text);
        assert!(
            r.cookies.contains_key("seamless-access") && r.cookies.contains_key("seamless-refresh")
        );
    }
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);

    let recorded = &api.calls_to("POST", "/refresh")[0];
    assert_eq!(recorded.header("authorization"), "Bearer r1");
    let service = service_claims(recorded);
    assert_eq!(str_claim(&service, "sub"), "u1");
    assert_eq!(str_claim(&service, "refreshToken"), "r1");
    assert_eq!(str_claim(&service, "aud"), "seamless-auth");
    assert_eq!(str_claim(&service, "iss"), "seamless-portal-api");
}

#[tokio::test]
async fn a_failed_refresh_is_not_shared() {
    let api = FakeApi::start().await;
    api.on(
        "POST",
        "/refresh",
        respond(401, json!({ "error": "refresh_token_reused" })),
    );
    let adapter = api.adapter(|b| b);
    let refresh = signed_cookie(
        "seamless-refresh",
        json!({ "sub": "u1", "refreshToken": "r1" }),
    );

    call("GET", "/users/me").cookie(&refresh).to(&adapter).await;
    call("GET", "/users/me").cookie(&refresh).to(&adapter).await;

    assert_eq!(api.calls_to("POST", "/refresh").len(), 2);
}

#[tokio::test]
async fn a_failed_refresh_clears_the_session() {
    let api = FakeApi::start().await;
    api.on(
        "POST",
        "/refresh",
        respond(401, json!({ "error": "refresh_token_reused" })),
    );

    let r = call("GET", "/users/me")
        .cookie(&signed_cookie(
            "seamless-refresh",
            json!({ "sub": "u1", "refreshToken": "r1" }),
        ))
        .to(&api.adapter(|b| b))
        .await;

    assert_eq!(r.status, 401);
    assert!(r.body["error"].is_string());
    assert!(
        r.cleared("seamless-access") && r.cleared("seamless-refresh"),
        "{:?}",
        r.cookies
    );
}

#[tokio::test]
async fn an_altered_access_cookie_is_refused_without_refreshing() {
    let api = FakeApi::start().await;
    let refresh = signed_cookie(
        "seamless-refresh",
        json!({ "sub": "u1", "refreshToken": "r1" }),
    );

    let r = call("GET", "/users/me")
        .cookie(&format!("{}x; {refresh}", access()))
        .to(&api.adapter(|b| b))
        .await;

    assert_eq!(r.status, 401);
    assert!(api.calls_to("POST", "/refresh").is_empty());
}

#[tokio::test]
async fn post_refresh_rotates_both_cookies_and_returns_no_tokens() {
    let api = FakeApi::start().await;
    api.on("POST", "/refresh", respond(200, api.session("u1")));

    let r = call("POST", "/refresh")
        .cookie(&signed_cookie(
            "seamless-refresh",
            json!({ "sub": "u1", "refreshToken": "r1" }),
        ))
        .to(&api.adapter(|b| b))
        .await;

    assert_eq!(r.status, 200, "{}", r.text);
    assert!(
        r.body.get("token").is_none() && r.body.get("refreshToken").is_none(),
        "{}",
        r.body
    );
    assert!(
        r.cookies.contains_key("seamless-access") && r.cookies.contains_key("seamless-refresh")
    );
}

#[tokio::test]
async fn bearer_refresh_is_shared_for_one_refresh_token() {
    let api = FakeApi::start().await;
    api.on("POST", "/refresh", respond(200, api.session("u1")));
    let adapter = api.adapter(|b| b);
    let refresh = || {
        call("POST", "/refresh")
            .header("x-seamless-auth-transport", "bearer")
            .header("authorization", "Bearer r1")
            .to(&adapter)
    };

    let first = refresh().await;
    let second = refresh().await;

    assert_eq!(first.status, 200);
    assert_eq!(first.body["refreshToken"], "refresh-u1");
    assert_eq!(second.body, first.body);
    assert_eq!(api.calls_to("POST", "/refresh").len(), 1);
    assert!(first.cookies.is_empty());
}

#[tokio::test]
async fn bearer_refresh_without_a_token_is_401() {
    let api = FakeApi::start().await;
    let r = call("POST", "/refresh")
        .header("x-seamless-auth-transport", "bearer")
        .to(&api.adapter(|b| b))
        .await;
    assert_eq!(r.status, 401);
}

#[tokio::test]
async fn logout_answers_204_and_clears_even_when_the_api_refuses() {
    let api = FakeApi::start().await;
    api.on(
        "DELETE",
        "/logout",
        respond(500, json!({ "error": "boom" })),
    );
    let adapter = api.adapter(|b| b);

    let r = call("DELETE", "/logout")
        .cookie(&access())
        .to(&adapter)
        .await;
    assert_eq!(r.status, 500);
    for name in ["seamless-access", "seamless-ephemeral", "seamless-refresh"] {
        assert!(r.cleared(name), "{name} not cleared");
    }

    api.on(
        "DELETE",
        "/logout",
        respond(200, json!({ "message": "ok" })),
    );
    let r = call("DELETE", "/logout")
        .cookie(&access())
        .to(&adapter)
        .await;
    assert_eq!(r.status, 204);
    assert!(r.text.is_empty());
}

#[tokio::test]
async fn delivery_routes_hand_the_message_to_the_application() {
    let api = FakeApi::start().await;
    api.on(
        "POST",
        "/otp/generate-login-email-otp",
        respond(
            200,
            json!({
                "message": "success", "token": "re-minted",
                "delivery": { "kind": "otp_email", "to": "a@b.test", "token": "123456" },
            }),
        ),
    );
    let got = Arc::new(std::sync::Mutex::new(None::<Delivery>));
    let sink = got.clone();
    let adapter = api.adapter(|b| {
        b.deliver(move |d| {
            *sink.lock().unwrap() = Some(d);
            async { Ok::<_, std::convert::Infallible>(()) }
        })
    });

    let r = call("POST", "/otp/generate-login-email-otp")
        .cookie(&pre_auth())
        .to(&adapter)
        .await;

    assert_eq!(r.status, 200);
    assert_eq!(
        r.body,
        json!({ "message": "success" }),
        "the re-minted token and the delivery must not reach the browser"
    );
    let delivery = got.lock().unwrap().clone().unwrap();
    assert_eq!(
        (delivery.kind.as_str(), delivery.to.as_str()),
        ("otp_email", "a@b.test")
    );
    assert_eq!(delivery.token.as_deref(), Some("123456"));

    let recorded = &api.calls_to("POST", "/otp/generate-login-email-otp")[0];
    assert_eq!(recorded.header("x-seamless-auth-delivery-mode"), "external");
    assert_eq!(
        str_claim(&service_claims(recorded), "sub"),
        DELIVERY_SUBJECT
    );
}

#[tokio::test]
async fn bearer_transport_strips_the_delivery_payload_too() {
    let api = FakeApi::start().await;
    api.on(
        "POST",
        "/otp/generate-login-email-otp",
        respond(
            200,
            json!({
                "message": "success", "token": "re-minted",
                "delivery": { "kind": "otp_email", "to": "a@b.test", "token": 123456 },
            }),
        ),
    );
    let got = Arc::new(std::sync::Mutex::new(None::<Delivery>));
    let sink = got.clone();
    let adapter = api.adapter(|b| {
        b.deliver(move |d| {
            *sink.lock().unwrap() = Some(d);
            async { Ok::<_, std::convert::Infallible>(()) }
        })
    });

    let r = call("POST", "/otp/generate-login-email-otp")
        .header("x-seamless-auth-transport", "bearer")
        .header("authorization", "Bearer pre-auth")
        .to(&adapter)
        .await;

    assert_eq!(r.status, 200);
    assert!(r.body.get("delivery").is_none(), "{}", r.body);
    assert_eq!(
        r.body["token"], "re-minted",
        "a bearer client keeps the re-minted token"
    );
    assert_eq!(
        got.lock().unwrap().clone().unwrap().token.as_deref(),
        Some("123456")
    );
}

#[tokio::test]
async fn a_failed_delivery_is_reported() {
    let api = FakeApi::start().await;
    api.on(
        "POST",
        "/magic-link",
        respond(200, json!({ "message": "sent", "delivery": { "kind": "magic_link_email", "to": "a@b.test", "magicLinkUrl": "https://x" } })),
    );
    let adapter = api.adapter(|b| b.deliver(|_| async { Err::<(), _>("smtp down") }));

    let r = call("POST", "/magic-link")
        .cookie(&pre_auth())
        .to(&adapter)
        .await;

    assert_eq!(r.status, 502);
    assert_eq!(r.body["error"], "delivery_failed");
}

#[tokio::test]
async fn without_deliver_the_api_sends_the_message() {
    let api = FakeApi::start().await;
    api.on(
        "POST",
        "/magic-link",
        respond(200, json!({ "message": "sent" })),
    );

    call("POST", "/magic-link")
        .cookie(&pre_auth())
        .to(&api.adapter(|b| b))
        .await;

    let recorded = &api.calls_to("POST", "/magic-link")[0];
    assert_eq!(recorded.header("x-seamless-auth-delivery-mode"), "");
    assert_eq!(str_claim(&service_claims(recorded), "sub"), PROXY_SUBJECT);
}

#[tokio::test]
async fn upstream_failures_pass_through() {
    let api = FakeApi::start().await;
    api.on(
        "POST",
        "/login",
        respond(
            400,
            json!({ "error": "invalid_request", "details": { "issues": [] } }),
        ),
    );
    let adapter = api.adapter(|b| b);

    let r = call("POST", "/login").body("{}").to(&adapter).await;
    assert_eq!(r.status, 400);
    assert_eq!(r.body["error"], "invalid_request");
    assert!(r.body["details"].is_object());

    api.on(
        "POST",
        "/login",
        Arc::new(|_| {
            let mut res = Response::new(Body::from("Too many requests"));
            *res.status_mut() = axum::http::StatusCode::TOO_MANY_REQUESTS;
            res
        }),
    );
    let r = call("POST", "/login").body("{}").to(&adapter).await;
    assert_eq!(r.status, 429);
    assert_eq!(r.body["error"], "upstream_error");
}

#[tokio::test]
async fn downloads_stream_unparsed() {
    let api = FakeApi::start().await;
    api.on(
        "GET",
        "/admin/auth-events/export",
        Arc::new(|_| {
            let mut res = Response::new(Body::from("{\"a\":1}\n{\"b\":2}\n"));
            res.headers_mut().insert(
                "content-type",
                HeaderValue::from_static("application/x-ndjson"),
            );
            res.headers_mut().insert(
                "content-disposition",
                HeaderValue::from_static("attachment; filename=\"events.ndjson\""),
            );
            res
        }),
    );

    let r = call("GET", "/admin/auth-events/export?from=x")
        .cookie(&access())
        .to(&api.adapter(|b| b))
        .await;

    assert_eq!(r.status, 200);
    assert_eq!(r.text, "{\"a\":1}\n{\"b\":2}\n");
    assert!(r.headers.get("content-disposition").is_some());
    assert_eq!(
        api.calls_to("GET", "/admin/auth-events/export")[0]
            .query
            .as_deref(),
        Some("from=x")
    );
}

#[tokio::test]
async fn unknown_routes_and_dot_segments_are_404() {
    let api = FakeApi::start().await;
    let adapter = api.adapter(|b| b);
    for target in [
        "/no-such-route",
        "/admin/users/..",
        "/admin/users/%2E%2E",
        "/admin/users/%2e",
        "/admin/users/%zz",
    ] {
        let r = call("GET", target).cookie(&access()).to(&adapter).await;
        assert_eq!(r.status, 404, "{target}");
    }
    assert!(api.calls_to("GET", "/admin/users").is_empty());
}

#[tokio::test]
async fn parameters_are_re_escaped_upstream() {
    let api = FakeApi::start().await;
    api.on(
        "GET",
        "/admin/users/a%2Fb%3Fc",
        respond(200, json!({ "ok": true })),
    );

    let r = call("GET", "/admin/users/a%2Fb%3Fc")
        .cookie(&access())
        .to(&api.adapter(|b| b))
        .await;

    assert_eq!(r.status, 200, "{}", r.text);
}

#[tokio::test]
async fn an_oversized_body_is_413() {
    let api = FakeApi::start().await;
    let big = format!(
        "{{\"x\":\"{}\"}}",
        "a".repeat(crate::adapter::MAX_BODY_BYTES)
    );

    let r = call("POST", "/login")
        .body(&big)
        .to(&api.adapter(|b| b))
        .await;

    assert_eq!(r.status, 413);
    assert!(api.calls_to("POST", "/login").is_empty());
}

#[tokio::test]
async fn cross_site_state_changes_are_blocked() {
    let api = FakeApi::start().await;
    let adapter = api.adapter(|b| b.allowed_origins(["https://app.example"]));

    let r = call("POST", "/login")
        .body("{}")
        .header("sec-fetch-site", "cross-site")
        .to(&adapter)
        .await;
    assert_eq!(r.status, 403);
    let r = call("POST", "/login")
        .body("{}")
        .header("origin", "https://evil.example")
        .to(&adapter)
        .await;
    assert_eq!(r.status, 403);
    let r = call("POST", "/login")
        .body("{}")
        .header("origin", "null")
        .to(&adapter)
        .await;
    assert_eq!(r.status, 403);

    api.on(
        "POST",
        "/login",
        respond(400, json!({ "error": "invalid_request" })),
    );
    let r = call("POST", "/login")
        .body("{}")
        .header("origin", "https://APP.example")
        .to(&adapter)
        .await;
    assert_eq!(r.status, 400);
}

#[tokio::test]
async fn the_live_manifest_adds_routes() {
    let api = FakeApi::start().await;
    api.set_manifest(json!({ "schemaVersion": 1, "routes": [{ "method": "GET", "path": "/brand-new/{id}", "credential": "access" }] }));
    api.on(
        "GET",
        "/brand-new/a%20b",
        respond(200, json!({ "fresh": true })),
    );
    let adapter = api.adapter(|b| b.disable_manifest_fetch(false));

    for _ in 0..2 {
        let r = call("GET", "/brand-new/a%20b")
            .cookie(&access())
            .to(&adapter)
            .await;
        assert_eq!(r.status, 200, "{}", r.text);
        assert_eq!(r.body["fresh"], true);
    }
    assert_eq!(api.calls_to("GET", crate::MANIFEST_PATH).len(), 1);
}

#[tokio::test]
async fn a_manifest_with_unknown_effects_is_refused_for_the_bundled_one() {
    let api = FakeApi::start().await;
    api.set_manifest(
        json!({ "schemaVersion": 1, "routes": [{ "method": "GET", "path": "/brand-new", "credential": "superuser" }] }),
    );
    let adapter = api.adapter(|b| b.disable_manifest_fetch(false));

    let r = call("GET", "/brand-new")
        .cookie(&access())
        .to(&adapter)
        .await;
    assert_eq!(r.status, 404);
    api.on("GET", "/users/me", respond(200, json!({ "user": {} })));
    let r = call("GET", "/users/me")
        .cookie(&access())
        .to(&adapter)
        .await;
    assert_eq!(r.status, 200, "the bundled manifest still serves");
}

#[tokio::test]
async fn forwards_the_client_address_and_user_agent() {
    let api = FakeApi::start().await;
    api.on("POST", "/login", respond(400, json!({ "error": "x" })));
    let adapter =
        api.adapter(|b| b.trusted_proxies(crate::TrustedProxies::new(["192.0.2.1"]).unwrap()));
    let long_agent = "b".repeat(600);

    call("POST", "/login")
        .body("{}")
        .peer("192.0.2.1:5000")
        .header("x-forwarded-for", "6.6.6.6, 203.0.113.50")
        .header("user-agent", &long_agent)
        .to(&adapter)
        .await;

    let recorded = &api.calls_to("POST", "/login")[0];
    assert_eq!(recorded.header("x-seamless-client-ip"), "203.0.113.50");
    assert_eq!(recorded.header("x-seamless-client-user-agent").len(), 512);
    let service = service_claims(recorded);
    assert_eq!(str_claim(&service, "sub"), PROXY_SUBJECT);
    assert_eq!(str_claim(&service, "iss"), "seamless-portal-api");
    assert_eq!(
        recorded.headers.get("x-seamless-service-token").map(|_| ()),
        Some(())
    );
}

#[tokio::test]
async fn without_a_resolver_the_peer_is_the_client() {
    let api = FakeApi::start().await;
    api.on("POST", "/login", respond(400, json!({ "error": "x" })));

    call("POST", "/login")
        .body("{}")
        .peer("[::ffff:198.51.100.7]:5000")
        .header("x-forwarded-for", "6.6.6.6")
        .to(&api.adapter(|b| b))
        .await;

    assert_eq!(
        api.calls_to("POST", "/login")[0].header("x-seamless-client-ip"),
        "198.51.100.7"
    );
}

#[tokio::test]
async fn redirects_from_the_api_are_not_followed() {
    let api = FakeApi::start().await;
    let target = format!("{}/elsewhere", api.url);
    api.on(
        "POST",
        "/login",
        Arc::new(move |_| {
            let mut res = Response::new(Body::empty());
            *res.status_mut() = axum::http::StatusCode::TEMPORARY_REDIRECT;
            res.headers_mut()
                .insert("location", HeaderValue::from_str(&target).unwrap());
            res
        }),
    );

    let r = call("POST", "/login")
        .body("{}")
        .to(&api.adapter(|b| b))
        .await;

    assert_eq!(r.status, 307);
    assert!(api.calls_to("POST", "/elsewhere").is_empty());
}

#[tokio::test]
async fn cookies_only_count_in_their_own_slot() {
    let api = FakeApi::start().await;
    api.on(
        "GET",
        "/users/me",
        respond(200, json!({ "user": { "id": "u1" } })),
    );
    let adapter = api.adapter(|b| b);

    // A pre-auth cookie in the access slot is not a session for the auth routes.
    let r = call("GET", "/users/me")
        .cookie(&raw_cookie(
            "seamless-access",
            "ephemeral",
            json!({ "sub": "u1", "token": "pre-auth" }),
        ))
        .to(&adapter)
        .await;
    assert_eq!(r.status, 401);
    assert!(api.calls_to("GET", "/users/me").is_empty());

    // An access cookie in the refresh slot does not refresh anything.
    let r = call("GET", "/users/me")
        .cookie(&raw_cookie(
            "seamless-refresh",
            "access",
            json!({ "sub": "u1", "refreshToken": "r1" }),
        ))
        .to(&adapter)
        .await;
    assert_eq!(r.status, 401);
    assert!(api.calls_to("POST", "/refresh").is_empty());

    // An access cookie is not a pre-auth credential.
    let r = call("POST", "/totp/verify-login")
        .body("{}")
        .cookie(&raw_cookie(
            "seamless-ephemeral",
            "access",
            json!({ "sub": "u1", "token": "t" }),
        ))
        .to(&adapter)
        .await;
    assert_eq!(r.status, 401);
    assert!(api.calls_to("POST", "/totp/verify-login").is_empty());
}

#[tokio::test]
async fn a_pre_auth_route_never_refreshes() {
    let api = FakeApi::start().await;
    let r = call("POST", "/totp/verify-login")
        .body("{}")
        .cookie(&signed_cookie(
            "seamless-refresh",
            json!({ "sub": "u1", "refreshToken": "r1" }),
        ))
        .to(&api.adapter(|b| b))
        .await;
    assert_eq!(r.status, 401);
    assert!(api.calls_to("POST", "/refresh").is_empty());
}

#[tokio::test]
async fn an_unusable_ttl_is_refused() {
    let api = FakeApi::start().await;
    for ttl in [json!(0), json!(-5), json!("soon"), json!(1.5), Value::Null] {
        let mut session = api.session("u1");
        session["ttl"] = ttl.clone();
        api.on("POST", "/totp/verify-login", respond(200, session));
        let r = call("POST", "/totp/verify-login")
            .body("{}")
            .cookie(&pre_auth())
            .to(&api.adapter(|b| b))
            .await;
        assert_eq!(r.status, 502, "ttl {ttl}");
        assert!(r.cookies.is_empty());
    }
}

#[test]
fn build_refuses_weak_or_missing_configuration() {
    let weak = [
        Adapter::builder("https://a")
            .cookie_secret("short")
            .service_secret(TEST_SERVICE)
            .build(),
        Adapter::builder("https://a")
            .cookie_secret(TEST_SECRET)
            .service_secret("short")
            .build(),
        Adapter::builder("")
            .cookie_secret(TEST_SECRET)
            .service_secret(TEST_SERVICE)
            .build(),
        Adapter::builder("ftp://a")
            .cookie_secret(TEST_SECRET)
            .service_secret(TEST_SERVICE)
            .build(),
        Adapter::builder("https://a")
            .cookie_secret(TEST_SECRET)
            .service_secret(TEST_SERVICE)
            .cookie_domain("a.example; Secure")
            .build(),
    ];
    for result in weak {
        assert!(result.is_err());
    }
}

#[test]
fn json_content_types() {
    for (content_type, want) in [
        (None, true),
        (Some("application/json"), true),
        (Some("application/json; charset=utf-8"), true),
        (Some("Application/JSON"), true),
        (Some("application/problem+json"), true),
        (Some("application/x-ndjson"), false),
        (Some("application/jsonl"), false),
        (Some("text/csv"), false),
        (Some("text/plain"), false),
        (Some("application/json/extra"), false),
    ] {
        let value = content_type.map(HeaderValue::from_static);
        assert_eq!(
            is_json_content_type(value.as_ref()),
            want,
            "{content_type:?}"
        );
    }
}

#[tokio::test]
async fn a_body_that_is_not_json_is_refused_before_anything_is_spent() {
    let api = FakeApi::start().await;
    let adapter = api.adapter(|b| b.insecure_cookies(true));
    let refresh = signed_cookie(
        "seamless-refresh",
        json!({ "sub": "u1", "refreshToken": "r1" }),
    );
    // What a cross-site form with enctype="text/plain" sends.
    let forged = r#"{"code":"attacker","state":"attacker","x":"="}"#;

    for request in [
        call("POST", "/oauth/mock/callback")
            .raw_body(forged)
            .header("content-type", "text/plain"),
        call("POST", "/oauth/mock/callback").raw_body(forged),
        call("POST", "/oauth/mock/callback")
            .raw_body(forged)
            .header("content-type", "application/x-www-form-urlencoded"),
        call("POST", "/users/credentials")
            .raw_body(forged)
            .header("content-type", "text/plain")
            .cookie(&refresh),
    ] {
        let r = request.to(&adapter).await;
        assert_eq!(r.status, 415, "{}", r.text);
    }
    assert!(api.calls_to("POST", "/oauth/mock/callback").is_empty());
    assert!(
        api.calls_to("POST", "/refresh").is_empty(),
        "a refused body must not spend the refresh token"
    );

    api.on(
        "POST",
        "/oauth/mock/callback",
        respond(400, json!({ "error": "invalid_request" })),
    );
    let r = call("POST", "/oauth/mock/callback")
        .raw_body("{}")
        .header("content-type", "application/json; charset=utf-8")
        .to(&adapter)
        .await;
    assert_eq!(r.status, 400);
    // No body needs no content type.
    api.on("GET", "/users/me", respond(200, json!({ "user": {} })));
    assert_eq!(
        call("GET", "/users/me")
            .cookie(&access())
            .to(&adapter)
            .await
            .status,
        200
    );
}

#[tokio::test]
async fn logout_clears_even_when_the_session_is_unreadable() {
    let api = FakeApi::start().await;
    let adapter = api.adapter(|b| b);
    let refresh = signed_cookie(
        "seamless-refresh",
        json!({ "sub": "u1", "refreshToken": "r1" }),
    );

    for target in ["/logout", "/logout/", "//logout", "/LOGOUT"] {
        let r = call("DELETE", target)
            .cookie(&format!("{}x; {refresh}", access()))
            .to(&adapter)
            .await;
        assert_eq!(r.status, 401, "{target}");
        for name in ["seamless-access", "seamless-ephemeral", "seamless-refresh"] {
            assert!(r.cleared(name), "{target}: {name} not cleared");
        }
    }
}

#[tokio::test]
async fn upstream_errors_are_logged_without_the_url() {
    // The address is a closed port, so the call fails with a connect error.
    let adapter = Adapter::builder("http://127.0.0.1:9")
        .cookie_secret(TEST_SECRET)
        .service_secret(TEST_SERVICE)
        .jwks_kid("test-main")
        .disable_manifest_fetch(true)
        .build()
        .unwrap();
    let r = call("GET", "/magic-link/verify/secret-token?code=abc")
        .to(&adapter)
        .await;
    assert_eq!(r.status, 502);
    let err = reqwest::get("http://127.0.0.1:9/magic-link/verify/secret-token")
        .await
        .unwrap_err();
    assert!(!err.without_url().to_string().contains("secret-token"));
}

#[test]
fn debug_output_redacts_credentials() {
    let delivery = crate::delivery::parse_delivery(&json!({
        "kind": "otp_email", "to": "a@b.test", "token": "123456", "magicLinkUrl": "https://x/verify/secret",
    }))
    .unwrap();
    let printed = format!("{delivery:?}");
    assert!(
        !printed.contains("123456") && !printed.contains("secret"),
        "{printed}"
    );
}
