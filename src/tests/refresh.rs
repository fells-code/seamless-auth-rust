//! Refresh sharing (#26): any caller shares a rotation in flight, and a cookie
//! caller shares a completed one for five seconds.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::json;

use super::*;
use crate::jwt::{str_claim, verify_hs256};

/// The auth API's rotation: the first presentation of a refresh token rotates
/// it, and any later one is reuse.
fn rotate_once(api: &FakeApi, delay: Duration) -> Arc<AtomicUsize> {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let session = api.session("u1");
    api.on(
        "POST",
        "/refresh",
        Arc::new(move |_| {
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
            if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                json_reply(200, session.clone())
            } else {
                json_reply(401, json!({ "error": "refresh_token_reused" }))
            }
        }),
    );
    calls
}

#[tokio::test]
async fn a_bearer_refresh_token_presented_after_rotation_reaches_the_api() {
    let api = FakeApi::start().await;
    let calls = rotate_once(&api, Duration::ZERO);
    let adapter = api.adapter(|b| b);
    let refresh = || {
        call("POST", "/refresh")
            .header("x-seamless-auth-transport", "bearer")
            .header("authorization", "Bearer r1")
            .to(&adapter)
    };

    let first = refresh().await;
    assert_eq!(first.status, 200, "{}", first.text);

    let replay = refresh().await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the replay never reached the API"
    );
    assert_eq!(replay.status, 401, "{}", replay.text);
    assert_eq!(replay.body["error"], "refresh_token_reused");
    assert!(replay.body.get("refreshToken").is_none());
}

fn refresh_cookie(token: &str) -> String {
    signed_cookie(
        "seamless-refresh",
        json!({ "sub": "u1", "refreshToken": token }),
    )
}

#[tokio::test]
async fn a_refresh_cookie_replayed_within_the_window_shares_the_completed_rotation() {
    let api = FakeApi::start().await;
    let calls = rotate_once(&api, Duration::ZERO);
    let adapter = api.adapter(|b| b);
    let cookie = refresh_cookie("r1");

    let first = call("POST", "/refresh").cookie(&cookie).to(&adapter).await;
    assert_eq!(first.status, 200, "{}", first.text);

    let replay = call("POST", "/refresh").cookie(&cookie).to(&adapter).await;
    assert_eq!(replay.status, 200, "{}", replay.text);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the replay reached the API"
    );
    assert_eq!(replay.body, first.body);
    for name in ["seamless-access", "seamless-refresh"] {
        let a = verify_hs256(&first.cookie_value(name), TEST_SECRET).unwrap();
        let b = verify_hs256(&replay.cookie_value(name), TEST_SECRET).unwrap();
        for claim in ["sub", "token", "refreshToken", "sessionId"] {
            assert_eq!(str_claim(&a, claim), str_claim(&b, claim), "{name} {claim}");
        }
    }
}

#[tokio::test]
async fn a_refresh_cookie_replayed_after_the_window_reaches_the_api() {
    let api = FakeApi::start().await;
    let calls = rotate_once(&api, Duration::ZERO);
    let adapter = api.adapter(|b| b);
    let cookie = refresh_cookie("r1");

    let first = call("POST", "/refresh").cookie(&cookie).to(&adapter).await;
    assert_eq!(first.status, 200, "{}", first.text);
    adapter.inner.refreshes.backdate_completed();

    let replay = call("POST", "/refresh").cookie(&cookie).to(&adapter).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the replay never reached the API"
    );
    assert_eq!(replay.status, 401, "{}", replay.text);
    assert!(replay.cleared("seamless-access") && replay.cleared("seamless-refresh"));
}

#[tokio::test]
async fn a_bearer_replay_within_a_cookie_window_reaches_the_api() {
    let api = FakeApi::start().await;
    let calls = rotate_once(&api, Duration::ZERO);
    let adapter = api.adapter(|b| b);

    let first = call("POST", "/refresh")
        .cookie(&refresh_cookie("r1"))
        .to(&adapter)
        .await;
    assert_eq!(first.status, 200, "{}", first.text);

    let replay = call("POST", "/refresh")
        .header("x-seamless-auth-transport", "bearer")
        .header("authorization", "Bearer r1")
        .to(&adapter)
        .await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the replay never reached the API"
    );
    assert_eq!(replay.status, 401, "{}", replay.text);
    assert_eq!(replay.body["error"], "refresh_token_reused");
}

#[tokio::test]
async fn expired_completed_rotations_are_pruned() {
    let api = FakeApi::start().await;
    let session = api.session("u1");
    api.on("POST", "/refresh", respond(200, session));
    let adapter = api.adapter(|b| b);

    for token in ["r1", "r2"] {
        let r = call("POST", "/refresh")
            .cookie(&refresh_cookie(token))
            .to(&adapter)
            .await;
        assert_eq!(r.status, 200, "{}", r.text);
    }
    assert_eq!(adapter.inner.refreshes.completed_len(), 2);

    adapter.inner.refreshes.backdate_completed();
    let r = call("POST", "/refresh")
        .cookie(&refresh_cookie("r3"))
        .to(&adapter)
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(adapter.inner.refreshes.completed_len(), 1);
}

#[tokio::test]
async fn concurrent_bearer_refreshes_share_the_rotation_in_flight() {
    let api = FakeApi::start().await;
    let calls = rotate_once(&api, Duration::from_millis(200));
    let adapter = api.adapter(|b| b);
    let refresh = || {
        call("POST", "/refresh")
            .header("x-seamless-auth-transport", "bearer")
            .header("authorization", "Bearer r1")
            .to(&adapter)
    };

    let (a, b) = tokio::join!(refresh(), refresh());

    assert_eq!(a.status, 200, "{}", a.text);
    assert_eq!(b.body, a.body);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// A refresh the adapter makes on its own: an auth route with an expired access
/// cookie and a live refresh cookie.
async fn silent_refresh(adapter: &crate::Adapter) -> Reply {
    call("GET", "/admin/applications")
        .cookie(&refresh_cookie("r1"))
        .to(adapter)
        .await
}

/// A browser asking for a refresh: `POST /refresh` in cookie transport.
async fn cookie_refresh(adapter: &crate::Adapter) -> Reply {
    call("POST", "/refresh")
        .cookie(&refresh_cookie("r1"))
        .to(adapter)
        .await
}

/// Both cookie-transport refreshes, each against a fresh adapter in front of
/// `api`, labelled for assertion messages.
async fn both_refreshes(api: &FakeApi) -> Vec<(&'static str, Reply)> {
    vec![
        ("silent", silent_refresh(&api.adapter(|b| b)).await),
        ("cookie", cookie_refresh(&api.adapter(|b| b)).await),
    ]
}

fn assert_kept(name: &str, r: &Reply) {
    assert!(
        r.cookies.is_empty(),
        "{name}: touched cookies {:?}",
        r.cookies.keys()
    );
}

fn assert_unavailable(name: &str, r: &Reply) {
    assert_eq!(r.status, 502, "{name}: {}", r.text);
    assert_eq!(r.body, json!({ "error": "upstream_unavailable" }), "{name}");
    assert_kept(name, r);
}

#[tokio::test]
async fn a_refresh_the_api_rejects_with_401_clears_the_session() {
    let api = FakeApi::start().await;
    api.on(
        "POST",
        "/refresh",
        respond(401, json!({ "error": "refresh_token_reused" })),
    );
    let replies = both_refreshes(&api).await;

    let (_, silent) = &replies[0];
    assert_eq!(silent.status, 401, "{}", silent.text);
    assert_eq!(silent.body["error"], "Refresh failed");
    let (_, cookie) = &replies[1];
    assert_eq!(cookie.status, 401, "{}", cookie.text);
    assert_eq!(cookie.body["error"], "invalid_refresh_token");
    for (name, r) in &replies {
        assert!(
            r.cleared("seamless-access") && r.cleared("seamless-refresh"),
            "{name}: {:?}",
            r.cookies
        );
    }
}

#[tokio::test]
async fn an_unreadable_refresh_cookie_clears_the_session() {
    let api = FakeApi::start().await;
    api.on("POST", "/refresh", respond(200, api.session("u1")));
    let adapter = api.adapter(|b| b);
    let forged = "seamless-refresh=not-a-cookie";

    let silent = call("GET", "/admin/applications")
        .cookie(forged)
        .to(&adapter)
        .await;
    assert_eq!(silent.status, 401, "{}", silent.text);
    assert_eq!(silent.body["error"], "Refresh failed");
    let cookie = call("POST", "/refresh").cookie(forged).to(&adapter).await;
    assert_eq!(cookie.status, 401, "{}", cookie.text);
    assert_eq!(cookie.body["error"], "invalid_refresh_token");
    for (name, r) in [("silent", &silent), ("cookie", &cookie)] {
        assert!(
            r.cleared("seamless-access") && r.cleared("seamless-refresh"),
            "{name}: {:?}",
            r.cookies
        );
    }
    assert!(api.calls_to("POST", "/refresh").is_empty());
}

#[tokio::test]
async fn a_refresh_that_cannot_reach_the_api_keeps_the_session() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let adapter = || {
        crate::Adapter::builder(&url)
            .cookie_secret(TEST_SECRET)
            .service_secret(TEST_SERVICE)
            .disable_manifest_fetch(true)
            .build()
            .unwrap()
    };

    assert_unavailable("silent", &silent_refresh(&adapter()).await);
    assert_unavailable("cookie", &cookie_refresh(&adapter()).await);
}

#[tokio::test]
async fn a_refresh_the_api_answers_with_another_error_passes_it_through_and_keeps_the_session() {
    let api = FakeApi::start().await;
    api.on(
        "POST",
        "/refresh",
        Arc::new(|_| {
            let mut res = json_reply(503, json!({ "error": "maintenance" }));
            res.headers_mut()
                .insert("retry-after", axum::http::HeaderValue::from_static("120"));
            res
        }),
    );

    for (name, r) in both_refreshes(&api).await {
        assert_eq!(r.status, 503, "{name}: {}", r.text);
        assert_eq!(r.body, json!({ "error": "maintenance" }), "{name}");
        assert_eq!(r.headers["retry-after"], "120", "{name}");
        assert_kept(name, &r);
    }
    assert!(api.calls_to("GET", "/admin/applications").is_empty());
}

#[tokio::test]
async fn a_failed_refresh_is_not_kept_for_other_tabs() {
    let api = FakeApi::start().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let session = api.session("u1");
    api.on(
        "POST",
        "/refresh",
        Arc::new(move |_| {
            if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                json_reply(503, json!({ "error": "maintenance" }))
            } else {
                json_reply(200, session.clone())
            }
        }),
    );
    let adapter = api.adapter(|b| b);

    let first = cookie_refresh(&adapter).await;
    assert_eq!(first.status, 503, "{}", first.text);
    assert_kept("first", &first);
    let retry = cookie_refresh(&adapter).await;
    assert_eq!(retry.status, 200, "{}", retry.text);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(retry.cookies.contains_key("seamless-access"));
}

#[tokio::test]
async fn a_refresh_answered_with_no_session_keeps_the_session() {
    let api = FakeApi::start().await;
    api.on("POST", "/refresh", respond(200, json!({ "message": "ok" })));
    for (name, r) in both_refreshes(&api).await {
        assert_unavailable(name, &r);
    }
}

#[tokio::test]
async fn a_refresh_answered_with_a_non_200_success_keeps_the_session() {
    let api = FakeApi::start().await;
    api.on("POST", "/refresh", respond(201, api.session("u1")));
    for (name, r) in both_refreshes(&api).await {
        assert_unavailable(name, &r);
    }
}

#[tokio::test]
async fn a_rotated_session_that_fails_verification_keeps_the_session() {
    let api = FakeApi::start().await;
    let mut session = api.session("u1");
    session["token"] = json!(sign_rs256_with(
        OTHER_KEY_PEM,
        json!({ "sub": "u1", "sid": "s-1", "typ": "access", "iss": api.url, "aud": api.url }),
    ));
    api.on("POST", "/refresh", respond(200, session));
    for (name, r) in both_refreshes(&api).await {
        assert_unavailable(name, &r);
    }
}

/// Resolves the auth API's host by hanging or by panicking, so the rotation never
/// settles or its task dies.
struct BrokenResolver {
    panics: bool,
}

impl reqwest::dns::Resolve for BrokenResolver {
    fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
        assert!(!self.panics, "resolver panicked");
        Box::pin(std::future::pending())
    }
}

fn broken_adapter(panics: bool) -> crate::Adapter {
    let client = reqwest::Client::builder()
        .dns_resolver(BrokenResolver { panics })
        .build()
        .unwrap();
    crate::Adapter::builder("http://auth.invalid")
        .cookie_secret(TEST_SECRET)
        .service_secret(TEST_SERVICE)
        .disable_manifest_fetch(true)
        .http_client(client)
        .build()
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn a_refresh_that_times_out_keeps_the_session() {
    assert_unavailable("silent", &silent_refresh(&broken_adapter(false)).await);
    assert_unavailable("cookie", &cookie_refresh(&broken_adapter(false)).await);
}

#[tokio::test]
async fn a_refresh_whose_task_panics_keeps_the_session() {
    assert_unavailable("silent", &silent_refresh(&broken_adapter(true)).await);
    assert_unavailable("cookie", &cookie_refresh(&broken_adapter(true)).await);
}
