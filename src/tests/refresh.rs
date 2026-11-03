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
