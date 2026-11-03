//! The JWKS cache under a slow key endpoint (#25).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use axum::routing::get;
use serde_json::json;

use super::*;
use crate::jwks::JwksCache;

const SLOW_FETCH: Duration = Duration::from_secs(3);

/// A JWKS endpoint that answers the first fetch at once and every later one
/// after `SLOW_FETCH`.
async fn slow_jwks() -> (String, Arc<AtomicUsize>) {
    let fetches = Arc::new(AtomicUsize::new(0));
    let counter = fetches.clone();
    let app = Router::new().route(
        "/jwks",
        get(move || {
            let counter = counter.clone();
            async move {
                if counter.fetch_add(1, Ordering::SeqCst) > 0 {
                    tokio::time::sleep(SLOW_FETCH).await;
                }
                json_reply(
                    200,
                    json!({ "keys": [{ "kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig", "n": TEST_KEY_N.trim(), "e": "AQAB" }] }),
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/jwks", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, fetches)
}

#[tokio::test]
async fn a_cached_kid_does_not_wait_on_a_slow_refetch() {
    let (url, fetches) = slow_jwks().await;
    let cache = Arc::new(JwksCache::at(url, reqwest::Client::new()));
    cache.key("k1").await.unwrap();
    cache.backdate_attempt().await;

    let unknown = {
        let cache = cache.clone();
        tokio::spawn(async move { cache.key("forged").await })
    };
    while fetches.load(Ordering::SeqCst) < 2 {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let started = Instant::now();
    let cached = tokio::time::timeout(Duration::from_millis(500), cache.key("k1")).await;
    assert!(
        matches!(cached, Ok(Ok(_))),
        "a cached, fresh kid waited {:?} behind the refetch",
        started.elapsed()
    );

    assert!(unknown.await.unwrap().is_err());
}

#[tokio::test]
async fn unknown_kids_share_one_refetch() {
    let (url, fetches) = slow_jwks().await;
    let cache = Arc::new(JwksCache::at(url, reqwest::Client::new()));
    cache.key("k1").await.unwrap();
    cache.backdate_attempt().await;

    let lookups: Vec<_> = (0..5)
        .map(|i| {
            let cache = cache.clone();
            tokio::spawn(async move { cache.key(&format!("forged-{i}")).await })
        })
        .collect();
    for lookup in lookups {
        assert!(lookup.await.unwrap().is_err());
    }

    assert_eq!(fetches.load(Ordering::SeqCst), 2);
}
