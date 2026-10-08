use axum::Json;
use axum::routing::get;
use serde_json::json;

use super::*;
use crate::User;

fn guarded(adapter: &Adapter) -> Router {
    Router::new().route(
        "/api/me",
        get(|user: User| async move { Json(json!({ "id": user.id, "roles": user.roles })) })
            .route_layer(adapter.require_auth()),
    )
}

#[tokio::test]
async fn require_auth() {
    let api = FakeApi::start().await;
    let adapter = api.adapter(|b| b);
    let token = |typ: &str| api.token("u1", typ);
    let hs256_access = sign_hs256(
        json!({ "sub": "u1", "typ": "access", "iss": api.url, "aud": api.url })
            .as_object()
            .unwrap()
            .clone(),
        TEST_SECRET,
        Duration::from_secs(60),
        Some("k1"),
    )
    .unwrap();
    let expired = sign_rs256(
        json!({ "sub": "u1", "typ": "access", "iss": api.url, "aud": api.url, "exp": 1_000_000 }),
    );

    let cases: Vec<(&str, Call, u16)> = vec![
        ("no credential", call("GET", "/api/me"), 401),
        (
            "session cookie",
            call("GET", "/api/me").cookie(&signed_cookie(
                "seamless-access",
                json!({ "sub": "u1", "token": token("access"), "roles": ["user"] }),
            )),
            200,
        ),
        // Every cookie is signed with the same secret. The pre-auth cookie /login
        // issues for any existing account must not pass for a session, in the
        // access slot or out of it.
        (
            "pre-auth cookie in the access slot",
            call("GET", "/api/me").cookie(&raw_cookie(
                "seamless-access",
                "ephemeral",
                json!({ "sub": "u1", "token": token("ephemeral") }),
            )),
            401,
        ),
        (
            "pre-auth cookie in its own slot",
            call("GET", "/api/me").cookie(&signed_cookie(
                "seamless-ephemeral",
                json!({ "sub": "u1", "token": token("ephemeral") }),
            )),
            401,
        ),
        (
            "refresh cookie in the access slot",
            call("GET", "/api/me").cookie(&raw_cookie(
                "seamless-access",
                "refresh",
                json!({ "sub": "u1", "refreshToken": "r1" }),
            )),
            401,
        ),
        (
            "access-kind cookie holding an ephemeral token",
            call("GET", "/api/me").cookie(&signed_cookie(
                "seamless-access",
                json!({ "sub": "u1", "token": token("ephemeral") }),
            )),
            401,
        ),
        (
            "access-kind cookie with no token",
            call("GET", "/api/me").cookie(&signed_cookie("seamless-access", json!({ "sub": "u1" }))),
            401,
        ),
        (
            "forged cookie",
            call("GET", "/api/me").cookie("seamless-access=a.b.c"),
            401,
        ),
        (
            "cookie wins over a valid bearer token",
            call("GET", "/api/me")
                .cookie("seamless-access=a.b.c")
                .header("authorization", &format!("Bearer {}", token("access"))),
            401,
        ),
        (
            "access token",
            call("GET", "/api/me").header("authorization", &format!("Bearer {}", token("access"))),
            200,
        ),
        // An ephemeral sign-in token is signed by the same key and must not pass.
        (
            "ephemeral token",
            call("GET", "/api/me").header("authorization", &format!("Bearer {}", token("ephemeral"))),
            401,
        ),
        (
            "token for another audience",
            call("GET", "/api/me").header(
                "authorization",
                &format!(
                    "Bearer {}",
                    sign_rs256(json!({ "sub": "u1", "typ": "access", "iss": api.url, "aud": "https://elsewhere" }))
                ),
            ),
            401,
        ),
        (
            "token from another issuer",
            call("GET", "/api/me").header(
                "authorization",
                &format!(
                    "Bearer {}",
                    sign_rs256(json!({ "sub": "u1", "typ": "access", "iss": "https://elsewhere", "aud": api.url }))
                ),
            ),
            401,
        ),
        (
            "audience as an array",
            call("GET", "/api/me").header(
                "authorization",
                &format!(
                    "Bearer {}",
                    sign_rs256(json!({ "sub": "u1", "typ": "access", "iss": api.url, "aud": ["other", api.url] }))
                ),
            ),
            200,
        ),
        (
            "expired token",
            call("GET", "/api/me").header("authorization", &format!("Bearer {expired}")),
            401,
        ),
        (
            "HS256 token under the cookie secret",
            call("GET", "/api/me").header("authorization", &format!("Bearer {hs256_access}")),
            401,
        ),
    ];

    for (name, request, status) in cases {
        let r = request.through(guarded(&adapter)).await;
        assert_eq!(r.status, status, "{name}: {}", r.text);
        if status == 200 {
            assert_eq!(r.body["id"], "u1", "{name}");
        } else {
            assert_eq!(r.body["error"], "unauthenticated", "{name}");
        }
    }
}

#[tokio::test]
async fn the_user_extractor_refuses_an_unguarded_route() {
    let api = FakeApi::start().await;
    let router = Router::new().route("/open", get(|user: User| async move { user.id }));
    let r = call("GET", "/open").through(router).await;
    assert_eq!(r.status, 401);
    let _ = api;
}

#[tokio::test]
async fn authenticate_without_the_layer() {
    let api = FakeApi::start().await;
    let adapter = api.adapter(|b| b);
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {}", api.token("u1", "access"))).unwrap(),
    );
    assert_eq!(adapter.authenticate(&headers).await.unwrap().id, "u1");
    assert!(adapter.authenticate(&HeaderMap::new()).await.is_err());
}

#[tokio::test]
async fn a_cookie_session_is_refused_for_cross_site_state_changes() {
    let api = FakeApi::start().await;
    let adapter = api.adapter(|b| b);
    let cookie = signed_cookie(
        "seamless-access",
        json!({ "sub": "u1", "token": api.token("u1", "access") }),
    );
    let router = || {
        Router::new().route(
            "/api/transfer",
            axum::routing::post(|user: User| async move { user.id })
                .route_layer(adapter.require_auth()),
        )
    };

    let r = call("POST", "/api/transfer")
        .cookie(&cookie)
        .header("sec-fetch-site", "cross-site")
        .through(router())
        .await;
    assert_eq!(r.status, 403);
    let r = call("POST", "/api/transfer")
        .cookie(&cookie)
        .header("sec-fetch-site", "same-origin")
        .through(router())
        .await;
    assert_eq!(r.status, 200);
    // A bearer token is never attached by a browser, so it needs no such check.
    let r = call("POST", "/api/transfer")
        .header(
            "authorization",
            &format!("Bearer {}", api.token("u1", "access")),
        )
        .header("sec-fetch-site", "cross-site")
        .through(router())
        .await;
    assert_eq!(r.status, 200);
}

#[test]
fn debug_output_redacts_the_token() {
    let user = User {
        id: "u1".into(),
        roles: vec![],
        email: None,
        phone: None,
        token: "live-access-token".into(),
    };
    assert!(!format!("{user:?}").contains("live-access-token"));
}
