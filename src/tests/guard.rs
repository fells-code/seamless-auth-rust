use axum::Json;
use axum::routing::get;
use serde_json::{Value, json};

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

#[tokio::test]
async fn a_recovery_session_needs_enrollment_unless_allowed() {
    let api = FakeApi::start().await;
    let adapter = api.adapter(|b| b);
    let recovery = sign_rs256(
        json!({ "sub": "u1", "typ": "access", "iss": api.url, "aud": api.url, "recovery": true }),
    );
    let not_recovery = sign_rs256(
        json!({ "sub": "u1", "typ": "access", "iss": api.url, "aud": api.url, "recovery": false }),
    );
    let cookie =
        |token: &str| signed_cookie("seamless-access", json!({ "sub": "u1", "token": token }));
    let allowing = Router::new().route(
        "/api/enroll",
        get(|user: User| async move { Json(json!({ "id": user.id, "recovery": user.recovery })) })
            .route_layer(adapter.require_auth().allow_recovery(true)),
    );

    for (name, request) in [
        ("cookie", call("GET", "/api/me").cookie(&cookie(&recovery))),
        (
            "bearer",
            call("GET", "/api/me").header("authorization", &format!("Bearer {recovery}")),
        ),
    ] {
        let r = request.through(guarded(&adapter)).await;
        assert_eq!(r.status, 403, "{name}: {}", r.text);
        assert_eq!(r.body, json!({ "error": "enrollment_required" }), "{name}");
    }

    let r = call("GET", "/api/me")
        .cookie(&cookie(&not_recovery))
        .through(guarded(&adapter))
        .await;
    assert_eq!(r.status, 200, "{}", r.text);

    let r = call("GET", "/api/enroll")
        .cookie(&cookie(&recovery))
        .through(allowing.clone())
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body, json!({ "id": "u1", "recovery": true }));
    let r = call("GET", "/api/enroll")
        .header(
            "authorization",
            &format!("Bearer {}", api.token("u1", "access")),
        )
        .through(allowing)
        .await;
    assert_eq!(r.body["recovery"], false);

    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {recovery}")).unwrap(),
    );
    assert!(adapter.authenticate(&headers).await.unwrap().recovery);
}

#[test]
fn debug_output_redacts_the_token() {
    let user = User {
        id: "u1".into(),
        roles: vec![],
        email: None,
        phone: None,
        token: "live-access-token".into(),
        recovery: false,
    };
    assert!(!format!("{user:?}").contains("live-access-token"));
}

fn access_cookie(sub: &str, token: &str, roles: Value) -> String {
    signed_cookie(
        "seamless-access",
        json!({ "sub": sub, "token": token, "roles": roles, "email": "u1@example.com" }),
    )
}

/// What a leaked cookie secret buys: any cookie, holding any inner token.
#[tokio::test]
async fn a_cookie_session_needs_an_inner_token_the_api_signed() {
    let api = FakeApi::start().await;
    let adapter = api.adapter(|b| b);
    let claims = |extra: Value| {
        let mut claims = json!({ "sub": "u1", "typ": "access", "iss": api.url, "aud": api.url });
        for (k, v) in extra.as_object().unwrap() {
            claims[k] = v.clone();
        }
        claims
    };
    let payload = sign_rs256(claims(json!({})))
        .split('.')
        .nth(1)
        .unwrap()
        .to_string();
    // {"alg":"none","typ":"JWT"}
    let unsigned = format!("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.{payload}.");

    let cases = [
        ("valid", sign_rs256(claims(json!({}))), 200),
        (
            "another key",
            sign_rs256_with(OTHER_KEY_PEM, claims(json!({}))),
            401,
        ),
        ("unsigned", unsigned, 401),
        (
            "another audience",
            sign_rs256(claims(json!({ "aud": "https://elsewhere" }))),
            401,
        ),
        (
            "another issuer",
            sign_rs256(claims(json!({ "iss": "https://elsewhere" }))),
            401,
        ),
        (
            "expired",
            sign_rs256(claims(json!({ "exp": 1_000_000 }))),
            401,
        ),
        (
            "not yet valid",
            sign_rs256(claims(
                json!({ "nbf": jsonwebtoken::get_current_timestamp() + 600 }),
            )),
            401,
        ),
        (
            "ephemeral",
            sign_rs256(claims(json!({ "typ": "ephemeral" }))),
            401,
        ),
        (
            "another subject",
            sign_rs256(claims(json!({ "sub": "u2" }))),
            401,
        ),
        ("not a token", "a.b.c".to_string(), 401),
    ];

    for (name, token, status) in cases {
        let r = call("GET", "/api/me")
            .cookie(&access_cookie("u1", &token, json!(["user"])))
            .through(guarded(&adapter))
            .await;
        assert_eq!(r.status, status, "{name}: {}", r.text);
        if status != 200 {
            assert_eq!(r.body, json!({ "error": "unauthenticated" }), "{name}");
        }
    }
}

#[tokio::test]
async fn a_cookie_session_takes_its_roles_from_the_verified_token() {
    let api = FakeApi::start().await;
    let adapter = api.adapter(|b| b);
    let token = sign_rs256(
        json!({ "sub": "u1", "typ": "access", "iss": api.url, "aud": api.url, "roles": ["user"] }),
    );
    let cookie = access_cookie("u1", &token, json!(["admin"]));
    let admin_only = Router::new().route(
        "/api/admin",
        get(|user: User| async move {
            if user.roles.iter().any(|r| r == "admin") {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            }
        })
        .route_layer(adapter.require_auth()),
    );

    let r = call("GET", "/api/me")
        .cookie(&cookie)
        .through(guarded(&adapter))
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["roles"], json!(["user"]));
    let r = call("GET", "/api/admin")
        .cookie(&cookie)
        .through(admin_only)
        .await;
    assert_eq!(r.status, 403);

    let mut headers = HeaderMap::new();
    headers.insert("cookie", HeaderValue::from_str(&cookie).unwrap());
    let user = adapter.authenticate(&headers).await.unwrap();
    assert_eq!(user.roles, ["user"]);
    assert_eq!(user.email.as_deref(), Some("u1@example.com"));
    assert_eq!(user.token, token);
}

#[tokio::test]
async fn a_cookie_session_fails_closed_when_the_jwks_is_unreachable() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let adapter = Adapter::builder(&url)
        .cookie_secret(TEST_SECRET)
        .service_secret(TEST_SERVICE)
        .jwks_kid("test-main")
        .disable_manifest_fetch(true)
        .build()
        .unwrap();
    let token = sign_rs256(json!({ "sub": "u1", "typ": "access", "iss": url, "aud": url }));

    let r = call("GET", "/api/me")
        .cookie(&access_cookie("u1", &token, json!(["user"])))
        .through(guarded(&adapter))
        .await;
    assert_eq!(r.status, 401, "{}", r.text);
}

#[tokio::test]
async fn an_empty_audience_verifies_nothing() {
    let api = FakeApi::start().await;
    let adapter = api.adapter(|b| b.audience(""));
    let token = sign_rs256(json!({ "sub": "u1", "typ": "access", "iss": api.url, "aud": "" }));

    for (name, request) in [
        (
            "cookie",
            call("GET", "/api/me").cookie(&access_cookie("u1", &token, json!(["user"]))),
        ),
        (
            "bearer",
            call("GET", "/api/me").header("authorization", &format!("Bearer {token}")),
        ),
    ] {
        let r = request.through(guarded(&adapter)).await;
        assert_eq!(r.status, 401, "{name}: {}", r.text);
    }
}

#[tokio::test]
async fn a_cookie_session_from_a_sibling_subdomain_needs_an_allowlisted_origin() {
    let api = FakeApi::start().await;
    let token = api.token("u1", "access");
    let cookie = access_cookie("u1", &token, json!(["user"]));
    let post = |adapter: &Adapter, origin: Option<&str>| {
        let router = Router::new().route(
            "/api/transfer",
            axum::routing::post(|user: User| async move { user.id })
                .route_layer(adapter.require_auth()),
        );
        let mut request = call("POST", "/api/transfer")
            .cookie(&cookie)
            .header("sec-fetch-site", "same-site");
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        request.through(router)
    };

    let listed = api.adapter(|b| b.allowed_origins(["https://app.example.com"]));
    assert_eq!(
        post(&listed, Some("https://app.example.com")).await.status,
        200
    );
    assert_eq!(
        post(&listed, Some("https://evil.example.com")).await.status,
        403
    );
    assert_eq!(post(&listed, None).await.status, 403);

    let unlisted = api.adapter(|b| b);
    assert_eq!(
        post(&unlisted, Some("https://evil.example.com"))
            .await
            .status,
        200
    );
}
