use axum::Json;
use axum::routing::get;
use serde_json::{Value, json};

use super::*;
use crate::token_guard::role_grants_access;
use crate::verifier::jwks_uri_from;
use crate::{PermissionRule, StepUp, TokenGuardLayer, TokenUser, Verifier, VerifierBuildError};

// Copied byte for byte from seamless-auth-server,
// packages/core/tests/fixtures/verify-only/vectors.json, which every adapter's
// verify-only mode is held to. Regenerate it there, never here.
const VECTORS: &str = include_str!("../testdata/verify-only-vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

async fn vector_verifier(v: &Value) -> (FakeApi, Verifier) {
    let api = FakeApi::start().await;
    api.on("GET", "/vectors/jwks", respond(200, v["jwks"].clone()));
    let now = v["now"].as_u64().unwrap();
    let verifier = Verifier::builder(v["issuer"].as_str().unwrap())
        .audience(v["audience"].as_str().unwrap())
        .jwks_uri(format!("{}/vectors/jwks", api.url))
        .clock(move || now)
        .build()
        .unwrap();
    (api, verifier)
}

fn guard_for(verifier: &Verifier, guard: &Value) -> Option<TokenGuardLayer> {
    let strings = |name: &str| -> Vec<String> {
        guard[name]
            .as_array()
            .map(|a| a.iter().map(|s| s.as_str().unwrap().to_string()).collect())
            .unwrap_or_default()
    };
    match guard["kind"].as_str()? {
        "scope" => Some(verifier.require_scope(strings("scopes")).unwrap()),
        "role" => Some(verifier.require_role(strings("roles")).unwrap()),
        "step_up" => {
            let mut step_up = StepUp::new()
                .acr_values(strings("acr_values"))
                .amr(strings("amr"));
            if let Some(max_age) = guard["max_age"].as_u64() {
                step_up = step_up.max_age(max_age);
            }
            Some(verifier.require_step_up(step_up).unwrap())
        }
        other => panic!("unknown guard kind {other}"),
    }
}

fn protected(verifier: &Verifier, guard: Option<TokenGuardLayer>) -> Router {
    protected_with(verifier, guard, true)
}

fn protected_with(
    verifier: &Verifier,
    guard: Option<TokenGuardLayer>,
    allow_clients: bool,
) -> Router {
    let route = get(|user: TokenUser| async move { Json(json!({ "sub": user.sub })) });
    let route = match guard {
        Some(guard) => route.route_layer(guard),
        None => route,
    };
    Router::new().route(
        "/resource",
        route.route_layer(verifier.require_auth().allow_clients(allow_clients)),
    )
}

async fn send(app: Router, authorization: Option<&str>) -> (u16, Option<String>, Value) {
    let mut req = Request::builder().uri("/resource");
    if let Some(value) = authorization {
        req = req.header("authorization", value);
    }
    let res = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
    let status = res.status().as_u16();
    let challenge = res
        .headers()
        .get("www-authenticate")
        .map(|v| v.to_str().unwrap().to_string());
    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    (
        status,
        challenge,
        serde_json::from_slice(&body).unwrap_or(Value::Null),
    )
}

fn parts_with(authorization: &str) -> axum::http::request::Parts {
    Request::builder()
        .uri("/resource")
        .header("authorization", authorization)
        .body(())
        .unwrap()
        .into_parts()
        .0
}

fn user_fields(user: &TokenUser) -> Value {
    json!({
        "sub": user.sub,
        "client_id": user.client_id,
        "scopes": user.scopes,
        "roles": user.roles,
        "sid": user.sid,
        "org_id": user.org_id,
        "acr": user.acr,
        "amr": user.amr,
        "auth_time": user.auth_time,
    })
}

#[tokio::test]
async fn verify_vectors() {
    let v = vectors();
    let (_api, verifier) = vector_verifier(&v).await;
    let cases = v["verify"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let token = v["tokens"][name].as_str().unwrap();
        let result = verifier
            .authenticate(&parts_with(&format!("Bearer {token}")))
            .await;
        if case["valid"].as_bool().unwrap() {
            let user = result.unwrap_or_else(|e| panic!("{name}: rejected ({e})"));
            assert_eq!(user_fields(&user), case["user"], "{name}");
            assert_eq!(
                user.is_client,
                case["is_client"].as_bool().unwrap(),
                "{name}"
            );
        } else {
            assert_eq!(result, Err(crate::TokenError::InvalidToken), "{name}");
        }
    }
}

#[tokio::test]
async fn request_vectors() {
    run_request_vectors("requests").await;
}

#[tokio::test]
async fn user_required_request_vectors() {
    run_request_vectors("user_required_requests").await;
}

async fn run_request_vectors(list: &str) {
    let v = vectors();
    let (_api, verifier) = vector_verifier(&v).await;
    let cases = v[list].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let allow_clients = case["auth"]["allow_clients"].as_bool().unwrap_or(true);
        let app = protected_with(
            &verifier,
            guard_for(&verifier, &case["guard"]),
            allow_clients,
        );
        let (status, challenge, body) = send(app, case["authorization"].as_str()).await;
        let expect = &case["expect"];
        assert_eq!(status, expect["status"].as_u64().unwrap() as u16, "{name}");
        assert_eq!(
            challenge.as_deref(),
            expect["www_authenticate"].as_str(),
            "{name}"
        );
        if expect["body"].is_null() {
            assert!(body["sub"].is_string(), "{name}: handler did not answer");
        } else {
            assert_eq!(body, expect["body"], "{name}");
        }
    }
}

fn own_token(issuer: &str, extra: Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("k1".into());
    header.typ = Some("at+jwt".into());
    let now = jsonwebtoken::get_current_timestamp();
    let mut body = json!({
        "iss": issuer,
        "aud": "https://api.example.test",
        "sub": "u1",
        "client_id": "app",
        "iat": now,
        "exp": now + 300,
    });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    let key = EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes()).unwrap();
    jsonwebtoken::encode(&header, &body, &key).unwrap()
}

fn discovering(api: &FakeApi) -> Verifier {
    Verifier::builder(&api.url)
        .audience("https://api.example.test")
        .build()
        .unwrap()
}

const DISCOVERY: &str = "/.well-known/openid-configuration";

#[tokio::test]
async fn discovery_happens_once() {
    let api = FakeApi::start().await;
    api.on(
        "GET",
        DISCOVERY,
        respond(
            200,
            json!({ "issuer": api.url, "jwks_uri": format!("{}/.well-known/jwks.json", api.url) }),
        ),
    );
    let verifier = discovering(&api);
    let token = own_token(&api.url, json!({}));
    for _ in 0..3 {
        let (status, _, body) =
            send(protected(&verifier, None), Some(&format!("Bearer {token}"))).await;
        assert_eq!(status, 200);
        assert_eq!(body["sub"], "u1");
    }
    assert_eq!(api.calls_to("GET", DISCOVERY).len(), 1);
    assert_eq!(api.calls_to("GET", "/.well-known/jwks.json").len(), 1);
}

#[tokio::test]
async fn discovery_issuer_mismatch_is_invalid_token() {
    let api = FakeApi::start().await;
    api.on(
        "GET",
        DISCOVERY,
        respond(
            200,
            json!({ "issuer": format!("{}/", api.url), "jwks_uri": format!("{}/.well-known/jwks.json", api.url) }),
        ),
    );
    let verifier = discovering(&api);
    let token = own_token(&api.url, json!({}));
    let (status, challenge, body) =
        send(protected(&verifier, None), Some(&format!("Bearer {token}"))).await;
    assert_eq!(status, 401);
    assert_eq!(challenge.as_deref(), Some("Bearer error=\"invalid_token\""));
    assert_eq!(body, json!({ "error": "invalid_token" }));
    assert!(api.calls_to("GET", "/.well-known/jwks.json").is_empty());
}

#[tokio::test]
async fn discovery_failure_is_401_and_backs_off() {
    let api = FakeApi::start().await;
    api.on("GET", DISCOVERY, respond(500, json!({ "error": "down" })));
    let verifier = discovering(&api);
    let token = own_token(&api.url, json!({}));
    for _ in 0..3 {
        let (status, _, body) =
            send(protected(&verifier, None), Some(&format!("Bearer {token}"))).await;
        assert_eq!(status, 401);
        assert_eq!(body, json!({ "error": "invalid_token" }));
    }
    assert_eq!(api.calls_to("GET", DISCOVERY).len(), 1);
}

#[tokio::test]
async fn unreachable_keys_are_invalid_token() {
    let verifier = Verifier::builder("https://login.example.test")
        .audience("https://api.example.test")
        .jwks_uri("http://127.0.0.1:9/jwks")
        .build()
        .unwrap();
    let token = own_token("https://login.example.test", json!({}));
    let (status, _, body) =
        send(protected(&verifier, None), Some(&format!("Bearer {token}"))).await;
    assert_eq!(status, 401);
    assert_eq!(body, json!({ "error": "invalid_token" }));
}

#[test]
fn discovery_document_checks() {
    let https = "https://login.example.test";
    let doc = |issuer: &str, jwks: Value| json!({ "issuer": issuer, "jwks_uri": jwks });
    assert_eq!(
        jwks_uri_from(&doc(https, json!("https://login.example.test/jwks")), https),
        Ok("https://login.example.test/jwks".to_string())
    );
    assert!(jwks_uri_from(&doc(https, json!("http://login.example.test/jwks")), https).is_err());
    assert!(
        jwks_uri_from(
            &doc("https://login.example.test/", json!("https://x/jwks")),
            https
        )
        .is_err()
    );
    assert!(jwks_uri_from(&doc(https, json!("ftp://login.example.test/jwks")), https).is_err());
    assert!(jwks_uri_from(&doc(https, json!(42)), https).is_err());
    assert!(jwks_uri_from(&json!(["not", "an", "object"]), https).is_err());
    let http = "http://localhost:5312";
    assert!(jwks_uri_from(&doc(http, json!("http://localhost:5312/jwks")), http).is_ok());
}

#[test]
fn construction_errors() {
    let build = |issuer: &str, audience: Option<&str>| {
        let mut b = Verifier::builder(issuer);
        if let Some(a) = audience {
            b = b.audience(a);
        }
        b.build().map(|_| ())
    };
    assert_eq!(
        build("login.example.test", Some("a")),
        Err(VerifierBuildError::InvalidIssuer)
    );
    assert_eq!(
        build("ftp://login.example.test", Some("a")),
        Err(VerifierBuildError::InvalidIssuer)
    );
    assert_eq!(
        build("https://login.example.test", None),
        Err(VerifierBuildError::MissingAudience)
    );
    assert_eq!(
        build("https://login.example.test", Some("")),
        Err(VerifierBuildError::MissingAudience)
    );
    assert_eq!(
        Verifier::builder("https://login.example.test")
            .audience("a")
            .jwks_uri("/jwks")
            .build()
            .map(|_| ()),
        Err(VerifierBuildError::InvalidJwksUri)
    );

    let verifier = Verifier::builder("https://login.example.test")
        .audience("a")
        .build()
        .unwrap();
    assert_eq!(
        verifier.require_step_up(StepUp::new()).map(|_| ()),
        Err(VerifierBuildError::EmptyStepUp)
    );
    assert!(
        verifier
            .require_step_up(StepUp::new().acr_values(["bad\"value"]))
            .is_err()
    );

    let empty: [&str; 0] = [];
    assert_eq!(
        verifier.require_scope(empty).map(|_| ()),
        Err(VerifierBuildError::EmptyGuard)
    );
    assert!(verifier.require_scope([""]).is_err());
    assert!(verifier.require_scope(["a b"]).is_err());
    assert_eq!(
        verifier.require_role(empty).map(|_| ()),
        Err(VerifierBuildError::EmptyGuard)
    );
    assert_eq!(
        verifier.require_role(["admin", " "]).map(|_| ()),
        Err(VerifierBuildError::EmptyGuard)
    );
}

#[tokio::test]
async fn confirmation_hook_accepts_a_cnf_token() {
    let v = vectors();
    let api = FakeApi::start().await;
    api.on("GET", "/vectors/jwks", respond(200, v["jwks"].clone()));
    let now = v["now"].as_u64().unwrap();
    let seen: Arc<Mutex<Vec<Value>>> = Arc::default();
    let sink = seen.clone();
    let verifier = Verifier::builder(v["issuer"].as_str().unwrap())
        .audience(v["audience"].as_str().unwrap())
        .jwks_uri(format!("{}/vectors/jwks", api.url))
        .clock(move || now)
        .confirmation(move |c| {
            sink.lock().unwrap().push(c.cnf.clone());
            async move { c.method == "GET" && c.uri.path() == "/resource" }
        })
        .build()
        .unwrap();
    let token = v["tokens"]["cnf_bound"].as_str().unwrap();
    let (status, _, _) = send(protected(&verifier, None), Some(&format!("Bearer {token}"))).await;
    assert_eq!(status, 200);
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].is_object());

    let refusing = Verifier::builder(v["issuer"].as_str().unwrap())
        .audience(v["audience"].as_str().unwrap())
        .jwks_uri(format!("{}/vectors/jwks", api.url))
        .clock(move || now)
        .confirmation(|_| async { false })
        .build()
        .unwrap();
    let (status, _, body) =
        send(protected(&refusing, None), Some(&format!("Bearer {token}"))).await;
    assert_eq!(status, 401);
    assert_eq!(body, json!({ "error": "invalid_token" }));
}

#[tokio::test]
async fn guard_without_verification_answers_missing_token() {
    let verifier = Verifier::builder("https://login.example.test")
        .audience("a")
        .build()
        .unwrap();
    let app = Router::new().route(
        "/resource",
        get(|| async { "ok" }).route_layer(verifier.require_scope(["x"]).unwrap()),
    );
    let (status, challenge, body) = send(app, Some("Bearer whatever")).await;
    assert_eq!(status, 401);
    assert_eq!(challenge.as_deref(), Some("Bearer"));
    assert_eq!(body, json!({ "error": "missing_token" }));
}

fn permission_app(verifier: &Verifier, guard: TokenGuardLayer) -> Router {
    let handler = || get(|user: TokenUser| async move { Json(json!({ "sub": user.sub })) });
    Router::new()
        .route(
            "/resource",
            handler()
                .route_layer(guard.clone())
                .route_layer(verifier.require_auth()),
        )
        .route(
            "/orgs/{organizationId}",
            handler()
                .route_layer(guard)
                .route_layer(verifier.require_auth()),
        )
}

#[tokio::test]
async fn require_permission_decides_from_the_token() {
    let api = FakeApi::start().await;
    let verifier = Verifier::builder(&api.url)
        .audience("https://api.example.test")
        .jwks_uri(format!("{}/.well-known/jwks.json", api.url))
        .build()
        .unwrap();
    let any = || verifier.require_permission(["a:read", "a:other"]).unwrap();
    let all = || {
        verifier
            .require_all_permissions(["a:read", "a:write"])
            .unwrap()
    };
    let org = || {
        verifier
            .require_permission_rule(PermissionRule::any(["a:read"]).organization())
            .unwrap()
    };
    let bound = || {
        verifier
            .require_permission_rule(
                PermissionRule::any(["a:read"]).organization_from_path("organizationId"),
            )
            .unwrap()
    };

    let cases: Vec<(&str, TokenGuardLayer, &str, Value, u16)> = vec![
        (
            "a provider token today has no permission claims",
            any(),
            "/resource",
            json!({}),
            403,
        ),
        (
            "any: one held",
            any(),
            "/resource",
            json!({ "permissions": ["a:other"] }),
            200,
        ),
        (
            "any: an organization grant counts by default",
            any(),
            "/resource",
            json!({ "org_permissions": ["a:read"] }),
            200,
        ),
        (
            "exact: write does not satisfy read",
            any(),
            "/resource",
            json!({ "permissions": ["a:write"] }),
            403,
        ),
        (
            "all: one short",
            all(),
            "/resource",
            json!({ "permissions": ["a:read"] }),
            403,
        ),
        (
            "all: each from either claim",
            all(),
            "/resource",
            json!({ "permissions": ["a:read"], "org_permissions": ["a:write"] }),
            200,
        ),
        (
            "organization: needs org_id",
            org(),
            "/resource",
            json!({ "org_permissions": ["a:read"] }),
            403,
        ),
        (
            "organization: an empty org_id is none",
            org(),
            "/resource",
            json!({ "org_id": "", "org_permissions": ["a:read"] }),
            403,
        ),
        (
            "organization: instance grants do not count",
            org(),
            "/resource",
            json!({ "org_id": "o1", "permissions": ["a:read"] }),
            403,
        ),
        (
            "organization: held",
            org(),
            "/resource",
            json!({ "org_id": "o1", "org_permissions": ["a:read"] }),
            200,
        ),
        (
            "bound: matching route",
            bound(),
            "/orgs/o1",
            json!({ "org_id": "o1", "org_permissions": ["a:read"] }),
            200,
        ),
        (
            "bound: another organization's route",
            bound(),
            "/orgs/o2",
            json!({ "org_id": "o1", "org_permissions": ["a:read"] }),
            403,
        ),
        (
            "bound: no such parameter on the route",
            bound(),
            "/resource",
            json!({ "org_id": "o1", "org_permissions": ["a:read"] }),
            403,
        ),
        (
            "malformed claims read as empty and do not fail verification",
            any(),
            "/resource",
            json!({ "permissions": "a:read", "org_permissions": [1, null, {}], "org_roles": 7 }),
            403,
        ),
        (
            "non-string entries are ignored",
            any(),
            "/resource",
            json!({ "permissions": [1, "a:read"] }),
            200,
        ),
        // There is no live read: the first-party endpoint refuses provider tokens.
        (
            "permissions_omitted denies",
            any(),
            "/resource",
            json!({ "permissions_omitted": true, "permissions": ["a:read"] }),
            403,
        ),
    ];
    for (name, guard, path, claims, want) in cases {
        let token = own_token(&api.url, claims);
        let req = Request::builder()
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let res = permission_app(&verifier, guard).oneshot(req).await.unwrap();
        assert_eq!(res.status().as_u16(), want, "{name}");
        if want == 403 {
            assert!(!res.headers().contains_key("www-authenticate"), "{name}");
            let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
            assert_eq!(body, r#"{"error":"insufficient_permission"}"#, "{name}");
        }
    }
    assert!(api.calls_to("GET", "/users/me/permissions").is_empty());

    let (status, challenge, body) = send(permission_app(&verifier, any()), None).await;
    assert_eq!(status, 401);
    assert_eq!(challenge.as_deref(), Some("Bearer"));
    assert_eq!(body, json!({ "error": "missing_token" }));
}

#[tokio::test]
async fn token_user_exposes_the_permission_claims() {
    let api = FakeApi::start().await;
    let verifier = Verifier::builder(&api.url)
        .audience("https://api.example.test")
        .jwks_uri(format!("{}/.well-known/jwks.json", api.url))
        .build()
        .unwrap();
    let app = Router::new().route(
        "/resource",
        get(|user: TokenUser| async move {
            Json(json!({
                "permissions": user.permissions,
                "org_roles": user.org_roles,
                "org_permissions": user.org_permissions,
                "permissions_omitted": user.permissions_omitted,
            }))
        })
        .route_layer(verifier.require_auth()),
    );
    let token = own_token(
        &api.url,
        json!({
            "permissions": ["a:read", 1],
            "org_roles": ["admin"],
            "org_permissions": "not a list",
            "permissions_omitted": true,
        }),
    );
    let (status, _, body) = send(app, Some(&format!("Bearer {token}"))).await;
    assert_eq!(status, 200);
    assert_eq!(
        body,
        json!({
            "permissions": ["a:read"],
            "org_roles": ["admin"],
            "org_permissions": [],
            "permissions_omitted": true,
        })
    );
}

#[test]
fn require_permission_refuses_an_empty_guard() {
    let verifier = Verifier::builder("https://login.example.test")
        .audience("a")
        .build()
        .unwrap();
    let none = Vec::<String>::new;
    for result in [
        verifier.require_permission(none()),
        verifier.require_all_permissions(none()),
        verifier.require_permission_rule(PermissionRule::any(none()).organization()),
        verifier.require_permission_rule(PermissionRule::all(none()).organization_from_path("id")),
        verifier.require_permission([""]),
        verifier.require_all_permissions(["a:read", " "]),
    ] {
        assert_eq!(result.unwrap_err(), VerifierBuildError::EmptyGuard);
    }
    assert!(verifier.require_permission(["a:read"]).is_ok());
}

#[test]
fn role_matching() {
    assert!(role_grants_access("admin", "admin"));
    assert!(role_grants_access("billing:*", "billing"));
    assert!(role_grants_access("billing:*", "billing:invoices:read"));
    assert!(!role_grants_access("billing:*", "users:read"));
    assert!(role_grants_access("billing", "billing:invoices"));
    assert!(!role_grants_access("billing", "billingx:invoices"));
    assert!(role_grants_access(
        "billing:invoices:write",
        "billing:invoices:read"
    ));
    assert!(!role_grants_access(
        "billing:invoices:read",
        "billing:invoices:write"
    ));
    assert!(!role_grants_access("billing:write", "users:read"));
    assert!(!role_grants_access("billing:invoices", "billing"));
    assert!(!role_grants_access("", "admin"));
    assert!(!role_grants_access("admin", "   "));
    assert!(role_grants_access(" admin ", "admin"));
}
