use axum::Json;
use axum::http::StatusCode;
use axum::routing::get;
use serde_json::{Value, json};

use super::*;
use crate::permission::Held;
use crate::{BuildError, PermissionRule, RequireAuthLayer, User};

const LIVE: &str = "/users/me/permissions";
const DENIED: &str = r#"{"error":"insufficient_permission"}"#;
const UNAVAILABLE: &str = r#"{"error":"permissions_unavailable"}"#;

fn app(guard: RequireAuthLayer) -> Router {
    let handler = || get(|user: User| async move { Json(json!({ "id": user.id })) });
    Router::new()
        .route("/resource", handler().route_layer(guard.clone()))
        .route(
            "/orgs/{organizationId}",
            handler().route_layer(guard.clone()),
        )
        .route("/teams/{teamId}", handler().route_layer(guard))
}

fn access_token(api: &FakeApi, extra: Value) -> String {
    let mut claims = json!({ "sub": "u1", "typ": "access", "iss": api.url, "aud": api.url });
    for (k, v) in extra.as_object().unwrap() {
        claims[k] = v.clone();
    }
    sign_rs256(claims)
}

fn bearer_call(api: &FakeApi, path: &str, claims: Value) -> Call {
    let token = access_token(api, claims);
    call("GET", path).header("authorization", &format!("Bearer {token}"))
}

fn any(permissions: &[&str]) -> PermissionRule {
    PermissionRule::any(permissions.iter().copied())
}

fn all(permissions: &[&str]) -> PermissionRule {
    PermissionRule::all(permissions.iter().copied())
}

#[tokio::test]
async fn decides_from_the_token() {
    let api = FakeApi::start().await;
    let adapter = api.adapter(|b| b);
    let org = || any(&["p:read"]).organization();
    let bound = || any(&["p:read"]).organization_from_path("organizationId");
    let org_grant = json!({ "org_id": "o1", "org_permissions": ["p:read"] });

    let cases: Vec<(&str, PermissionRule, &str, Value, u16)> = vec![
        // Any of, the default.
        (
            "any: first held",
            any(&["p:read", "p:other"]),
            "/resource",
            json!({ "permissions": ["p:read"] }),
            200,
        ),
        (
            "any: second held",
            any(&["p:read", "p:other"]),
            "/resource",
            json!({ "permissions": ["p:other"] }),
            200,
        ),
        (
            "any: none held",
            any(&["p:read", "p:other"]),
            "/resource",
            json!({ "permissions": ["p:else"] }),
            403,
        ),
        (
            "any: no claims",
            any(&["p:read"]),
            "/resource",
            json!({}),
            403,
        ),
        (
            "any: empty claim",
            any(&["p:read"]),
            "/resource",
            json!({ "permissions": [] }),
            403,
        ),
        (
            "any: an organization grant counts by default",
            any(&["p:read"]),
            "/resource",
            json!({ "org_permissions": ["p:read"] }),
            200,
        ),
        (
            "any: with an active organization",
            any(&["p:read"]),
            "/resource",
            org_grant.clone(),
            200,
        ),
        // All of.
        (
            "all: both held",
            all(&["p:read", "p:write"]),
            "/resource",
            json!({ "permissions": ["p:read", "p:write"] }),
            200,
        ),
        (
            "all: one short",
            all(&["p:read", "p:write"]),
            "/resource",
            json!({ "permissions": ["p:read"] }),
            403,
        ),
        (
            "all: each from either claim",
            all(&["p:read", "p:write"]),
            "/resource",
            json!({ "permissions": ["p:read"], "org_permissions": ["p:write"] }),
            200,
        ),
        (
            "all: none held",
            all(&["p:read", "p:write"]),
            "/resource",
            json!({}),
            403,
        ),
        // Matching is exact, unlike a role.
        (
            "exact: write does not satisfy read",
            any(&["p:read"]),
            "/resource",
            json!({ "permissions": ["p:write"] }),
            403,
        ),
        (
            "exact: case-sensitive",
            any(&["p:read"]),
            "/resource",
            json!({ "permissions": ["P:READ"] }),
            403,
        ),
        (
            "exact: no trimming of the claim",
            any(&["p:read"]),
            "/resource",
            json!({ "permissions": [" p:read "] }),
            403,
        ),
        (
            "exact: no trimming of the requirement",
            any(&[" p:read"]),
            "/resource",
            json!({ "permissions": ["p:read"] }),
            403,
        ),
        (
            "exact: no wildcard",
            any(&["p:read"]),
            "/resource",
            json!({ "permissions": ["p:*", "*"] }),
            403,
        ),
        (
            "exact: no unscoped grant",
            any(&["p:read"]),
            "/resource",
            json!({ "permissions": ["p"] }),
            403,
        ),
        // Roles are a different thing.
        (
            "a role is not a permission",
            any(&["admin"]),
            "/resource",
            json!({ "roles": ["admin"] }),
            403,
        ),
        (
            "an organization role is not a permission",
            any(&["admin"]),
            "/resource",
            json!({ "org_id": "o1", "org_roles": ["admin"] }),
            403,
        ),
        // Organization scope.
        (
            "organization: held",
            org(),
            "/resource",
            org_grant.clone(),
            200,
        ),
        (
            "organization: instance grants do not count",
            org(),
            "/resource",
            json!({ "org_id": "o1", "permissions": ["p:read"] }),
            403,
        ),
        (
            "organization: needs org_id",
            org(),
            "/resource",
            json!({ "org_permissions": ["p:read"] }),
            403,
        ),
        (
            "organization: an empty org_id is none",
            org(),
            "/resource",
            json!({ "org_id": "", "org_permissions": ["p:read"] }),
            403,
        ),
        (
            "organization: not held",
            org(),
            "/resource",
            json!({ "org_id": "o1", "org_permissions": ["p:else"] }),
            403,
        ),
        (
            "organization: all of",
            all(&["p:read", "p:write"]).organization(),
            "/resource",
            json!({ "org_id": "o1", "permissions": ["p:read"], "org_permissions": ["p:write"] }),
            403,
        ),
        // Organization scope bound to the route.
        (
            "bound: matching route",
            bound(),
            "/orgs/o1",
            org_grant.clone(),
            200,
        ),
        (
            "bound: another organization's route",
            bound(),
            "/orgs/o2",
            org_grant.clone(),
            403,
        ),
        (
            "bound: case-sensitive",
            bound(),
            "/orgs/O1",
            org_grant.clone(),
            403,
        ),
        (
            "bound: percent-decoded like any route parameter",
            bound(),
            "/orgs/%6F1",
            org_grant.clone(),
            200,
        ),
        (
            "bound: a route without the parameter",
            bound(),
            "/resource",
            org_grant.clone(),
            403,
        ),
        (
            "bound: a route naming another parameter",
            bound(),
            "/teams/o1",
            org_grant.clone(),
            403,
        ),
        (
            "bound: instance grants do not count",
            bound(),
            "/orgs/o1",
            json!({ "org_id": "o1", "permissions": ["p:read"] }),
            403,
        ),
        (
            "bound: no active organization",
            bound(),
            "/orgs/o1",
            json!({ "org_permissions": ["p:read"] }),
            403,
        ),
        // Malformed claims read as empty, and never fail the request.
        (
            "malformed: permissions a string",
            any(&["p:read"]),
            "/resource",
            json!({ "permissions": "p:read" }),
            403,
        ),
        (
            "malformed: permissions an object",
            any(&["p:read"]),
            "/resource",
            json!({ "permissions": { "p:read": true } }),
            403,
        ),
        (
            "malformed: permissions null",
            any(&["p:read"]),
            "/resource",
            json!({ "permissions": null }),
            403,
        ),
        (
            "malformed: org_permissions a number",
            any(&["p:read"]),
            "/resource",
            json!({ "org_permissions": 1 }),
            403,
        ),
        (
            "malformed: non-string entries ignored",
            any(&["p:read"]),
            "/resource",
            json!({ "permissions": [1, null, {}, "p:read"] }),
            200,
        ),
        (
            "malformed: org_id not a string",
            org(),
            "/resource",
            json!({ "org_id": 7, "org_permissions": ["p:read"] }),
            403,
        ),
        (
            "malformed: permissions_omitted not true is not omitted",
            any(&["p:read"]),
            "/resource",
            json!({ "permissions_omitted": "true", "permissions": ["p:read"] }),
            200,
        ),
        (
            "malformed: permissions_omitted false",
            any(&["p:read"]),
            "/resource",
            json!({ "permissions_omitted": false }),
            403,
        ),
    ];

    for (name, rule, path, claims, want) in cases {
        let guard = adapter.require_permission_rule(rule).unwrap();
        let reply = bearer_call(&api, path, claims).through(app(guard)).await;
        assert_eq!(reply.status, want, "{name}: {}", reply.text);
        if want == 403 {
            assert_eq!(reply.text, DENIED, "{name}");
        }
    }
    assert!(api.calls_to("GET", LIVE).is_empty());
}

#[tokio::test]
async fn the_shorthands_mean_any_and_all() {
    let api = FakeApi::start().await;
    let adapter = api.adapter(|b| b);
    let one = json!({ "permissions": ["p:read"] });

    let guard = adapter.require_permission(["p:read", "p:write"]).unwrap();
    let reply = bearer_call(&api, "/resource", one.clone())
        .through(app(guard))
        .await;
    assert_eq!(reply.status, 200);

    let guard = adapter
        .require_all_permissions(vec!["p:read".to_string(), "p:write".to_string()])
        .unwrap();
    let reply = bearer_call(&api, "/resource", one)
        .through(app(guard))
        .await;
    assert_eq!(reply.status, 403);
}

#[tokio::test]
async fn an_empty_list_never_opens_a_route() {
    let api = FakeApi::start().await;
    let adapter = api.adapter(|b| b);
    let none = Vec::<String>::new;

    for result in [
        adapter.require_permission(none()),
        adapter.require_all_permissions(none()),
        adapter.require_permission_rule(PermissionRule::any(none()).organization()),
        adapter.require_permission_rule(PermissionRule::all(none()).organization()),
        adapter.require_permission_rule(PermissionRule::any(none()).organization_from_path("id")),
        adapter.require_permission_rule(PermissionRule::all(none()).organization_from_path("id")),
        adapter.require_permission([""]),
        adapter.require_all_permissions(["p:read", "  "]),
    ] {
        assert_eq!(result.unwrap_err(), BuildError::EmptyGuard);
    }
    assert!(adapter.require_permission(["p:read"]).is_ok());

    // No guard can be built from one, and the rule refuses on its own as well.
    let held = ["p:read".to_string()];
    let everything = Held {
        permissions: &held,
        organization_id: Some("o1"),
        organization_permissions: &held,
    };
    for rule in [
        PermissionRule::any(none()),
        PermissionRule::all(none()),
        PermissionRule::any(none()).organization(),
        PermissionRule::all(none()).organization(),
        PermissionRule::any(none()).organization_from_path("id"),
        PermissionRule::all(none()).organization_from_path("id"),
    ] {
        assert!(!rule.allows(everything, Some("o1")), "{rule:?}");
    }
}

#[tokio::test]
async fn leaves_authentication_answers_unchanged() {
    let api = FakeApi::start().await;
    let adapter = api.adapter(|b| b);
    let guard = || adapter.require_permission(["p:read"]).unwrap();

    let reply = call("GET", "/resource").through(app(guard())).await;
    assert_eq!(reply.status, 401);
    assert_eq!(reply.body, json!({ "error": "unauthenticated" }));

    let reply = call("GET", "/resource")
        .header("authorization", "Bearer not.a.token")
        .through(app(guard()))
        .await;
    assert_eq!(reply.status, 401);
    assert_eq!(reply.body, json!({ "error": "unauthenticated" }));

    let recovering = json!({ "recovery": true, "permissions": ["p:read"] });
    let reply = bearer_call(&api, "/resource", recovering.clone())
        .through(app(guard()))
        .await;
    assert_eq!(reply.status, 403);
    assert_eq!(reply.body, json!({ "error": "enrollment_required" }));

    let reply = bearer_call(&api, "/resource", recovering)
        .through(app(guard().allow_recovery(true)))
        .await;
    assert_eq!(reply.status, 200);

    let reply = bearer_call(&api, "/resource", json!({ "recovery": true }))
        .through(app(guard().allow_recovery(true)))
        .await;
    assert_eq!(reply.status, 403);
    assert_eq!(reply.text, DENIED);

    // Omitted permissions change nothing for a recovery session: no live read.
    let reply = bearer_call(
        &api,
        "/resource",
        json!({ "recovery": true, "permissions_omitted": true }),
    )
    .through(app(guard()))
    .await;
    assert_eq!(reply.body, json!({ "error": "enrollment_required" }));
    assert!(api.calls_to("GET", LIVE).is_empty());
}

#[tokio::test]
async fn a_cookie_session_reads_the_token_inside_it() {
    let api = FakeApi::start().await;
    let adapter = api.adapter(|b| b);
    let guard = || adapter.require_permission(["p:read"]).unwrap();
    let cookie = |token: &str, extra: Value| {
        let mut claims = json!({ "sub": "u1", "token": token });
        for (k, v) in extra.as_object().unwrap() {
            claims[k] = v.clone();
        }
        signed_cookie("seamless-access", claims)
    };

    let holding = access_token(&api, json!({ "permissions": ["p:read"] }));
    let reply = call("GET", "/resource")
        .cookie(&cookie(&holding, json!({})))
        .through(app(guard()))
        .await;
    assert_eq!(reply.status, 200);

    // The cookie secret alone can sign a cookie, so its own claims grant nothing.
    let empty = access_token(&api, json!({}));
    let reply = call("GET", "/resource")
        .cookie(&cookie(&empty, json!({ "permissions": ["p:read"] })))
        .through(app(guard()))
        .await;
    assert_eq!(reply.status, 403);
    assert_eq!(reply.text, DENIED);

    let bound = adapter
        .require_permission_rule(any(&["p:read"]).organization_from_path("organizationId"))
        .unwrap();
    let org_token = access_token(
        &api,
        json!({ "org_id": "o1", "org_permissions": ["p:read"] }),
    );
    let reply = call("GET", "/orgs/o1")
        .cookie(&cookie(&org_token, json!({ "org_id": "o2" })))
        .through(app(bound.clone()))
        .await;
    assert_eq!(reply.status, 200);
    let reply = call("GET", "/orgs/o2")
        .cookie(&cookie(&org_token, json!({ "org_id": "o2" })))
        .through(app(bound))
        .await;
    assert_eq!(reply.status, 403);

    // A cookie's token that omits its permissions is read live, as the caller.
    api.on(
        "GET",
        LIVE,
        respond(
            200,
            json!({ "permissions": ["p:read"], "organizationId": null, "organizationPermissions": [] }),
        ),
    );
    let omitted = access_token(&api, json!({ "permissions_omitted": true }));
    let reply = call("GET", "/resource")
        .cookie(&cookie(&omitted, json!({})))
        .through(app(guard()))
        .await;
    assert_eq!(reply.status, 200);
    let calls = api.calls_to("GET", LIVE);
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].header("authorization"),
        format!("Bearer {omitted}")
    );
}

#[tokio::test]
async fn the_user_exposes_the_claims() {
    let api = FakeApi::start().await;
    let adapter = api.adapter(|b| b);
    let router = Router::new().route(
        "/resource",
        get(|user: User| async move {
            Json(json!({
                "organization_id": user.organization_id,
                "permissions": user.permissions,
                "organization_roles": user.organization_roles,
                "organization_permissions": user.organization_permissions,
                "permissions_omitted": user.permissions_omitted,
            }))
        })
        .route_layer(adapter.require_auth()),
    );
    let claims = json!({
        "org_id": "o1",
        "permissions": ["p:read", 1],
        "org_roles": ["admin"],
        "org_permissions": ["p:write"],
    });
    let want = json!({
        "organization_id": "o1",
        "permissions": ["p:read"],
        "organization_roles": ["admin"],
        "organization_permissions": ["p:write"],
        "permissions_omitted": false,
    });

    let reply = bearer_call(&api, "/resource", claims.clone())
        .through(router.clone())
        .await;
    assert_eq!(reply.body, want);

    let token = access_token(&api, claims);
    let reply = call("GET", "/resource")
        .cookie(&signed_cookie(
            "seamless-access",
            json!({ "sub": "u1", "token": token, "permissions": ["forged"], "org_id": "forged" }),
        ))
        .through(router.clone())
        .await;
    assert_eq!(reply.body, want);

    let reply = bearer_call(
        &api,
        "/resource",
        json!({ "org_id": "o1", "permissions_omitted": true }),
    )
    .through(router)
    .await;
    assert_eq!(
        reply.body,
        json!({
            "organization_id": "o1",
            "permissions": [],
            "organization_roles": [],
            "organization_permissions": [],
            "permissions_omitted": true,
        })
    );
}

#[tokio::test]
async fn organization_roles_never_count_for_require_role() {
    let api = FakeApi::start().await;
    let adapter = api.adapter(|b| b);
    let guard = adapter.require_role(["admin"]).unwrap();
    let reply = bearer_call(
        &api,
        "/resource",
        json!({ "org_id": "o1", "org_roles": ["admin"], "roles": ["user"] }),
    )
    .through(app(guard))
    .await;
    assert_eq!(reply.status, 403);
    assert_eq!(reply.body, json!({ "error": "insufficient_role" }));
}

fn live(permissions: Value, organization_id: Value, organization_permissions: Value) -> Value {
    json!({
        "roles": ["user"],
        "permissions": permissions,
        "organizationId": organization_id,
        "organizationRoles": [],
        "organizationPermissions": organization_permissions,
    })
}

#[tokio::test]
async fn omitted_permissions_are_read_live() {
    let api = FakeApi::start().await;
    let adapter = api.adapter(|b| b);
    let omitted = json!({ "permissions_omitted": true, "org_id": "o1" });
    let org = || any(&["p:read"]).organization();
    let bound = || any(&["p:read"]).organization_from_path("organizationId");

    let cases: Vec<(&str, PermissionRule, &str, Value, u16)> = vec![
        (
            "any: held",
            any(&["p:read", "p:other"]),
            "/resource",
            live(json!(["p:read"]), json!(null), json!([])),
            200,
        ),
        (
            "any: not held",
            any(&["p:read"]),
            "/resource",
            live(json!(["p:write"]), json!(null), json!([])),
            403,
        ),
        (
            "any: nothing held",
            any(&["p:read"]),
            "/resource",
            live(json!([]), json!(null), json!([])),
            403,
        ),
        (
            "any: an organization grant counts",
            any(&["p:read"]),
            "/resource",
            live(json!([]), json!("o1"), json!(["p:read"])),
            200,
        ),
        (
            "all: one short",
            all(&["p:read", "p:write"]),
            "/resource",
            live(json!(["p:read"]), json!(null), json!([])),
            403,
        ),
        (
            "all: each from either",
            all(&["p:read", "p:write"]),
            "/resource",
            live(json!(["p:read"]), json!("o1"), json!(["p:write"])),
            200,
        ),
        (
            "organization: held",
            org(),
            "/resource",
            live(json!([]), json!("o1"), json!(["p:read"])),
            200,
        ),
        (
            "organization: instance grants do not count",
            org(),
            "/resource",
            live(json!(["p:read"]), json!("o1"), json!([])),
            403,
        ),
        // The token still says o1, and the live answer is what counts.
        (
            "organization: gone from the live answer",
            org(),
            "/resource",
            live(json!([]), json!(null), json!(["p:read"])),
            403,
        ),
        (
            "bound: matching route",
            bound(),
            "/orgs/o1",
            live(json!([]), json!("o1"), json!(["p:read"])),
            200,
        ),
        (
            "bound: another organization's route",
            bound(),
            "/orgs/o2",
            live(json!([]), json!("o1"), json!(["p:read"])),
            403,
        ),
        (
            "bound: a route without the parameter",
            bound(),
            "/resource",
            live(json!([]), json!("o1"), json!(["p:read"])),
            403,
        ),
        (
            "non-string entries are ignored",
            any(&["p:read"]),
            "/resource",
            live(json!([1, "p:read"]), json!(null), json!([])),
            200,
        ),
    ];
    for (name, rule, path, body, want) in cases {
        api.on("GET", LIVE, respond(200, body));
        let guard = adapter.require_permission_rule(rule).unwrap();
        let reply = bearer_call(&api, path, omitted.clone())
            .through(app(guard))
            .await;
        assert_eq!(reply.status, want, "{name}: {}", reply.text);
        if want == 403 {
            assert_eq!(reply.text, DENIED, "{name}");
        }
    }
}

#[tokio::test]
async fn the_live_read_is_the_callers_and_is_not_cached() {
    let api = FakeApi::start().await;
    let adapter = api.adapter(|b| b);
    api.on(
        "GET",
        LIVE,
        respond(200, live(json!(["p:read"]), json!(null), json!([]))),
    );
    let guard = adapter.require_permission(["p:read"]).unwrap();
    let token = access_token(&api, json!({ "permissions_omitted": true }));
    let authorization = format!("Bearer {token}");
    let request = || call("GET", "/resource").header("authorization", &authorization);

    assert_eq!(request().through(app(guard.clone())).await.status, 200);
    assert_eq!(request().through(app(guard.clone())).await.status, 200);

    let calls = api.calls_to("GET", LIVE);
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].header("authorization"), authorization);
    assert_eq!(calls[0].header("x-seamless-service-token"), "");

    // A revocation applies at the very next request.
    api.on(
        "GET",
        LIVE,
        respond(200, live(json!([]), json!(null), json!([]))),
    );
    assert_eq!(request().through(app(guard)).await.status, 403);
}

#[tokio::test]
async fn a_token_without_the_marker_is_not_read_live() {
    let api = FakeApi::start().await;
    let adapter = api.adapter(|b| b);
    api.on(
        "GET",
        LIVE,
        respond(200, live(json!(["p:read"]), json!(null), json!([]))),
    );
    let guard = adapter.require_permission(["p:read"]).unwrap();
    let reply = bearer_call(&api, "/resource", json!({}))
        .through(app(guard))
        .await;
    assert_eq!(reply.status, 403);
    assert!(api.calls_to("GET", LIVE).is_empty());
}

#[tokio::test]
async fn a_failed_live_read_fails_closed() {
    let api = FakeApi::start().await;
    let adapter = api.adapter(|b| b);
    let guard = adapter.require_permission(["p:read"]).unwrap();
    let omitted = json!({ "permissions_omitted": true, "permissions": ["p:read"] });
    let raw = |status: u16, body: &'static str| -> Handler {
        Arc::new(move |_| {
            let mut res = Response::new(Body::from(body));
            *res.status_mut() = StatusCode::from_u16(status).unwrap();
            res
        })
    };
    let good_permissions = json!(["p:read"]);
    let oversized = Box::leak(format!("[\"{}\"]", "x".repeat(2 << 20)).into_boxed_str());

    let cases: Vec<(&str, Handler)> = vec![
        ("500", respond(500, json!({ "error": "boom" }))),
        ("503", respond(503, json!({ "error": "down" }))),
        ("403", respond(403, json!({ "error": "forbidden" }))),
        ("404", respond(404, json!({ "error": "not_found" }))),
        ("redirect", raw(302, "")),
        // A non-2xx whose body claims the permission.
        (
            "500 with a good body",
            respond(500, live(good_permissions.clone(), json!(null), json!([]))),
        ),
        ("not JSON", raw(200, "<html>")),
        ("empty body", raw(200, "")),
        ("204", raw(204, "")),
        ("JSON array", respond(200, json!(["p:read"]))),
        ("JSON string", respond(200, json!("p:read"))),
        ("JSON null", respond(200, Value::Null)),
        ("empty object", respond(200, json!({}))),
        (
            "permissions absent",
            respond(
                200,
                json!({ "organizationId": null, "organizationPermissions": [] }),
            ),
        ),
        (
            "permissions not a list",
            respond(200, live(json!("p:read"), json!(null), json!([]))),
        ),
        (
            "organizationPermissions absent",
            respond(
                200,
                json!({ "permissions": ["p:read"], "organizationId": null }),
            ),
        ),
        (
            "organizationPermissions not a list",
            respond(200, live(good_permissions.clone(), json!(null), json!("x"))),
        ),
        (
            "organizationId absent",
            respond(
                200,
                json!({ "permissions": ["p:read"], "organizationPermissions": [] }),
            ),
        ),
        (
            "organizationId not a string",
            respond(200, live(good_permissions.clone(), json!(7), json!([]))),
        ),
        ("too large", raw(200, oversized)),
    ];
    for (name, handler) in cases {
        api.on("GET", LIVE, handler);
        let before = api.calls_to("GET", LIVE).len();
        let reply = bearer_call(&api, "/resource", omitted.clone())
            .through(app(guard.clone()))
            .await;
        assert_eq!(reply.status, 503, "{name}: {}", reply.text);
        assert_eq!(reply.text, UNAVAILABLE, "{name}");
        assert_eq!(
            api.calls_to("GET", LIVE).len(),
            before + 1,
            "{name}: no retry"
        );
    }
}

#[tokio::test]
async fn a_401_from_the_live_read_is_the_existing_401() {
    let api = FakeApi::start().await;
    let adapter = api.adapter(|b| b);
    api.on("GET", LIVE, respond(401, json!({ "error": "revoked" })));
    let guard = adapter.require_permission(["p:read"]).unwrap();
    let reply = bearer_call(&api, "/resource", json!({ "permissions_omitted": true }))
        .through(app(guard))
        .await;
    assert_eq!(reply.status, 401);
    assert_eq!(reply.body, json!({ "error": "unauthenticated" }));
}

// A worker thread is left free to run the client's timer while the handler sleeps.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_read_timeout_fails_closed() {
    let api = FakeApi::start().await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(200))
        .build()
        .unwrap();
    let adapter = api.adapter(|b| b.http_client(client));
    api.on(
        "GET",
        LIVE,
        Arc::new(|_| {
            std::thread::sleep(Duration::from_millis(600));
            json_reply(200, live(json!(["p:read"]), json!(null), json!([])))
        }),
    );
    let guard = adapter.require_permission(["p:read"]).unwrap();
    let reply = bearer_call(&api, "/resource", json!({ "permissions_omitted": true }))
        .through(app(guard))
        .await;
    assert_eq!(reply.status, 503);
    assert_eq!(reply.text, UNAVAILABLE);
}
