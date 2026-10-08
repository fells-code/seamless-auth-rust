use axum::body::Body;
use axum::http::HeaderValue;
use axum::response::Response;
use serde_json::json;

use super::*;

fn console_app(adapter: &Adapter) -> Router {
    Router::new().merge(adapter.console_router())
}

fn html(body: &'static str) -> Handler {
    Arc::new(move |_| {
        let mut res = Response::new(Body::from(body));
        res.headers_mut()
            .insert("content-type", HeaderValue::from_static("text/html"));
        res
    })
}

fn redirect(to: &'static str) -> Handler {
    Arc::new(move |_| {
        let mut res = Response::new(Body::empty());
        *res.status_mut() = axum::http::StatusCode::FOUND;
        res.headers_mut()
            .insert("location", HeaderValue::from_static(to));
        res
    })
}

#[tokio::test]
async fn the_console_is_proxied_from_the_auth_api() {
    let api = FakeApi::start().await;
    api.on(
        "GET",
        "/console/assets/app.js",
        Arc::new(|_| {
            let mut res = Response::new(Body::from("console();"));
            let headers = res.headers_mut();
            headers.insert("content-type", HeaderValue::from_static("text/javascript"));
            headers.insert("cache-control", HeaderValue::from_static("max-age=60"));
            headers.insert("set-cookie", HeaderValue::from_static("upstream=1"));
            res
        }),
    );
    let adapter = api.adapter(|b| b);
    let cookie = signed_cookie("seamless-access", json!({ "sub": "u1", "token": "t" }));

    let r = call("GET", "/console/assets/app.js?v=2")
        .cookie(&cookie)
        .header("authorization", "Bearer t")
        .through(console_app(&adapter))
        .await;

    assert_eq!(r.status, 200);
    assert_eq!(r.text, "console();");
    assert_eq!(r.headers["content-type"], "text/javascript");
    assert_eq!(r.headers["cache-control"], "max-age=60");
    assert!(
        r.headers.get("set-cookie").is_none(),
        "an upstream Set-Cookie reached the browser"
    );
    let recorded = &api.calls_to("GET", "/console/assets/app.js")[0];
    assert_eq!(recorded.query.as_deref(), Some("v=2"));
    assert_eq!(recorded.header("cookie"), "");
    assert_eq!(recorded.header("authorization"), "");
}

#[tokio::test]
async fn the_console_root_and_head() {
    let api = FakeApi::start().await;
    api.on("GET", "/console", html("<html>"));
    api.on("HEAD", "/console", html(""));
    let adapter = api.adapter(|b| b);

    let r = call("GET", "/console/")
        .through(console_app(&adapter))
        .await;
    assert_eq!((r.status, r.text.as_str()), (200, "<html>"));
    let r = call("HEAD", "/console/")
        .through(console_app(&adapter))
        .await;
    assert_eq!((r.status, r.text.as_str()), (200, ""));
}

#[tokio::test]
async fn the_console_refuses_other_methods() {
    let api = FakeApi::start().await;
    let adapter = api.adapter(|b| b);
    for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"] {
        let r = call(method, "/console/x")
            .through(console_app(&adapter))
            .await;
        assert_eq!(r.status, 405, "{method}");
    }
}

#[tokio::test]
async fn the_console_never_leaves_its_subtree() {
    let api = FakeApi::start().await;
    let adapter = api.adapter(|b| b);
    for target in [
        "/console/../admin/users",
        "/console/%2e%2e/admin/users",
        "/console/assets/%2E%2E/%2e%2e/jwks.json",
        "/console/..%2fadmin",
        "/console/..%2Fadmin",
        "/console/..%5cadmin",
        "/console/a/./b",
        "/console/%zz",
    ] {
        let r = call("GET", target).through(console_app(&adapter)).await;
        assert_eq!(r.status, 400, "{target}");
    }
    assert!(api.calls_to("GET", "/admin/users").is_empty());
    assert!(api.calls_to("GET", "/.well-known/jwks.json").is_empty());
}

#[tokio::test]
async fn the_console_follows_redirects_only_within_itself() {
    let api = FakeApi::start().await;
    api.on("GET", "/console/old", redirect("/console/new"));
    api.on("GET", "/console/new", html("moved"));
    api.on("GET", "/console/escape", redirect("/.well-known/jwks.json"));
    let adapter = api.adapter(|b| b);

    let r = call("GET", "/console/old")
        .through(console_app(&adapter))
        .await;
    assert_eq!((r.status, r.text.as_str()), (200, "moved"));
    let r = call("GET", "/console/escape")
        .through(console_app(&adapter))
        .await;
    assert_eq!(r.status, 502);
    assert!(api.calls_to("GET", "/.well-known/jwks.json").is_empty());
}

#[tokio::test]
async fn the_console_under_an_auth_server_path() {
    let api = FakeApi::start().await;
    api.on("GET", "/base/console/x", html("ok"));
    let adapter = Adapter::builder(format!("{}/base", api.url))
        .cookie_secret(TEST_SECRET)
        .service_secret(TEST_SERVICE)
        .jwks_kid("test-main")
        .disable_manifest_fetch(true)
        .build()
        .unwrap();

    let r = call("GET", "/console/x")
        .through(console_app(&adapter))
        .await;
    assert_eq!((r.status, r.text.as_str()), (200, "ok"));
}

#[tokio::test]
async fn the_console_reports_an_unreachable_upstream() {
    let adapter = Adapter::builder("http://127.0.0.1:9")
        .cookie_secret(TEST_SECRET)
        .service_secret(TEST_SERVICE)
        .jwks_kid("test-main")
        .disable_manifest_fetch(true)
        .build()
        .unwrap();
    let r = call("GET", "/console/x")
        .through(console_app(&adapter))
        .await;
    assert_eq!(r.status, 502);
    assert!(r.text.contains("unreachable"));
}
