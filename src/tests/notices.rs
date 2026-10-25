use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use super::*;
use crate::Delivery;
use crate::jwt::str_claim;
use crate::service_token::{DELIVERY_SUBJECT, PROXY_SUBJECT};

fn pre_auth() -> String {
    signed_cookie(
        "seamless-ephemeral",
        json!({ "sub": "u1", "token": "pre-auth" }),
    )
}

fn access(api: &FakeApi) -> String {
    signed_cookie(
        "seamless-access",
        json!({ "sub": "u1", "token": api.token("u1", "access") }),
    )
}

type Sent = Arc<Mutex<Vec<Delivery>>>;

fn recording(sent: &Sent, notices: bool) -> impl FnOnce(Builder) -> Builder {
    let sink = sent.clone();
    move |b| {
        b.deliver(move |d| {
            sink.lock().unwrap().push(d);
            async { Ok::<_, std::convert::Infallible>(()) }
        })
        .deliver_account_notices(notices)
    }
}

fn opened() -> Value {
    json!({
        "state": "pending",
        "completesAt": "2026-10-25T00:00:00Z",
        "deliveries": [
            {
                "kind": "account_notice_email", "to": "a@b.test", "notice": "account_recovery_opened",
                "subject": "Recovery requested", "text": "Cancel: https://app.test/recovery/cancel#tok",
                "cancelUrl": "https://app.test/recovery/cancel#tok",
            },
            {
                "kind": "account_notice_sms", "to": "+15555550100", "notice": "account_recovery_opened",
                "text": "Recovery requested", "cancelUrl": "https://app.test/recovery/cancel#tok",
            },
        ],
    })
}

#[tokio::test]
async fn recovery_verify_asks_for_notices_and_delivers_each_one() {
    let api = FakeApi::start().await;
    api.on("POST", "/recovery/verify", respond(200, opened()));
    let sent = Sent::default();
    let adapter = api.adapter(recording(&sent, true));

    for bearer in [false, true] {
        sent.lock().unwrap().clear();
        let request = call("POST", "/recovery/verify").body(r#"{"code":"123456"}"#);
        let request = if bearer {
            request
                .header("x-seamless-auth-transport", "bearer")
                .header("authorization", "Bearer pre-auth")
        } else {
            request.cookie(&pre_auth())
        };
        let r = request.to(&adapter).await;

        assert_eq!(r.status, 200, "{}", r.text);
        assert!(r.body.get("deliveries").is_none(), "{}", r.body);
        assert_eq!(r.body["state"], "pending");
        assert!(!r.text.contains("cancel"), "{}", r.text);

        let sent = sent.lock().unwrap().clone();
        let kinds: Vec<_> = sent
            .iter()
            .map(|d| (d.kind.as_str(), d.to.as_str()))
            .collect();
        assert_eq!(
            kinds,
            [
                ("account_notice_email", "a@b.test"),
                ("account_notice_sms", "+15555550100")
            ]
        );
        assert_eq!(sent[0].subject.as_deref(), Some("Recovery requested"));
        assert_eq!(sent[0].notice.as_deref(), Some("account_recovery_opened"));
        assert_eq!(
            sent[1].cancel_url.as_deref(),
            Some("https://app.test/recovery/cancel#tok")
        );
    }

    for recorded in api.calls_to("POST", "/recovery/verify") {
        assert_eq!(recorded.header("x-seamless-auth-delivery-mode"), "external");
        assert_eq!(
            recorded.header("x-seamless-auth-delivery-kinds"),
            "account_notice_email,account_notice_sms"
        );
        assert_eq!(
            str_claim(&service_claims(&recorded), "sub"),
            DELIVERY_SUBJECT
        );
        assert_eq!(recorded.header("authorization"), "Bearer pre-auth");
    }
}

#[tokio::test]
async fn notices_are_left_to_the_api_unless_the_application_delivers_them() {
    let api = FakeApi::start().await;
    api.on("POST", "/recovery/verify", respond(200, opened()));
    let sent = Sent::default();

    for adapter in [
        api.adapter(recording(&sent, false)),
        api.adapter(|b| b.deliver_account_notices(true)),
    ] {
        let r = call("POST", "/recovery/verify")
            .body(r#"{"code":"123456"}"#)
            .cookie(&pre_auth())
            .to(&adapter)
            .await;
        assert_eq!(r.status, 200, "{}", r.text);
        assert!(r.body.get("deliveries").is_none(), "{}", r.body);
    }

    assert!(sent.lock().unwrap().is_empty());
    for recorded in api.calls_to("POST", "/recovery/verify") {
        assert_eq!(recorded.header("x-seamless-auth-delivery-mode"), "");
        assert_eq!(recorded.header("x-seamless-auth-delivery-kinds"), "");
        assert_eq!(str_claim(&service_claims(&recorded), "sub"), PROXY_SUBJECT);
    }
}

#[tokio::test]
async fn delivery_routes_do_not_ask_for_notices() {
    let api = FakeApi::start().await;
    api.on(
        "POST",
        "/recovery/start",
        respond(
            200,
            json!({ "message": "sent", "delivery": { "kind": "otp_email", "to": "a@b.test", "token": "654321", "purpose": "account_recovery" } }),
        ),
    );
    let sent = Sent::default();
    let adapter = api.adapter(recording(&sent, true));

    let r = call("POST", "/recovery/start")
        .body(r#"{"channel":"email"}"#)
        .cookie(&pre_auth())
        .to(&adapter)
        .await;

    assert_eq!(r.status, 200, "{}", r.text);
    let recorded = &api.calls_to("POST", "/recovery/start")[0];
    assert_eq!(recorded.header("x-seamless-auth-delivery-mode"), "external");
    assert_eq!(recorded.header("x-seamless-auth-delivery-kinds"), "");
    let sent = sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].purpose.as_deref(), Some("account_recovery"));
    assert!(sent[0].is_account_recovery());
}

fn failing_on(
    kinds: &'static [&'static str],
    tried: &Arc<Mutex<Vec<String>>>,
) -> impl FnOnce(Builder) -> Builder {
    let sink = tried.clone();
    move |b| {
        b.deliver(move |d: Delivery| {
            sink.lock().unwrap().push(d.kind.clone());
            async move {
                if kinds.contains(&d.kind.as_str()) {
                    Err("transport down")
                } else {
                    Ok(())
                }
            }
        })
        .deliver_account_notices(true)
    }
}

#[tokio::test]
async fn one_notice_delivered_is_enough() {
    let api = FakeApi::start().await;
    api.on("POST", "/recovery/verify", respond(200, opened()));
    api.on(
        "POST",
        "/recovery/cancel",
        respond(200, json!({ "message": "ok" })),
    );
    let tried = Arc::new(Mutex::new(Vec::new()));
    let adapter = api.adapter(failing_on(&["account_notice_email"], &tried));

    let r = call("POST", "/recovery/verify")
        .body(r#"{"code":"123456"}"#)
        .cookie(&pre_auth())
        .to(&adapter)
        .await;

    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body["state"], "pending");
    assert!(r.body.get("deliveries").is_none(), "{}", r.body);
    assert_eq!(
        *tried.lock().unwrap(),
        ["account_notice_email", "account_notice_sms"]
    );
    assert!(api.calls_to("POST", "/recovery/cancel").is_empty());
}

#[tokio::test]
async fn no_notice_delivered_cancels_the_request() {
    let api = FakeApi::start().await;
    api.on("POST", "/recovery/verify", respond(200, opened()));
    api.on(
        "POST",
        "/recovery/cancel",
        respond(200, json!({ "message": "ok" })),
    );
    let tried = Arc::new(Mutex::new(Vec::new()));
    let adapter = api.adapter(failing_on(
        &["account_notice_email", "account_notice_sms"],
        &tried,
    ));

    let r = call("POST", "/recovery/verify")
        .body(r#"{"code":"123456"}"#)
        .cookie(&pre_auth())
        .to(&adapter)
        .await;

    assert_eq!(r.status, 503, "{}", r.text);
    assert_eq!(r.body, json!({ "error": "recovery_notice_failed" }));
    assert_eq!(tried.lock().unwrap().len(), 2);
    let cancels = api.calls_to("POST", "/recovery/cancel");
    assert_eq!(cancels.len(), 1);
    let body: Value = serde_json::from_str(&cancels[0].body).unwrap();
    assert_eq!(body, json!({ "cancelToken": "tok" }));
    assert_eq!(cancels[0].header("authorization"), "");
    assert_eq!(cancels[0].header("x-seamless-auth-delivery-mode"), "");
    assert_eq!(
        str_claim(&service_claims(&cancels[0]), "sub"),
        PROXY_SUBJECT
    );
}

#[tokio::test]
async fn an_unknown_delivery_kind_is_skipped() {
    let api = FakeApi::start().await;
    api.on(
        "POST",
        "/recovery/verify",
        respond(
            200,
            json!({ "state": "pending", "deliveries": [
                { "kind": "carrier_pigeon", "to": "a@b.test", "extra": { "nested": true } },
                { "kind": "account_notice_sms", "to": "+15555550100", "notice": "account_recovery_opened", "text": "t" },
            ] }),
        ),
    );
    api.on(
        "POST",
        "/otp/generate-login-email-otp",
        respond(
            200,
            json!({ "message": "sent", "delivery": { "kind": "carrier_pigeon", "to": "a@b.test" } }),
        ),
    );
    let sent = Sent::default();
    let adapter = api.adapter(recording(&sent, true));

    let r = call("POST", "/recovery/verify")
        .body(r#"{"code":"123456"}"#)
        .cookie(&pre_auth())
        .to(&adapter)
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = call("POST", "/otp/generate-login-email-otp")
        .cookie(&pre_auth())
        .to(&adapter)
        .await;
    assert_eq!(r.status, 200, "{}", r.text);

    let kinds: Vec<_> = sent
        .lock()
        .unwrap()
        .iter()
        .map(|d| d.kind.clone())
        .collect();
    assert_eq!(kinds, ["account_notice_sms"]);
}

#[tokio::test]
async fn recovery_and_policy_routes_and_their_errors_pass_through() {
    let api = FakeApi::start().await;
    api.on(
        "POST",
        "/recovery/verify",
        respond(503, json!({ "error": "recovery_notice_failed" })),
    );
    let step_up =
        json!({ "error": "step_up_required", "methods": ["passkey"], "maxAgeSeconds": 300 });
    api.on("PATCH", "/admin/users/u-2", respond(403, step_up.clone()));
    let routes = [
        ("GET", "/recovery/requests"),
        ("DELETE", "/recovery/requests/r-1"),
        ("GET", "/recovery-codes"),
        ("POST", "/recovery-codes"),
        ("GET", "/system-config/policy"),
        ("PUT", "/system-config/policy/draft"),
        ("DELETE", "/system-config/policy/draft"),
        ("POST", "/system-config/policy/publish"),
        ("POST", "/system-config/policy/rollback"),
        ("POST", "/system-config/policy/dry-run"),
        ("GET", "/system-config/policy/versions"),
    ];
    for (method, path) in routes {
        api.on(method, path, respond(200, json!({ "ok": path })));
    }
    for (method, path) in [("POST", "/recovery/cancel"), ("GET", "/recovery/status")] {
        api.on(method, path, respond(200, json!({ "ok": path })));
    }
    api.on(
        "POST",
        "/recovery-codes/redeem",
        respond(200, api.session("u1")),
    );
    api.on(
        "POST",
        "/recovery/complete",
        respond(200, api.session("u1")),
    );
    let sent = Sent::default();
    let adapter = api.adapter(recording(&sent, true));

    let r = call("POST", "/recovery/verify")
        .body(r#"{"code":"123456"}"#)
        .cookie(&pre_auth())
        .to(&adapter)
        .await;
    assert_eq!(r.status, 503);
    assert_eq!(r.body, json!({ "error": "recovery_notice_failed" }));

    let r = call("PATCH", "/admin/users/u-2")
        .body(r#"{"roles":["admin"]}"#)
        .cookie(&access(&api))
        .to(&adapter)
        .await;
    assert_eq!(r.status, 403);
    assert_eq!(r.body, step_up);

    for (method, path) in routes {
        let r = call(method, path)
            .body("{}")
            .cookie(&access(&api))
            .to(&adapter)
            .await;
        assert_eq!(r.status, 200, "{method} {path}: {}", r.text);
        assert_eq!(r.body["ok"], path);
        let recorded = api.calls_to(method, path);
        assert!(
            recorded[0].header("authorization").starts_with("Bearer ey"),
            "{method} {path}"
        );
    }

    let r = call("POST", "/recovery/cancel")
        .body(r#"{"cancelToken":"tok"}"#)
        .to(&adapter)
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    let r = call("GET", "/recovery/status")
        .cookie(&pre_auth())
        .to(&adapter)
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    for path in ["/recovery-codes/redeem", "/recovery/complete"] {
        let r = call("POST", path)
            .body("{}")
            .cookie(&pre_auth())
            .to(&adapter)
            .await;
        assert_eq!(r.status, 200, "{path}: {}", r.text);
        assert!(r.cookies.contains_key("seamless-access"), "{path}");
        assert!(r.cookies.contains_key("seamless-refresh"), "{path}");
    }
}

#[test]
fn the_bundled_manifest_marks_recovery_verify_for_notices() {
    let manifest = crate::Manifest::bundled();
    let noticed: Vec<_> = manifest
        .routes
        .iter()
        .filter(|r| r.notices)
        .map(|r| (r.method.as_str(), r.path.as_str()))
        .collect();
    assert_eq!(noticed, [("POST", "/recovery/verify")]);
}

#[test]
fn a_manifest_may_carry_fields_this_version_does_not_know() {
    let manifest = crate::Manifest::parse(
        br#"{"schemaVersion":1,"apiVersion":"9.9.9","futureTopLevel":1,"routes":[
            {"method":"POST","path":"/recovery/verify","credential":"preAuth","notices":true,"futureField":{"x":1}}
        ]}"#,
    )
    .unwrap();
    assert!(manifest.routes[0].notices);
}

#[test]
fn debug_output_redacts_notice_credentials() {
    let delivery = crate::delivery::parse_delivery(&json!({
        "kind": "account_notice_email", "to": "a@b.test", "notice": "account_recovery_opened",
        "subject": "Recovery requested", "text": "Cancel at https://app.test/recovery/cancel#k3y-secret",
        "cancelUrl": "https://app.test/recovery/cancel#k3y-secret",
    }))
    .unwrap();
    let printed = format!("{delivery:?}");
    assert!(!printed.contains("k3y-secret"), "{printed}");
    assert!(printed.contains("account_recovery_opened"), "{printed}");
}
