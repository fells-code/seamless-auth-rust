use serde_json::json;

use super::*;

const VERIFY: &str = "/magic-link/verify/abc";

fn ok() -> Value {
    json!({ "message": "Success" })
}

#[tokio::test]
async fn verify_forwards_the_client_bearer() {
    let api = FakeApi::start().await;
    api.on("GET", VERIFY, respond(200, ok()));

    let r = call("GET", VERIFY)
        .header("x-seamless-auth-transport", "bearer")
        .header("authorization", "Bearer pre-auth")
        .to(&api.adapter(|b| b))
        .await;

    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(
        api.calls_to("GET", VERIFY)[0].header("authorization"),
        "Bearer pre-auth"
    );
}

#[tokio::test]
async fn verify_forwards_a_valid_pre_auth_cookie_as_bearer() {
    let api = FakeApi::start().await;
    api.on("GET", VERIFY, respond(200, ok()));

    let r = call("GET", VERIFY)
        .cookie(&signed_cookie(
            "seamless-ephemeral",
            json!({ "sub": "u1", "token": "pre-auth" }),
        ))
        .to(&api.adapter(|b| b))
        .await;

    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(
        api.calls_to("GET", VERIFY)[0].header("authorization"),
        "Bearer pre-auth"
    );
}

#[tokio::test]
async fn verify_without_a_usable_pre_auth_sends_no_authorization() {
    let wrong_kind = raw_cookie(
        "seamless-ephemeral",
        crate::cookies::KIND_ACCESS,
        json!({ "sub": "u1", "token": "t" }),
    );
    let cases: [(&str, Vec<(&str, &str)>); 4] = [
        ("no cookie", vec![]),
        (
            "altered cookie",
            vec![("cookie", "seamless-ephemeral=not-a-signed-cookie")],
        ),
        ("wrong kind", vec![("cookie", wrong_kind.as_str())]),
        (
            "bearer without token",
            vec![("x-seamless-auth-transport", "bearer")],
        ),
    ];
    for (name, headers) in cases {
        let api = FakeApi::start().await;
        api.on("GET", VERIFY, respond(200, ok()));

        let mut request = call("GET", VERIFY);
        for (k, v) in headers {
            request = request.header(k, v);
        }
        let r = request.to(&api.adapter(|b| b)).await;

        assert_eq!(r.status, 200, "{name}: {}", r.text);
        let calls = api.calls_to("GET", VERIFY);
        assert_eq!(calls.len(), 1, "{name}");
        assert!(
            calls[0].headers.get("authorization").is_none(),
            "{name}: sent {}",
            calls[0].header("authorization")
        );
    }
}

#[tokio::test]
async fn confirmation_required_passes_through() {
    let api = FakeApi::start().await;
    let body = json!({
        "error": "confirmation_required",
        "message": "Confirm this sign-in",
        "requestedFrom": { "deviceClass": "desktop", "requestedAt": "2026-10-16T12:00:00.000Z" },
    });
    api.on("GET", VERIFY, respond(409, body.clone()));

    let r = call("GET", VERIFY).to(&api.adapter(|b| b)).await;

    assert_eq!(r.status, 409);
    assert_eq!(r.body, body);
}

#[tokio::test]
async fn confirm_is_proxied_without_a_credential() {
    let api = FakeApi::start().await;
    let confirm = format!("{VERIFY}/confirm");
    api.on("POST", &confirm, respond(200, ok()));

    let r = call("POST", &confirm).to(&api.adapter(|b| b)).await;

    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body, ok());
    let calls = api.calls_to("POST", &confirm);
    assert_eq!(calls.len(), 1);
    assert!(calls[0].headers.get("authorization").is_none());
}

#[tokio::test]
async fn a_check_without_tokens_sets_no_cookies() {
    let api = FakeApi::start().await;
    api.on("GET", "/magic-link/check", respond(200, ok()));

    let r = call("GET", "/magic-link/check")
        .cookie(&signed_cookie(
            "seamless-ephemeral",
            json!({ "sub": "u1", "token": "pre-auth" }),
        ))
        .to(&api.adapter(|b| b))
        .await;

    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body, ok());
    assert!(r.cookies.is_empty());
}
