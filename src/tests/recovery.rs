use std::sync::Arc;

use serde_json::{Value, json};

use super::*;
use crate::jwt::{str_claim, unverified_claims, verify_hs256};

fn session(api: &FakeApi, refresh_token: &str, recovery: bool) -> Value {
    let mut session = api.session("u1");
    session["refreshToken"] = Value::from(refresh_token);
    if recovery {
        session["token"] = Value::from(sign_rs256(json!({
            "sub": "u1", "sid": "s-1", "typ": "access", "iss": api.url, "aud": api.url,
            "recovery": true,
        })));
    }
    session
}

fn recovery_token(api: &FakeApi) -> String {
    sign_rs256(
        json!({ "sub": "u1", "typ": "access", "iss": api.url, "aud": api.url, "recovery": true }),
    )
}

/// The token inside the access cookie the adapter set.
fn cookie_token(r: &Reply) -> Claims {
    let cookie = verify_hs256(&r.cookie_value("seamless-access"), TEST_SECRET).unwrap();
    unverified_claims(str_claim(&cookie, "token")).unwrap()
}

fn refresh_by_token(api: &FakeApi) {
    let after = session(api, "r3", false);
    let before = session(api, "r2", true);
    api.on(
        "POST",
        "/refresh",
        Arc::new(move |req| match req.header("authorization") {
            "Bearer r2" => json_reply(200, after.clone()),
            _ => json_reply(200, before.clone()),
        }),
    );
}

#[tokio::test]
async fn enrolling_from_a_recovery_session_refreshes_the_claim_away() {
    for (method, path) in [
        ("POST", "/webauthn/register/finish"),
        ("POST", "/totp/enroll/verify"),
    ] {
        let api = FakeApi::start().await;
        api.on(method, path, respond(200, json!({ "message": "Success" })));
        api.on("POST", "/refresh", respond(200, session(&api, "r2", false)));
        let adapter = api.adapter(|b| b);
        let access = signed_cookie(
            "seamless-access",
            json!({ "sub": "u1", "token": recovery_token(&api) }),
        );
        let refresh = signed_cookie(
            "seamless-refresh",
            json!({ "sub": "u1", "refreshToken": "r1" }),
        );

        let r = call(method, path)
            .body("{}")
            .cookie(&format!("{access}; {refresh}"))
            .to(&adapter)
            .await;

        assert_eq!(r.status, 200, "{path}: {}", r.text);
        assert_eq!(r.body, json!({ "message": "Success" }));
        let refreshes = api.calls_to("POST", "/refresh");
        assert_eq!(refreshes.len(), 1, "{path}");
        assert_eq!(refreshes[0].header("authorization"), "Bearer r1");
        assert!(cookie_token(&r).get("recovery").is_none(), "{path}");
        let refresh = verify_hs256(&r.cookie_value("seamless-refresh"), TEST_SECRET).unwrap();
        assert_eq!(str_claim(&refresh, "refreshToken"), "r2");
    }
}

#[tokio::test]
async fn a_refresh_earlier_in_the_request_is_followed_by_one_on_its_new_token() {
    let api = FakeApi::start().await;
    api.on(
        "POST",
        "/webauthn/register/finish",
        respond(200, json!({ "message": "Success" })),
    );
    refresh_by_token(&api);
    let adapter = api.adapter(|b| b);
    let refresh = signed_cookie(
        "seamless-refresh",
        json!({ "sub": "u1", "refreshToken": "r1" }),
    );

    let r = call("POST", "/webauthn/register/finish")
        .body("{}")
        .cookie(&refresh)
        .to(&adapter)
        .await;

    assert_eq!(r.status, 200, "{}", r.text);
    let spent: Vec<_> = api
        .calls_to("POST", "/refresh")
        .iter()
        .map(|c| c.header("authorization").to_string())
        .collect();
    assert_eq!(spent, ["Bearer r1", "Bearer r2"]);
    assert_eq!(r.headers.get_all("set-cookie").iter().count(), 2);
    assert!(cookie_token(&r).get("recovery").is_none());
    let refresh = verify_hs256(&r.cookie_value("seamless-refresh"), TEST_SECRET).unwrap();
    assert_eq!(str_claim(&refresh, "refreshToken"), "r3");
}

#[tokio::test]
async fn only_a_recovery_session_in_cookie_transport_refreshes_after_enrollment() {
    let api = FakeApi::start().await;
    api.on(
        "POST",
        "/webauthn/register/finish",
        respond(200, json!({ "message": "Success" })),
    );
    api.on("POST", "/refresh", respond(200, session(&api, "r2", false)));
    let adapter = api.adapter(|b| b);
    let refresh = signed_cookie(
        "seamless-refresh",
        json!({ "sub": "u1", "refreshToken": "r1" }),
    );
    let access =
        |token: String| signed_cookie("seamless-access", json!({ "sub": "u1", "token": token }));

    let r = call("POST", "/webauthn/register/finish")
        .body("{}")
        .cookie(&format!("{}; {refresh}", access(api.token("u1", "access"))))
        .to(&adapter)
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert!(r.cookies.is_empty());

    let r = call("POST", "/webauthn/register/finish")
        .body("{}")
        .header("x-seamless-auth-transport", "bearer")
        .header("authorization", &format!("Bearer {}", recovery_token(&api)))
        .to(&adapter)
        .await;
    assert_eq!(r.status, 200, "{}", r.text);
    assert!(r.cookies.is_empty());

    assert!(api.calls_to("POST", "/refresh").is_empty());
}

#[tokio::test]
async fn a_failed_refresh_after_enrollment_keeps_the_enrollment_answer() {
    let api = FakeApi::start().await;
    api.on(
        "POST",
        "/totp/enroll/verify",
        respond(200, json!({ "message": "Success" })),
    );
    api.on(
        "POST",
        "/refresh",
        respond(401, json!({ "error": "invalid_refresh_token" })),
    );
    let adapter = api.adapter(|b| b);
    let access = signed_cookie(
        "seamless-access",
        json!({ "sub": "u1", "token": recovery_token(&api) }),
    );
    let refresh = signed_cookie(
        "seamless-refresh",
        json!({ "sub": "u1", "refreshToken": "r1" }),
    );

    let r = call("POST", "/totp/enroll/verify")
        .body("{}")
        .cookie(&format!("{access}; {refresh}"))
        .to(&adapter)
        .await;

    assert_eq!(r.status, 200, "{}", r.text);
    assert_eq!(r.body, json!({ "message": "Success" }));
    assert!(r.cookies.is_empty());
}
