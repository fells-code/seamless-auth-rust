use std::time::{Duration, SystemTime};

use axum::http::{HeaderMap, HeaderValue, header::COOKIE};
use serde_json::Value;

use crate::jwt::{Claims, sign_hs256, verify_hs256};
use crate::options::Config;

// Cookie kinds. Every cookie is signed with the same secret, so the kind is
// signed into the payload and checked on read: otherwise a cookie from one slot,
// such as the pre-auth cookie /login issues for any existing account, would pass
// in another.
pub(crate) const KIND_ACCESS: &str = "access";
pub(crate) const KIND_REFRESH: &str = "refresh";
pub(crate) const KIND_EPHEMERAL: &str = "ephemeral";
pub(crate) const KIND_CLAIM: &str = "kind";

pub(crate) struct CookieWrite {
    pub name: String,
    pub kind: &'static str,
    pub value: Claims,
    pub max_age: u64,
}

/// The `Set-Cookie` value for a cookie this adapter issues.
pub(crate) fn set_cookie(config: &Config, cookie: &CookieWrite) -> Result<HeaderValue, String> {
    let mut value = cookie.value.clone();
    value.insert(KIND_CLAIM.into(), Value::from(cookie.kind));
    let signed = sign_hs256(
        value,
        &config.cookie_secret,
        Duration::from_secs(cookie.max_age),
        None,
    )
    .map_err(|e| e.to_string())?;

    let expires = httpdate::fmt_http_date(SystemTime::now() + Duration::from_secs(cookie.max_age));
    let header = format!(
        "{}={}; Path=/{}; Max-Age={}; Expires={}; HttpOnly{}; SameSite={}",
        cookie.name,
        signed,
        domain_attribute(config),
        cookie.max_age,
        expires,
        secure_attribute(config),
        config.same_site.as_str(),
    );
    HeaderValue::from_str(&header).map_err(|e| e.to_string())
}

/// The `Set-Cookie` value that ends one of this adapter's cookies.
pub(crate) fn clear_cookie(config: &Config, name: &str) -> Option<HeaderValue> {
    let header = format!(
        "{name}=; Path=/{}; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly{}; SameSite={}",
        domain_attribute(config),
        secure_attribute(config),
        config.same_site.as_str(),
    );
    HeaderValue::from_str(&header).ok()
}

fn domain_attribute(config: &Config) -> String {
    config
        .cookie_domain
        .as_ref()
        .map(|d| format!("; Domain={d}"))
        .unwrap_or_default()
}

fn secure_attribute(config: &Config) -> &'static str {
    if config.secure_cookies {
        "; Secure"
    } else {
        ""
    }
}

/// The raw value of the first cookie called `name`, if the request holds one.
pub(crate) fn raw_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v.trim_matches('"'))
}

/// The verified payload of one of the adapter's cookies, if it is the kind
/// expected in that slot.
pub(crate) fn read_cookie(
    config: &Config,
    headers: &HeaderMap,
    name: &str,
    kind: &str,
) -> Option<Claims> {
    let raw = raw_cookie(headers, name).filter(|v| !v.is_empty())?;
    let claims = verify_hs256(raw, &config.cookie_secret)?;
    (crate::jwt::str_claim(&claims, KIND_CLAIM) == kind).then_some(claims)
}

/// The kind of cookie a held credential lives in.
pub(crate) fn cookie_kind(held: &str) -> &'static str {
    match held {
        "access" => KIND_ACCESS,
        "refresh" => KIND_REFRESH,
        _ => KIND_EPHEMERAL,
    }
}

/// Reads a lifetime the auth API sent, which may be a number or a numeric
/// string. Anything that is not a positive whole number of seconds is refused:
/// a cookie is the session, and one with a lifetime nobody can vouch for is worse
/// than refusing the response.
pub(crate) fn ttl_seconds(value: Option<&Value>) -> Result<u64, String> {
    let ttl = match value {
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) => s.parse::<u64>().ok(),
        _ => None,
    };
    ttl.filter(|t| *t > 0)
        .map(|t| t.min(MAX_COOKIE_AGE))
        .ok_or_else(|| format!("unusable cookie ttl {value:?}"))
}

/// Browsers cap a cookie's lifetime at 400 days (RFC 6265bis), and the cap keeps
/// the expiry arithmetic far from overflow.
const MAX_COOKIE_AGE: u64 = 400 * 24 * 60 * 60;

fn field(session: &Claims, name: &str) -> Value {
    session.get(name).cloned().unwrap_or(Value::Null)
}

/// The cookies for a verified session response: access, and refresh unless the
/// response only reissues access.
pub(crate) fn session_cookies(
    config: &Config,
    session: &Claims,
    session_id: &str,
    with_refresh: bool,
) -> Result<Vec<CookieWrite>, String> {
    let ttl = ttl_seconds(session.get("ttl"))?;

    let mut access = Claims::new();
    for name in ["sub", "token", "roles", "email", "phone", "organizationId"] {
        access.insert(name.into(), field(session, name));
    }
    if !session_id.is_empty() {
        access.insert("sessionId".into(), Value::from(session_id));
    }
    let mut cookies = vec![CookieWrite {
        name: config.access_cookie_name.clone(),
        kind: KIND_ACCESS,
        value: access,
        max_age: ttl,
    }];

    if with_refresh {
        let refresh_ttl = ttl_seconds(session.get("refreshTtl"))?;
        let mut refresh = Claims::new();
        refresh.insert("sub".into(), field(session, "sub"));
        refresh.insert("refreshToken".into(), field(session, "refreshToken"));
        cookies.push(CookieWrite {
            name: config.refresh_cookie_name.clone(),
            kind: KIND_REFRESH,
            value: refresh,
            max_age: refresh_ttl,
        });
    }
    Ok(cookies)
}

/// The cookie a pre-auth or registration response issues.
pub(crate) fn ephemeral_cookie(
    config: &Config,
    issues: &str,
    session: &Claims,
) -> Result<CookieWrite, String> {
    let ttl = ttl_seconds(session.get("ttl"))?;
    let mut value = Claims::new();
    value.insert("sub".into(), field(session, "sub"));
    value.insert("token".into(), field(session, "token"));
    Ok(CookieWrite {
        name: config.cookie_name(issues).to_string(),
        kind: KIND_EPHEMERAL,
        value,
        max_age: ttl,
    })
}
