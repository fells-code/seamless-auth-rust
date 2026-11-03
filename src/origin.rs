use axum::http::{HeaderMap, Method, StatusCode};

use crate::adapter::Reply;
use crate::options::Config;

/// Blocks cross-site state changes whatever the cookies' `SameSite` setting: a
/// sibling subdomain is same-site, so `Lax` and `Strict` cookies still reach it.
pub(crate) fn check_origin(config: &Config, method: &Method, headers: &HeaderMap) -> Option<Reply> {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return None;
    }

    let blocked = || {
        Some(Reply::error(
            StatusCode::FORBIDDEN,
            "cross_site_request_blocked",
        ))
    };

    if let Some(site) = headers.get("sec-fetch-site") {
        let site = site.as_bytes();
        if site.eq_ignore_ascii_case(b"cross-site") {
            return blocked();
        }
        if !site.eq_ignore_ascii_case(b"same-site") {
            return None;
        }
        if headers.get("origin").is_some_and(|origin| origin == "null") {
            return blocked();
        }
        let Some(allowed) = &config.allowed_origins else {
            return None;
        };
        return match headers.get("origin") {
            Some(origin) if is_allowed(allowed, origin.as_bytes()) => None,
            _ => blocked(),
        };
    }

    let origin = headers.get("origin")?;
    if origin == "null" {
        return blocked();
    }
    // An Origin a browser would never send is not one to trust.
    if origin.to_str().is_err() {
        return blocked();
    }
    match &config.allowed_origins {
        Some(allowed) if !is_allowed(allowed, origin.as_bytes()) => blocked(),
        _ => None,
    }
}

/// Whether an Origin is on the allowlist. An Origin, or an allowlist entry, that
/// does not normalize never matches, so two unparseable values cannot pass for
/// one another.
fn is_allowed(allowed: &[String], origin: &[u8]) -> bool {
    let Some(origin) = std::str::from_utf8(origin).ok().and_then(normalize_origin) else {
        return false;
    };
    allowed
        .iter()
        .filter_map(|allowed| normalize_origin(allowed))
        .any(|allowed| allowed == origin)
}

/// `scheme://host[:port]`, lowercased, or `None` for anything that is not one.
fn normalize_origin(origin: &str) -> Option<String> {
    let origin = origin.trim();
    let (scheme, rest) = origin.split_once("://")?;
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if scheme.is_empty() || host.is_empty() || host.contains('@') {
        return None;
    }
    Some(format!("{scheme}://{host}").to_ascii_lowercase())
}
