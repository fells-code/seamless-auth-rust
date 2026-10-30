use axum::http::{HeaderMap, Method, StatusCode};

use crate::adapter::Reply;
use crate::options::{Config, SameSite};

/// Blocks cross-site state changes while cookies are `SameSite=None`, which is
/// when the browser would otherwise attach them to such a request.
pub(crate) fn check_origin(config: &Config, method: &Method, headers: &HeaderMap) -> Option<Reply> {
    if config.same_site != SameSite::None {
        return None;
    }
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
        // A sibling subdomain is same-site too, so with an allowlist the Origin
        // has to be on it.
        if !site.eq_ignore_ascii_case(b"same-site") || config.allowed_origins.is_empty() {
            return None;
        }
        return match headers.get("origin") {
            Some(origin) if is_allowed(config, origin.as_bytes()) => None,
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
    if config.allowed_origins.is_empty() || is_allowed(config, origin.as_bytes()) {
        return None;
    }
    blocked()
}

/// Whether an Origin is on the allowlist. An Origin, or an allowlist entry, that
/// does not normalize never matches, so two unparseable values cannot pass for
/// one another.
fn is_allowed(config: &Config, origin: &[u8]) -> bool {
    let Some(origin) = std::str::from_utf8(origin).ok().and_then(normalize_origin) else {
        return false;
    };
    config
        .allowed_origins
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
