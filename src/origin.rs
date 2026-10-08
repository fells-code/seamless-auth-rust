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
        return if site.as_bytes().eq_ignore_ascii_case(b"cross-site") {
            blocked()
        } else {
            None
        };
    }

    let origin = headers.get("origin")?;
    // An Origin a browser would never send is not one to trust.
    let Ok(origin) = origin.to_str() else {
        return blocked();
    };
    if origin == "null" {
        return blocked();
    }
    if config.allowed_origins.is_empty() {
        return None;
    }

    let origin = normalize_origin(origin);
    if origin.is_some()
        && config
            .allowed_origins
            .iter()
            .any(|allowed| normalize_origin(allowed) == origin)
    {
        return None;
    }
    blocked()
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
