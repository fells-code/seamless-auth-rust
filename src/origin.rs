use axum::http::{HeaderMap, Method, StatusCode, Uri};

use crate::adapter::Reply;
use crate::options::Config;

/// Blocks cross-site state changes whatever the cookies' `SameSite` setting: a
/// sibling subdomain is same-site, so `Lax` and `Strict` cookies still reach it.
pub(crate) fn check_origin(
    config: &Config,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Option<Reply> {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return None;
    }

    let blocked = || {
        Some(Reply::error(
            StatusCode::FORBIDDEN,
            "cross_site_request_blocked",
        ))
    };

    // A null Origin is opaque or sandboxed, never the adopter's own page, so it
    // is refused whatever Sec-Fetch-Site and the allowlist say.
    if headers
        .get("origin")
        .is_some_and(|origin| origin.as_bytes().trim_ascii().eq_ignore_ascii_case(b"null"))
    {
        return blocked();
    }

    let trusted = |origin: &[u8]| match &config.allowed_origins {
        Some(allowed) => is_allowed(allowed, origin),
        None => is_own_host(origin, uri, headers),
    };

    if let Some(site) = headers.get("sec-fetch-site") {
        let site = site.as_bytes();
        if site.eq_ignore_ascii_case(b"same-origin") || site.eq_ignore_ascii_case(b"none") {
            return None;
        }
        // Anything else, a value this check does not know included, is treated
        // as cross-site unless it is same-site from a trusted Origin.
        if !site.eq_ignore_ascii_case(b"same-site") {
            return blocked();
        }
        return match headers.get("origin") {
            Some(origin) if trusted(origin.as_bytes()) => None,
            _ => blocked(),
        };
    }

    let origin = headers.get("origin")?;
    // An Origin a browser would never send is not one to trust.
    if origin.to_str().is_err() || !trusted(origin.as_bytes()) {
        return blocked();
    }
    None
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

/// Whether the Origin names the host this request was sent to: the `Host`
/// header, or the URI authority an HTTP/2 request carries instead. A default
/// port written on either side does not count against a match.
fn is_own_host(origin: &[u8], uri: &Uri, headers: &HeaderMap) -> bool {
    let Some(origin) = std::str::from_utf8(origin).ok().and_then(normalize_origin) else {
        return false;
    };
    let Some(host) = headers
        .get("host")
        .and_then(|host| host.to_str().ok())
        .or_else(|| uri.authority().map(|authority| authority.as_str()))
    else {
        return false;
    };
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty() || host.contains(['@', '/', '?', '#']) {
        return false;
    }
    let (scheme, authority) = origin.split_once("://").unwrap_or_default();
    let default_port = match scheme {
        "https" => ":443",
        "http" => ":80",
        _ => "",
    };
    let strip = |authority: &str| {
        authority
            .strip_suffix(default_port)
            .unwrap_or(authority)
            .to_string()
    };
    strip(authority) == strip(&host)
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
