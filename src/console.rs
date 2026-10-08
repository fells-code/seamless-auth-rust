use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, LAST_MODIFIED};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::Response;
use axum::routing::any;
use reqwest::Url;
use reqwest::redirect::Policy;
use serde_json::json;

use crate::adapter::{Adapter, Inner, json_response};
use crate::manifest::percent_decode;

const CONSOLE_BASE_PATH: &str = "/console";
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REDIRECTS: usize = 5;

/// The auth API's origin and the console's path on it.
#[derive(Clone)]
struct ConsoleOrigin {
    base: Url,
    prefix: String,
}

impl ConsoleOrigin {
    fn new(auth_server_url: &str) -> Option<Self> {
        let base = Url::parse(auth_server_url).ok()?;
        base.host_str()?;
        let prefix = format!("{}{CONSOLE_BASE_PATH}", base.path().trim_end_matches('/'));
        Some(ConsoleOrigin { base, prefix })
    }

    /// Holds a URL to the auth API's origin and the console subtree.
    fn contains(&self, url: &Url) -> bool {
        url.scheme() == self.base.scheme()
            && url.host_str() == self.base.host_str()
            && url.port_or_known_default() == self.base.port_or_known_default()
            && (url.path() == self.prefix || url.path().starts_with(&format!("{}/", self.prefix)))
    }

    /// Maps a path below the mount to the console on the auth API, refusing
    /// anything that could leave the console subtree: an encoded separator (an
    /// upstream that decodes it would read a traversal), and any dot segment,
    /// literal or encoded.
    fn upstream(&self, subpath: &str, query: Option<&str>) -> Option<Url> {
        let lower = subpath.to_ascii_lowercase();
        if lower.contains("%2f") || lower.contains("%5c") || subpath.contains('\\') {
            return None;
        }
        for segment in subpath.split('/') {
            match percent_decode(segment) {
                Some(decoded) if decoded != "." && decoded != ".." => {}
                _ => return None,
            }
        }

        let suffix = match subpath {
            "" | "/" => String::new(),
            s if s.starts_with('/') => s.to_string(),
            s => format!("/{s}"),
        };
        let mut url = self.base.clone();
        url.set_path(&format!("{}{suffix}", self.prefix));
        url.set_query(query.filter(|q| !q.is_empty()));
        self.contains(&url).then_some(url)
    }
}

impl Adapter {
    /// Reverse-proxies the Seamless admin dashboard from the auth API, so it loads
    /// from the same origin as the cookie-based auth routes. It serves `/console`,
    /// the path the dashboard is built against, so merge it rather than nest it:
    /// `Router::new().merge(auth.console_router())`. (A router nested at
    /// `/console` never sees `/console/`, where the browser lands.)
    ///
    /// Nothing from the incoming request is forwarded but the method and the
    /// path: the console is public static hosting, and the browser's session
    /// cookies have no business at the upstream.
    pub fn console_router<S>(&self) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        let inner = self.inner.clone();
        let handler = move |req: Request| {
            let inner = inner.clone();
            async move { inner.serve_console(req).await }
        };
        Router::new()
            .route(CONSOLE_BASE_PATH, any(handler.clone()))
            .route(&format!("{CONSOLE_BASE_PATH}/"), any(handler.clone()))
            .route(&format!("{CONSOLE_BASE_PATH}/{{*path}}"), any(handler))
    }
}

impl Inner {
    /// Its own client: the adapter's follows no redirects at all, and the
    /// console follows them while they stay inside it.
    fn console_client(&self, origin: &ConsoleOrigin) -> Option<reqwest::Client> {
        self.console_client
            .get_or_init(|| {
                let origin = origin.clone();
                reqwest::Client::builder()
                    .timeout(UPSTREAM_TIMEOUT)
                    .redirect(Policy::custom(move |attempt| {
                        if attempt.previous().len() >= MAX_REDIRECTS {
                            attempt.error("too many redirects")
                        } else if origin.contains(attempt.url()) {
                            attempt.follow()
                        } else {
                            attempt.error("redirect leaves the console")
                        }
                    }))
                    .build()
                    .ok()
            })
            .clone()
    }

    async fn serve_console(&self, req: Request) -> Response {
        let method = req.method().clone();
        if method != Method::GET && method != Method::HEAD {
            return json_response(
                StatusCode::METHOD_NOT_ALLOWED,
                &json!({ "error": "Method not allowed" }),
            );
        }

        let invalid = || {
            json_response(
                StatusCode::BAD_REQUEST,
                &json!({ "error": "Invalid console path" }),
            )
        };
        let Some(origin) = ConsoleOrigin::new(&self.config.auth_server_url) else {
            return invalid();
        };
        let subpath = req
            .uri()
            .path()
            .strip_prefix(CONSOLE_BASE_PATH)
            .unwrap_or_default();
        let Some(upstream) = origin.upstream(subpath, req.uri().query()) else {
            return invalid();
        };
        let Some(client) = self.console_client(&origin) else {
            return json_response(
                StatusCode::BAD_GATEWAY,
                &json!({ "error": "Console upstream unreachable" }),
            );
        };

        let res = match client.request(method.clone(), upstream).send().await {
            Ok(res) => res,
            Err(_) => {
                return json_response(
                    StatusCode::BAD_GATEWAY,
                    &json!({ "error": "Console upstream unreachable" }),
                );
            }
        };

        let mut headers = HeaderMap::new();
        for name in [CONTENT_TYPE, CACHE_CONTROL, ETAG, LAST_MODIFIED] {
            if let Some(value) = res.headers().get(&name) {
                headers.insert(name, value.clone());
            }
        }
        let status = res.status();
        let body = if method == Method::HEAD {
            Body::empty()
        } else {
            Body::new(reqwest::Body::from(res))
        };
        let mut response = Response::new(body);
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        response
    }
}
