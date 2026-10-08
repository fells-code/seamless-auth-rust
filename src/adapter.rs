use std::collections::HashSet;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Request};
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, request::Parts};
use axum::response::Response;
use axum::routing::any;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use serde_json::{Value, json};

use crate::client_ip::{canonical, client_user_agent};
use crate::cookies::{CookieWrite, clear_cookie, set_cookie};
use crate::jwks::JwksCache;
use crate::manifest::ManifestSource;
use crate::options::{Builder, Config};
use crate::origin::check_origin;
use crate::refresh::Refresher;
use crate::service_token::ServiceTokens;

const TRANSPORT_HEADER: &str = "x-seamless-auth-transport";
pub(crate) const DELIVERY_MODE_HEADER: &str = "x-seamless-auth-delivery-mode";
pub(crate) const MAX_BODY_BYTES: usize = 1 << 20;

/// Serves the Seamless Auth routes and guards the application's own.
///
/// Cheap to clone: clones share the manifest, key set and refresh state.
#[derive(Clone)]
pub struct Adapter {
    pub(crate) inner: Arc<Inner>,
}

impl fmt::Debug for Adapter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Adapter")
            .field("auth_server_url", &self.inner.config.auth_server_url)
            .finish_non_exhaustive()
    }
}

pub(crate) struct Inner {
    pub config: Config,
    pub jwks: JwksCache,
    pub manifest: ManifestSource,
    pub tokens: ServiceTokens,
    pub refreshes: Arc<Refresher>,
    pub console_client: std::sync::OnceLock<Option<reqwest::Client>>,
}

impl Adapter {
    /// Starts configuring an adapter for the auth API at `auth_server_url`.
    pub fn builder(auth_server_url: impl Into<String>) -> Builder {
        Builder::new(auth_server_url)
    }

    pub(crate) fn from_config(config: Config) -> Self {
        let jwks = JwksCache::new(&config.auth_server_url, config.http_client.clone());
        let manifest = ManifestSource::new(
            &config.auth_server_url,
            config.http_client.clone(),
            config.fetch_manifest,
        );
        let tokens = ServiceTokens::new(config.service_secret.clone(), config.jwks_kid.clone());
        Adapter {
            inner: Arc::new(Inner {
                config,
                jwks,
                manifest,
                tokens,
                refreshes: Arc::default(),
                console_client: std::sync::OnceLock::new(),
            }),
        }
    }

    /// The auth routes, relative to wherever they are nested. Nest them at
    /// `/auth`, which is where the client SDKs call:
    /// `Router::new().nest("/auth", auth.router())`.
    pub fn router<S>(&self) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        let inner = self.inner.clone();
        let handler = move |req: Request| {
            let inner = inner.clone();
            async move { inner.serve(req).await }
        };
        Router::new()
            .route("/", any(handler.clone()))
            .route("/{*path}", any(handler))
    }
}

/// What a route answers, applied to the response in one place.
pub(crate) struct Reply {
    pub status: StatusCode,
    pub body: Option<Value>,
    pub raw: Option<reqwest::Response>,
    pub set: Vec<CookieWrite>,
    pub clear: Vec<String>,
}

impl Reply {
    pub fn new(status: StatusCode, body: Option<Value>) -> Self {
        Reply {
            status,
            body,
            raw: None,
            set: Vec::new(),
            clear: Vec::new(),
        }
    }

    pub fn error(status: StatusCode, code: &str) -> Self {
        Reply::new(status, Some(json!({ "error": code })))
    }

    pub fn with_set(mut self, set: Vec<CookieWrite>) -> Self {
        self.set = set;
        self
    }

    pub fn with_clear(mut self, clear: Vec<String>) -> Self {
        self.clear = clear;
        self
    }
}

/// The end user's address and user agent, forwarded to the auth API.
#[derive(Clone, Default)]
pub(crate) struct Forwarded {
    pub ip: Option<String>,
    pub user_agent: Option<Vec<u8>>,
}

/// One request to the auth API.
pub(crate) struct UpstreamCall {
    pub method: Method,
    pub path: String,
    pub query: Option<String>,
    pub body: Option<Bytes>,
    pub authorization: Option<String>,
    pub service: Option<String>,
    pub external_delivery: bool,
}

impl UpstreamCall {
    pub fn new(method: Method, path: impl Into<String>) -> Self {
        UpstreamCall {
            method,
            path: path.into(),
            query: None,
            body: None,
            authorization: None,
            service: None,
            external_delivery: false,
        }
    }
}

pub(crate) fn json_response(status: StatusCode, body: &Value) -> Response {
    let mut res = Response::new(Body::from(body.to_string()));
    *res.status_mut() = status;
    res.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    res
}

impl Inner {
    async fn serve(self: Arc<Self>, req: Request) -> Response {
        let (parts, body) = req.into_parts();

        if let Some(blocked) = check_origin(&self.config, &parts.method, &parts.headers) {
            return self.write(blocked, false);
        }

        let bearer = parts
            .headers
            .get(TRANSPORT_HEADER)
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"bearer"));
        let forwarded = self.forwarded(&parts);
        let path = parts.uri.path();
        // Matched on segments, as manifest routes are, so `/logout/` and `//logout`
        // are still logout and never fall through to a route that clears less.
        let special = path
            .split('/')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("/")
            .to_ascii_lowercase();

        let reply = if parts.method == Method::POST && special == "refresh" {
            self.refresh_route(&parts.headers, &forwarded, bearer).await
        } else if parts.method == Method::DELETE && special == "logout" {
            self.logout_route(&parts.headers, &forwarded, bearer, "/logout")
                .await
        } else if parts.method == Method::DELETE && special == "logout/all" {
            self.logout_route(&parts.headers, &forwarded, bearer, "/logout/all")
                .await
        } else {
            let manifest = self.manifest.get().await;
            match manifest.find(parts.method.as_str(), path) {
                Some(found) => {
                    self.manifest_route(&parts, body, &forwarded, found, bearer)
                        .await
                }
                None => Reply::error(StatusCode::NOT_FOUND, "not_found"),
            }
        };

        self.write(reply, bearer)
    }

    fn forwarded(&self, parts: &Parts) -> Forwarded {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip());
        let ip = match &self.config.client_ip {
            Some(resolve) => resolve(&parts.headers, peer),
            None => peer,
        };
        Forwarded {
            ip: ip.map(canonical),
            user_agent: client_user_agent(&parts.headers),
        }
    }

    /// Applies a reply. Clears go before sets, because a reply that does both is
    /// replacing a session rather than ending one. Bearer transport writes no
    /// cookies at all.
    fn write(&self, reply: Reply, bearer: bool) -> Response {
        let mut cookies = HeaderMap::new();
        if !bearer {
            let mut seen = HashSet::new();
            for name in reply.clear.iter().filter(|n| seen.insert(n.as_str())) {
                if let Some(value) = clear_cookie(&self.config, name) {
                    cookies.append(SET_COOKIE, value);
                }
            }
            for cookie in &reply.set {
                match set_cookie(&self.config, cookie) {
                    Ok(value) => {
                        cookies.append(SET_COOKIE, value);
                    }
                    Err(err) => {
                        tracing::error!(
                            "[seamless-auth] Could not issue cookie {}: {err}",
                            cookie.name
                        );
                        return json_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &json!({ "error": "internal_error" }),
                        );
                    }
                }
            }
        }

        let mut res = if let Some(raw) = reply.raw {
            let mut headers = HeaderMap::new();
            for name in [CONTENT_TYPE, CONTENT_DISPOSITION, CACHE_CONTROL] {
                if let Some(value) = raw.headers().get(&name) {
                    headers.insert(name, value.clone());
                }
            }
            let mut res = Response::new(Body::new(reqwest::Body::from(raw)));
            *res.status_mut() = reply.status;
            res.headers_mut().extend(headers);
            res
        } else if let Some(body) = &reply.body {
            json_response(reply.status, body)
        } else {
            let mut res = Response::new(Body::empty());
            *res.status_mut() = reply.status;
            res
        };

        for value in cookies.get_all(SET_COOKIE) {
            res.headers_mut().append(SET_COOKIE, value.clone());
        }
        res
    }

    pub(crate) async fn call(
        &self,
        forwarded: &Forwarded,
        call: UpstreamCall,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let mut url = format!("{}{}", self.config.auth_server_url, call.path);
        if let Some(query) = call.query.as_deref().filter(|q| !q.is_empty()) {
            url.push('?');
            url.push_str(query);
        }

        let mut req = self
            .config
            .http_client
            .request(call.method.clone(), url)
            .header("accept", "application/json");
        if let Some(body) = call.body.filter(|_| call.method != Method::GET) {
            req = req.header("content-type", "application/json").body(body);
        }
        if let Some(authorization) = call.authorization {
            req = req.header("authorization", authorization);
        }
        if let Some(service) = call.service {
            req = req.header("x-seamless-service-token", service);
        }
        if let Some(ip) = &forwarded.ip {
            req = req.header("x-seamless-client-ip", ip.as_str());
        }
        if let Some(ua) = forwarded
            .user_agent
            .as_ref()
            .and_then(|ua| HeaderValue::from_bytes(ua).ok())
        {
            req = req.header("x-seamless-client-user-agent", ua);
        }
        if call.external_delivery {
            req = req.header(DELIVERY_MODE_HEADER, "external");
        }
        req.send().await
    }
}

/// Reads at most `max` bytes of a response body, refusing a larger one.
pub(crate) async fn read_limited(
    mut res: reqwest::Response,
    max: usize,
) -> Result<Vec<u8>, String> {
    if res.content_length().is_some_and(|len| len > max as u64) {
        return Err("response body too large".into());
    }
    let mut out = Vec::new();
    while let Some(chunk) = res.chunk().await.map_err(|e| e.to_string())? {
        if out.len() + chunk.len() > max {
            return Err("response body too large".into());
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Reads a JSON response body. An empty body is `None`; a body that is not JSON
/// reports false.
pub(crate) async fn read_json(res: reqwest::Response) -> (Option<Value>, bool) {
    let Ok(data) = read_limited(res, MAX_BODY_BYTES).await else {
        return (None, false);
    };
    if data.trim_ascii().is_empty() {
        return (None, true);
    }
    match serde_json::from_slice::<Value>(&data) {
        Ok(Value::Null) => (None, true),
        Ok(value) => (Some(value), true),
        Err(_) => (None, false),
    }
}

/// Passes an upstream error through. Callers read fields off the auth API's own
/// error body, so an object goes out as-is; anything else becomes a code they can
/// still branch on.
pub(crate) fn failure(status: StatusCode, body: Option<Value>, is_json: bool) -> Reply {
    match body {
        Some(Value::Object(obj)) if is_json => Reply::new(status, Some(Value::Object(obj))),
        _ => Reply::error(status, "upstream_error"),
    }
}

pub(crate) enum BodyError {
    TooLarge,
    Unreadable,
}

pub(crate) async fn read_request_body(body: Body) -> Result<Option<Bytes>, BodyError> {
    match Limited::new(body, MAX_BODY_BYTES).collect().await {
        Ok(collected) => {
            let bytes = collected.to_bytes();
            Ok((!bytes.trim_ascii().is_empty()).then_some(bytes))
        }
        Err(err) if err.downcast_ref::<LengthLimitError>().is_some() => Err(BodyError::TooLarge),
        Err(_) => Err(BodyError::Unreadable),
    }
}

/// `application/json` or a `+json` type. A download such as
/// `application/x-ndjson` is not: parsing it would keep only its first line.
pub(crate) fn is_json_content_type(content_type: Option<&HeaderValue>) -> bool {
    let Some(value) = content_type else {
        return true;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    if value.trim().is_empty() {
        return true;
    }
    let media_type = value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let Some((kind, subtype)) = media_type.split_once('/') else {
        return false;
    };
    let token = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    };
    if !token(kind) || !token(subtype) {
        return false;
    }
    media_type == "application/json" || subtype.ends_with("+json")
}

/// The token in an `Authorization: Bearer` header.
pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let header = headers.get("authorization")?.to_str().ok()?;
    if header.len() > 7 && header[..7].eq_ignore_ascii_case("bearer ") {
        let token = header[7..].trim();
        return (!token.is_empty()).then_some(token);
    }
    None
}
