//! A fake auth API and helpers for driving the adapter as a client would.

mod adapter;
mod client_ip;
mod console;
mod guard;
mod manifest;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::jwt::{Claims, sign_hs256};
use crate::{Adapter, Builder};

pub(crate) const TEST_SECRET: &str = "cookie-secret-cookie-secret-cookie-secret";
pub(crate) const TEST_SERVICE: &str = "service-secret-service-secret-service-secret";

const TEST_KEY_PEM: &str = include_str!("../testdata/rsa-test-only.pem");
const TEST_KEY_N: &str = include_str!("../testdata/rsa-test-only.n");

/// Signs a token as the auth API would.
pub(crate) fn sign_rs256(claims: Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("k1".into());
    let now = jsonwebtoken::get_current_timestamp();
    let mut body = json!({ "iat": now, "exp": now + 300 });
    for (k, v) in claims.as_object().unwrap() {
        body[k] = v.clone();
    }
    let key = EncodingKey::from_rsa_pem(TEST_KEY_PEM.as_bytes()).unwrap();
    jsonwebtoken::encode(&header, &body, &key).unwrap()
}

pub(crate) type Handler = Arc<dyn Fn(&Recorded) -> Response + Send + Sync>;

/// One request the fake auth API received.
#[derive(Clone, Debug)]
pub(crate) struct Recorded {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: HeaderMap,
    pub body: String,
}

impl Recorded {
    pub fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    }
}

#[derive(Default)]
struct FakeState {
    calls: Mutex<Vec<Recorded>>,
    routes: Mutex<HashMap<String, Handler>>,
    manifest: Mutex<Option<Value>>,
}

/// An auth API: JWKS, an optional manifest, and per-route handlers.
pub(crate) struct FakeApi {
    pub url: String,
    state: Arc<FakeState>,
}

impl FakeApi {
    pub async fn start() -> FakeApi {
        let state = Arc::new(FakeState::default());
        let app = Router::new().fallback(serve_fake).with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        FakeApi { url, state }
    }

    pub fn on(&self, method: &str, path: &str, handler: Handler) {
        self.state
            .routes
            .lock()
            .unwrap()
            .insert(format!("{method} {path}"), handler);
    }

    pub fn set_manifest(&self, manifest: Value) {
        *self.state.manifest.lock().unwrap() = Some(manifest);
    }

    pub fn calls_to(&self, method: &str, path: &str) -> Vec<Recorded> {
        self.state
            .calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.method == method && c.path == path)
            .cloned()
            .collect()
    }

    /// A token this API signs, of the given type.
    pub fn token(&self, sub: &str, typ: &str) -> String {
        sign_rs256(json!({ "sub": sub, "typ": typ, "iss": self.url, "aud": self.url }))
    }

    /// A session response this API returns.
    pub fn session(&self, sub: &str) -> Value {
        json!({
            "message": "Success",
            "sub": sub,
            "token": sign_rs256(json!({ "sub": sub, "sid": "s-1", "typ": "access", "iss": self.url, "aud": self.url })),
            "refreshToken": format!("refresh-{sub}"),
            "ttl": 900,
            "refreshTtl": 3600,
        })
    }

    /// An adapter in front of this API, on the bundled manifest unless the
    /// configuration turns fetching back on.
    pub fn adapter(&self, configure: impl FnOnce(Builder) -> Builder) -> Adapter {
        let builder = Adapter::builder(&self.url)
            .cookie_secret(TEST_SECRET)
            .service_secret(TEST_SERVICE)
            .jwks_kid("test-main")
            .disable_manifest_fetch(true);
        configure(builder).build().unwrap()
    }
}

async fn serve_fake(State(state): State<Arc<FakeState>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let body = to_bytes(body, usize::MAX).await.unwrap();
    let recorded = Recorded {
        method: parts.method.to_string(),
        path: parts.uri.path().to_string(),
        query: parts.uri.query().map(str::to_string),
        headers: parts.headers.clone(),
        body: String::from_utf8_lossy(&body).into_owned(),
    };
    state.calls.lock().unwrap().push(recorded.clone());

    if recorded.path == "/.well-known/jwks.json" {
        return json_reply(
            200,
            json!({ "keys": [{ "kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig", "n": TEST_KEY_N.trim(), "e": "AQAB" }] }),
        );
    }
    if recorded.path == crate::MANIFEST_PATH
        && let Some(manifest) = state.manifest.lock().unwrap().clone()
    {
        return json_reply(200, manifest);
    }
    let handler = state
        .routes
        .lock()
        .unwrap()
        .get(&format!("{} {}", recorded.method, recorded.path))
        .cloned();
    match handler {
        Some(handler) => handler(&recorded),
        None => json_reply(404, json!({ "error": "not_found" })),
    }
}

pub(crate) fn json_reply(status: u16, body: Value) -> Response {
    let mut res = Response::new(Body::from(body.to_string()));
    *res.status_mut() = StatusCode::from_u16(status).unwrap();
    res.headers_mut()
        .insert("content-type", HeaderValue::from_static("application/json"));
    res
}

pub(crate) fn respond(status: u16, body: Value) -> Handler {
    Arc::new(move |_| json_reply(status, body.clone()))
}

/// A cookie as the adapter writes it, with the kind its name implies.
pub(crate) fn signed_cookie(name: &str, claims: Value) -> String {
    let kind = match name {
        "seamless-access" => crate::cookies::KIND_ACCESS,
        "seamless-refresh" => crate::cookies::KIND_REFRESH,
        _ => crate::cookies::KIND_EPHEMERAL,
    };
    raw_cookie(name, kind, claims)
}

/// Signs claims with the cookie secret under any kind, including the wrong one
/// for the slot.
pub(crate) fn raw_cookie(name: &str, kind: &str, claims: Value) -> String {
    let mut body: Claims = claims.as_object().unwrap().clone();
    body.insert("kind".into(), Value::from(kind));
    let value = sign_hs256(body, TEST_SECRET, Duration::from_secs(3600), None).unwrap();
    format!("{name}={value}")
}

/// A request to the adapter's auth routes or to a guarded app.
pub(crate) struct Call {
    method: String,
    target: String,
    body: String,
    headers: Vec<(String, String)>,
    peer: Option<SocketAddr>,
}

pub(crate) fn call(method: &str, target: &str) -> Call {
    Call {
        method: method.into(),
        target: target.into(),
        body: String::new(),
        headers: Vec::new(),
        peer: None,
    }
}

impl Call {
    /// A JSON body, as the client SDKs send.
    pub fn body(self, body: &str) -> Self {
        self.raw_body(body)
            .header("content-type", "application/json")
    }

    /// A body with no content type of its own.
    pub fn raw_body(mut self, body: &str) -> Self {
        self.body = body.into();
        self
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn cookie(self, cookie: &str) -> Self {
        self.header("cookie", cookie)
    }

    pub fn peer(mut self, peer: &str) -> Self {
        self.peer = Some(peer.parse().unwrap());
        self
    }

    fn request(self) -> Request {
        let mut req = Request::builder()
            .method(self.method.as_str())
            .uri(self.target.as_str());
        for (k, v) in &self.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let mut req = req.body(Body::from(self.body)).unwrap();
        if let Some(peer) = self.peer {
            req.extensions_mut().insert(ConnectInfo(peer));
        }
        req
    }

    /// Sends the request to the adapter's auth routes, mounted at the root.
    pub async fn to(self, adapter: &Adapter) -> Reply {
        self.through(adapter.router()).await
    }

    pub async fn through(self, router: Router) -> Reply {
        Reply::read(router.oneshot(self.request()).await.unwrap()).await
    }
}

/// What the adapter answered.
pub(crate) struct Reply {
    pub status: u16,
    pub headers: HeaderMap,
    pub text: String,
    pub body: Value,
    /// Set-Cookie headers by cookie name.
    pub cookies: HashMap<String, String>,
}

impl Reply {
    async fn read(res: Response) -> Reply {
        let status = res.status().as_u16();
        let headers = res.headers().clone();
        let text = String::from_utf8(
            to_bytes(res.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        let body = serde_json::from_str(&text).unwrap_or(Value::Null);
        let cookies = headers
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .map(|v| (v.split('=').next().unwrap().to_string(), v))
            .collect();
        Reply {
            status,
            headers,
            text,
            body,
            cookies,
        }
    }

    /// The signed value of a cookie the adapter set.
    pub fn cookie_value(&self, name: &str) -> String {
        let header = &self.cookies[name];
        header
            .split(';')
            .next()
            .unwrap()
            .split_once('=')
            .unwrap()
            .1
            .to_string()
    }

    /// Whether the adapter ended a cookie.
    pub fn cleared(&self, name: &str) -> bool {
        self.cookies
            .get(name)
            .is_some_and(|c| c.contains("Max-Age=0") && c.starts_with(&format!("{name}=;")))
    }
}

/// The value of a `name=value` attribute in a Set-Cookie header.
pub(crate) fn attribute<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix(&format!("{name}=")))
}

/// Whether a Set-Cookie header carries a bare flag such as `HttpOnly`.
pub(crate) fn flag(header: &str, name: &str) -> bool {
    header.split(';').map(str::trim).any(|part| part == name)
}

/// The claims of a service token the adapter sent.
pub(crate) fn service_claims(recorded: &Recorded) -> Claims {
    let token = recorded
        .header("x-seamless-service-token")
        .strip_prefix("Bearer ")
        .unwrap();
    crate::jwt::verify_hs256(token, TEST_SERVICE).expect("service token verifies")
}
