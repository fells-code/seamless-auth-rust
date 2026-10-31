use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::FromRequestParts;
use axum::http::header::WWW_AUTHENTICATE;
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::Algorithm;
use serde_json::{Map, Value, json};
use tokio::sync::Mutex;

use crate::adapter::{json_response, read_limited};
use crate::jwks::JwksCache;
use crate::jwt::CLOCK_SKEW_SECS;

const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const DISCOVERY_BACKOFF: Duration = Duration::from_secs(5);
const MAX_DISCOVERY_BYTES: usize = 256 * 1024;

pub(crate) type ClockFn = Arc<dyn Fn() -> u64 + Send + Sync>;
type ConfirmFuture = Pin<Box<dyn Future<Output = bool> + Send>>;
type ConfirmFn = Arc<dyn Fn(Confirmation) -> ConfirmFuture + Send + Sync>;

/// Verifies OpenID Provider access tokens (RFC 9068 JWTs) for a resource server
/// that only receives `Authorization: Bearer` tokens. It has no cookies, no
/// service secret and no auth routes. Start one with [`Verifier::builder`].
///
/// Cloning is cheap and shares the key cache.
#[derive(Clone)]
pub struct Verifier {
    pub(crate) inner: Arc<VerifierInner>,
}

impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verifier")
            .field("issuer", &self.inner.issuer)
            .field("audience", &self.inner.audience)
            .finish_non_exhaustive()
    }
}

pub(crate) struct VerifierInner {
    issuer: String,
    audience: String,
    client: reqwest::Client,
    confirm: Option<ConfirmFn>,
    pub(crate) now: ClockFn,
    keys: Mutex<KeySource>,
}

#[derive(Default)]
struct KeySource {
    jwks: Option<Arc<JwksCache>>,
    attempted_at: Option<Instant>,
}

/// Why [`VerifierBuilder::build`] or a guard refused its configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifierBuildError {
    /// The issuer is not an absolute http(s) URL.
    InvalidIssuer,
    /// No audience, or an empty one. A verifier never accepts any audience.
    MissingAudience,
    /// The JWKS URI is not an absolute http(s) URL.
    InvalidJwksUri,
    /// A step-up guard names no `acr_values`, `amr` or `max_age`.
    EmptyStepUp,
    /// A scope or role guard names no values, or an empty one.
    EmptyGuard,
    /// A guard value cannot be carried in a `WWW-Authenticate` header.
    InvalidChallenge(String),
    /// The HTTP client could not be built.
    HttpClient(String),
}

impl fmt::Display for VerifierBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifierBuildError::InvalidIssuer => {
                f.write_str("seamless-auth: the issuer must be an absolute http or https URL")
            }
            VerifierBuildError::MissingAudience => {
                f.write_str("seamless-auth: the verifier needs a non-empty audience")
            }
            VerifierBuildError::InvalidJwksUri => {
                f.write_str("seamless-auth: the JWKS URI must be an absolute http or https URL")
            }
            VerifierBuildError::EmptyStepUp => {
                f.write_str("seamless-auth: a step-up guard needs acr_values, amr or max_age")
            }
            VerifierBuildError::EmptyGuard => f.write_str(
                "seamless-auth: a scope or role guard needs at least one non-empty value",
            ),
            VerifierBuildError::InvalidChallenge(what) => {
                write!(f, "seamless-auth: {what:?} cannot be sent in a challenge")
            }
            VerifierBuildError::HttpClient(err) => {
                write!(f, "seamless-auth: could not build the HTTP client: {err}")
            }
        }
    }
}

impl std::error::Error for VerifierBuildError {}

/// Configures a [`Verifier`].
pub struct VerifierBuilder {
    issuer: String,
    audience: Option<String>,
    jwks_uri: Option<String>,
    http_client: Option<reqwest::Client>,
    confirm: Option<ConfirmFn>,
    now: Option<ClockFn>,
}

impl fmt::Debug for VerifierBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifierBuilder")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("jwks_uri", &self.jwks_uri)
            .finish_non_exhaustive()
    }
}

impl Verifier {
    /// Starts a verifier for tokens from `issuer`, the provider's `oidc_issuer`.
    /// The `iss` claim must equal it exactly.
    pub fn builder(issuer: impl Into<String>) -> VerifierBuilder {
        VerifierBuilder {
            issuer: issuer.into(),
            audience: None,
            jwks_uri: None,
            http_client: None,
            confirm: None,
            now: None,
        }
    }
}

impl VerifierBuilder {
    /// This API's resource identifier. Required: a token's `aud` must be it or
    /// contain it.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Fetches keys here instead of discovering the JWKS URI from the issuer's
    /// `/.well-known/openid-configuration`.
    pub fn jwks_uri(mut self, uri: impl Into<String>) -> Self {
        self.jwks_uri = Some(uri.into());
        self
    }

    /// The client for discovery and key fetches. The default follows no
    /// redirects.
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Accepts sender-constrained tokens. A token with a `cnf` claim is
    /// rejected unless this hook, given the claim and the request, returns true.
    /// It runs after every other check has passed.
    pub fn confirmation<F, Fut>(mut self, confirm: F) -> Self
    where
        F: Fn(Confirmation) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = bool> + Send + 'static,
    {
        self.confirm = Some(Arc::new(move |c| Box::pin(confirm(c))));
        self
    }

    #[cfg(test)]
    pub(crate) fn clock(mut self, now: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.now = Some(Arc::new(now));
        self
    }

    /// Validates the configuration and returns the verifier.
    pub fn build(self) -> Result<Verifier, VerifierBuildError> {
        if !is_http_url(&self.issuer) {
            return Err(VerifierBuildError::InvalidIssuer);
        }
        let audience = self
            .audience
            .filter(|a| !a.trim().is_empty())
            .ok_or(VerifierBuildError::MissingAudience)?;
        if let Some(uri) = &self.jwks_uri
            && !is_http_url(uri)
        {
            return Err(VerifierBuildError::InvalidJwksUri);
        }
        let client = match self.http_client {
            Some(client) => client,
            None => reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|e| VerifierBuildError::HttpClient(e.to_string()))?,
        };
        let keys = KeySource {
            jwks: self
                .jwks_uri
                .map(|uri| Arc::new(JwksCache::at(uri, client.clone()))),
            attempted_at: None,
        };
        Ok(Verifier {
            inner: Arc::new(VerifierInner {
                issuer: self.issuer,
                audience,
                client,
                confirm: self.confirm,
                now: self.now.unwrap_or_else(|| Arc::new(unix_now)),
                keys: Mutex::new(keys),
            }),
        })
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn is_http_url(value: &str) -> bool {
    reqwest::Url::parse(value).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https") && url.host_str().is_some_and(|h| !h.is_empty())
    })
}

/// What the [`confirmation`](VerifierBuilder::confirmation) hook is asked to
/// accept: the token's `cnf` claim and the request that presented it, enough to
/// check a DPoP proof against `cnf.jkt`.
#[derive(Clone)]
#[non_exhaustive]
pub struct Confirmation {
    pub cnf: Value,
    /// The access token, for a proof's `ath`.
    pub token: String,
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
}

impl fmt::Debug for Confirmation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Confirmation")
            .field("cnf", &self.cnf)
            .field("token", &"[redacted]")
            .field("method", &self.method)
            .field("uri", &self.uri)
            .finish_non_exhaustive()
    }
}

/// The caller of a request a [`Verifier`] accepted. The verifier's layer puts it
/// in the request extensions, and it is an extractor for handlers behind it.
///
/// A client-credentials token (`sub` equal to `client_id`) carries no user
/// claims, so it has no roles, `acr`, `amr` or `auth_time`.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TokenUser {
    pub sub: String,
    pub client_id: String,
    /// The `scope` claim split on spaces, in order.
    pub scopes: Vec<String>,
    pub roles: Vec<String>,
    pub sid: Option<String>,
    pub org_id: Option<String>,
    pub acr: Option<String>,
    pub amr: Vec<String>,
    /// Seconds since the epoch.
    pub auth_time: Option<i64>,
    pub iat: Option<i64>,
    pub exp: i64,
    /// The access token, for calling further APIs on the caller's behalf.
    pub token: String,
}

impl TokenUser {
    /// Whether the token was granted `scope`, compared exactly.
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    /// Whether any of the user's roles grants `role`, with the same scoped
    /// matching as [`Verifier::require_role`].
    pub fn has_role(&self, role: &str) -> bool {
        self.roles
            .iter()
            .any(|granted| crate::token_guard::role_grants_access(granted, role))
    }
}

impl fmt::Debug for TokenUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenUser")
            .field("sub", &self.sub)
            .field("client_id", &self.client_id)
            .field("scopes", &self.scopes)
            .field("roles", &self.roles)
            .field("sid", &self.sid)
            .field("org_id", &self.org_id)
            .field("acr", &self.acr)
            .field("amr", &self.amr)
            .field("auth_time", &self.auth_time)
            .field("iat", &self.iat)
            .field("exp", &self.exp)
            .field("token", &"[redacted]")
            .finish()
    }
}

impl<S: Send + Sync> FromRequestParts<S> for TokenUser {
    type Rejection = TokenError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<TokenUser>()
            .cloned()
            .ok_or(TokenError::MissingToken)
    }
}

/// Why a [`Verifier`] refused a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TokenError {
    /// No bearer token. Answers 401 `{"error":"missing_token"}` with
    /// `WWW-Authenticate: Bearer`.
    MissingToken,
    /// The token failed verification, or its keys could not be fetched. Answers
    /// 401 `{"error":"invalid_token"}` with
    /// `WWW-Authenticate: Bearer error="invalid_token"`.
    InvalidToken,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TokenError::MissingToken => "missing_token",
            TokenError::InvalidToken => "invalid_token",
        })
    }
}

impl std::error::Error for TokenError {}

impl IntoResponse for TokenError {
    fn into_response(self) -> Response {
        let (code, challenge) = match self {
            TokenError::MissingToken => ("missing_token", "Bearer"),
            TokenError::InvalidToken => ("invalid_token", "Bearer error=\"invalid_token\""),
        };
        let mut res = json_response(StatusCode::UNAUTHORIZED, &json!({ "error": code }));
        res.headers_mut()
            .insert(WWW_AUTHENTICATE, HeaderValue::from_static(challenge));
        res
    }
}

/// The token in `Authorization: Bearer <token>`: the scheme in any case, and
/// exactly one token after it.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    let header = headers.get("authorization")?.to_str().ok()?;
    let mut parts = header.split_whitespace();
    let scheme = parts.next()?;
    let token = parts.next()?;
    (scheme.eq_ignore_ascii_case("bearer") && parts.next().is_none()).then_some(token)
}

impl Verifier {
    /// Verifies the bearer token on a request. [`Verifier::require_auth`] does
    /// this for a route.
    pub async fn authenticate(&self, parts: &Parts) -> Result<TokenUser, TokenError> {
        let token = bearer(&parts.headers).ok_or(TokenError::MissingToken)?;
        self.inner
            .verify(token, parts)
            .await
            .map_err(|_| TokenError::InvalidToken)
    }
}

impl VerifierInner {
    async fn jwks(&self) -> Result<Arc<JwksCache>, String> {
        let mut source = self.keys.lock().await;
        if let Some(jwks) = &source.jwks {
            return Ok(jwks.clone());
        }
        if source
            .attempted_at
            .is_some_and(|at| at.elapsed() < DISCOVERY_BACKOFF)
        {
            return Err("discovery failed recently".into());
        }
        source.attempted_at = Some(Instant::now());
        match self.discover().await {
            Ok(uri) => {
                let jwks = Arc::new(JwksCache::at(uri, self.client.clone()));
                source.jwks = Some(jwks.clone());
                Ok(jwks)
            }
            Err(err) => {
                tracing::warn!("[seamless-auth] OpenID discovery failed ({err}).");
                Err(err)
            }
        }
    }

    async fn discover(&self) -> Result<String, String> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.issuer.trim_end_matches('/')
        );
        let res = self
            .client
            .get(&url)
            .timeout(DISCOVERY_TIMEOUT)
            .send()
            .await
            .map_err(|e| format!("discovery: {e}"))?;
        if res.status() != reqwest::StatusCode::OK {
            return Err(format!("discovery: HTTP {}", res.status().as_u16()));
        }
        let body = read_limited(res, MAX_DISCOVERY_BYTES).await?;
        let doc: Value = serde_json::from_slice(&body).map_err(|e| format!("discovery: {e}"))?;
        jwks_uri_from(&doc, &self.issuer)
    }

    async fn verify(&self, token: &str, parts: &Parts) -> Result<TokenUser, String> {
        let segments: Vec<&str> = token.split('.').collect();
        let [header_b64, payload_b64, signature] = segments[..] else {
            return Err("not a compact JWS".into());
        };
        let header = decode_object(header_b64)?;

        if header.get("alg").and_then(Value::as_str) != Some("RS256") {
            return Err("unexpected algorithm".into());
        }
        let typ = header.get("typ").and_then(Value::as_str).unwrap_or("");
        if !(typ.eq_ignore_ascii_case("at+jwt") || typ.eq_ignore_ascii_case("application/at+jwt")) {
            return Err("not an access token".into());
        }
        let kid = header
            .get("kid")
            .and_then(Value::as_str)
            .filter(|k| !k.is_empty())
            .ok_or("no key id")?;
        if header.contains_key("crit") {
            return Err("critical header".into());
        }

        let key = self.jwks().await?.key(kid).await?;
        if key.usage.as_ref().is_some_and(|u| *u != "sig")
            || key.alg.as_ref().is_some_and(|a| *a != "RS256")
        {
            return Err("key not for RS256 signatures".into());
        }
        let message = &token[..header_b64.len() + 1 + payload_b64.len()];
        let valid = jsonwebtoken::crypto::verify(
            signature,
            message.as_bytes(),
            &key.decoding,
            Algorithm::RS256,
        )
        .unwrap_or(false);
        if !valid {
            return Err("bad signature".into());
        }

        let claims = decode_object(payload_b64)?;
        let user = self.check_claims(&claims, token)?;

        if let Some(cnf) = claims.get("cnf").filter(|v| !v.is_null()) {
            let accepted = match &self.confirm {
                Some(confirm) => {
                    confirm(Confirmation {
                        cnf: cnf.clone(),
                        token: token.to_string(),
                        method: parts.method.clone(),
                        uri: parts.uri.clone(),
                        headers: parts.headers.clone(),
                    })
                    .await
                }
                None => false,
            };
            if !accepted {
                return Err("confirmation not accepted".into());
            }
        }
        Ok(user)
    }

    fn check_claims(&self, claims: &Map<String, Value>, token: &str) -> Result<TokenUser, String> {
        if claims.get("iss").and_then(Value::as_str) != Some(self.issuer.as_str()) {
            return Err("wrong issuer".into());
        }
        let audience_ok = match claims.get("aud") {
            Some(Value::String(aud)) => *aud == self.audience,
            Some(Value::Array(auds)) => auds.iter().any(|a| a.as_str() == Some(&self.audience)),
            _ => false,
        };
        if !audience_ok {
            return Err("wrong audience".into());
        }

        let now = (self.now)() as f64;
        let skew = CLOCK_SKEW_SECS as f64;
        let exp = claims
            .get("exp")
            .and_then(Value::as_f64)
            .ok_or("no expiry")?;
        if now >= exp + skew {
            return Err("expired".into());
        }
        match claims.get("nbf") {
            None => {}
            Some(nbf) => match nbf.as_f64() {
                Some(nbf) if now + skew >= nbf => {}
                _ => return Err("not yet valid".into()),
            },
        }

        let required = |name: &str| {
            claims
                .get(name)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .ok_or(format!("no {name}"))
        };
        let sub = required("sub")?;
        let client_id = required("client_id")?;

        // A first-party token is signed by the same provider; its `typ` claim is
        // what keeps it from passing for an OAuth access token.
        if claims.contains_key("typ") {
            return Err("first-party token".into());
        }

        let string = |name: &str| match claims.get(name) {
            None => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(format!("{name} is not a string")),
        };
        let strings = |name: &str| match claims.get(name) {
            None => Ok(Vec::new()),
            Some(Value::Array(items)) => items
                .iter()
                .map(|v| v.as_str().map(str::to_string))
                .collect::<Option<Vec<_>>>()
                .ok_or(format!("{name} is not an array of strings")),
            Some(_) => Err(format!("{name} is not an array of strings")),
        };
        let number = |name: &str| match claims.get(name) {
            None => Ok(None),
            Some(v) => whole_seconds(v)
                .map(Some)
                .ok_or(format!("{name} is not a number")),
        };

        let scopes = string("scope")?
            .map(|s| {
                s.split(' ')
                    .filter(|p| !p.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let org_id = match claims.get("org_id") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => return Err("org_id is not a string".into()),
        };

        Ok(TokenUser {
            sub,
            client_id,
            scopes,
            roles: strings("roles")?,
            sid: string("sid")?,
            org_id,
            acr: string("acr")?,
            amr: strings("amr")?,
            auth_time: number("auth_time")?,
            iat: claims.get("iat").and_then(whole_seconds),
            exp: exp.floor() as i64,
            token: token.to_string(),
        })
    }
}

/// A NumericDate as whole seconds, rounded down so a fractional `auth_time`
/// never counts as more recent than it was.
fn whole_seconds(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_f64().map(|f| f.floor() as i64))
}

fn decode_object(segment: &str) -> Result<Map<String, Value>, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| format!("base64: {e}"))?;
    match serde_json::from_slice(&bytes) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err("not a JSON object".into()),
    }
}

/// The JWKS URI a discovery document names, when the document is for `issuer`
/// and the URI is http(s), and https under an https issuer.
pub(crate) fn jwks_uri_from(doc: &Value, issuer: &str) -> Result<String, String> {
    let doc = doc.as_object().ok_or("discovery: not a JSON object")?;
    if doc.get("issuer").and_then(Value::as_str) != Some(issuer) {
        return Err("discovery: issuer mismatch".into());
    }
    let uri = doc
        .get("jwks_uri")
        .and_then(Value::as_str)
        .ok_or("discovery: no jwks_uri")?;
    let parsed = reqwest::Url::parse(uri).map_err(|e| format!("discovery: jwks_uri: {e}"))?;
    let https_issuer = reqwest::Url::parse(issuer).is_ok_and(|url| url.scheme() == "https");
    match parsed.scheme() {
        "https" => {}
        "http" if !https_issuer => {}
        _ => return Err("discovery: jwks_uri scheme not allowed".into()),
    }
    Ok(uri.to_string())
}
