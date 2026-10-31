use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::extract::Request;
use axum::http::header::WWW_AUTHENTICATE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};
use tower_layer::Layer;
use tower_service::Service;

use crate::adapter::json_response;
use crate::verifier::{ClockFn, TokenError, TokenUser, Verifier, VerifierBuildError};

/// Whether a granted role satisfies a required one, as `roleGrantsAccess` in
/// `@seamless-auth/types/role/matching`: `x:*` grants `x` and everything under
/// it, an unscoped role grants everything beneath it, and `p:write` grants
/// `p:read`.
pub(crate) fn role_grants_access(granted: &str, required: &str) -> bool {
    let granted = granted.trim();
    let required = required.trim();
    if granted.is_empty() || required.is_empty() {
        return false;
    }
    if granted == required {
        return true;
    }
    if let Some(prefix) = granted.strip_suffix(":*") {
        return required == prefix || required.starts_with(&format!("{prefix}:"));
    }
    if !required.contains(':') {
        return false;
    }
    if !granted.contains(':') {
        return required.starts_with(&format!("{granted}:"));
    }
    let granted_parts: Vec<&str> = granted.split(':').collect();
    let required_parts: Vec<&str> = required.split(':').collect();
    let (granted_action, granted_prefix) = granted_parts.split_last().unwrap_or((&"", &[]));
    let (required_action, required_prefix) = required_parts.split_last().unwrap_or((&"", &[]));
    *granted_action == "write" && *required_action == "read" && granted_prefix == required_prefix
}

/// The authentication a [`Verifier::require_step_up`] guard asks for (RFC 9470).
/// At least one of `acr_values`, `amr` and `max_age` must be set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StepUp {
    acr_values: Vec<String>,
    amr: Vec<String>,
    max_age: Option<u64>,
}

impl StepUp {
    pub fn new() -> Self {
        Self::default()
    }

    /// The token's `acr` must be one of these. Listing `phr` also accepts
    /// `phrh`, which is stronger.
    pub fn acr_values<I, T>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.acr_values = values.into_iter().map(Into::into).collect();
        self
    }

    /// Every one of these must be in the token's `amr`.
    pub fn amr<I, T>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.amr = values.into_iter().map(Into::into).collect();
        self
    }

    /// The user must have authenticated at most this many seconds ago.
    pub fn max_age(mut self, seconds: u64) -> Self {
        self.max_age = Some(seconds);
        self
    }
}

enum Check {
    Scope {
        required: Vec<String>,
        joined: String,
        challenge: HeaderValue,
    },
    Role(Vec<String>),
    StepUp {
        step_up: StepUp,
        accepted_acr: Vec<String>,
        now: ClockFn,
    },
}

impl Verifier {
    /// A layer that answers 401 unless the request carries a valid bearer token,
    /// and puts the [`TokenUser`] in the request extensions for what is behind
    /// it: the guards below, and the handler.
    pub fn require_auth(&self) -> RequireTokenLayer {
        RequireTokenLayer {
            verifier: self.clone(),
        }
    }

    /// A guard that answers 403 `insufficient_scope` unless the token has every
    /// one of `scopes`. Place it behind [`require_auth`](Self::require_auth).
    pub fn require_scope<I, T>(&self, scopes: I) -> TokenGuardLayer
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        let required: Vec<String> = scopes.into_iter().map(Into::into).collect();
        let joined = required.join(" ");
        let challenge = HeaderValue::from_str(&format!(
            "Bearer error=\"insufficient_scope\", scope=\"{joined}\""
        ))
        .unwrap_or_else(|_| HeaderValue::from_static("Bearer error=\"insufficient_scope\""));
        TokenGuardLayer {
            check: Arc::new(Check::Scope {
                required,
                joined,
                challenge,
            }),
        }
    }

    /// A guard that answers 403 `insufficient_role` unless one of the token's
    /// roles grants any one of `roles`, with scoped matching (`orders:write`
    /// grants `orders:read`, `orders` and `orders:*` grant `orders:...`). Place
    /// it behind [`require_auth`](Self::require_auth).
    pub fn require_role<I, T>(&self, roles: I) -> TokenGuardLayer
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        TokenGuardLayer {
            check: Arc::new(Check::Role(roles.into_iter().map(Into::into).collect())),
        }
    }

    /// A guard that answers 401 with the RFC 9470 `insufficient_user_authentication`
    /// challenge unless the token's `acr`, `amr` and `auth_time` meet `step_up`.
    /// Place it behind [`require_auth`](Self::require_auth).
    pub fn require_step_up(&self, step_up: StepUp) -> Result<TokenGuardLayer, VerifierBuildError> {
        if step_up.acr_values.is_empty() && step_up.amr.is_empty() && step_up.max_age.is_none() {
            return Err(VerifierBuildError::EmptyStepUp);
        }
        for value in &step_up.acr_values {
            if value.is_empty()
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
            {
                return Err(VerifierBuildError::InvalidChallenge(value.clone()));
            }
        }
        let mut accepted_acr = step_up.acr_values.clone();
        if accepted_acr.iter().any(|v| v == "phr") {
            accepted_acr.push("phrh".into());
        }
        Ok(TokenGuardLayer {
            check: Arc::new(Check::StepUp {
                step_up,
                accepted_acr,
                now: self.inner.now.clone(),
            }),
        })
    }
}

impl Check {
    fn reject(&self, user: &TokenUser) -> Option<Response> {
        match self {
            Check::Scope {
                required,
                joined,
                challenge,
            } => {
                if required.iter().all(|s| user.has_scope(s)) {
                    return None;
                }
                let mut res = json_response(
                    StatusCode::FORBIDDEN,
                    &json!({ "error": "insufficient_scope", "scope": joined }),
                );
                res.headers_mut()
                    .insert(WWW_AUTHENTICATE, challenge.clone());
                Some(res)
            }
            Check::Role(required) => {
                if required.iter().any(|r| user.has_role(r)) {
                    return None;
                }
                Some(json_response(
                    StatusCode::FORBIDDEN,
                    &json!({ "error": "insufficient_role" }),
                ))
            }
            Check::StepUp {
                step_up,
                accepted_acr,
                now,
            } => {
                let acr_ok = step_up.acr_values.is_empty()
                    || user
                        .acr
                        .as_ref()
                        .is_some_and(|acr| accepted_acr.contains(acr));
                let amr_ok = step_up.amr.iter().all(|m| user.amr.contains(m));
                let recent = step_up.max_age.is_none_or(|max_age| {
                    user.auth_time
                        .is_some_and(|at| i128::from(now()) - i128::from(at) <= i128::from(max_age))
                });
                if acr_ok && amr_ok && recent {
                    return None;
                }
                Some(step_up_challenge(step_up, acr_ok && amr_ok))
            }
        }
    }
}

fn step_up_challenge(step_up: &StepUp, level_ok: bool) -> Response {
    let description = if level_ok {
        "More recent authentication is required"
    } else {
        "A different authentication level is required"
    };
    let mut header = format!(
        "Bearer error=\"insufficient_user_authentication\", error_description=\"{description}\""
    );
    let mut body = Map::new();
    body.insert("error".into(), "insufficient_user_authentication".into());
    body.insert("error_description".into(), description.into());
    if !step_up.acr_values.is_empty() {
        let joined = step_up.acr_values.join(" ");
        header.push_str(&format!(", acr_values=\"{joined}\""));
        body.insert("acr_values".into(), joined.into());
    }
    if let Some(max_age) = step_up.max_age {
        header.push_str(&format!(", max_age=\"{max_age}\""));
        body.insert("max_age".into(), max_age.into());
    }
    let mut res = json_response(StatusCode::UNAUTHORIZED, &Value::Object(body));
    if let Ok(value) = HeaderValue::from_str(&header) {
        res.headers_mut().insert(WWW_AUTHENTICATE, value);
    }
    res
}

/// The layer [`Verifier::require_auth`] returns.
#[derive(Clone, Debug)]
pub struct RequireTokenLayer {
    verifier: Verifier,
}

impl<S> Layer<S> for RequireTokenLayer {
    type Service = RequireToken<S>;

    fn layer(&self, service: S) -> Self::Service {
        RequireToken {
            verifier: self.verifier.clone(),
            service,
        }
    }
}

/// The service [`RequireTokenLayer`] wraps around a handler.
#[derive(Clone)]
pub struct RequireToken<S> {
    verifier: Verifier,
    service: S,
}

impl<S> fmt::Debug for RequireToken<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequireToken").finish_non_exhaustive()
    }
}

impl<S> Service<Request> for RequireToken<S>
where
    S: Service<Request> + Clone + Send + 'static,
    S::Response: IntoResponse,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        // The clone has not been driven to readiness, so the ready one is the one
        // that handles this request.
        let clone = self.service.clone();
        let mut service = std::mem::replace(&mut self.service, clone);
        let verifier = self.verifier.clone();

        Box::pin(async move {
            let (mut parts, body) = req.into_parts();
            match verifier.authenticate(&parts).await {
                Ok(user) => {
                    parts.extensions.insert(user);
                    service
                        .call(Request::from_parts(parts, body))
                        .await
                        .map(IntoResponse::into_response)
                }
                Err(rejected) => Ok(rejected.into_response()),
            }
        })
    }
}

/// The layer [`Verifier::require_scope`], [`Verifier::require_role`] and
/// [`Verifier::require_step_up`] return. Reached without a [`TokenUser`], it
/// answers as if no token was sent.
#[derive(Clone)]
pub struct TokenGuardLayer {
    check: Arc<Check>,
}

impl fmt::Debug for TokenGuardLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenGuardLayer").finish_non_exhaustive()
    }
}

impl<S> Layer<S> for TokenGuardLayer {
    type Service = TokenGuard<S>;

    fn layer(&self, service: S) -> Self::Service {
        TokenGuard {
            check: self.check.clone(),
            service,
        }
    }
}

/// The service [`TokenGuardLayer`] wraps around a handler.
#[derive(Clone)]
pub struct TokenGuard<S> {
    check: Arc<Check>,
    service: S,
}

impl<S> fmt::Debug for TokenGuard<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenGuard").finish_non_exhaustive()
    }
}

impl<S> Service<Request> for TokenGuard<S>
where
    S: Service<Request> + Clone + Send + 'static,
    S::Response: IntoResponse,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let clone = self.service.clone();
        let mut service = std::mem::replace(&mut self.service, clone);
        let rejected = match req.extensions().get::<TokenUser>() {
            None => Some(TokenError::MissingToken.into_response()),
            Some(user) => self.check.reject(user),
        };

        Box::pin(async move {
            match rejected {
                Some(res) => Ok(res),
                None => service.call(req).await.map(IntoResponse::into_response),
            }
        })
    }
}
