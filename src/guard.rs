use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::extract::{FromRequestParts, Request};
use axum::http::{HeaderMap, StatusCode, request::Parts};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use tower_layer::Layer;
use tower_service::Service;

use crate::adapter::{Adapter, Inner, bearer_token, json_response};
use crate::cookies::{KIND_ACCESS, raw_cookie, read_cookie};
use crate::jwt::{Claims, str_claim, unverified_claims};
use crate::origin::check_origin;

/// The session a request was authenticated with. [`RequireAuth`] puts it in the
/// request extensions, and it is an extractor for handlers behind the guard.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct User {
    pub id: String,
    pub roles: Vec<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    /// The auth API access token, for calling the API on the user's behalf.
    pub token: String,
}

// The token is a live credential, so it stays out of logs that print a User.
impl fmt::Debug for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("roles", &self.roles)
            .field("email", &self.email)
            .field("phone", &self.phone)
            .field("token", &"[redacted]")
            .finish()
    }
}

/// A request carried no valid session. Answers 401 `{"error":"unauthenticated"}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unauthenticated;

impl fmt::Display for Unauthenticated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unauthenticated")
    }
}

impl std::error::Error for Unauthenticated {}

impl IntoResponse for Unauthenticated {
    fn into_response(self) -> Response {
        json_response(
            StatusCode::UNAUTHORIZED,
            &json!({ "error": "unauthenticated" }),
        )
    }
}

impl<S: Send + Sync> FromRequestParts<S> for User {
    type Rejection = Unauthenticated;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<User>()
            .cloned()
            .ok_or(Unauthenticated)
    }
}

impl Adapter {
    /// Verifies a request's session: the adapter's access cookie, or an auth API
    /// access token in `Authorization: Bearer` for clients with no cookie jar. The
    /// cookie wins when present. It reads the `Cookie` header itself, so it works
    /// on any route. It does not refresh: silent refresh belongs to the auth
    /// routes, and a bearer client refreshes through `POST /auth/refresh` itself.
    pub async fn authenticate(&self, headers: &HeaderMap) -> Result<User, Unauthenticated> {
        self.inner.authenticate(headers).await.map(|(user, _)| user)
    }

    /// A layer that answers 401 unless the request carries a valid session, and
    /// puts the [`User`] in the request extensions for the handler behind it.
    pub fn require_auth(&self) -> RequireAuthLayer {
        RequireAuthLayer {
            inner: self.inner.clone(),
        }
    }
}

impl Inner {
    /// The session, and whether it came from the cookie (which a browser attaches
    /// to cross-site requests) rather than a bearer token (which it never does).
    async fn authenticate(&self, headers: &HeaderMap) -> Result<(User, bool), Unauthenticated> {
        let name = &self.config.access_cookie_name;
        if raw_cookie(headers, name).is_some_and(|v| !v.is_empty()) {
            let claims =
                read_cookie(&self.config, headers, name, KIND_ACCESS).ok_or(Unauthenticated)?;
            let token = str_claim(&claims, "token");
            if str_claim(&claims, "sub").is_empty() || !is_access_token(token) {
                return Err(Unauthenticated);
            }
            return Ok((user_from(&claims, token), true));
        }

        let token = bearer_token(headers).ok_or(Unauthenticated)?;
        let claims = self
            .jwks
            .verify(
                token,
                &self.config.auth_server_issuer,
                &self.config.audience,
            )
            .await
            .map_err(|_| Unauthenticated)?;
        // An ephemeral sign-in token is signed by the same key, so the type is what
        // keeps it from passing for a session.
        if str_claim(&claims, "typ") != "access" || str_claim(&claims, "sub").is_empty() {
            return Err(Unauthenticated);
        }
        Ok((user_from(&claims, token), false))
    }
}

/// Reads the type of the auth API token inside a session cookie. It was verified
/// against the API's key set before the adapter signed it into the cookie, so its
/// claims are read without verifying it again.
fn is_access_token(token: &str) -> bool {
    unverified_claims(token).is_some_and(|claims| str_claim(&claims, "typ") == "access")
}

fn user_from(claims: &Claims, token: &str) -> User {
    let optional = |name: &str| {
        Some(str_claim(claims, name))
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    User {
        id: str_claim(claims, "sub").to_string(),
        roles: claims
            .get("roles")
            .and_then(Value::as_array)
            .map(|roles| {
                roles
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        email: optional("email"),
        phone: optional("phone"),
        token: token.to_string(),
    }
}

/// The layer [`Adapter::require_auth`] returns.
#[derive(Clone)]
pub struct RequireAuthLayer {
    inner: Arc<Inner>,
}

impl fmt::Debug for RequireAuthLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequireAuthLayer").finish_non_exhaustive()
    }
}

impl<S> Layer<S> for RequireAuthLayer {
    type Service = RequireAuth<S>;

    fn layer(&self, service: S) -> Self::Service {
        RequireAuth {
            adapter: self.inner.clone(),
            service,
        }
    }
}

/// The service [`RequireAuthLayer`] wraps around a handler.
#[derive(Clone)]
pub struct RequireAuth<S> {
    adapter: Arc<Inner>,
    service: S,
}

impl<S> fmt::Debug for RequireAuth<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequireAuth").finish_non_exhaustive()
    }
}

impl<S> Service<Request> for RequireAuth<S>
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

    fn call(&mut self, mut req: Request) -> Self::Future {
        // The clone has not been driven to readiness, so the ready one is the one
        // that handles this request.
        let clone = self.service.clone();
        let mut service = std::mem::replace(&mut self.service, clone);
        let adapter = self.adapter.clone();

        Box::pin(async move {
            match adapter.authenticate(req.headers()).await {
                // A cookie session gets the same cross-site check as the auth
                // routes, or a form on another site could act as the user.
                Ok((_, true))
                    if check_origin(&adapter.config, req.method(), req.headers()).is_some() =>
                {
                    Ok(json_response(
                        StatusCode::FORBIDDEN,
                        &json!({ "error": "cross_site_request_blocked" }),
                    ))
                }
                Ok((user, _)) => {
                    req.extensions_mut().insert(user);
                    service.call(req).await.map(IntoResponse::into_response)
                }
                Err(rejected) => Ok(rejected.into_response()),
            }
        })
    }
}
