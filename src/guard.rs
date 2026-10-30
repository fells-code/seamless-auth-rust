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
use crate::jwt::{Claims, str_claim};
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
    /// A recovery session: signed in with a recovery code or self-service
    /// recovery, and able to do little but enroll a new passkey or authenticator
    /// app. [`Adapter::require_auth`] refuses one unless told otherwise.
    pub recovery: bool,
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
            .field("recovery", &self.recovery)
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
    ///
    /// The access token inside a cookie is verified against the auth API's JWKS
    /// like a bearer token, and the roles and recovery state come from it.
    ///
    /// It accepts a recovery session, so check [`User::recovery`] before treating
    /// the user as fully signed in.
    pub async fn authenticate(&self, headers: &HeaderMap) -> Result<User, Unauthenticated> {
        self.inner.authenticate(headers).await.map(|(user, _)| user)
    }

    /// A layer that answers 401 unless the request carries a valid session, and
    /// puts the [`User`] in the request extensions for the handler behind it.
    ///
    /// A recovery session answers 403 `{"error":"enrollment_required"}`, so an
    /// account that is only part way through recovery is not taken for signed in.
    /// [`RequireAuthLayer::allow_recovery`] lets one through, for the screens that
    /// guide the user to enroll.
    pub fn require_auth(&self) -> RequireAuthLayer {
        RequireAuthLayer {
            inner: self.inner.clone(),
            allow_recovery: false,
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
            let subject = str_claim(&claims, "sub");
            let token = str_claim(&claims, "token");
            if subject.is_empty() || token.is_empty() {
                return Err(Unauthenticated);
            }
            // The cookie secret alone can sign a cookie, so the token inside is held
            // to the API's key set and the session's authority comes from it.
            let verified = self.verify_access_token(token).await?;
            if str_claim(&verified, "sub") != subject {
                return Err(Unauthenticated);
            }
            let mut user = user_from(&claims, token);
            user.roles = roles(&verified);
            user.recovery = is_recovery(&verified);
            return Ok((user, true));
        }

        let token = bearer_token(headers).ok_or(Unauthenticated)?;
        let claims = self.verify_access_token(token).await?;
        Ok((user_from(&claims, token), false))
    }

    async fn verify_access_token(&self, token: &str) -> Result<Claims, Unauthenticated> {
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
        Ok(claims)
    }
}

pub(crate) fn is_recovery(claims: &Claims) -> bool {
    claims.get("recovery") == Some(&Value::Bool(true))
}

fn user_from(claims: &Claims, token: &str) -> User {
    let optional = |name: &str| {
        Some(str_claim(claims, name))
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    User {
        id: str_claim(claims, "sub").to_string(),
        roles: roles(claims),
        email: optional("email"),
        phone: optional("phone"),
        token: token.to_string(),
        recovery: is_recovery(claims),
    }
}

fn roles(claims: &Claims) -> Vec<String> {
    claims
        .get("roles")
        .and_then(Value::as_array)
        .map(|roles| {
            roles
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// The layer [`Adapter::require_auth`] returns.
#[derive(Clone)]
pub struct RequireAuthLayer {
    inner: Arc<Inner>,
    allow_recovery: bool,
}

impl RequireAuthLayer {
    /// Lets a recovery session through instead of answering 403
    /// `enrollment_required`. The handler can still tell it apart by
    /// [`User::recovery`].
    pub fn allow_recovery(mut self, allow: bool) -> Self {
        self.allow_recovery = allow;
        self
    }
}

impl fmt::Debug for RequireAuthLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequireAuthLayer")
            .field("allow_recovery", &self.allow_recovery)
            .finish_non_exhaustive()
    }
}

impl<S> Layer<S> for RequireAuthLayer {
    type Service = RequireAuth<S>;

    fn layer(&self, service: S) -> Self::Service {
        RequireAuth {
            adapter: self.inner.clone(),
            allow_recovery: self.allow_recovery,
            service,
        }
    }
}

/// The service [`RequireAuthLayer`] wraps around a handler.
#[derive(Clone)]
pub struct RequireAuth<S> {
    adapter: Arc<Inner>,
    allow_recovery: bool,
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
        let allow_recovery = self.allow_recovery;

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
                Ok((user, _)) if user.recovery && !allow_recovery => Ok(json_response(
                    StatusCode::FORBIDDEN,
                    &json!({ "error": "enrollment_required" }),
                )),
                Ok((user, _)) => {
                    req.extensions_mut().insert(user);
                    service.call(req).await.map(IntoResponse::into_response)
                }
                Err(rejected) => Ok(rejected.into_response()),
            }
        })
    }
}
