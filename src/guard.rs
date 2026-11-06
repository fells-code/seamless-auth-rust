use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::extract::{FromRequestParts, OptionalFromRequestParts, Request};
use axum::http::{HeaderMap, StatusCode, request::Parts};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use tower_layer::Layer;
use tower_service::Service;

use crate::adapter::{Adapter, Inner, MAX_BODY_BYTES, bearer_token, json_response, read_limited};
use crate::cookies::{KIND_ACCESS, raw_cookie, read_cookie};
use crate::jwt::{Claims, str_claim};
use crate::options::BuildError;
use crate::origin::check_origin;
use crate::permission::{
    Held, PermissionRule, insufficient_permission, permissions_omitted, string_list,
};
use crate::token_guard::role_grants_access;

/// The session a request was authenticated with. [`RequireAuth`] puts it in the
/// request extensions, and it is an extractor for handlers behind the guard.
///
/// `Option<User>` is an extractor too. It yields the user exactly when
/// [`Adapter::require_auth`] with default options would let the request through,
/// and `None` otherwise, including for a recovery session. It never rejects. On
/// a route with no guard in front, put [`Adapter::optional_auth`] there so it
/// has a session to read.
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
    /// The active organization, from the `org_id` claim of the verified access
    /// token. `None` when the session has no organization.
    pub organization_id: Option<String>,
    /// The `permissions` claim. Empty when [`permissions_omitted`](Self::permissions_omitted).
    pub permissions: Vec<String>,
    /// The `org_roles` claim, the roles in the active organization. They never
    /// count for [`Adapter::require_role`]. Empty when
    /// [`permissions_omitted`](Self::permissions_omitted).
    pub organization_roles: Vec<String>,
    /// The `org_permissions` claim. Empty when
    /// [`permissions_omitted`](Self::permissions_omitted).
    pub organization_permissions: Vec<String>,
    /// The token left its permissions out because they would not fit, so the
    /// empty lists above mean "ask", not "none". [`Adapter::require_permission`]
    /// reads the live set in that case.
    pub permissions_omitted: bool,
}

impl User {
    /// Whether any of the user's roles grants `role`, with the same scoped
    /// matching as [`Adapter::require_role`].
    pub fn has_role(&self, role: &str) -> bool {
        self.roles
            .iter()
            .any(|granted| role_grants_access(granted, role))
    }
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
            .field("organization_id", &self.organization_id)
            .field("permissions", &self.permissions)
            .field("organization_roles", &self.organization_roles)
            .field("organization_permissions", &self.organization_permissions)
            .field("permissions_omitted", &self.permissions_omitted)
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

impl<S: Send + Sync> OptionalFromRequestParts<S> for User {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<User>()
            .filter(|user| !user.recovery)
            .cloned())
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
            roles: Arc::from([]),
            permissions: None,
            optional: false,
        }
    }

    /// A layer that does what [`require_auth`](Self::require_auth) does, then
    /// answers 403 `{"error":"insufficient_role"}` unless one of the user's
    /// roles grants any one of `roles`. Matching is scoped: `orders:write`
    /// grants `orders:read`, and `orders` or `orders:*` grant `orders:...`.
    /// Roles come from the verified access token, never from the cookie alone.
    ///
    /// An empty list, or an empty role, is an error: a guard that requires
    /// nothing would let every session through.
    pub fn require_role<I, T>(&self, roles: I) -> Result<RequireAuthLayer, BuildError>
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        let roles: Vec<String> = roles.into_iter().map(Into::into).collect();
        if roles.is_empty() || roles.iter().any(|r| r.trim().is_empty()) {
            return Err(BuildError::EmptyGuard);
        }
        Ok(RequireAuthLayer {
            roles: roles.into(),
            ..self.require_auth()
        })
    }

    /// A layer that does what [`require_auth`](Self::require_auth) does, then
    /// answers 403 `{"error":"insufficient_permission"}` unless the user holds at
    /// least one of `permissions`, from the `permissions` or `org_permissions`
    /// claim. Matching is exact: see [`PermissionRule`].
    ///
    /// When the token has `permissions_omitted`, each request reads the live set
    /// from the auth API with the caller's token. If that read fails the guard
    /// answers 503 `{"error":"permissions_unavailable"}`, and a 401 from it
    /// answers the usual 401.
    ///
    /// An empty list, or an empty permission, is an error: a guard that requires
    /// nothing must not open a route.
    pub fn require_permission<I, T>(&self, permissions: I) -> Result<RequireAuthLayer, BuildError>
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.require_permission_rule(PermissionRule::any(permissions))
    }

    /// Like [`require_permission`](Self::require_permission), but every one of
    /// `permissions` must be held. Each may come from either claim.
    pub fn require_all_permissions<I, T>(
        &self,
        permissions: I,
    ) -> Result<RequireAuthLayer, BuildError>
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.require_permission_rule(PermissionRule::all(permissions))
    }

    /// Like [`require_permission`](Self::require_permission), for a
    /// [`PermissionRule`] with an organization scope.
    pub fn require_permission_rule(
        &self,
        rule: PermissionRule,
    ) -> Result<RequireAuthLayer, BuildError> {
        if rule.requires_nothing() {
            return Err(BuildError::EmptyGuard);
        }
        Ok(RequireAuthLayer {
            permissions: Some(Arc::new(rule)),
            ..self.require_auth()
        })
    }

    /// A layer that never answers itself. It puts the [`User`] in the request
    /// extensions when [`require_auth`](Self::require_auth) would let the
    /// request through, and nothing otherwise, for handlers that take
    /// `Option<User>` on routes open to everyone.
    pub fn optional_auth(&self) -> RequireAuthLayer {
        RequireAuthLayer {
            optional: true,
            ..self.require_auth()
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
            user.organization_id = optional_claim(&verified, "org_id");
            // Read from the token, never copied to the cookie: it is already in
            // there, and a cookie has a 4 KiB limit.
            user.permissions = string_list(&verified, "permissions");
            user.organization_roles = string_list(&verified, "org_roles");
            user.organization_permissions = string_list(&verified, "org_permissions");
            user.permissions_omitted = permissions_omitted(&verified);
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

    /// The answer when `user` does not meet `rule`, or `None` when they do.
    async fn refuse_permission(
        &self,
        user: &User,
        rule: &PermissionRule,
        route_organization: Option<&str>,
    ) -> Option<Response> {
        let allowed = if user.permissions_omitted {
            match self.live_permissions(&user.token).await {
                Ok(live) => rule.allows(live.held(), route_organization),
                Err(LiveReadError::Unauthenticated) => {
                    return Some(Unauthenticated.into_response());
                }
                Err(LiveReadError::Unavailable(why)) => {
                    tracing::warn!("[seamless-auth] reading live permissions failed ({why}).");
                    return Some(json_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &json!({ "error": "permissions_unavailable" }),
                    ));
                }
            }
        } else {
            rule.allows(
                Held {
                    permissions: &user.permissions,
                    organization_id: user.organization_id.as_deref(),
                    organization_permissions: &user.organization_permissions,
                },
                route_organization,
            )
        };
        (!allowed).then(insufficient_permission)
    }

    /// `GET /users/me/permissions` as the caller, with no cache and no retry. It
    /// carries only the caller's token, never the service token.
    async fn live_permissions(&self, token: &str) -> Result<LivePermissions, LiveReadError> {
        let url = format!("{}/users/me/permissions", self.config.auth_server_url);
        let res = self
            .config
            .http_client
            .get(url)
            .header("accept", "application/json")
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| LiveReadError::Unavailable(e.without_url().to_string()))?;
        let status = res.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(LiveReadError::Unauthenticated);
        }
        if !status.is_success() {
            return Err(LiveReadError::Unavailable(format!(
                "HTTP {}",
                status.as_u16()
            )));
        }
        let body = read_limited(res, MAX_BODY_BYTES)
            .await
            .map_err(LiveReadError::Unavailable)?;
        LivePermissions::parse(&body)
            .ok_or_else(|| LiveReadError::Unavailable("malformed response body".into()))
    }
}

enum LiveReadError {
    Unauthenticated,
    Unavailable(String),
}

struct LivePermissions {
    permissions: Vec<String>,
    organization_id: Option<String>,
    organization_permissions: Vec<String>,
}

impl LivePermissions {
    /// A claim that is not a list reads as empty, but this is the answer to a
    /// question: a body of the wrong shape says nothing about what the user holds,
    /// so it fails closed rather than reading as "holds nothing".
    fn parse(body: &[u8]) -> Option<Self> {
        let Value::Object(body) = serde_json::from_slice(body).ok()? else {
            return None;
        };
        body.get("permissions")?.as_array()?;
        body.get("organizationPermissions")?.as_array()?;
        let organization_id = match body.get("organizationId")? {
            Value::Null => None,
            Value::String(id) => Some(id.clone()),
            _ => return None,
        };
        Some(Self {
            permissions: string_list(&body, "permissions"),
            organization_id,
            organization_permissions: string_list(&body, "organizationPermissions"),
        })
    }

    fn held(&self) -> Held<'_> {
        Held {
            permissions: &self.permissions,
            organization_id: self.organization_id.as_deref(),
            organization_permissions: &self.organization_permissions,
        }
    }
}

pub(crate) fn is_recovery(claims: &Claims) -> bool {
    claims.get("recovery") == Some(&Value::Bool(true))
}

fn optional_claim(claims: &Claims, name: &str) -> Option<String> {
    Some(str_claim(claims, name))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn user_from(claims: &Claims, token: &str) -> User {
    User {
        id: str_claim(claims, "sub").to_string(),
        roles: roles(claims),
        email: optional_claim(claims, "email"),
        phone: optional_claim(claims, "phone"),
        token: token.to_string(),
        recovery: is_recovery(claims),
        organization_id: optional_claim(claims, "org_id"),
        permissions: string_list(claims, "permissions"),
        organization_roles: string_list(claims, "org_roles"),
        organization_permissions: string_list(claims, "org_permissions"),
        permissions_omitted: permissions_omitted(claims),
    }
}

fn roles(claims: &Claims) -> Vec<String> {
    string_list(claims, "roles")
}

/// The layer [`Adapter::require_auth`], [`Adapter::require_role`],
/// [`Adapter::require_permission`] and [`Adapter::optional_auth`] return.
#[derive(Clone)]
pub struct RequireAuthLayer {
    inner: Arc<Inner>,
    allow_recovery: bool,
    roles: Arc<[String]>,
    permissions: Option<Arc<PermissionRule>>,
    optional: bool,
}

impl RequireAuthLayer {
    /// Lets a recovery session through instead of answering 403
    /// `enrollment_required`. The handler can still tell it apart by
    /// [`User::recovery`]. A layer from [`Adapter::optional_auth`] passes a
    /// recovery session on in the extensions, but `Option<User>` still yields
    /// `None` for it.
    pub fn allow_recovery(mut self, allow: bool) -> Self {
        self.allow_recovery = allow;
        self
    }
}

impl fmt::Debug for RequireAuthLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequireAuthLayer")
            .field("allow_recovery", &self.allow_recovery)
            .field("roles", &self.roles)
            .field("permissions", &self.permissions)
            .field("optional", &self.optional)
            .finish_non_exhaustive()
    }
}

impl<S> Layer<S> for RequireAuthLayer {
    type Service = RequireAuth<S>;

    fn layer(&self, service: S) -> Self::Service {
        RequireAuth {
            adapter: self.inner.clone(),
            allow_recovery: self.allow_recovery,
            roles: self.roles.clone(),
            permissions: self.permissions.clone(),
            optional: self.optional,
            service,
        }
    }
}

/// The service [`RequireAuthLayer`] wraps around a handler.
#[derive(Clone)]
pub struct RequireAuth<S> {
    adapter: Arc<Inner>,
    allow_recovery: bool,
    roles: Arc<[String]>,
    permissions: Option<Arc<PermissionRule>>,
    optional: bool,
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
        let roles = self.roles.clone();
        let permissions = self.permissions.clone();
        let optional = self.optional;

        Box::pin(async move {
            let refused = match adapter.authenticate(req.headers()).await {
                // A cookie session gets the same cross-site check as the auth
                // routes, or a form on another site could act as the user.
                Ok((_, true))
                    if check_origin(&adapter.config, req.method(), req.headers()).is_some() =>
                {
                    json_response(
                        StatusCode::FORBIDDEN,
                        &json!({ "error": "cross_site_request_blocked" }),
                    )
                }
                Ok((user, _)) if user.recovery && !allow_recovery => json_response(
                    StatusCode::FORBIDDEN,
                    &json!({ "error": "enrollment_required" }),
                ),
                Ok((user, _))
                    if !roles.is_empty() && !roles.iter().any(|role| user.has_role(role)) =>
                {
                    json_response(
                        StatusCode::FORBIDDEN,
                        &json!({ "error": "insufficient_role" }),
                    )
                }
                Ok((user, _)) => {
                    let refused = match &permissions {
                        Some(rule) => {
                            let (request, route_organization) = rule.route_organization(req).await;
                            req = request;
                            adapter
                                .refuse_permission(&user, rule, route_organization.as_deref())
                                .await
                        }
                        None => None,
                    };
                    match refused {
                        Some(refused) => refused,
                        None => {
                            req.extensions_mut().insert(user);
                            return service.call(req).await.map(IntoResponse::into_response);
                        }
                    }
                }
                Err(rejected) => rejected.into_response(),
            };
            if optional {
                return service.call(req).await.map(IntoResponse::into_response);
            }
            Ok(refused)
        })
    }
}
