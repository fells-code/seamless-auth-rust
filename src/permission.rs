use axum::extract::{FromRequestParts, RawPathParams, Request};
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::{Value, json};

use crate::adapter::json_response;
use crate::jwt::Claims;

/// What a permission guard requires: which permissions, whether any or all of
/// them, and where they count from. [`Adapter::require_permission_rule`] and
/// [`Verifier::require_permission_rule`] take one.
///
/// Matching is exact and case-sensitive, with no wildcards and no implied
/// grants: `invoices:write` does not satisfy `invoices:read`.
///
/// By default a permission counts from either the `permissions` or the
/// `org_permissions` claim. Prefer
/// [`organization_from_path`](Self::organization_from_path) for a route that
/// names an organization: without it, a token for organization A passes on
/// `/orgs/B/...`.
///
/// [`Adapter::require_permission_rule`]: crate::Adapter::require_permission_rule
/// [`Verifier::require_permission_rule`]: crate::Verifier::require_permission_rule
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermissionRule {
    required: Vec<String>,
    mode: Mode,
    scope: Scope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Any,
    All,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Scope {
    Default,
    Organization,
    OrganizationFromPath(String),
}

impl PermissionRule {
    /// At least one of `permissions` must be held.
    pub fn any<I, T>(permissions: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        Self::new(permissions, Mode::Any)
    }

    /// Every one of `permissions` must be held. Each may come from either claim.
    pub fn all<I, T>(permissions: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        Self::new(permissions, Mode::All)
    }

    fn new<I, T>(permissions: I, mode: Mode) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        Self {
            required: permissions.into_iter().map(Into::into).collect(),
            mode,
            scope: Scope::Default,
        }
    }

    /// Only `org_permissions` counts, and the token must have an active
    /// organization. It does not say which organization: see
    /// [`organization_from_path`](Self::organization_from_path).
    pub fn organization(mut self) -> Self {
        self.scope = Scope::Organization;
        self
    }

    /// Organization scope, and the route parameter `param` must equal the active
    /// organization exactly. A route without that parameter refuses everyone, as
    /// does a guard outside the router, where no route has been matched yet: use
    /// `route_layer` or `Router::layer`.
    pub fn organization_from_path(mut self, param: impl Into<String>) -> Self {
        self.scope = Scope::OrganizationFromPath(param.into());
        self
    }

    pub(crate) fn requires_nothing(&self) -> bool {
        self.required.is_empty() || self.required.iter().any(|p| p.trim().is_empty())
    }

    pub(crate) fn allows(&self, held: Held<'_>, route_organization: Option<&str>) -> bool {
        // `all` over nothing is vacuously true, so an empty list is refused here
        // as well as when the guard is built.
        if self.requires_nothing() {
            return false;
        }
        let organization = held.organization_id.filter(|id| !id.is_empty());
        let in_scope = match &self.scope {
            Scope::Default => true,
            Scope::Organization => organization.is_some(),
            Scope::OrganizationFromPath(_) => {
                organization.is_some() && organization == route_organization
            }
        };
        if !in_scope {
            return false;
        }
        let counts = |permission: &String| {
            held.organization_permissions.contains(permission)
                || (self.scope == Scope::Default && held.permissions.contains(permission))
        };
        match self.mode {
            Mode::Any => self.required.iter().any(counts),
            Mode::All => self.required.iter().all(counts),
        }
    }

    /// The route parameter this rule is bound to, read out of the request, which
    /// is handed back. Percent-decoded, as `Path` would give it. `None` when the
    /// rule is not bound or the route has no such parameter.
    pub(crate) async fn route_organization(&self, req: Request) -> (Request, Option<String>) {
        let Scope::OrganizationFromPath(param) = &self.scope else {
            return (req, None);
        };
        let (mut parts, body) = req.into_parts();
        let value = RawPathParams::from_request_parts(&mut parts, &())
            .await
            .ok()
            .and_then(|params| {
                params
                    .iter()
                    .find(|(name, _)| name == param)
                    .map(|(_, value)| value.to_string())
            });
        (Request::from_parts(parts, body), value)
    }
}

/// The grants a rule is evaluated against, from a token or the live read.
#[derive(Clone, Copy)]
pub(crate) struct Held<'a> {
    pub permissions: &'a [String],
    pub organization_id: Option<&'a str>,
    pub organization_permissions: &'a [String],
}

/// A claim that is not an array reads as empty, and non-string entries are
/// ignored: a malformed claim grants nothing, and never fails the request.
pub(crate) fn string_list(claims: &Claims, name: &str) -> Vec<String> {
    claims
        .get(name)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn permissions_omitted(claims: &Claims) -> bool {
    claims.get("permissions_omitted") == Some(&Value::Bool(true))
}

pub(crate) fn insufficient_permission() -> Response {
    json_response(
        StatusCode::FORBIDDEN,
        &json!({ "error": "insufficient_permission" }),
    )
}
