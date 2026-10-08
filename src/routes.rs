use std::sync::Arc;

use axum::body::Body;
use axum::http::{
    HeaderMap, HeaderValue, Method, StatusCode, header::CONTENT_TYPE, request::Parts,
};
use serde_json::{Map, Value};

use crate::adapter::{
    BodyError, Forwarded, Inner, Reply, UpstreamCall, bearer_token, failure, is_json_content_type,
    read_json, read_request_body,
};
use crate::cookies::{
    CookieWrite, cookie_kind, ephemeral_cookie, raw_cookie, read_cookie, session_cookies,
};
use crate::delivery::parse_delivery;
use crate::jwt::{Claims, str_claim};
use crate::manifest::RouteMatch;
use crate::refresh::SilentRefreshError;

/// What the adapter sends for a route, and any cookies a silent refresh
/// produced on the way.
pub(crate) struct Credential {
    pub authorization: Option<String>,
    pub set: Vec<CookieWrite>,
}

impl Inner {
    /// Resolves the held token a route names. In cookie transport it reads the
    /// route's cookie, refreshing a missing access token from the refresh cookie;
    /// in bearer transport the client holds its own token.
    pub(crate) async fn credential_for(
        self: &Arc<Self>,
        headers: &HeaderMap,
        forwarded: &Forwarded,
        kind: &str,
        bearer: bool,
    ) -> Result<Credential, Reply> {
        if kind == "none" {
            return Ok(Credential {
                authorization: None,
                set: Vec::new(),
            });
        }

        if bearer {
            return match bearer_token(headers) {
                Some(token) => Ok(Credential {
                    authorization: Some(format!("Bearer {token}")),
                    set: Vec::new(),
                }),
                None => Err(Reply::error(
                    StatusCode::UNAUTHORIZED,
                    &format!("{kind} session required"),
                )),
            };
        }

        let name = self.config.cookie_name(kind);
        let has_cookie = raw_cookie(headers, name).is_some();
        let payload = read_cookie(&self.config, headers, name, cookie_kind(kind));
        let valid = payload.is_some();
        let token = payload
            .as_ref()
            .map(|p| str_claim(p, "token"))
            .unwrap_or("");

        if valid && !token.is_empty() {
            return Ok(Credential {
                authorization: Some(format!("Bearer {token}")),
                set: Vec::new(),
            });
        }

        // A refresh only ever yields an access token, so only the access cookie can
        // be restored from it. Spending it for a pre-auth or registration route
        // would store an access token under that route's cookie. A cookie that
        // fails verification is refused rather than refreshed past.
        if kind == "access" && (!has_cookie || valid) {
            match self.silent_refresh(headers, forwarded).await {
                Ok((session, cookies)) => {
                    return Ok(Credential {
                        authorization: Some(format!("Bearer {}", str_claim(&session, "token"))),
                        set: cookies,
                    });
                }
                Err(SilentRefreshError::NoRefreshCookie) => {}
                Err(SilentRefreshError::Failed(err)) => {
                    tracing::debug!("[seamless-auth] Silent refresh failed: {err}");
                    return Err(Reply::error(StatusCode::UNAUTHORIZED, "Refresh failed")
                        .with_clear(vec![
                            self.config.access_cookie_name.clone(),
                            self.config.registration_cookie_name.clone(),
                            self.config.refresh_cookie_name.clone(),
                        ]));
                }
            }
        }

        if has_cookie {
            Err(Reply::error(
                StatusCode::UNAUTHORIZED,
                &format!("Invalid or expired {name} cookie"),
            ))
        } else {
            Err(Reply::error(
                StatusCode::UNAUTHORIZED,
                &format!("Missing required cookie \"{name}\""),
            ))
        }
    }

    /// Checks the token in a session response: signed by the auth API, of the
    /// expected type, and belonging to the subject the body names. Returns the
    /// session id. A response that fails any of these is one this adapter cannot
    /// vouch for, so nothing is issued from it.
    pub(crate) async fn verify_session(
        &self,
        session: &Claims,
        typ: &str,
    ) -> Result<String, String> {
        let claims = self
            .jwks
            .verify(
                str_claim(session, "token"),
                &self.config.auth_server_issuer,
                &self.config.audience,
            )
            .await?;
        if str_claim(&claims, "typ") != typ {
            return Err("unexpected token type".into());
        }
        let subject = str_claim(&claims, "sub");
        if subject.is_empty() || subject != str_claim(session, "sub") {
            return Err("token subject does not match the response".into());
        }
        Ok(str_claim(&claims, "sid").to_string())
    }

    pub(crate) async fn manifest_route(
        self: &Arc<Self>,
        parts: &Parts,
        body: Body,
        forwarded: &Forwarded,
        found: RouteMatch<'_>,
        bearer: bool,
    ) -> Reply {
        let route = found.route;
        if route.credential == "refresh" {
            return Reply::error(StatusCode::NOT_FOUND, "not_found");
        }

        let body = match read_request_body(body).await {
            Ok(body) => body,
            Err(BodyError::TooLarge) => {
                return Reply::error(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large");
            }
            Err(BodyError::Unreadable) => {
                return Reply::error(StatusCode::BAD_REQUEST, "bad_request");
            }
        };
        // The body goes upstream as JSON, so it has to be JSON. A cross-site form
        // can send a text/plain body shaped like JSON with no CORS preflight; read
        // as JSON, that would be a sign-in the victim never made.
        if body.is_some() && !is_explicit_json(parts.headers.get(CONTENT_TYPE)) {
            return Reply::error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type");
        }

        let credential = match self
            .credential_for(&parts.headers, forwarded, &route.credential, bearer)
            .await
        {
            Ok(credential) => credential,
            Err(rejected) => return rejected,
        };
        let set = credential.set;

        let Ok(method) = Method::from_bytes(route.method.as_bytes()) else {
            return Reply::error(StatusCode::NOT_FOUND, "not_found");
        };
        let external = route.delivery && self.config.deliver.is_some();
        let mut call = UpstreamCall::new(method, route.upstream_path(&found.params));
        call.query = parts.uri.query().map(str::to_string);
        call.body = body;
        call.authorization = credential.authorization;
        call.external_delivery = external;
        call.service = if external {
            self.tokens.delivery_authorization()
        } else {
            self.tokens.proxy_authorization()
        };

        let res = match self.call(forwarded, call).await {
            Ok(res) => res,
            Err(err) => {
                // Without the URL: a path or query can hold a magic-link token or an
                // OAuth code.
                let err = err.without_url();
                tracing::warn!("[seamless-auth] {} {}: {err}", route.method, route.path);
                return Reply::error(StatusCode::BAD_GATEWAY, "upstream_unavailable").with_set(set);
            }
        };

        let status = res.status();
        if status.is_success() && !is_json_content_type(res.headers().get(CONTENT_TYPE)) {
            let mut reply = Reply::new(status, None).with_set(set);
            reply.raw = Some(res);
            return reply;
        }

        let (mut data, is_json) = read_json(res).await;
        if !status.is_success() {
            return failure(status, data, is_json).with_set(set);
        }

        if route.delivery
            && let Some(Value::Object(obj)) = data.as_mut()
        {
            // The message is the application's to send. It never goes back to the
            // caller, in either transport.
            let delivery = obj.remove("delivery").filter(|d| !d.is_null());
            if let (Some(raw), Some(deliver), true) =
                (delivery, self.config.deliver.as_ref(), external)
            {
                let sent = match parse_delivery(&raw) {
                    Ok(delivery) => deliver(delivery).await.map_err(|e| e.to_string()),
                    Err(err) => Err(err),
                };
                if let Err(err) = sent {
                    tracing::warn!(
                        "[seamless-auth] Delivery for {} {} failed: {err}",
                        route.method,
                        route.path
                    );
                    return Reply::error(StatusCode::BAD_GATEWAY, "delivery_failed").with_set(set);
                }
            }
        }

        let mut reply = Reply::new(status, None).with_set(set);
        for held in &route.clears {
            reply.clear.push(self.config.cookie_name(held).to_string());
        }

        if let (Some(issues), Some(Value::Object(session))) =
            (route.issues.as_deref(), data.as_ref())
            && carries_session(session)
        {
            let session_id = match self
                .verify_session(session, issued_token_type(issues))
                .await
            {
                Ok(id) => id,
                Err(err) => {
                    tracing::warn!(
                        "[seamless-auth] Refusing an unverifiable session from {} {}: {err}",
                        route.method,
                        route.path
                    );
                    return Reply::error(StatusCode::BAD_GATEWAY, "invalid_upstream_session");
                }
            };

            if !bearer {
                let issued = match issues {
                    "preAuth" | "registration" => {
                        ephemeral_cookie(&self.config, issues, session).map(|c| vec![c])
                    }
                    "session" => session_cookies(&self.config, session, &session_id, true),
                    _ => session_cookies(&self.config, session, &session_id, false),
                };
                match issued {
                    Ok(cookies) => reply.set.extend(cookies),
                    Err(err) => {
                        tracing::warn!("[seamless-auth] {} {}: {err}", route.method, route.path);
                        return Reply::error(StatusCode::BAD_GATEWAY, "invalid_upstream_session");
                    }
                }
            }
        }

        reply.body = match data {
            Some(data) if !bearer => Some(cookie_transport_body(
                route.body.as_ref().map(|b| b.pick.as_slice()),
                data,
            )),
            data => data,
        };
        reply
    }
}

/// A request content type that names JSON. Unlike a response, a request with a
/// body and no content type is not taken for JSON.
fn is_explicit_json(content_type: Option<&HeaderValue>) -> bool {
    content_type.is_some() && is_json_content_type(content_type)
}

/// The type of token a route that issues a session must return.
fn issued_token_type(issues: &str) -> &'static str {
    match issues {
        "preAuth" | "registration" => "ephemeral",
        _ => "access",
    }
}

pub(crate) fn carries_session(body: &Map<String, Value>) -> bool {
    !str_claim(body, "token").is_empty() && !str_claim(body, "sub").is_empty()
}

/// What a browser sees: a pick, or everything but tokens. The cookies carry
/// every token, including the ephemeral one the auth API re-mints on an OTP send.
pub(crate) fn cookie_transport_body(pick: Option<&[String]>, body: Value) -> Value {
    let Value::Object(mut obj) = body else {
        return body;
    };
    match pick {
        Some(pick) => {
            let mut out = Map::new();
            for key in pick {
                if let Some(value) = obj.remove(key) {
                    out.insert(key.clone(), value);
                }
            }
            out.remove("token");
            out.remove("refreshToken");
            Value::Object(out)
        }
        None => {
            obj.remove("token");
            obj.remove("refreshToken");
            Value::Object(obj)
        }
    }
}
