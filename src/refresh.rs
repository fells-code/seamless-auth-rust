use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, Method, StatusCode};
use serde_json::Value;
use tokio::sync::watch;

use crate::adapter::{Forwarded, Inner, Reply, UpstreamCall, bearer_token, failure, read_json};
use crate::cookies::{CookieWrite, KIND_REFRESH, raw_cookie, read_cookie, session_cookies};
use crate::jwt::{Claims, str_claim};
use crate::routes::{carries_session, cookie_transport_body};

/// A refresh token presented again within this window gets the rotation it
/// already got, so parallel requests from several tabs with one expired session
/// all succeed instead of tripping the auth API's reuse detection.
const REUSE_WINDOW: Duration = Duration::from_secs(5);
const FLIGHT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub(crate) enum RefreshOutcome {
    Session(Claims),
    Rejected {
        status: StatusCode,
        body: Option<Value>,
        is_json: bool,
    },
    Failed(String),
}

struct Flight {
    id: u64,
    rx: watch::Receiver<Option<RefreshOutcome>>,
    finished: Option<Instant>,
}

#[derive(Default)]
pub(crate) struct Refresher {
    flights: Mutex<HashMap<String, Flight>>,
    next_id: Mutex<u64>,
}

impl Refresher {
    /// Runs `rotation` once per key at a time, and hands a successful outcome to
    /// every caller with the same key for the reuse window afterwards. A failure
    /// is not kept, so each later caller sees it from the auth API itself.
    ///
    /// The rotation runs on its own task: a caller that goes away mid-flight must
    /// not drop a rotation the auth API has already made, or every other tab would
    /// replay a spent refresh token.
    pub async fn share<Fut>(
        self: &Arc<Self>,
        key: String,
        rotation: impl FnOnce() -> Fut,
    ) -> RefreshOutcome
    where
        Fut: Future<Output = RefreshOutcome> + Send + 'static,
    {
        let mut rx = {
            let mut flights = self.flights.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            flights.retain(|_, flight| {
                flight
                    .finished
                    .is_none_or(|at| now.duration_since(at) <= REUSE_WINDOW)
            });

            match flights.get(&key) {
                Some(flight) => flight.rx.clone(),
                None => {
                    let id = {
                        let mut next = self.next_id.lock().unwrap_or_else(|e| e.into_inner());
                        *next += 1;
                        *next
                    };
                    let (tx, rx) = watch::channel(None);
                    flights.insert(
                        key.clone(),
                        Flight {
                            id,
                            rx: rx.clone(),
                            finished: None,
                        },
                    );

                    let this = self.clone();
                    let rotation = rotation();
                    let flight_key = key.clone();
                    tokio::spawn(async move {
                        // Bounded whatever client the adopter supplied: a flight that
                        // never settles would hang every caller holding this token.
                        let outcome = tokio::time::timeout(FLIGHT_TIMEOUT, rotation)
                            .await
                            .unwrap_or_else(|_| RefreshOutcome::Failed("refresh timed out".into()));
                        this.settle(
                            &flight_key,
                            id,
                            matches!(outcome, RefreshOutcome::Session(_)),
                        );
                        let _ = tx.send(Some(outcome));
                    });
                    rx
                }
            }
        };

        match rx.wait_for(Option::is_some).await {
            Ok(outcome) => outcome
                .clone()
                .unwrap_or_else(|| RefreshOutcome::Failed("refresh lost".into())),
            // The rotation task ended without an answer (it panicked).
            Err(_) => {
                let mut flights = self.flights.lock().unwrap_or_else(|e| e.into_inner());
                if flights.get(&key).is_some_and(|f| f.finished.is_none()) {
                    flights.remove(&key);
                }
                RefreshOutcome::Failed("refresh task ended".into())
            }
        }
    }

    fn settle(&self, key: &str, id: u64, succeeded: bool) {
        let mut flights = self.flights.lock().unwrap_or_else(|e| e.into_inner());
        if flights.get(key).is_some_and(|f| f.id == id) {
            if succeeded {
                if let Some(flight) = flights.get_mut(key) {
                    flight.finished = Some(Instant::now());
                }
            } else {
                flights.remove(key);
            }
        }
    }
}

pub(crate) enum SilentRefreshError {
    NoRefreshCookie,
    Failed(String),
}

impl Inner {
    /// Rotates the session held in the refresh cookie.
    pub(crate) async fn silent_refresh(
        self: &Arc<Self>,
        headers: &HeaderMap,
        forwarded: &Forwarded,
    ) -> Result<(Claims, Vec<CookieWrite>), SilentRefreshError> {
        let name = &self.config.refresh_cookie_name;
        let Some(raw) = raw_cookie(headers, name).filter(|v| !v.is_empty()) else {
            return Err(SilentRefreshError::NoRefreshCookie);
        };

        let payload = read_cookie(&self.config, headers, name, KIND_REFRESH);
        let refresh_token = payload
            .as_ref()
            .map(|p| str_claim(p, "refreshToken"))
            .unwrap_or("");
        if refresh_token.is_empty() {
            return Err(SilentRefreshError::Failed("invalid refresh cookie".into()));
        }
        let subject = payload.as_ref().map(|p| str_claim(p, "sub")).unwrap_or("");

        let mut extra = Claims::new();
        extra.insert("refreshToken".into(), Value::from(refresh_token));
        let Some(service) = self.tokens.sign(subject, extra) else {
            return Err(SilentRefreshError::Failed(
                "could not sign the service token".into(),
            ));
        };

        let inner = self.clone();
        let refresh_token = refresh_token.to_string();
        let forwarded = forwarded.clone();
        let outcome = self
            .refreshes
            .share(format!("cookie:{raw}"), move || async move {
                inner.rotate(&forwarded, &refresh_token, service).await
            })
            .await;

        let session = match outcome {
            RefreshOutcome::Session(session) => session,
            RefreshOutcome::Rejected { status, .. } => {
                return Err(SilentRefreshError::Failed(format!(
                    "refresh answered {}",
                    status.as_u16()
                )));
            }
            RefreshOutcome::Failed(err) => return Err(SilentRefreshError::Failed(err)),
        };

        let session_id = self
            .verify_session(&session, "access")
            .await
            .map_err(SilentRefreshError::Failed)?;
        let cookies = session_cookies(&self.config, &session, &session_id, true)
            .map_err(SilentRefreshError::Failed)?;
        Ok((session, cookies))
    }

    async fn rotate(
        &self,
        forwarded: &Forwarded,
        refresh_token: &str,
        service: String,
    ) -> RefreshOutcome {
        let mut call = UpstreamCall::new(Method::POST, "/refresh");
        call.authorization = Some(format!("Bearer {refresh_token}"));
        call.service = Some(service);

        let res = match self.call(forwarded, call).await {
            Ok(res) => res,
            Err(err) => return RefreshOutcome::Failed(err.without_url().to_string()),
        };
        let status = res.status();
        let (body, is_json) = read_json(res).await;
        if status != StatusCode::OK {
            return RefreshOutcome::Rejected {
                status,
                body,
                is_json,
            };
        }
        match body {
            Some(Value::Object(session)) if carries_session(&session) => {
                RefreshOutcome::Session(session)
            }
            _ => RefreshOutcome::Failed("refresh returned no session".into()),
        }
    }

    pub(crate) async fn refresh_route(
        self: &Arc<Self>,
        headers: &HeaderMap,
        forwarded: &Forwarded,
        bearer: bool,
    ) -> Reply {
        if bearer {
            let Some(token) = bearer_token(headers) else {
                return Reply::error(StatusCode::UNAUTHORIZED, "refresh token required");
            };
            let Some(service) = self.tokens.proxy_authorization() else {
                return Reply::error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
            };

            let inner = self.clone();
            let refresh_token = token.to_string();
            let forwarded = forwarded.clone();
            let outcome = self
                .refreshes
                .share(format!("bearer:{token}"), move || async move {
                    inner.rotate(&forwarded, &refresh_token, service).await
                })
                .await;

            return match outcome {
                RefreshOutcome::Session(session) => {
                    match self.verify_session(&session, "access").await {
                        Ok(_) => Reply::new(StatusCode::OK, Some(Value::Object(session))),
                        Err(_) => Reply::error(StatusCode::BAD_GATEWAY, "invalid_upstream_session"),
                    }
                }
                RefreshOutcome::Rejected {
                    status,
                    body,
                    is_json,
                } => failure(status, body, is_json),
                RefreshOutcome::Failed(_) => {
                    Reply::error(StatusCode::BAD_GATEWAY, "upstream_unavailable")
                }
            };
        }

        match self.silent_refresh(headers, forwarded).await {
            Ok((session, cookies)) => Reply::new(
                StatusCode::OK,
                Some(cookie_transport_body(None, Value::Object(session))),
            )
            .with_set(cookies),
            Err(SilentRefreshError::NoRefreshCookie) => {
                Reply::error(StatusCode::UNAUTHORIZED, "refresh token required")
            }
            Err(SilentRefreshError::Failed(err)) => {
                tracing::debug!("[seamless-auth] Refresh failed: {err}");
                Reply::error(StatusCode::UNAUTHORIZED, "invalid_refresh_token").with_clear(vec![
                    self.config.access_cookie_name.clone(),
                    self.config.refresh_cookie_name.clone(),
                ])
            }
        }
    }

    /// Answers 204 and clears every held cookie, even when the auth API refuses,
    /// so a browser is never left holding a session it asked to end.
    pub(crate) async fn logout_route(
        self: &Arc<Self>,
        headers: &HeaderMap,
        forwarded: &Forwarded,
        bearer: bool,
        path: &str,
    ) -> Reply {
        let clears = vec![
            self.config.access_cookie_name.clone(),
            self.config.registration_cookie_name.clone(),
            self.config.refresh_cookie_name.clone(),
        ];

        let credential = match self
            .credential_for(headers, forwarded, "access", bearer)
            .await
        {
            Ok(credential) => credential,
            Err(rejected) => return rejected.with_clear(clears),
        };

        let mut call = UpstreamCall::new(Method::DELETE, path);
        call.authorization = credential.authorization;
        call.service = self.tokens.proxy_authorization();

        match self.call(forwarded, call).await {
            Err(_) => {
                Reply::error(StatusCode::BAD_GATEWAY, "upstream_unavailable").with_clear(clears)
            }
            Ok(res) => {
                let status = if res.status().is_success() {
                    StatusCode::NO_CONTENT
                } else {
                    res.status()
                };
                Reply::new(status, None).with_clear(clears)
            }
        }
    }
}
