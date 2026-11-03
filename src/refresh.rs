use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http::header::RETRY_AFTER;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use serde_json::Value;
use tokio::sync::watch;

use crate::adapter::{Forwarded, Inner, Reply, UpstreamCall, bearer_token, failure, read_json};
use crate::cookies::{CookieWrite, KIND_REFRESH, raw_cookie, read_cookie, session_cookies};
use crate::jwt::{Claims, str_claim};
use crate::routes::{carries_session, cookie_transport_body};

const FLIGHT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a completed cookie-transport rotation is handed to later callers.
const COOKIE_WINDOW: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub(crate) enum RefreshOutcome {
    Session(Claims),
    Rejected {
        status: StatusCode,
        body: Option<Value>,
        is_json: bool,
        retry_after: Option<HeaderValue>,
    },
    Failed(String),
}

struct Flight {
    id: u64,
    rx: watch::Receiver<Option<RefreshOutcome>>,
}

struct Completed {
    at: Instant,
    outcome: RefreshOutcome,
}

#[derive(Default)]
struct Flights {
    running: HashMap<String, Flight>,
    completed: HashMap<String, Completed>,
}

impl Flights {
    fn prune(&mut self) {
        self.completed.retain(|_, c| c.at.elapsed() < COOKIE_WINDOW);
    }
}

#[derive(Default)]
pub(crate) struct Refresher {
    flights: Mutex<Flights>,
    next_id: Mutex<u64>,
}

impl Refresher {
    /// Runs `rotation` once per key at a time, and hands its outcome to every
    /// caller that presents the same key while it is in flight, so parallel
    /// requests from several tabs with one expired session all succeed instead of
    /// tripping the auth API's reuse detection.
    ///
    /// With `keep` (cookie transport), a successful rotation is also handed to
    /// callers that present the key within five seconds of it settling, for tabs
    /// that sent the old refresh cookie just after another tab rotated it.
    /// Otherwise nothing is kept once it settles: a later caller is sent to the
    /// auth API, which sees a replayed token as reuse.
    ///
    /// The rotation runs on its own task: a caller that goes away mid-flight must
    /// not drop a rotation the auth API has already made, or every other tab would
    /// replay a spent refresh token.
    pub async fn share<Fut>(
        self: &Arc<Self>,
        key: String,
        keep: bool,
        rotation: impl FnOnce() -> Fut,
    ) -> RefreshOutcome
    where
        Fut: Future<Output = RefreshOutcome> + Send + 'static,
    {
        let mut rx = {
            let mut flights = self.lock();
            if keep {
                flights.prune();
                if let Some(done) = flights.completed.get(&key) {
                    return done.outcome.clone();
                }
            }
            match flights.running.get(&key) {
                Some(flight) => flight.rx.clone(),
                None => {
                    let id = {
                        let mut next = self.next_id.lock().unwrap_or_else(|e| e.into_inner());
                        *next += 1;
                        *next
                    };
                    let (tx, rx) = watch::channel(None);
                    flights
                        .running
                        .insert(key.clone(), Flight { id, rx: rx.clone() });

                    let this = self.clone();
                    let rotation = rotation();
                    let flight_key = key.clone();
                    tokio::spawn(async move {
                        // Bounded whatever client the adopter supplied: a flight that
                        // never settles would hang every caller holding this token.
                        let outcome = tokio::time::timeout(FLIGHT_TIMEOUT, rotation)
                            .await
                            .unwrap_or_else(|_| RefreshOutcome::Failed("refresh timed out".into()));
                        this.settle(&flight_key, id, keep, &outcome);
                        let _ = tx.send(Some(outcome));
                    });
                    rx
                }
            }
        };

        let settled = rx.wait_for(Option::is_some).await.map(|o| o.clone());
        match settled {
            Ok(outcome) => outcome.unwrap_or_else(|| RefreshOutcome::Failed("refresh lost".into())),
            // The rotation task ended without an answer (it panicked).
            Err(_) => {
                let mut flights = self.lock();
                if flights
                    .running
                    .get(&key)
                    .is_some_and(|f| f.rx.same_channel(&rx))
                {
                    flights.running.remove(&key);
                }
                RefreshOutcome::Failed("refresh task ended".into())
            }
        }
    }

    /// Ends a flight. A kept outcome is stored under the same lock, so no caller
    /// can find the key neither running nor completed and replay it.
    fn settle(&self, key: &str, id: u64, keep: bool, outcome: &RefreshOutcome) {
        let mut flights = self.lock();
        if flights.running.get(key).is_some_and(|f| f.id == id) {
            flights.running.remove(key);
        }
        flights.prune();
        if keep && matches!(outcome, RefreshOutcome::Session(_)) {
            flights.completed.insert(
                key.to_string(),
                Completed {
                    at: Instant::now(),
                    outcome: outcome.clone(),
                },
            );
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Flights> {
        self.flights.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Makes every completed rotation look older than the window.
    #[cfg(test)]
    pub(crate) fn backdate_completed(&self) {
        let at = Instant::now().checked_sub(COOKIE_WINDOW + Duration::from_secs(1));
        for done in self.lock().completed.values_mut() {
            if let Some(at) = at {
                done.at = at;
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn completed_len(&self) -> usize {
        self.lock().completed.len()
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
        self.refresh_session(
            format!("cookie:{raw}"),
            true,
            refresh_token,
            subject,
            forwarded,
        )
        .await
    }

    /// Rotates a refresh token, shared under `key` (and kept for the cookie
    /// window with `keep`), and returns the verified session with its cookies.
    pub(crate) async fn refresh_session(
        self: &Arc<Self>,
        key: String,
        keep: bool,
        refresh_token: &str,
        subject: &str,
        forwarded: &Forwarded,
    ) -> Result<(Claims, Vec<CookieWrite>), SilentRefreshError> {
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
            .share(key, keep, move || async move {
                // Verified before it settles, so a session the adapter would refuse
                // is never kept.
                match inner.rotate(&forwarded, &refresh_token, service).await {
                    RefreshOutcome::Session(session) => {
                        match inner.verify_session(&session, "access").await {
                            Ok(_) => RefreshOutcome::Session(session),
                            Err(err) => RefreshOutcome::Failed(err),
                        }
                    }
                    other => other,
                }
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
        let retry_after = res.headers().get(RETRY_AFTER).cloned();
        let (body, is_json) = read_json(res).await;
        if status != StatusCode::OK {
            return RefreshOutcome::Rejected {
                status,
                body,
                is_json,
                retry_after,
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
                .share(format!("bearer:{token}"), false, move || async move {
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
                    retry_after,
                } => failure(status, body, is_json).with_retry_after(retry_after),
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

    /// Clears every held cookie whatever the outcome, so a browser is never left
    /// holding a session it asked to end. Answers 204 when the auth API ends the
    /// session, the API's own status when it refuses, 401 when the request
    /// carries no readable session, and 502 when the API cannot be reached.
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
            self.config.pre_auth_cookie_name.clone(),
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
            Ok(res) if res.status().is_success() => {
                Reply::new(StatusCode::NO_CONTENT, None).with_clear(clears)
            }
            Ok(res) => Reply::new(res.status(), None)
                .with_clear(clears)
                .with_retry_after(res.headers().get(RETRY_AFTER).cloned()),
        }
    }
}
