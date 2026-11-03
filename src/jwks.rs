use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;

use crate::jwt::{CLOCK_SKEW_SECS, Claims};

/// A kid the cached key set does not know triggers at most one refetch per this
/// interval, so a stream of forged kids cannot turn into a stream of fetches.
const REFETCH_INTERVAL: Duration = Duration::from_secs(30);
/// A key set older than this is fetched again, so a key the API retires stops
/// verifying.
const MAX_AGE: Duration = Duration::from_secs(10 * 60);
/// With no key set at all, how long a failed fetch holds off the next.
const FAILED_FETCH_BACKOFF: Duration = Duration::from_secs(5);
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_JWKS_BYTES: usize = 256 * 1024;

pub(crate) struct JwksCache {
    url: String,
    client: reqwest::Client,
    /// Held only to read or update the key set, never across a fetch.
    state: Mutex<KeySet>,
    /// Held across a fetch, so only one runs at a time.
    fetching: tokio::sync::Mutex<()>,
}

#[derive(Default)]
struct KeySet {
    keys: Option<HashMap<String, Key>>,
    /// When `keys` was last fetched.
    fetched_at: Option<Instant>,
    /// When a fetch was last tried, whether it worked or not.
    attempted_at: Option<Instant>,
}

/// A published RSA key, with the `use` and `alg` it was published under.
#[derive(Clone)]
pub(crate) struct Key {
    pub decoding: DecodingKey,
    pub usage: Option<Value>,
    pub alg: Option<Value>,
}

#[derive(Deserialize)]
struct Jwk {
    #[serde(default)]
    kty: String,
    #[serde(default)]
    kid: String,
    #[serde(default)]
    n: String,
    #[serde(default)]
    e: String,
    #[serde(default, rename = "use")]
    usage: Option<Value>,
    #[serde(default)]
    alg: Option<Value>,
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

/// What the key set holds for a kid.
enum Lookup {
    Fresh(Key),
    /// A key from a set past its maximum age, or none, and whether a fetch is
    /// due.
    Cached {
        key: Option<Key>,
        due: bool,
    },
}

impl JwksCache {
    pub fn new(auth_server_url: &str, client: reqwest::Client) -> Self {
        Self::at(format!("{auth_server_url}/.well-known/jwks.json"), client)
    }

    pub fn at(url: String, client: reqwest::Client) -> Self {
        JwksCache {
            url,
            client,
            state: Mutex::new(KeySet::default()),
            fetching: tokio::sync::Mutex::new(()),
        }
    }

    pub async fn key(&self, kid: &str) -> Result<Key, String> {
        let cached = match self.lookup(kid) {
            Lookup::Fresh(key)
            | Lookup::Cached {
                key: Some(key),
                due: false,
            } => return Ok(key),
            Lookup::Cached { key, .. } => key,
        };
        // A kid already cached is served while another caller fetches, so a slow
        // JWKS endpoint never holds up tokens it would verify anyway. An unknown
        // kid waits for the fetch in flight, which may bring it.
        let _fetching = match cached {
            Some(key) => match self.fetching.try_lock() {
                Ok(guard) => guard,
                Err(_) => return Ok(key),
            },
            None => self.fetching.lock().await,
        };
        match self.lookup(kid) {
            Lookup::Fresh(key) => return Ok(key),
            Lookup::Cached { key, due: false } => {
                return key.ok_or_else(|| format!("unknown key id {kid:?}"));
            }
            Lookup::Cached { due: true, .. } => {}
        }

        self.lock_state().attempted_at = Some(Instant::now());
        let fetched = self.fetch().await;
        let mut state = self.lock_state();
        match fetched {
            Ok(keys) => {
                state.keys = Some(keys);
                state.fetched_at = Some(Instant::now());
            }
            // A stale key set keeps verifying while the API cannot be reached,
            // rather than signing every user out.
            Err(err) if state.keys.is_some() => {
                tracing::warn!("[seamless-auth] Could not refresh the JWKS ({err}).");
            }
            Err(err) => return Err(err),
        }
        known(&state, kid)
    }

    fn lookup(&self, kid: &str) -> Lookup {
        let state = self.lock_state();
        let fresh = state.fetched_at.is_some_and(|at| at.elapsed() < MAX_AGE);
        let key = state.keys.as_ref().and_then(|keys| keys.get(kid)).cloned();
        if let (true, Some(key)) = (fresh, &key) {
            return Lookup::Fresh(key.clone());
        }

        let backoff = if state.keys.is_some() {
            REFETCH_INTERVAL
        } else {
            FAILED_FETCH_BACKOFF
        };
        let due = state.attempted_at.is_none_or(|at| at.elapsed() >= backoff);
        Lookup::Cached { key, due }
    }

    fn lock_state(&self) -> MutexGuard<'_, KeySet> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Makes the last fetch attempt look older than the refetch interval, so the
    /// next unknown kid fetches again.
    #[cfg(test)]
    pub(crate) async fn backdate_attempt(&self) {
        self.lock_state().attempted_at =
            Instant::now().checked_sub(REFETCH_INTERVAL + Duration::from_secs(1));
    }

    async fn fetch(&self) -> Result<HashMap<String, Key>, String> {
        let res = self
            .client
            .get(&self.url)
            .timeout(FETCH_TIMEOUT)
            .send()
            .await
            .map_err(|e| format!("jwks: {e}"))?;
        if res.status() != reqwest::StatusCode::OK {
            return Err(format!("jwks: HTTP {}", res.status().as_u16()));
        }
        let body = crate::adapter::read_limited(res, MAX_JWKS_BYTES)
            .await
            .map_err(|e| format!("jwks: {e}"))?;
        let set: JwkSet = serde_json::from_slice(&body).map_err(|e| format!("jwks: {e}"))?;

        let mut keys = HashMap::with_capacity(set.keys.len());
        for jwk in set.keys {
            if jwk.kty != "RSA" {
                continue;
            }
            if let Ok(decoding) = DecodingKey::from_rsa_components(&jwk.n, &jwk.e) {
                keys.insert(
                    jwk.kid,
                    Key {
                        decoding,
                        usage: jwk.usage,
                        alg: jwk.alg,
                    },
                );
            }
        }
        Ok(keys)
    }

    /// Checks a token the auth API signed: RS256 under a key it publishes, issued
    /// by `issuer` for `audience`, and in date.
    pub async fn verify(
        &self,
        token: &str,
        issuer: &str,
        audience: &str,
    ) -> Result<Claims, String> {
        // An empty expectation must never stand for "any issuer" or "any audience".
        if issuer.is_empty() || audience.is_empty() {
            return Err("no expected issuer or audience".into());
        }
        let header = jsonwebtoken::decode_header(token).map_err(|e| e.to_string())?;
        if header.alg != Algorithm::RS256 {
            return Err("unexpected algorithm".into());
        }
        let key = self.key(header.kid.as_deref().unwrap_or("")).await?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.leeway = CLOCK_SKEW_SECS;
        validation.validate_nbf = true;
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);

        jsonwebtoken::decode::<Claims>(token, &key.decoding, &validation)
            .map(|data| data.claims)
            .map_err(|e| e.to_string())
    }
}

fn known(state: &KeySet, kid: &str) -> Result<Key, String> {
    state
        .keys
        .as_ref()
        .and_then(|keys| keys.get(kid))
        .cloned()
        .ok_or_else(|| format!("unknown key id {kid:?}"))
}
