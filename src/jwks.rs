use std::collections::HashMap;
use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use tokio::sync::Mutex;

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
    state: Mutex<KeySet>,
}

#[derive(Default)]
struct KeySet {
    keys: Option<HashMap<String, DecodingKey>>,
    /// When `keys` was last fetched.
    fetched_at: Option<Instant>,
    /// When a fetch was last tried, whether it worked or not.
    attempted_at: Option<Instant>,
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
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

impl JwksCache {
    pub fn new(auth_server_url: &str, client: reqwest::Client) -> Self {
        JwksCache {
            url: format!("{auth_server_url}/.well-known/jwks.json"),
            client,
            state: Mutex::new(KeySet::default()),
        }
    }

    async fn key(&self, kid: &str) -> Result<DecodingKey, String> {
        let mut state = self.state.lock().await;

        let fresh = state.fetched_at.is_some_and(|at| at.elapsed() < MAX_AGE);
        let known = state.keys.as_ref().and_then(|keys| keys.get(kid)).cloned();
        if let (true, Some(key)) = (fresh, &known) {
            return Ok(key.clone());
        }

        let backoff = if state.keys.is_some() {
            REFETCH_INTERVAL
        } else {
            FAILED_FETCH_BACKOFF
        };
        if state.attempted_at.is_none_or(|at| at.elapsed() >= backoff) {
            state.attempted_at = Some(Instant::now());
            match self.fetch().await {
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
        }

        state
            .keys
            .as_ref()
            .and_then(|keys| keys.get(kid))
            .cloned()
            .ok_or_else(|| format!("unknown key id {kid:?}"))
    }

    async fn fetch(&self) -> Result<HashMap<String, DecodingKey>, String> {
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
            if let Ok(key) = DecodingKey::from_rsa_components(&jwk.n, &jwk.e) {
                keys.insert(jwk.kid, key);
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

        jsonwebtoken::decode::<Claims>(token, &key, &validation)
            .map(|data| data.claims)
            .map_err(|e| e.to_string())
    }
}
