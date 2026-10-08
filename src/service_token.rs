use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::jwt::{Claims, sign_hs256};

// The auth API validates service tokens against a fixed issuer and audience,
// whatever the adopter's own audience is.
const ISSUER: &str = "seamless-portal-api";
const AUDIENCE: &str = "seamless-auth";
const TTL: Duration = Duration::from_secs(60);
pub(crate) const PROXY_SUBJECT: &str = "seamless-auth-rust-adapter";
pub(crate) const DELIVERY_SUBJECT: &str = "seamless-auth-external-delivery";
// Reused for a little less than its lifetime, so a request never signs a fresh
// token and never presents one that expires in flight.
const PROXY_REUSE: Duration = Duration::from_secs(45);

pub(crate) struct ServiceTokens {
    secret: String,
    kid: String,
    proxy: Mutex<Option<(String, Instant)>>,
}

impl ServiceTokens {
    pub fn new(secret: String, kid: String) -> Self {
        ServiceTokens {
            secret,
            kid,
            proxy: Mutex::new(None),
        }
    }

    /// A `Bearer` service token for `subject`, carrying `extra` claims.
    pub fn sign(&self, subject: &str, extra: Claims) -> Option<String> {
        let mut claims = extra;
        claims.insert("iss".into(), Value::from(ISSUER));
        claims.insert("aud".into(), Value::from(AUDIENCE));
        claims.insert("sub".into(), Value::from(subject));
        sign_hs256(claims, &self.secret, TTL, Some(&self.kid))
            .ok()
            .map(|token| format!("Bearer {token}"))
    }

    /// Lets the auth API trust the client address and user agent this adapter
    /// forwards.
    pub fn proxy_authorization(&self) -> Option<String> {
        let mut cached = self.proxy.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((token, until)) = cached.as_ref()
            && Instant::now() < *until
        {
            return Some(token.clone());
        }
        let token = self.sign(PROXY_SUBJECT, Claims::new())?;
        *cached = Some((token.clone(), Instant::now() + PROXY_REUSE));
        Some(token)
    }

    /// Asks the auth API to return a message instead of sending it.
    pub fn delivery_authorization(&self) -> Option<String> {
        self.sign(DELIVERY_SUBJECT, Claims::new())
    }
}
