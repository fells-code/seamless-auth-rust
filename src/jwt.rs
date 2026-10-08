use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde_json::{Map, Value};

pub(crate) type Claims = Map<String, Value>;

/// Tolerated clock difference between this server and the auth API.
pub(crate) const CLOCK_SKEW_SECS: u64 = 5;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Issues a compact HS256 JWT. The claims gain `iat` and `exp`.
pub(crate) fn sign_hs256(
    claims: Claims,
    secret: &str,
    ttl: Duration,
    kid: Option<&str>,
) -> Result<String, jsonwebtoken::errors::Error> {
    let issued = now();
    let mut body = claims;
    body.insert("iat".into(), issued.into());
    body.insert("exp".into(), (issued + ttl.as_secs()).into());

    let mut header = Header::new(Algorithm::HS256);
    header.kid = kid.map(str::to_string);
    jsonwebtoken::encode(&header, &body, &EncodingKey::from_secret(secret.as_bytes()))
}

/// The claims of a token this adapter signed, when its signature, algorithm and
/// expiry hold.
pub(crate) fn verify_hs256(token: &str, secret: &str) -> Option<Claims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = CLOCK_SKEW_SECS;
    validation.validate_aud = false;
    validation.validate_nbf = true;
    validation.set_required_spec_claims(&["exp"]);
    jsonwebtoken::decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .ok()
    .map(|data| data.claims)
}

/// Reads a token's claims without verifying it. Only for a token whose
/// signature was already verified before it was stored.
pub(crate) fn unverified_claims(token: &str) -> Option<Claims> {
    jsonwebtoken::dangerous::insecure_decode_claims::<Claims>(token).ok()
}

pub(crate) fn str_claim<'a>(claims: &'a Claims, name: &str) -> &'a str {
    claims.get(name).and_then(Value::as_str).unwrap_or("")
}
