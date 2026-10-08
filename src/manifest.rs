use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::sync::Mutex;

/// Where the auth API publishes which token each route takes and which tokens
/// its response issues or clears.
pub const MANIFEST_PATH: &str = "/.well-known/seamless-adapter.json";

const BUNDLED_MANIFEST: &str = include_str!("../manifest.json");
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const RETRY_AFTER: Duration = Duration::from_secs(60);
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;

/// The auth API's adapter manifest (`schemaVersion` 1).
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Manifest {
    pub schema_version: u32,
    #[serde(default)]
    pub api_version: String,
    pub routes: Vec<ManifestRoute>,
}

/// One route an adapter serves.
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct ManifestRoute {
    pub method: String,
    pub path: String,
    /// The held token the route takes: `none`, `preAuth`, `registration`,
    /// `access` or `refresh`.
    pub credential: String,
    /// The tokens its response issues: `preAuth`, `registration`, `session` or
    /// `access`.
    #[serde(default)]
    pub issues: Option<String>,
    /// The held tokens its response ends.
    #[serde(default)]
    pub clears: Vec<String>,
    /// The only fields a browser sees, when set.
    #[serde(default)]
    pub body: Option<PickBody>,
    /// Whether the route sends an OTP code or magic link.
    #[serde(default)]
    pub delivery: bool,
}

/// The fields of a response body a browser may see.
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct PickBody {
    pub pick: Vec<String>,
}

/// Why a manifest was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestError(String);

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ManifestError {}

const KNOWN_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE"];
const KNOWN_CREDENTIALS: &[&str] = &["none", "preAuth", "registration", "access", "refresh"];
const KNOWN_ISSUES: &[&str] = &["preAuth", "registration", "session", "access"];
const KNOWN_HELD: &[&str] = &["preAuth", "registration", "access", "refresh"];

impl Manifest {
    /// Accepts a manifest only if every route is one this crate knows how to
    /// follow. A route with a credential or effect it does not understand could
    /// be proxied with the wrong token, so such a manifest is refused whole.
    pub fn parse(data: &[u8]) -> Result<Manifest, ManifestError> {
        let mut manifest: Manifest =
            serde_json::from_slice(data).map_err(|e| ManifestError(e.to_string()))?;
        if manifest.schema_version != 1 {
            return Err(ManifestError(format!(
                "unsupported manifest schemaVersion {}",
                manifest.schema_version
            )));
        }
        for route in &mut manifest.routes {
            if route.issues.as_deref() == Some("") {
                route.issues = None;
            }
            let known = KNOWN_METHODS.contains(&route.method.as_str())
                && route.path.starts_with('/')
                && KNOWN_CREDENTIALS.contains(&route.credential.as_str())
                && route
                    .issues
                    .as_deref()
                    .is_none_or(|i| KNOWN_ISSUES.contains(&i))
                && route
                    .clears
                    .iter()
                    .all(|held| KNOWN_HELD.contains(&held.as_str()));
            if !known {
                return Err(ManifestError(format!(
                    "unsupported manifest route {} {}",
                    route.method, route.path
                )));
            }
        }
        Ok(manifest)
    }

    /// The manifest this version of the crate was built against.
    pub fn bundled() -> Arc<Manifest> {
        static BUNDLED: OnceLock<Arc<Manifest>> = OnceLock::new();
        BUNDLED
            .get_or_init(|| {
                Arc::new(
                    Manifest::parse(BUNDLED_MANIFEST.as_bytes()).unwrap_or_else(|e| {
                        panic!("seamless-auth: bundled manifest is invalid: {e}")
                    }),
                )
            })
            .clone()
    }

    /// Finds the route for a request. Static segments compare
    /// case-insensitively, and a static segment beats a parameter at the same
    /// position, so `/admin/users/import` is never read as `/admin/users/{userId}`.
    pub(crate) fn find(&self, method: &str, path: &str) -> Option<RouteMatch<'_>> {
        let requested = segments(path);
        let mut best: Option<(RouteMatch<'_>, usize)> = None;

        for route in &self.routes {
            if !route.method.eq_ignore_ascii_case(method) {
                continue;
            }
            let pattern = segments(&route.path);
            if pattern.len() != requested.len() {
                continue;
            }

            let mut params = HashMap::new();
            let mut score = 0;
            let mut matched = true;

            for (part, value) in pattern.iter().zip(&requested) {
                if let Some(name) = param_name(part) {
                    match percent_decode(value) {
                        // Re-encoded, a dot segment survives as a literal ".." that
                        // the HTTP client resolves, sending the held token to another
                        // upstream path.
                        Some(decoded) if decoded != "." && decoded != ".." => {
                            params.insert(name.to_string(), decoded);
                        }
                        _ => {
                            matched = false;
                            break;
                        }
                    }
                    continue;
                }
                if !part.eq_ignore_ascii_case(value) {
                    matched = false;
                    break;
                }
                score += 1;
            }

            if matched && best.as_ref().is_none_or(|(_, s)| score > *s) {
                best = Some((RouteMatch { route, params }, score));
            }
        }

        best.map(|(m, _)| m)
    }
}

pub(crate) struct RouteMatch<'a> {
    pub route: &'a ManifestRoute,
    pub params: HashMap<String, String>,
}

impl ManifestRoute {
    /// The upstream path, with each `{param}` segment filled and escaped.
    pub(crate) fn upstream_path(&self, params: &HashMap<String, String>) -> String {
        self.path
            .split('/')
            .map(|part| match param_name(part) {
                Some(name) => percent_encode(params.get(name).map(String::as_str).unwrap_or("")),
                None => part.to_string(),
            })
            .collect::<Vec<_>>()
            .join("/")
    }
}

fn param_name(part: &str) -> Option<&str> {
    part.strip_prefix('{').and_then(|p| p.strip_suffix('}'))
}

fn segments(path: &str) -> Vec<&str> {
    path.split('/').filter(|s| !s.is_empty()).collect()
}

/// Decodes a path segment. Refuses a malformed escape or a result that is not
/// UTF-8, as Go's `url.PathUnescape` does.
pub(crate) fn percent_decode(segment: &str) -> Option<String> {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            // from_str_radix alone would take "+1".
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            out.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Escapes a value for one path segment, leaving alone exactly what Go's
/// `url.PathEscape` does.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~$&+:=@".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Fetches the live manifest once and keeps it, falling back to the bundled
/// copy. A failed fetch is retried a minute later, not on every request.
pub(crate) struct ManifestSource {
    url: String,
    client: reqwest::Client,
    fetch: bool,
    state: Mutex<SourceState>,
}

#[derive(Default)]
struct SourceState {
    loaded: Option<Arc<Manifest>>,
    retry_at: Option<Instant>,
}

impl ManifestSource {
    pub fn new(auth_server_url: &str, client: reqwest::Client, fetch: bool) -> Self {
        ManifestSource {
            url: format!("{auth_server_url}{MANIFEST_PATH}"),
            client,
            fetch,
            state: Mutex::new(SourceState::default()),
        }
    }

    pub async fn get(&self) -> Arc<Manifest> {
        if !self.fetch {
            return Manifest::bundled();
        }

        let mut state = self.state.lock().await;
        if let Some(loaded) = &state.loaded {
            return loaded.clone();
        }
        if state.retry_at.is_some_and(|at| Instant::now() < at) {
            return Manifest::bundled();
        }

        match self.load().await {
            Ok(manifest) => {
                let manifest = Arc::new(manifest);
                state.loaded = Some(manifest.clone());
                manifest
            }
            Err(err) => {
                tracing::warn!(
                    "[seamless-auth] Could not load the adapter manifest ({err}). Using the bundled copy."
                );
                state.retry_at = Some(Instant::now() + RETRY_AFTER);
                Manifest::bundled()
            }
        }
    }

    async fn load(&self) -> Result<Manifest, String> {
        let res = self
            .client
            .get(&self.url)
            .header("accept", "application/json")
            .timeout(FETCH_TIMEOUT)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if res.status() != reqwest::StatusCode::OK {
            return Err(format!("HTTP {}", res.status().as_u16()));
        }
        let body = crate::adapter::read_limited(res, MAX_MANIFEST_BYTES).await?;
        Manifest::parse(&body).map_err(|e| e.to_string())
    }
}
