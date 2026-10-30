use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::http::HeaderMap;

use crate::adapter::Adapter;
use crate::client_ip::TrustedProxies;
use crate::delivery::{Delivery, DeliveryError, DeliveryFuture};

const MIN_SECRET_LENGTH: usize = 32;

// Example values from the starters and the portal, long enough to pass the
// length check, so a deployment that never replaced them would otherwise boot.
const PLACEHOLDER_SECRETS: &[&str] = &[
    "dev-only-cookie-signing-key-replace-me",
    "GRAB_FROM_SEAMLESS_AUTH_PORTAL_DEV",
];

fn is_placeholder(secret: &str) -> bool {
    let secret = secret.trim();
    PLACEHOLDER_SECRETS.contains(&secret) || secret.to_ascii_lowercase().contains("replace-me")
}

/// The `SameSite` attribute of the adapter's cookies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl SameSite {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
            SameSite::None => "None",
        }
    }
}

pub(crate) type DeliverFn = Arc<dyn Fn(Delivery) -> DeliveryFuture + Send + Sync>;
pub(crate) type ClientIpFn =
    Arc<dyn Fn(&HeaderMap, Option<IpAddr>) -> Option<IpAddr> + Send + Sync>;

/// Why [`Builder::build`] refused its configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BuildError {
    /// The auth server URL is empty or not an http(s) URL.
    InvalidAuthServerUrl,
    /// The cookie secret is shorter than 32 bytes.
    WeakCookieSecret,
    /// The service secret is shorter than 32 bytes.
    WeakServiceSecret,
    /// The cookie secret is a known example value. Allowed only with
    /// [`Builder::insecure_cookies`].
    PlaceholderCookieSecret,
    /// The service secret is a known example value. Allowed only with
    /// [`Builder::insecure_cookies`].
    PlaceholderServiceSecret,
    /// A cookie name or domain holds characters a `Set-Cookie` header cannot carry.
    InvalidCookieAttribute(String),
    /// The HTTP client could not be built.
    HttpClient(String),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::InvalidAuthServerUrl => {
                f.write_str("seamless-auth: the auth server URL must be an http or https URL")
            }
            BuildError::WeakCookieSecret => write!(
                f,
                "seamless-auth: the cookie secret must be at least {MIN_SECRET_LENGTH} bytes"
            ),
            BuildError::WeakServiceSecret => write!(
                f,
                "seamless-auth: the service secret must be at least {MIN_SECRET_LENGTH} bytes"
            ),
            BuildError::PlaceholderCookieSecret => f.write_str(
                "seamless-auth: the cookie secret is an example value; replace it with a random secret",
            ),
            BuildError::PlaceholderServiceSecret => f.write_str(
                "seamless-auth: the service secret is an example value; replace it with the API's API_SERVICE_TOKEN",
            ),
            BuildError::InvalidCookieAttribute(what) => {
                write!(f, "seamless-auth: invalid cookie attribute {what}")
            }
            BuildError::HttpClient(err) => {
                write!(f, "seamless-auth: could not build the HTTP client: {err}")
            }
        }
    }
}

impl std::error::Error for BuildError {}

/// Configures an [`Adapter`]. Start one with [`Adapter::builder`].
pub struct Builder {
    auth_server_url: String,
    auth_server_issuer: Option<String>,
    audience: Option<String>,
    cookie_secret: String,
    service_secret: String,
    jwks_kid: Option<String>,
    cookie_domain: Option<String>,
    insecure_cookies: bool,
    same_site: Option<SameSite>,
    allowed_origins: Vec<String>,
    access_cookie_name: String,
    registration_cookie_name: String,
    refresh_cookie_name: String,
    pre_auth_cookie_name: String,
    deliver: Option<DeliverFn>,
    deliver_account_notices: bool,
    client_ip: Option<ClientIpFn>,
    disable_manifest_fetch: bool,
    http_client: Option<reqwest::Client>,
}

impl fmt::Debug for Builder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Builder")
            .field("auth_server_url", &self.auth_server_url)
            .field("auth_server_issuer", &self.auth_server_issuer)
            .finish_non_exhaustive()
    }
}

impl Builder {
    pub(crate) fn new(auth_server_url: impl Into<String>) -> Self {
        Builder {
            auth_server_url: auth_server_url.into(),
            auth_server_issuer: None,
            audience: None,
            cookie_secret: String::new(),
            service_secret: String::new(),
            jwks_kid: None,
            cookie_domain: None,
            insecure_cookies: false,
            same_site: None,
            allowed_origins: Vec::new(),
            access_cookie_name: "seamless-access".into(),
            registration_cookie_name: "seamless-ephemeral".into(),
            refresh_cookie_name: "seamless-refresh".into(),
            // Shares the registration cookie on purpose: registration and sign-in
            // never hold an ephemeral cookie at the same time.
            pre_auth_cookie_name: "seamless-ephemeral".into(),
            deliver: None,
            deliver_account_notices: false,
            client_ip: None,
            disable_manifest_fetch: false,
            http_client: None,
        }
    }

    /// The expected `iss` of the auth API's tokens. Defaults to the auth server URL.
    /// Set it when this server reaches the API at another URL than the issuer it
    /// advertises.
    pub fn auth_server_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.auth_server_issuer = Some(issuer.into());
        self
    }

    /// The expected `aud` of the auth API's tokens. The auth API sets it to its
    /// issuer, so it defaults to the issuer.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Signs the session cookies. At least 32 bytes. Required.
    pub fn cookie_secret(mut self, secret: impl Into<String>) -> Self {
        self.cookie_secret = secret.into();
        self
    }

    /// Signs the service tokens the auth API trusts this adapter by. It holds the
    /// same value as the API's `API_SERVICE_TOKEN`; apps conventionally read it
    /// from `SEAMLESS_SERVICE_TOKEN`. At least 32 bytes. Required.
    pub fn service_secret(mut self, secret: impl Into<String>) -> Self {
        self.service_secret = secret.into();
        self
    }

    /// The `kid` header on service tokens. Defaults to `dev-main`, a placeholder.
    pub fn jwks_kid(mut self, kid: impl Into<String>) -> Self {
        self.jwks_kid = Some(kid.into());
        self
    }

    /// The cookie `Domain` attribute. None by default.
    pub fn cookie_domain(mut self, domain: impl Into<String>) -> Self {
        self.cookie_domain = Some(domain.into());
        self
    }

    /// Drops the `Secure` attribute, for local development over plain HTTP. It
    /// also lets the cookie and service secrets hold a known example value.
    pub fn insecure_cookies(mut self, insecure: bool) -> Self {
        self.insecure_cookies = insecure;
        self
    }

    /// The cookie `SameSite` attribute. Defaults to `None`, or `Lax` with
    /// [`insecure_cookies`](Self::insecure_cookies).
    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = Some(same_site);
        self
    }

    /// The only cross-origin callers allowed to change state while cookies are
    /// `SameSite=None`. With it set, a `Sec-Fetch-Site: same-site` request (which
    /// includes a sibling subdomain) needs an `Origin` on the list as well.
    pub fn allowed_origins<I, S>(mut self, origins: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_origins = origins.into_iter().map(Into::into).collect();
        self
    }

    /// Session cookie names. Default `seamless-access` and `seamless-refresh`.
    pub fn session_cookie_names(
        mut self,
        access: impl Into<String>,
        refresh: impl Into<String>,
    ) -> Self {
        self.access_cookie_name = access.into();
        self.refresh_cookie_name = refresh.into();
        self
    }

    /// Sign-in flow cookie names. Both default to `seamless-ephemeral`.
    pub fn flow_cookie_names(
        mut self,
        registration: impl Into<String>,
        pre_auth: impl Into<String>,
    ) -> Self {
        self.registration_cookie_name = registration.into();
        self.pre_auth_cookie_name = pre_auth.into();
        self
    }

    /// Sends OTP codes and magic links through the application's own transports.
    /// With it, the adapter asks the auth API for the message instead of having
    /// the API send it. A delivery error answers the request with 502
    /// `delivery_failed`.
    pub fn deliver<F, Fut, E>(mut self, deliver: F) -> Self
    where
        F: Fn(Delivery) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), E>> + Send + 'static,
        E: Into<DeliveryError>,
    {
        self.deliver = Some(Arc::new(move |delivery| {
            let fut = deliver(delivery);
            Box::pin(async move { fut.await.map_err(Into::into) })
        }));
        self
    }

    /// Declares that the [`deliver`](Self::deliver) callback sends the auth API's
    /// account notices (`account_notice_email` and `account_notice_sms`), such as
    /// the one that tells an owner someone opened a recovery of their account.
    /// The auth API counts a notice it hands back as the owner being told, so it
    /// hands them back only to an adapter that says it delivers both kinds.
    /// Without this, the auth API sends those notices itself.
    pub fn deliver_account_notices(mut self, deliver: bool) -> Self {
        self.deliver_account_notices = deliver;
        self
    }

    /// Resolves the end user's address from the request headers and the
    /// connecting peer. Defaults to the peer. Behind a proxy, use
    /// [`trusted_proxies`](Self::trusted_proxies).
    pub fn resolve_client_ip<F>(mut self, resolve: F) -> Self
    where
        F: Fn(&HeaderMap, Option<IpAddr>) -> Option<IpAddr> + Send + Sync + 'static,
    {
        self.client_ip = Some(Arc::new(resolve));
        self
    }

    /// Resolves the end user's address through these proxies.
    pub fn trusted_proxies(self, proxies: TrustedProxies) -> Self {
        self.resolve_client_ip(move |headers, peer| proxies.resolve(headers, peer))
    }

    /// Uses only the manifest bundled with this version instead of fetching the
    /// auth API's on the first request.
    pub fn disable_manifest_fetch(mut self, disable: bool) -> Self {
        self.disable_manifest_fetch = disable;
        self
    }

    /// The client for calls to the auth API. The default has a 15 second timeout
    /// and follows no redirects. A client that follows redirects would carry the
    /// service token to wherever the auth API pointed it.
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    /// Validates the configuration and returns the adapter.
    pub fn build(self) -> Result<Adapter, BuildError> {
        let auth_server_url = self
            .auth_server_url
            .trim()
            .trim_end_matches('/')
            .to_string();
        if !(auth_server_url.starts_with("http://") || auth_server_url.starts_with("https://"))
            || auth_server_url.len() <= "https://".len()
        {
            return Err(BuildError::InvalidAuthServerUrl);
        }
        if self.cookie_secret.len() < MIN_SECRET_LENGTH {
            return Err(BuildError::WeakCookieSecret);
        }
        if self.service_secret.len() < MIN_SECRET_LENGTH {
            return Err(BuildError::WeakServiceSecret);
        }
        for (secret, refused, what) in [
            (
                &self.cookie_secret,
                BuildError::PlaceholderCookieSecret,
                "cookie secret",
            ),
            (
                &self.service_secret,
                BuildError::PlaceholderServiceSecret,
                "service secret",
            ),
        ] {
            if !is_placeholder(secret) {
                continue;
            }
            if !self.insecure_cookies {
                return Err(refused);
            }
            tracing::warn!(
                "[seamless-auth] The {what} is an example value. It is allowed only because insecure_cookies is on."
            );
        }

        for name in [
            &self.access_cookie_name,
            &self.registration_cookie_name,
            &self.refresh_cookie_name,
            &self.pre_auth_cookie_name,
        ] {
            if name.is_empty() || !name.bytes().all(is_token_byte) {
                return Err(BuildError::InvalidCookieAttribute(format!("name {name:?}")));
            }
        }
        if let Some(domain) = &self.cookie_domain
            && (domain.is_empty()
                || !domain
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'))
        {
            return Err(BuildError::InvalidCookieAttribute(format!(
                "domain {domain:?}"
            )));
        }

        let auth_server_issuer = self
            .auth_server_issuer
            .unwrap_or_else(|| auth_server_url.clone());
        let audience = self.audience.unwrap_or_else(|| auth_server_issuer.clone());
        let jwks_kid = self.jwks_kid.filter(|k| !k.is_empty()).unwrap_or_else(|| {
            tracing::warn!(
                "[seamless-auth] jwks_kid is not set and defaults to \"dev-main\", a placeholder. Set it to name the service-token key explicitly."
            );
            "dev-main".to_string()
        });
        let same_site = self.same_site.unwrap_or(if self.insecure_cookies {
            SameSite::Lax
        } else {
            SameSite::None
        });

        let http_client = match self.http_client {
            Some(client) => client,
            None => reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|e| BuildError::HttpClient(e.to_string()))?,
        };

        Ok(Adapter::from_config(Config {
            auth_server_url,
            auth_server_issuer,
            audience,
            cookie_secret: self.cookie_secret,
            service_secret: self.service_secret,
            jwks_kid,
            cookie_domain: self.cookie_domain,
            secure_cookies: !self.insecure_cookies,
            same_site,
            allowed_origins: self.allowed_origins,
            access_cookie_name: self.access_cookie_name,
            registration_cookie_name: self.registration_cookie_name,
            refresh_cookie_name: self.refresh_cookie_name,
            pre_auth_cookie_name: self.pre_auth_cookie_name,
            deliver_account_notices: self.deliver_account_notices && self.deliver.is_some(),
            deliver: self.deliver,
            client_ip: self.client_ip,
            fetch_manifest: !self.disable_manifest_fetch,
            http_client,
        }))
    }
}

/// RFC 7230 token characters, which is what a cookie name may hold.
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

pub(crate) struct Config {
    pub auth_server_url: String,
    pub auth_server_issuer: String,
    pub audience: String,
    pub cookie_secret: String,
    pub service_secret: String,
    pub jwks_kid: String,
    pub cookie_domain: Option<String>,
    pub secure_cookies: bool,
    pub same_site: SameSite,
    pub allowed_origins: Vec<String>,
    pub access_cookie_name: String,
    pub registration_cookie_name: String,
    pub refresh_cookie_name: String,
    pub pre_auth_cookie_name: String,
    pub deliver: Option<DeliverFn>,
    pub deliver_account_notices: bool,
    pub client_ip: Option<ClientIpFn>,
    pub fetch_manifest: bool,
    pub http_client: reqwest::Client,
}

impl Config {
    /// The cookie a held credential lives in.
    pub fn cookie_name(&self, held: &str) -> &str {
        match held {
            "access" => &self.access_cookie_name,
            "registration" => &self.registration_cookie_name,
            "refresh" => &self.refresh_cookie_name,
            _ => &self.pre_auth_cookie_name,
        }
    }
}
