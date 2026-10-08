# seamless-auth-rust

A [Seamless Auth](https://github.com/fells-code/seamless-auth-api) server adapter for Rust and
[Axum](https://github.com/tokio-rs/axum).

The adapter sits in your backend between your users and the Seamless Auth API:

- **Browsers** talk to it over `HttpOnly` cookies on your own domain. The API's tokens never
  reach page scripts.
- **Native clients** (mobile, CLIs) talk to it over bearer tokens, sending
  `x-seamless-auth-transport: bearer`.
- **The auth API** sees bearer tokens plus a service token that lets it trust the client
  address and user agent the adapter forwards.

Which routes the adapter serves, and what each does to the session, comes from the adapter
manifest the auth API publishes, so a new API route works without a new release of this crate.

It is held to the same [conformance suite](https://github.com/fells-code/seamless-cli/blob/main/verify/CONFORMANCE.md)
as the Express, Fastify and Go adapters, in CI on every change.

## Install

```bash
cargo add seamless-auth
```

Rust 1.88 or later, Axum 0.8.

## Use

```rust
use std::net::SocketAddr;

use axum::{Json, Router, routing::get};
use seamless_auth::{Adapter, User};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth = Adapter::builder(std::env::var("AUTH_SERVER_URL")?)
        .cookie_secret(std::env::var("COOKIE_SECRET")?) // at least 32 bytes
        .service_secret(std::env::var("SERVICE_SECRET")?) // the API's API_SERVICE_TOKEN
        .jwks_kid(std::env::var("JWKS_KID")?)
        .build()?;

    let app = Router::new()
        // Your own routes, behind the adapter's guard.
        .route(
            "/api/me",
            get(|user: User| async move { Json(json!({ "id": user.id })) })
                .route_layer(auth.require_auth()),
        )
        // The auth routes, at /auth, which is where the client SDKs call.
        .nest("/auth", auth.router());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    // Connect info gives the adapter the peer address to forward.
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}
```

Serve with `into_make_service_with_connect_info::<SocketAddr>()`. Without it the adapter has no
peer address and forwards no client address to the auth API.

### The guard

`require_auth()` is a tower layer. It answers 401 `{"error":"unauthenticated"}` unless the
request carries a session, and puts a `User` in the request extensions, which handlers take as an
extractor. It accepts the adapter's session cookie, or an auth API access token in
`Authorization: Bearer` for clients with no cookie jar. The cookie wins when both are present. It
reads the `Cookie` header itself, so it works on any route. It does not refresh: the auth routes
refresh a browser session silently, and a bearer client calls `POST /auth/refresh` itself.
`Adapter::authenticate(&HeaderMap)` does the same check without answering.

A request the guard admits on the session cookie also gets the auth routes' cross-site check: while
cookies are `SameSite=None`, a state-changing request from another site (`Sec-Fetch-Site:
cross-site`, or an `Origin` outside `allowed_origins`) answers 403 `cross_site_request_blocked`.
A bearer token is never attached by a browser, so it is not checked.

### Request bodies

The auth routes forward a request body to the auth API as JSON, so a body must be sent as
`application/json` (or a `+json` type). Anything else answers 415 `unsupported_media_type`: a
cross-site form can post a `text/plain` body shaped like JSON with no CORS preflight, and read as
JSON it would be a sign-in the user never made. The client SDKs already send JSON.

## Options

| Builder method | Default | Purpose |
| --- | --- | --- |
| `Adapter::builder(url)` | required | Where the adapter reaches the auth API |
| `auth_server_issuer` | the URL | Expected `iss` of the API's tokens, when it differs from the URL you reach it at |
| `audience` | the issuer | Expected `aud` of the API's tokens |
| `cookie_secret` | required | Signs the session cookies (32 bytes or more) |
| `service_secret` | required | The API's `API_SERVICE_TOKEN` (32 bytes or more) |
| `jwks_kid` | `dev-main` | `kid` header on service tokens |
| `cookie_domain` | none | Cookie `Domain` |
| `insecure_cookies` | `false` | Drops `Secure`, for local development over HTTP |
| `same_site` | `None`, or `Lax` with `insecure_cookies` | Cookie `SameSite` |
| `allowed_origins` | none | The only cross-origin callers allowed to change state while cookies are `SameSite=None` |
| `session_cookie_names` | `seamless-access`, `seamless-refresh` | Session cookie names |
| `flow_cookie_names` | `seamless-ephemeral` | Sign-in flow cookie names |
| `deliver` | none | Sends OTP codes and magic links through your own transports |
| `trusted_proxies`, `resolve_client_ip` | the connecting peer | The end user's address. See below |
| `disable_manifest_fetch` | `false` | Use only the manifest bundled with this version |
| `http_client` | 15 second timeout, no redirects | Outbound `reqwest::Client` |

### Client IP

The adapter forwards the end user's address and user agent so the auth API rate limits and
audits against the user, not your server. Behind a proxy, name it:

```rust
use seamless_auth::TrustedProxies;

let auth = Adapter::builder(url)
    // ...
    .trusted_proxies(TrustedProxies::new(["10.0.0.0/8"])?)
    .build()?;
```

`TrustedProxies` walks `X-Forwarded-For` from the right, skipping trusted proxies. There is
deliberately no hop-count option: a hop count cannot tell a proxy from a client that sent its
own header.

### Delivery

Without `deliver`, the auth API sends OTP codes and magic links itself. With it, the adapter
asks the API for the message and hands it to you:

```rust
.deliver(move |d: seamless_auth::Delivery| {
    let mailer = mailer.clone();
    async move { mailer.send(&d.to, &d.kind, d.token.as_deref(), d.magic_link_url.as_deref()).await }
})
```

A delivery error answers the request with 502 `delivery_failed`.

## Features

| Feature | Default | Purpose |
| --- | --- | --- |
| `rustls` | yes | TLS to the auth API with rustls |
| `native-tls` | no | TLS to the auth API with the platform's TLS library |

With neither, the adapter reaches the auth API over plain HTTP only.

## The manifest

On its first request the adapter fetches `/.well-known/seamless-adapter.json` from the auth API
(5 second timeout) and keeps it for the life of the process. If the API serves none, it uses the
copy embedded in this crate and tries again a minute later. A manifest with anything this version
does not understand is refused whole, rather than following a route with the wrong token. Refresh
the embedded copy with `scripts/sync-manifest.sh`.

## Conformance

`conformance/refapp` is the reference app the conformance suite drives. To run it locally you need
Docker, a checkout of `seamless-auth-api` and the `seamless` CLI:

```bash
PORT=8080 AUTH_SERVER_URL=http://localhost:5312 AUTH_SERVER_ISSUER=http://auth-api:5312 \
  API_SERVICE_TOKEN=verify-dev-service-token-not-a-real-secret \
  COOKIE_SIGNING_KEY=verify-dev-service-token-not-a-real-secret JWKS_KID=dev-main \
  cargo run --example refapp &

SEAMLESS_API_DIR=../seamless-auth-api seamless verify --adapter-url=http://localhost:8080
```

## Status

Pre-1.0. The public API may change between minor versions until 1.0.

## License

Apache-2.0
