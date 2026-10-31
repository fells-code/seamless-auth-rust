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

A service that only checks OpenID Provider access tokens can use [verify-only mode](#verify-only-mode)
instead, with no cookies, secrets or auth routes.

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
        .service_secret(std::env::var("SEAMLESS_SERVICE_TOKEN")?) // same value as the API's API_SERVICE_TOKEN
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

The auth server reads the service token from `API_SERVICE_TOKEN` and your app reads it from
`SEAMLESS_SERVICE_TOKEN`; both hold the same value.

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

The cookie is signed with the cookie secret, and the auth API access token inside it is verified
again against the API's JWKS, exactly as a bearer token is: RS256, the expected issuer and
audience, in date, of type `access`, and for the cookie's subject. The user's roles and recovery
state come from that verified token, so a cookie forged with a leaked cookie secret carries no
claims of its own. When the JWKS cannot be fetched the session is refused.

A request the guard admits on the session cookie also gets the auth routes' cross-site check. It
applies only while cookies are `SameSite=None`, and only to state-changing methods (not `GET`,
`HEAD` or `OPTIONS`); a refused request answers 403 `cross_site_request_blocked`:

- `Sec-Fetch-Site: cross-site` is refused, and `same-origin` (or `none`) passes.
- `Sec-Fetch-Site: same-site` also covers a sibling subdomain, so when `allowed_origins` is set
  the `Origin` must be on it, and a request with no `Origin` is refused. Without
  `allowed_origins` it passes.
- With no `Sec-Fetch-Site` (an older browser or a server), a request with no `Origin` passes, a
  `null` `Origin` is refused, and when `allowed_origins` is set the `Origin` must be on it.

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
| `cookie_secret` | required | Signs the session cookies (32 bytes or more, and not an example value) |
| `service_secret` | required | The service token, read from `SEAMLESS_SERVICE_TOKEN` in the examples; the same value as the API's `API_SERVICE_TOKEN` (32 bytes or more, and not an example value) |
| `jwks_kid` | `dev-main` | `kid` header on service tokens |
| `cookie_domain` | none | Cookie `Domain` |
| `insecure_cookies` | `false` | Drops `Secure`, for local development over HTTP, and allows example secrets |
| `same_site` | `None`, or `Lax` with `insecure_cookies` | Cookie `SameSite` |
| `allowed_origins` | none | The only cross-origin (including same-site) callers allowed to change state while cookies are `SameSite=None` |
| `session_cookie_names` | `seamless-access`, `seamless-refresh` | Session cookie names |
| `flow_cookie_names` | `seamless-ephemeral` | Sign-in flow cookie names |
| `deliver` | none | Sends OTP codes and magic links through your own transports |
| `deliver_account_notices` | `false` | Your `deliver` also sends account notices (see Delivery) |
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

A delivery error answers the request with 502 `delivery_failed`. A kind this version does not
know is logged and skipped.

An OTP code with `purpose` `account_recovery` (`d.is_account_recovery()`) was sent because someone
is recovering the account: word it as a recovery code rather than a sign-in code, so an owner who
did not ask for it knows something is happening.

#### Account notices

The auth API tells an account's owner when something happens to the account, such as a recovery
being opened. Those notices are `account_notice_email` (`to`, `subject`, `text`, `notice`) and
`account_notice_sms` (`to`, `text`, `notice`), and either may carry `cancel_url`. The API counts a
notice it hands back as the owner being told, so the adapter asks for them only when you say your
`deliver` sends both kinds:

```rust
.deliver(deliver)
.deliver_account_notices(true)
```

Then, on the routes the manifest marks `notices` (today `POST /recovery/verify`), the adapter sends
`x-seamless-auth-delivery-kinds: account_notice_email,account_notice_sms`, hands each notice in the
response to `deliver`, and strips them from what the client sees. Every notice is tried, and one
that reaches the owner is enough. If none does, the API has already opened the recovery, so the
adapter cancels it with the token from the notice's cancel link and answers 503
`recovery_notice_failed`. Without the option the API sends
notices itself. `cancel_url` (and `text`, which can hold it) is a credential: send it only to `to`
and never log it.

### Magic links

The auth API signs a user in from a magic link only on the device that asked for it. On
`GET /magic-link/verify/{token}` the adapter forwards that device's pre-auth token when it has
one: the client's own bearer token in bearer transport, or the pre-auth cookie in cookie
transport if it verifies. Without one it sends none, and never answers 401, because the API
falls back to the client address and user agent the adapter forwards.

Opened anywhere else, the link answers 409 `confirmation_required`, with `requestedFrom`
(`deviceClass`, `requestedAt`) describing the request, and is not consumed. Once the user
approves it, `POST /magic-link/verify/{token}/confirm` consumes it. The requesting attempt's
first `GET /magic-link/check` after that issues the session; later checks answer
`{ "message": "Success" }` with no tokens, and the adapter then leaves the cookies as they are.

### Recovery sessions

Signing in with a recovery code, or completing self-service recovery, issues a recovery session:
its access token carries `recovery: true`, and the auth API lets it do little but enroll a new
passkey or authenticator app. `require_auth()` answers such a session with 403
`{"error":"enrollment_required"}`, so a half-recovered account is not taken for signed in. Let one
through on the screens that guide the user to enroll, and tell it apart by `User::recovery`:

```rust
get(enroll_page).route_layer(auth.require_auth().allow_recovery(true))
```

`authenticate()` accepts a recovery session, so check `user.recovery` yourself when you use it.

When a recovery session finishes passkey registration (`POST /webauthn/register/finish`) or TOTP
enrollment (`POST /totp/enroll/verify`) in cookie transport, the adapter refreshes the session in
the same response, so the access cookie drops the claim. A bearer client holds its own tokens and
should call `POST /auth/refresh` after enrolling.

### The admin console

`console_router()` serves the Seamless admin dashboard from your API, proxied from the auth API, so
it shares the origin and cookie scope of the `/auth` routes. It serves `/console`, the path the
dashboard is built against, so merge it (a router nested at `/console` never sees `/console/`):

```rust
let app = Router::new()
    .nest("/auth", auth.router())
    .merge(auth.console_router());
```

It serves `GET` and `HEAD` only and forwards nothing but the method and path, so the browser's
cookies never reach the upstream. It refuses any path that could leave the console (dot segments,
encoded separators), and follows a redirect only while it stays inside the console on the auth API.
When you serve it, add your API's origin to the auth server's `ORIGINS` so passkey ceremonies
started in the console verify.

## Verify-only mode

A service that only receives access tokens from the Seamless OpenID Provider (RFC 9068 JWTs in
`Authorization: Bearer`) needs no cookies, no service secret and no auth routes. `Verifier` checks
those tokens with only the issuer and this API's resource identifier:

```rust
use axum::{Json, Router, routing::get};
use seamless_auth::{StepUp, TokenUser, Verifier};

let verifier = Verifier::builder("https://login.example.com")
    .audience("https://api.example.com")
    .build()?;

let app: Router = Router::new()
    .route(
        "/orders",
        get(|user: TokenUser| async move { Json(serde_json::json!({ "sub": user.sub })) })
            .route_layer(verifier.require_scope(["orders:write"])?)
            .route_layer(verifier.require_auth()),
    )
    .route(
        "/admin",
        get(admin)
            .route_layer(verifier.require_role(["admin"])?)
            .route_layer(verifier.require_auth()),
    )
    .route(
        "/payouts",
        get(payouts)
            .route_layer(verifier.require_step_up(StepUp::new().acr_values(["phr"]).max_age(300))?)
            .route_layer(verifier.require_auth()),
    );
```

In axum the last `route_layer` runs first, so add `require_auth()` last. A guard reached without a
verified token answers as if no token was sent.

The verifier finds the provider's JWKS from `<issuer>/.well-known/openid-configuration` on the
first request (the document's `issuer` must equal yours, and its `jwks_uri` must be https under an
https issuer), or uses `jwks_uri(...)` when you set one. If discovery or the key fetch fails, the
request answers 401 and discovery is tried again at most every 5 seconds.

A token is accepted only when it is RS256 under a published signing key (`kid` required, the key's
`use` and `alg` when present must be `sig` and `RS256`), with header `typ` `at+jwt`, no `crit`,
`iss` equal to the issuer, `aud` naming the audience, in date (5 seconds of clock skew), and with
`sub` and `client_id`. A first-party session token (one with a `typ` claim) is refused.
`TokenUser` carries `sub`, `client_id`, `scopes`, `roles`, `sid`, `org_id`, `acr`, `amr` and
`auth_time`. A client-credentials token has no user claims, so it passes scope guards only.

| Outcome | Status | `WWW-Authenticate` | Body |
| --- | --- | --- | --- |
| No bearer token | 401 | `Bearer` | `{"error":"missing_token"}` |
| Token refused | 401 | `Bearer error="invalid_token"` | `{"error":"invalid_token"}` |
| `require_scope`: not every scope granted | 403 | `Bearer error="insufficient_scope", scope="..."` | `{"error":"insufficient_scope","scope":"..."}` |
| `require_role`: no listed role granted | 403 | none | `{"error":"insufficient_role"}` |
| `require_step_up`: not met | 401 | `Bearer error="insufficient_user_authentication", ...` (RFC 9470) | `{"error":"insufficient_user_authentication",...}` |

`require_role` uses the same scoped matching as the JS adapters: `orders:write` grants
`orders:read`, and `orders` or `orders:*` grant every `orders:...` role. `require_step_up` takes any
of `acr_values` (listing `phr` also accepts `phrh`), `amr` (all required) and `max_age` in seconds
since `auth_time`.

The guards return an error at setup when they would require nothing: `require_scope` or
`require_role` with no values or an empty value, or `require_step_up` with none of its three
settings.

A token bound to a key (a `cnf` claim) is refused unless you add a `confirmation` hook. It gets the
claim and the request, so a DPoP proof can be checked against `cnf.jkt`:

```rust
let verifier = Verifier::builder(issuer)
    .audience(audience)
    .confirmation(|c: seamless_auth::Confirmation| async move { check_dpop(&c.cnf, &c.headers) })
    .build()?;
```

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
  SEAMLESS_SERVICE_TOKEN=verify-dev-service-token-not-a-real-secret \
  COOKIE_SIGNING_KEY=verify-dev-service-token-not-a-real-secret JWKS_KID=dev-main \
  cargo run --example refapp &

SEAMLESS_API_DIR=../seamless-auth-api seamless verify --adapter-url=http://localhost:8080
```

With `VERIFY_ONLY_ISSUER` and `VERIFY_ONLY_AUDIENCE` set (and `VERIFY_ONLY_JWKS_URI` to skip
discovery), the reference app also serves verify-only routes under `/verify-only`: `/me`,
`/orders` (scope `orders:write`), `/admin` (role `admin`) and `/step-up` (`acr` `phr` within 300
seconds).

## Status

Pre-1.0. The public API may change between minor versions until 1.0.

## License

Apache-2.0

Project governance, including the
[Seamless Auth License Pledge](https://github.com/fells-code/.github/blob/main/GOVERNANCE.md#the-seamless-auth-license-pledge),
is in the fells-code [GOVERNANCE.md](https://github.com/fells-code/.github/blob/main/GOVERNANCE.md).
