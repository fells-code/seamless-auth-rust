//! A [Seamless Auth](https://github.com/fells-code/seamless-auth-api) server adapter for Axum.
//!
//! The adapter sits in front of the Seamless Auth API. Browsers talk to it over
//! `HttpOnly` cookies on the application's own domain, native clients over bearer
//! tokens, and it talks to the auth API over bearer tokens and a service token.
//! Which routes it serves, and what each does to the session, comes from the auth
//! API's adapter manifest.
//!
//! ```no_run
//! use axum::{Json, Router, routing::get};
//! use seamless_auth::{Adapter, User};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let auth = Adapter::builder(std::env::var("AUTH_SERVER_URL")?)
//!     .cookie_secret(std::env::var("COOKIE_SECRET")?)
//!     .service_secret(std::env::var("SERVICE_SECRET")?)
//!     .jwks_kid(std::env::var("JWKS_KID")?)
//!     .build()?;
//!
//! let app: Router = Router::new()
//!     .route(
//!         "/api/me",
//!         get(|user: User| async move { Json(serde_json::json!({ "id": user.id })) })
//!             .route_layer(auth.require_auth()),
//!     )
//!     .nest("/auth", auth.router());
//!
//! let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
//! axum::serve(
//!     listener,
//!     app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
//! )
//! .await?;
//! # Ok(())
//! # }
//! ```

mod adapter;
mod client_ip;
mod console;
mod cookies;
mod delivery;
mod guard;
mod jwks;
mod jwt;
mod manifest;
mod options;
mod origin;
mod refresh;
mod routes;
mod service_token;

#[cfg(test)]
mod tests;

pub use adapter::Adapter;
pub use client_ip::{InvalidProxy, TrustedProxies};
pub use delivery::{Delivery, DeliveryError};
pub use guard::{RequireAuth, RequireAuthLayer, Unauthenticated, User};
pub use manifest::{MANIFEST_PATH, Manifest, ManifestError, ManifestRoute, PickBody};
pub use options::{BuildError, Builder, SameSite};
