//! The reference app the Seamless Auth adapter conformance suite drives
//! (`seamless verify --adapter-url`). Its routes and configuration follow
//! `verify/CONFORMANCE.md` in fells-code/seamless-cli. It is a test fixture, not
//! an example deployment: `/__captured` exposes one-time codes.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use axum::extract::Path;
use axum::routing::get;
use axum::{Json, Router};
use seamless_auth::{Adapter, Delivery, User};
use serde_json::{Value, json};

type Captured = Arc<Mutex<HashMap<String, Value>>>;

#[tokio::main]
async fn main() {
    let captured: Captured = Arc::default();
    let sink = captured.clone();

    let auth = Adapter::builder(env("AUTH_SERVER_URL"))
        .auth_server_issuer(env("AUTH_SERVER_ISSUER"))
        .cookie_secret(env("COOKIE_SIGNING_KEY"))
        .service_secret(env("API_SERVICE_TOKEN"))
        .jwks_kid(env("JWKS_KID"))
        .deliver(move |d: Delivery| {
            let sink = sink.clone();
            async move {
                let mut entry = json!({ "token": d.token.unwrap_or_default() });
                if let Some(url) = d.magic_link_url {
                    entry["magicLinkUrl"] = Value::from(url);
                }
                if let Some(url) = d.sign_in_url {
                    entry["inviteUrl"] = Value::from(url);
                }
                sink.lock().unwrap().insert(d.to, entry);
                Ok::<_, std::convert::Infallible>(())
            }
        })
        // One trusted hop: the harness sends each virtual user with its own
        // X-Forwarded-For. Trusting whatever the immediate peer is would be wrong
        // in a deployment, and is acceptable only because this is a test app.
        .resolve_client_ip(|headers, peer| {
            let last = headers
                .get_all("x-forwarded-for")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(','))
                .next_back()
                .map(str::trim);
            match last {
                Some(hop) => hop.parse::<IpAddr>().ok(),
                None => peer,
            }
        })
        .build()
        .unwrap_or_else(|e| panic!("{e}"));

    let app = Router::new()
        .route("/", get(|| async { Json(json!({ "ok": true })) }))
        .route(
            "/__captured/{recipient}",
            get(move |Path(recipient): Path<String>| {
                let captured = captured.clone();
                async move {
                    Json(
                        captured
                            .lock()
                            .unwrap()
                            .get(&recipient)
                            .cloned()
                            .unwrap_or(Value::Null),
                    )
                }
            }),
        )
        .route(
            "/api/me",
            get(|user: User| async move { Json(json!({ "id": user.id })) })
                .route_layer(auth.require_auth()),
        )
        .nest("/auth", auth.router());

    let port = std::env::var("PORT")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "8080".into());
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port.parse::<u16>().expect("PORT")))
        .await
        .expect("bind");
    println!("seamless-auth-rust reference app listening on :{port}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("serve");
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}
