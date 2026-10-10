use axum::{http::{HeaderValue, Method}, response::IntoResponse, routing::get, Extension, Router};
use tower_service::Service;
use crate::proxy::proxy_fallback;
use worker::*;

pub mod atproto;
pub mod auth;
pub mod car;
pub mod cbor;
pub mod email;
pub mod cid;
pub mod firehose;
pub mod firehose_ws;
pub mod identity;
pub mod keys;
pub mod mst;
pub mod oauth;
pub mod pds_env;
pub mod proxy;
pub mod repo;
pub mod routes_misc;
pub mod routes_repo;
pub mod routes_server;
pub mod routes_sync;
pub mod xrpc;

fn router(env: Env) -> Router {
    Router::new()
        .route("/", get(root))
        .route("/xrpc/_health", get(health))
        .merge(routes_server::router(env.clone()))
        .merge(routes_repo::router(env.clone()))
        .merge(routes_sync::router(env.clone()))
        .merge(routes_misc::identity_router(env.clone()))
        .merge(routes_misc::blob_router(env.clone()))
        .merge(routes_misc::admin_router(env.clone()))
        .merge(routes_misc::oauth_router(env.clone()))
        .fallback(proxy_fallback)
        .layer(Extension(env.clone()))
}

#[event(fetch)]
async fn fetch(
    req: HttpRequest,
    env: Env,
    _ctx: Context,
) -> Result<axum::http::Response<axum::body::Body>> {
    // Native WebSocket firehose (event-stream v0). Plain GETs without an
    // upgrade fall through to the poll-compatible JSON handler below.
    if req.method() == Method::GET
        && req.uri().path() == "/xrpc/com.atproto.sync.subscribeRepos"
        && crate::firehose_ws::is_ws_upgrade(&req)
    {
        return match crate::firehose_ws::accept(env, &req).await {
            Ok(res) => Ok(res),
            Err(e) => Ok(axum::Json(serde_json::json!({
                "error": "InternalError",
                "message": e.to_string(),
            }))
            .into_response()),
        };
    }
    // Attach permissive CORS preflight at the edge (simple, spec-encouraged).
    if req.method() == Method::OPTIONS {
        let mut res = axum::http::Response::new(axum::body::Body::empty());
        for (k, v) in cors_headers() {
            res.headers_mut().insert(k, v);
        }
        return Ok(res);
    }
    let mut router = router(env);
    let mut resp = router.call(req).await?;
    for (k, v) in cors_headers() {
        resp.headers_mut().insert(k, v);
    }
    // Sync visibility header (Atproto-Repo-Rev) is set by write paths via JSON;
    // edge-level default omitted until repo state is authoritative.
    Ok(resp)
}

fn cors_headers() -> Vec<(axum::http::header::HeaderName, HeaderValue)> {
    vec![
        (axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*")),
        (axum::http::header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET, POST, OPTIONS")),
        (axum::http::header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("Authorization, Content-Type, DPoP, atproto-proxy, atproto-accept-labelers")),
    ]
}

pub async fn root() -> &'static str {
    "bsky-pds-rs: atproto PDS (Rust + Workers). See /xrpc/_health and docs/ROADMAP.md"
}

pub async fn health(Extension(env): Extension<Env>) -> axum::Json<serde_json::Value> {
    let hostname = env.var("PDS_HOSTNAME").map(|v| v.to_string()).unwrap_or_else(|_| "localhost".into());
    axum::Json(serde_json::json!({ "version": env!("CARGO_PKG_VERSION"), "hostname": hostname }))
}
