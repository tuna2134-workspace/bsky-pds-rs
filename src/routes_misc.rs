//! Identity + blob + admin + OAuth discovery routes.

use axum::{extract::{Query, State}, http::HeaderMap, Json};
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use worker::Env;

use crate::{atproto, auth, pds_env, xrpc::{XrpcError, XrpcResult}};

// ---------- identity ----------

#[derive(Clone)]
pub struct IdentityState {
    pub env: Env,
}

pub fn identity_router(env: Env) -> Router {
    Router::new()
        .route("/xrpc/com.atproto.identity.resolveHandle", get(resolve_handle))
        .route("/xrpc/com.atproto.identity.updateHandle", post(update_handle))
        .route("/xrpc/com.atproto.identity.getRecommendedDidCredentials", get(not_impl))
        .route("/.well-known/atproto-did", get(well_known_did))
        .with_state(IdentityState { env })
}

#[derive(Deserialize)]
struct HandleParam {
    #[serde(rename = "handle")]
    handle: String,
}

#[worker::send]
async fn resolve_handle(State(s): State<IdentityState>, Query(q): Query<HandleParam>) -> XrpcResult<Json<serde_json::Value>> {
    if !atproto::handle::validate(&q.handle) {
        return Err(XrpcError::bad_request("InvalidHandle", "bad handle"));
    }
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let row: Option<DidRow> = db.prepare("SELECT did FROM account WHERE handle = ?1")
        .bind(&[q.handle.clone().into()]).map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None).await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let Some(r) = row else { return Err(XrpcError::not_found("HandleNotFound", "unknown handle")); };
    Ok(Json(serde_json::json!({ "did": r.did })))
}

#[derive(Deserialize)]
struct DidRow {
    did: String,
}

#[derive(Deserialize)]
struct UpdateHandleReq {
    #[serde(rename = "handle")]
    handle: String,
}

#[worker::send]
async fn update_handle(State(s): State<IdentityState>, headers: HeaderMap, Json(req): Json<UpdateHandleReq>) -> XrpcResult<Json<serde_json::Value>> {
    let caller = auth::caller_from_headers(&headers)?;
    if !atproto::handle::validate(&req.handle) {
        return Err(XrpcError::bad_request("InvalidHandle", "bad handle"));
    }
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let now = pds_env::now_iso();
    db.prepare("UPDATE account SET handle = ?1, updated_at = ?2 WHERE did = ?3")
        .bind(&[req.handle.into(), now.into(), caller.did.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok(Json(serde_json::json!({})))
}

/// `/.well-known/atproto-did` — handle -> DID (plain text DID).
#[worker::send]
async fn well_known_did(State(s): State<IdentityState>) -> XrpcResult<String> {
    let cfg = pds_env::PdsEnv::from_env(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok(format!("did:web:{}", cfg.hostname))
}

#[worker::send]
async fn not_impl() -> XrpcError {
    XrpcError::not_implemented("staged (see ROADMAP)")
}

// ---------- blobs (R2) ----------

#[derive(Clone)]
pub struct BlobState {
    pub env: Env,
}

pub fn blob_router(env: Env) -> Router {
    Router::new()
        .route("/xrpc/com.atproto.repo.uploadBlob", post(upload_blob))
        .route("/xrpc/com.atproto.sync.listBlobs", get(list_blobs))
        .route("/xrpc/com.atproto.sync.getBlob", get(get_blob))
        .with_state(BlobState { env })
}

#[worker::send]
async fn upload_blob(State(s): State<BlobState>, headers: HeaderMap, body: axum::body::Bytes) -> XrpcResult<Json<serde_json::Value>> {
    let caller = auth::caller_from_headers(&headers)?;
    let cfg = pds_env::PdsEnv::from_env(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    if body.len() > cfg.blob_upload_limit {
        return Err(XrpcError::too_large("blob exceeds PDS_BLOB_UPLOAD_LIMIT"));
    }
    let mime = headers.get(axum::http::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("application/octet-stream").to_string();
    // Blob reference CID: raw sha2-256 (`bafkrei…`), content-addressed R2 key.
    let cid = crate::cid::Cid::raw(&body).to_string();
    let r2_key = format!("{}/{cid}", caller.did);
    let bucket = s.env.bucket("BLOBS").map_err(|e| XrpcError::internal(e.to_string()))?;
    bucket.put(&r2_key, body.to_vec())
        .http_metadata(worker::HttpMetadata { content_type: Some(mime.clone()), ..Default::default() })
        .execute().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let now = pds_env::now_iso();
    let _ = db.prepare("INSERT OR IGNORE INTO blob (did, cid, mime, size, r2_key, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)")
        .bind(&[caller.did.into(), cid.clone().into(), mime.clone().into(), (body.len() as f64).into(), r2_key.into(), now.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run().await;
    Ok(Json(serde_json::json!({ "blob": { "$type": "blob", "ref": { "$link": cid }, "mimeType": mime, "size": body.len() } })))
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct BlobListParam {
    #[serde(rename = "did")]
    did: String,
    #[serde(rename = "limit")]
    limit: Option<i64>,
    #[serde(rename = "cursor")]
    cursor: Option<String>,
}

#[worker::send]
async fn list_blobs(State(s): State<BlobState>, Query(q): Query<BlobListParam>) -> XrpcResult<Json<serde_json::Value>> {
    let limit = q.limit.unwrap_or(500).clamp(1, 1000);
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let rows = db.prepare("SELECT cid, mime, size FROM blob WHERE did = ?1 ORDER BY created_at LIMIT ?2")
        .bind(&[q.did.clone().into(), (limit as f64).into()]).map_err(|e| XrpcError::internal(e.to_string()))?
        .all().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let mut cids = Vec::new();
    for r in rows.results::<BlobRow>().unwrap_or_default() {
        cids.push(r.cid);
    }
    Ok(Json(serde_json::json!({ "cids": cids })))
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct BlobRow {
    cid: String,
    mime: String,
    size: f64,
}

#[derive(Deserialize)]
struct GetBlobParam {
    #[serde(rename = "did")]
    did: String,
    #[serde(rename = "cid")]
    cid: String,
}

#[worker::send]
async fn get_blob(State(s): State<BlobState>, Query(q): Query<GetBlobParam>) -> XrpcResult<axum::response::Response> {
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let row: Option<BlobFull> = db.prepare("SELECT mime, r2_key AS k FROM blob WHERE did = ?1 AND cid = ?2")
        .bind(&[q.did.clone().into(), q.cid.clone().into()]).map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None).await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let Some(b) = row else { return Err(XrpcError::not_found("BlobNotFound", "unknown blob")); };
    let bucket = s.env.bucket("BLOBS").map_err(|e| XrpcError::internal(e.to_string()))?;
    let obj = bucket.get(&b.k).execute().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let Some(obj) = obj else { return Err(XrpcError::not_found("BlobNotFound", "missing from store")); };
    let body = obj.body().ok_or_else(|| XrpcError::not_found("BlobNotFound", "empty object body"))?;
    let bytes = body.bytes().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    use axum::response::IntoResponse;
    Ok(([("content-type", b.mime)], bytes).into_response())
}

#[derive(Deserialize)]
struct BlobFull {
    mime: String,
    k: String,
}

// ---------- admin ----------

#[derive(Clone)]
pub struct AdminState {
    pub env: Env,
}

pub fn admin_router(env: Env) -> Router {
    Router::new()
        .route("/xrpc/com.atproto.admin.getAccountInfo", get(get_account_info))
        .with_state(AdminState { env })
}

#[worker::send]
async fn get_account_info(State(s): State<AdminState>, headers: HeaderMap, Query(q): Query<DidParam2>) -> XrpcResult<Json<serde_json::Value>> {
    let cfg = pds_env::PdsEnv::from_env(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    auth::check_admin(&headers, cfg.admin_password.as_deref())?;
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let row: Option<AcctFull> = db.prepare("SELECT did, handle, email, email_confirmed, status, active FROM account WHERE did = ?1")
        .bind(&[q.did.clone().into()]).map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None).await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let Some(a) = row else { return Err(XrpcError::not_found("AccountNotFound", "unknown")); };
    Ok(Json(serde_json::json!({
        "did": a.did, "handle": a.handle, "email": a.email,
        "emailConfirmed": a.email_confirmed == 1, "active": a.active == 1,
        "status": a.status,
    })))
}

#[derive(Deserialize)]
struct DidParam2 {
    #[serde(rename = "did")]
    did: String,
}

#[derive(Deserialize)]
struct AcctFull {
    did: String,
    handle: String,
    email: Option<String>,
    email_confirmed: i64,
    status: String,
    active: i64,
}

// ---------- OAuth discovery + server ----------

#[derive(Clone)]
pub struct OAuthState {
    pub env: Env,
}

pub fn oauth_router(env: Env) -> Router {
    Router::new()
        .route("/.well-known/oauth-protected-resource", get(protected_resource))
        .route("/.well-known/oauth-authorization-server", get(auth_server_meta))
        .route("/.well-known/did.json", get(did_json))
        .route("/jwks.json", get(jwks))
        .route("/oauth/par", post(par))
        .route("/oauth/authorize", get(authorize))
        .route("/oauth/token", post(token))
        .with_state(OAuthState { env })
}

#[worker::send]
async fn protected_resource(State(s): State<OAuthState>) -> Json<serde_json::Value> {
    let cfg = pds_env::PdsEnv::from_env(&s.env).map(|v| v).unwrap_or_else(|_| crate::pds_env::PdsEnv {
        hostname: "localhost".into(), plc_url: "".into(), appview_url: "".into(),
        appview_did: "".into(), admin_password: None, invite_required: true, blob_upload_limit: 52_428_800,
    });
    Json(serde_json::json!({
        "resource": format!("https://{}", cfg.hostname),
        "authorization_servers": [format!("https://{}", cfg.hostname)],
        "scopes_supported": ["atproto", "transition:generic", "transition:chat.bsky", "transition:email"],
        "bearer_methods_supported": ["header"],
    }))
}

#[worker::send]
async fn auth_server_meta(State(s): State<OAuthState>) -> Json<serde_json::Value> {
    let cfg = pds_env::PdsEnv::from_env(&s.env).map(|v| v).unwrap_or_else(|_| crate::pds_env::PdsEnv {
        hostname: "localhost".into(), plc_url: "".into(), appview_url: "".into(),
        appview_did: "".into(), admin_password: None, invite_required: true, blob_upload_limit: 52_428_800,
    });
    let iss = format!("https://{}", cfg.hostname);
    Json(serde_json::json!({
        "issuer": iss,
        "authorization_endpoint": format!("{iss}/oauth/authorize"),
        "token_endpoint": format!("{iss}/oauth/token"),
        "pushed_authorization_request_endpoint": format!("{iss}/oauth/par"),
        "jwks_uri": format!("{iss}/jwks.json"),
        "scopes_supported": ["atproto", "transition:generic", "transition:chat.bsky", "transition:email"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "require_pushed_authorization_requests": true,
    }))
}

#[worker::send]
async fn did_json(State(s): State<OAuthState>) -> Json<serde_json::Value> {
    let cfg = pds_env::PdsEnv::from_env(&s.env).map(|v| v).unwrap_or_else(|_| crate::pds_env::PdsEnv {
        hostname: "localhost".into(), plc_url: "".into(), appview_url: "".into(),
        appview_did: "".into(), admin_password: None, invite_required: true, blob_upload_limit: 52_428_800,
    });
    let origin = format!("https://{}", cfg.hostname);
    Json(serde_json::json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": format!("did:web:{}", cfg.hostname),
        "service": [
            { "id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": origin },
            { "id": "#atproto_oauth", "type": "AtprotoOAuthAuthorizationServer", "serviceEndpoint": origin },
        ],
    }))
}

#[worker::send]
async fn jwks() -> Json<serde_json::Value> {
    // TODO: publish real PDS signing JWKS (ES256K + ES256 rotation). Empty set
    // forces clients to fail closed until keys are configured — intentional.
    Json(serde_json::json!({ "keys": [] }))
}

#[derive(Deserialize)]
struct ParReq {
    #[serde(rename = "client_id")]
    client_id: String,
    #[serde(rename = "redirect_uri")]
    redirect_uri: String,
    #[serde(rename = "scope")]
    scope: Option<String>,
    #[serde(rename = "state")]
    state: Option<String>,
    #[serde(rename = "code_challenge")]
    code_challenge: Option<String>,
    #[serde(rename = "code_challenge_method")]
    code_challenge_method: Option<String>,
    #[serde(rename = "login_hint")]
    login_hint: Option<String>,
}

#[derive(Serialize)]
struct ParResp {
    #[serde(rename = "request_uri")]
    request_uri: String,
    #[serde(rename = "expires_in")]
    expires_in: i64,
}

#[worker::send]
async fn par(State(s): State<OAuthState>, axum::Form(req): axum::Form<ParReq>) -> XrpcResult<Json<ParResp>> {
    if !req.client_id.starts_with("https://") && !req.client_id.starts_with("http://localhost") {
        return Err(XrpcError::bad_request("InvalidClient", "client_id must be https URL (or http://localhost for dev)"));
    }
    let cc = req.code_challenge.ok_or_else(|| XrpcError::bad_request("InvalidRequest", "PKCE code_challenge required"))?;
    let ccm = req.code_challenge_method.unwrap_or_else(|| "S256".into());
    if ccm != "S256" {
        return Err(XrpcError::bad_request("InvalidRequest", "only S256 PKCE supported"));
    }
    let scope = req.scope.unwrap_or_else(|| "atproto".into());
    if !scope.split(' ').any(|x| x == "atproto") {
        return Err(XrpcError::bad_request("InvalidScope", "atproto scope required"));
    }
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::new_v4());
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let now = pds_env::now_iso();
    db.prepare("INSERT INTO oauth_par (request_uri, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, login_hint, expires_at, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)")
        .bind(&[
            request_uri.clone().into(),
            req.client_id.into(),
            req.redirect_uri.into(),
            scope.into(),
            req.state.unwrap_or_default().into(),
            cc.into(),
            ccm.into(),
            req.login_hint.unwrap_or_default().into(),
            now.into(),
        ])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok(Json(ParResp { request_uri, expires_in: 300 }))
}

#[derive(Deserialize)]
struct AuthorizeParam {
    #[serde(rename = "request_uri")]
    request_uri: Option<String>,
    #[serde(rename = "client_id")]
    client_id: Option<String>,
}

#[worker::send]
async fn authorize(State(_s): State<OAuthState>, Query(q): Query<AuthorizeParam>) -> XrpcResult<Json<serde_json::Value>> {
    // TODO: real login/consent screen (PDS_SERVICE_NAME branding).
    // Return the pending request so UI work can proceed against a stable shape.
    if q.request_uri.is_none() {
        return Err(XrpcError::bad_request("InvalidRequest", "request_uri (PAR) required"));
    }
    Ok(Json(serde_json::json!({
        "todo": "render login + consent for client",
        "request_uri": q.request_uri,
        "client_id": q.client_id,
    })))
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct TokenReq {
    #[serde(rename = "grant_type")]
    grant_type: Option<String>,
    #[serde(rename = "code")]
    code: Option<String>,
    #[serde(rename = "redirect_uri")]
    redirect_uri: Option<String>,
    #[serde(rename = "code_verifier")]
    code_verifier: Option<String>,
}

#[worker::send]
async fn token(State(_s): State<OAuthState>, headers: HeaderMap, axum::Form(req): axum::Form<TokenReq>) -> XrpcResult<Json<serde_json::Value>> {
    // DPoP proof is MANDATORY in the atproto profile. Enforce presence here;
    // full proof/JKT verification is staged (ROADMAP) alongside JWKS publish.
    if headers.get("DPoP").is_none() {
        return Err(XrpcError::new(axum::http::StatusCode::BAD_REQUEST, "InvalidDpopProof", "DPoP header required"));
    }
    let _ = req;
    Err(XrpcError::not_implemented("token issuance staged with DPoP verification + JWKS (see ROADMAP)"))
}

#[derive(Serialize)]
#[allow(dead_code)]
struct Empty {}
