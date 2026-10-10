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
        .route("/xrpc/com.atproto.identity.resolveDid", get(resolve_did))
        .route("/xrpc/com.atproto.identity.resolveIdentity", get(resolve_identity))
        .route("/xrpc/com.atproto.identity.refreshIdentity", post(refresh_identity))
        .route("/xrpc/com.atproto.identity.getRecommendedDidCredentials", get(get_recommended_did_credentials))
        .route("/xrpc/com.atproto.identity.requestPlcOperationSignature", post(request_plc_operation_signature))
        .route("/xrpc/com.atproto.identity.signPlcOperation", post(sign_plc_operation))
        .route("/xrpc/com.atproto.identity.submitPlcOperation", post(submit_plc_operation))
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
    let caller = auth::authenticate(&s.env, &headers, "POST", "/xrpc/com.atproto.identity.updateHandle").await?;
    if !atproto::handle::validate(&req.handle) {
        return Err(XrpcError::bad_request("InvalidHandle", "bad handle"));
    }
    let cfg = pds_env::PdsEnv::from_env(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let own_domain = req.handle == cfg.hostname || req.handle.ends_with(&format!(".{}", cfg.hostname));
    if !own_domain {
        // External handle: require bidirectional proof that it points at this DID.
        match crate::identity::resolve_handle_to_did(&s.env, &req.handle).await {
            Ok(Some(d)) if d == caller.did => {}
            _ => {
                return Err(XrpcError::bad_request(
                    "InvalidHandle",
                    "handle does not resolve to your DID (set DNS TXT _dnslink or /.well-known/atproto-did first)",
                ))
            }
        }
    }
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    #[derive(Deserialize)]
    struct TakenRow {
        did: String,
    }
    let taken: Option<TakenRow> = db
        .prepare("SELECT did FROM account WHERE handle = ?1")
        .bind(&[req.handle.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    if let Some(t) = taken {
        if t.did != caller.did {
            return Err(XrpcError::bad_request("InvalidHandle", "handle already taken"));
        }
    }
    let now = pds_env::now_iso();
    let handle = req.handle.clone();
    db.prepare("UPDATE account SET handle = ?1, updated_at = ?2 WHERE did = ?3")
        .bind(&[req.handle.into(), now.into(), caller.did.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run()
        .await
        .map_err(|_| XrpcError::bad_request("InvalidHandle", "handle update failed"))?;
    crate::firehose::emit_identity(&s.env, &caller.did, Some(&handle)).await?;
    Ok(Json(serde_json::json!({})))
}

/// `/.well-known/atproto-did` — per-host handle -> DID (plain text).
/// Served for every subdomain thanks to the wildcard DNS: the Host header
/// selects the account; the bare PDS hostname answers its own DID.
#[worker::send]
async fn well_known_did(State(s): State<IdentityState>, headers: HeaderMap) -> XrpcResult<String> {
    let cfg = pds_env::PdsEnv::from_env(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or(&cfg.hostname)
        .split(':')
        .next()
        .unwrap_or(&cfg.hostname)
        .to_lowercase();
    if host != cfg.hostname {
        let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
        #[derive(Deserialize)]
        struct HRow {
            did: String,
        }
        let row: Option<HRow> = db
            .prepare("SELECT did FROM account WHERE handle = ?1")
            .bind(&[host.clone().into()])
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .first(None)
            .await
            .map_err(|e| XrpcError::internal(e.to_string()))?;
        if let Some(r) = row {
            return Ok(r.did);
        }
    }
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
    let caller = auth::authenticate(&s.env, &headers, "POST", "/xrpc/com.atproto.repo.uploadBlob").await?;
    crate::repo::require_active(&s.env, &caller.did).await?;
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
        .route("/oauth/authorize", get(authorize_get).post(authorize_post))
        .route("/oauth/token", post(token))
        .with_state(OAuthState { env })
}

#[worker::send]
async fn protected_resource(State(s): State<OAuthState>) -> Json<serde_json::Value> {
    let cfg = pds_env::PdsEnv::from_env(&s.env).map(|v| v).unwrap_or_else(|_| crate::pds_env::PdsEnv {
        hostname: "localhost".into(), plc_url: "".into(), appview_url: "".into(),
        appview_did: "".into(), admin_password: None, jwt_secret: None, invite_required: true, blob_upload_limit: 52_428_800, crawlers: "https://bsky.network".into(), email_from: None,
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
        appview_did: "".into(), admin_password: None, jwt_secret: None, invite_required: true, blob_upload_limit: 52_428_800, crawlers: "https://bsky.network".into(), email_from: None,
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
        appview_did: "".into(), admin_password: None, jwt_secret: None, invite_required: true, blob_upload_limit: 52_428_800, crawlers: "https://bsky.network".into(), email_from: None,
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

// ---------- OAuth server (atproto profile) ----------

fn iso_plus_secs(secs: i64) -> String {
    // now_iso() is fixed-width RFC3339 UTC; Durations via millis shift are
    // easier: recompute from epoch millis with the same civil algorithm.
    // pds_env::now_iso uses Date::now(); replicate offset here.
    let ms = worker::Date::now().as_millis() as i64 + secs * 1000;
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_ymd(days + 719_468);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z", y, m, d, tod / 3600, (tod % 3600) / 60, tod % 60, millis)
}

fn civil_ymd(z: i64) -> (i64, u32, u32) {
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn expired(expires_at: &str) -> bool {
    expires_at <= pds_env::now_iso().as_str()
}

fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[worker::send]
async fn jwks(State(s): State<OAuthState>) -> XrpcResult<Json<serde_json::Value>> {
    let (_, pub_hex) = crate::oauth::oauth_keypair(&s.env).await?;
    let mut jwk = crate::keys::public_jwk(&pub_hex, &crate::keys::Curve::P256)
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let kid = crate::keys::jwk_thumbprint(&jwk).map_err(|e| XrpcError::internal(e.to_string()))?;
    jwk["use"] = serde_json::Value::String("sig".into());
    jwk["alg"] = serde_json::Value::String("ES256".into());
    jwk["kid"] = serde_json::Value::String(kid);
    Ok(Json(serde_json::json!({ "keys": [jwk] })))
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
    #[serde(rename = "client_assertion")]
    client_assertion: Option<String>,
    #[serde(rename = "client_assertion_type")]
    client_assertion_type: Option<String>,
}

#[derive(Serialize)]
struct ParResp {
    #[serde(rename = "request_uri")]
    request_uri: String,
    #[serde(rename = "expires_in")]
    expires_in: i64,
}

#[worker::send]
async fn par(State(s): State<OAuthState>, headers: HeaderMap, axum::Form(req): axum::Form<ParReq>) -> XrpcResult<Json<ParResp>> {
    let cc = req.code_challenge.ok_or_else(|| XrpcError::bad_request("InvalidRequest", "PKCE code_challenge required"))?;
    if cc.len() < 43 || cc.len() > 128 {
        return Err(XrpcError::bad_request("InvalidRequest", "bad code_challenge"));
    }
    let ccm = req.code_challenge_method.unwrap_or_else(|| "S256".into());
    if ccm != "S256" {
        return Err(XrpcError::bad_request("InvalidRequest", "only S256 PKCE supported"));
    }
    let scope = req.scope.unwrap_or_else(|| "atproto".into());
    if !scope.split(' ').any(|x| x == "atproto") {
        return Err(XrpcError::bad_request("InvalidScope", "atproto scope required"));
    }
    // Client metadata: redirect_uri + scope allow-list, confidential auth.
    let meta = crate::oauth::fetch_client_metadata(&s.env, &req.client_id).await?;
    if !meta.redirect_uris.iter().any(|r| r == &req.redirect_uri) {
        return Err(XrpcError::bad_request("InvalidRequest", "redirect_uri not registered"));
    }
    let declared: std::collections::HashSet<&str> = meta.scope.split(' ').collect();
    for sc in scope.split(' ') {
        if !declared.contains(sc) {
            return Err(XrpcError::bad_request("InvalidScope", format!("scope not declared: {sc}")));
        }
    }
    if meta.token_endpoint_auth_method == "private_key_jwt" {
        if req.client_assertion_type.as_deref() != Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer") {
            return Err(XrpcError::new(axum::http::StatusCode::UNAUTHORIZED, "InvalidClient", "client_assertion required"));
        }
        let aud = format!("{}{}", crate::auth::public_origin(&headers, &cfg_hostname(&s.env)), "/oauth/par");
        crate::oauth::verify_client_assertion(&s.env, &meta, req.client_assertion.as_deref(), &aud).await?;
    }
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", uuid::Uuid::new_v4());
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let now = pds_env::now_iso();
    let exp = iso_plus_secs(300);
    db.prepare("INSERT INTO oauth_par (request_uri, client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, login_hint, expires_at, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)")
        .bind(&[
            request_uri.clone().into(),
            req.client_id.into(),
            req.redirect_uri.into(),
            scope.into(),
            req.state.unwrap_or_default().into(),
            cc.into(),
            ccm.into(),
            req.login_hint.unwrap_or_default().into(),
            exp.into(),
            now.into(),
        ])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok(Json(ParResp { request_uri, expires_in: 300 }))
}

fn cfg_hostname(env: &worker::Env) -> String {
    pds_env::PdsEnv::from_env(env).map(|c| c.hostname).unwrap_or_else(|_| "localhost".into())
}

#[derive(Deserialize)]
struct ParRow {
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    code_challenge: String,
    #[allow(dead_code)]
    code_challenge_method: String,
    login_hint: String,
    expires_at: String,
}

async fn load_par(env: &worker::Env, request_uri: &str) -> XrpcResult<ParRow> {
    let db = pds_env::db(env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let row: Option<ParRow> = db
        .prepare("SELECT client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, login_hint, expires_at FROM oauth_par WHERE request_uri = ?1")
        .bind(&[request_uri.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let Some(par) = row else {
        return Err(XrpcError::bad_request("InvalidRequest", "unknown request_uri"));
    };
    if expired(&par.expires_at) {
        return Err(XrpcError::bad_request("InvalidRequest", "request_uri expired"));
    }
    Ok(par)
}

// ---------- authorize ----------

#[derive(Deserialize)]
struct AuthorizeParam {
    #[serde(rename = "request_uri")]
    request_uri: Option<String>,
    #[serde(rename = "format")]
    format: Option<String>,
}

fn wants_json(headers: &HeaderMap, format: Option<&str>) -> bool {
    if format == Some("json") {
        return true;
    }
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("application/json"))
        .unwrap_or(false)
}

#[worker::send]
async fn authorize_get(
    State(s): State<OAuthState>,
    headers: HeaderMap,
    Query(q): Query<AuthorizeParam>,
) -> XrpcResult<axum::response::Response> {
    use axum::response::IntoResponse;
    let request_uri = q.request_uri.ok_or_else(|| XrpcError::bad_request("InvalidRequest", "request_uri (PAR) required"))?;
    let par = load_par(&s.env, &request_uri).await?;
    if wants_json(&headers, q.format.as_deref()) {
        return Ok(Json(serde_json::json!({
            "request_uri": request_uri,
            "client_id": par.client_id,
            "scope": par.scope,
            "login_hint": par.login_hint,
        }))
        .into_response());
    }
    let host = cfg_hostname(&s.env);
    let page = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize — {host} PDS</title>
<style>body{{font-family:system-ui,sans-serif;max-width:28rem;margin:4rem auto;padding:0 1rem}}input{{display:block;width:100%;margin:.5rem 0;padding:.6rem}}button{{padding:.6rem 1.2rem}}</style></head>
<body><h1>{host} PDS</h1><p><b>{client}</b> is requesting access with scope:</p><p><code>{scope}</code></p>
<form method="post" action="/oauth/authorize"><input type="hidden" name="request_uri" value="{ru}">
<label>Handle or DID<input name="handle" value="{hint}" autocomplete="username"></label>
<label>Password or app password<input name="password" type="password" autocomplete="current-password"></label>
<button type="submit" name="approve" value="true">Authorize</button></form></body></html>"#,
        host = host,
        client = par.client_id,
        scope = par.scope,
        ru = request_uri,
        hint = par.login_hint,
    );
    Ok(([(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")], page).into_response())
}

#[derive(Deserialize)]
struct AuthorizePost {
    #[serde(rename = "request_uri")]
    request_uri: String,
    #[serde(rename = "handle")]
    handle: String,
    #[serde(rename = "password")]
    password: String,
    #[serde(rename = "format")]
    format: Option<String>,
}

#[worker::send]
async fn authorize_post(
    State(s): State<OAuthState>,
    headers: HeaderMap,
    Query(q): Query<AuthorizeParam>,
    axum::Form(req): axum::Form<AuthorizePost>,
) -> XrpcResult<axum::response::Response> {
    use axum::response::IntoResponse;
    let par = load_par(&s.env, &req.request_uri).await?;
    let format = req.format.as_deref().or(q.format.as_deref());
    // Authenticate the account (password or app password; both verify here).
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    #[derive(Deserialize)]
    struct LoginRow {
        did: String,
        handle: String,
        password_hash: Option<String>,
        active: i64,
    }
    let row: Option<LoginRow> = db
        .prepare("SELECT did, handle, password_hash, active FROM account WHERE handle = ?1 OR email = ?1 OR did = ?1")
        .bind(&[req.handle.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let bad = || XrpcError::new(axum::http::StatusCode::UNAUTHORIZED, "AccessDenied", "invalid login");
    let Some(acct) = row else {
        return Err(bad());
    };
    if acct.active == 0 {
        return Err(XrpcError::forbidden("AccountDeactivated", "account is not active"));
    }
    // login_hint binding: the authorizing account must match the hint.
    if !par.login_hint.is_empty() && par.login_hint != acct.did && par.login_hint != acct.handle && par.login_hint != req.handle {
        return Err(bad());
    }
    let stored = acct.password_hash.clone().unwrap_or_default();
    if stored.is_empty() || !crate::oauth::verify_password(&stored, &req.password) {
        return Err(bad());
    }
    // Issue single-use authorization code bound to the PAR + account.
    let code = crate::keys::random_b64u32().map_err(|e| XrpcError::internal(e.to_string()))?;
    let now = pds_env::now_iso();
    let exp = iso_plus_secs(600);
    db.prepare("INSERT INTO oauth_code (code, request_uri, did, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)")
        .bind(&[code.clone().into(), req.request_uri.clone().into(), acct.did.clone().into(), now.into(), exp.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let sep = if par.redirect_uri.contains('?') { "&" } else { "?" };
    let location = format!(
        "{}{}code={}&state={}",
        par.redirect_uri,
        sep,
        url_encode(&code),
        url_encode(&par.state)
    );
    if wants_json(&headers, format) {
        return Ok(Json(serde_json::json!({ "redirect_to": location, "code": code, "state": par.state })).into_response());
    }
    Ok((axum::http::StatusCode::FOUND, [(axum::http::header::LOCATION, location)]).into_response())
}

// ---------- token ----------

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
    #[serde(rename = "refresh_token")]
    refresh_token: Option<String>,
    #[serde(rename = "scope")]
    scope: Option<String>,
    #[serde(rename = "client_id")]
    client_id: Option<String>,
    #[serde(rename = "client_assertion")]
    client_assertion: Option<String>,
    #[serde(rename = "client_assertion_type")]
    client_assertion_type: Option<String>,
}

fn oauth_error(status: axum::http::StatusCode, code: &str, desc: &str, dpop_nonce: Option<String>) -> axum::response::Response {
    use axum::response::IntoResponse;
    let mut res = (
        status,
        Json(serde_json::json!({ "error": code, "error_description": desc })),
    )
        .into_response();
    if let Some(n) = dpop_nonce {
        res.headers_mut().insert("DPoP-Nonce", n.parse().unwrap());
    }
    res
}

#[worker::send]
async fn token(
    State(s): State<OAuthState>,
    headers: HeaderMap,
    axum::Form(req): axum::Form<TokenReq>,
) -> axum::response::Response {
    match token_inner(&s.env, &headers, req).await {
        Ok(res) => res,
        Err(TokenFail::OAuth(status, code, desc)) => oauth_error(status, &code, &desc, None),
        Err(TokenFail::Nonce(nonce)) => oauth_error(
            axum::http::StatusCode::BAD_REQUEST,
            "use_dpop_nonce",
            "DPoP nonce required",
            Some(nonce),
        ),
        Err(TokenFail::Xrpc(e)) => {
            use axum::response::IntoResponse;
            e.into_response()
        }
    }
}

enum TokenFail {
    OAuth(axum::http::StatusCode, String, String),
    Nonce(String),
    Xrpc(XrpcError),
}

impl From<XrpcError> for TokenFail {
    fn from(e: XrpcError) -> Self {
        TokenFail::Xrpc(e)
    }
}

fn ofail(code: &str, desc: impl Into<String>) -> TokenFail {
    TokenFail::OAuth(axum::http::StatusCode::BAD_REQUEST, code.into(), desc.into())
}

async fn token_inner(
    env: &worker::Env,
    headers: &HeaderMap,
    req: TokenReq,
) -> Result<axum::response::Response, TokenFail> {
    use axum::response::IntoResponse;
    let cfg = pds_env::PdsEnv::from_env(env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let token_url = format!("{}{}", crate::auth::public_origin(headers, &cfg.hostname), "/oauth/token");
    // DPoP is mandatory at the token endpoint (fresh proof + server nonce).
    let dpop = crate::oauth::verify_dpop(env, headers, "POST", &token_url, None, true)
        .await
        .map_err(|e| match e {
            crate::oauth::DpopError::NonceRequired(n) => TokenFail::Nonce(n),
            crate::oauth::DpopError::Invalid(m) => ofail("invalid_dpop_proof", m),
        })?;
    match req.grant_type.as_deref() {
        Some("authorization_code") => {
            let code = req.code.ok_or_else(|| ofail("invalid_request", "code required"))?;
            let redirect_uri = req.redirect_uri.ok_or_else(|| ofail("invalid_request", "redirect_uri required"))?;
            let verifier = req.code_verifier.ok_or_else(|| ofail("invalid_request", "code_verifier required"))?;
            let db = pds_env::db(env).map_err(|e| XrpcError::internal(e.to_string()))?;
            #[derive(Deserialize)]
            struct CodeRow {
                request_uri: String,
                did: String,
                expires_at: String,
                used_at: Option<String>,
            }
            let row: Option<CodeRow> = db
                .prepare("SELECT request_uri, did, expires_at, used_at FROM oauth_code WHERE code = ?1")
                .bind(&[code.clone().into()])
                .map_err(|e| XrpcError::internal(e.to_string()))?
                .first(None)
                .await
                .map_err(|e| XrpcError::internal(e.to_string()))?;
            let Some(code_row) = row else {
                return Err(ofail("invalid_grant", "bad code"));
            };
            if code_row.used_at.is_some() || expired(&code_row.expires_at) {
                return Err(ofail("invalid_grant", "code expired or reused"));
            }
            let par = load_par(env, &code_row.request_uri).await?;
            if redirect_uri != par.redirect_uri {
                return Err(ofail("invalid_grant", "redirect_uri mismatch"));
            }
            if let Some(cid) = req.client_id.as_deref() {
                if cid != par.client_id {
                    return Err(ofail("invalid_grant", "client_id mismatch"));
                }
            }
            if crate::keys::pkce_s256_challenge(&verifier) != par.code_challenge {
                return Err(ofail("invalid_grant", "PKCE verification failed"));
            }
            let meta = crate::oauth::fetch_client_metadata(env, &par.client_id).await?;
            crate::oauth::verify_client_assertion(env, &meta, req.client_assertion.as_deref(), &token_url)
                .await
                .map_err(|_| ofail("invalid_client", "bad client assertion"))?;
            let now = pds_env::now_iso();
            db.prepare("UPDATE oauth_code SET used_at = ?1 WHERE code = ?2")
                .bind(&[now.into(), code.into()])
                .map_err(|e| XrpcError::internal(e.to_string()))?
                .run()
                .await
                .map_err(|e| XrpcError::internal(e.to_string()))?;
            let body = issue_session(env, &cfg, &code_row.did, &par.client_id, &par.scope, &dpop.jkt).await?;
            Ok(Json(body).into_response())
        }
        Some("refresh_token") => {
            let refresh = req.refresh_token.ok_or_else(|| ofail("invalid_request", "refresh_token required"))?;
            let (_, server_pub) = crate::oauth::oauth_keypair(env).await?;
            let payload = crate::keys::verify_jwt_es256(&refresh, &server_pub, Some("refresh+jwt"))
                .map_err(|_| ofail("invalid_grant", "bad refresh token"))?;
            let did = payload.get("sub").and_then(|v| v.as_str()).ok_or_else(|| ofail("invalid_grant", "bad sub"))?;
            let exp = payload.get("exp").and_then(|v| v.as_i64()).unwrap_or(0);
            if (worker::Date::now().as_millis() / 1000) as i64 > exp + 30 {
                return Err(ofail("invalid_grant", "refresh token expired"));
            }
            let db = pds_env::db(env).map_err(|e| XrpcError::internal(e.to_string()))?;
            #[derive(Deserialize)]
            struct SessRow {
                jti: String,
                did: String,
                client_id: String,
                scope: String,
                dpop_jkt: String,
                expires_at: String,
            }
            let row: Option<SessRow> = db
                .prepare("SELECT jti, did, client_id, scope, dpop_jkt, expires_at FROM oauth_token WHERE refresh_token_hash = ?1")
                .bind(&[crate::keys::sha256_hex(&refresh).into()])
                .map_err(|e| XrpcError::internal(e.to_string()))?
                .first(None)
                .await
                .map_err(|e| XrpcError::internal(e.to_string()))?;
            let Some(sess) = row else {
                return Err(ofail("invalid_grant", "unknown session (rotated or revoked)"));
            };
            if sess.did != did || expired(&sess.expires_at) {
                return Err(ofail("invalid_grant", "session expired"));
            }
            if dpop.jkt != sess.dpop_jkt {
                return Err(ofail("invalid_grant", "DPoP key changed"));
            }
            if let Some(cid) = req.client_id.as_deref() {
                if cid != sess.client_id {
                    return Err(ofail("invalid_client", "client_id mismatch"));
                }
            }
            // Optional down-scoping.
            let scope = match req.scope {
                Some(want) => {
                    let granted: std::collections::HashSet<&str> = sess.scope.split(' ').collect();
                    for sc in want.split(' ') {
                        if !granted.contains(sc) {
                            return Err(ofail("invalid_scope", format!("scope not granted: {sc}")));
                        }
                    }
                    if !want.split(' ').any(|x| x == "atproto") {
                        return Err(ofail("invalid_scope", "atproto scope required"));
                    }
                    want
                }
                None => sess.scope.clone(),
            };
            // Rotate: drop the old session row, issue fresh tokens.
            db.prepare("DELETE FROM oauth_token WHERE jti = ?1")
                .bind(&[sess.jti.clone().into()])
                .map_err(|e| XrpcError::internal(e.to_string()))?
                .run()
                .await
                .map_err(|e| XrpcError::internal(e.to_string()))?;
            let body = issue_session(env, &cfg, &sess.did, &sess.client_id, &scope, &dpop.jkt).await?;
            Ok(Json(body).into_response())
        }
        _ => Err(ofail("unsupported_grant_type", "grant_type must be authorization_code or refresh_token")),
    }
}

/// Mint + persist an OAuth session (access 2h, refresh 30d, both DPoP-bound).
async fn issue_session(
    env: &worker::Env,
    cfg: &pds_env::PdsEnv,
    did: &str,
    client_id: &str,
    scope: &str,
    jkt: &str,
) -> XrpcResult<serde_json::Value> {
    let (priv_hex, _) = crate::oauth::oauth_keypair(env).await?;
    let iss = format!("https://{}", cfg.hostname);
    let now = (worker::Date::now().as_millis() / 1000) as i64;
    let access_jti = crate::keys::random_b64u32().map_err(|e| XrpcError::internal(e.to_string()))?;
    let refresh_jti = crate::keys::random_b64u32().map_err(|e| XrpcError::internal(e.to_string()))?;
    let access_exp = now + 7200;
    let refresh_exp = now + 30 * 86400;
    let access = crate::keys::sign_jwt_es256(
        &priv_hex,
        "at+jwt",
        &serde_json::json!({"iss": iss, "sub": did, "scope": scope, "iat": now, "exp": access_exp, "jti": access_jti, "cnf": {"jkt": jkt}, "client_id": client_id}),
    )
    .map_err(|e| XrpcError::internal(e.to_string()))?;
    let refresh = crate::keys::sign_jwt_es256(
        &priv_hex,
        "refresh+jwt",
        &serde_json::json!({"iss": iss, "sub": did, "scope": scope, "iat": now, "exp": refresh_exp, "jti": refresh_jti, "cnf": {"jkt": jkt}, "client_id": client_id}),
    )
    .map_err(|e| XrpcError::internal(e.to_string()))?;
    let db = pds_env::db(env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let created = pds_env::now_iso();
    let exp_iso = iso_plus_secs(30 * 86400);
    db.prepare("INSERT INTO oauth_token (jti, did, client_id, scope, dpop_jkt, access_token_hash, refresh_token_hash, expires_at, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)")
        .bind(&[
            refresh_jti.into(),
            did.into(),
            client_id.into(),
            scope.into(),
            jkt.into(),
            crate::keys::sha256_hex(&access).into(),
            crate::keys::sha256_hex(&refresh).into(),
            exp_iso.into(),
            created.into(),
        ])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok(serde_json::json!({
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "DPoP",
        "expires_in": 7200,
        "scope": scope,
        "sub": did,
    }))
}

// ---------- identity resolution + PLC operations (lexicon-exact) ----------

#[derive(Deserialize)]
struct DidParam {
    #[serde(rename = "did")]
    did: String,
}

/// resolveDid: raw DID document, no bidirectional handle check.
#[worker::send]
async fn resolve_did(State(s): State<IdentityState>, Query(q): Query<DidParam>) -> XrpcResult<Json<serde_json::Value>> {
    if !atproto::did::validate(&q.did) {
        return Err(XrpcError::bad_request("InvalidDid", "bad DID"));
    }
    let doc = crate::identity::fetch_did_doc(&s.env, &q.did).await?;
    Ok(Json(serde_json::json!({ "didDoc": doc })))
}

#[derive(Deserialize)]
struct IdentifierParam {
    #[serde(rename = "identifier")]
    identifier: String,
}

fn identity_info(did: &str, handle: Option<&str>, doc: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "did": did,
        "handle": handle.unwrap_or("handle.invalid"),
        "didDoc": doc,
    })
}

/// resolveIdentity: full identity bundle with bidirectionally verified handle
/// (`handle.invalid` when the check fails).
#[worker::send]
async fn resolve_identity(
    State(s): State<IdentityState>,
    Query(q): Query<IdentifierParam>,
) -> XrpcResult<Json<serde_json::Value>> {
    let id = q.identifier.trim();
    // DID input.
    if id.starts_with("did:") {
        if !atproto::did::validate(id) {
            return Err(XrpcError::bad_request("DidNotFound", "bad DID"));
        }
        let doc = crate::identity::fetch_did_doc(&s.env, id).await
            .map_err(|_| XrpcError::not_found("DidNotFound", "DID not found"))?;
        let parsed = crate::identity::parse_did_doc(&doc, id)
            .map_err(|_| XrpcError::not_found("DidNotFound", "bad DID document"))?;
        let mut verified: Option<String> = None;
        if let Some(claimed) = parsed.handle {
            if crate::identity::handle_is_correct(&s.env, id, &claimed).await {
                verified = Some(claimed);
            }
        }
        return Ok(Json(identity_info(id, verified.as_deref(), &doc)));
    }
    // Handle input.
    if !atproto::handle::validate(id) {
        return Err(XrpcError::not_found("HandleNotFound", "bad handle"));
    }
    // Local accounts first (authoritative, no network needed).
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    #[derive(Deserialize)]
    struct LocalRow {
        did: String,
    }
    let local: Option<LocalRow> = db
        .prepare("SELECT did FROM account WHERE handle = ?1")
        .bind(&[id.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let did = match local {
        Some(r) => r.did,
        None => crate::identity::resolve_handle_to_did(&s.env, id)
            .await?
            .ok_or_else(|| XrpcError::not_found("HandleNotFound", "handle does not resolve"))?,
    };
    let doc = crate::identity::fetch_did_doc(&s.env, &did).await
        .map_err(|_| XrpcError::not_found("DidNotFound", "DID not found"))?;
    let verified = crate::identity::handle_is_correct(&s.env, &did, id).await;
    Ok(Json(identity_info(&did, verified.then_some(id), &doc)))
}

#[derive(Deserialize)]
struct RefreshIdentityReq {
    identifier: String,
}

/// refreshIdentity: drop cached resolution, re-resolve, return the bundle.
#[worker::send]
async fn refresh_identity(
    State(s): State<IdentityState>,
    Json(req): Json<RefreshIdentityReq>,
) -> XrpcResult<Json<serde_json::Value>> {
    let id = req.identifier.trim().to_string();
    // Best-effort cache invalidation (KV keys mirror identity.rs).
    if let Ok(store) = s.env.kv("CACHE") {
        if id.starts_with("did:") {
            let _ = store.delete(&format!("did:doc:{}", crate::keys::sha256_hex(&id))).await;
        } else {
            let _ = store.delete(&format!("handle:did:{id}")).await;
        }
    }
    resolve_identity(State(s), Query(IdentifierParam { identifier: id })).await
}

/// Credentials a migrating account should adopt on THIS service.
#[worker::send]
async fn get_recommended_did_credentials(
    State(s): State<IdentityState>,
    headers: HeaderMap,
) -> XrpcResult<Json<serde_json::Value>> {
    let caller = auth::authenticate(&s.env, &headers, "GET", "/xrpc/com.atproto.identity.getRecommendedDidCredentials").await?;
    let cfg = pds_env::PdsEnv::from_env(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    #[derive(serde::Deserialize)]
    struct KeyRow2 {
        handle: String,
        signing_key_k256_pub_hex: Option<String>,
        rotation_key_k256_priv_hex: Option<String>,
    }
    let row: Option<KeyRow2> = db
        .prepare("SELECT handle, signing_key_k256_pub_hex, rotation_key_k256_priv_hex FROM account WHERE did = ?1")
        .bind(&[caller.did.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let Some(acct) = row else {
        return Err(XrpcError::unauthorized("unknown account"));
    };
    // Rotation recommendation: current rotation key if we hold it.
    let mut rotation_keys = Vec::new();
    if let Some(priv_hex) = acct.rotation_key_k256_priv_hex {
        if let Ok(pub_hex) = crate::keys::k256_pub_from_priv(&priv_hex) {
            if let Ok(dk) = crate::identity::did_key_encode(&pub_hex, &crate::keys::Curve::K256) {
                rotation_keys.push(dk);
            }
        }
    }
    let signing_did_key = acct
        .signing_key_k256_pub_hex
        .and_then(|h| crate::identity::did_key_encode(&h, &crate::keys::Curve::K256).ok());
    Ok(Json(serde_json::json!({
        "rotationKeys": rotation_keys,
        "alsoKnownAs": [format!("at://{}", acct.handle)],
        "verificationMethods": signing_did_key.map(|k| serde_json::json!({ "atproto": k })).unwrap_or(serde_json::json!({})),
        "services": { "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": format!("https://{}", cfg.hostname) } },
    })))
}

// --- PLC operation signing (email-code gated, entryway-style) ---

/// Send the email code that authorizes `signPlcOperation`.
#[worker::send]
async fn request_plc_operation_signature(
    State(s): State<IdentityState>,
    headers: HeaderMap,
) -> XrpcResult<Json<serde_json::Value>> {
    let caller = auth::authenticate(&s.env, &headers, "POST", "/xrpc/com.atproto.identity.requestPlcOperationSignature").await?;
    if !caller.did.starts_with("did:plc:") {
        return Err(XrpcError::bad_request("InvalidDid", "PLC operations need a did:plc"));
    }
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    #[derive(serde::Deserialize)]
    struct ERow3 {
        email: Option<String>,
    }
    let row: Option<ERow3> = db
        .prepare("SELECT email FROM account WHERE did = ?1")
        .bind(&[caller.did.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let email = row.and_then(|r| r.email).unwrap_or_default();
    if email.is_empty() {
        return Err(XrpcError::bad_request("InvalidEmail", "no email on file"));
    }
    let token = issue_plc_token(&s.env, &caller.did).await?;
    let text = format!("Authorize your identity update with this code:\n\n{token}\n\nIt expires in 1 hour.\n");
    crate::email::send_email(&s.env, &email, "Authorize your identity update", &text).await?;
    Ok(Json(serde_json::json!({})))
}

async fn issue_plc_token(env: &worker::Env, did: &str) -> XrpcResult<String> {
    let db = pds_env::db(env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let token = crate::keys::random_b64u32().map_err(|e| XrpcError::internal(e.to_string()))?;
    let now = pds_env::now_iso();
    let exp_ms = worker::Date::now().as_millis() as i64 + 3600 * 1000;
    let exp = format!("{:013}", exp_ms);
    // Reuse email_token with a sortable millis expiry (compared as text).
    // NOTE: other purposes store ISO; plc rows are distinguished by purpose.
    let _ = now;
    db.prepare("INSERT INTO email_token (did, purpose, token_hash, email, expires_at, used_at, created_at) VALUES (?1, 'plc', ?2, '', ?3, NULL, ?4)")
        .bind(&[did.into(), crate::keys::sha256_hex(&token).into(), exp.into(), pds_env::now_iso().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok(token)
}

async fn consume_plc_token(env: &worker::Env, did: &str, token: &str) -> XrpcResult<()> {
    let db = pds_env::db(env).map_err(|e| XrpcError::internal(e.to_string()))?;
    #[derive(serde::Deserialize)]
    struct PlcTokRow {
        did: String,
        expires_at: String,
    }
    let row: Option<PlcTokRow> = db
        .prepare("SELECT did, expires_at FROM email_token WHERE purpose = 'plc' AND token_hash = ?1 AND used_at IS NULL")
        .bind(&[crate::keys::sha256_hex(token).into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let Some(r) = row else {
        return Err(XrpcError::bad_request("InvalidToken", "bad token"));
    };
    if r.did != did {
        return Err(XrpcError::bad_request("InvalidToken", "token mismatch"));
    }
    let now_ms = format!("{:013}", worker::Date::now().as_millis() as i64);
    if r.expires_at <= now_ms {
        return Err(XrpcError::bad_request("InvalidToken", "token expired"));
    }
    db.prepare("UPDATE email_token SET used_at = ?1 WHERE purpose = 'plc' AND token_hash = ?2")
        .bind(&[pds_env::now_iso().into(), crate::keys::sha256_hex(token).into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok(())
}

#[derive(serde::Deserialize)]
struct SignPlcOperationReq {
    #[serde(default)]
    token: Option<String>,
    #[serde(default, rename = "rotationKeys")]
    rotation_keys: Option<Vec<String>>,
    #[serde(default, rename = "alsoKnownAs")]
    also_known_as: Option<Vec<String>>,
    #[serde(default, rename = "verificationMethods")]
    verification_methods: Option<serde_json::Value>,
    #[serde(default)]
    services: Option<serde_json::Value>,
}

/// Sign a PLC update for the caller's DID (email-code gated). Returns the
/// signed operation; submit it via `submitPlcOperation` (or elsewhere).
#[worker::send]
async fn sign_plc_operation(
    State(s): State<IdentityState>,
    headers: HeaderMap,
    Json(req): Json<SignPlcOperationReq>,
) -> XrpcResult<Json<serde_json::Value>> {
    let caller = auth::authenticate(&s.env, &headers, "POST", "/xrpc/com.atproto.identity.signPlcOperation").await?;
    if !caller.did.starts_with("did:plc:") || caller.did.starts_with("did:plc:dev") {
        return Err(XrpcError::bad_request("InvalidDid", "PLC operations need a registered did:plc"));
    }
    let token = req.token.as_deref().ok_or_else(|| XrpcError::bad_request("InvalidToken", "email token required"))?;
    consume_plc_token(&s.env, &caller.did, token).await?;
    if req.rotation_keys.is_none()
        && req.also_known_as.is_none()
        && req.verification_methods.is_none()
        && req.services.is_none()
    {
        return Err(XrpcError::bad_request("InvalidRequest", "nothing to update"));
    }
    let current = crate::identity::plc_current(&s.env, &caller.did)
        .await
        .map_err(|e| XrpcError::new(axum::http::StatusCode::BAD_GATEWAY, "PlcError", e.to_string()))?;
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    #[derive(serde::Deserialize)]
    struct RotRow {
        rotation_key_k256_priv_hex: Option<String>,
    }
    let row: Option<RotRow> = db
        .prepare("SELECT rotation_key_k256_priv_hex FROM account WHERE did = ?1")
        .bind(&[caller.did.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let rot_priv = row.and_then(|r| r.rotation_key_k256_priv_hex).unwrap_or_default();
    if rot_priv.is_empty() {
        return Err(XrpcError::bad_request("InvalidRequest", "no rotation key held; rotate externally"));
    }
    let op = crate::identity::plc_update_op(
        &rot_priv,
        &current,
        &crate::identity::PlcChanges {
            rotation_keys: req.rotation_keys,
            verification_methods: req.verification_methods,
            also_known_as: req.also_known_as,
            services: req.services,
        },
    )
    .map_err(XrpcError::internal)?;
    Ok(Json(serde_json::json!({ "operation": op })))
}

#[derive(serde::Deserialize)]
struct SubmitPlcOperationReq {
    operation: serde_json::Value,
}

/// Validate a PLC op against service constraints, then submit it to the
/// directory. Migration-away (PDS endpoint leaves us) deactivates the local
/// account; handle changes update it — both with firehose events.
#[worker::send]
async fn submit_plc_operation(
    State(s): State<IdentityState>,
    headers: HeaderMap,
    Json(req): Json<SubmitPlcOperationReq>,
) -> XrpcResult<Json<serde_json::Value>> {
    let caller = auth::authenticate(&s.env, &headers, "POST", "/xrpc/com.atproto.identity.submitPlcOperation").await?;
    let op = &req.operation;
    if op.get("type").and_then(|v| v.as_str()) != Some("plc_operation") {
        return Err(XrpcError::bad_request("InvalidRequest", "only plc_operation supported here"));
    }
    if op.get("prev").is_none() {
        return Err(XrpcError::bad_request("InvalidRequest", "update ops need prev"));
    }
    // Constraint: alsoKnownAs handles must be valid; services keep shape.
    if let Some(aka) = op.get("alsoKnownAs").and_then(|v| v.as_array()) {
        for h in aka {
            let uri = h.as_str().unwrap_or("");
            let handle = uri.strip_prefix("at://").unwrap_or("");
            if !atproto::handle::validate(handle) {
                return Err(XrpcError::bad_request("InvalidRequest", "bad handle in alsoKnownAs"));
            }
        }
    }
    // Must be signed by one of the CURRENT rotation keys (anti-takeover).
    let current = crate::identity::plc_current(&s.env, &caller.did)
        .await
        .map_err(|e| XrpcError::new(axum::http::StatusCode::BAD_GATEWAY, "PlcError", e.to_string()))?;
    crate::identity::verify_plc_op(op, &current.fields.rotation_keys)
        .map_err(|e| XrpcError::bad_request("InvalidRequest", e))?;
    crate::identity::plc_submit(&s.env, &caller.did, op).await?;
    // Directory state changed: drop cached resolution so reads go fresh.
    if let Ok(store) = s.env.kv("CACHE") {
        let _ = store.delete(&format!("did:doc:{}", crate::keys::sha256_hex(&caller.did))).await;
    }
    // Post-submit local reconciliation.
    let cfg = pds_env::PdsEnv::from_env(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let our_endpoint = format!("https://{}", cfg.hostname);
    let new_endpoint = op
        .get("services")
        .and_then(|v| v.get("atproto_pds"))
        .and_then(|v| v.get("endpoint"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    if !new_endpoint.is_empty() && new_endpoint != our_endpoint {
        // Migrated away: deactivate locally so relays stop pulling from us.
        let now = pds_env::now_iso();
        db.prepare("UPDATE account SET active = 0, status = 'deactivated', updated_at = ?1 WHERE did = ?2")
            .bind(&[now.into(), caller.did.clone().into()])
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .run()
            .await
            .map_err(|e| XrpcError::internal(e.to_string()))?;
        crate::firehose::emit_account(&s.env, &caller.did, false, Some("deactivated")).await?;
    }
    if let Some(first) = op.get("alsoKnownAs").and_then(|v| v.as_array()).and_then(|a| a.first()).and_then(|h| h.as_str()) {
        if let Some(handle) = first.strip_prefix("at://") {
            if atproto::handle::validate(handle) {
                let now = pds_env::now_iso();
                db.prepare("UPDATE account SET handle = ?1, updated_at = ?2 WHERE did = ?3")
                    .bind(&[handle.into(), now.into(), caller.did.clone().into()])
                    .map_err(|e| XrpcError::internal(e.to_string()))?
                    .run()
                    .await
                    .map_err(|e| XrpcError::internal(e.to_string()))?;
                crate::firehose::emit_identity(&s.env, &caller.did, Some(handle)).await?;
            }
        }
    }
    Ok(Json(serde_json::json!({})))
}

