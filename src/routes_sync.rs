//! `com.atproto.sync.*` — repo export, status, firehose cursor API.
//! Spec: /specs/sync. WebSocket `subscribeRepos` is served as a
//! poll-compatible JSON view (Workers WS upgrade staged in ROADMAP).

use axum::{extract::{Query, State}, Json};
use axum::routing::get;
use axum::Router;
use serde::{Deserialize, Serialize};
use worker::Env;

use crate::{pds_env, xrpc::{XrpcError, XrpcResult}};

#[derive(Clone)]
pub struct SyncState {
    pub env: Env,
}

pub fn router(env: Env) -> Router {
    Router::new()
        .route("/xrpc/com.atproto.sync.getRepoStatus", get(get_repo_status))
        .route("/xrpc/com.atproto.sync.listRepos", get(list_repos))
        .route("/xrpc/com.atproto.sync.getRepo", get(get_repo))
        .route("/xrpc/com.atproto.sync.getBlocks", get(get_blocks))
        .route("/xrpc/com.atproto.sync.getRecord", get(get_record_sync))
        // NOTE: listBlobs/getBlob live in blob_router (R2-backed). Do not re-register here.
        .route("/xrpc/com.atproto.sync.subscribeRepos", get(subscribe_repos))
        .route("/xrpc/com.atproto.sync.getLatestCommit", get(get_latest_commit))
        .with_state(SyncState { env })
}

#[derive(Deserialize)]
struct DidParam {
    #[serde(rename = "did")]
    did: String,
}

#[derive(Serialize)]
struct RepoStatus {
    #[serde(rename = "did")]
    did: String,
    #[serde(rename = "active")]
    active: bool,
    #[serde(rename = "status")]
    status: Option<String>,
    #[serde(rename = "rev")]
    rev: Option<String>,
}

#[worker::send]
async fn get_repo_status(State(s): State<SyncState>, Query(q): Query<DidParam>) -> XrpcResult<Json<RepoStatus>> {
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let acct: Option<AcctStatus> = db.prepare("SELECT status, active FROM account WHERE did = ?1")
        .bind(&[q.did.clone().into()]).map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None).await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let Some(a) = acct else { return Err(XrpcError::not_found("RepoNotFound", "unknown account")); };
    let root: Option<RootRow> = db.prepare("SELECT rev FROM repo_root WHERE did = ?1")
        .bind(&[q.did.clone().into()]).map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None).await.map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok(Json(RepoStatus {
        did: q.did,
        active: a.active == 1,
        status: Some(a.status),
        rev: root.map(|r| r.rev),
    }))
}

#[derive(Deserialize)]
struct AcctStatus {
    status: String,
    active: i64,
}

#[derive(Deserialize)]
struct RootRow {
    rev: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ListParam {
    #[serde(rename = "limit")]
    limit: Option<i64>,
    #[serde(rename = "cursor")]
    cursor: Option<String>,
}

#[worker::send]
async fn list_repos(State(s): State<SyncState>, Query(q): Query<ListParam>) -> XrpcResult<Json<serde_json::Value>> {
    let limit = q.limit.unwrap_or(500).clamp(1, 1000);
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let rows = db.prepare("SELECT a.did AS did, a.handle AS handle, a.active AS active, r.rev AS rev FROM account a LEFT JOIN repo_root r ON r.did = a.did ORDER BY a.created_at ASC LIMIT ?1")
        .bind(&[(limit as f64).into()]).map_err(|e| XrpcError::internal(e.to_string()))?
        .all().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let mut repos = Vec::new();
    for r in rows.results::<ListRow>().unwrap_or_default() {
        repos.push(serde_json::json!({"did": r.did, "handle": r.handle, "active": r.active == 1, "rev": r.rev, "status": if r.active == 1 { "active" } else { "deactivated" }}));
    }
    Ok(Json(serde_json::json!({ "repos": repos })))
}

#[derive(Deserialize)]
struct ListRow {
    did: String,
    handle: String,
    active: i64,
    rev: Option<String>,
}

#[worker::send]
async fn get_repo(State(s): State<SyncState>, Query(q): Query<DidParam>) -> XrpcResult<Json<serde_json::Value>> {
    // MVP returns a JSON diagnostic; binary CAR (`application/vnd.ipld.car`)
    // export is staged (see ROADMAP) to keep R2/D1 framing exact.
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let root: Option<FullRoot> = db.prepare("SELECT rev, data_cid AS data_cid, commit_cid AS commit_cid FROM repo_root WHERE did = ?1")
        .bind(&[q.did.clone().into()]).map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None).await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let Some(root) = root else { return Err(XrpcError::not_found("RepoNotFound", "no repo root")); };
    let recs = db.prepare("SELECT collection, rkey, cid FROM record WHERE did = ?1 ORDER BY collection, rkey")
        .bind(&[q.did.clone().into()]).map_err(|e| XrpcError::internal(e.to_string()))?
        .all().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let mut paths = Vec::new();
    for r in recs.results::<RecLite>().unwrap_or_default() {
        paths.push(format!("{}/{}:{}", r.collection, r.rkey, r.cid));
    }
    Ok(Json(serde_json::json!({
        "did": q.did, "rev": root.rev, "data": root.data_cid, "commit": root.commit_cid,
        "paths": paths,
        "note": "binary CAR export staged; consume listRecords + getRecord until then",
    })))
}

#[derive(Deserialize)]
struct FullRoot {
    rev: String,
    data_cid: String,
    commit_cid: String,
}

#[derive(Deserialize)]
struct RecLite {
    collection: String,
    rkey: String,
    cid: String,
}

#[worker::send]
async fn get_blocks() -> XrpcError {
    XrpcError::not_implemented("getBlocks binary CAR framing staged (see ROADMAP)")
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct SyncRecordParam {
    #[serde(rename = "did")]
    did: String,
    #[serde(rename = "collection")]
    collection: String,
    #[serde(rename = "rkey")]
    rkey: String,
}

#[worker::send]
async fn get_record_sync(State(s): State<SyncState>, Query(q): Query<SyncRecordParam>) -> XrpcResult<Json<serde_json::Value>> {
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let row: Option<ValRow> = db.prepare("SELECT cid, value_json AS v FROM record WHERE did = ?1 AND collection = ?2 AND rkey = ?3")
        .bind(&[q.did.clone().into(), q.collection.clone().into(), q.rkey.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None).await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let Some(r) = row else { return Err(XrpcError::not_found("RecordNotFound", "not found")); };
    Ok(Json(serde_json::json!({"uri": format!("at://{}/{}/{}", q.did, q.collection, q.rkey), "cid": r.cid, "value": serde_json::from_str::<serde_json::Value>(&r.v).unwrap_or_default()})))
}

#[derive(Deserialize)]
struct ValRow {
    cid: String,
    v: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct SubParam {
    #[serde(rename = "cursor")]
    cursor: Option<i64>,
    #[serde(rename = "limit")]
    limit: Option<i64>,
}

/// Poll-compatible view of `subscribeRepos`: returns events after `cursor`.
/// Workers WebSocket upgrade for the true firehose is staged (ROADMAP).
#[worker::send]
async fn subscribe_repos(State(s): State<SyncState>, Query(q): Query<SubParam>) -> XrpcResult<Json<serde_json::Value>> {
    let cursor = q.cursor.unwrap_or(0);
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let rows = db.prepare("SELECT seq, payload_json AS p FROM firehose_event WHERE seq > ?1 ORDER BY seq ASC LIMIT ?2")
        .bind(&[(cursor as f64).into(), (limit as f64).into()]).map_err(|e| XrpcError::internal(e.to_string()))?
        .all().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let mut events = Vec::new();
    let mut last = cursor;
    for r in rows.results::<EvRow>().unwrap_or_default() {
        last = r.seq;
        events.push(serde_json::from_str::<serde_json::Value>(&r.p).unwrap_or_default());
    }
    Ok(Json(serde_json::json!({ "cursor": last, "events": events, "transport": "poll; websocket staged" })))
}

#[derive(Deserialize)]
struct EvRow {
    seq: i64,
    p: String,
}

#[worker::send]
async fn get_latest_commit(State(s): State<SyncState>, Query(q): Query<DidParam>) -> XrpcResult<Json<serde_json::Value>> {
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let root: Option<FullRoot> = db.prepare("SELECT rev, data_cid AS data_cid, commit_cid AS commit_cid FROM repo_root WHERE did = ?1")
        .bind(&[q.did.clone().into()]).map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None).await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let Some(r) = root else { return Err(XrpcError::not_found("RepoNotFound", "no repo root")); };
    Ok(Json(serde_json::json!({"cid": r.commit_cid, "rev": r.rev})))
}
