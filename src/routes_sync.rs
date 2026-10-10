//! `com.atproto.sync.*` — repo export, status, firehose cursor API.
//! Spec: /specs/sync. WebSocket `subscribeRepos` is served as a
//! poll-compatible JSON view (Workers WS upgrade staged in ROADMAP).

use axum::{extract::{Query, State}, http::HeaderMap, Json};
use axum::routing::{get, post};
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
        .route("/xrpc/com.atproto.sync.getCheckout", get(get_repo))
        .route("/xrpc/com.atproto.sync.getHead", get(get_head))
        .route("/xrpc/com.atproto.sync.getBlocks", get(get_blocks))
        .route("/xrpc/com.atproto.sync.getRecord", get(get_record_sync))
        // NOTE: listBlobs/getBlob live in blob_router (R2-backed). Do not re-register here.
        .route("/xrpc/com.atproto.sync.subscribeRepos", get(subscribe_repos))
        .route("/xrpc/com.atproto.sync.requestCrawl", post(request_crawl))
        .route("/xrpc/com.atproto.sync.getLatestCommit", get(get_latest_commit))
        .route("/xrpc/com.atproto.sync.listReposByCollection", get(list_repos_by_collection))
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
async fn get_repo(State(s): State<SyncState>, Query(q): Query<DidParam>) -> XrpcResult<axum::response::Response> {
    crate::repo::require_active_for_sync(&s.env, &q.did).await?;
    let exp = crate::repo::export_repo(&s.env, &q.did).await?;
    use axum::response::IntoResponse;
    Ok(([(axum::http::header::CONTENT_TYPE, "application/vnd.ipld.car")], exp.car).into_response())
}

#[derive(Deserialize)]
struct GetBlocksParam {
    #[serde(rename = "did")]
    did: String,
    #[serde(rename = "cids", deserialize_with = "string_or_seq")]
    cids: Vec<String>,
}

/// Accept `?cids=a&cids=b`, a single `?cids=a`, or comma-joined `?cids=a,b`.
fn string_or_seq<'de, D>(d: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct V;
    impl<'de> serde::de::Visitor<'de> for V {
        type Value = Vec<String>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("string or sequence of strings")
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Vec<String>, E> {
            Ok(vec![v.to_string()])
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<String>, A::Error> {
            let mut out = Vec::new();
            while let Some(s) = seq.next_element::<String>()? {
                out.push(s);
            }
            Ok(out)
        }
    }
    d.deserialize_any(V)
}

#[worker::send]
async fn get_blocks(State(s): State<SyncState>, Query(q): Query<GetBlocksParam>) -> XrpcResult<axum::response::Response> {
    // Accept repeated `?cids=` params; also tolerate a single comma-joined value.
    let mut wanted: Vec<String> = Vec::new();
    for raw in &q.cids {
        for part in raw.split(',') {
            let part = part.trim();
            if !part.is_empty() {
                wanted.push(part.to_string());
            }
        }
    }
    if wanted.is_empty() {
        return Err(XrpcError::bad_request("InvalidRequest", "cids required"));
    }
    if wanted.len() > 500 {
        return Err(XrpcError::bad_request("InvalidRequest", "too many cids"));
    }
    crate::repo::require_active_for_sync(&s.env, &q.did).await?;
    let exp = crate::repo::export_repo(&s.env, &q.did).await?;
    // Re-split commit/MST/record blocks from the full export CAR.
    let (_, blocks) = crate::mst::parse_car(&exp.car).map_err(|e| XrpcError::internal(e.to_string()))?;
    let mut out_blocks = Vec::new();
    for w in &wanted {
        let Some(found) = blocks.iter().find(|(c, _)| &c.to_string() == w) else {
            return Err(XrpcError::not_found("BlockNotFound", format!("block not found: {w}")));
        };
        out_blocks.push(found.clone());
    }
    let car = crate::mst::build_car(&exp.commit, &out_blocks);
    use axum::response::IntoResponse;
    Ok(([(axum::http::header::CONTENT_TYPE, "application/vnd.ipld.car")], car).into_response())
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
    crate::repo::require_active_for_sync(&s.env, &q.did).await?;
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let row: Option<ValRow> = db.prepare("SELECT cid, value_json AS v FROM record WHERE did = ?1 AND collection = ?2 AND rkey = ?3 AND takendown = 0")
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
    #[derive(Deserialize)]
    struct RootLite {
        rev: String,
        #[serde(rename = "commit_cid")]
        commit_cid: String,
    }
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let root: Option<RootLite> = db.prepare("SELECT rev, commit_cid FROM repo_root WHERE did = ?1")
        .bind(&[q.did.clone().into()]).map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None).await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let Some(r) = root else { return Err(XrpcError::not_found("RepoNotFound", "no repo root")); };
    Ok(Json(serde_json::json!({"cid": r.commit_cid, "rev": r.rev})))
}

// ---------- requestCrawl ----------

#[derive(serde::Deserialize)]
struct CrawlReq {
    #[serde(rename = "hostname")]
    hostname: String,
}

/// Ask this PDS to announce itself to its configured crawlers/relays
/// (`PDS_CRAWLERS`). Called automatically on account creation; relays and
/// admins can re-trigger it here (authenticated to avoid amplification).
#[worker::send]
async fn request_crawl(
    State(s): State<SyncState>,
    headers: HeaderMap,
    Json(req): Json<CrawlReq>,
) -> XrpcResult<Json<serde_json::Value>> {
    let cfg = pds_env::PdsEnv::from_env(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    // Any authenticated caller may trigger; the announcement always names
    // OUR hostname, so this cannot be abused to crawl third parties... unless
    // the caller passes another hostname — pin to our own.
    let _ = crate::auth::authenticate(&s.env, &headers, "POST", "/xrpc/com.atproto.sync.requestCrawl").await?;
    if req.hostname != cfg.hostname {
        return Err(XrpcError::bad_request("InvalidHostname", "can only announce our own hostname"));
    }
    let notified = notify_crawlers(&s.env, &cfg).await;
    Ok(Json(serde_json::json!({ "notified": notified })))
}

/// Best-effort announce to every configured crawler. Returns hosts that
/// accepted (2xx). Failures are swallowed (logged by the platform).
pub async fn notify_crawlers(_env: &worker::Env, cfg: &pds_env::PdsEnv) -> Vec<String> {
    use worker::{Fetch, Method, Request, RequestInit};
    let mut ok = Vec::new();
    let crawlers: Vec<&str> = cfg
        .crawlers
        .split([',', ' ', '\n'])
        .map(|s| s.trim().trim_end_matches('/'))
        .filter(|s| !s.is_empty())
        .collect();
    for crawler in crawlers {
        let url = format!("{crawler}/xrpc/com.atproto.sync.requestCrawl?hostname={}", cfg.hostname);
        let mut init = RequestInit::new();
        init.with_method(Method::Get);
        let req = match Request::new_with_init(&url, &init) {
            Ok(r) => r,
            Err(_) => continue,
        };
        match Fetch::Request(req).send().await {
            Ok(resp) if (200..300).contains(&resp.status_code()) => ok.push(crawler.to_string()),
            _ => {}
        }
    }
    ok
}

// ---------- listReposByCollection ----------

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct ByCollectionParam {
    #[serde(rename = "collection")]
    collection: String,
    #[serde(rename = "limit")]
    limit: Option<i64>,
    #[serde(rename = "cursor")]
    cursor: Option<String>,
}

/// DIDs holding at least one record in `collection` (record-level resync
/// bootstrap). Cursor is a DID offset; empty cursor omits.
#[worker::send]
async fn list_repos_by_collection(
    State(s): State<SyncState>,
    Query(q): Query<ByCollectionParam>,
) -> XrpcResult<Json<serde_json::Value>> {
    if !crate::atproto::nsid::validate(&q.collection) {
        return Err(XrpcError::bad_request("InvalidNsid", "bad collection"));
    }
    let limit = q.limit.unwrap_or(500).clamp(1, 1000);
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let rows = if let Some(cur) = q.cursor.clone() {
        db.prepare("SELECT DISTINCT did AS d FROM record WHERE collection = ?1 AND did > ?2 ORDER BY did ASC LIMIT ?3")
            .bind(&[q.collection.clone().into(), cur.into(), (limit as f64).into()])
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .all().await.map_err(|e| XrpcError::internal(e.to_string()))?
    } else {
        db.prepare("SELECT DISTINCT did AS d FROM record WHERE collection = ?1 ORDER BY did ASC LIMIT ?2")
            .bind(&[q.collection.clone().into(), (limit as f64).into()])
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .all().await.map_err(|e| XrpcError::internal(e.to_string()))?
    };
    #[derive(serde::Deserialize)]
    struct DidLite {
        d: String,
    }
    let mut repos = Vec::new();
    let mut last: Option<String> = None;
    for r in rows.results::<DidLite>().unwrap_or_default() {
        repos.push(serde_json::json!({ "did": r.d }));
        last = Some(r.d);
    }
    let mut out = serde_json::json!({ "repos": repos });
    if repos.len() as i64 == limit {
        if let Some(c) = last {
            out["cursor"] = serde_json::Value::String(c);
        }
    }
    Ok(Json(out))
}

/// Deprecated alias target: current head commit root CID.
#[worker::send]
async fn get_head(State(s): State<SyncState>, Query(q): Query<DidParam>) -> XrpcResult<Json<serde_json::Value>> {
    crate::repo::require_active_for_sync(&s.env, &q.did).await
        .map_err(|_| XrpcError::not_found("HeadNotFound", "no head for this repo"))?;
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    #[derive(serde::Deserialize)]
    struct RootRow {
        commit_cid: String,
    }
    let row: Option<RootRow> = db
        .prepare("SELECT commit_cid FROM repo_root WHERE did = ?1")
        .bind(&[q.did.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    match row {
        Some(r) => Ok(Json(serde_json::json!({ "root": r.commit_cid }))),
        None => Err(XrpcError::not_found("HeadNotFound", "no head for this repo")),
    }
}
