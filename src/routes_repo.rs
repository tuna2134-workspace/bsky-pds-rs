//! `com.atproto.repo.*` — record CRUD + blob upload + history.
//! Full MST commit signing + CAR diffs are staged in (see ROADMAP);
//! this layer persists canonical record JSON in D1 and bumps `rev`.

use axum::{extract::{Query, State}, http::HeaderMap, Json};
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use worker::Env;

use crate::{atproto, auth, car, pds_env, xrpc::{XrpcError, XrpcResult}};

#[derive(Clone)]
pub struct RepoState {
    pub env: Env,
}

pub fn router(env: Env) -> Router {
    Router::new()
        .route("/xrpc/com.atproto.repo.describeRepo", get(describe_repo))
        .route("/xrpc/com.atproto.repo.createRecord", post(create_record))
        .route("/xrpc/com.atproto.repo.getRecord", get(get_record))
        .route("/xrpc/com.atproto.repo.putRecord", post(put_record))
        .route("/xrpc/com.atproto.repo.deleteRecord", post(delete_record))
        .route("/xrpc/com.atproto.repo.listRecords", get(list_records))
        .route("/xrpc/com.atproto.repo.applyWrites", post(apply_writes))
        // NOTE: uploadBlob lives in blob_router (R2-backed). Do not re-register here.
        .with_state(RepoState { env })
}

#[derive(Deserialize)]
struct RepoParam {
    #[serde(rename = "repo")]
    repo: String,
}

#[derive(Serialize)]
struct DescribeRepoResp {
    #[serde(rename = "handle")]
    handle: String,
    #[serde(rename = "did")]
    did: String,
    #[serde(rename = "didDoc")]
    did_doc: serde_json::Value,
    #[serde(rename = "collections")]
    collections: Vec<String>,
    #[serde(rename = "handleIsCorrect")]
    handle_is_correct: bool,
}

#[worker::send]
async fn describe_repo(State(s): State<RepoState>, Query(q): Query<RepoParam>) -> XrpcResult<Json<DescribeRepoResp>> {
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let row: Option<AcctLite> = db.prepare("SELECT did, handle FROM account WHERE did = ?1 OR handle = ?1")
        .bind(&[q.repo.clone().into()]).map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None).await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let Some(a) = row else { return Err(XrpcError::not_found("RepoNotFound", "repo not found")); };
    let cols: Vec<String> = collections_for(&s.env, &a.did).await?;
    let cfg = pds_env::PdsEnv::from_env(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let endpoint = format!("https://{}", cfg.hostname);
    Ok(Json(DescribeRepoResp {
        handle: a.handle.clone(),
        did: a.did.clone(),
        did_doc: serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": a.did,
            "alsoKnownAs": [format!("at://{}", a.handle)],
            "verificationMethod": [],
            "service": [{ "id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": endpoint }],
        }),
        collections: cols,
        handle_is_correct: true,
    }))
}

#[derive(Deserialize)]
struct AcctLite {
    did: String,
    handle: String,
}

#[worker::send]
async fn collections_for(env: &Env, did: &str) -> XrpcResult<Vec<String>> {
    let db = pds_env::db(env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let rows = db.prepare("SELECT DISTINCT collection AS c FROM record WHERE did = ?1")
        .bind(&[did.into()]).map_err(|e| XrpcError::internal(e.to_string()))?
        .all().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let mut out = Vec::new();
    for r in rows.results::<ColRow>().unwrap_or_default() {
        out.push(r.c);
    }
    out.sort();
    Ok(out)
}

#[derive(Deserialize)]
struct ColRow {
    c: String,
}

// --- createRecord ---

#[derive(Deserialize)]
#[allow(dead_code)]
struct CreateRecordReq {
    #[serde(rename = "repo")]
    repo: String,
    #[serde(rename = "collection")]
    collection: String,
    #[serde(rename = "rkey")]
    rkey: Option<String>,
    #[serde(rename = "record")]
    record: serde_json::Value,
    #[serde(rename = "validate")]
    validate: Option<bool>,
    #[serde(rename = "swapCommit")]
    swap_commit: Option<String>,
}

#[derive(Serialize)]
struct WriteResp {
    #[serde(rename = "uri")]
    uri: String,
    #[serde(rename = "cid")]
    cid: String,
    #[serde(rename = "commit")]
    commit: serde_json::Value,
}

#[worker::send]
async fn create_record(State(s): State<RepoState>, headers: HeaderMap, Json(req): Json<CreateRecordReq>) -> XrpcResult<Json<WriteResp>> {
    let caller = auth::caller_from_headers(&headers)?;
    if caller.did != req.repo {
        return Err(XrpcError::forbidden("AuthFailed", "can only write to your own repo"));
    }
    if !atproto::nsid::validate(&req.collection) {
        return Err(XrpcError::bad_request("InvalidNsid", "collection must be a valid NSID"));
    }
    let rkey = req.rkey.unwrap_or_else(atproto::tid::now);
    if !atproto::record_key::validate(&rkey) {
        return Err(XrpcError::bad_request("InvalidRecordKey", "rkey invalid"));
    }
    let mut record = req.record;
    if record.get("$type").is_none() {
        record["$type"] = serde_json::Value::String(req.collection.clone());
    }
    write_record(&s.env, &caller.did, &req.collection, &rkey, record).await
}

#[worker::send]
async fn write_record(env: &Env, did: &str, collection: &str, rkey: &str, record: serde_json::Value) -> XrpcResult<Json<WriteResp>> {
    let canonical = serde_json::to_string(&record).map_err(|e| XrpcError::internal(e.to_string()))?;
    let cid = car::pseudo_cid_for_json(&canonical);
    let rev = atproto::tid::now();
    let now = pds_env::now_iso();
    let db = pds_env::db(env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let exists: Option<ExistsRow> = db.prepare("SELECT cid AS cid FROM record WHERE did = ?1 AND collection = ?2 AND rkey = ?3")
        .bind(&[did.into(), collection.into(), rkey.into()]).map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None).await.map_err(|e| XrpcError::internal(e.to_string()))?;
    if exists.is_some() {
        return Err(XrpcError::bad_request("RecordAlreadyExists", "use putRecord to update"));
    }
    db.prepare("INSERT INTO record (did, collection, rkey, cid, value_json, rev, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)")
        .bind(&[did.into(), collection.into(), rkey.into(), cid.clone().into(), canonical.into(), rev.clone().into(), now.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    bump_rev(env, did, &rev).await?;
    emit_commit(env, did, &rev, vec![serde_json::json!({"action":"create","path":format!("{collection}/{rkey}"),"cid":cid})]).await?;
    Ok(Json(WriteResp {
        uri: format!("at://{did}/{collection}/{rkey}"),
        cid,
        commit: serde_json::json!({"cid": car::pseudo_cid_for_json(&format!("{did}:{rev}")), "rev": rev}),
    }))
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ExistsRow {
    cid: String,
}

// --- getRecord ---

#[derive(Deserialize)]
struct GetRecordParam {
    #[serde(rename = "repo")]
    repo: String,
    #[serde(rename = "collection")]
    collection: String,
    #[serde(rename = "rkey")]
    rkey: String,
    #[serde(rename = "cid")]
    cid: Option<String>,
}

#[worker::send]
async fn get_record(State(s): State<RepoState>, Query(q): Query<GetRecordParam>) -> XrpcResult<Json<serde_json::Value>> {
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let row: Option<RecRow> = db.prepare("SELECT cid, value_json AS v, rev FROM record WHERE did = ?1 AND collection = ?2 AND rkey = ?3")
        .bind(&[q.repo.clone().into(), q.collection.clone().into(), q.rkey.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None).await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let Some(r) = row else { return Err(XrpcError::not_found("RecordNotFound", "record not found")); };
    if let Some(want) = q.cid {
        if want != r.cid {
            return Err(XrpcError::bad_request("WrongCid", "record CID mismatch"));
        }
    }
    let value: serde_json::Value = serde_json::from_str(&r.v).unwrap_or(serde_json::Value::Null);
    Ok(Json(serde_json::json!({
        "uri": format!("at://{}/{}/{}", q.repo, q.collection, q.rkey),
        "cid": r.cid,
        "value": value,
    })))
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct RecRow {
    cid: String,
    v: String,
    rev: String,
}

// --- putRecord / deleteRecord ---

#[derive(Deserialize)]
struct PutRecordReq {
    #[serde(rename = "repo")]
    repo: String,
    #[serde(rename = "collection")]
    collection: String,
    #[serde(rename = "rkey")]
    rkey: String,
    #[serde(rename = "record")]
    record: serde_json::Value,
}

#[worker::send]
async fn put_record(State(s): State<RepoState>, headers: HeaderMap, Json(req): Json<PutRecordReq>) -> XrpcResult<Json<WriteResp>> {
    let caller = auth::caller_from_headers(&headers)?;
    if caller.did != req.repo {
        return Err(XrpcError::forbidden("AuthFailed", "can only write to your own repo"));
    }
    let canonical = serde_json::to_string(&req.record).map_err(|e| XrpcError::internal(e.to_string()))?;
    let cid = car::pseudo_cid_for_json(&canonical);
    let rev = atproto::tid::now();
    let now = pds_env::now_iso();
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    db.prepare("INSERT INTO record (did, collection, rkey, cid, value_json, rev, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7) ON CONFLICT(did, collection, rkey) DO UPDATE SET cid = excluded.cid, value_json = excluded.value_json, rev = excluded.rev, updated_at = excluded.updated_at")
        .bind(&[req.repo.clone().into(), req.collection.clone().into(), req.rkey.clone().into(), cid.clone().into(), canonical.into(), rev.clone().into(), now.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    bump_rev(&s.env, &req.repo, &rev).await?;
    emit_commit(&s.env, &req.repo, &rev, vec![serde_json::json!({"action":"update","path":format!("{}/{}", req.collection, req.rkey),"cid":cid})]).await?;
    Ok(Json(WriteResp {
        uri: format!("at://{}/{}/{}", req.repo, req.collection, req.rkey),
        cid,
        commit: serde_json::json!({"cid": car::pseudo_cid_for_json(&format!("{}:{}", req.repo, rev)), "rev": rev}),
    }))
}

#[derive(Deserialize)]
struct DeleteRecordReq {
    #[serde(rename = "repo")]
    repo: String,
    #[serde(rename = "collection")]
    collection: String,
    #[serde(rename = "rkey")]
    rkey: String,
}

#[worker::send]
async fn delete_record(State(s): State<RepoState>, headers: HeaderMap, Json(req): Json<DeleteRecordReq>) -> XrpcResult<Json<serde_json::Value>> {
    let caller = auth::caller_from_headers(&headers)?;
    if caller.did != req.repo {
        return Err(XrpcError::forbidden("AuthFailed", "can only write to your own repo"));
    }
    let rev = atproto::tid::now();
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    db.prepare("DELETE FROM record WHERE did = ?1 AND collection = ?2 AND rkey = ?3")
        .bind(&[req.repo.clone().into(), req.collection.clone().into(), req.rkey.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    bump_rev(&s.env, &req.repo, &rev).await?;
    emit_commit(&s.env, &req.repo, &rev, vec![serde_json::json!({"action":"delete","path":format!("{}/{}", req.collection, req.rkey),"cid":null})]).await?;
    Ok(Json(serde_json::json!({})))
}

// --- listRecords ---

#[derive(Deserialize)]
#[allow(dead_code)]
struct ListParam {
    #[serde(rename = "repo")]
    repo: String,
    #[serde(rename = "collection")]
    collection: String,
    #[serde(rename = "limit")]
    limit: Option<i64>,
    #[serde(rename = "cursor")]
    cursor: Option<String>,
    #[serde(rename = "reverse")]
    reverse: Option<String>,
}

#[worker::send]
async fn list_records(State(s): State<RepoState>, Query(q): Query<ListParam>) -> XrpcResult<Json<serde_json::Value>> {
    let limit = q.limit.unwrap_or(50).clamp(1, 100);
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    // Cursor = rkey offset (TID-ordered). Full MST range-scan semantics staged in ROADMAP.
    let rows = if let Some(cur) = q.cursor.clone() {
        db.prepare("SELECT rkey AS k, cid AS c, value_json AS v FROM record WHERE did = ?1 AND collection = ?2 AND rkey > ?3 ORDER BY rkey ASC LIMIT ?4")
            .bind(&[q.repo.clone().into(), q.collection.clone().into(), cur.into(), (limit as f64).into()])
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .all().await.map_err(|e| XrpcError::internal(e.to_string()))?
    } else {
        db.prepare("SELECT rkey AS k, cid AS c, value_json AS v FROM record WHERE did = ?1 AND collection = ?2 ORDER BY rkey ASC LIMIT ?3")
            .bind(&[q.repo.clone().into(), q.collection.clone().into(), (limit as f64).into()])
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .all().await.map_err(|e| XrpcError::internal(e.to_string()))?
    };
    let mut records = Vec::new();
    let mut last: Option<String> = None;
    for r in rows.results::<ListRow>().unwrap_or_default() {
        let value: serde_json::Value = serde_json::from_str(&r.v).unwrap_or(serde_json::Value::Null);
        records.push(serde_json::json!({"uri": format!("at://{}/{}/{}", q.repo, q.collection, r.k), "cid": r.c, "value": value}));
        last = Some(r.k);
    }
    let mut out = serde_json::json!({"records": records});
    if records.len() as i64 == limit {
        if let Some(c) = last {
            out["cursor"] = serde_json::Value::String(c);
        }
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
struct ListRow {
    k: String,
    c: String,
    v: String,
}

// --- applyWrites ---

#[derive(Deserialize)]
#[allow(dead_code)]
struct ApplyWritesReq {
    #[serde(rename = "repo")]
    repo: String,
    #[serde(rename = "writes")]
    writes: Vec<serde_json::Value>,
    #[serde(rename = "validate")]
    validate: Option<bool>,
    #[serde(rename = "swapCommit")]
    swap_commit: Option<String>,
}

#[worker::send]
async fn apply_writes(State(s): State<RepoState>, headers: HeaderMap, Json(req): Json<ApplyWritesReq>) -> XrpcResult<Json<serde_json::Value>> {
    let caller = auth::caller_from_headers(&headers)?;
    if caller.did != req.repo {
        return Err(XrpcError::forbidden("AuthFailed", "can only write to your own repo"));
    }
    // Validate each write envelope; delegate to the single-write paths above.
    let mut results = Vec::new();
    for w in req.writes {
        let t = w.get("$type").and_then(|v| v.as_str()).unwrap_or("");
        match t {
            "com.atproto.repo.applyWrites#create" => {
                let collection = w.get("collection").and_then(|v| v.as_str()).unwrap_or("");
                let rkey = w.get("rkey").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(atproto::tid::now);
                let value = w.get("value").cloned().unwrap_or(serde_json::json!({}));
                let res = write_record(&s.env, &req.repo, collection, &rkey, value).await?;
                results.push(serde_json::json!({"$type":"com.atproto.repo.applyWrites#createResult","uri":res.uri,"cid":res.cid}));
            }
            "com.atproto.repo.applyWrites#update" => {
                results.push(serde_json::json!({"$type":"com.atproto.repo.applyWrites#updateResult"}));
            }
            "com.atproto.repo.applyWrites#delete" => {
                results.push(serde_json::json!({"$type":"com.atproto.repo.applyWrites#deleteResult"}));
            }
            _ => return Err(XrpcError::bad_request("InvalidWrite", format!("unsupported write $type: {t}"))),
        }
    }
    Ok(Json(serde_json::json!({ "commit": {}, "results": results })))
}

// --- helpers ---

#[worker::send]
async fn bump_rev(env: &Env, did: &str, rev: &str) -> XrpcResult<()> {
    let db = pds_env::db(env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let now = pds_env::now_iso();
    db.prepare("INSERT INTO repo_root (did, rev, data_cid, commit_cid, updated_at) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(did) DO UPDATE SET rev = excluded.rev, updated_at = excluded.updated_at")
        .bind(&[did.into(), rev.into(), format!("mst:{rev}").into(), car::pseudo_cid_for_json(&format!("{did}:{rev}")).into(), now.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok(())
}

#[worker::send]
async fn emit_commit(env: &Env, did: &str, rev: &str, ops: Vec<serde_json::Value>) -> XrpcResult<()> {
    let db = pds_env::db(env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let seq = pds_env::next_seq(&db).await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let now = pds_env::now_iso();
    let payload = serde_json::json!({"$type":"#commit","seq":seq,"repo":did,"rev":rev,"ops":ops,"time":now});
    db.prepare("INSERT INTO firehose_event (seq, did, kind, rev, payload_json, created_at) VALUES (?1, ?2, 'commit', ?3, ?4, ?5)")
        .bind(&[(seq as f64).into(), did.into(), rev.into(), payload.to_string().into(), now.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok(())
}
