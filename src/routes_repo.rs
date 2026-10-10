//! `com.atproto.repo.*` — record CRUD + history.
//! Every mutation funnels through `repo::commit_repo`: real DAG-CBOR CIDs,
//! rebuilt MST, signed commits, firehose CAR slices.

use axum::{extract::{Query, State}, http::HeaderMap, Json};
use axum::{extract::DefaultBodyLimit, routing::{get, post}};
use axum::Router;
use serde::{Deserialize, Serialize};
use worker::Env;

use crate::{atproto, auth, keys, pds_env, repo, xrpc::{XrpcError, XrpcResult}};

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
        // NOTE: uploadBlob lives in blob_router (R2-backed). Do not re-register here.
        .route("/xrpc/com.atproto.repo.applyWrites", post(apply_writes))
        .route(
            "/xrpc/com.atproto.repo.importRepo",
            post(import_repo).layer(DefaultBodyLimit::disable()),
        )
        .route("/xrpc/com.atproto.repo.listMissingBlobs", get(list_missing_blobs))
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

/// Shared DID-document builder (PDS service + atproto signing key).
pub fn did_doc_for(did: &str, handle: &str, pub_hex: Option<&str>, endpoint: &str) -> serde_json::Value {
    let mut verification = Vec::new();
    if let Some(pub_hex) = pub_hex {
        if let Ok(multibase) = keys::multikey_encode(pub_hex, &keys::Curve::K256) {
            verification.push(serde_json::json!({
                "id": format!("{did}#atproto"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": multibase,
            }));
        }
    }
    serde_json::json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "alsoKnownAs": [format!("at://{handle}")],
        "verificationMethod": verification,
        "service": [{ "id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": endpoint }],
    })
}

#[worker::send]
async fn describe_repo(State(s): State<RepoState>, Query(q): Query<RepoParam>) -> XrpcResult<Json<DescribeRepoResp>> {
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let row: Option<AcctLite> = db.prepare("SELECT did, handle, signing_key_k256_pub_hex AS pub_hex FROM account WHERE did = ?1 OR handle = ?1")
        .bind(&[q.repo.clone().into()]).map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None).await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let Some(a) = row else { return Err(XrpcError::not_found("RepoNotFound", "repo not found")); };
    let cols: Vec<String> = collections_for(&s.env, &a.did).await?;
    let cfg = pds_env::PdsEnv::from_env(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let endpoint = format!("https://{}", cfg.hostname);
    let handle_is_correct = crate::identity::handle_is_correct(&s.env, &a.did, &a.handle).await;
    Ok(Json(DescribeRepoResp {
        handle: a.handle.clone(),
        did: a.did.clone(),
        did_doc: did_doc_for(&a.did, &a.handle, a.pub_hex.as_deref(), &endpoint),
        collections: cols,
        handle_is_correct,
    }))
}

#[derive(Deserialize)]
struct AcctLite {
    did: String,
    handle: String,
    pub_hex: Option<String>,
}

#[worker::send]
async fn collections_for(env: &Env, did: &str) -> XrpcResult<Vec<String>> {
    let db = pds_env::db(env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let rows = db.prepare("SELECT DISTINCT collection AS c FROM record WHERE did = ?1 AND takendown = 0")
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

/// Spec: sync visibility — every mutation response carries the new `rev`.
fn with_rev(rev: &str, body: serde_json::Value) -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        [("atproto-repo-rev", rev.to_string())],
        Json(body),
    )
        .into_response()
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

#[worker::send]
async fn create_record(State(s): State<RepoState>, headers: HeaderMap, Json(req): Json<CreateRecordReq>) -> XrpcResult<axum::response::Response> {
    let caller = auth::authenticate(&s.env, &headers, "POST", "/xrpc/com.atproto.repo.createRecord").await?;
    if caller.did != req.repo {
        return Err(XrpcError::forbidden("AuthFailed", "can only write to your own repo"));
    }
    repo::require_active(&s.env, &caller.did).await?;
    crate::ratelimit::check(&s.env, &format!("write:{}", caller.did), 600, 60).await?;
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
    let (canonical, cid, bytes) = repo::canonical_record_cid(&record)?;
    let now = pds_env::now_iso();
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let exists: Option<ExistsRow> = db.prepare("SELECT cid AS cid FROM record WHERE did = ?1 AND collection = ?2 AND rkey = ?3")
        .bind(&[req.repo.clone().into(), req.collection.clone().into(), rkey.clone().into()]).map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None).await.map_err(|e| XrpcError::internal(e.to_string()))?;
    if exists.is_some() {
        return Err(XrpcError::bad_request("RecordAlreadyExists", "use putRecord to update"));
    }
    db.prepare("INSERT INTO record (did, collection, rkey, cid, value_json, rev, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, '', ?6, ?6)")
        .bind(&[req.repo.clone().into(), req.collection.clone().into(), rkey.clone().into(), cid.to_string().into(), canonical.into(), now.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let ops = vec![serde_json::json!({"action":"create","path":format!("{}/{}", req.collection, rkey),"cid":{ "$link": cid.to_string() }})];
    let out = repo::commit_repo(&s.env, &req.repo, ops, vec![(cid.clone(), bytes)], req.swap_commit.as_deref()).await?;
    db.prepare("UPDATE record SET rev = ?1 WHERE did = ?2 AND collection = ?3 AND rkey = ?4")
        .bind(&[out.rev.clone().into(), req.repo.clone().into(), req.collection.clone().into(), rkey.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok(with_rev(
        &out.rev,
        serde_json::json!({
            "uri": format!("at://{}/{}/{}", req.repo, req.collection, rkey),
            "cid": cid.to_string(),
            "commit": {"cid": out.commit.to_string(), "rev": out.rev},
        }),
    ))
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ExistsRow {
    cid: String,
}

#[derive(Deserialize)]
struct PrevRow {
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
    let row: Option<RecRow> = db.prepare("SELECT cid, value_json AS v, rev FROM record WHERE did = ?1 AND collection = ?2 AND rkey = ?3 AND takendown = 0")
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
    #[serde(rename = "swapRecord")]
    swap_record: Option<String>,
    #[serde(rename = "swapCommit")]
    swap_commit: Option<String>,
}

#[worker::send]
async fn put_record(State(s): State<RepoState>, headers: HeaderMap, Json(req): Json<PutRecordReq>) -> XrpcResult<axum::response::Response> {
    let caller = auth::authenticate(&s.env, &headers, "POST", "/xrpc/com.atproto.repo.putRecord").await?;
    if caller.did != req.repo {
        return Err(XrpcError::forbidden("AuthFailed", "can only write to your own repo"));
    }
    repo::require_active(&s.env, &caller.did).await?;
    crate::ratelimit::check(&s.env, &format!("write:{}", caller.did), 600, 60).await?;
    if !atproto::nsid::validate(&req.collection) || !atproto::record_key::validate(&req.rkey) {
        return Err(XrpcError::bad_request("InvalidRequest", "bad collection or rkey"));
    }
    let (canonical, cid, bytes) = repo::canonical_record_cid(&req.record)?;
    let now = pds_env::now_iso();
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let prev_cid: Option<String> = db.prepare("SELECT cid FROM record WHERE did = ?1 AND collection = ?2 AND rkey = ?3")
        .bind(&[req.repo.clone().into(), req.collection.clone().into(), req.rkey.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first::<PrevRow>(None).await.map_err(|e| XrpcError::internal(e.to_string()))?
        .map(|r| r.cid);
    if let Some(expected) = req.swap_record.as_deref() {
        let cur: Option<ExistsRow> = db.prepare("SELECT cid AS cid FROM record WHERE did = ?1 AND collection = ?2 AND rkey = ?3")
            .bind(&[req.repo.clone().into(), req.collection.clone().into(), req.rkey.clone().into()])
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .first(None).await.map_err(|e| XrpcError::internal(e.to_string()))?;
        match cur {
            Some(row) if row.cid == expected => {}
            _ => return Err(XrpcError::bad_request("InvalidSwap", "swapRecord does not match")),
        }
    }
    db.prepare("INSERT INTO record (did, collection, rkey, cid, value_json, rev, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, '', ?6, ?6) ON CONFLICT(did, collection, rkey) DO UPDATE SET cid = excluded.cid, value_json = excluded.value_json, updated_at = excluded.updated_at")
        .bind(&[req.repo.clone().into(), req.collection.clone().into(), req.rkey.clone().into(), cid.to_string().into(), canonical.into(), now.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let mut update_op = serde_json::json!({"action":"update","path":format!("{}/{}", req.collection, req.rkey),"cid":{ "$link": cid.to_string() }});
    if let Some(prev) = prev_cid.as_deref() {
        update_op["prev"] = serde_json::json!({ "$link": prev });
    }
    let out = repo::commit_repo(&s.env, &req.repo, vec![update_op], vec![(cid.clone(), bytes)], req.swap_commit.as_deref()).await?;
    db.prepare("UPDATE record SET rev = ?1 WHERE did = ?2 AND collection = ?3 AND rkey = ?4")
        .bind(&[out.rev.clone().into(), req.repo.clone().into(), req.collection.clone().into(), req.rkey.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok(with_rev(
        &out.rev,
        serde_json::json!({
            "uri": format!("at://{}/{}/{}", req.repo, req.collection, req.rkey),
            "cid": cid.to_string(),
            "commit": {"cid": out.commit.to_string(), "rev": out.rev},
        }),
    ))
}

#[derive(Deserialize)]
struct DeleteRecordReq {
    #[serde(rename = "repo")]
    repo: String,
    #[serde(rename = "collection")]
    collection: String,
    #[serde(rename = "rkey")]
    rkey: String,
    #[serde(rename = "swapRecord")]
    swap_record: Option<String>,
    #[serde(rename = "swapCommit")]
    swap_commit: Option<String>,
}

#[worker::send]
async fn delete_record(State(s): State<RepoState>, headers: HeaderMap, Json(req): Json<DeleteRecordReq>) -> XrpcResult<axum::response::Response> {
    let caller = auth::authenticate(&s.env, &headers, "POST", "/xrpc/com.atproto.repo.deleteRecord").await?;
    if caller.did != req.repo {
        return Err(XrpcError::forbidden("AuthFailed", "can only write to your own repo"));
    }
    repo::require_active(&s.env, &caller.did).await?;
    crate::ratelimit::check(&s.env, &format!("write:{}", caller.did), 600, 60).await?;
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    if let Some(expected) = req.swap_record.as_deref() {
        let cur: Option<ExistsRow> = db.prepare("SELECT cid AS cid FROM record WHERE did = ?1 AND collection = ?2 AND rkey = ?3")
            .bind(&[req.repo.clone().into(), req.collection.clone().into(), req.rkey.clone().into()])
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .first(None).await.map_err(|e| XrpcError::internal(e.to_string()))?;
        match cur {
            Some(row) if row.cid == expected => {}
            _ => return Err(XrpcError::bad_request("InvalidSwap", "swapRecord does not match")),
        }
    }
    let prev_cid: Option<String> = db.prepare("SELECT cid FROM record WHERE did = ?1 AND collection = ?2 AND rkey = ?3")
        .bind(&[req.repo.clone().into(), req.collection.clone().into(), req.rkey.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first::<PrevRow>(None).await.map_err(|e| XrpcError::internal(e.to_string()))?
        .map(|r| r.cid);
    db.prepare("DELETE FROM record WHERE did = ?1 AND collection = ?2 AND rkey = ?3")
        .bind(&[req.repo.clone().into(), req.collection.clone().into(), req.rkey.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let mut delete_op = serde_json::json!({"action":"delete","path":format!("{}/{}", req.collection, req.rkey)});
    if let Some(prev) = prev_cid.as_deref() {
        delete_op["prev"] = serde_json::json!({ "$link": prev });
    }
    let out = repo::commit_repo(&s.env, &req.repo, vec![delete_op], vec![], req.swap_commit.as_deref()).await?;
    Ok(with_rev(
        &out.rev,
        serde_json::json!({"commit": {"cid": out.commit.to_string(), "rev": out.rev}}),
    ))
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
    // Cursor = rkey offset (TID-ordered).
    let rows = if let Some(cur) = q.cursor.clone() {
        db.prepare("SELECT rkey AS k, cid AS c, value_json AS v FROM record WHERE did = ?1 AND collection = ?2 AND rkey > ?3 AND takendown = 0 ORDER BY rkey ASC LIMIT ?4")
            .bind(&[q.repo.clone().into(), q.collection.clone().into(), cur.into(), (limit as f64).into()])
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .all().await.map_err(|e| XrpcError::internal(e.to_string()))?
    } else {
        db.prepare("SELECT rkey AS k, cid AS c, value_json AS v FROM record WHERE did = ?1 AND collection = ?2 AND takendown = 0 ORDER BY rkey ASC LIMIT ?3")
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

// --- applyWrites (single commit for the whole batch) ---

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
async fn apply_writes(State(s): State<RepoState>, headers: HeaderMap, Json(req): Json<ApplyWritesReq>) -> XrpcResult<axum::response::Response> {
    let caller = auth::authenticate(&s.env, &headers, "POST", "/xrpc/com.atproto.repo.applyWrites").await?;
    if caller.did != req.repo {
        return Err(XrpcError::forbidden("AuthFailed", "can only write to your own repo"));
    }
    repo::require_active(&s.env, &caller.did).await?;
    crate::ratelimit::check(&s.env, &format!("write:{}", caller.did), 600, 60).await?;
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let now = pds_env::now_iso();
    let mut ops = Vec::new();
    let mut changed = Vec::new();
    let mut results = Vec::new();
    for w in &req.writes {
        let t = w.get("$type").and_then(|v| v.as_str()).unwrap_or("");
        match t {
            "com.atproto.repo.applyWrites#create" => {
                let collection = w.get("collection").and_then(|v| v.as_str()).unwrap_or("");
                if !atproto::nsid::validate(collection) {
                    return Err(XrpcError::bad_request("InvalidNsid", "bad collection"));
                }
                let rkey = w.get("rkey").and_then(|v| v.as_str()).map(|x| x.to_string()).unwrap_or_else(atproto::tid::now);
                if !atproto::record_key::validate(&rkey) {
                    return Err(XrpcError::bad_request("InvalidRecordKey", "bad rkey"));
                }
                let mut value = w.get("value").cloned().unwrap_or(serde_json::json!({}));
                if value.get("$type").is_none() {
                    value["$type"] = serde_json::Value::String(collection.to_string());
                }
                let (canonical, cid, bytes) = repo::canonical_record_cid(&value)?;
                let exists: Option<ExistsRow> = db.prepare("SELECT cid AS cid FROM record WHERE did = ?1 AND collection = ?2 AND rkey = ?3")
                    .bind(&[req.repo.clone().into(), collection.into(), rkey.clone().into()]).map_err(|e| XrpcError::internal(e.to_string()))?
                    .first(None).await.map_err(|e| XrpcError::internal(e.to_string()))?;
                if exists.is_some() {
                    return Err(XrpcError::bad_request("RecordAlreadyExists", format!("{collection}/{rkey} exists")));
                }
                db.prepare("INSERT INTO record (did, collection, rkey, cid, value_json, rev, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, '', ?6, ?6)")
                    .bind(&[req.repo.clone().into(), collection.into(), rkey.clone().into(), cid.to_string().into(), canonical.into(), now.clone().into()])
                    .map_err(|e| XrpcError::internal(e.to_string()))?
                    .run().await.map_err(|e| XrpcError::internal(e.to_string()))?;
                ops.push(serde_json::json!({"action":"create","path":format!("{collection}/{rkey}"),"cid":{ "$link": cid.to_string() }}));
                changed.push((cid.clone(), bytes));
                results.push(serde_json::json!({"$type":"com.atproto.repo.applyWrites#createResult","uri":format!("at://{}/{}/{rkey}", req.repo, collection),"cid":cid.to_string()}));
            }
            "com.atproto.repo.applyWrites#update" => {
                let collection = w.get("collection").and_then(|v| v.as_str()).unwrap_or("");
                let rkey = w.get("rkey").and_then(|v| v.as_str()).unwrap_or("");
                let value = w.get("value").cloned().unwrap_or(serde_json::json!({}));
                let (canonical, cid, bytes) = repo::canonical_record_cid(&value)?;
                let prev_cid: Option<String> = db.prepare("SELECT cid FROM record WHERE did = ?1 AND collection = ?2 AND rkey = ?3")
                    .bind(&[req.repo.clone().into(), collection.into(), rkey.into()])
                    .map_err(|e| XrpcError::internal(e.to_string()))?
                    .first::<PrevRow>(None).await.map_err(|e| XrpcError::internal(e.to_string()))?
                    .map(|r| r.cid);
                db.prepare("INSERT INTO record (did, collection, rkey, cid, value_json, rev, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, '', ?6, ?6) ON CONFLICT(did, collection, rkey) DO UPDATE SET cid = excluded.cid, value_json = excluded.value_json, updated_at = excluded.updated_at")
                    .bind(&[req.repo.clone().into(), collection.into(), rkey.into(), cid.to_string().into(), canonical.into(), now.clone().into()])
                    .map_err(|e| XrpcError::internal(e.to_string()))?
                    .run().await.map_err(|e| XrpcError::internal(e.to_string()))?;
                let mut update_op = serde_json::json!({"action":"update","path":format!("{collection}/{rkey}"),"cid":{ "$link": cid.to_string() }});
                if let Some(prev) = prev_cid.as_deref() {
                    update_op["prev"] = serde_json::json!({ "$link": prev });
                }
                ops.push(update_op);
                changed.push((cid.clone(), bytes));
                results.push(serde_json::json!({"$type":"com.atproto.repo.applyWrites#updateResult","uri":format!("at://{}/{}/{rkey}", req.repo, collection),"cid":cid.to_string()}));
            }
            "com.atproto.repo.applyWrites#delete" => {
                let collection = w.get("collection").and_then(|v| v.as_str()).unwrap_or("");
                let rkey = w.get("rkey").and_then(|v| v.as_str()).unwrap_or("");
                let prev_cid: Option<String> = db.prepare("SELECT cid FROM record WHERE did = ?1 AND collection = ?2 AND rkey = ?3")
                    .bind(&[req.repo.clone().into(), collection.into(), rkey.into()])
                    .map_err(|e| XrpcError::internal(e.to_string()))?
                    .first::<PrevRow>(None).await.map_err(|e| XrpcError::internal(e.to_string()))?
                    .map(|r| r.cid);
                db.prepare("DELETE FROM record WHERE did = ?1 AND collection = ?2 AND rkey = ?3")
                    .bind(&[req.repo.clone().into(), collection.into(), rkey.into()])
                    .map_err(|e| XrpcError::internal(e.to_string()))?
                    .run().await.map_err(|e| XrpcError::internal(e.to_string()))?;
                let mut delete_op = serde_json::json!({"action":"delete","path":format!("{collection}/{rkey}")});
                if let Some(prev) = prev_cid.as_deref() {
                    delete_op["prev"] = serde_json::json!({ "$link": prev });
                }
                ops.push(delete_op);
                results.push(serde_json::json!({"$type":"com.atproto.repo.applyWrites#deleteResult"}));
            }
            _ => return Err(XrpcError::bad_request("InvalidWrite", format!("unsupported write $type: {t}"))),
        }
    }
    let out = repo::commit_repo(&s.env, &req.repo, ops, changed, req.swap_commit.as_deref()).await?;
    db.prepare("UPDATE record SET rev = ?1 WHERE did = ?2 AND rev = ''")
        .bind(&[out.rev.clone().into(), req.repo.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok(with_rev(
        &out.rev,
        serde_json::json!({
            "commit": {"cid": out.commit.to_string(), "rev": out.rev},
            "results": results,
        }),
    ))
}

// --- importRepo (migration target) ---

/// Import a full-repo CAR (migration reset semantics). The commit must belong
/// to the caller, verify against the DID key, and be internally consistent
/// (hash chain + rebuilt root). State is replaced wholesale and a `#sync`
/// event fires. Blobs travel separately — see `listMissingBlobs`.
#[worker::send]
async fn import_repo(
    State(s): State<RepoState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> XrpcResult<Json<serde_json::Value>> {
    if body.len() > 64_000_000 {
        return Err(XrpcError::too_large("CAR exceeds 64MB import limit"));
    }
    if body.is_empty() {
        return Err(XrpcError::bad_request("InvalidRequest", "empty CAR"));
    }
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if ct != "application/vnd.ipld.car" && ct != "application/octet-stream" {
        return Err(XrpcError::bad_request("InvalidRequest", "content-type must be application/vnd.ipld.car"));
    }
    let (roots, blocks) = crate::mst::parse_car(&body).map_err(|e| XrpcError::bad_request("InvalidCar", e.to_string()))?;
    let root = roots.into_iter().next().ok_or_else(|| XrpcError::bad_request("InvalidCar", "no roots"))?;
    let (commit_cid, commit_bytes) = blocks.first().cloned().ok_or_else(|| XrpcError::bad_request("InvalidCar", "no commit"))?;
    if commit_cid != root {
        return Err(XrpcError::bad_request("InvalidCar", "first block must be the commit"));
    }
    let commit = crate::mst::parse_commit(&commit_bytes).map_err(|e| XrpcError::bad_request("InvalidCar", e.to_string()))?;
    // Caller must own the repo (or be the admin assisting a migration).
    let cfg = pds_env::PdsEnv::from_env(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let is_admin = auth::check_admin(&headers, cfg.admin_password.as_deref()).is_ok();
    let caller_did = if is_admin {
        None
    } else {
        // Method+path for DPoP binding: this procedure itself.
        Some(auth::authenticate(&s.env, &headers, "POST", "/xrpc/com.atproto.repo.importRepo").await?.did)
    };
    if let Some(caller) = caller_did.as_deref() {
        if caller != commit.did {
            return Err(XrpcError::forbidden("AuthFailed", "can only import your own repo"));
        }
    }
    let did = commit.did.clone();
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    // Target account must exist (create it — possibly via reserved key — first).
    #[derive(serde::Deserialize)]
    struct ExistsAcct {
        #[allow(dead_code)]
        did: String,
    }
    let acct: Option<ExistsAcct> = db
        .prepare("SELECT did FROM account WHERE did = ?1")
        .bind(&[did.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    if acct.is_none() {
        return Err(XrpcError::not_found("RepoNotFound", "no local account for this DID; create it first"));
    }
    // Signature: resolved DID key preferred, stored account key as fallback.
    let verified = verify_commit_against_did(&s.env, &did, &commit_bytes).await;
    if verified.is_err() {
        // Fallback: stored repo key (dev DIDs, pre-PLC accounts).
        let key_row: Option<StoredKeyRow> = db
            .prepare("SELECT signing_key_k256_pub_hex AS pub_hex FROM account WHERE did = ?1")
            .bind(&[did.clone().into()])
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .first(None)
            .await
            .map_err(|e| XrpcError::internal(e.to_string()))?;
        match key_row.and_then(|k| k.pub_hex) {
            Some(pub_hex) => {
                crate::mst::verify_commit(&pub_hex, &commit_bytes)
                    .map_err(|_| XrpcError::bad_request("InvalidCar", "commit signature invalid"))?;
            }
            None => return Err(XrpcError::bad_request("InvalidCar", "commit signature invalid")),
        }
    }
    // Full integrity: walk reachable nodes, collect records, rebuild root.
    let mut nodes: std::collections::HashMap<String, crate::mst::ParsedNode> = std::collections::HashMap::new();
    let mut records: Vec<(String, String, String, serde_json::Value)> = Vec::new(); // collection, rkey, cid, json
    {
        let mut by_cid: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
        for (cid, bytes) in blocks.iter().skip(1) {
            by_cid.insert(cid.to_string(), bytes.clone());
        }
        let mut stack = vec![commit.data.clone()];
        let mut seen = std::collections::HashSet::new();
        while let Some(cid) = stack.pop() {
            if !seen.insert(cid.to_string()) {
                continue;
            }
            let bytes = by_cid.get(&cid.to_string()).ok_or_else(|| XrpcError::bad_request("InvalidCar", "dangling MST link"))?;
            let node = crate::mst::parse_node(bytes).map_err(|e| XrpcError::bad_request("InvalidCar", e.to_string()))?;
            if let Some(left) = &node.left {
                stack.push(left.clone());
            }
            for e in &node.entries {
                let path = String::from_utf8(e.key.clone()).map_err(|_| XrpcError::bad_request("InvalidCar", "non-UTF8 path"))?;
                let (collection, rkey) = path.split_once('/').ok_or_else(|| XrpcError::bad_request("InvalidCar", "bad path"))?;
                if !crate::atproto::nsid::validate(collection) || !crate::atproto::record_key::validate(rkey) {
                    return Err(XrpcError::bad_request("InvalidCar", format!("bad record path: {path}")));
                }
                let rec_bytes = by_cid.get(&e.value.to_string()).ok_or_else(|| XrpcError::bad_request("InvalidCar", "dangling record link"))?;
                if crate::cid::Cid::dag_cbor(rec_bytes) != e.value {
                    return Err(XrpcError::bad_request("InvalidCar", "record bytes mismatch"));
                }
                let dag = crate::cbor::decode_exact(rec_bytes).map_err(|e| XrpcError::bad_request("InvalidCar", e.to_string()))?;
                let value = crate::cbor::to_json(&dag);
                if value.get("$type").and_then(|v| v.as_str()).is_none_or(|t| t.is_empty()) {
                    return Err(XrpcError::bad_request("InvalidCar", "record missing $type"));
                }
                records.push((collection.to_string(), rkey.to_string(), e.value.to_string(), value));
                if let Some(right) = &e.right {
                    stack.push(right.clone());
                }
            }
            nodes.insert(cid.to_string(), node);
        }
        // Rebuild must reproduce the commit root exactly.
        let mut entries: Vec<crate::mst::MstEntry> = Vec::with_capacity(records.len());
        for (c, k, cid, _) in &records {
            let parsed = crate::cid::Cid::parse(cid).map_err(|e| XrpcError::bad_request("InvalidCar", e.to_string()))?;
            entries.push(crate::mst::MstEntry { key: format!("{c}/{k}").into_bytes(), cid: parsed });
        }
        entries.sort_by(|a, b| a.key.cmp(&b.key));
        let rebuilt = crate::mst::build(&entries).map_err(|e| XrpcError::internal(e.to_string()))?;
        if rebuilt.root != commit.data {
            return Err(XrpcError::bad_request("InvalidCar", "tree root mismatch"));
        }
        // Rev must advance (reset semantics forbid rewinding history), except
        // into a fresh migration target holding no records yet (adopts rev).
        #[derive(serde::Deserialize)]
        struct RevRow {
            rev: String,
        }
        let cur: Option<RevRow> = db
            .prepare("SELECT rev FROM repo_root WHERE did = ?1")
            .bind(&[did.clone().into()])
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .first(None)
            .await
            .map_err(|e| XrpcError::internal(e.to_string()))?;
        #[derive(serde::Deserialize)]
        struct CountRow {
            n: f64,
        }
        let existing: i64 = db
            .prepare("SELECT COUNT(*) AS n FROM record WHERE did = ?1")
            .bind(&[did.clone().into()])
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .first::<CountRow>(None)
            .await
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .map(|r| r.n as i64)
            .unwrap_or(0);
        if let Some(cur) = cur {
            if existing > 0 && commit.rev.as_str() <= cur.rev.as_str() {
                return Err(XrpcError::bad_request("InvalidCar", "imported rev must advance"));
            }
        }
    }
    // Replace state wholesale.
    let now = pds_env::now_iso();
    db.prepare("DELETE FROM record WHERE did = ?1")
        .bind(&[did.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    for (collection, rkey, cid, value) in &records {
        let canonical = serde_json::to_string(value).map_err(|e| XrpcError::internal(e.to_string()))?;
        db.prepare("INSERT INTO record (did, collection, rkey, cid, value_json, rev, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)")
            .bind(&[did.clone().into(), collection.clone().into(), rkey.clone().into(), cid.clone().into(), canonical.into(), commit.rev.clone().into(), now.clone().into()])
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .run()
            .await
            .map_err(|e| XrpcError::internal(e.to_string()))?;
    }
    db.prepare("INSERT INTO repo_root (did, rev, data_cid, commit_cid, updated_at) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(did) DO UPDATE SET rev = excluded.rev, data_cid = excluded.data_cid, commit_cid = excluded.commit_cid, updated_at = excluded.updated_at")
        .bind(&[did.clone().into(), commit.rev.clone().into(), commit.data.to_string().into(), commit_cid.to_string().into(), now.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    crate::firehose::emit_sync(&s.env, &did, &commit.rev, &commit_cid, &commit_bytes).await?;
    Ok(Json(serde_json::json!({})))
}

#[derive(serde::Deserialize)]
struct StoredKeyRow {
    pub_hex: Option<String>,
}

async fn verify_commit_against_did(env: &Env, did: &str, commit_bytes: &[u8]) -> XrpcResult<()> {
    let doc = crate::identity::resolve_did(env, did).await?;
    let (_, pub_hex) = doc
        .signing_key
        .ok_or_else(|| XrpcError::bad_request("InvalidCar", "DID has no signing key"))?;
    crate::mst::verify_commit(&pub_hex, commit_bytes)
        .map_err(|_| XrpcError::bad_request("InvalidCar", "commit signature invalid"))?;
    Ok(())
}

// --- listMissingBlobs (migration helper) ---

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct MissingBlobsParam {
    limit: Option<i64>,
    cursor: Option<String>,
}

/// Blobs referenced by records but absent from the store, with the
/// referencing record URI. Cursor is a `cid` offset over the sorted set.
#[worker::send]
async fn list_missing_blobs(
    State(s): State<RepoState>,
    headers: HeaderMap,
    Query(q): Query<MissingBlobsParam>,
) -> XrpcResult<Json<serde_json::Value>> {
    let caller = auth::authenticate(&s.env, &headers, "GET", "/xrpc/com.atproto.repo.listMissingBlobs").await?;
    let limit = q.limit.unwrap_or(500).clamp(1, 1000);
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let rows = db
        .prepare("SELECT collection, rkey, value_json AS v FROM record WHERE did = ?1")
        .bind(&[caller.did.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .all()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    #[derive(serde::Deserialize)]
    struct RecVal {
        #[serde(rename = "v")]
        v: String,
        collection: String,
        rkey: String,
    }
    // cid -> first recordUri (sorted for stable pagination).
    let mut missing: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    // Present blob cids for this account.
    let present_rows = db
        .prepare("SELECT cid AS c FROM blob WHERE did = ?1")
        .bind(&[caller.did.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .all()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    #[derive(serde::Deserialize)]
    struct CidRow {
        c: String,
    }
    let present: std::collections::HashSet<String> = present_rows
        .results::<CidRow>()
        .unwrap_or_default()
        .into_iter()
        .map(|r| r.c)
        .collect();
    for r in rows.results::<RecVal>().unwrap_or_default() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&r.v) else {
            continue;
        };
        for cid in find_blob_refs(&value) {
            if !present.contains(&cid) {
                missing
                    .entry(cid)
                    .or_insert_with(|| format!("at://{}/{}/{}", caller.did, r.collection, r.rkey));
            }
        }
    }
    let mut blobs = Vec::new();
    let mut last: Option<String> = None;
    let after = q.cursor.clone().unwrap_or_default();
    for (cid, uri) in &missing {
        if cid.as_str() <= after.as_str() && !after.is_empty() {
            continue;
        }
        blobs.push(serde_json::json!({ "cid": cid, "recordUri": uri }));
        last = Some(cid.clone());
        if blobs.len() as i64 >= limit {
            break;
        }
    }
    let mut out = serde_json::json!({ "blobs": blobs });
    if blobs.len() as i64 >= limit {
        if let Some(c) = last {
            out["cursor"] = serde_json::Value::String(c);
        }
    }
    Ok(Json(out))
}

/// Recursively collect `{"$type":"blob","ref":{"$link":cid}}` references.
fn find_blob_refs(value: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    collect_blob_refs(value, &mut out);
    out
}

fn collect_blob_refs(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(m) => {
            if m.get("$type").and_then(|v| v.as_str()) == Some("blob") {
                if let Some(cid) = m.get("ref").and_then(|r| r.get("$link")).and_then(|l| l.as_str()) {
                    out.push(cid.to_string());
                    return;
                }
            }
            for v in m.values() {
                collect_blob_refs(v, out);
            }
        }
        serde_json::Value::Array(a) => {
            for v in a {
                collect_blob_refs(v, out);
            }
        }
        _ => {}
    }
}
