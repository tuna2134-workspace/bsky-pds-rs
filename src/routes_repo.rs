//! `com.atproto.repo.*` — record CRUD + history.
//! Every mutation funnels through `repo::commit_repo`: real DAG-CBOR CIDs,
//! rebuilt MST, signed commits, firehose CAR slices.

use axum::{extract::{Query, State}, http::HeaderMap, Json};
use axum::routing::{get, post};
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
    if !atproto::nsid::validate(&req.collection) || !atproto::record_key::validate(&req.rkey) {
        return Err(XrpcError::bad_request("InvalidRequest", "bad collection or rkey"));
    }
    let (canonical, cid, bytes) = repo::canonical_record_cid(&req.record)?;
    let now = pds_env::now_iso();
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
    db.prepare("INSERT INTO record (did, collection, rkey, cid, value_json, rev, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, '', ?6, ?6) ON CONFLICT(did, collection, rkey) DO UPDATE SET cid = excluded.cid, value_json = excluded.value_json, updated_at = excluded.updated_at")
        .bind(&[req.repo.clone().into(), req.collection.clone().into(), req.rkey.clone().into(), cid.to_string().into(), canonical.into(), now.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let ops = vec![serde_json::json!({"action":"update","path":format!("{}/{}", req.collection, req.rkey),"cid":{ "$link": cid.to_string() }})];
    let out = repo::commit_repo(&s.env, &req.repo, ops, vec![(cid.clone(), bytes)], req.swap_commit.as_deref()).await?;
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
    db.prepare("DELETE FROM record WHERE did = ?1 AND collection = ?2 AND rkey = ?3")
        .bind(&[req.repo.clone().into(), req.collection.clone().into(), req.rkey.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let ops = vec![serde_json::json!({"action":"delete","path":format!("{}/{}", req.collection, req.rkey)})];
    let out = repo::commit_repo(&s.env, &req.repo, ops, vec![], req.swap_commit.as_deref()).await?;
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
                db.prepare("INSERT INTO record (did, collection, rkey, cid, value_json, rev, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, '', ?6, ?6) ON CONFLICT(did, collection, rkey) DO UPDATE SET cid = excluded.cid, value_json = excluded.value_json, updated_at = excluded.updated_at")
                    .bind(&[req.repo.clone().into(), collection.into(), rkey.into(), cid.to_string().into(), canonical.into(), now.clone().into()])
                    .map_err(|e| XrpcError::internal(e.to_string()))?
                    .run().await.map_err(|e| XrpcError::internal(e.to_string()))?;
                ops.push(serde_json::json!({"action":"update","path":format!("{collection}/{rkey}"),"cid":{ "$link": cid.to_string() }}));
                changed.push((cid.clone(), bytes));
                results.push(serde_json::json!({"$type":"com.atproto.repo.applyWrites#updateResult","uri":format!("at://{}/{}/{rkey}", req.repo, collection),"cid":cid.to_string()}));
            }
            "com.atproto.repo.applyWrites#delete" => {
                let collection = w.get("collection").and_then(|v| v.as_str()).unwrap_or("");
                let rkey = w.get("rkey").and_then(|v| v.as_str()).unwrap_or("");
                db.prepare("DELETE FROM record WHERE did = ?1 AND collection = ?2 AND rkey = ?3")
                    .bind(&[req.repo.clone().into(), collection.into(), rkey.into()])
                    .map_err(|e| XrpcError::internal(e.to_string()))?
                    .run().await.map_err(|e| XrpcError::internal(e.to_string()))?;
                ops.push(serde_json::json!({"action":"delete","path":format!("{collection}/{rkey}")}));
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
