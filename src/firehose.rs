//! Firehose event emission (`com.atproto.sync.subscribeRepos`).
//! Spec: <https://atproto.com/specs/sync>
//!
//! Poll-compatible JSON transport: each row stores the full event payload,
//! including a base64 CAR slice in `blocks_b64` for `#commit`/`#sync`.
//! (True WebSocket CBOR transport is ROADMAP §2.)

use base64::{engine::general_purpose::STANDARD as B64, Engine};

use crate::cid::Cid;
use crate::mst;
use crate::pds_env;
use crate::xrpc::{XrpcError, XrpcResult};
use worker::Env;

/// CAR slice for a `#commit`: commit block + all MST nodes + changed records.
/// Full node set keeps operation-inversion verifiable; unmodified records are
/// omitted (available via getRepo/getRecord).
pub fn commit_slice(
    commit: &Cid,
    commit_bytes: &[u8],
    nodes: &[(Cid, Vec<u8>)],
    changed_records: &[(Cid, Vec<u8>)],
) -> Vec<u8> {
    let mut blocks = Vec::with_capacity(1 + nodes.len() + changed_records.len());
    blocks.push((commit.clone(), commit_bytes.to_vec()));
    for (cid, bytes) in nodes {
        blocks.push((cid.clone(), bytes.clone()));
    }
    for (cid, bytes) in changed_records {
        blocks.push((cid.clone(), bytes.clone()));
    }
    mst::build_car(commit, &blocks)
}

async fn insert_event(
    env: &Env,
    did: &str,
    kind: &str,
    rev: Option<&str>,
    payload: serde_json::Value,
) -> XrpcResult<i64> {
    let db = pds_env::db(env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let seq = pds_env::next_seq(&db).await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let now = pds_env::now_iso();
    let mut payload = payload;
    payload["seq"] = serde_json::Value::from(seq);
    payload["did"] = serde_json::Value::String(did.to_string());
    if payload.get("repo").is_none() {
        payload["repo"] = serde_json::Value::String(did.to_string());
    }
    payload["time"] = serde_json::Value::String(now.clone());
    let rev_val = rev.map(|s| s.to_string());
    db.prepare("INSERT INTO firehose_event (seq, did, kind, rev, payload_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)")
        .bind(&[
            (seq as f64).into(),
            did.into(),
            kind.into(),
            rev_val.unwrap_or_default().into(),
            payload.to_string().into(),
            now.into(),
        ])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok(seq)
}

#[allow(clippy::too_many_arguments)]
pub async fn emit_commit(
    env: &Env,
    did: &str,
    rev: &str,
    since: Option<&str>,
    prev_data: Option<&Cid>,
    commit: &Cid,
    ops: Vec<serde_json::Value>,
    slice: &[u8],
) -> XrpcResult<i64> {
    let mut payload = serde_json::json!({
        "$type": "#commit",
        "rev": rev,
        "commit": { "$link": commit.to_string() },
        "tooBig": false,
        "blocks": { "$bytes": B64.encode(slice) },
        "ops": ops,
        "blobs": [],
    });
    if let Some(s) = since {
        payload["since"] = serde_json::Value::String(s.to_string());
    } else {
        payload["since"] = serde_json::Value::Null;
    }
    if let Some(p) = prev_data {
        payload["prevData"] = serde_json::json!({ "$link": p.to_string() });
    }
    insert_event(env, did, "commit", Some(rev), payload).await
}

pub async fn emit_account(env: &Env, did: &str, active: bool, status: Option<&str>) -> XrpcResult<i64> {
    let mut payload = serde_json::json!({ "$type": "#account", "active": active });
    if let Some(s) = status {
        payload["status"] = serde_json::Value::String(s.to_string());
    }
    insert_event(env, did, "account", None, payload).await
}

pub async fn emit_sync(env: &Env, did: &str, rev: &str, commit: &Cid, commit_bytes: &[u8]) -> XrpcResult<i64> {
    let slice = mst::build_car(commit, &[(commit.clone(), commit_bytes.to_vec())]);
    let payload = serde_json::json!({
        "$type": "#sync",
        "rev": rev,
        "blocks": { "$bytes": B64.encode(slice) },
    });
    insert_event(env, did, "sync", Some(rev), payload).await
}
