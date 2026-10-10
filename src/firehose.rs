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

// ---------- #identity ----------

pub async fn emit_identity(env: &Env, did: &str, handle: Option<&str>) -> XrpcResult<i64> {
    let mut payload = serde_json::json!({ "$type": "#identity" });
    if let Some(h) = handle {
        payload["handle"] = serde_json::Value::String(h.to_string());
    }
    insert_event(env, did, "identity", None, payload).await
}

// ---------- WebSocket wire framing (event-stream v0) ----------

/// Build one binary WS frame: header `{"op":1,"t":…}` + payload, concatenated.
/// `$type` is stripped (it travels in the header); explicit nulls are dropped
/// (lexicon-optional fields); `did`/`repo` are normalized per message kind.
pub fn ws_frame(t: &str, payload: &serde_json::Value) -> Result<Vec<u8>, String> {
    let mut body = payload.clone();
    if let Some(obj) = body.as_object_mut() {
        obj.remove("$type");
        if t == "#commit" {
            obj.remove("did");
        } else {
            obj.remove("repo");
        }
        obj.retain(|_, v| !v.is_null());
    }
    let header = crate::cbor::encode(&crate::cbor::DagCbor::Map(vec![
        (b"op".to_vec(), crate::cbor::DagCbor::Int(1)),
        (b"t".to_vec(), crate::cbor::DagCbor::Text(t.to_string())),
    ]));
    let payload_bytes = crate::cbor::encode_json(&body).map_err(|e| e.to_string())?;
    if header.len() + payload_bytes.len() > 5_000_000 {
        return Err("frame too large".into());
    }
    let mut out = Vec::with_capacity(header.len() + payload_bytes.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&payload_bytes);
    Ok(out)
}

/// Error frame: header `{"op":-1}` + `{"error","message?"}`. Server closes after.
pub fn ws_error_frame(error: &str, message: Option<&str>) -> Vec<u8> {
    let header = crate::cbor::encode(&crate::cbor::DagCbor::Map(vec![(
        b"op".to_vec(),
        crate::cbor::DagCbor::Int(-1),
    )]));
    let mut payload = serde_json::json!({ "error": error });
    if let Some(m) = message {
        payload["message"] = serde_json::Value::String(m.to_string());
    }
    let payload_bytes = crate::cbor::encode_json(&payload).unwrap_or_default();
    [header, payload_bytes].concat()
}

#[cfg(test)]
mod frame_tests {
    use super::*;

    #[test]
    fn commit_frame_shape() {
        let commit_cid = crate::cid::Cid::dag_cbor(b"commit-bytes").to_string();
        let payload = serde_json::json!({
            "$type": "#commit", "seq": 7, "repo": "did:plc:test", "did": "did:plc:test",
            "rev": "abc", "since": serde_json::Value::Null,
            "commit": { "$link": commit_cid },
            "ops": [], "blobs": [], "tooBig": false,
            "blocks": { "$bytes": "AA==" }, "time": "2026-10-10T00:00:00.000Z",
        });
        let frame = ws_frame("#commit", &payload).unwrap();
        // Decode both concatenated objects with the crate decoder.
        let mut d = crate::cbor::Decoder::new(&frame);
        let header = d.decode_one().unwrap();
        let body = d.decode_one().unwrap();
        assert!(matches!(header, crate::cbor::DagCbor::Map(_)));
        // $type/did/since stripped.
        let crate::cbor::DagCbor::Map(fields) = body else {
            panic!("body must be map")
        };
        let keys: Vec<String> = fields.iter().map(|(k, _)| String::from_utf8_lossy(k).into_owned()).collect();
        assert!(keys.contains(&"repo".to_string()));
        assert!(!keys.contains(&"$type".to_string()));
        assert!(!keys.contains(&"did".to_string()));
        assert!(!keys.contains(&"since".to_string()));
    }

    #[test]
    fn error_frame_shape() {
        let frame = ws_error_frame("FutureCursor", Some("behind"));
        let mut d = crate::cbor::Decoder::new(&frame);
        let crate::cbor::DagCbor::Map(h) = d.decode_one().unwrap() else {
            panic!("header")
        };
        assert!(h.iter().any(|(k, v)| k == b"op" && *v == crate::cbor::DagCbor::Int(-1)));
        let crate::cbor::DagCbor::Map(b) = d.decode_one().unwrap() else {
            panic!("body")
        };
        assert!(b.iter().any(|(k, v)| k == b"error".as_slice()
            && *v == crate::cbor::DagCbor::Text("FutureCursor".into())));
    }
}
