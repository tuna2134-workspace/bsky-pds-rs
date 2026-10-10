//! Repository assembly: records -> MST -> signed commit -> firehose.
//! Single-commit batches: every write endpoint funnels through `commit_repo`
//! so `rev` bumps, signatures, and firehose events stay consistent.

use crate::cbor;
use crate::cid::Cid;
use crate::firehose;
use crate::mst;
use crate::pds_env;
use crate::xrpc::{XrpcError, XrpcResult};
use worker::Env;

pub const MAX_RECORD_BYTES: usize = 1_000_000;

pub struct StoredRecord {
    pub collection: String,
    pub rkey: String,
    pub cid: String,
    pub value_json: String,
}

#[derive(serde::Deserialize)]
struct RecordRow {
    collection: String,
    rkey: String,
    cid: String,
    #[serde(rename = "v")]
    v: String,
}

#[derive(serde::Deserialize)]
struct RootRow {
    rev: String,
    #[serde(rename = "data_cid")]
    data_cid: String,
    #[allow(dead_code)]
    #[serde(rename = "commit_cid")]
    commit_cid: String,
}

#[derive(serde::Deserialize)]
struct KeyRow {
    #[serde(rename = "priv_hex")]
    priv_hex: Option<String>,
}

pub struct CommitOutcome {
    pub rev: String,
    pub root: Cid,
    pub commit: Cid,
    pub commit_bytes: Vec<u8>,
    pub seq: i64,
}

/// Canonicalize client JSON and compute its real record CID.
pub fn canonical_record_cid(value: &serde_json::Value) -> XrpcResult<(String, Cid, Vec<u8>)> {
    let canonical = serde_json::to_string(value).map_err(|e| XrpcError::internal(e.to_string()))?;
    let bytes = cbor::encode_json(value)
        .map_err(|e| XrpcError::bad_request("InvalidRecord", format!("record is not valid DAG-CBOR data: {e}")))?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(XrpcError::bad_request("InvalidRecord", "record exceeds 1MB limit"));
    }
    let cid = Cid::dag_cbor(&bytes);
    Ok((canonical, cid, bytes))
}


/// Fetch the account signing key, backfilling one for pre-CBOR accounts
/// (zero-downtime upgrade: old rows have NULL key columns).
pub(crate) async fn signing_key(db: &worker::D1Database, did: &str) -> XrpcResult<String> {
    let row: Option<KeyRow> = db
        .prepare("SELECT signing_key_k256_priv_hex AS priv_hex FROM account WHERE did = ?1")
        .bind(&[did.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    if let Some(k) = row {
        if let Some(priv_hex) = k.priv_hex {
            if !priv_hex.is_empty() {
                return Ok(priv_hex);
            }
        }
    }
    let (priv_hex, pub_hex) =
        crate::keys::generate_k256().map_err(|e| XrpcError::internal(e.to_string()))?;
    db.prepare("UPDATE account SET signing_key_k256_priv_hex = ?1, signing_key_k256_pub_hex = ?2 WHERE did = ?3")
        .bind(&[priv_hex.clone().into(), pub_hex.into(), did.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok(priv_hex)
}

async fn load_records(db: &worker::D1Database, did: &str) -> XrpcResult<Vec<StoredRecord>> {    let rows = db
        .prepare("SELECT collection, rkey, cid, value_json AS v FROM record WHERE did = ?1")
        .bind(&[did.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .all()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok(rows
        .results::<RecordRow>()
        .unwrap_or_default()
        .into_iter()
        .map(|r| StoredRecord { collection: r.collection, rkey: r.rkey, cid: r.cid, value_json: r.v })
        .collect())
}

/// Rebuild the MST from stored records, self-healing legacy `dev…` CIDs by
/// recomputing from record JSON. Returns (entries, changed_updates).
async fn build_entries(
    db: &worker::D1Database,
    did: &str,
    records: &[StoredRecord],
) -> XrpcResult<(Vec<mst::MstEntry>, Vec<(Cid, Vec<u8>)>)> {
    let mut entries = Vec::with_capacity(records.len());
    let mut changed = Vec::new();
    for r in records {
        let value: serde_json::Value =
            serde_json::from_str(&r.value_json).map_err(|e| XrpcError::internal(e.to_string()))?;
        let (canonical, cid, bytes) = canonical_record_cid(&value)?;
        if cid.to_string() != r.cid {
            // Self-heal pre-CBOR rows.
            db.prepare("UPDATE record SET cid = ?1, value_json = ?2 WHERE did = ?3 AND collection = ?4 AND rkey = ?5")
                .bind(&[cid.to_string().into(), canonical.into(), did.into(), r.collection.clone().into(), r.rkey.clone().into()])
                .map_err(|e| XrpcError::internal(e.to_string()))?
                .run()
                .await
                .map_err(|e| XrpcError::internal(e.to_string()))?;
        }
        let key = format!("{}/{}", r.collection, r.rkey).into_bytes();
        entries.push(mst::MstEntry { key, cid: cid.clone() });
        changed.push((cid, bytes));
    }
    Ok((entries, changed))
}

fn next_rev_after(prev: Option<&str>) -> String {
    let mut micros = (worker::Date::now().as_millis() as u64) * 1000;
    if let Some(p) = prev {
        // TID logical clock must strictly increase.
        loop {
            let cand = crate::atproto::tid::encode(micros);
            if cand.as_str() > p {
                return cand;
            }
            micros += 1;
        }
    }
    crate::atproto::tid::encode(micros)
}

/// Apply already-staged D1 mutations as one commit: rebuild MST, sign, store
/// root, emit firehose. `ops` are record-level ops; `changed` holds CBOR of
/// created/updated records for the CAR slice. `swap_commit` enforces CAS.
pub async fn commit_repo(
    env: &Env,
    did: &str,
    ops: Vec<serde_json::Value>,
    changed: Vec<(Cid, Vec<u8>)>,
    swap_commit: Option<&str>,
) -> XrpcResult<CommitOutcome> {
    let db = pds_env::db(env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let prev: Option<RootRow> = db
        .prepare("SELECT rev, data_cid, commit_cid FROM repo_root WHERE did = ?1")
        .bind(&[did.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    if let Some(expected) = swap_commit {
        match &prev {
            Some(p) if p.rev == expected => {}
            _ => {
                return Err(XrpcError::bad_request(
                    "InvalidSwap",
                    "swapCommit does not match current commit",
                ))
            }
        }
    }
    let prev_rev = prev.as_ref().map(|p| p.rev.clone());
    let prev_data = prev.as_ref().and_then(|p| Cid::parse(&p.data_cid).ok());

    let records = load_records(&db, did).await?;
    let (entries, _all_changed) = build_entries(&db, did, &records).await?;
    let tree = mst::build(&entries).map_err(|e| XrpcError::internal(e.to_string()))?;

    let priv_hex = signing_key(&db, did).await?;

    let rev = next_rev_after(prev_rev.as_deref());
    let (commit_bytes, commit_cid) =
        mst::sign_commit(&priv_hex, did, &rev, &tree.root).map_err(|e| XrpcError::internal(e.to_string()))?;

    let now = pds_env::now_iso();
    db.prepare("INSERT INTO repo_root (did, rev, data_cid, commit_cid, updated_at) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT(did) DO UPDATE SET rev = excluded.rev, data_cid = excluded.data_cid, commit_cid = excluded.commit_cid, updated_at = excluded.updated_at")
        .bind(&[did.into(), rev.clone().into(), tree.root.to_string().into(), commit_cid.to_string().into(), now.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;

    let nodes: Vec<(Cid, Vec<u8>)> = tree.nodes_preorder.into_iter().map(|n| (n.cid, n.bytes)).collect();
    let slice = firehose::commit_slice(&commit_cid, &commit_bytes, &nodes, &changed);
    // Chain continuity: only reference previous state when it parses as real CIDs.
    let (since, prev_data_ref) = match (prev_rev, prev_data) {
        (Some(r), Some(d)) => (Some(r), Some(d)),
        _ => (None, None),
    };
    let seq = firehose::emit_commit(
        env,
        did,
        &rev,
        since.as_deref(),
        prev_data_ref.as_ref(),
        &commit_cid,
        ops,
        &slice,
    )
    .await?;

    Ok(CommitOutcome { rev, root: tree.root, commit: commit_cid, commit_bytes, seq })
}

pub struct RepoExport {
    pub rev: String,
    pub root: Cid,
    pub commit: Cid,
    pub commit_bytes: Vec<u8>,
    pub car: Vec<u8>,
}

/// Full repository export (deterministic rebuild + CAR).
pub async fn export_repo(env: &Env, did: &str) -> XrpcResult<RepoExport> {
    let db = pds_env::db(env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let root_row: Option<RootRow> = db
        .prepare("SELECT rev, data_cid, commit_cid FROM repo_root WHERE did = ?1")
        .bind(&[did.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let Some(root_row) = root_row else {
        return Err(XrpcError::not_found("RepoNotFound", "no repo root"));
    };
    let records = load_records(&db, did).await?;
    let (entries, changed) = build_entries(&db, did, &records).await?;
    let tree = mst::build(&entries).map_err(|e| XrpcError::internal(e.to_string()))?;
    let priv_hex = signing_key(&db, did).await?;
    // Deterministic re-sign of the stored rev reproduces the commit bytes.
    let (commit_bytes, commit_cid) =
        mst::sign_commit(&priv_hex, did, &root_row.rev, &tree.root).map_err(|e| XrpcError::internal(e.to_string()))?;
    let nodes: Vec<(Cid, Vec<u8>)> = tree.nodes_preorder.into_iter().map(|n| (n.cid, n.bytes)).collect();
    let mut blocks = Vec::with_capacity(1 + nodes.len() + changed.len());
    blocks.push((commit_cid.clone(), commit_bytes.clone()));
    blocks.extend(nodes);
    blocks.extend(changed);
    let car = mst::build_car(&commit_cid, &blocks);
    Ok(RepoExport { rev: root_row.rev, root: tree.root, commit: commit_cid, commit_bytes, car })
}
