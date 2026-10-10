//! Periodic maintenance: PLC audit re-verification for hosted DIDs.
//!
//! A compromised or misbehaving directory could serve a forked log; the PDS
//! re-validates every hosted `did:plc` chain (genesis recompute, rotation
//! signatures, CID linkage) on a cron cadence and records the outcome where
//! operators can see it (`/metrics` + platform logs). Tampering never
//! auto-takedowns accounts — that stays an explicit operator decision
//! (`updateSubjectStatus`).

use crate::identity;
use crate::pds_env;
use worker::Env;

#[derive(serde::Deserialize)]
struct DidRow {
    did: String,
}

/// Re-verify up to 25 hosted PLC DIDs (KV cursor rotates across runs).
/// Returns (checked, failures).
pub async fn audit_hosted_dids(env: &Env) -> (usize, usize) {
    let db = match pds_env::db(env) {
        Ok(db) => db,
        Err(e) => {
            worker::console_warn!("audit: no D1: {e}");
            return (0, 0);
        }
    };
    let cursor: i64 = kv_get_i64(env, "plc:audit:cursor").await;
    let rows = db
        .prepare(
            "SELECT did FROM account WHERE did LIKE 'did:plc:%' AND did NOT LIKE 'did:plc:dev%' ORDER BY did ASC LIMIT 25 OFFSET ?1",
        )
        .bind(&[(cursor as f64).into()])
        .map_err(|e| {
            worker::console_warn!("audit: list failed: {e}");
            e
        });
    let rows = match rows {
        Ok(q) => q,
        Err(_) => return (0, 0),
    };
    let rows = match rows.all().await {
        Ok(r) => r,
        Err(_) => return (0, 0),
    };
    let dids: Vec<String> = rows
        .results::<DidRow>()
        .unwrap_or_default()
        .into_iter()
        .map(|r| r.did)
        .collect();
    // Rotate the cursor when we hit the end so the next run restarts.
    let next_cursor = if dids.len() < 25 { "0".to_string() } else { (cursor + 25).to_string() };
    kv_put(env, "plc:audit:cursor", &next_cursor).await;
    let mut checked = 0usize;
    let mut failures = 0usize;
    for did in &dids {
        checked += 1;
        match audit_one(env, did).await {
            Ok(ops) => {
                worker::console_log!("audit: {did} ok ({ops} ops)");
            }
            Err(e) => {
                failures += 1;
                worker::console_warn!("audit: {did} FAILED: {e}");
            }
        }
    }
    // Summary for /metrics + operators.
    let now = pds_env::now_iso();
    kv_put(
        env,
        "plc:audit:summary",
        &serde_json::json!({ "checked": checked, "failures": failures, "at": now }).to_string(),
    )
    .await;
    (checked, failures)
}

async fn audit_one(env: &Env, did: &str) -> Result<usize, String> {
    let entries = identity::fetch_audit_log(env, did).await?;
    let ops = identity::verify_audit_log(did, &entries)?;
    kv_put(
        env,
        &format!("plc:audit:{did}"),
        &serde_json::json!({ "ok": true, "ops": ops, "at": pds_env::now_iso() }).to_string(),
    )
    .await;
    Ok(ops)
}

async fn kv_get_i64(env: &Env, key: &str) -> i64 {
    if let Ok(store) = env.kv("CACHE") {
        if let Ok(Some(s)) = store.get(key).text().await {
            if let Ok(n) = s.parse::<i64>() {
                return n;
            }
        }
    }
    0
}

async fn kv_put(env: &Env, key: &str, value: &str) {
    if let Ok(store) = env.kv("CACHE") {
        if let Ok(put) = store.put(key, value.to_string()) {
            let _ = put.expiration_ttl(86400).execute().await;
        }
    }
}
