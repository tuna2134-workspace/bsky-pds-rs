//! Fixed-window rate limiting (D1-backed, shared across isolates).
//! Spec-wise XRPC uses 429 + `Retry-After`; see [`crate::xrpc::XrpcError`].

use crate::pds_env;
use crate::xrpc::XrpcError;
use worker::Env;

/// Check + increment a named bucket. `limit` events per `window_secs`.
/// On exhaustion returns 429 with `Retry-After` seconds.
pub async fn check(env: &Env, bucket: &str, limit: i64, window_secs: i64) -> Result<(), XrpcError> {
    let now = (worker::Date::now().as_millis() / 1000) as i64;
    let window_start = now - (now % window_secs.max(1));
    let db = pds_env::db(env).map_err(|e| XrpcError::internal(e.to_string()))?;
    // Opportunistic GC of old windows (cheap, runs inline).
    let _ = db
        .prepare("DELETE FROM rate_limit WHERE window_start < ?1")
        .bind(&[((window_start - 2 * window_secs.max(1)) as f64).into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run()
        .await;
    db.prepare("INSERT INTO rate_limit (bucket, window_start, count) VALUES (?1, ?2, 1) ON CONFLICT(bucket, window_start) DO UPDATE SET count = count + 1")
        .bind(&[bucket.into(), (window_start as f64).into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    #[derive(serde::Deserialize)]
    struct CountRow {
        count: f64,
    }
    let row: Option<CountRow> = db
        .prepare("SELECT count FROM rate_limit WHERE bucket = ?1 AND window_start = ?2")
        .bind(&[bucket.into(), (window_start as f64).into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let count = row.map(|r| r.count as i64).unwrap_or(1);
    if count > limit {
        let retry_after = (window_start + window_secs - now).max(1).to_string();
        return Err(XrpcError::rate_limited("slow down")
            .header("retry-after", retry_after));
    }
    Ok(())
}

/// Best-effort client identity for bucketing (CDN header, else unknown).
/// Note: trivially spoofable without a trusted edge; per-DID buckets carry
/// the real weight for authenticated routes.
pub fn client_ip(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        })
}
