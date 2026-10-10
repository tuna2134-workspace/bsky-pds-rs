//! PDS environment + D1 helpers.

use worker::*;

pub struct PdsEnv {
    pub hostname: String,
    pub plc_url: String,
    pub appview_url: String,
    pub appview_did: String,
    pub admin_password: Option<String>,
    pub jwt_secret: Option<String>,
    pub invite_required: bool,
    pub blob_upload_limit: usize,
}

impl PdsEnv {
    pub fn from_env(env: &Env) -> Result<Self> {
        Ok(Self {
            hostname: env.var("PDS_HOSTNAME").map(|v| v.to_string()).unwrap_or_else(|_| "localhost".into()),
            plc_url: env.var("PDS_DID_PLC_URL").map(|v| v.to_string()).unwrap_or_else(|_| "https://plc.directory".into()),
            appview_url: env.var("PDS_BSKY_APP_VIEW_URL").map(|v| v.to_string()).unwrap_or_else(|_| "https://api.bsky.app".into()),
            appview_did: env.var("PDS_BSKY_APP_VIEW_DID").map(|v| v.to_string()).unwrap_or_else(|_| "did:web:api.bsky.app".into()),
            admin_password: env.var("PDS_ADMIN_PASSWORD").map(|v| v.to_string()).ok(),
            jwt_secret: env.var("PDS_JWT_SECRET").map(|v| v.to_string()).ok(),
            invite_required: env.var("PDS_INVITE_REQUIRED").map(|v| v.to_string()).unwrap_or_else(|_| "true".into()) == "true",
            blob_upload_limit: env.var("PDS_BLOB_UPLOAD_LIMIT").map(|v| v.to_string()).ok().and_then(|s| s.parse().ok()).unwrap_or(52_428_800),
        })
    }
}

pub fn db(env: &Env) -> Result<D1Database> {
    env.d1("DB")
}

pub fn now_iso() -> String {
    // RFC3339 UTC (`2026-10-10T00:00:00.000Z`) from epoch millis without
    // chrono (kept out for wasm size). Howard Hinnant's days-from-civil.
    let ms = Date::now().as_millis() as i64;
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days + 719_468); // days since 0000-03-01 base
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y, m, d,
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60,
        millis
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Allocate next firehose `seq` atomically (best-effort on D1).
pub async fn next_seq(db: &D1Database) -> Result<i64> {
    db.prepare("UPDATE seq_state SET seq = seq + 1 WHERE name = 'repo_seq'")
        .run()
        .await?;
    let row: Option<SeqRow> = db
        .prepare("SELECT seq FROM seq_state WHERE name = 'repo_seq'")
        .first(None)
        .await?;
    Ok(row.map(|r| r.seq).unwrap_or(0))
}

#[derive(serde::Deserialize)]
struct SeqRow {
    seq: i64,
}
