//! WebSocket firehose transport (`subscribeRepos`, event-stream v0).
//! Poll-compatible JSON stays available when the client does not upgrade.

use worker::{Env, WebSocketPair};

use crate::firehose;
use crate::pds_env;

/// Is this a WebSocket upgrade request?
pub fn is_ws_upgrade(req: &worker::HttpRequest) -> bool {
    let upgrade = req
        .headers()
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    upgrade.to_lowercase().contains("websocket")
}

/// Accept a firehose subscription: validate cursor, replay, then live-tail.
/// Returns an axum response carrying the 101 upgrade (socket via extension).
pub async fn accept(
    env: Env,
    req: &worker::HttpRequest,
) -> Result<axum::http::Response<axum::body::Body>, worker::Error> {
    // Method already checked by the caller (GET only).
    let query = req.uri().query().unwrap_or("");
    let cursor = parse_cursor(query).map_err(|e| worker::Error::RustError(e))?;
    let db = pds_env::db(&env).map_err(|e| worker::Error::RustError(e.to_string()))?;
    let max_seq: Option<MaxRow> = db
        .prepare("SELECT COALESCE(MAX(seq), 0) AS m FROM firehose_event")
        .first(None)
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))?;
    let max_seq = max_seq.map(|r| r.m).unwrap_or(0);
    let start = cursor.unwrap_or(max_seq);
    if start < 0 {
        return Err(worker::Error::RustError("bad cursor".into()));
    }
    if start > max_seq {
        // Spec: cursor in the future -> error frame, then close.
        let pair = WebSocketPair::new()?;
        pair.server.accept()?;
        let frame = firehose::ws_error_frame("FutureCursor", Some("cursor is ahead of the stream"));
        let _ = pair.server.send_with_bytes(frame);
        pair.server.close(Some(4400), Some("FutureCursor"))?;
        return Ok(worker::Response::from_websocket(pair.client)?.into());
    }
    let pair = WebSocketPair::new()?;
    pair.server.accept()?;
    let server = pair.server.clone();
    // Pump runs detached; the isolate stays alive while the socket is open.
    worker::wasm_bindgen_futures::spawn_local(async move {
        pump(env, server, start).await;
    });
    Ok(worker::Response::from_websocket(pair.client)?.into())
}

#[derive(serde::Deserialize)]
struct MaxRow {
    m: i64,
}

#[derive(serde::Deserialize)]
struct EvRow {
    seq: i64,
    kind: String,
    #[serde(rename = "p")]
    p: String,
}

fn parse_cursor(query: &str) -> Result<Option<i64>, String> {
    for part in query.split('&') {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        if k == "cursor" {
            if v.is_empty() {
                continue;
            }
            return v.parse::<i64>().map(Some).map_err(|_| "bad cursor".into());
        }
    }
    Ok(None)
}

/// Map stored kinds to stream message types (`#commit`, `#sync`, …).
/// Our `kind` column already stores the fragment without `#`; identity and
/// account events map directly.
fn message_type(kind: &str) -> Option<&'static str> {
    match kind {
        "commit" => Some("#commit"),
        "sync" => Some("#sync"),
        "identity" => Some("#identity"),
        "account" => Some("#account"),
        _ => None,
    }
}

async fn pump(env: Env, server: worker::WebSocket, mut last: i64) {
    let db = match pds_env::db(&env) {
        Ok(db) => db,
        Err(_) => return,
    };
    loop {
        let rows = db
            .prepare("SELECT seq, kind, payload_json AS p FROM firehose_event WHERE seq > ?1 ORDER BY seq ASC LIMIT 200")
            .bind(&[(last as f64).into()]);
        let rows = match rows {
            Ok(q) => q,
            Err(_) => return,
        };
        let rows = match rows.all().await {
            Ok(r) => r,
            Err(_) => return,
        };
        let events = rows.results::<EvRow>().unwrap_or_default();
        if events.is_empty() {
            worker::Delay::from(std::time::Duration::from_millis(500)).await;
            // Closed underneath us? Stop quietly on send failure below.
            continue;
        }
        let mut ok = true;
        for ev in events {
            let Some(t) = message_type(&ev.kind) else {
                last = last.max(ev.seq);
                continue;
            };
            let payload: serde_json::Value =
                serde_json::from_str(&ev.p).unwrap_or(serde_json::Value::Null);
            let frame = match firehose::ws_frame(t, &payload) {
                Ok(f) => f,
                Err(_) => continue,
            };
            if server.send_with_bytes(frame).is_err() {
                ok = false;
                break;
            }
            last = last.max(ev.seq);
        }
        if !ok {
            break;
        }
    }
    let _ = server.close(Some(1000), Some("done"));
}
