//! `com.atproto.server.*` — account/session/invite endpoints.
//! Lexicon sources: bluesky-social/atproto `lexicons/com/atproto/server/*`.

use axum::{extract::State, http::HeaderMap, Json};
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use worker::Env;

use crate::{atproto, auth, pds_env, xrpc::{XrpcError, XrpcResult}};

#[derive(Clone)]
pub struct ServerState {
    pub env: Env,
}

pub fn router(env: Env) -> Router {
    Router::new()
        .route("/xrpc/com.atproto.server.describeServer", get(describe_server))
        .route("/xrpc/com.atproto.server.createAccount", post(create_account))
        .route("/xrpc/com.atproto.server.createSession", post(create_session_compat))
        .route("/xrpc/com.atproto.server.refreshSession", post(refresh_session_post))
        .route("/xrpc/com.atproto.server.getSession", get(get_session))
        .route("/xrpc/com.atproto.server.createInviteCode", post(create_invite_code))
        .route("/xrpc/com.atproto.server.createInviteCodes", post(create_invite_codes))
        .route("/xrpc/com.atproto.server.requestPasswordReset", post(request_password_reset))
        .route("/xrpc/com.atproto.server.resetPassword", post(reset_password))
        .route("/xrpc/com.atproto.server.requestEmailConfirmation", post(request_email_confirmation))
        .route("/xrpc/com.atproto.server.confirmEmail", post(confirm_email))
        .route("/xrpc/com.atproto.server.updateEmail", post(update_email))
        .route("/xrpc/com.atproto.server.deleteAccount", post(delete_account))
        .route("/xrpc/com.atproto.server.checkAccountStatus", get(not_implemented_get))
        .route("/xrpc/com.atproto.server.deactivateAccount", post(deactivate_account))
        .route("/xrpc/com.atproto.server.activateAccount", post(activate_account))
        .with_state(ServerState { env })
}

// --- describeServer ---

#[derive(Serialize)]
struct DescribeServerResp {
    #[serde(rename = "did")]
    did: String,
    #[serde(rename = "availableUserDomains")]
    available_user_domains: Vec<String>,
    #[serde(rename = "inviteCodeRequired")]
    invite_code_required: bool,
    #[serde(rename = "phoneVerificationRequired")]
    phone_verification_required: bool,
    links: serde_json::Value,
    #[serde(rename = "contact")]
    contact: serde_json::Value,
}

#[worker::send]
async fn describe_server(State(s): State<ServerState>) -> XrpcResult<Json<DescribeServerResp>> {
    let cfg = pds_env::PdsEnv::from_env(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok(Json(DescribeServerResp {
        did: format!("did:web:{}", cfg.hostname),
        available_user_domains: vec![cfg.hostname.clone()],
        invite_code_required: cfg.invite_required,
        phone_verification_required: false,
        links: serde_json::json!({}),
        contact: serde_json::json!({}),
    }))
}

// --- createAccount ---

#[derive(Deserialize)]
#[allow(dead_code)]
struct CreateAccountReq {
    #[serde(rename = "handle")]
    handle: String,
    #[serde(rename = "email")]
    email: Option<String>,
    #[serde(rename = "password")]
    password: Option<String>,
    #[serde(rename = "inviteCode")]
    invite_code: Option<String>,
    #[serde(rename = "did")]
    did: Option<String>,
}

#[derive(Serialize)]
struct CreateAccountResp {
    #[serde(rename = "did")]
    did: String,
    #[serde(rename = "handle")]
    handle: String,
    #[serde(rename = "email")]
    email: Option<String>,
    #[serde(rename = "emailConfirmed")]
    email_confirmed: bool,
    #[serde(rename = "accessJwt")]
    access_jwt: String,
    #[serde(rename = "refreshJwt")]
    refresh_jwt: String,
    #[serde(rename = "active")]
    active: bool,
}

#[worker::send]
async fn create_account(
    State(s): State<ServerState>,
    headers: HeaderMap,
    Json(req): Json<CreateAccountReq>,
) -> XrpcResult<Json<CreateAccountResp>> {
    let cfg = pds_env::PdsEnv::from_env(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    if !atproto::handle::validate(&req.handle) {
        return Err(XrpcError::bad_request("InvalidHandle", "handle syntax invalid"));
    }
    if cfg.invite_required && req.invite_code.is_none() {
        // Admin token can bypass invite requirement.
        if auth::check_admin(&headers, cfg.admin_password.as_deref()).is_err() {
            return Err(XrpcError::bad_request("InvalidInviteCode", "invite code required"));
        }
    }
    let password = req.password.ok_or_else(|| {
        // OAuth-primary PDS still accepts password for compat/App Passwords.
        XrpcError::bad_request("InvalidPassword", "password required for compat session")
    })?;
    let password_hash = crate::oauth::hash_password(&password)?;

    // Fresh atproto signing key + PLC rotation key (both secp256k1).
    // Rotation keys belong in a secret store long-term (ROADMAP §4).
    let (priv_hex, pub_hex) = crate::keys::generate_k256().map_err(|e| XrpcError::internal(e.to_string()))?;
    let (rot_priv_hex, rot_pub_hex) = crate::keys::generate_k256().map_err(|e| XrpcError::internal(e.to_string()))?;

    // DID: caller-provided (migration/reservation), real PLC registration for
    // public handles, or a local dev DID for loopback handles.
    let local_handle = req.handle == "localhost"
        || req.handle.ends_with(".localhost")
        || req.handle.starts_with("localhost:")
        || req.handle.starts_with("127.")
        || req.handle.starts_with("[::1]");
    let did = match req.did {
        Some(d) => {
            if !atproto::did::validate(&d) {
                return Err(XrpcError::bad_request("InvalidDid", "did syntax invalid"));
            }
            d
        }
        None if local_handle => {
            format!("did:plc:dev{}", &uuid::Uuid::new_v4().simple().to_string()[..24])
        }
        None => {
            // Real federation path: build + sign a PLC genesis op and register it.
            let rotation_did_key = crate::identity::did_key_encode(&rot_pub_hex, &crate::keys::Curve::K256)
                .map_err(|e| XrpcError::internal(e.to_string()))?;
            let signing_did_key = crate::identity::did_key_encode(&pub_hex, &crate::keys::Curve::K256)
                .map_err(|e| XrpcError::internal(e.to_string()))?;
            let (did, op) = crate::identity::plc_genesis_op(
                &rot_priv_hex,
                &crate::identity::PlcGenesis {
                    rotation_did_key,
                    signing_did_key,
                    handle: req.handle.clone(),
                    pds_endpoint: format!("https://{}", cfg.hostname),
                },
            )
            .map_err(|e| XrpcError::internal(e.to_string()))?;
            crate::identity::plc_submit(&s.env, &did, &op).await?;
            did
        }
    };

    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let now = pds_env::now_iso();
    // Minimal account insert; duplicate handle/DID surfaces as 400.
    let insert = db
        .prepare("INSERT INTO account (did, handle, email, email_confirmed, password_hash, signing_key_k256_priv_hex, signing_key_k256_pub_hex, rotation_key_k256_priv_hex, status, active, created_at, updated_at) VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6, ?7, 'active', 1, ?8, ?8)")
        .bind(&{
            let email_js: worker::wasm_bindgen::JsValue = match req.email.clone() {
                Some(e) if !e.trim().is_empty() => e.into(),
                _ => worker::wasm_bindgen::JsValue::NULL,
            };
            [did.clone().into(), req.handle.clone().into(), email_js, password_hash.into(), priv_hex.into(), pub_hex.into(), rot_priv_hex.into(), now.clone().into()]
        })
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run()
        .await;
    if insert.is_err() {
        return Err(XrpcError::bad_request("DuplicateAccount", "handle or DID already exists"));
    }
    // Genesis: empty repo, signed commit, #account + #sync firehose events.
    let out = crate::repo::commit_repo(&s.env, &did, vec![], vec![], None).await?;
    crate::firehose::emit_account(&s.env, &did, true, None).await?;
    crate::firehose::emit_identity(&s.env, &did, Some(&req.handle)).await?;
    crate::firehose::emit_sync(&s.env, &did, &out.rev, &out.commit, &out.commit_bytes).await?;
    // Announce to relays (best-effort; a relay that misses this can still
    // discover the PDS via requestCrawl or handle resolution).
    let _ = crate::routes_sync::notify_crawlers(&s.env, &cfg).await;

    // Compat tokens: HS256-signed JWTs (OAuth DPoP tokens come from /oauth/token).
    let (access_jwt, refresh_jwt) = issue_compat_pair(&s.env, &did)?;

    Ok(Json(CreateAccountResp {
        did: did.clone(),
        handle: req.handle,
        email: req.email,
        email_confirmed: false,
        access_jwt,
        refresh_jwt,
        active: true,
    }))
}

/// Issue a compat session pair (HS256, `PDS_JWT_SECRET`). Access 1h, refresh 7d.
fn issue_compat_pair(env: &worker::Env, did: &str) -> XrpcResult<(String, String)> {
    let cfg = pds_env::PdsEnv::from_env(env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let secret = cfg.jwt_secret.ok_or_else(|| {
        XrpcError::internal("PDS_JWT_SECRET not configured; compat sessions disabled")
    })?;
    let now = (worker::Date::now().as_millis() / 1000) as i64;
    let access = crate::keys::sign_jwt_hs256(
        &secret,
        "at+jwt",
        &serde_json::json!({"iss": format!("https://{}", cfg.hostname), "sub": did, "scope": "transition:generic", "iat": now, "exp": now + 3600}),
    )
    .map_err(|e| XrpcError::internal(e.to_string()))?;
    let refresh = crate::keys::sign_jwt_hs256(
        &secret,
        "refresh+jwt",
        &serde_json::json!({"iss": format!("https://{}", cfg.hostname), "sub": did, "scope": "transition:generic", "iat": now, "exp": now + 7 * 86400}),
    )
    .map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok((access, refresh))
}

// --- compat session (legacy) ---

#[derive(Deserialize)]
#[allow(dead_code)]
struct CreateSessionReq {
    #[serde(rename = "identifier")]
    identifier: String,
    #[serde(rename = "password")]
    password: String,
}

#[derive(Serialize)]
struct SessionResp {
    #[serde(rename = "did")]
    did: String,
    #[serde(rename = "handle")]
    handle: String,
    #[serde(rename = "email")]
    email: Option<String>,
    #[serde(rename = "emailConfirmed")]
    email_confirmed: bool,
    #[serde(rename = "accessJwt")]
    access_jwt: String,
    #[serde(rename = "refreshJwt")]
    refresh_jwt: String,
    #[serde(rename = "active")]
    active: bool,
}

#[worker::send]
async fn create_session_compat(
    State(s): State<ServerState>,
    Json(req): Json<CreateSessionReq>,
) -> XrpcResult<Json<SessionResp>> {
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let row: Option<AccountRow> = db
        .prepare("SELECT did, handle, email, email_confirmed, password_hash AS password_hash, active FROM account WHERE handle = ?1 OR email = ?1 OR did = ?1")
        .bind(&[req.identifier.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let bad = || XrpcError::new(axum::http::StatusCode::UNAUTHORIZED, "AuthenticationRequired", "invalid identifier or password");
    let Some(a) = row else {
        return Err(bad());
    };
    let stored = a.password_hash.clone().unwrap_or_default();
    if stored.is_empty() || !crate::oauth::verify_password(&stored, &req.password) {
        return Err(bad());
    }
    if a.active == 0 {
        return Err(XrpcError::forbidden("AccountDeactivated", "account is not active"));
    }
    let (access_jwt, refresh_jwt) = issue_compat_pair(&s.env, &a.did)?;
    Ok(Json(SessionResp {
        did: a.did.clone(),
        handle: a.handle,
        email: a.email,
        email_confirmed: a.email_confirmed == 1,
        access_jwt,
        refresh_jwt,
        active: a.active == 1,
    }))
}

#[worker::send]
async fn refresh_session_compat(
    State(s): State<ServerState>,
    headers: HeaderMap,
) -> XrpcResult<Json<SessionResp>> {
    let cfg = pds_env::PdsEnv::from_env(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let secret = cfg.jwt_secret.ok_or_else(|| XrpcError::unauthorized("compat sessions not configured"))?;
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| XrpcError::unauthorized("refresh token required"))?;
    let (typ, payload) =
        crate::keys::verify_jwt_hs256(token, &secret).map_err(|_| XrpcError::unauthorized("bad refresh token"))?;
    if typ != "refresh+jwt" {
        return Err(XrpcError::unauthorized("access token cannot refresh"));
    }
    let did = payload.get("sub").and_then(|v| v.as_str()).ok_or_else(|| XrpcError::unauthorized("bad token"))?;
    let exp = payload.get("exp").and_then(|v| v.as_i64()).unwrap_or(0);
    if (worker::Date::now().as_millis() / 1000) as i64 > exp + 30 {
        return Err(XrpcError::unauthorized("refresh token expired"));
    }
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let row: Option<AccountRow> = db
        .prepare("SELECT did, handle, email, email_confirmed, password_hash AS password_hash, active FROM account WHERE did = ?1")
        .bind(&[did.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let Some(a) = row else {
        return Err(XrpcError::unauthorized("unknown account"));
    };
    let (access_jwt, refresh_jwt) = issue_compat_pair(&s.env, &a.did)?;
    Ok(Json(SessionResp {
        did: a.did.clone(),
        handle: a.handle,
        email: a.email,
        email_confirmed: a.email_confirmed == 1,
        access_jwt,
        refresh_jwt,
        active: a.active == 1,
    }))
}

#[worker::send]
#[worker::send]
async fn refresh_session_post(State(s): State<ServerState>, headers: HeaderMap) -> XrpcResult<Json<SessionResp>> {
    refresh_session_compat(State(s), headers).await
}

#[derive(Serialize)]
struct GetSessionResp {
    #[serde(rename = "did")]
    did: String,
    #[serde(rename = "handle")]
    handle: String,
    #[serde(rename = "email", skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(rename = "emailConfirmed")]
    email_confirmed: bool,
    #[serde(rename = "active")]
    active: bool,
}

#[worker::send]
async fn get_session(State(s): State<ServerState>, headers: HeaderMap) -> XrpcResult<Json<GetSessionResp>> {
    let caller = auth::authenticate(&s.env, &headers, "GET", "/xrpc/com.atproto.server.getSession").await?;
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let row: Option<AccountRow> = db
        .prepare("SELECT did, handle, email, email_confirmed, password_hash AS password_hash, active FROM account WHERE did = ?1")
        .bind(&[caller.did.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let Some(a) = row else {
        return Err(XrpcError::unauthorized("unknown account"));
    };
    // OAuth sessions may not expose email unless transition:email was granted.
    let email = if caller.oauth && !caller.scope.split(' ').any(|x| x == "transition:email") {
        None
    } else {
        a.email
    };
    Ok(Json(GetSessionResp {
        did: a.did,
        handle: a.handle,
        email,
        email_confirmed: a.email_confirmed == 1,
        active: a.active == 1,
    }))
}

#[derive(Deserialize)]
struct AccountRow {
    did: String,
    handle: String,
    email: Option<String>,
    email_confirmed: i64,
    password_hash: Option<String>,
    active: i64,
}

// --- invites ---

#[derive(Deserialize)]
#[allow(dead_code)]
struct CreateInviteCodesReq {
    #[serde(rename = "codeCount")]
    code_count: Option<i64>,
    #[serde(rename = "useCount")]
    use_count: Option<i64>,
}

#[derive(Serialize)]
struct InviteCodesResp {
    #[serde(rename = "codes")]
    codes: Vec<InviteCode>,
}

#[derive(Serialize)]
struct InviteCode {
    #[serde(rename = "code")]
    code: String,
    #[serde(rename = "available")]
    available: i64,
    #[serde(rename = "disabled")]
    disabled: bool,
    #[serde(rename = "forAccount")]
    for_account: String,
    #[serde(rename = "createdBy")]
    created_by: String,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "uses")]
    uses: Vec<serde_json::Value>,
}

#[worker::send]
async fn create_invite_code(State(s): State<ServerState>, headers: HeaderMap) -> XrpcResult<Json<InviteCodesResp>> {
    create_invite_codes(State(s), headers, Json(CreateInviteCodesReq { code_count: Some(1), use_count: Some(1) })).await
}

#[worker::send]
async fn create_invite_codes(
    State(s): State<ServerState>,
    headers: HeaderMap,
    Json(req): Json<CreateInviteCodesReq>,
) -> XrpcResult<Json<InviteCodesResp>> {
    let cfg = pds_env::PdsEnv::from_env(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    auth::check_admin(&headers, cfg.admin_password.as_deref())?;
    let n = req.code_count.unwrap_or(1).clamp(1, 100);
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let now = pds_env::now_iso();
    let mut codes = Vec::new();
    for _ in 0..n {
        let code = format!("{}-{}", &cfg.hostname[..cfg.hostname.len().min(4)], &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let _ = db.prepare("INSERT OR IGNORE INTO invite_code (code, created_at) VALUES (?1, ?2)")
            .bind(&[code.clone().into(), now.clone().into()])
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .run().await;
        codes.push(InviteCode {
            code, available: req.use_count.unwrap_or(1), disabled: false,
            for_account: "admin".into(), created_by: "admin".into(),
            created_at: now.clone(), uses: vec![],
        });
    }
    Ok(Json(InviteCodesResp { codes }))
}

#[worker::send]
async fn not_implemented() -> XrpcError {
    XrpcError::not_implemented("endpoint planned (see ROADMAP)")
}

#[worker::send]
async fn not_implemented_get() -> XrpcError {
    XrpcError::not_implemented("endpoint planned (see ROADMAP)")
}

// --- activate / deactivate (account lifecycle) ---

/// Deactivate your own account: content stops being redistributed
/// (`active: false`, `status: deactivated`) and a `#account` event fires.
#[worker::send]
async fn deactivate_account(
    State(s): State<ServerState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> XrpcResult<Json<serde_json::Value>> {
    let _ = body;
    let caller = auth::authenticate(&s.env, &headers, "POST", "/xrpc/com.atproto.server.deactivateAccount").await?;
    set_account_status(&s.env, &caller.did, false, "deactivated").await?;
    Ok(Json(serde_json::json!({})))
}

/// Reactivate your own deactivated account.
#[worker::send]
async fn activate_account(
    State(s): State<ServerState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> XrpcResult<Json<serde_json::Value>> {
    let _ = body;
    let caller = auth::authenticate(&s.env, &headers, "POST", "/xrpc/com.atproto.server.activateAccount").await?;
    set_account_status(&s.env, &caller.did, true, "active").await?;
    Ok(Json(serde_json::json!({})))
}

async fn set_account_status(env: &worker::Env, did: &str, active: bool, status: &str) -> XrpcResult<()> {
    let db = pds_env::db(env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let now = pds_env::now_iso();
    db.prepare("UPDATE account SET active = ?1, status = ?2, updated_at = ?3 WHERE did = ?4")
        .bind(&[(if active { 1.0 } else { 0.0 }).into(), status.into(), now.into(), did.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    crate::firehose::emit_account(env, did, active, if active { None } else { Some(status) }).await?;
    Ok(())
}

// --- email + password-reset + deletion ---

/// Issue a single-use email token (stored hashed).
async fn issue_email_token(
    env: &worker::Env,
    did: &str,
    purpose: &str,
    email: Option<&str>,
    ttl_secs: i64,
) -> XrpcResult<String> {
    let db = pds_env::db(env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let token = crate::keys::random_b64u32().map_err(|e| XrpcError::internal(e.to_string()))?;
    let now = pds_env::now_iso();
    // Expiry as ISO: now + ttl (recompute via millis to stay fixed-width).
    let exp_ms = worker::Date::now().as_millis() as i64 + ttl_secs * 1000;
    let exp = iso_from_millis(exp_ms);
    db.prepare("INSERT INTO email_token (did, purpose, token_hash, email, expires_at, used_at, created_at) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6)")
        .bind(&[
            did.into(),
            purpose.into(),
            crate::keys::sha256_hex(&token).into(),
            email.unwrap_or("").into(),
            exp.into(),
            now.into(),
        ])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok(token)
}

fn iso_from_millis(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_ymd(days + 719_468);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z", y, m, d, tod / 3600, (tod % 3600) / 60, tod % 60, millis)
}

fn civil_ymd(z: i64) -> (i64, u32, u32) {
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

#[derive(serde::Deserialize)]
struct TokenRow {
    did: String,
    email: String,
    expires_at: String,
}

/// Verify + burn an email token. Returns (did, email-field).
async fn consume_email_token(
    env: &worker::Env,
    purpose: &str,
    token: &str,
) -> XrpcResult<(String, String)> {
    let db = pds_env::db(env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let row: Option<TokenRow> = db
        .prepare("SELECT did, email, expires_at FROM email_token WHERE purpose = ?1 AND token_hash = ?2 AND used_at IS NULL")
        .bind(&[purpose.into(), crate::keys::sha256_hex(token).into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let Some(row) = row else {
        return Err(XrpcError::bad_request("InvalidToken", "bad or expired token"));
    };
    if row.expires_at <= pds_env::now_iso() {
        return Err(XrpcError::bad_request("InvalidToken", "token expired"));
    }
    let now = pds_env::now_iso();
    db.prepare("UPDATE email_token SET used_at = ?1 WHERE purpose = ?2 AND token_hash = ?3")
        .bind(&[now.into(), purpose.into(), crate::keys::sha256_hex(token).into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok((row.did, row.email))
}

fn valid_email(email: &str) -> bool {
    email.len() >= 3 && email.len() <= 320 && {
        match email.split_once('@') {
            Some((local, domain)) => {
                !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
                    && email.bytes().all(|b| !b.is_ascii_whitespace())
            }
            None => false,
        }
    }
}

#[derive(serde::Deserialize)]
struct RequestEmailConfirmationReq {
    #[serde(default)]
    email: Option<String>,
}

#[worker::send]
async fn request_email_confirmation(
    State(s): State<ServerState>,
    headers: HeaderMap,
    Json(req): Json<RequestEmailConfirmationReq>,
) -> XrpcResult<Json<serde_json::Value>> {
    let caller = auth::authenticate(&s.env, &headers, "POST", "/xrpc/com.atproto.server.requestEmailConfirmation").await?;
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    #[derive(serde::Deserialize)]
    struct EmailRow {
        email: Option<String>,
        handle: String,
    }
    let row: Option<EmailRow> = db
        .prepare("SELECT email, handle FROM account WHERE did = ?1")
        .bind(&[caller.did.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let Some(acct) = row else {
        return Err(XrpcError::unauthorized("unknown account"));
    };
    let target = req.email.or(acct.email).unwrap_or_default();
    if !valid_email(&target) {
        return Err(XrpcError::bad_request("InvalidEmail", "no usable email on file"));
    }
    let token = issue_email_token(&s.env, &caller.did, "confirm", Some(&target), 24 * 3600).await?;
    let cfg = pds_env::PdsEnv::from_env(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let text = format!(
        "Confirm your email for @{handle} on {host} with this code:\n\n{token}\n\nIt expires in 24 hours. If you did not request this, ignore this message.\n",
        handle = acct.handle,
        host = cfg.hostname
    );
    crate::email::send_email(&s.env, &target, "Confirm your email", &text).await?;
    Ok(Json(serde_json::json!({})))
}

#[derive(serde::Deserialize)]
struct ConfirmEmailReq {
    email: String,
    token: String,
}

#[worker::send]
async fn confirm_email(State(s): State<ServerState>, Json(req): Json<ConfirmEmailReq>) -> XrpcResult<Json<serde_json::Value>> {
    let (did, _) = consume_email_token(&s.env, "confirm", &req.token).await?;
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    #[derive(serde::Deserialize)]
    struct WhoRow {
        did: String,
    }
    // The email in the request must belong to the token holder.
    let row: Option<WhoRow> = db
        .prepare("SELECT did FROM account WHERE email = ?1")
        .bind(&[req.email.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    match row {
        Some(r) if r.did == did => {}
        _ => return Err(XrpcError::bad_request("InvalidToken", "email does not match token")),
    }
    db.prepare("UPDATE account SET email_confirmed = 1 WHERE did = ?1")
        .bind(&[did.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok(Json(serde_json::json!({})))
}

#[derive(serde::Deserialize)]
struct UpdateEmailReq {
    email: String,
    #[serde(default)]
    token: Option<String>,
}

#[worker::send]
async fn update_email(
    State(s): State<ServerState>,
    headers: HeaderMap,
    Json(req): Json<UpdateEmailReq>,
) -> XrpcResult<Json<serde_json::Value>> {
    let caller = auth::authenticate(&s.env, &headers, "POST", "/xrpc/com.atproto.server.updateEmail").await?;
    if !valid_email(&req.email) {
        return Err(XrpcError::bad_request("InvalidEmail", "bad email address"));
    }
    // With a confirmation token, apply immediately; otherwise stage + send code.
    if let Some(token) = req.token.as_deref() {
        let (did, token_email) = consume_email_token(&s.env, "update", token).await?;
        if did != caller.did || token_email != req.email {
            return Err(XrpcError::bad_request("InvalidToken", "token does not match"));
        }
        let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
        db.prepare("UPDATE account SET email = ?1, email_confirmed = 1 WHERE did = ?2")
            .bind(&[req.email.clone().into(), caller.did.into()])
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .run()
            .await
            .map_err(|e| XrpcError::internal(e.to_string()))?;
        return Ok(Json(serde_json::json!({})));
    }
    let token = issue_email_token(&s.env, &caller.did, "update", Some(&req.email), 24 * 3600).await?;
    let text = format!("Confirm your new email address with this code:\n\n{token}\n\nIt expires in 24 hours.\n");
    crate::email::send_email(&s.env, &req.email, "Confirm your new email", &text).await?;
    Ok(Json(serde_json::json!({})))
}

#[derive(serde::Deserialize)]
struct RequestPasswordResetReq {
    email: String,
}

#[worker::send]
async fn request_password_reset(State(s): State<ServerState>, Json(req): Json<RequestPasswordResetReq>) -> XrpcResult<Json<serde_json::Value>> {
    // Never reveal whether the email exists.
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    #[derive(serde::Deserialize)]
    struct DidRow2 {
        did: String,
    }
    let row: Option<DidRow2> = db
        .prepare("SELECT did FROM account WHERE email = ?1")
        .bind(&[req.email.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    if let Some(r) = row {
        let token = issue_email_token(&s.env, &r.did, "reset", None, 3600).await?;
        let text = format!("Reset your password with this code:\n\n{token}\n\nIt expires in 1 hour. If you did not request this, ignore this message.\n");
        let _ = crate::email::send_email(&s.env, &req.email, "Reset your password", &text).await;
    }
    Ok(Json(serde_json::json!({})))
}

#[derive(serde::Deserialize)]
struct ResetPasswordReq {
    token: String,
    password: String,
}

#[worker::send]
async fn reset_password(State(s): State<ServerState>, Json(req): Json<ResetPasswordReq>) -> XrpcResult<Json<serde_json::Value>> {
    let (did, _) = consume_email_token(&s.env, "reset", &req.token).await?;
    let hash = crate::oauth::hash_password(&req.password)?;
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    db.prepare("UPDATE account SET password_hash = ?1 WHERE did = ?2")
        .bind(&[hash.into(), did.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok(Json(serde_json::json!({})))
}

#[derive(serde::Deserialize)]
struct DeleteAccountReq {
    #[serde(default)]
    did: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

/// Delete your own account (password required): wipes records, blobs, repo
/// state and sessions, then emits `#account` deleted. PLC tombstoning is a
/// separate rotation-key operation (see ROADMAP §4).
#[worker::send]
async fn delete_account(
    State(s): State<ServerState>,
    headers: HeaderMap,
    Json(req): Json<DeleteAccountReq>,
) -> XrpcResult<Json<serde_json::Value>> {
    let caller = auth::authenticate(&s.env, &headers, "POST", "/xrpc/com.atproto.server.deleteAccount").await?;
    let did = req.did.clone().unwrap_or_else(|| caller.did.clone());
    if did != caller.did {
        return Err(XrpcError::forbidden("AuthFailed", "can only delete your own account"));
    }
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    #[derive(serde::Deserialize)]
    struct PwRow {
        password_hash: Option<String>,
    }
    let row: Option<PwRow> = db
        .prepare("SELECT password_hash FROM account WHERE did = ?1")
        .bind(&[did.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let Some(pw) = row else {
        return Err(XrpcError::not_found("AccountNotFound", "unknown account"));
    };
    let password = req.password.ok_or_else(|| XrpcError::bad_request("InvalidPassword", "password required"))?;
    match pw.password_hash {
        Some(h) if crate::oauth::verify_password(&h, &password) => {}
        _ => return Err(XrpcError::new(axum::http::StatusCode::UNAUTHORIZED, "AuthenticationRequired", "bad password")),
    }
    // Blobs: drop R2 objects, then all relational state.
    if let Ok(bucket) = s.env.bucket("BLOBS") {
        if let Ok(listed) = bucket.list().prefix(format!("{did}/")).execute().await {
            for obj in listed.objects() {
                let _ = bucket.delete(&obj.key()).await;
            }
        }
    }
    // Wipe relational state (kept explicit per table for audit).
    for stmt in [
        "DELETE FROM record WHERE did = ?1",
        "DELETE FROM blob WHERE did = ?1",
        "DELETE FROM repo_root WHERE did = ?1",
        "DELETE FROM firehose_event WHERE did = ?1",
        "DELETE FROM oauth_token WHERE did = ?1",
        "DELETE FROM email_token WHERE did = ?1",
        "DELETE FROM account WHERE did = ?1",
    ] {
        db.prepare(stmt)
            .bind(&[did.clone().into()])
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .run()
            .await
            .map_err(|e| XrpcError::internal(e.to_string()))?;
    }
    crate::firehose::emit_account(&s.env, &did, false, Some("deleted")).await?;
    Ok(Json(serde_json::json!({})))
}
