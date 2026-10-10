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
        .route("/xrpc/com.atproto.server.requestPasswordReset", post(not_implemented))
        .route("/xrpc/com.atproto.server.resetPassword", post(not_implemented))
        .route("/xrpc/com.atproto.server.checkAccountStatus", get(not_implemented_get))
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

    // DID: accept caller-provided did:plc (migration/reservation) else mint placeholder.
    // Full PLC directory registration happens out-of-band; doc updated on activation.
    let did = match req.did {
        Some(d) => {
            if !atproto::did::validate(&d) {
                return Err(XrpcError::bad_request("InvalidDid", "did syntax invalid"));
            }
            d
        }
        None => format!("did:plc:dev{}", &uuid::Uuid::new_v4().simple().to_string()[..24]),
    };

    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let now = pds_env::now_iso();
    // Fresh atproto signing key (secp256k1). Stored alongside the account;
    // rotation into a secret store is ROADMAP §4.
    let (priv_hex, pub_hex) = crate::keys::generate_k256().map_err(|e| XrpcError::internal(e.to_string()))?;
    // Minimal account insert; duplicate handle/DID surfaces as 400.
    let insert = db
        .prepare("INSERT INTO account (did, handle, email, email_confirmed, password_hash, signing_key_k256_priv_hex, signing_key_k256_pub_hex, status, active, created_at, updated_at) VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6, 'active', 1, ?7, ?7)")
        .bind(&{
            let email_js: worker::wasm_bindgen::JsValue = match req.email.clone() {
                Some(e) if !e.trim().is_empty() => e.into(),
                _ => worker::wasm_bindgen::JsValue::NULL,
            };
            [did.clone().into(), req.handle.clone().into(), email_js, password_hash.into(), priv_hex.into(), pub_hex.into(), now.clone().into()]
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
    crate::firehose::emit_sync(&s.env, &did, &out.rev, &out.commit, &out.commit_bytes).await?;

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
