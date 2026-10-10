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
        .route("/xrpc/com.atproto.server.refreshSession", post(refresh_session_compat))
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
    if req.password.is_none() {
        // OAuth-primary PDS still accepts password for compat/App Passwords.
        // Require *something* so legacy createSession keeps working.
        return Err(XrpcError::bad_request("InvalidPassword", "password required for compat session"));
    }

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
        .prepare("INSERT INTO account (did, handle, email, email_confirmed, signing_key_k256_priv_hex, signing_key_k256_pub_hex, status, active, created_at, updated_at) VALUES (?1, ?2, ?3, 0, ?4, ?5, 'active', 1, ?6, ?6)")
        .bind(&[did.clone().into(), req.handle.clone().into(), req.email.clone().unwrap_or_default().into(), priv_hex.into(), pub_hex.into(), now.clone().into()])
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

    // Compat tokens: unsigned dev JWTs (header.alg=none) so shape matches
    // createSession clients; OAuth DPoP tokens are issued via /oauth/token.
    let access_jwt = dev_jwt(&did, "at+jwt");
    let refresh_jwt = dev_jwt(&did, "refresh+jwt");

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

fn dev_jwt(did: &str, typ: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64U;
    use base64::Engine;
    let h = B64U.encode(serde_json::json!({"alg":"none","typ":typ}).to_string());
    let p = B64U.encode(serde_json::json!({"sub":did,"iat":0,"exp":9999999999i64,"scope":"transition:generic"}).to_string());
    format!("{h}.{p}.")
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
    let _ = req.password; // TODO: picks up password_hash verification (argon2) — compat only
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let row: Option<AccountRow> = db
        .prepare("SELECT did, handle, email, email_confirmed, active FROM account WHERE handle = ?1 OR email = ?1 OR did = ?1")
        .bind(&[req.identifier.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let Some(a) = row else {
        return Err(XrpcError::new(axum::http::StatusCode::UNAUTHORIZED, "AuthenticationRequired", "invalid identifier or password"));
    };
    if a.active == 0 {
        return Err(XrpcError::forbidden("AccountDeactivated", "account is not active"));
    }
    Ok(Json(SessionResp {
        did: a.did.clone(),
        handle: a.handle,
        email: a.email,
        email_confirmed: a.email_confirmed == 1,
        access_jwt: dev_jwt(&a.did, "at+jwt"),
        refresh_jwt: dev_jwt(&a.did, "refresh+jwt"),
        active: a.active == 1,
    }))
}

#[worker::send]
async fn refresh_session_compat(State(s): State<ServerState>, headers: HeaderMap) -> XrpcResult<Json<SessionResp>> {
    let caller = auth::caller_from_headers(&headers)?;
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let row: Option<AccountRow> = db
        .prepare("SELECT did, handle, email, email_confirmed, active FROM account WHERE did = ?1")
        .bind(&[caller.did.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let Some(a) = row else {
        return Err(XrpcError::unauthorized("unknown account"));
    };
    Ok(Json(SessionResp {
        did: a.did.clone(),
        handle: a.handle,
        email: a.email,
        email_confirmed: a.email_confirmed == 1,
        access_jwt: dev_jwt(&a.did, "at+jwt"),
        refresh_jwt: dev_jwt(&a.did, "refresh+jwt"),
        active: a.active == 1,
    }))
}

#[worker::send]
async fn get_session(State(s): State<ServerState>, headers: HeaderMap) -> XrpcResult<Json<SessionResp>> {
    refresh_session_compat(State(s), headers).await
}

#[derive(Deserialize)]
struct AccountRow {
    did: String,
    handle: String,
    email: Option<String>,
    email_confirmed: i64,
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
