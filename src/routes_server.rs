//! `com.atproto.server.*` — account/session/invite endpoints.
//! Lexicon sources: bluesky-social/atproto `lexicons/com/atproto/server/*`.

use axum::{extract::{Query, State}, http::HeaderMap, Json};
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
        .route("/xrpc/com.atproto.server.deactivateAccount", post(deactivate_account))
        .route("/xrpc/com.atproto.server.activateAccount", post(activate_account))
        .route("/xrpc/com.atproto.server.deleteSession", post(delete_session))
        .route("/xrpc/com.atproto.server.createAppPassword", post(create_app_password))
        .route("/xrpc/com.atproto.server.listAppPasswords", get(list_app_passwords))
        .route("/xrpc/com.atproto.server.revokeAppPassword", post(revoke_app_password))
        .route("/xrpc/com.atproto.server.getServiceAuth", get(get_service_auth))
        .route("/xrpc/com.atproto.server.checkAccountStatus", get(check_account_status))
        .route("/xrpc/com.atproto.server.requestEmailUpdate", post(request_email_update))
        .route("/xrpc/com.atproto.server.requestAccountDelete", post(request_account_delete))
        .route("/xrpc/com.atproto.server.getAccountInviteCodes", get(get_account_invite_codes))
        .route("/xrpc/com.atproto.server.reserveSigningKey", post(reserve_signing_key))
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
    #[serde(rename = "blobUploadLimit")]
    blob_upload_limit: i64,
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
        blob_upload_limit: cfg.blob_upload_limit as i64,
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
    #[serde(rename = "recoveryKey")]
    recovery_key: Option<String>,
    #[serde(rename = "plcOp")]
    plc_op: Option<serde_json::Value>,
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
    #[serde(rename = "didDoc")]
    did_doc: serde_json::Value,
}

#[worker::send]
async fn create_account(
    State(s): State<ServerState>,
    headers: HeaderMap,
    Json(req): Json<CreateAccountReq>,
) -> XrpcResult<Json<CreateAccountResp>> {
    let cfg = pds_env::PdsEnv::from_env(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    // Operator provisioning (valid admin token) is exempt from the abuse
    // bucket; anonymous/public signups are not.
    let admin_bypass = auth::check_admin(&headers, cfg.admin_password.as_deref()).is_ok();
    if !admin_bypass {
        crate::ratelimit::check(&s.env, &format!("acct:{}", crate::ratelimit::client_ip(&headers)), 20, 300).await?;
    }
    if !atproto::handle::validate(&req.handle) {
        return Err(XrpcError::bad_request("InvalidHandle", "handle syntax invalid"));
    }
    if cfg.invite_required && req.invite_code.is_none() && !admin_bypass {
        return Err(XrpcError::bad_request("InvalidInviteCode", "invite code required"));
    }
    if let Some(code) = req.invite_code.as_deref() {
        if !admin_bypass {
            let db0 = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
            #[derive(serde::Deserialize)]
            struct InviteRow {
                used_by: Option<String>,
                disabled: i64,
            }
            let row: Option<InviteRow> = db0
                .prepare("SELECT used_by, disabled FROM invite_code WHERE code = ?1")
                .bind(&[code.into()])
                .map_err(|e| XrpcError::internal(e.to_string()))?
                .first(None)
                .await
                .map_err(|e| XrpcError::internal(e.to_string()))?;
            match row {
                Some(r) if r.used_by.is_none() && r.disabled == 0 => {}
                _ => return Err(XrpcError::bad_request("InvalidInviteCode", "bad, used, or disabled invite code")),
            }
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

    // Recovery key: user-held rotation key, highest PLC priority when given.
    // Must be a did:key the PDS can parse (private half stays with the user).
    let user_recovery_key: Option<String> = match req.recovery_key.as_deref() {
        Some(k) => {
            // Validate shape now; the directory enforces the rest on submit.
            if !k.starts_with("did:key:z") {
                return Err(XrpcError::bad_request("InvalidRequest", "recoveryKey must be a did:key"));
            }
            Some(k.to_string())
        }
        None => None,
    };

    // DID: caller-provided (migration/reservation, optionally with a signed
    // plcOp), real PLC registration for public handles, or a local dev DID
    // for loopback handles.
    let local_handle = req.handle == "localhost"
        || req.handle.ends_with(".localhost")
        || req.handle.starts_with("localhost:")
        || req.handle.starts_with("127.")
        || req.handle.starts_with("[::1]");
    let did = match req.did.clone() {
        Some(d) => {
            if !atproto::did::validate(&d) {
                return Err(XrpcError::bad_request("InvalidDid", "did syntax invalid"));
            }
            if let Some(op) = req.plc_op.as_ref() {
                // Migration import: verify the caller's signed op and submit it.
                submit_account_plc_op(&s.env, &d, op).await?;
            }
            d
        }
        None if local_handle => {
            format!("did:plc:dev{}", &uuid::Uuid::new_v4().simple().to_string()[..24])
        }
        None => {
            // Real federation path: build + sign a PLC genesis op and register it.
            let mut rotation_keys = Vec::new();
            if let Some(user_key) = user_recovery_key.clone() {
                rotation_keys.push(user_key);
            }
            let own_rotation = crate::identity::did_key_encode(&rot_pub_hex, &crate::keys::Curve::K256)
                .map_err(|e| XrpcError::internal(e.to_string()))?;
            rotation_keys.push(own_rotation);
            let signing_did_key = crate::identity::did_key_encode(&pub_hex, &crate::keys::Curve::K256)
                .map_err(|e| XrpcError::internal(e.to_string()))?;
            let (did, op) = crate::identity::plc_genesis_op(
                &rot_priv_hex,
                rotation_keys,
                &crate::identity::PlcGenesis {
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

    // Network availability: a non-local handle already pointing at a
    // DIFFERENT did is taken (HandleNotAvailable). Unresolvable handles
    // proceed; DNS proof completes out-of-band (see handleIsCorrect).
    if !local_handle {
        if let Ok(Some(other)) = crate::identity::resolve_handle_to_did(&s.env, &req.handle).await {
            if Some(other.as_str()) != req.did.as_deref() {
                return Err(XrpcError::bad_request("HandleNotAvailable", "handle already claimed on the network"));
            }
        }
    }

    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    // Adopt a reserved signing key when migrating in (reserveSigningKey).
    let mut priv_hex = priv_hex;
    let mut pub_hex = pub_hex;
    #[derive(serde::Deserialize)]
    struct ReservedRow {
        priv_hex: String,
        pub_hex: String,
    }
    let reserved: Option<ReservedRow> = db
        .prepare("SELECT priv_hex, pub_hex FROM reserved_key WHERE did = ?1")
        .bind(&[did.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    if let Some(r) = reserved {
        priv_hex = r.priv_hex;
        pub_hex = r.pub_hex;
        db.prepare("DELETE FROM reserved_key WHERE did = ?1")
            .bind(&[did.clone().into()])
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .run()
            .await
            .map_err(|e| XrpcError::internal(e.to_string()))?;
    }
    let now = pds_env::now_iso();
    // Minimal account insert; duplicate handle/DID surfaces as 400.
    let insert = db
        .prepare("INSERT INTO account (did, handle, email, email_confirmed, password_hash, signing_key_k256_priv_hex, signing_key_k256_pub_hex, rotation_key_k256_priv_hex, status, active, created_at, updated_at) VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6, ?7, 'active', 1, ?8, ?8)")
        .bind(&{
            let email_js: worker::wasm_bindgen::JsValue = match req.email.clone() {
                Some(e) if !e.trim().is_empty() => e.into(),
                _ => worker::wasm_bindgen::JsValue::NULL,
            };
            [did.clone().into(), req.handle.clone().into(), email_js, password_hash.into(), priv_hex.clone().into(), pub_hex.clone().into(), rot_priv_hex.into(), now.clone().into()]
        })
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run()
        .await;
    if insert.is_err() {
        // Distinguish handle vs DID collisions for lexicon error names.
        let db2 = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
        #[derive(serde::Deserialize)]
        struct TakenRow {
            #[allow(dead_code)]
            handle: String,
        }
        let taken: Option<TakenRow> = db2
            .prepare("SELECT handle FROM account WHERE handle = ?1")
            .bind(&[req.handle.clone().into()])
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .first(None)
            .await
            .map_err(|e| XrpcError::internal(e.to_string()))?;
        if taken.is_some() {
            return Err(XrpcError::bad_request("HandleNotAvailable", "handle already taken"));
        }
        return Err(XrpcError::bad_request("InvalidDid", "DID already registered here"));
    }
    if let Some(code) = req.invite_code.as_deref() {
        if !admin_bypass {
            let now_used = pds_env::now_iso();
            db.prepare("UPDATE invite_code SET used_by = ?1, used_at = ?2 WHERE code = ?3")
                .bind(&[did.clone().into(), now_used.into(), code.into()])
                .map_err(|e| XrpcError::internal(e.to_string()))?
                .run()
                .await
                .map_err(|e| XrpcError::internal(e.to_string()))?;
        }
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
    let (access_jwt, refresh_jwt) = issue_compat_pair(&s.env, &did, 0, None, &priv_hex)?;

    Ok(Json(CreateAccountResp {
        did: did.clone(),
        handle: req.handle.clone(),
        email: req.email,
        email_confirmed: false,
        access_jwt,
        refresh_jwt,
        active: true,
        did_doc: crate::routes_repo::did_doc_for(
            &did,
            &req.handle,
            Some(&pub_hex),
            &format!("https://{}", cfg.hostname),
        ),
    }))
}

/// Verify a caller-supplied migration PLC op and submit it for `did`.
/// Genesis ops (prev null) are self-certifying: the DID recomputes from the
/// signed bytes and the signature must verify under the op's own rotation
/// keys. Update ops (prev set) are authorized by the CURRENT rotation keys
/// with `prev` pinned to the directory head (TOFU-free chaining).
async fn submit_account_plc_op(env: &worker::Env, did: &str, op: &serde_json::Value) -> XrpcResult<()> {
    if op.get("type").and_then(|v| v.as_str()) != Some("plc_operation") {
        return Err(XrpcError::bad_request("InvalidRequest", "only plc_operation supported here"));
    }
    let is_genesis = op.get("prev").map(|v| v.is_null()).unwrap_or(true);
    if is_genesis {
        let rotation_keys: Vec<String> = op
            .get("rotationKeys")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|k| k.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();
        if rotation_keys.is_empty() {
            return Err(XrpcError::bad_request("InvalidRequest", "rotationKeys required"));
        }
        // Recompute the DID from the signed bytes (self-certifying check).
        let signed_bytes = crate::cbor::encode_json(op).map_err(|e| XrpcError::bad_request("InvalidRequest", e.to_string()))?;
        let hash = crate::keys::sha256_of(&signed_bytes);
        let b32 = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &hash).to_lowercase();
        if did != format!("did:plc:{}", &b32[..24]) {
            return Err(XrpcError::bad_request("IncompatibleDidDoc", "plcOp does not match the DID"));
        }
        crate::identity::verify_plc_op(op, &rotation_keys)
            .map_err(|e| XrpcError::bad_request("IncompatibleDidDoc", e))?;
    } else {
        // Update: pin to the directory head, verify under current keys.
        let current = crate::identity::plc_current(env, did)
            .await
            .map_err(|e| XrpcError::bad_request("UnresolvableDid", e))?;
        let prev = op.get("prev").and_then(|v| v.as_str()).unwrap_or_default();
        if prev != current.prev_cid {
            return Err(XrpcError::bad_request("IncompatibleDidDoc", "plcOp prev is stale"));
        }
        crate::identity::verify_plc_op(op, &current.fields.rotation_keys)
            .map_err(|e| XrpcError::bad_request("IncompatibleDidDoc", e))?;
    }
    crate::identity::plc_submit(env, did, op).await?;
    Ok(())
}

/// Issue a compat session pair. Access is ES256K under the account key
/// (`iss` = account DID, verifiable by any federation peer via the DID
/// doc); refresh stays HS256 (`PDS_JWT_SECRET`, only this PDS consumes it).
/// Access 1h, refresh 7d. `app_password`: None for primary, Some(privileged).
fn issue_compat_pair(
    env: &worker::Env,
    did: &str,
    epoch: i64,
    app_password: Option<bool>,
    signing_priv_hex: &str,
) -> XrpcResult<(String, String)> {
    let cfg = pds_env::PdsEnv::from_env(env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let secret = cfg.jwt_secret.ok_or_else(|| {
        XrpcError::internal("PDS_JWT_SECRET not configured; compat sessions disabled")
    })?;
    let now = (worker::Date::now().as_millis() / 1000) as i64;
    let mut access_claims = serde_json::json!({"iss": did, "sub": did, "scope": "transition:generic", "iat": now, "exp": now + 3600, "epoch": epoch});
    let mut refresh_claims = serde_json::json!({"iss": format!("https://{}", cfg.hostname), "sub": did, "scope": "transition:generic", "iat": now, "exp": now + 7 * 86400, "epoch": epoch});
    if let Some(privileged) = app_password {
        access_claims["appPassword"] = serde_json::Value::Bool(true);
        access_claims["privileged"] = serde_json::Value::Bool(privileged);
        refresh_claims["appPassword"] = serde_json::Value::Bool(true);
        refresh_claims["privileged"] = serde_json::Value::Bool(privileged);
    }
    let access = crate::keys::sign_access_es256k(signing_priv_hex, &access_claims)
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let refresh = crate::keys::sign_jwt_hs256(&secret, "refresh+jwt", &refresh_claims)
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
    headers: HeaderMap,
    Json(req): Json<CreateSessionReq>,
) -> XrpcResult<Json<SessionResp>> {
    crate::ratelimit::check(&s.env, &format!("session:{}", crate::ratelimit::client_ip(&headers)), 60, 60).await?;
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let row: Option<AccountRow> = db
        .prepare("SELECT did, handle, email, email_confirmed, password_hash AS password_hash, session_epoch, active, signing_key_k256_priv_hex AS signing_priv FROM account WHERE handle = ?1 OR email = ?1 OR did = ?1")
        .bind(&[req.identifier.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let bad = || XrpcError::new(axum::http::StatusCode::UNAUTHORIZED, "AuthenticationRequired", "invalid identifier or password");
    let Some(a) = row else {
        return Err(bad());
    };
    // Primary password first, then app passwords (reduced privilege surface).
    let stored = a.password_hash.clone().unwrap_or_default();
    let app_password: Option<bool>;
    if !stored.is_empty() && crate::oauth::verify_password(&stored, &req.password) {
        app_password = None;
    } else {
        #[derive(serde::Deserialize)]
        struct AppPwRow {
            password_hash: String,
            privileged: i64,
        }
        let pwrow: Option<AppPwRow> = db
            .prepare("SELECT password_hash, privileged FROM app_password WHERE did = ?1")
            .bind(&[a.did.clone().into()])
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .all()
            .await
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .results::<AppPwRow>()
            .unwrap_or_default()
            .into_iter()
            .find(|r| crate::oauth::verify_password(&r.password_hash, &req.password));
        match pwrow {
            Some(r) => app_password = Some(r.privileged == 1),
            None => return Err(bad()),
        }
    }
    if a.active == 0 {
        return Err(XrpcError::forbidden("AccountDeactivated", "account is not active"));
    }
    let (access_jwt, refresh_jwt) = issue_compat_pair(&s.env, &a.did, a.session_epoch, app_password, a.signing_priv.as_deref().unwrap_or_default())?;
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
    let token_epoch = payload.get("epoch").and_then(|v| v.as_i64()).unwrap_or(-1);
    let token_app_pw = payload.get("appPassword").and_then(|v| v.as_bool()).unwrap_or(false);
    let token_priv = payload.get("privileged").and_then(|v| v.as_bool()).unwrap_or(false);
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let row: Option<AccountRow> = db
        .prepare("SELECT did, handle, email, email_confirmed, password_hash AS password_hash, session_epoch, active, signing_key_k256_priv_hex AS signing_priv FROM account WHERE did = ?1")
        .bind(&[did.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let Some(a) = row else {
        return Err(XrpcError::unauthorized("unknown account"));
    };
    if a.session_epoch != token_epoch {
        return Err(XrpcError::unauthorized("session revoked"));
    }
    let app_password = token_app_pw.then_some(token_priv);
    let (access_jwt, refresh_jwt) = issue_compat_pair(&s.env, &a.did, a.session_epoch, app_password, a.signing_priv.as_deref().unwrap_or_default())?;
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
    #[serde(rename = "emailAuthFactor")]
    email_auth_factor: bool,
    #[serde(rename = "active")]
    active: bool,
    #[serde(rename = "status", skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    #[serde(rename = "didDoc", skip_serializing_if = "Option::is_none")]
    did_doc: Option<serde_json::Value>,
}

#[worker::send]
async fn get_session(State(s): State<ServerState>, headers: HeaderMap) -> XrpcResult<Json<GetSessionResp>> {
    let caller = auth::authenticate(&s.env, &headers, "GET", "/xrpc/com.atproto.server.getSession").await?;
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let row: Option<AccountRow> = db
        .prepare("SELECT did, handle, email, email_confirmed, password_hash AS password_hash, session_epoch, active, signing_key_k256_priv_hex AS signing_priv FROM account WHERE did = ?1")
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
    let active = a.active == 1;
    // Lexicon status for inactive accounts (takendown/suspended/deactivated).
    let status: Option<String> = if active {
        None
    } else {
        let db2 = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
        #[derive(serde::Deserialize)]
        struct StatusOnly {
            status: String,
        }
        db2.prepare("SELECT status FROM account WHERE did = ?1")
            .bind(&[a.did.clone().into()])
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .first::<StatusOnly>(None)
            .await
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .map(|r| r.status)
    };
    let cfg = pds_env::PdsEnv::from_env(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let db3 = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    #[derive(serde::Deserialize)]
    struct PubRow {
        signing_key_k256_pub_hex: Option<String>,
    }
    let pub_hex: Option<String> = db3
        .prepare("SELECT signing_key_k256_pub_hex FROM account WHERE did = ?1")
        .bind(&[a.did.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first::<PubRow>(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .and_then(|r| r.signing_key_k256_pub_hex);
    Ok(Json(GetSessionResp {
        did: a.did.clone(),
        handle: a.handle.clone(),
        email,
        email_confirmed: a.email_confirmed == 1,
        email_auth_factor: false,
        active,
        status,
        did_doc: Some(crate::routes_repo::did_doc_for(
            &a.did,
            &a.handle,
            pub_hex.as_deref(),
            &format!("https://{}", cfg.hostname),
        )),
    }))
}

#[derive(Deserialize)]
struct AccountRow {
    did: String,
    handle: String,
    email: Option<String>,
    email_confirmed: i64,
    password_hash: Option<String>,
    session_epoch: i64,
    active: i64,
    #[serde(rename = "signing_priv")]
    signing_priv: Option<String>,
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
    crate::ratelimit::check(&s.env, &format!("email:{}", caller.did), 10, 3600).await?;
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
    email_auth_factor: Option<bool>,
    #[serde(default)]
    token: Option<String>,
}

/// Lexicon behavior: accounts with a CONFIRMED address must present the
/// `requestEmailUpdate` token (`TokenRequired` otherwise); unconfirmed
/// accounts may rotate freely. Successful changes reset confirmation and
/// trigger a fresh confirmation code to the new address.
#[worker::send]
async fn update_email(
    State(s): State<ServerState>,
    headers: HeaderMap,
    Json(req): Json<UpdateEmailReq>,
) -> XrpcResult<Json<serde_json::Value>> {
    let caller = auth::authenticate(&s.env, &headers, "POST", "/xrpc/com.atproto.server.updateEmail").await?;
    auth::require_full_password(&caller, "updateEmail")?;
    if !valid_email(&req.email) {
        return Err(XrpcError::bad_request("InvalidEmail", "bad email address"));
    }
    let _ = req.email_auth_factor;
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    #[derive(serde::Deserialize)]
    struct ConfRow {
        email_confirmed: i64,
        email: Option<String>,
    }
    let row: Option<ConfRow> = db
        .prepare("SELECT email_confirmed, email FROM account WHERE did = ?1")
        .bind(&[caller.did.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let Some(acct) = row else {
        return Err(XrpcError::unauthorized("unknown account"));
    };
    if acct.email_confirmed == 1 {
        let token = req.token.as_deref().ok_or_else(|| XrpcError::bad_request("TokenRequired", "email update token required"))?;
        let (did, _) = consume_email_token(&s.env, "update", token).await
            .map_err(|_| XrpcError::bad_request("InvalidToken", "bad or expired token"))?;
        if did != caller.did {
            return Err(XrpcError::bad_request("InvalidToken", "token does not match"));
        }
    }
    if acct.email.as_deref() != Some(req.email.as_str()) {
        db.prepare("UPDATE account SET email = ?1, email_confirmed = 0 WHERE did = ?2")
            .bind(&[req.email.clone().into(), caller.did.clone().into()])
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .run()
            .await
            .map_err(|e| XrpcError::internal(e.to_string()))?;
        let token = issue_email_token(&s.env, &caller.did, "confirm", Some(&req.email), 24 * 3600).await?;
        let text = format!("Confirm your new email address with this code:\n\n{token}\n\nIt expires in 24 hours.\n");
        crate::email::send_email(&s.env, &req.email, "Confirm your new email", &text).await?;
    }
    Ok(Json(serde_json::json!({})))
}

#[derive(serde::Deserialize)]
struct RequestPasswordResetReq {
    email: String,
}

#[worker::send]
async fn request_password_reset(State(s): State<ServerState>, Json(req): Json<RequestPasswordResetReq>) -> XrpcResult<Json<serde_json::Value>> {
    crate::ratelimit::check(&s.env, &format!("email-reset:{}", crate::keys::sha256_hex(&req.email)), 5, 3600).await?;
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
    did: String,
    password: String,
    token: String,
}

/// Lexicon-exact deletion: authenticated self + password + emailed token.
/// Wipes records, blobs, repo state and sessions, then emits `#account`
/// deleted. PLC tombstoning is a separate rotation-key operation (ROADMAP §4).
#[worker::send]
async fn delete_account(
    State(s): State<ServerState>,
    headers: HeaderMap,
    Json(req): Json<DeleteAccountReq>,
) -> XrpcResult<Json<serde_json::Value>> {
    let caller = auth::authenticate(&s.env, &headers, "POST", "/xrpc/com.atproto.server.deleteAccount").await?;
    auth::require_full_password(&caller, "deleteAccount")?;
    if req.did != caller.did {
        return Err(XrpcError::forbidden("AuthFailed", "can only delete your own account"));
    }
    let (token_did, _) = consume_email_token(&s.env, "delete", &req.token)
        .await
        .map_err(|_| XrpcError::new(axum::http::StatusCode::BAD_REQUEST, "InvalidToken", "bad or expired token"))?;
    if token_did != caller.did {
        return Err(XrpcError::new(axum::http::StatusCode::BAD_REQUEST, "InvalidToken", "token does not match"));
    }
    let did = caller.did.clone();
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
    let password = req.password;
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
        "DELETE FROM app_password WHERE did = ?1",
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

// --- sessions: deleteSession (epoch revocation) ---

/// Delete the compat session: bumps the account epoch so every previously
/// issued HS256 token stops verifying. OAuth refresh sessions are unaffected
/// (rotate via the token endpoint); pass `oauth: false` sessions only here
/// by construction (DPoP tokens cannot call this compat endpoint usefully).
#[worker::send]
async fn delete_session(State(s): State<ServerState>, headers: HeaderMap) -> XrpcResult<Json<serde_json::Value>> {
    let caller = auth::authenticate(&s.env, &headers, "POST", "/xrpc/com.atproto.server.deleteSession").await?;
    if caller.oauth {
        return Err(XrpcError::bad_request("InvalidRequest", "OAuth sessions rotate via /oauth/token"));
    }
    auth::require_full_password(&caller, "deleteSession")?;
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    db.prepare("UPDATE account SET session_epoch = session_epoch + 1 WHERE did = ?1")
        .bind(&[caller.did.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok(Json(serde_json::json!({})))
}

// --- App Passwords ---

fn new_app_password() -> String {
    // 10 random bytes -> 16 base32 chars -> xxxx-xxxx-xxxx-xxxx.
    let mut bytes = [0u8; 10];
    let _ = getrandom::getrandom(&mut bytes);
    let s = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &bytes).to_lowercase();
    format!("{}-{}-{}-{}", &s[0..4], &s[4..8], &s[8..12], &s[12..16])
}

#[derive(serde::Deserialize)]
struct CreateAppPasswordReq {
    name: String,
    #[serde(default)]
    privileged: Option<bool>,
}

#[worker::send]
async fn create_app_password(
    State(s): State<ServerState>,
    headers: HeaderMap,
    Json(req): Json<CreateAppPasswordReq>,
) -> XrpcResult<Json<serde_json::Value>> {
    let caller = auth::authenticate(&s.env, &headers, "POST", "/xrpc/com.atproto.server.createAppPassword").await?;
    auth::require_full_password(&caller, "createAppPassword")?;
    if req.name.is_empty() || req.name.len() > 64 {
        return Err(XrpcError::bad_request("InvalidRequest", "bad app password name"));
    }
    let password = new_app_password();
    let hash = crate::oauth::hash_password(&password)?;
    let privileged = req.privileged.unwrap_or(false);
    let now = pds_env::now_iso();
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let inserted = db
        .prepare("INSERT INTO app_password (did, name, password_hash, privileged, created_at) VALUES (?1, ?2, ?3, ?4, ?5)")
        .bind(&[
            caller.did.into(),
            req.name.clone().into(),
            hash.into(),
            (if privileged { 1.0 } else { 0.0 }).into(),
            now.clone().into(),
        ])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run()
        .await;
    if inserted.is_err() {
        return Err(XrpcError::bad_request("DuplicateCreate", "an app password with this name exists"));
    }
    Ok(Json(serde_json::json!({
        "name": req.name, "password": password, "createdAt": now, "privileged": privileged,
    })))
}

#[worker::send]
async fn list_app_passwords(State(s): State<ServerState>, headers: HeaderMap) -> XrpcResult<Json<serde_json::Value>> {
    let caller = auth::authenticate(&s.env, &headers, "GET", "/xrpc/com.atproto.server.listAppPasswords").await?;
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    #[derive(serde::Deserialize)]
    struct PwRow {
        name: String,
        privileged: i64,
        created_at: String,
    }
    let rows = db
        .prepare("SELECT name, privileged, created_at FROM app_password WHERE did = ?1 ORDER BY created_at ASC")
        .bind(&[caller.did.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .all()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let mut passwords = Vec::new();
    for r in rows.results::<PwRow>().unwrap_or_default() {
        passwords.push(serde_json::json!({
            "name": r.name, "createdAt": r.created_at, "privileged": r.privileged == 1,
        }));
    }
    Ok(Json(serde_json::json!({ "passwords": passwords })))
}

#[derive(serde::Deserialize)]
struct RevokeAppPasswordReq {
    name: String,
}

#[worker::send]
async fn revoke_app_password(
    State(s): State<ServerState>,
    headers: HeaderMap,
    Json(req): Json<RevokeAppPasswordReq>,
) -> XrpcResult<Json<serde_json::Value>> {
    let caller = auth::authenticate(&s.env, &headers, "POST", "/xrpc/com.atproto.server.revokeAppPassword").await?;
    auth::require_full_password(&caller, "revokeAppPassword")?;
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    db.prepare("DELETE FROM app_password WHERE did = ?1 AND name = ?2")
        .bind(&[caller.did.into(), req.name.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok(Json(serde_json::json!({})))
}

// --- getServiceAuth ---

#[derive(serde::Deserialize)]
struct GetServiceAuthParam {
    aud: String,
    exp: Option<i64>,
    lxm: Option<String>,
}

/// Mint an inter-service JWT for the caller (ES256K, account key).
/// Used by clients that talk to AppViews/labelers through or past the PDS.
#[worker::send]
async fn get_service_auth(
    State(s): State<ServerState>,
    headers: HeaderMap,
    Query(q): Query<GetServiceAuthParam>,
) -> XrpcResult<Json<serde_json::Value>> {
    let caller = auth::authenticate(&s.env, &headers, "GET", "/xrpc/com.atproto.server.getServiceAuth").await?;
    // aud is a DID or `did#service` reference.
    let (aud_did, _frag) = match q.aud.split_once('#') {
        Some((d, f)) if !d.is_empty() && !f.is_empty() => (d, Some(f)),
        None if !q.aud.is_empty() => (q.aud.as_str(), None),
        _ => return Err(XrpcError::bad_request("InvalidAud", "bad audience")),
    };
    if !crate::atproto::did::validate(aud_did) {
        return Err(XrpcError::bad_request("InvalidAud", "audience must be a DID"));
    }
    if let Some(lxm) = q.lxm.as_deref() {
        if !crate::atproto::nsid::validate(lxm) {
            return Err(XrpcError::bad_request("InvalidLxm", "lxm must be an NSID"));
        }
    }
    let now = (worker::Date::now().as_millis() / 1000) as i64;
    let exp = q.exp.unwrap_or(now + 60);
    if exp <= now {
        return Err(XrpcError::new(axum::http::StatusCode::BAD_REQUEST, "BadExpiration", "expiration is in the past"));
    }
    if exp > now + 3600 {
        return Err(XrpcError::new(axum::http::StatusCode::BAD_REQUEST, "BadExpiration", "expiration too far out (max 1h)"));
    }
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let priv_hex = crate::repo::signing_key(&db, &caller.did).await?;
    let jti = crate::keys::random_b64u32().map_err(|e| XrpcError::internal(e.to_string()))?;
    let mut claims = serde_json::json!({
        "iss": caller.did, "aud": q.aud, "iat": now, "exp": exp, "jti": jti,
    });
    if let Some(lxm) = q.lxm {
        claims["lxm"] = serde_json::Value::String(lxm);
    }
    let token = crate::keys::sign_jwt_es256k(&priv_hex, &claims).map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok(Json(serde_json::json!({ "token": token })))
}

// --- checkAccountStatus ---

/// Migration/recovery-oriented self status: repo pointers plus blob/index
/// accounting. Requires auth, callable only about oneself.
#[worker::send]
async fn check_account_status(State(s): State<ServerState>, headers: HeaderMap) -> XrpcResult<Json<serde_json::Value>> {
    let caller = auth::authenticate(&s.env, &headers, "GET", "/xrpc/com.atproto.server.checkAccountStatus").await?;
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    #[derive(serde::Deserialize)]
    struct StatusRow {
        active: i64,
    }
    let row: Option<StatusRow> = db
        .prepare("SELECT active FROM account WHERE did = ?1")
        .bind(&[caller.did.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let activated = matches!(&row, Some(r) if r.active == 1);
    // validDid: syntax + local existence + (remote doc match when resolvable).
    let mut valid_did = crate::atproto::did::validate(&caller.did) && row.is_some();
    if valid_did && !caller.did.starts_with("did:plc:dev") {
        match crate::identity::resolve_did(&s.env, &caller.did).await {
            Ok(doc) => valid_did = doc.did == caller.did,
            Err(_) => valid_did = false,
        }
    }
    let exp = crate::repo::export_repo(&s.env, &caller.did).await?;
    let (_, blocks) = crate::mst::parse_car(&exp.car).map_err(|e| XrpcError::internal(e.to_string()))?;
    // records = blocks that are not MST nodes and not the commit.
    let mut indexed_records = 0i64;
    let mut node_count = 0i64;
    for (cid, bytes) in &blocks {
        if cid == &exp.commit {
            continue;
        }
        if crate::mst::parse_node(bytes).is_ok() {
            node_count += 1;
        } else {
            indexed_records += 1;
        }
    }
    // Blobs: expected (rows) vs imported (present in R2).
    #[derive(serde::Deserialize)]
    struct BlobKey {
        #[serde(rename = "k")]
        k: String,
    }
    let blob_rows = db
        .prepare("SELECT r2_key AS k FROM blob WHERE did = ?1")
        .bind(&[caller.did.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .all()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let keys: Vec<String> = blob_rows.results::<BlobKey>().unwrap_or_default().into_iter().map(|r| r.k).collect();
    let expected_blobs = keys.len() as i64;
    let mut imported_blobs = 0i64;
    if let Ok(bucket) = s.env.bucket("BLOBS") {
        for k in &keys {
            if let Ok(Some(_)) = bucket.get(k).execute().await {
                imported_blobs += 1;
            }
        }
    }
    Ok(Json(serde_json::json!({
        "activated": activated,
        "validDid": valid_did,
        "repoCommit": exp.commit.to_string(),
        "repoRev": exp.rev,
        "repoBlocks": 1 + node_count + indexed_records,
        "indexedRecords": indexed_records,
        "privateStateValues": 0,
        "expectedBlobs": expected_blobs,
        "importedBlobs": imported_blobs,
    })))
}


// --- requestEmailUpdate (lexicon-aligned) ---

/// Send an email-update token to the CURRENT address. Returns whether a
/// token is required (always true once the address is confirmed).
#[worker::send]
async fn request_email_update(State(s): State<ServerState>, headers: HeaderMap) -> XrpcResult<Json<serde_json::Value>> {
    let caller = auth::authenticate(&s.env, &headers, "POST", "/xrpc/com.atproto.server.requestEmailUpdate").await?;
    crate::ratelimit::check(&s.env, &format!("email:{}", caller.did), 10, 3600).await?;
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    #[derive(serde::Deserialize)]
    struct ERow {
        email: Option<String>,
    }
    let row: Option<ERow> = db
        .prepare("SELECT email FROM account WHERE did = ?1")
        .bind(&[caller.did.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let email = row.and_then(|r| r.email).unwrap_or_default();
    if email.is_empty() {
        return Ok(Json(serde_json::json!({ "tokenRequired": false })));
    }
    let token = issue_email_token(&s.env, &caller.did, "update", Some(&email), 24 * 3600).await?;
    let text = format!("Use this code to authorize changing your account email:\n\n{token}\n\nIt expires in 24 hours.\n");
    crate::email::send_email(&s.env, &email, "Authorize your email change", &text).await?;
    Ok(Json(serde_json::json!({ "tokenRequired": true })))
}

// --- requestAccountDelete / deleteAccount (lexicon: did+password+token) ---

#[worker::send]
async fn request_account_delete(State(s): State<ServerState>, headers: HeaderMap) -> XrpcResult<Json<serde_json::Value>> {
    let caller = auth::authenticate(&s.env, &headers, "POST", "/xrpc/com.atproto.server.requestAccountDelete").await?;
    crate::ratelimit::check(&s.env, &format!("email:{}", caller.did), 10, 3600).await?;
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    #[derive(serde::Deserialize)]
    struct ERow2 {
        email: Option<String>,
    }
    let row: Option<ERow2> = db
        .prepare("SELECT email FROM account WHERE did = ?1")
        .bind(&[caller.did.clone().into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let email = row.and_then(|r| r.email).unwrap_or_default();
    if email.is_empty() {
        return Err(XrpcError::bad_request("InvalidEmail", "no email on file; set one first"));
    }
    let token = issue_email_token(&s.env, &caller.did, "delete", None, 3600).await?;
    let text = format!("Delete your account with this code:\n\n{token}\n\nIt expires in 1 hour. If you did not request this, ignore this message.\n");
    crate::email::send_email(&s.env, &email, "Delete your account", &text).await?;
    Ok(Json(serde_json::json!({})))
}

// --- invites: consumption + listing ---

#[derive(serde::Deserialize)]
struct GetAccountInviteCodesParam {
    #[serde(default)]
    #[serde(rename = "includeUsed")]
    include_used: Option<bool>,
    #[serde(default)]
    #[serde(rename = "createAvailable")]
    create_available: Option<bool>,
}

/// Codes redeemed by the calling account. (This PDS issues global invites;
/// per-account earning quotas are out of scope.)
#[worker::send]
async fn get_account_invite_codes(
    State(s): State<ServerState>,
    headers: HeaderMap,
    Query(q): Query<GetAccountInviteCodesParam>,
) -> XrpcResult<Json<serde_json::Value>> {
    let caller = auth::authenticate(&s.env, &headers, "GET", "/xrpc/com.atproto.server.getAccountInviteCodes").await?;
    let _ = q.create_available;
    let include_used = q.include_used.unwrap_or(true);
    let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
    #[derive(serde::Deserialize)]
    struct CodeRow {
        code: String,
        used_by: Option<String>,
        created_at: String,
        used_at: Option<String>,
    }
    let rows = db
        .prepare("SELECT code, used_by, created_at, used_at FROM invite_code WHERE used_by = ?1 ORDER BY created_at ASC")
        .bind(&[caller.did.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .all()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let mut codes = Vec::new();
    for r in rows.results::<CodeRow>().unwrap_or_default() {
        let used = r.used_by.is_some();
        if used && !include_used {
            continue;
        }
        codes.push(serde_json::json!({
            "code": r.code,
            "available": if used { 0 } else { 1 },
            "disabled": false,
            "forAccount": "admin",
            "createdBy": "admin",
            "createdAt": r.created_at,
            "uses": r.used_by.map(|u| serde_json::json!([{"usedBy": u, "usedAt": r.used_at}])).unwrap_or(serde_json::json!([])),
        }));
    }
    Ok(Json(serde_json::json!({ "codes": codes })))
}

// --- reserveSigningKey (migration handshake) ---

#[derive(serde::Deserialize)]
struct ReserveSigningKeyReq {
    #[serde(default)]
    did: Option<String>,
}

/// Reserve a repo signing key for a DID that is about to migrate here.
/// Public (no auth): the key is useless without the matching private half,
/// which only this PDS holds. `createAccount` adopts the reservation.
#[worker::send]
async fn reserve_signing_key(
    State(s): State<ServerState>,
    Json(req): Json<ReserveSigningKeyReq>,
) -> XrpcResult<Json<serde_json::Value>> {
    if let Some(did) = req.did.as_deref() {
        if !crate::atproto::did::validate(did) {
            return Err(XrpcError::bad_request("InvalidDid", "bad DID"));
        }
    }
    let (priv_hex, pub_hex) = crate::keys::generate_k256().map_err(|e| XrpcError::internal(e.to_string()))?;
    let signing_did_key = crate::identity::did_key_encode(&pub_hex, &crate::keys::Curve::K256)
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    if let Some(did) = req.did {
        let db = pds_env::db(&s.env).map_err(|e| XrpcError::internal(e.to_string()))?;
        let now = pds_env::now_iso();
        db.prepare("INSERT INTO reserved_key (did, priv_hex, pub_hex, created_at) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(did) DO UPDATE SET priv_hex = excluded.priv_hex, pub_hex = excluded.pub_hex, created_at = excluded.created_at")
            .bind(&[did.into(), priv_hex.into(), pub_hex.into(), now.into()])
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .run()
            .await
            .map_err(|e| XrpcError::internal(e.to_string()))?;
    }
    Ok(Json(serde_json::json!({ "signingKey": signing_did_key })))
}
