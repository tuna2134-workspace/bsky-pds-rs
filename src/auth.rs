//! Auth: OAuth DPoP-bound access tokens (primary) + HS256 compat sessions.
//! Specs: <https://atproto.com/specs/oauth>, <https://atproto.com/specs/xrpc>
//!
//! All token verification is strict: ES256 signatures against the PDS OAuth
//! server key, DPoP `ath`/`jkt` binding, expiry, issuer. Nothing is accepted
//! on an unverified `sub` claim.

use axum::http::{HeaderMap, StatusCode};
use base64::Engine as _;

use crate::oauth;
use crate::pds_env;
use crate::xrpc::XrpcError;
use worker::Env;

/// Result of authenticating an XRPC request.
pub struct Caller {
    pub did: String,
    /// Space-separated granted scope string.
    pub scope: String,
    /// True for OAuth DPoP sessions, false for compat App Password sessions.
    pub oauth: bool,
    /// True when the session was opened with an App Password.
    pub app_password: bool,
    /// App Password privilege flag (meaningful only with `app_password`).
    pub privileged: bool,
}

fn now_secs() -> i64 {
    (worker::Date::now().as_millis() / 1000) as i64
}

fn check_claims(payload: &serde_json::Value, hostname: &str, expect_typ: &str) -> Result<(String, String), XrpcError> {
    let unauth = |m: &str| XrpcError::unauthorized(m);
    let sub = payload.get("sub").and_then(|v| v.as_str()).ok_or_else(|| unauth("token has no sub"))?;
    if !crate::atproto::did::validate(sub) {
        return Err(unauth("token sub is not a valid DID"));
    }
    let scope = payload.get("scope").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if !scope.split(' ').any(|s| s == "atproto" || s == "transition:generic") {
        return Err(unauth("token scope insufficient"));
    }
    let exp = payload.get("exp").and_then(|v| v.as_i64()).ok_or_else(|| unauth("token has no exp"))?;
    if now_secs() > exp + 30 {
        return Err(unauth("token expired"));
    }
    let iss = payload.get("iss").and_then(|v| v.as_str()).unwrap_or("");
    let expect_iss = format!("https://{hostname}");
    if !iss.is_empty() && iss != expect_iss {
        return Err(unauth("token issuer mismatch"));
    }
    let _ = expect_typ;
    Ok((sub.to_string(), scope))
}

/// Authenticate an XRPC request against `Authorization` (+ `DPoP` proof).
///
/// - `DPoP <access-jwt>`: OAuth flow. Verifies ES256, expiry, and the DPoP
///   proof binding (`htm` = `method`, `htu` = origin + `path`, `ath` over the
///   token, `jkt` equals token `cnf.jkt`).
/// - `Bearer <compat-jwt>`: legacy/App Password flow. Verifies HS256 with
///   `PDS_JWT_SECRET` and `typ: at+jwt` (refresh tokens are rejected here).
pub async fn authenticate(env: &Env, headers: &HeaderMap, method: &str, path: &str) -> Result<Caller, XrpcError> {
    let cfg = pds_env::PdsEnv::from_env(env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| XrpcError::unauthorized("Authentication required"))?;

    if let Some(token) = auth.strip_prefix("DPoP ") {
        let (_, server_pub) = oauth::oauth_keypair(env).await?;
        let payload = crate::keys::verify_jwt_es256(token, &server_pub, Some("at+jwt"))
            .map_err(|_| XrpcError::unauthorized("bad access token"))?;
        let (did, scope) = check_claims(&payload, &cfg.hostname, "at+jwt")?;
        let token_jkt = payload
            .get("cnf")
            .and_then(|v| v.get("jkt"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| XrpcError::unauthorized("token not DPoP-bound"))?;
        let url = format!("{}{}", public_origin(headers, &cfg.hostname), path);
        let info = oauth::verify_dpop(env, headers, method, &url, Some(token), false)
            .await
            .map_err(oauth::dpop_http_error)?;
        if info.jkt != token_jkt {
            return Err(XrpcError::unauthorized("DPoP key mismatch"));
        }
        return Ok(Caller { did, scope, oauth: true, app_password: false, privileged: false });
    }
    if let Some(token) = auth.strip_prefix("Bearer ") {
        let secret = cfg
            .jwt_secret
            .ok_or_else(|| XrpcError::unauthorized("compat sessions not configured"))?;
        let (typ, payload) =
            crate::keys::verify_jwt_hs256(token, &secret).map_err(|_| XrpcError::unauthorized("bad session token"))?;
        if typ != "at+jwt" {
            return Err(XrpcError::unauthorized("refresh token cannot authorize requests"));
        }
        let (did, scope) = check_claims(&payload, &cfg.hostname, "at+jwt")?;
        // Epoch revocation (deleteSession bumps it).
        let epoch = payload.get("epoch").and_then(|v| v.as_i64()).unwrap_or(-1);
        let db = pds_env::db(env).map_err(|e| XrpcError::internal(e.to_string()))?;
        #[derive(serde::Deserialize)]
        struct EpochRow {
            session_epoch: i64,
        }
        let row: Option<EpochRow> = db
            .prepare("SELECT session_epoch FROM account WHERE did = ?1")
            .bind(&[did.clone().into()])
            .map_err(|e| XrpcError::internal(e.to_string()))?
            .first(None)
            .await
            .map_err(|e| XrpcError::internal(e.to_string()))?;
        match row {
            Some(r) if r.session_epoch == epoch => {}
            _ => return Err(XrpcError::unauthorized("session revoked")),
        }
        let app_password = payload.get("appPassword").and_then(|v| v.as_bool()).unwrap_or(false);
        let privileged = payload.get("privileged").and_then(|v| v.as_bool()).unwrap_or(false);
        return Ok(Caller { did, scope, oauth: false, app_password, privileged });
    }
    Err(XrpcError::new(StatusCode::UNAUTHORIZED, "AuthenticationRequired", "Unsupported authorization scheme"))
}

/// Best-effort public origin (`scheme://host`) for DPoP `htu` checks.
/// Honors `X-Forwarded-Proto`; loopback hosts stay `http`.
pub fn public_origin(headers: &HeaderMap, hostname: &str) -> String {
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or(hostname);
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            if host.starts_with("localhost") || host.starts_with("127.") || host.starts_with("[::1]") {
                "http".to_string()
            } else {
                "https".to_string()
            }
        });
    format!("{proto}://{host}")
}

/// Admin auth: `Authorization: Basic base64(admin:<PDS_ADMIN_PASSWORD>)`.
pub fn check_admin(headers: &HeaderMap, expected: Option<&str>) -> Result<(), XrpcError> {
    let expected = expected.ok_or_else(|| XrpcError::unauthorized("Admin not configured"))?;
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let Some(b64) = auth.strip_prefix("Basic ") else {
        return Err(XrpcError::unauthorized("Admin token required"));
    };
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| XrpcError::unauthorized("Bad admin credentials"))?;
    let decoded = String::from_utf8(decoded).map_err(|_| XrpcError::unauthorized("Bad admin credentials"))?;
    if decoded == format!("admin:{expected}") {
        Ok(())
    } else {
        Err(XrpcError::unauthorized("Bad admin credentials"))
    }
}

/// Reject App Password sessions on account-management endpoints.
/// Matches the `transition:generic` privilege model: app passwords may read
/// and write records, but may not manage the account itself (unless created
/// with the privileged flag by a trusted client).
pub fn require_full_password(caller: &Caller, endpoint: &str) -> Result<(), XrpcError> {
    if caller.oauth {
        return Ok(());
    }
    if caller.app_password && !caller.privileged {
        return Err(XrpcError::forbidden("AuthFailed", format!("{endpoint} requires the account password")));
    }
    Ok(())
}
