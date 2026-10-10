//! Auth: OAuth (primary, per goal) + legacy JWT/App Password compat notes.
//! Specs: /specs/oauth, /specs/xrpc (App Passwords, Admin Token, Inter-Service JWT).

use axum::http::{HeaderMap, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use crate::xrpc::XrpcError;

/// Result of authenticating an XRPC request.
pub struct Caller {
    pub did: String,
    /// OAuth scope string (space-separated) or legacy marker.
    pub scope: String,
}

/// Parse `Authorization` header. Supports:
/// - `DPoP <access-jwt>` (OAuth, primary)
/// - `Bearer <access-jwt>` (legacy session tokens; accepted during migration)
/// Full DPoP proof + JKT binding verification is TODO (see ROADMAP).
pub fn caller_from_headers(headers: &HeaderMap) -> Result<Caller, XrpcError> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| XrpcError::unauthorized("Authentication required"))?;

    if let Some(token) = auth.strip_prefix("DPoP ") {
        let did = did_from_unverified_jwt(token)?;
        return Ok(Caller { did, scope: "atproto".into() });
    }
    if let Some(token) = auth.strip_prefix("Bearer ") {
        let did = did_from_unverified_jwt(token)?;
        return Ok(Caller { did, scope: "transition:generic".into() });
    }
    Err(XrpcError::new(StatusCode::UNAUTHORIZED, "AuthenticationRequired", "Unsupported authorization scheme"))
}

/// Extract `sub` (DID) from a JWT without verifying signature.
/// Verification (ES256/ES256K against PDS JWKS / account key) happens in
/// `verify_access_jwt` before any federation-trusted path.
pub fn did_from_unverified_jwt(jwt: &str) -> Result<String, XrpcError> {
    let mut parts = jwt.split('.');
    let (_h, payload, _s) = (parts.next(), parts.next(), parts.next());
    let payload = payload.ok_or_else(|| XrpcError::unauthorized("Malformed token"))?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|_| XrpcError::unauthorized("Malformed token"))?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| XrpcError::unauthorized("Malformed token"))?;
    let sub = v.get("sub").and_then(|s| s.as_str()).ok_or_else(|| XrpcError::unauthorized("Token has no sub"))?;
    if !crate::atproto::did::validate(sub) {
        return Err(XrpcError::unauthorized("Token sub is not a valid DID"));
    }
    Ok(sub.to_string())
}

/// Admin auth: `Authorization: Basic YWRtaW46<token>` (user `admin`).
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
