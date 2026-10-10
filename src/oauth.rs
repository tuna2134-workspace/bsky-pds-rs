//! OAuth server core: DPoP, nonces, client metadata, server keys, passwords.
//! Spec: <https://atproto.com/specs/oauth> (+ RFC 9449 DPoP, RFC 7638 JKT).

use axum::http::HeaderMap;
use base64::Engine as _;

use crate::keys::{self, KeyError};
use crate::pds_env;
use crate::xrpc::{XrpcError, XrpcResult};
use worker::Env;

const B64U: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn key_err(e: KeyError) -> XrpcError {
    XrpcError::unauthorized(format!("bad key material: {e}"))
}

// ---------- server signing key (ES256, lazily generated, D1-persisted) ----------

#[derive(serde::Deserialize)]
struct KeyRow {
    priv_hex: String,
    pub_hex: String,
}

/// PDS OAuth server keypair (ES256). Generated once, then reused.
pub async fn oauth_keypair(env: &Env) -> XrpcResult<(String, String)> {
    let db = pds_env::db(env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let row: Option<KeyRow> = db
        .prepare("SELECT priv_hex, pub_hex FROM oauth_keys WHERE kind = 'oauth-es256'")
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    if let Some(k) = row {
        return Ok((k.priv_hex, k.pub_hex));
    }
    let (priv_hex, pub_hex) = keys::generate_p256().map_err(key_err)?;
    let now = pds_env::now_iso();
    db.prepare("INSERT OR IGNORE INTO oauth_keys (kind, alg, priv_hex, pub_hex, created_at) VALUES ('oauth-es256', 'ES256', ?1, ?2, ?3)")
        .bind(&[priv_hex.clone().into(), pub_hex.clone().into(), now.into()])
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .run()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let row: Option<KeyRow> = db
        .prepare("SELECT priv_hex, pub_hex FROM oauth_keys WHERE kind = 'oauth-es256'")
        .first(None)
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    row.map(|k| (k.priv_hex, k.pub_hex))
        .ok_or_else(|| XrpcError::internal("oauth key init failed"))
}

// ---------- DPoP ----------

pub struct DpopInfo {
    /// JWK thumbprint the proof (and bound tokens) belong to.
    pub jkt: String,
    pub jwk: serde_json::Value,
}

#[derive(Debug)]
pub enum DpopError {
    /// Client must (re)fetch a server nonce and retry.
    NonceRequired(String),
    Invalid(String),
}

pub fn dpop_http_error(e: DpopError) -> XrpcError {
    match e {
        DpopError::NonceRequired(_) => XrpcError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "InvalidDpopProof",
            "DPoP nonce required or expired; retry with fresh nonce",
        ),
        DpopError::Invalid(m) => XrpcError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "InvalidDpopProof",
            m,
        ),
    }
}

fn kv(env: &Env) -> XrpcResult<worker::KvStore> {
    env.kv("CACHE").map_err(|e| XrpcError::internal(e.to_string()))
}

/// Issue a fresh server nonce (single-use window via KV TTL).
pub async fn fresh_nonce(env: &Env) -> XrpcResult<String> {
    let nonce = keys::random_b64u32().map_err(key_err)?;
    kv(env)?
        .put(&format!("dpop:nonce:{nonce}"), "1")
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .expiration_ttl(600)
        .execute()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok(nonce)
}

async fn consume_nonce(env: &Env, nonce: &str) -> XrpcResult<bool> {
    if nonce.len() < 16 || nonce.len() > 128 {
        return Ok(false);
    }
    let store = kv(env)?;
    let key = format!("dpop:nonce:{nonce}");
    let seen: Option<String> = store.get(&key).text().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    if seen.is_none() {
        return Ok(false);
    }
    // Single-use: delete after first acceptance.
    let _ = store.delete(&key).await;
    Ok(true)
}

async fn mark_jti(env: &Env, jti: &str) -> XrpcResult<bool> {
    if jti.len() < 8 || jti.len() > 256 {
        return Ok(false);
    }
    let store = kv(env)?;
    let key = format!("dpop:jti:{jti}");
    let seen: Option<String> = store.get(&key).text().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    if seen.is_some() {
        return Ok(false);
    }
    store
        .put(&key, "1")
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .expiration_ttl(180)
        .execute()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    Ok(true)
}

fn now_secs() -> i64 {
    (worker::Date::now().as_millis() / 1000) as i64
}

/// Verify a DPoP proof JWT.
///
/// - `method`/`url`: expected `htm`/`htu` (url without query/fragment).
/// - `access_token`: when presenting a bound token, `ath` is enforced.
/// - `require_nonce`: token endpoint requires a fresh server nonce.
pub async fn verify_dpop(
    env: &Env,
    headers: &HeaderMap,
    method: &str,
    url: &str,
    access_token: Option<&str>,
    require_nonce: bool,
) -> Result<DpopInfo, DpopError> {
    let proof = headers
        .get("DPoP")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| DpopError::Invalid("DPoP header required".into()))?;
    verify_dpop_proof(env, proof, method, url, access_token, require_nonce).await
}

async fn verify_dpop_proof(
    env: &Env,
    proof: &str,
    method: &str,
    url: &str,
    access_token: Option<&str>,
    require_nonce: bool,
) -> Result<DpopInfo, DpopError> {
    let invalid = |m: &str| DpopError::Invalid(m.to_string());
    let mut parts = proof.split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err(invalid("malformed DPoP JWT")),
    };
    let header: serde_json::Value =
        serde_json::from_slice(&B64U.decode(h).map_err(|_| invalid("bad header"))?)
            .map_err(|_| invalid("bad header json"))?;
    let payload: serde_json::Value =
        serde_json::from_slice(&B64U.decode(p).map_err(|_| invalid("bad payload"))?)
            .map_err(|_| invalid("bad payload json"))?;
    if header.get("typ").and_then(|v| v.as_str()) != Some("dpop+jwt") {
        return Err(invalid("typ must be dpop+jwt"));
    }
    if header.get("alg").and_then(|v| v.as_str()) != Some("ES256") {
        return Err(invalid("only ES256 DPoP supported"));
    }
    let jwk = header.get("jwk").ok_or_else(|| invalid("embedded jwk required"))?.clone();
    if jwk.get("d").is_some() {
        return Err(invalid("jwk must be public"));
    }
    // Only EC keys accepted for DPoP.
    let jkt = keys::jwk_thumbprint(&jwk).map_err(|_| invalid("bad jwk"))?;
    // Verify signature over h.p with the embedded key.
    verify_with_jwk(&jwk, &format!("{h}.{p}"), s).await?;
    // Claims.
    if payload.get("htm").and_then(|v| v.as_str()) != Some(method) {
        return Err(invalid("htm mismatch"));
    }
    let htu = payload.get("htu").and_then(|v| v.as_str()).ok_or_else(|| invalid("htu required"))?;
    if normalize_htu(htu) != normalize_htu(url) {
        return Err(invalid("htu mismatch"));
    }
    let iat = payload.get("iat").and_then(|v| v.as_i64()).ok_or_else(|| invalid("iat required"))?;
    if (now_secs() - iat).abs() > 120 {
        return Err(invalid("stale DPoP proof"));
    }
    let jti = payload.get("jti").and_then(|v| v.as_str()).ok_or_else(|| invalid("jti required"))?;
    let fresh = mark_jti(env, jti).await.map_err(|_| invalid("replay store unavailable"))?;
    if !fresh {
        return Err(invalid("DPoP proof replay"));
    }
    if require_nonce {
        match payload.get("nonce").and_then(|v| v.as_str()) {
            Some(n) => {
                let ok = consume_nonce(env, n).await.map_err(|_| invalid("nonce store unavailable"))?;
                if !ok {
                    let fresh = fresh_nonce(env).await.map_err(|_| invalid("nonce store unavailable"))?;
                    return Err(DpopError::NonceRequired(fresh));
                }
            }
            None => {
                let fresh = fresh_nonce(env).await.map_err(|_| invalid("nonce store unavailable"))?;
                return Err(DpopError::NonceRequired(fresh));
            }
        }
    }
    if let Some(tok) = access_token {
        let ath = payload.get("ath").and_then(|v| v.as_str()).ok_or_else(|| invalid("ath required"))?;
        let expect = {
            use sha2::{Digest, Sha256};
            B64U.encode(Sha256::digest(tok.as_bytes()))
        };
        if ath != expect {
            return Err(invalid("ath mismatch"));
        }
    }
    Ok(DpopInfo { jkt, jwk })
}

async fn verify_with_jwk(jwk: &serde_json::Value, signing_input: &str, sig_b64: &str) -> Result<(), DpopError> {
    let invalid = |m: &str| DpopError::Invalid(m.to_string());
    let sig = B64U.decode(sig_b64).map_err(|_| invalid("bad sig"))?;
    if sig.len() != 64 {
        return Err(invalid("sig must be 64 bytes"));
    }
    let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or("");
    if crv != "P-256" && crv != "secp256k1" {
        return Err(invalid("unsupported DPoP crv"));
    }
    let x = jwk.get("x").and_then(|v| v.as_str()).ok_or_else(|| invalid("jwk x"))?;
    let y = jwk.get("y").and_then(|v| v.as_str()).ok_or_else(|| invalid("jwk y"))?;
    let xb = B64U.decode(x).map_err(|_| invalid("bad x"))?;
    let yb = B64U.decode(y).map_err(|_| invalid("bad y"))?;
    if xb.len() != 32 || yb.len() != 32 {
        return Err(invalid("bad coords"));
    }
    let prefix = if yb[31] & 1 == 0 { 0x02 } else { 0x03 };
    let mut comp = vec![prefix];
    comp.extend_from_slice(&xb);
    let digest = keys::sha256_of(signing_input.as_bytes());
    keys::verify_digest(&hex::encode(&comp), &digest, &sig).map_err(|_| invalid("DPoP signature invalid"))
}

/// Strip query/fragment + lowercase scheme/host for `htu` comparison.
fn normalize_htu(url: &str) -> String {
    let url = url.split(['?', '#']).next().unwrap_or(url);
    if let Some((scheme, rest)) = url.split_once("://") {
        format!("{}://{}", scheme.to_lowercase(), rest)
    } else {
        url.to_string()
    }
}

// ---------- client metadata ----------

#[derive(Debug, Clone)]
pub struct ClientMeta {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub scope: String,
    pub application_type: String,
    pub token_endpoint_auth_method: String,
    pub jwks: Option<serde_json::Value>,
    pub jwks_uri: Option<String>,
}

/// Fetch + validate OAuth client metadata (cached 1h in KV).
pub async fn fetch_client_metadata(env: &Env, client_id: &str) -> XrpcResult<ClientMeta> {
    check_client_id_url(client_id)?;
    let cache_key = format!("oauth:client:{}", keys::sha256_hex(client_id));
    let store = kv(env)?;
    if let Some(cached) = store
        .get(&cache_key)
        .text()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?
    {
        if let Ok(meta) = serde_json::from_str::<ClientMetaWire>(&cached) {
            return meta.into_meta(client_id);
        }
    }
    let body = fetch_json_doc(client_id).await?;
    store
        .put(&cache_key, body.to_string())
        .map_err(|e| XrpcError::internal(e.to_string()))?
        .expiration_ttl(3600)
        .execute()
        .await
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let wire: ClientMetaWire =
        serde_json::from_value(body).map_err(|_| XrpcError::bad_request("InvalidClient", "bad client metadata"))?;
    wire.into_meta(client_id)
}

fn check_client_id_url(client_id: &str) -> XrpcResult<()> {
    if client_id.len() > 2048 {
        return Err(XrpcError::bad_request("InvalidClient", "client_id too long"));
    }
    if client_id.starts_with("http://localhost") || client_id.starts_with("http://127.0.0.1") || client_id.starts_with("http://[::1]") {
        return Ok(()); // dev loopback exception
    }
    if !client_id.starts_with("https://") {
        return Err(XrpcError::bad_request("InvalidClient", "client_id must be https"));
    }
    if client_id.contains('@') || client_id.contains('#') {
        return Err(XrpcError::bad_request("InvalidClient", "bad client_id"));
    }
    Ok(())
}

async fn fetch_json_doc(url: &str) -> XrpcResult<serde_json::Value> {
    use worker::{Fetch, Method, Request, RequestInit};
    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    let req = Request::new_with_init(url, &init).map_err(|e| XrpcError::bad_request("InvalidClient", e.to_string()))?;
    let mut resp = Fetch::Request(req).send().await.map_err(|e| XrpcError::bad_request("InvalidClient", format!("fetch failed: {e}")))?;
    if resp.status_code() != 200 {
        return Err(XrpcError::bad_request("InvalidClient", "client metadata not reachable"));
    }
    let ct = resp.headers().get("content-type").ok().flatten().unwrap_or_default();
    if !ct.contains("json") {
        return Err(XrpcError::bad_request("InvalidClient", "client metadata must be JSON"));
    }
    let text = resp.text().await.map_err(|e| XrpcError::bad_request("InvalidClient", e.to_string()))?;
    if text.len() > 32 * 1024 {
        return Err(XrpcError::bad_request("InvalidClient", "client metadata too large"));
    }
    serde_json::from_str(&text).map_err(|_| XrpcError::bad_request("InvalidClient", "client metadata not JSON"))
}

#[derive(serde::Deserialize)]
struct ClientMetaWire {
    client_id: String,
    redirect_uris: Vec<String>,
    scope: String,
    #[serde(default = "default_app_type")]
    application_type: String,
    #[serde(default = "default_auth_method")]
    token_endpoint_auth_method: String,
    jwks: Option<serde_json::Value>,
    jwks_uri: Option<String>,
}

fn default_app_type() -> String {
    "web".to_string()
}
fn default_auth_method() -> String {
    "none".to_string()
}

impl ClientMetaWire {
    fn into_meta(self, fetched_url: &str) -> XrpcResult<ClientMeta> {
        if self.client_id != fetched_url {
            return Err(XrpcError::bad_request("InvalidClient", "client_id mismatch"));
        }
        if self.redirect_uris.is_empty() {
            return Err(XrpcError::bad_request("InvalidClient", "redirect_uris required"));
        }
        if !self.scope.split(' ').any(|s| s == "atproto") {
            return Err(XrpcError::bad_request("InvalidClient", "atproto scope must be declared"));
        }
        if self.token_endpoint_auth_method != "none" && self.token_endpoint_auth_method != "private_key_jwt" {
            return Err(XrpcError::bad_request("InvalidClient", "unsupported token auth method"));
        }
        if self.token_endpoint_auth_method == "private_key_jwt" && self.jwks.is_none() && self.jwks_uri.is_none() {
            return Err(XrpcError::bad_request("InvalidClient", "jwks required for private_key_jwt"));
        }
        // redirect_uri sanity per application_type (full rules enforced at authorize).
        for r in &self.redirect_uris {
            if r.len() > 2048 || r.contains('#') {
                return Err(XrpcError::bad_request("InvalidClient", "bad redirect_uri"));
            }
            if self.application_type == "web" && !(r.starts_with("https://") || r.starts_with("http://127.0.0.1") || r.starts_with("http://[::1]")) {
                return Err(XrpcError::bad_request("InvalidClient", "web redirect_uri must be https"));
            }
        }
        Ok(ClientMeta {
            client_id: self.client_id,
            redirect_uris: self.redirect_uris,
            scope: self.scope,
            application_type: self.application_type,
            token_endpoint_auth_method: self.token_endpoint_auth_method,
            jwks: self.jwks,
            jwks_uri: self.jwks_uri,
        })
    }
}

// ---------- passwords (argon2id) ----------

/// Hash a password for storage. Lightweight params for the Workers CPU budget.
pub fn hash_password(password: &str) -> XrpcResult<String> {
    use argon2::{Algorithm, Argon2, Params, Version};
    use argon2::password_hash::{PasswordHasher, SaltString};
    if password.len() < 8 || password.len() > 256 {
        return Err(XrpcError::bad_request("InvalidPassword", "password must be 8..256 chars"));
    }
    let params = Params::new(8192, 2, 1, None).map_err(|e| XrpcError::internal(e.to_string()))?;
    let ctx = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut salt_bytes = [0u8; 16];
    getrandom::getrandom(&mut salt_bytes).map_err(|e| XrpcError::internal(e.to_string()))?;
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|e| XrpcError::internal(e.to_string()))?;
    ctx.hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| XrpcError::internal(e.to_string()))
}

/// Verify a password (constant-shape errors to avoid user enumeration timing).
pub fn verify_password(phc: &str, password: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    argon2::Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

// ---------- confidential client assertions (private_key_jwt, ES256) ----------

/// Verify a `private_key_jwt` client assertion. Public clients (`none`) skip.
pub async fn verify_client_assertion(
    env: &Env,
    meta: &ClientMeta,
    assertion: Option<&str>,
    audience: &str,
) -> XrpcResult<()> {
    if meta.token_endpoint_auth_method == "none" {
        return Ok(());
    }
    let assertion = assertion
        .ok_or_else(|| XrpcError::new(axum::http::StatusCode::UNAUTHORIZED, "InvalidClient", "client_assertion required"))?;
    let invalid = |m: &str| XrpcError::new(axum::http::StatusCode::UNAUTHORIZED, "InvalidClient", m);
    let mut parts = assertion.split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err(invalid("malformed assertion")),
    };
    let header: serde_json::Value = serde_json::from_slice(
        &B64U.decode(h).map_err(|_| invalid("bad header"))?,
    )
    .map_err(|_| invalid("bad header json"))?;
    let claims: serde_json::Value = serde_json::from_slice(
        &B64U.decode(p).map_err(|_| invalid("bad claims"))?,
    )
    .map_err(|_| invalid("bad claims json"))?;
    if header.get("alg").and_then(|v| v.as_str()) != Some("ES256") {
        return Err(invalid("only ES256 assertions supported"));
    }
    if claims.get("iss").and_then(|v| v.as_str()) != Some(meta.client_id.as_str())
        || claims.get("sub").and_then(|v| v.as_str()) != Some(meta.client_id.as_str())
    {
        return Err(invalid("iss/sub must be client_id"));
    }
    let aud_ok = match claims.get("aud") {
        Some(serde_json::Value::String(a)) => a == audience,
        Some(serde_json::Value::Array(a)) => a.iter().any(|v| v.as_str() == Some(audience)),
        _ => false,
    };
    if !aud_ok {
        return Err(invalid("aud mismatch"));
    }
    let exp = claims.get("exp").and_then(|v| v.as_i64()).ok_or_else(|| invalid("exp required"))?;
    if now_secs() > exp + 30 {
        return Err(invalid("assertion expired"));
    }
    claims.get("jti").and_then(|v| v.as_str()).ok_or_else(|| invalid("jti required"))?;
    if !mark_jti(env, &format!("assertion:{}", claims["jti"].as_str().unwrap_or_default())).await?
    {
        return Err(invalid("assertion replay"));
    }
    // Candidate keys: embedded jwks, else fetched jwks_uri.
    let mut key_set: Vec<serde_json::Value> = Vec::new();
    if let Some(jwks) = meta.jwks.as_ref().and_then(|v| v.get("keys")).and_then(|v| v.as_array()) {
        key_set.extend(jwks.iter().cloned());
    } else if let Some(uri) = meta.jwks_uri.as_ref() {
        let doc = fetch_json_doc(uri).await?;
        if let Some(arr) = doc.get("keys").and_then(|v| v.as_array()) {
            key_set.extend(arr.iter().cloned());
        }
    }
    if key_set.is_empty() {
        return Err(invalid("no client keys"));
    }
    let kid = header.get("kid").and_then(|v| v.as_str());
    let digest = keys::sha256_of(format!("{h}.{p}").as_bytes());
    let sig = B64U.decode(s).map_err(|_| invalid("bad sig"))?;
    if sig.len() != 64 {
        return Err(invalid("sig must be 64 bytes"));
    }
    for key in &key_set {
        if let Some(kid) = kid {
            if key.get("kid").and_then(|v| v.as_str()) != Some(kid) {
                continue;
            }
        }
        if key.get("crv").and_then(|v| v.as_str()) != Some("P-256") {
            continue;
        }
        let (x, y) = match (key.get("x").and_then(|v| v.as_str()), key.get("y").and_then(|v| v.as_str())) {
            (Some(x), Some(y)) => (x, y),
            _ => continue,
        };
        let (xb, yb) = match (B64U.decode(x), B64U.decode(y)) {
            (Ok(xb), Ok(yb)) if xb.len() == 32 && yb.len() == 32 => (xb, yb),
            _ => continue,
        };
        let prefix = if yb[31] & 1 == 0 { 0x02 } else { 0x03 };
        let mut comp = vec![prefix];
        comp.extend_from_slice(&xb);
        if keys::verify_digest(&hex::encode(&comp), &digest, &sig).is_ok() {
            return Ok(());
        }
    }
    Err(invalid("assertion signature invalid"))
}
