//! Identity: DID resolution (plc/web), handle verification, PLC operations.
//! Specs: <https://atproto.com/specs/did>, <https://atproto.com/specs/handle>,
//! did:plc v0.3 (<https://web.plc.directory/spec/v0.1/did-plc>).

use base64::Engine as _;
use crate::cbor;
use crate::keys::{self, Curve, KeyError};
use crate::pds_env;
use crate::xrpc::{XrpcError, XrpcResult};
use worker::Env;

// ---------- hardened fetch ----------

async fn fetch_text(url: &str, accept: &str) -> XrpcResult<(u16, String)> {
    use worker::{Fetch, Method, Request, RequestInit};
    let mut init = RequestInit::new();
    init.with_method(Method::Get);
    let mut req = Request::new_with_init(url, &init).map_err(|e| XrpcError::internal(e.to_string()))?;
    req.headers_mut()
        .map(|h| h.set("accept", accept).ok())
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let mut resp = Fetch::Request(req).send().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    let status = resp.status_code();
    let text = resp.text().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    if text.len() > 64 * 1024 {
        return Err(XrpcError::internal("identity doc too large"));
    }
    Ok((status, text))
}

fn kv(env: &Env) -> XrpcResult<worker::KvStore> {
    env.kv("CACHE").map_err(|e| XrpcError::internal(e.to_string()))
}

async fn kv_get(env: &Env, key: &str) -> Option<String> {
    kv(env).ok()?.get(key).text().await.ok().flatten()
}

async fn kv_put(env: &Env, key: &str, value: &str, ttl: u64) {
    if let Ok(store) = kv(env) {
        if let Ok(put) = store.put(key, value.to_string()) {
            let _ = put.expiration_ttl(ttl).execute().await;
        }
    }
}

// ---------- DID documents ----------

#[derive(Debug, Clone)]
pub struct DidDoc {
    pub did: String,
    pub handle: Option<String>,
    pub signing_key: Option<(Curve, String)>,
    pub pds_endpoint: Option<String>,
}

fn curve_of_multikey(multibase: &str) -> Option<(Curve, String)> {
    crate::keys::multikey_decode(multibase)
        .ok()
        .map(|(c, hex)| (c, hex))
}

/// Parse an atproto DID document (any blessed method) per /specs/did.
pub fn parse_did_doc(doc: &serde_json::Value, expect_did: &str) -> Result<DidDoc, String> {
    let id = doc.get("id").and_then(|v| v.as_str()).ok_or("missing id")?;
    if id != expect_did {
        return Err("DID mismatch".into());
    }
    // alsoKnownAs: first syntactically valid at:// handle wins.
    let mut handle = None;
    if let Some(aka) = doc.get("alsoKnownAs").and_then(|v| v.as_array()) {
        for entry in aka {
            if let Some(uri) = entry.as_str() {
                if let Some(h) = uri.strip_prefix("at://") {
                    if crate::atproto::handle::validate(h) {
                        handle = Some(h.to_string());
                        break;
                    }
                }
            }
        }
    }
    // verificationMethod: first valid #atproto key (Multikey, else legacy).
    let mut signing_key = None;
    if let Some(methods) = doc.get("verificationMethod").and_then(|v| v.as_array()) {
        for m in methods {
            let mid = m.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let is_atproto = mid == "#atproto" || mid.ends_with("#atproto");
            if !is_atproto {
                continue;
            }
            if m.get("controller").and_then(|v| v.as_str()) != Some(expect_did) {
                continue;
            }
            if m.get("type").and_then(|v| v.as_str()) == Some("Multikey") {
                if let Some(mb) = m.get("publicKeyMultibase").and_then(|v| v.as_str()) {
                    if let Some((curve, hex)) = curve_of_multikey(mb) {
                        signing_key = Some((curve, hex));
                        break;
                    }
                }
            } else if let Some(hex) = legacy_key(m) {
                signing_key = Some(hex);
                break;
            }
        }
    }
    // service: first #atproto_pds / AtprotoPersonalDataServer entry.
    let mut pds_endpoint = None;
    if let Some(services) = doc.get("service").and_then(|v| v.as_array()) {
        for s in services {
            let sid = s.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let is_pds = sid == "#atproto_pds" || sid.ends_with("#atproto_pds");
            let typ = s.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if is_pds && typ == "AtprotoPersonalDataServer" {
                if let Some(ep) = s.get("serviceEndpoint").and_then(|v| v.as_str()) {
                    if ep.starts_with("https://") || ep.starts_with("http://localhost") {
                        pds_endpoint = Some(ep.to_string());
                        break;
                    }
                }
            }
        }
    }
    Ok(DidDoc { did: expect_did.to_string(), handle, signing_key, pds_endpoint })
}

/// Legacy `EcdsaSecp256{k1,r1}VerificationKey2019` (uncompressed, no multicodec).
fn legacy_key(m: &serde_json::Value) -> Option<(Curve, String)> {
    let typ = m.get("type").and_then(|v| v.as_str())?;
    let curve = match typ {
        "EcdsaSecp256k1VerificationKey2019" => Curve::K256,
        "EcdsaSecp256r1VerificationKey2019" => Curve::P256,
        _ => return None,
    };
    let mb = m.get("publicKeyMultibase").and_then(|v| v.as_str())?;
    let body = mb.strip_prefix('z')?;
    let raw = bs58::decode(body).with_alphabet(bs58::Alphabet::BITCOIN).into_vec().ok()?;
    if raw.len() != 65 || raw[0] != 0x04 {
        return None;
    }
    let compressed = match curve {
        Curve::K256 => k256_compress(&raw).ok()?,
        Curve::P256 => p256_compress(&raw).ok()?,
    };
    Some((curve, compressed))
}

fn k256_compress(uncompressed: &[u8]) -> Result<String, String> {
    let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(uncompressed).map_err(|_| "bad k256 point")?;
    Ok(hex::encode(vk.to_encoded_point(true).as_bytes()))
}

fn p256_compress(uncompressed: &[u8]) -> Result<String, String> {
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(uncompressed).map_err(|_| "bad p256 point")?;
    Ok(hex::encode(vk.to_encoded_point(true).as_bytes()))
}

/// Fetch the raw DID document JSON (KV-cached 5 min).
pub async fn fetch_did_doc(env: &Env, did: &str) -> XrpcResult<serde_json::Value> {
    if !crate::atproto::did::validate(did) {
        return Err(XrpcError::bad_request("InvalidDid", "bad DID syntax"));
    }
    let cache_key = format!("did:doc:{}", keys::sha256_hex(did));
    if let Some(cached) = kv_get(env, &cache_key).await {
        if let Ok(doc) = serde_json::from_str::<serde_json::Value>(&cached) {
            return Ok(doc);
        }
    }
    let url = did_resolution_url(env, did)?;
    let (status, text) = fetch_text(&url, "application/json").await?;
    if status != 200 {
        return Err(XrpcError::bad_request("DidNotFound", format!("DID resolution failed: {status}")));
    }
    let doc: serde_json::Value =
        serde_json::from_str(&text).map_err(|_| XrpcError::bad_request("DidNotFound", "bad DID document"))?;
    kv_put(env, &cache_key, &text, 300).await;
    Ok(doc)
}

/// Resolve a DID to its parsed document.
pub async fn resolve_did(env: &Env, did: &str) -> XrpcResult<DidDoc> {
    let doc = fetch_did_doc(env, did).await?;
    parse_did_doc(&doc, did).map_err(|e| XrpcError::bad_request("DidNotFound", e))
}

/// Resolve an arbitrary named service endpoint from a DID document.
pub async fn resolve_service(env: &Env, did: &str, service_id: &str) -> XrpcResult<String> {
    let doc = fetch_did_doc(env, did).await?;
    let want = format!("#{service_id}");
    if let Some(services) = doc.get("service").and_then(|v| v.as_array()) {
        for s in services {
            let sid = s.get("id").and_then(|v| v.as_str()).unwrap_or("");
            if sid == want || sid == format!("{did}{want}") {
                if let Some(ep) = s.get("serviceEndpoint").and_then(|v| v.as_str()) {
                    if ep.starts_with("https://") || ep.starts_with("http://localhost") || ep.starts_with("http://127.0.0.1") || ep.starts_with("http://[::1]") {
                        return Ok(ep.to_string());
                    }
                    return Err(XrpcError::bad_request("InvalidService", "service endpoint must be https"));
                }
            }
        }
    }
    Err(XrpcError::not_found("ServiceNotFound", "no such service in DID document"))
}

fn did_resolution_url(env: &Env, did: &str) -> XrpcResult<String> {
    if let Some(rest) = did.strip_prefix("did:plc:") {
        if rest.is_empty() {
            return Err(XrpcError::bad_request("InvalidDid", "bad plc DID"));
        }
        let cfg = pds_env::PdsEnv::from_env(env).map_err(|e| XrpcError::internal(e.to_string()))?;
        Ok(format!("{}/{did}", cfg.plc_url.trim_end_matches('/')))
    } else if let Some(rest) = did.strip_prefix("did:web:") {
        // Hostname-level only; port allowed for localhost (colon hex-encoded).
        let decoded = rest.replace("%3A", ":").replace("%3a", ":");
        if decoded.contains('/') || decoded.contains('?') || decoded.contains('#') {
            return Err(XrpcError::bad_request("InvalidDid", "path DIDs unsupported"));
        }
        let (host, port) = match decoded.split_once(':') {
            Some((h, p)) => {
                if h != "localhost" && h != "127.0.0.1" && h != "[::1]" {
                    return Err(XrpcError::bad_request("InvalidDid", "ports only for localhost"));
                }
                (h.to_string(), Some(p.to_string()))
            }
            None => (decoded, None),
        };
        let origin = match port {
            Some(p) => format!("http://{host}:{p}"),
            None => format!("https://{host}"),
        };
        Ok(format!("{origin}/.well-known/did.json"))
    } else {
        Err(XrpcError::bad_request("UnsupportedDid", "only did:plc and did:web"))
    }
}

// ---------- handles ----------

/// Resolve a handle to its declared DID via `/.well-known/atproto-did`,
/// falling back to DNS TXT `_dnslink.<handle>` over DNS-over-HTTPS.
pub async fn resolve_handle_to_did(env: &Env, handle: &str) -> XrpcResult<Option<String>> {
    if !crate::atproto::handle::validate(handle) {
        return Err(XrpcError::bad_request("InvalidHandle", "bad handle"));
    }
    if let Some(cached) = kv_get(env, &format!("handle:did:{handle}")).await {
        return Ok(if cached.is_empty() { None } else { Some(cached) });
    }
    let local = handle == "localhost"
        || handle.ends_with(".localhost")
        || handle.starts_with("localhost:")
        || handle.starts_with("127.")
        || handle.starts_with("[::1]");
    // 1. well-known (http for loopback, https otherwise).
    let scheme = if local { "http" } else { "https" };
    let url = format!("{scheme}://{handle}/.well-known/atproto-did");
    if let Ok((200, text)) = fetch_text(&url, "text/plain").await {
        let did = text.trim().to_string();
        if crate::atproto::did::validate(&did) {
            kv_put(env, &format!("handle:did:{handle}"), &did, 300).await;
            return Ok(Some(did));
        }
    }
    if local {
        kv_put(env, &format!("handle:did:{handle}"), "", 60).await;
        return Ok(None);
    }
    // 2. DNS TXT via DoH.
    let doh = format!("https://cloudflare-dns.com/dns-query?name=_dnslink.{handle}&type=TXT");
    if let Ok((200, text)) = fetch_text(&doh, "application/dns-json").await {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(answers) = v.get("Answer").and_then(|a| a.as_array()) {
                for a in answers {
                    let data = a.get("data").and_then(|d| d.as_str()).unwrap_or("").trim_matches('"');
                    if let Some(did) = data.strip_prefix("did=") {
                        let did = did.trim().to_string();
                        if crate::atproto::did::validate(&did) {
                            kv_put(env, &format!("handle:did:{handle}"), &did, 300).await;
                            return Ok(Some(did));
                        }
                    }
                }
            }
        }
    }
    kv_put(env, &format!("handle:did:{handle}"), "", 60).await;
    Ok(None)
}

/// Bidirectional handle check: DID doc claims it AND it resolves back.
pub async fn handle_is_correct(env: &Env, did: &str, handle: &str) -> bool {
    // Cheap path: our own domain never needs network proof (wildcard DNS).
    if let Ok(cfg) = pds_env::PdsEnv::from_env(env) {
        if handle == cfg.hostname || handle.ends_with(&format!(".{}", cfg.hostname)) {
            // Still confirm the DID doc claims it (prevents handle theft display).
            if let Ok(doc) = resolve_did(env, did).await {
                // Local accounts resolve via DB, not PLC; fall through to DB check below.
                if doc.handle.as_deref() == Some(handle) {
                    return true;
                }
            }
            return local_handle_matches(env, did, handle).await;
        }
    }
    match resolve_did(env, did).await {
        Ok(doc) if doc.handle.as_deref() == Some(handle) => (),
        _ => return false,
    }
    match resolve_handle_to_did(env, handle).await {
        Ok(Some(d)) => d == did,
        _ => false,
    }
}

async fn local_handle_matches(env: &Env, did: &str, handle: &str) -> bool {
    let db = match pds_env::db(env) {
        Ok(db) => db,
        Err(_) => return false,
    };
    #[derive(serde::Deserialize)]
    struct Row {
        did: String,
    }
    let bound = db.prepare("SELECT did FROM account WHERE handle = ?1");
    let stmt = match bound.bind(&[handle.into()]) {
        Ok(stmt) => stmt,
        Err(_) => return false,
    };
    match stmt.first::<Row>(None).await {
        Ok(Some(row)) => row.did == did,
        _ => false,
    }
}

// ---------- did:key ----------

/// Encode a compressed pubkey as `did:key:z…`.
pub fn did_key_encode(pub_compressed_hex: &str, curve: &Curve) -> Result<String, KeyError> {
    let raw = hex::decode(pub_compressed_hex.trim()).map_err(|_| KeyError::BadEncoding("pub hex".into()))?;
    if raw.len() != 33 {
        return Err(KeyError::BadEncoding("compressed pubkey must be 33 bytes".into()));
    }
    let prefix: &[u8] = match curve {
        Curve::K256 => &[0xe7, 0x01],
        Curve::P256 => &[0x80, 0x24],
    };
    let mut prefixed = prefix.to_vec();
    prefixed.extend_from_slice(&raw);
    Ok(format!(
        "did:key:z{}",
        bs58::encode(prefixed).with_alphabet(bs58::Alphabet::BITCOIN).into_string()
    ))
}

#[allow(dead_code)]
fn did_key_decode(did_key: &str) -> Result<(Curve, String), KeyError> {
    let body = did_key
        .strip_prefix("did:key:z")
        .ok_or_else(|| KeyError::BadEncoding("must be did:key:z…".into()))?;
    let bytes = bs58::decode(body)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_vec()
        .map_err(|_| KeyError::BadEncoding("base58".into()))?;
    if bytes.starts_with(&[0xe7, 0x01]) && bytes.len() == 35 {
        Ok((Curve::K256, hex::encode(&bytes[2..])))
    } else if bytes.starts_with(&[0x80, 0x24]) && bytes.len() == 35 {
        Ok((Curve::P256, hex::encode(&bytes[2..])))
    } else {
        Err(KeyError::Unsupported("did:key multicodec".into()))
    }
}


// ---------- PLC operations ----------

#[derive(Debug, Clone)]
pub struct PlcGenesis {
    pub rotation_did_key: String,
    pub signing_did_key: String,
    pub handle: String,
    pub pds_endpoint: String,
}

/// Build the unsigned genesis operation object (field order irrelevant: CBOR sorts).
fn unsigned_genesis(gen: &PlcGenesis) -> serde_json::Value {
    serde_json::json!({
        "type": "plc_operation",
        "rotationKeys": [gen.rotation_did_key],
        "verificationMethods": { "atproto": gen.signing_did_key },
        "alsoKnownAs": [format!("at://{}", gen.handle)],
        "services": { "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": gen.pds_endpoint } },
        "prev": null,
    })
}

/// DAG-CBOR encode an op WITHOUT the `sig` field (spec: field absent, not null).
fn unsigned_op_cbor(op: &serde_json::Value) -> Result<Vec<u8>, String> {
    let mut map = op.as_object().ok_or("op must be object")?.clone();
    map.remove("sig");
    cbor::encode_json(&serde_json::Value::Object(map)).map_err(|e| e.to_string())
}

/// Sign an op with low-S canonicalization (PLC strictly rejects high-S).
pub fn low_s_k256(priv_hex: &str, digest: &[u8; 32]) -> Result<[u8; 64], KeyError> {
    /// secp256k1 group order.
    const N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x14, 0x41,
    ];
    /// floor(N / 2); valid low-S values satisfy s <= HALF_N.
    const HALF_N: [u8; 32] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x0A, 0x20,
    ];
    let mut sig = keys::sign_digest_k256(priv_hex, digest)?;
    if sig[32..] > HALF_N[..] {
        // s = N - s (big-endian subtraction).
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = N[i] as i16 - sig[32 + i] as i16 - borrow;
            sig[32 + i] = (d & 0xff) as u8;
            borrow = i16::from(d < 0);
        }
    }
    Ok(sig)
}

/// Create + sign a genesis op. Returns (did, signed_op_json).
pub fn plc_genesis_op(
    rotation_priv_hex: &str,
    gen: &PlcGenesis,
) -> Result<(String, serde_json::Value), String> {
    let unsigned = unsigned_genesis(gen);
    let bytes = unsigned_op_cbor(&unsigned)?;
    if bytes.len() > 7500 {
        return Err("op exceeds 7500 bytes".into());
    }
    let digest = keys::sha256_of(&bytes);
    let sig = low_s_k256(rotation_priv_hex, &digest).map_err(|e| e.to_string())?;
    let mut signed = unsigned.clone();
    signed["sig"] = serde_json::Value::String(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig));
    let signed_bytes = cbor::encode_json(&signed).map_err(|e| e.to_string())?;
    let hash = keys::sha256_of(&signed_bytes);
    // base32 (lowercase, no pad), first 24 chars.
    let b32 = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &hash).to_lowercase();
    let did = format!("did:plc:{}", &b32[..24]);
    Ok((did, signed))
}

/// Submit a signed op JSON to the PLC directory. Returns the canonical DID.
pub async fn plc_submit(env: &Env, did: &str, op: &serde_json::Value) -> XrpcResult<String> {
    use worker::{Fetch, Method, Request, RequestInit};
    let cfg = pds_env::PdsEnv::from_env(env).map_err(|e| XrpcError::internal(e.to_string()))?;
    let url = format!("{}/{did}", cfg.plc_url.trim_end_matches('/'));
    let body = serde_json::to_string(op).map_err(|e| XrpcError::internal(e.to_string()))?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(body.into()));
    let mut req = Request::new_with_init(&url, &init).map_err(|e| XrpcError::internal(e.to_string()))?;
    req.headers_mut()
        .map(|h| h.set("content-type", "application/json").ok())
        .map_err(|e| XrpcError::internal(e.to_string()))?;
    let resp = Fetch::Request(req).send().await.map_err(|e| XrpcError::internal(e.to_string()))?;
    if resp.status_code() != 200 {
        return Err(XrpcError::new(
            axum::http::StatusCode::BAD_GATEWAY,
            "PlcError",
            format!("PLC directory rejected operation: {}", resp.status_code()),
        ));
    }
    Ok(did.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROT_PRIV: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn genesis_fixture() -> PlcGenesis {
        let rot_pub = keys::k256_pub_from_priv(ROT_PRIV).unwrap();
        let sign_pub = keys::k256_pub_from_priv(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        )
        .unwrap();
        PlcGenesis {
            rotation_did_key: did_key_encode(&rot_pub, &Curve::K256).unwrap(),
            signing_did_key: did_key_encode(&sign_pub, &Curve::K256).unwrap(),
            handle: "alice.test".into(),
            pds_endpoint: "https://example.test".into(),
        }
    }

    #[test]
    fn did_key_roundtrip() {
        let pub_hex = keys::k256_pub_from_priv(ROT_PRIV).unwrap();
        let dk = did_key_encode(&pub_hex, &Curve::K256).unwrap();
        assert!(dk.starts_with("did:key:z"));
        let (curve, back) = did_key_decode(&dk).unwrap();
        assert!(matches!(curve, Curve::K256));
        assert_eq!(back, pub_hex);
    }

    #[test]
    fn genesis_did_is_deterministic_and_well_formed() {
        let (did1, op1) = plc_genesis_op(ROT_PRIV, &genesis_fixture()).unwrap();
        let (did2, _) = plc_genesis_op(ROT_PRIV, &genesis_fixture()).unwrap();
        assert_eq!(did1, did2);
        assert!(did1.starts_with("did:plc:"));
        assert_eq!(did1.len(), 8 + 24);
        assert!(crate::atproto::did::validate(&did1));
        // sig is base64url compact (86 chars for 64 bytes), low-S enforced.
        let sig_b64 = op1["sig"].as_str().unwrap();
        assert_eq!(sig_b64.len(), 86);
        use base64::Engine as _;
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig_b64).unwrap();
        assert!(is_low_s_k256(&sig));
    }

    #[test]
    fn genesis_sig_verifies_under_rotation_key() {
        let (_, op) = plc_genesis_op(ROT_PRIV, &genesis_fixture()).unwrap();
        let mut unsigned = op.clone();
        unsigned.as_object_mut().unwrap().remove("sig");
        let bytes = unsigned_op_cbor(&unsigned).unwrap();
        let digest = keys::sha256_of(&bytes);
        use base64::Engine as _;
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(op["sig"].as_str().unwrap()).unwrap();
        let pub_hex = keys::k256_pub_from_priv(ROT_PRIV).unwrap();
        keys::verify_digest(&pub_hex, &digest, &sig).unwrap();
    }

    #[test]
    fn parse_modern_and_legacy_did_docs() {
        let modern = serde_json::json!({
            "id": "did:plc:test",
            "alsoKnownAs": ["at://alice.test"],
            "verificationMethod": [{
                "id": "did:plc:test#atproto", "type": "Multikey",
                "controller": "did:plc:test",
                "publicKeyMultibase": keys::multikey_encode(&keys::k256_pub_from_priv(ROT_PRIV).unwrap(), &Curve::K256).unwrap(),
            }],
            "service": [{
                "id": "#atproto_pds", "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://example.test",
            }],
        });
        let doc = parse_did_doc(&modern, "did:plc:test").unwrap();
        assert_eq!(doc.handle.as_deref(), Some("alice.test"));
        assert_eq!(doc.pds_endpoint.as_deref(), Some("https://example.test"));
        assert!(doc.signing_key.is_some());

        // Legacy P-256 doc (uncompressed point, no multicodec), bare-fragment id.
        // Generator point uncompressed (well-known test value).
        let p256_uncompressed = hex::decode("04\
            6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
            4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5").unwrap();
        use base64::Engine as _;
        let legacy_mb = format!("z{}", bs58::encode(p256_uncompressed).with_alphabet(bs58::Alphabet::BITCOIN).into_string());
        let legacy = serde_json::json!({
            "id": "did:web:example.test",
            "alsoKnownAs": ["at://bob.test", "at://not a handle!!"],
            "verificationMethod": [{
                "id": "#atproto", "type": "EcdsaSecp256r1VerificationKey2019",
                "controller": "did:web:example.test",
                "publicKeyMultibase": legacy_mb,
            }],
            "service": [{
                "id": "did:web:example.test#atproto_pds", "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://example.test",
            }],
        });
        let doc = parse_did_doc(&legacy, "did:web:example.test").unwrap();
        assert_eq!(doc.handle.as_deref(), Some("bob.test"));
        let (curve, hex) = doc.signing_key.unwrap();
        assert!(matches!(curve, Curve::P256));
        assert_eq!(hex, "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
    }

    fn is_low_s_k256(sig: &[u8]) -> bool {
        const HALF_N: [u8; 32] = [
            0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x0A, 0x20,
        ];
        sig.len() == 64 && sig[32..] <= HALF_N[..]
    }
}

// ---------- PLC updates (rotation / handle / service changes) ----------

#[derive(Debug, Clone, Default)]
pub struct PlcFields {
    pub rotation_keys: Vec<String>,
    pub verification_methods: serde_json::Value,
    pub also_known_as: Vec<String>,
    pub services: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct PlcCurrent {
    pub fields: PlcFields,
    pub prev_cid: String,
}

/// Fetch current PLC state (`/data`) plus the head op CID (`/log/audit`).
pub async fn plc_current(env: &Env, did: &str) -> Result<PlcCurrent, String> {
    let cfg = pds_env::PdsEnv::from_env(env).map_err(|e| e.to_string())?;
    let base = cfg.plc_url.trim_end_matches('/');
    let (status, text) = fetch_text(&format!("{base}/{did}/data"), "application/json")
        .await
        .map_err(|e| e.message.clone())?;
    if status != 200 {
        return Err(format!("PLC state fetch failed: {status}"));
    }
    let data: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let get_strs = |v: Option<&serde_json::Value>| -> Vec<String> {
        v.and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(|e| e.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default()
    };
    let fields = PlcFields {
        rotation_keys: get_strs(data.get("rotationKeys")),
        verification_methods: data.get("verificationMethods").cloned().unwrap_or(serde_json::json!({})),
        also_known_as: get_strs(data.get("alsoKnownAs")),
        services: data.get("services").cloned().unwrap_or(serde_json::json!({})),
    };
    // Audit log -> head CID (accept array-of-entries or single object).
    let (astatus, atext) = fetch_text(&format!("{base}/{did}/log/audit"), "application/json")
        .await
        .map_err(|e| e.message.clone())?;
    if astatus != 200 {
        return Err(format!("PLC audit fetch failed: {astatus}"));
    }
    let audit: serde_json::Value = serde_json::from_str(&atext).map_err(|e| e.to_string())?;
    let prev_cid = match &audit {
        serde_json::Value::Array(entries) => entries
            .last()
            .and_then(|e| e.get("cid"))
            .and_then(|c| c.as_str())
            .ok_or("audit has no head cid")?
            .to_string(),
        serde_json::Value::Object(map) => map
            .get("cid")
            .and_then(|c| c.as_str())
            .ok_or("audit has no cid")?
            .to_string(),
        _ => return Err("bad audit shape".into()),
    };
    if Cid::parse(&prev_cid).is_err() {
        return Err("bad prev cid".into());
    }
    Ok(PlcCurrent { fields, prev_cid })
}

use crate::cid::Cid;

#[derive(Debug, Clone, Default)]
pub struct PlcChanges {
    pub rotation_keys: Option<Vec<String>>,
    pub verification_methods: Option<serde_json::Value>,
    pub also_known_as: Option<Vec<String>>,
    pub services: Option<serde_json::Value>,
}

/// Build + low-S sign an update op against the current state.
pub fn plc_update_op(
    rotation_priv_hex: &str,
    current: &PlcCurrent,
    changes: &PlcChanges,
) -> Result<serde_json::Value, String> {
    let rotation_keys = changes.rotation_keys.clone().unwrap_or_else(|| current.fields.rotation_keys.clone());
    if rotation_keys.is_empty() || rotation_keys.len() > 5 {
        return Err("rotationKeys must have 1..=5 keys".into());
    }
    for k in &rotation_keys {
        did_key_decode(k).map_err(|e| format!("bad rotationKey: {e}"))?;
    }
    let op = serde_json::json!({
        "type": "plc_operation",
        "rotationKeys": rotation_keys,
        "verificationMethods": changes.verification_methods.clone().unwrap_or_else(|| current.fields.verification_methods.clone()),
        "alsoKnownAs": changes.also_known_as.clone().unwrap_or_else(|| current.fields.also_known_as.clone()),
        "services": changes.services.clone().unwrap_or_else(|| current.fields.services.clone()),
        "prev": current.prev_cid,
    });
    let bytes = unsigned_op_cbor(&op)?;
    if bytes.len() > 7500 {
        return Err("op exceeds 7500 bytes".into());
    }
    let digest = keys::sha256_of(&bytes);
    let sig = low_s_k256(rotation_priv_hex, &digest).map_err(|e| e.to_string())?;
    let mut signed = op.clone();
    signed["sig"] = serde_json::Value::String(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig));
    Ok(signed)
}

/// Verify an update op's signature against one of the given rotation did:keys.
pub fn verify_plc_op(op: &serde_json::Value, rotation_keys: &[String]) -> Result<(), String> {
    let sig_b64 = op.get("sig").and_then(|v| v.as_str()).ok_or("missing sig")?;
    use base64::Engine as _;
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| "bad sig encoding")?;
    if sig.len() != 64 {
        return Err("bad sig length".into());
    }
    let mut unsigned = op.clone();
    unsigned.as_object_mut().ok_or("op must be object")?.remove("sig");
    let bytes = unsigned_op_cbor(&unsigned)?;
    let digest = keys::sha256_of(&bytes);
    for rk in rotation_keys {
        let (_, pub_hex) = did_key_decode(rk).map_err(|e| e.to_string())?;
        if keys::verify_digest(&pub_hex, &digest, &sig).is_ok() {
            return Ok(());
        }
    }
    Err("no rotation key verifies this op".into())
}

// ---------- PLC audit verification ----------

/// Fully validate a DID's operation log: genesis DID recomputation, per-op
/// rotation-key signatures, and CID hash chaining. `entries` are audit items
/// with `operation` + `cid` (sequenced export shape).
pub fn verify_audit_log(did: &str, entries: &[serde_json::Value]) -> Result<usize, String> {
    if entries.is_empty() {
        return Err("empty audit log".into());
    }
    // Genesis: DID must recompute.
    let genesis = entries[0].get("operation").ok_or("entry lacks operation".to_string())?;
    let genesis_bytes = cbor::encode_json(genesis).map_err(|e| e.to_string())?;
    let hash = keys::sha256_of(&genesis_bytes);
    let b32 = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &hash).to_lowercase();
    if did != format!("did:plc:{}", &b32[..24]) {
        return Err("genesis does not match DID".into());
    }
    let mut rotation_keys: Vec<String> = genesis
        .get("rotationKeys")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|k| k.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    if rotation_keys.is_empty() {
        return Err("genesis lacks rotationKeys".into());
    }
    verify_plc_op(genesis, &rotation_keys)?;
    let mut prev_bytes = genesis_bytes;
    for entry in &entries[1..] {
        let op = entry.get("operation").ok_or("entry lacks operation".to_string())?;
        // CID linkage.
        let op_bytes = cbor::encode_json(op).map_err(|e| e.to_string())?;
        let expect_prev = {
            let h = keys::sha256_of(&prev_bytes);
            let mut raw = vec![0x01, 0x71, 0x12, 0x20];
            raw.extend_from_slice(&h);
            format!("b{}", base32::encode(base32::Alphabet::RFC4648 { padding: false }, &raw).to_lowercase())
        };
        match op.get("prev") {
            Some(serde_json::Value::String(prev)) if prev == &expect_prev => {}
            _ => return Err("prev CID break".into()),
        }
        verify_plc_op(op, &rotation_keys)?;
        // Advance rotation keys from this op.
        if let Some(keys) = op.get("rotationKeys").and_then(|v| v.as_array()) {
            rotation_keys = keys.iter().filter_map(|k| k.as_str().map(|s| s.to_string())).collect();
        }
        prev_bytes = op_bytes;
    }
    Ok(entries.len())
}

#[cfg(test)]
mod audit_tests {
    use super::*;

    const ROT_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const ROT_B: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";

    fn did_key(priv_hex: &str) -> String {
        let pub_hex = keys::k256_pub_from_priv(priv_hex).unwrap();
        did_key_encode(&pub_hex, &Curve::K256).unwrap()
    }

    fn sign_op(priv_hex: &str, mut op: serde_json::Value) -> serde_json::Value {
        let bytes = unsigned_op_cbor(&op).unwrap();
        let sig = low_s_k256(priv_hex, &keys::sha256_of(&bytes)).unwrap();
        use base64::Engine as _;
        op["sig"] = serde_json::Value::String(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig));
        op
    }

    fn genesis_op_for(key_priv: &str) -> (String, serde_json::Value) {
        plc_genesis_op(
            key_priv,
            &PlcGenesis {
                rotation_did_key: did_key(key_priv),
                signing_did_key: did_key(key_priv),
                handle: "audit.test".into(),
                pds_endpoint: "https://example.test".into(),
            },
        )
        .unwrap()
    }

    fn op_cid(op: &serde_json::Value) -> String {
        let bytes = cbor::encode_json(op).unwrap();
        let h = keys::sha256_of(&bytes);
        let mut raw = vec![0x01, 0x71, 0x12, 0x20];
        raw.extend_from_slice(&h);
        format!("b{}", base32::encode(base32::Alphabet::RFC4648 { padding: false }, &raw).to_lowercase())
    }

    #[test]
    fn audit_chain_validates() {
        let (did, genesis) = genesis_op_for(ROT_A);
        // Update: rotate to key B, signed by A.
        let update = sign_op(
            ROT_A,
            serde_json::json!({
                "type": "plc_operation",
                "rotationKeys": [did_key(ROT_B)],
                "verificationMethods": {"atproto": did_key(ROT_A)},
                "alsoKnownAs": ["at://audit.test"],
                "services": {"atproto_pds": {"type": "AtprotoPersonalDataServer", "endpoint": "https://example.test"}},
                "prev": op_cid(&genesis),
            }),
        );
        // Recovery-style follow-up signed by B.
        let update2 = sign_op(
            ROT_B,
            serde_json::json!({
                "type": "plc_operation",
                "rotationKeys": [did_key(ROT_B)],
                "verificationMethods": {"atproto": did_key(ROT_B)},
                "alsoKnownAs": ["at://audit2.test"],
                "services": {"atproto_pds": {"type": "AtprotoPersonalDataServer", "endpoint": "https://example.test"}},
                "prev": op_cid(&update),
            }),
        );
        let entries = vec![
            serde_json::json!({"did": did, "cid": op_cid(&genesis), "operation": genesis}),
            serde_json::json!({"did": did, "cid": op_cid(&update), "operation": update}),
            serde_json::json!({"did": did, "cid": op_cid(&update2), "operation": update2}),
        ];
        assert_eq!(verify_audit_log(&did, &entries).unwrap(), 3);
    }

    #[test]
    fn audit_rejects_forgery_and_reorder() {
        let (did, genesis) = genesis_op_for(ROT_A);
        let update = sign_op(
            ROT_A,
            serde_json::json!({
                "type": "plc_operation",
                "rotationKeys": [did_key(ROT_B)],
                "verificationMethods": {"atproto": did_key(ROT_A)},
                "alsoKnownAs": ["at://audit.test"],
                "services": {"atproto_pds": {"type": "AtprotoPersonalDataServer", "endpoint": "https://example.test"}},
                "prev": op_cid(&genesis),
            }),
        );
        let entries = vec![
            serde_json::json!({"did": did, "cid": op_cid(&genesis), "operation": genesis.clone()}),
            serde_json::json!({"did": did, "cid": op_cid(&update), "operation": update}),
        ];
        verify_audit_log(&did, &entries).unwrap();
        // Reordered.
        let mut swapped = entries.clone();
        swapped.swap(0, 1);
        assert!(verify_audit_log(&did, &swapped).is_err());
        // Attacker-signed update (unknown key) fails even with a fixed prev.
        let evil = sign_op(
            "0000000000000000000000000000000000000000000000000000000000000001",
            serde_json::json!({
                "type": "plc_operation",
                "rotationKeys": [did_key(ROT_A)],
                "verificationMethods": {"atproto": did_key(ROT_A)},
                "alsoKnownAs": ["at://evil.test"],
                "services": {"atproto_pds": {"type": "AtprotoPersonalDataServer", "endpoint": "https://evil.test"}},
                "prev": op_cid(&genesis),
            }),
        );
        let evil_entries = vec![
            serde_json::json!({"did": did, "cid": op_cid(&genesis), "operation": genesis}),
            serde_json::json!({"did": did, "cid": op_cid(&evil), "operation": evil}),
        ];
        assert!(verify_audit_log(&did, &evil_entries).is_err());
        // Wrong DID.
        assert!(verify_audit_log("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", &entries[0..1].to_vec()).is_err());
    }
}
