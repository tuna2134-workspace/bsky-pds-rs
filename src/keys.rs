//! atproto signing keys: secp256k1 (k256, repo standard) + p256 verification.
//! Specs: <https://atproto.com/specs/cryptography>, <https://atproto.com/specs/did>
//!
//! Commits are signed over SHA-256(unsigned-commit-DAG-CBOR) with deterministic
//! RFC 6979 ECDSA (matches `@noble/curves` `sign(hash, priv)` on the TS side).

use k256::ecdsa::{signature::hazmat::PrehashVerifier, SigningKey as K256Signing, VerifyingKey as K256Verifying};
use sha2::{Digest, Sha256};
use base64::Engine as _;

#[derive(Debug)]
pub enum KeyError {
    BadEncoding(String),
    Unsupported(String),
    VerifyFailed,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::BadEncoding(s) => write!(f, "bad key encoding: {s}"),
            KeyError::Unsupported(s) => write!(f, "unsupported key: {s}"),
            KeyError::VerifyFailed => write!(f, "signature verification failed"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    K256,
    P256,
}

/// Generate a fresh secp256k1 keypair. Returns (priv_hex, pub_compressed_hex).
/// Requires a browser/worker RNG (getrandom js) — call only on wasm targets.
pub fn generate_k256() -> Result<(String, String), KeyError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| KeyError::BadEncoding("rng unavailable".into()))?;
    let signing = K256Signing::from_bytes(bytes.as_slice().into())
        .map_err(|_| KeyError::BadEncoding("secret key".into()))?;
    let verifying = signing.verifying_key();
    Ok((
        hex::encode(signing.to_bytes()),
        hex::encode(verifying.to_encoded_point(true).as_bytes()),
    ))
}

pub fn k256_pub_from_priv(priv_hex: &str) -> Result<String, KeyError> {
    let bytes = hex::decode(priv_hex.trim()).map_err(|_| KeyError::BadEncoding("priv hex".into()))?;
    let signing = K256Signing::from_bytes(bytes.as_slice().into())
        .map_err(|_| KeyError::BadEncoding("secret key".into()))?;
    Ok(hex::encode(signing.verifying_key().to_encoded_point(true).as_bytes()))
}

/// Sign a 32-byte SHA-256 digest deterministically (RFC 6979). Returns 64-byte compact sig.
pub fn sign_digest_k256(priv_hex: &str, digest: &[u8; 32]) -> Result<[u8; 64], KeyError> {
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    let bytes = hex::decode(priv_hex.trim()).map_err(|_| KeyError::BadEncoding("priv hex".into()))?;
    let signing = K256Signing::from_bytes(bytes.as_slice().into())
        .map_err(|_| KeyError::BadEncoding("secret key".into()))?;
    let (sig, _) = signing
        .sign_prehash(digest)
        .map_err(|_| KeyError::BadEncoding("sign failed".into()))?;
    Ok(sig.to_bytes().into())
}

/// Verify a compact signature over a digest against a compressed pubkey (hex, either curve).
pub fn verify_digest(pub_hex: &str, digest: &[u8; 32], sig64: &[u8]) -> Result<(), KeyError> {
    let pub_bytes = hex::decode(pub_hex.trim()).map_err(|_| KeyError::BadEncoding("pub hex".into()))?;
    if pub_bytes.len() != 33 {
        return Err(KeyError::BadEncoding("compressed pubkey must be 33 bytes".into()));
    }
    // Try k256 first, then p256 (both use 33-byte compressed points here).
    if verify_k256(&pub_bytes, digest, sig64).is_ok() {
        return Ok(());
    }
    verify_p256(&pub_bytes, digest, sig64)
}

fn verify_k256(pub_bytes: &[u8], digest: &[u8; 32], sig64: &[u8]) -> Result<(), KeyError> {
    let vk = K256Verifying::from_sec1_bytes(pub_bytes).map_err(|_| KeyError::VerifyFailed)?;
    let sig = k256::ecdsa::Signature::try_from(sig64).map_err(|_| KeyError::VerifyFailed)?;
    vk.verify_prehash(digest, &sig).map_err(|_| KeyError::VerifyFailed)
}

fn verify_p256(pub_bytes: &[u8], digest: &[u8; 32], sig64: &[u8]) -> Result<(), KeyError> {
    use p256::ecdsa::{signature::hazmat::PrehashVerifier as P256Verifier, VerifyingKey as P256Verifying};
    let vk = P256Verifying::from_sec1_bytes(pub_bytes).map_err(|_| KeyError::VerifyFailed)?;
    let sig = p256::ecdsa::Signature::try_from(sig64).map_err(|_| KeyError::VerifyFailed)?;
    vk.verify_prehash(digest, &sig).map_err(|_| KeyError::VerifyFailed)
}

// ---------- DID Multikey ----------

/// Multicodec prefixes: secp256k1-pub 0xe7, p256-pub 0x1200.
fn multicodec_prefix(curve: &Curve) -> Vec<u8> {
    match curve {
        Curve::K256 => vec![0xe7, 0x01],
        Curve::P256 => vec![0x80, 0x24],
    }
}

/// Encode a compressed pubkey (hex) as `publicKeyMultibase` (`z…` base58btc Multikey).
pub fn multikey_encode(pub_compressed_hex: &str, curve: &Curve) -> Result<String, KeyError> {
    let raw = hex::decode(pub_compressed_hex.trim()).map_err(|_| KeyError::BadEncoding("pub hex".into()))?;
    if raw.len() != 33 {
        return Err(KeyError::BadEncoding("compressed pubkey must be 33 bytes".into()));
    }
    let mut prefixed = multicodec_prefix(curve);
    prefixed.extend_from_slice(&raw);
    Ok(format!("z{}", bs58::encode(prefixed).with_alphabet(bs58::Alphabet::BITCOIN).into_string()))
}

/// Decode `publicKeyMultibase` back to (curve, compressed pubkey hex).
pub fn multikey_decode(multibase: &str) -> Result<(Curve, String), KeyError> {
    let body = multibase.strip_prefix('z').ok_or_else(|| KeyError::BadEncoding("must start with z".into()))?;
    let bytes = bs58::decode(body)
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_vec()
        .map_err(|_| KeyError::BadEncoding("base58".into()))?;
    if bytes.starts_with(&[0xe7, 0x01]) && bytes.len() == 35 {
        Ok((Curve::K256, hex::encode(&bytes[2..])))
    } else if bytes.starts_with(&[0x80, 0x24]) && bytes.len() == 35 {
        Ok((Curve::P256, hex::encode(&bytes[2..])))
    } else {
        Err(KeyError::Unsupported("unknown multicodec".into()))
    }
}

pub fn sha256_of(data: &[u8]) -> [u8; 32] {
    let d = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fixed test key (never used in production).
    const PRIV: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn pubkey_and_multikey_roundtrip() {
        let pub_hex = k256_pub_from_priv(PRIV).unwrap();
        assert_eq!(pub_hex.len(), 66); // 33 bytes compressed
        let mk = multikey_encode(&pub_hex, &Curve::K256).unwrap();
        assert!(mk.starts_with('z'));
        let (curve, back) = multikey_decode(&mk).unwrap();
        assert!(matches!(curve, Curve::K256));
        assert_eq!(back, pub_hex);
    }

    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let digest = sha256_of(b"unsigned-commit-bytes");
        let sig = sign_digest_k256(PRIV, &digest).unwrap();
        assert_eq!(sig.len(), 64);
        let pub_hex = k256_pub_from_priv(PRIV).unwrap();
        verify_digest(&pub_hex, &digest, &sig).unwrap();
        // Tampered digest must fail.
        let bad = sha256_of(b"unsigned-commit-bytez");
        assert!(verify_digest(&pub_hex, &bad, &sig).is_err());
        // Tampered sig must fail.
        let mut bad_sig = sig;
        bad_sig[0] ^= 0xff;
        assert!(verify_digest(&pub_hex, &digest, &bad_sig).is_err());
    }

    #[test]
    fn deterministic_signature() {
        // RFC 6979: same key + digest => same bytes (no RNG involved).
        let digest = sha256_of(b"determinism-check");
        assert_eq!(
            sign_digest_k256(PRIV, &digest).unwrap(),
            sign_digest_k256(PRIV, &digest).unwrap()
        );
    }

    #[test]
    fn pkce_rfc7636_vector() {
        // RFC 7636 Appendix B (verified against the RFC text).
        assert_eq!(
            pkce_s256_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn jwk_thumbprint_reference() {
        // Canonicalization per RFC 7638 §3 (sorted members, no whitespace);
        // digest cross-checked with Python hashlib.
        let jwk = serde_json::json!({
            "kty": "EC", "crv": "P-256",
            "x": "axfR8uEsQkf4vOblY6RA8nc_____8AzjyTg5pYn0i5c",
            "y": "axfR8uEsQkf4vOblY6RA8nc_____8AzjyTg5pYn0i5c",
        });
        assert_eq!(jwk_thumbprint(&jwk).unwrap(), "mzuTQrAFpY4o8VrnfkZt3mpV3SF2cWWbSycwKj4uvqg");
    }

    #[test]
    fn es256_jwt_roundtrip() {
        let (priv_hex, pub_hex) = {
            // Deterministic P-256 key from fixed bytes (test only).
            let signing = p256::ecdsa::SigningKey::from_bytes(
                hex::decode(PRIV).unwrap().as_slice().into(),
            )
            .unwrap();
            (
                PRIV.to_string(),
                hex::encode(signing.verifying_key().to_encoded_point(true).as_bytes()),
            )
        };
        let claims = serde_json::json!({ "sub": "did:plc:test", "scope": "atproto", "jti": "x" });
        let tok = sign_jwt_es256(&priv_hex, "at+jwt", &claims).unwrap();
        let back = verify_jwt_es256(&tok, &pub_hex, Some("at+jwt")).unwrap();
        assert_eq!(back["sub"], serde_json::Value::String("did:plc:test".into()));
        assert!(verify_jwt_es256(&tok, &pub_hex, Some("refresh+jwt")).is_err());
        // Tampered payload fails.
        let mut parts: Vec<&str> = tok.split('.').collect();
        parts[1] = "e30";
        assert!(verify_jwt_es256(&parts.join("."), &pub_hex, None).is_err());
    }

    #[test]
    fn hs256_jwt_roundtrip() {
        let claims = serde_json::json!({ "sub": "did:plc:test", "scope": "transition:generic" });
        let tok = sign_jwt_hs256("test-secret-32-chars-minimum-00", "at+jwt", &claims).unwrap();
        let (typ, back) = verify_jwt_hs256(&tok, "test-secret-32-chars-minimum-00").unwrap();
        assert_eq!(typ, "at+jwt");
        assert_eq!(back["sub"], serde_json::Value::String("did:plc:test".into()));
        assert!(verify_jwt_hs256(&tok, "wrong-secret").is_err());
    }
}

// ---------- P-256 (OAuth server keys, ES256) ----------

/// Generate a fresh P-256 keypair. Returns (priv_hex, pub_compressed_hex).
pub fn generate_p256() -> Result<(String, String), KeyError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| KeyError::BadEncoding("rng unavailable".into()))?;
    let signing = p256::ecdsa::SigningKey::from_bytes(bytes.as_slice().into())
        .map_err(|_| KeyError::BadEncoding("secret key".into()))?;
    let verifying = signing.verifying_key();
    Ok((
        hex::encode(signing.to_bytes()),
        hex::encode(verifying.to_encoded_point(true).as_bytes()),
    ))
}

pub fn p256_pub_from_priv(priv_hex: &str) -> Result<String, KeyError> {
    let bytes = hex::decode(priv_hex.trim()).map_err(|_| KeyError::BadEncoding("priv hex".into()))?;
    let signing = p256::ecdsa::SigningKey::from_bytes(bytes.as_slice().into())
        .map_err(|_| KeyError::BadEncoding("secret key".into()))?;
    Ok(hex::encode(signing.verifying_key().to_encoded_point(true).as_bytes()))
}

/// Deterministic RFC 6979 P-256 signature over a digest. 64-byte compact.
pub fn sign_digest_p256(priv_hex: &str, digest: &[u8; 32]) -> Result<[u8; 64], KeyError> {
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    let bytes = hex::decode(priv_hex.trim()).map_err(|_| KeyError::BadEncoding("priv hex".into()))?;
    let signing = p256::ecdsa::SigningKey::from_bytes(bytes.as_slice().into())
        .map_err(|_| KeyError::BadEncoding("secret key".into()))?;
    let (sig, _) = signing
        .sign_prehash(digest)
        .map_err(|_| KeyError::BadEncoding("sign failed".into()))?;
    Ok(sig.to_bytes().into())
}

// ---------- JWK (public keys) ----------

/// Uncompressed coordinates of a compressed pubkey (either curve).
pub fn decompressed_coords(pub_compressed_hex: &str, curve: &Curve) -> Result<([u8; 32], [u8; 32]), KeyError> {
    let raw = hex::decode(pub_compressed_hex.trim()).map_err(|_| KeyError::BadEncoding("pub hex".into()))?;
    if raw.len() != 33 {
        return Err(KeyError::BadEncoding("compressed pubkey must be 33 bytes".into()));
    }
    let point = match curve {
        Curve::K256 => K256Verifying::from_sec1_bytes(&raw)
            .map_err(|_| KeyError::BadEncoding("bad k256 point".into()))?
            .to_encoded_point(false),
        Curve::P256 => p256::ecdsa::VerifyingKey::from_sec1_bytes(&raw)
            .map_err(|_| KeyError::BadEncoding("bad p256 point".into()))?
            .to_encoded_point(false),
    };
    let (x, y) = (point.x().ok_or_else(|| KeyError::BadEncoding("no x".into()))?, point.y().ok_or_else(|| KeyError::BadEncoding("no y".into()))?);
    let mut xb = [0u8; 32];
    let mut yb = [0u8; 32];
    xb.copy_from_slice(&x);
    yb.copy_from_slice(&y);
    Ok((xb, yb))
}

fn b64u(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Public JWK for an EC key (`{"kty":"EC","crv":…,"x":…,"y":…}`).
pub fn public_jwk(pub_compressed_hex: &str, curve: &Curve) -> Result<serde_json::Value, KeyError> {
    let (x, y) = decompressed_coords(pub_compressed_hex, curve)?;
    let crv = match curve {
        Curve::K256 => "secp256k1",
        Curve::P256 => "P-256",
    };
    Ok(serde_json::json!({ "kty": "EC", "crv": crv, "x": b64u(&x), "y": b64u(&y) }))
}

/// RFC 7638 JWK SHA-256 thumbprint (required members only, sorted, no whitespace).
pub fn jwk_thumbprint(jwk: &serde_json::Value) -> Result<String, KeyError> {
    let obj = jwk.as_object().ok_or_else(|| KeyError::BadEncoding("jwk must be object".into()))?;
    let kty = obj.get("kty").and_then(|v| v.as_str()).ok_or_else(|| KeyError::BadEncoding("jwk kty".into()))?;
    let canon = if kty == "EC" {
        let crv = obj.get("crv").and_then(|v| v.as_str()).ok_or_else(|| KeyError::BadEncoding("jwk crv".into()))?;
        let x = obj.get("x").and_then(|v| v.as_str()).ok_or_else(|| KeyError::BadEncoding("jwk x".into()))?;
        let y = obj.get("y").and_then(|v| v.as_str()).ok_or_else(|| KeyError::BadEncoding("jwk y".into()))?;
        format!("{{\"crv\":\"{crv}\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}")
    } else if kty == "oct" {
        let k = obj.get("k").and_then(|v| v.as_str()).ok_or_else(|| KeyError::BadEncoding("jwk k".into()))?;
        format!("{{\"k\":\"{k}\",\"kty\":\"oct\"}}")
    } else {
        return Err(KeyError::Unsupported("jwk kty for thumbprint".into()));
    };
    Ok(b64u(&sha256_of(canon.as_bytes())))
}

// ---------- JWT (ES256 / HS256) ----------

fn jwt_split(token: &str) -> Result<(serde_json::Value, serde_json::Value, Vec<u8>, String), KeyError> {
    let mut parts = token.split('.');
    let (h, p, s) = (parts.next(), parts.next(), parts.next());
    match (h, p, s, parts.next()) {
        (Some(h), Some(p), Some(s), None) => {
            let hb = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(h)
                .map_err(|_| KeyError::BadEncoding("jwt header".into()))?;
            let pb = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(p)
                .map_err(|_| KeyError::BadEncoding("jwt payload".into()))?;
            let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(s)
                .map_err(|_| KeyError::BadEncoding("jwt sig".into()))?;
            let header: serde_json::Value =
                serde_json::from_slice(&hb).map_err(|_| KeyError::BadEncoding("jwt header json".into()))?;
            let payload: serde_json::Value =
                serde_json::from_slice(&pb).map_err(|_| KeyError::BadEncoding("jwt payload json".into()))?;
            Ok((header, payload, sig, format!("{h}.{p}")))
        }
        _ => Err(KeyError::BadEncoding("jwt structure".into())),
    }
}

/// Sign JWT claims with ES256 (P-256). `typ` goes in the header.
pub fn sign_jwt_es256(priv_hex: &str, typ: &str, claims: &serde_json::Value) -> Result<String, KeyError> {
    let header = serde_json::json!({ "alg": "ES256", "typ": typ });
    let h = b64u(header.to_string().as_bytes());
    let p = b64u(claims.to_string().as_bytes());
    let digest = sha256_of(format!("{h}.{p}").as_bytes());
    let sig = sign_digest_p256(priv_hex, &digest)?;
    // JWS ES256 uses raw R||S (not DER).
    Ok(format!("{h}.{p}.{}", b64u(&sig)))
}

/// Verify an ES256 JWT against a compressed P-256 pubkey (hex). Returns payload.
pub fn verify_jwt_es256(token: &str, pub_hex: &str, expect_typ: Option<&str>) -> Result<serde_json::Value, KeyError> {
    let (header, payload, sig, signing_input) = jwt_split(token)?;
    if header.get("alg").and_then(|v| v.as_str()) != Some("ES256") {
        return Err(KeyError::BadEncoding("alg must be ES256".into()));
    }
    if let Some(t) = expect_typ {
        if header.get("typ").and_then(|v| v.as_str()) != Some(t) {
            return Err(KeyError::BadEncoding("bad typ".into()));
        }
    }
    if sig.len() != 64 {
        return Err(KeyError::BadEncoding("sig must be 64 bytes".into()));
    }
    let digest = sha256_of(signing_input.as_bytes());
    verify_digest_p256(pub_hex, &digest, &sig)?;
    Ok(payload)
}

fn verify_digest_p256(pub_hex: &str, digest: &[u8; 32], sig64: &[u8]) -> Result<(), KeyError> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    let raw = hex::decode(pub_hex.trim()).map_err(|_| KeyError::BadEncoding("pub hex".into()))?;
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&raw).map_err(|_| KeyError::VerifyFailed)?;
    let sig = p256::ecdsa::Signature::try_from(sig64).map_err(|_| KeyError::VerifyFailed)?;
    vk.verify_prehash(digest, &sig).map_err(|_| KeyError::VerifyFailed)
}

/// Sign JWT claims with ES256K (secp256k1 + SHA-256, atproto inter-service auth).
/// Header: {"alg":"ES256K","typ":"JWT"}. Compact R||S signature, base64url.
pub fn sign_jwt_es256k(priv_hex: &str, claims: &serde_json::Value) -> Result<String, KeyError> {
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    let header = serde_json::json!({ "alg": "ES256K", "typ": "JWT" });
    let h = b64u(header.to_string().as_bytes());
    let p = b64u(claims.to_string().as_bytes());
    let digest = sha256_of(format!("{h}.{p}").as_bytes());
    let bytes = hex::decode(priv_hex.trim()).map_err(|_| KeyError::BadEncoding("priv hex".into()))?;
    let signing = K256Signing::from_bytes(bytes.as_slice().into())
        .map_err(|_| KeyError::BadEncoding("secret key".into()))?;
    let (sig, _) = signing.sign_prehash(&digest).map_err(|_| KeyError::BadEncoding("sign failed".into()))?;
    Ok(format!("{h}.{p}.{}", b64u(&sig.to_bytes())))
}

/// Verify an ES256K JWT against a compressed secp256k1 pubkey (hex). Returns payload.
pub fn verify_jwt_es256k(token: &str, pub_hex: &str) -> Result<serde_json::Value, KeyError> {
    let (header, payload, sig, signing_input) = jwt_split(token)?;
    if header.get("alg").and_then(|v| v.as_str()) != Some("ES256K") {
        return Err(KeyError::BadEncoding("alg must be ES256K".into()));
    }
    if sig.len() != 64 {
        return Err(KeyError::BadEncoding("sig must be 64 bytes".into()));
    }
    let digest = sha256_of(signing_input.as_bytes());
    verify_digest(pub_hex, &digest, &sig)?;
    Ok(payload)
}

/// Sign access claims with ES256K (account key) and `typ: at+jwt`.
/// Lets any federation peer verify sessions via the DID doc — unlike HS256
/// server secrets, which only this PDS can check.
pub fn sign_access_es256k(priv_hex: &str, claims: &serde_json::Value) -> Result<String, KeyError> {
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    let header = serde_json::json!({ "alg": "ES256K", "typ": "at+jwt" });
    let h = b64u(header.to_string().as_bytes());
    let p = b64u(claims.to_string().as_bytes());
    let digest = sha256_of(format!("{h}.{p}").as_bytes());
    let bytes = hex::decode(priv_hex.trim()).map_err(|_| KeyError::BadEncoding("priv hex".into()))?;
    let signing = K256Signing::from_bytes(bytes.as_slice().into())
        .map_err(|_| KeyError::BadEncoding("secret key".into()))?;
    let (sig, _) = signing.sign_prehash(&digest).map_err(|_| KeyError::BadEncoding("sign failed".into()))?;
    Ok(format!("{h}.{p}.{}", b64u(&sig.to_bytes())))
}

/// Peek at a JWT header `alg` without verifying (dispatch only).
pub fn jwt_alg(token: &str) -> Option<String> {
    let (header, _, _, _) = jwt_split(token).ok()?;
    header.get("alg").and_then(|v| v.as_str()).map(|s| s.to_string())
}

/// JWT header `typ` without verifying (dispatch only).
pub fn jwt_typ(token: &str) -> Option<String> {
    let (header, _, _, _) = jwt_split(token).ok()?;
    header.get("typ").and_then(|v| v.as_str()).map(|s| s.to_string())
}

/// Full JWT split without verifying (resolve-then-verify flows).
pub fn jwt_split_unverified(token: &str) -> Option<(serde_json::Value, serde_json::Value)> {
    let (header, payload, _, _) = jwt_split(token).ok()?;
    Some((header, payload))
}

/// Sign JWT claims with HS256 (compat session tokens). `typ`: `at+jwt` / `refresh+jwt`.
pub fn sign_jwt_hs256(secret: &str, typ: &str, claims: &serde_json::Value) -> Result<String, KeyError> {
    use hmac::{Hmac, Mac};
    let header = serde_json::json!({ "alg": "HS256", "typ": typ });
    let h = b64u(header.to_string().as_bytes());
    let p = b64u(claims.to_string().as_bytes());
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| KeyError::BadEncoding("hmac key".into()))?;
    mac.update(format!("{h}.{p}").as_bytes());
    Ok(format!("{h}.{p}.{}", b64u(&mac.finalize().into_bytes())))
}

/// Verify an HS256 JWT. Returns (typ, payload).
pub fn verify_jwt_hs256(token: &str, secret: &str) -> Result<(String, serde_json::Value), KeyError> {
    use hmac::{Hmac, Mac};
    let (header, payload, sig, signing_input) = jwt_split(token)?;
    if header.get("alg").and_then(|v| v.as_str()) != Some("HS256") {
        return Err(KeyError::BadEncoding("alg must be HS256".into()));
    }
    let typ = header.get("typ").and_then(|v| v.as_str()).ok_or_else(|| KeyError::BadEncoding("typ".into()))?.to_string();
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| KeyError::BadEncoding("hmac key".into()))?;
    mac.update(signing_input.as_bytes());
    mac.verify_slice(&sig).map_err(|_| KeyError::VerifyFailed)?;
    Ok((typ, payload))
}

// ---------- misc crypto helpers ----------

/// 32 random bytes as base64url (auth codes, nonces, PKCE verifiers).
pub fn random_b64u32() -> Result<String, KeyError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| KeyError::BadEncoding("rng unavailable".into()))?;
    Ok(b64u(&bytes))
}

/// S256 PKCE challenge: BASE64URL(SHA256(verifier)).
pub fn pkce_s256_challenge(verifier: &str) -> String {
    b64u(&sha256_of(verifier.as_bytes()))
}

/// SHA-256 hex (for storing token hashes, never the tokens).
pub fn sha256_hex(s: &str) -> String {
    hex::encode(sha256_of(s.as_bytes()))
}

#[cfg(test)]
mod es256k_tests {
    use super::*;

    #[test]
    fn es256k_jwt_roundtrip() {
        // Fixed k256 key (test only).
        let priv_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let pub_hex = k256_pub_from_priv(priv_hex).unwrap();
        let claims = serde_json::json!({"iss": "did:plc:test", "aud": "did:web:example.com#service", "lxm": "com.atproto.sync.getRepo"});
        let tok = sign_jwt_es256k(priv_hex, &claims).unwrap();
        let back = verify_jwt_es256k(&tok, &pub_hex).unwrap();
        assert_eq!(back["lxm"], serde_json::Value::String("com.atproto.sync.getRepo".into()));
        assert!(verify_jwt_es256k(&tok, &pub_hex.replace('0', "1")).is_err());
    }
}
