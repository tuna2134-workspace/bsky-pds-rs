//! atproto signing keys: secp256k1 (k256, repo standard) + p256 verification.
//! Specs: <https://atproto.com/specs/cryptography>, <https://atproto.com/specs/did>
//!
//! Commits are signed over SHA-256(unsigned-commit-DAG-CBOR) with deterministic
//! RFC 6979 ECDSA (matches `@noble/curves` `sign(hash, priv)` on the TS side).

use k256::ecdsa::{signature::hazmat::PrehashVerifier, SigningKey as K256Signing, VerifyingKey as K256Verifying};
use sha2::{Digest, Sha256};

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
}
