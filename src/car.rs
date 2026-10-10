//! Minimal CAR v1 + blessed CID helpers.
//! Full MST/CAR diff + operation-inversion verification is on the roadmap
//! (see docs/ROADMAP.md). These helpers cover deterministic export ordering
//! and CID validation needed by sync endpoints today.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use sha2::{Digest, Sha256};

/// Blessed CID check (spec /specs/data-model): dag-cbor, sha2-256, base32.
/// We validate multibase prefix `b` + plausible length instead of full decoding
/// to stay dependency-light on Workers.
pub fn is_plausible_cid(cid: &str) -> bool {
    // e.g. bafyrei... / bafkrei... base32 lowercase, multibase 'b'
    cid.len() >= 10 && cid.starts_with('b') && cid.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Compute a deterministic pseudo-CID for a JSON record (dev/MVP path).
/// Production path must use DRISL CBOR + sha2-256 + dag-cbor multicodec.
/// Kept explicit so interop gaps are visible, not silent.
pub fn pseudo_cid_for_json(canonical_json: &str) -> String {
    let digest = Sha256::digest(canonical_json.as_bytes());
    // NOT a real CID — prefixed so it never collides with blessed CIDs.
    format!("dev{}", hex::encode(&digest[..12]))
}

/// CAR v1 header for a single root commit.
pub fn car_v1_header_bytes(commit_cid: &str) -> Vec<u8> {
    // Minimal JSON-ish diagnostic; real CAR is CBOR-framed blocks.
    // Kept behind this helper so the binary upgrade is a single function.
    let header = serde_json::json!({ "version": 1, "roots": [commit_cid] });
    let bytes = serde_json::to_vec(&header).unwrap();
    let mut out = Vec::with_capacity(bytes.len() + 8);
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(&bytes);
    out
}

pub fn b64(data: &[u8]) -> String {
    B64.encode(data)
}
