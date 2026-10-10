//! Legacy CAR helpers. Canonical implementations live in
//! [`crate::mst`] (CAR framing), [`crate::cid`] (blessed CIDs) and
//! [`crate::cbor`] (DAG-CBOR). This module keeps the base64 helper and a
//! compatibility CID plausibility check.

use base64::{engine::general_purpose::STANDARD as B64, Engine};

/// Blessed CID check (spec /specs/data-model): CIDv1, dag-cbor/raw codec,
/// sha2-256, base32 multibase.
pub fn is_plausible_cid(cid: &str) -> bool {
    crate::cid::Cid::parse(cid).is_ok()
}

pub fn b64(data: &[u8]) -> String {
    B64.encode(data)
}
