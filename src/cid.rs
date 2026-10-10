//! Blessed CIDs: CIDv1 + dag-cbor/raw codec + sha2-256, base32 multibase.
//! Spec: <https://atproto.com/specs/data-model>

use base32::{Alphabet, decode as b32_decode, encode as b32_encode};

/// Multibase-base32 alphabet (RFC4648, no padding); CIDs render lowercase.
const B32: Alphabet = Alphabet::RFC4648 { padding: false };
use sha2::{Digest, Sha256};

/// Raw CID bytes (binary `0x01 <codec-varint> <multihash>`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cid {
    pub bytes: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub enum CidError {
    Invalid(String),
}

impl std::fmt::Display for CidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CidError::Invalid(s) => write!(f, "invalid cid: {s}"),
        }
    }
}

// Multicodecs used in atproto repos.
pub const CODEC_DAG_CBOR: u64 = 0x71;
pub const CODEC_RAW: u64 = 0x55;
// sha2-256 multihash prefix.
const MH_SHA2_256: [u8; 2] = [0x12, 0x20];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

fn varint(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            b |= 0x80;
        }
        out.push(b);
        if n == 0 {
            break;
        }
    }
    out
}

fn read_varint(bytes: &[u8]) -> Result<(u64, usize), CidError> {
    let mut n: u64 = 0;
    let mut shift = 0;
    for (i, b) in bytes.iter().enumerate() {
        if shift >= 64 {
            return Err(CidError::Invalid("varint overflow".into()));
        }
        n |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok((n, i + 1));
        }
    }
    Err(CidError::Invalid("truncated varint".into()))
}

impl Cid {
    /// CIDv1 dag-cbor sha2-256 (`bafyre…`).
    pub fn dag_cbor(data: &[u8]) -> Self {
        Self::with_codec(CODEC_DAG_CBOR, data)
    }

    /// CIDv1 raw sha2-256 (`bafkrei…`), used for blob references.
    pub fn raw(data: &[u8]) -> Self {
        Self::with_codec(CODEC_RAW, data)
    }

    fn with_codec(codec: u64, data: &[u8]) -> Self {
        let hash = sha256(data);
        let mut bytes = vec![0x01];
        bytes.extend_from_slice(&varint(codec));
        bytes.extend_from_slice(&MH_SHA2_256);
        bytes.extend_from_slice(&hash);
        Self { bytes }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::cbor::CborError> {
        Self::parse_bytes(bytes).map_err(|e| crate::cbor::CborError::Invalid(e))
    }

    fn parse_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 6 || bytes[0] != 0x01 {
            return Err("only CIDv1 supported".into());
        }
        let (codec, n1) = read_varint(&bytes[1..]).map_err(|e| e.to_string())?;
        if codec != CODEC_DAG_CBOR && codec != CODEC_RAW {
            return Err(format!("unsupported codec {codec:#x}"));
        }
        let rest = &bytes[1 + n1..];
        if rest.len() < 2 || rest[0] != 0x12 || rest[1] != 0x20 {
            return Err("only sha2-256 multihash supported".into());
        }
        if rest.len() != 34 {
            return Err("bad multihash length".into());
        }
        Ok(Self { bytes: bytes.to_vec() })
    }

    /// Parse `"b…"` base32 multibase CID string, enforcing blessed formats.
    pub fn parse(s: &str) -> Result<Self, String> {
        let body = s.strip_prefix('b').ok_or_else(|| "CID must use base32 multibase (b…)".to_string())?;
        if body.len() < 10 || body.len() > 128 {
            return Err("CID length out of range".into());
        }
        if !body.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')) {
            return Err("CID must be lowercase base32".to_string());
        }
        // base32 without padding; length must be valid (no stray bits).
        let bytes = b32_decode(B32, &body.to_uppercase())
            .ok_or_else(|| "base32 decode failed".to_string())?;
        Self::parse_bytes(&bytes)
    }

    pub fn codec(&self) -> Result<u64, String> {
        read_varint(&self.bytes[1..]).map(|(c, _)| c).map_err(|e| e.to_string())
    }

    pub fn is_dag_cbor(&self) -> bool {
        self.codec() == Ok(CODEC_DAG_CBOR)
    }
}

impl std::fmt::Display for Cid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Multibase base32, no padding, lowercase.
        let s = b32_encode(B32, &self.bytes).to_lowercase();
        write!(f, "b{s}")
    }
}

/// Compatibility shim used by sync/record code while migration completes.
pub fn is_plausible_cid(cid: &str) -> bool {
    Cid::parse(cid).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dag_cbor_cid_shape() {
        let c = Cid::dag_cbor(b"hello");
        let s = c.to_string();
        assert!(s.starts_with("bafyre"), "{s}");
        assert_eq!(Cid::parse(&s).unwrap(), c);
    }

    #[test]
    fn raw_cid_shape() {
        let c = Cid::raw(b"hello-blob");
        let s = c.to_string();
        assert!(s.starts_with("bafkrei"), "{s}");
        assert_eq!(Cid::parse(&s).unwrap(), c);
    }

    #[test]
    fn known_answer_hello() {
        // Independent known answers (Python hashlib + base32):
        // sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        let c = Cid::dag_cbor(b"hello");
        assert_eq!(
            c.to_string(),
            "bafyreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yegnrjhc4yeq"
        );
        let r = Cid::raw(b"hello-blob");
        assert_eq!(
            r.to_string(),
            "bafkreicxujlmmxnvv4mpricmpjbn6jwdaco5ae4b7ovk5r5ugl6dbvgi2a"
        );
    }

    #[test]
    fn rejects_non_blessed() {
        assert!(Cid::parse("").is_err());
        assert!(Cid::parse("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79o9T").is_err()); // v0
        assert!(Cid::parse("bafkreiINVALID!").is_err());
        // uppercase base32 must fail
        let c = Cid::dag_cbor(b"x").to_string().to_uppercase();
        assert!(Cid::parse(&c).is_err());
    }
}
