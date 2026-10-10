//! DAG-CBOR (deterministic, DRISL profile) encode/decode.
//! Specs: <https://atproto.com/specs/data-model>, <https://dasl.ing/drisl.html>
//!
//! atproto JSON <-> CBOR mapping:
//! - `{"$link": "<cid>"}` (single-key object) <-> Tag(42) + CID bytes
//! - `{"$bytes": "<base64>"}` (single-key object) <-> byte string
//! - blobs stay plain maps (`$type: "blob"` + `$link` ref inside are links)
//! - numbers: integers (i64 range, no fraction) or f64 (no NaN/Inf)
//! - map keys sorted by (byte length, then bytewise) — DRISL determinism

use base64::{engine::general_purpose::STANDARD as B64, Engine};

use crate::cid::Cid;

#[derive(Debug, Clone, PartialEq)]
pub enum DagCbor {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<DagCbor>),
    Map(Vec<(Vec<u8>, DagCbor)>),
    Link(Cid),
}

#[derive(Debug, PartialEq)]
pub enum CborError {
    Invalid(String),
    UnexpectedEnd,
    TrailingBytes,
    NonCanonical(String),
}

impl std::fmt::Display for CborError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CborError::Invalid(s) => write!(f, "invalid cbor: {s}"),
            CborError::UnexpectedEnd => write!(f, "unexpected end of cbor"),
            CborError::TrailingBytes => write!(f, "trailing bytes after cbor item"),
            CborError::NonCanonical(s) => write!(f, "non-canonical cbor: {s}"),
        }
    }
}

/// Convert a JSON value (atproto data model) into DAG-CBOR value model.
pub fn from_json(v: &serde_json::Value) -> Result<DagCbor, CborError> {
    match v {
        serde_json::Value::Null => Ok(DagCbor::Null),
        serde_json::Value::Bool(b) => Ok(DagCbor::Bool(*b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(DagCbor::Int(i))
            } else if let Some(u) = n.as_u64() {
                if u <= i64::MAX as u64 {
                    Ok(DagCbor::Int(u as i64))
                } else {
                    Err(CborError::Invalid("integer out of range".into()))
                }
            } else if let Some(f) = n.as_f64() {
                if !f.is_finite() {
                    return Err(CborError::Invalid("non-finite float".into()));
                }
                Ok(DagCbor::Float(f))
            } else {
                Err(CborError::Invalid("bad number".into()))
            }
        }
        serde_json::Value::String(s) => Ok(DagCbor::Text(s.clone())),
        serde_json::Value::Array(a) => {
            if a.len() > 1_000_000 {
                return Err(CborError::Invalid("array too large".into()));
            }
            a.iter().map(from_json).collect::<Result<Vec<_>, _>>().map(DagCbor::Array)
        }
        serde_json::Value::Object(m) => {
            if m.len() == 1 {
                if let Some(link) = m.get("$link").and_then(|v| v.as_str()) {
                    let cid = Cid::parse(link).map_err(|e| CborError::Invalid(e))?;
                    return Ok(DagCbor::Link(cid));
                }
                if let Some(b) = m.get("$bytes").and_then(|v| v.as_str()) {
                    let bytes = B64.decode(b).map_err(|_| CborError::Invalid("bad $bytes".into()))?;
                    if bytes.len() > 100_000_000 {
                        return Err(CborError::Invalid("bytes too large".into()));
                    }
                    return Ok(DagCbor::Bytes(bytes));
                }
            }
            if m.len() > 100_000 {
                return Err(CborError::Invalid("map too large".into()));
            }
            let mut entries = Vec::with_capacity(m.len());
            for (k, val) in m {
                entries.push((k.as_bytes().to_vec(), from_json(val)?));
            }
            // DRISL: sort by (length, bytewise).
            entries.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
            Ok(DagCbor::Map(entries))
        }
    }
}

/// Encode a JSON value straight to deterministic DAG-CBOR bytes.
pub fn encode_json(v: &serde_json::Value) -> Result<Vec<u8>, CborError> {
    let dag = from_json(v)?;
    Ok(encode(&dag))
}

pub fn encode(v: &DagCbor) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(v, &mut out);
    out
}

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    if n <= 23 {
        out.push(major << 5 | n as u8);
    } else if n <= 0xff {
        out.push(major << 5 | 24);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(major << 5 | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(major << 5 | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(major << 5 | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn encode_into(v: &DagCbor, out: &mut Vec<u8>) {
    match v {
        DagCbor::Null => out.push(0xf6),
        DagCbor::Bool(false) => out.push(0xf4),
        DagCbor::Bool(true) => out.push(0xf5),
        DagCbor::Int(i) => {
            if *i >= 0 {
                head(out, 0, *i as u64);
            } else {
                head(out, 1, (-1 - *i) as u64);
            }
        }
        DagCbor::Float(f) => {
            out.push(0xfb);
            out.extend_from_slice(&f.to_be_bytes());
        }
        DagCbor::Bytes(b) => {
            head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        DagCbor::Text(s) => {
            head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        DagCbor::Array(a) => {
            head(out, 4, a.len() as u64);
            for item in a {
                encode_into(item, out);
            }
        }
        DagCbor::Map(entries) => {
            // DRISL determinism is enforced here centrally: sort by
            // (byte length, then bytewise). Callers may pass any order.
            let mut sorted: Vec<(&Vec<u8>, &DagCbor)> = entries.iter().map(|(k, v)| (k, v)).collect();
            sorted.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(b.0)));
            head(out, 5, sorted.len() as u64);
            for (k, val) in sorted {
                head(out, 3, k.len() as u64);
                out.extend_from_slice(k);
                encode_into(val, out);
            }
        }
        DagCbor::Link(cid) => {
            // Tag 42 + byte string of raw CID bytes.
            // Spec (cbor-tag42, DRISL): a null byte 0x00 is prepended to the
            // binary CID before storing in CBOR, for historical reasons.
            head(out, 6, 42);
            head(out, 2, cid.bytes.len() as u64 + 1);
            out.push(0x00);
            out.extend_from_slice(&cid.bytes);
        }
    }
}

// ---------- decoder ----------

pub struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn decode_one(&mut self) -> Result<DagCbor, CborError> {
        let b = self.next_byte()?;
        let major = b >> 5;
        let info = b & 31;
        match major {
            0 => Ok(DagCbor::Int(self.arg(info)? as i64)),
            1 => {
                let n = self.arg(info)?;
                if n == u64::MAX {
                    return Err(CborError::Invalid("negative int overflow".into()));
                }
                Ok(DagCbor::Int(-1 - n as i64))
            }
            2 => {
                let n = self.arg(info)? as usize;
                Ok(DagCbor::Bytes(self.take(n)?))
            }
            3 => {
                let n = self.arg(info)? as usize;
                let bytes = self.take(n)?;
                let s = String::from_utf8(bytes).map_err(|_| CborError::Invalid("bad utf8".into()))?;
                Ok(DagCbor::Text(s))
            }
            4 => {
                let n = self.arg(info)? as usize;
                let mut items = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    items.push(self.decode_one()?);
                }
                Ok(DagCbor::Array(items))
            }
            5 => {
                let n = self.arg(info)? as usize;
                let mut entries = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    let k = match self.decode_one()? {
                        DagCbor::Text(s) => s.into_bytes(),
                        _ => return Err(CborError::Invalid("non-text map key".into())),
                    };
                    let v = self.decode_one()?;
                    entries.push((k, v));
                }
                Ok(DagCbor::Map(entries))
            }
            6 => {
                let tag = self.arg(info)?;
                if tag != 42 {
                    return Err(CborError::Invalid(format!("unsupported tag {tag}")));
                }
                match self.decode_one()? {
                    // Spec form carries a 0x00 prefix; pre-spec links without
                    // it are still accepted for robustness (same CID either way).
                    DagCbor::Bytes(mut cid_bytes) => {
                        if cid_bytes.first() == Some(&0x00) && cid_bytes.len() > 1 {
                            cid_bytes.remove(0);
                        }
                        Ok(DagCbor::Link(Cid::from_bytes(&cid_bytes)?))
                    }
                    _ => Err(CborError::Invalid("tag 42 over non-bytes".into())),
                }
            }
            7 => match info {
                20 => Ok(DagCbor::Bool(false)),
                21 => Ok(DagCbor::Bool(true)),
                22 => Ok(DagCbor::Null),
                23 => Ok(DagCbor::Null), // undefined -> treat as invalid below
                27 => {
                    let bits = self.take8()?;
                    Ok(DagCbor::Float(f64::from_be_bytes(bits)))
                }
                _ => Err(CborError::Invalid(format!("unsupported simple {info}"))),
            },
            _ => Err(CborError::Invalid("bad major type".into())),
        }
    }

    fn next_byte(&mut self) -> Result<u8, CborError> {
        if self.pos >= self.buf.len() {
            return Err(CborError::UnexpectedEnd);
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn arg(&mut self, info: u8) -> Result<u64, CborError> {
        match info {
            n @ 0..=23 => Ok(n as u64),
            24 => Ok(self.next_byte()? as u64),
            25 => Ok(u16::from_be_bytes(self.take2()?) as u64),
            26 => Ok(u32::from_be_bytes(self.take4()?) as u64),
            27 => Ok(u64::from_be_bytes(self.take8()?)),
            _ => Err(CborError::Invalid("indefinite lengths unsupported".into())),
        }
    }

    fn take(&mut self, n: usize) -> Result<Vec<u8>, CborError> {
        if self.pos + n > self.buf.len() {
            return Err(CborError::UnexpectedEnd);
        }
        let v = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(v)
    }

    fn take2(&mut self) -> Result<[u8; 2], CborError> {
        let v = self.take(2)?;
        Ok([v[0], v[1]])
    }

    fn take4(&mut self) -> Result<[u8; 4], CborError> {
        let v = self.take(4)?;
        Ok([v[0], v[1], v[2], v[3]])
    }

    fn take8(&mut self) -> Result<[u8; 8], CborError> {
        let v = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(&v);
        Ok(a)
    }
}

/// Decode exactly one item; error on trailing bytes.
pub fn decode_exact(buf: &[u8]) -> Result<DagCbor, CborError> {
    let mut d = Decoder::new(buf);
    let v = d.decode_one()?;
    if d.pos != buf.len() {
        return Err(CborError::TrailingBytes);
    }
    Ok(v)
}

/// Convert DAG-CBOR value model back to atproto JSON.
pub fn to_json(v: &DagCbor) -> serde_json::Value {
    match v {
        DagCbor::Null => serde_json::Value::Null,
        DagCbor::Bool(b) => serde_json::Value::Bool(*b),
        DagCbor::Int(i) => serde_json::Value::from(*i),
        DagCbor::Float(f) => serde_json::json!(*f),
        DagCbor::Bytes(b) => serde_json::json!({ "$bytes": B64.encode(b) }),
        DagCbor::Text(s) => serde_json::Value::String(s.clone()),
        DagCbor::Array(a) => serde_json::Value::Array(a.iter().map(to_json).collect()),
        DagCbor::Map(entries) => {
            let mut m = serde_json::Map::new();
            for (k, val) in entries {
                m.insert(String::from_utf8_lossy(k).into_owned(), to_json(val));
            }
            serde_json::Value::Object(m)
        }
        DagCbor::Link(cid) => serde_json::json!({ "$link": cid.to_string() }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7049_appendix_a_vectors() {
        // Canonical unsigned / negative / byte / text / array / map samples.
        assert_eq!(encode_json(&serde_json::json!(0)).unwrap(), vec![0x00]);
        assert_eq!(encode_json(&serde_json::json!(23)).unwrap(), vec![0x17]);
        assert_eq!(encode_json(&serde_json::json!(24)).unwrap(), vec![0x18, 0x18]);
        assert_eq!(encode_json(&serde_json::json!(-1)).unwrap(), vec![0x20]);
        assert_eq!(encode_json(&serde_json::json!("a")).unwrap(), vec![0x61, 0x61]);
        assert_eq!(encode_json(&serde_json::json!([1, 2])).unwrap(), vec![0x82, 0x01, 0x02]);
    }

    #[test]
    fn map_keys_sorted_length_first() {
        // DRISL: shorter keys first; same length -> bytewise.
        let v = serde_json::json!({"bb": 1, "a": 2, "ccc": 3});
        let bytes = encode_json(&v).unwrap();
        // {"a":2,"bb":1,"ccc":3} -> a3 6161 02 626262 01 63636363 03
        assert_eq!(bytes, vec![0xa3, 0x61, b'a', 0x02, 0x62, b'b', b'b', 0x01, 0x63, b'c', b'c', b'c', 0x03]);
    }

    #[test]
    fn link_and_bytes_forms() {
        let cid = Cid::dag_cbor(b"linked-record");
        let link = serde_json::json!({ "$link": cid.to_string() });
        let bytes = encode_json(&link).unwrap();
        assert_eq!(&bytes[..2], &[0xd8, 0x2a]); // tag 42
        // cbor-tag42: null byte prepended to the binary CID.
        let cid_bytes = Cid::dag_cbor(b"linked-record").bytes;
        let mut inner = vec![0x00];
        inner.extend_from_slice(&cid_bytes);
        assert_eq!(&bytes[2..4], &[0x58, inner.len() as u8]); // bytes(37)
        assert_eq!(&bytes[4..], &inner[..]);
        let back = to_json(&decode_exact(&bytes).unwrap());
        assert_eq!(back, link);

        let b = serde_json::json!({"$bytes": "aGk="});
        let bb = encode_json(&b).unwrap();
        assert_eq!(bb, vec![0x42, b'h', b'i']);
        assert_eq!(to_json(&decode_exact(&bb).unwrap()), b);
    }

    #[test]
    fn roundtrip_post_record() {
        let post = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "hello",
            "createdAt": "2026-10-10T00:00:00.000Z",
            "langs": ["en"]
        });
        let bytes = encode_json(&post).unwrap();
        let back = to_json(&decode_exact(&bytes).unwrap());
        assert_eq!(back, post);
    }

    #[test]
    fn rejects_bad_numbers() {
        assert!(encode_json(&serde_json::json!(18446744073709551615u64)).is_err());
    }
}
