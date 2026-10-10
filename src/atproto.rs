//! atproto primitives: NSID / TID / DID / handle / record-key / AT-URI.
//! Specs: /specs/nsid, /specs/tid, /specs/did, /specs/handle,
//!        /specs/record-key, /specs/at-uri-scheme

pub mod nsid {
    /// Validate NSID per spec: 1+ dot-separated labels, each [a-zA-Z0-9-],
    /// Spec: atproto.com/specs/nsid. Authority segments (all but last) are a
    /// reversed hostname: lowercase [a-z0-9-], no leading/trailing hyphen,
    /// TLD (first segment) must not start with a digit. Final name segment is
    /// camelCase: [A-Za-z0-9], no hyphens, must not start with a digit.
    pub fn validate(nsid: &str) -> bool {
        if nsid.is_empty() || nsid.len() > 317 {
            return false;
        }
        let parts: Vec<&str> = nsid.split('.').collect();
        if parts.len() < 3 {
            return false;
        }
        let (authority, name) = (&parts[..parts.len() - 1], parts[parts.len() - 1]);
        // Authority: at least 2 segments, <= 253 chars incl. dots.
        if authority.len() < 2 || authority.join(".").len() > 253 {
            return false;
        }
        for p in authority {
            if p.is_empty() || p.len() > 63 {
                return false;
            }
            if !p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
                return false;
            }
            if p.starts_with('-') || p.ends_with('-') {
                return false;
            }
        }
        if authority[0].as_bytes()[0].is_ascii_digit() {
            return false;
        }
        // Name segment.
        if name.is_empty() || name.len() > 63 {
            return false;
        }
        if !name.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return false;
        }
        if name.as_bytes()[0].is_ascii_digit() {
            return false;
        }
        true
    }
}

pub mod tid {
    use sha2::{Digest, Sha256};

    const ALPHABET: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";
    // TID = 64-bit unix micros, base32-sortable, 13 chars.
    pub fn now() -> String {
        let micros = js_micros();
        encode(micros)
    }

    pub fn encode(micros: u64) -> String {
        let mut v = micros;
        let mut out = [b'2'; 13];
        for i in (0..13).rev() {
            out[i] = ALPHABET[(v & 31) as usize];
            v >>= 5;
        }
        String::from_utf8(out.to_vec()).unwrap()
    }

    pub fn validate(tid: &str) -> bool {
        tid.len() == 13 && tid.bytes().all(|b| ALPHABET.contains(&b))
    }

    fn js_micros() -> u64 {
        // worker::Date::now() is millis since epoch.
        (worker::Date::now().as_millis() as u64) * 1000
    }

    /// MST depth rule uses SHA-256 of key, count leading zero bits / 2 (fanout 4).
    pub fn mst_depth(key: &[u8]) -> u32 {
        let h = Sha256::digest(key);
        let mut zeros = 0u32;
        for byte in h.iter() {
            if *byte == 0 {
                zeros += 8;
            } else {
                zeros += byte.leading_zeros();
                break;
            }
        }
        zeros / 2
    }
}

pub mod did {
    /// Generic DID syntax check (atproto): `did:[a-z]+:[...]`, <= 2048 chars.
    pub fn validate(did: &str) -> bool {
        if did.len() > 2048 || !did.starts_with("did:") {
            return false;
        }
        let rest = &did[4..];
        let Some(colon) = rest.find(':') else { return false };
        let (method, id) = rest.split_at(colon);
        if method.is_empty() || !method.bytes().all(|b| b.is_ascii_lowercase()) {
            return false;
        }
        let id = &id[1..];
        if id.is_empty() || id.ends_with(':') || id.ends_with('%') {
            return false;
        }
        if !id.bytes().all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b':' | b'%' | b'-')) {
            return false;
        }
        // blessed methods
        method == "plc" || method == "web"
    }

    pub fn is_plc(did: &str) -> bool {
        did.starts_with("did:plc:")
    }
}

pub mod handle {
    /// Simplified handle validation: DNS hostname, dot-separated, TLD alpha.
    pub fn validate(handle: &str) -> bool {
        if handle.is_empty() || handle.len() > 253 {
            return false;
        }
        let h = handle.strip_suffix('.').unwrap_or(handle);
        let parts: Vec<&str> = h.split('.').collect();
        if parts.len() < 2 {
            return false;
        }
        for p in &parts {
            if p.is_empty() || p.len() > 63 {
                return false;
            }
            if !p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                return false;
            }
            if p.starts_with('-') || p.ends_with('-') {
                return false;
            }
        }
        // TLD must contain a letter
        if let Some(tld) = parts.last() {
            if !tld.bytes().any(|b| b.is_ascii_alphabetic()) {
                return false;
            }
        }
        if handle != handle.to_lowercase() {
            // handles are case-insensitive but normalized lowercase
            return false;
        }
        true
    }
}

pub mod record_key {
    use super::tid;
    /// `self.` prefix, `literal:` prefix, or TID (or any [A-Za-z0-9._~:-], <=512).
    pub fn validate(rkey: &str) -> bool {
        if rkey.is_empty() || rkey.len() > 512 {
            return false;
        }
        if rkey == "." || rkey == ".." {
            return false;
        }
        if tid::validate(rkey) {
            return true;
        }
        rkey.bytes().all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'~' | b':' | b'-'))
    }

    pub fn repo_path(collection: &str, rkey: &str) -> Option<String> {
        if !super::nsid::validate(collection) || !validate(rkey) {
            return None;
        }
        Some(format!("{collection}/{rkey}"))
    }
}

pub mod at_uri {
    use super::{did, handle, nsid, record_key};

    /// Validate `at://did-or-handle[/collection[/rkey]]`.
    pub fn validate(uri: &str) -> bool {
        let Some(rest) = uri.strip_prefix("at://") else { return false };
        if rest.is_empty() || rest.len() > 2048 {
            return false;
        }
        let mut parts = rest.splitn(3, '/');
        let authority = parts.next().unwrap_or("");
        if !(did::validate(authority) || handle::validate(authority)) {
            return false;
        }
        if let Some(collection) = parts.next() {
            if !nsid::validate(collection) {
                return false;
            }
            if let Some(rkey) = parts.next() {
                if !record_key::validate(rkey) {
                    return false;
                }
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nsid_validation() {
        assert!(nsid::validate("com.atproto.server.createSession"));
        assert!(nsid::validate("app.bsky.feed.post"));
        assert!(!nsid::validate("com.atproto"));
        assert!(!nsid::validate("Com.Atproto.server.x"));
        assert!(!nsid::validate("com.atproto..x"));
    }

    #[test]
    fn tid_roundtrip() {
        let t = tid::encode(1_756_000_000_123_456);
        assert_eq!(t.len(), 13);
        assert!(tid::validate(&t));
        assert!(!tid::validate("short"));
        assert!(!tid::validate("0000000000000")); // '0','1' not in alphabet
    }

    #[test]
    fn did_validation() {
        assert!(did::validate("did:plc:ewvi7nxzyoun6zhxrhs64oiz"));
        assert!(did::validate("did:web:user.example.com"));
        assert!(!did::validate("did:key:zQ3shZc2QzApp2oymGvQbzP8eKheVshBHbU4ZYjeXqwSKEn6N"));
        assert!(!did::validate("did:METHOD:val"));
        assert!(!did::validate("did:method:"));
    }

    #[test]
    fn handle_validation() {
        assert!(handle::validate("user.example.com"));
        assert!(handle::validate("tuna2134.bsky.social"));
        assert!(!handle::validate("User.Example.com"));
        assert!(!handle::validate("localhost"));
        assert!(!handle::validate("a."));
    }

    #[test]
    fn record_key_and_path() {
        assert!(record_key::validate("3lrgja7t6uc24"));
        assert!(record_key::validate("self"));
        assert!(!record_key::validate("../evil"));
        assert!(record_key::repo_path("app.bsky.feed.post", "3lrgja7t6uc24").is_some());
        assert!(record_key::repo_path("bad", "3lrgja7t6uc24").is_none());
    }

    #[test]
    fn at_uri_validation() {
        assert!(at_uri::validate("at://did:plc:ewvi7nxzyoun6zhxrhs64oiz"));
        assert!(at_uri::validate("at://user.example.com/app.bsky.feed.post/3lrgja7t6uc24"));
        assert!(!at_uri::validate("https://example.com/x"));
    }

    #[test]
    fn mst_depth_stable() {
        // Known-answer: depth is deterministic per key.
        assert_eq!(tid::mst_depth(b"blue"), 1);
        let d0 = tid::mst_depth(b"2653ae71");
        assert_eq!(d0, 0);
    }
}
