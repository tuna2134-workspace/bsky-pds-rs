//! Merkle Search Tree (repo v3), signed commits, CARv1 framing.
//! Specs: <https://atproto.com/specs/repository>, <https://atproto.com/specs/sync>
//!
//! Node layout mirrors the reference implementation
//! (`@atproto/repo` `mst/util.serializeNodeData`): `{l, e[]}` with `l`/`t`
//! always present (null when absent), prefix-compressed keys, DagCbor links.
//! Trees are rebuilt deterministically from the full key set (shape-identical
//! to incremental add/delete: level-partitioned, empty intermediates kept,
//! top trimmed).

use crate::cbor::{self, CborError, DagCbor};
use crate::cid::Cid;
use crate::keys::{self, KeyError};

#[derive(Debug, Clone)]
pub struct MstEntry {
    pub key: Vec<u8>,
    pub cid: Cid,
}

#[derive(Debug, Clone)]
pub struct BuiltNode {
    pub cid: Cid,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BuiltTree {
    pub root: Cid,
    pub nodes_preorder: Vec<BuiltNode>,
}

#[derive(Debug)]
pub enum MstError {
    Cbor(CborError),
    Key(KeyError),
    Invalid(String),
}

impl std::fmt::Display for MstError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MstError::Cbor(e) => write!(f, "mst cbor: {e}"),
            MstError::Key(e) => write!(f, "mst key: {e}"),
            MstError::Invalid(s) => write!(f, "mst invalid: {s}"),
        }
    }
}

impl From<CborError> for MstError {
    fn from(e: CborError) -> Self {
        MstError::Cbor(e)
    }
}

impl From<KeyError> for MstError {
    fn from(e: KeyError) -> Self {
        MstError::Key(e)
    }
}

/// Key depth: sha256(key), leading zero bits / 2 (fanout 4).
pub fn depth(key: &[u8]) -> u32 {
    crate::atproto::tid::mst_depth(key)
}

/// Build a deterministic MST from (key, record-cid) pairs.
pub fn build(entries: &[MstEntry]) -> Result<BuiltTree, MstError> {
    let mut sorted = entries.to_vec();
    sorted.sort_by(|a, b| a.key.cmp(&b.key));
    for w in sorted.windows(2) {
        if w[0].key.is_empty() || w[1].key.is_empty() {
            return Err(MstError::Invalid("empty mst key".into()));
        }
        if w[0].key == w[1].key {
            return Err(MstError::Invalid("duplicate mst key".into()));
        }
    }
    if sorted.is_empty() {
        let node = serialize_node(None)?;
        let cid = Cid::dag_cbor(&node);
        return Ok(BuiltTree {
            root: cid.clone(),
            nodes_preorder: vec![BuiltNode { cid, bytes: node }],
        });
    }
    let max_depth = sorted.iter().map(|e| depth(&e.key)).max().unwrap_or(0);
    let mut out = Vec::new();
    let root_cid = build_level(&sorted, max_depth, &mut out)?;
    // Pre-order: out was collected children-first; rebuild in parent-first order.
    out.reverse();
    let root = out
        .first()
        .map(|n: &BuiltNode| n.cid.clone())
        .ok_or_else(|| MstError::Invalid("empty build".into()))?;
    assert_eq!(root, root_cid);
    Ok(BuiltTree { root, nodes_preorder: out })
}

enum Item<'a> {
    Leaf(&'a MstEntry),
    Tree(Cid),
}

/// Recursive level build. Returns node CID; pushes node + descendants
/// (children-first; caller reverses for pre-order).
fn build_level(entries: &[MstEntry], level: u32, out: &mut Vec<BuiltNode>) -> Result<Cid, MstError> {
    // Partition into leaves-at-this-level and gaps (keys with depth < level).
    let mut items: Vec<Item> = Vec::new();
    let mut gap: Vec<&MstEntry> = Vec::new();
    let mut leading_gap: Vec<&MstEntry> = Vec::new();
    let mut seen_leaf = false;

    let flush_gap = |gap: &mut Vec<&MstEntry>, items: &mut Vec<Item>, level: u32, out: &mut Vec<BuiltNode>| -> Result<(), MstError> {
        if gap.is_empty() {
            return Ok(());
        }
        let owned: Vec<MstEntry> = gap.drain(..).map(|e| (*e).clone()).collect();
        let child = build_level(&owned, level.checked_sub(1).ok_or_else(|| MstError::Invalid("level underflow".into()))?, out)?;
        items.push(Item::Tree(child));
        Ok(())
    };

    for e in entries {
        let d = depth(&e.key);
        if d > level {
            return Err(MstError::Invalid("key depth above build level".into()));
        }
        if d == level {
            if !seen_leaf {
                flush_gap(&mut leading_gap, &mut items, level, out)?;
                seen_leaf = true;
            } else {
                // gap between previous leaf and this one attaches after prev leaf:
                // it's currently in `gap`; flush as tree right after prev leaf,
                // i.e. just push before this leaf.
                flush_gap(&mut gap, &mut items, level, out)?;
            }
            items.push(Item::Leaf(e));
        } else if !seen_leaf {
            leading_gap.push(e);
        } else {
            gap.push(e);
        }
    }
    if !seen_leaf {
        // No leaves at this level.
        if entries.is_empty() {
            let node = serialize_node(None)?;
            let cid = Cid::dag_cbor(&node);
            out.push(BuiltNode { cid: cid.clone(), bytes: node });
            return Ok(cid);
        }
        // Empty intermediate node: single left link down one level.
        let owned: Vec<MstEntry> = entries.iter().cloned().collect();
        let child = build_level(
            &owned,
            level.checked_sub(1).ok_or_else(|| MstError::Invalid("level underflow".into()))?,
            out,
        )?;
        let node = serialize_node(Some(&child))?;
        let cid = Cid::dag_cbor(&node);
        out.push(BuiltNode { cid: cid.clone(), bytes: node });
        return Ok(cid);
    }
    // Trailing gap attaches after the last leaf.
    flush_gap(&mut gap, &mut items, level, out)?;

    // Serialize: first item tree => left link; leaves with right links.
    let mut left: Option<Cid> = None;
    let mut idx = 0;
    if matches!(items.first(), Some(Item::Tree(_))) {
        if let Some(Item::Tree(c)) = items.first() {
            left = Some(c.clone());
        }
        idx = 1;
    }
    let mut leaves: Vec<(&MstEntry, Option<Cid>)> = Vec::new();
    while idx < items.len() {
        match &items[idx] {
            Item::Leaf(e) => {
                let right = match items.get(idx + 1) {
                    Some(Item::Tree(c)) => {
                        idx += 1;
                        Some(c.clone())
                    }
                    _ => None,
                };
                leaves.push((e, right));
            }
            Item::Tree(_) => return Err(MstError::Invalid("adjacent subtrees".into())),
        }
        idx += 1;
    }
    let node = serialize_node_with(left.as_ref(), &leaves)?;
    let cid = Cid::dag_cbor(&node);
    out.push(BuiltNode { cid: cid.clone(), bytes: node });
    Ok(cid)
}

fn link_or_null(cid: Option<&Cid>) -> DagCbor {
    match cid {
        Some(c) => DagCbor::Link(c.clone()),
        None => DagCbor::Null,
    }
}

fn serialize_node(left: Option<&Cid>) -> Result<Vec<u8>, MstError> {
    Ok(cbor::encode(&DagCbor::Map(vec![
        (b"e".to_vec(), DagCbor::Array(vec![])),
        (b"l".to_vec(), link_or_null(left)),
    ])))
}

fn serialize_node_with(left: Option<&Cid>, leaves: &[(&MstEntry, Option<Cid>)]) -> Result<Vec<u8>, MstError> {
    let mut enc_entries = Vec::with_capacity(leaves.len());
    let mut prev_key: &[u8] = &[];
    for (e, right) in leaves {
        let p = common_prefix_len(prev_key, &e.key);
        prev_key = &e.key;
        enc_entries.push(DagCbor::Map(vec![
            (b"k".to_vec(), DagCbor::Bytes(e.key[p..].to_vec())),
            (b"p".to_vec(), DagCbor::Int(p as i64)),
            (b"t".to_vec(), link_or_null(right.as_ref())),
            (b"v".to_vec(), DagCbor::Link(e.cid.clone())),
        ]));
    }
    Ok(cbor::encode(&DagCbor::Map(vec![
        (b"e".to_vec(), DagCbor::Array(enc_entries)),
        (b"l".to_vec(), link_or_null(left)),
    ])))
}

fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
}

// ---------- node parsing / verification ----------

#[derive(Debug, Clone)]
pub struct ParsedEntry {
    pub key: Vec<u8>,
    pub value: Cid,
    pub right: Option<Cid>,
}

#[derive(Debug, Clone)]
pub struct ParsedNode {
    pub left: Option<Cid>,
    pub entries: Vec<ParsedEntry>,
}

pub fn parse_node(bytes: &[u8]) -> Result<ParsedNode, MstError> {
    let root = cbor::decode_exact(bytes)?;
    let DagCbor::Map(top) = root else {
        return Err(MstError::Invalid("node must be a map".into()));
    };
    let mut left: Option<Cid> = None;
    let mut entries_raw: Option<&Vec<DagCbor>> = None;
    for (k, v) in &top {
        match k.as_slice() {
            b"l" => match v {
                DagCbor::Null => {}
                DagCbor::Link(c) => {
                    if !c.is_dag_cbor() {
                        return Err(MstError::Invalid("bad link codec".into()));
                    }
                    left = Some(c.clone());
                }
                _ => return Err(MstError::Invalid("bad l".into())),
            },
            b"e" => match v {
                DagCbor::Array(a) => entries_raw = Some(a),
                _ => return Err(MstError::Invalid("bad e".into())),
            },
            _ => return Err(MstError::Invalid("unknown node field".into())),
        }
    }
    let entries_raw = entries_raw.ok_or_else(|| MstError::Invalid("missing e".into()))?;
    let mut entries = Vec::with_capacity(entries_raw.len());
    let mut prev_key: Vec<u8> = Vec::new();
    for item in entries_raw {
        let DagCbor::Map(fields) = item else {
            return Err(MstError::Invalid("entry must be a map".into()));
        };
        let (mut p, mut k, mut v, mut t) = (None, None, None, None);
        for (fk, fv) in fields {
            match fk.as_slice() {
                b"p" => match fv {
                    DagCbor::Int(n) => p = Some(*n),
                    _ => return Err(MstError::Invalid("bad p".into())),
                },
                b"k" => match fv {
                    DagCbor::Bytes(b) => k = Some(b.clone()),
                    _ => return Err(MstError::Invalid("bad k".into())),
                },
                b"v" => match fv {
                    DagCbor::Link(c) => v = Some(c.clone()),
                    _ => return Err(MstError::Invalid("bad v".into())),
                },
                b"t" => match fv {
                    DagCbor::Null => t = Some(None),
                    DagCbor::Link(c) => t = Some(Some(c.clone())),
                    _ => return Err(MstError::Invalid("bad t".into())),
                },
                _ => return Err(MstError::Invalid("unknown entry field".into())),
            }
        }
        let (p, k, v, t) = (p, k, v, t);
        match (p, k, v, t) {
            (Some(p), Some(k), Some(v), Some(t)) => {
                if p < 0 || (p as usize) > prev_key.len() {
                    return Err(MstError::Invalid("bad prefix len".into()));
                }
                let mut full = prev_key[..p as usize].to_vec();
                full.extend_from_slice(&k);
                if !entries.is_empty() && full <= prev_key {
                    return Err(MstError::Invalid("keys out of order".into()));
                }
                prev_key = full.clone();
                entries.push(ParsedEntry { key: full, value: v, right: t });
            }
            _ => return Err(MstError::Invalid("incomplete entry".into())),
        }
    }
    Ok(ParsedNode { left, entries })
}

// ---------- commits ----------

/// Unsigned commit bytes (all fields except `sig`), repo format v3.
pub fn unsigned_commit_bytes(did: &str, rev: &str, data: &Cid) -> Vec<u8> {
    cbor::encode(&DagCbor::Map(vec![
        (b"did".to_vec(), DagCbor::Text(did.to_string())),
        (b"version".to_vec(), DagCbor::Int(3)),
        (b"data".to_vec(), DagCbor::Link(data.clone())),
        (b"rev".to_vec(), DagCbor::Text(rev.to_string())),
        (b"prev".to_vec(), DagCbor::Null),
    ]))
}

/// Sign a commit. Returns (signed_commit_bytes, commit_cid).
pub fn sign_commit(priv_hex: &str, did: &str, rev: &str, data: &Cid) -> Result<(Vec<u8>, Cid), MstError> {
    let unsigned = unsigned_commit_bytes(did, rev, data);
    let digest = keys::sha256_of(&unsigned);
    let sig = keys::sign_digest_k256(priv_hex, &digest)?;
    let signed = cbor::encode(&DagCbor::Map(vec![
        (b"did".to_vec(), DagCbor::Text(did.to_string())),
        (b"version".to_vec(), DagCbor::Int(3)),
        (b"data".to_vec(), DagCbor::Link(data.clone())),
        (b"rev".to_vec(), DagCbor::Text(rev.to_string())),
        (b"prev".to_vec(), DagCbor::Null),
        (b"sig".to_vec(), DagCbor::Bytes(sig.to_vec())),
    ]));
    let cid = Cid::dag_cbor(&signed);
    Ok((signed, cid))
}

#[derive(Debug, Clone)]
pub struct ParsedCommit {
    pub did: String,
    pub rev: String,
    pub data: Cid,
    pub sig: Vec<u8>,
}

pub fn parse_commit(bytes: &[u8]) -> Result<ParsedCommit, MstError> {
    let root = cbor::decode_exact(bytes)?;
    let DagCbor::Map(top) = root else {
        return Err(MstError::Invalid("commit must be a map".into()));
    };
    let (mut did, mut rev, mut data, mut sig, mut version) = (None, None, None, None, None);
    for (k, v) in &top {
        match k.as_slice() {
            b"did" => match v {
                DagCbor::Text(s) => did = Some(s.clone()),
                _ => return Err(MstError::Invalid("bad did".into())),
            },
            b"rev" => match v {
                DagCbor::Text(s) => rev = Some(s.clone()),
                _ => return Err(MstError::Invalid("bad rev".into())),
            },
            b"data" => match v {
                DagCbor::Link(c) => data = Some(c.clone()),
                _ => return Err(MstError::Invalid("bad data".into())),
            },
            b"sig" => match v {
                DagCbor::Bytes(b) => sig = Some(b.clone()),
                _ => return Err(MstError::Invalid("bad sig".into())),
            },
            b"prev" => match v {
                DagCbor::Null => {}
                _ => return Err(MstError::Invalid("prev must be null".into())),
            },
            b"version" => match v {
                DagCbor::Int(3) => version = Some(3),
                _ => return Err(MstError::Invalid("unsupported version".into())),
            },
            _ => return Err(MstError::Invalid("unknown commit field".into())),
        }
    }
    match (did, rev, data, sig, version) {
        (Some(did), Some(rev), Some(data), Some(sig), Some(_)) => Ok(ParsedCommit { did, rev, data, sig }),
        _ => Err(MstError::Invalid("incomplete commit".into())),
    }
}

/// Verify a signed commit against the account's compressed pubkey (hex).
pub fn verify_commit(pub_hex: &str, bytes: &[u8]) -> Result<ParsedCommit, MstError> {
    let commit = parse_commit(bytes)?;
    let unsigned = unsigned_commit_bytes(&commit.did, &commit.rev, &commit.data);
    let digest = keys::sha256_of(&unsigned);
    keys::verify_digest(pub_hex, &digest, &commit.sig).map_err(MstError::Key)?;
    // Defense: CID of the commit must be recomputed by callers from `bytes`.
    Ok(commit)
}

// ---------- CAR v1 ----------

fn leb128(mut n: u64) -> Vec<u8> {
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

fn read_leb128(bytes: &[u8]) -> Result<(u64, usize), MstError> {
    let mut n: u64 = 0;
    let mut shift = 0;
    for (i, b) in bytes.iter().enumerate() {
        if shift >= 64 {
            return Err(MstError::Invalid("leb128 overflow".into()));
        }
        n |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok((n, i + 1));
        }
    }
    Err(MstError::Invalid("truncated leb128".into()))
}

/// Build a CARv1 file: header + blocks. `blocks` should start with the commit
/// block; MST nodes pre-order then records is the recommended order.
pub fn build_car(root: &Cid, blocks: &[(Cid, Vec<u8>)]) -> Vec<u8> {
    let header = cbor::encode(&DagCbor::Map(vec![
        (
            b"roots".to_vec(),
            DagCbor::Array(vec![DagCbor::Link(root.clone())]),
        ),
        (b"version".to_vec(), DagCbor::Int(1)),
    ]));
    let mut out = Vec::new();
    out.extend_from_slice(&leb128(header.len() as u64));
    out.extend_from_slice(&header);
    for (cid, data) in blocks {
        out.extend_from_slice(&leb128((cid.bytes.len() + data.len()) as u64));
        out.extend_from_slice(&cid.bytes);
        out.extend_from_slice(data);
    }
    out
}

/// Parse + hash-verify a CARv1 file. Returns (roots, blocks).
pub fn parse_car(bytes: &[u8]) -> Result<(Vec<Cid>, Vec<(Cid, Vec<u8>)>), MstError> {
    let mut pos = 0;
    let take = |pos: &mut usize, n: usize| -> Result<Vec<u8>, MstError> {
        if *pos + n > bytes.len() {
            return Err(MstError::Invalid("truncated car".into()));
        }
        let v = bytes[*pos..*pos + n].to_vec();
        *pos += n;
        Ok(v)
    };
    let (hlen, n) = read_leb128(&bytes[pos..])?;
    pos += n;
    let header_bytes = take(&mut pos, hlen as usize)?;
    let header = cbor::decode_exact(&header_bytes)?;
    let DagCbor::Map(fields) = header else {
        return Err(MstError::Invalid("bad car header".into()));
    };
    let (mut roots, mut version) = (None, None);
    for (k, v) in &fields {
        match k.as_slice() {
            b"roots" => match v {
                DagCbor::Array(a) => {
                    let mut r = Vec::new();
                    for item in a {
                        match item {
                            DagCbor::Link(c) => r.push(c.clone()),
                            _ => return Err(MstError::Invalid("bad root".into())),
                        }
                    }
                    roots = Some(r);
                }
                _ => return Err(MstError::Invalid("bad roots".into())),
            },
            b"version" => match v {
                DagCbor::Int(1) => version = Some(1),
                _ => return Err(MstError::Invalid("bad car version".into())),
            },
            _ => return Err(MstError::Invalid("unknown header field".into())),
        }
    }
    let (roots, version) = (roots, version);
    match (roots, version) {
        (Some(roots), Some(_)) => {
            if roots.is_empty() {
                return Err(MstError::Invalid("no roots".into()));
            }
            let mut blocks = Vec::new();
            while pos < bytes.len() {
                let (blen, n) = read_leb128(&bytes[pos..])?;
                pos += n;
                let block = take(&mut pos, blen as usize)?;
                // Split CID prefix: CID is self-delimiting via multihash length.
                let raw = prefix_cid(&block)?;
                let cid = Cid::from_bytes(&raw).map_err(MstError::Cbor)?;
                let data = block[cid.bytes.len()..].to_vec();
                // Hash-verify.
                if Cid::dag_cbor(&data) != cid && Cid::raw(&data) != cid {
                    return Err(MstError::Invalid("block hash mismatch".into()));
                }
                blocks.push((cid, data));
            }
            Ok((roots, blocks))
        }
        _ => Err(MstError::Invalid("incomplete car header".into())),
    }
}

/// Extract the leading CID bytes from a CAR block (version+codec+multihash framing).
fn prefix_cid(block: &[u8]) -> Result<Vec<u8>, MstError> {
    if block.len() < 6 || block[0] != 0x01 {
        return Err(MstError::Invalid("bad block cid".into()));
    }
    // codec varint
    let mut pos = 1;
    loop {
        if pos >= block.len() {
            return Err(MstError::Invalid("truncated block cid".into()));
        }
        let b = block[pos];
        pos += 1;
        if b & 0x80 == 0 {
            break;
        }
    }
    // multihash: 0x12 0x20 + 32 bytes
    if block.len() < pos + 34 || block[pos] != 0x12 || block[pos + 1] != 0x20 {
        return Err(MstError::Invalid("only sha2-256 blocks supported".into()));
    }
    Ok(block[..pos + 34].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(key: &str, tag: &str) -> MstEntry {
        let cid = Cid::dag_cbor(format!("record:{key}:{tag}").as_bytes());
        MstEntry { key: key.as_bytes().to_vec(), cid }
    }

    #[test]
    fn empty_tree_shape() {
        let t = build(&[]).unwrap();
        assert_eq!(t.nodes_preorder.len(), 1);
        let node = parse_node(&t.nodes_preorder[0].bytes).unwrap();
        assert!(node.left.is_none() && node.entries.is_empty());
        assert_eq!(t.root, t.nodes_preorder[0].cid);
    }

    #[test]
    fn insertion_order_independent() {
        let keys = [
            "app.bsky.feed.post/3lrgja7t6uc24",
            "app.bsky.actor.profile/self",
            "app.bsky.feed.like/9adeb165882c",
            "app.bsky.graph.follow/454397e440ec",
            "app.bsky.feed.post/3lrgja7t6uc25",
        ];
        let base: Vec<MstEntry> = keys.iter().map(|k| entry(k, "v1")).collect();
        let root = build(&base).unwrap().root;
        let mut rev = base.clone();
        rev.reverse();
        assert_eq!(build(&rev).unwrap().root, root);
        // And a different value changes the root.
        let mut diff = base.clone();
        diff[0] = entry(keys[0], "v2");
        assert_ne!(build(&diff).unwrap().root, root);
    }

    #[test]
    fn cross_language_root_vector() {
        // Same key set + record bytes as the independent Python implementation.
        // Byte-exact interop anchor: both must print the same root CID.
        let keys = [
            "app.bsky.feed.post/3lrgja7t6uc24",
            "app.bsky.actor.profile/self",
            "app.bsky.feed.like/9adeb165882c",
            "app.bsky.graph.follow/454397e440ec",
            "app.bsky.feed.post/3lrgja7t6uc25",
        ];
        let entries: Vec<MstEntry> = keys.iter().map(|k| entry(k, "v1")).collect();
        let tree = build(&entries).unwrap();
        assert_eq!(
            tree.root.to_string(),
            "bafyreiencqzo2owznbniw6u4led7nbyag54h2xqbzim4kajvre37fucwvy"
        );
    }

    #[test]
    fn depths_match_spec_vectors() {
        // From atproto-interop-tests/mst/key_heights.json.
        assert_eq!(depth(b"asdf"), 0);
        assert_eq!(depth(b"blue"), 1);
        assert_eq!(depth(b"2653ae71"), 0);
        assert_eq!(depth(b"88bfafc7"), 2);
        assert_eq!(depth(b"2a92d355"), 4);
        assert_eq!(depth(b"884976f5"), 6);
        assert_eq!(depth(b"app.bsky.feed.post/454397e440ec"), 4);
        assert_eq!(depth(b"app.bsky.feed.post/9adeb165882c"), 8);
    }

    #[test]
    fn tree_lookup_all_keys() {
        // Build a 300-key tree; descend manually to find every key.
        let mut entries = Vec::new();
        for i in 0..300 {
            entries.push(entry(&format!("app.bsky.feed.post/{i:013}"), "v1"));
        }
        let tree = build(&entries).unwrap();
        let nodes: std::collections::HashMap<String, ParsedNode> = tree
            .nodes_preorder
            .iter()
            .map(|n| (n.cid.to_string(), parse_node(&n.bytes).unwrap()))
            .collect();
        assert_eq!(nodes.len(), tree.nodes_preorder.len());
        for e in &entries {
            let mut node = nodes.get(&tree.root.to_string()).unwrap();
            let mut found: Option<Cid> = None;
            loop {
                // Scan entries; track the child covering e.key.
                let mut child: Option<Cid> = node.left.clone();
                let mut done = false;
                for en in &node.entries {
                    if en.key == e.key {
                        found = Some(en.value.clone());
                        done = true;
                        break;
                    }
                    if en.key.as_slice() > e.key.as_slice() {
                        break;
                    }
                    child = en.right.clone();
                }
                if done || found.is_some() {
                    break;
                }
                match child {
                    Some(c) => {
                        node = nodes.get(&c.to_string()).expect("missing child node");
                    }
                    None => break,
                }
            }
            assert_eq!(found.as_ref(), Some(&e.cid), "key {:?}", String::from_utf8_lossy(&e.key));
        }
    }

    #[test]
    fn unsigned_commit_key_order() {
        // DRISL regression: keys sorted by (length, bytewise) regardless of
        // construction order -> did, rev, data, prev, version.
        // Independent Python reference produces the identical bytes.
        let data = Cid::from_bytes(&hex::decode("01711220aa".to_string() + &"aa".repeat(31)).unwrap()).unwrap();
        let u = unsigned_commit_bytes("did:plc:test", "223mxiaevlz62", &data);
        assert_eq!(
            hex::encode(&u),
            "a5636469646c6469643a706c633a74657374637265766d3232336d78696165766c7a36326464617461d82a582401711220aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa6470726576f66776657273696f6e03"
        );
    }

    #[test]
    fn commit_sign_verify_roundtrip() {
        let data = Cid::dag_cbor(b"fake-mst-root");
        let (bytes, cid) = sign_commit(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "did:plc:test",
            "223mxiaevlz62",
            &data,
        )
        .unwrap();
        assert_eq!(Cid::dag_cbor(&bytes), cid);
        let pub_hex = keys::k256_pub_from_priv(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let parsed = verify_commit(&pub_hex, &bytes).unwrap();
        assert_eq!(parsed.did, "did:plc:test");
        assert_eq!(parsed.data, data);
        // Tamper with rev -> fails.
        let mut tampered = bytes.clone();
        tampered[20] ^= 0xff;
        assert!(verify_commit(&pub_hex, &tampered).is_err());
    }

    #[test]
    fn car_roundtrip_and_tamper() {
        let data = Cid::dag_cbor(b"root");
        let (commit_bytes, commit_cid) = sign_commit(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "did:plc:test",
            "223mxiaevlz62",
            &data,
        )
        .unwrap();
        let rec = Cid::dag_cbor(b"record");
        let car = build_car(
            &commit_cid,
            &[(commit_cid.clone(), commit_bytes.clone()), (rec.clone(), b"record".to_vec())],
        );
        let (roots, blocks) = parse_car(&car).unwrap();
        assert_eq!(roots, vec![commit_cid]);
        assert_eq!(blocks.len(), 2);
        // Tamper with a byte inside the record block -> hash mismatch.
        let mut bad = car.clone();
        *bad.last_mut().unwrap() ^= 0xff;
        assert!(parse_car(&bad).is_err());
    }
}

// ---------- consumer-side diff verification (operation inversion) ----------

#[derive(Debug, Clone, PartialEq)]
pub enum OpAction {
    Create,
    Update,
    Delete,
}

#[derive(Debug, Clone)]
pub struct FirehoseOp {
    pub action: OpAction,
    pub path: Vec<u8>,
    pub cid: Option<Cid>,
    pub prev: Option<Cid>,
}

/// Parse `#commit` ops from their JSON form (`cid`/`prev` as `$link`).
pub fn parse_ops(ops: &[serde_json::Value]) -> Result<Vec<FirehoseOp>, MstError> {
    let bad = |m: &str| MstError::Invalid(m.into());
    let mut out = Vec::with_capacity(ops.len());
    if ops.len() > 200 {
        return Err(bad("too many ops"));
    }
    for op in ops {
        let action = match op.get("action").and_then(|v| v.as_str()) {
            Some("create") => OpAction::Create,
            Some("update") => OpAction::Update,
            Some("delete") => OpAction::Delete,
            _ => return Err(bad("bad op action")),
        };
        let path = op
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| bad("op missing path"))?
            .as_bytes()
            .to_vec();
        if path.is_empty() || path.len() > 1024 {
            return Err(bad("bad op path"));
        }
        let link = |name: &str| -> Result<Option<Cid>, MstError> {
            match op.get(name) {
                None | Some(serde_json::Value::Null) => Ok(None),
                Some(v) => {
                    let s = v
                        .get("$link")
                        .and_then(|l| l.as_str())
                        .ok_or_else(|| bad("op link must be $link"))?;
                    Cid::parse(s).map(Some).map_err(|_| bad("bad op cid"))
                }
            }
        };
        out.push(FirehoseOp { action, path, cid: link("cid")?, prev: link("prev")? });
    }
    Ok(out)
}

/// Verify a `#commit` CAR slice by operation inversion (spec §Repository Diffs):
/// rewind every op against the new tree and require the rebuilt root to equal
/// `prev_data`. With `prev_data == None` (genesis/resync boundary) only
/// internal consistency is checked.
///
/// Signature verification is intentionally separate (see `verify_commit`):
/// callers verify with the account's current key, refreshing identity first.
pub fn verify_commit_slice(
    car_bytes: &[u8],
    rev: &str,
    ops: &[FirehoseOp],
    prev_data: Option<&Cid>,
) -> Result<(), MstError> {
    let bad = |m: &str| MstError::Invalid(m.into());
    if car_bytes.len() > 2_000_000 {
        return Err(bad("slice exceeds 2MB"));
    }
    let (roots, blocks) = parse_car(car_bytes)?;
    let root = roots.into_iter().next().ok_or_else(|| bad("no roots"))?;
    let (commit_cid, commit_bytes) = blocks.first().cloned().ok_or_else(|| bad("no commit block"))?;
    if commit_cid != root {
        return Err(bad("first block must be the commit"));
    }
    let commit = parse_commit(&commit_bytes)?;
    if commit.rev != rev {
        return Err(bad("rev mismatch"));
    }
    // Index blocks; parse every node.
    let mut nodes: std::collections::HashMap<String, ParsedNode> = std::collections::HashMap::new();
    let mut records: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
    for (cid, bytes) in blocks.iter().skip(1) {
        if bytes.len() > 1_000_000 {
            return Err(bad("block too large"));
        }
        match parse_node(bytes) {
            Ok(node) => {
                nodes.insert(cid.to_string(), node);
            }
            Err(_) => {
                records.insert(cid.to_string(), bytes.clone());
            }
        }
    }
    // Walk the new tree to recover the full key set.
    let mut state: std::collections::BTreeMap<Vec<u8>, Cid> = std::collections::BTreeMap::new();
    let mut stack = vec![commit.data.clone()];
    let mut seen_nodes = std::collections::HashSet::new();
    while let Some(cid) = stack.pop() {
        if !seen_nodes.insert(cid.to_string()) {
            continue;
        }
        let node = nodes.get(&cid.to_string()).ok_or_else(|| bad("missing MST node"))?;
        if let Some(left) = &node.left {
            stack.push(left.clone());
        }
        for e in &node.entries {
            state.insert(e.key.clone(), e.value.clone());
            if let Some(right) = &e.right {
                stack.push(right.clone());
            }
        }
    }
    // Rewind each op (reverse application) and check record presence.
    // Reverse rules: create -> remove path (must hold op.cid);
    // update -> restore prev (current must hold op.cid); delete -> re-add prev.
    // update/delete without `prev` cannot be rewound: relay-tolerated, but
    // this strict verifier rejects (our producer always emits `prev`).
    for op in ops {
        match op.action {
            OpAction::Create => {
                let new_cid = op.cid.as_ref().ok_or_else(|| bad("create needs cid"))?;
                let bytes = records.get(&new_cid.to_string()).ok_or_else(|| bad("missing record block"))?;
                if Cid::dag_cbor(bytes) != *new_cid {
                    return Err(bad("record block mismatch"));
                }
                match state.remove(&op.path) {
                    Some(cur) if &cur == new_cid => {}
                    _ => return Err(bad("create rewind mismatch")),
                }
            }
            OpAction::Update => {
                let new_cid = op.cid.as_ref().ok_or_else(|| bad("update needs cid"))?;
                let prev = op.prev.as_ref().ok_or_else(|| bad("update prev required for inversion"))?;
                let bytes = records.get(&new_cid.to_string()).ok_or_else(|| bad("missing record block"))?;
                if Cid::dag_cbor(bytes) != *new_cid {
                    return Err(bad("record block mismatch"));
                }
                match state.get(&op.path) {
                    Some(cur) if cur == new_cid => {}
                    _ => return Err(bad("update rewind mismatch")),
                }
                state.insert(op.path.clone(), prev.clone());
            }
            OpAction::Delete => {
                let prev = op.prev.as_ref().ok_or_else(|| bad("delete prev required for inversion"))?;
                if state.insert(op.path.clone(), prev.clone()).is_some() {
                    return Err(bad("delete rewind mismatch"));
                }
            }
        }
    }
    if let Some(prev_data) = prev_data {
        let entries: Vec<MstEntry> = state
            .into_iter()
            .map(|(key, cid)| MstEntry { key, cid })
            .collect();
        let rebuilt = build(&entries)?;
        if rebuilt.root != *prev_data {
            return Err(bad("inversion root mismatch"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod inversion_tests {
    use super::*;

    fn rec_bytes(key: &str, tag: &str) -> (Cid, Vec<u8>) {
        let v = serde_json::json!({"$type": "app.bsky.feed.post", "text": tag, "k": key});
        let bytes = crate::cbor::encode_json(&v).unwrap();
        let cid = Cid::dag_cbor(&bytes);
        (cid, bytes)
    }

    fn build_tree(pairs: &[(&str, &str, &str)]) -> (BuiltTree, std::collections::HashMap<String, (Cid, Vec<u8>)>) {
        // (path, tag) with tag selecting record content; returns tree + record blocks.
        let mut entries = Vec::new();
        let mut recs = std::collections::HashMap::new();
        for (path, tag, _) in pairs {
            let (cid, bytes) = rec_bytes(path, tag);
            entries.push(MstEntry { key: path.as_bytes().to_vec(), cid: cid.clone() });
            recs.insert(path.to_string(), (cid, bytes));
        }
        (build(&entries).unwrap(), recs)
    }

    fn commit_for(did: &str, rev: &str, root: &Cid) -> (Vec<u8>, Cid) {
        sign_commit(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            did,
            rev,
            root,
        )
        .unwrap()
    }

    #[test]
    fn inversion_roundtrip_batch() {
        // Start: 3 records. Batch: create D, update B, delete C.
        let (old_tree, mut recs) = build_tree(&[
            ("app.bsky.feed.post/aaaa", "v1", ""),
            ("app.bsky.feed.post/bbbb", "v1", ""),
            ("app.bsky.feed.post/cccc", "v1", ""),
        ]);
        let (b_cid, _) = recs["app.bsky.feed.post/bbbb"].clone();
        let (c_cid, _) = recs["app.bsky.feed.post/cccc"].clone();
        let (d_cid, d_bytes) = rec_bytes("app.bsky.feed.post/dddd", "v1");
        let (b2_cid, b2_bytes) = rec_bytes("app.bsky.feed.post/bbbb", "v2");
        recs.insert("app.bsky.feed.post/dddd".into(), (d_cid.clone(), d_bytes.clone()));
        recs.insert("app.bsky.feed.post/bbbb".into(), (b2_cid.clone(), b2_bytes.clone()));

        let mut new_entries = vec![
            MstEntry { key: b"app.bsky.feed.post/aaaa".to_vec(), cid: recs["app.bsky.feed.post/aaaa"].0.clone() },
            MstEntry { key: b"app.bsky.feed.post/bbbb".to_vec(), cid: b2_cid.clone() },
            MstEntry { key: b"app.bsky.feed.post/dddd".to_vec(), cid: d_cid.clone() },
        ];
        new_entries.sort_by(|a, b| a.key.cmp(&b.key));
        let new_tree = build(&new_entries).unwrap();
        let (commit_bytes, commit_cid) = commit_for("did:plc:test", "rev2", &new_tree.root);

        // Slice: commit + ALL new nodes + changed records only.
        let mut blocks = vec![(commit_cid.clone(), commit_bytes.clone())];
        for n in &new_tree.nodes_preorder {
            blocks.push((n.cid.clone(), n.bytes.clone()));
        }
        blocks.push((d_cid.clone(), d_bytes.clone()));
        blocks.push((b2_cid.clone(), b2_bytes.clone()));
        let car = build_car(&commit_cid, &blocks);

        let ops = parse_ops(&[
            serde_json::json!({"action": "create", "path": "app.bsky.feed.post/dddd", "cid": {"$link": d_cid.to_string()}}),
            serde_json::json!({"action": "update", "path": "app.bsky.feed.post/bbbb", "cid": {"$link": b2_cid.to_string()}, "prev": {"$link": b_cid.to_string()}}),
            serde_json::json!({"action": "delete", "path": "app.bsky.feed.post/cccc", "prev": {"$link": c_cid.to_string()}}),
        ])
        .unwrap();
        verify_commit_slice(&car, "rev2", &ops, Some(&old_tree.root)).unwrap();
    }

    #[test]
    fn inversion_rejects_tampering() {
        let (old_tree, mut recs) = build_tree(&[
            ("app.bsky.feed.post/aaaa", "v1", ""),
            ("app.bsky.feed.post/bbbb", "v1", ""),
        ]);
        let (b_cid, _) = recs["app.bsky.feed.post/bbbb"].clone();
        let (b2_cid, b2_bytes) = rec_bytes("app.bsky.feed.post/bbbb", "v2");
        recs.insert("app.bsky.feed.post/bbbb".into(), (b2_cid.clone(), b2_bytes.clone()));
        let new_entries = vec![
            MstEntry { key: b"app.bsky.feed.post/aaaa".to_vec(), cid: recs["app.bsky.feed.post/aaaa"].0.clone() },
            MstEntry { key: b"app.bsky.feed.post/bbbb".to_vec(), cid: b2_cid.clone() },
        ];
        let new_tree = build(&new_entries).unwrap();
        let (commit_bytes, commit_cid) = commit_for("did:plc:test", "rev2", &new_tree.root);
        let mut blocks = vec![(commit_cid.clone(), commit_bytes.clone())];
        for n in &new_tree.nodes_preorder {
            blocks.push((n.cid.clone(), n.bytes.clone()));
        }
        blocks.push((b2_cid.clone(), b2_bytes.clone()));
        let car = build_car(&commit_cid, &blocks);
        let good_op = serde_json::json!({"action": "update", "path": "app.bsky.feed.post/bbbb", "cid": {"$link": b2_cid.to_string()}, "prev": {"$link": b_cid.to_string()}});
        let ops = parse_ops(&[good_op.clone()]).unwrap();
        verify_commit_slice(&car, "rev2", &ops, Some(&old_tree.root)).unwrap();

        // Wrong prev root.
        let other = build(&[MstEntry { key: b"x/y".to_vec(), cid: b2_cid.clone() }]).unwrap();
        assert!(verify_commit_slice(&car, "rev2", &ops, Some(&other.root)).is_err());
        // Wrong prev op CID.
        let bad_prev = serde_json::json!({"action": "update", "path": "app.bsky.feed.post/bbbb", "cid": {"$link": b2_cid.to_string()}, "prev": {"$link": b2_cid.to_string()}});
        let bad_ops = parse_ops(&[bad_prev]).unwrap();
        assert!(verify_commit_slice(&car, "rev2", &bad_ops, Some(&old_tree.root)).is_err());
        // Missing record block.
        let car_no_rec = build_car(&commit_cid, &[(commit_cid.clone(), commit_bytes.clone())]);
        assert!(verify_commit_slice(&car_no_rec, "rev2", &ops, Some(&old_tree.root)).is_err());
        // Resync boundary (no prev): internal consistency passes, chain unchecked.
        verify_commit_slice(&car, "rev2", &ops, None).unwrap();
    }
}
