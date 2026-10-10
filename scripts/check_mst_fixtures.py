#!/usr/bin/env python3
"""Cross-validate the MST algorithm against official interop fixtures.

Fetches firehose/commit-proof-fixtures.json and rebuilds every before/after
tree with an independent implementation of the same algorithm. All 12 must
match byte-for-byte (root CIDs).
"""
import sys, json, base64, hashlib, urllib.request


def sha256(b):
    return hashlib.sha256(b).digest()


def depth(key: bytes) -> int:
    h = sha256(key)
    zeros = 0
    for byte in h:
        lz = 8 - byte.bit_length() if byte else 8
        zeros += lz
        if byte:
            break
    return zeros // 2


def head(major, n):
    if n <= 23:
        return bytes([major << 5 | n])
    if n <= 0xFF:
        return bytes([major << 5 | 24, n])
    if n <= 0xFFFF:
        return bytes([major << 5 | 25]) + n.to_bytes(2, "big")
    if n <= 0xFFFFFFFF:
        return bytes([major << 5 | 26]) + n.to_bytes(4, "big")
    return bytes([major << 5 | 27]) + n.to_bytes(8, "big")


def bstr(b):
    return head(2, len(b)) + b


def tstr(s: bytes):
    return head(3, len(s)) + s


def arr(items):
    return head(4, len(items)) + b"".join(items)


def mmap(pairs):
    pairs = sorted(pairs, key=lambda kv: (len(kv[0]), kv[0]))
    return head(5, len(pairs)) + b"".join(tstr(k) + v for k, v in pairs)


def tag42(cid):
    # cbor-tag42 (DRISL): null byte prepended to the binary CID.
    return head(6, 42) + bstr(b"\x00" + cid)


def dag_cid(data: bytes) -> bytes:
    return b"\x01\x71\x12\x20" + sha256(data)


def cid_str(b):
    return "b" + base64.b32encode(b).decode().lower().rstrip("=")


def node_bytes(left, entries):
    es = []
    for (suf, p, v, t) in entries:
        es.append(mmap([(b"k", bstr(suf)), (b"p", head(0, p)),
                        (b"t", tag42(t) if t else b"\xf6"), (b"v", tag42(v))]))
    return mmap([(b"e", arr(es)), (b"l", tag42(left) if left else b"\xf6")])


def parse_cid(s):
    raw = base64.b32decode(s[1:].upper() + "=" * (-(len(s) - 1) % 8))
    assert raw[:4] == b"\x01\x71\x12\x20", s
    return raw


NODES = {}


def build_level(keys, level):
    items, gap, leading, seen = [], [], [], False

    def flush(g):
        if not g:
            return
        items.append(("tree", build_level(list(g), level - 1)))
        g.clear()

    for k, c in keys:
        d = depth(k)
        assert d <= level, (k, d, level)
        if d == level:
            flush(leading) if not seen else flush(gap)
            seen = True
            items.append(("leaf", k, c))
        elif not seen:
            leading.append((k, c))
        else:
            gap.append((k, c))
    if not seen:
        if not keys:
            nb = node_bytes(None, [])
            NODES[dag_cid(nb)] = nb
            return dag_cid(nb)
        child = build_level(list(keys), level - 1)
        nb = node_bytes(child, [])
        NODES[dag_cid(nb)] = nb
        return dag_cid(nb)
    flush(gap)
    left, idx = None, 0
    if items and items[0][0] == "tree":
        left = items[0][1]
        idx = 1
    leaves = []
    while idx < len(items):
        assert items[idx][0] == "leaf"
        _, k, c = items[idx]
        right = None
        if idx + 1 < len(items) and items[idx + 1][0] == "tree":
            right = items[idx + 1][1]
            idx += 1
        leaves.append((k, c, right))
        idx += 1
    prev, enc_entries = b"", []
    for k, c, t in leaves:
        p = 0
        for a, b in zip(prev, k):
            if a != b:
                break
            p += 1
        enc_entries.append((k[p:], p, c, t))
        prev = k
    nb = node_bytes(left, enc_entries)
    NODES[dag_cid(nb)] = nb
    return dag_cid(nb)


def main():
    with urllib.request.urlopen(
            "https://raw.githubusercontent.com/bluesky-social/atproto-interop-tests"
            "/main/firehose/commit-proof-fixtures.json", timeout=30) as r:
        fixtures = json.loads(r.read())
    ok = 0
    for fx in fixtures:
        leaf = parse_cid(fx["leafValue"])
        before = sorted([(k.encode(), leaf) for k in fx["keys"]])
        maxd = max(depth(k) for k, _ in before)
        NODES.clear()
        match = cid_str(build_level(before, maxd)) == fx["rootBeforeCommit"]
        ok += match
        print(("PASS " if match else "FAIL ") + fx["comment"])
        after_keys = [k for k in fx["keys"] if k not in fx["dels"]] + fx["adds"]
        after = sorted([(k.encode(), leaf) for k in after_keys])
        maxd2 = max(depth(k) for k, _ in after)
        NODES.clear()
        m2 = cid_str(build_level(after, maxd2)) == fx["rootAfterCommit"]
        ok += m2
        print(("PASS " if m2 else "FAIL ") + fx["comment"] + " (after)")
    print(f"{ok}/12 matched")
    sys.exit(0 if ok == 12 else 1)


if __name__ == "__main__":
    main()
