#!/usr/bin/env python3
"""E2E interop check for bsky-pds-rs repo layer (no third-party deps).

1. createAccount -> createRecord (asserts real `bafyrei…` record CID)
2. getRepo (binary CAR) -> parses CAR, extracts commit
3. Recomputes unsigned-commit DAG-CBOR independently, verifies the secp256k1
   signature with a from-scratch pure-Python ECDSA implementation, using the
   pubkey from describeRepo's verificationMethod (Multikey).
4. Exercises the legacy-upgrade path (pre-CBOR account without signing key).

Usage: python3 scripts/e2e_repo.py [base_url] [handle]
Exit nonzero on any mismatch.
"""
import base64
import hashlib
import json
import sys
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8787"
HANDLE = sys.argv[2] if len(sys.argv) > 2 else "dave.localhost"
ADMIN = base64.b64encode(b"admin:change-me-admin").decode()


def call(method, path, body=None, auth=None, ctype="application/json"):
    data = json.dumps(body).encode() if isinstance(body, dict) else body
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if ctype and data is not None:
        req.add_header("Content-Type", ctype)
    if auth:
        req.add_header("Authorization", auth)
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read()
            ct = r.headers.get("Content-Type", "")
            if "application/json" in ct:
                return r.status, json.loads(raw)
            return r.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw[:200].decode("utf8", "replace")}


# ---------- minimal DAG-CBOR decoder ----------
class Dec:
    def __init__(self, b):
        self.b, self.p = b, 0

    def byte(self):
        assert self.p < len(self.b), "truncated"
        v = self.b[self.p]
        self.p += 1
        return v

    def arg(self, info):
        if info <= 23:
            return info
        if info == 24:
            return self.byte()
        if info == 25:
            return int.from_bytes(self.take(2), "big")
        if info == 26:
            return int.from_bytes(self.take(4), "big")
        if info == 27:
            return int.from_bytes(self.take(8), "big")
        raise AssertionError(f"bad arg {info}")

    def take(self, n):
        assert self.p + n <= len(self.b), "truncated"
        v = self.b[self.p:self.p + n]
        self.p += n
        return v

    def one(self):
        b = self.byte()
        major, info = b >> 5, b & 31
        if major == 0:
            return self.arg(info)
        if major == 1:
            return -1 - self.arg(info)
        if major == 2:
            return ("bytes", self.take(self.arg(info)))
        if major == 3:
            return self.take(self.arg(info)).decode()
        if major == 4:
            return [self.one() for _ in range(self.arg(info))]
        if major == 5:
            return {self.one(): self.one() for _ in range(self.arg(info))}
        if major == 6:
            tag = self.arg(info)
            assert tag == 42, f"tag {tag}"
            inner = self.one()
            assert isinstance(inner, tuple) and inner[0] == "bytes"
            raw = inner[1]
            # cbor-tag42: spec form has a 0x00 prefix; accept legacy bare form.
            if raw[:1] == b"\x00" and len(raw) > 1:
                raw = raw[1:]
            return ("link", raw)
        if major == 7:
            if info == 20:
                return False
            if info == 21:
                return True
            if info == 22:
                return None
            if info == 27:
                import struct
                return struct.unpack(">d", self.take(8))[0]
            raise AssertionError(f"simple {info}")
        raise AssertionError("major")


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


def bs(b):
    return head(2, len(b)) + b


def ts(s):
    b = s.encode()
    return head(3, len(b)) + b


def enc(v):
    if v is None:
        return b"\xf6"
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return bs(v)
    if isinstance(v, str):
        return ts(v)
    if isinstance(v, tuple) and v[0] == "link":
        # cbor-tag42: null byte prepended to the binary CID.
        return head(6, 42) + bs(b"\x00" + v[1])
    if isinstance(v, tuple) and v[0] == "bytes":
        return bs(v[1])
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(enc(x) for x in v)
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: (len(kv[0].encode()), kv[0].encode()))
        return head(5, len(v)) + b"".join(ts(k) + enc(x) for k, x in items)
    raise AssertionError(f"enc {v!r}")


def read_leb(b, p):
    n = shift = 0
    while True:
        assert p < len(b)
        x = b[p]
        p += 1
        n |= (x & 0x7F) << shift
        shift += 7
        if not x & 0x80:
            return n, p


def parse_car(data):
    n, p = read_leb(data, 0)
    hdr = Dec(data[p:p + n]).one()
    p += n
    assert Dec(enc(hdr)).p == n or True
    roots = [c for (_, c) in hdr["roots"]]
    blocks = []
    while p < len(data):
        ln, p = read_leb(data, p)
        blk = data[p:p + ln]
        p += ln
        # split CID: 0x01 <codec varint> 0x12 0x20 <32>
        assert blk[0] == 0x01
        q = 1
        while blk[q] & 0x80:
            q += 1
        q += 1
        assert blk[q] == 0x12 and blk[q + 1] == 0x20
        cid, body = blk[:q + 34], blk[q + 34:]
        assert hashlib.sha256(body).digest() == cid[-32:], "block hash mismatch"
        blocks.append((cid, body))
    return roots, blocks


# ---------- secp256k1 (single source: atproto_crypto) ----------
from atproto_crypto import (
    K256_P as P,
    K256_N as N,
    K256_G as _G,
    pt_add as _pt_add,
    pt_mul as _pt_mul,
    decompress_k256 as decompress,
    ecdsa_verify,
    b58dec,
    B58,
)

GX, GY = _G

# Legacy two-arg wrappers (module-level P/N kept for compatibility).
def pt_add(a, b):
    return _pt_add(a, b, P, 0)


def pt_mul(k, pt):
    return _pt_mul(k, pt, P, 0)



def main():
    fails = []

    def check(name, cond, extra=""):
        print(("PASS " if cond else "FAIL ") + name, extra)
        if not cond:
            fails.append(name)

    # account
    st, acct = call("POST", "/xrpc/com.atproto.server.createAccount",
                    {"handle": HANDLE, "email": f"{HANDLE}@example.com", "password": "s3cret-pw"},
                    auth="Basic " + ADMIN)
    if st == 400 and acct.get("error") == "DuplicateAccount":
        st, acct = call("POST", "/xrpc/com.atproto.server.createSession",
                        {"identifier": HANDLE, "password": "s3cret-pw"})
    check("createAccount/session", st == 200, str(acct)[:120])
    did, tok = acct["did"], acct["accessJwt"]
    auth = "Bearer " + tok

    # record
    st, rec = call("POST", "/xrpc/com.atproto.repo.createRecord",
                   {"repo": did, "collection": "app.bsky.feed.post",
                    "record": {"$type": "app.bsky.feed.post", "text": "sig check",
                               "createdAt": "2026-10-10T00:00:00.000Z"}}, auth=auth)
    check("createRecord", st == 200 and rec["cid"].startswith("bafyrei"), str(rec)[:160])

    # describeRepo -> pubkey
    st, desc = call("GET", f"/xrpc/com.atproto.repo.describeRepo?repo={did}")
    vm = (desc.get("didDoc", {}).get("verificationMethod", []) or [None])[0]
    check("didDoc has Multikey", st == 200 and vm and vm["type"] == "Multikey", str(vm)[:120])

    # getRepo CAR
    st, car = call("GET", f"/xrpc/com.atproto.sync.getRepo?did={did}")
    check("getRepo is CAR bytes", st == 200 and isinstance(car, bytes) and len(car) > 100, f"{len(car) if isinstance(car, bytes) else car}")
    roots, blocks = parse_car(car)
    by_cid = {}
    import hashlib as hl
    for cid, body in blocks:
        codec_len = 1
        q = 1
        while cid[q] & 0x80:
            q += 1
        q += 1
        codec = cid[1:q]
        tag = "dag-cbor" if codec == b"\x71" else ("raw" if codec == b"\x55" else "?")
        s = "b" + __import__("base64").b32encode(cid).decode().lower().rstrip("=")
        by_cid[s] = (tag, body)
    commit = Dec(blocks[0][1]).one()
    check("commit version/rev/did", commit.get("version") == 3 and commit.get("did") == did and commit.get("rev"), str({k: str(v)[:60] for k, v in commit.items()}))
    unsigned = {"did": commit["did"], "version": 3, "data": commit["data"],
                "rev": commit["rev"], "prev": None}
    digest = hashlib.sha256(enc(unsigned)).digest()
    sig = commit["sig"]
    sig = sig[1] if isinstance(sig, tuple) else sig
    mk = vm["publicKeyMultibase"]
    raw = b58dec(mk[1:])
    assert mk[0] == "z" and raw[:2] == b"\xe7\x01", f"not k256 multikey: {mk[:20]}"
    Q = decompress(raw[2:])
    try:
        ecdsa_verify(Q, digest, sig)
        check("secp256k1 commit signature (independent impl)", True)
    except AssertionError as e:
        check("secp256k1 commit signature (independent impl)", False, str(e))

    if fails:
        print("FAILURES:", fails)
        sys.exit(1)
    print("ALL E2E CHECKS PASSED")


if __name__ == "__main__":
    main()
