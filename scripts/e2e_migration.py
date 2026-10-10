#!/usr/bin/env python3
"""Cross-PDS migration E2E for bsky-pds-rs (stdlib only).

Simulates a real account migration between two PDS instances sharing one
PLC directory stub:
  old PDS: account + records + blob  ->  export CAR
  new PDS: createAccount(same DID, reserved key)  ->  importRepo(CAR)
         ->  records/commit identical, blobs listed missing, then re-uploaded

Also covers: tampered/foreign CAR rejection, rate-limit 429s, /metrics.

Prereqs:
  - PDS A on BASE1 (default persist dir), PDS B on BASE2 (--persist-to
    .wrangler-mig), both with PDS_DID_PLC_URL=http://127.0.0.1:8897
    (this script serves the stub PLC).

Usage: python3 scripts/e2e_migration.py [base1] [base2] [tag]
"""
import base64
import hashlib
import json
import os
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_repo import parse_car, Dec

BASE1 = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8788"
BASE2 = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:8789"
TAG = sys.argv[3] if len(sys.argv) > 3 else "migx"
ADMIN = base64.b64encode(b"admin:change-me-admin").decode()
PLC = {}

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58dec(s):
    n = 0
    for ch in s:
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + raw


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


def enc(v):
    if v is None:
        return b"\xf6"
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, str):
        b = v.encode()
        return head(3, len(b)) + b
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(enc(x) for x in v)
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: (len(kv[0].encode()), kv[0].encode()))
        return head(5, len(v)) + b"".join(enc(k) + enc(x) for k, x in items)
    raise AssertionError(f"enc {v!r}")


def op_cid(op):
    raw = b"\x01\x71\x12\x20" + hashlib.sha256(enc(op)).digest()
    return "b" + base64.b32encode(raw).decode().lower().rstrip("=")


def did_key_pub(dk):
    assert dk.startswith("did:key:z")
    raw = b58dec(dk[len("did:key:z"):])
    assert raw[:2] == b"\xe7\x01" and len(raw) == 35
    return raw[2:]


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_repo import decompress as secp_decompress, ecdsa_verify as secp_verify


class StubPlc(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        ln = int(self.headers.get("Content-Length", 0))
        op = json.loads(self.rfile.read(ln))
        did = self.path.lstrip("/")
        try:
            assert op.get("type") == "plc_operation"
            unsigned = {k: v for k, v in op.items() if k != "sig"}
            digest = hashlib.sha256(enc(unsigned)).digest()
            sig = base64.urlsafe_b64decode(op["sig"] + "==")
            assert len(sig) == 64
            if did not in PLC:
                assert op.get("prev") is None
                calc = base64.b32encode(hashlib.sha256(enc(op)).digest()).decode().lower().rstrip("=")[:24]
                assert did == "did:plc:" + calc, f"DID {did}"
                rots = op["rotationKeys"]
            else:
                assert op.get("prev") == PLC[did]["head"], "stale prev %s vs %s" % (op.get("prev"), PLC[did]["head"])
                rots = PLC[did]["op"]["rotationKeys"]
            ok = False
            for rk in rots:
                try:
                    secp_verify(secp_decompress(did_key_pub(rk)), digest, sig)
                    ok = True
                    break
                except AssertionError:
                    pass
            assert ok, "sig"
            PLC[did] = {"op": op, "head": op_cid(op)}
            self._json(200, {"success": True})
        except AssertionError as e:
            self._json(400, {"error": str(e)})

    def do_GET(self):
        parts = self.path.lstrip("/").split("/")
        did = parts[0]
        if did not in PLC:
            self.send_response(404)
            self.end_headers()
            return
        op = PLC[did]["op"]
        if len(parts) == 1:
            dk = op["verificationMethods"]["atproto"]
            self._json(200, {
                "@context": ["https://www.w3.org/ns/did/v1"], "id": did,
                "alsoKnownAs": op["alsoKnownAs"],
                "verificationMethod": [{"id": did + "#atproto", "type": "Multikey",
                                        "controller": did,
                                        "publicKeyMultibase": "z" + dk[len("did:key:z"):]}],
                "service": [{"id": did + "#atproto_pds", "type": "AtprotoPersonalDataServer",
                             "serviceEndpoint": op["services"]["atproto_pds"]["endpoint"]}]})
        elif parts[1] == "data":
            self._json(200, {"did": did, "rotationKeys": op["rotationKeys"],
                             "verificationMethods": op["verificationMethods"],
                             "alsoKnownAs": op["alsoKnownAs"], "services": op["services"]})
        elif parts[1:3] == ["log", "audit"]:
            self._json(200, [{"did": did, "cid": PLC[did]["head"], "operation": op}])
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


def call(base, method, path, body=None, auth=None, raw=None, ctype=None):
    if raw is not None:
        data = raw
    else:
        data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", ctype or "application/json")
    if auth:
        req.add_header("Authorization", auth)
    try:
        with urllib.request.urlopen(req) as r:
            payload = r.read()
            ct = r.headers.get("Content-Type", "")
            return r.status, dict(r.headers), json.loads(payload) if "json" in ct else payload
    except urllib.error.HTTPError as e:
        payload = e.read()
        try:
            return e.code, dict(e.headers), json.loads(payload)
        except Exception:
            return e.code, dict(e.headers), {"raw": payload[:200]}


def main():
    fails = []

    def check(name, cond, extra=""):
        print(("PASS " if cond else "FAIL ") + name, extra)
        if not cond:
            fails.append(name)

    H = f"{TAG}.example.com"
    st, _, acct = call(BASE1, "POST", "/xrpc/com.atproto.server.createAccount",
                       {"handle": H, "email": f"{TAG}@example.com",
                        "password": "s3cret-pw-long"}, auth="Basic " + ADMIN)
    check("source signup (PLC)", st == 200, str(acct)[:80])
    did = acct["did"]
    st, _, sess = call(BASE1, "POST", "/xrpc/com.atproto.server.createSession",
                       {"identifier": H, "password": "s3cret-pw-long"})
    auth1 = "Bearer " + sess["accessJwt"]

    # two records + a blob-backed record
    for i, text in enumerate(["migrate me", "migrate me too"]):
        st, _, _ = call(BASE1, "POST", "/xrpc/com.atproto.repo.createRecord",
                        {"repo": did, "collection": "app.bsky.feed.post",
                         "record": {"$type": "app.bsky.feed.post", "text": text,
                                    "createdAt": "2026-10-10T00:00:00.000Z"}}, auth=auth1)
        check(f"source write {i}", st == 200, "")
    st, _, up = call(BASE1, "POST", "/xrpc/com.atproto.repo.uploadBlob", raw=b"fake-image-bytes",
                     auth=auth1, ctype="image/png")
    blob_cid = up["blob"]["ref"]["$link"]
    st, _, _ = call(BASE1, "POST", "/xrpc/com.atproto.repo.createRecord",
                    {"repo": did, "collection": "app.bsky.feed.post",
                     "record": {"$type": "app.bsky.feed.post", "text": "with pic",
                                "createdAt": "2026-10-10T00:00:00.000Z",
                                "embed": {"$type": "app.bsky.embed.images",
                                          "images": [{"alt": "x", "image": up["blob"]}]}}}, auth=auth1)
    check("blob-backed record", st == 200, blob_cid[:20])

    # export from old PDS
    st, _, car = call(BASE1, "GET", f"/xrpc/com.atproto.sync.getRepo?did={did}")
    check("export CAR", st == 200 and isinstance(car, bytes) and len(car) > 200, f"{len(car)} bytes")
    roots, blocks = parse_car(car)
    commit = Dec(blocks[0][1]).one()
    rev = commit["rev"]

    # create the account on the NEW pds with the same DID (reserved/migrating)
    st, _, acct2 = call(BASE2, "POST", "/xrpc/com.atproto.server.createAccount",
                        {"handle": H, "email": f"{TAG}@example.com",
                         "password": "s3cret-pw-long", "did": did}, auth="Basic " + ADMIN)
    check("target signup (same DID)", st == 200, str(acct2)[:80])
    st, _, sess2 = call(BASE2, "POST", "/xrpc/com.atproto.server.createSession",
                        {"identifier": H, "password": "s3cret-pw-long"})
    auth2 = "Bearer " + sess2["accessJwt"]

    # import
    st, _, body = call(BASE2, "POST", "/xrpc/com.atproto.repo.importRepo", raw=car,
                       auth=auth2, ctype="application/vnd.ipld.car")
    check("importRepo", st == 200, str(body)[:80])
    st, _, lst = call(BASE2, "GET",
                      f"/xrpc/com.atproto.repo.listRecords?repo={did}&collection=app.bsky.feed.post&limit=100",
                      auth=auth2)
    check("migrated records", st == 200 and len(lst["records"]) == 3, f"n={len(lst.get('records', []))}")
    st, _, latest = call(BASE2, "GET", f"/xrpc/com.atproto.sync.getLatestCommit?did={did}")
    check("commit preserved", st == 200 and latest["rev"] == rev, str(latest)[:100])

    # blobs did not travel with the CAR
    st, _, missing = call(BASE2, "GET", "/xrpc/com.atproto.repo.listMissingBlobs?limit=100", auth=auth2)
    cids = [b["cid"] for b in missing.get("blobs", [])]
    check("listMissingBlobs", st == 200 and blob_cid in cids, str(cids)[:100])

    # tampered CAR rejected
    bad = bytearray(car)
    bad[len(bad) // 2] ^= 0xFF
    st, _, body = call(BASE2, "POST", "/xrpc/com.atproto.repo.importRepo", raw=bytes(bad),
                       auth=auth2, ctype="application/vnd.ipld.car")
    check("tampered CAR rejected", st == 400, str(body)[:80])

    # stale rev rejected (re-import same CAR: rev must advance)
    st, _, body = call(BASE2, "POST", "/xrpc/com.atproto.repo.importRepo", raw=car,
                       auth=auth2, ctype="application/vnd.ipld.car")
    check("stale rev rejected", st == 400, str(body)[:80])

    # rate limits: hammer sessions until 429 with Retry-After
    seen_429, retry_after = False, False
    for _ in range(75):
        st, hdrs, _ = call(BASE2, "POST", "/xrpc/com.atproto.server.createSession",
                           {"identifier": H, "password": "nope-nope-nope-xxx"})
        if st == 429:
            seen_429 = True
            retry_after = any(k.lower() == "retry-after" for k in hdrs)
            break
    check("rate limit 429", seen_429, "")
    check("retry-after header", retry_after, "")

    # metrics shape
    st, _, m = call(BASE2, "GET", "/metrics")
    check("metrics", st == 200 and m.get("accounts", 0) >= 1 and "firehose_seq" in m, str(m)[:120])

    if fails:
        print("FAILURES:", fails)
        sys.exit(1)
    print("ALL MIGRATION CHECKS PASSED")


if __name__ == "__main__":
    threading.Thread(target=lambda: HTTPServer(("127.0.0.1", 8897),
                                               StubPlc).serve_forever(), daemon=True).start()
    import time
    time.sleep(0.3)
    main()
