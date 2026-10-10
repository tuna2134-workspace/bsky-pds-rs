#!/usr/bin/env python3
"""Scheduled PLC-audit E2E for bsky-pds-rs (stdlib only).

Spins a stub PLC directory, signs a user up through the PDS, triggers the
cron handler via wrangler's `--test-scheduled` hook (`POST /__scheduled`),
and checks `/metrics` for the audit outcome. Then it tampers the served
audit log (forged trailing op) and confirms the failure is recorded —
without any account being auto-touched.

Prereqs: dev server with PDS_DID_PLC_URL=http://127.0.0.1:8897 and
`wrangler dev --test-scheduled`.

Usage: python3 scripts/e2e_audit.py [pds_base] [tag]
"""
import base64
import hashlib
import json
import os
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8788"
TAG = sys.argv[2] if len(sys.argv) > 2 else "aud"
ADMIN = base64.b64encode(b"admin:change-me-admin").decode()
PLC = {}
TAMPER = {"on": False}

from atproto_crypto import b58dec, B58, K256_G, es256k_sign, b64u


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


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_repo import decompress as secp_decompress, ecdsa_verify as secp_verify


def did_key_pub(dk):
    assert dk.startswith("did:key:z")
    raw = b58dec(dk[len("did:key:z"):])
    assert raw[:2] == b"\xe7\x01" and len(raw) == 35
    return raw[2:]


EVIL_PRIV = 1
EVIL_Q = K256_G


def pt_add(a, b):
    from atproto_crypto import pt_add as _pa, K256_P
    return _pa(a, b, K256_P, 0)


def pt_mul(k, pt):
    from atproto_crypto import pt_mul as _pm, K256_P
    return _pm(k, pt, K256_P, 0)


def evil_sign(digest):
    return es256k_sign(digest, EVIL_PRIV, low_s=True)


def forged_op(prev_cid, rotation_did_key):
    unsigned = {"type": "plc_operation", "rotationKeys": [rotation_did_key],
                "verificationMethods": {"atproto": rotation_did_key},
                "alsoKnownAs": ["at://evil.example.com"],
                "services": {"atproto_pds": {"type": "AtprotoPersonalDataServer",
                                             "endpoint": "https://evil.example.com"}},
                "prev": prev_cid}
    digest = hashlib.sha256(enc(unsigned)).digest()
    sig = evil_sign(digest)
    return dict(unsigned, sig=b64u(sig))


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
                assert did == "did:plc:" + calc
                rots = op["rotationKeys"]
            else:
                assert op.get("prev") == PLC[did]["head"]
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
            entries = [{"did": did, "cid": PLC[did]["head"], "operation": op}]
            if TAMPER["on"]:
                evil = forged_op(PLC[did]["head"], op["rotationKeys"][0])
                entries.append({"did": did, "cid": op_cid(evil), "operation": evil})
            self._json(200, entries)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


def call(method, path, body=None, auth=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if auth:
        req.add_header("Authorization", auth)
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read()
            return r.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw[:200]}


def trigger_cron():
    req = urllib.request.Request(BASE + "/__scheduled?cron=*/30+*+*+*+*",
                                 data=b"", method="POST")
    try:
        with urllib.request.urlopen(req) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def metrics():
    with urllib.request.urlopen(BASE + "/metrics") as r:
        return json.loads(r.read())


def main():
    fails = []

    def check(name, cond, extra=""):
        print(("PASS " if cond else "FAIL ") + name, extra)
        if not cond:
            fails.append(name)

    H = f"{TAG}.example.com"
    st, acct = call("POST", "/xrpc/com.atproto.server.createAccount",
                    {"handle": H, "email": f"{TAG}@example.com",
                     "password": "s3cret-pw-long"}, auth="Basic " + ADMIN)
    check("PLC signup", st == 200, str(acct)[:80])
    did = acct["did"]

    st = trigger_cron()
    check("cron trigger accepted", st in (200, 201, 202, 404), f"http {st}")
    audit = None
    for _ in range(20):
        time.sleep(1)
        m = metrics()
        if isinstance(m.get("plc_audit"), dict):
            audit = m["plc_audit"]
            break
    check("audit recorded", isinstance(audit, dict) and audit.get("failures") == 0,
          str(audit)[:120])

    TAMPER["on"] = True
    trigger_cron()
    audit2 = None
    for _ in range(20):
        time.sleep(1)
        m = metrics()
        a = m.get("plc_audit")
        if isinstance(a, dict) and a != audit:
            audit2 = a
            break
    check("tamper detected", isinstance(audit2, dict) and audit2.get("failures", 0) >= 1,
          str(audit2)[:120])

    # account itself untouched (no auto-takedown)
    st, status = call("GET", f"/xrpc/com.atproto.sync.getRepoStatus?did={did}")
    check("no auto-takedown", st == 200 and status.get("active") is True, str(status)[:100])

    if fails:
        print("FAILURES:", fails)
        sys.exit(1)
    print("ALL AUDIT CHECKS PASSED")


if __name__ == "__main__":
    threading.Thread(target=lambda: HTTPServer(("127.0.0.1", 8897),
                                               StubPlc).serve_forever(), daemon=True).start()
    import time
    time.sleep(0.3)
    main()
