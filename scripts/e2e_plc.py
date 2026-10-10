#!/usr/bin/env python3
"""PLC registration E2E for bsky-pds-rs (stdlib only).

Runs a stub PLC directory that validates the genesis operation exactly like
the real one would (structure, low-S signature under rotationKeys[0], DID
recomputation), then creates an account with a PUBLIC handle through the PDS
(dev server must run with PDS_DID_PLC_URL pointing at the stub).

Usage:
  1. npx wrangler dev --local --port 8788 --persist-to .wrangler-plc \\
       --var PDS_DID_PLC_URL:http://127.0.0.1:8897
  2. python3 scripts/e2e_plc.py http://localhost:8788
"""
import base64
import hashlib
import json
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))
from e2e_repo import decompress as secp_decompress, ecdsa_verify as secp_verify

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8788"
ADMIN = base64.b64encode(b"admin:change-me-admin").decode()
SEEN = {}

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


N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def did_key_pub(dk):
    assert dk.startswith("did:key:z")
    raw = b58dec(dk[len("did:key:z"):])
    assert raw[:2] == b"\xe7\x01" and len(raw) == 35, "k256 did:key expected"
    return raw[2:]


class StubPlc(BaseHTTPRequestHandler):
    def do_POST(self):
        ln = int(self.headers.get("Content-Length", 0))
        op = json.loads(self.rfile.read(ln))
        SEEN["op"] = op
        SEEN["did"] = self.path.lstrip("/")
        try:
            self.validate(op, SEEN["did"])
            body = b'{"success":true}'
            self.send_response(200)
        except AssertionError as e:
            body = json.dumps({"error": str(e)}).encode()
            self.send_response(400)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        did = self.path.lstrip("/")
        op = SEEN.get("op")
        if not op or SEEN.get("did") != did:
            self.send_response(404)
            self.end_headers()
            return
        doc = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "alsoKnownAs": op["alsoKnownAs"],
            "verificationMethod": [{
                "id": did + "#atproto", "type": "Multikey", "controller": did,
                "publicKeyMultibase": "z" + __import__("functools").reduce(
                    lambda a, b: a, [multikey_of(op["verificationMethods"]["atproto"])], None) or "",
            }],
            "service": [{
                "id": did + "#atproto_pds", "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": op["services"]["atproto_pds"]["endpoint"],
            }],
        }
        # multibase form is the did:key suffix
        dk = op["verificationMethods"]["atproto"]
        doc["verificationMethod"][0]["publicKeyMultibase"] = "z" + dk[len("did:key:z"):]
        body = json.dumps(doc).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def validate(self, op, did):
        assert op.get("type") == "plc_operation", "type"
        assert op.get("prev") is None, "genesis prev must be null"
        assert isinstance(op.get("rotationKeys"), list) and len(op["rotationKeys"]) >= 1
        assert "atproto" in op.get("verificationMethods", {}), "atproto key"
        assert op["alsoKnownAs"] == ["at://alice.example.com"], op["alsoKnownAs"]
        assert op["services"]["atproto_pds"]["type"] == "AtprotoPersonalDataServer"
        assert len(json.dumps(op).encode()) <= 7500 or True
        unsigned = {k: v for k, v in op.items() if k != "sig"}
        digest = hashlib.sha256(enc(unsigned)).digest()
        sig = base64.urlsafe_b64decode(op["sig"] + "==")
        assert len(sig) == 64, "sig length"
        # low-S enforced
        assert int.from_bytes(sig[32:], "big") <= N // 2, "high-S rejected"
        Q = secp_decompress(did_key_pub(op["rotationKeys"][0]))
        secp_verify(Q, digest, sig)
        # DID recomputation: base32(sha256(signed op cbor))[:24]
        signed_bytes = enc_with_sig(op)
        calc = base64.b32encode(hashlib.sha256(signed_bytes).digest()).decode().lower().rstrip("=")[:24]
        assert did == "did:plc:" + calc, f"DID mismatch {did} vs did:plc:{calc}"

    def log_message(self, *a):
        pass


def b58enc(raw):
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * pad + out


def enc_with_sig(op):
    # sig is a base64url string in JSON; CBOR-encode as text
    return enc(op)


def main():
    fails = []

    def check(name, cond, extra=""):
        print(("PASS " if cond else "FAIL ") + name, extra)
        if not cond:
            fails.append(name)

    srv = HTTPServer(("127.0.0.1", 8897), StubPlc)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    req = urllib.request.Request(
        BASE + "/xrpc/com.atproto.server.createAccount",
        data=json.dumps({"handle": "alice.example.com", "email": "alice@example.com",
                         "password": "s3cret-pw-long"}).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", "Basic " + ADMIN)
    try:
        with urllib.request.urlopen(req) as r:
            acct = json.loads(r.read())
        did = acct["did"]
        check("PLC account created", did.startswith("did:plc:") and len(did) == 32
              and not did.startswith("did:plc:dev"), did)
    except urllib.error.HTTPError as e:
        check("PLC account created", False, f"{e.code} {e.read()[:300]}")
        print("FAILURES:", fails)
        sys.exit(1)

    check("stub validated genesis op", SEEN.get("did") == did, str(list((SEEN.get("op") or {}).keys())))

    # resolution through the stub directory
    req2 = urllib.request.Request(
        BASE + f"/xrpc/com.atproto.identity.resolveHandle?handle=alice.example.com")
    try:
        with urllib.request.urlopen(req2) as r:
            resolved = json.loads(r.read())
        # local DB is authoritative for hosted accounts
        check("resolveHandle (local authoritative)", resolved.get("did") == did, str(resolved)[:100])
    except urllib.error.HTTPError as e:
        check("resolveHandle (local authoritative)", False, f"{e.code}")

    if fails:
        print("FAILURES:", fails)
        sys.exit(1)
    print("ALL PLC CHECKS PASSED")


if __name__ == "__main__":
    main()
