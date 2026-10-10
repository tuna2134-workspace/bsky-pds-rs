#!/usr/bin/env python3
"""Service-proxy E2E for bsky-pds-rs (stdlib only).

Spins up a stub "AppView" on 127.0.0.1 with a did:web DID document, then
asks the PDS to proxy an XRPC call to it via `atproto-proxy`. The stub
verifies the inter-service JWT (ES256K, iss/aud/lxm/expiry) against the
user's repo signing key from describeRepo, proving end-to-end
authenticated proxying.

Usage: python3 scripts/e2e_proxy.py [pds_base] [handle]
"""
import base64
import hashlib
import json
import os
import sys
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_repo import decompress as secp_decompress, ecdsa_verify as secp_verify

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8787"
HANDLE = sys.argv[2] if len(sys.argv) > 2 else "karl.localhost"
ADMIN = base64.b64encode(b"admin:change-me-admin").decode()
STUB_PORT = 8898
STUB_DID = "did:web:127.0.0.1%3A8898"
PROXY_VALUE = STUB_DID + "#test_view"

STUB_DOC = {
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": STUB_DID,
    "service": [{
        "id": STUB_DID + "#test_view",
        "type": "TestView",
        "serviceEndpoint": f"http://127.0.0.1:{STUB_PORT}",
    }],
}

SEEN = {}


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58dec(s):
    n = 0
    for ch in s:
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + raw


class StubHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/.well-known/did.json":
            body = json.dumps(STUB_DOC).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/xrpc/com.test.view.getData"):
            auth = self.headers.get("Authorization", "")
            SEEN["auth"] = auth
            SEEN["path"] = self.path
            SEEN["labelers"] = self.headers.get("atproto-accept-labelers")
            body = json.dumps({"ok": True, "echo": self.path}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *a):
        pass


def main():
    fails = []

    def check(name, cond, extra=""):
        print(("PASS " if cond else "FAIL ") + name, extra)
        if not cond:
            fails.append(name)

    srv = HTTPServer(("127.0.0.1", STUB_PORT), StubHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    # account (admin bypass, loopback handle -> dev DID)
    req = urllib.request.Request(
        BASE + "/xrpc/com.atproto.server.createAccount",
        data=json.dumps({"handle": HANDLE, "email": f"{HANDLE}@example.com",
                         "password": "s3cret-pw-long"}).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", "Basic " + ADMIN)
    try:
        with urllib.request.urlopen(req) as r:
            acct = json.loads(r.read())
        did = acct["did"]
        check("createAccount", True, did)
    except urllib.error.HTTPError as e:
        body = json.loads(e.read())
        if body.get("error") == "DuplicateAccount":
            req2 = urllib.request.Request(
                BASE + "/xrpc/com.atproto.server.createSession",
                data=json.dumps({"identifier": HANDLE, "password": "s3cret-pw-long"}).encode(),
                method="POST")
            req2.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req2) as r:
                sess = json.loads(r.read())
            did = sess["did"]
            check("createSession", True, did)
        else:
            check("createAccount", False, str(body))
            print("FAILURES:", fails)
            sys.exit(1)

    # user pubkey from describeRepo
    with urllib.request.urlopen(BASE + f"/xrpc/com.atproto.repo.describeRepo?repo={did}") as r:
        desc = json.loads(r.read())
    vm = desc["didDoc"]["verificationMethod"][0]
    raw = b58dec(vm["publicKeyMultibase"][1:])
    assert raw[:2] == b"\xe7\x01", "k256 multikey expected"
    Q = secp_decompress(raw[2:])
    check("user signing key available", True, vm["publicKeyMultibase"][:20])

    # fresh compat session for a token:
    req3 = urllib.request.Request(
        BASE + "/xrpc/com.atproto.server.createSession",
        data=json.dumps({"identifier": HANDLE, "password": "s3cret-pw-long"}).encode(),
        method="POST")
    req3.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req3) as r:
        sess = json.loads(r.read())
    token = sess["accessJwt"]

    # proxied call
    preq = urllib.request.Request(
        BASE + "/xrpc/com.test.view.getData?foo=bar", method="GET")
    preq.add_header("Authorization", "Bearer " + token)
    preq.add_header("atproto-proxy", PROXY_VALUE)
    preq.add_header("atproto-accept-labelers", "did:example:labeler")
    try:
        with urllib.request.urlopen(preq) as r:
            st, body = r.status, json.loads(r.read())
        check("proxied call", st == 200 and body.get("ok") is True, str(body)[:100])
    except urllib.error.HTTPError as e:
        check("proxied call", False, f"{e.code} {e.read()[:200]}")
        print("FAILURES:", fails)
        sys.exit(1)

    check("stub saw query + labelers",
          SEEN.get("path") == "/xrpc/com.test.view.getData?foo=bar"
          and SEEN.get("labelers") == "did:example:labeler", str(SEEN.get("path")))

    # verify inter-service JWT
    assert SEEN["auth"].startswith("Bearer "), SEEN["auth"][:40]
    jwt = SEEN["auth"][len("Bearer "):]
    h_b64, p_b64, s_b64 = jwt.split(".")
    header = json.loads(base64.urlsafe_b64decode(h_b64 + "=="))
    claims = json.loads(base64.urlsafe_b64decode(p_b64 + "=="))
    sig = base64.urlsafe_b64decode(s_b64 + "==")
    check("service JWT header", header.get("alg") == "ES256K", str(header))
    digest = hashlib.sha256(f"{h_b64}.{p_b64}".encode()).digest()
    try:
        secp_verify(Q, digest, sig)
        sig_ok = True
    except AssertionError as e:
        sig_ok, sig_err = False, str(e)
    check("service JWT signature (user key)", sig_ok, "" if sig_ok else sig_err)
    import time
    # aud is the BARE service DID (reference verifyJwt compares exact
    # equality with the service's own DID; the #fragment form is rejected).
    check("service JWT claims",
          claims.get("iss") == did
          and claims.get("aud") == STUB_DID
          and claims.get("lxm") == "com.test.view.getData"
          and claims.get("exp", 0) > time.time()
          and claims.get("jti"), str(claims)[:160])

    # unknown route without proxy header stays 404
    try:
        urllib.request.urlopen(BASE + "/xrpc/com.test.view.getData")
        check("no-proxy 404", False, "unexpected 200")
    except urllib.error.HTTPError as e:
        check("no-proxy 404", e.code == 404, str(e.code))

    if fails:
        print("FAILURES:", fails)
        sys.exit(1)
    print("ALL PROXY CHECKS PASSED")


if __name__ == "__main__":
    main()
