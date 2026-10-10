#!/usr/bin/env python3
"""Account-operations E2E for bsky-pds-rs (stdlib only).

Covers the lexicon-aligned account surface with stub PLC directory + stub
SMTP MTA. Prereqs: dev server on BASE with
  --var PDS_DID_PLC_URL:http://127.0.0.1:8897
  --var PDS_EMAIL_SMTP_URL:smtp://u:p@127.0.0.1:8825/
  --var PDS_EMAIL_FROM_ADDRESS:no-reply@localhost

Checks: reserveSigningKey adoption, app passwords (+privilege gating,
deleteSession epoch kill), getServiceAuth (ES256K verified), status,
email-update token flow, delete-by-token, invite consume+list, PLC
sign/submit handle change, resolve trio.
"""
import base64
import hashlib
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_repo import decompress as secp_decompress, ecdsa_verify as secp_verify

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8788"
TAG = sys.argv[2] if len(sys.argv) > 2 else "acct"
ADMIN = base64.b64encode(b"admin:change-me-admin").decode()
PLC = {}
MAILBOX = []

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
    # Real dag-cbor CID of the operation (as the PLC directory returns).
    raw = b"\x01\x71\x12\x20" + hashlib.sha256(enc(op)).digest()
    return "b" + base64.b32encode(raw).decode().lower().rstrip("=")


def did_key_pub(dk):
    assert dk.startswith("did:key:z")
    raw = b58dec(dk[len("did:key:z"):])
    assert raw[:2] == b"\xe7\x01" and len(raw) == 35
    return raw[2:]


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
            if op.get("type") != "plc_operation":
                raise AssertionError("type")
            unsigned = {k: v for k, v in op.items() if k != "sig"}
            digest = hashlib.sha256(enc(unsigned)).digest()
            sig = base64.urlsafe_b64decode(op["sig"] + "==")
            assert len(sig) == 64
            if did not in PLC:
                assert op.get("prev") is None, "genesis prev"
                calc = base64.b32encode(hashlib.sha256(enc(op)).digest()).decode().lower().rstrip("=")[:24]
                assert did == "did:plc:" + calc, f"DID {did} vs {calc}"
                rots = op["rotationKeys"]
            else:
                assert op.get("prev") == PLC[did]["head"], "stale prev"
                rots = PLC[did]["op"]["rotationKeys"]
            ok = False
            for rk in rots:
                try:
                    secp_verify(secp_decompress(did_key_pub(rk)), digest, sig)
                    ok = True
                    break
                except AssertionError:
                    pass
            assert ok, "no rotation key verifies"
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
            doc = {"@context": ["https://www.w3.org/ns/did/v1"], "id": did,
                   "alsoKnownAs": op["alsoKnownAs"],
                   "verificationMethod": [{"id": did + "#atproto", "type": "Multikey",
                                           "controller": did,
                                           "publicKeyMultibase": "z" + dk[len("did:key:z"):]}],
                   "service": [{"id": did + "#atproto_pds", "type": "AtprotoPersonalDataServer",
                                "serviceEndpoint": op["services"]["atproto_pds"]["endpoint"]}],
                   }
            self._json(200, doc)
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


def smtp_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 8825))
    srv.listen(10)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=smtp_conn, args=(conn,), daemon=True).start()


def smtp_conn(conn):
    f = conn.makefile("rwb")
    msg = {"body": []}

    def w(s):
        f.write(s.encode() + b"\r\n")
        f.flush()

    try:
        w("220 stub ESMTP")
        data = False
        while True:
            line = f.readline().decode().strip()
            if data:
                if line == ".":
                    data = False
                    MAILBOX.append(msg)
                    msg = {"body": []}
                    w("250 OK queued")
                else:
                    msg["body"].append(line)
                continue
            if not line:
                break
            cmd = line.split(" ")[0].upper()
            if cmd == "EHLO":
                w("250-Hello stub")
                w("250 8BITMIME")
            elif cmd in ("MAIL", "RCPT"):
                w("250 OK")
            elif cmd == "DATA":
                data = True
                w("354 End data")
            elif cmd == "QUIT":
                w("221 Bye")
                break
            else:
                w("502 no")
    except Exception:
        pass
    finally:
        conn.close()


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
            return e.code, {"raw": raw[:200].decode("utf8", "replace")}


def last_token():
    assert MAILBOX, "no mail"
    text = "\n".join(MAILBOX[-1]["body"])
    m = re.search(r"\n([A-Za-z0-9_-]{43})\n", "\n" + text + "\n")
    assert m, text[:200]
    return m.group(1)


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
    check("PLC signup", st == 200 and acct["did"].startswith("did:plc:")
          and len(acct["did"]) == 32, str(acct)[:100])
    did = acct["did"]
    st, sess = call("POST", "/xrpc/com.atproto.server.createSession",
                    {"identifier": H, "password": "s3cret-pw-long"})
    auth = "Bearer " + sess["accessJwt"]

    # reserveSigningKey + adoption
    resv_did = ("did:plc:rsv" + TAG + "00000000000000000000")[:32].lower()
    st, res = call("POST", "/xrpc/com.atproto.server.reserveSigningKey",
                   {"did": resv_did})
    check("reserveSigningKey", st == 200 and res["signingKey"].startswith("did:key:z"),
          str(res)[:80])
    st, acct2 = call("POST", "/xrpc/com.atproto.server.createAccount",
                     {"handle": f"mig-{TAG}.example.com", "email": f"mig-{TAG}@example.com",
                      "password": "s3cret-pw-long", "did": resv_did},
                     auth="Basic " + ADMIN)
    # NOTE: provided-DID path skips PLC submit (migration reservation).
    check("reserved-key adoption", st == 200, str(acct2)[:100])
    if st == 200:
        st, desc = call("GET", f"/xrpc/com.atproto.repo.describeRepo?repo={resv_did}")
        vm = desc["didDoc"]["verificationMethod"]
        import json as J
        check("adopted key in doc", vm and vm[0]["publicKeyMultibase"][1:] == res["signingKey"][len("did:key:z"):],
              str(vm)[:80])

    # app passwords
    st, ap = call("POST", "/xrpc/com.atproto.server.createAppPassword",
                  {"name": "laptop"}, auth=auth)
    check("createAppPassword", st == 200 and re.match(r"^....-....-....-....$", ap["password"]), str(ap)[:80])
    appw = ap["password"]
    st, lst = call("GET", "/xrpc/com.atproto.server.listAppPasswords", auth=auth)
    check("listAppPasswords", st == 200 and any(p["name"] == "laptop" for p in lst["passwords"]),
          str(lst)[:100])
    st, sess2 = call("POST", "/xrpc/com.atproto.server.createSession",
                     {"identifier": H, "password": appw})
    check("app-password login", st == 200, "")
    # unprivileged app password cannot manage the account
    st, body = call("POST", "/xrpc/com.atproto.server.deleteAccount",
                    {"did": did, "password": appw, "token": "x"},
                    auth="Bearer " + sess2["accessJwt"])
    check("app-password delete gated", st in (400, 403), f"{st} {str(body)[:60]}")
    # but it can write records
    st, rec = call("POST", "/xrpc/com.atproto.repo.createRecord",
                   {"repo": did, "collection": "app.bsky.feed.post",
                    "record": {"$type": "app.bsky.feed.post", "text": "via app pw",
                               "createdAt": "2026-10-10T00:00:00.000Z"}},
                   auth="Bearer " + sess2["accessJwt"])
    check("app-password write", st == 200, "")
    st, _ = call("POST", "/xrpc/com.atproto.server.revokeAppPassword",
                 {"name": "laptop"}, auth=auth)
    check("revokeAppPassword", st == 200, "")
    st, _ = call("POST", "/xrpc/com.atproto.server.createSession",
                 {"identifier": H, "password": appw})
    check("revoked login dead", st == 401, "")

    # deleteSession epoch kill
    st, sess3 = call("POST", "/xrpc/com.atproto.server.createSession",
                     {"identifier": H, "password": "s3cret-pw-long"})
    tok3 = sess3["accessJwt"]
    st, _ = call("POST", "/xrpc/com.atproto.server.deleteSession", {}, auth="Bearer " + tok3)
    check("deleteSession", st == 200, "")
    st, _ = call("GET", "/xrpc/com.atproto.server.getSession", auth="Bearer " + tok3)
    check("epoch kill", st == 401, "")
    st, sess = call("POST", "/xrpc/com.atproto.server.createSession",
                    {"identifier": H, "password": "s3cret-pw-long"})
    auth = "Bearer " + sess["accessJwt"]
    check("re-login after epoch bump", st == 200, "")

    # getServiceAuth verified locally
    aud = "did:web:example.com#test_service"
    st, sa = call("GET", f"/xrpc/com.atproto.server.getServiceAuth?aud={urllib.parse.quote(aud)}&lxm=com.atproto.sync.getRepo",
                  auth=auth)
    check("getServiceAuth", st == 200 and sa["token"].count(".") == 2, str(sa)[:80])
    st, desc = call("GET", f"/xrpc/com.atproto.repo.describeRepo?repo={did}")
    raw = b58dec(desc["didDoc"]["verificationMethod"][0]["publicKeyMultibase"][1:])
    Q = secp_decompress(raw[2:])
    h_b64, p_b64, s_b64 = sa["token"].split(".")
    header = json.loads(base64.urlsafe_b64decode(h_b64 + "=="))
    claims = json.loads(base64.urlsafe_b64decode(p_b64 + "=="))
    sig = base64.urlsafe_b64decode(s_b64 + "==")
    import hashlib
    try:
        secp_verify(Q, hashlib.sha256(f"{h_b64}.{p_b64}".encode()).digest(), sig)
        ok = (header.get("alg") == "ES256K" and claims.get("iss") == did
              and claims.get("aud") == aud and claims.get("lxm") == "com.atproto.sync.getRepo")
    except AssertionError:
        ok = False
    check("service token verifies", ok, str(claims)[:120])
    st, body = call("GET", f"/xrpc/com.atproto.server.getServiceAuth?aud={urllib.parse.quote(aud)}&exp=1",
                    auth=auth)
    check("BadExpiration", st == 400 and body.get("error") == "BadExpiration", str(body)[:60])

    # checkAccountStatus
    st, stt = call("GET", "/xrpc/com.atproto.server.checkAccountStatus", auth=auth)
    check("checkAccountStatus", st == 200 and stt["activated"] is True
          and stt["indexedRecords"] >= 1 and stt["repoBlocks"] >= 3
          and stt["validDid"] is True, str(stt)[:160])

    # confirm the address first so the token gate engages below
    st, _ = call("POST", "/xrpc/com.atproto.server.requestEmailConfirmation", {}, auth=auth)
    check("requestEmailConfirmation", st == 200, "")
    tokc = last_token_plc()
    st, _ = call("POST", "/xrpc/com.atproto.server.confirmEmail",
                 {"email": f"{TAG}@example.com", "token": tokc})
    check("confirm current", st == 200, "")
    # confirmed account: updateEmail without token must demand one
    st, body = call("POST", "/xrpc/com.atproto.server.updateEmail",
                    {"email": f"new-{TAG}@example.com"}, auth=auth)
    check("TokenRequired", st == 400 and body.get("error") == "TokenRequired", str(body)[:60])
    st, body = call("POST", "/xrpc/com.atproto.server.requestEmailUpdate", {}, auth=auth)
    check("requestEmailUpdate", st == 200 and body.get("tokenRequired") is True, str(body)[:60])
    toku = last_token_plc()
    st, _ = call("POST", "/xrpc/com.atproto.server.updateEmail",
                 {"email": f"new-{TAG}@example.com", "token": toku}, auth=auth)
    check("updateEmail with token", st == 200, "")
    st, gsess = call("GET", "/xrpc/com.atproto.server.getSession", auth=auth)
    check("email rotated unconfirmed", st == 200 and gsess.get("email") == f"new-{TAG}@example.com"
          and gsess.get("emailConfirmed") is not True, str(gsess)[:120])

    # invites: create, consume, list
    st, inv = call("POST", "/xrpc/com.atproto.server.createInviteCode", {}, auth="Basic " + ADMIN)
    code = inv["codes"][0]["code"]
    st, acct3 = call("POST", "/xrpc/com.atproto.server.createAccount",
                     {"handle": f"inv-{TAG}.localhost", "email": f"inv-{TAG}@example.com",
                      "password": "s3cret-pw-long", "inviteCode": code})
    check("invite signup", st == 200, str(acct3)[:80])
    st, _ = call("POST", "/xrpc/com.atproto.server.createAccount",
                 {"handle": f"inv2-{TAG}.localhost", "email": f"inv2-{TAG}@example.com",
                  "password": "s3cret-pw-long", "inviteCode": code})
    check("invite single-use", st == 400, "")
    st, sess3 = call("POST", "/xrpc/com.atproto.server.createSession",
                     {"identifier": f"inv-{TAG}.localhost", "password": "s3cret-pw-long"})
    st, codes = call("GET", "/xrpc/com.atproto.server.getAccountInviteCodes",
                     auth="Bearer " + sess3["accessJwt"])
    check("getAccountInviteCodes", st == 200 and any(c["code"] == code for c in codes["codes"]),
          str(codes)[:120])

    # PLC sign/submit: change handle on the directory
    st, _ = call("POST", "/xrpc/com.atproto.identity.requestPlcOperationSignature", {}, auth=auth)
    check("requestPlcOperationSignature", st == 200, "")
    tokp = last_token_plc()
    st, signed = call("POST", "/xrpc/com.atproto.identity.signPlcOperation",
                      {"token": tokp, "alsoKnownAs": [f"at://renamed-{TAG}.example.com"]}, auth=auth)
    check("signPlcOperation", st == 200 and signed["operation"]["type"] == "plc_operation",
          str(signed)[:100])
    st, _ = call("POST", "/xrpc/com.atproto.identity.submitPlcOperation",
                 {"operation": signed["operation"]}, auth=auth)
    check("submitPlcOperation", st == 200, "")
    st, ident = call("GET", f"/xrpc/com.atproto.identity.resolveIdentity?identifier={did}")
    check("resolveIdentity follows PLC", st == 200 and ident["did"] == did
          and ident["handle"] == "handle.invalid", str(ident)[:160])
    st, dd = call("GET", f"/xrpc/com.atproto.identity.resolveDid?did={did}")
    check("resolveDid shows new claim", st == 200
          and f"at://renamed-{TAG}.example.com" in str(dd), "")
    st, dd = call("POST", "/xrpc/com.atproto.identity.refreshIdentity",
                  {"identifier": did})
    check("refreshIdentity", st == 200 and dd["did"] == did, "")

    # delete by token
    st, _ = call("POST", "/xrpc/com.atproto.server.requestAccountDelete", {}, auth=auth)
    check("requestAccountDelete", st == 200, "")
    tokd = last_token_plc()
    st, _ = call("POST", "/xrpc/com.atproto.server.deleteAccount",
                 {"did": did, "password": "s3cret-pw-long", "token": tokd}, auth=auth)
    check("deleteAccount by token", st == 200, "")
    st, _ = call("GET", f"/xrpc/com.atproto.sync.getRepoStatus?did={did}")
    check("gone", st == 404, "")

    if fails:
        print("FAILURES:", fails)
        sys.exit(1)
    print("ALL ACCOUNT CHECKS PASSED")


def last_token_plc():
    for m in reversed(MAILBOX):
        t = "\n".join(m["body"])
        mm = re.search(r"\n([A-Za-z0-9_-]{43})\n", "\n" + t + "\n")
        if mm:
            return mm.group(1)
    raise AssertionError("no token mail")


if __name__ == "__main__":
    threading.Thread(target=smtp_server, daemon=True).start()
    srv = HTTPServer(("127.0.0.1", 8897), StubPlc)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    import time
    time.sleep(0.3)
    main()
