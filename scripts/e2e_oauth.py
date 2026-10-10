#!/usr/bin/env python3
"""Full OAuth loop E2E for bsky-pds-rs (stdlib only).

Client side is implemented from scratch: P-256 keygen, ES256 DPoP proofs,
PKCE, PAR -> authorize(login+consent) -> token -> DPoP-authed XRPC -> refresh.

A tiny metadata server serves the public-client metadata document over
http://127.0.0.1 (loopback exception), exercising the real server-side
client-metadata fetch + validation path.

Usage: python3 scripts/e2e_oauth.py [pds_base] [handle]
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

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8787"
HANDLE = sys.argv[2] if len(sys.argv) > 2 else "ivan.localhost"
META_PORT = 8899
META_URL = f"http://127.0.0.1:{META_PORT}/oauth-client-metadata.json"
REDIRECT = f"http://127.0.0.1:{META_PORT}/callback"
ADMIN = base64.b64encode(b"admin:change-me-admin").decode()

CONF_JWK = None  # filled after keygen below
# Unique per run: server caches metadata by client_id (1h TTL).
RUN_TAG = base64.urlsafe_b64encode(__import__("os").urandom(6)).decode().rstrip("=")
CONF_META_URL = f"http://127.0.0.1:{META_PORT}/oauth-client-metadata-conf.json?run={RUN_TAG}"
CONF_REDIRECT = f"http://127.0.0.1:{META_PORT}/callback2"

META_DOC = {
    "client_id": META_URL,
    "application_type": "web",
    "grant_types": ["authorization_code", "refresh_token"],
    "scope": "atproto transition:generic",
    "response_types": ["code"],
    "redirect_uris": [REDIRECT],
    "token_endpoint_auth_method": "none",
    "dpop_bound_access_tokens": True,
}


CONF_DOC = {}

class MetaHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/oauth-client-metadata.json":
            body = json.dumps(META_DOC).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/oauth-client-metadata-conf.json"):
            body = json.dumps(CONF_DOC).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


# ---------- P-256 (single source: atproto_crypto) ----------
from atproto_crypto import (
    P256_P as P,
    P256_N as N,
    P256_G as G,
    P256_A as A,
    pt_add as _pt_add,
    pt_mul as _pt_mul,
    es256_sign_p256,
    b64u,
)

GX, GY = G


def pt_add(a, b):
    return _pt_add(a, b, P, A)


def pt_mul(k, pt):
    return _pt_mul(k, pt, P, A)


priv = int.from_bytes(os.urandom(32), "big") % N
Q = pt_mul(priv, G)
JWK = {"kty": "EC", "crv": "P-256",
       "x": b64u(Q[0].to_bytes(32, "big")), "y": b64u(Q[1].to_bytes(32, "big"))}
JKT = b64u(hashlib.sha256(
    ('{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}' % (JWK["x"], JWK["y"])).encode()
).digest())


def es256_sign(digest, key=priv):
    return es256_sign_p256(digest, key)


def dpop_proof(method, url, nonce=None, ath=None):
    h = b64u(json.dumps({"typ": "dpop+jwt", "alg": "ES256", "jwk": JWK},
                        separators=(",", ":")).encode())
    claims = {"htm": method, "htu": url, "iat": __import__("time").time().__int__(),
              "jti": b64u(os.urandom(16))}
    if nonce:
        claims["nonce"] = nonce
    if ath:
        claims["ath"] = ath
    p = b64u(json.dumps(claims, separators=(",", ":")).encode())
    sig = es256_sign(hashlib.sha256(f"{h}.{p}".encode()).digest())
    return f"{h}.{p}.{b64u(sig)}"


# ---------- HTTP helpers ----------
def form(path, fields, dpop=None):
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(BASE + path, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if dpop:
        req.add_header("DPoP", dpop)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, dict(r.headers), json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), json.loads(e.read())


def get(path, auth=None, dpop=None, accept=None):
    req = urllib.request.Request(BASE + path, method="GET")
    if auth:
        req.add_header("Authorization", auth)
    if dpop:
        req.add_header("DPoP", dpop)
    if accept:
        req.add_header("Accept", accept)
    try:
        with urllib.request.urlopen(req) as r:
            ct = r.headers.get("Content-Type", "")
            raw = r.read()
            body = json.loads(raw) if "json" in ct else raw
            return r.status, dict(r.headers), body
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, dict(e.headers), json.loads(raw)
        except Exception:
            return e.code, dict(e.headers), {"raw": raw[:200].decode("utf8", "replace")}


def post_json(path, body, auth=None, dpop=None):
    data = json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if auth:
        req.add_header("Authorization", auth)
    if dpop:
        req.add_header("DPoP", dpop)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, dict(r.headers), json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), json.loads(e.read())


def main():
    fails = []

    def check(name, cond, extra=""):
        print(("PASS " if cond else "FAIL ") + name, extra)
        if not cond:
            fails.append(name)

    srv = HTTPServer(("127.0.0.1", META_PORT), MetaHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    # account
    req = urllib.request.Request(
        BASE + "/xrpc/com.atproto.server.createAccount",
        data=json.dumps({"handle": HANDLE, "email": f"{HANDLE}@example.com",
                         "password": "s3cret-pw-long"}).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", "Basic " + ADMIN)
    try:
        with urllib.request.urlopen(req) as r:
            acct = json.loads(r.read())
        check("createAccount", True, acct["did"])
        did = acct["did"]
    except urllib.error.HTTPError as e:
        body = json.loads(e.read())
        if body.get("error") == "DuplicateAccount":
            st, _, sess = post_json("/xrpc/com.atproto.server.createSession",
                                    {"identifier": HANDLE, "password": "s3cret-pw-long"})
            check("createSession (compat, hashed pw)", st == 200, str(sess)[:80])
            did = sess["did"]
        else:
            check("createAccount", False, str(body))
            print("FAILURES:", fails)
            sys.exit(1)

    # PKCE
    verifier = b64u(os.urandom(32))
    challenge = b64u(hashlib.sha256(verifier.encode()).digest())

    # PAR
    st, _, par = form("/oauth/par", {
        "client_id": META_URL, "redirect_uri": REDIRECT,
        "scope": "atproto transition:generic", "state": "xyz-state",
        "code_challenge": challenge, "code_challenge_method": "S256",
        "login_hint": HANDLE})
    check("PAR (metadata fetch + validation)", st == 200, str(par)[:120])
    request_uri = par["request_uri"]

    # authorize (JSON mode) + login/consent
    st, _, pending = get(f"/oauth/authorize?request_uri={urllib.parse.quote(request_uri)}&format=json",
                         accept="application/json")
    check("authorize pending", st == 200 and pending["client_id"] == META_URL, str(pending)[:100])
    st, _, done = form(f"/oauth/authorize?format=json",
                       {"request_uri": request_uri, "handle": HANDLE, "password": "s3cret-pw-long"})
    check("authorize login+consent", st == 200 and "code" in done, str(done)[:120])
    code = done["code"]
    assert done["redirect_to"].startswith(REDIRECT + "?code="), done["redirect_to"]

    token_url = BASE + "/oauth/token"

    def hget(hdrs, name):
        for k, v in hdrs.items():
            if k.lower() == name.lower():
                return v
        return None

    def token_exchange(fields, nonce=None):
        proof = dpop_proof("POST", token_url, nonce=nonce)
        return form("/oauth/token", fields, dpop=proof)

    # first attempt without nonce -> use_dpop_nonce
    st, hdrs, body = token_exchange({"grant_type": "authorization_code", "code": code,
                                     "redirect_uri": REDIRECT, "code_verifier": verifier})
    nonce = None
    if st == 400 and body.get("error") == "use_dpop_nonce":
        nonce = hget(hdrs, "dpop-nonce")
        check("DPoP nonce challenge", bool(nonce), str(body)[:80])
    else:
        check("DPoP nonce challenge", False, f"{st} {body}")

    st, _, toks = token_exchange({"grant_type": "authorization_code", "code": code,
                                  "redirect_uri": REDIRECT, "code_verifier": verifier}, nonce=nonce)
    check("token exchange", st == 200 and toks.get("sub") == did, str(toks)[:160])
    access, refresh = toks["access_token"], toks["refresh_token"]
    assert toks["token_type"] == "DPoP" and "atproto" in toks["scope"]

    # wrong verifier must fail (need a fresh code for that; reuse check via refresh instead).
    # Use the access token on XRPC with bound DPoP proof.
    ath = b64u(hashlib.sha256(access.encode()).digest())
    proof = dpop_proof("POST", BASE + "/xrpc/com.atproto.repo.createRecord", ath=ath)
    st, _, rec = post_json("/xrpc/com.atproto.repo.createRecord",
                           {"repo": did, "collection": "app.bsky.feed.post",
                            "record": {"$type": "app.bsky.feed.post", "text": "via oauth",
                                       "createdAt": "2026-10-10T00:00:00.000Z"}},
                           auth="DPoP " + access, dpop=proof)
    check("DPoP-authed createRecord", st == 200 and rec["cid"].startswith("bafyrei"), str(rec)[:140])
    RKEY = rec["uri"].rsplit("/", 1)[-1]

    # getSession over OAuth (email hidden without transition:email)
    proof2 = dpop_proof("GET", BASE + "/xrpc/com.atproto.server.getSession", ath=ath)
    st, _, sess = get("/xrpc/com.atproto.server.getSession", auth="DPoP " + access, dpop=proof2)
    check("getSession over OAuth", st == 200 and sess.get("did") == did and "email" not in sess, str(sess)[:120])

    def refresh_with(tok):
        pr = dpop_proof("POST", token_url)
        st, hdrs, body = form("/oauth/token",
                              {"grant_type": "refresh_token", "refresh_token": tok}, dpop=pr)
        if st == 400 and body.get("error") == "use_dpop_nonce":
            n = hget(hdrs, "dpop-nonce")
            pr2 = dpop_proof("POST", token_url, nonce=n)
            st, _, body = form("/oauth/token",
                               {"grant_type": "refresh_token", "refresh_token": tok}, dpop=pr2)
        return st, body

    st, toks2 = refresh_with(refresh)
    check("refresh rotation", st == 200 and toks2["access_token"] != access, str(toks2)[:120] if isinstance(toks2, dict) else toks2)

    # old refresh must now be rejected (rotated)
    st, body = refresh_with(refresh)
    check("old refresh rejected", st == 400 and body.get("error") == "invalid_grant", f"{st} {body}")

    # ---- confidential client (private_key_jwt) ----
    conf_priv = int.from_bytes(os.urandom(32), "big") % N
    conf_Q = pt_mul(conf_priv, G)
    conf_jwk = {"kty": "EC", "crv": "P-256", "kid": "conf1",
                "x": b64u(conf_Q[0].to_bytes(32, "big")),
                "y": b64u(conf_Q[1].to_bytes(32, "big"))}
    CONF_DOC.update({
        "client_id": CONF_META_URL.split("?")[0] + "?run=" + RUN_TAG,
        "application_type": "web",
        "grant_types": ["authorization_code", "refresh_token"],
        "scope": "atproto transition:generic",
        "response_types": ["code"],
        "redirect_uris": [CONF_REDIRECT],
        "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_signing_alg": "ES256",
        "jwks": {"keys": [conf_jwk]},
        "dpop_bound_access_tokens": True,
    })

    def client_assertion(aud):
        h = b64u(json.dumps({"alg": "ES256", "kid": "conf1", "typ": "jwt"},
                            separators=(",", ":")).encode())
        claims = {"iss": CONF_META_URL, "sub": CONF_META_URL, "aud": aud,
                  "jti": b64u(os.urandom(16)),
                  "exp": __import__("time").time().__int__() + 300}
        p = b64u(json.dumps(claims, separators=(",", ":")).encode())
        sig = es256_sign(hashlib.sha256(f"{h}.{p}".encode()).digest(), key=conf_priv)
        return f"{h}.{p}.{b64u(sig)}"

    verifier2 = b64u(os.urandom(32))
    challenge2 = b64u(hashlib.sha256(verifier2.encode()).digest())
    par_url = BASE + "/oauth/par"
    st, _, par2 = form("/oauth/par", {
        "client_id": CONF_META_URL, "redirect_uri": CONF_REDIRECT,
        "scope": "atproto", "state": "conf-state",
        "code_challenge": challenge2, "code_challenge_method": "S256",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion(par_url)})
    check("confidential PAR", st == 200, str(par2)[:100])
    if st == 200:
        st, _, done2 = form("/oauth/authorize?format=json",
                            {"request_uri": par2["request_uri"], "handle": HANDLE,
                             "password": "s3cret-pw-long"})
        check("confidential authorize", st == 200 and "code" in done2, str(done2)[:100])
        code2 = done2["code"]

        def conf_exchange(fields, nonce=None):
            proof = dpop_proof("POST", token_url, nonce=nonce)
            f2 = dict(fields)
            f2["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            f2["client_assertion"] = client_assertion(token_url)
            return form("/oauth/token", f2, dpop=proof)

        st, hdrs, body2 = conf_exchange(
            {"grant_type": "authorization_code", "code": code2,
             "redirect_uri": CONF_REDIRECT, "code_verifier": verifier2})
        if st == 400 and body2.get("error") == "use_dpop_nonce":
            n = hget(hdrs, "dpop-nonce")
            st, _, body2 = conf_exchange(
                {"grant_type": "authorization_code", "code": code2,
                 "redirect_uri": CONF_REDIRECT, "code_verifier": verifier2}, nonce=n)
        check("confidential token exchange", st == 200 and body2.get("sub") == did,
              str(body2)[:140])

    # ---- atproto-only scope is read-only ----
    verifier3 = b64u(os.urandom(32))
    challenge3 = b64u(hashlib.sha256(verifier3.encode()).digest())
    st, _, par3 = form("/oauth/par", {
        "client_id": META_URL, "redirect_uri": REDIRECT,
        "scope": "atproto", "state": "ro-state",
        "code_challenge": challenge3, "code_challenge_method": "S256"})
    check("atproto-only PAR", st == 200, "")
    st, _, done3 = form("/oauth/authorize?format=json",
                        {"request_uri": par3["request_uri"], "handle": HANDLE,
                         "password": "s3cret-pw-long"})
    code3 = done3["code"]
    st, hdrs, body3 = token_exchange({"grant_type": "authorization_code", "code": code3,
                                      "redirect_uri": REDIRECT, "code_verifier": verifier3})
    if st == 400 and body3.get("error") == "use_dpop_nonce":
        n = hget(hdrs, "dpop-nonce")
        st, _, body3 = token_exchange({"grant_type": "authorization_code", "code": code3,
                                       "redirect_uri": REDIRECT, "code_verifier": verifier3}, nonce=n)
    check("atproto-only token", st == 200 and body3.get("scope") == "atproto", str(body3)[:100])
    ro_access = body3["access_token"]
    ro_ath = b64u(hashlib.sha256(ro_access.encode()).digest())
    # read works
    proof_ro = dpop_proof("GET", BASE + "/xrpc/com.atproto.server.getSession", ath=ro_ath)
    st, _, _ = get("/xrpc/com.atproto.server.getSession", auth="DPoP " + ro_access, dpop=proof_ro)
    check("atproto-only read", st == 200, "")
    # write rejected
    proof_ro_w = dpop_proof("POST", BASE + "/xrpc/com.atproto.repo.createRecord", ath=ro_ath)
    st, _, body_ro = post_json("/xrpc/com.atproto.repo.createRecord",
                               {"repo": did, "collection": "app.bsky.feed.post",
                                "record": {"$type": "app.bsky.feed.post", "text": "nope",
                                           "createdAt": "2026-10-10T00:00:00.000Z"}},
                               auth="DPoP " + ro_access, dpop=proof_ro_w)
    check("atproto-only write rejected", st == 403, f"{st} {str(body_ro)[:80]}")

    # ---- deactivation gates redistribution, not owner reads ----
    st, _, fresh = post_json("/xrpc/com.atproto.server.createSession",
                             {"identifier": HANDLE, "password": "s3cret-pw-long"})
    check("fresh compat session", st == 200, "")
    owner = "Bearer " + fresh["accessJwt"]
    st, _, _ = post_json("/xrpc/com.atproto.server.deactivateAccount", {},
                         auth=owner)
    check("deactivate", st == 200, "")
    st, _, _ = get(f"/xrpc/com.atproto.sync.getRepo?did={did}")
    check("getRepo gated", st == 403, "")
    import urllib.request as _u
    try:
        _u.urlopen(BASE + f"/xrpc/com.atproto.repo.getRecord?repo={did}&collection=app.bsky.feed.post&rkey={RKEY}")
        read_open = True
    except urllib.error.HTTPError as e:
        read_open = e.code == 200
    check("owner read stays open", read_open, "")
    st, _, _ = post_json("/xrpc/com.atproto.server.activateAccount", {},
                         auth=owner)
    check("reactivate", st == 200, "")
    st, _, _ = get(f"/xrpc/com.atproto.sync.getRepo?did={did}")
    check("getRepo restored", st == 200, "")

    if fails:
        print("FAILURES:", fails)
        sys.exit(1)
    print("ALL OAUTH CHECKS PASSED")


if __name__ == "__main__":
    main()
