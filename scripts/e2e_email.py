#!/usr/bin/env python3
"""Email + deletion + collection-index E2E for bsky-pds-rs (stdlib only).

Runs a stub SMTP server (no AUTH advertised) and points the PDS at it via
PDS_EMAIL_SMTP_URL, exercising the real transport path. Covers:

- requestEmailConfirmation -> stub receives token -> confirmEmail ->
  emailConfirmed flips
- updateEmail (staged token) -> confirm with token -> applied+confirmed
- requestPasswordReset -> resetPassword -> new password works, old fails
- deleteAccount (password) -> repo gone, handle unresolvable
- listReposByCollection returns the writer DID

Prereqs: dev server on BASE with
  --var PDS_EMAIL_SMTP_URL:smtp://u:p@127.0.0.1:8825/
  --var PDS_EMAIL_FROM_ADDRESS:no-reply@localhost

Usage: python3 scripts/e2e_email.py [pds_base] [handle]
"""
import base64
import json
import re
import socket
import sys
import threading
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8787"
HANDLE = sys.argv[2] if len(sys.argv) > 2 else "tara.localhost"
ADMIN = base64.b64encode(b"admin:change-me-admin").decode()
MAILBOX = []


def smtp_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 8825))
    srv.listen(10)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle_conn, args=(conn,), daemon=True).start()


def handle_conn(conn):
    f = conn.makefile("rwb")
    msg = {"headers": [], "body": []}

    def w(s):
        f.write(s.encode() + b"\r\n")
        f.flush()

    def rd():
        return f.readline().decode().strip()

    try:
        w("220 stub ESMTP")
        data_mode = False
        while True:
            line = rd()
            if data_mode:
                if line == ".":
                    data_mode = False
                    MAILBOX.append(msg)
                    msg = {"headers": [], "body": []}
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
                data_mode = True
                w("354 End data")
            elif cmd == "QUIT":
                w("221 Bye")
                break
            elif cmd == "RSET":
                w("250 OK")
            else:
                w("502 unimplemented")
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
    assert MAILBOX, "no mail received"
    text = "\n".join(MAILBOX[-1]["body"])
    m = re.search(r"\n([A-Za-z0-9_-]{43})\n", "\n" + text + "\n")
    assert m, f"no token in mail: {text[:200]}"
    return m.group(1)


def main():
    fails = []

    def check(name, cond, extra=""):
        print(("PASS " if cond else "FAIL ") + name, extra)
        if not cond:
            fails.append(name)

    # account (fresh handle per run to avoid state coupling)
    st, acct = call("POST", "/xrpc/com.atproto.server.createAccount",
                    {"handle": HANDLE, "email": f"{HANDLE}@example.com",
                     "password": "s3cret-pw-long"}, auth="Basic " + ADMIN)
    if st == 400 and acct.get("error") == "DuplicateAccount":
        st, acct = call("POST", "/xrpc/com.atproto.server.createSession",
                        {"identifier": HANDLE, "password": "s3cret-pw-long"})
    check("account ready", st == 200, acct.get("did", acct))
    did = acct["did"]
    st, sess = call("POST", "/xrpc/com.atproto.server.createSession",
                    {"identifier": HANDLE, "password": "s3cret-pw-long"})
    token = sess["accessJwt"]
    auth = "Bearer " + token

    # confirm flow
    st, _ = call("POST", "/xrpc/com.atproto.server.requestEmailConfirmation", {}, auth=auth)
    check("requestEmailConfirmation", st == 200, f"mailbox={len(MAILBOX)}")
    tok = last_token()
    st, _ = call("POST", "/xrpc/com.atproto.server.confirmEmail",
                 {"email": f"{HANDLE}@example.com", "token": tok})
    check("confirmEmail", st == 200, "")
    st, gsess = call("GET", "/xrpc/com.atproto.server.getSession", auth=auth)
    check("emailConfirmed", st == 200 and gsess.get("emailConfirmed") is True, str(gsess)[:120])

    # bad token rejected + single-use enforced
    st, body = call("POST", "/xrpc/com.atproto.server.confirmEmail",
                    {"email": f"{HANDLE}@example.com", "token": tok})
    check("token single-use", st == 400, str(body)[:80])

    # updateEmail staged flow
    new_email = f"new-{HANDLE}@example.com"
    st, _ = call("POST", "/xrpc/com.atproto.server.updateEmail", {"email": new_email}, auth=auth)
    check("updateEmail staged", st == 200, "")
    tok2 = last_token()
    st, _ = call("POST", "/xrpc/com.atproto.server.updateEmail",
                 {"email": new_email, "token": tok2}, auth=auth)
    check("updateEmail confirmed", st == 200, "")
    st, gsess = call("GET", "/xrpc/com.atproto.server.getSession", auth=auth)
    check("email applied", st == 200 and gsess.get("email") == new_email, str(gsess)[:120])

    # password reset
    st, _ = call("POST", "/xrpc/com.atproto.server.requestPasswordReset", {"email": new_email})
    check("requestPasswordReset (always 200)", st == 200, "")
    tok3 = last_token()
    st, _ = call("POST", "/xrpc/com.atproto.server.resetPassword",
                 {"token": tok3, "password": "brand-new-pw-long"})
    check("resetPassword", st == 200, "")
    st, _ = call("POST", "/xrpc/com.atproto.server.createSession",
                 {"identifier": HANDLE, "password": "s3cret-pw-long"})
    check("old password dead", st == 401, "")
    st, sess2 = call("POST", "/xrpc/com.atproto.server.createSession",
                     {"identifier": HANDLE, "password": "brand-new-pw-long"})
    check("new password works", st == 200, "")
    token2 = sess2["accessJwt"]

    # write something, then check collection index
    st, rec = call("POST", "/xrpc/com.atproto.repo.createRecord",
                   {"repo": did, "collection": "app.bsky.feed.post",
                    "record": {"$type": "app.bsky.feed.post", "text": "before delete",
                               "createdAt": "2026-10-10T00:00:00.000Z"}},
                   auth="Bearer " + token2)
    check("pre-delete write", st == 200, "")
    st, lst = call("GET", "/xrpc/com.atproto.sync.listReposByCollection?collection=app.bsky.feed.post&limit=100")
    dids = [r["did"] for r in lst.get("repos", [])]
    check("listReposByCollection", st == 200 and did in dids, f"n={len(dids)}")

    # deleteAccount
    st, _ = call("POST", "/xrpc/com.atproto.server.deleteAccount",
                 {"password": "brand-new-pw-long"}, auth="Bearer " + token2)
    check("deleteAccount", st == 200, "")
    st, body = call("GET", f"/xrpc/com.atproto.sync.getRepoStatus?did={did}")
    check("repo gone", st == 404, f"{st} {str(body)[:80]}")
    st, body = call("GET", f"/xrpc/com.atproto.identity.resolveHandle?handle={HANDLE}")
    check("handle unresolvable", st == 404, f"{st} {str(body)[:80]}")
    st, _ = call("POST", "/xrpc/com.atproto.server.createSession",
                 {"identifier": HANDLE, "password": "brand-new-pw-long"})
    check("session dead", st == 401, "")

    if fails:
        print("FAILURES:", fails)
        sys.exit(1)
    print("ALL EMAIL/LIFECYCLE CHECKS PASSED")


if __name__ == "__main__":
    threading.Thread(target=smtp_server, daemon=True).start()
    import time
    time.sleep(0.3)
    main()
