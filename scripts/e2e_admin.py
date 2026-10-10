#!/usr/bin/env python3
"""Admin + moderation E2E for bsky-pds-rs (stdlib only).

Prereqs: dev server on BASE (needs no special vars except defaults).
Covers: admin auth gating, account updates, signing-key rotation,
force delete, invite kill-switches, account search/infos, subject
takedown lifecycle (account/record/blob), admin sendEmail, blob sniffing.

Usage: python3 scripts/e2e_admin.py [pds_base] [tag]
"""
import base64
import json
import os
import re
import socket
import sys
import threading
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8788"
TAG = sys.argv[2] if len(sys.argv) > 2 else "adm"
ADMIN = base64.b64encode(b"admin:change-me-admin").decode()
BAD_ADMIN = base64.b64encode(b"admin:wrong").decode()
MAILBOX = []

PNG = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) + b"\x00" * 20


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
    body = []
    try:
        f.write(b"220 stub ESMTP\r\n")
        f.flush()
        data = False
        while True:
            line = f.readline().decode().strip()
            if data:
                if line == ".":
                    data = False
                    MAILBOX.append(list(body))
                    body = []
                    f.write(b"250 OK\r\n")
                    f.flush()
                else:
                    body.append(line)
                continue
            if not line:
                break
            cmd = line.split(" ")[0].upper()
            if cmd == "EHLO":
                f.write(b"250-Hello\r\n250 8BITMIME\r\n")
                f.flush()
            elif cmd in ("MAIL", "RCPT"):
                f.write(b"250 OK\r\n")
                f.flush()
            elif cmd == "DATA":
                data = True
                f.write(b"354 End\r\n")
                f.flush()
            elif cmd == "QUIT":
                f.write(b"221 Bye\r\n")
                f.flush()
                break
            else:
                f.write(b"502 no\r\n")
                f.flush()
    except Exception:
        pass
    finally:
        conn.close()


def call(method, path, body=None, auth=None, raw=None, ctype=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(BASE + path, data=data, method=method)
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

    AUTH = "Basic " + ADMIN
    badauth = "Basic " + BAD_ADMIN
    H = f"{TAG}.localhost"

    st, _, body = call("GET", "/xrpc/com.atproto.admin.getAccountInfo?did=did:plc:x", auth=badauth)
    check("admin gate", st == 401, "")

    st, _, acct = call("POST", "/xrpc/com.atproto.server.createAccount",
                       {"handle": H, "email": f"{TAG}@example.com",
                        "password": "s3cret-pw-long"}, auth=AUTH)
    check("signup", st == 200, acct.get("did", acct))
    did = acct["did"]
    st, _, sess = call("POST", "/xrpc/com.atproto.server.createSession",
                       {"identifier": H, "password": "s3cret-pw-long"})
    userauth = "Bearer " + sess["accessJwt"]

    # admin updates
    st, _, _ = call("POST", "/xrpc/com.atproto.admin.updateAccountPassword",
                    {"did": did, "password": "new-admin-set-pw-long"}, auth=AUTH)
    check("updateAccountPassword", st == 200, "")
    st, _, _ = call("POST", "/xrpc/com.atproto.server.createSession",
                    {"identifier": H, "password": "s3cret-pw-long"})
    check("old password dead", st == 401, "")
    st, _, sess = call("POST", "/xrpc/com.atproto.server.createSession",
                       {"identifier": H, "password": "new-admin-set-pw-long"})
    check("new password works", st == 200, "")
    userauth = "Bearer " + sess["accessJwt"]

    st, _, _ = call("POST", "/xrpc/com.atproto.admin.updateAccountEmail",
                    {"did": did, "email": f"admin-{TAG}@example.com"}, auth=AUTH)
    check("updateAccountEmail", st == 200, "")
    st, _, info = call("GET", f"/xrpc/com.atproto.admin.getAccountInfo?did={did}", auth=AUTH)
    check("email applied", st == 200 and info.get("email") == f"admin-{TAG}@example.com",
          str(info)[:100])

    st, _, _ = call("POST", "/xrpc/com.atproto.admin.updateAccountHandle",
                    {"did": did, "handle": f"renamed-{TAG}.localhost"}, auth=AUTH)
    check("updateAccountHandle", st == 200, "")
    H2 = f"renamed-{TAG}.localhost"
    st, _, sess = call("POST", "/xrpc/com.atproto.server.createSession",
                       {"identifier": H2, "password": "new-admin-set-pw-long"})
    check("login via new handle", st == 200, "")
    userauth = "Bearer " + sess["accessJwt"]

    # signing key rotation via reservation
    st, _, res = call("POST", "/xrpc/com.atproto.server.reserveSigningKey", {"did": did}, auth=AUTH)
    check("reserve for rotation", st == 200, str(res)[:60])
    st, _, _ = call("POST", "/xrpc/com.atproto.admin.updateAccountSigningKey",
                    {"did": did, "signingKey": res["signingKey"]}, auth=AUTH)
    check("updateAccountSigningKey", st == 200, "")
    st, _, desc = call("GET", f"/xrpc/com.atproto.repo.describeRepo?repo={did}")
    check("new key in doc", st == 200 and desc["didDoc"]["verificationMethod"][0]
          ["publicKeyMultibase"][1:] == res["signingKey"][len("did:key:z"):], "")
    st, _, rec = call("POST", "/xrpc/com.atproto.repo.createRecord",
                      {"repo": did, "collection": "app.bsky.feed.post",
                       "record": {"$type": "app.bsky.feed.post", "text": "after rotation",
                                  "createdAt": "2026-10-10T00:00:00.000Z"}}, auth=userauth)
    check("write under new key", st == 200 and rec["cid"].startswith("bafyrei"), "")
    rkey = rec["uri"].rsplit("/", 1)[-1]

    # search + infos
    st, _, found = call("GET", f"/xrpc/com.atproto.admin.searchAccounts?email=admin-{TAG}@example.com", auth=AUTH)
    check("searchAccounts", st == 200 and any(a["did"] == did for a in found["accounts"]),
          f"n={len(found.get('accounts', []))}")
    st, _, infos = call("POST", "/xrpc/com.atproto.admin.getAccountInfos",
                        {"dids": [did, "did:plc:nope"]}, auth=AUTH)
    check("getAccountInfos", st == 200 and len(infos["infos"]) == 1, "")

    # invites kill-switch
    st, _, inv = call("POST", "/xrpc/com.atproto.server.createInviteCode", {}, auth=AUTH)
    code = inv["codes"][0]["code"]
    st, _, _ = call("POST", "/xrpc/com.atproto.admin.disableInviteCodes",
                    {"codes": [code]}, auth=AUTH)
    check("disableInviteCodes", st == 200, "")
    st, _, body = call("POST", "/xrpc/com.atproto.server.createAccount",
                       {"handle": f"nope-{TAG}.localhost", "email": f"nope-{TAG}@example.com",
                        "password": "s3cret-pw-long", "inviteCode": code})
    check("disabled code rejected", st == 400, str(body)[:60])
    st, _, _ = call("POST", "/xrpc/com.atproto.admin.disableAccountInvites",
                    {"account": did}, auth=AUTH)
    check("disableAccountInvites", st == 200, "")
    st, _, info = call("GET", f"/xrpc/com.atproto.admin.getAccountInfo?did={did}", auth=AUTH)
    check("invitesDisabled surfaced", st == 200 and info.get("invitesDisabled") is True, "")
    st, _, _ = call("POST", "/xrpc/com.atproto.admin.enableAccountInvites",
                    {"account": did}, auth=AUTH)
    check("enableAccountInvites", st == 200, "")

    # subject takedown: account
    st, _, sub = call("GET", f"/xrpc/com.atproto.admin.getSubjectStatus?did={did}", auth=AUTH)
    check("subject status (clean)", st == 200, str(sub)[:80])
    st, _, upd = call("POST", "/xrpc/com.atproto.admin.updateSubjectStatus",
                      {"subject": {"did": did}, "takedown": {"applied": True}}, auth=AUTH)
    check("account takedown", st == 200 and upd["takedown"]["applied"] is True, "")
    st, _, body = call("POST", "/xrpc/com.atproto.repo.createRecord",
                       {"repo": did, "collection": "app.bsky.feed.post",
                        "record": {"$type": "app.bsky.feed.post", "text": "x",
                                   "createdAt": "2026-10-10T00:00:00.000Z"}}, auth=userauth)
    check("takedown blocks writes", st == 403, f"{st}")
    st, _, sub = call("GET", f"/xrpc/com.atproto.admin.getSubjectStatus?did={did}", auth=AUTH)
    check("takedown reflected", st == 200 and sub["takedown"]["applied"] is True, "")
    st, _, upd = call("POST", "/xrpc/com.atproto.admin.updateSubjectStatus",
                      {"subject": {"did": did}, "takedown": {"applied": False}}, auth=AUTH)
    check("untakedown", st == 200, "")
    st, _, sess = call("POST", "/xrpc/com.atproto.server.createSession",
                       {"identifier": H2, "password": "new-admin-set-pw-long"})
    userauth = "Bearer " + sess["accessJwt"]
    check("re-login after untakedown", st == 200, "")

    # subject takedown: record (hidden but preserved)
    uri = f"at://{did}/app.bsky.feed.post/{rkey}"
    st, _, upd = call("POST", "/xrpc/com.atproto.admin.updateSubjectStatus",
                      {"subject": {"uri": uri, "cid": rec["cid"]}, "takedown": {"applied": True}},
                      auth=AUTH)
    check("record takedown", st == 200, "")
    st, _, _ = call("GET", f"/xrpc/com.atproto.repo.getRecord?repo={did}&collection=app.bsky.feed.post&rkey={rkey}")
    check("record hidden", st == 404, "")
    st, _, lst = call("GET", f"/xrpc/com.atproto.repo.listRecords?repo={did}&collection=app.bsky.feed.post&limit=100")
    check("list skips it", st == 200 and all(r["uri"] != uri for r in lst["records"]), "")
    st, _, sub = call("GET", f"/xrpc/com.atproto.admin.getSubjectStatus?uri={urllib.parse.quote(uri, safe='')}",
                      auth=AUTH)
    check("record status", st == 200 and sub["takedown"]["applied"] is True, "")
    st, _, upd = call("POST", "/xrpc/com.atproto.admin.updateSubjectStatus",
                      {"subject": {"uri": uri}, "takedown": {"applied": False}}, auth=AUTH)
    check("record untakedown", st == 200, "")
    st, _, _ = call("GET", f"/xrpc/com.atproto.repo.getRecord?repo={did}&collection=app.bsky.feed.post&rkey={rkey}")
    check("record visible again", st == 200, "")

    # blob sniffing + blob takedown
    st, _, _ = call("POST", "/xrpc/com.atproto.repo.uploadBlob", raw=b"not a png",
                    auth=userauth, ctype="image/png")
    check("sniff rejects fake png", st == 400, "")
    png = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) + b"\x00" * 32
    st, _, up = call("POST", "/xrpc/com.atproto.repo.uploadBlob", raw=png,
                     auth=userauth, ctype="image/png")
    check("real png accepted", st == 200, "")
    blob_cid = up["blob"]["ref"]["$link"]
    st, _, upd = call("POST", "/xrpc/com.atproto.admin.updateSubjectStatus",
                      {"subject": {"did": did, "cid": blob_cid}, "takedown": {"applied": True}},
                      auth=AUTH)
    check("blob takedown", st == 200, "")
    st, _, _ = call("GET", f"/xrpc/com.atproto.sync.getBlob?did={did}&cid={blob_cid}")
    check("blob hidden", st == 404, "")

    # admin sendEmail
    st, _, sent = call("POST", "/xrpc/com.atproto.admin.sendEmail",
                       {"recipientDid": did, "senderDid": did, "subject": "hello",
                        "content": "mod note"}, auth=AUTH)
    check("admin sendEmail", st == 200 and sent.get("sent") is True and len(MAILBOX) > 0,
          str(sent)[:60])

    # admin force delete
    st, _, _ = call("POST", "/xrpc/com.atproto.admin.deleteAccount", {"did": did}, auth=AUTH)
    check("admin deleteAccount", st == 200, "")
    st, _, _ = call("GET", f"/xrpc/com.atproto.admin.getAccountInfo?did={did}", auth=AUTH)
    check("gone", st == 404, "")

    if fails:
        print("FAILURES:", fails)
        sys.exit(1)
    print("ALL ADMIN CHECKS PASSED")


if __name__ == "__main__":
    threading.Thread(target=smtp_server, daemon=True).start()
    import time
    time.sleep(0.3)
    main()
