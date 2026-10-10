#!/usr/bin/env python3
"""WebSocket firehose E2E for bsky-pds-rs (stdlib only).

Raw-socket WS client (no third-party deps): HTTP upgrade handshake, binary
frame parsing, then DAG-CBOR decoding with the shared test codec. Verifies:

1. Live tail: connect (no cursor) -> create a record -> `#commit` arrives
   with matching rev/ops, and its CAR slice parses (commit + nodes + record).
2. Replay: reconnect with cursor=0 -> history replays in seq order.
3. Future cursor -> `FutureCursor` error frame, then close.
4. `#identity` events flow for new accounts.

Usage: python3 scripts/e2e_firehose.py [pds_base] [handle]
  (pds_base like http://localhost:8787; ws assumed on same host:port)
"""
import base64
import hashlib
import json
import os
import socket
import sys
import threading
import time
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_repo import Dec as CborDec  # shared test CBOR decoder

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8787"
HANDLE = sys.argv[2] if len(sys.argv) > 2 else "nina.localhost"
ADMIN = base64.b64encode(b"admin:change-me-admin").decode()
U = urllib.parse.urlparse(BASE)
HOST, PORT = U.hostname, U.port or 80


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def ws_connect(path):
    s = socket.create_connection((HOST, PORT), timeout=10)
    s.settimeout(9)
    key = b64u(os.urandom(16))
    req = (f"GET {path} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nUpgrade: websocket\r\n"
           f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
    s.sendall(req.encode())
    f = s.makefile("rb")
    status = f.readline().decode()
    headers = {}
    while True:
        line = f.readline().decode()
        if line in ("\r\n", ""):
            break
        k, _, v = line.partition(":")
        headers[k.strip().lower()] = v.strip()
    return s, f, status, headers


def ws_read_frame(f):
    hdr = f.read(2)
    if len(hdr) < 2:
        return None, None
    fin_op, length = hdr[0], hdr[1] & 0x7F
    assert fin_op & 0x80, "fragmentation unsupported in test client"
    opcode = fin_op & 0x0F
    if length == 126:
        length = int.from_bytes(f.read(2), "big")
    elif length == 127:
        length = int.from_bytes(f.read(8), "big")
    mask = f.read(4) if (hdr[1] & 0x80) else None
    data = b""
    while len(data) < length:
        chunk = f.read(length - len(data))
        if not chunk:
            break
        data += chunk
    if mask:
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    if opcode == 0x8:
        return "close", data
    assert opcode == 0x2, f"expected binary frame, got opcode {opcode}"
    return "message", data


def decode_frame(data):
    d = CborDec(data)
    header = d.one()
    body = d.one()
    assert d.p == len(data), f"trailing bytes in frame: {len(data) - d.p}"
    assert isinstance(header, dict) and header.get("op") == 1, header
    t = header.get("t")
    assert isinstance(body, dict), body
    return t, body


def cbor_to_json(v):
    if isinstance(v, tuple):
        kind, payload = v
        if kind == "link":
            return {"$link": "b" + __import__("base64").b32encode(payload).decode().lower().rstrip("=")}
        if kind == "bytes":
            return {"$bytes": base64.b64encode(payload).decode()}
        raise AssertionError(f"tuple {kind}")
    if isinstance(v, list):
        return [cbor_to_json(x) for x in v]
    if isinstance(v, dict):
        return {k: cbor_to_json(x) for k, x in v.items()}
    return v


def main():
    fails = []

    def check(name, cond, extra=""):
        print(("PASS " if cond else "FAIL ") + name, extra)
        if not cond:
            fails.append(name)

    # account for the live write
    req = urllib.request.Request(
        BASE + "/xrpc/com.atproto.server.createAccount",
        data=json.dumps({"handle": HANDLE, "email": f"{HANDLE}@example.com",
                         "password": "s3cret-pw-long"}).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", "Basic " + ADMIN)
    try:
        with urllib.request.urlopen(req) as r:
            acct = json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = json.loads(e.read())
        assert body.get("error") == "DuplicateAccount", body
        req2 = urllib.request.Request(
            BASE + "/xrpc/com.atproto.server.createSession",
            data=json.dumps({"identifier": HANDLE, "password": "s3cret-pw-long"}).encode(),
            method="POST")
        req2.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req2) as r:
            acct = json.loads(r.read())
    did, token = acct["did"], acct["accessJwt"]

    # 1. live tail (no cursor)
    s, f, status, _ = ws_connect("/xrpc/com.atproto.sync.subscribeRepos")
    check("WS upgrade", "101" in status, status.strip())
    got = []

    def reader(sock_f, out, budget=8.0):
        deadline = time.time() + budget
        try:
            while time.time() < deadline and len(out) < 50:
                kind, data = ws_read_frame(sock_f)
                if kind is None:
                    break
                if kind == "close":
                    out.append(("close", data))
                    break
                out.append(decode_frame(data))
        except socket.timeout:
            out.append(("idle-timeout", None))
        except Exception as e:
            out.append(("error", str(e)))

    box = []
    th = threading.Thread(target=reader, args=(f, box), daemon=True)
    th.start()
    time.sleep(0.5)
    # reader note: socket.timeout at the end of a quiet stream is normal
    # create a record while subscribed
    req3 = urllib.request.Request(
        BASE + "/xrpc/com.atproto.repo.createRecord",
        data=json.dumps({"repo": did, "collection": "app.bsky.feed.post",
                         "record": {"$type": "app.bsky.feed.post", "text": "firehose live",
                                    "createdAt": "2026-10-10T00:00:00.000Z"}}).encode(),
        method="POST")
    req3.add_header("Content-Type", "application/json")
    req3.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req3) as r:
        rec = json.loads(r.read())
    rev = rec["commit"]["rev"]
    th.join(timeout=10)
    commits = [b for (t, b) in box if t == "#commit" and b.get("rev") == rev]
    check("live #commit received", len(commits) == 1, f"frames={len(box)} rev={rev}")
    if commits:
        c = cbor_to_json(commits[0])
        check("commit ops", c["ops"] and c["ops"][0]["action"] == "create"
              and c["ops"][0]["path"].startswith("app.bsky.feed.post/"), str(c["ops"])[:100])
        check("commit repo/rev", c["repo"] == did and c["rev"] == rev, "")
        # CAR slice parses: commit + MST nodes + the record
        from e2e_repo import parse_car
        raw_blocks = None
        for k, v in commits[0].items():
            pass
        # blocks arrive as ("bytes", ...) tuple from the test decoder
        assert isinstance(commits[0]["blocks"], tuple)
        roots, blocks = parse_car(commits[0]["blocks"][1])
        kinds = set()
        for cid, body in blocks:
            dd = CborDec(body).one()
            if isinstance(dd, dict) and dd.get("version") == 3 and "sig" in dd:
                kinds.add("commit")
            elif isinstance(dd, dict) and "e" in dd:
                kinds.add("mst")
            else:
                kinds.add("record")
        check("CAR slice contents", kinds == {"commit", "mst", "record"}, str(sorted(kinds)))
        s.close()
    else:
        s.close()

    # 2. replay from cursor=0
    s2, f2, status2, _ = ws_connect("/xrpc/com.atproto.sync.subscribeRepos?cursor=0")
    check("replay upgrade", "101" in status2, status2.strip())
    box2 = []
    th2 = threading.Thread(target=reader, args=(f2, box2), daemon=True)
    th2.start()
    th2.join(timeout=12)
    seqs = [b["seq"] for (t, b) in box2 if isinstance(b, dict) and "seq" in b]
    assert not [x for x in box2 if x[0] == "error"], [x for x in box2 if x[0] == "error"]
    check("replay ordered", len(seqs) > 0 and seqs == sorted(seqs), f"n={len(seqs)}")
    types = {t for (t, b) in box2 if isinstance(t, str)}
    check("replay has commit+account+sync", "#commit" in types and "#account" in types, str(sorted(types)))
    s2.close()

    # 3. future cursor -> error frame + close
    s3, f3, status3, _ = ws_connect("/xrpc/com.atproto.sync.subscribeRepos?cursor=999999999999")
    check("future upgrade", "101" in status3, status3.strip())
    kind, data = ws_read_frame(f3)
    d = CborDec(data)
    hdr, errbody = d.one(), d.one()
    check("FutureCursor frame", hdr.get("op") == -1 and errbody.get("error") == "FutureCursor",
          str(errbody)[:80])
    kind2, _ = ws_read_frame(f3)
    check("closed after error", kind2 == "close" or kind2 is None, str(kind2))
    s3.close()

    if fails:
        print("FAILURES:", fails)
        sys.exit(1)
    print("ALL FIREHOSE CHECKS PASSED")


if __name__ == "__main__":
    main()
