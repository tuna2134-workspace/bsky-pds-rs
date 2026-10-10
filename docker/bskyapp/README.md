# Official-client interop probe (Docker + Puppeteer)

Drives the real https://bsky.app in headless Chrome against this PDS:

1. handle discovery (official AppView, well-known fallback)
2. manual hosting-provider selection + credential consent dialog
3. login (createSession/refreshSession/getSession on our PDS)
4. preferences, profile/chat records from our repo, proxied AppView reads
5. age-assurance gate (birthdate from `BSKY_TEST_BIRTHDATE`) to home timeline
6. composer post from the official client, verified in our repo
   (`applyWrites` + blob upload); chat UI load check

## Run

```bash
docker build -t bskyapp-pds-test docker/bskyapp
mkdir -p docker/bskyapp/out
docker run --rm \
  -v $PWD/docker/bskyapp/out:/out \
  -e BSKY_PDS=https://your-pds.example \
  -e BSKY_TEST_DID=did:plc:... \
  -e BSKY_TEST_EMAIL=user@example.com \
  -e BSKY_TEST_HANDLE=user.example.com \
  -e BSKY_TEST_PASSWORD='...' \
  -e BSKY_TEST_BIRTHDATE='1990-01-01' \
  bskyapp-pds-test
```

Results: `/out/report.json` (steps + captured XRPC traffic) and screenshots.
Credentials come from env only — never committed. `out/` is git-ignored.

## Findings baked in

- bsky.app login accepts handle/email identifiers (raw DIDs are rejected
  client-side); custom PDS needs the Manual provider path with a bare
  hostname (no scheme).
- Some web-client calls omit `atproto-proxy`; the PDS auto-routes known
  `app.bsky.*`/`chat.bsky.*` NSIDs to the AppView (see `src/proxy.rs`).
- Service JWT `aud` must be the bare service DID (reference `verifyJwt`
  compares exact equality).
- Post pages need relay indexing; everything else works PDS-natively.
