# bsky-pds-rs — Bluesky PDS in Rust + Cloudflare Workers

[Bluesky PDS](https://github.com/bluesky-social/pds) (Personal Data Server) の
Rust + Cloudflare Workers (D1 + KV + R2) 実装。AT Protocol 仕様
([atproto.com](https://atproto.com/ja), `/specs/*`) に準拠したフル互換 PDS を目指す。

> 現状: XRPC 基盤・主要 `com.atproto.*` エンドポイント・OAuth ディスカバリが
> 動作する **開発者向け基盤**。MST/CAR 完全検証・OAuth トークン発行・Relay 連合は
> [docs/ROADMAP.md](docs/ROADMAP.md) の計画に沿って段階実装中。
> 仕様カバレッジは [docs/SPEC_COVERAGE.md](docs/SPEC_COVERAGE.md)。

## 構成

- `src/atproto.rs` — NSID / TID / DID / handle / record-key / AT-URI 検証
- `src/xrpc.rs` — XRPC エラー標準 `{"error","message"}` + プロキシヘッダ
- `src/car.rs` — CAR v1 / CID ヘルパー (完全 MST 検証は ROADMAP)
- `src/auth.rs` — DPoP/Bearer 抽出・管理者トークン (OAuth 本体は routes_misc)
- `src/routes_server.rs` — `com.atproto.server.*` (アカウント/セッション/招待)
- `src/routes_repo.rs` — `com.atproto.repo.*` (レコード CRUD/applyWrites)
- `src/routes_sync.rs` — `com.atproto.sync.*` (status/list/getRepo/firehose 取得系)
- `src/routes_misc.rs` — identity / blob (R2) / admin / OAuth (PAR・メタデータ)
- `migrations/0001_init.sql` — D1 スキーマ (account/repo/blob/seq/OAuth)

ストレージ方針 (D1 + R2):

- D1: アカウント・レコード JSON・repo rev・firehose `seq`・招待・OAuth (PAR/コード/トークン)
- R2 (`BLOBS`): blob 原本 (content-addressed key `<did>/<cid>`)
- KV (`CACHE`): DPoP nonce・解決キャッシュ (配線は ROADMAP)

## 必要条件

- Rust (stable) + `wasm32-unknown-unknown` ターゲット
- Node.js 18+ / npx (wrangler 4 系を使用)
- Cloudflare アカウント (デプロイ時)

Rust/npm のキャッシュはすべてリポジトリ内 (`.cargo-home/` `.cargo-target/`
`.npm-cache/` `.xdg-config/`) に置く。`wrangler.toml` の `[build]` が自動設定するので、
`$HOME/.cargo` が read-only な環境でもビルドできる。

## 開発

```bash
# 型チェック / 単体テスト (atproto 検証器)
cargo check
cargo test --lib

# wasm リリースビルド
cargo install -q "worker-build@^0.8" && worker-build --release

# 設定検証 (ビルド + バインディング確認のみ)
npx wrangler deploy --dry-run

# ローカル起動 (D1/R2/KV はローカルエミュレーション)
cp .dev.vars.example .dev.vars   # PDS_ADMIN_PASSWORD 等を設定
npx wrangler dev --local --port 8787
curl localhost:8787/xrpc/_health
curl 'localhost:8787/xrpc/com.atproto.server.describeServer'
```

## デプロイ

```bash
# 本番用 D1/KV/R2 を作り、wrangler.toml の database_id / id / bucket 名を更新
npx wrangler d1 create bsky-pds
npx wrangler kv:namespace create CACHE
npx wrangler r2 bucket create bsky-pds-blobs

# マイグレーション + シークレット + デプロイ
npx wrangler d1 migrations apply bsky-pds --remote
npx wrangler secret put PDS_ADMIN_PASSWORD
npx wrangler secret put PDS_JWT_SECRET
npx wrangler secret put PDS_EMAIL_SMTP_URL  # contains the SMTP password
npx wrangler deploy
```

`PDS_HOSTNAME` を自ドメインにし、DNS の `A` + `*.domain` ワイルドカードと
`/.well-known/atproto-did` 解決を確認 (本家手順は
[bluesky-social/pds](https://github.com/bluesky-social/pds) README 参照)。

## レート制限・運用

- D1 固定ウィンドウ制限: 作成 20/5分・セッション 60/分・OAuth 120/分・書込
  600/分・プロキシ 300/分 (429 + `Retry-After`)
- `GET /metrics`: アカウント/レコード/ブロブ/発火 seq の集計
- SMTP 全体に 30 秒タイムアウト。メール未設定時はログモード (開発用)

## 認証方針

- **OAuth (atproto プロファイル) が正規**: PAR 必須・PKCE S256・DPoP 必須。
  `/.well-known/oauth-*`・`jwks.json`・`/oauth/par`・`/oauth/authorize` を実装済み、
  `/oauth/token` は DPoP 検証と合わせて発行ロジックを実装中。
- 互換 `createSession` / `refreshSession` (Bearer) は移行期のみ受付。
- 管理系は `Authorization: Basic base64(admin:<PDS_ADMIN_PASSWORD>)`。

## ライセンス

MIT OR Apache-2.0 (本家 PDS と同じデュアルライセンス)。
