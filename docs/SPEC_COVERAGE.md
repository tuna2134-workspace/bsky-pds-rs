# SPEC_COVERAGE — エンドポイント対応表

凡例: ✅ 実装 / 🚧 スタブ (形のみ・501) / ⬜ 未着手。Lexicon 原典は
[bluesky-social/atproto](https://github.com/bluesky-social/atproto) `lexicons/com/atproto/*`。

## server (`com.atproto.server.*`)

| NSID | 状態 | 備考 |
|---|---|---|
| describeServer | ✅ | ドメイン/招待要否を返す |
| createAccount | ✅ | D1 登録・空 repo 初期化・互換 JWT 返却 |
| createSession / refreshSession / getSession | ✅ (互換) | Bearer 移行期。OAuth へ移行予定 |
| createInviteCode(s) | ✅ | 管理者トークン必須 |
| requestPasswordReset / resetPassword | 🚧 | SMTP 配線と同時実装 |
| checkAccountStatus | 🚧 | |
| activateAccount / deactivateAccount / deleteAccount | ⬜ | アカウント LC と同時実装 |
| confirmEmail / requestEmailConfirmation / requestEmailUpdate / updateEmail | ⬜ | SMTP と同時実装 |
| getServiceAuth / refreshAppPassword 相当 | ⬜ | service JWT 発行として実装予定 |

## repo (`com.atproto.repo.*`)

| NSID | 状態 | 備考 |
|---|---|---|
| describeRepo | ✅ | DID Doc (PDS service + `#atproto` Multikey 検証鍵)・collections |
| createRecord / getRecord / putRecord / deleteRecord / listRecords | ✅ | 実 DAG-CBOR CID・署名 commit・`rev` 採番・firehose CAR slice。`swapCommit`/`swapRecord` 対応 |
| applyWrites | ✅ (create のみ完全) | update/delete は結果形のみ、次段で完全化 |
| uploadBlob | ✅ | R2 実体 + D1 インデックス。参照 CID は raw sha2-256 (`bafkrei…`) |
| listMissingBlobs / importRepo | ⬜ | 移行フローと同時実装 |

## sync (`com.atproto.sync.*`)

| NSID | 状態 | 備考 |
|---|---|---|
| getRepoStatus / listRepos / getLatestCommit | ✅ | 実 commit CID・rev |
| getRepo / getRecord / getBlocks | ✅ | バイナリ CAR (`application/vnd.ipld.car`)。ハッシュ検証付き parse |
| getBlocks | 🚧 | binary CAR 化待ち |
| listBlobs / getBlob | ✅ | R2 実体 (blob_router) |
| subscribeRepos | ✅ (ポーリング互換) | `?cursor=&limit=` で JSON。WS/CBOR は ROADMAP §2 |
| requestCrawl | ⬜ | Relay 通知 (`PDS_CRAWLERS`) と同時実装 |

## identity (`com.atproto.identity.*`)

| NSID | 状態 | 備考 |
|---|---|---|
| resolveHandle | ✅ | 自 PDS の handle→DID |
| updateHandle | ✅ | 要認証 |
| getRecommendedDidCredentials | 🚧 | PLC 鍵連携と同時実装 |
| signPlcOperation / submitPlcOperation / requestPlcOperationSignature | ⬜ | PLC 連携 (ROADMAP §4) |

## admin (`com.atproto.admin.*`)

| NSID | 状態 | 備考 |
|---|---|---|
| getAccountInfo | ✅ | 管理者トークン必須 |
| その他 (updateAccount*/deleteAccount/takedown 類) | ⬜ | 監査ログと同時実装 |

## OAuth (`/.well-known/*`, `/oauth/*`, `/jwks.json`)

| 経路 | 状態 | 備考 |
|---|---|---|
| oauth-protected-resource / oauth-authorization-server | ✅ | |
| `/.well-known/did.json` / `/jwks.json` | ✅ | JWKS は空で fail-closed |
| POST /oauth/par | ✅ | PKCE S256・atproto スコープ強制 |
| GET /oauth/authorize | 🚧 | 同意画面スタブ (JSON で保留中要求を返す) |
| POST /oauth/token | 🚧 | DPoP 必須を強制、発行は ROADMAP §3 |

## その他

| 項目 | 状態 | 備考 |
|---|---|---|
| `GET /xrpc/_health` | ✅ | `{"version","hostname"}` |
| `GET /.well-known/atproto-did` | ✅ | handle→DID テキスト |
| XRPC エラー標準 | ✅ | `{"error","message"}` + 仕様ステータス |
| CORS | ✅ (暫定) | `*` 許可。厳密化は本番設定で |
| `Atproto-Repo-Rev` ヘッダ | ⬜ | ROADMAP §2 |
| service proxying (`atproto-proxy`) | ⬜ | ヘッダパースのみ実装済み |
