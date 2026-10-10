# SPEC_COVERAGE — エンドポイント対応表

凡例: ✅ 実装 / 🚧 スタブ (形のみ・501) / ⬜ 未着手。Lexicon 原典は
[bluesky-social/atproto](https://github.com/bluesky-social/atproto) `lexicons/com/atproto/*`。

## server (`com.atproto.server.*`)

| NSID | 状態 | 備考 |
|---|---|---|
| describeServer | ✅ | ドメイン/招待要否を返す |
| createAccount | ✅ | D1 登録・空 repo 初期化・互換 JWT 返却 |
| createAccount | ✅ | argon2id・k256 鍵・genesis commit・#account/#sync。`recoveryKey`/`plcOp` 移行対応・didDoc 返却・HandleNotAvailable |
| describeServer | ✅ | +blobUploadLimit |
| getSession | ✅ | +didDoc/emailAuthFactor/status |
| createSession / refreshSession | ✅ (互換) | argon2 検証・HS256 署名ペア (access 1h/refresh 7d)。refresh は回転 |
| getSession | ✅ | Lexicon 形 (トークンなし)。OAuth 時 email は `transition:email` 要求 |
| createInviteCode(s) | ✅ | 管理者トークン必須 |
| requestPasswordReset / resetPassword | ✅ | ハッシュ化トークン (1h)・列挙耐性・SMTP/log 配送 |
| requestEmailConfirmation / confirmEmail / updateEmail | ✅ | 24h トークン・単発・SMTP/log 配送 |
| deleteAccount | ✅ | パスワード要求・全消去・`#account deleted` |
| listReposByCollection | ✅ | コレクション逆引き (DID カーソル) |
| checkAccountStatus | ✅ | repo/ブロブ実測 | |
| activateAccount / deactivateAccount | ✅ | 自アカウントの停止・再開。`#account` 発火・非 active は書き込み不可 |
| confirmEmail / requestEmailConfirmation | ✅ | 24h 単発トークン・SMTP/log 配送 |
| getServiceAuth | ✅ | ES256K サービス JWT (aud/lxm/exp 上限1h) |

## repo (`com.atproto.repo.*`)

| NSID | 状態 | 備考 |
|---|---|---|
| describeRepo | ✅ | DID Doc (PDS service + `#atproto` Multikey 検証鍵)・collections |
| createRecord / getRecord / putRecord / deleteRecord / listRecords | ✅ | 実 DAG-CBOR CID・署名 commit・`rev` 採番・firehose CAR slice。`swapCommit`/`swapRecord` 対応 |
| applyWrites | ✅ (create のみ完全) | update/delete は結果形のみ、次段で完全化 |
| uploadBlob | ✅ | R2 実体 + D1 インデックス。参照 CID は raw sha2-256 (`bafkrei…`) |
| listMissingBlobs | ✅ | 参照-保持差分 (recordUri 付き・cid カーソル) |
| importRepo | ✅ | 署名・連鎖・再構築検証・`#sync`・空標的 rev 採用 |

## sync (`com.atproto.sync.*`)

| NSID | 状態 | 備考 |
|---|---|---|
| getRepoStatus / listRepos / getLatestCommit | ✅ | 実 commit CID・rev |
| getRepo / getRecord / getBlocks | ✅ | バイナリ CAR。非 active は配布停止 (403)、未知は 404 |
| blob 取得系 | ✅ | 非 active・takedown は秘匿 |
| getBlocks | ✅ | バイナリ CAR サブセット |
| listBlobs / getBlob | ✅ | R2 実体 (blob_router) |
| subscribeRepos | ✅ | WebSocket (event-stream v0: header+payload CBOR 連結)。`cursor` 再開・`FutureCursor`・ポーリング JSON 互換も維持 |
| requestCrawl | ✅ | 自ホスト名の announce を crawlers へ best-effort 転送。作成時にも自動通知 |

## identity (`com.atproto.identity.*`)

| NSID | 状態 | 備考 |
|---|---|---|
| resolveHandle | ✅ | 自 PDS の handle→DID (DB 権威) |
| `/.well-known/atproto-did` | ✅ | Host 別 (ワイルドカード想定) の handle→DID |
| atproto-proxy 転送 | ✅ | 未定義 `/xrpc/*` + ヘッダで他サービスへ転送。ES256K サービス JWT・SSRF ガード |
| PLC 登録 | ✅ | 公開 handle は genesis+submit で実 `did:plc`。loopback は dev DID |
| updateHandle | ✅ | 要認証 |
| getRecommendedDidCredentials | ✅ | 移行先推奨資格情報 | PLC 鍵連携と同時実装 |
| signPlcOperation / submitPlcOperation / requestPlcOperationSignature | ✅ | メール符号・更新op署名・検証付き提出・移行時自動処理 | PLC 連携 (ROADMAP §4) |

## admin (`com.atproto.admin.*`)

| NSID | 状態 | 備考 |
|---|---|---|
| getAccountInfo | ✅ | 管理者トークン必須 |
| updateAccountPassword / updateAccountEmail / updateAccountHandle | ✅ | 管理者代行 (handle 変更は identity 発火) |
| updateAccountSigningKey | ✅ | did:key 採用・空 commit 再署名 |
| deleteAccount (admin) | ✅ | 強制削除 |
| disableAccountInvites / enableAccountInvites | ✅ | フラグ管理 |
| disableInviteCodes / getInviteCodes | ✅ | kill-switch・一覧 |
| getAccountInfos / searchAccounts | ✅ | 一括・検索 |
| getSubjectStatus / updateSubjectStatus | ✅ | takedown/停止の伝播 (記録・blob は非破壊秘匿) |
| sendEmail (admin) | ✅ | 任意送信 |
| レート制限 (429+Retry-After) / /metrics | ✅ | D1 固定ウィンドウ・集計 (+plc_audit) |
| 定期 PLC 監査 (cron) | ✅ | 監査連鎖の再検証・改竄検知 (自動処置なし) |

## OAuth (`/.well-known/*`, `/oauth/*`, `/jwks.json`)

| 経路 | 状態 | 備考 |
|---|---|---|
| oauth-protected-resource / oauth-authorization-server | ✅ | |
| `/.well-known/did.json` / `/jwks.json` | ✅ | JWKS は実 ES256 鍵 (kid=jkt) |
| POST /oauth/par | ✅ | PKCE S256・atproto スコープ強制・client メタデータ検証 (redirect/scope)・confidential アサーション |
| GET /oauth/authorize | ✅ | HTML ログイン+同意画面 / JSON 保留表示 |
| POST /oauth/authorize | ✅ | パスワード認証・login_hint 束縛・単発 code 発行 (302 / JSON) |
| POST /oauth/token | ✅ | authorization_code + refresh_token (回転・失効)。DPoP+nonce 必須・PKCE・client 検証。OAuth 形式エラー + `use_dpop_nonce` |

## その他

| 項目 | 状態 | 備考 |
|---|---|---|
| `GET /xrpc/_health` | ✅ | `{"version","hostname"}` |
| `GET /.well-known/atproto-did` | ✅ | handle→DID テキスト |
| XRPC エラー標準 | ✅ | `{"error","message"}` + 仕様ステータス |
| CORS | ✅ (暫定) | `*` 許可。厳密化は本番設定で |
| `Atproto-Repo-Rev` ヘッダ | ✅ | 全 repo 書き込みに付与 |
| service proxying (`atproto-proxy`) | ✅ | 転送+ES256K JWT・SSRF ガード |
