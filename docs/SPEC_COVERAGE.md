# SPEC_COVERAGE — エンドポイント対応表

凡例: ✅ 実装 / ⬜ 対象外 (別サービスの責務として文書化)。Lexicon 原典は
[bluesky-social/atproto](https://github.com/bluesky-social/atproto) `lexicons/com/atproto/*`。
重複・陳腐化行は Round 13 で整理。各行は E2E (`scripts/e2e_*.py`) または単体試験で検証済み。

## server (`com.atproto.server.*`)

| NSID | 状態 | 備考 |
|---|---|---|
| describeServer | ✅ | +blobUploadLimit |
| createAccount | ✅ | argon2id・k256 鍵・genesis commit・#account/#sync。`recoveryKey`/`plcOp` 移行対応・didDoc 返却・HandleNotAvailable |
| createSession / refreshSession / deleteSession | ✅ (互換) | argon2 検証・HS256 ペア (access 1h/refresh 7d)。refresh 回転・epoch 失効 |
| getSession | ✅ | didDoc/emailAuthFactor/status。OAuth 時 email は `transition:email` 要求 |
| createInviteCode(s) / getAccountInviteCodes | ✅ | 管理者発行・単発消費・kill-switch |
| requestPasswordReset / resetPassword | ✅ | ハッシュ化トークン (1h)・列挙耐性・SMTP/log 配送 |
| requestEmailConfirmation / confirmEmail / updateEmail / requestEmailUpdate | ✅ | 24h トークン・単発・SMTP/log 配送 |
| requestAccountDelete / deleteAccount | ✅ | トークン+パスワード・全消去・`#account deleted`・admin 強制削除あり |
| createAppPassword / listAppPasswords / revokeAppPassword | ✅ | 権限ゲート付き互換ログイン |
| checkAccountStatus | ✅ | repo/ブロブ実測 |
| activateAccount / deactivateAccount | ✅ | `#account` 発火・非 active は書き込み不可・sync 配布停止 |
| getServiceAuth | ✅ | ES256K サービス JWT (aud/lxm/exp 上限1h) |

## repo (`com.atproto.repo.*`)

| NSID | 状態 | 備考 |
|---|---|---|
| describeRepo | ✅ | DID Doc (PDS service + `#atproto` Multikey)・collections |
| createRecord / getRecord / putRecord / deleteRecord / listRecords | ✅ | 実 DAG-CBOR CID・署名 commit・`rev` 採番・firehose slice。`swapCommit`/`swapRecord` 対応 |
| applyWrites | ✅ | create/update/delete を単一 commit 化 (prev 検証付き) |
| uploadBlob | ✅ | R2 実体 + D1 インデックス。raw sha2-256 (`bafkrei…`)・MIME sniffing |
| listMissingBlobs | ✅ | 参照-保持差分 (recordUri 付き・cid カーソル) |
| importRepo | ✅ | 署名・連鎖・再構築検証・`#sync`・空標的 rev 採用・時間制限 |

## sync (`com.atproto.sync.*`)

| NSID | 状態 | 備考 |
|---|---|---|
| getRepoStatus / listRepos / getLatestCommit / getHead | ✅ | 実 commit CID・rev。getHead は非推奨別名 |
| getRepo / getCheckout / getRecord / getBlocks | ✅ | バイナリ CAR。非 active は配布停止 (403)、未知は 404。getCheckout は非推奨別名 |
| listBlobs / getBlob | ✅ | R2 実体。非 active・takedown は秘匿 |
| listReposByCollection | ✅ | コレクション逆引き (DID カーソル) |
| subscribeRepos | ✅ | WebSocket (event-stream v0)。`cursor` 再開・`FutureCursor`・ポーリング JSON 互換 |
| requestCrawl | ✅ | crawlers へ best-effort 転送。作成時にも自動通知 |
| getHostStatus / listHosts / notifyOfUpdate | ⬜ | Relay 側実装 (PDS 範囲外)。notifyOfUpdate は非推奨 |

## identity (`com.atproto.identity.*`)

| NSID | 状態 | 備考 |
|---|---|---|
| resolveHandle / resolveDid / resolveIdentity / refreshIdentity | ✅ | DB 権威+PLC/DoH 連合・KV キャッシュ |
| updateHandle | ✅ | 要認証 (atproto-only は読取専用) |
| getRecommendedDidCredentials | ✅ | 移行先推奨資格情報 |
| requestPlcOperationSignature / signPlcOperation / submitPlcOperation | ✅ | メール符号・更新 op 署名・検証付き提出 |
| PLC 登録 | ✅ | 公開 handle は genesis+submit で実 `did:plc`。loopback は dev DID |

## admin (`com.atproto.admin.*`)

| NSID | 状態 | 備考 |
|---|---|---|
| getAccountInfo(s) / searchAccounts | ✅ | 管理者トークン必須 |
| updateAccount{Password,Email,Handle,SigningKey} | ✅ | 代行 (handle 変更は identity 発火・鍵変更は再 commit) |
| deleteAccount (admin) | ✅ | 強制削除 |
| disableAccountInvites / enableAccountInvites | ✅ | フラグ管理 |
| disableInviteCodes / getInviteCodes | ✅ | kill-switch・一覧 |
| getSubjectStatus / updateSubjectStatus | ✅ | takedown/停止の伝播 (記録・blob は非破壊秘匿) |
| sendEmail (admin) | ✅ | 任意送信 |

## OAuth (`/.well-known/*`, `/oauth/*`, `/jwks.json`)

| 経路 | 状態 | 備考 |
|---|---|---|
| oauth-protected-resource / oauth-authorization-server | ✅ | |
| `/.well-known/did.json` / `/jwks.json` | ✅ | 実 ES256 鍵 (kid=jkt) |
| POST /oauth/par | ✅ | 単発・PKCE S256・client 検証・confidential アサーション |
| GET /oauth/authorize | ✅ | HTML ログイン+同意 / JSON 保留表示 |
| POST /oauth/authorize | ✅ | パスワード認証・login_hint 束縛・単発 code 発行 |
| POST /oauth/token | ✅ | authorization_code + refresh_token (回転)。DPoP+nonce 必須・PKCE・assertion jti 使い捨て |

## 運用・横断

| 項目 | 状態 | 備考 |
|---|---|---|
| `GET /xrpc/_health` / `GET /metrics` | ✅ | 集計 (+plc_audit) |
| `GET /.well-known/atproto-did` | ✅ | handle→DID テキスト |
| XRPC エラー標準 | ✅ | `{"error","message"}` + 仕様ステータス |
| CORS | ✅ (暫定) | `*` 許可。厳密化は本番設定で |
| `Atproto-Repo-Rev` ヘッダ | ✅ | 全 repo 書き込みに付与 |
| service proxying (`atproto-proxy`) | ✅ | 転送+ES256K JWT・SSRF ガード |
| レート制限 (429+Retry-After) | ✅ | D1 固定ウィンドウ (作成/セッション/OAuth/書込/プロキシ/メール/import) |
| 定期 PLC 監査 (cron) | ✅ | 監査連鎖の再検証・改竄検知 (自動処置なし) |
| OAuth リプレイ対策 | ✅ | DPoP/assertion jti (KV 180s)・code 単発・refresh 回転・PAR 単発 |
| SMTP | ✅ | STARTTLS・30s タイムアウト・未設定時ログモード |

## 対象外 (別サービスの責務)

| 項目 | 理由 |
|---|---|
| `app.bsky.*` / フィード・ラベラー適用 | AppView の責務。PDS は原記録の配布に専念 |
| `com.atproto.moderation.*` / Ozone | モデレーションサービスの責務。PDS 側は takedown 伝播で連携 |
| `com.atproto.sync.getHostStatus/listHosts/notifyOfUpdate` | Relay 実装 |
| 動画トランスコード・サムネイル | CDN/AppView の責務。PDS はバイト保管+上限 |
| OAuth client 信頼 UI・承認画面の装飾 | 最小実装で互換。磨き上げは今後 |
