# ROADMAP — フル互換 PDS への道

ゴール (選択済み): **フル互換 PDS** / ストレージ **D1+R2** / 認証 **OAuth のみ**
(互換セッションは移行期のみ)。各項目は参照 Spec と受入条件付き。

## 0. 済み (このリポジトリ)

- XRPC 基盤: `{"error","message"}` 標準・CORS・`atproto-proxy` パース ([XRPC](https://atproto.com/specs/xrpc))
- 識別子検証 + 単体テスト: NSID / TID / DID / handle / record-key / AT-URI
- `server.describeServer/createAccount` (D1)・互換 `createSession/refreshSession/getSession`
- 招待コード (`createInviteCode(s)`, 管理者トークン)
- `repo.*` CRUD + `applyWrites(create)`・`rev` (TID) 採番・`repo_root` 更新
- `sync.*` 取得系: `getRepoStatus/listRepos/getRepo/getRecord/getLatestCommit` + `subscribeRepos` ポーリング互換
- blob: `uploadBlob/listBlobs/getBlob` (R2 実体 + D1 インデックス)
- `identity.resolveHandle/updateHandle` + `/.well-known/atproto-did`
- OAuth: `oauth-protected-resource` / `oauth-authorization-server` / `did.json` /
  `jwks.json` (空で fail-closed) / `POST /oauth/par` (PKCE・atproto スコープ強制) /
  `GET /oauth/authorize` (同意画面スタブ)
- D1 マイグレーション・`wrangler deploy --dry-run` 通過・wasm リリースビルド通過

## 1. Repository 完全性 (Spec: [repository](https://atproto.com/specs/repository))

- [ ] DRISL CBOR エンコーダ + blessed CID (dag-cbor/sha2-256/base32) 生成・検証
- [ ] MST 実装: 挿入/削除・depth 検証・ノードあたりエントリ上限 (DoS 対策)
- [ ] 署名付き commit (`sig` over unsigned-commit sha256, k256/p256) と鍵ローテーション時 re-commit
- [ ] CAR v1 バイナリ export (`getRepo/getBlocks`) と `blocks` 2MB / record 1MB / ops 200 上限制御
- [ ] diff (CAR slice) + operation-inversion 検証 (test vectors: atproto-interop-tests)
- [ ] `pseudo_cid_for_json` / `mst:{rev}` プレースホルダの置換 (現状 `dev…` 接頭辞で明示)

## 2. Sync / Firehose (Spec: [sync](https://atproto.com/specs/sync), [event-stream](https://atproto.com/specs/event-stream))

- [ ] `#commit/#sync/#identity/#account` の CBOR + WebSocket 本体 (`wss://…/subscribeRepos?cursor=`)
- [ ] `seq` 永続化の競合対策 (D1 単調採番の検証・Relay desync 修復手順の文書化)
- [ ] `Atproto-Repo-Rev` レスポンスヘッダ
- [ ] record-level resync ワーカー設計 (外部 Relay 向けは別サービス)

## 3. OAuth 完成 (Spec: [oauth](https://atproto.com/specs/oauth))

- [ ] DPoP proof 検証 + `jkt` バインド・サーバ発行 nonce (KV)
- [ ] `/oauth/token`: authorization_code → access/refresh 発行 (`sub`=DID, `scope` 必須返却)
- [ ] refresh_token ローテーション・失効、機密クライアント `private_key_jwt` (ES256)
- [ ] `jwks.json` 実鍵公開 (ES256K + ES256、ローテーション運用)
- [ ] client metadata 取得・検証・キャッシュ (SSRF 対策の hardened fetch)
- [ ] 認可 UI (PDS_SERVICE_NAME ブランディング・scope 表示・trusted client 表示制御)
- [ ] `transition:*` スコープの段階廃止計画
- [ ] 互換セッション (password) の無効化フラグ (OAuth のみ運用へ)

## 4. Identity / 連合 (Specs: [did](https://atproto.com/specs/did), [handle](https://atproto.com/specs/handle), [account](https://atproto.com/specs/account))

- [ ] `did:plc` 解決 + `did:web` 解決・DID Document 検証 (署名鍵 `#atproto` Multikey 新旧形式)
- [ ] handle 双方向検証 (DNS TXT + `/.well-known/atproto-did`)
- [ ] PLC 監査ログ連携 (rotation key 運用・`PDS_PLC_ROTATION_KEY_*`)
- [ ] アカウント移行フロー (`#identity/#account` 発火順・旧/新 PDS 状態遷移)
- [ ] 取下げ/停止/削除のホスティング状態伝播・Relay 通知 (`PDS_CRAWLERS`)

## 5. AppView/Relay 連携・運用

- [ ] service proxying (`atproto-proxy` 転送 + inter-service JWT `lxm/aud/kid`)
- [ ] メール (SMTP) 検証・パスワードリセット・`checkAccountStatus`
- [ ] `com.atproto.admin.*` 拡充・監査ログ
- [ ] レート制限・サイズ制限の本番値・OpenTelemetry メトリクス
- [ ] バックアップ/リストア (repo CAR + D1 ダンプ)・Bsky app 接続 E2E

## 非目標 (PDS の外)

- 非公開データ・E2E 暗号 DM・検索/フィード集約 (AppView の責務)
- `did:plc` ディレクトリ自体の運営 (利用のみ)
