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

- [x] DRISL CBOR エンコーダ + blessed CID (dag-cbor/sha2-256/base32) 生成・検証 (`src/cbor.rs`, `src/cid.rs`; RFC7049 ベクタ + Python 独立既知値でテスト)
- [x] MST 実装: 決定論リビルド (挿入順不変)・depth 検証・ノード parse (参照 TS 実装と同形。言語間ルートベクタ一致済み)
- [x] 署名付き commit (`sig` over unsigned-commit sha256, k256 決定論署名; p256 検証対応) とアカウント作成時鍵生成 + DID Multikey 公開 + 旧行の鍵バックフィル
- [x] CAR v1 バイナリ export (`getRepo/getBlocks`) と record 1MB 上限制御 (`MAX_RECORD_BYTES`)
- [ ] diff (CAR slice) + operation-inversion 検証 (test vectors: atproto-interop-tests) — commit イベントは commit+全 MST ノード+変更レコードの slice を搬送 (検証可能)、厳密な最小 diff は次段
- [x] `pseudo_cid_for_json` / `mst:{rev}` プレースホルダの置換 (旧 `dev…` 行は自己修復で実 CID 化)
- [ ] MST ノードあたりエントリ上限・CAR streamable 順序・鍵ローテーション時 re-commit

## 2. Sync / Firehose (Spec: [sync](https://atproto.com/specs/sync), [event-stream](https://atproto.com/specs/event-stream))

- [ ] `#commit/#sync/#identity/#account` の CBOR + WebSocket 本体 (`wss://…/subscribeRepos?cursor=`)
- [ ] `seq` 永続化の競合対策 (D1 単調採番の検証・Relay desync 修復手順の文書化)
- [x] `Atproto-Repo-Rev` レスポンスヘッダ (全 repo 書き込みに付与)
- [ ] record-level resync ワーカー設計 (外部 Relay 向けは別サービス)

## 3. OAuth 完成 (Spec: [oauth](https://atproto.com/specs/oauth))

- [x] DPoP proof 検証 (ES256・htm/htu/iat/jti/ath) + `jkt` バインド・サーバ発行 nonce (KV 単発) — `scripts/e2e_oauth.py` でループ検証
- [x] `/oauth/token`: authorization_code → access/refresh 発行 (`sub`=DID, `scope`・`token_type: DPoP` 返却)、PKCE 照合・redirect 照合・PAR 有効期限・code 単発
- [x] refresh_token ローテーション・失効 (使用済み refresh は `invalid_grant`)
- [x] 機密クライアント `private_key_jwt` (ES256) 検証 (jwks/jwks_uri)
- [x] `jwks.json` 実鍵公開 (ES256 サーバ鍵、D1 永続・初回生成)
- [x] client metadata 取得・検証・キャッシュ (https 強制・loopback 例外・32KB 上限・KV 1h)
- [x] 認可 UI (HTML ログイン+同意画面。PDS_SERVICE_NAME ブランディングは任意項目として残存)
- [x] 互換セッションの署名化 (HS256 + `PDS_JWT_SECRET`)・argon2id パスワード検証・`getSession` の Lexicon 形修正・OAuth 時の email 非表示 (`transition:email` のみ)
- [x] handle/email の UNIQUE 制約 (migration 0003; email 未設定は NULL)
- [ ] `transition:*` スコープの段階廃止計画
- [ ] 互換セッション (password) の無効化フラグ (OAuth のみ運用へ)
- [ ] ES256K DPoP/JWKS・鍵ローテーション運用・trusted client 表示制御

## 4. Identity / 連合 (Specs: [did](https://atproto.com/specs/did), [handle](https://atproto.com/specs/handle), [account](https://atproto.com/specs/account))

- [x] `did:plc` 解決 + `did:web` 解決 (localhost ポート対応)・DID Document 検証 (署名鍵 `#atproto` Multikey 新旧形式)・KV キャッシュ (`src/identity.rs`)
- [x] handle 双方向検証 (well-known + DNS TXT over DoH)。自ドメインは DB 権威 + 文書主張確認。`describeRepo.handleIsCorrect` が live 判定
- [x] PLC genesis 生成・low-S 署名・DID 計算・submit + rotation 鍵保存。公開 handle の signup で実登録 (`scripts/e2e_plc.py` がスタブ相手に検証)。loopback は dev DID
- [x] Relay 通知: 作成時 + `requestCrawl` 経由の best-effort announce (`PDS_CRAWLERS`)
- [ ] PLC 監査ログ連携・rotation 鍵の secret store 移管・`PDS_PLC_ROTATION_KEY_*` 運用
- [ ] アカウント移行フロー (`#identity/#account` 発火順・旧/新 PDS 状態遷移)
- [ ] 取下げ/停止/削除のホスティング状態伝播

## 5. AppView/Relay 連携・運用

- [x] service proxying (`atproto-proxy` 転送 + inter-service JWT `lxm/aud` ES256K・SSRF ガード)。スタブ AppView 相手に中継+署名検証の E2E 済み (`scripts/e2e_proxy.py`)
- [ ] メール (SMTP) 検証・パスワードリセット・`checkAccountStatus`
- [ ] `com.atproto.admin.*` 拡充・監査ログ
- [ ] レート制限・サイズ制限の本番値・OpenTelemetry メトリクス
- [ ] バックアップ/リストア (repo CAR + D1 ダンプ)・Bsky app 接続 E2E

## 非目標 (PDS の外)

- 非公開データ・E2E 暗号 DM・検索/フィード集約 (AppView の責務)
- `did:plc` ディレクトリ自体の運営 (利用のみ)
