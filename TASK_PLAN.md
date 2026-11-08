# Longinus — Defensive Posture & Architectural Threat Modeling Platform

## Architecture / Overview

Longinus は、ローカルリポジトリのソースコードおよびインフラ設定を**完全読み取り専用・非破壊**で静的解析し、`@google/genai`（Interactions API Structured Output）と決定論的ルールエンジンを組み合わせて「どの信頼境界が・どの脅威カテゴリ（STRIDE / OWASP ASVS / CWE）に対して構造的に脆いか」を可視化し、**具体的な防御パッチ・ハードニング設定（CSP / WAF / Firestore Rules / IAM / 入力検証）**を提示する予防・防御特化型 Web ダッシュボードである。

```
[Local Repository (Read-Only)]
        │  AT_FDCWD 単一要素 O_NOFOLLOW 検証・親ディレクトリ競合遮断・逐次 opendir 予算上限
        ▼
[1. Multi-Stack Static Scanner (src/scanner.ts, src/rules.ts)]
   ├─ TypeScript / Next.js / Node.js (DOM XSS sinks, CORS, CSP, Cookie, Exec)
   ├─ Flutter / Dart + Firebase (firestore.rules, storage.rules, Cleartext, Functions)
   ├─ Python / Go / Cloud Run (Dockerfile root/ENV, IAM allUsers, shell=True, TLS)
   └─ Generic Supply-Chain & Secrets (Secret 検出・Lockfile・GitHub Actions)
        │
        ▼
[2. Lexical Multiline Secret Redactor & Zero-Snippet Digest (src/redactor.ts)]
   └─ 引用符付きキー・複数行 .env/テンプレート・PEM・YAML をローカルで即時マスクし、外部送信はコード抜粋ゼロの構造テレメトリに限定
        │
        ▼
[3. Closed-Catalog Architectural Threat Modeler (src/geminiAnalyzer.ts)]
   ├─ Live Mode: `@google/genai` Interactions API (`store: false`, 閉世界 Enum カタログ JSON Schema `response_format`)
   │    Models: `gemini-4-argon` (`thinking_level: 'high'` 深層分析・調査) / `gemini-3.8-flash` (`thinking_level: 'low' | 'medium' | 'high'` 自動最適判定)
   └─ Deterministic Mode: API キー未設定時・0トークン指定時も完全動作する STRIDE 構造推論
        │
        ▼
[4. Loopback Hardened Web Server & Quiet Luxury UI (src/server.ts, public/*)]
   └─ `127.0.0.1` 限定バインド・リクエスト毎 CSP Nonce・Trusted Types・Fetch Metadata 保護
```

### Hard Invariants

1. **防御・予防専守（Defensive-Only Invariant）**: 攻撃ペイロード、エクスプロイトコード、インジェクション文字列、PoC クラッシュ入力、認証バイパススクリプト、能動的ネットワーク走査を一切生成・実行しない。出力は「欠陥箇所・根本原因・STRIDE/CWE 分類・防御パッチ」に厳格限定する。
2. **対象リポジトリ完全非変更（Read-Only Target Invariant）**: 監査対象ディレクトリに対して書込み・削除・コード実行（`child_process` 等での対象スクリプト実行）を一切行わない。
3. **ゼロ機密漏洩（Zero Secret Exfiltration Invariant）**: 検出された API キー・秘密鍵・トークンはローカルメモリ上で `[REDACTED]` に置換し、UI 生表示および Gemini API 送信ペイロードから完全に除去する。Gemini API 呼び出しは常に `store: false` を指定する。
4. **ローカル専用セキュアバインド（Loopback & Web Security Invariant）**: Web サーバーは `127.0.0.1` のみにバインドし、Per-request CSP Nonce、`require-trusted-types-for 'script'`、`X-Frame-Options: DENY`、`X-Content-Type-Options: nosniff`、`Sec-Fetch-Site` 検証を強制する。クライアント JS で `innerHTML` を一切使用しない。
5. **最新 Gemini SDK 準拠**: `@google/genai` (`>=2.29.1`) の `ai.interactions.create` + `response_format: { type: "text", mime_type: "application/json", schema }` と `zod` 検証のみを使用し、旧 SDK や廃止済みモデル ID を一切含めない。

### Non-Goals（やらないこと）

- 能動的なペネトレーションテスト、ポートスキャン、ファジング、実際の HTTP 攻撃リクエスト送信。
- バイナリ逆コンパイル・ディスアセンブルによる脆弱性探索。
- 外部ネットワーク公開（`0.0.0.0` バインド）やクラウドへの自動デプロイ・`git commit`・`git push`。
- 不要なサブフォルダ乱造やプロジェクト外へのファイル生成。

---

## Task List

- [x] **Task-1: プロジェクト基盤・型契約・機密リダクション実装**
  - 対象ファイル: `package.json`, `tsconfig.json`, `.gitignore`, `src/types.ts`, `src/redactor.ts`
  - 内容: Node.js 22 + TypeScript + `@google/genai` + `zod` の最小構成を定義し、4スタック共通の脅威モデル型（STRIDE・Finding・TrustBoundary・DefensivePatch）とローカル機密マスク器を実装する。
  - やらないこと: 重厚なフロントエンドバンドラ（Webpack/Next 等）の導入や過剰な依存追加。
- [x] **Task-2: 4スタック横断・決定論的静的解析エンジン実装**
  - 対象ファイル: `src/rules.ts`, `src/scanner.ts`
  - 内容: TS/Next.js/Node.js、Flutter/Dart+Firebase、Python/Go/Cloud Run、汎用サプライチェーン/Secret の静的監査ルール群、安全なパス正規化・シンボリックリンク防御付きファイル走査器、信頼境界（Trust Boundary）自動抽出を実装する。
  - やらないこと: 監査対象コードの動的実行、攻撃ペイロード生成。
- [x] **Task-3: Gemini Interactions API 構造化脅威モデリングエンジン実装**
  - 対象ファイル: `src/geminiAnalyzer.ts`
  - 内容: `@google/genai` の `interactions.create`（`store: false`, JSON Schema 構造化出力）を用いたトークン節約型アーキテクチャ脅威分析（`gemini-3.8-flash` / `gemini-4-argon` 切替対応）と、API キー未設定時の決定論的 STRIDE フォールバック分析、および防御出力ガードレール検証を実装する。
  - やらないこと: 未マスクの生コード全文送信、廃止済み `generateContent` / 旧モデル名の使用。
- [x] **Task-4: ハードニング済みローカル Web サーバー & Quiet Luxury ダッシュボード実装**
  - 対象ファイル: `src/server.ts`, `src/cli.ts`, `public/styles.css`, `public/app.js`
  - 内容: `127.0.0.1` バインド・CSP Nonce・Trusted Types・Fetch Metadata 保護を備えた HTTP サーバーと、LVMH カラーパレット（`#0284c7`, `#059669`, `#e11d48`）・細字タイポグラフィ・STRIDE マトリクス・SVG 信頼境界マップ・コンテナクエリ対応レスポンシブ比較表・`<dialog closedby="any">` 防御パッチ詳細モーダル・Markdown レポート出力を実装する。
  - やらないこと: `innerHTML` の使用、外部 CDN フォント/スクリプト読込（完全ローカル自己完結でゼロ外部通信リークを実現）。
- [x] **Task-5: 決定論的ユニットテスト・ベンチマーク Fixture・Pixel Visual Gate 検証**
  - 対象ファイル: `test/scanner.test.ts`, `test/fixtures/sample-polyglot-app/*`, `.agents/pixel-visual-gate.json`
  - 内容: 4スタックの脆弱な設定例（安全なダミー設定のみ）を含む検証用 Fixture、機密マスク・パストラバーサル拒否・CSP/ヘッダ検証・Gemini スキーマ検証のユニットテスト、およびモバイル/デスクトップ両画面の Pixel Visual Gate 検証を実施する。
  - やらないこと: 実在の認証情報や攻撃スクリプトのテストデータ化。

---

## Acceptance Criteria

以下の全コマンドが終了コード `0` で通過すること：

1. 型検査・ビルド検証: `pnpm run build`
2. ユニット＆セキュリティ不変条件テスト（Node 標準テストランナー）: `pnpm test`
3. Pixel Visual Gate ツール自己診断 & デスクトップ/モバイル UI 検証:
   - `node ~/.gemini/config/scripts/pixel-visual-gate.mjs --self-test`
   - サーバー起動状態で `node ~/.gemini/config/scripts/pixel-visual-gate.mjs --config .agents/pixel-visual-gate.json --base-url http://127.0.0.1:4310`
