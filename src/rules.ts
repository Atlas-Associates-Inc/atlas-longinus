import path from 'node:path';
import { PUBLIC_ENV_SECRET_RE } from './redactor.js';
import type { SecurityFinding, SeverityLevel, StackDomain, StrideCategory } from './types.js';

export interface FileContext {
  relativePath: string;
  baseName: string;
  ext: string;
  redactedContent: string;
  redactedLines: readonly string[];
  redactedLineNumbers: readonly number[];
}

export interface StaticRule {
  ruleId: string;
  title: string;
  stack: StackDomain;
  severity: SeverityLevel;
  stride: StrideCategory;
  cwe: string;
  owaspAsvs: string;
  appliesTo: (ctx: FileContext) => boolean;
  evaluate: (ctx: FileContext) => Array<{ line: number; snippet: string }>;
  rootCause: string;
  defensivePatch: string;
  verificationHint: string;
}

const JS_TS_EXTS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs']);

function isCommentOrRegexDef(trimmedLine: string): boolean {
  return (
    trimmedLine.startsWith('//') ||
    trimmedLine.startsWith('*') ||
    trimmedLine.startsWith('/*') ||
    trimmedLine.startsWith('regex:') ||
    trimmedLine.startsWith('pattern:')
  );
}

function sliceRedactedWindow(lines: readonly string[], zeroBasedIndex: number): string {
  const start = Math.max(0, zeroBasedIndex - 1);
  const end = Math.min(lines.length, zeroBasedIndex + 2);
  return lines.slice(start, end).join('\n');
}

function findMatchingLines(
  ctx: FileContext,
  matcher: (line: string, lineIndex: number, allLines: readonly string[]) => boolean,
  maxPerFile = 3,
): Array<{ line: number; snippet: string }> {
  const hits: Array<{ line: number; snippet: string }> = [];
  for (let i = 0; i < ctx.redactedLines.length; i++) {
    const line = ctx.redactedLines[i] ?? '';
    const trimmed = line.trim();
    if (!trimmed || isCommentOrRegexDef(trimmed)) continue;
    if (matcher(line, i, ctx.redactedLines)) {
      hits.push({
        line: i + 1,
        snippet: sliceRedactedWindow(ctx.redactedLines, i),
      });
      if (hits.length >= maxPerFile) break;
    }
  }
  return hits;
}

export const STATIC_RULES: readonly StaticRule[] = [
  // =========================================================================
  // 1. TypeScript / Next.js / Node.js (ts-web-api)
  // =========================================================================
  {
    ruleId: 'LNG-TS-001',
    title: '未サニタイズ DOM シンクへの直接代入（DOM XSS 露出）',
    stack: 'ts-web-api',
    severity: 'high',
    stride: 'Tampering',
    cwe: 'CWE-79',
    owaspAsvs: 'V5.3.3 Output Encoding & Trusted Types',
    appliesTo: (ctx) => JS_TS_EXTS.has(ctx.ext) || ctx.ext === '.html',
    evaluate: (ctx) =>
      findMatchingLines(
        ctx,
        (line) =>
          /\.(?:innerHTML|outerHTML)\s*\+?=\s*/.test(line) ||
          /\bdangerouslySetInnerHTML\s*=\s*\{/.test(line) ||
          /\bdocument\.write\s*\(/.test(line),
      ),
    rootCause:
      '信頼境界外の文字列が HTML パーサシンク（innerHTML / dangerouslySetInnerHTML / document.write）へ直接渡されると、任意の Script 実行（DOM-based XSS）が成立する構造になっています。',
    defensivePatch: `// 防御パッチ: textContent または Sanitizer API + CSP Trusted Types を強制
element.textContent = untrustedInput;

// サーバーレスポンスヘッダで Trusted Types と Nonce CSP を強制:
// Content-Security-Policy: script-src 'nonce-<RANDOM>' 'strict-dynamic'; object-src 'none'; base-uri 'none'; require-trusted-types-for 'script';`,
    verificationHint:
      '静的 grep で innerHTML / dangerouslySetInnerHTML が 0 件であること、およびレスポンスヘッダに require-trusted-types-for が含まれることを確認。',
  },
  {
    ruleId: 'LNG-TS-002',
    title: '動的コード評価またはシェル補間実行（コマンド・コード注入露出）',
    stack: 'ts-web-api',
    severity: 'critical',
    stride: 'Elevation of Privilege',
    cwe: 'CWE-78',
    owaspAsvs: 'V5.3.8 OS Command & Dynamic Execution Prevention',
    appliesTo: (ctx) => JS_TS_EXTS.has(ctx.ext),
    evaluate: (ctx) =>
      findMatchingLines(
        ctx,
        (line) =>
          /(?:^|[^\w.])eval\s*\(/.test(line) ||
          /\bnew\s+Function\s*\(/.test(line) ||
          /\b(?:exec|execSync)\s*\(\s*`[^`]*\$\{/.test(line),
      ),
    rootCause:
      'eval / new Function またはテンプレート文字列を用いた exec() はシェルメタ文字を解釈するため、入力値次第でサーバー権限での任意コマンド実行に至る危険があります。',
    defensivePatch: `// 防御パッチ: シェルを介さない execFile と固定引数配列 + Zod 厳格検証を使用
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const execFileAsync = promisify(execFile);

const safeArg = z.string().regex(/^[a-zA-Z0-9._-]+$/).parse(inputArg);
await execFileAsync('/usr/bin/git', ['status', '--', safeArg], { shell: false, timeout: 5000 });`,
    verificationHint: 'eval / new Function / 文字列補間付き exec を排除し、shell: false の execFile のみに統一されていることをテストで検証。',
  },
  {
    ruleId: 'LNG-TS-003',
    title: 'ワイルドカード CORS 許可構成（クロスオリジン情報読取リスク）',
    stack: 'ts-web-api',
    severity: 'high',
    stride: 'Information Disclosure',
    cwe: 'CWE-942',
    owaspAsvs: 'V14.5.3 Cross-Origin Resource Sharing',
    appliesTo: (ctx) => JS_TS_EXTS.has(ctx.ext) || ctx.baseName.startsWith('next.config'),
    evaluate: (ctx) =>
      findMatchingLines(
        ctx,
        (line) =>
          /['"]Access-Control-Allow-Origin['"]\s*,\s*['"]\*['"]/.test(line) ||
          /\borigin\s*:\s*(?:['"]\*['"]|true)\b/.test(line),
      ),
    rootCause:
      'Access-Control-Allow-Origin に * や無条件反射（origin: true）を設定すると、悪意ある外部サイトから API 応答を読み取られる恐れがあります。',
    defensivePatch: `// 防御パッチ: 明示的な許可オリジン Allowlist と Vary: Origin、Sec-Fetch-Site 検証を併用
const ALLOWED_ORIGINS = new Set(['https://app.example.com']);
const origin = req.headers.origin;
res.setHeader('Vary', 'Origin, Sec-Fetch-Site');
if (origin && ALLOWED_ORIGINS.has(origin)) {
  res.setHeader('Access-Control-Allow-Origin', origin);
}`,
    verificationHint: '未許可 Origin ヘッダを付与した OPTIONS/GET リクエストに対し Access-Control-Allow-Origin が返らないことを単体テストで確認。',
  },
  {
    ruleId: 'LNG-TS-004',
    title: 'クライアント公開プレフィックス環境変数への機密キー混入',
    stack: 'ts-web-api',
    severity: 'critical',
    stride: 'Information Disclosure',
    cwe: 'CWE-200',
    owaspAsvs: 'V2.10.4 Secret Segregation',
    appliesTo: (ctx) =>
      JS_TS_EXTS.has(ctx.ext) || ctx.baseName.startsWith('.env') || ctx.baseName.startsWith('next.config'),
    evaluate: (ctx) => findMatchingLines(ctx, (line) => PUBLIC_ENV_SECRET_RE.test(line)),
    rootCause:
      'NEXT_PUBLIC_ や VITE_ プレフィックス付きの環境変数はフロントエンド JS バンドルに平文埋め込みされるため、全ユーザーに秘密鍵が露出します。',
    defensivePatch: `// 防御パッチ: 公開プレフィックスを削除し、サーバー専用 Route Handler / Cloud Run 側でのみ Secret Manager から参照
import 'server-only';
const serviceSecret = process.env.INTERNAL_SERVICE_SECRET; // NEXT_PUBLIC_ 絶対禁止`,
    verificationHint: 'クライアントビルド成果物内に SECRET / PRIVATE / SERVICE_ROLE 文字列が含まれないことをビルドゲートで検査。',
  },
  {
    ruleId: 'LNG-TS-005',
    title: 'postMessage のワイルドカード送信または送信元 Origin 未検証',
    stack: 'ts-web-api',
    severity: 'medium',
    stride: 'Spoofing',
    cwe: 'CWE-346',
    owaspAsvs: 'V14.5.4 Origin Validation',
    appliesTo: (ctx) => JS_TS_EXTS.has(ctx.ext),
    evaluate: (ctx) =>
      findMatchingLines(ctx, (line) => /\.postMessage\s*\([^,]+,\s*['"]\*['"]\s*\)/.test(line)),
    rootCause:
      'targetOrigin に "*" を指定した postMessage は、意図しない第三者フレームやリダイレクト先オリジンへ機密データを漏洩させます。',
    defensivePatch: `// 防御パッチ: 厳格な targetOrigin 指定と受信側 event.origin の完全一致検証
targetWindow.postMessage({ type: 'SYNC_STATE' }, 'https://trusted.example.com');

window.addEventListener('message', (event) => {
  if (event.origin !== 'https://trusted.example.com') return;
  // Zod 等で event.data のスキーマを検証してから処理
});`,
    verificationHint: 'postMessage 呼び出しの第2引数がすべて固定オリジン定数であることを確認。',
  },

  // =========================================================================
  // 2. Flutter / Dart + Firebase (flutter-firebase)
  // =========================================================================
  {
    ruleId: 'LNG-FB-001',
    title: 'Firestore / Storage Rules の無条件許可または全階層ワイルドカード書込み',
    stack: 'flutter-firebase',
    severity: 'critical',
    stride: 'Elevation of Privilege',
    cwe: 'CWE-284',
    owaspAsvs: 'V4.1.3 Principle of Least Privilege (Deny by Default)',
    appliesTo: (ctx) => ctx.ext === '.rules',
    evaluate: (ctx) =>
      findMatchingLines(
        ctx,
        (line) =>
          /\ballow\s+[^:;]*:\s*if\s+true\s*;/.test(line) ||
          /match\s+\/\{document=\*\*\}/.test(line),
      ),
    rootCause:
      '`if true` またはルート `{document=**}` 再帰ワイルドカードにより、未認証の外部クライアントから全コレクションの閲覧・改ざん・削除（課金枯渇攻撃を含む）が可能になっています。',
    defensivePatch: `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // デフォルト全拒否（Deny by Default）
    match /{document=**} {
      allow read, write: if false;
    }

    // コレクション単位の所有者一致 + フィールドホワイトリスト検証
    match /users/{userId} {
      allow read: if request.auth != null && request.auth.uid == userId;
      allow create, update: if request.auth != null
        && request.auth.uid == userId
        && request.resource.data.keys().hasOnly(['displayName', 'updatedAt'])
        && request.resource.data.displayName is string
        && request.resource.data.displayName.size() <= 80;
      allow delete: if false;
    }
  }
}`,
    verificationHint:
      '@firebase/rules-unit-testing エミュレータで未認証ユーザーおよび他 UID からの read/write が PERMISSION_DENIED になることを検証。',
  },
  {
    ruleId: 'LNG-FB-002',
    title: 'Firestore Rules の認証のみチェックによる水平権限昇格（IDOR）露出',
    stack: 'flutter-firebase',
    severity: 'high',
    stride: 'Tampering',
    cwe: 'CWE-285',
    owaspAsvs: 'V4.2.1 Object-Level Access Control',
    appliesTo: (ctx) => ctx.ext === '.rules',
    evaluate: (ctx) =>
      findMatchingLines(ctx, (line) =>
        /\ballow\s+(?:write|update|delete|create|read,\s*write)\s*:\s*if\s+request\.auth\s*!=\s*null\s*;/.test(
          line,
        ),
      ),
    rootCause:
      '`request.auth != null` のみでは匿名認証や新規登録した任意の攻撃者アカウントが他ユーザーのドキュメントを上書き・削除でき、テナント分離とスキーマ検証が欠落しています。',
    defensivePatch: `// 防御パッチ: UID 所有権検証 + ロール/フィールド不変条件（role 自己昇格防止）を追加
allow update: if request.auth != null
  && resource.data.ownerId == request.auth.uid
  && request.resource.data.ownerId == resource.data.ownerId
  && !request.resource.data.diff(resource.data).affectedKeys().hasAny(['role', 'plan', 'isAdmin']);`,
    verificationHint: '別 UID でログインしたクライアントからの他者ドキュメント update/delete が拒否されることを Rules テストで確認。',
  },
  {
    ruleId: 'LNG-FB-003',
    title: 'Firebase Functions onRequest エンドポイントの App Check / 認証検証欠落',
    stack: 'flutter-firebase',
    severity: 'high',
    stride: 'Spoofing',
    cwe: 'CWE-306',
    owaspAsvs: 'V4.1.1 Enforced Access Control at Trusted Service Layer',
    appliesTo: (ctx) => JS_TS_EXTS.has(ctx.ext) && ctx.redactedContent.includes('firebase-functions'),
    evaluate: (ctx) => {
      if (!/\bonRequest\s*\(/.test(ctx.redactedContent)) return [];
      const hasAuthVerification =
        ctx.redactedContent.includes('verifyIdToken') ||
        ctx.redactedContent.includes('verifySessionCookie') ||
        ctx.redactedContent.includes('appCheck') ||
        ctx.redactedContent.includes('enforceAppCheck');
      if (hasAuthVerification) return [];
      return findMatchingLines(ctx, (line) => /\bonRequest\s*\(/.test(line), 2);
    },
    rootCause:
      '公開 HTTP トリガー（onRequest）に Firebase Auth トークン検証および App Check 強制がないため、正規アプリ外からの直接リプレイ・自動課金枯渇リクエストを防げません。',
    defensivePatch: `// 防御パッチ: onCall + enforceAppCheck: true または ID トークン検証を必須化
import { onCall, HttpsError } from 'firebase-functions/v2/https';

export const secureAction = onCall(
  { region: 'asia-northeast1', enforceAppCheck: true, cors: ['https://app.example.com'] },
  async (request) => {
    if (!request.auth?.uid) {
      throw new HttpsError('unauthenticated', 'Authentication required.');
    }
  },
);`,
    verificationHint: 'Authorization ヘッダまたは X-Firebase-AppCheck なしの呼び出しが 401/403 で即時拒否されることを確認。',
  },
  {
    ruleId: 'LNG-FB-004',
    title: 'Flutter / モバイル通信の TLS 証明書検証無効化または平文 HTTP 許可',
    stack: 'flutter-firebase',
    severity: 'high',
    stride: 'Information Disclosure',
    cwe: 'CWE-295',
    owaspAsvs: 'V9.2.1 Strict TLS Certificate Validation',
    appliesTo: (ctx) =>
      ctx.ext === '.dart' || ctx.baseName === 'AndroidManifest.xml' || ctx.baseName === 'Info.plist',
    evaluate: (ctx) =>
      findMatchingLines(
        ctx,
        (line, idx, all) =>
          /\bbadCertificateCallback\b/.test(line) ||
          /usesCleartextTraffic\s*=\s*["']true["']/.test(line) ||
          (/NSAllowsArbitraryLoads/.test(line) && /<true\s*\/>/.test(all[idx + 1] ?? '')),
      ),
    rootCause:
      'badCertificateCallback や平文 HTTP 許可（usesCleartextTraffic / NSAllowsArbitraryLoads）は中間者攻撃（MITM）によるトークン傍受・応答改ざんを許します。',
    defensivePatch: `// 防御パッチ: badCertificateCallback を完全削除し OS 標準 Trust Store + HTTPS のみ強制
// AndroidManifest.xml: android:usesCleartextTraffic="false"
// Info.plist: NSAllowsArbitraryLoads を削除（デフォルト false 維持）`,
    verificationHint: '自己署名証明書や http:// スキームへの接続がハンドシェイク段階で例外拒否されることを確認。',
  },
  {
    ruleId: 'LNG-FB-005',
    title: 'Flutter SharedPreferences への認証トークン・機密情報の平文保存',
    stack: 'flutter-firebase',
    severity: 'medium',
    stride: 'Information Disclosure',
    cwe: 'CWE-312',
    owaspAsvs: 'V8.2.2 Client-Side Secure Storage',
    appliesTo: (ctx) => ctx.ext === '.dart',
    evaluate: (ctx) =>
      findMatchingLines(ctx, (line) =>
        /\bsetString\s*\(\s*['"][^'"]*(?:token|secret|password|api_key|privateKey)[^'"]*['"]/i.test(line),
      ),
    rootCause:
      'SharedPreferences は端末上に暗号化されない XML/plist として保存されるため、バックアップ抽出や侵害端末からセッション鍵が平文で流出します。',
    defensivePatch: `// 防御パッチ: Keychain / Android Keystore ハードウェア保護付きの FlutterSecureStorage を使用
const storage = FlutterSecureStorage(
  aOptions: AndroidOptions(encryptedSharedPreferences: true),
  iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock_this_device),
);
await storage.write(key: 'session_token', value: token);`,
    verificationHint: 'SharedPreferences への機密キー保存箇所が 0 件であり、FlutterSecureStorage ラッパ経由のみであることを確認。',
  },

  // =========================================================================
  // 3. Python / Go / Cloud Run / Docker (python-go-cloud)
  // =========================================================================
  {
    ruleId: 'LNG-CLD-001',
    title: 'Python シェル経由コマンド実行または安全でないデシリアライズ',
    stack: 'python-go-cloud',
    severity: 'critical',
    stride: 'Elevation of Privilege',
    cwe: 'CWE-78',
    owaspAsvs: 'V5.5.1 Safe Deserialization & Subprocess Isolation',
    appliesTo: (ctx) => ctx.ext === '.py',
    evaluate: (ctx) =>
      findMatchingLines(
        ctx,
        (line) =>
          /\bsubprocess\.(?:run|Popen|call|check_output)\s*\([^)]*shell\s*=\s*True/.test(line) ||
          /\bpickle\.loads?\s*\(/.test(line) ||
          (/\byaml\.load\s*\(/.test(line) && !/SafeLoader/.test(line)),
      ),
    rootCause:
      '`shell=True` や `pickle.loads` / `yaml.load`（SafeLoader なし）は、細工された入力で任意の OS コマンド実行・RCE に直結します。',
    defensivePatch: `# 防御パッチ: shell=False 固定引数リストと yaml.safe_load / Pydantic JSON 検証を使用
import subprocess
import yaml

subprocess.run(["/usr/bin/convert", input_path, output_path], shell=False, check=True, timeout=10)
config = yaml.safe_load(raw_yaml_text)`,
    verificationHint: 'bandit / grep により shell=True、pickle.load、SafeLoader なしの yaml.load が 0 件であることを確認。',
  },
  {
    ruleId: 'LNG-CLD-002',
    title: 'Dockerfile の root 実行または未固定 :latest ベースイメージ',
    stack: 'python-go-cloud',
    severity: 'high',
    stride: 'Elevation of Privilege',
    cwe: 'CWE-250',
    owaspAsvs: 'V14.2.1 Container Least Privilege & Immutable Base',
    appliesTo: (ctx) =>
      ctx.baseName === 'Dockerfile' || ctx.baseName.startsWith('Dockerfile.') || ctx.ext === '.dockerfile',
    evaluate: (ctx) => {
      const hits = findMatchingLines(ctx, (line) => /^FROM\s+\S+:latest\b/i.test(line.trim()), 1);
      const hasNonRootUser = ctx.redactedLines.some((l) => {
        const m = l.trim().match(/^USER\s+(\S+)/i);
        return Boolean(m && m[1] && m[1] !== 'root' && m[1] !== '0');
      });
      if (!hasNonRootUser && ctx.redactedLines.length > 0 && hits.length === 0) {
        const fromIdx = ctx.redactedLines.findIndex((l) => /^FROM\s+/i.test(l.trim()));
        const idx = fromIdx >= 0 ? fromIdx : 0;
        hits.push({ line: idx + 1, snippet: sliceRedactedWindow(ctx.redactedLines, idx) });
      }
      return hits;
    },
    rootCause:
      'コンテナがデフォルトの root (UID 0) で稼働するとプロセス侵害時のエスケープ被害が最大化され、`:latest` タグはサプライチェーン上の意図しない破壊的更新を招きます。',
    defensivePatch: `# 防御パッチ: バージョン/ダイジェスト固定 + Distroless または非 root USER 強制
FROM gcr.io/distroless/nodejs22-debian12:nonroot
WORKDIR /app
COPY --chown=nonroot:nonroot dist/ ./dist/
USER nonroot:nonroot
ENTRYPOINT ["/nodejs/bin/node", "dist/src/cli.js"]`,
    verificationHint: '`docker inspect` または Dockerfile 検査で `USER` が非 root であり `:latest` が存在しないことを確認。',
  },
  {
    ruleId: 'LNG-CLD-003',
    title: 'Cloud Run / IAM 設定における allUsers 未認証公開バインディング',
    stack: 'python-go-cloud',
    severity: 'high',
    stride: 'Spoofing',
    cwe: 'CWE-284',
    owaspAsvs: 'V4.1.2 Cloud Service Perimeter & WAF',
    appliesTo: (ctx) =>
      ctx.ext === '.yaml' || ctx.ext === '.yml' || ctx.ext === '.tf' || ctx.ext === '.sh',
    evaluate: (ctx) =>
      findMatchingLines(
        ctx,
        (line) =>
          /\ballUsers\b/.test(line) ||
          /\ballAuthenticatedUsers\b/.test(line) ||
          /--allow-unauthenticated\b/.test(line),
      ),
    rootCause:
      'Cloud Run サービスへ `allUsers` や `--allow-unauthenticated` を直接付与すると、内部マイクロサービスや推論 API がインターネットから無制限に呼び出され、DDoS・高額課金攻撃の対象になります。',
    defensivePatch: `# 防御パッチ: 内部通信限定（ingress: internal-and-cloud-load-balancing）+ Cloud Armor レート制限 + IAM 認証強制
gcloud run services update my-service \\
  --no-allow-unauthenticated \\
  --ingress=internal-and-cloud-load-balancing \\
  --service-account=minimal-runner@project.iam.gserviceaccount.com`,
    verificationHint: 'gcloud run services get-iam-policy で allUsers が不要な内部サービスに付与されていないことを確認。',
  },
  {
    ruleId: 'LNG-CLD-004',
    title: 'Go / Python バックエンドの TLS 証明書検証スキップまたは HTTP タイムアウト未設定',
    stack: 'python-go-cloud',
    severity: 'high',
    stride: 'Denial of Service',
    cwe: 'CWE-400',
    owaspAsvs: 'V9.2.1 & V11.1.4 Connection Exhaustion & TLS Hardening',
    appliesTo: (ctx) => ctx.ext === '.go' || ctx.ext === '.py',
    evaluate: (ctx) =>
      findMatchingLines(
        ctx,
        (line) =>
          /\bInsecureSkipVerify\s*:\s*true\b/.test(line) ||
          /\bverify\s*=\s*False\b/.test(line) ||
          /\bhttp\.ListenAndServe\s*\(/.test(line),
      ),
    rootCause:
      '`InsecureSkipVerify: true` / `verify=False` は通信経路での盗聴を許し、Go の素の `http.ListenAndServe` は ReadHeaderTimeout を持たないため Slowloris 接続枯渇攻撃に脆弱です。',
    defensivePatch: `// 防御パッチ (Go): 明示的なタイムアウトとヘッダ上限を持つ http.Server + 厳格な TLS 1.3 設定
srv := &http.Server{
    Addr:              "127.0.0.1:8080",
    Handler:           mux,
    ReadHeaderTimeout: 5 * time.Second,
    ReadTimeout:       15 * time.Second,
    WriteTimeout:      30 * time.Second,
    IdleTimeout:       60 * time.Second,
    MaxHeaderBytes:    1 << 16,
}`,
    verificationHint: 'go vet / gosec で G402 (TLS InsecureSkipVerify) と G114 (http.ListenAndServe) が 0 件であることを確認。',
  },

  // =========================================================================
  // 4. Supply-Chain & Secrets (supply-chain-secrets)
  // =========================================================================
  {
    ruleId: 'LNG-SEC-001',
    title: 'ソースコード・構成ファイル内のハードコードされた機密情報・秘密鍵',
    stack: 'supply-chain-secrets',
    severity: 'critical',
    stride: 'Information Disclosure',
    cwe: 'CWE-798',
    owaspAsvs: 'V2.10.4 Zero Hardcoded Credentials',
    appliesTo: (ctx) =>
      ctx.ext !== '.lock' &&
      ctx.baseName !== 'pnpm-lock.yaml' &&
      ctx.baseName !== 'package-lock.json' &&
      !ctx.relativePath.endsWith('redactor.ts'),
    evaluate: (ctx) => {
      const hits: Array<{ line: number; snippet: string }> = [];
      for (const lineNum of ctx.redactedLineNumbers) {
        const idx = lineNum - 1;
        const line = ctx.redactedLines[idx] ?? '';
        const trimmed = line.trim();
        if (!trimmed || isCommentOrRegexDef(trimmed)) continue;
        hits.push({
          line: lineNum,
          snippet: sliceRedactedWindow(ctx.redactedLines, idx),
        });
        if (hits.length >= 3) break;
      }
      return hits;
    },
    rootCause:
      'リポジトリ内に API キー・秘密鍵・パスワード文字列が直接記述されており、Git 履歴やクライアント配布物を経由した資格情報漏洩リスクがあります（表示・送信前に自動マスク済み）。',
    defensivePatch: `# 防御パッチ: キーを即時ローテーションして失効させ、環境変数または Secret Manager 参照へ移行
# 1. Google Cloud Secret Manager または実行時環境変数から取得
export GEMINI_API_KEY="$(gcloud secrets versions access latest --secret=gemini-api-key)"
# 2. .gitignore に .env / .env.* を必ず登録`,
    verificationHint: 'リポジトリ全体に対する Secret Redactor スキャンで検出数が 0 件になることを確認。',
  },
  {
    ruleId: 'LNG-SEC-002',
    title: 'GitHub Actions の pull_request_target 使用または未固定サードパーティ Action',
    stack: 'supply-chain-secrets',
    severity: 'high',
    stride: 'Tampering',
    cwe: 'CWE-829',
    owaspAsvs: 'V14.2.3 CI/CD Supply-Chain Pinning',
    appliesTo: (ctx) =>
      ctx.relativePath.includes('.github/workflows/') && (ctx.ext === '.yml' || ctx.ext === '.yaml'),
    evaluate: (ctx) =>
      findMatchingLines(
        ctx,
        (line) =>
          /\bpull_request_target\b/.test(line) ||
          /\buses:\s*[^@\s]+@(?:main|master|latest|v\d+)\s*$/.test(line.trim()),
      ),
    rootCause:
      '`pull_request_target` はフォーク PR にシークレット読取権限を与えかねず、タグ指定のみの `uses: action@v4` はタグ書き換えによるサプライチェーン汚染を受けます。',
    defensivePatch: `# 防御パッチ: 最小権限 permissions と 40桁フルコミット SHA 固定を徹底
permissions:
  contents: read

steps:
  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2 pinned SHA`,
    verificationHint: '.github/workflows 配下の全 uses が 40 桁 16進 SHA に固定され、permissions が明示宣言されていることを確認。',
  },
];

export function evaluateFileRules(ctx: FileContext): SecurityFinding[] {
  if (ctx.relativePath.endsWith('src/rules.ts') || ctx.relativePath.endsWith('src/redactor.ts')) {
    return [];
  }
  const findings: SecurityFinding[] = [];
  for (const rule of STATIC_RULES) {
    if (!rule.appliesTo(ctx)) continue;
    const matches = rule.evaluate(ctx);
    for (const match of matches) {
      findings.push({
        id: `${rule.ruleId}:${ctx.relativePath}:${match.line}`,
        ruleId: rule.ruleId,
        title: rule.title,
        stack: rule.stack,
        severity: rule.severity,
        stride: rule.stride,
        cwe: rule.cwe,
        owaspAsvs: rule.owaspAsvs,
        filePath: ctx.relativePath,
        line: match.line,
        snippetRedacted: match.snippet,
        rootCause: rule.rootCause,
        defensivePatch: rule.defensivePatch,
        verificationHint: rule.verificationHint,
        source: 'static-rule',
      });
    }
  }
  return findings;
}

export function classifyFileStack(relativePath: string): StackDomain {
  const ext = path.extname(relativePath).toLowerCase();
  const base = path.basename(relativePath);
  if (
    ext === '.dart' ||
    ext === '.rules' ||
    base === 'pubspec.yaml' ||
    base === 'firebase.json' ||
    base === 'AndroidManifest.xml' ||
    base === 'Info.plist'
  ) {
    return 'flutter-firebase';
  }
  if (
    ext === '.py' ||
    ext === '.go' ||
    ext === '.tf' ||
    base === 'Dockerfile' ||
    base.startsWith('Dockerfile.') ||
    base === 'go.mod' ||
    base === 'pyproject.toml' ||
    base === 'requirements.txt'
  ) {
    return 'python-go-cloud';
  }
  if (JS_TS_EXTS.has(ext) || base.startsWith('next.config') || ext === '.html' || ext === '.css') {
    return 'ts-web-api';
  }
  return 'supply-chain-secrets';
}
