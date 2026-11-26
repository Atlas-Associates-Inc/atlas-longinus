import crypto from 'node:crypto';
import fsSync from 'node:fs';
import fs from 'node:fs/promises';
import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { executeDefensiveAudit, scanPortfolioDirectory } from './geminiAnalyzer.ts';
import { buildSarifReport } from './sarif.ts';
import { SafeClientError } from './scanner.ts';
import type { AnalysisMode } from './types.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RAW_PROJECT_ROOT = path.resolve(
  __dirname,
  __dirname.includes(`${path.sep}dist${path.sep}`) ? '../../..' : '../..',
);
const PROJECT_ROOT = fsSync.realpathSync(RAW_PROJECT_ROOT);
const DEFAULT_PORTFOLIO_ROOT = path.dirname(PROJECT_ROOT);
const PUBLIC_DIR = path.join(PROJECT_ROOT, 'public');
const FIXTURE_DIR = path.join(PROJECT_ROOT, 'test', 'fixtures', 'sample-polyglot-app');

const MAX_JSON_BODY_BYTES = 32 * 1024;
const MAX_DRAIN_BODY_BYTES = 1024 * 1024;

export class PayloadTooLargeError extends SafeClientError {
  constructor(message: string) {
    super(message);
    this.name = 'PayloadTooLargeError';
  }
}

interface ParsedAuditRequest {
  targetPath: string;
  mode: AnalysisMode;
  apiKey?: string;
  excludeFixtures?: boolean;
}

const VALID_AUDIT_MODES = new Set<AnalysisMode>([
  'gemini-4-carbon',
  'gemini-4-neon',
  'gemini-4-hydrogen',
  'gemini-4-argon',
  'gemini-3.8-flash',
  'deterministic',
]);
const ALLOWED_AUDIT_KEYS = new Set(['targetPath', 'mode', 'apiKey', 'excludeFixtures']);

const AuditRequestSchema = {
  safeParse(
    raw: unknown,
  ): { success: true; data: ParsedAuditRequest } | { success: false } {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      return { success: false };
    }
    const obj = raw as Record<string, unknown>;
    for (const k of Object.keys(obj)) {
      if (!ALLOWED_AUDIT_KEYS.has(k)) return { success: false };
    }
    const targetPath = obj['targetPath'];
    if (typeof targetPath !== 'string' || targetPath.length < 1 || targetPath.length > 1024) {
      return { success: false };
    }
    const rawMode = obj['mode'] ?? 'gemini-3.8-flash';
    if (typeof rawMode !== 'string' || !VALID_AUDIT_MODES.has(rawMode as AnalysisMode)) {
      return { success: false };
    }
    const rawApiKey = obj['apiKey'];
    if (rawApiKey !== undefined && (typeof rawApiKey !== 'string' || rawApiKey.length > 256)) {
      return { success: false };
    }
    const rawExclude = obj['excludeFixtures'];
    if (rawExclude !== undefined && typeof rawExclude !== 'boolean') {
      return { success: false };
    }
    const data: ParsedAuditRequest = {
      targetPath,
      mode: rawMode as AnalysisMode,
    };
    if (rawApiKey !== undefined) data.apiKey = rawApiKey;
    if (rawExclude !== undefined) data.excludeFixtures = rawExclude;
    return { success: true, data };
  },
};

const EmptyObjectSchema = {
  safeParse(raw: unknown): { success: true } | { success: false } {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      return { success: false };
    }
    if (Object.keys(raw as Record<string, unknown>).length !== 0) {
      return { success: false };
    }
    return { success: true };
  },
};

function applyHardenedHeaders(res: ServerResponse, nonce?: string): void {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Vary', 'Host, Origin, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader(
    'Permissions-Policy',
    'camera=(), geolocation=(), microphone=(), focus-without-user-activation=()',
  );
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');

  if (nonce) {
    const csp = [
      "default-src 'self'",
      `script-src 'nonce-${nonce}' 'strict-dynamic' 'report-sample'`,
      "style-src 'self'",
      "img-src 'self' data:",
      "connect-src 'self'",
      "object-src 'none'",
      "base-uri 'none'",
      "frame-ancestors 'none'",
      "form-action 'self'",
      "require-trusted-types-for 'script'",
    ].join('; ');
    res.setHeader('Content-Security-Policy', csp);
  }
}

/**
 * Enforces strict loopback Host header matching to defeat DNS rebinding.
 */
function hasValidLoopbackHost(req: IncomingMessage, boundPort: number): boolean {
  const host = req.headers.host;
  if (!host || typeof host !== 'string') return false;
  return host === `127.0.0.1:${boundPort}`;
}

function verifyTimingSafeToken(provided: string | string[] | undefined, expectedHex: string): boolean {
  if (typeof provided !== 'string' || provided.length !== expectedHex.length) {
    return false;
  }
  const a = Buffer.from(provided, 'utf8');
  const b = Buffer.from(expectedHex, 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function isAllowedDocumentNavigation(req: IncomingMessage): boolean {
  const site = req.headers['sec-fetch-site'];
  const mode = req.headers['sec-fetch-mode'];
  const dest = req.headers['sec-fetch-dest'];

  if (Array.isArray(site) || Array.isArray(mode) || Array.isArray(dest)) {
    return false;
  }

  if (site === undefined) return true;
  if (site === 'same-origin' || site === 'none') return true;

  if (
    site === 'cross-site' &&
    mode === 'navigate' &&
    req.method === 'GET' &&
    dest !== 'object' &&
    dest !== 'embed' &&
    dest !== 'iframe'
  ) {
    return true;
  }

  return false;
}

/**
 * Strict Zero-Trust verification for API endpoints (/api/*):
 * - Requires explicit Sec-Fetch-Site: same-origin (rejects missing, array, cross-site, or same-site).
 * - Requires cryptographic X-Longinus-Csrf capability token rendered in same-origin HTML.
 * - For state/audit POSTs, requires explicit Origin === http://127.0.0.1:<port>.
 */
function isAuthorizedApiCall(
  req: IncomingMessage,
  boundPort: number,
  expectedCsrfToken: string,
  requireOrigin: boolean,
): boolean {
  const site = req.headers['sec-fetch-site'];
  if (typeof site !== 'string' || site !== 'same-origin') {
    return false;
  }

  const expectedOrigin = `http://127.0.0.1:${boundPort}`;
  const origin = req.headers.origin;
  if (Array.isArray(origin)) {
    return false;
  }
  if (requireOrigin) {
    if (origin !== expectedOrigin) return false;
  } else if (origin !== undefined && origin !== expectedOrigin) {
    return false;
  }

  return verifyTimingSafeToken(req.headers['x-longinus-csrf'], expectedCsrfToken);
}

async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  const declaredLen = req.headers['content-length'];
  if (typeof declaredLen === 'string' && /^\d+$/.test(declaredLen.trim())) {
    const parsedLen = Number(declaredLen.trim());
    if (parsedLen > MAX_JSON_BODY_BYTES) {
      let drained = 0;
      req.on('data', (chunk: Buffer) => {
        drained += chunk.length;
        if (drained > MAX_DRAIN_BODY_BYTES) {
          req.destroy();
        }
      });
      throw new PayloadTooLargeError('リクエストボディがサイズ上限を超えています。');
    }
  }

  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let rejectedTooLarge = false;

    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (rejectedTooLarge) {
        if (total > MAX_DRAIN_BODY_BYTES) {
          req.destroy();
        }
        return;
      }
      if (total > MAX_JSON_BODY_BYTES) {
        rejectedTooLarge = true;
        chunks.length = 0;
        reject(new PayloadTooLargeError('リクエストボディがサイズ上限を超えています。'));
        if (total > MAX_DRAIN_BODY_BYTES) {
          req.destroy();
        }
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (rejectedTooLarge) return;
      try {
        const raw = Buffer.concat(chunks).toString('utf8');
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(new SafeClientError('不正な JSON ペイロードです。'));
      }
    });

    req.on('error', (err) => {
      if (!rejectedTooLarge) {
        reject(err);
      }
    });
  });
}

function sendJson(res: ServerResponse, statusCode: number, payload: unknown): void {
  applyHardenedHeaders(res);
  res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

function renderIndexHtml(nonce: string, csrfToken: string): string {
  return `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="longinus-csrf" content="${csrfToken}" />
  <title>LONGINUS — Sovereign Consulting &amp; Cyber Defense Spear</title>
  <link rel="icon" type="image/svg+xml" href="/longinus-icon.svg" />
  <link rel="stylesheet" href="/styles.css" />
</head>
<body>
  <header class="topbar" role="banner">
    <div class="topbar-inner">
      <div class="brand-row">
        <img src="/longinus-icon.svg" alt="" width="34" height="34" class="brand-logo" />
        <div class="brand-block">
          <span class="brand-kicker">SOVEREIGN DEFENSIVE SHIELD</span>
          <h1 class="brand-title">LONGINUS</h1>
        </div>
      </div>
      <div class="header-badges" id="header-badges" aria-live="polite">
        <span class="pill pill-blue" id="engine-badge">Gemini Structured Threat Modeler</span>
        <span class="pill pill-emerald">Read-Only &bull; Secret Redacted &bull; 127.0.0.1</span>
      </div>
    </div>
  </header>

  <main class="main-shell" id="main-content">
    <section class="control-panel card" aria-labelledby="scan-form-heading">
      <div class="section-head">
        <div>
          <p class="eyebrow">PREVENTIVE SIMULATION &amp; STATIC HARDENING</p>
          <h2 id="scan-form-heading" class="section-title">監査対象リポジトリ &amp; 推論モード指定</h2>
        </div>
        <div class="preset-group" role="group" aria-label="クイック監査プリセット">
          <button type="button" class="btn btn-outline" id="preset-portfolio-btn">全プロダクト一括監査</button>
          <button type="button" class="btn btn-ghost" id="preset-fixture-btn">4スタック脆弱サンプル検証</button>
          <button type="button" class="btn btn-ghost" id="preset-self-btn">Longinus 自己防御監査</button>
          <button type="button" class="btn btn-outline" id="export-md-btn">レポート出力 (.md)</button>
          <button type="button" class="btn btn-outline" id="export-sarif-btn">SARIF出力 (.sarif)</button>
        </div>
      </div>

      <form id="audit-form" class="audit-form" novalidate>
        <div class="field-group field-wide">
          <label for="target-path-input">ローカルリポジトリ絶対パス（完全読取専用）</label>
          <input
            id="target-path-input"
            name="targetPath"
            type="text"
            autocomplete="off"
            spellcheck="false"
            required
            placeholder="/Users/.../your-product-repo"
          />
        </div>

        <div class="field-group">
          <label for="analysis-mode-select">脅威分析エンジン</label>
          <select id="analysis-mode-select" name="mode">
            <option value="gemini-4-carbon">Gemini 4 Carbon（最高峰脅威アーキテクチャ監査 / thinking: high）</option>
            <option value="gemini-4-neon">Gemini 4 Neon（2026-11 GA 高速バランス分析 / thinking: medium〜xhigh 自動）</option>
            <option value="gemini-4-hydrogen">Gemini 4 Hydrogen（超高速エージェント防御分析 / thinking: low〜xhigh 自動）</option>
            <option value="gemini-3.8-flash">Gemini 3.8 Flash（防御パッチ実装・最適 Reasoning 自動選択）</option>
            <option value="gemini-4-argon">Argon High（深層脅威分析・調査・根本解決計画 / thinking: high）</option>
            <option value="deterministic">0トークン決定論的 STRIDE + 静的ルールのみ</option>
          </select>
        </div>

        <div class="field-group">
          <label for="api-key-input">GEMINI_API_KEY（任意・メモリ一時利用のみ）</label>
          <input
            id="api-key-input"
            name="apiKey"
            type="password"
            autocomplete="off"
            placeholder="環境変数設定時は空欄で自動適用"
          />
        </div>

        <div class="field-actions">
          <button type="submit" class="btn btn-primary" id="run-audit-btn">予防脅威シミュレーション実行</button>
        </div>
      </form>

      <p class="status-banner" id="status-banner" role="status" aria-live="polite"></p>
    </section>

    <section class="card isolated-region" id="portfolio-section" hidden aria-labelledby="portfolio-heading">
      <div class="section-head">
        <div>
          <p class="eyebrow">PORTFOLIO FLEET SHIELD</p>
          <h2 id="portfolio-heading" class="section-title">ローカル全プロダクト・予防防御姿勢一覧比較表</h2>
        </div>
        <div class="preset-group">
          <div class="telemetry-strip" id="portfolio-kpis"></div>
          <button type="button" class="btn btn-ghost btn-sm" id="close-portfolio-btn">一覧を閉じる</button>
        </div>
      </div>
      <div tabindex="0" role="region" aria-labelledby="portfolio-table-caption" class="table-wrapper">
        <table class="luxury-table portfolio-table">
          <caption id="portfolio-table-caption" class="sr-only">ローカル全プロダクト防御スコア一覧比較表</caption>
          <thead>
            <tr>
              <th scope="col">プロダクト</th>
              <th scope="col">防御スコア</th>
              <th scope="col">走査ファイル</th>
              <th scope="col">深刻度内訳 (C / H / M)</th>
              <th scope="col">最優先予防ハードニング項目</th>
              <th scope="col">詳細分析</th>
            </tr>
          </thead>
          <tbody id="portfolio-tbody"></tbody>
        </table>
      </div>
    </section>

    <section class="hero-metrics" aria-label="総合防御スコアと監査サマリ">
      <article class="card metric-score-card">
        <p class="eyebrow">OVERALL DEFENSE POSTURE</p>
        <div class="score-row">
          <span class="score-numeral" id="overall-score">--</span>
          <span class="score-unit">/ 100</span>
        </div>
        <p class="score-caption" id="repo-meta-line">監査待機中</p>
      </article>

      <article class="card metric-summary-card">
        <p class="eyebrow">EXECUTIVE PREVENTIVE BRIEF</p>
        <p class="executive-text" id="executive-summary">ローカルリポジトリを選択して予防脅威分析を開始してください。</p>
        <div class="telemetry-strip" id="telemetry-strip"></div>
      </article>
    </section>

    <section class="stack-grid" id="stack-grid" aria-label="4スタック別防御スコア一覧"></section>

    <section class="dual-layout">
      <article class="card isolated-region" aria-labelledby="trust-map-heading">
        <div class="section-head">
          <div>
            <p class="eyebrow">ARCHITECTURAL TRUST BOUNDARIES</p>
            <h2 id="trust-map-heading" class="section-title">攻撃表面 &amp; 信頼境界マップ</h2>
          </div>
          <span class="legend-inline">
            <span class="dot dot-emerald"></span>堅牢
            <span class="dot dot-amber"></span>要注意
            <span class="dot dot-crimson"></span>要防御パッチ
          </span>
        </div>
        <div class="trust-map-wrap" id="trust-map-container" role="img" aria-label="アーキテクチャ信頼境界グラフ"></div>
      </article>

      <article class="card isolated-region" aria-labelledby="roadmap-heading">
        <div class="section-head">
          <div>
            <p class="eyebrow">PRIORITIZED REMEDIATION</p>
            <h2 id="roadmap-heading" class="section-title">予防ハードニング優先ロードマップ</h2>
          </div>
        </div>
        <ol class="roadmap-list" id="roadmap-list"></ol>
      </article>
    </section>

    <section class="card isolated-region" aria-labelledby="stride-table-caption">
      <div class="section-head">
        <div>
          <p class="eyebrow">STRIDE THREAT EXPOSURE SIMULATION</p>
          <h2 class="section-title">6軸脅威カテゴリ別・受けやすい攻撃傾向と予防制御比較表</h2>
        </div>
      </div>
      <div tabindex="0" role="region" aria-labelledby="stride-table-caption" class="table-wrapper">
        <table class="luxury-table stride-table">
          <caption id="stride-table-caption" class="sr-only">STRIDE 6軸脅威露出と予防対策一覧</caption>
          <thead>
            <tr>
              <th scope="col">脅威軸 (STRIDE)</th>
              <th scope="col">露出リスク</th>
              <th scope="col">防御準備度</th>
              <th scope="col">想定される弱点傾向</th>
              <th scope="col">推奨される予防制御</th>
            </tr>
          </thead>
          <tbody id="stride-tbody"></tbody>
        </table>
      </div>
    </section>

    <section class="card isolated-region" aria-labelledby="findings-table-caption">
      <div class="section-head">
        <div>
          <p class="eyebrow">ACTIONABLE DEFENSIVE PATCHES</p>
          <h2 class="section-title">検出リスク箇所 &amp; 即時適用可能な防御パッチ一覧</h2>
        </div>
        <div class="filter-bar" role="group" aria-label="技術スタックフィルタ">
          <button type="button" class="chip chip-active" data-stack-filter="all">すべて</button>
          <button type="button" class="chip" data-stack-filter="ts-web-api">TS / Next / Node</button>
          <button type="button" class="chip" data-stack-filter="flutter-firebase">Flutter / Firebase</button>
          <button type="button" class="chip" data-stack-filter="python-go-cloud">Python / Go / Cloud</button>
          <button type="button" class="chip" data-stack-filter="supply-chain-secrets">Secrets / CI</button>
          <button type="button" class="btn btn-outline btn-sm" id="copy-prompt-btn">修正プロンプトをコピー</button>
        </div>
      </div>

      <div tabindex="0" role="region" aria-labelledby="findings-table-caption" class="table-wrapper">
        <table class="luxury-table findings-table">
          <caption id="findings-table-caption" class="sr-only">検出された構造的リスクと防御パッチ比較表</caption>
          <thead>
            <tr>
              <th scope="col">Rule / 深刻度</th>
              <th scope="col">スタック</th>
              <th scope="col">対象ファイル</th>
              <th scope="col">脅威分類 (STRIDE / CWE)</th>
              <th scope="col">リスク概要</th>
              <th scope="col">防御パッチ</th>
            </tr>
          </thead>
          <tbody id="findings-tbody"></tbody>
        </table>
      </div>
    </section>

    <section class="card isolated-region" aria-labelledby="destruction-cert-heading">
      <div class="section-head">
        <div>
          <p class="eyebrow">DOD 5220.22-M SANITIZATION &amp; ECDSA P-256 ATTESTATION</p>
          <h2 id="destruction-cert-heading" class="section-title">米国国防総省規格 DoD 5220.22-M 3パス消去 &amp; ECDSA P-256 暗号署名入りデータ破棄証明書</h2>
        </div>
        <span class="pill pill-emerald" id="destruction-cert-badge">VERIFIED &bull; 0o700 ACL + Fernet</span>
      </div>
      <div tabindex="0" role="region" aria-labelledby="destruction-cert-caption" class="table-wrapper">
        <table class="luxury-table">
          <caption id="destruction-cert-caption" class="sr-only">DoD 5220.22-M データ破棄証明書およびECDSA P-256暗号署名</caption>
          <thead>
            <tr>
              <th scope="col">証明項目</th>
              <th scope="col">暗号学的検証値・規格詳細</th>
            </tr>
          </thead>
          <tbody id="destruction-cert-tbody"></tbody>
        </table>
      </div>
    </section>
  </main>

  <dialog id="patch-dialog" closedby="any" aria-labelledby="patch-dialog-title">
    <div class="dialog-body">
      <div class="dialog-header">
        <div>
          <p class="eyebrow" id="dialog-meta-kicker">DEFENSIVE REMEDIATION SPEC</p>
          <h3 id="patch-dialog-title" class="dialog-title">防御パッチ詳細</h3>
        </div>
        <form method="dialog">
          <button type="submit" class="btn btn-ghost" aria-label="モーダルを閉じる">閉じる (Esc)</button>
        </form>
      </div>

      <div class="dialog-section">
        <h4 class="sub-heading">対象箇所（機密自動マスク済み）</h4>
        <p class="mono-location" id="dialog-location"></p>
        <pre class="code-block code-exposed" id="dialog-snippet"></pre>
      </div>

      <div class="dialog-section">
        <h4 class="sub-heading">構造的な根本原因（なぜ狙われやすいか）</h4>
        <p class="dialog-prose" id="dialog-root-cause"></p>
      </div>

      <div class="dialog-section">
        <div class="patch-head-row">
          <h4 class="sub-heading emerald-text">推奨される防御ハードニングパッチ</h4>
          <button type="button" class="btn btn-outline btn-sm" id="copy-patch-btn">パッチをコピー</button>
        </div>
        <pre class="code-block code-hardened" id="dialog-patch"></pre>
      </div>

      <div class="dialog-section">
        <h4 class="sub-heading">決定論的検証ポイント</h4>
        <p class="dialog-prose" id="dialog-verify"></p>
      </div>
    </div>
  </dialog>

  <script nonce="${nonce}" src="/app.js" defer></script>
</body>
</html>`;
}

export interface LonginusServerOptions {
  portfolioRoot?: string;
}

export function createLonginusServer(options?: LonginusServerOptions): http.Server {
  const bootCsrfToken = crypto.randomBytes(32).toString('hex');
  const pinnedPortfolioRoot = options?.portfolioRoot ?? DEFAULT_PORTFOLIO_ROOT;

  const server = http.createServer(async (req, res) => {
    try {
      const addr = server.address();
      const boundPort =
        typeof addr === 'object' && addr !== null ? addr.port : (req.socket.localPort ?? 4310);

      // 1. Strict Host allowlist check against DNS rebinding on every route
      if (!hasValidLoopbackHost(req, boundPort)) {
        sendJson(res, 403, { error: 'Forbidden Host header.' });
        return;
      }

      const urlObj = new URL(req.url ?? '/', `http://127.0.0.1:${boundPort}`);
      const pathname = urlObj.pathname;

      // 2. API routes enforce Origin + Sec-Fetch-Site + timing-safe CSRF capability token
      if (pathname.startsWith('/api/')) {
        const requireOrigin = req.method !== 'GET';
        if (!isAuthorizedApiCall(req, boundPort, bootCsrfToken, requireOrigin)) {
          sendJson(res, 403, {
            error: 'Unauthorized API call blocked by Origin / Fetch Metadata / CSRF policy.',
          });
          return;
        }
      } else if (!isAllowedDocumentNavigation(req)) {
        sendJson(res, 403, { error: 'Cross-site request blocked by Fetch Metadata policy.' });
        return;
      }

      if (req.method === 'GET' && pathname === '/') {
        const nonce = crypto.randomBytes(16).toString('base64');
        applyHardenedHeaders(res, nonce);
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(renderIndexHtml(nonce, bootCsrfToken));
        return;
      }

      if (
        req.method === 'GET' &&
        (pathname === '/styles.css' || pathname === '/app.js' || pathname === '/longinus-icon.svg')
      ) {
        const fileName = pathname.slice(1);
        const filePath = path.join(PUBLIC_DIR, fileName);
        const content = await fs.readFile(filePath, 'utf8');
        applyHardenedHeaders(res);
        const mime = fileName.endsWith('.css')
          ? 'text/css; charset=utf-8'
          : fileName.endsWith('.svg')
            ? 'image/svg+xml; charset=utf-8'
            : 'application/javascript; charset=utf-8';
        res.writeHead(200, { 'Content-Type': mime });
        res.end(content);
        return;
      }

      if (req.method === 'GET' && pathname === '/api/presets') {
        sendJson(res, 200, {
          selfPath: PROJECT_ROOT,
          fixturePath: FIXTURE_DIR,
          envApiKeyConfigured: Boolean(process.env['GEMINI_API_KEY']?.trim()),
        });
        return;
      }

      if (req.method === 'POST' && pathname === '/api/audit') {
        const contentType = req.headers['content-type'] ?? '';
        if (!contentType.toLowerCase().startsWith('application/json')) {
          sendJson(res, 415, { error: 'Content-Type must be application/json.' });
          return;
        }

        const rawBody = await readJsonBody(req);
        const parsed = AuditRequestSchema.safeParse(rawBody);
        if (!parsed.success) {
          sendJson(res, 400, { error: '監査リクエストの形式が不正です。' });
          return;
        }

        const { targetPath, mode, apiKey, excludeFixtures } = parsed.data;
        const auditParams: {
          targetPath: string;
          mode: AnalysisMode;
          apiKeyOverride?: string;
          excludeRelativePrefixes?: string[];
        } = {
          targetPath,
          mode: mode as AnalysisMode,
        };
        if (apiKey) {
          auditParams.apiKeyOverride = apiKey;
        }
        if (excludeFixtures) {
          auditParams.excludeRelativePrefixes = ['test'];
        }

        const report = await executeDefensiveAudit(auditParams);
        sendJson(res, 200, report);
        return;
      }

      if (req.method === 'POST' && pathname === '/api/sarif') {
        const contentType = req.headers['content-type'] ?? '';
        if (!contentType.toLowerCase().startsWith('application/json')) {
          sendJson(res, 415, { error: 'Content-Type must be application/json.' });
          return;
        }

        const rawBody = await readJsonBody(req);
        const parsed = AuditRequestSchema.safeParse(rawBody);
        if (!parsed.success) {
          sendJson(res, 400, { error: 'SARIF 出力リクエストの形式が不正です。' });
          return;
        }

        const { targetPath, excludeFixtures } = parsed.data;
        const report = await executeDefensiveAudit({
          targetPath,
          mode: 'deterministic',
          ...(excludeFixtures ? { excludeRelativePrefixes: ['test'] } : {}),
        });
        const sarif = buildSarifReport(report);
        applyHardenedHeaders(res);
        res.writeHead(200, { 'Content-Type': 'application/sarif+json; charset=utf-8' });
        res.end(JSON.stringify(sarif, null, 2));
        return;
      }

      if (req.method === 'POST' && pathname === '/api/portfolio') {
        const contentType = req.headers['content-type'] ?? '';
        if (!contentType.toLowerCase().startsWith('application/json')) {
          sendJson(res, 415, { error: 'Content-Type must be application/json.' });
          return;
        }

        const rawBody = await readJsonBody(req);
        const parsed = EmptyObjectSchema.safeParse(rawBody);
        if (!parsed.success) {
          sendJson(res, 400, { error: 'ポートフォリオ監査リクエストには追加パラメータを指定できません。' });
          return;
        }

        const portfolio = await scanPortfolioDirectory({
          portfolioRoot: pinnedPortfolioRoot,
          selfProjectRoot: PROJECT_ROOT,
        });
        sendJson(res, 200, portfolio);
        return;
      }

      sendJson(res, 404, { error: 'Not Found' });
    } catch (err) {
      if (res.headersSent) {
        if (!req.destroyed) req.destroy();
        return;
      }
      if (err instanceof PayloadTooLargeError) {
        res.shouldKeepAlive = false;
        res.setHeader('Connection', 'close');
        sendJson(res, 413, { error: err.message });
        req.resume();
        const destroyTimer = setTimeout(() => {
          if (!req.destroyed) {
            req.destroy();
          }
        }, 250);
        destroyTimer.unref();
        req.once('end', () => clearTimeout(destroyTimer));
        req.once('close', () => clearTimeout(destroyTimer));
      } else if (err instanceof SafeClientError) {
        sendJson(res, 400, { error: err.message });
      } else {
        sendJson(res, 500, { error: '監査処理中に内部エラーが発生しました。' });
      }
    }
  });

  server.headersTimeout = 10_000;
  server.requestTimeout = 45_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 64;

  return server;
}

export async function startLonginusServer(
  port = 4310,
  options?: LonginusServerOptions,
): Promise<{ server: http.Server; url: string }> {
  const server = createLonginusServer(options);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve());
  });
  const addr = server.address();
  const actualPort = typeof addr === 'object' && addr ? addr.port : port;
  return {
    server,
    url: `http://127.0.0.1:${actualPort}`,
  };
}
