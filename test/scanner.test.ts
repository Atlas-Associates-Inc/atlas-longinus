import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { runCli } from '../src/shield/cli.ts';
import {
  classifySafeGeminiFallbackReason,
  executeDefensiveAudit,
  scanPortfolioDirectory,
  selectOptimalReasoningLevel,
  validateAndTransformGeminiOutput,
} from '../src/shield/geminiAnalyzer.ts';
import { redactSecrets, redactSecretsPreserveLines } from '../src/shield/redactor.ts';
import {
  buildSarifReport,
  meetsFailOnThreshold,
  meetsPortfolioFailOnThreshold,
} from '../src/shield/sarif.ts';
import {
  readBoundedFromHandle,
  resolveSafeTargetDirectory,
  runStaticRepositoryScan,
} from '../src/shield/scanner.ts';
import { startLonginusServer } from '../src/shield/server.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(
  __dirname,
  __dirname.includes(`${path.sep}dist${path.sep}`) ? '../..' : '..',
);
const FIXTURE_ROOT = path.join(PROJECT_ROOT, 'test', 'fixtures', 'sample-polyglot-app');

describe('Longinus Defensive Security Invariants', () => {
  it('masks quoted properties, escaped quotes, multiline .env/YAML/PEM continuations while preserving line count', () => {
    const beginMarker = ['-----BEGIN', 'PRIVATE', 'KEY-----'].join(' ');
    const endMarker = ['-----END', 'PRIVATE', 'KEY-----'].join(' ');
    const codeSample = [
      'API_SECRET = "my_ultra_sensitive_secret_value_12345"',
      'const config = {"NEXT_PUBLIC_ADMIN_KEY": "AUDIT_CANARY_A9"};',
      'const typedKey: string = "safe"; const NEXT_PUBLIC_ADMIN_KEY: string = "AUDIT_TS_TYPED_Z1";',
      'apiSecret := "AUDIT_GO_SHORT_Z2"',
      'const NEXT_PUBLIC_SECRET = flag ? "AUDIT_TERNARY_Z3" : "AUDIT_TERNARY_Z4";',
      'const NEXT_PUBLIC_API_KEY = `${flag ? "AUDIT_TPL_TER_Z5" : "AUDIT_TPL_TER_Z6"}`;',
      'const escaped = {"NEXT_PUBLIC_ADMIN_KEY": "AUDIT_\\"ESCAPED\\"_B8"};',
      'const fallback = process.env.NEXT_PUBLIC_ADMIN_KEY ?? "AUDIT_FALLBACK_D6";',
      'prefs.setString("session_token", "AUDIT_FLUTTER_E5");',
      'const gcp = "AIzaSyA1234567890abcdefghijklmnopqrstuvwx";',
      'const aws = "AKIAIOSFODNN7EXAMPLE";',
      `const pem = \`${beginMarker}`,
      'syntheticKeyBodyLineOne123456789',
      'syntheticKeyBodyLineTwo987654321',
      `${endMarker}\`;`,
    ].join('\n');

    const res = redactSecretsPreserveLines(codeSample);
    assert.equal(res.redactedLines.length, 15, 'Must preserve exact line count');
    for (const canary of [
      'my_ultra_sensitive_secret_value_12345',
      'AUDIT_CANARY_A9',
      'AUDIT_TS_TYPED_Z1',
      'AUDIT_GO_SHORT_Z2',
      'AUDIT_TERNARY_Z3',
      'AUDIT_TERNARY_Z4',
      'AUDIT_TPL_TER_Z5',
      'AUDIT_TPL_TER_Z6',
      'AUDIT_\\"ESCAPED\\"_B8',
      'ESCAPED',
      'AUDIT_FALLBACK_D6',
      'AUDIT_FLUTTER_E5',
      'AIzaSyA1234567890abcdefghijklmnopqrstuvwx',
      'AKIAIOSFODNN7EXAMPLE',
      'syntheticKeyBodyLineOne123456789',
      'syntheticKeyBodyLineTwo987654321',
    ]) {
      assert.ok(!res.redactedText.includes(canary), `Canary leaked in code redaction: ${canary}`);
    }

    // Closed and unclosed multiline .env values + backslash continuations
    const envSample = [
      'NEXT_PUBLIC_ADMIN_KEY="AUDIT_FIRST_LINE',
      'AUDIT_CONTINUATION_29',
      'AUDIT_LAST_LINE"',
      'NEXT_PUBLIC_SECRET="${ADMIN_KEY:-AUDIT_ENV_DEFAULT_77}"',
      'WEBHOOK_SECRET=part_alpha_\\',
      'part_beta_secret',
      'UNCLOSED_API_SECRET="AUDIT_UNCLOSED_LINE_1',
      'AUDIT_UNCLOSED_EOF_LINE_2',
    ].join('\n');

    const envRes = redactSecretsPreserveLines(envSample, { isEnvFile: true });
    assert.equal(envRes.redactedLines.length, 8, 'Must preserve exact .env line count');
    for (const canary of [
      'AUDIT_FIRST_LINE',
      'AUDIT_CONTINUATION_29',
      'AUDIT_LAST_LINE',
      'AUDIT_ENV_DEFAULT_77',
      'part_alpha_',
      'part_beta_secret',
      'AUDIT_UNCLOSED_LINE_1',
      'AUDIT_UNCLOSED_EOF_LINE_2',
    ]) {
      assert.ok(!envRes.redactedText.includes(canary), `Canary leaked in .env redaction: ${canary}`);
    }

    // YAML block scalar secret (including explicit indent indicator |-2)
    const yamlSample = ['env:', '  api_secret: |-2', '    AUDIT_YAML_LINE_1', '    AUDIT_YAML_LINE_2', '  mode: safe'].join(
      '\n',
    );
    const yamlRes = redactSecrets(yamlSample);
    assert.ok(!yamlRes.redactedText.includes('AUDIT_YAML_LINE_1'));
    assert.ok(!yamlRes.redactedText.includes('AUDIT_YAML_LINE_2'));
    assert.ok(yamlRes.redactedText.includes('mode: safe'));
  });

  it('prevents leakage of quoted keys and multiline .env secrets across snippets and zero-snippet digests', async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'longinus-redact-test-'));
    const beginMarker = ['-----BEGIN', 'PRIVATE', 'KEY-----'].join(' ');
    const endMarker = ['-----END', 'PRIVATE', 'KEY-----'].join(' ');
    try {
      await fs.writeFile(
        path.join(tmpDir, '.env'),
        [
          'NEXT_PUBLIC_ADMIN_KEY="AUDIT_FIRST_LINE',
          'AUDIT_CONTINUATION_29',
          'AUDIT_LAST_LINE"',
          'CUSTOM_OTHER_ENV=custom-secret-val-888',
        ].join('\n'),
        'utf8',
      );
      await fs.writeFile(
        path.join(tmpDir, 'config.ts'),
        [
          'export const config = {"NEXT_PUBLIC_ADMIN_KEY": "AUDIT_CANARY_A9"};',
          'export function render(el: HTMLElement) {',
          `  el.innerHTML = \`${beginMarker}`,
          'syntheticMultilineBodyAlpha',
          'syntheticMultilineBodyOmega',
          `${endMarker}\`;`,
          '}',
        ].join('\n'),
        'utf8',
      );

      const scan = await runStaticRepositoryScan(tmpDir);
      const serialized = JSON.stringify({
        findings: scan.findings,
        digest: scan.architectureDigest,
      });

      assert.ok(scan.findings.some((f) => f.ruleId === 'LNG-TS-004'));
      assert.ok(scan.findings.some((f) => f.ruleId === 'LNG-SEC-001'));
      assert.ok(scan.findings.some((f) => f.ruleId === 'LNG-TS-001'));

      for (const secret of [
        'AUDIT_CANARY_A9',
        'AUDIT_FIRST_LINE',
        'AUDIT_CONTINUATION_29',
        'AUDIT_LAST_LINE',
        'custom-secret-val-888',
        'syntheticMultilineBodyAlpha',
        'syntheticMultilineBodyOmega',
      ]) {
        assert.ok(!serialized.includes(secret), `Secret value must never leak: ${secret}`);
      }
      assert.ok(
        scan.architectureDigest.includes('Zero Source Snippets'),
        'Outbound digest must be strictly structural with zero source snippets',
      );
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it('enforces closed-world enum catalogs for Gemini output and never echoes raw parser errors', () => {
    const validMock = JSON.stringify({
      executivePostureId: 'POSTURE_WEB_CSP_AND_ORIGIN_PRIORITY',
      strideMatrix: [
        {
          category: 'Spoofing',
          exposureScore: 20,
          readinessScore: 80,
          riskCatalogId: 'SPOOFING_ORIGIN_AND_TOKEN_GAP',
          defenseCatalogId: 'DEF_STRICT_ORIGIN_CSRF_APPCHECK',
        },
      ],
      priorityRoadmap: [
        {
          phaseId: 'PHASE_1_24H',
          targetStack: 'ts-web-api',
          playbookId: 'PLAYBOOK_WEB_CSP_TRUSTED_TYPES',
        },
      ],
      architecturalFindings: [
        {
          findingCatalogId: 'ARCH_WEB_CSP_TRUSTED_TYPES_BOUNDARY',
          stack: 'ts-web-api',
          severity: 'medium',
          stride: 'Tampering',
          filePath: 'src/server.ts',
          patchTemplateId: 'CSP_NONCE_TRUSTED_TYPES',
        },
      ],
    });

    const allowedPaths = new Set(['src/server.ts']);
    const transformed = validateAndTransformGeminiOutput(validMock, {
      allowedFilePaths: allowedPaths,
      repoLabel: 'Longinus',
      scannedFiles: 12,
      findingCount: 0,
    });
    assert.ok(transformed.architecturalFindings[0]?.defensivePatch.includes('Trusted Types'));

    const rejectedPayloads = [
      // Arbitrary offensive command in enum field (Round 2 Finding #4 regression)
      validMock.replace('POSTURE_WEB_CSP_AND_ORIGIN_PRIORITY', 'nmap -sn 192.0.2.0/24'),
      validMock.replace('SPOOFING_ORIGIN_AND_TOKEN_GAP', '<script>alert(1)</script>'),
      validMock.replace('PLAYBOOK_WEB_CSP_TRUSTED_TYPES', 'Run sqlmap against target'),
      // Path traversal & non-allowlisted repository file
      validMock.replace('src/server.ts', '../../etc/passwd'),
      validMock.replace('src/server.ts', 'unscanned/hallucinated.ts'),
      // Extra unapproved free-text property rejected by .strict()
      JSON.stringify({ ...JSON.parse(validMock), extraFreeText: 'nmap -sn 192.0.2.0/24' }),
    ];

    for (const bad of rejectedPayloads) {
      assert.throws(
        () => validateAndTransformGeminiOutput(bad, { allowedFilePaths: allowedPaths }),
        'Closed-world schema must fail-closed on any non-catalog or unindexed value',
      );
    }

    // Round 2 Finding #3 regression: JSON.parse error containing <script> must never echo fragment
    let caughtParseErr: unknown;
    try {
      JSON.parse('<script>void 0</script>');
    } catch (err) {
      caughtParseErr = err;
    }
    const safeReason = classifySafeGeminiFallbackReason(caughtParseErr);
    assert.ok(!safeReason.includes('<script>'), 'Fallback reason must never echo rejected input');
    assert.ok(!safeReason.includes('void 0'));
    assert.ok(safeReason.includes('決定論的 STRIDE エンジンへ安全フォールバック'));

    // Model division & dynamic reasoning tier selection (gemini-3.8-flash supports low|medium|high)
    assert.equal(selectOptimalReasoningLevel({ findings: [] }, 'deterministic'), 'none');
    assert.equal(selectOptimalReasoningLevel({ findings: [] }, 'gemini-4-argon'), 'high');
    assert.equal(selectOptimalReasoningLevel({ findings: [] }, 'gemini-3.8-flash'), 'low');
    assert.equal(
      selectOptimalReasoningLevel(
        { findings: [{ severity: 'low', stack: 'ts-web-api' } as never] },
        'gemini-3.8-flash',
      ),
      'low',
    );
    assert.equal(
      selectOptimalReasoningLevel(
        { findings: [{ severity: 'high', stack: 'ts-web-api' } as never] },
        'gemini-3.8-flash',
      ),
      'medium',
    );
    assert.equal(
      selectOptimalReasoningLevel(
        { findings: [{ severity: 'critical', stack: 'supply-chain-secrets' } as never] },
        'gemini-3.8-flash',
      ),
      'high',
    );
    assert.equal(selectOptimalReasoningLevel({ findings: [] }, 'gemini-4-carbon'), 'high');
    assert.equal(selectOptimalReasoningLevel({ findings: [] }, 'gemini-4-neon'), 'medium');
    assert.equal(
      selectOptimalReasoningLevel(
        { findings: [{ severity: 'high', stack: 'ts-web-api' } as never] },
        'gemini-4-neon',
      ),
      'high',
    );
    assert.equal(
      selectOptimalReasoningLevel(
        { findings: [{ severity: 'critical', stack: 'supply-chain-secrets' } as never] },
        'gemini-4-neon',
      ),
      'xhigh',
    );
    assert.equal(selectOptimalReasoningLevel({ findings: [] }, 'gemini-4-hydrogen'), 'low');
    assert.equal(
      selectOptimalReasoningLevel(
        { findings: [{ severity: 'high', stack: 'ts-web-api' } as never] },
        'gemini-4-hydrogen',
      ),
      'medium',
    );
    assert.equal(
      selectOptimalReasoningLevel(
        {
          findings: [
            { severity: 'high', stack: 'ts-web-api' } as never,
            { severity: 'high', stack: 'python-go-cloud' } as never,
          ],
        },
        'gemini-4-hydrogen',
      ),
      'high',
    );
    assert.equal(
      selectOptimalReasoningLevel(
        { findings: [{ severity: 'critical', stack: 'supply-chain-secrets' } as never] },
        'gemini-4-hydrogen',
      ),
      'xhigh',
    );
  });

  it('enforces AT_FDCWD symlink rejection, streaming opendir budget, and skipped-file byte accounting', async () => {
    await assert.rejects(() => resolveSafeTargetDirectory('/invalid\0path'));
    await assert.rejects(() =>
      resolveSafeTargetDirectory(path.join(PROJECT_ROOT, 'does-not-exist-99999')),
    );

    // 1. Growing-file byte budget accounting (Round 2 Finding #6 exact reproduction: maxFileBytes=5, maxTotalBytes=8)
    let simulatedTotalBytes = 0;
    let simulatedTruncated = false;
    const maxFileBytes = 5;
    const maxTotalBytes = 8;

    for (let i = 0; i < 3; i++) {
      const remaining = maxTotalBytes - simulatedTotalBytes;
      if (remaining <= 0) {
        simulatedTruncated = true;
        break;
      }
      let returnedOnce = false;
      const mockGrowingHandle = {
        async stat() {
          return { isFile: () => true, size: 4 };
        },
        async read(buffer: Buffer, offset: number, length: number) {
          if (returnedOnce) return { bytesRead: 0 };
          returnedOnce = true;
          const payload = Buffer.from('ABCDEF'); // 6 bytes (> stat.size=4 and > maxFileBytes=5)
          const n = Math.min(length, payload.length);
          payload.copy(buffer, offset, 0, n);
          return { bytesRead: n };
        },
      };

      const res = await readBoundedFromHandle({
        handle: mockGrowingHandle,
        maxFileBytes,
        remainingTotalBudget: remaining,
      });
      simulatedTotalBytes += res.bytesRead;
      if (res.status === 'budget_exceeded' || simulatedTotalBytes > maxTotalBytes) {
        simulatedTruncated = true;
        break;
      }
    }
    assert.equal(simulatedTotalBytes, 6, 'Skipped growing file bytes must be charged to cumulative budget');
    assert.equal(simulatedTruncated, true, 'Second file must trigger budget_exceeded before reading');

    // 2. Symlink rejection (file + directory) & streaming opendir entry cap (Round 2 Finding #5 & #7)
    const cwdBefore = process.cwd();
    const tmpRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'longinus-fs-bound-'));
    const outsideDir = await fs.mkdtemp(path.join(os.tmpdir(), 'longinus-outside-dir-'));
    const outsideFile = path.join(outsideDir, 'outside-secret.ts');
    try {
      await fs.writeFile(outsideFile, 'API_SECRET="outside_secret_should_not_be_read"', 'utf8');
      await fs.symlink(outsideFile, path.join(tmpRoot, 'escaped-file.ts'));
      await fs.symlink(outsideDir, path.join(tmpRoot, 'escaped-subdir'));

      for (let i = 0; i < 12; i++) {
        await fs.writeFile(path.join(tmpRoot, `bin-${String(i).padStart(2, '0')}.dat`), Buffer.from([0x00, 0x01, i]));
      }

      const byOpenCap = await runStaticRepositoryScan(tmpRoot, { maxOpenedFiles: 3 });
      assert.equal(byOpenCap.scannedFiles, 0);
      assert.equal(byOpenCap.scanTruncated, true);
      assert.equal(byOpenCap.redactedSecretsCount, 0, 'External symlinks must never be opened');

      const byEntryCap = await runStaticRepositoryScan(tmpRoot, { maxInspectedEntries: 2 });
      assert.equal(byEntryCap.inspectedEntries, 2, 'Streaming opendir must stop at maxInspectedEntries');
      assert.equal(byEntryCap.scanTruncated, true);
      assert.equal(process.cwd(), cwdBefore, 'Scanner must always restore process.cwd()');
    } finally {
      await fs.rm(tmpRoot, { recursive: true, force: true });
      await fs.rm(outsideDir, { recursive: true, force: true });
    }
  });

  it('detects structural exposures across all 4 stacks and passes Longinus self-audit cleanly', async () => {
    const scan = await runStaticRepositoryScan(FIXTURE_ROOT);
    const stacksHit = new Set(scan.findings.map((f) => f.stack));

    assert.ok(stacksHit.has('ts-web-api'));
    assert.ok(stacksHit.has('flutter-firebase'));
    assert.ok(stacksHit.has('python-go-cloud'));
    assert.ok(stacksHit.has('supply-chain-secrets'));
    assert.ok(!scan.architectureDigest.includes('synthetic_placeholder_not_real_987654321'));

    const selfReport = await executeDefensiveAudit({
      targetPath: PROJECT_ROOT,
      mode: 'deterministic',
      excludeRelativePrefixes: ['test'],
    });
    const severe = selfReport.findings.filter(
      (f) => f.severity === 'critical' || f.severity === 'high',
    );
    assert.equal(severe.length, 0);
    assert.ok(selfReport.overallDefenseScore >= 90);
  });

  it('blocks DNS rebinding Host headers, unauthenticated local API calls, and cross-site requests', async () => {
    const { server, url } = await startLonginusServer(0);
    try {
      const addr = server.address();
      assert.ok(typeof addr === 'object' && addr !== null);
      assert.equal(addr.address, '127.0.0.1');
      const port = addr.port;

      const res1 = await fetch(`${url}/`);
      const res2 = await fetch(`${url}/`);
      assert.equal(res1.status, 200);
      const html = await res1.text();
      const csrfMatch = html.match(/<meta\s+name="longinus-csrf"\s+content="([a-f0-9]{64})"/);
      assert.ok(csrfMatch && csrfMatch[1], 'Expected CSRF meta token in index HTML');
      const csrfToken = csrfMatch[1];

      const csp1 = res1.headers.get('content-security-policy') ?? '';
      const csp2 = res2.headers.get('content-security-policy') ?? '';
      assert.ok(csp1.includes("require-trusted-types-for 'script'"));
      assert.notEqual(csp1, csp2);

      // 1. DNS rebinding / arbitrary Host header must be rejected with 403
      const rebindStatus = await new Promise<number>((resolve, reject) => {
        const req = http.request(
          {
            hostname: '127.0.0.1',
            port,
            path: '/',
            method: 'GET',
            headers: { Host: `evil.attacker.example:${port}` },
          },
          (res) => {
            res.resume();
            resolve(res.statusCode ?? 0);
          },
        );
        req.on('error', reject);
        req.end();
      });
      assert.equal(rebindStatus, 403, 'Arbitrary Host header must be rejected with 403');

      // 2. POST /api/audit without Origin header must be rejected with 403 (even with Sec-Fetch-Site)
      const noOriginRes = await fetch(`${url}/api/audit`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Longinus-Csrf': csrfToken,
          'Sec-Fetch-Site': 'same-origin',
        },
        body: JSON.stringify({ targetPath: FIXTURE_ROOT, mode: 'deterministic' }),
      });
      assert.equal(noOriginRes.status, 403, 'Missing Origin header on POST must be rejected');

      // 2b. Missing Sec-Fetch-Site header on /api/* must be rejected with 403 even with valid Origin + CSRF
      const noFetchSiteRes = await fetch(`${url}/api/audit`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Origin: url,
          'X-Longinus-Csrf': csrfToken,
        },
        body: JSON.stringify({ targetPath: FIXTURE_ROOT, mode: 'deterministic' }),
      });
      assert.equal(noFetchSiteRes.status, 403, 'Missing Sec-Fetch-Site header must be rejected');

      const noFetchSiteGetRes = await fetch(`${url}/api/presets`, {
        headers: { 'X-Longinus-Csrf': csrfToken },
      });
      assert.equal(noFetchSiteGetRes.status, 403, 'GET /api/presets without Sec-Fetch-Site must be rejected');
      assert.equal(res1.headers.get('cache-control'), 'no-store');

      // 3. Cross-site Sec-Fetch-Site must be rejected even if other headers exist
      const crossSiteRes = await fetch(`${url}/api/audit`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Origin: url,
          'X-Longinus-Csrf': csrfToken,
          'Sec-Fetch-Site': 'cross-site',
        },
        body: JSON.stringify({ targetPath: FIXTURE_ROOT, mode: 'deterministic' }),
      });
      assert.equal(crossSiteRes.status, 403, 'Cross-site request must be rejected');

      // 4. Authorized same-origin request with matching Host + Origin + CSRF succeeds
      const authorizedRes = await fetch(`${url}/api/audit`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Origin: url,
          'X-Longinus-Csrf': csrfToken,
          'Sec-Fetch-Site': 'same-origin',
        },
        body: JSON.stringify({ targetPath: FIXTURE_ROOT, mode: 'deterministic' }),
      });
      assert.equal(authorizedRes.status, 200, 'Authorized loopback same-origin call must succeed');
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it('eliminates real-world false positives (HTML password inputs, Python identifiers, OIDC id-token) while preserving true secret redaction', () => {
    const benignJs = [
      '<input type="password" id="pw-1" class="luxury-input" style="width:100%">',
      'const privateKey = crypto.createPrivateKey(rawPem.replace(/\\n/g, "\\n"));',
      'if (privateKey.asymmetricKeyType !== "ed25519") return null;',
      'const out = privateValues.reduce((t, pv) => t.split(pv).join("***"), src);',
    ].join('\n');
    const jsRes = redactSecretsPreserveLines(benignJs, { ext: '.js' });
    assert.equal(jsRes.redactionCount, 0, 'Benign JS/HTML patterns must trigger 0 false redactions');

    const pythonMixed = [
      'def __init__(self, api_key: str) -> None:',
      '    """api_key: 使用するAPIキー文字列"""',
      '    self._api_key = api_key',
      '    self._env_key = os.environ.get("ANTHROPIC_API_KEY", "")',
      '    self._fallback_key = os.environ.get("ANTHROPIC_API_KEY", "AUDIT_PY_FALLBACK_99")',
    ].join('\n');
    const pyRes = redactSecretsPreserveLines(pythonMixed, { ext: '.py' });
    assert.equal(pyRes.redactionCount, 1, 'Only true hardcoded fallback literal should be redacted');
    assert.ok(!pyRes.redactedText.includes('AUDIT_PY_FALLBACK_99'));
    assert.ok(pyRes.redactedText.includes('self._api_key = api_key'));
    assert.ok(pyRes.redactedText.includes('"ANTHROPIC_API_KEY"'));

    const ghaYaml = [
      'permissions:',
      '  contents: read',
      '  id-token: write',
      'env:',
      '  API_SECRET: AUDIT_GHA_YAML_SECRET_88',
    ].join('\n');
    const ghaRes = redactSecretsPreserveLines(ghaYaml, { ext: '.yml' });
    assert.equal(ghaRes.redactionCount, 1, 'id-token: write must not be flagged as a secret');
    assert.ok(ghaRes.redactedText.includes('id-token: write'));
    assert.ok(!ghaRes.redactedText.includes('AUDIT_GHA_YAML_SECRET_88'));
  });

  it('detects SQLi, SSRF, weak token crypto, CI script injection, committed keystores, and exports valid SARIF 2.1.0 + Portfolio Shield', async () => {
    const portfolioTmp = await fs.mkdtemp(path.join(os.tmpdir(), 'longinus-portfolio-test-'));
    const repoVuln = path.join(portfolioTmp, 'alpha-service');
    const repoClean = path.join(portfolioTmp, 'beta-hardened');
    const outsideTarget = await fs.mkdtemp(path.join(os.tmpdir(), 'longinus-portfolio-outside-'));
    try {
      await fs.mkdir(path.join(repoVuln, '.github', 'workflows'), { recursive: true });
      await fs.mkdir(repoClean, { recursive: true });
      await fs.writeFile(path.join(outsideTarget, 'leak.ts'), 'API_SECRET="OUTSIDE_LEAK_777"', 'utf8');
      await fs.symlink(outsideTarget, path.join(portfolioTmp, 'symlinked-repo'));

      // Populate alpha-service with all 6 Phase-2 vulnerability patterns
      await fs.writeFile(
        path.join(repoVuln, 'api.ts'),
        [
          'export async function handler(req: any, res: any, db: any, crypto: any) {',
          '  const rows = await db.query(`SELECT * FROM accounts WHERE email = ${req.query.email}`);',
          '  const sessionToken = Math.random().toString(36).slice(2);',
          '  const digest = crypto.createHash("md5").update(sessionToken).digest("hex");',
          '  const upstream = await fetch(req.query.targetUrl);',
          '  return { rows, digest, upstream };',
          '}',
        ].join('\n'),
        'utf8',
      );
      await fs.writeFile(
        path.join(repoVuln, 'repo.py'),
        [
          'def find_user(cursor, uid: str):',
          '    cursor.execute(f"SELECT id FROM users WHERE uid = {uid}")',
        ].join('\n'),
        'utf8',
      );
      await fs.writeFile(
        path.join(repoVuln, '.github', 'workflows', 'ci.yml'),
        [
          'name: CI',
          'on: pull_request',
          'jobs:',
          '  check:',
          '    runs-on: ubuntu-latest',
          '    steps:',
          '      - name: Safe env binding',
          '        env:',
          '          SAFE_TITLE: ${{ github.event.pull_request.title }}',
          '        run: echo "$SAFE_TITLE"',
          '      - name: Unsafe direct interpolation',
          '        run: echo "${{ github.event.issue.title }}"',
        ].join('\n'),
        'utf8',
      );
      await fs.writeFile(path.join(repoVuln, 'release-signing.jks'), Buffer.from([0xfe, 0xed, 0xfa, 0xce]));

      // Populate beta-hardened with clean code + lockfile
      await fs.writeFile(path.join(repoClean, 'package.json'), '{"name":"beta","private":true}', 'utf8');
      await fs.writeFile(path.join(repoClean, 'pnpm-lock.yaml'), 'lockfileVersion: "9.0"\n', 'utf8');
      await fs.writeFile(path.join(repoClean, 'index.ts'), 'export const health = () => "ok";\n', 'utf8');

      const vulnReport = await executeDefensiveAudit({
        targetPath: repoVuln,
        mode: 'deterministic',
      });
      const ruleIds = new Set(vulnReport.findings.map((f) => f.ruleId));
      for (const expectedRule of [
        'LNG-TS-006',
        'LNG-TS-007',
        'LNG-TS-008',
        'LNG-CLD-005',
        'LNG-SEC-004',
        'LNG-SEC-005',
      ]) {
        assert.ok(ruleIds.has(expectedRule), `Expected ${expectedRule} to be detected`);
      }

      // Verify safe env: line in ci.yml was NOT flagged by LNG-SEC-004 (only line 12 unsafe run:)
      const sec004Hits = vulnReport.findings.filter((f) => f.ruleId === 'LNG-SEC-004');
      assert.equal(sec004Hits.length, 1);
      assert.equal(sec004Hits[0]?.line, 12);

      // Verify SARIF 2.1.0 serializer & CI threshold gate
      assert.equal(meetsFailOnThreshold(vulnReport.findings, 'critical'), true);
      const sarif = buildSarifReport(vulnReport);
      assert.equal(sarif.version, '2.1.0');
      assert.equal(sarif.runs[0]?.results.length, vulnReport.findings.length);

      // Verify Portfolio Fleet Shield + HTTP /api/portfolio & /api/sarif zero-trust guards
      const portfolio = await scanPortfolioDirectory({ portfolioRoot: portfolioTmp });
      assert.equal(portfolio.totalRepos, 2, 'Symlinked child repo must be skipped');
      assert.equal(portfolio.repos[0]?.dirName, 'alpha-service', 'Lowest score must sort first');
      assert.equal(portfolio.repos[1]?.dirName, 'beta-hardened');
      assert.ok(!JSON.stringify(portfolio).includes('OUTSIDE_LEAK_777'));

      const { server, url } = await startLonginusServer(0, { portfolioRoot: portfolioTmp });
      try {
        const indexHtml = await (await fetch(`${url}/`)).text();
        const csrf = indexHtml.match(/<meta\s+name="longinus-csrf"\s+content="([a-f0-9]{64})"/)?.[1] ?? '';

        // Reject arbitrary path injection on /api/portfolio
        const badBodyRes = await fetch(`${url}/api/portfolio`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Origin: url,
            'X-Longinus-Csrf': csrf,
            'Sec-Fetch-Site': 'same-origin',
          },
          body: JSON.stringify({ portfolioRoot: '/etc' }),
        });
        assert.equal(badBodyRes.status, 400, '/api/portfolio must reject unexpected body fields');

        const okPortfolioRes = await fetch(`${url}/api/portfolio`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Origin: url,
            'X-Longinus-Csrf': csrf,
            'Sec-Fetch-Site': 'same-origin',
          },
          body: '{}',
        });
        assert.equal(okPortfolioRes.status, 200);
        const okPortfolioJson = (await okPortfolioRes.json()) as { totalRepos: number };
        assert.equal(okPortfolioJson.totalRepos, 2);

        const okSarifRes = await fetch(`${url}/api/sarif`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Origin: url,
            'X-Longinus-Csrf': csrf,
            'Sec-Fetch-Site': 'same-origin',
          },
          body: JSON.stringify({ targetPath: repoVuln, mode: 'deterministic' }),
        });
        assert.equal(okSarifRes.status, 200);
        assert.equal(okSarifRes.headers.get('cache-control'), 'no-store');
        assert.match(okSarifRes.headers.get('content-type') ?? '', /application\/sarif\+json/);
      } finally {
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    } finally {
      await fs.rm(portfolioTmp, { recursive: true, force: true });
      await fs.rm(outsideTarget, { recursive: true, force: true });
    }
  });

  it('enforces direct root symlink rejection, depth cap, multiline call/YAML/connstring redaction, and filePath redaction', async () => {
    // 1. Direct symlink target root rejection & expectedRootIdentity check + depth cap
    const realOutside = await fs.mkdtemp(path.join(os.tmpdir(), 'longinus-symroot-real-'));
    const symHolder = await fs.mkdtemp(path.join(os.tmpdir(), 'longinus-symroot-holder-'));
    const symRootPath = path.join(symHolder, 'linked-root');
    try {
      await fs.writeFile(path.join(realOutside, 'app.ts'), 'export const x = 1;\n', 'utf8');
      await fs.symlink(realOutside, symRootPath);

      await assert.rejects(
        () => resolveSafeTargetDirectory(symRootPath),
        /ローカルディレクトリ/,
        'Direct symlink root must be rejected without dereferencing',
      );
      await assert.rejects(
        () => runStaticRepositoryScan(`${symRootPath}/`),
        /ローカルディレクトリ/,
        'Trailing-slash symlink root must also be rejected',
      );
      await assert.rejects(
        () =>
          runStaticRepositoryScan(realOutside, {
            expectedRootIdentity: { dev: -1, ino: -1, parentDev: -1, parentIno: -1 },
          }),
        /境界検証/,
        'Mismatched expectedRootIdentity must abort before walking',
      );

      // Deep nested directory chain must truncate cleanly at maxDirectoryDepth
      const deepLeaf = path.join(realOutside, 'd1', 'd2', 'd3', 'd4', 'd5');
      await fs.mkdir(deepLeaf, { recursive: true });
      await fs.writeFile(path.join(deepLeaf, 'deep.ts'), 'export const z = 2;\n', 'utf8');
      const depthCapped = await runStaticRepositoryScan(realOutside, { maxDirectoryDepth: 3 });
      assert.equal(depthCapped.scanTruncated, true);
      assert.equal(depthCapped.scannedFiles, 1, 'Only root app.ts should be scanned within depth 3');

      // Secret-bearing filename must be redacted in SecurityFinding.id and filePath
      const fakeTok = `ghp_${'A'.repeat(28)}`;
      const secretNamedFile = path.join(realOutside, `leak-${fakeTok}.ts`);
      await fs.writeFile(secretNamedFile, 'element.innerHTML = userHtml;\n', 'utf8');
      const secretPathScan = await runStaticRepositoryScan(realOutside);
      const serializedFindings = JSON.stringify(secretPathScan.findings);
      assert.ok(!serializedFindings.includes(fakeTok), 'Secret in filename must never leak in findings');
    } finally {
      await fs.rm(symHolder, { recursive: true, force: true });
      await fs.rm(realOutside, { recursive: true, force: true });
    }

    // 2. Unquoted YAML scalars, connection strings with ';', and multiline calls/ternaries
    const yamlComplex = [
      'api_secret: ${API_SECRET:-CANARY_YAML_FALLBACK_01}',
      'webhook_secret: p@ss(word)!99',
      'signing_key: multi word passphrase # prod note',
      'pin_secret: 9a7',
      'pure_ref_secret: ${API_SECRET}',
    ].join('\n');
    const yamlOut = redactSecretsPreserveLines(yamlComplex, { ext: '.yml' });
    for (const c of [
      'CANARY_YAML_FALLBACK_01',
      'p@ss(word)!99',
      'multi word passphrase',
      '9a7',
    ]) {
      assert.ok(!yamlOut.redactedText.includes(c), `Unquoted YAML canary leaked: ${c}`);
    }
    assert.ok(yamlOut.redactedText.includes('pure_ref_secret: ${API_SECRET}'));

    const connOut = redactSecrets('DATABASE_URL=Host=db;Password=CANARY_CONN_SECRET_02;');
    assert.ok(!connOut.redactedText.includes('CANARY_CONN_SECRET_02'));

    const pyMultiline = [
      'a = os.environ.get(',
      '    "API_KEY",',
      ')',
      'b = os.environ.get(',
      '    "API_KEY",',
      '    "CANARY_PY_ML_03",',
      ')',
      'c = os.environ.setdefault(',
      '    "AUTH_TOKEN",',
      '    "CANARY_PY_SETDEF_04",',
      ')',
    ].join('\n');
    const pyOut = redactSecretsPreserveLines(pyMultiline, { ext: '.py' });
    assert.equal(pyOut.redactionCount, 2, '1-arg trailing-comma call must not trigger false redaction');
    assert.ok(!pyOut.redactedText.includes('CANARY_PY_ML_03'));
    assert.ok(!pyOut.redactedText.includes('CANARY_PY_SETDEF_04'));

    const multiLangCalls = [
      'os.Setenv(',
      '  "API_KEY",',
      '  "CANARY_GO_ML_05",',
      ')',
      'apiSecret :=',
      '  "CANARY_GO_ASSIGN_06"',
      'await storage.write(',
      "  key: 'session_token',",
      "  value: 'CANARY_DART_ML_07',",
      ');',
      'headers.set("X-Api-Key", "CANARY_HDR_SET_08");',
      'const API_SECRET =',
      '  cond ? primary : "CANARY_TS_TERNARY_09";',
    ].join('\n');
    const mlOut = redactSecretsPreserveLines(multiLangCalls, { ext: '.ts' });
    for (const c of [
      'CANARY_GO_ML_05',
      'CANARY_GO_ASSIGN_06',
      'CANARY_DART_ML_07',
      'CANARY_HDR_SET_08',
      'CANARY_TS_TERNARY_09',
    ]) {
      assert.ok(!mlOut.redactedText.includes(c), `Multiline call/assignment canary leaked: ${c}`);
    }
  });

  it('hardens Round-2 clean-room edge cases (F-01..F-07): .env comments/multi-assign, DSN/URI/K8s/Python-paren redaction, oversize/sibling truncation, external rules.ts scanning, portfolio --fail-on, and HTTP 413 JSON', async () => {
    // F-01: .env commented secrets & multi-assignments on a single line
    const envEdge = [
      '# API_SECRET="CANARY_ENV_COMMENT_01"',
      'PORT=8080 # SECRET_TOKEN=CANARY_ENV_INLINE_COMMENT_02',
      'NODE_ENV="production" NEXT_PUBLIC_API_SECRET="CANARY_ENV_MULTI_03" API_KEY=CANARY_ENV_MULTI_04',
    ].join('\n');
    const envOut = redactSecretsPreserveLines(envEdge, { isEnvFile: true });
    assert.equal(envOut.redactedText.split('\n').length, 3);
    for (const c of [
      'CANARY_ENV_COMMENT_01',
      'CANARY_ENV_INLINE_COMMENT_02',
      'CANARY_ENV_MULTI_03',
      'CANARY_ENV_MULTI_04',
    ]) {
      assert.ok(!envOut.redactedText.includes(c), `.env canary leaked: ${c}`);
    }

    // F-02: empty-username Redis URI, semicolon connstring literals, Python parens, + / ? continuations, Docker ENV \, K8s - name/value
    const codeEdge = [
      'const redisUrl = "redis://:CANARY_REDIS_EMPTY_USER_05@127.0.0.1:6379/0";',
      'const conn = "Host=db;Password=CANARY_CONN_LIT_06;Port=5432";',
      'const azure = "Endpoint=sb://demo;SharedAccessKey=CANARY_AZURE_SAS_07;";',
      'API_SECRET = (',
      '    "CANARY_PY_PAREN_08"',
      '    "CANARY_PY_PAREN_09"',
      ')',
      'const NEXT_PUBLIC_API_KEY = "CANARY_PLUS_10" +',
      '  "CANARY_PLUS_11";',
      'const AUTH_TOKEN = isProd',
      '  ? "CANARY_TERN_12"',
      '  : "CANARY_TERN_13";',
    ].join('\n');
    const codeOut = redactSecretsPreserveLines(codeEdge, { ext: '.ts' });
    for (const c of [
      'CANARY_REDIS_EMPTY_USER_05',
      'CANARY_CONN_LIT_06',
      'CANARY_AZURE_SAS_07',
      'CANARY_PY_PAREN_08',
      'CANARY_PY_PAREN_09',
      'CANARY_PLUS_10',
      'CANARY_PLUS_11',
      'CANARY_TERN_12',
      'CANARY_TERN_13',
    ]) {
      assert.ok(!codeOut.redactedText.includes(c), `Code edge canary leaked: ${c}`);
    }

    const dockerEdge = ['ENV API_SECRET \\', '  CANARY_DOCKER_BS_14'].join('\n');
    const dockerOut = redactSecretsPreserveLines(dockerEdge, { ext: '' });
    assert.ok(!dockerOut.redactedText.includes('CANARY_DOCKER_BS_14'));

    const k8sEdge = [
      'env:',
      '  - name: API_SECRET',
      '    value: "CANARY_K8S_VAL_15"',
      '  - name: SAFE_MODE',
      '    value: "enabled"',
    ].join('\n');
    const k8sOut = redactSecretsPreserveLines(k8sEdge, { ext: '.yaml' });
    assert.ok(!k8sOut.redactedText.includes('CANARY_K8S_VAL_15'));
    assert.ok(k8sOut.redactedText.includes('value: "enabled"'));

    // F-02 (label redaction) + F-03 (oversize & branch-local truncation) + F-04 (external src/rules.ts MUST be scanned) + F-06 (CLI --portfolio --fail-on)
    const tmpHolder = await fs.mkdtemp(path.join(os.tmpdir(), 'longinus-r2-suite-'));
    const dynTok = `${'ghp'}_${'D'.repeat(28)}`;
    const dynAws = `${'AKIA'}${'E'.repeat(16)}`;
    const extRepo = path.join(tmpHolder, `svc-${dynTok}`);
    try {
      await fs.mkdir(path.join(extRepo, 'a', 'b', 'c', 'd'), { recursive: true });
      await fs.mkdir(path.join(extRepo, 'src'), { recursive: true });
      await fs.writeFile(
        path.join(extRepo, 'a', 'b', 'c', 'd', 'deep.ts'),
        'export const deep = 1;\n',
        'utf8',
      );
      await fs.writeFile(
        path.join(extRepo, 'src', 'rules.ts'),
        `export const bad = eval(untrusted);\nexport const k = "${dynAws}";\n`,
        'utf8',
      );
      await fs.writeFile(path.join(extRepo, 'oversize.ts'), 'x'.repeat(2048), 'utf8');

      // 1. Oversize file sets scanTruncated=true AND branch-local depth cap still scans shallow sibling src/rules.ts!
      const boundedScan = await runStaticRepositoryScan(extRepo, {
        maxDirectoryDepth: 2,
        maxFileBytes: 512,
      });
      assert.equal(boundedScan.scanTruncated, true);
      assert.ok(
        boundedScan.findings.some((f) => f.filePath === 'src/rules.ts'),
        'External repository src/rules.ts MUST be scanned even when sibling branch hits depth cap',
      );
      assert.ok(boundedScan.redactedSecretsCount >= 1);

      // 2. Repo name containing a token shape is redacted in AuditReport.repoName & executiveSummary
      const fullAudit = await executeDefensiveAudit({
        targetPath: extRepo,
        mode: 'deterministic',
      });
      assert.ok(!JSON.stringify(fullAudit).includes(dynTok), 'Token in repo directory name must be redacted');
      assert.ok(!JSON.stringify(fullAudit).includes(dynAws), 'AWS key in external src/rules.ts must be redacted');

      // 3. Portfolio CLI --fail-on skips secret-named dir, flags vuln-child, and exits with code 2
      const vulnChild = path.join(tmpHolder, 'vuln-child');
      await fs.mkdir(vulnChild, { recursive: true });
      await fs.writeFile(path.join(vulnChild, 'index.ts'), 'export const r = eval(rawInput);\n', 'utf8');

      let cliOut = '';
      const exitCodeCrit = await runCli(['--portfolio', tmpHolder, '--fail-on', 'critical'], {
        writeStdout: (s) => {
          cliOut += s;
        },
        writeStderr: () => {},
      });
      assert.equal(exitCodeCrit, 2, '--portfolio --fail-on critical must return exit code 2');
      const parsedPortfolio = JSON.parse(cliOut) as {
        repos: Parameters<typeof meetsPortfolioFailOnThreshold>[0];
      };
      assert.ok(!cliOut.includes(dynTok), 'Secret-bearing child dir must never appear in portfolio JSON');
      assert.equal(meetsPortfolioFailOnThreshold(parsedPortfolio.repos, 'critical'), true);

      // F-07: Oversize HTTP POST body (> 32 KiB) returns clean 413 JSON response (never ECONNRESET)
      const { server, url } = await startLonginusServer(0, { portfolioRoot: tmpHolder });
      try {
        const html = await (await fetch(`${url}/`)).text();
        const csrf = html.match(/<meta\s+name="longinus-csrf"\s+content="([a-f0-9]{64})"/)?.[1] ?? '';
        const oversizePayload = JSON.stringify({
          targetPath: extRepo,
          mode: 'deterministic',
          pad: 'P'.repeat(48 * 1024),
        });
        const oversizeRes = await fetch(`${url}/api/audit`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Origin: url,
            'X-Longinus-Csrf': csrf,
            'Sec-Fetch-Site': 'same-origin',
          },
          body: oversizePayload,
        });
        assert.equal(oversizeRes.status, 413, 'Oversize POST must return HTTP 413 Payload Too Large');
        const oversizeJson = (await oversizeRes.json()) as { error?: string };
        assert.match(oversizeJson.error ?? '', /サイズ上限/);
      } finally {
        await new Promise<void>((resolve) => server.close(() => resolve()));
      }
    } finally {
      await fs.rm(tmpHolder, { recursive: true, force: true });
    }
  });

  it('hardens Round-3 clean-room edge cases: pending-state token/comment redaction, external redactor.ts LNG-SEC-001 detection, standalone --sarif & --fail-on=level CLI parity, and KEY=VALUE repo label digest redaction', async () => {
    const awsBackup = `${'AKIA'}${'F'.repeat(16)}`;
    const ghInline = `${'ghp'}_${'G'.repeat(28)}`;
    const r3Tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'longinus-r3-suite-'));
    const kvDir = path.join(r3Tmp, 'API_SECRET=CANARY_DIR_KV_99');

    try {
      await fs.mkdir(path.join(kvDir, 'src'), { recursive: true });

      // HIGH-1 reproduction: Python secret assignment followed immediately by comment line with AWS key,
      // plus multiline RHS & call with inline trailing token comments
      await fs.writeFile(
        path.join(kvDir, 'worker.py'),
        [
          'API_SECRET = "CANARY_PY_PRIMARY_01"',
          `# rotation_backup: ${awsBackup}`,
          'os.environ.setdefault(',
          '    "AUTH_TOKEN",',
          `    "CANARY_PY_CALL_02",  # old: ${ghInline}`,
          ')',
        ].join('\n'),
        'utf8',
      );

      // HIGH-2 reproduction: External repository src/redactor.ts containing hardcoded secret MUST trigger LNG-SEC-001
      await fs.writeFile(
        path.join(kvDir, 'src', 'redactor.ts'),
        `export const leakedKey = "${awsBackup}";\n`,
        'utf8',
      );

      const scan = await runStaticRepositoryScan(kvDir);
      const serializedScan = JSON.stringify(scan);
      for (const secret of [
        awsBackup,
        ghInline,
        'CANARY_PY_PRIMARY_01',
        'CANARY_PY_CALL_02',
        'CANARY_DIR_KV_99',
      ]) {
        assert.ok(!serializedScan.includes(secret), `Secret leaked in StaticScanResult/digest: ${secret}`);
      }
      assert.ok(
        scan.findings.some((f) => f.ruleId === 'LNG-SEC-001' && f.filePath === 'src/redactor.ts'),
        'External src/redactor.ts MUST trigger LNG-SEC-001 hardcoded secret finding',
      );

      // MEDIUM-1 reproduction: standalone --sarif (without --audit) + --fail-on=critical (= syntax)
      let sarifStdout = '';
      const sarifExit = await runCli(
        ['--sarif', kvDir, '--deterministic', '--fail-on=critical'],
        {
          writeStdout: (s) => {
            sarifStdout += s;
          },
          writeStderr: () => {},
        },
      );
      assert.equal(sarifExit, 2, 'Standalone --sarif with --fail-on=critical must exit 2');
      const parsedSarif = JSON.parse(sarifStdout) as { version?: string };
      assert.equal(parsedSarif.version, '2.1.0');
      assert.ok(!sarifStdout.includes(awsBackup));
      assert.ok(!sarifStdout.includes(ghInline));

      // Dangling --fail-on without --audit/--sarif/--portfolio must exit 1 (never hang starting server)
      let errText = '';
      const badCliExit = await runCli(['--fail-on=high'], {
        writeStdout: () => {},
        writeStderr: (s) => {
          errText += s;
        },
      });
      assert.equal(badCliExit, 1, 'Dangling --fail-on without command must fail fast with exit 1');
      assert.match(errText, /Longinus fatal error/);
    } finally {
      await fs.rm(r3Tmp, { recursive: true, force: true });
    }
  });

  it('diagnoses orthogonal engineering craft archetypes (ALGORITHMIC_MONOLITH_UNTESTABLE vs SOVEREIGN_ARCHITECT)', async () => {
    const tmpCraft = await fs.mkdtemp(path.join(os.tmpdir(), 'longinus-craft-archetype-'));
    try {
      await fs.mkdir(path.join(tmpCraft, 'src'), { recursive: true });
      await fs.writeFile(
        path.join(tmpCraft, 'src', 'cryptoGraphEngine.ts'),
        [
          'import crypto from "node:crypto";',
          'import fs from "node:fs";',
          'export function solveShortestRatchetPath(adj: Map<string, string[]>, payload: Uint8Array) {',
          '  const mac = crypto.createHmac("sha256", "key").update(payload).digest();',
          '  const sig = crypto.timingSafeEqual(mac, mac);',
          '  const shifted = (payload[0]! << 4) | (payload[1]! >> 2);',
          '  const stamp = Date.now();',
          '  (globalThis as Record<string, unknown>).lastRatchetRun = stamp;',
          '  fs.writeFileSync("/tmp/ratchet-audit.bin", mac);',
          '  void fetch("https://telemetry.example.com/ingest", { method: "POST" });',
          '  return { sig, shifted, stamp };',
          '}',
        ].join('\n'),
        'utf8',
      );

      const scan = await runStaticRepositoryScan(tmpCraft);
      assert.equal(scan.craftProfile.archetypeId, 'ALGORITHMIC_MONOLITH_UNTESTABLE');
      assert.match(scan.craftProfile.archetypeLabel, /Good at Algorithms, Writes Untestable Code/);
      assert.ok(scan.craftProfile.dimensions.algorithmicDepthScore >= 70);
      assert.ok(scan.craftProfile.dimensions.testabilityScore < 65);
      assert.ok(
        scan.craftProfile.untestableHotspots.some(
          (h) => h.ruleId === 'LNG-CRAFT-001' && h.filePath === 'src/cryptoGraphEngine.ts',
        ),
      );
      assert.ok(
        scan.craftProfile.untestableHotspots.some(
          (h) => h.ruleId === 'LNG-CRAFT-002' && h.filePath === 'src/cryptoGraphEngine.ts',
        ),
      );

      const selfScan = await runStaticRepositoryScan(PROJECT_ROOT, {
        excludeRelativePrefixes: ['test'],
      });
      assert.equal(selfScan.craftProfile.archetypeId, 'SOVEREIGN_ARCHITECT');
      assert.ok(selfScan.craftProfile.dimensions.algorithmicDepthScore >= 85);
      assert.equal(selfScan.craftProfile.dimensions.testabilityScore, 100);
    } finally {
      await fs.rm(tmpCraft, { recursive: true, force: true });
    }
  });

  it('returns unscoped 0 scores and UNSCOPED_NO_SOURCE_CODE for empty directories instead of vacuous 100/100', async () => {
    const emptyDir = await fs.mkdtemp(path.join(os.tmpdir(), 'longinus-empty-unscoped-'));
    try {
      const scan = await runStaticRepositoryScan(emptyDir);
      assert.equal(scan.scannedFiles, 0);
      assert.equal(scan.craftProfile.archetypeId, 'UNSCOPED_NO_SOURCE_CODE');
      assert.equal(scan.craftProfile.dimensions.algorithmicDepthScore, 0);
      assert.equal(scan.craftProfile.dimensions.testabilityScore, 0);

      const report = await executeDefensiveAudit({
        targetPath: emptyDir,
        mode: 'deterministic',
      });
      assert.equal(report.overallDefenseScore, 0);
      assert.match(report.executiveSummary, /未評価 \/ UNSCOPED/);
      assert.ok(report.stackSummaries.every((s) => s.evaluated === false && s.defenseScore === 0));
      assert.ok(report.strideMatrix.every((s) => s.exposureScore === 0 && s.readinessScore === 0));
    } finally {
      await fs.rm(emptyDir, { recursive: true, force: true });
    }
  });
});
