import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  classifySafeGeminiFallbackReason,
  executeDefensiveAudit,
  selectOptimalReasoningLevel,
  validateAndTransformGeminiOutput,
} from '../src/geminiAnalyzer.js';
import { redactSecrets, redactSecretsPreserveLines } from '../src/redactor.js';
import {
  readBoundedFromHandle,
  resolveSafeTargetDirectory,
  runStaticRepositoryScan,
} from '../src/scanner.js';
import { startLonginusServer } from '../src/server.js';

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

      // 2. POST /api/audit without Origin header must be rejected with 403
      const noOriginRes = await fetch(`${url}/api/audit`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Longinus-Csrf': csrfToken,
        },
        body: JSON.stringify({ targetPath: FIXTURE_ROOT, mode: 'deterministic' }),
      });
      assert.equal(noOriginRes.status, 403, 'Missing Origin header on POST must be rejected');

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
});
