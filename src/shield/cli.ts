import fsSync from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanDirectory } from '../graph/attack-graph.ts';
import { formatBlueprint } from '../report/formatter.ts';
import { proposeRemediations } from '../report/remediation.ts';
import { SUPPORTED_LANGUAGES, type ConsultingAudience, type ReportLanguage } from '../types.ts';
import { executeDefensiveAudit, scanPortfolioDirectory } from './geminiAnalyzer.ts';
import { redactSecrets } from './redactor.ts';
import {
  buildSarifReport,
  meetsFailOnThreshold,
  meetsPortfolioFailOnThreshold,
} from './sarif.ts';
import { startLonginusServer } from './server.ts';
import type { AnalysisMode, AuditReport, SeverityLevel } from './types.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RAW_PROJECT_ROOT = path.resolve(
  __dirname,
  __dirname.includes(`${path.sep}dist${path.sep}`) ? '../../..' : '../..',
);
const PROJECT_ROOT = fsSync.realpathSync(RAW_PROJECT_ROOT);

const VALID_FAIL_THRESHOLDS = new Set<SeverityLevel>(['critical', 'high', 'medium', 'low']);
const VALID_AUDIENCES = new Set<ConsultingAudience>(['enterprise', 'municipal', 'sme']);
const VALID_LANGUAGES = new Set<string>(SUPPORTED_LANGUAGES);

interface ParsedCliOptions {
  command: 'server' | 'portfolio' | 'audit';
  targetPath?: string;
  emitSarif: boolean;
  emitBlueprint: boolean;
  emitPatch: boolean;
  emitPrompt: boolean;
  lang: ReportLanguage;
  audience: ConsultingAudience;
  mode: AnalysisMode;
  failOn?: SeverityLevel;
}

function validateFailThreshold(raw: string): SeverityLevel {
  const normalized = raw.trim().toLowerCase() as SeverityLevel;
  if (!VALID_FAIL_THRESHOLDS.has(normalized)) {
    throw new Error('Invalid --fail-on value. Expected one of: critical, high, medium, low.');
  }
  return normalized;
}

function validateLanguage(raw: string): ReportLanguage {
  const trimmed = raw.trim();
  if (!VALID_LANGUAGES.has(trimmed)) {
    throw new Error(`Invalid --lang value: ${trimmed}`);
  }
  return trimmed as ReportLanguage;
}

function validateAudience(raw: string): ConsultingAudience {
  const normalized = raw.trim().toLowerCase() as ConsultingAudience;
  if (!VALID_AUDIENCES.has(normalized)) {
    throw new Error('Invalid --audience value. Expected one of: enterprise, municipal, sme.');
  }
  return normalized;
}

function formatUnifiedBlueprintAndShield(
  blueprintMarkdown: string,
  shieldReport: AuditReport,
  lang: ReportLanguage,
): string {
  const isJa = lang === 'ja';
  const shieldUnscoped =
    shieldReport.scannedFiles === 0 ||
    shieldReport.stackSummaries.every((s) => !s.evaluated);
  const overallScoreLabel = shieldUnscoped
    ? isJa
      ? '**N/A (UNSCOPED — 評価対象のコード・構成ファイル 0 件のため未評価)**'
      : '**N/A (UNSCOPED — 0 code/stack files evaluated)**'
    : `**${shieldReport.overallDefenseScore}/100**`;

  const sectionLines: string[] = [
    blueprintMarkdown.trimEnd(),
    '',
    '---',
    '',
    isJa
      ? `## 9. 4-Stack ソースコード＆1,529種シークレット防衛シールド統合監査 (${shieldReport.repoName})`
      : `## 9. 4-Stack Source Code & 1,529-Pattern Secret Shield Unified Audit (${shieldReport.repoName})`,
    isJa
      ? `- **総合コード防御スコア**: ${overallScoreLabel}`
      : `- **Overall Code Defense Score**: ${overallScoreLabel}`,
    isJa
      ? `- **走査ファイル数**: ${shieldReport.scannedFiles} files (切り詰め: \`${shieldReport.scanTruncated}\` · 自動マスク保護機密: ${shieldReport.redactedSecretsCount} 箇所 · 所要 ${shieldReport.durationMs}ms)`
      : `- **Scanned Files**: ${shieldReport.scannedFiles} files (Truncated: \`${shieldReport.scanTruncated}\` · Redacted Secrets Protected: ${shieldReport.redactedSecretsCount} · Duration: ${shieldReport.durationMs}ms)`,
    isJa
      ? `- **エグゼクティブ予防要約**: ${shieldReport.executiveSummary}`
      : `- **Executive Preventive Summary**: ${shieldReport.executiveSummary}`,
    '',
    isJa ? '### 4技術スタック別・防御姿勢スコア一覧' : '### 4-Stack Defense Posture Breakdown',
    isJa
      ? '| 技術スタック | 対象ファイル | 防御スコア | 指摘内訳 (Critical / High / Medium / Low) |'
      : '| Stack | Detected Files | Defense Score | Findings (Critical / High / Medium / Low) |',
    '| --- | ---: | ---: | --- |',
    ...shieldReport.stackSummaries.map((s) => {
      const hasAnyFinding = s.criticalCount + s.highCount + s.mediumCount + s.lowCount > 0;
      if (s.detectedFiles === 0 && !hasAnyFinding) {
        return isJa
          ? `| ${s.label} | 0 | N/A (対象 0件) | - |`
          : `| ${s.label} | 0 | N/A (0 files) | - |`;
      }
      return `| ${s.label} | ${s.detectedFiles} | **${s.defenseScore}/100** | C:${s.criticalCount} / H:${s.highCount} / M:${s.mediumCount} / L:${s.lowCount} |`;
    }),
    '',
    isJa
      ? '### 直交エンジニアリング・クラフト＆テスタビリティ診断 (Orthogonal Skill & Testability Archetype)'
      : '### Orthogonal Engineering Craft & Testability Archetype Diagnosis',
    isJa
      ? `- **診断アーキタイプ**: \`${shieldReport.craftProfile.archetypeId}\` — **${shieldReport.craftProfile.archetypeLabel}**`
      : `- **Diagnosed Archetype**: \`${shieldReport.craftProfile.archetypeId}\` — **${shieldReport.craftProfile.archetypeLabel}**`,
    isJa
      ? `- **構造診断サマリー**: ${shieldReport.craftProfile.diagnosisSummary}`
      : `- **Structural Diagnosis**: ${shieldReport.craftProfile.diagnosisSummary}`,
    '',
    isJa
      ? '| 直交スキル評価軸 (Orthogonal Axis) | スコア | 構造テレメトリ指標 |'
      : '| Orthogonal Evaluation Axis | Score | Structural Telemetry Metric |',
    '| --- | ---: | --- |',
    isJa
      ? `| アルゴリズム・暗号・データ構造深度 | **${shieldReport.craftProfile.dimensions.algorithmicDepthScore}/100** | アルゴリズム/暗号プリミティブ信号: ${shieldReport.craftProfile.metrics.algorithmicSignalCount} 件 |`
      : `| Algorithmic, Crypto & Data-Structure Depth | **${shieldReport.craftProfile.dimensions.algorithmicDepthScore}/100** | Algorithmic/Crypto Primitive Signals: ${shieldReport.craftProfile.metrics.algorithmicSignalCount} |`,
    isJa
      ? `| テスタビリティ・DI疎結合度 (Testability) | **${shieldReport.craftProfile.dimensions.testabilityScore}/100** | 本番コード: ${shieldReport.craftProfile.metrics.productionCodeFiles} / テスト: ${shieldReport.craftProfile.metrics.testFiles} (比率: ${shieldReport.craftProfile.metrics.testToCodeRatio}) · I/O密結合: ${shieldReport.craftProfile.metrics.coupledIoInAlgorithmicFiles} 件 |`
      : `| Testability & Dependency Injection Decoupling | **${shieldReport.craftProfile.dimensions.testabilityScore}/100** | Prod Files: ${shieldReport.craftProfile.metrics.productionCodeFiles} / Tests: ${shieldReport.craftProfile.metrics.testFiles} (Ratio: ${shieldReport.craftProfile.metrics.testToCodeRatio}) · Coupled I/O in Algo: ${shieldReport.craftProfile.metrics.coupledIoInAlgorithmicFiles} |`,
    isJa
      ? `| 決定論性・境界制御 (Determinism & Bounds) | **${shieldReport.craftProfile.dimensions.determinismScore}/100** | 非注入クロック/PRNG状態: ${shieldReport.craftProfile.metrics.uninjectedNonDeterminismFiles} 件 · 巨大Godモジュール: ${shieldReport.craftProfile.metrics.oversizedGodModules} 件 |`
      : `| Determinism & Resource Bounds | **${shieldReport.craftProfile.dimensions.determinismScore}/100** | Uninjected Clock/PRNG Files: ${shieldReport.craftProfile.metrics.uninjectedNonDeterminismFiles} · Untested God-Modules: ${shieldReport.craftProfile.metrics.oversizedGodModules} |`,
    isJa
      ? `| セキュリティ信頼境界 (Security Boundary) | **${shieldReport.craftProfile.dimensions.securityBoundaryScore}/100** | 4-Stack ゼロトラスト境界防御スコア連動 |`
      : `| Security & Trust Boundary Isolation | **${shieldReport.craftProfile.dimensions.securityBoundaryScore}/100** | Coupled with 4-Stack Zero-Trust Boundary Posture |`,
    '',
    ...(shieldReport.craftProfile.untestableHotspots.length > 0
      ? [
          isJa
            ? '#### Untestable Code / 非対称結合ホットスポット (`LNG-CRAFT-001..003`)'
            : '#### Untestable Code & Asymmetry Hotspots (`LNG-CRAFT-001..003`)',
          ...shieldReport.craftProfile.untestableHotspots.flatMap((h) => [
            `- **[\`${h.ruleId}\`]** \`${h.filePath}:${h.line}\` — **${h.title}**`,
            `  - ${h.asymmetrySignal}`,
            `  - *Refactoring*: ${h.refactoringPatch}`,
          ]),
          '',
        ]
      : []),
    isJa ? '### 4-Stack コードレベル優先指摘一覧' : '### 4-Stack Code-Level Prioritized Findings',
  ];

  if (shieldReport.findings.length === 0) {
    sectionLines.push(
      isJa
        ? '4技術スタック全体で重大な静的コード露出は検出されませんでした。'
        : 'No static code exposures were detected across the 4 technology stacks.',
    );
  } else {
    for (const f of shieldReport.findings.slice(0, 25)) {
      sectionLines.push(
        `- **[${f.severity.toUpperCase()}]** \`${f.filePath}:${f.line}\` — **${f.title}** (\`${f.ruleId}\` · *${f.stride}* · *${f.cwe}* · *${f.owaspAsvs}*)`,
        `  - ${f.rootCause}`,
      );
    }
  }

  sectionLines.push(
    '',
    isJa
      ? '### AI エージェント用・第一原理修正プロンプト'
      : '### AI Agent First-Principles Remediation Prompt',
    '```text',
    shieldReport.remediationPrompt,
    '```',
  );

  return `${sectionLines.join('\n')}\n`;
}

function parseCliArgs(args: readonly string[]): ParsedCliOptions {
  if (args.length === 0) {
    return {
      command: 'server',
      emitSarif: false,
      emitBlueprint: false,
      emitPatch: false,
      emitPrompt: false,
      lang: 'en',
      audience: 'enterprise',
      mode: 'gemini-3.8-flash',
    };
  }

  let hasPortfolio = false;
  let hasAudit = false;
  let emitSarif = false;
  let emitBlueprint = false;
  let emitPatch = false;
  let emitPrompt = false;
  let lang: ReportLanguage = 'en';
  let audience: ConsultingAudience = 'enterprise';
  let explicitMode: AnalysisMode | undefined;
  let failOn: SeverityLevel | undefined;
  const positionals: string[] = [];

  for (let i = 0; i < args.length; i++) {
    const arg = args[i] ?? '';
    if (arg === 'audit' && positionals.length === 0 && !hasAudit) {
      hasAudit = true;
      continue;
    }
    if (arg === '--portfolio') {
      hasPortfolio = true;
      continue;
    }
    if (arg === '--audit') {
      hasAudit = true;
      continue;
    }
    if (arg === '--sarif' || arg === '--format=sarif') {
      emitSarif = true;
      continue;
    }
    if (arg === '--blueprint' || arg === '--unified' || arg === '--format=blueprint') {
      emitBlueprint = true;
      continue;
    }
    if (arg === '--format') {
      const val = args[i + 1];
      if (val === 'blueprint') {
        emitBlueprint = true;
        i += 1;
        continue;
      }
      if (val === 'sarif') {
        emitSarif = true;
        i += 1;
        continue;
      }
      throw new Error('Invalid --format value. Expected blueprint or sarif.');
    }
    if (arg === '--emit-patch') {
      emitPatch = true;
      continue;
    }
    if (arg === '--emit-prompt' || arg === '--prompt' || arg === '--format=prompt') {
      emitPrompt = true;
      continue;
    }
    if (arg === '--lang') {
      const val = args[i + 1];
      if (!val || val.startsWith('-')) {
        throw new Error('Invalid --lang value.');
      }
      lang = validateLanguage(val);
      i += 1;
      continue;
    }
    if (arg.startsWith('--lang=')) {
      lang = validateLanguage(arg.slice('--lang='.length));
      continue;
    }
    if (arg === '--audience') {
      const val = args[i + 1];
      if (!val || val.startsWith('-')) {
        throw new Error('Invalid --audience value.');
      }
      audience = validateAudience(val);
      i += 1;
      continue;
    }
    if (arg.startsWith('--audience=')) {
      audience = validateAudience(arg.slice('--audience='.length));
      continue;
    }
    if (arg === '--deterministic') {
      explicitMode = 'deterministic';
      continue;
    }
    if (arg === '--carbon') {
      explicitMode = 'gemini-4-carbon';
      continue;
    }
    if (arg === '--neon') {
      explicitMode = 'gemini-4-neon';
      continue;
    }
    if (arg === '--hydrogen') {
      explicitMode = 'gemini-4-hydrogen';
      continue;
    }
    if (arg === '--argon') {
      explicitMode = 'gemini-4-argon';
      continue;
    }
    if (arg === '--flash') {
      explicitMode = 'gemini-3.8-flash';
      continue;
    }
    if (arg === '--fail-on') {
      const val = args[i + 1];
      if (!val || val.startsWith('-')) {
        throw new Error('Invalid --fail-on value. Expected one of: critical, high, medium, low.');
      }
      failOn = validateFailThreshold(val);
      i += 1;
      continue;
    }
    if (arg.startsWith('--fail-on=')) {
      failOn = validateFailThreshold(arg.slice('--fail-on='.length));
      continue;
    }
    if (arg.startsWith('-')) {
      throw new Error(`Unknown CLI flag: ${arg}`);
    }
    positionals.push(arg);
  }

  if (positionals.length > 1) {
    throw new Error('At most one target directory path may be specified.');
  }

  if (hasPortfolio && (hasAudit || emitSarif || emitBlueprint || emitPrompt)) {
    throw new Error('--portfolio cannot be combined with --audit, --sarif, --blueprint, or --emit-prompt.');
  }

  if (hasPortfolio) {
    return {
      command: 'portfolio',
      ...(positionals[0] !== undefined ? { targetPath: positionals[0] } : {}),
      emitSarif: false,
      emitBlueprint: false,
      emitPatch: false,
      emitPrompt: false,
      lang,
      audience,
      mode: 'deterministic',
      ...(failOn !== undefined ? { failOn } : {}),
    };
  }

  if (hasAudit || emitSarif || emitBlueprint || emitPrompt || positionals.length === 1 || explicitMode !== undefined) {
    return {
      command: 'audit',
      ...(positionals[0] !== undefined ? { targetPath: positionals[0] } : {}),
      emitSarif,
      emitBlueprint,
      emitPatch,
      emitPrompt,
      lang,
      audience,
      mode: explicitMode ?? (emitBlueprint || emitPrompt ? 'deterministic' : 'gemini-3.8-flash'),
      ...(failOn !== undefined ? { failOn } : {}),
    };
  }

  throw new Error(
    'Specify --audit [path], --blueprint [path], --sarif [path], --emit-prompt [path], or --portfolio [path] (or run with no arguments to start the 127.0.0.1 dashboard).',
  );
}

function tryCanonicalizePath(targetPath: string): string {
  const resolved = path.resolve(targetPath);
  try {
    return fsSync.realpathSync(resolved);
  } catch {
    return resolved;
  }
}

export interface CliIoHooks {
  writeStdout?: (chunk: string) => void;
  writeStderr?: (chunk: string) => void;
}

export async function runCli(args: readonly string[], io?: CliIoHooks): Promise<number> {
  const out = io?.writeStdout ?? ((s: string) => process.stdout.write(s));
  const errOut = io?.writeStderr ?? ((s: string) => process.stderr.write(s));

  try {
    const parsed = parseCliArgs(args);

    if (parsed.command === 'portfolio') {
      const portfolioRoot = parsed.targetPath ?? path.dirname(PROJECT_ROOT);
      const portfolio = await scanPortfolioDirectory({
        portfolioRoot,
        selfProjectRoot: PROJECT_ROOT,
      });
      out(`${JSON.stringify(portfolio, null, 2)}\n`);
      if (parsed.failOn && meetsPortfolioFailOnThreshold(portfolio.repos, parsed.failOn)) {
        return 2;
      }
      return 0;
    }

    if (parsed.command === 'audit') {
      const targetPath = parsed.targetPath ?? process.cwd();
      const canonicalTarget = tryCanonicalizePath(targetPath);
      const report = await executeDefensiveAudit({
        targetPath: canonicalTarget,
        mode: parsed.mode,
        ...(canonicalTarget === PROJECT_ROOT ? { excludeRelativePrefixes: ['test'] } : {}),
      });

      if (parsed.emitBlueprint) {
        const graph = scanDirectory(canonicalTarget);
        const remediations = parsed.emitPatch ? proposeRemediations(graph.findings, canonicalTarget) : [];
        const blueprintMarkdown = formatBlueprint(graph, undefined, remediations, parsed.lang, parsed.audience, {
          shieldReport: report,
        });
        out(formatUnifiedBlueprintAndShield(blueprintMarkdown, report, parsed.lang));
      } else if (parsed.emitSarif) {
        const sarif = buildSarifReport(report);
        out(`${JSON.stringify(sarif, null, 2)}\n`);
      } else if (parsed.emitPrompt) {
        out(`${report.remediationPrompt}\n`);
      } else {
        out(`${JSON.stringify(report, null, 2)}\n`);
      }

      if (parsed.failOn && meetsFailOnThreshold(report.findings, parsed.failOn)) {
        return 2;
      }
      return 0;
    }

    const portEnv = Number(process.env['PORT'] ?? '4310');
    const port = Number.isInteger(portEnv) && portEnv >= 0 && portEnv <= 65535 ? portEnv : 4310;
    const { url } = await startLonginusServer(port);
    out(`LONGINUS Defensive Posture Dashboard listening on ${url}\n`);
    return 0;
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    errOut(`Longinus fatal error: ${redactSecrets(message).redactedText.slice(0, 200)}\n`);
    return 1;
  }
}

function isDirectCliEntrypoint(): boolean {
  const invoked = process.argv[1];
  if (typeof invoked !== 'string' || invoked.length === 0) return false;
  const candidates = [
    fileURLToPath(import.meta.url),
    fileURLToPath(new URL('../../bin/longinus.mjs', import.meta.url)),
  ];
  try {
    const realInvoked = fsSync.realpathSync(invoked);
    return candidates.some((c) => {
      try {
        return realInvoked === fsSync.realpathSync(c);
      } catch {
        return false;
      }
    });
  } catch {
    const absInvoked = path.resolve(invoked);
    return candidates.some((c) => absInvoked === path.resolve(c));
  }
}

if (isDirectCliEntrypoint()) {
  void runCli(process.argv.slice(2)).then((code) => {
    if (code !== 0) {
      process.exitCode = code;
    }
  });
}
