import fsSync from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { executeDefensiveAudit, scanPortfolioDirectory } from './geminiAnalyzer.ts';
import { redactSecrets } from './redactor.ts';
import {
  buildSarifReport,
  meetsFailOnThreshold,
  meetsPortfolioFailOnThreshold,
} from './sarif.ts';
import { startLonginusServer } from './server.ts';
import type { AnalysisMode, SeverityLevel } from './types.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RAW_PROJECT_ROOT = path.resolve(
  __dirname,
  __dirname.includes(`${path.sep}dist${path.sep}`) ? '../../..' : '../..',
);
const PROJECT_ROOT = fsSync.realpathSync(RAW_PROJECT_ROOT);

const VALID_FAIL_THRESHOLDS = new Set<SeverityLevel>(['critical', 'high', 'medium', 'low']);

interface ParsedCliOptions {
  command: 'server' | 'portfolio' | 'audit';
  targetPath?: string;
  emitSarif: boolean;
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

function parseCliArgs(args: readonly string[]): ParsedCliOptions {
  if (args.length === 0) {
    return {
      command: 'server',
      emitSarif: false,
      mode: 'gemini-3.8-flash',
    };
  }

  let hasPortfolio = false;
  let hasAudit = false;
  let emitSarif = false;
  let explicitMode: AnalysisMode | undefined;
  let failOn: SeverityLevel | undefined;
  const positionals: string[] = [];

  for (let i = 0; i < args.length; i++) {
    const arg = args[i] ?? '';
    if (arg === '--portfolio') {
      hasPortfolio = true;
      continue;
    }
    if (arg === '--audit') {
      hasAudit = true;
      continue;
    }
    if (arg === '--sarif') {
      emitSarif = true;
      continue;
    }
    if (arg === '--deterministic') {
      explicitMode = 'deterministic';
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

  if (hasPortfolio && (hasAudit || emitSarif)) {
    throw new Error('--portfolio cannot be combined with --audit or --sarif.');
  }

  if (hasPortfolio) {
    return {
      command: 'portfolio',
      ...(positionals[0] !== undefined ? { targetPath: positionals[0] } : {}),
      emitSarif: false,
      mode: 'deterministic',
      ...(failOn !== undefined ? { failOn } : {}),
    };
  }

  if (hasAudit || emitSarif || positionals.length === 1 || explicitMode !== undefined) {
    return {
      command: 'audit',
      ...(positionals[0] !== undefined ? { targetPath: positionals[0] } : {}),
      emitSarif,
      mode: explicitMode ?? 'gemini-3.8-flash',
      ...(failOn !== undefined ? { failOn } : {}),
    };
  }

  throw new Error(
    'Specify --audit [path], --sarif [path], or --portfolio [path] (or run with no arguments to start the 127.0.0.1 dashboard).',
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

      if (parsed.emitSarif) {
        const sarif = buildSarifReport(report);
        out(`${JSON.stringify(sarif, null, 2)}\n`);
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
