import { readFileSync, realpathSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { scanDirectory } from './graph/attack-graph.ts';
import { runStdioProxy } from './airlock/stdio-proxy.ts';
import { buildMcpConfig, getAirlockProfile } from './airlock/profiles.ts';
import { redactSecrets, sanitizeTelemetry } from './airlock/sanitizer.ts';
import { runProver } from './prove/dual-prover.ts';
import { formatBlueprint, formatTable, meetsThreshold } from './report/formatter.ts';
import { proposeRemediations } from './report/remediation.ts';
import { toSarif } from './report/sarif.ts';
import { executeDefensiveAudit } from './shield/geminiAnalyzer.ts';
import { SUPPORTED_LANGUAGES } from './types.ts';
import type { AirlockProfileId, ConsultingAudience, McpConfigClient, ProverMode, ReportLanguage, Severity } from './types.ts';

function normalizeLanguage(raw: string | undefined): ReportLanguage | undefined {
  if (!raw) return 'en';
  const lower = raw.toLowerCase();
  if (lower === 'zh-hans' || lower === 'zh-cn') return 'zh-Hans';
  if (lower === 'zh-hant' || lower === 'zh-tw' || lower === 'zh-hk') return 'zh-Hant';
  return SUPPORTED_LANGUAGES.find(lang => lang.toLowerCase() === lower);
}

const version: string = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
const help = `Atlas Sovereign ${version}

Usage:
  atlas-sovereign audit <dir> [--format table|json|sarif|blueprint]
      [--lang en|ja] [--audience enterprise|municipal|sme]
      [--fail-on blocker|high|medium] [--emit-patch]
      [--prove] [--prover-mode gemini|dual]
  atlas-sovereign airlock [--profile <name>] --upstream-cmd <cmd> [--upstream-arg <arg>...]
  atlas-sovereign mcp-config [--profile <name>...] [--client agy|gemini]
  atlas-sovereign sanitize < telemetry.txt
  atlas-sovereign --help [--lang en|ja] | --version

Audit is offline unless --prove is selected. Reports and proposed patches go to
stdout; target files are never changed. Defaults: table, lang en, audience enterprise, fail-on high, gemini.
--emit-patch includes review-only proposals in the selected report format.
For upstream arguments starting with '-', use --upstream-arg=--flag.
Airlock accepts newline-delimited JSON-RPC; select a trusted MCP server program.
Profiles: scc, secops, firebase, cloudrun, developer-knowledge, prowler, semgrep.
mcp-config emits JSON templates for caller-installed binaries to stdout only;
no files are changed, programs run or installations verified. Omitted profiles
select all profiles; the default client is gemini.

Prover configuration (only read with --prove):
  ATLAS_GEMINI_BACKEND=gemini|vertex|agy (default: gemini)
  gemini: GEMINI_API_KEY
  vertex: GOOGLE_CLOUD_PROJECT, GOOGLE_CLOUD_LOCATION, GOOGLE_OAUTH_ACCESS_TOKEN
  agy: installed authenticated agy CLI; plan mode and sandbox required
  dual: also requires installed authenticated codex CLI in read-only mode
Provider retention/perimeter settings and CLI sandbox enforcement must be
configured in your environment. No live-provider verification is implied.

Exit codes: 0 below threshold; 1 threshold exceeded or prover BLOCKER;
            2 invalid arguments, incomplete scan, prover ERROR or proxy failure.
`;

const helpJa = `Atlas Sovereign ${version}

使い方:
  atlas-sovereign audit <dir> [--format table|json|sarif|blueprint]
      [--lang en|ja] [--audience enterprise|municipal|sme]
      [--fail-on blocker|high|medium] [--emit-patch]
      [--prove] [--prover-mode gemini|dual]
  atlas-sovereign airlock [--profile <name>] --upstream-cmd <cmd> [--upstream-arg <arg>...]
  atlas-sovereign mcp-config [--profile <name>...] [--client agy|gemini]
  atlas-sovereign sanitize < telemetry.txt
  atlas-sovereign --help [--lang en|ja] | --version

--prove を指定しない限り、audit は完全オフラインで動作します。レポートと修正パッチ案は
標準出力（stdout）のみに出力され、対象ファイルを書き換えることはありません。
既定値: format=table, lang=en, audience=enterprise, fail-on=high, prover-mode=gemini。
--lang ja を指定すると、テーブルおよび Blueprint レポートを日本語で出力します。
--audience で対象組織プロファイル（enterprise: 大企業・上場企業, municipal: 地方自治体, sme: 中小企業）を切り替えられます。
--emit-patch はレビュー専用の unified diff をレポートに含めます。
'-' で始まる上流引数には --upstream-arg=--flag を使用してください。
Airlock は改行区切りの JSON-RPC を仲介します。プロファイル:
  scc, secops, firebase, cloudrun, developer-knowledge, prowler, semgrep.

終了コード: 0 しきい値未満; 1 しきい値以上の指摘または Prover BLOCKER;
            2 引数不正、不完全な走査、Prover ERROR、またはプロキシ障害。
`;

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += bytes.length;
    if (size > 1024 * 1024) throw new Error('Telemetry exceeds the 1 MiB input limit.');
    chunks.push(bytes);
  }
  return Buffer.concat(chunks).toString('utf8');
}

export async function main(args: string[]): Promise<number> {
  if (!args.length || (args.includes('--help') || args.includes('-h')) && args.every((arg, idx) => arg === '--help' || arg === '-h' || arg === '--lang' || arg.startsWith('--lang=') || (idx > 0 && args[idx - 1] === '--lang'))) {
    const langIdx = args.indexOf('--lang');
    const langEq = args.find(arg => arg.startsWith('--lang='))?.slice(7);
    const rawHelpLang = langEq ?? (langIdx >= 0 ? args[langIdx + 1] : process.env.ATLAS_LANG ?? 'en');
    const helpLang = normalizeLanguage(rawHelpLang);
    if (!helpLang) throw new Error('--lang must be one of the 20 supported language tags.');
    process.stdout.write(helpLang === 'ja' ? helpJa : help);
    return 0;
  }
  if (args.length === 1 && args[0] === '--version') {
    process.stdout.write(version + '\n');
    return 0;
  }
  const command = args[0];
  if (!['audit', 'sanitize', 'airlock', 'mcp-config'].includes(command)) throw new Error('Unknown command. Use --help.');
  if (args.length === 2 && ['--help', '-h'].includes(args[1])) {
    process.stdout.write(process.env.ATLAS_LANG === 'ja' ? helpJa : help);
    return 0;
  }
  if (command === 'sanitize') {
    if (args.length !== 1) throw new Error('sanitize accepts telemetry on stdin and no arguments.');
    process.stdout.write(sanitizeTelemetry(await readStdin()).text + '\n');
    return 0;
  }
  if (command === 'mcp-config') {
    const { values, positionals } = parseArgs({ args: args.slice(1), strict: true, allowPositionals: true, options: {
      profile: { type: 'string', multiple: true }, client: { type: 'string', default: 'gemini' },
    } });
    if (positionals.length) throw new Error('mcp-config accepts --profile and --client options only.');
    const config = buildMcpConfig({ profiles: values.profile as AirlockProfileId[] | undefined,
      client: values.client as McpConfigClient });
    process.stdout.write(JSON.stringify(config, null, 2) + '\n');
    return 0;
  }
  if (command === 'airlock') {
    const { values, positionals } = parseArgs({ args: args.slice(1), strict: true, allowPositionals: true, options: {
      'upstream-cmd': { type: 'string' }, 'upstream-arg': { type: 'string', multiple: true },
      profile: { type: 'string' },
    } });
    if (positionals.length || !values['upstream-cmd']) throw new Error('airlock requires --upstream-cmd and optional --upstream-arg values only.');
    if (values.profile !== undefined && !getAirlockProfile(values.profile)) throw new Error('Unknown airlock --profile.');
    return runStdioProxy({ command: values['upstream-cmd'], args: values['upstream-arg'] ?? [], profile: values.profile });
  }
  const { values, positionals } = parseArgs({ args: args.slice(1), strict: true, allowPositionals: true, options: {
    format: { type: 'string', default: 'table' }, lang: { type: 'string', default: process.env.ATLAS_LANG ?? 'en' },
    audience: { type: 'string', default: process.env.ATLAS_AUDIENCE ?? 'enterprise' },
    'fail-on': { type: 'string', default: 'high' },
    'emit-patch': { type: 'boolean', default: false }, prove: { type: 'boolean', default: false },
    'prover-mode': { type: 'string', default: 'gemini' },
  } });
  if (positionals.length !== 1) throw new Error('audit requires exactly one directory.');
  if (!['table', 'json', 'sarif', 'blueprint'].includes(values.format!)) throw new Error('--format must be table, json, sarif or blueprint.');
  const lang = normalizeLanguage(values.lang);
  if (!lang) throw new Error('--lang must be one of the 20 supported language tags.');
  if (!['enterprise', 'municipal', 'sme'].includes(values.audience!)) throw new Error('--audience must be enterprise, municipal or sme.');
  if (!['blocker', 'high', 'medium'].includes(values['fail-on']!)) throw new Error('--fail-on must be blocker, high or medium.');
  if (!['gemini', 'dual'].includes(values['prover-mode']!)) throw new Error('--prover-mode must be gemini or dual.');
  const audience = values.audience as ConsultingAudience;
  const directory = resolve(positionals[0]);
  const graph = scanDirectory(directory);
  const incomplete = graph.findings.some(finding => finding.ruleId.startsWith('scan/'));
  // A provider cannot turn an incomplete local scan into a successful gate.
  const prover = values.prove && !incomplete ? await runProver(graph, { mode: values['prover-mode'] as ProverMode }) : undefined;
  const remediations = values['emit-patch'] ? proposeRemediations(graph.findings, directory) : [];
  const selfRoot = tryRealpath(fileURLToPath(new URL('../', import.meta.url)));
  const realDir = tryRealpath(directory) ?? directory;
  let shieldReport: Awaited<ReturnType<typeof executeDefensiveAudit>> | undefined;
  if (values.format === 'blueprint' && !incomplete) {
    try {
      shieldReport = await executeDefensiveAudit({
        targetPath: realDir,
        mode: 'deterministic',
        ...(selfRoot && realDir === selfRoot ? { excludeRelativePrefixes: ['test'] } : {}),
      });
    } catch {
      shieldReport = undefined;
    }
  }
  const report = values.format === 'table' ? formatTable(graph, prover, remediations, lang)
    : values.format === 'blueprint' ? formatBlueprint(graph, prover, remediations, lang, audience, { shieldReport })
    : JSON.stringify(JSON.parse(redactSecrets(JSON.stringify(values.format === 'sarif' ? toSarif(graph, version, prover, remediations)
      : { ...graph, ...(prover ? { prover } : {}), ...(values['emit-patch'] ? { remediations } : {}) }))), null, 2) + '\n';
  process.stdout.write(values.format === 'table' || values.format === 'blueprint' ? redactSecrets(report) : report);
  if (incomplete || prover?.status === 'ERROR') return 2;
  return prover?.status === 'BLOCKER' || meetsThreshold(graph, values['fail-on'] as Severity) ? 1 : 0;
}

function tryRealpath(path: string | undefined): string | undefined {
  try { return path ? realpathSync(path) : undefined; } catch { return undefined; }
}

const entry = tryRealpath(process.argv[1]);
if (entry && [import.meta.url, new URL('../bin/atlas-sovereign.mjs', import.meta.url)]
  .some(url => entry === tryRealpath(fileURLToPath(url)))) {
  process.stdout.on('error', () => { process.exitCode = 2; });
  main(process.argv.slice(2)).then(code => { process.exitCode = process.exitCode || code; }).catch(error => {
    // Native I/O/argument errors may include untrusted paths or snippets.
    const message = error instanceof Error ? error.message : 'Operation failed.';
    process.stderr.write(`Atlas Sovereign: ${redactSecrets(message).replace(/[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, ' ')}\n`);
    process.exitCode = 2;
  });
}
