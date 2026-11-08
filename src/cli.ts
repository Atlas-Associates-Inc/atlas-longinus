import { executeDefensiveAudit } from './geminiAnalyzer.js';
import { redactSecrets } from './redactor.js';
import { startLonginusServer } from './server.js';
import type { AnalysisMode } from './types.js';

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const auditIdx = args.indexOf('--audit');

  if (auditIdx !== -1) {
    const nextArg = args[auditIdx + 1];
    const targetPath = nextArg && !nextArg.startsWith('--') ? nextArg : process.cwd();
    const modeArg = args.includes('--deterministic')
      ? 'deterministic'
      : args.includes('--argon')
        ? 'gemini-4-argon'
        : 'gemini-3.8-flash';

    const report = await executeDefensiveAudit({
      targetPath,
      mode: modeArg as AnalysisMode,
      ...(targetPath === process.cwd() ? { excludeRelativePrefixes: ['test'] } : {}),
    });

    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    return;
  }

  const portEnv = Number(process.env['PORT'] ?? '4310');
  const port = Number.isInteger(portEnv) && portEnv >= 0 && portEnv <= 65535 ? portEnv : 4310;
  const { url } = await startLonginusServer(port);
  process.stdout.write(`LONGINUS Defensive Posture Dashboard listening on ${url}\n`);
}

main().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`Longinus fatal error: ${redactSecrets(message).redactedText.slice(0, 200)}\n`);
  process.exitCode = 1;
});
