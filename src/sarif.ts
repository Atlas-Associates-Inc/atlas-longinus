import { redactSecrets } from './redactor.js';
import type {
  AuditReport,
  PortfolioRepoSummary,
  SecurityFinding,
  SeverityLevel,
} from './types.js';

export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: Array<{
          id: string;
          name: string;
          shortDescription: { text: string };
          fullDescription: { text: string };
          help: { text: string; markdown: string };
          defaultConfiguration: { level: 'error' | 'warning' | 'note' };
          properties: {
            tags: string[];
            'security-severity': string;
          };
        }>;
      };
    };
    invocations: Array<{
      executionSuccessful: boolean;
      endTimeUtc: string;
    }>;
    results: Array<{
      ruleId: string;
      ruleIndex: number;
      level: 'error' | 'warning' | 'note';
      message: { text: string };
      locations: Array<{
        physicalLocation: {
          artifactLocation: { uri: string; uriBaseId: '%SRCROOT%' };
          region: {
            startLine: number;
            snippet: { text: string };
          };
        };
      }>;
      properties: {
        stack: string;
        stride: string;
        cwe: string;
        owaspAsvs: string;
      };
    }>;
  }>;
}

const SEVERITY_RANK: Record<SeverityLevel, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

function toSarifLevel(severity: SeverityLevel): 'error' | 'warning' | 'note' {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}

function toSecuritySeverityScore(severity: SeverityLevel): string {
  switch (severity) {
    case 'critical':
      return '9.2';
    case 'high':
      return '7.5';
    case 'medium':
      return '5.0';
    case 'low':
      return '2.5';
  }
}

/**
 * Checks whether any finding meets or exceeds the configured CI failure threshold.
 */
export function meetsFailOnThreshold(
  findings: readonly SecurityFinding[],
  threshold: SeverityLevel,
): boolean {
  const minRank = SEVERITY_RANK[threshold];
  return findings.some((f) => SEVERITY_RANK[f.severity] >= minRank);
}

/**
 * Checks whether any repository in a portfolio summary meets or exceeds the CI failure threshold.
 */
export function meetsPortfolioFailOnThreshold(
  repos: readonly PortfolioRepoSummary[],
  threshold: SeverityLevel,
): boolean {
  switch (threshold) {
    case 'critical':
      return repos.some((r) => r.criticalCount > 0);
    case 'high':
      return repos.some((r) => r.criticalCount > 0 || r.highCount > 0);
    case 'medium':
      return repos.some((r) => r.criticalCount > 0 || r.highCount > 0 || r.mediumCount > 0);
    case 'low':
      return repos.some(
        (r) => r.criticalCount > 0 || r.highCount > 0 || r.mediumCount > 0 || r.lowCount > 0,
      );
  }
}

/**
 * Builds an OASIS SARIF 2.1.0 compliant JSON object from a Longinus AuditReport.
 * Enforces an extra pass of `redactSecrets` on every location URI and snippet as a fail-safe.
 */
export function buildSarifReport(report: AuditReport): SarifLog {
  const ruleIndexById = new Map<string, number>();
  const rules: SarifLog['runs'][number]['tool']['driver']['rules'] = [];

  for (const f of report.findings) {
    if (ruleIndexById.has(f.ruleId)) continue;
    const idx = rules.length;
    ruleIndexById.set(f.ruleId, idx);

    const safeTitle = redactSecrets(f.title).redactedText;
    const safeRootCause = redactSecrets(f.rootCause).redactedText;
    const safePatch = redactSecrets(f.defensivePatch).redactedText;
    const safeHint = redactSecrets(f.verificationHint).redactedText;

    rules.push({
      id: f.ruleId,
      name: f.ruleId,
      shortDescription: { text: safeTitle },
      fullDescription: { text: safeRootCause },
      help: {
        text: `${safeRootCause}\n\n推奨防御パッチ:\n${safePatch}\n\n検証ポイント: ${safeHint}`,
        markdown: `**根本原因**: ${safeRootCause}\n\n\`\`\`\n${safePatch}\n\`\`\`\n\n**検証ポイント**: ${safeHint}`,
      },
      defaultConfiguration: { level: toSarifLevel(f.severity) },
      properties: {
        tags: ['security', 'defensive-posture', f.stride, f.cwe, f.stack],
        'security-severity': toSecuritySeverityScore(f.severity),
      },
    });
  }

  const results: SarifLog['runs'][number]['results'] = report.findings.map((f) => {
    const safeUri = redactSecrets(f.filePath).redactedText.replace(/^\/+/, '');
    const safeSnippet = redactSecrets(f.snippetRedacted).redactedText;
    const safeTitle = redactSecrets(f.title).redactedText;
    const safeRootCause = redactSecrets(f.rootCause).redactedText;
    const ruleIndex = ruleIndexById.get(f.ruleId) ?? 0;

    return {
      ruleId: f.ruleId,
      ruleIndex,
      level: toSarifLevel(f.severity),
      message: {
        text: `[${f.stride} / ${f.cwe}] ${safeTitle} — ${safeRootCause}`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: safeUri || 'boundary/unknown',
              uriBaseId: '%SRCROOT%',
            },
            region: {
              startLine: Math.max(1, f.line),
              snippet: { text: safeSnippet },
            },
          },
        },
      ],
      properties: {
        stack: f.stack,
        stride: f.stride,
        cwe: f.cwe,
        owaspAsvs: f.owaspAsvs,
      },
    };
  });

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Longinus Defensive Posture Shield',
            version: '1.1.0',
            informationUri: 'http://127.0.0.1:4310',
            rules,
          },
        },
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: report.auditedAt,
          },
        ],
        results,
      },
    ],
  };
}
