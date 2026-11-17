import type { DestructionCertificate } from '../airlock/destruction-certificate.ts';

export type StackDomain =
  | 'ts-web-api'
  | 'flutter-firebase'
  | 'python-go-cloud'
  | 'supply-chain-secrets';

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low';

export type StrideCategory =
  | 'Spoofing'
  | 'Tampering'
  | 'Repudiation'
  | 'Information Disclosure'
  | 'Denial of Service'
  | 'Elevation of Privilege';

export type AnalysisMode = 'gemini-3.8-flash' | 'gemini-4-argon' | 'deterministic';

export type ReasoningLevel = 'low' | 'medium' | 'high' | 'none';

export interface SecurityFinding {
  id: string;
  ruleId: string;
  title: string;
  stack: StackDomain;
  severity: SeverityLevel;
  stride: StrideCategory;
  cwe: string;
  owaspAsvs: string;
  filePath: string;
  line: number;
  snippetRedacted: string;
  rootCause: string;
  defensivePatch: string;
  verificationHint: string;
  source: 'static-rule' | 'gemini-architecture';
}

export interface TrustBoundaryNode {
  id: string;
  label: string;
  zone: 'edge' | 'auth' | 'application' | 'data' | 'infra';
  stack: StackDomain;
  status: 'hardened' | 'attention' | 'exposed';
  findingCount: number;
  summary: string;
}

export interface TrustBoundaryEdge {
  from: string;
  to: string;
  protocol: string;
  riskLevel: 'low' | 'medium' | 'high';
}

export interface StrideScoreItem {
  category: StrideCategory;
  exposureScore: number;
  readinessScore: number;
  topRiskSummary: string;
  primaryDefense: string;
}

export interface StackPostureSummary {
  stack: StackDomain;
  label: string;
  detectedFiles: number;
  defenseScore: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  verifiedControls: string[];
}

export interface RoadmapStep {
  phase: string;
  title: string;
  impact: string;
  targetStack: StackDomain;
  action: string;
}

export interface AuditReport {
  auditId: string;
  targetPath: string;
  repoName: string;
  auditedAt: string;
  durationMs: number;
  scannedFiles: number;
  inspectedEntries: number;
  scanTruncated: boolean;
  truncationReason?: string;
  redactedSecretsCount: number;
  analysisModeUsed: AnalysisMode;
  reasoningLevelUsed: ReasoningLevel;
  geminiLiveUsed: boolean;
  geminiFallbackReason?: string;
  tokenEstimate: number;
  overallDefenseScore: number;
  executiveSummary: string;
  priorityRoadmap: RoadmapStep[];
  strideMatrix: StrideScoreItem[];
  stackSummaries: StackPostureSummary[];
  trustGraph: {
    nodes: TrustBoundaryNode[];
    edges: TrustBoundaryEdge[];
  };
  findings: SecurityFinding[];
  destructionCertificate: DestructionCertificate;
}

export interface PortfolioRepoSummary {
  dirName: string;
  repoName: string;
  targetPath: string;
  overallDefenseScore: number;
  scannedFiles: number;
  scanTruncated: boolean;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  redactedSecretsCount: number;
  verifiedControlsCount: number;
  primaryStack: StackDomain;
  topAction: string;
}

export interface PortfolioReport {
  portfolioRootLabel: string;
  scannedAt: string;
  durationMs: number;
  totalRepos: number;
  averageDefenseScore: number;
  criticalReposCount: number;
  totalRedactedSecrets: number;
  repos: PortfolioRepoSummary[];
}
