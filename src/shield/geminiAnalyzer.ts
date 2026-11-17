import crypto from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import { executeEphemeralFernetDoDCycle } from '../airlock/destruction-certificate.ts';
import {
  DEFENSIVE_PATCH_TEMPLATES,
  type DefensivePatchTemplateId,
  redactSecrets,
} from './redactor.ts';
import {
  buildStackSummaries,
  openPinnedSafeTargetDirectory,
  resolveSafeTargetDirectory,
  runStaticRepositoryScan,
  SafeClientError,
  type ScanOptions,
  type StaticScanResult,
} from './scanner.ts';
import type {
  AnalysisMode,
  AuditReport,
  PortfolioRepoSummary,
  PortfolioReport,
  ReasoningLevel,
  RoadmapStep,
  SecurityFinding,
  SeverityLevel,
  StackDomain,
  StrideCategory,
  StrideScoreItem,
} from './types.ts';

export class ClosedSchemaValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ClosedSchemaValidationError';
  }
}

const ALLOWED_GEMINI_MODELS = new Set(['gemini-3.8-flash', 'gemini-4-argon']);

const PATCH_TEMPLATE_IDS = Object.keys(DEFENSIVE_PATCH_TEMPLATES) as [
  DefensivePatchTemplateId,
  ...DefensivePatchTemplateId[],
];

/**
 * Closed-world approved Japanese executive posture templates.
 * Eliminates arbitrary model prose pass-through so offensive instructions can never enter reports.
 */
export const EXECUTIVE_POSTURE_CATALOG = Object.freeze({
  POSTURE_HARDENED_CONTINUOUS_CI:
    '主要な信頼境界に致命的な露出は認められません。CSP Trusted Types・最小権限 IAM・暗号学的ロックファイル検証を CI ゲートで継続維持してください。',
  POSTURE_VAULT_AND_BOUNDARY_PRIORITY:
    '資格情報の分離とデフォルト全拒否（Deny-by-Default）境界の確立が最優先です。機密キーの Secret Manager 移行と境界ルールの即時適用を推奨します。',
  POSTURE_WEB_CSP_AND_ORIGIN_PRIORITY:
    'Web / API 境界における DOM シンク排除、Per-request CSP Nonce + Trusted Types、および Strict Origin / Fetch Metadata 検証の優先適用が必要です。',
  POSTURE_MOBILE_RULES_AND_TLS_PRIORITY:
    'モバイルおよび Firebase 境界において、Firestore 所有者 UID + スキーマ検証、App Check 強制、OS 標準 TLS / Keystore 保護の徹底が必要です。',
  POSTURE_CLOUD_IAM_AND_CONTAINER_PRIORITY:
    'クラウド実行基盤における非 root Distroless コンテナ化、未認証公開（allUsers）の排除、および HTTP タイムアウト保護の優先適用が必要です。',
} as const);

export type ExecutivePostureId = keyof typeof EXECUTIVE_POSTURE_CATALOG;
const EXECUTIVE_POSTURE_IDS = Object.keys(EXECUTIVE_POSTURE_CATALOG) as [
  ExecutivePostureId,
  ...ExecutivePostureId[],
];

export const STRIDE_RISK_CATALOG = Object.freeze({
  SPOOFING_ORIGIN_AND_TOKEN_GAP: 'Origin / Fetch Metadata 検証またはエンドポイント認証・App Check 境界の不足傾向',
  SPOOFING_UNAUTHENTICATED_CLOUD_INGRESS: 'allUsers 等による未認証クラウド公開エンドポイントの露出傾向',
  TAMPERING_DOM_SINK_AND_SCHEMA: '未サニタイズ DOM シンクまたは書込みスキーマ制限（hasOnly）の不足傾向',
  TAMPERING_SUPPLY_CHAIN_PINNING: '未固定 CI Action タグまたはロックファイル未検証による改ざん混入リスク',
  REPUDIATION_AUDIT_TRAIL_GAP: '権限変更・管理操作における構造化監査ログおよびリクエスト相関 ID の不足傾向',
  INFO_DISCLOSURE_HARDCODED_KEYS: 'ハードコード機密・公開環境変数プレフィックス・平文トークン保存による漏洩傾向',
  INFO_DISCLOSURE_CORS_AND_TLS: 'ワイルドカード CORS または TLS 証明書検証無効化による通信傍受リスク',
  DOS_UNBOUNDED_IO_AND_TIMEOUTS: 'HTTP ヘッダ読取タイムアウト未設定または未認証リソース消費による枯渇リスク',
  EOP_SHELL_AND_DYNAMIC_EXEC: 'シェル経由コマンド実行・動的コード評価・安全でないデシリアライズの露出傾向',
  EOP_CONTAINER_ROOT_AND_WILDCARD_RULES: 'コンテナ root 稼働またはワイルドカード認可ルールによる権限昇格リスク',
} as const);

export type StrideRiskCatalogId = keyof typeof STRIDE_RISK_CATALOG;
const STRIDE_RISK_IDS = Object.keys(STRIDE_RISK_CATALOG) as [
  StrideRiskCatalogId,
  ...StrideRiskCatalogId[],
];

export const STRIDE_DEFENSE_CATALOG = Object.freeze({
  DEF_STRICT_ORIGIN_CSRF_APPCHECK: 'Strict Origin + Sec-Fetch-Site + 暗号学的 CSRF トークン + App Check 強制',
  DEF_TRUSTED_TYPES_AND_SCHEMA_ALLOWLIST: 'Per-request CSP Nonce + Trusted Types および Firestore hasOnly スキーマ制限',
  DEF_IMMUTABLE_AUDIT_LOGGING: '改ざん耐性のある Cloud Audit Logs とリクエスト単位の相関 ID 記録',
  DEF_VAULT_ROTATION_AND_KEYSTORE: 'Secret Manager 実行時注入、ローカル自動マスク、TLS 1.3 + Keychain/Keystore 保護',
  DEF_READ_HEADER_TIMEOUT_AND_WAF: 'ReadHeaderTimeout 明示設定、リクエスト上限、Cloud Armor レート制限',
  DEF_NONROOT_EXECFILE_DENY_DEFAULT: 'Distroless nonroot 実行、Deny-by-Default 認可、shell=false 固定配列実行',
  DEF_SHA_PINNED_LOCKFILE_CI: '40桁フルコミット SHA 固定と frozen-lockfile CI ゲート強制',
} as const);

export type StrideDefenseCatalogId = keyof typeof STRIDE_DEFENSE_CATALOG;
const STRIDE_DEFENSE_IDS = Object.keys(STRIDE_DEFENSE_CATALOG) as [
  StrideDefenseCatalogId,
  ...StrideDefenseCatalogId[],
];

export const ROADMAP_PHASE_CATALOG = Object.freeze({
  PHASE_1_24H: 'Phase 1 (即時・24h以内)',
  PHASE_2_72H: 'Phase 2 (短期・72h以内)',
  PHASE_3_CI: 'Phase 3 (恒久・CI統合)',
} as const);

export type RoadmapPhaseId = keyof typeof ROADMAP_PHASE_CATALOG;
const ROADMAP_PHASE_IDS = Object.keys(ROADMAP_PHASE_CATALOG) as [
  RoadmapPhaseId,
  ...RoadmapPhaseId[],
];

export const ROADMAP_PLAYBOOK_CATALOG = Object.freeze({
  PLAYBOOK_SECRET_SEGREGATION: {
    title: '機密情報の完全分離と即時ローテーション',
    impact: 'ハードコード鍵および公開環境変数からの資格情報漏洩を根絶',
    action:
      '検出された秘密鍵・トークンを失効・再発行し、Secret Manager 注入と .gitignore 除外ゲートへ統一する。',
  },
  PLAYBOOK_DENY_BY_DEFAULT_AUTHZ: {
    title: 'デフォルト全拒否（Deny-by-Default）認可境界の確立',
    impact: '未認証アクセス・水平権限昇格（IDOR）・不正書込みの遮断',
    action:
      'Firestore / Storage Rules のワイルドカード許可を廃止し、UID 一致 + hasOnly フィールド検証 + App Check を必須化する。',
  },
  PLAYBOOK_WEB_CSP_TRUSTED_TYPES: {
    title: 'DOM シンク排除と CSP Nonce + Trusted Types 強制',
    impact: 'DOM-based XSS およびクロスサイト操作の予防的無力化',
    action:
      'innerHTML 系シンクを textContent へ置換し、Per-request Nonce CSP・Sec-Fetch-Site・固定 CORS Allowlist を適用する。',
  },
  PLAYBOOK_SUBPROCESS_AND_DESERIALIZATION: {
    title: 'シェル非経由プロセス実行と型安全パーサへの統一',
    impact: 'OS コマンド注入および任意コード実行（RCE）経路の閉鎖',
    action:
      'eval / shell=True / 安全でない load を廃止し、execFile 固定配列と Zod / SafeLoader 検証へ置換する。',
  },
  PLAYBOOK_CLOUD_PERIMETER_NONROOT: {
    title: '非 root コンテナ化・IAM 内部化・タイムアウト保護',
    impact: 'コンテナ侵害時の権限拡大防止と接続・課金枯渇（DoS）の抑制',
    action:
      'Distroless nonroot USER 指定、allUsers 削除、および HTTP ReadHeaderTimeout / ボディ上限設定を徹底する。',
  },
  PLAYBOOK_SUPPLY_CHAIN_SHA_PIN: {
    title: 'CI/CD 40桁 SHA 固定とロックファイル不変検証',
    impact: 'サードパーティ依存・ワークフロー経由のサプライチェーン汚染防止',
    action:
      'GitHub Actions の pull_request_target を排除してフルコミット SHA に固定し、frozen-lockfile ビルドを強制する。',
  },
} as const);

export type RoadmapPlaybookId = keyof typeof ROADMAP_PLAYBOOK_CATALOG;
const ROADMAP_PLAYBOOK_IDS = Object.keys(ROADMAP_PLAYBOOK_CATALOG) as [
  RoadmapPlaybookId,
  ...RoadmapPlaybookId[],
];

export const ARCHITECTURAL_FINDING_CATALOG = Object.freeze({
  ARCH_WEB_CSP_TRUSTED_TYPES_BOUNDARY: {
    title: 'Web クライアント境界における CSP Nonce / Trusted Types 防御層の強化',
    cwe: 'CWE-79',
    owaspAsvs: 'V5.3.3 Output Encoding & Trusted Types',
    rootCause:
      'DOM 操作境界でブラウザ側の型強制（Trusted Types）とリクエスト毎の Nonce 制限が統一されていない場合、万一の出力エスケープ漏れがスクリプト実行に直結します。',
    verificationHint:
      'レスポンスヘッダに require-trusted-types-for と毎回変化する nonce が付与され、innerHTML が 0 件であることを確認。',
  },
  ARCH_API_ORIGIN_CSRF_ISOLATION: {
    title: 'API 状態変更境界における Origin / Fetch Metadata / CSRF 三重検証の徹底',
    cwe: 'CWE-352',
    owaspAsvs: 'V4.2.2 Cross-Origin & CSRF Isolation',
    rootCause:
      'CORS 許可範囲やブラウザ自動送信リクエストに対する Origin・Sec-Fetch-Site・専用トークン検証が欠けると、外部サイト経由の意図しない操作を許します。',
    verificationHint:
      '異なる Origin または Sec-Fetch-Site: cross-site を持つリクエストが 403 で拒否されることを単体テストで確認。',
  },
  ARCH_SUBPROCESS_SHELL_ISOLATION: {
    title: 'プロセス実行境界におけるシェル解釈排除と引数ホワイトリスト化',
    cwe: 'CWE-78',
    owaspAsvs: 'V5.3.8 OS Command Isolation',
    rootCause:
      'シェル文字列連結や動的コード評価が存在すると、境界外パラメータのメタ文字解釈により実行権限を奪取される構造的リスクが生じます。',
    verificationHint:
      'execFile / subprocess(shell=False) の固定配列呼び出しのみに限定されていることを静的解析で確認。',
  },
  ARCH_FIRESTORE_ZERO_TRUST_RULES: {
    title: 'データストア境界の Deny-by-Default 化とフィールドスキーマ検証',
    cwe: 'CWE-284',
    owaspAsvs: 'V4.1.3 Deny-by-Default Data Access',
    rootCause:
      '広範なワイルドカード一致や認証有無のみのチェックでは、正規アカウントを用いた他テナントデータの閲覧・改ざん・ロール自己昇格を防げません。',
    verificationHint:
      'Rules エミュレータで未認証・別 UID・未許可キー付与書込みがすべて拒否されることを確認。',
  },
  ARCH_MOBILE_TLS_AND_KEYSTORE: {
    title: 'モバイル通信・端末保存境界における標準 TLS 強制とハードウェア鍵保護',
    cwe: 'CWE-295',
    owaspAsvs: 'V8.2.2 & V9.2.1 Mobile Transport & Keystore Security',
    rootCause:
      '証明書検証コールバックの緩和や平文プリファレンス保存は、公衆無線環境での通信傍受や端末バックアップからのトークン流出を招きます。',
    verificationHint:
      'badCertificateCallback と平文トークン保存が 0 件であり、Keychain/Keystore 経由のみであることを確認。',
  },
  ARCH_CLOUD_PERIMETER_AND_NONROOT: {
    title: 'クラウド実行境界における最小権限 IAM・非 root 稼働・タイムアウト防御',
    cwe: 'CWE-250',
    owaspAsvs: 'V14.2.1 Container & Cloud Perimeter Hardening',
    rootCause:
      'root コンテナや未認証公開エンドポイント、無制限のヘッダ読取待機が重なると、侵害時の影響拡大および低帯域接続枯渇・課金攻撃に晒されます。',
    verificationHint:
      'Dockerfile の非 root USER、IAM の allUsers 不在、および HTTP ReadHeaderTimeout 設定を確認。',
  },
  ARCH_SECRET_SEGREGATION_AND_CI_PINNING: {
    title: '機密ライフサイクル分離と CI/CD サプライチェーン不変固定',
    cwe: 'CWE-798',
    owaspAsvs: 'V2.10.4 & V14.2.3 Secret & Supply-Chain Integrity',
    rootCause:
      'リポジトリ内の静的資格情報や可変タグ参照の外部 Action・未固定依存関係は、ビルドパイプライン経由での連鎖侵害リスクを高めます。',
    verificationHint:
      '機密スキャン検出 0 件、全 Action の 40桁 SHA 固定、および frozen-lockfile の適用を確認。',
  },
} as const);

export type ArchitecturalFindingCatalogId = keyof typeof ARCHITECTURAL_FINDING_CATALOG;
const ARCHITECTURAL_FINDING_IDS = Object.keys(ARCHITECTURAL_FINDING_CATALOG) as [
  ArchitecturalFindingCatalogId,
  ...ArchitecturalFindingCatalogId[],
];

const CANONICAL_BOUNDARY_PATHS = new Set<string>([
  'boundary/ts-web-api',
  'boundary/flutter-firebase',
  'boundary/python-go-cloud',
  'boundary/supply-chain-secrets',
]);

const DEFENSIVE_SYSTEM_INSTRUCTION = [
  'あなたは防御・予防専守のセキュリティアーキテクトです。',
  '与えられた構造メタデータ（ソースコード抜粋ゼロ）から、定義済み防御カタログ列挙値（Enum ID）と 0〜100 のスコアのみを用いて JSON を返してください。',
  'filePath には AllowedRepositoryPaths に含まれる実在パス、または boundary/<stack> のみを指定してください。',
].join('\n');

const THREAT_MODEL_JSON_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    executivePostureId: {
      type: 'string',
      enum: EXECUTIVE_POSTURE_IDS,
    },
    strideMatrix: {
      type: 'array',
      maxItems: 6,
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          category: {
            type: 'string',
            enum: [
              'Spoofing',
              'Tampering',
              'Repudiation',
              'Information Disclosure',
              'Denial of Service',
              'Elevation of Privilege',
            ],
          },
          exposureScore: { type: 'integer', description: '0-100（低いほど安全）' },
          readinessScore: { type: 'integer', description: '0-100（高いほど堅牢）' },
          riskCatalogId: {
            type: 'string',
            enum: STRIDE_RISK_IDS,
          },
          defenseCatalogId: {
            type: 'string',
            enum: STRIDE_DEFENSE_IDS,
          },
        },
        required: [
          'category',
          'exposureScore',
          'readinessScore',
          'riskCatalogId',
          'defenseCatalogId',
        ],
      },
    },
    priorityRoadmap: {
      type: 'array',
      maxItems: 6,
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          phaseId: {
            type: 'string',
            enum: ROADMAP_PHASE_IDS,
          },
          targetStack: {
            type: 'string',
            enum: ['ts-web-api', 'flutter-firebase', 'python-go-cloud', 'supply-chain-secrets'],
          },
          playbookId: {
            type: 'string',
            enum: ROADMAP_PLAYBOOK_IDS,
          },
        },
        required: ['phaseId', 'targetStack', 'playbookId'],
      },
    },
    architecturalFindings: {
      type: 'array',
      maxItems: 6,
      items: {
        type: 'object',
        additionalProperties: false,
        properties: {
          findingCatalogId: {
            type: 'string',
            enum: ARCHITECTURAL_FINDING_IDS,
          },
          stack: {
            type: 'string',
            enum: ['ts-web-api', 'flutter-firebase', 'python-go-cloud', 'supply-chain-secrets'],
          },
          severity: {
            type: 'string',
            enum: ['critical', 'high', 'medium', 'low'],
          },
          stride: {
            type: 'string',
            enum: [
              'Spoofing',
              'Tampering',
              'Repudiation',
              'Information Disclosure',
              'Denial of Service',
              'Elevation of Privilege',
            ],
          },
          filePath: { type: 'string' },
          patchTemplateId: {
            type: 'string',
            enum: PATCH_TEMPLATE_IDS,
          },
        },
        required: [
          'findingCatalogId',
          'stack',
          'severity',
          'stride',
          'filePath',
          'patchTemplateId',
        ],
      },
    },
  },
  required: ['executivePostureId', 'strideMatrix', 'priorityRoadmap', 'architecturalFindings'],
};

const SAFE_REL_PATH_RE = /^(?!.*\.\.)(?!\/)[A-Za-z0-9._/-]{1,140}$/;

const VALID_STRIDE_CATEGORIES = new Set<StrideCategory>([
  'Spoofing',
  'Tampering',
  'Repudiation',
  'Information Disclosure',
  'Denial of Service',
  'Elevation of Privilege',
]);
const VALID_STACK_DOMAINS = new Set<StackDomain>([
  'ts-web-api',
  'flutter-firebase',
  'python-go-cloud',
  'supply-chain-secrets',
]);
const VALID_SEVERITIES = new Set<SeverityLevel>(['critical', 'high', 'medium', 'low']);
const EXEC_POSTURE_SET = new Set<string>(EXECUTIVE_POSTURE_IDS);
const STRIDE_RISK_SET = new Set<string>(STRIDE_RISK_IDS);
const STRIDE_DEFENSE_SET = new Set<string>(STRIDE_DEFENSE_IDS);
const ROADMAP_PHASE_SET = new Set<string>(ROADMAP_PHASE_IDS);
const ROADMAP_PLAYBOOK_SET = new Set<string>(ROADMAP_PLAYBOOK_IDS);
const ARCH_FINDING_SET = new Set<string>(ARCHITECTURAL_FINDING_IDS);
const PATCH_TEMPLATE_SET = new Set<string>(PATCH_TEMPLATE_IDS);

interface ValidatedGeminiThreatPayload {
  executivePostureId: ExecutivePostureId;
  strideMatrix: Array<{
    category: StrideCategory;
    exposureScore: number;
    readinessScore: number;
    riskCatalogId: StrideRiskId;
    defenseCatalogId: StrideDefenseId;
  }>;
  priorityRoadmap: Array<{
    phaseId: RoadmapPhaseId;
    targetStack: StackDomain;
    playbookId: RoadmapPlaybookId;
  }>;
  architecturalFindings: Array<{
    findingCatalogId: ArchitecturalFindingId;
    stack: StackDomain;
    severity: SeverityLevel;
    stride: StrideCategory;
    filePath: string;
    patchTemplateId: DefensivePatchTemplateId;
  }>;
}

function assertStrictKeys(
  obj: unknown,
  allowedKeys: readonly string[],
): Record<string, unknown> {
  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) {
    throw new ClosedSchemaValidationError('Expected plain object.');
  }
  const rec = obj as Record<string, unknown>;
  const allowed = new Set(allowedKeys);
  for (const k of Object.keys(rec)) {
    if (!allowed.has(k)) {
      throw new ClosedSchemaValidationError(`Unexpected key: ${k}`);
    }
  }
  for (const req of allowedKeys) {
    if (!(req in rec)) {
      throw new ClosedSchemaValidationError(`Missing required key: ${req}`);
    }
  }
  return rec;
}

function parseGeminiThreatResponse(raw: unknown): ValidatedGeminiThreatPayload {
  const root = assertStrictKeys(raw, [
    'executivePostureId',
    'strideMatrix',
    'priorityRoadmap',
    'architecturalFindings',
  ]);

  const executivePostureId = root['executivePostureId'];
  if (typeof executivePostureId !== 'string' || !EXEC_POSTURE_SET.has(executivePostureId)) {
    throw new ClosedSchemaValidationError('Invalid executivePostureId.');
  }

  const rawStride = root['strideMatrix'];
  if (!Array.isArray(rawStride) || rawStride.length > 6) {
    throw new ClosedSchemaValidationError('Invalid strideMatrix array.');
  }
  const strideMatrix = rawStride.map((entry) => {
    const item = assertStrictKeys(entry, [
      'category',
      'exposureScore',
      'readinessScore',
      'riskCatalogId',
      'defenseCatalogId',
    ]);
    const category = item['category'];
    const exposureScore = item['exposureScore'];
    const readinessScore = item['readinessScore'];
    const riskCatalogId = item['riskCatalogId'];
    const defenseCatalogId = item['defenseCatalogId'];
    if (
      typeof category !== 'string' ||
      !VALID_STRIDE_CATEGORIES.has(category as StrideCategory) ||
      typeof exposureScore !== 'number' ||
      !Number.isFinite(exposureScore) ||
      exposureScore < 0 ||
      exposureScore > 100 ||
      typeof readinessScore !== 'number' ||
      !Number.isFinite(readinessScore) ||
      readinessScore < 0 ||
      readinessScore > 100 ||
      typeof riskCatalogId !== 'string' ||
      !STRIDE_RISK_SET.has(riskCatalogId) ||
      typeof defenseCatalogId !== 'string' ||
      !STRIDE_DEFENSE_SET.has(defenseCatalogId)
    ) {
      throw new ClosedSchemaValidationError('Invalid strideMatrix item.');
    }
    return {
      category: category as StrideCategory,
      exposureScore,
      readinessScore,
      riskCatalogId: riskCatalogId as StrideRiskId,
      defenseCatalogId: defenseCatalogId as StrideDefenseId,
    };
  });

  const rawRoadmap = root['priorityRoadmap'];
  if (!Array.isArray(rawRoadmap) || rawRoadmap.length > 6) {
    throw new ClosedSchemaValidationError('Invalid priorityRoadmap array.');
  }
  const priorityRoadmap = rawRoadmap.map((entry) => {
    const item = assertStrictKeys(entry, ['phaseId', 'targetStack', 'playbookId']);
    const phaseId = item['phaseId'];
    const targetStack = item['targetStack'];
    const playbookId = item['playbookId'];
    if (
      typeof phaseId !== 'string' ||
      !ROADMAP_PHASE_SET.has(phaseId) ||
      typeof targetStack !== 'string' ||
      !VALID_STACK_DOMAINS.has(targetStack as StackDomain) ||
      typeof playbookId !== 'string' ||
      !ROADMAP_PLAYBOOK_SET.has(playbookId)
    ) {
      throw new ClosedSchemaValidationError('Invalid priorityRoadmap item.');
    }
    return {
      phaseId: phaseId as RoadmapPhaseId,
      targetStack: targetStack as StackDomain,
      playbookId: playbookId as RoadmapPlaybookId,
    };
  });

  const rawFindings = root['architecturalFindings'];
  if (!Array.isArray(rawFindings) || rawFindings.length > 6) {
    throw new ClosedSchemaValidationError('Invalid architecturalFindings array.');
  }
  const architecturalFindings = rawFindings.map((entry) => {
    const item = assertStrictKeys(entry, [
      'findingCatalogId',
      'stack',
      'severity',
      'stride',
      'filePath',
      'patchTemplateId',
    ]);
    const findingCatalogId = item['findingCatalogId'];
    const stack = item['stack'];
    const severity = item['severity'];
    const stride = item['stride'];
    const filePath = item['filePath'];
    const patchTemplateId = item['patchTemplateId'];
    if (
      typeof findingCatalogId !== 'string' ||
      !ARCH_FINDING_SET.has(findingCatalogId) ||
      typeof stack !== 'string' ||
      !VALID_STACK_DOMAINS.has(stack as StackDomain) ||
      typeof severity !== 'string' ||
      !VALID_SEVERITIES.has(severity as SeverityLevel) ||
      typeof stride !== 'string' ||
      !VALID_STRIDE_CATEGORIES.has(stride as StrideCategory) ||
      typeof filePath !== 'string' ||
      !SAFE_REL_PATH_RE.test(filePath) ||
      typeof patchTemplateId !== 'string' ||
      !PATCH_TEMPLATE_SET.has(patchTemplateId)
    ) {
      throw new ClosedSchemaValidationError('Invalid architecturalFindings item.');
    }
    return {
      findingCatalogId: findingCatalogId as ArchitecturalFindingId,
      stack: stack as StackDomain,
      severity: severity as SeverityLevel,
      stride: stride as StrideCategory,
      filePath,
      patchTemplateId: patchTemplateId as DefensivePatchTemplateId,
    };
  });

  return {
    executivePostureId: executivePostureId as ExecutivePostureId,
    strideMatrix,
    priorityRoadmap,
    architecturalFindings,
  };
}

export interface GeminiValidationContext {
  allowedFilePaths?: ReadonlySet<string>;
  repoLabel?: string;
  scannedFiles?: number;
  findingCount?: number;
  criticalCount?: number;
  highCount?: number;
  scanTruncated?: boolean;
}

function sanitizeDisplayLabel(raw: string): string {
  const redacted = redactSecrets(raw).redactedText;
  return redacted.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 64) || 'repository';
}

/**
 * Selects the optimal Gemini reasoning (`thinking_level`) per role and static finding telemetry:
 * - `gemini-4-argon` (Argon High): dedicated to deep threat analysis, investigation & root-cause planning -> always `'high'`.
 * - `gemini-3.8-flash`: dedicated to fast defensive patch mapping -> dynamically scales `'low' | 'medium' | 'high'`
 *   (`'minimal'` is intentionally excluded because `gemini-3.8-flash` supports only `low` / `medium` / `high`).
 * - `deterministic`: 0-token offline mode -> `'none'`.
 */
export function selectOptimalReasoningLevel(
  scan: Pick<StaticScanResult, 'findings'>,
  mode: AnalysisMode,
): ReasoningLevel {
  if (mode === 'deterministic') {
    return 'none';
  }
  if (mode === 'gemini-4-argon') {
    return 'high';
  }
  const criticalCount = scan.findings.filter((f) => f.severity === 'critical').length;
  const highCount = scan.findings.filter((f) => f.severity === 'high').length;
  const mediumCount = scan.findings.filter((f) => f.severity === 'medium').length;
  const activeStacks = new Set(scan.findings.map((f) => f.stack)).size;

  if (criticalCount >= 1 || highCount >= 3 || activeStacks >= 3) {
    return 'high';
  }
  if (highCount >= 1 || mediumCount >= 2) {
    return 'medium';
  }
  return 'low';
}

/**
 * Classifies Gemini errors into immutable pre-approved Japanese fallback messages.
 * NEVER interpolates raw `err.message`, parser fragments, or model text into the report.
 */
export function classifySafeGeminiFallbackReason(err: unknown): string {
  if (err instanceof SyntaxError) {
    return 'Gemini 応答が有効な JSON 形式ではなかったため、決定論的 STRIDE エンジンへ安全フォールバックしました。';
  }
  if (err instanceof ClosedSchemaValidationError) {
    return 'Gemini 応答が閉世界防御スキーマ契約に適合しなかったため、決定論的 STRIDE エンジンへ安全フォールバックしました。';
  }
  if (typeof err === 'object' && err !== null && 'status' in err) {
    const status = (err as { status?: unknown }).status;
    if (status === 401 || status === 403 || status === 429) {
      return 'Gemini API 認証またはクォータ制限のため、決定論的 STRIDE エンジンへ安全フォールバックしました。';
    }
  }
  return 'Gemini API 通信または構造化検証エラーのため、決定論的 STRIDE エンジンへ安全フォールバックしました。';
}

/**
 * Validates raw JSON from Gemini Interactions API fail-closed using ONLY finite enum catalogs
 * and allowlisted repository paths. Zero arbitrary model prose can ever enter the returned objects.
 */
export function validateAndTransformGeminiOutput(
  rawJson: string,
  context?: GeminiValidationContext,
): {
  executiveSummary: string;
  strideMatrix: StrideScoreItem[];
  priorityRoadmap: RoadmapStep[];
  architecturalFindings: SecurityFinding[];
} {
  const parsed = parseGeminiThreatResponse(JSON.parse(rawJson));
  const allowedPaths = context?.allowedFilePaths;

  for (const arch of parsed.architecturalFindings) {
    if (redactSecrets(arch.filePath).redactedText.includes('[REDACTED')) {
      throw new ClosedSchemaValidationError('Secret-like token rejected in filePath.');
    }
    if (
      allowedPaths &&
      !CANONICAL_BOUNDARY_PATHS.has(arch.filePath) &&
      !allowedPaths.has(arch.filePath)
    ) {
      throw new ClosedSchemaValidationError(
        'filePath must match a scanned repository file or canonical boundary.',
      );
    }
  }

  const postureBody = EXECUTIVE_POSTURE_CATALOG[parsed.executivePostureId];
  const truncPrefix = context?.scanTruncated ? '【部分監査】上限到達のため一部未走査あり。' : '';
  const executiveSummary =
    context?.repoLabel !== undefined && context.scannedFiles !== undefined
      ? `${truncPrefix}${sanitizeDisplayLabel(context.repoLabel)}（走査 ${context.scannedFiles} 件 / 静的指摘 ${context.findingCount ?? 0} 件）: ${postureBody}`
      : `${truncPrefix}${postureBody}`;

  const strideMatrix: StrideScoreItem[] = parsed.strideMatrix.map((item) => ({
    category: item.category,
    exposureScore: Math.round(item.exposureScore),
    readinessScore: Math.round(item.readinessScore),
    topRiskSummary: STRIDE_RISK_CATALOG[item.riskCatalogId],
    primaryDefense: STRIDE_DEFENSE_CATALOG[item.defenseCatalogId],
  }));

  const priorityRoadmap: RoadmapStep[] = parsed.priorityRoadmap.slice(0, 4).map((step) => {
    const playbook = ROADMAP_PLAYBOOK_CATALOG[step.playbookId];
    return {
      phase: ROADMAP_PHASE_CATALOG[step.phaseId],
      title: playbook.title,
      impact: playbook.impact,
      targetStack: step.targetStack,
      action: playbook.action,
    };
  });

  const architecturalFindings: SecurityFinding[] = parsed.architecturalFindings
    .slice(0, 5)
    .map((arch, idx) => {
      const spec = ARCHITECTURAL_FINDING_CATALOG[arch.findingCatalogId];
      return {
        id: `LNG-AI-${idx + 1}:${arch.filePath}`,
        ruleId: `LNG-AI-00${idx + 1}`,
        title: spec.title,
        stack: arch.stack,
        severity: arch.severity,
        stride: arch.stride,
        cwe: spec.cwe,
        owaspAsvs: spec.owaspAsvs,
        filePath: arch.filePath,
        line: 1,
        snippetRedacted: '[Gemini Architectural Boundary Synthesis — Zero Raw Code]',
        rootCause: spec.rootCause,
        defensivePatch: DEFENSIVE_PATCH_TEMPLATES[arch.patchTemplateId],
        verificationHint: spec.verificationHint,
        source: 'gemini-architecture',
      };
    });

  return {
    executiveSummary,
    strideMatrix,
    priorityRoadmap,
    architecturalFindings,
  };
}

const STRIDE_CATEGORIES: readonly StrideCategory[] = [
  'Spoofing',
  'Tampering',
  'Repudiation',
  'Information Disclosure',
  'Denial of Service',
  'Elevation of Privilege',
];

export function buildDeterministicThreatSynthesis(scan: StaticScanResult): {
  executiveSummary: string;
  strideMatrix: StrideScoreItem[];
  priorityRoadmap: RoadmapStep[];
} {
  const strideDefaults: Record<StrideCategory, { summary: string; defense: string }> = {
    Spoofing: {
      summary: STRIDE_RISK_CATALOG.SPOOFING_ORIGIN_AND_TOKEN_GAP,
      defense: STRIDE_DEFENSE_CATALOG.DEF_STRICT_ORIGIN_CSRF_APPCHECK,
    },
    Tampering: {
      summary: STRIDE_RISK_CATALOG.TAMPERING_DOM_SINK_AND_SCHEMA,
      defense: STRIDE_DEFENSE_CATALOG.DEF_TRUSTED_TYPES_AND_SCHEMA_ALLOWLIST,
    },
    Repudiation: {
      summary: STRIDE_RISK_CATALOG.REPUDIATION_AUDIT_TRAIL_GAP,
      defense: STRIDE_DEFENSE_CATALOG.DEF_IMMUTABLE_AUDIT_LOGGING,
    },
    'Information Disclosure': {
      summary: STRIDE_RISK_CATALOG.INFO_DISCLOSURE_HARDCODED_KEYS,
      defense: STRIDE_DEFENSE_CATALOG.DEF_VAULT_ROTATION_AND_KEYSTORE,
    },
    'Denial of Service': {
      summary: STRIDE_RISK_CATALOG.DOS_UNBOUNDED_IO_AND_TIMEOUTS,
      defense: STRIDE_DEFENSE_CATALOG.DEF_READ_HEADER_TIMEOUT_AND_WAF,
    },
    'Elevation of Privilege': {
      summary: STRIDE_RISK_CATALOG.EOP_CONTAINER_ROOT_AND_WILDCARD_RULES,
      defense: STRIDE_DEFENSE_CATALOG.DEF_NONROOT_EXECFILE_DENY_DEFAULT,
    },
  };

  const strideMatrix: StrideScoreItem[] = STRIDE_CATEGORIES.map((category) => {
    const matching = scan.findings.filter((f) => f.stride === category);
    const rawExposure = matching.reduce((acc, item) => {
      if (item.severity === 'critical') return acc + 36;
      if (item.severity === 'high') return acc + 22;
      if (item.severity === 'medium') return acc + 12;
      return acc + 5;
    }, 6);
    const exposureScore = Math.min(96, rawExposure);
    const readinessScore = Math.max(4, 100 - exposureScore);
    const topFinding = matching[0];
    const safeTopPath =
      topFinding && SAFE_REL_PATH_RE.test(topFinding.filePath)
        ? `${redactSecrets(topFinding.filePath).redactedText}:${topFinding.line}`
        : undefined;

    return {
      category,
      exposureScore,
      readinessScore,
      topRiskSummary:
        topFinding && safeTopPath
          ? `${topFinding.title} (${safeTopPath})`
          : strideDefaults[category].summary,
      primaryDefense: strideDefaults[category].defense,
    };
  });

  const criticals = scan.findings.filter((f) => f.severity === 'critical').length;
  const highs = scan.findings.filter((f) => f.severity === 'high').length;
  const truncPrefix = scan.scanTruncated ? '【部分監査】上限到達のため一部未走査あり。' : '';
  const safeRepoName = sanitizeDisplayLabel(scan.repoName);

  const executiveSummary =
    scan.findings.length === 0
      ? `${truncPrefix}${safeRepoName}（走査ファイル ${scan.scannedFiles} 件）では重大な静的露出は検出されず、CSP・境界隔離・依存ロック等の主要な予防制御が確認されました。継続的な CI ゲート監視を維持してください。`
      : `${truncPrefix}${safeRepoName}（走査ファイル ${scan.scannedFiles} 件）にて合計 ${scan.findings.length} 件（Critical ${criticals} 件 / High ${highs} 件）の構造的リスク箇所を検出しました。攻撃を受ける前に信頼境界のデフォルト拒否化・機密分離・CSP/TLS 強制パッチを優先適用してください。`;

  const priorityRoadmap: RoadmapStep[] = [
    {
      phase: ROADMAP_PHASE_CATALOG.PHASE_1_24H,
      title: ROADMAP_PLAYBOOK_CATALOG.PLAYBOOK_SECRET_SEGREGATION.title,
      impact: ROADMAP_PLAYBOOK_CATALOG.PLAYBOOK_SECRET_SEGREGATION.impact,
      targetStack:
        criticals > 0 ? (scan.findings[0]?.stack ?? 'supply-chain-secrets') : 'supply-chain-secrets',
      action: ROADMAP_PLAYBOOK_CATALOG.PLAYBOOK_SECRET_SEGREGATION.action,
    },
    {
      phase: ROADMAP_PHASE_CATALOG.PHASE_2_72H,
      title: ROADMAP_PLAYBOOK_CATALOG.PLAYBOOK_WEB_CSP_TRUSTED_TYPES.title,
      impact: ROADMAP_PLAYBOOK_CATALOG.PLAYBOOK_WEB_CSP_TRUSTED_TYPES.impact,
      targetStack: 'ts-web-api',
      action: ROADMAP_PLAYBOOK_CATALOG.PLAYBOOK_WEB_CSP_TRUSTED_TYPES.action,
    },
    {
      phase: ROADMAP_PHASE_CATALOG.PHASE_3_CI,
      title: ROADMAP_PLAYBOOK_CATALOG.PLAYBOOK_CLOUD_PERIMETER_NONROOT.title,
      impact: ROADMAP_PLAYBOOK_CATALOG.PLAYBOOK_CLOUD_PERIMETER_NONROOT.impact,
      targetStack: 'python-go-cloud',
      action: ROADMAP_PLAYBOOK_CATALOG.PLAYBOOK_CLOUD_PERIMETER_NONROOT.action,
    },
  ];

  return { executiveSummary, strideMatrix, priorityRoadmap };
}

export async function executeDefensiveAudit(params: {
  targetPath: string;
  mode: AnalysisMode;
  apiKeyOverride?: string;
  excludeRelativePrefixes?: string[];
  scanOptions?: ScanOptions;
}): Promise<AuditReport> {
  const startedAt = performance.now();
  const mergedScanOptions: ScanOptions = {
    ...(params.scanOptions ?? {}),
    ...(params.excludeRelativePrefixes
      ? { excludeRelativePrefixes: params.excludeRelativePrefixes }
      : {}),
  };

  const scan = await runStaticRepositoryScan(params.targetPath, mergedScanOptions);
  const stackSummaries = buildStackSummaries(scan);

  const deterministic = buildDeterministicThreatSynthesis(scan);
  let executiveSummary = deterministic.executiveSummary;
  let strideMatrix = deterministic.strideMatrix;
  let priorityRoadmap = deterministic.priorityRoadmap;
  const mergedFindings: SecurityFinding[] = [...scan.findings];

  const plannedReasoning = selectOptimalReasoningLevel(scan, params.mode);
  let geminiLiveUsed = false;
  let reasoningLevelUsed: ReasoningLevel = 'none';
  let geminiFallbackReason: string | undefined;
  let tokenEstimate = 0;

  const resolvedApiKey =
    (params.apiKeyOverride?.trim() || process.env['GEMINI_API_KEY']?.trim()) ?? '';

  if (params.mode !== 'deterministic') {
    const requestedModel = ALLOWED_GEMINI_MODELS.has(params.mode)
      ? params.mode
      : 'gemini-3.8-flash';
    if (!resolvedApiKey) {
      geminiFallbackReason =
        'GEMINI_API_KEY 未設定のため、0トークン決定論的 STRIDE エンジンで予防分析を完了しました。';
    } else {
      try {
        const safeDigest = redactSecrets(scan.architectureDigest).redactedText;
        tokenEstimate = Math.ceil(safeDigest.length / 4) + 320;
        const activeThinkingLevel = plannedReasoning === 'none' ? 'low' : plannedReasoning;

        const apiRes = await fetch('https://generativelanguage.googleapis.com/v1beta/interactions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-goog-api-key': resolvedApiKey,
          },
          body: JSON.stringify({
            model: requestedModel,
            store: false,
            system_instruction: DEFENSIVE_SYSTEM_INSTRUCTION,
            input: `以下のゼロ抜粋・構造境界テレメトリから防御カタログ列挙値を選択して JSON で出力してください:\n\n${safeDigest}`,
            generation_config: {
              thinking_level: activeThinkingLevel,
            },
            response_format: {
              type: 'text',
              mime_type: 'application/json',
              schema: THREAT_MODEL_JSON_SCHEMA,
            },
          }),
        });
        if (!apiRes.ok) {
          throw Object.assign(new Error('Gemini HTTP status error'), { status: apiRes.status });
        }
        const interaction = (await apiRes.json()) as { output_text?: string };
        const rawJson = interaction.output_text;
        if (!rawJson) {
          throw new Error('Empty structured output');
        }

        const criticalCount = scan.findings.filter((f) => f.severity === 'critical').length;
        const highCount = scan.findings.filter((f) => f.severity === 'high').length;
        const validated = validateAndTransformGeminiOutput(rawJson, {
          allowedFilePaths: new Set(scan.manifestPaths),
          repoLabel: scan.repoName,
          scannedFiles: scan.scannedFiles,
          findingCount: scan.findings.length,
          criticalCount,
          highCount,
          scanTruncated: scan.scanTruncated,
        });

        executiveSummary = validated.executiveSummary;
        if (validated.strideMatrix.length > 0) {
          const byCat = new Map(validated.strideMatrix.map((s) => [s.category, s]));
          strideMatrix = deterministic.strideMatrix.map((defItem) => byCat.get(defItem.category) ?? defItem);
        }
        if (validated.priorityRoadmap.length > 0) {
          priorityRoadmap = validated.priorityRoadmap;
        }
        mergedFindings.push(...validated.architecturalFindings);
        geminiLiveUsed = true;
        reasoningLevelUsed = activeThinkingLevel;
      } catch (err) {
        geminiFallbackReason = classifySafeGeminiFallbackReason(err);
      }
    }
  }

  const activeStacks = stackSummaries.filter((s) => s.detectedFiles > 0);
  const stackAvg =
    activeStacks.length > 0
      ? activeStacks.reduce((sum, s) => sum + s.defenseScore, 0) / activeStacks.length
      : 100;
  const strideAvg =
    strideMatrix.reduce((sum, item) => sum + item.readinessScore, 0) / strideMatrix.length;
  const overallDefenseScore = Math.round(stackAvg * 0.65 + strideAvg * 0.35);

  const destructionCertificate = executeEphemeralFernetDoDCycle(scan.architectureDigest);
  const durationMs = Math.max(1, Math.round(performance.now() - startedAt));

  const report: AuditReport = {
    auditId: crypto.randomUUID(),
    targetPath: redactSecrets(scan.canonicalRoot).redactedText,
    repoName: sanitizeDisplayLabel(scan.repoName),
    auditedAt: new Date().toISOString(),
    durationMs,
    scannedFiles: scan.scannedFiles,
    inspectedEntries: scan.inspectedEntries,
    scanTruncated: scan.scanTruncated,
    redactedSecretsCount: scan.redactedSecretsCount,
    analysisModeUsed: params.mode,
    reasoningLevelUsed,
    geminiLiveUsed,
    tokenEstimate,
    overallDefenseScore,
    executiveSummary,
    priorityRoadmap,
    strideMatrix,
    stackSummaries,
    trustGraph: scan.trustGraph,
    findings: mergedFindings,
    destructionCertificate,
  };

  if (scan.truncationReason !== undefined) {
    report.truncationReason = scan.truncationReason;
  }
  if (geminiFallbackReason !== undefined) {
    report.geminiFallbackReason = geminiFallbackReason;
  }

  return report;
}

const MAX_PORTFOLIO_ENTRIES = 80;
const MAX_PORTFOLIO_REPOS = 25;

function sanitizePortfolioDirName(raw: string): string {
  const cleaned = redactSecrets(raw).redactedText.replace(/[\u0000-\u001F\u007F]/g, '').trim();
  return cleaned.slice(0, 64) || 'repository';
}

/**
 * Performs a strictly read-only, 0-token deterministic defensive posture audit across
 * direct child repositories of `portfolioRoot`. Returns zero source snippets.
 */
export async function scanPortfolioDirectory(params: {
  portfolioRoot: string;
  selfProjectRoot?: string;
}): Promise<PortfolioReport> {
  const startedAt = performance.now();
  const canonicalSelf = params.selfProjectRoot
    ? await resolveSafeTargetDirectory(params.selfProjectRoot).catch(() => '')
    : '';

  const openFlags =
    fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW;
  let portfolioRootFh: fs.FileHandle | undefined;
  let canonicalRoot = '';
  const repos: PortfolioRepoSummary[] = [];

  try {
    const pinnedPortfolio = await openPinnedSafeTargetDirectory(params.portfolioRoot);
    canonicalRoot = pinnedPortfolio.canonicalRoot;
    portfolioRootFh = pinnedPortfolio.handle;
    const portfolioStat = pinnedPortfolio.stat;

    const candidateNames: string[] = [];
    const dirHandle = await fs.opendir(canonicalRoot);
    let inspected = 0;
    try {
      for await (const dirent of dirHandle) {
        inspected += 1;
        if (inspected > MAX_PORTFOLIO_ENTRIES) break;
        if (
          !dirent.name ||
          dirent.name.startsWith('.') ||
          dirent.name.includes('/') ||
          dirent.name.includes('\\') ||
          dirent.name.includes('\0')
        ) {
          continue;
        }
        if (dirent.isSymbolicLink() || !dirent.isDirectory()) continue;
        if (redactSecrets(dirent.name).redactionCount > 0) continue;
        candidateNames.push(dirent.name);
        if (candidateNames.length >= MAX_PORTFOLIO_REPOS) break;
      }
    } finally {
      await dirHandle.close().catch(() => undefined);
    }

    const postListStat = await fs.lstat(canonicalRoot).catch(() => null);
    if (
      !postListStat ||
      postListStat.isSymbolicLink() ||
      !postListStat.isDirectory() ||
      postListStat.dev !== portfolioStat.dev ||
      postListStat.ino !== portfolioStat.ino
    ) {
      throw new SafeClientError('ポートフォリオディレクトリの境界検証で競合を検出しました。');
    }

    candidateNames.sort((a, b) => a.localeCompare(b));

    for (const name of candidateNames) {
      const fullPath = path.join(canonicalRoot, name);
      let childFh: fs.FileHandle | undefined;
      let childDev = 0;
      let childIno = 0;
      try {
        const lstat = await fs.lstat(fullPath);
        if (!lstat.isDirectory() || lstat.isSymbolicLink()) {
          continue;
        }
        childFh = await fs.open(fullPath, openFlags);
        const childStat = await childFh.stat();
        if (
          !childStat.isDirectory() ||
          childStat.dev !== lstat.dev ||
          childStat.ino !== lstat.ino
        ) {
          continue;
        }
        childDev = childStat.dev;
        childIno = childStat.ino;
      } catch {
        continue;
      } finally {
        if (childFh) {
          await childFh.close().catch(() => undefined);
        }
      }

      const isSelf = canonicalSelf !== '' && fullPath === canonicalSelf;
      try {
        const report = await executeDefensiveAudit({
          targetPath: fullPath,
          mode: 'deterministic',
          ...(isSelf ? { excludeRelativePrefixes: ['test'] } : {}),
          scanOptions: {
            expectedRootIdentity: {
              dev: childDev,
              ino: childIno,
              parentDev: portfolioStat.dev,
              parentIno: portfolioStat.ino,
            },
          },
        });

        if (report.scannedFiles === 0 && report.findings.length === 0) {
          continue;
        }

        const criticalCount = report.findings.filter((f) => f.severity === 'critical').length;
        const highCount = report.findings.filter((f) => f.severity === 'high').length;
        const mediumCount = report.findings.filter((f) => f.severity === 'medium').length;
        const lowCount = report.findings.filter((f) => f.severity === 'low').length;
        const verifiedControlsCount = report.stackSummaries.reduce(
          (acc, s) => acc + s.verifiedControls.length,
          0,
        );

        const topStackSummary = [...report.stackSummaries].sort(
          (a, b) => b.detectedFiles - a.detectedFiles,
        )[0];
        const primaryStack: StackDomain =
          report.findings[0]?.stack ?? topStackSummary?.stack ?? 'ts-web-api';

        const topAction = report.findings[0]
          ? `${report.findings[0].ruleId}: ${report.findings[0].title}`
          : '✓ 重大な静的露出なし（CI ゲート継続監視）';

        repos.push({
          dirName: sanitizePortfolioDirName(name),
          repoName: report.repoName,
          targetPath: report.targetPath,
          overallDefenseScore: report.overallDefenseScore,
          scannedFiles: report.scannedFiles,
          scanTruncated: report.scanTruncated,
          criticalCount,
          highCount,
          mediumCount,
          lowCount,
          redactedSecretsCount: report.redactedSecretsCount,
          verifiedControlsCount,
          primaryStack,
          topAction,
        });
      } catch {
        // Skip inaccessible or concurrently swapped child directory safely
      }
    }
  } finally {
    if (portfolioRootFh) {
      await portfolioRootFh.close().catch(() => undefined);
    }
  }

  repos.sort(
    (a, b) =>
      a.overallDefenseScore - b.overallDefenseScore ||
      b.criticalCount - a.criticalCount ||
      a.dirName.localeCompare(b.dirName),
  );

  const totalRepos = repos.length;
  const averageDefenseScore =
    totalRepos > 0
      ? Math.round(repos.reduce((sum, r) => sum + r.overallDefenseScore, 0) / totalRepos)
      : 100;
  const criticalReposCount = repos.filter((r) => r.criticalCount > 0).length;
  const totalRedactedSecrets = repos.reduce((sum, r) => sum + r.redactedSecretsCount, 0);

  return {
    portfolioRootLabel: sanitizeDisplayLabel(path.basename(canonicalRoot)),
    scannedAt: new Date().toISOString(),
    durationMs: Math.max(1, Math.round(performance.now() - startedAt)),
    totalRepos,
    averageDefenseScore,
    criticalReposCount,
    totalRedactedSecrets,
    repos,
  };
}
