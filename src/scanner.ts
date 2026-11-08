import { constants as fsConstants, type Dirent, type Stats } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import { redactSecrets, redactSecretsPreserveLines } from './redactor.js';
import { classifyFileStack, evaluateFileRules, type FileContext } from './rules.js';
import type {
  SecurityFinding,
  StackDomain,
  StackPostureSummary,
  TrustBoundaryEdge,
  TrustBoundaryNode,
} from './types.js';

export class SafeClientError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SafeClientError';
  }
}

class DirectoryRaceAbortError extends Error {
  constructor() {
    super('Directory containment invariant interrupted due to concurrent filesystem mutation.');
    this.name = 'DirectoryRaceAbortError';
  }
}

const IGNORED_DIRS = new Set([
  '.git',
  '.ssh',
  '.gnupg',
  '.aws',
  '.gcloud',
  '.codex',
  '.claude',
  '.gemini',
  'node_modules',
  'dist',
  'build',
  '.next',
  '.dart_tool',
  '.gradle',
  'Pods',
  '__pycache__',
  '.venv',
  'venv',
  'coverage',
  '.turbo',
]);

const DEFAULT_MAX_FILE_BYTES = 512 * 1024; // 512 KB per file
const DEFAULT_MAX_OPENED_FILES = 1500; // Includes binary & text open attempts
const DEFAULT_MAX_INSPECTED_ENTRIES = 3500; // Total directory/file entries visited
const DEFAULT_MAX_TOTAL_BYTES = 24 * 1024 * 1024; // 24 MB cumulative read cap

export interface ScanOptions {
  excludeRelativePrefixes?: string[];
  maxFileBytes?: number;
  maxOpenedFiles?: number;
  maxInspectedEntries?: number;
  maxTotalBytes?: number;
}

export interface StaticScanResult {
  canonicalRoot: string;
  repoName: string;
  scannedFiles: number;
  inspectedEntries: number;
  totalBytesRead: number;
  scanTruncated: boolean;
  truncationReason?: string;
  redactedSecretsCount: number;
  manifestPaths: readonly string[];
  stackFileCounts: Record<StackDomain, number>;
  verifiedControlsByStack: Record<StackDomain, string[]>;
  findings: SecurityFinding[];
  trustGraph: {
    nodes: TrustBoundaryNode[];
    edges: TrustBoundaryEdge[];
  };
  architectureDigest: string;
}

export interface ReadableFileHandleLike {
  stat(): Promise<{ isFile(): boolean; size: number }>;
  read(
    buffer: Buffer,
    offset: number,
    length: number,
    position: number | null,
  ): Promise<{ bytesRead: number }>;
}

export type BoundedFileReadResult =
  | { status: 'ok'; buffer: Buffer; bytesRead: number }
  | { status: 'skipped'; bytesRead: number }
  | { status: 'budget_exceeded'; bytesRead: number };

let activeScanQueue: Promise<void> = Promise.resolve();

function withScanMutex<T>(task: () => Promise<T>): Promise<T> {
  const result = activeScanQueue.then(task, task);
  activeScanQueue = result.then(
    () => undefined,
    () => undefined,
  );
  return result;
}

function assertPosixNoFollowFlags(): { oNoFollow: number; oDirectory: number; oNonBlock: number } {
  const oNoFollow = fsConstants.O_NOFOLLOW;
  const oDirectory = fsConstants.O_DIRECTORY;
  const oNonBlock = typeof fsConstants.O_NONBLOCK === 'number' ? fsConstants.O_NONBLOCK : 0;
  if (typeof oNoFollow !== 'number' || oNoFollow === 0 || typeof oDirectory !== 'number' || oDirectory === 0) {
    throw new Error('OS kernel does not expose O_NOFOLLOW / O_DIRECTORY required for symlink-safe scanning.');
  }
  return { oNoFollow, oDirectory, oNonBlock };
}

function isSinglePathComponent(name: string): boolean {
  return (
    name.length > 0 &&
    name !== '.' &&
    name !== '..' &&
    !name.includes('/') &&
    !name.includes('\\') &&
    !name.includes('\0')
  );
}

function isLikelyBinary(buffer: Buffer, length: number): boolean {
  const sampleLen = Math.min(length, 2048);
  for (let i = 0; i < sampleLen; i++) {
    if (buffer[i] === 0) return true;
  }
  return false;
}

/**
 * Reads from an already-opened file handle under strict per-file and cumulative byte caps.
 * Reports exact `bytesRead` on ALL return paths (ok, skipped, budget_exceeded, and partial errors).
 */
export async function readBoundedFromHandle(params: {
  handle: ReadableFileHandleLike;
  maxFileBytes: number;
  remainingTotalBudget: number;
}): Promise<BoundedFileReadResult> {
  let bytesReadSoFar = 0;
  try {
    if (params.remainingTotalBudget < 0) {
      return { status: 'budget_exceeded', bytesRead: 0 };
    }
    const fdStat = await params.handle.stat();
    if (!fdStat.isFile()) {
      return { status: 'skipped', bytesRead: 0 };
    }
    if (fdStat.size > params.maxFileBytes) {
      return { status: 'skipped', bytesRead: 0 };
    }
    if (fdStat.size > params.remainingTotalBudget) {
      return { status: 'budget_exceeded', bytesRead: 0 };
    }

    const cap = Math.min(params.maxFileBytes + 1, params.remainingTotalBudget + 1);
    const initialLen = Math.max(1, Math.min(Math.max(fdStat.size + 1, 64), cap));
    let buf = Buffer.allocUnsafe(initialLen);

    while (bytesReadSoFar < cap) {
      if (bytesReadSoFar >= buf.length) {
        const nextLen = Math.min(buf.length * 2, cap);
        const grown = Buffer.allocUnsafe(nextLen);
        buf.copy(grown, 0, 0, bytesReadSoFar);
        buf = grown;
      }
      const { bytesRead } = await params.handle.read(
        buf,
        bytesReadSoFar,
        buf.length - bytesReadSoFar,
        bytesReadSoFar,
      );
      if (bytesRead <= 0) break;
      bytesReadSoFar += bytesRead;
    }

    if (bytesReadSoFar > params.remainingTotalBudget) {
      return { status: 'budget_exceeded', bytesRead: bytesReadSoFar };
    }
    if (bytesReadSoFar > params.maxFileBytes) {
      return { status: 'skipped', bytesRead: bytesReadSoFar };
    }

    return {
      status: 'ok',
      buffer: buf.subarray(0, bytesReadSoFar),
      bytesRead: bytesReadSoFar,
    };
  } catch {
    return { status: 'skipped', bytesRead: bytesReadSoFar };
  }
}

/**
 * Opens a single-component entry directly inside the kernel's pinned AT_FDCWD directory
 * using O_RDONLY | O_NOFOLLOW | O_NONBLOCK (never re-traversing mutable parent path strings).
 */
async function readSingleComponentSafeFile(params: {
  entryName: string;
  maxFileBytes: number;
  remainingTotalBudget: number;
  oNoFollow: number;
  oNonBlock: number;
}): Promise<BoundedFileReadResult> {
  if (!isSinglePathComponent(params.entryName)) {
    return { status: 'skipped', bytesRead: 0 };
  }
  let fh: fs.FileHandle | undefined;
  try {
    fh = await fs.open(
      params.entryName,
      fsConstants.O_RDONLY | params.oNoFollow | params.oNonBlock,
    );
    return await readBoundedFromHandle({
      handle: fh,
      maxFileBytes: params.maxFileBytes,
      remainingTotalBudget: params.remainingTotalBudget,
    });
  } catch {
    // ELOOP (symlink rejected by O_NOFOLLOW), EACCES, ENOENT, etc.
    return { status: 'skipped', bytesRead: 0 };
  } finally {
    if (fh) {
      await fh.close().catch(() => undefined);
    }
  }
}

/**
 * Safely validates and canonicalizes a local directory path.
 * Strictly read-only; rejects NUL bytes, non-existent paths, and non-directories.
 */
export async function resolveSafeTargetDirectory(rawTargetPath: string): Promise<string> {
  if (!rawTargetPath || rawTargetPath.includes('\0')) {
    throw new SafeClientError('無効な監査対象パスです。');
  }
  const resolved = path.resolve(rawTargetPath.trim());
  let canonical: string;
  try {
    canonical = await fs.realpath(resolved);
  } catch {
    throw new SafeClientError('監査対象パスが存在しないかアクセスできません。');
  }
  let stat: Stats;
  try {
    stat = await fs.lstat(canonical);
  } catch {
    throw new SafeClientError('監査対象パスが存在しないかアクセスできません。');
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new SafeClientError('監査対象パスはローカルディレクトリである必要があります。');
  }
  return canonical;
}

export async function runStaticRepositoryScan(
  targetPath: string,
  options?: ScanOptions,
): Promise<StaticScanResult> {
  return withScanMutex(async () => {
    const { oNoFollow, oDirectory, oNonBlock } = assertPosixNoFollowFlags();
    const canonicalRoot = await resolveSafeTargetDirectory(targetPath);
    const repoName = path.basename(canonicalRoot);
    const excludePrefixes = options?.excludeRelativePrefixes ?? [];
    const maxFileBytes = options?.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
    const maxOpenedFiles = options?.maxOpenedFiles ?? DEFAULT_MAX_OPENED_FILES;
    const maxInspectedEntries = options?.maxInspectedEntries ?? DEFAULT_MAX_INSPECTED_ENTRIES;
    const maxTotalBytes = options?.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES;

    let scannedFiles = 0;
    let openedFiles = 0;
    let inspectedEntries = 0;
    let totalBytesRead = 0;
    let scanTruncated = false;
    let abortAllWork = false;
    let truncationReason: string | undefined;
    let redactedSecretsCount = 0;

    const findings: SecurityFinding[] = [];
    const manifestSet = new Set<string>();

    const stackFileCounts: Record<StackDomain, number> = {
      'ts-web-api': 0,
      'flutter-firebase': 0,
      'python-go-cloud': 0,
      'supply-chain-secrets': 0,
    };

    const verifiedControlsByStack: Record<StackDomain, Set<string>> = {
      'ts-web-api': new Set(),
      'flutter-firebase': new Set(),
      'python-go-cloud': new Set(),
      'supply-chain-secrets': new Set(),
    };

    function markTruncated(reason: string): void {
      if (!scanTruncated) {
        scanTruncated = true;
        truncationReason = reason;
      }
    }

    const savedCwd = process.cwd();
    let rootDirFh: fs.FileHandle | undefined;

    try {
      // Pin canonicalRoot directory FD so its (dev, ino) cannot be recycled during scan
      rootDirFh = await fs.open(canonicalRoot, fsConstants.O_RDONLY | oDirectory | oNoFollow);
      const rootStat = await rootDirFh.stat();
      if (!rootStat.isDirectory()) {
        throw new SafeClientError('監査対象パスはローカルディレクトリである必要があります。');
      }

      process.chdir(canonicalRoot);
      const rootDot = await fs.lstat('.');
      if (rootDot.dev !== rootStat.dev || rootDot.ino !== rootStat.ino) {
        markTruncated('対象ルートディレクトリの境界検証で競合を検出したため安全停止しました。');
        throw new DirectoryRaceAbortError();
      }

      const ancestorInodes = new Set<string>([`${rootStat.dev}:${rootStat.ino}`]);

      const walkPinnedDir = async (relDirPrefix: string, currentDirStat: Stats): Promise<void> => {
        if (abortAllWork) return;

        // Stream directory entries from '.' (pinned AT_FDCWD) bounded strictly by maxInspectedEntries
        const batch: Dirent[] = [];
        let dirHandle;
        try {
          dirHandle = await fs.opendir('.');
        } catch {
          return;
        }

        try {
          for await (const dirent of dirHandle) {
            if (inspectedEntries >= maxInspectedEntries) {
              markTruncated(
                `走査エントリ上限 (${maxInspectedEntries} 件) に達したため部分監査となりました。`,
              );
              break;
            }
            inspectedEntries += 1;
            batch.push(dirent);
          }
        } finally {
          await dirHandle.close().catch(() => undefined);
        }

        batch.sort((a, b) => a.name.localeCompare(b.name));

        for (const entry of batch) {
          if (abortAllWork) break;
          if (!isSinglePathComponent(entry.name)) continue;
          if (entry.isSymbolicLink()) continue;

          const relPath = relDirPrefix ? `${relDirPrefix}/${entry.name}` : entry.name;
          if (
            excludePrefixes.some(
              (prefix) => relPath === prefix || relPath.startsWith(`${prefix}/`),
            )
          ) {
            continue;
          }

          if (entry.isDirectory()) {
            if (IGNORED_DIRS.has(entry.name)) continue;
            if (scanTruncated) continue;

            // Step into child directory via single-component O_NOFOLLOW + AT_FDCWD inode pin check
            let childFh: fs.FileHandle | undefined;
            try {
              childFh = await fs.open(
                entry.name,
                fsConstants.O_RDONLY | oDirectory | oNoFollow,
              );
              const childStat = await childFh.stat();
              if (!childStat.isDirectory()) continue;

              const inodeKey = `${childStat.dev}:${childStat.ino}`;
              if (ancestorInodes.has(inodeKey)) continue;

              process.chdir(entry.name);
              const enteredDot = await fs.lstat('.');
              if (enteredDot.dev !== childStat.dev || enteredDot.ino !== childStat.ino) {
                markTruncated('走査中にディレクトリ差し替え競合を検出したため安全停止しました。');
                throw new DirectoryRaceAbortError();
              }

              ancestorInodes.add(inodeKey);
              try {
                await walkPinnedDir(relPath, childStat);
              } finally {
                ancestorInodes.delete(inodeKey);
              }

              process.chdir('..');
              const returnedDot = await fs.lstat('.');
              if (
                returnedDot.dev !== currentDirStat.dev ||
                returnedDot.ino !== currentDirStat.ino
              ) {
                markTruncated('走査中に親ディレクトリ構造の変更を検出したため安全停止しました。');
                throw new DirectoryRaceAbortError();
              }
            } catch (err) {
              if (err instanceof DirectoryRaceAbortError) throw err;
              const verifyDot = await fs.lstat('.').catch(() => null);
              if (
                !verifyDot ||
                verifyDot.dev !== currentDirStat.dev ||
                verifyDot.ino !== currentDirStat.ino
              ) {
                markTruncated('走査中にディレクトリ境界の不整合を検出したため安全停止しました。');
                throw new DirectoryRaceAbortError();
              }
            } finally {
              if (childFh) {
                await childFh.close().catch(() => undefined);
              }
            }
            continue;
          }

          if (!entry.isFile()) continue;
          manifestSet.add(relPath);

          if (openedFiles >= maxOpenedFiles) {
            markTruncated(
              `ファイル読取試行数上限 (${maxOpenedFiles} 件) に達したため部分監査となりました。`,
            );
            abortAllWork = true;
            break;
          }
          if (totalBytesRead >= maxTotalBytes) {
            markTruncated(
              `累積読取バイト予算 (${formatByteBudgetLabel(maxTotalBytes)}) に達したため部分監査となりました。`,
            );
            abortAllWork = true;
            break;
          }

          openedFiles += 1;
          const remainingBudgetBeforeRead = maxTotalBytes - totalBytesRead;
          const readRes = await readSingleComponentSafeFile({
            entryName: entry.name,
            maxFileBytes,
            remainingTotalBudget: remainingBudgetBeforeRead,
            oNoFollow,
            oNonBlock,
          });

          // Account for ALL bytes read regardless of ok / skipped / budget_exceeded
          totalBytesRead += readRes.bytesRead;

          if (readRes.status === 'budget_exceeded' || totalBytesRead > maxTotalBytes) {
            markTruncated(
              `累積読取バイト予算 (${formatByteBudgetLabel(maxTotalBytes)}) に達したため部分監査となりました。`,
            );
            abortAllWork = true;
            break;
          }
          if (readRes.status === 'skipped') {
            continue;
          }

          const buf = readRes.buffer;
          if (isLikelyBinary(buf, buf.length)) {
            continue;
          }

          scannedFiles += 1;
          const rawContent = buf.toString('utf8');
          const stack = classifyFileStack(relPath);
          stackFileCounts[stack] += 1;

          const isEnvFile = entry.name === '.env' || entry.name.startsWith('.env.');
          const redaction = redactSecretsPreserveLines(rawContent, { isEnvFile });
          if (!relPath.endsWith('src/redactor.ts') && !relPath.endsWith('src/rules.ts')) {
            redactedSecretsCount += redaction.redactionCount;
          }

          // Evaluate positive controls & static rules strictly on full-file-redacted text
          detectVerifiedControls(relPath, redaction.redactedText, verifiedControlsByStack);

          const ctx: FileContext = {
            relativePath: relPath,
            baseName: entry.name,
            ext: path.extname(entry.name).toLowerCase(),
            redactedContent: redaction.redactedText,
            redactedLines: redaction.redactedLines,
            redactedLineNumbers: redaction.redactedLineNumbers,
          };

          const fileFindings = evaluateFileRules(ctx);
          findings.push(...fileFindings);
        }
      };

      await walkPinnedDir('', rootStat);
    } catch (err) {
      if (!(err instanceof DirectoryRaceAbortError)) {
        throw err;
      }
    } finally {
      try {
        process.chdir(savedCwd);
      } catch {
        // Ignore if savedCwd became unavailable
      }
      if (rootDirFh) {
        await rootDirFh.close().catch(() => undefined);
      }
    }

    checkLockfileHygiene(
      manifestSet,
      findings,
      verifiedControlsByStack['supply-chain-secrets'],
      scanTruncated,
    );

    const severityOrder: Record<SecurityFinding['severity'], number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
    };
    findings.sort((a, b) => {
      const diff = severityOrder[a.severity] - severityOrder[b.severity];
      if (diff !== 0) return diff;
      return a.filePath.localeCompare(b.filePath) || a.line - b.line;
    });

    const trustGraph = buildTrustBoundaryGraph(stackFileCounts, findings, verifiedControlsByStack);

    const controlsRecord: Record<StackDomain, string[]> = {
      'ts-web-api': Array.from(verifiedControlsByStack['ts-web-api']),
      'flutter-firebase': Array.from(verifiedControlsByStack['flutter-firebase']),
      'python-go-cloud': Array.from(verifiedControlsByStack['python-go-cloud']),
      'supply-chain-secrets': Array.from(verifiedControlsByStack['supply-chain-secrets']),
    };

    const manifestPaths = Array.from(manifestSet).sort();

    const architectureDigest = buildStructuralZeroSnippetDigest({
      repoName,
      scannedFiles,
      scanTruncated,
      stackFileCounts,
      controlsRecord,
      findings,
      manifestPaths,
    });

    const result: StaticScanResult = {
      canonicalRoot,
      repoName,
      scannedFiles,
      inspectedEntries,
      totalBytesRead,
      scanTruncated,
      redactedSecretsCount,
      manifestPaths,
      stackFileCounts,
      verifiedControlsByStack: controlsRecord,
      findings,
      trustGraph,
      architectureDigest,
    };
    if (truncationReason !== undefined) {
      result.truncationReason = truncationReason;
    }
    return result;
  });
}

function formatByteBudgetLabel(bytes: number): string {
  if (bytes >= 1024 * 1024) {
    return `${Math.round(bytes / (1024 * 1024))}MB`;
  }
  return `${bytes}B`;
}

function detectVerifiedControls(
  relPath: string,
  content: string,
  verified: Record<StackDomain, Set<string>>,
): void {
  if (content.includes('Content-Security-Policy') && content.includes('nonce-')) {
    verified['ts-web-api'].add('Per-Request CSP Nonce');
  }
  if (content.includes("require-trusted-types-for 'script'")) {
    verified['ts-web-api'].add('Trusted Types DOM Enforcement');
  }
  if (content.includes('Sec-Fetch-Site')) {
    verified['ts-web-api'].add('Fetch Metadata Cross-Site Isolation');
  }
  if (content.includes('X-Content-Type-Options') && content.includes('nosniff')) {
    verified['ts-web-api'].add('MIME Sniffing Guard (nosniff)');
  }
  if (content.includes('127.0.0.1')) {
    verified['ts-web-api'].add('Loopback-Only Socket Binding');
  }
  if (relPath.endsWith('.rules') && /allow\s+read,\s*write:\s*if\s+false/.test(content)) {
    verified['flutter-firebase'].add('Firestore Deny-by-Default Root Rule');
  }
  if (relPath.endsWith('.rules') && content.includes('.hasOnly(')) {
    verified['flutter-firebase'].add('Firestore Schema Key Allowlist (hasOnly)');
  }
  if (content.includes('enforceAppCheck: true') || content.includes('FlutterSecureStorage')) {
    verified['flutter-firebase'].add('App Check / Hardware Keystore Storage');
  }
  if (
    (relPath.endsWith('Dockerfile') || relPath.includes('Dockerfile.')) &&
    /^USER\s+(?!root\b|0\b)\S+/m.test(content)
  ) {
    verified['python-go-cloud'].add('Non-Root Container User');
  }
  if (content.includes('ReadHeaderTimeout') || content.includes('headersTimeout')) {
    verified['python-go-cloud'].add('Slowloris Header Timeout Protection');
  }
  if (relPath === '.gitignore' && content.includes('.env')) {
    verified['supply-chain-secrets'].add('.env Git Exclusion Guard');
  }
  if (content.includes('redactSecretsPreserveLines')) {
    verified['supply-chain-secrets'].add('Local Memory Secret Redaction');
  }
}

function checkLockfileHygiene(
  manifests: Set<string>,
  findings: SecurityFinding[],
  supplyChainControls: Set<string>,
  scanTruncated: boolean,
): void {
  const hasPkgJson = manifests.has('package.json');
  const hasNodeLock =
    manifests.has('pnpm-lock.yaml') ||
    manifests.has('package-lock.json') ||
    manifests.has('yarn.lock');

  if (hasPkgJson && hasNodeLock) {
    supplyChainControls.add('Deterministic Node Lockfile Present');
  } else if (hasPkgJson && !hasNodeLock && !scanTruncated) {
    findings.push({
      id: 'LNG-SEC-003:package.json:1',
      ruleId: 'LNG-SEC-003',
      title: '依存関係ロックファイル未検出（非決定論的サプライチェーン解決）',
      stack: 'supply-chain-secrets',
      severity: 'medium',
      stride: 'Tampering',
      cwe: 'CWE-353',
      owaspAsvs: 'V14.2.1 Deterministic Dependency Pinning',
      filePath: 'package.json',
      line: 1,
      snippetRedacted: 'package.json without pnpm-lock.yaml / package-lock.json',
      rootCause:
        'ロックファイルが存在しない場合、ビルド毎にセマンティックバージョン範囲内で新規公開パッケージが自動取得され、悪意あるマイナー更新の混入を防げません。',
      defensivePatch: `# 防御パッチ: ロックファイルを生成・コミットし CI では frozen-lockfile を強制
pnpm install --lockfile-only
pnpm install --frozen-lockfile`,
      verificationHint: 'pnpm-lock.yaml または package-lock.json がリポジトリルートに存在することを確認。',
      source: 'static-rule',
    });
  }
}

function buildTrustBoundaryGraph(
  stackCounts: Record<StackDomain, number>,
  findings: SecurityFinding[],
  verified: Record<StackDomain, Set<string>>,
): { nodes: TrustBoundaryNode[]; edges: TrustBoundaryEdge[] } {
  const countByStack = (stack: StackDomain, minSeverity?: 'high' | 'critical'): number =>
    findings.filter((f) => {
      if (f.stack !== stack) return false;
      if (minSeverity === 'critical') return f.severity === 'critical';
      if (minSeverity === 'high') return f.severity === 'critical' || f.severity === 'high';
      return true;
    }).length;

  const computeStatus = (stack: StackDomain): 'hardened' | 'attention' | 'exposed' => {
    if (countByStack(stack, 'high') > 0) return 'exposed';
    if (countByStack(stack) > 0) return 'attention';
    return 'hardened';
  };

  const nodes: TrustBoundaryNode[] = [
    {
      id: 'edge-client',
      label: 'Web / Client Surface',
      zone: 'edge',
      stack: 'ts-web-api',
      status: computeStatus('ts-web-api'),
      findingCount: countByStack('ts-web-api'),
      summary:
        verified['ts-web-api'].size > 0
          ? `保護確認: ${Array.from(verified['ts-web-api']).slice(0, 2).join(' / ')}`
          : `検出ファイル ${stackCounts['ts-web-api']} 件・CSP/Origin 境界`,
    },
    {
      id: 'mobile-rules',
      label: 'Flutter & Firebase Rules',
      zone: 'auth',
      stack: 'flutter-firebase',
      status: computeStatus('flutter-firebase'),
      findingCount: countByStack('flutter-firebase'),
      summary:
        stackCounts['flutter-firebase'] > 0
          ? `モバイル/Rules ${stackCounts['flutter-firebase']} 件・認可/TLS 境界`
          : '対象ファイル未検出（待機中）',
    },
    {
      id: 'cloud-runtime',
      label: 'Python / Go / Cloud Run',
      zone: 'application',
      stack: 'python-go-cloud',
      status: computeStatus('python-go-cloud'),
      findingCount: countByStack('python-go-cloud'),
      summary:
        stackCounts['python-go-cloud'] > 0
          ? `バックエンド/Infra ${stackCounts['python-go-cloud']} 件・コンテナ/IAM 境界`
          : 'Node ランタイム統合境界',
    },
    {
      id: 'secrets-supply',
      label: 'Secrets & Supply Chain',
      zone: 'infra',
      stack: 'supply-chain-secrets',
      status: computeStatus('supply-chain-secrets'),
      findingCount: countByStack('supply-chain-secrets'),
      summary: `機密管理・CI/Lockfile 境界（検出指摘 ${countByStack('supply-chain-secrets')} 件）`,
    },
  ];

  const edges: TrustBoundaryEdge[] = [
    {
      from: 'edge-client',
      to: 'mobile-rules',
      protocol: 'HTTPS / Auth Token / CSP',
      riskLevel: countByStack('ts-web-api', 'high') > 0 ? 'high' : 'low',
    },
    {
      from: 'mobile-rules',
      to: 'cloud-runtime',
      protocol: 'IAM / AppCheck / TLS 1.3',
      riskLevel:
        countByStack('flutter-firebase', 'high') > 0 || countByStack('python-go-cloud', 'high') > 0
          ? 'high'
          : 'low',
    },
    {
      from: 'cloud-runtime',
      to: 'secrets-supply',
      protocol: 'Secret Manager / Lockfile SHA',
      riskLevel: countByStack('supply-chain-secrets', 'high') > 0 ? 'high' : 'low',
    },
  ];

  return { nodes, edges };
}

const SAFE_MANIFEST_PATH_RE = /^(?!.*\.\.)(?!\/)[A-Za-z0-9._/-]{1,140}$/;

/**
 * Builds an outbound Gemini digest containing ZERO bytes of file source code or snippets.
 * Only structural telemetry, rule IDs, CWEs, and safe allowlisted relative paths are emitted.
 */
function buildStructuralZeroSnippetDigest(params: {
  repoName: string;
  scannedFiles: number;
  scanTruncated: boolean;
  stackFileCounts: Record<StackDomain, number>;
  controlsRecord: Record<StackDomain, string[]>;
  findings: SecurityFinding[];
  manifestPaths: readonly string[];
}): string {
  const safeRepoLabel = params.repoName.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 64) || 'repository';
  const safeSamplePaths = params.manifestPaths
    .filter((p) => SAFE_MANIFEST_PATH_RE.test(p))
    .map((p) => redactSecrets(p).redactedText)
    .filter((p) => !p.includes('[REDACTED'))
    .slice(0, 24);

  const structuralFindings = params.findings.slice(0, 20).map((f) => {
    const safePath =
      SAFE_MANIFEST_PATH_RE.test(f.filePath) && !redactSecrets(f.filePath).redactedText.includes('[REDACTED')
        ? f.filePath
        : `boundary/${f.stack}`;
    return `- rule=${f.ruleId} severity=${f.severity} stack=${f.stack} stride=${f.stride} cwe=${f.cwe} file=${safePath}:${f.line}`;
  });

  const lines: string[] = [
    `RepositoryLabel: ${safeRepoLabel}`,
    `ScannedFiles: ${params.scannedFiles}`,
    `ScanTruncated: ${params.scanTruncated}`,
    `StackFiles: ts-web-api=${params.stackFileCounts['ts-web-api']}, flutter-firebase=${params.stackFileCounts['flutter-firebase']}, python-go-cloud=${params.stackFileCounts['python-go-cloud']}, supply-chain-secrets=${params.stackFileCounts['supply-chain-secrets']}`,
    `VerifiedControls: ${JSON.stringify(params.controlsRecord)}`,
    `AllowedRepositoryPaths: ${JSON.stringify(safeSamplePaths)}`,
    `StaticFindingCount: ${params.findings.length}`,
    'StaticRuleTelemetry (Zero Source Snippets):',
    ...structuralFindings,
  ];
  return redactSecrets(lines.join('\n')).redactedText.slice(0, 4000);
}

export function buildStackSummaries(scan: StaticScanResult): StackPostureSummary[] {
  const definitions: Array<{ stack: StackDomain; label: string }> = [
    { stack: 'ts-web-api', label: 'TypeScript / Next.js / Node' },
    { stack: 'flutter-firebase', label: 'Flutter / Dart + Firebase' },
    { stack: 'python-go-cloud', label: 'Python / Go / Cloud Run' },
    { stack: 'supply-chain-secrets', label: 'Secrets & Supply Chain' },
  ];

  return definitions.map(({ stack, label }) => {
    const stackFindings = scan.findings.filter((f) => f.stack === stack);
    const criticalCount = stackFindings.filter((f) => f.severity === 'critical').length;
    const highCount = stackFindings.filter((f) => f.severity === 'high').length;
    const mediumCount = stackFindings.filter((f) => f.severity === 'medium').length;
    const lowCount = stackFindings.filter((f) => f.severity === 'low').length;

    const penalty = criticalCount * 28 + highCount * 16 + mediumCount * 8 + lowCount * 3;
    const bonus = Math.min(8, (scan.verifiedControlsByStack[stack]?.length ?? 0) * 2);
    const defenseScore = Math.max(0, Math.min(100, 100 - penalty + (penalty > 0 ? bonus : 0)));

    return {
      stack,
      label,
      detectedFiles: scan.stackFileCounts[stack],
      defenseScore,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      verifiedControls: scan.verifiedControlsByStack[stack] ?? [],
    };
  });
}
