import fsSync, { constants as fsConstants, type Dirent, type Stats } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { redactSecrets, redactSecretsPreserveLines } from './redactor.ts';
import { classifyFileStack, evaluateFileRules, type FileContext } from './rules.ts';
import type {
  EngineeringArchetypeId,
  EngineeringCraftProfile,
  SecurityFinding,
  StackDomain,
  StackPostureSummary,
  TrustBoundaryEdge,
  TrustBoundaryNode,
  UntestableCodeHotspot,
} from './types.ts';

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
  '.agents',
  '.worktrees',
  'ai',
  'node_modules',
  '.pnpm-store',
  '.yarn',
  'dist',
  'build',
  '_build',
  'out',
  '.build',
  'DerivedData',
  '.next',
  '.svelte-kit',
  '.output',
  '.nuxt',
  '.astro',
  '.vercel',
  '.firebase',
  '.terraform',
  '.wrangler',
  '.parcel-cache',
  '.cache',
  '.dart_tool',
  '.fvm',
  '.symlinks',
  '.plugin_symlinks',
  '.pub-cache',
  'ephemeral',
  '.gradle',
  'Pods',
  'target',
  '__pycache__',
  '.pytest_cache',
  '.mypy_cache',
  '.ruff_cache',
  '.venv',
  'venv',
  'coverage',
  '.turbo',
]);

const KNOWN_MEDIA_ARCHIVE_EXTS = new Set([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.webp',
  '.avif',
  '.ico',
  '.icns',
  '.woff',
  '.woff2',
  '.ttf',
  '.otf',
  '.eot',
  '.mp3',
  '.mp4',
  '.wav',
  '.ogg',
  '.webm',
  '.mov',
  '.pdf',
  '.wasm',
  '.zip',
  '.gz',
  '.tar',
  '.tgz',
  '.aab',
  '.apk',
  '.ipa',
  '.diff',
  '.patch',
  '.log',
  '.svg',
  '.map',
  '.sql',
  '.csv',
]);

const KEYSTORE_BINARY_EXTS = new Set(['.jks', '.keystore', '.p12', '.pfx']);

const INITIAL_CWD = process.cwd();
const __scannerDirname = path.dirname(fileURLToPath(import.meta.url));
const LONGINUS_PROJECT_ROOT = fsSync.realpathSync(
  path.resolve(
    __scannerDirname,
    __scannerDirname.includes(`${path.sep}dist${path.sep}`) ? '../../..' : '../..',
  ),
);

const DEFAULT_MAX_FILE_BYTES = 4 * 1024 * 1024; // 4 MB per file
const DEFAULT_MAX_OPENED_FILES = 10000; // Includes binary & text open attempts
const DEFAULT_MAX_INSPECTED_ENTRIES = 25000; // Total directory/file entries visited
const DEFAULT_MAX_TOTAL_BYTES = 128 * 1024 * 1024; // 128 MB cumulative read cap
const DEFAULT_MAX_DIRECTORY_DEPTH = 48; // Bounds recursion depth while keeping O(1) open FDs

function buildRootGitignoreMatcher(gitignoreContent: string): (relPath: string, baseName: string) => boolean {
  const regexes: RegExp[] = [];
  for (const rawLine of gitignoreContent.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith('!')) continue;
    let pat = line.replace(/\/+$/, '');
    if (!pat) continue;
    const anchored = pat.startsWith('/');
    if (anchored) pat = pat.slice(1);
    if (pat.startsWith('**/')) pat = pat.slice(3);
    const escaped = pat
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*\*\//g, '(?:.+/)?')
      .replace(/\*\*/g, '.*')
      .replace(/\*/g, '[^/]*')
      .replace(/\?/g, '[^/]');
    const prefix = anchored || pat.includes('/') ? '^(?:.+/)?' : '(?:^|/)';
    try {
      regexes.push(new RegExp(`${prefix}${escaped}(?:/|$)`));
    } catch {
      // Ignore malformed pattern
    }
  }
  return (relPath: string, baseName: string) => {
    if (baseName === '.gitignore') return false;
    return regexes.some((re) => re.test(relPath) || re.test(baseName));
  };
}

export interface ExpectedRootIdentity {
  dev: number;
  ino: number;
  parentDev: number;
  parentIno: number;
}

export interface ScanOptions {
  excludeRelativePrefixes?: string[];
  maxFileBytes?: number;
  maxOpenedFiles?: number;
  maxInspectedEntries?: number;
  maxTotalBytes?: number;
  maxDirectoryDepth?: number;
  expectedRootIdentity?: ExpectedRootIdentity;
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
  craftProfile: EngineeringCraftProfile;
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
  | { status: 'oversize'; bytesRead: number }
  | { status: 'read_error'; bytesRead: number }
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
      return { status: 'oversize', bytesRead: 0 };
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
      return { status: 'oversize', bytesRead: bytesReadSoFar };
    }

    return {
      status: 'ok',
      buffer: buf.subarray(0, bytesReadSoFar),
      bytesRead: bytesReadSoFar,
    };
  } catch {
    return { status: 'read_error', bytesRead: bytesReadSoFar };
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
  } catch (err) {
    const errCode =
      typeof err === 'object' && err !== null && 'code' in err
        ? String((err as { code?: unknown }).code)
        : '';
    if (
      errCode === 'ELOOP' ||
      errCode === 'ENOENT' ||
      errCode === 'EISDIR' ||
      errCode === 'ENXIO' ||
      errCode === 'EOPNOTSUPP'
    ) {
      return { status: 'skipped', bytesRead: 0 };
    }
    return { status: 'read_error', bytesRead: 0 };
  } finally {
    if (fh) {
      await fh.close().catch(() => undefined);
    }
  }
}

export interface PinnedSafeDirectory {
  canonicalRoot: string;
  handle: fs.FileHandle;
  stat: Stats;
}

/**
 * Validates, canonicalizes, and returns an ALREADY-PINNED O_RDONLY | O_DIRECTORY | O_NOFOLLOW
 * file handle with verified `(dev, ino)` continuity so zero close-then-reopen TOCTOU gap exists.
 */
export async function openPinnedSafeTargetDirectory(
  rawTargetPath: string,
): Promise<PinnedSafeDirectory> {
  if (typeof rawTargetPath !== 'string' || !rawTargetPath.trim() || rawTargetPath.includes('\0')) {
    throw new SafeClientError('無効な監査対象パスです。');
  }
  const { oNoFollow, oDirectory } = assertPosixNoFollowFlags();
  const resolved = path.resolve(INITIAL_CWD, rawTargetPath.trim());

  let lstatResolved: Stats;
  try {
    lstatResolved = await fs.lstat(resolved);
  } catch {
    throw new SafeClientError('監査対象パスが存在しないかアクセスできません。');
  }
  if (!lstatResolved.isDirectory() || lstatResolved.isSymbolicLink()) {
    throw new SafeClientError('監査対象パスはローカルディレクトリである必要があります。');
  }

  let resolvedFh: fs.FileHandle | undefined;
  let canonicalFh: fs.FileHandle | undefined;
  let handedOff = false;
  try {
    try {
      resolvedFh = await fs.open(resolved, fsConstants.O_RDONLY | oDirectory | oNoFollow);
    } catch {
      throw new SafeClientError('監査対象パスはローカルディレクトリである必要があります。');
    }
    const resolvedStat = await resolvedFh.stat();
    if (
      !resolvedStat.isDirectory() ||
      resolvedStat.dev !== lstatResolved.dev ||
      resolvedStat.ino !== lstatResolved.ino
    ) {
      throw new SafeClientError('監査対象パスはローカルディレクトリである必要があります。');
    }

    let canonical: string;
    try {
      canonical = await fs.realpath(resolved);
    } catch {
      throw new SafeClientError('監査対象パスが存在しないかアクセスできません。');
    }

    try {
      canonicalFh = await fs.open(canonical, fsConstants.O_RDONLY | oDirectory | oNoFollow);
    } catch {
      throw new SafeClientError('監査対象パスはローカルディレクトリである必要があります。');
    }
    const canonicalStat = await canonicalFh.stat();
    if (
      !canonicalStat.isDirectory() ||
      canonicalStat.dev !== resolvedStat.dev ||
      canonicalStat.ino !== resolvedStat.ino
    ) {
      throw new SafeClientError('監査対象パスはローカルディレクトリである必要があります。');
    }
    handedOff = true;
    return { canonicalRoot: canonical, handle: canonicalFh, stat: canonicalStat };
  } finally {
    if (!handedOff && canonicalFh) {
      await canonicalFh.close().catch(() => undefined);
    }
    if (resolvedFh) {
      await resolvedFh.close().catch(() => undefined);
    }
  }
}

/**
 * Safely validates and canonicalizes a local directory path.
 * Strictly read-only; rejects NUL bytes, non-existent paths, leaf symlinks, and non-directories.
 */
export async function resolveSafeTargetDirectory(rawTargetPath: string): Promise<string> {
  const pinned = await openPinnedSafeTargetDirectory(rawTargetPath);
  await pinned.handle.close().catch(() => undefined);
  return pinned.canonicalRoot;
}

export async function runStaticRepositoryScan(
  targetPath: string,
  options?: ScanOptions,
): Promise<StaticScanResult> {
  return withScanMutex(async () => {
    const { oNoFollow, oDirectory, oNonBlock } = assertPosixNoFollowFlags();
    const excludePrefixes = options?.excludeRelativePrefixes ?? [];
    const maxFileBytes = options?.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
    const maxOpenedFiles = options?.maxOpenedFiles ?? DEFAULT_MAX_OPENED_FILES;
    const maxInspectedEntries = options?.maxInspectedEntries ?? DEFAULT_MAX_INSPECTED_ENTRIES;
    const maxTotalBytes = options?.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES;
    const maxDirectoryDepth = options?.maxDirectoryDepth ?? DEFAULT_MAX_DIRECTORY_DEPTH;

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
    const untestableHotspots: UntestableCodeHotspot[] = [];
    let productionCodeFiles = 0;
    let testFiles = 0;
    let algorithmicSignalCount = 0;
    let coupledIoInAlgorithmicFiles = 0;
    let uninjectedNonDeterminismFiles = 0;
    let oversizedGodModules = 0;
    const rawGodModuleCandidates: Array<{ filePath: string; lineCount: number; branchCount: number }> = [];

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
    let canonicalRoot = '';
    let repoName = 'repository';

    try {
      // Continuously hold the exact FD verified during realpath resolution (zero reopen gap)
      const pinnedRoot = await openPinnedSafeTargetDirectory(targetPath);
      canonicalRoot = pinnedRoot.canonicalRoot;
      repoName = path.basename(canonicalRoot);
      rootDirFh = pinnedRoot.handle;
      const rootStat = pinnedRoot.stat;
      const isLonginusSelfRoot = canonicalRoot === LONGINUS_PROJECT_ROOT;
      if (isLonginusSelfRoot && excludePrefixes.includes('test') && !excludePrefixes.includes('fixtures')) {
        excludePrefixes.push('fixtures');
      }

      process.chdir(canonicalRoot);
      const rootDot = await fs.lstat('.');
      if (rootDot.dev !== rootStat.dev || rootDot.ino !== rootStat.ino) {
        markTruncated('対象ルートディレクトリの境界検証で競合を検出したため安全停止しました。');
        throw new DirectoryRaceAbortError();
      }

      if (options?.expectedRootIdentity) {
        const exp = options.expectedRootIdentity;
        const parentDotDot = await fs.lstat('..').catch(() => null);
        if (
          rootStat.dev !== exp.dev ||
          rootStat.ino !== exp.ino ||
          !parentDotDot ||
          parentDotDot.dev !== exp.parentDev ||
          parentDotDot.ino !== exp.parentIno
        ) {
          throw new SafeClientError('監査対象ディレクトリの境界検証で競合を検出しました。');
        }
      }

      const ancestorInodes = new Set<string>([`${rootStat.dev}:${rootStat.ino}`]);
      let isIgnoredByGitignore: (relPath: string, baseName: string) => boolean = () => false;
      try {
        const gitignoreStat = await fs.lstat('.gitignore');
        if (gitignoreStat.isFile() && !gitignoreStat.isSymbolicLink() && gitignoreStat.size <= 65536) {
          const gitignoreRaw = await fs.readFile('.gitignore', 'utf8');
          isIgnoredByGitignore = buildRootGitignoreMatcher(gitignoreRaw);
        }
      } catch {
        // No root .gitignore present
      }

      const walkPinnedDir = async (
        relDirPrefix: string,
        currentDirStat: Stats,
        depth: number,
        parentGitignoreMatcher: (relPath: string, baseName: string) => boolean,
      ): Promise<void> => {
        if (abortAllWork) return;

        // Stream directory entries from '.' (pinned AT_FDCWD) bounded strictly by maxInspectedEntries
        const batch: Dirent[] = [];
        let dirHandle;
        try {
          dirHandle = await fs.opendir('.');
        } catch {
          markTruncated('一部ディレクトリの読取権限またはFD上限により部分監査となりました。');
          return;
        }

        try {
          for await (const dirent of dirHandle) {
            if (inspectedEntries >= maxInspectedEntries) {
              markTruncated(
                `走査エントリ上限 (${maxInspectedEntries} 件) に達したため部分監査となりました。`,
              );
              abortAllWork = true;
              break;
            }
            inspectedEntries += 1;
            batch.push(dirent);
          }
        } finally {
          await dirHandle.close().catch(() => undefined);
        }

        batch.sort((a, b) => a.name.localeCompare(b.name));

        let activeGitignoreMatcher = parentGitignoreMatcher;
        if (
          relDirPrefix !== '' &&
          batch.some((e) => e.name === '.gitignore' && e.isFile() && !e.isSymbolicLink())
        ) {
          try {
            const subStat = await fs.lstat('.gitignore');
            if (subStat.isFile() && !subStat.isSymbolicLink() && subStat.size <= 65536) {
              const subRaw = await fs.readFile('.gitignore', 'utf8');
              const subMatcher = buildRootGitignoreMatcher(subRaw);
              activeGitignoreMatcher = (relPath: string, baseName: string) => {
                if (parentGitignoreMatcher(relPath, baseName)) return true;
                const subRel = relPath.startsWith(`${relDirPrefix}/`)
                  ? relPath.slice(relDirPrefix.length + 1)
                  : relPath;
                return subMatcher(subRel, baseName);
              };
            }
          } catch {
            // Ignore unreadable nested .gitignore
          }
        }

        for (const entry of batch) {
          if (abortAllWork) break;
          if (!isSinglePathComponent(entry.name)) continue;
          if (entry.isSymbolicLink()) continue;

          const relPath = relDirPrefix ? `${relDirPrefix}/${entry.name}` : entry.name;
          if (
            entry.isDirectory() &&
            /^(?:test|tests|__tests__|spec|integration_test)$/i.test(entry.name) &&
            excludePrefixes.some(
              (prefix) => relPath === prefix || relPath.startsWith(`${prefix}/`),
            )
          ) {
            testFiles += 4;
          }
          if (
            excludePrefixes.some(
              (prefix) => relPath === prefix || relPath.startsWith(`${prefix}/`),
            ) ||
            activeGitignoreMatcher(relPath, entry.name)
          ) {
            continue;
          }

          if (entry.isDirectory()) {
            if (IGNORED_DIRS.has(entry.name)) continue;
            if (depth + 1 > maxDirectoryDepth) {
              markTruncated(
                `ディレクトリ階層上限 (${maxDirectoryDepth} 階層) に達したため部分監査となりました。`,
              );
              continue;
            }

            // Step into child directory via serialized single-component process.chdir under withScanMutex
            // paired with O_NOFOLLOW + immediate lstat('.') / lstat('..') (dev, ino) verification
            // (Node.js standard fs does not expose POSIX fchdir(fd); close childFh after verification so FDs stay O(1)).
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

              await childFh.close().catch(() => undefined);
              childFh = undefined;

              ancestorInodes.add(inodeKey);
              try {
                await walkPinnedDir(relPath, childStat, depth + 1, activeGitignoreMatcher);
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
              const errCode =
                typeof err === 'object' && err !== null && 'code' in err
                  ? String((err as { code?: unknown }).code)
                  : '';
              if (errCode !== 'ELOOP' && errCode !== 'ENOTDIR' && errCode !== 'ENOENT') {
                markTruncated('一部サブディレクトリへのアクセス制限により部分監査となりました。');
              }
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
          const safeRelPath = redactSecrets(relPath).redactedText;
          manifestSet.add(safeRelPath);

          const entryExt = path.extname(entry.name).toLowerCase();
          if (
            KNOWN_MEDIA_ARCHIVE_EXTS.has(entryExt) ||
            KEYSTORE_BINARY_EXTS.has(entryExt) ||
            entryExt === '.lock' ||
            entry.name === 'package-lock.json' ||
            entry.name === 'pnpm-lock.yaml'
          ) {
            continue;
          }

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

          // Account for ALL bytes read regardless of ok / skipped / oversize / read_error / budget_exceeded
          totalBytesRead += readRes.bytesRead;

          if (readRes.status === 'budget_exceeded' || totalBytesRead > maxTotalBytes) {
            markTruncated(
              `累積読取バイト予算 (${formatByteBudgetLabel(maxTotalBytes)}) に達したため部分監査となりました。`,
            );
            abortAllWork = true;
            break;
          }
          if (readRes.status === 'oversize') {
            if (options?.maxFileBytes !== undefined) {
              markTruncated(
                `単一ファイルサイズ上限 (${formatByteBudgetLabel(maxFileBytes)}) を超えるファイルが存在したため部分監査となりました。`,
              );
            }
            continue;
          }
          if (readRes.status === 'read_error') {
            markTruncated('一部ファイルの読取権限またはFD上限により部分監査となりました。');
            continue;
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
          const stack = classifyFileStack(safeRelPath);
          stackFileCounts[stack] += 1;

          const isEnvFile = entry.name === '.env' || entry.name.startsWith('.env.');
          const redaction = redactSecretsPreserveLines(rawContent, { isEnvFile, ext: entryExt });
          const isLonginusSelfPatternFile =
            isLonginusSelfRoot &&
            (safeRelPath === 'src/redactor.ts' ||
              safeRelPath === 'src/rules.ts' ||
              safeRelPath === 'src/shield/redactor.ts' ||
              safeRelPath === 'src/shield/rules.ts' ||
              safeRelPath === 'src/airlock/sanitizer.ts');
          if (!isLonginusSelfPatternFile) {
            redactedSecretsCount += redaction.redactionCount;
          }
          if (safeRelPath === 'package.json') {
            try {
              const pkgParsed = JSON.parse(rawContent) as {
                dependencies?: Record<string, unknown>;
                devDependencies?: Record<string, unknown>;
              };
              const depCount = Object.keys(pkgParsed.dependencies ?? {}).length;
              const devDepCount = Object.keys(pkgParsed.devDependencies ?? {}).length;
              if (depCount === 0 && devDepCount === 0 && ('dependencies' in pkgParsed || 'devDependencies' in pkgParsed)) {
                verifiedControlsByStack['supply-chain-secrets'].add('Deterministic Node Lockfile Present');
              }
            } catch {
              // Ignore malformed package.json
            }
          }

          // Evaluate positive controls & static rules strictly on full-file-redacted text
          detectVerifiedControls(safeRelPath, redaction.redactedText, verifiedControlsByStack);

          const ctx: FileContext = {
            relativePath: safeRelPath,
            baseName: redactSecrets(entry.name).redactedText,
            ext: entryExt,
            redactedContent: redaction.redactedText,
            redactedLines: redaction.redactedLines,
            redactedLineNumbers: redaction.redactedLineNumbers,
            ...(isLonginusSelfPatternFile ? { skipSelfPatternDefinitions: true } : {}),
          };

          const fileFindings = evaluateFileRules(ctx);
          findings.push(...fileFindings);

          evaluateEngineeringCraftSignals({
            ctx,
            onTestFile: () => {
              testFiles += 1;
            },
            onProductionFile: (signals) => {
              productionCodeFiles += 1;
              algorithmicSignalCount += signals.algoSignals;
              if (signals.coupledIoInAlgo) coupledIoInAlgorithmicFiles += 1;
              if (signals.uninjectedNonDeterminism) uninjectedNonDeterminismFiles += 1;
              if (signals.godModuleCandidate) {
                rawGodModuleCandidates.push(signals.godModuleCandidate);
              }
              untestableHotspots.push(...signals.hotspots);
            },
          });
        }
      };

      await walkPinnedDir('', rootStat, 0, isIgnoredByGitignore);
    } catch (err) {
      if (!(err instanceof DirectoryRaceAbortError)) {
        throw err;
      }
    } finally {
      try {
        process.chdir(savedCwd);
      } catch {
        try {
          process.chdir(INITIAL_CWD);
        } catch {
          // Ignore if fallback cwd is also unavailable
        }
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

    if (testFiles === 0 && rawGodModuleCandidates.length > 0) {
      for (const candidate of rawGodModuleCandidates) {
        oversizedGodModules += 1;
        untestableHotspots.push({
          ruleId: 'LNG-CRAFT-003',
          title: 'High-Complexity Untested God-Module (>500 LOC without test harness)',
          filePath: candidate.filePath,
          line: 1,
          asymmetrySignal: `Module spans ${candidate.lineCount} lines and ${candidate.branchCount} branches with 0 test files in the repository.`,
          refactoringPatch:
            'Split monolithic control flow into pure domain functions and add table-driven unit tests.',
        });
      }
    }

    const craftProfile = buildEngineeringCraftProfile({
      productionCodeFiles,
      testFiles,
      algorithmicSignalCount,
      coupledIoInAlgorithmicFiles,
      uninjectedNonDeterminismFiles,
      oversizedGodModules,
      untestableHotspots,
      findings,
      verifiedControlsByStack: controlsRecord,
      stackFileCounts,
    });

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
      canonicalRoot: redactSecrets(canonicalRoot).redactedText,
      repoName: redactSecrets(repoName).redactedText,
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
      craftProfile,
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
  } else if (
    hasPkgJson &&
    !hasNodeLock &&
    !supplyChainControls.has('Deterministic Node Lockfile Present') &&
    !scanTruncated
  ) {
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

  if (
    (manifests.has('pubspec.yaml') && manifests.has('pubspec.lock')) ||
    (manifests.has('go.mod') && manifests.has('go.sum')) ||
    (manifests.has('pyproject.toml') && (manifests.has('uv.lock') || manifests.has('poetry.lock')))
  ) {
    supplyChainControls.add('Deterministic Language Lockfile Present');
  }

  for (const relPath of manifests) {
    const ext = path.extname(relPath).toLowerCase();
    const base = path.basename(relPath);
    if (
      KEYSTORE_BINARY_EXTS.has(ext) ||
      base === 'serviceAccountKey.json' ||
      /-firebase-adminsdk-[a-z0-9-]+\.json$/i.test(base)
    ) {
      const safeRel = redactSecrets(relPath).redactedText;
      findings.push({
        id: `LNG-SEC-005:${safeRel}:1`,
        ruleId: 'LNG-SEC-005',
        title: 'リポジトリ内に配置された署名鍵ストアまたはサービスアカウント鍵ファイル',
        stack: 'supply-chain-secrets',
        severity: 'critical',
        stride: 'Information Disclosure',
        cwe: 'CWE-522',
        owaspAsvs: 'V2.10.4 Keystore & Service Account Key Segregation',
        filePath: safeRel,
        line: 1,
        snippetRedacted: `[REDACTED_KEYSTORE_ARTIFACT: ${redactSecrets(base).redactedText}]`,
        rootCause:
          'モバイル署名用キーストア（.jks / .keystore / .p12）や Firebase Admin 秘密鍵 JSON がワークツリー内に存在すると、誤コミットやバックアップ経由で署名偽造・管理者権限奪取に直結します。',
        defensivePatch: `# 防御パッチ: キーストア・サービスアカウント鍵をリポジトリ外へ即時退避し Workload Identity / CI Secret 注入へ移行
# .gitignore に *.jks, *.keystore, *.p12, *.pfx, *firebase-adminsdk*.json を追加`,
        verificationHint:
          'git ls-files およびワークツリー内に .jks / .keystore / .p12 / サービスアカウント JSON が存在しないことを確認。',
        source: 'static-rule',
      });
    }
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
  const redactedRepoName = redactSecrets(params.repoName).redactedText;
  const safeRepoLabel =
    redactedRepoName.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 64) || 'repository';
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

const CODE_FILE_EXT_RE = /\.(?:ts|tsx|js|jsx|mjs|cjs|dart|py|go|rs|ex|exs|java|kt|swift)$/i;
const TEST_FILE_PATH_RE =
  /(?:^|\/)(?:test|tests|__tests__|spec|integration_test)\//i;
const TEST_FILE_NAME_RE =
  /(?:\.(?:test|spec)\.[a-z0-9]+|_test\.(?:dart|go|py|rs|exs))$/i;

const ALGORITHMIC_SIGNAL_RE =
  /\b(?:createHmac|createCipheriv|createDecipheriv|createSign|createVerify|timingSafeEqual|scrypt|pbkdf2|argon2|XEdDSA|DoubleRatchet|libsignal|Fernet|ECDSA|Uint8Array|BigInt|PriorityQueue|dijkstra|bfs|dfs|merkle|bloomFilter|binarySearch|topological|adjacency|findAttackPaths|walkPinnedDir|DoD\s*5220)\b|(?:<<|>>)\s*\d+/g;

const DIRECT_IO_SIDE_EFFECT_RE =
  /\b(?:fetch\s*\(|axios\.(?:get|post|put|delete)\s*\(|fs\.(?:writeFileSync|appendFileSync|unlinkSync)\s*\(|child_process\.(?:execSync|exec)\s*\(|FirebaseFirestore\.instance|http\.(?:get|post)\s*\()/;

const NON_DETERMINISTIC_STATE_RE =
  /\b(?:Date\.now\s*\(\)|Math\.random\s*\(\))/;

const GLOBAL_MUTABLE_SINGLETON_RE =
  /\b(?:globalThis|window)(?:\s+as\s+[^)]+\))?(?:\.[A-Za-z0-9_$]+|\[[^\]]+\])\s*=[^=]/;

const DI_SEAM_RE =
  /\b(?:CliIoHooks|io\??\s*:|deps\??\s*:|clock\??\s*:|now\??\s*:|options\??\s*:|inject|Provider\b|Repository\b)/;

function evaluateEngineeringCraftSignals(params: {
  ctx: FileContext;
  onTestFile: () => void;
  onProductionFile: (signals: {
    algoSignals: number;
    coupledIoInAlgo: boolean;
    uninjectedNonDeterminism: boolean;
    godModuleCandidate?: { filePath: string; lineCount: number; branchCount: number };
    hotspots: UntestableCodeHotspot[];
  }) => void;
}): void {
  const { ctx } = params;
  if (ctx.skipSelfPatternDefinitions) return;
  if (!CODE_FILE_EXT_RE.test(ctx.relativePath) || ctx.relativePath.endsWith('.d.ts')) {
    return;
  }

  if (TEST_FILE_PATH_RE.test(ctx.relativePath) || TEST_FILE_NAME_RE.test(ctx.baseName)) {
    params.onTestFile();
    return;
  }

  const algoMatches = ctx.redactedContent.match(ALGORITHMIC_SIGNAL_RE) ?? [];
  const algoSignals = algoMatches.length;
  const hasDiSeam = DI_SEAM_RE.test(ctx.redactedContent);
  const isEntrypoint = /^(?:cli|server|main|index)\.[a-z0-9]+$/i.test(ctx.baseName);

  const hotspots: UntestableCodeHotspot[] = [];
  let coupledIoLine = 0;
  let nonDetLine = 0;
  let globalMutationLine = 0;
  let branchCount = 0;

  for (let i = 0; i < ctx.redactedLines.length; i++) {
    const line = ctx.redactedLines[i] ?? '';
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) {
      continue;
    }
    if (/\b(?:if|switch|for|while|catch)\s*\(/.test(trimmed)) {
      branchCount += 1;
    }
    if (coupledIoLine === 0 && DIRECT_IO_SIDE_EFFECT_RE.test(trimmed)) {
      coupledIoLine = i + 1;
    }
    if (nonDetLine === 0 && NON_DETERMINISTIC_STATE_RE.test(trimmed)) {
      nonDetLine = i + 1;
    }
    if (globalMutationLine === 0 && GLOBAL_MUTABLE_SINGLETON_RE.test(trimmed)) {
      globalMutationLine = i + 1;
    }
  }

  const coupledIoInAlgo =
    algoSignals >= 2 && coupledIoLine > 0 && nonDetLine > 0 && !hasDiSeam && !isEntrypoint;
  const uninjectedNonDeterminism = nonDetLine > 0 && !hasDiSeam && !isEntrypoint;

  if (coupledIoInAlgo) {
    hotspots.push({
      ruleId: 'LNG-CRAFT-001',
      title: 'Algorithmic Logic Tightly Coupled with Uninjected I/O & Non-Deterministic State',
      filePath: ctx.relativePath,
      line: coupledIoLine,
      asymmetrySignal: `High algorithmic/crypto density (${algoSignals} signals) mixed directly with uninjected external I/O (line ${coupledIoLine}) and wall-clock/PRNG state (line ${nonDetLine}).`,
      refactoringPatch:
        'Extract pure algorithmic core into `(input, deps: { now: () => number; io: ... }) => Result` and inject side-effect adapters at the boundary.',
    });
  }

  if (algoSignals >= 1 && globalMutationLine > 0 && !isEntrypoint) {
    hotspots.push({
      ruleId: 'LNG-CRAFT-002',
      title: 'Global Mutable Singleton / Hidden State Inside Algorithmic Module',
      filePath: ctx.relativePath,
      line: globalMutationLine,
      asymmetrySignal:
        'Algorithmic module mutates global singleton state (`globalThis`/`window`), preventing isolated parallel unit testing.',
      refactoringPatch:
        'Encapsulate state inside an explicit instance or immutable context passed via function arguments.',
    });
  }

  const godModuleCandidate =
    ctx.redactedLines.length > 500 && branchCount > 45 && !hasDiSeam
      ? { filePath: ctx.relativePath, lineCount: ctx.redactedLines.length, branchCount }
      : undefined;

  params.onProductionFile({
    algoSignals,
    coupledIoInAlgo,
    uninjectedNonDeterminism,
    ...(godModuleCandidate !== undefined ? { godModuleCandidate } : {}),
    hotspots,
  });
}

function buildEngineeringCraftProfile(params: {
  productionCodeFiles: number;
  testFiles: number;
  algorithmicSignalCount: number;
  coupledIoInAlgorithmicFiles: number;
  uninjectedNonDeterminismFiles: number;
  oversizedGodModules: number;
  untestableHotspots: UntestableCodeHotspot[];
  findings: SecurityFinding[];
  verifiedControlsByStack: Record<StackDomain, string[]>;
  stackFileCounts: Record<StackDomain, number>;
}): EngineeringCraftProfile {
  const prodCount = Math.max(1, params.productionCodeFiles);
  const ratio = Number((params.testFiles / prodCount).toFixed(2));

  const algorithmicDepthScore = Math.max(
    40,
    Math.min(100, 55 + params.algorithmicSignalCount * 4),
  );

  let testabilityScore = 100;
  if (params.productionCodeFiles > 0 && params.testFiles === 0) {
    testabilityScore -= 42;
  } else if (params.productionCodeFiles >= 4 && ratio < 0.15) {
    testabilityScore -= 18;
  }
  testabilityScore -= Math.min(36, params.coupledIoInAlgorithmicFiles * 20);
  testabilityScore -= Math.min(24, params.untestableHotspots.filter((h) => h.ruleId === 'LNG-CRAFT-002').length * 15);
  testabilityScore -= Math.min(24, params.oversizedGodModules * 15);
  testabilityScore = Math.max(0, Math.min(100, testabilityScore));

  let determinismScore = 100;
  if (params.findings.some((f) => f.ruleId === 'LNG-SEC-003' || f.ruleId === 'LNG-SEC-002')) {
    determinismScore -= 18;
  }
  if (params.findings.some((f) => f.ruleId === 'LNG-TS-004' || f.ruleId === 'LNG-PY-004')) {
    determinismScore -= 20;
  }
  determinismScore -= Math.min(36, params.uninjectedNonDeterminismFiles * 14);
  determinismScore = Math.max(0, Math.min(100, determinismScore));

  const criticalCount = params.findings.filter((f) => f.severity === 'critical').length;
  const highCount = params.findings.filter((f) => f.severity === 'high').length;
  const mediumCount = params.findings.filter((f) => f.severity === 'medium').length;
  const securityBoundaryScore = Math.max(
    0,
    Math.min(100, 100 - (criticalCount * 25 + highCount * 12 + mediumCount * 5)),
  );

  let archetypeId: EngineeringArchetypeId;
  let archetypeLabel: string;
  let diagnosisSummary: string;

  if (
    algorithmicDepthScore >= 70 &&
    (testabilityScore < 65 || params.coupledIoInAlgorithmicFiles > 0 || params.untestableHotspots.length > 0)
  ) {
    archetypeId = 'ALGORITHMIC_MONOLITH_UNTESTABLE';
    archetypeLabel = 'Good at Algorithms, Writes Untestable Code (Algorithmic Monolith)';
    diagnosisSummary =
      'Strong algorithmic/cryptographic implementation depth detected, but tight coupling to direct I/O, global mutable state, or non-deterministic clock/PRNG without dependency injection makes the core logic untestable in isolation.';
  } else if (
    algorithmicDepthScore >= 75 &&
    testabilityScore >= 80 &&
    determinismScore >= 80 &&
    securityBoundaryScore >= 85
  ) {
    archetypeId = 'SOVEREIGN_ARCHITECT';
    archetypeLabel = 'Sovereign Architect (High Algorithmic Craft × Deterministic Testability)';
    diagnosisSummary =
      'High algorithmic and cryptographic sophistication paired with clean dependency injection, deterministic resource bounds, and isolated unit test coverage.';
  } else if (testabilityScore >= 75 && securityBoundaryScore < 70) {
    archetypeId = 'WELL_TESTED_SURFACE_SHALLOW_CORE';
    archetypeLabel = 'Well-Tested Surface, Exposed Security/Trust Boundaries';
    diagnosisSummary =
      'Modular structure and unit test coverage are present, but critical trust boundaries (IAM, secrets, or injection sinks) remain exposed.';
  } else if (testabilityScore < 65) {
    archetypeId = 'FAST_PROTOTYPE_COUPLED';
    archetypeLabel = 'Rapid Prototype — Tight I/O Coupling & Missing Test Harness';
    diagnosisSummary =
      'Direct side-effect coupling and low automated test coverage indicate a rapid prototype requiring dependency injection and deterministic test harnesses.';
  } else {
    archetypeId = 'BALANCED_PRODUCTION_ENGINEER';
    archetypeLabel = 'Balanced Production Engineering';
    diagnosisSummary =
      'Balanced production codebase with decoupled modules, automated test coverage, and enforced security controls.';
  }

  return {
    archetypeId,
    archetypeLabel,
    diagnosisSummary,
    dimensions: {
      algorithmicDepthScore,
      testabilityScore,
      determinismScore,
      securityBoundaryScore,
    },
    metrics: {
      productionCodeFiles: params.productionCodeFiles,
      testFiles: params.testFiles,
      testToCodeRatio: ratio,
      algorithmicSignalCount: params.algorithmicSignalCount,
      coupledIoInAlgorithmicFiles: params.coupledIoInAlgorithmicFiles,
      uninjectedNonDeterminismFiles: params.uninjectedNonDeterminismFiles,
      oversizedGodModules: params.oversizedGodModules,
    },
    untestableHotspots: params.untestableHotspots.slice(0, 15),
  };
}
