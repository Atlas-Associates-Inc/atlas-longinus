import path from 'node:path';
import { parseFirebaseRules } from '../graph/firebase-rules-parser.ts';
import { PUBLIC_ENV_SECRET_RE, redactSecrets } from './redactor.ts';
import type { SecurityFinding, SeverityLevel, StackDomain, StrideCategory } from './types.ts';

export interface JsLocalImportEdge {
  importedIdentifiers: readonly string[];
  rawSpecifier: string;
  targetRelativePath?: string;
}

export interface JsModuleRecord {
  relativePath: string;
  redactedContent: string;
  redactedLines: readonly string[];
  localImports: JsLocalImportEdge[];
}

export interface RepoScanContext {
  jsModules: ReadonlyMap<string, JsModuleRecord>;
  publicHostingRewriteFunctions: ReadonlySet<string>;
  orphanDirectories: ReadonlySet<string>;
}

export interface FileContext {
  relativePath: string;
  baseName: string;
  ext: string;
  redactedContent: string;
  redactedLines: readonly string[];
  redactedLineNumbers: readonly number[];
  skipSelfPatternDefinitions?: boolean;
  repoContext?: RepoScanContext;
}

export interface StaticRuleMatch {
  line: number;
  snippet: string;
  severityOverride?: SeverityLevel;
  rootCauseOverride?: string;
  defensivePatchOverride?: string;
  orphanAsset?: boolean;
}

export interface StaticRule {
  ruleId: string;
  title: string;
  stack: StackDomain;
  severity: SeverityLevel;
  stride: StrideCategory;
  cwe: string;
  owaspAsvs: string;
  appliesTo: (ctx: FileContext) => boolean;
  evaluate: (ctx: FileContext) => StaticRuleMatch[];
  rootCause: string;
  defensivePatch: string;
  verificationHint: string;
}

const JS_TS_EXTS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs']);

function isNonProductionOrTemplateFile(ctx: FileContext): boolean {
  const rel = ctx.relativePath;
  const base = ctx.baseName;
  if (
    /\.(?:example|sample|template|dist)$/i.test(base) ||
    base.startsWith('.env.example') ||
    base.startsWith('.env.sample') ||
    base.startsWith('.env.template')
  ) {
    return true;
  }
  if (
    ctx.ext === '.md' ||
    ctx.ext === '.mdx' ||
    ctx.ext === '.txt' ||
    ctx.ext === '.arb' ||
    /^(?:ai|docs)\//i.test(rel) ||
    /(?:^|\/)(?:l10n|locales|i18n|messages|translations)\//i.test(rel) ||
    /(?:i18n|missing|site)-keys\.mjs$/i.test(base)
  ) {
    return true;
  }
  if (
    /(?:^|\/)(?:test|tests|__tests__|__mocks__)\//i.test(rel) ||
    /\.(?:test|spec)\.[a-z0-9]+$/i.test(base) ||
    /(?:^test_|_test|_spec)\.(?:dart|go|py|rs|ts|js|mjs|cjs|exs)$/i.test(base) ||
    /^test_[a-z0-9_]+\.[a-z0-9]+$/i.test(base) ||
    /(?:^|\/)config\/(?:dev|test)\.exs$/i.test(rel)
  ) {
    return true;
  }
  if (
    base === 'google-services.json' ||
    base === 'GoogleService-Info.plist' ||
    base === 'firebase_options.dart'
  ) {
    return true;
  }
  return false;
}

function isCommentOrRegexDef(trimmedLine: string): boolean {
  return (
    trimmedLine.startsWith('//') ||
    trimmedLine.startsWith('*') ||
    trimmedLine.startsWith('/*') ||
    trimmedLine.startsWith('regex:') ||
    trimmedLine.startsWith('pattern:')
  );
}

function sliceRedactedWindow(lines: readonly string[], zeroBasedIndex: number): string {
  const start = Math.max(0, zeroBasedIndex - 1);
  const end = Math.min(lines.length, zeroBasedIndex + 2);
  return lines.slice(start, end).join('\n');
}

type LinePredicateResult = boolean | Omit<StaticRuleMatch, 'line' | 'snippet'>;

function findMatchingLines(
  ctx: FileContext,
  matcher: (line: string, lineIndex: number, allLines: readonly string[]) => LinePredicateResult,
  maxPerFile = 3,
): StaticRuleMatch[] {
  const hits: StaticRuleMatch[] = [];
  for (let i = 0; i < ctx.redactedLines.length; i++) {
    const line = ctx.redactedLines[i] ?? '';
    const trimmed = line.trim();
    if (!trimmed || isCommentOrRegexDef(trimmed)) continue;
    const outcome = matcher(line, i, ctx.redactedLines);
    if (!outcome) continue;
    hits.push({
      line: i + 1,
      snippet: sliceRedactedWindow(ctx.redactedLines, i),
      ...(typeof outcome === 'object' ? outcome : {}),
    });
    if (hits.length >= maxPerFile) break;
  }
  return hits;
}

const REGEX_ESCAPE_RE = /[.*+?^${}()|[\]\\]/g;
function escapeRegExp(literal: string): string {
  return literal.replace(REGEX_ESCAPE_RE, '\\$&');
}

function extractIdentifiersFromBinding(binding: string): string[] {
  const out = new Set<string>();
  const cleaned = binding.replace(/\/\*[\s\S]*?\*\//g, ' ');
  for (const part of cleaned.split(',')) {
    const parts = part.split(/\s*(?:\bas\b|:)\s*/);
    for (const piece of parts) {
      const matches = piece.match(/[A-Za-z_$][A-Za-z0-9_$]*/g);
      if (!matches) continue;
      for (const tok of matches) {
        if (tok !== 'type' && tok !== 'default') {
          out.add(tok);
        }
      }
    }
  }
  return Array.from(out);
}

/**
 * Extracts relative CommonJS (`require('./...')`) and ESM (`import ... from './...'`)
 * edges from a single JS/TS file for 1-to-2 hop verification without loading external packages.
 */
export function parseLocalJsImports(redactedContent: string): JsLocalImportEdge[] {
  const stripped = redactedContent
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/^[ \t]*\/\/.*$/gm, '');
  const edges: JsLocalImportEdge[] = [];
  const seenKey = new Set<string>();

  const pushEdge = (rawSpecifier: string, ids: string[]): void => {
    if (!rawSpecifier.startsWith('./') && !rawSpecifier.startsWith('../')) return;
    const key = `${rawSpecifier}:${ids.join(',')}`;
    if (seenKey.has(key)) return;
    seenKey.add(key);
    edges.push({ importedIdentifiers: ids, rawSpecifier });
  };

  const cjsRe =
    /(?:(?:const|let|var)\s+(\{[^}]{1,600}\}|[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*)?require\s*\(\s*['"](\.\.?\/[^'"]+)['"]\s*\)/g;
  for (const m of stripped.matchAll(cjsRe)) {
    pushEdge(m[2] ?? '', m[1] ? extractIdentifiersFromBinding(m[1]) : []);
  }

  const esmRe =
    /\bimport\s+(?:(\{[^}]{1,600}\}|[A-Za-z0-9_$*,\s{}]{1,240}?)\s+from\s+)?['"](\.\.?\/[^'"]+)['"]/g;
  for (const m of stripped.matchAll(esmRe)) {
    pushEdge(m[2] ?? '', m[1] ? extractIdentifiersFromBinding(m[1]) : []);
  }

  const reExportRe = /\bexport\s+(?:\*|\{[^}]{1,600}\})\s+from\s+['"](\.\.?\/[^'"]+)['"]/g;
  for (const m of stripped.matchAll(reExportRe)) {
    pushEdge(m[1] ?? '', []);
  }

  const dynImportRe = /\bimport\s*\(\s*['"](\.\.?\/[^'"]+)['"]\s*\)/g;
  for (const m of stripped.matchAll(dynImportRe)) {
    pushEdge(m[1] ?? '', []);
  }

  return edges;
}

const JS_TS_RESOLVE_EXTS = ['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs'];

export function resolveRelativeModulePath(
  fromFilePath: string,
  specifier: string,
  knownPaths: ReadonlySet<string>,
): string | undefined {
  if (!specifier.startsWith('./') && !specifier.startsWith('../')) return undefined;
  const fromDir = path.posix.dirname(fromFilePath);
  const rawJoined = fromDir === '.' ? specifier : `${fromDir}/${specifier}`;
  const normalized = path.posix.normalize(rawJoined);
  if (normalized.startsWith('../') || normalized === '..') return undefined;

  if (knownPaths.has(normalized)) return normalized;
  const extMatch = normalized.match(/(\.(?:m|c)?js)$/i);
  if (extMatch) {
    const stem = normalized.slice(0, -extMatch[1].length);
    for (const tsExt of ['.ts', '.tsx', '.mts', '.cts']) {
      if (knownPaths.has(`${stem}${tsExt}`)) return `${stem}${tsExt}`;
    }
  }
  for (const ext of JS_TS_RESOLVE_EXTS) {
    if (knownPaths.has(`${normalized}${ext}`)) return `${normalized}${ext}`;
  }
  for (const ext of JS_TS_RESOLVE_EXTS) {
    if (knownPaths.has(`${normalized}/index${ext}`)) return `${normalized}/index${ext}`;
  }
  return undefined;
}

function hasWholeIdentifier(haystack: string, identifier: string): boolean {
  if (!identifier) return false;
  return new RegExp(`(?<![A-Za-z0-9_$])${escapeRegExp(identifier)}(?![A-Za-z0-9_$])`).test(haystack);
}

function stripJsCommentsSimple(text: string): string {
  return text.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/^[ \t]*\/\/.*$/gm, '');
}

function extractBalancedSlice(
  lines: readonly string[],
  startLineIdx: number,
  startCol: number,
  openChar: '(' | '{',
  closeChar: ')' | '}',
  maxLines = 180,
): string {
  let depth = 0;
  let started = false;
  let quote: string | null = null;
  const out: string[] = [];
  const limit = Math.min(lines.length, startLineIdx + maxLines);
  for (let i = startLineIdx; i < limit; i++) {
    const line = lines[i] ?? '';
    const colStart = i === startLineIdx ? startCol : 0;
    out.push(i === startLineIdx ? line.slice(colStart) : line);
    for (let j = colStart; j < line.length; j++) {
      const ch = line[j] ?? '';
      if (quote) {
        if (ch === '\\') {
          j += 1;
          continue;
        }
        if (ch === quote) quote = null;
        continue;
      }
      if (ch === '/' && line[j + 1] === '/') break;
      if (ch === '"' || ch === "'" || ch === '`') {
        quote = ch;
        continue;
      }
      if (ch === openChar) {
        depth += 1;
        started = true;
      } else if (ch === closeChar && started) {
        depth -= 1;
        if (depth <= 0) return out.join('\n');
      }
    }
  }
  return out.join('\n');
}

function extractLocalSymbolBody(lines: readonly string[], symbolName: string): string {
  const esc = escapeRegExp(symbolName);
  const fnRe = new RegExp(`(?:^|[;\\s])(?:async\\s+)?function\\s+${esc}\\s*\\(`);
  const varRe = new RegExp(`(?:(?:const|let|var)\\s+|exports\\.)${esc}\\s*=\\s*(?!onRequest\\b)`);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('*')) continue;
    if (fnRe.test(line)) {
      for (let k = i; k < Math.min(lines.length, i + 8); k++) {
        const braceCol = (lines[k] ?? '').indexOf('{');
        if (braceCol >= 0) {
          return extractBalancedSlice(lines, k, braceCol, '{', '}', 200);
        }
      }
    } else if (varRe.test(line)) {
      const eqCol = line.indexOf('=');
      if (eqCol < 0) continue;
      const afterEq = line.slice(eqCol + 1);
      const arrowIdx = afterEq.indexOf('=>');
      if (arrowIdx >= 0) {
        const restCol = eqCol + 1 + arrowIdx + 2;
        for (let k = i; k < Math.min(lines.length, i + 6); k++) {
          const braceCol = (lines[k] ?? '').indexOf('{', k === i ? restCol : 0);
          if (braceCol >= 0) {
            return extractBalancedSlice(lines, k, braceCol, '{', '}', 200);
          }
          if ((lines[k] ?? '').includes(';')) break;
        }
      }
      const parenCol = line.indexOf('(', eqCol + 1);
      if (parenCol >= 0) {
        return line.slice(eqCol + 1) + '\n' + extractBalancedSlice(lines, i, parenCol, '(', ')', 40);
      }
      return lines.slice(i, Math.min(lines.length, i + 10)).join('\n');
    }
  }
  return '';
}

const AUTH_OR_APPCHECK_PROOF_RE =
  /\b(?:verifyIdToken|verifySessionCookie|enforceAppCheck\s*:\s*true|appCheck\s*\(\s*\)\s*\.\s*verifyToken|verifyAppCheck|X-Firebase-AppCheck|timingSafeEqual|createHmac|createVerify|crypto\.verify(?=\s*\()|constructEvent|verifyWebhook|verifyAndDecodeAppleJws|stripe-signature|svix-signature|wellKnown|apple-app-site-association|assetlinks)\b/i;

const DB_OR_STORAGE_MUTATION_RE =
  /\b(?:collection|collectionGroup)\s*\([^)]*\)\s*\.\s*add\s*\(|\bdoc\s*\([^)]*\)\s*\.\s*(?:set|update|delete|create)\s*\(|\b(?:db|database|firestore)\s*\.\s*(?:runTransaction|batch)\s*\(|\b(?:tx|transaction|batch)\s*\.\s*(?:set|update|delete|create|commit)\s*\(|\b(?:bucket|storage)\b[\s\S]{0,80}?\.\s*(?:save|upload|delete|createWriteStream)\s*\(/i;

function extractImportedScopedText(
  mod: JsModuleRecord,
  importedIdentifiers: readonly string[],
): string {
  if (importedIdentifiers.length === 0) return mod.redactedContent;
  const parts: string[] = [];
  const seen = new Set<string>();
  const skip = new Set([
    'req', 'res', 'request', 'response', 'error', 'async', 'await', 'return',
    'const', 'let', 'var', 'function', 'if', 'else', 'try', 'catch', 'throw', 'new', 'true', 'false', 'null',
  ]);
  for (const id of importedIdentifiers) {
    if (seen.has(id)) continue;
    seen.add(id);
    const body = extractLocalSymbolBody(mod.redactedLines, id);
    if (body) parts.push(body);
  }
  if (parts.length === 0) return mod.redactedContent;
  const tokens = parts.join('\n').match(/\b[A-Za-z_$][A-Za-z0-9_$]{1,64}\b/g) ?? [];
  for (const tok of tokens) {
    if (skip.has(tok) || seen.has(tok)) continue;
    seen.add(tok);
    const body = extractLocalSymbolBody(mod.redactedLines, tok);
    if (body) parts.push(body);
  }
  return parts.join('\n');
}

function shouldPassOnRequest(
  ctx: FileContext,
  lineIdx: number,
  allLines: readonly string[],
): boolean {
  const headerSlice = allLines.slice(Math.max(0, lineIdx - 2), lineIdx + 1).join('\n');
  const exportMatch = headerSlice.match(
    /(?:exports\.|module\.exports\.|export\s+(?:const|let|var)\s+)([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:[^;{]*\s)?onRequest\s*\(/,
  );
  const constMatch =
    exportMatch ??
    headerSlice.match(/(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*onRequest\s*\(/);
  const exportedName = constMatch?.[1];

  const col = (allLines[lineIdx] ?? '').indexOf('onRequest');
  const callSlice = extractBalancedSlice(allLines, lineIdx, Math.max(0, col), '(', ')', 160);

  // Hop 0: follow local helper functions/factories referenced in this onRequest call (2 sub-hops)
  const localBodyParts: string[] = [callSlice];
  const resolvedLocalSymbols = new Set<string>();
  const skipTokens = new Set([
    'onRequest', 'req', 'res', 'request', 'response', 'error', 'async', 'await', 'return',
    'const', 'let', 'var', 'function', 'if', 'else', 'try', 'catch', 'throw', 'new', 'true', 'false', 'null',
    exportedName ?? '',
  ]);
  for (let hop0 = 0; hop0 < 2; hop0++) {
    const combined = localBodyParts.join('\n');
    const tokens = combined.match(/\b[A-Za-z_$][A-Za-z0-9_$]{1,64}\b/g) ?? [];
    for (const tok of tokens) {
      if (skipTokens.has(tok) || resolvedLocalSymbols.has(tok)) continue;
      resolvedLocalSymbols.add(tok);
      const body = extractLocalSymbolBody(allLines, tok);
      if (body) localBodyParts.push(body);
    }
  }
  const localReachableText = localBodyParts.join('\n');

  // Hop 1 & Hop 2: follow local relative imports from jsModules strictly up to 2 hops
  const importedContents: string[] = [];
  const scopedImportedContents: string[] = [];
  const jsModules = ctx.repoContext?.jsModules;
  const selfRecord = jsModules?.get(ctx.relativePath);
  const onRequestCountInFile = (ctx.redactedContent.match(/\bonRequest\s*\(/g) ?? []).length;

  if (jsModules && selfRecord) {
    const visited = new Set<string>([ctx.relativePath]);
    const hop1Entries: Array<{ mod: JsModuleRecord; scopedText: string }> = [];
    for (const edge of selfRecord.localImports) {
      if (!edge.targetRelativePath || visited.has(edge.targetRelativePath)) continue;
      const usedDirectly = edge.importedIdentifiers.some((id) =>
        hasWholeIdentifier(localReachableText, id),
      );
      if (edge.importedIdentifiers.length > 0 && !usedDirectly) {
        continue;
      }
      if (edge.importedIdentifiers.length === 0 && !(onRequestCountInFile === 1 && selfRecord.localImports.length <= 6)) {
        continue;
      }
      const mod = jsModules.get(edge.targetRelativePath);
      if (mod) {
        visited.add(mod.relativePath);
        const scopedText = extractImportedScopedText(mod, edge.importedIdentifiers);
        hop1Entries.push({ mod, scopedText });
        importedContents.push(mod.redactedContent);
        scopedImportedContents.push(scopedText);
      }
    }
    for (const h1 of hop1Entries) {
      for (const edge2 of h1.mod.localImports) {
        if (!edge2.targetRelativePath || visited.has(edge2.targetRelativePath)) continue;
        if (
          edge2.importedIdentifiers.length > 0 &&
          !edge2.importedIdentifiers.some((id) => hasWholeIdentifier(h1.scopedText, id))
        ) {
          continue;
        }
        const mod2 = jsModules.get(edge2.targetRelativePath);
        if (mod2) {
          visited.add(mod2.relativePath);
          importedContents.push(mod2.redactedContent);
          scopedImportedContents.push(extractImportedScopedText(mod2, edge2.importedIdentifiers));
        }
      }
    }
  }

  const reachableText = stripJsCommentsSimple(
    [localReachableText, ...importedContents].join('\n'),
  );
  const mutationReachableText = stripJsCommentsSimple(
    [localReachableText, ...scopedImportedContents].join('\n'),
  );

  // 1. Auth, App Check, HMAC / timingSafeEqual / ECDSA crypto.verify, or .well-known
  if (AUTH_OR_APPCHECK_PROOF_RE.test(reachableText)) {
    return true;
  }

  // 2. Public GET/HEAD-only Firebase Hosting rewrite target or public CDN-cached catalog API
  const enforcesGetHeadOnly =
    /(?:req\.method|method)\s*!==\s*['"]GET['"]|\b405\b|methodNotAllowed|method-not-allowed/i.test(
      reachableText,
    );
  const hasDbOrStorageMutation = DB_OR_STORAGE_MUTATION_RE.test(mutationReachableText);
  if (enforcesGetHeadOnly && !hasDbOrStorageMutation) {
    const isPublicHostingTarget = Boolean(
      exportedName && ctx.repoContext?.publicHostingRewriteFunctions.has(exportedName),
    );
    const hasPublicCacheHeaders =
      /\b(?:s-maxage\s*=|stale-while-revalidate)\b/i.test(reachableText) ||
      (/\bCache-Control\b/i.test(reachableText) && /\bpublic\b/i.test(reachableText));
    const readsAuthCookies =
      /\b(?:req\.cookies|req\.headers\.cookie|req\.headers\.authorization|req\.get\s*\(\s*['"](?:cookie|authorization)['"]\s*\))/i.test(
        reachableText,
      );
    const touchesSensitiveUserCollections =
      /\bcollection\s*\(\s*['"](?:users|accounts|orders|payments|sessions|tokens|secrets|admin)['"]/i.test(
        reachableText,
      );
    if (
      isPublicHostingTarget ||
      (hasPublicCacheHeaders && !readsAuthCookies && !touchesSensitiveUserCollections)
    ) {
      return true;
    }
  }

  // 3. Retired / no-op stub endpoint: zero DB/Storage, zero Secrets, zero external HTTP/AI/exec calls
  const touchesDbOrStorage =
    /\b(?:firestore|getFirestore|collection|collectionGroup|doc|runTransaction|batch|getDatabase|getStorage|bucket)\s*\(|\bdb\./i.test(
      reachableText,
    );
  const touchesSecrets = /\bsecrets\s*:|defineSecret\s*\(|process\.env\.|secretmanager/i.test(
    reachableText,
  );
  const touchesExternalApi =
    /\b(?:fetch|axios|https?\.request|https?\.get|https?\.post|generativeModel|GoogleGenAI|vertex|openai|exec|execFile|spawn)\s*\(/i.test(
      reachableText,
    );
  if (!touchesDbOrStorage && !touchesSecrets && !touchesExternalApi) {
    return true;
  }

  return false;
}

const ESCAPER_FN_RE =
  /^(?:[A-Za-z_$][A-Za-z0-9_$]*\.)?(?:escapeHtml|escapeHTML|escHtml|htmlEscape|encodeHtml|sanitizeHtml|DOMPurify\.sanitize|sanitize)\s*\(/;
const STATIC_QUOTED_LITERAL_RE = /^(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')$/;
const SAFE_NUMBER_COERCION_RE = /^(?:Number|parseInt|parseFloat|Math\.(?:round|floor|ceil|max|min))\s*\(/;
const SAFE_DATE_FORMAT_RE =
  /^new\s+Date\s*\([^)]*\)\s*\.\s*(?:toLocale(?:Date|Time)?String|toISOString)\s*\(/;

function isSingleOuterCallMatching(expr: string, prefixRe: RegExp): boolean {
  const trimmed = expr.trim();
  const match = trimmed.match(prefixRe);
  if (!match) return false;
  const openIdx = trimmed.indexOf('(', Math.max(0, match[0].length - 1));
  if (openIdx < 0) return false;
  let depth = 0;
  let quote: string | null = null;
  for (let i = openIdx; i < trimmed.length; i++) {
    const ch = trimmed[i] ?? '';
    if (quote) {
      if (ch === '\\') {
        i += 1;
        continue;
      }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch;
      continue;
    }
    if (ch === '(') depth += 1;
    else if (ch === ')') {
      depth -= 1;
      if (depth === 0) return i === trimmed.length - 1;
    }
  }
  return false;
}

function stripStatementSemicolonAndComment(text: string): string {
  let quote: string | null = null;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i] ?? '';
    if (quote) {
      if (ch === '\\') {
        i += 1;
        continue;
      }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch;
      continue;
    }
    if (ch === '/' && text[i + 1] === '/') {
      return text.slice(0, i).trim().replace(/;+\s*$/, '').trim();
    }
    if (ch === ';') {
      return text.slice(0, i).trim();
    }
  }
  return text.trim().replace(/;+\s*$/, '').trim();
}

function extractTemplateLiteralInfo(
  rawRhs: string,
): { interpolations: string[]; trailingCode: string } | null {
  const trimmed = rawRhs.trimStart();
  if (!trimmed.startsWith('`')) return null;
  const interpolations: string[] = [];
  let i = 1;
  while (i < trimmed.length) {
    const ch = trimmed[i] ?? '';
    if (ch === '\\') {
      i += 2;
      continue;
    }
    if (ch === '`') {
      const trailingCode = stripStatementSemicolonAndComment(trimmed.slice(i + 1));
      return { interpolations, trailingCode };
    }
    if (ch === '$' && trimmed[i + 1] === '{') {
      i += 2;
      const exprStart = i;
      let braceDepth = 1;
      let innerQuote: string | null = null;
      while (i < trimmed.length && braceDepth > 0) {
        const inner = trimmed[i] ?? '';
        if (innerQuote) {
          if (inner === '\\') {
            i += 2;
            continue;
          }
          if (inner === innerQuote) innerQuote = null;
          i += 1;
          continue;
        }
        if (inner === '"' || inner === "'" || inner === '`') {
          innerQuote = inner;
          i += 1;
          continue;
        }
        if (inner === '{') braceDepth += 1;
        else if (inner === '}') {
          braceDepth -= 1;
          if (braceDepth === 0) break;
        }
        i += 1;
      }
      if (braceDepth !== 0) return null;
      interpolations.push(trimmed.slice(exprStart, i).trim());
      i += 1;
      continue;
    }
    i += 1;
  }
  return null;
}

function isSimpleSafeLiteralRhs(rhs: string): boolean {
  const clean = stripStatementSemicolonAndComment(rhs);
  if (STATIC_QUOTED_LITERAL_RE.test(clean)) return true;
  if (/^\d+(?:\.\d+)?$/.test(clean) || /^(?:true|false)$/.test(clean)) return true;
  if (isSingleOuterCallMatching(clean, SAFE_NUMBER_COERCION_RE)) return true;
  if (isSingleOuterCallMatching(clean, SAFE_DATE_FORMAT_RE)) return true;
  return false;
}

function isSafeLocalConstant(
  expr: string,
  allLines: readonly string[],
  sinkLineIdx: number,
): boolean {
  const clean = expr.trim();
  if (!clean) return true;
  if (isSimpleSafeLiteralRhs(clean)) return true;
  if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(clean)) return false;

  const esc = escapeRegExp(clean);
  const start = Math.max(0, sinkLineIdx - 70);
  const declRe = new RegExp(`(?:const|let)\\s+${esc}\\s*=\\s*(.+)$`);
  const paramRe = new RegExp(`(?:function[^)]*\\b${esc}\\b|=>|\\{[^}]*\\b${esc}\\b[^}]*\\}\\s*=)`);
  const assignRe = new RegExp(`(?:^|[^.\\w$])${esc}\\s*([+\\-*/&|^]?=)(?!=)\\s*(.*)$`);

  let declIdx = -1;
  for (let i = sinkLineIdx - 1; i >= start; i--) {
    const l = allLines[i] ?? '';
    if (declRe.test(l)) {
      declIdx = i;
      break;
    }
  }
  if (declIdx < 0) return false;

  // Reject if a closer enclosing function parameter shadows or supplies this identifier
  for (let i = declIdx - 1; i >= Math.max(0, declIdx - 4); i--) {
    const l = allLines[i] ?? '';
    if (/\bfunction\b/.test(l) && new RegExp(`\\([^)]*\\b${esc}\\b[^)]*\\)`).test(l)) {
      return false;
    }
  }
  if (paramRe.test(allLines[declIdx] ?? '') && !declRe.test(allLines[declIdx] ?? '')) {
    return false;
  }

  for (let i = declIdx; i < sinkLineIdx; i++) {
    const l = (allLines[i] ?? '').trim();
    if (!l || l.startsWith('//')) continue;
    const am = l.match(assignRe);
    if (!am) continue;
    if (am[1] !== '=') return false;
    if (!isSimpleSafeLiteralRhs(am[2] ?? '')) return false;
  }
  return true;
}

function extractDomSinkRhs(allLines: readonly string[], lineIdx: number, afterEquals: string): string {
  const collected = [afterEquals];
  const initialTrimmed = afterEquals.trimStart();
  const limit = Math.min(allLines.length, lineIdx + 35);
  if (initialTrimmed.startsWith('`') && !extractTemplateLiteralInfo(afterEquals)) {
    for (let i = lineIdx + 1; i < limit; i++) {
      collected.push(allLines[i] ?? '');
      if (extractTemplateLiteralInfo(collected.join('\n'))) break;
    }
  } else if (initialTrimmed === '' || /\($/.test(initialTrimmed)) {
    for (let i = lineIdx + 1; i < limit; i++) {
      collected.push(allLines[i] ?? '');
      const joined = collected.join('\n');
      if (joined.trimStart().startsWith('`')) {
        if (extractTemplateLiteralInfo(joined)) break;
      } else if (joined.includes(';')) {
        break;
      }
    }
  }
  return collected.join('\n');
}

function classifyDomSinkLine(
  line: string,
  idx: number,
  allLines: readonly string[],
): LinePredicateResult {
  if (/\bdangerouslySetInnerHTML\s*=\s*\{/.test(line)) {
    const win = allLines.slice(Math.max(0, idx - 6), Math.min(allLines.length, idx + 6)).join('\n');
    if (/\b(?:application\/ld\+json|jsonLdString|JSON\.stringify)\b/.test(win)) {
      return false;
    }
    if (/\b(?:DOMPurify\.sanitize|sanitizeHtml|escapeHtml|sanitize)\s*\(/.test(line)) {
      return {
        severityOverride: 'low',
        rootCauseOverride:
          'サニタイズ関数を経由していますが、dangerouslySetInnerHTML の利用箇所として継続監視対象（Low）に分類しました。',
      };
    }
    return true;
  }

  if (/\bdocument\.write\s*\(/.test(line)) {
    return true;
  }

  const assignMatch = line.match(/\.(?:innerHTML|outerHTML)\s*\+?=\s*(.*)$/);
  if (!assignMatch) return false;

  const rhs = extractDomSinkRhs(allLines, idx, assignMatch[1] ?? '');
  if (/\[REDACTED_|<script\b|\bon[a-z]+\s*=|javascript:/i.test(rhs)) {
    return true;
  }

  const expr = stripStatementSemicolonAndComment(rhs);
  if (!expr) return true;
  if (STATIC_QUOTED_LITERAL_RE.test(expr)) {
    return false;
  }

  const tpl = extractTemplateLiteralInfo(rhs);
  if (tpl) {
    if (tpl.trailingCode !== '') return true;
    if (tpl.interpolations.length === 0) return false;
    let sawEscaper = false;
    for (const interp of tpl.interpolations) {
      if (isSingleOuterCallMatching(interp, ESCAPER_FN_RE)) {
        sawEscaper = true;
        continue;
      }
      if (isSafeLocalConstant(interp, allLines, idx)) {
        continue;
      }
      return true;
    }
    if (!sawEscaper) return false;
    return {
      severityOverride: 'low',
      rootCauseOverride:
        'すべての動的補間式が escapeHtml / sanitize 系関数またはローカル定数を通過しているため危険度は Low です（より堅牢にするには textContent / createElement 構築を推奨）。',
    };
  }

  if (isSingleOuterCallMatching(expr, ESCAPER_FN_RE)) {
    return {
      severityOverride: 'low',
      rootCauseOverride:
        '出力は escapeHtml / sanitize 系関数を経由しているため High ではなく Low に分離しました（Trusted Types 準拠には textContent / createElement を推奨）。',
    };
  }

  return true;
}

export const STATIC_RULES: readonly StaticRule[] = [
  // =========================================================================
  // 1. TypeScript / Next.js / Node.js (ts-web-api)
  // =========================================================================
  {
    ruleId: 'LNG-TS-001',
    title: '未サニタイズ DOM シンクへの直接代入（DOM XSS 露出）',
    stack: 'ts-web-api',
    severity: 'high',
    stride: 'Tampering',
    cwe: 'CWE-79',
    owaspAsvs: 'V5.3.3 Output Encoding & Trusted Types',
    appliesTo: (ctx) =>
      (JS_TS_EXTS.has(ctx.ext) || ctx.ext === '.html') &&
      !/(?:^|\/)(?:pitch_deck\.html|pitch-figma\.html|public\/pitch\/|public\/(?:[a-z]{2}\/)?arc\/aegis\/map\/)/i.test(
        ctx.relativePath,
      ),
    evaluate: (ctx) => findMatchingLines(ctx, classifyDomSinkLine),
    rootCause:
      '信頼境界外の文字列が HTML パーサシンク（innerHTML / dangerouslySetInnerHTML / document.write）へ直接渡されると、任意の Script 実行（DOM-based XSS）が成立する構造になっています。',
    defensivePatch: `// 防御パッチ: textContent または Sanitizer API + CSP Trusted Types を強制
element.textContent = untrustedInput;

// サーバーレスポンスヘッダで Trusted Types と Nonce CSP を強制:
// Content-Security-Policy: script-src 'nonce-<RANDOM>' 'strict-dynamic'; object-src 'none'; base-uri 'none'; require-trusted-types-for 'script';`,
    verificationHint:
      '静的 grep で innerHTML / dangerouslySetInnerHTML が 0 件であること、およびレスポンスヘッダに require-trusted-types-for が含まれることを確認。',
  },
  {
    ruleId: 'LNG-TS-002',
    title: '動的コード評価またはシェル補間実行（コマンド・コード注入露出）',
    stack: 'ts-web-api',
    severity: 'critical',
    stride: 'Elevation of Privilege',
    cwe: 'CWE-78',
    owaspAsvs: 'V5.3.8 OS Command & Dynamic Execution Prevention',
    appliesTo: (ctx) => JS_TS_EXTS.has(ctx.ext),
    evaluate: (ctx) => {
      const isLocalRepoScript = /(?:^|\/)scripts\/[A-Za-z0-9_.-]+\.(?:mjs|cjs|js|ts)$/.test(
        ctx.relativePath,
      );
      return findMatchingLines(
        ctx,
        (line) =>
          /(?:^|[^\w.])eval\s*\(/.test(line) ||
          /\bnew\s+Function\s*\(/.test(line) ||
          (/\b(?:exec|execSync)\s*\(\s*`[^`]*\$\{/.test(line) &&
            !(isLocalRepoScript && /\bexecSync\s*\(\s*`git\s+/.test(line))),
      );
    },
    rootCause:
      'eval / new Function またはテンプレート文字列を用いた exec() はシェルメタ文字を解釈するため、入力値次第でサーバー権限での任意コマンド実行に至る危険があります。',
    defensivePatch: `// 防御パッチ: シェルを介さない execFile と固定引数配列 + Zod 厳格検証を使用
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const execFileAsync = promisify(execFile);

const safeArg = z.string().regex(/^[a-zA-Z0-9._-]+$/).parse(inputArg);
await execFileAsync('/usr/bin/git', ['status', '--', safeArg], { shell: false, timeout: 5000 });`,
    verificationHint: 'eval / new Function / 文字列補間付き exec を排除し、shell: false の execFile のみに統一されていることをテストで検証。',
  },
  {
    ruleId: 'LNG-TS-003',
    title: 'ワイルドカード CORS 許可構成（クロスオリジン情報読取リスク）',
    stack: 'ts-web-api',
    severity: 'high',
    stride: 'Information Disclosure',
    cwe: 'CWE-942',
    owaspAsvs: 'V14.5.3 Cross-Origin Resource Sharing',
    appliesTo: (ctx) => JS_TS_EXTS.has(ctx.ext) || ctx.baseName.startsWith('next.config'),
    evaluate: (ctx) => {
      const fullNonComment = stripJsCommentsSimple(ctx.redactedContent);
      const isFileGetMethodGuarded = /req\.method\s*!==\s*['"]GET['"]/.test(fullNonComment);
      const hasSignedQueryStreamHelpers = /\b(?:extractQueryTicket|timingSafeEqual|createHmac|createVerify)\b/.test(
        fullNonComment,
      );
      return findMatchingLines(ctx, (line, idx, all) => {
        const isStarAcao = /['"]Access-Control-Allow-Origin['"]\s*,\s*['"]\*['"]/.test(line);
        const isOriginConfig = /\borigin\s*:\s*(?:['"]\*['"]|true)\b/.test(line);
        if (!isStarAcao && !isOriginConfig) return false;

        const isOriginReflectTrue = /\borigin\s*:\s*true\b/.test(line);
        const localWindow = stripJsCommentsSimple(
          all.slice(Math.max(0, idx - 20), Math.min(all.length, idx + 25)).join('\n'),
        );
        const wideWindow = stripJsCommentsSimple(
          all.slice(Math.max(0, idx - 80), Math.min(all.length, idx + 80)).join('\n'),
        );

        const hasCredentials =
          /['"]Access-Control-Allow-Credentials['"]\s*,\s*['"]?true\b/i.test(wideWindow) ||
          /\bcredentials\s*:\s*true\b/.test(wideWindow);
        const readsCookieOrAuth =
          /\b(?:req\.(?:cookies|signedCookies|session)\b|req\.headers(?:\.(?:cookie|authorization)|\[['"](?:cookie|authorization)['"]\])|req\.get\s*\(\s*['"](?:cookie|authorization)['"]\s*\)|cookies\s*\(\s*\)|headers\s*\(\s*\)\s*\.\s*get\s*\(\s*['"](?:cookie|authorization)['"]\s*\))/i.test(
            wideWindow,
          );

        if (isOriginReflectTrue || hasCredentials || readsCookieOrAuth) {
          return true;
        }

        const isGetHeadOnlyCors =
          /['"]Access-Control-Allow-Methods['"]\s*,\s*['"]\s*(?:GET|HEAD|OPTIONS)(?:\s*,\s*(?:GET|HEAD|OPTIONS))*\s*['"]/i.test(
            localWindow,
          ) || isFileGetMethodGuarded;
        const isPublicCacheOrSignedStream =
          /\b(?:s-maxage|stale-while-revalidate)\b/i.test(wideWindow) ||
          (/\bCache-Control\b/i.test(localWindow) && /\bpublic\b/i.test(wideWindow)) ||
          /['"]Cross-Origin-Resource-Policy['"]\s*,\s*['"]cross-origin['"]/i.test(localWindow) ||
          (hasSignedQueryStreamHelpers && /\bRange\b/.test(localWindow));

        if (isGetHeadOnlyCors && isPublicCacheOrSignedStream) {
          return false;
        }

        return {
          severityOverride: 'low',
          rootCauseOverride:
            '状態なし・非認証（Cookie / Authorization / Allow-Credentials 未使用）エンドポイントでの Access-Control-Allow-Origin: "*" 検出です。資格情報付きでない限り重大露出（High）には当たりません（公開 CDN キャッシュ API へ安易に Vary: Origin を入れるとキャッシュ分割を招きます）。',
          defensivePatchOverride: `// 資格情報や Authorization を扱わない公開 GET/HEAD API・クエリ署名ストリームでは "*" が正当設計です。
// ※ 公開 CDN キャッシュ（s-maxage 等）へ安易に Vary: Origin を追加しないでください（キャッシュ分割の原因）。
// ※ 逆に Cookie / Authorization / Credentials: true を併用する場合のみ明示 Allowlist を適用してください：
// const ALLOWED_ORIGINS = new Set(['https://app.example.com']);`,
        };
      });
    },
    rootCause:
      'Cookie / Authorization 参照または Access-Control-Allow-Credentials: true と併用して Access-Control-Allow-Origin: * / origin: true を設定すると、クロスオリジンでの資格情報・非公開応答の読取が成立します。',
    defensivePatch: `// 防御パッチ（Cookie / Authorization / Credentials 併用エンドポイントのみ適用）:
// ※ 公開 CDN キャッシュ GET API（s-maxage 等）へ安易に Vary: Origin を付与するとキャッシュ効率が毀損するため適用対象を限定すること。
const ALLOWED_ORIGINS = new Set(['https://app.example.com']);
const origin = req.headers.origin;
if (origin && ALLOWED_ORIGINS.has(origin)) {
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin, Sec-Fetch-Site');
}`,
    verificationHint: '未許可 Origin ヘッダを付与した OPTIONS/GET リクエストに対し Access-Control-Allow-Origin が返らないことを単体テストで確認。',
  },
  {
    ruleId: 'LNG-TS-004',
    title: 'クライアント公開プレフィックス環境変数への機密キー混入',
    stack: 'ts-web-api',
    severity: 'critical',
    stride: 'Information Disclosure',
    cwe: 'CWE-200',
    owaspAsvs: 'V2.10.4 Secret Segregation',
    appliesTo: (ctx) =>
      !isNonProductionOrTemplateFile(ctx) &&
      (JS_TS_EXTS.has(ctx.ext) || ctx.baseName.startsWith('.env') || ctx.baseName.startsWith('next.config')),
    evaluate: (ctx) => findMatchingLines(ctx, (line) => PUBLIC_ENV_SECRET_RE.test(line)),
    rootCause:
      'NEXT_PUBLIC_ や VITE_ プレフィックス付きの環境変数はフロントエンド JS バンドルに平文埋め込みされるため、全ユーザーに秘密鍵が露出します。',
    defensivePatch: `// 防御パッチ: 公開プレフィックスを削除し、サーバー専用 Route Handler / Cloud Run 側でのみ Secret Manager から参照
import 'server-only';
const serviceSecret = process.env.INTERNAL_SERVICE_SECRET; // NEXT_PUBLIC_ 絶対禁止`,
    verificationHint: 'クライアントビルド成果物内に SECRET / PRIVATE / SERVICE_ROLE 文字列が含まれないことをビルドゲートで検査。',
  },
  {
    ruleId: 'LNG-TS-005',
    title: 'postMessage のワイルドカード送信または送信元 Origin 未検証',
    stack: 'ts-web-api',
    severity: 'medium',
    stride: 'Spoofing',
    cwe: 'CWE-346',
    owaspAsvs: 'V14.5.4 Origin Validation',
    appliesTo: (ctx) => JS_TS_EXTS.has(ctx.ext),
    evaluate: (ctx) =>
      findMatchingLines(ctx, (line) => /\.postMessage\s*\([^,]+,\s*['"]\*['"]\s*\)/.test(line)),
    rootCause:
      'targetOrigin に "*" を指定した postMessage は、意図しない第三者フレームやリダイレクト先オリジンへ機密データを漏洩させます。',
    defensivePatch: `// 防御パッチ: 厳格な targetOrigin 指定と受信側 event.origin の完全一致検証
targetWindow.postMessage({ type: 'SYNC_STATE' }, 'https://trusted.example.com');

window.addEventListener('message', (event) => {
  if (event.origin !== 'https://trusted.example.com') return;
  // Zod 等で event.data のスキーマを検証してから処理
});`,
    verificationHint: 'postMessage 呼び出しの第2引数がすべて固定オリジン定数であることを確認。',
  },
  {
    ruleId: 'LNG-TS-006',
    title: 'SQL クエリへのテンプレート文字列補間または Unsafe Raw 実行（SQL 注入露出）',
    stack: 'ts-web-api',
    severity: 'critical',
    stride: 'Tampering',
    cwe: 'CWE-89',
    owaspAsvs: 'V5.3.4 Parameterized Database Queries',
    appliesTo: (ctx) => JS_TS_EXTS.has(ctx.ext),
    evaluate: (ctx) =>
      findMatchingLines(
        ctx,
        (line) =>
          /\b(?:\$queryRawUnsafe|\$executeRawUnsafe)\s*\(/.test(line) ||
          /\.\s*(?:query|execute|raw)\s*\(\s*`\s*(?:SELECT|INSERT|UPDATE|DELETE|WITH)\b[^`]*\$\{/i.test(
            line,
          ),
      ),
    rootCause:
      'クエリ文字列へ `${...}` 補間や Unsafe Raw メソッドを直接使用すると、境界外入力が SQL 構文木そのものを書き換え、全レコード漏洩や改ざんに繋がります。',
    defensivePatch: `// 防御パッチ: プレースホルダ束縛（Parameterized Query）または型付きタグテンプレートへ統一
const result = await db.query('SELECT id, email FROM users WHERE id = $1', [validatedUserId]);
// Prisma の場合: await prisma.$queryRaw\`SELECT id FROM users WHERE id = \${validatedUserId}\`;`,
    verificationHint:
      '$queryRawUnsafe / $executeRawUnsafe および SQL テンプレート補間が 0 件であることを静的検査で確認。',
  },
  {
    ruleId: 'LNG-TS-007',
    title: 'トークン・署名用途での非暗号論的乱数または脆弱ハッシュアルゴリズム使用',
    stack: 'ts-web-api',
    severity: 'high',
    stride: 'Spoofing',
    cwe: 'CWE-338',
    owaspAsvs: 'V6.2.1 & V6.3.1 Cryptographic Randomness & Approved Digests',
    appliesTo: (ctx) => JS_TS_EXTS.has(ctx.ext),
    evaluate: (ctx) => {
      const isOperationalScript = /(?:^|\/)scripts\//i.test(ctx.relativePath);
      return findMatchingLines(ctx, (line, idx, all) => {
        const isMd5 = /\bcreateHash\s*\(\s*['"]md5['"]\s*\)/i.test(line);
        const isSha1 = /\bcreateHash\s*\(\s*['"]sha1['"]\s*\)/i.test(line);
        const isWeakMathRandom =
          /\bMath\.random\s*\(\s*\)/.test(line) &&
          /\b(?:token|nonce|csrf|secret|session|otp|apiKey|password|salt)\b/i.test(line);

        if (!isMd5 && !isSha1 && !isWeakMathRandom) return false;

        if (isMd5 && !isWeakMathRandom) {
          const isAuthDigestLine =
            /\b(?:password|passwd|pwd|token|session|jwt|auth|secret|sign|signature|otp|apiKey|csrf|nonce)\b/i.test(
              line,
            );
          if (!isAuthDigestLine) {
            const win = all
              .slice(Math.max(0, idx - 15), Math.min(all.length, idx + 30))
              .join('\n');
            const isStorageChecksum =
              /\b(?:md5Hash|Content-MD5|contentMd5|ContentMD5|gcsMd5|objectMd5)\b/.test(win) ||
              (/\b(?:bucket\.file|\.save|\.getMetadata|createWriteStream|Storage)\b/.test(win) &&
                /\.digest\s*\(\s*['"]base64['"]\s*\)/.test(line));
            if (isStorageChecksum) {
              return false;
            }
          }
        }

        if (isOperationalScript) {
          return {
            severityOverride: 'low',
            rootCauseOverride:
              'scripts/ 配下のオフライン運用スクリプトにおける非暗号論的ハッシュ / 乱数の使用です（本番リクエスト経路ではないため Low へ重み付け分離しました）。',
          };
        }
        return true;
      });
    },
    rootCause:
      '`Math.random()` は内部状態を予測可能であり、`MD5` / `SHA-1` は衝突耐性が破綻しているため、セッショントークン・Nonce・署名ダイジェストの偽造リスクがあります。',
    defensivePatch: `// 防御パッチ: CSPRNG (crypto.randomBytes / crypto.randomUUID) と SHA-256 以上を使用
import crypto from 'node:crypto';
const csrfToken = crypto.randomBytes(32).toString('hex');
const digest = crypto.createHash('sha256').update(payload).digest('hex');`,
    verificationHint:
      '認証・Nonce・ダイジェスト処理で Math.random / md5 / sha1 が使用されていないことを確認。',
  },
  {
    ruleId: 'LNG-TS-008',
    title: '未検証リクエストパラメータを用いた外部 URL フェッチ・リダイレクト（SSRF 露出）',
    stack: 'ts-web-api',
    severity: 'high',
    stride: 'Spoofing',
    cwe: 'CWE-918',
    owaspAsvs: 'V10.2.3 Server-Side Request Forgery & Egress Allowlisting',
    appliesTo: (ctx) => JS_TS_EXTS.has(ctx.ext),
    evaluate: (ctx) =>
      findMatchingLines(
        ctx,
        (line) =>
          /\b(?:fetch|axios(?:\.(?:get|post|request))?)\s*\(\s*(?:req\.(?:query|body|params)\b|searchParams\.get\s*\()/.test(
            line,
          ) ||
          /\bres\.redirect\s*\(\s*(?:req\.(?:query|body|params)\b|searchParams\.get\s*\()/.test(
            line,
          ),
      ),
    rootCause:
      'クライアント制御パラメータをそのまま `fetch` や `redirect` に渡すと、クラウドメタデータ（`169.254.169.254` / `[::ffff:169.254.169.254]`）や IPv6 Site-Local（`fec0::/10`）・ULA（`fc00::/7`）を含む内部ネットワーク走査・フィッシング転送に悪用されます。',
    defensivePatch: `// 防御パッチ: HTTPS スキーム強制 + 許可ホスト Allowlist + IPv6 リテラル/Site-Local(fec0::/10)/メタデータ IP 拒否
const ALLOWED_HOSTS = new Set(['api.trusted-partner.example']);
const parsed = new URL(rawTargetUrl);
if (parsed.protocol !== 'https:' || parsed.hostname.startsWith('[') || !ALLOWED_HOSTS.has(parsed.hostname)) {
  throw new Error('Blocked outbound URL by SSRF allowlist policy.');
}`,
    verificationHint:
      '169.254.169.254・127.0.0.1・[fec0::1]・[::ffff:169.254.169.254]・未登録外部ドメインを渡した際にリクエスト送信前に拒否されることをテストで確認。',
  },

  // =========================================================================
  // 2. Flutter / Dart + Firebase (flutter-firebase)
  // =========================================================================
  {
    ruleId: 'LNG-FB-001',
    title: 'Firestore / Storage Rules の無条件許可または全階層ワイルドカード書込み',
    stack: 'flutter-firebase',
    severity: 'critical',
    stride: 'Elevation of Privilege',
    cwe: 'CWE-284',
    owaspAsvs: 'V4.1.3 Principle of Least Privilege (Deny by Default)',
    appliesTo: (ctx) => ctx.ext === '.rules',
    evaluate: (ctx) => {
      if (/\bservice\s+(?:cloud\.firestore|firebase\.storage)\s*\{/.test(ctx.redactedContent)) {
        const parsed = parseFirebaseRules(ctx.redactedContent, ctx.relativePath);
        const seenLines = new Set<number>();
        const hits: Array<{ line: number; snippet: string }> = [];
        for (const f of parsed.findings) {
          if (
            (f.ruleId === 'firebase/public-read' ||
              f.ruleId === 'firebase/public-write' ||
              f.ruleId === 'firebase/recursive-wildcard') &&
            !seenLines.has(f.location.line)
          ) {
            seenLines.add(f.location.line);
            const rawLine = ctx.redactedLines[f.location.line - 1] ?? f.evidence;
            hits.push({ line: f.location.line, snippet: rawLine.trim().slice(0, 180) });
          }
        }
        return hits;
      }
      return findMatchingLines(ctx, (line) => /\ballow\s+[^:;]*:\s*if\s+true\s*;/.test(line));
    },
    rootCause:
      '`if true` またはルート `{document=**}` 再帰ワイルドカードにより、未認証の外部クライアントから全コレクションの閲覧・改ざん・削除（課金枯渇攻撃を含む）が可能になっています。',
    defensivePatch: `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // デフォルト全拒否（Deny by Default）
    match /{document=**} {
      allow read, write: if false;
    }

    // コレクション単位の所有者一致 + フィールドホワイトリスト検証
    match /users/{userId} {
      allow read: if request.auth != null && request.auth.uid == userId;
      allow create, update: if request.auth != null
        && request.auth.uid == userId
        && request.resource.data.keys().hasOnly(['displayName', 'updatedAt'])
        && request.resource.data.displayName is string
        && request.resource.data.displayName.size() <= 80;
      allow delete: if false;
    }
  }
}`,
    verificationHint:
      '@firebase/rules-unit-testing エミュレータで未認証ユーザーおよび他 UID からの read/write が PERMISSION_DENIED になることを検証。',
  },
  {
    ruleId: 'LNG-FB-002',
    title: 'Firestore Rules の認証のみチェックによる水平権限昇格（IDOR）露出',
    stack: 'flutter-firebase',
    severity: 'high',
    stride: 'Tampering',
    cwe: 'CWE-285',
    owaspAsvs: 'V4.2.1 Object-Level Access Control',
    appliesTo: (ctx) => ctx.ext === '.rules',
    evaluate: (ctx) =>
      findMatchingLines(ctx, (line) =>
        /\ballow\s+(?:write|update|delete|create|read,\s*write)\s*:\s*if\s+request\.auth\s*!=\s*null\s*;/.test(
          line,
        ),
      ),
    rootCause:
      '`request.auth != null` のみでは匿名認証や新規登録した任意の攻撃者アカウントが他ユーザーのドキュメントを上書き・削除でき、テナント分離とスキーマ検証が欠落しています。',
    defensivePatch: `// 防御パッチ: UID 所有権検証 + ロール/フィールド不変条件（role 自己昇格防止）を追加
allow update: if request.auth != null
  && resource.data.ownerId == request.auth.uid
  && request.resource.data.ownerId == resource.data.ownerId
  && !request.resource.data.diff(resource.data).affectedKeys().hasAny(['role', 'plan', 'isAdmin']);`,
    verificationHint: '別 UID でログインしたクライアントからの他者ドキュメント update/delete が拒否されることを Rules テストで確認。',
  },
  {
    ruleId: 'LNG-FB-003',
    title: 'Firebase Functions onRequest エンドポイントの App Check / 認証検証欠落',
    stack: 'flutter-firebase',
    severity: 'high',
    stride: 'Spoofing',
    cwe: 'CWE-306',
    owaspAsvs: 'V4.1.1 Enforced Access Control at Trusted Service Layer',
    appliesTo: (ctx) => JS_TS_EXTS.has(ctx.ext) && ctx.redactedContent.includes('firebase-functions'),
    evaluate: (ctx) => {
      if (!/\bonRequest\s*\(/.test(ctx.redactedContent)) return [];
      return findMatchingLines(
        ctx,
        (line, idx, all) => {
          if (!/\bonRequest\s*\(/.test(line)) return false;
          return !shouldPassOnRequest(ctx, idx, all);
        },
        4,
      );
    },
    rootCause:
      '公開 HTTP トリガー（onRequest）に Firebase Auth トークン検証および App Check 強制がないため、正規アプリ外からの直接リプレイ・自動課金枯渇リクエストを防げません。',
    defensivePatch: `// 防御パッチ: onCall + enforceAppCheck: true または ID トークン検証を必須化
import { onCall, HttpsError } from 'firebase-functions/v2/https';

export const secureAction = onCall(
  { region: 'asia-northeast1', enforceAppCheck: true, cors: ['https://app.example.com'] },
  async (request) => {
    if (!request.auth?.uid) {
      throw new HttpsError('unauthenticated', 'Authentication required.');
    }
  },
);`,
    verificationHint: 'Authorization ヘッダまたは X-Firebase-AppCheck なしの呼び出しが 401/403 で即時拒否されることを確認。',
  },
  {
    ruleId: 'LNG-FB-004',
    title: 'Flutter / モバイル通信の TLS 証明書検証無効化または平文 HTTP 許可',
    stack: 'flutter-firebase',
    severity: 'high',
    stride: 'Information Disclosure',
    cwe: 'CWE-295',
    owaspAsvs: 'V9.2.1 Strict TLS Certificate Validation',
    appliesTo: (ctx) =>
      ctx.ext === '.dart' || ctx.baseName === 'AndroidManifest.xml' || ctx.baseName === 'Info.plist',
    evaluate: (ctx) =>
      findMatchingLines(
        ctx,
        (line, idx, all) =>
          /\bbadCertificateCallback\b/.test(line) ||
          /usesCleartextTraffic\s*=\s*["']true["']/.test(line) ||
          (/NSAllowsArbitraryLoads/.test(line) && /<true\s*\/>/.test(all[idx + 1] ?? '')),
      ),
    rootCause:
      'badCertificateCallback や平文 HTTP 許可（usesCleartextTraffic / NSAllowsArbitraryLoads）は中間者攻撃（MITM）によるトークン傍受・応答改ざんを許します。',
    defensivePatch: `// 防御パッチ: badCertificateCallback を完全削除し OS 標準 Trust Store + HTTPS のみ強制
// AndroidManifest.xml: android:usesCleartextTraffic="false"
// Info.plist: NSAllowsArbitraryLoads を削除（デフォルト false 維持）`,
    verificationHint: '自己署名証明書や http:// スキームへの接続がハンドシェイク段階で例外拒否されることを確認。',
  },
  {
    ruleId: 'LNG-FB-005',
    title: 'Flutter SharedPreferences への認証トークン・機密情報の平文保存',
    stack: 'flutter-firebase',
    severity: 'medium',
    stride: 'Information Disclosure',
    cwe: 'CWE-312',
    owaspAsvs: 'V8.2.2 Client-Side Secure Storage',
    appliesTo: (ctx) => ctx.ext === '.dart',
    evaluate: (ctx) =>
      findMatchingLines(ctx, (line) =>
        /\bsetString\s*\(\s*['"][^'"]*(?:token|secret|password|api_key|privateKey)[^'"]*['"]/i.test(line),
      ),
    rootCause:
      'SharedPreferences は端末上に暗号化されない XML/plist として保存されるため、バックアップ抽出や侵害端末からセッション鍵が平文で流出します。',
    defensivePatch: `// 防御パッチ: Keychain / Android Keystore ハードウェア保護付きの FlutterSecureStorage を使用
const storage = FlutterSecureStorage(
  aOptions: AndroidOptions(encryptedSharedPreferences: true),
  iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock_this_device),
);
await storage.write(key: 'session_token', value: token);`,
    verificationHint: 'SharedPreferences への機密キー保存箇所が 0 件であり、FlutterSecureStorage ラッパ経由のみであることを確認。',
  },

  // =========================================================================
  // 3. Python / Go / Cloud Run / Docker (python-go-cloud)
  // =========================================================================
  {
    ruleId: 'LNG-CLD-001',
    title: 'Python シェル経由コマンド実行または安全でないデシリアライズ',
    stack: 'python-go-cloud',
    severity: 'critical',
    stride: 'Elevation of Privilege',
    cwe: 'CWE-78',
    owaspAsvs: 'V5.5.1 Safe Deserialization & Subprocess Isolation',
    appliesTo: (ctx) => ctx.ext === '.py',
    evaluate: (ctx) =>
      findMatchingLines(
        ctx,
        (line) =>
          /\bsubprocess\.(?:run|Popen|call|check_output)\s*\([^)]*shell\s*=\s*True/.test(line) ||
          /\bpickle\.loads?\s*\(/.test(line) ||
          (/\byaml\.load\s*\(/.test(line) && !/SafeLoader/.test(line)),
      ),
    rootCause:
      '`shell=True` や `pickle.loads` / `yaml.load`（SafeLoader なし）は、細工された入力で任意の OS コマンド実行・RCE に直結します。',
    defensivePatch: `# 防御パッチ: shell=False 固定引数リストと yaml.safe_load / Pydantic JSON 検証を使用
import subprocess
import yaml

subprocess.run(["/usr/bin/convert", input_path, output_path], shell=False, check=True, timeout=10)
config = yaml.safe_load(raw_yaml_text)`,
    verificationHint: 'bandit / grep により shell=True、pickle.load、SafeLoader なしの yaml.load が 0 件であることを確認。',
  },
  {
    ruleId: 'LNG-CLD-002',
    title: 'Dockerfile の root 実行または未固定 :latest ベースイメージ',
    stack: 'python-go-cloud',
    severity: 'high',
    stride: 'Elevation of Privilege',
    cwe: 'CWE-250',
    owaspAsvs: 'V14.2.1 Container Least Privilege & Immutable Base',
    appliesTo: (ctx) =>
      ctx.baseName === 'Dockerfile' || ctx.baseName.startsWith('Dockerfile.') || ctx.ext === '.dockerfile',
    evaluate: (ctx) => {
      const hits = findMatchingLines(ctx, (line) => /^FROM\s+\S+:latest\b/i.test(line.trim()), 1);
      const hasNonRootUser = ctx.redactedLines.some((l) => {
        const m = l.trim().match(/^USER\s+(\S+)/i);
        return Boolean(m && m[1] && m[1] !== 'root' && m[1] !== '0');
      });
      if (!hasNonRootUser && ctx.redactedLines.length > 0 && hits.length === 0) {
        const fromIdx = ctx.redactedLines.findIndex((l) => /^FROM\s+/i.test(l.trim()));
        const idx = fromIdx >= 0 ? fromIdx : 0;
        hits.push({ line: idx + 1, snippet: sliceRedactedWindow(ctx.redactedLines, idx) });
      }
      return hits;
    },
    rootCause:
      'コンテナがデフォルトの root (UID 0) で稼働するとプロセス侵害時のエスケープ被害が最大化され、`:latest` タグはサプライチェーン上の意図しない破壊的更新を招きます。',
    defensivePatch: `# 防御パッチ: バージョン/ダイジェスト固定 + Distroless または非 root USER 強制
FROM gcr.io/distroless/nodejs22-debian12:nonroot
WORKDIR /app
COPY --chown=nonroot:nonroot dist/ ./dist/
USER nonroot:nonroot
ENTRYPOINT ["/nodejs/bin/node", "dist/src/cli.js"]`,
    verificationHint: '`docker inspect` または Dockerfile 検査で `USER` が非 root であり `:latest` が存在しないことを確認。',
  },
  {
    ruleId: 'LNG-CLD-003',
    title: 'Cloud Run / IAM 設定における allUsers 未認証公開バインディング',
    stack: 'python-go-cloud',
    severity: 'high',
    stride: 'Spoofing',
    cwe: 'CWE-284',
    owaspAsvs: 'V4.1.2 Cloud Service Perimeter & WAF',
    appliesTo: (ctx) =>
      ctx.ext === '.yaml' || ctx.ext === '.yml' || ctx.ext === '.tf' || ctx.ext === '.sh',
    evaluate: (ctx) => {
      const hasHardenedPublicGatewayControls =
        /(?:--service-account|--max-instances|--set-secrets)\b/.test(ctx.redactedContent);
      return findMatchingLines(
        ctx,
        (line) =>
          /\ballUsers\b/.test(line) ||
          /\ballAuthenticatedUsers\b/.test(line) ||
          (!hasHardenedPublicGatewayControls && /--allow-unauthenticated\b/.test(line)),
      );
    },
    rootCause:
      '内部マイクロサービスへ最小権限SAやスケーリング上限なしに `allUsers` や `--allow-unauthenticated` を直接付与すると、インターネットから無制限に呼び出され、DDoS・高額課金攻撃の対象になります（クライアントから Firebase Auth Bearer JWT + App Check で直接呼ぶ公開 API ゲートウェイの場合は、専用 `--service-account` と `--max-instances` を併用してください）。',
    defensivePatch: `# 防御パッチ: 内部サービスは --no-allow-unauthenticated、公開APIゲートウェイは最小権限SA + max-instances を強制
gcloud run services update my-service \\
  --no-allow-unauthenticated \\
  --ingress=internal-and-cloud-load-balancing \\
  --max-instances=20 \\
  --service-account=minimal-runner@project.iam.gserviceaccount.com`,
    verificationHint: 'gcloud run services get-iam-policy で allUsers が不要な内部サービスに付与されていないこと、公開APIは最小権限SAと上限が設定されていることを確認。',
  },
  {
    ruleId: 'LNG-CLD-004',
    title: 'Go / Python バックエンドの TLS 証明書検証スキップまたは HTTP タイムアウト未設定',
    stack: 'python-go-cloud',
    severity: 'high',
    stride: 'Denial of Service',
    cwe: 'CWE-400',
    owaspAsvs: 'V9.2.1 & V11.1.4 Connection Exhaustion & TLS Hardening',
    appliesTo: (ctx) => ctx.ext === '.go' || ctx.ext === '.py',
    evaluate: (ctx) =>
      findMatchingLines(
        ctx,
        (line) =>
          /\bInsecureSkipVerify\s*:\s*true\b/.test(line) ||
          /\bverify\s*=\s*False\b/.test(line) ||
          /\bhttp\.ListenAndServe\s*\(/.test(line),
      ),
    rootCause:
      '`InsecureSkipVerify: true` / `verify=False` は通信経路での盗聴を許し、Go の素の `http.ListenAndServe` は ReadHeaderTimeout を持たないため Slowloris 接続枯渇攻撃に脆弱です。',
    defensivePatch: `// 防御パッチ (Go): 明示的なタイムアウトとヘッダ上限を持つ http.Server + 厳格な TLS 1.3 設定
srv := &http.Server{
    Addr:              "127.0.0.1:8080",
    Handler:           mux,
    ReadHeaderTimeout: 5 * time.Second,
    ReadTimeout:       15 * time.Second,
    WriteTimeout:      30 * time.Second,
    IdleTimeout:       60 * time.Second,
    MaxHeaderBytes:    1 << 16,
}`,
    verificationHint: 'go vet / gosec で G402 (TLS InsecureSkipVerify) と G114 (http.ListenAndServe) が 0 件であることを確認。',
  },
  {
    ruleId: 'LNG-CLD-005',
    title: 'Python / Go における SQL クエリ文字列フォーマット結合（SQL 注入露出）',
    stack: 'python-go-cloud',
    severity: 'critical',
    stride: 'Tampering',
    cwe: 'CWE-89',
    owaspAsvs: 'V5.3.4 Parameterized Database Queries',
    appliesTo: (ctx) => ctx.ext === '.py' || ctx.ext === '.go',
    evaluate: (ctx) =>
      findMatchingLines(
        ctx,
        (line) =>
          /\.\s*(?:execute|executemany)\s*\(\s*f['"](?:SELECT|INSERT|UPDATE|DELETE|WITH)\b[^'"]*\{/i.test(
            line,
          ) ||
          /\.\s*(?:Query|QueryRow|QueryContext|Exec|ExecContext)\s*\([^)]*fmt\.Sprintf\s*\(\s*["'`](?:SELECT|INSERT|UPDATE|DELETE|WITH)\b/i.test(
            line,
          ),
      ),
    rootCause:
      'Python の f-string や Go の `fmt.Sprintf` で SQL 文を直接構築すると、境界外パラメータによりクエリ構造が改変されます。',
    defensivePatch: `# 防御パッチ (Python): プレースホルダ束縛タプルを使用
cursor.execute("SELECT id, role FROM accounts WHERE email = %s", (validated_email,))

// 防御パッチ (Go): プリペアドプレースホルダ ($1 / ?) を使用
rows, err := db.QueryContext(ctx, "SELECT id, role FROM accounts WHERE email = $1", validatedEmail)`,
    verificationHint: 'execute(f"...") および db.Query(fmt.Sprintf(...)) が 0 件であることを確認。',
  },

  // =========================================================================
  // 4. Supply-Chain & Secrets (supply-chain-secrets)
  // =========================================================================
  {
    ruleId: 'LNG-SEC-001',
    title: 'ソースコード・構成ファイル内のハードコードされた機密情報・秘密鍵',
    stack: 'supply-chain-secrets',
    severity: 'critical',
    stride: 'Information Disclosure',
    cwe: 'CWE-798',
    owaspAsvs: 'V2.10.4 Zero Hardcoded Credentials',
    appliesTo: (ctx) =>
      !isNonProductionOrTemplateFile(ctx) &&
      ctx.ext !== '.lock' &&
      ctx.baseName !== 'pnpm-lock.yaml' &&
      ctx.baseName !== 'package-lock.json',
    evaluate: (ctx) => {
      const hits: Array<{ line: number; snippet: string }> = [];
      for (const lineNum of ctx.redactedLineNumbers) {
        const idx = lineNum - 1;
        const line = ctx.redactedLines[idx] ?? '';
        const trimmed = line.trim();
        if (!trimmed || isCommentOrRegexDef(trimmed) || trimmed.startsWith('#')) continue;
        // Skip Firebase Web SDK public client apiKey inside firebaseConfig / initializeApp blocks
        if (
          /\bapiKey\s*:[^\r\n]*\[REDACTED_(?:GCP_API_KEY|SECRET)\]/.test(line)
        ) {
          const windowText = ctx.redactedLines
            .slice(Math.max(0, idx - 6), Math.min(ctx.redactedLines.length, idx + 7))
            .join('\n');
          if (
            /\b(?:authDomain|messagingSenderId|appId|storageBucket|firebase\.initializeApp|FIREBASE_CONFIG|WEB_CONFIG)\b/.test(
              windowText,
            )
          ) {
            continue;
          }
        }
        hits.push({
          line: lineNum,
          snippet: sliceRedactedWindow(ctx.redactedLines, idx),
        });
        if (hits.length >= 3) break;
      }
      return hits;
    },
    rootCause:
      'リポジトリ内に API キー・秘密鍵・パスワード文字列が直接記述されており、Git 履歴やクライアント配布物を経由した資格情報漏洩リスクがあります（表示・送信前に自動マスク済み）。',
    defensivePatch: `# 防御パッチ: キーを即時ローテーションして失効させ、環境変数または Secret Manager 参照へ移行
# 1. Google Cloud Secret Manager または実行時環境変数から取得
export GEMINI_API_KEY="$(gcloud secrets versions access latest --secret=gemini-api-key)"
# 2. .gitignore に .env / .env.* を必ず登録`,
    verificationHint: 'リポジトリ全体に対する Secret Redactor スキャンで検出数が 0 件になることを確認。',
  },
  {
    ruleId: 'LNG-SEC-002',
    title: 'GitHub Actions の pull_request_target 使用または未固定サードパーティ Action',
    stack: 'supply-chain-secrets',
    severity: 'high',
    stride: 'Tampering',
    cwe: 'CWE-829',
    owaspAsvs: 'V14.2.3 CI/CD Supply-Chain Pinning',
    appliesTo: (ctx) =>
      ctx.relativePath.includes('.github/workflows/') && (ctx.ext === '.yml' || ctx.ext === '.yaml'),
    evaluate: (ctx) => {
      const hasPrTarget = /\bpull_request_target\b/.test(ctx.redactedContent);
      return findMatchingLines(
        ctx,
        (line) => {
          if (/\bpull_request_target\b/.test(line)) return true;
          const trimmed = line.trim();
          if (/\buses:\s*[^@\s]+@(?:main|master|latest|HEAD|dev|develop)\s*$/.test(trimmed)) {
            return true;
          }
          const tagMatch = trimmed.match(/\buses:\s*([^@\s]+)@(v\d+(?:\.\d+)*)\s*$/);
          if (!tagMatch) return false;
          const actionRepo = tagMatch[1] ?? '';
          if (
            !hasPrTarget &&
            /^(?:actions\/|github\/|google-github-actions\/|hashicorp\/|subosito\/flutter-action\b|erlef\/setup-beam\b|Swatinem\/rust-cache\b|aws-actions\/|azure\/|docker\/)/.test(
              actionRepo,
            )
          ) {
            return false;
          }
          return true;
        },
      );
    },
    rootCause:
      '`pull_request_target` はフォーク PR にシークレット読取権限を与えかねず、タグ指定のみの `uses: action@v4` はタグ書き換えによるサプライチェーン汚染を受けます。',
    defensivePatch: `# 防御パッチ: 最小権限 permissions と 40桁フルコミット SHA 固定を徹底
permissions:
  contents: read

steps:
  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2 pinned SHA`,
    verificationHint: '.github/workflows 配下の全 uses が 40 桁 16進 SHA に固定され、permissions が明示宣言されていることを確認。',
  },
  {
    ruleId: 'LNG-SEC-004',
    title: 'GitHub Actions シェル実行への外部イベント入力直接展開（CI コマンド注入露出）',
    stack: 'supply-chain-secrets',
    severity: 'critical',
    stride: 'Elevation of Privilege',
    cwe: 'CWE-78',
    owaspAsvs: 'V14.2.3 CI/CD Untrusted Context Isolation',
    appliesTo: (ctx) =>
      ctx.relativePath.includes('.github/workflows/') && (ctx.ext === '.yml' || ctx.ext === '.yaml'),
    evaluate: (ctx) =>
      findMatchingLines(ctx, (line) => {
        if (/^\s*[A-Z_][A-Z0-9_]*\s*:\s*['"]?\$\{\{[^}]+\}\}['"]?\s*$/.test(line)) {
          return false;
        }
        return /\$\{\{\s*github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label)|comment\.body|review\.body|discussion\.(?:title|body)|commits\[[^\]]+\]\.message|head_commit\.message|pages\[[^\]]+\]\.page_name)\s*\}\}/.test(
          line,
        );
      }),
    rootCause:
      'PR タイトル・Issue 本文・ブランチ名などの外部入力（`github.event.*`）を `run:` スクリプト内で直接 `${{ ... }}` 展開すると、シェル実行前に文字列展開されて CI トークン窃取・任意コマンド実行が成立します。',
    defensivePatch: `# 防御パッチ: env: 中間環境変数へ束縛し、シェル側では二重引用符付き "$PR_TITLE" として参照
- name: Validate PR metadata safely
  env:
    PR_TITLE: \${{ github.event.pull_request.title }}
  run: |
    printf '%s\\n' "$PR_TITLE" | head -c 120`,
    verificationHint: 'run: ブロック内に github.event.* の直接 ${{ }} 展開が 0 件であり、すべて env: 経由であることを確認。',
  },
];

function findContainingOrphanDirectory(
  relPath: string,
  orphanDirs: ReadonlySet<string> | undefined,
): string | undefined {
  if (!orphanDirs || orphanDirs.size === 0) return undefined;
  for (const dir of orphanDirs) {
    if (relPath === dir || relPath.startsWith(`${dir}/`)) {
      return dir;
    }
  }
  return undefined;
}

export function evaluateFileRules(ctx: FileContext): SecurityFinding[] {
  if (ctx.skipSelfPatternDefinitions === true || isNonProductionOrTemplateFile(ctx)) {
    return [];
  }
  const safeFilePath = redactSecrets(ctx.relativePath).redactedText;
  const orphanDir = findContainingOrphanDirectory(
    safeFilePath,
    ctx.repoContext?.orphanDirectories,
  );
  const findings: SecurityFinding[] = [];
  for (const rule of STATIC_RULES) {
    if (!rule.appliesTo(ctx)) continue;
    const isCredentialLeakRule =
      rule.ruleId === 'LNG-SEC-001' ||
      rule.ruleId === 'LNG-SEC-005' ||
      rule.ruleId === 'LNG-TS-004';
    const matches = rule.evaluate(ctx);
    for (const match of matches) {
      const baseSeverity = match.severityOverride ?? rule.severity;
      const effectiveSeverity: SeverityLevel =
        orphanDir && !isCredentialLeakRule ? 'low' : baseSeverity;
      const baseRootCause = match.rootCauseOverride ?? rule.rootCause;
      const effectiveRootCause = orphanDir
        ? `【孤立資産 (Orphan Asset): \`${orphanDir}/\`】CI・firebase.json・デプロイ定義から未参照のディレクトリです。パッチ修正ではなく「未使用ディレクトリの削除可否確認」を優先してください。 — ${baseRootCause}`
        : baseRootCause;
      const basePatch = match.defensivePatchOverride ?? rule.defensivePatch;
      const effectivePatch = orphanDir
        ? `# [最優先推奨] 未使用ディレクトリの削除可否確認（${orphanDir}/）\n# CI・firebase.json・デプロイ定義から未参照のため、パッチ修正前に退役済み資産として削除可能か確認してください。\n\n${basePatch}`
        : basePatch;
      const isOrphan = Boolean(orphanDir || match.orphanAsset);

      findings.push({
        id: `${rule.ruleId}:${safeFilePath}:${match.line}`,
        ruleId: rule.ruleId,
        title: rule.title,
        stack: rule.stack,
        severity: effectiveSeverity,
        stride: rule.stride,
        cwe: rule.cwe,
        owaspAsvs: rule.owaspAsvs,
        filePath: safeFilePath,
        line: match.line,
        snippetRedacted: match.snippet,
        rootCause: effectiveRootCause,
        defensivePatch: effectivePatch,
        verificationHint: rule.verificationHint,
        source: 'static-rule',
        ...(isOrphan ? { orphanAsset: true } : {}),
      });
    }
  }
  return findings;
}

export function classifyFileStack(relativePath: string): StackDomain {
  const ext = path.extname(relativePath).toLowerCase();
  const base = path.basename(relativePath);
  if (
    ext === '.dart' ||
    ext === '.rules' ||
    base === 'pubspec.yaml' ||
    base === 'firebase.json' ||
    base === 'AndroidManifest.xml' ||
    base === 'Info.plist'
  ) {
    return 'flutter-firebase';
  }
  if (
    ext === '.py' ||
    ext === '.go' ||
    ext === '.tf' ||
    base === 'Dockerfile' ||
    base.startsWith('Dockerfile.') ||
    base === 'go.mod' ||
    base === 'pyproject.toml' ||
    base === 'requirements.txt'
  ) {
    return 'python-go-cloud';
  }
  if (JS_TS_EXTS.has(ext) || base.startsWith('next.config') || ext === '.html' || ext === '.css') {
    return 'ts-web-api';
  }
  return 'supply-chain-secrets';
}
