import { hash } from 'node:crypto';
import type { Finding, GraphEdge, GraphNode, GraphResult, Severity } from '../types.ts';

export function emptyGraph(): GraphResult {
  return { nodes: [], edges: [], findings: [], paths: [], limitations: [] };
}

let lastHashFile: string | undefined;
let lastHashLine: number | undefined;
let lastHashRuleId: string | undefined;
let lastHashEvidence: string | undefined;
let lastHashId: string | undefined;

export function addFinding(graph: GraphResult, file: string, line: number, ruleId: string,
  severity: Severity, title: string, message: string, evidence: string): Finding {
  let id: string;
  if (file === lastHashFile && line === lastHashLine && ruleId === lastHashRuleId && evidence === lastHashEvidence && lastHashId !== undefined) {
    id = lastHashId;
  } else {
    id = hash('sha256', `${file}\0${line}\0${ruleId}\0${evidence}`, 'hex').slice(0, 20);
    lastHashFile = file;
    lastHashLine = line;
    lastHashRuleId = ruleId;
    lastHashEvidence = evidence;
    lastHashId = id;
  }
  const finding = { id, ruleId, severity, title, message, location: { file, line }, evidence };
  graph.findings.push(finding);
  return finding;
}

/** Preserve offsets while ignoring comments, including URLs inside quoted literals. */
export function stripComments(source: string, hashComments = false, allowSingleQuotes = true): string {
  return maskComments(source, hashComments, allowSingleQuotes).text;
}

export function stripHclCommentsAndHeredocs(source: string): { text: string; hasHeredoc: boolean } {
  return maskComments(source, true, false);
}

function maskComments(source: string, hashComments: boolean, allowSingleQuotes: boolean):
  { text: string; hasHeredoc: boolean } {
  // Without introducers there is nothing to mask; avoid rebuilding the source one character at a time.
  if (!source.includes('//') && !source.includes('/*') && (!hashComments || !source.includes('#')) &&
    (allowSingleQuotes || !source.includes('<<'))) return { text: source, hasHeredoc: false };
  let result = '', quote = '', escaped = false, hasHeredoc = false;
  const heredoc = /<<(-?)([A-Za-z_][A-Za-z0-9_]*)[ \t]*\r?\n/y;
  for (let i = 0; i < source.length; i++) {
    const c = source[i], next = source[i + 1];
    if (quote) {
      result += c;
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === quote) quote = '';
    } else if (c === '"' || (allowSingleQuotes && c === "'")) { quote = c; result += c; }
    else if (!allowSingleQuotes && c === '<' && next === '<') {
      heredoc.lastIndex = i;
      const marker = heredoc.exec(source);
      if (!marker) { result += c; continue; }
      hasHeredoc = true;
      // Keep the introducer as an unsupported value so the next attribute cannot
      // be consumed as this attribute's value. Mask body and terminator together.
      result += marker[0];
      const start = heredoc.lastIndex;
      let end = start;
      while (end < source.length) {
        const newline = source.indexOf('\n', end);
        const lineEnd = newline < 0 ? source.length : newline;
        let left = end, right = lineEnd;
        if (source[right - 1] === '\r') right--;
        while (right > left && (source[right - 1] === ' ' || source[right - 1] === '\t')) right--;
        if (marker[1]) while (left < right && (source[left] === ' ' || source[left] === '\t')) left++;
        const terminator = source.slice(left, right);
        end = newline < 0 ? source.length : newline + 1;
        if (terminator === marker[2]) break;
      }
      result += source.slice(start, end).replace(/[^\r\n]/g, ' ');
      i = end - 1;
    }
    else if ((c === '/' && next === '/') || (hashComments && c === '#')) {
      while (i < source.length && source[i] !== '\n') { result += ' '; i++; }
      if (i < source.length) result += '\n';
    } else if (c === '/' && next === '*') {
      result += '  '; i += 2;
      while (i < source.length && !(source[i] === '*' && source[i + 1] === '/')) {
        result += source[i] === '\n' ? '\n' : ' '; i++;
      }
      if (i < source.length) { result += '  '; i++; }
    } else result += c;
  }
  return { text: result, hasHeredoc };
}

/** Build once per source; offsets refer to UTF-16 positions, like RegExp.index. */
export function createLineIndex(source: string): (offset: number) => number {
  const newlines: number[] = [];
  for (let i = 0; i < source.length; i++) if (source[i] === '\n') newlines.push(i);
  let lastOffset = 0, lastIndex = 0;
  return (offset) => {
    if (offset >= lastOffset) {
      while (lastIndex < newlines.length && newlines[lastIndex] < offset) lastIndex++;
      lastOffset = offset;
      return lastIndex + 1;
    }
    let low = 0, high = newlines.length;
    while (low < high) {
      const middle = low + Math.floor((high - low) / 2);
      if (newlines[middle] < offset) low = middle + 1;
      else high = middle;
    }
    lastOffset = offset;
    lastIndex = low;
    return low + 1;
  };
}

export function sourceLine(source: string, offset: number): number {
  return createLineIndex(source)(offset);
}

/** Comments must already be masked; quoted and escaped braces are not syntax. */
export function buildBraceMap(source: string, allowSingleQuotes = true): Map<number, number> {
  const pairs = new Map<number, number>(), stack: number[] = [];
  let quote = '', escaped = false;
  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    if (quote) {
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === quote) quote = '';
    } else if (c === '"' || (allowSingleQuotes && c === "'")) quote = c;
    else if (c === '{') stack.push(i);
    else if (c === '}') {
      const open = stack.pop();
      if (open !== undefined) pairs.set(open, i);
    }
  }
  return pairs;
}

export function closingBrace(source: string, open: number, allowSingleQuotes = true): number {
  let depth = 0, quote = '', escaped = false;
  for (let i = open; i < source.length; i++) {
    const c = source[i];
    if (quote) {
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === quote) quote = '';
    } else if (c === '"' || (allowSingleQuotes && c === "'")) quote = c;
    else if (c === '{') depth++;
    else if (c === '}' && --depth === 0) return i;
  }
  return -1;
}

function isSpaceCode(code: number): boolean {
  return code === 32 || (code >= 9 && code <= 13) || (code >= 160 && /\s/.test(String.fromCharCode(code)));
}

function isLowerAlphaCode(code: number): boolean {
  return code >= 97 && code <= 122;
}

function isWordCode(code: number): boolean {
  return (code >= 97 && code <= 122) || (code >= 65 && code <= 90) || (code >= 48 && code <= 57) || code === 95;
}

function isWordOrDotCode(code: number): boolean {
  return isWordCode(code) || code === 46;
}

function isOperatorResetCode(code: number): boolean {
  return code === 61 || code === 58 || code === 63 || code === 33 || code === 38 ||
    code === 124 || code === 60 || code === 62 || code === 43 || code === 42 || code === 37;
}

function isPathOrMemberDelimiter(code: number): boolean {
  return isWordOrDotCode(code) || code === 47 || code === 45;
}

function isHeaderKeywordAt(text: string, cursor: number): boolean {
  const code = text.charCodeAt(cursor);
  if (code !== 109 && code !== 102 && code !== 115) return false;
  if (isPathOrMemberDelimiter(text.charCodeAt(cursor - 1))) return false;
  const end = code === 109
    ? (text.startsWith('match', cursor) ? cursor + 5 : -1)
    : code === 102
      ? (text.startsWith('function', cursor) ? cursor + 8 : -1)
      : (text.startsWith('service', cursor) ? cursor + 7 : -1);
  if (end < 0) return false;
  const next = text.charCodeAt(end);
  return !isWordOrDotCode(next) && next !== 45;
}

function isCelInOperatorAt(text: string, cursor: number): boolean {
  return text.charCodeAt(cursor) === 105 &&
    text.charCodeAt(cursor + 1) === 110 &&
    !isPathOrMemberDelimiter(text.charCodeAt(cursor - 1)) &&
    !isPathOrMemberDelimiter(text.charCodeAt(cursor + 2));
}

function parseAllowHeader(text: string, start: number, end: number):
  { operations: string[]; condition: string } | undefined {
  const operations: string[] = [];
  let cursor = start + 'allow'.length;
  for (;;) {
    while (cursor < end && isSpaceCode(text.charCodeAt(cursor))) cursor++;
    const operationStart = cursor;
    while (cursor < end && isLowerAlphaCode(text.charCodeAt(cursor))) cursor++;
    if (cursor === operationStart) return undefined;
    operations.push(text.slice(operationStart, cursor));
    while (cursor < end && isSpaceCode(text.charCodeAt(cursor))) cursor++;
    if (cursor >= end || text.charCodeAt(cursor) !== 44) break;
    cursor++;
  }
  if (cursor === end) return { operations, condition: 'true' };
  if (text.charCodeAt(cursor++) !== 58) return undefined;
  while (cursor < end && isSpaceCode(text.charCodeAt(cursor))) cursor++;
  if (!text.startsWith('if', cursor) || isWordCode(text.charCodeAt(cursor + 2))) return undefined;
  cursor += 2;
  while (cursor < end && isSpaceCode(text.charCodeAt(cursor))) cursor++;
  const condition = text.slice(cursor, end).trim();
  return condition ? { operations, condition } : undefined;
}

function forEachAllowClause(text: string, emit: (offset: number, operations: string[], condition: string, evidence: string) => void): void {
  let start = -1, quote = 0, escaped = false, parens = 0, boundary = true;
  let afterColon = false, braces = 0, headerKeyword = false;
  let lastClauseRaw: string | undefined;
  let lastOperations: string[] | undefined;
  let lastCondition: string | undefined;
  let lastEvidence: string | undefined;
  for (let cursor = 0; cursor < text.length; cursor++) {
    const code = text.charCodeAt(cursor);
    if (quote) {
      if (escaped) escaped = false;
      else if (code === 92) escaped = true;
      else if (code === quote) quote = 0;
      continue;
    }
    if (code === 34 || code === 39) { quote = code; boundary = false; continue; }
    if (code === 40) parens++;
    else if (code === 41) parens = Math.max(0, parens - 1);
    if (start >= 0 && !afterColon && parens === 0 && code === 58) {
      afterColon = true;
      headerKeyword = false;
    }
    if (afterColon && parens === 0 && code === 123) {
      // A missing semicolon must not turn the next rules block into a CEL map.
      if (braces > 0 || !headerKeyword) { braces++; boundary = false; continue; }
    }
    if (afterColon && parens === 0 && code === 125 && braces > 0) {
      if (--braces === 0) headerKeyword = false;
      continue;
    }
    if (parens === 0 && (code === 123 || code === 125)) {
      start = -1;
      afterColon = false;
      braces = 0;
      headerKeyword = false;
      boundary = true;
    } else if (parens === 0 && braces === 0 && code === 59) {
      const offset = start;
      start = -1;
      afterColon = false;
      braces = 0;
      headerKeyword = false;
      boundary = true;
      if (offset >= 0) {
        const rawLen = cursor - offset;
        if (lastClauseRaw !== undefined && lastClauseRaw.length === rawLen && text.startsWith(lastClauseRaw, offset)) {
          if (lastOperations !== undefined) {
            emit(offset, lastOperations, lastCondition!, lastEvidence!);
          }
        } else {
          const raw = text.slice(offset, cursor);
          lastClauseRaw = raw;
          const clause = parseAllowHeader(raw, 0, rawLen);
          if (clause) {
            lastOperations = clause.operations;
            lastCondition = clause.condition;
            lastEvidence = (raw + ';').trim();
            emit(offset, lastOperations, lastCondition, lastEvidence);
          } else {
            lastOperations = undefined;
            lastCondition = undefined;
            lastEvidence = undefined;
          }
        }
      }
    } else if (boundary && start < 0 && text.startsWith('allow', cursor) && !isWordOrDotCode(text.charCodeAt(cursor - 1)) &&
      isSpaceCode(text.charCodeAt(cursor + 5))) {
      start = cursor;
      boundary = false;
    } else {
      // Relational/logical/list delimiters separate CEL map operands; '/' and '-' can be match path syntax.
      if (afterColon && parens === 0 && braces === 0) {
        if (isHeaderKeywordAt(text, cursor)) headerKeyword = true;
        else if (isOperatorResetCode(code) || code === 44 || code === 91 || isCelInOperatorAt(text, cursor)) headerKeyword = false;
      } else if (afterColon && parens > 0 && (code === 123 || code === 59)) {
        headerKeyword = false;
      }
      if (!isSpaceCode(code)) boundary = false;
    }
  }
}

/** Consume each candidate once, including unterminated clauses and quoted semicolons. */
export function* scanAllowClauses(text: string): Generator<{
  offset: number; operations: string[]; condition: string; evidence: string;
}> {
  const clauses: Array<{ offset: number; operations: string[]; condition: string; evidence: string }> = [];
  forEachAllowClause(text, (offset, operations, condition, evidence) => {
    clauses.push({ offset, operations: operations.slice(), condition, evidence });
  });
  for (const clause of clauses) {
    yield clause;
  }
}

interface CelFunctionAst {
  name: string;
  params: string[];
  bodyExpr: string;
  scopeStart: number;
  scopeEnd: number;
}

interface FirebaseScope {
  path: string;
  start: number;
  end: number;
  recursive: boolean;
  limited: boolean;
  data: string;
  resource: string;
  resourceLabel?: string;
  dataLabel?: string;
  resourceNode?: GraphNode;
  resourceLineLex?: string;
  readTitle?: string;
  readMessage?: string;
  writeTitle?: string;
  writeMessage?: string;
  wildcardMessage?: string;
  privFieldsLabel?: string;
  clauseFlags?: number;
}

const FLAG_PUBLIC_WRITE = 1;
const FLAG_RESTRICTED_WRITE = 2;
const FLAG_PUBLIC_LIST = 4;
const FLAG_RESTRICTED_LIST = 8;
const FLAG_ADMIN_OR_FALSE_WRITE = 16;

const PUBLIC_ASSET_PATH_RE =
  /(?:^|\/)(?:public|assets|static|badges|avatars|icons|media|ai_image|notifications|catalog|announcements|releases|banners|wines|articles)(?:\/|$)/i;

const SENSITIVE_USER_OR_PRIVATE_PATH_RE =
  /(?:^|\/)(?:users|users_v2|profiles|accounts|members|chats|chat_media|groups|private|encrypted|temp|review_inputs|orders|payments|secrets|tokens|keys|keybackups|passkeys|sessions|devicesessions|messages|dm|admin|adminpermissions|internal|audit|logs|backups|customers|wallets|invoices)(?:\/|$)/i;

const ROOT_CATCHALL_PATH_RE =
  /^(?:\/databases\/\{[^/}]+\}\/documents|\/b\/\{[^/}]+\}\/o)?\/\{[^/}]+\}$/i;

function resolveCelBodyWithLetBindings(rawBody: string): string | undefined {
  let rest = rawBody.trim();
  const letNames: string[] = [];
  const letValues: string[] = [];
  for (let count = 0; count < 16; count++) {
    const letMatch = rest.match(/^let\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([\s\S]*?);\s*([\s\S]*)$/);
    if (!letMatch) break;
    const varName = letMatch[1];
    const resolvedVal = substituteCelParams(letMatch[2].trim(), letNames, letValues);
    letNames.push(varName);
    letValues.push(resolvedVal);
    rest = letMatch[3].trim();
  }
  const retMatch = rest.match(/^return\s+([\s\S]*?)\s*;?\s*$/);
  if (!retMatch) return undefined;
  return substituteCelParams(retMatch[1].trim(), letNames, letValues);
}

function extractCelFunctions(
  text: string,
  bracePairs: ReadonlyMap<number, number>,
): CelFunctionAst[] {
  if (!text.includes('function')) return [];
  const fns: CelFunctionAst[] = [];
  const enclosingBraces: Array<{ open: number; close: number }> = [];
  for (const [open, close] of bracePairs.entries()) {
    enclosingBraces.push({ open, close });
  }

  for (const match of text.matchAll(
    /\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*\{/g,
  )) {
    const fnStart = match.index!;
    const openBrace = fnStart + match[0].length - 1;
    const closeBrace = bracePairs.get(openBrace) ?? -1;
    if (closeBrace < 0) continue;
    const rawBody = text.slice(openBrace + 1, closeBrace);
    const bodyExpr = resolveCelBodyWithLetBindings(rawBody);
    if (!bodyExpr) continue;
    const params = match[2]
      .split(',')
      .map((p) => p.trim())
      .filter((p) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(p));

    let scopeStart = 0;
    let scopeEnd = text.length;
    for (const b of enclosingBraces) {
      if (b.open < fnStart && b.close > closeBrace && b.open >= scopeStart) {
        scopeStart = b.open;
        scopeEnd = b.close;
      }
    }
    fns.push({
      name: match[1],
      params,
      bodyExpr,
      scopeStart,
      scopeEnd,
    });
  }
  return fns;
}

function splitBalancedArgs(argListText: string): string[] {
  const trimmed = argListText.trim();
  if (!trimmed) return [];
  const args: string[] = [];
  let start = 0;
  let depth = 0;
  let quote = 0;
  let escaped = false;
  for (let i = 0; i < trimmed.length; i++) {
    const code = trimmed.charCodeAt(i);
    if (quote) {
      if (escaped) escaped = false;
      else if (code === 92) escaped = true;
      else if (code === quote) quote = 0;
      continue;
    }
    if (code === 34 || code === 39) {
      quote = code;
      continue;
    }
    if (code === 40 || code === 91 || code === 123) depth++;
    else if (code === 41 || code === 93 || code === 125) depth = Math.max(0, depth - 1);
    else if (code === 44 && depth === 0) {
      args.push(trimmed.slice(start, i).trim());
      start = i + 1;
    }
  }
  args.push(trimmed.slice(start).trim());
  return args;
}

function substituteCelParams(
  bodyExpr: string,
  params: readonly string[],
  args: readonly string[],
): string {
  if (params.length === 0) return bodyExpr;
  const paramMap = new Map<string, string>();
  for (let i = 0; i < params.length; i++) {
    paramMap.set(params[i], `(${args[i] ?? 'null'})`);
  }
  let out = '';
  let i = 0;
  let quote = 0;
  let escaped = false;
  while (i < bodyExpr.length) {
    const code = bodyExpr.charCodeAt(i);
    if (quote) {
      out += bodyExpr[i];
      if (escaped) escaped = false;
      else if (code === 92) escaped = true;
      else if (code === quote) quote = 0;
      i++;
      continue;
    }
    if (code === 34 || code === 39) {
      quote = code;
      out += bodyExpr[i];
      i++;
      continue;
    }
    if (isWordCode(code) && (i === 0 || !isWordOrDotCode(bodyExpr.charCodeAt(i - 1)))) {
      let end = i + 1;
      while (end < bodyExpr.length && isWordCode(bodyExpr.charCodeAt(end))) end++;
      const ident = bodyExpr.slice(i, end);
      const replacement = paramMap.get(ident);
      if (replacement !== undefined && bodyExpr.charCodeAt(end) !== 40) {
        out += replacement;
        i = end;
        continue;
      }
      out += ident;
      i = end;
      continue;
    }
    out += bodyExpr[i];
    i++;
  }
  return out;
}

export function expandCelConditionAst(
  condition: string,
  clauseOffset: number,
  functions: readonly CelFunctionAst[],
): string {
  if (functions.length === 0 || !condition.includes('(')) return condition;
  let current = condition;
  for (let pass = 0; pass < 6; pass++) {
    let changed = false;
    let next = '';
    let i = 0;
    let quote = 0;
    let escaped = false;
    while (i < current.length) {
      const code = current.charCodeAt(i);
      if (quote) {
        next += current[i];
        if (escaped) escaped = false;
        else if (code === 92) escaped = true;
        else if (code === quote) quote = 0;
        i++;
        continue;
      }
      if (code === 34 || code === 39) {
        quote = code;
        next += current[i];
        i++;
        continue;
      }
      if (isWordCode(code) && (i === 0 || !isWordOrDotCode(current.charCodeAt(i - 1)))) {
        let nameEnd = i + 1;
        while (nameEnd < current.length && isWordCode(current.charCodeAt(nameEnd))) nameEnd++;
        const fnName = current.slice(i, nameEnd);
        let wsEnd = nameEnd;
        while (wsEnd < current.length && isSpaceCode(current.charCodeAt(wsEnd))) wsEnd++;
        if (current.charCodeAt(wsEnd) === 40) {
          let matchedFn: CelFunctionAst | undefined;
          for (const fn of functions) {
            if (
              fn.name === fnName &&
              fn.scopeStart <= clauseOffset &&
              clauseOffset <= fn.scopeEnd &&
              (!matchedFn || fn.scopeStart >= matchedFn.scopeStart)
            ) {
              matchedFn = fn;
            }
          }
          if (matchedFn) {
            let pDepth = 1;
            let pQuote = 0;
            let pEsc = false;
            let pCursor = wsEnd + 1;
            while (pCursor < current.length && pDepth > 0) {
              const pc = current.charCodeAt(pCursor);
              if (pQuote) {
                if (pEsc) pEsc = false;
                else if (pc === 92) pEsc = true;
                else if (pc === pQuote) pQuote = 0;
              } else if (pc === 34 || pc === 39) pQuote = pc;
              else if (pc === 40) pDepth++;
              else if (pc === 41) pDepth--;
              pCursor++;
            }
            if (pDepth === 0) {
              const args = splitBalancedArgs(current.slice(wsEnd + 1, pCursor - 1));
              const inlined = substituteCelParams(matchedFn.bodyExpr, matchedFn.params, args);
              next += `(${inlined})`;
              i = pCursor;
              changed = true;
              continue;
            }
          }
        }
        next += current.slice(i, nameEnd);
        i = nameEnd;
        continue;
      }
      next += current[i];
      i++;
    }
    current = next;
    if (!changed || current.length > 16_384) break;
  }
  return current;
}

function isUnconditionalTrueCel(expr: string): boolean {
  return expr === 'true' || /^[\s(]*true[\s)]*$/.test(expr);
}

function isExplicitlyRestrictedCel(expr: string): boolean {
  if (/^[\s(]*false[\s)]*$/.test(expr)) return true;
  if (isUnconditionalTrueCel(expr)) return false;
  return /\brequest\.auth\b/.test(expr);
}

function isAdminOrFalseRestrictedCel(rawCondition: string, expandedCondition: string): boolean {
  if (/^[\s(]*false[\s)]*$/.test(expandedCondition)) return true;
  if (!isExplicitlyRestrictedCel(expandedCondition)) return false;
  return (
    /\b(?:is[A-Za-z0-9_]*(?:Admin|Operator|Staff|Moderator)|admin_role|adminPermissions|superAdmin)\b/i.test(
      rawCondition,
    ) ||
    /\b(?:admin_role|adminPermissions|superAdmin|token\.admin|token\.role)\b/i.test(
      expandedCondition,
    )
  );
}

function recordScopeClauseFlags(
  scope: FirebaseScope,
  operations: readonly string[],
  rawCondition: string,
  expandedCondition: string,
): void {
  const isPub = isUnconditionalTrueCel(expandedCondition);
  const isRestricted = isExplicitlyRestrictedCel(expandedCondition);
  const isAdminOrFalse = isAdminOrFalseRestrictedCel(rawCondition, expandedCondition);
  let flags = scope.clauseFlags ?? 0;
  for (const op of operations) {
    if (op === 'write' || op === 'create' || op === 'update' || op === 'delete') {
      if (isPub) flags |= FLAG_PUBLIC_WRITE;
      if (isRestricted) flags |= FLAG_RESTRICTED_WRITE;
      if (isAdminOrFalse) flags |= FLAG_ADMIN_OR_FALSE_WRITE;
    }
    if (op === 'list' || op === 'read') {
      if (isPub) flags |= FLAG_PUBLIC_LIST;
      if (isRestricted && op === 'list') flags |= FLAG_RESTRICTED_LIST;
    }
  }
  scope.clauseFlags = flags;
}

function isWriteProtectedPublicReadScope(
  scope: FirebaseScope,
  clauseOps: readonly string[],
): boolean {
  const flags = scope.clauseFlags ?? 0;
  if ((flags & FLAG_PUBLIC_WRITE) !== 0 || (flags & FLAG_RESTRICTED_WRITE) === 0) return false;
  if (
    ROOT_CATCHALL_PATH_RE.test(scope.path) ||
    SENSITIVE_USER_OR_PRIVATE_PATH_RE.test(scope.path)
  ) {
    return false;
  }
  const isGetOnlyClause =
    clauseOps.length === 1 &&
    clauseOps[0] === 'get' &&
    (flags & FLAG_PUBLIC_LIST) === 0 &&
    (flags & FLAG_RESTRICTED_LIST) !== 0;
  if (isGetOnlyClause) return true;
  if (PUBLIC_ASSET_PATH_RE.test(scope.path)) return true;
  return (flags & FLAG_ADMIN_OR_FALSE_WRITE) !== 0;
}

export function parseFirebaseRules(source: string, file: string,
  kind: 'firestore' | 'storage' = file.includes('storage') ? 'storage' : 'firestore',
  collapseDuplicateEdges = false): GraphResult {
  const graph = emptyGraph(), text = stripComments(source);
  const nodeList: GraphNode[] = [];
  const nodes = new Map<string, { node: GraphNode; index: number; lineLex?: string }>();
  type EdgeAccumulator = { edge: GraphEdge; rawFrom: string; rawTo: string; rawKind: string; rawConfidence: string; rawEvidence: string };
  const edgeMap = collapseDuplicateEdges ? new Map<string, EdgeAccumulator>() : undefined;
  let mru0: EdgeAccumulator | undefined;
  let mru1: EdgeAccumulator | undefined;

  const accumulateEdge = (
    edgeId: string,
    from: string,
    to: string,
    edgeKind: GraphEdge['kind'],
    confidence: GraphEdge['confidence'],
    evidence: string,
    f1?: Finding,
    f2?: Finding,
    f3?: Finding,
  ): void => {
    let entry: EdgeAccumulator | undefined;
    if (mru0 && mru0.rawFrom === from && mru0.rawTo === to && mru0.rawKind === edgeKind &&
      mru0.rawConfidence === confidence && mru0.rawEvidence === evidence) {
      entry = mru0;
    } else if (mru1 && mru1.rawFrom === from && mru1.rawTo === to && mru1.rawKind === edgeKind &&
      mru1.rawConfidence === confidence && mru1.rawEvidence === evidence) {
      entry = mru1;
      mru1 = mru0;
      mru0 = entry;
    } else {
      const key = `${from.length}:${from}|${to.length}:${to}|${edgeKind.length}:${edgeKind}|${confidence.length}:${confidence}|${evidence}`;
      entry = edgeMap!.get(key);
      if (!entry) {
        entry = {
          edge: { id: edgeId, from, to, kind: edgeKind, confidence, evidence, findingIds: [] },
          rawFrom: from, rawTo: to, rawKind: edgeKind, rawConfidence: confidence, rawEvidence: evidence,
        };
        edgeMap!.set(key, entry);
      }
      mru1 = mru0;
      mru0 = entry;
    }
    if (edgeId < entry.edge.id) entry.edge.id = edgeId;
    if (f1) entry.edge.findingIds.push(f1.id);
    if (f2) entry.edge.findingIds.push(f2.id);
    if (f3) entry.edge.findingIds.push(f3.id);
  };
  const addNode = (id: string, nodeKind: GraphNode['kind'], label: string, line?: number): void => {
    const previous = nodes.get(id);
    if (previous && previous.node.label === label) {
      // Matching parser nodes differ only in line; include the JSON closing brace
      // to preserve mergeGraphs' lexical tie-break (e.g. line 10 precedes line 2).
      if (line !== undefined && previous.node.location) {
        const lex = `${line}}`;
        if (lex < (previous.lineLex ??= `${previous.node.location.line}}`)) {
          previous.node.location.line = line;
          previous.lineLex = lex;
        }
      }
      return;
    }
    const node: GraphNode = { id, kind: nodeKind, label, ...(line === undefined ? {} : { location: { file, line } }) };
    if (!previous) {
      const index = nodeList.length;
      nodeList.push(node);
      nodes.set(id, { node, index, lineLex: line === undefined ? undefined : `${line}}` });
    } else if (JSON.stringify(node) < JSON.stringify(previous.node)) {
      nodeList[previous.index] = node;
      previous.node = node;
      previous.lineLex = line === undefined ? undefined : `${line}}`;
    }
  };
  const lineIndex = createLineIndex(text), bracePairs = buildBraceMap(text);
  const scopes: FirebaseScope[] = [];
  const active: FirebaseScope[] = [];
  let traversalLimited = false;
  // Keep segments separate so a wildcard's opening brace cannot become the block brace.
  for (const match of text.matchAll(/\bmatch\s+((?:\/(?:[^/{}\s]|\{[^/{}\s]+\})+)+)\s*\{/g)) {
    const start = match.index! + match[0].length - 1;
    const end = bracePairs.get(start) ?? -1;
    if (end < 0) {
      addFinding(graph, file, lineIndex(start), 'scan/invalid-input', 'high',
        'Unbalanced Firebase rules', 'The rules could not be completely parsed.', 'Unclosed match block');
      continue;
    }
    while (active.length && active[active.length - 1].end <= start) active.pop();
    const parent = active[active.length - 1];
    if (parent?.limited) continue;
    const limited = active.length >= 64 || (parent?.path.length ?? 0) + match[1].length > 4096;
    if (limited && !traversalLimited) {
      addFinding(graph, file, lineIndex(start), 'scan/traversal-limit', 'high', 'Firebase scope expansion was bounded',
        'Match nesting exceeds 64 levels or the joined path exceeds 4096 characters; the scan is incomplete.',
        'Limits: 64 match levels, 4096 path characters');
      traversalLimited = true;
    }
    // A bounded sentinel also suppresses allow clauses inside the skipped subtree.
    const path = limited ? '' : (parent?.path ?? '') + match[1];
    const scope: FirebaseScope = { start, end, limited, path, data: `data:${kind}:${file}:${path}`, resource: `rules:${file}:${start}`,
      recursive: (parent?.recursive ?? false) || /\{[^}]+=\*\*\}/.test(match[1]) };
    active.push(scope);
    scopes.push(scope);
  }
  if (!/\bservice\s+(?:cloud\.firestore|firebase\.storage)\s*\{/.test(text) || scopes.length === 0) {
    addFinding(graph, file, 1, 'scan/invalid-input', 'high', 'Unsupported Firebase rules',
      'Expected a service and match blocks; this file was not treated as a clean ruleset.', 'Missing supported rules structure');
  }
  const entry = 'entry:firebase:public';
  const celFunctions = extractCelFunctions(text, bracePairs);
  const canHaveProtectedPublicScope =
    /\bif\b/.test(text) && /\b(?:write|create|update|delete|list)\b/.test(text);
  if (canHaveProtectedPublicScope) {
    active.length = 0;
    let preScopeIdx = 0;
    forEachAllowClause(text, (offset, operations, condition) => {
      while (active.length && active[active.length - 1].end <= offset) active.pop();
      while (preScopeIdx < scopes.length && scopes[preScopeIdx].start < offset) {
        const scope = scopes[preScopeIdx++];
        if (scope.end > offset) active.push(scope);
      }
      if (!active.length || active[active.length - 1].limited) return;
      const scope = active[active.length - 1];
      const expanded =
        celFunctions.length > 0 ? expandCelConditionAst(condition, offset, celFunctions) : condition;
      recordScopeClauseFlags(scope, operations, condition, expanded);
    });
  }
  // matchAll already emits scopes in source order.
  active.length = 0;
  let nextScope = 0;
  forEachAllowClause(text, (offset, operations, condition, evidence) => {
    const line = lineIndex(offset);
    while (active.length && active[active.length - 1].end <= offset) active.pop();
    while (nextScope < scopes.length && scopes[nextScope].start < offset) {
      const scope = scopes[nextScope++];
      if (scope.end > offset) active.push(scope);
    }
    if (!active.length || active[active.length - 1].limited) return;
    const scope = active[active.length - 1];
    const { path, data, resource } = scope;
    const expandedCondition =
      celFunctions.length > 0 ? expandCelConditionAst(condition, offset, celFunctions) : condition;
    let read = false, write = false, writeCreateUpdate = false;
    for (const op of operations) {
      if (op === 'read' || op === 'get' || op === 'list') read = true;
      if (op === 'write' || op === 'create' || op === 'update' || op === 'delete') write = true;
      if (op === 'write' || op === 'create' || op === 'update') writeCreateUpdate = true;
    }
    const publicAccess = isUnconditionalTrueCel(expandedCondition);
    const suppressedPublicRead =
      publicAccess &&
      read &&
      !write &&
      canHaveProtectedPublicScope &&
      isWriteProtectedPublicReadScope(scope, operations);
    const effectivePublicRead = publicAccess && read && !suppressedPublicRead;
    const effectivePublicWrite = publicAccess && write;
    if (effectivePublicRead || effectivePublicWrite) {
      let readFinding: Finding | undefined;
      let writeFinding: Finding | undefined;
      let wildcardFinding: Finding | undefined;
      if (effectivePublicRead) {
        const title = scope.readTitle ??= `Public ${kind} read`;
        const message = scope.readMessage ??= `The unconditional grant permits unauthenticated read at ${path}.`;
        readFinding = addFinding(graph, file, line, 'firebase/public-read', 'high', title, message, evidence);
      }
      if (effectivePublicWrite) {
        const title = scope.writeTitle ??= `Public ${kind} write`;
        const message = scope.writeMessage ??= `The unconditional grant permits unauthenticated write at ${path}.`;
        writeFinding = addFinding(graph, file, line, 'firebase/public-write', 'high', title, message, evidence);
      }
      if (effectivePublicRead && scope.recursive) {
        const message = scope.wildcardMessage ??= `The public read grant covers the recursive match ${path}.`;
        wildcardFinding = addFinding(graph, file, line, 'firebase/recursive-wildcard', 'high',
          'Recursive wildcard exposes descendants', message, evidence);
      }
      addNode(entry, 'entry', 'Unauthenticated Firebase client');
      if (!scope.resourceNode) {
        const resourceLabel = scope.resourceLabel ??= `${kind} rules ${path}`;
        const resourceNode: GraphNode = {
          id: resource,
          kind: 'resource',
          label: resourceLabel,
          location: { file, line },
        };
        scope.resourceNode = resourceNode;
        scope.resourceLineLex = `${line}}`;
        nodeList.push(resourceNode);
      } else if (scope.resourceNode.location) {
        const lex = `${line}}`;
        if (lex < (scope.resourceLineLex ??= `${scope.resourceNode.location.line}}`)) {
          scope.resourceNode.location.line = line;
          scope.resourceLineLex = lex;
        }
      }
      const dataLabel = scope.dataLabel ??= `${kind} data matching ${path}`;
      addNode(data, 'data', dataLabel, line);
      const firstFinding = (readFinding ?? writeFinding)!;
      const dataKind: GraphEdge['kind'] = effectivePublicRead ? 'read-data' : 'write-data';
      if (!collapseDuplicateEdges) {
        const findingIds: string[] = [];
        if (readFinding) findingIds.push(readFinding.id);
        if (writeFinding) findingIds.push(writeFinding.id);
        if (wildcardFinding) findingIds.push(wildcardFinding.id);
        graph.edges.push({ id: `${firstFinding.id}:entry`, from: entry, to: resource, kind: 'public-rule-grant',
          findingIds, evidence, confidence: 'confirmed' },
        { id: `${firstFinding.id}:data`, from: resource, to: data, kind: dataKind,
          findingIds, evidence, confidence: 'confirmed' });
      } else {
        accumulateEdge(`${firstFinding.id}:entry`, entry, resource, 'public-rule-grant', 'confirmed', evidence,
          readFinding, writeFinding, wildcardFinding);
        accumulateEdge(`${firstFinding.id}:data`, resource, data, dataKind, 'confirmed', evidence,
          readFinding, writeFinding, wildcardFinding);
      }
    }
    if (kind === 'firestore' && writeCreateUpdate &&
      /request\.auth/.test(expandedCondition) &&
      /\/(?:users|profiles|accounts|members)(?:\/\{[^/}]+\})?$/i.test(path) &&
      !/\.hasOnly\s*\(|!\s*request\.resource\.data[\s\S]*?\.hasAny\s*\(|\b(?:role|isAdmin|adminStatus)\b/.test(expandedCondition)) {
      const finding = addFinding(graph, file, line, 'firebase/privilege-fields', 'medium',
        'User document writes lack an explicit field allowlist',
        'If this document stores trusted role or privilege fields, authenticated writers may be able to modify them. Function-based validation and application trust require review.', evidence);
      const authenticated = 'entry:firebase:authenticated';
      addNode(authenticated, 'entry', 'Authenticated Firebase client');
      addNode(data, 'data', scope.privFieldsLabel ??= `Potential privilege fields at ${path}`, line);
      if (!collapseDuplicateEdges) {
        graph.edges.push({ id: finding.id, from: authenticated, to: data, kind: 'potential-privilege-field-write',
          findingIds: [finding.id], evidence, confidence: 'potential' });
      } else {
        accumulateEdge(finding.id, authenticated, data, 'potential-privilege-field-write', 'potential', evidence, finding);
      }
    }
  });
  if (collapseDuplicateEdges && edgeMap) {
    graph.edges = Array.from(edgeMap.values(), item => item.edge);
  }
  graph.nodes = nodeList;
  graph.limitations.push(`${file}: Static rules analysis recognizes literal public grants and potential field-allowlist omissions; it does not evaluate functions, compound expressions, rule validity, or deployed configuration.`);
  return graph;
}

export interface FirebaseConfigResult { graph: GraphResult; rulesFiles: string[] }

export function parseFirebaseConfig(source: string, file: string): FirebaseConfigResult {
  const graph = emptyGraph(), rulesFiles: string[] = [];
  try {
    const config: unknown = JSON.parse(source);
    if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('Expected an object');
    for (const service of ['firestore', 'storage']) {
      const value = (config as Record<string, unknown>)[service];
      for (const entry of Array.isArray(value) ? value : value === undefined ? [] : [value]) {
        if (!entry || typeof entry !== 'object' || Array.isArray(entry)) throw new Error(`Invalid ${service} configuration`);
        const rules = (entry as Record<string, unknown>).rules;
        if (rules !== undefined && (typeof rules !== 'string' || !rules.trim())) throw new Error(`Invalid ${service} rules path`);
        if (typeof rules === 'string') rulesFiles.push(rules);
      }
    }
  } catch {
    addFinding(graph, file, 1, 'scan/invalid-input', 'high', 'Invalid Firebase configuration',
      'firebase.json must be valid JSON with string rules paths in supported service configurations.', 'Invalid configuration shape or JSON');
  }
  return { graph, rulesFiles };
}
