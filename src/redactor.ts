export interface RedactionResult {
  redactedText: string;
  redactionCount: number;
}

export interface LinePreservingRedactionResult {
  redactedText: string;
  redactedLines: string[];
  redactedLineNumbers: number[];
  redactionCount: number;
}

/**
 * Shared canonical keyword alternation for secret-bearing variable, property, and env names.
 * Supports both SCREAMING_SNAKE_CASE, kebab-case, and camelCase identifiers across all 4 stacks.
 */
export const SECRET_KEYWORD_GROUP =
  '(?:PASS(?:WORD|WD)|SECRET|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?TOKEN|AUTH[_-]?TOKEN|REFRESH[_-]?TOKEN|SESSION[_-]?TOKEN|ID[_-]?TOKEN|BEARER[_-]?TOKEN|API[_-]?TOKEN|GITHUB[_-]?TOKEN|SLACK[_-]?TOKEN|CLIENT[_-]?SECRET|MASTER[_-]?KEY|SIGNING[_-]?KEY|ENCRYPTION[_-]?KEY|ADMIN[_-]?KEY|SERVICE[_-]?ROLE|CREDENTIAL|WEBHOOK[_-]?SECRET|DATABASE[_-]?URL|CONNECTION[_-]?STRING|PRIVATE)';

/**
 * Shared client-exposed environment variable detector used identically by redactor.ts and rules.ts.
 */
export const PUBLIC_ENV_SECRET_RE = new RegExp(
  `\\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC)_[A-Za-z0-9_]*${SECRET_KEYWORD_GROUP}[A-Za-z0-9_]*\\b`,
  'i',
);

const SECRET_IDENT_RE = new RegExp(
  `^[A-Za-z0-9_.-]*${SECRET_KEYWORD_GROUP}[A-Za-z0-9_.-]*$`,
  'i',
);

interface TokenShapePattern {
  regex: RegExp;
  replacement: string | ((substring: string, ...args: string[]) => string);
}

const TOKEN_SHAPE_PATTERNS: readonly TokenShapePattern[] = [
  {
    regex: /\bAIza[0-9A-Za-z\-_]{33,40}\b/g,
    replacement: '[REDACTED_GCP_API_KEY]',
  },
  {
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    replacement: '[REDACTED_AWS_KEY]',
  },
  {
    regex: /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g,
    replacement: '[REDACTED_GITHUB_TOKEN]',
  },
  {
    regex: /\b(?:xox[baprs]-[A-Za-z0-9-]{10,}|sk-(?:live|test|proj)?-?[A-Za-z0-9_-]{20,}|rk_live_[A-Za-z0-9]{16,}|ya29\.[0-9A-Za-z\-_]{20,})\b/g,
    replacement: '[REDACTED_API_TOKEN]',
  },
  {
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    replacement: '[REDACTED_JWT]',
  },
  {
    regex: /\b(Bearer\s+)(?!\[REDACTED|\$\{|\$\()([A-Za-z0-9._~+/=-]{12,})\b/gi,
    replacement: (_m: string, prefix: string) => `${prefix}[REDACTED_BEARER_TOKEN]`,
  },
  {
    // Connection URLs with embedded user:password@host
    regex: /\b([a-z][a-z0-9+.-]*:\/\/[^/\s:@'"]+:)(?!\[REDACTED)([^@\s/'"]+)(@)/gi,
    replacement: (_m: string, prefix: string, _secret: string, at: string) =>
      `${prefix}[REDACTED_URL_SECRET]${at}`,
  },
  {
    // Query-string secret parameters (?api_key=... or &access_token=...)
    regex: new RegExp(
      `([?&][A-Za-z0-9_.-]*${SECRET_KEYWORD_GROUP}[A-Za-z0-9_.-]*=)(?!\\[REDACTED|\\$\\{|\\$\\()([^&\\s'"\`#]+)`,
      'gi',
    ),
    replacement: (_m: string, prefix: string) => `${prefix}[REDACTED_QUERY_SECRET]`,
  },
];

const PEM_BEGIN_RE =
  /-----BEGIN [A-Z0-9 ]*(?:PRIVATE KEY|SECRET|PGP PRIVATE|RSA PRIVATE|EC PRIVATE|OPENSSH PRIVATE)[A-Z0-9 ]*-----/;
const PEM_END_RE =
  /-----END [A-Z0-9 ]*(?:PRIVATE KEY|SECRET|PGP PRIVATE|RSA PRIVATE|EC PRIVATE|OPENSSH PRIVATE)[A-Z0-9 ]*-----/;

type QuoteDelimiter = '"""' | "'''" | '"' | "'" | '`';

type MultilineSecretState =
  | { kind: 'pem'; counted: boolean }
  | { kind: 'quote'; delimiter: QuoteDelimiter }
  | { kind: 'backslash' }
  | { kind: 'yaml_block'; baseIndent: number }
  | { kind: 'pending_rhs' };

function detectOpeningQuote(text: string, index: number): QuoteDelimiter | null {
  if (text.startsWith('"""', index)) return '"""';
  if (text.startsWith("'''", index)) return "'''";
  const ch = text[index];
  if (ch === '"' || ch === "'" || ch === '`') return ch;
  return null;
}

/**
 * Character-level quote scanner that respects backslash escapes (e.g. \" and \\").
 * Returns the index of the matching closing delimiter on the same line, or -1 if unclosed.
 */
function findClosingQuoteOnLine(
  text: string,
  contentStart: number,
  delimiter: QuoteDelimiter,
): number {
  let i = contentStart;
  while (i < text.length) {
    if (text[i] === '\\') {
      i += 2;
      continue;
    }
    if (text.startsWith(delimiter, i)) {
      return i;
    }
    i += 1;
  }
  return -1;
}

function endsWithUnescapedBackslash(text: string): boolean {
  let backslashes = 0;
  for (let i = text.length - 1; i >= 0 && text[i] === '\\'; i--) {
    backslashes += 1;
  }
  return backslashes % 2 === 1;
}

const PURE_DYNAMIC_REF_RE =
  /^(?:\$\([A-Za-z0-9_.\s/=-]+\)|\$\{\s*[A-Za-z_][A-Za-z0-9_.\[\]'"]*\s*\}|\$\{\{\s*[A-Za-z_][A-Za-z0-9_.]*\s*\}\}|\$[A-Za-z_][A-Za-z0-9_]*)$/;

const LEADING_PURE_DYNAMIC_REF_RE =
  /^(?:\$\([A-Za-z0-9_.\s/=-]+\)|\$\{\s*[A-Za-z_][A-Za-z0-9_.\[\]'"]*\s*\})/;

function isDynamicOrAlreadyRedacted(val: string): boolean {
  const trimmed = val.trim();
  if (!trimmed) return true;
  if (trimmed.includes('[REDACTED')) return true;
  return PURE_DYNAMIC_REF_RE.test(trimmed);
}

function isTrivialBenignEnvLiteral(val: string): boolean {
  const trimmed = val.trim();
  return /^(?:true|false|null|none|development|production|staging|test|localhost|127\.0\.0\.1|\d+)$/i.test(
    trimmed,
  );
}

const ENV_LINE_ASSIGNMENT_RE = /^(\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*)(.*)$/;

/**
 * Matches secret-bearing LHS contexts:
 * 1. Quoted or unquoted object/config/env/bracket assignments, TS/Python type annotations,
 *    Go `:=` / `var x string =`, & fallback operators (`??`, `||`):
 *    `"NEXT_PUBLIC_ADMIN_KEY": `, `const NEXT_PUBLIC_ADMIN_KEY: string = `, `apiSecret := `
 * 2. Dockerfile `ENV SECRET_KEY ...` / `ARG SECRET_KEY=...`
 */
const SECRET_LHS_OPERATOR_RE = new RegExp(
  `(?:^\\s*(?:ENV|ARG)\\s+([A-Za-z0-9_]*${SECRET_KEYWORD_GROUP}[A-Za-z0-9_]*)(\\s*=\\s*|\\s+)|(['"\`]?)([A-Za-z0-9_.-]*${SECRET_KEYWORD_GROUP}[A-Za-z0-9_.-]*)\\3(?:\\s*\\])?(?:\\s*:\\s*[^='"\\x60;{\\r\\n]{1,64}\\s*(=)|\\s+[A-Za-z0-9_.*\\[\\]]+\\s*(=)|\\s*(:=|\\?\\?|\\|\\||===|!==|==|!=|[:=])(?![=>]))\\s*)`,
  'gi',
);

/**
 * Matches setter calls passing a secret key name as 1st string arg and literal secret as 2nd string arg:
 * e.g. `prefs.setString('session_token', 'secret')`, `os.Setenv("API_KEY", "secret")`, `write(key: 'auth_token', value: 'secret')`
 */
const SECRET_CALL_ARG_PAIR_RE = new RegExp(
  `(\\b(?:setString|Setenv|setenv|putenv|setItem|write|put|setHeader)\\s*\\(\\s*(?:key\\s*:\\s*)?(['"\`])[A-Za-z0-9_.-]*(?:${SECRET_KEYWORD_GROUP}|TOKEN|AUTHORIZATION)[A-Za-z0-9_.-]*\\2\\s*,\\s*(?:value\\s*:\\s*)?)(?=['"\`])`,
  'gi',
);

function applyTokenShapePatterns(line: string): { text: string; count: number } {
  let current = line;
  let count = 0;

  for (const { regex, replacement } of TOKEN_SHAPE_PATTERNS) {
    const cloned = new RegExp(regex.source, regex.flags);
    const matches = current.match(cloned);
    if (matches && matches.length > 0) {
      count += matches.length;
      if (typeof replacement === 'string') {
        current = current.replace(cloned, replacement);
      } else {
        current = current.replace(cloned, replacement);
      }
    }
  }
  return { text: current, count };
}

function redactQuotedOrContinuationAt(
  line: string,
  rhsStart: number,
  placeholder: string,
): {
  handled: boolean;
  newLine: string;
  nextCursor: number;
  countDelta: number;
  nextState: MultilineSecretState | null;
} {
  const delim = detectOpeningQuote(line, rhsStart);
  if (!delim) {
    return {
      handled: false,
      newLine: line,
      nextCursor: rhsStart,
      countDelta: 0,
      nextState: null,
    };
  }

  const contentStart = rhsStart + delim.length;
  const closeIdx = findClosingQuoteOnLine(line, contentStart, delim);

  if (closeIdx === -1) {
    // Multiline quoted secret continues onto subsequent lines
    const before = line.slice(0, contentStart);
    const replaced = `${before}${placeholder}`;
    return {
      handled: true,
      newLine: replaced,
      nextCursor: replaced.length,
      countDelta: 1,
      nextState: { kind: 'quote', delimiter: delim },
    };
  }

  const inner = line.slice(contentStart, closeIdx);
  if (isDynamicOrAlreadyRedacted(inner)) {
    return {
      handled: true,
      newLine: line,
      nextCursor: closeIdx + delim.length,
      countDelta: 0,
      nextState: null,
    };
  }

  const before = line.slice(0, contentStart);
  const after = line.slice(closeIdx);
  const newLine = `${before}${placeholder}${after}`;
  const nextCursor = before.length + placeholder.length + delim.length;
  return {
    handled: true,
    newLine,
    nextCursor,
    countDelta: 1,
    nextState: null,
  };
}

function isLookupKeyContext(prefixBeforeQuote: string): boolean {
  return (
    /[A-Za-z0-9_$)\]]\s*\[\s*$/.test(prefixBeforeQuote) ||
    /\b(?:getElementById|querySelector|querySelectorAll|getAttribute|Getenv|getenv|hasOwnProperty)\s*\(\s*$/i.test(
      prefixBeforeQuote,
    )
  );
}

/**
 * Checks whether `targetPos` lies inside an already-open string/template literal on `line`.
 * If so, returns that outer delimiter so we never mistake its closing quote for a new opening quote.
 */
function findEnclosingQuoteBefore(line: string, targetPos: number): QuoteDelimiter | null {
  let i = 0;
  let active: QuoteDelimiter | null = null;
  while (i < targetPos) {
    if (line[i] === '\\') {
      i += 2;
      continue;
    }
    if (active !== null) {
      if (line.startsWith(active, i)) {
        i += active.length;
        active = null;
        continue;
      }
      i += 1;
      continue;
    }
    const opened = detectOpeningQuote(line, i);
    if (opened !== null) {
      active = opened;
      i += opened.length;
      continue;
    }
    i += 1;
  }
  return active;
}

function redactQuotesInRhsExpression(
  line: string,
  exprStart: number,
  stopAtTopLevelComma: boolean,
  outerDelimiter: QuoteDelimiter | null,
): {
  handled: boolean;
  newLine: string;
  nextCursor: number;
  countDelta: number;
  nextState: MultilineSecretState | null;
} {
  const trimmedStart = line.slice(exprStart).trimStart();
  if (LEADING_PURE_DYNAMIC_REF_RE.test(trimmedStart)) {
    return {
      handled: false,
      newLine: line,
      nextCursor: exprStart,
      countDelta: 0,
      nextState: null,
    };
  }

  let current = line;
  let i = exprStart;
  let depth = 0;
  let countDelta = 0;
  let handledAnyQuote = false;

  while (i < current.length) {
    if (outerDelimiter !== null && depth === 0 && current.startsWith(outerDelimiter, i)) {
      break;
    }
    const ch = current[i];
    if (ch === '/' && current[i + 1] === '/') break;
    if (depth === 0 && (ch === ';' || (stopAtTopLevelComma && (ch === ',' || ch === '}')))) {
      break;
    }
    if (ch === '(' || ch === '[' || ch === '{') {
      depth += 1;
      i += 1;
      continue;
    }
    if (ch === ')' || ch === ']' || ch === '}') {
      if (depth === 0) break;
      depth -= 1;
      i += 1;
      continue;
    }

    const delim = detectOpeningQuote(current, i);
    if (delim) {
      if (outerDelimiter !== null && delim === outerDelimiter) {
        break;
      }
      handledAnyQuote = true;
      if (isLookupKeyContext(current.slice(0, i))) {
        const skipClose = findClosingQuoteOnLine(current, i + delim.length, delim);
        if (skipClose === -1) {
          return {
            handled: true,
            newLine: current,
            nextCursor: current.length,
            countDelta,
            nextState: null,
          };
        }
        i = skipClose + delim.length;
        continue;
      }

      const quoted = redactQuotedOrContinuationAt(current, i, '[REDACTED_SECRET]');
      current = quoted.newLine;
      countDelta += quoted.countDelta;
      i = quoted.nextCursor;
      if (quoted.nextState) {
        return {
          handled: true,
          newLine: current,
          nextCursor: current.length,
          countDelta,
          nextState: quoted.nextState,
        };
      }
      continue;
    }
    i += 1;
  }

  return {
    handled: handledAnyQuote,
    newLine: current,
    nextCursor: i,
    countDelta,
    nextState: null,
  };
}

function redactGeneralCodeLine(
  inputLine: string,
): { text: string; count: number; nextState: MultilineSecretState | null } {
  const shaped = applyTokenShapePatterns(inputLine);
  let current = shaped.text;
  let count = shaped.count;
  let nextState: MultilineSecretState | null = null;

  // 1. Scan LHS secret assignments / properties / fallback operators left-to-right
  let searchPos = 0;
  while (searchPos < current.length) {
    const lhsRe = new RegExp(SECRET_LHS_OPERATOR_RE.source, 'gi');
    lhsRe.lastIndex = searchPos;
    const match = lhsRe.exec(current);
    if (!match) break;

    const dockerIdent = match[1];
    const dockerOp = match[2];
    const keyQuote = match[3] ?? '';
    const typedEq = match[5];
    const goTypedEq = match[6];
    const generalOp = match[7] ?? '';
    const operator = dockerIdent
      ? dockerOp?.includes('=')
        ? '='
        : 'ENV'
      : (typedEq ?? goTypedEq ?? generalOp);
    const rhsStart = match.index + match[0].length;
    const rest = current.slice(rhsStart);

    // 1a. Direct or expression-embedded quoted string literals on RHS (single-line, ternary, or multiline)
    const outerDelimiter = findEnclosingQuoteBefore(current, match.index);
    const exprQuoted = redactQuotesInRhsExpression(
      current,
      rhsStart,
      operator === ':',
      outerDelimiter,
    );
    if (exprQuoted.handled) {
      current = exprQuoted.newLine;
      count += exprQuoted.countDelta;
      searchPos = Math.max(rhsStart + 1, exprQuoted.nextCursor);
      if (exprQuoted.nextState) {
        nextState = exprQuoted.nextState;
        return { text: current, count, nextState };
      }
      continue;
    }

    // 1b. YAML block scalar (`|`, `>`, `|-2`, `|2+`, etc.) on colon property
    if (operator === ':' && /^[|>](?:[+-]?[1-9]?|[1-9]?[+-]?)\s*(?:#.*)?$/.test(rest)) {
      const indentMatch = current.match(/^(\s*)/);
      const baseIndent = indentMatch?.[1]?.length ?? 0;
      nextState = { kind: 'yaml_block', baseIndent };
      count += 1;
      return { text: current, count, nextState };
    }

    // 1c. Empty RHS at end of line (`"NEXT_PUBLIC_ADMIN_KEY":\n  "secret"`)
    if (
      (operator === ':' || operator === '=' || operator === '??' || operator === '||') &&
      /^\s*(?:\/\/.*|#.*)?$/.test(rest)
    ) {
      // Avoid flagging TS interface/type lines (`foo?:` has `?` before `:`)
      const charBeforeMatch = match.index > 0 ? current[match.index - 1] : '';
      if (charBeforeMatch !== '?') {
        nextState = { kind: 'pending_rhs' };
      }
      searchPos = current.length;
      break;
    }

    // 1d. Unquoted RHS for `=`, `ENV`, or YAML `:`
    if (operator === '=' || operator === 'ENV') {
      const trimmedRest = rest.trim();
      if (LEADING_PURE_DYNAMIC_REF_RE.test(trimmedRest)) {
        searchPos = rhsStart + 2;
        continue;
      }
      // Exclude code statements ending with `;` or function calls `(...)` or member chains `obj.prop`
      const tokenMatch = rest.match(/^([^\s#'"`,;\\()]+)(.*)$/);
      const rawToken = tokenMatch?.[1] ?? '';
      const trailing = tokenMatch?.[2] ?? '';
      const looksLikeCodeExpr =
        trimmedRest.endsWith(';') ||
        rawToken.includes('(') ||
        /^(?:process\.env|os\.environ|os\.Getenv|true|false|null|undefined|None|nil|\d+|[A-Za-z_$][A-Za-z0-9_$]*\.[A-Za-z_$][A-Za-z0-9_$.]*)$/.test(
          rawToken,
        );

      if (rawToken.length >= 3 && !looksLikeCodeExpr && !isDynamicOrAlreadyRedacted(rawToken)) {
        const hasBackslashCont = endsWithUnescapedBackslash(rest.trimEnd());
        const replacement = hasBackslashCont ? '[REDACTED_SECRET] \\' : `[REDACTED_SECRET]${trailing}`;
        current = `${current.slice(0, rhsStart)}${replacement}`;
        count += 1;
        if (hasBackslashCont) {
          nextState = { kind: 'backslash' };
          return { text: current, count, nextState };
        }
        searchPos = rhsStart + '[REDACTED_SECRET]'.length;
        continue;
      }
    } else if (operator === ':' && keyQuote === '') {
      // Unquoted YAML `api_secret: raw-value` (not ending with `;` or `,` or `{`)
      const yamlValMatch = rest.match(/^([^\s#'"`,;{}[\]()]{4,})(\s*(?:#.*)?)$/);
      const rawYamlVal = yamlValMatch?.[1] ?? '';
      const yamlTrailing = yamlValMatch?.[2] ?? '';
      const isTypeOrConst =
        /^(?:true|false|null|string|number|boolean|unknown|never|void|any|object|\d+|[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*)$/i.test(
          rawYamlVal,
        );
      if (rawYamlVal && !isTypeOrConst && !isDynamicOrAlreadyRedacted(rawYamlVal)) {
        current = `${current.slice(0, rhsStart)}[REDACTED_SECRET]${yamlTrailing}`;
        count += 1;
        searchPos = current.length;
        continue;
      }
    }

    searchPos = rhsStart;
  }

  // 2. Scan setter calls (`setString('session_token', 'secret')`, `Setenv("API_KEY", "secret")`)
  let callPos = 0;
  while (callPos < current.length) {
    const callRe = new RegExp(SECRET_CALL_ARG_PAIR_RE.source, 'gi');
    callRe.lastIndex = callPos;
    const callMatch = callRe.exec(current);
    if (!callMatch) break;

    const valStart = callMatch.index + callMatch[0].length;
    const quoted = redactQuotedOrContinuationAt(current, valStart, '[REDACTED_SECRET]');
    if (quoted.handled) {
      current = quoted.newLine;
      count += quoted.countDelta;
      callPos = quoted.nextCursor;
      if (quoted.nextState) {
        nextState = quoted.nextState;
        return { text: current, count, nextState };
      }
      continue;
    }
    callPos = valStart + 1;
  }

  return { text: current, count, nextState };
}

function redactEnvLine(
  inputLine: string,
): { text: string; count: number; nextState: MultilineSecretState | null } {
  const trimmed = inputLine.trim();
  if (!trimmed || trimmed.startsWith('#')) {
    return { text: inputLine, count: 0, nextState: null };
  }

  const envMatch = inputLine.match(ENV_LINE_ASSIGNMENT_RE);
  if (!envMatch) {
    return redactGeneralCodeLine(inputLine);
  }

  const prefix = envMatch[1] ?? '';
  const keyName = envMatch[2] ?? '';
  const rhs = envMatch[3] ?? '';
  const isSecretKey = SECRET_IDENT_RE.test(keyName) || PUBLIC_ENV_SECRET_RE.test(keyName);
  const placeholder = isSecretKey ? '[REDACTED_SECRET]' : '[REDACTED_ENV_VALUE]';

  if (!rhs.trim() || rhs.trim().startsWith('#')) {
    return { text: inputLine, count: 0, nextState: null };
  }

  const rhsStart = prefix.length;
  const delim = detectOpeningQuote(inputLine, rhsStart);
  if (delim) {
    const contentStart = rhsStart + delim.length;
    const closeIdx = findClosingQuoteOnLine(inputLine, contentStart, delim);
    if (closeIdx === -1) {
      return {
        text: `${prefix}${delim}${placeholder}`,
        count: 1,
        nextState: { kind: 'quote', delimiter: delim },
      };
    }

    const inner = inputLine.slice(contentStart, closeIdx);
    if (
      isDynamicOrAlreadyRedacted(inner) ||
      (!isSecretKey && isTrivialBenignEnvLiteral(inner))
    ) {
      return { text: inputLine, count: 0, nextState: null };
    }

    const afterQuote = inputLine.slice(closeIdx);
    return {
      text: `${prefix}${delim}${placeholder}${afterQuote}`,
      count: 1,
      nextState: null,
    };
  }

  // Unquoted .env value (strip optional inline ` # comment`)
  const commentMatch = rhs.match(/^(.*?)(\s+#.*)?$/);
  const rawVal = (commentMatch?.[1] ?? rhs).trimEnd();
  const commentSuffix = commentMatch?.[2] ?? '';

  if (endsWithUnescapedBackslash(rawVal)) {
    return {
      text: `${prefix}${placeholder} \\${commentSuffix}`,
      count: 1,
      nextState: { kind: 'backslash' },
    };
  }

  if (
    isDynamicOrAlreadyRedacted(rawVal) ||
    (!isSecretKey && isTrivialBenignEnvLiteral(rawVal))
  ) {
    return { text: inputLine, count: 0, nextState: null };
  }

  return {
    text: `${prefix}${placeholder}${commentSuffix}`,
    count: 1,
    nextState: null,
  };
}

/**
 * Redacts multiline PEM keys, multiline quoted .env/code strings, backslash continuations,
 * YAML block scalars, and single-line credentials across an entire file BEFORE any snippet
 * slicing occurs, preserving exact 1-based line numbers.
 */
export function redactSecretsPreserveLines(
  input: string,
  options?: { isEnvFile?: boolean },
): LinePreservingRedactionResult {
  const isEnvFile = options?.isEnvFile === true;
  const rawLines = input.split(/\r?\n/);
  const redactedLines: string[] = [];
  const redactedLineNumbers: number[] = [];
  let redactionCount = 0;
  let state: MultilineSecretState | null = null;

  const markLineRedacted = (lineNo: number, deltaCount: number): void => {
    if (deltaCount > 0) {
      redactionCount += deltaCount;
    }
    if (redactedLineNumbers[redactedLineNumbers.length - 1] !== lineNo) {
      redactedLineNumbers.push(lineNo);
    }
  };

  for (let idx = 0; idx < rawLines.length; idx++) {
    const lineNo = idx + 1;
    const line = rawLines[idx] ?? '';

    // 1. Handle active multiline states first
    if (state !== null) {
      if (state.kind === 'pem') {
        markLineRedacted(lineNo, state.counted ? 0 : 1);
        state.counted = true;
        redactedLines.push('[REDACTED_PRIVATE_KEY]');
        if (PEM_END_RE.test(line)) {
          state = null;
        }
        continue;
      }

      if (state.kind === 'quote') {
        const closeIdx = findClosingQuoteOnLine(line, 0, state.delimiter);
        markLineRedacted(lineNo, 0);
        if (closeIdx === -1) {
          redactedLines.push('[REDACTED_MULTILINE_SECRET]');
          continue;
        }
        const remainder = line.slice(closeIdx + state.delimiter.length);
        const closedPrefix = `[REDACTED_MULTILINE_SECRET]${state.delimiter}`;
        state = null;
        if (!remainder.trim()) {
          redactedLines.push(`${closedPrefix}${remainder}`);
          continue;
        }
        const tailRes = isEnvFile ? redactEnvLine(remainder) : redactGeneralCodeLine(remainder);
        if (tailRes.count > 0) {
          redactionCount += tailRes.count;
        }
        state = tailRes.nextState;
        redactedLines.push(`${closedPrefix}${tailRes.text}`);
        continue;
      }

      if (state.kind === 'backslash') {
        markLineRedacted(lineNo, 0);
        const trimmedEnd = line.trimEnd();
        if (endsWithUnescapedBackslash(trimmedEnd)) {
          redactedLines.push('[REDACTED_MULTILINE_SECRET] \\');
        } else {
          redactedLines.push('[REDACTED_MULTILINE_SECRET]');
          state = null;
        }
        continue;
      }

      if (state.kind === 'yaml_block') {
        if (!line.trim()) {
          redactedLines.push('');
          continue;
        }
        const indentMatch = line.match(/^(\s*)/);
        const indentLen = indentMatch?.[1]?.length ?? 0;
        if (indentLen > state.baseIndent) {
          markLineRedacted(lineNo, 0);
          redactedLines.push(`${' '.repeat(indentLen)}[REDACTED_MULTILINE_SECRET]`);
          continue;
        }
        // Dedented back out of YAML block scalar — fall through to normal processing
        state = null;
      } else if (state.kind === 'pending_rhs') {
        state = null;
        const firstNonWs = line.search(/\S/);
        if (firstNonWs >= 0 && detectOpeningQuote(line, firstNonWs) !== null) {
          const quoted = redactQuotedOrContinuationAt(line, firstNonWs, '[REDACTED_SECRET]');
          if (quoted.handled) {
            markLineRedacted(lineNo, Math.max(1, quoted.countDelta));
            state = quoted.nextState;
            redactedLines.push(quoted.newLine);
            continue;
          }
        }
      }
    }

    // 2. Detect start of PEM / Private Key block
    if (PEM_BEGIN_RE.test(line)) {
      const beginPos = line.search(PEM_BEGIN_RE);
      const prefixPart =
        beginPos > 0
          ? (isEnvFile ? redactEnvLine(line.slice(0, beginPos)) : redactGeneralCodeLine(line.slice(0, beginPos))).text
          : '';
      markLineRedacted(lineNo, 1);
      redactedLines.push(`${prefixPart}[REDACTED_PRIVATE_KEY]`);
      if (!PEM_END_RE.test(line)) {
        state = { kind: 'pem', counted: true };
      }
      continue;
    }

    // 3. Standard line-level & multiline-opening lexical redaction
    const res = isEnvFile ? redactEnvLine(line) : redactGeneralCodeLine(line);
    if (res.count > 0) {
      markLineRedacted(lineNo, res.count);
    }
    state = res.nextState;
    redactedLines.push(res.text);
  }

  return {
    redactedText: redactedLines.join('\n'),
    redactedLines,
    redactedLineNumbers,
    redactionCount,
  };
}

/**
 * Convenience wrapper for string-level redaction.
 */
export function redactSecrets(input: string, options?: { isEnvFile?: boolean }): RedactionResult {
  const res = redactSecretsPreserveLines(input, options);
  return {
    redactedText: res.redactedText,
    redactionCount: res.redactionCount,
  };
}

/**
 * Verified, pre-audited defensive remediation templates.
 * Gemini structured output selects a template ID rather than emitting free-form scripts.
 */
export const DEFENSIVE_PATCH_TEMPLATES = Object.freeze({
  CSP_NONCE_TRUSTED_TYPES: `// 防御パッチ: DOM 文字列代入を廃止し Per-request CSP Nonce + Trusted Types を強制
element.textContent = untrustedText;
// Content-Security-Policy: default-src 'self'; script-src 'nonce-<RANDOM>' 'strict-dynamic'; object-src 'none'; base-uri 'none'; require-trusted-types-for 'script';`,
  EXECFILE_NO_SHELL: `// 防御パッチ: シェルを介さない execFile 固定配列と厳格な入力ホワイトリスト検証
import { execFile } from 'node:child_process';
execFile('/usr/bin/git', ['status', '--', validatedPath], { shell: false, timeout: 5000 }, callback);`,
  CORS_STRICT_ALLOWLIST: `// 防御パッチ: 固定オリジン Allowlist + Vary: Origin + Sec-Fetch-Site 検証
const ALLOWED_ORIGINS = new Set(['https://app.example.com']);
res.setHeader('Vary', 'Origin, Sec-Fetch-Site');
if (req.headers.origin && ALLOWED_ORIGINS.has(req.headers.origin)) {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
}`,
  FIRESTORE_DENY_BY_DEFAULT: `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} { allow read, write: if false; }
    match /users/{uid} {
      allow read, update: if request.auth != null && request.auth.uid == uid
        && request.resource.data.keys().hasOnly(['displayName', 'updatedAt']);
    }
  }
}`,
  FIREBASE_APPCHECK_ONCALL: `// 防御パッチ: Firebase App Check 強制 + 認証 UID 検証
export const protectedFn = onCall({ enforceAppCheck: true, cors: ['https://app.example.com'] }, async (req) => {
  if (!req.auth?.uid) throw new HttpsError('unauthenticated', 'Auth required');
});`,
  FLUTTER_SECURE_STORAGE_TLS: `// 防御パッチ: OS 標準 TLS 証明書検証を維持し、トークンは FlutterSecureStorage (Keychain/Keystore) に保存
const storage = FlutterSecureStorage(aOptions: AndroidOptions(encryptedSharedPreferences: true));
await storage.write(key: 'session_token', value: token);`,
  DOCKER_DISTROLESS_NONROOT: `# 防御パッチ: ダイジェスト固定 + Distroless nonroot ユーザー実行
FROM gcr.io/distroless/nodejs22-debian12:nonroot
WORKDIR /app
COPY --chown=nonroot:nonroot dist/ ./dist/
USER nonroot:nonroot`,
  CLOUDRUN_IAM_INTERNAL: `# 防御パッチ: 未認証公開を無効化し Cloud Armor + IAM 最小権限サービスアカウントを適用
gcloud run services update service-name --no-allow-unauthenticated --ingress=internal-and-cloud-load-balancing`,
  GO_HTTP_SERVER_TIMEOUTS: `// 防御パッチ: 明示的 ReadHeaderTimeout / ReadTimeout / MaxHeaderBytes 設定
srv := &http.Server{ Addr: "127.0.0.1:8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, MaxHeaderBytes: 1 << 16 }`,
  SECRET_MANAGER_ROTATION: `# 防御パッチ: ハードコードされた鍵を即時失効・ローテーションし Secret Manager 実行時注入へ移行
# .gitignore に .env* を登録し、クライアント公開プレフィックス (NEXT_PUBLIC_ 等) から秘密鍵を完全排除`,
  GITHUB_ACTIONS_SHA_PIN: `# 防御パッチ: pull_request_target を排除し、最小 permissions と 40桁フルコミット SHA 固定を適用
permissions:
  contents: read
steps:
  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`,
  LOCKFILE_FROZEN_CI: `# 防御パッチ: 暗号学的ロックファイルをリポジトリにコミットし CI で frozen-lockfile を強制
pnpm install --frozen-lockfile`,
} as const);

export type DefensivePatchTemplateId = keyof typeof DEFENSIVE_PATCH_TEMPLATES;
