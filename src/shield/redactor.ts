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
  '(?:PASS(?:WORD|WD)|PWD|DSN|SECRET|API[_-]?KEY|PRIVATE[_-]?KEY|ACCESS[_-]?TOKEN|AUTH[_-]?TOKEN|REFRESH[_-]?TOKEN|SESSION[_-]?TOKEN|ID[_-]?TOKEN|BEARER[_-]?TOKEN|API[_-]?TOKEN|GITHUB[_-]?TOKEN|SLACK[_-]?TOKEN|CLIENT[_-]?SECRET|MASTER[_-]?KEY|SIGNING[_-]?KEY|ENCRYPTION[_-]?KEY|ADMIN[_-]?KEY|SERVICE[_-]?ROLE|CREDENTIAL|WEBHOOK[_-]?SECRET|DATABASE[_-]?URL|CONNECTION[_-]?STRING|PRIVATE)';

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
    // Connection URLs with embedded user:password@host or empty-user :password@host (e.g. redis://:pass@host)
    regex: /\b([a-z][a-z0-9+.-]*:\/\/[^/\s:@'"]*:)(?!\[REDACTED)([^@\s/'"]+)(@)/gi,
    replacement: (_m: string, prefix: string, _secret: string, at: string) =>
      `${prefix}[REDACTED_URL_SECRET]${at}`,
  },
  {
    // Semicolon-delimited connection string credentials after ';' (e.g. Host=db;Password=SECRET; or ;Pwd=SECRET)
    regex:
      /(;[ \t]*(?:Password|Passwd|Pwd|SharedAccessKey|AccountKey|SecretKey|AccessKey)\s*=\s*)(?!\[REDACTED|\$\{|\$\()([^;'"`\r\n]+)/gi,
    replacement: (_m: string, prefix: string) => `${prefix}[REDACTED_CONN_SECRET]`,
  },
  {
    // Semicolon-delimited connection string credentials at start followed by ';' (e.g. Password=SECRET;Host=db)
    regex:
      /\b((?:Password|Passwd|Pwd|SharedAccessKey|AccountKey|SecretKey|AccessKey)\s*=\s*)(?!\[REDACTED|\$\{|\$\()([^;'"`\s\r\n]+)(?=;)/gi,
    replacement: (_m: string, prefix: string) => `${prefix}[REDACTED_CONN_SECRET]`,
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
  | {
      kind: 'pending_rhs';
      operator: string;
      baseIndent: number;
      remainingLines: number;
      inParens?: boolean;
      awaitLeadingOp?: boolean;
    }
  | { kind: 'pending_call'; stage: 'await_key' | 'await_val'; remainingLines: number }
  | { kind: 'pending_env_entry'; baseIndent: number; remainingLines: number };

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
  if (/^\.{2,}$/.test(trimmed)) return true;
  if (/^(?:\\[nrt0])+$/.test(trimmed)) return true;
  if (trimmed.includes('[REDACTED')) return true;
  return PURE_DYNAMIC_REF_RE.test(trimmed);
}

function isTrivialBenignEnvLiteral(val: string): boolean {
  const trimmed = val.trim();
  return /^(?:true|false|null|none|development|production|staging|test|localhost|127\.0\.0\.1|\d+)$/i.test(
    trimmed,
  );
}

function isBenignYamlScalar(val: string): boolean {
  const trimmed = val.trim();
  return (
    trimmed === '' ||
    trimmed === '{}' ||
    trimmed === '[]' ||
    trimmed === '{' ||
    trimmed === '[' ||
    /^(?:true|false|null|none|~|read|write|string|number|boolean|unknown|never|void|any|object|\d+(?:\.\d+)?|[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*)$/i.test(
      trimmed,
    )
  );
}

const ENV_LINE_ASSIGNMENT_RE = /^(\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*)(.*)$/;

/**
 * Matches secret-bearing LHS contexts:
 * 1. Dockerfile `ENV SECRET_KEY ...` / `ARG SECRET_KEY=...`
 * 2. Go explicit typed `var apiSecret string = ...` / `const apiSecret string = ...`
 * 3. Quoted keys (`"auth.api_secret": ...`) allowing dots, or unquoted identifiers (`apiSecret := ...`,
 *    `const NEXT_PUBLIC_ADMIN_KEY: string = ...`, `process.env.ADMIN_KEY ?? ...`) without member-chain false matches.
 */
const SECRET_LHS_OPERATOR_RE = new RegExp(
  `(?:^\\s*(?:ENV|ARG)\\s+([A-Za-z0-9_]*${SECRET_KEYWORD_GROUP}[A-Za-z0-9_]*)(\\s*=\\s*|\\s+)|\\b(?:var|const)\\s+([A-Za-z0-9_]*${SECRET_KEYWORD_GROUP}[A-Za-z0-9_]*)\\s+[A-Za-z0-9_.*\\[\\]]+\\s*(=)\\s*|(?:(['"\`])([A-Za-z0-9_.-]*${SECRET_KEYWORD_GROUP}[A-Za-z0-9_.-]*)\\5|([A-Za-z0-9_-]*${SECRET_KEYWORD_GROUP}[A-Za-z0-9_-]*))(?:\\s*\\])?(?:\\s*:\\s*[A-Za-z_][A-Za-z0-9_<>\\[\\]|&\\s.?]{0,48}\\s*(=)(?!=)|\\s*(:=|\\?\\?|\\|\\||===|!==|==|!=|[:=])(?![=>]))\\s*)`,
  'gi',
);

const QUOTED_STRING_CODE_EXTS = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.py',
  '.go',
  '.dart',
  '.rs',
  '.java',
  '.kt',
  '.swift',
]);

const SECRET_CALL_FN_GROUP =
  '(?:\\b(?:setString|Setenv|setenv|putenv|setItem|write|put|setHeader|environ\\.get|environ\\.setdefault|os\\.getenv|getenv)|\\.set)';

/**
 * Matches setter or env-default calls passing a secret key name as 1st string arg and literal/expression secret as 2nd arg:
 * e.g. `prefs.setString('session_token', 'secret')`, `os.Setenv("API_KEY", "secret")`, `os.environ.get("API_KEY", "fallback")`, `headers.set("X-Api-Key", "secret")`
 */
const SECRET_CALL_ARG_PAIR_RE = new RegExp(
  `(${SECRET_CALL_FN_GROUP}\\s*\\(\\s*(?:key\\s*[:=]\\s*)?(['"\`])[A-Za-z0-9_.-]*(?:${SECRET_KEYWORD_GROUP}|TOKEN|AUTHORIZATION)[A-Za-z0-9_.-]*\\2\\s*,\\s*(?:(?:value|default)\\s*[:=]\\s*)?)`,
  'gi',
);

const SECRET_CALL_OPEN_EOL_RE = new RegExp(
  `${SECRET_CALL_FN_GROUP}\\s*\\(\\s*(?:\\/\\/.*|#.*)?$`,
  'i',
);

const SECRET_KEY_FIRST_ARG_LINE_RE = new RegExp(
  `^(\\s*(?:key\\s*[:=]\\s*)?(['"\`])[A-Za-z0-9_.-]*(?:${SECRET_KEYWORD_GROUP}|TOKEN|AUTHORIZATION)[A-Za-z0-9_.-]*\\2)(.*)$`,
  'i',
);

const YAML_ENV_NAME_LINE_RE = new RegExp(
  `^(\\s*)(?:-\\s*)?['"\`]?(?:name|key)['"\`]?\\s*:\\s*['"\`]?([A-Za-z0-9_.-]*(?:${SECRET_KEYWORD_GROUP}|TOKEN|AUTHORIZATION)[A-Za-z0-9_.-]*)['"\`]?\\s*,?\\s*(?:#.*)?$`,
  'i',
);

function hasTrailingContinuationOp(codeSegment: string, ext?: string): boolean {
  const trimmed = codeSegment.trim();
  if (!trimmed) return false;
  if (/(?:\+\s*|\?\?\s*|\|\|\s*)$/.test(trimmed)) {
    return true;
  }
  if (ext !== '.py') {
    if (/(?<![?.])\?\s*$/.test(trimmed)) {
      return true;
    }
    if (trimmed.includes('?') && /:\s*$/.test(trimmed)) {
      return true;
    }
  }
  return false;
}

function stripTrailingCodeComment(text: string): string {
  let i = 0;
  let activeQuote: QuoteDelimiter | null = null;
  while (i < text.length) {
    if (text[i] === '\\') {
      i += 2;
      continue;
    }
    if (activeQuote !== null) {
      if (text.startsWith(activeQuote, i)) {
        i += activeQuote.length;
        activeQuote = null;
        continue;
      }
      i += 1;
      continue;
    }
    const opened = detectOpeningQuote(text, i);
    if (opened !== null) {
      activeQuote = opened;
      i += opened.length;
      continue;
    }
    if (text[i] === '/' && text[i + 1] === '/') {
      return text.slice(0, i);
    }
    if (text[i] === '#' && (i === 0 || /\s/.test(text[i - 1] ?? ''))) {
      return text.slice(0, i);
    }
    i += 1;
  }
  return text;
}

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
    /\b(?:getElementById|querySelector|querySelectorAll|getAttribute|Getenv|getenv|requiredEnvironment|hasOwnProperty|GetString|environ\.(?:get|setdefault)|(?:headers|cookies|params|searchParams|config|viper|settings|storage|Map)\.get)\s*\(\s*$/i.test(
      prefixBeforeQuote,
    ) ||
    /\.\s*(?:split|join)\s*\(\s*$/.test(prefixBeforeQuote) ||
    /\btypeof\s+[A-Za-z0-9_$.[\]()]+?\s*(?:===|!==|==|!=)\s*$/.test(prefixBeforeQuote)
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
  const trimmedStart = line.slice(exprStart).trim().replace(/;$/, '').trim();
  if (PURE_DYNAMIC_REF_RE.test(trimmedStart)) {
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
  ext?: string,
): { text: string; count: number; nextState: MultilineSecretState | null } {
  const shaped = applyTokenShapePatterns(inputLine);
  let current = shaped.text;
  let count = shaped.count;
  let nextState: MultilineSecretState | null = null;
  const isQuotedCodeLang = ext !== undefined && QUOTED_STRING_CODE_EXTS.has(ext);

  // 1. Scan LHS secret assignments / properties / fallback operators left-to-right
  let searchPos = 0;
  while (searchPos < current.length) {
    const lhsRe = new RegExp(SECRET_LHS_OPERATOR_RE.source, 'gi');
    lhsRe.lastIndex = searchPos;
    const match = lhsRe.exec(current);
    if (!match) break;

    const dockerIdent = match[1];
    const dockerOp = match[2];
    const goTypedEq = match[4];
    const keyQuote = match[5] ?? '';
    const typedEq = match[8];
    const generalOp = match[9] ?? '';
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
      const codeTail = stripTrailingCodeComment(current.slice(rhsStart)).trim();
      if (codeTail.endsWith('(') || hasTrailingContinuationOp(codeTail, ext)) {
        const baseIndent = (current.match(/^(\s*)/)?.[1] ?? '').length;
        nextState = {
          kind: 'pending_rhs',
          operator,
          baseIndent,
          remainingLines: 6,
          ...(codeTail.endsWith('(') ? { inParens: true } : {}),
        };
        return { text: current, count, nextState };
      }
      if (
        isQuotedCodeLang &&
        (operator === '=' || operator === ':=' || operator === '??' || operator === '||') &&
        !codeTail.endsWith(';') &&
        !codeTail.endsWith(',') &&
        !codeTail.endsWith('}')
      ) {
        const baseIndent = (current.match(/^(\s*)/)?.[1] ?? '').length;
        nextState = {
          kind: 'pending_rhs',
          operator,
          baseIndent,
          remainingLines: 4,
          awaitLeadingOp: true,
        };
      }
      continue;
    }

    // 1b. YAML block scalar (`|`, `>`, `|-2`, `|2+`, etc.) on colon property
    if (
      !isQuotedCodeLang &&
      operator === ':' &&
      /^[|>](?:[+-]?[1-9]?|[1-9]?[+-]?)\s*(?:#.*)?$/.test(rest)
    ) {
      const indentMatch = current.match(/^(\s*)/);
      const baseIndent = indentMatch?.[1]?.length ?? 0;
      nextState = { kind: 'yaml_block', baseIndent };
      count += 1;
      return { text: current, count, nextState };
    }

    // 1b2. Dockerfile / shell empty-token backslash continuation (`ENV API_SECRET \` or `API_SECRET = \`)
    if ((operator === '=' || operator === 'ENV') && /^\s*\\\s*(?:#.*)?$/.test(rest)) {
      nextState = { kind: 'backslash' };
      count += 1;
      return { text: current, count, nextState };
    }

    // 1c. Empty RHS, open paren `(`, or multiline expression continuation at end of line
    if (
      operator === ':' ||
      operator === '=' ||
      operator === ':=' ||
      operator === '??' ||
      operator === '||'
    ) {
      const charBeforeMatch = match.index > 0 ? current[match.index - 1] : '';
      const baseIndent = (current.match(/^(\s*)/)?.[1] ?? '').length;
      if (/^\s*(?:\/\/.*|#.*)?$/.test(rest)) {
        if (charBeforeMatch !== '?') {
          nextState = { kind: 'pending_rhs', operator, baseIndent, remainingLines: 5 };
        }
        searchPos = current.length;
        break;
      }
      const strippedRest = stripTrailingCodeComment(rest).trim();
      if (/^\(\s*$/.test(strippedRest) && charBeforeMatch !== '?') {
        nextState = {
          kind: 'pending_rhs',
          operator,
          baseIndent,
          remainingLines: 8,
          inParens: true,
        };
        searchPos = current.length;
        break;
      }
      if (
        charBeforeMatch !== '?' &&
        strippedRest &&
        !strippedRest.endsWith(';') &&
        !strippedRest.endsWith('{') &&
        !strippedRest.endsWith('}')
      ) {
        if (hasTrailingContinuationOp(strippedRest, ext)) {
          nextState = { kind: 'pending_rhs', operator, baseIndent, remainingLines: 5 };
          searchPos = current.length;
          break;
        }
        if (isQuotedCodeLang && (operator === '=' || operator === ':=')) {
          nextState = {
            kind: 'pending_rhs',
            operator,
            baseIndent,
            remainingLines: 4,
            awaitLeadingOp: true,
          };
          searchPos = current.length;
          break;
        }
      }
    }

    // 1d. Unquoted RHS for `=`, `ENV`, or YAML `:`
    if ((operator === '=' && !isQuotedCodeLang) || operator === 'ENV') {
      const commentSplit = rest.match(/^(.*?)(\s+#.*)?$/);
      const rawBody = (commentSplit?.[1] ?? rest).trim();
      const commentTail = commentSplit?.[2] ?? '';

      if (!rawBody || isDynamicOrAlreadyRedacted(rawBody)) {
        searchPos = rhsStart + Math.max(1, rest.length);
        continue;
      }

      // For Dockerfile `ENV KEY=val OTHER=2`, stop at whitespace when `=` was used without `;`
      let candidateVal = rawBody;
      let candidateTrailing = commentTail;
      if (operator === 'ENV' || (!rawBody.includes(';') && /\s/.test(rawBody))) {
        const wsSplit = rest.match(/^([^\s#'"`,\\()]+)(.*)$/);
        candidateVal = wsSplit?.[1] ?? '';
        candidateTrailing = wsSplit?.[2] ?? '';
      }

      const prefixBeforeLhs = current.slice(0, match.index);
      const isCodeKeywordAssign = /\b(?:const|let|var|return)\s+$/.test(prefixBeforeLhs);
      const looksLikeCodeExpr =
        /^(?:process\.env|os\.environ|os\.Getenv|import\.meta\.env)\b/.test(candidateVal) ||
        /^(?:true|false|null|undefined|None|nil|\d+(?:\.\d+)?)$/i.test(candidateVal) ||
        /^[A-Za-z_$][A-Za-z0-9_$.]*\s*\(/.test(candidateVal) ||
        /^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+$/.test(candidateVal) ||
        (isCodeKeywordAssign && /^[A-Za-z_$][A-Za-z0-9_$]*;?$/.test(candidateVal)) ||
        (candidateVal.endsWith(';') && !/[=/:@]/.test(candidateVal.slice(0, -1)));

      if (candidateVal.length >= 1 && !looksLikeCodeExpr && !isDynamicOrAlreadyRedacted(candidateVal)) {
        const hasBackslashCont = endsWithUnescapedBackslash(rest.trimEnd());
        const replacement = hasBackslashCont
          ? '[REDACTED_SECRET] \\'
          : `[REDACTED_SECRET]${candidateTrailing}`;
        current = `${current.slice(0, rhsStart)}${replacement}`;
        count += 1;
        if (hasBackslashCont) {
          nextState = { kind: 'backslash' };
          return { text: current, count, nextState };
        }
        searchPos = rhsStart + '[REDACTED_SECRET]'.length;
        continue;
      }
    } else if (
      !isQuotedCodeLang &&
      ext !== '.css' &&
      ext !== '.scss' &&
      ext !== '.html' &&
      operator === ':' &&
      keyQuote === '' &&
      /(?:^|[{,])\s*(?:-\s*)?$/.test(current.slice(0, match.index))
    ) {
      // Unquoted YAML/config scalar (`api_secret: ${API_SECRET:-fallback}`, `api_secret: p@ss(word)!`, `api_secret: raw value`)
      const insideInlineMap = current.slice(0, match.index).includes('{');
      const yamlSplit = insideInlineMap
        ? rest.match(/^([^#}\r\n]*?)(\s*[},].*)?$/)
        : rest.match(/^(.*?)(\s+#.*)?$/);
      const rawYamlVal = (yamlSplit?.[1] ?? rest).trim();
      const yamlTrailing = yamlSplit?.[2] ?? '';
      if (rawYamlVal && !isBenignYamlScalar(rawYamlVal) && !isDynamicOrAlreadyRedacted(rawYamlVal)) {
        current = `${current.slice(0, rhsStart)}[REDACTED_SECRET]${yamlTrailing}`;
        count += 1;
        searchPos = rhsStart + '[REDACTED_SECRET]'.length;
        continue;
      }
    }

    searchPos = rhsStart;
  }

  // 2. Scan setter / env-default calls (`setString('session_token', 'secret')`, `os.environ.get("API_KEY", "fallback")`, `headers.set(...)`)
  let callPos = 0;
  while (callPos < current.length) {
    const callRe = new RegExp(SECRET_CALL_ARG_PAIR_RE.source, 'gi');
    callRe.lastIndex = callPos;
    const callMatch = callRe.exec(current);
    if (!callMatch) break;

    const valStart = callMatch.index + callMatch[0].length;
    const afterMatch = current.slice(valStart);
    if (/^\s*(?:\/\/.*|#.*)?$/.test(afterMatch)) {
      nextState = { kind: 'pending_call', stage: 'await_val', remainingLines: 5 };
      return { text: current, count, nextState };
    }

    const exprQuoted = redactQuotesInRhsExpression(current, valStart, true, null);
    if (exprQuoted.handled) {
      current = exprQuoted.newLine;
      count += exprQuoted.countDelta;
      callPos = Math.max(valStart + 1, exprQuoted.nextCursor);
      if (exprQuoted.nextState) {
        nextState = exprQuoted.nextState;
        return { text: current, count, nextState };
      }
      continue;
    }
    callPos = valStart + 1;
  }

  // 3. Detect multiline setter / env-default call opening `(` at end of line (`os.environ.get(\n "API_KEY",\n "SECRET")`)
  if (nextState === null && SECRET_CALL_OPEN_EOL_RE.test(current)) {
    nextState = { kind: 'pending_call', stage: 'await_key', remainingLines: 6 };
  }

  // 4. Detect Cloud Run / K8s YAML or JSON `- name: API_SECRET` followed by `value: "..."`
  if (nextState === null) {
    const envNameMatch = current.match(YAML_ENV_NAME_LINE_RE);
    if (envNameMatch) {
      nextState = {
        kind: 'pending_env_entry',
        baseIndent: (envNameMatch[1] ?? '').length,
        remainingLines: 4,
      };
    }
  }

  return { text: current, count, nextState };
}

function redactEnvLine(
  inputLine: string,
): { text: string; count: number; nextState: MultilineSecretState | null } {
  const trimmed = inputLine.trim();
  if (!trimmed) {
    return { text: inputLine, count: 0, nextState: null };
  }
  if (trimmed.startsWith('#')) {
    const commentLeadMatch = inputLine.match(/^(\s*#+\s*)(.*)$/);
    const lead = commentLeadMatch?.[1] ?? '# ';
    const body = commentLeadMatch?.[2] ?? '';
    if (!body.trim()) {
      return { text: inputLine, count: 0, nextState: null };
    }
    const innerRes = redactEnvLine(body);
    return {
      text: `${lead}${innerRes.text}`,
      count: innerRes.count,
      nextState: innerRes.nextState,
    };
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

  if (!rhs.trim()) {
    return { text: inputLine, count: 0, nextState: null };
  }
  if (rhs.trim().startsWith('#')) {
    const commentRes = redactEnvLine(rhs);
    return {
      text: `${prefix}${commentRes.text}`,
      count: commentRes.count,
      nextState: commentRes.nextState,
    };
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
    const skipFirst =
      isDynamicOrAlreadyRedacted(inner) || (!isSecretKey && isTrivialBenignEnvLiteral(inner));
    const firstPart = skipFirst
      ? inputLine.slice(0, closeIdx + delim.length)
      : `${prefix}${delim}${placeholder}${delim}`;
    const firstCount = skipFirst ? 0 : 1;

    const tailAfterClose = inputLine.slice(closeIdx + delim.length);
    if (!tailAfterClose.trim()) {
      return {
        text: `${firstPart}${tailAfterClose}`,
        count: firstCount,
        nextState: null,
      };
    }

    const tailWsMatch = tailAfterClose.match(/^(\s*)(.*)$/);
    const tailWs = tailWsMatch?.[1] ?? '';
    const tailBody = tailWsMatch?.[2] ?? '';
    const tailRes = redactEnvLine(tailBody);
    return {
      text: `${firstPart}${tailWs}${tailRes.text}`,
      count: firstCount + tailRes.count,
      nextState: tailRes.nextState,
    };
  }

  // Unquoted multi-assignment on one line (`NODE_ENV=production NEXT_PUBLIC_API_SECRET=secret`)
  const multiAssignMatch = rhs.match(/^([^\s#'"`\\]+)(\s+(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*=.*)$/);
  if (multiAssignMatch) {
    const firstTok = multiAssignMatch[1] ?? '';
    const restAssign = multiAssignMatch[2] ?? '';
    const skipFirst =
      isDynamicOrAlreadyRedacted(firstTok) ||
      (!isSecretKey && isTrivialBenignEnvLiteral(firstTok));
    const firstRendered = skipFirst ? `${prefix}${firstTok}` : `${prefix}${placeholder}`;
    const firstCount = skipFirst ? 0 : 1;
    const wsSplit = restAssign.match(/^(\s+)(.*)$/);
    const tailRes = redactEnvLine(wsSplit?.[2] ?? restAssign.trimStart());
    return {
      text: `${firstRendered}${wsSplit?.[1] ?? ' '}${tailRes.text}`,
      count: firstCount + tailRes.count,
      nextState: tailRes.nextState,
    };
  }

  // Unquoted .env value (strip optional inline ` # comment` and redact secrets inside comments too)
  const commentMatch = rhs.match(/^(.*?)(\s+#.*)?$/);
  const rawVal = (commentMatch?.[1] ?? rhs).trimEnd();
  const rawCommentSuffix = commentMatch?.[2] ?? '';
  let renderedComment = rawCommentSuffix;
  let commentCount = 0;
  if (rawCommentSuffix) {
    const wsLead = rawCommentSuffix.match(/^(\s+)/)?.[1] ?? ' ';
    const cRes = redactEnvLine(rawCommentSuffix.trimStart());
    renderedComment = `${wsLead}${cRes.text}`;
    commentCount = cRes.count;
  }

  if (endsWithUnescapedBackslash(rawVal)) {
    return {
      text: `${prefix}${placeholder} \\${renderedComment}`,
      count: 1 + commentCount,
      nextState: { kind: 'backslash' },
    };
  }

  if (
    isDynamicOrAlreadyRedacted(rawVal) ||
    (!isSecretKey && isTrivialBenignEnvLiteral(rawVal))
  ) {
    return {
      text: `${prefix}${rawVal}${renderedComment}`,
      count: commentCount,
      nextState: null,
    };
  }

  return {
    text: `${prefix}${placeholder}${renderedComment}`,
    count: 1 + commentCount,
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
  options?: { isEnvFile?: boolean; ext?: string },
): LinePreservingRedactionResult {
  const isEnvFile = options?.isEnvFile === true;
  const ext = options?.ext;
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

  const pushRedactedKeepingState = (rawLine: string, lineNo: number): void => {
    if (!rawLine.trim()) {
      redactedLines.push(rawLine);
      return;
    }
    const subRes = isEnvFile ? redactEnvLine(rawLine) : redactGeneralCodeLine(rawLine, ext);
    if (subRes.count > 0) {
      markLineRedacted(lineNo, subRes.count);
    }
    redactedLines.push(subRes.text);
  };

  const evalPendingQuotedLine = (
    rawLine: string,
    exprStart: number,
    stopAtComma: boolean,
  ): {
    handled: boolean;
    newLine: string;
    countDelta: number;
    nextState: MultilineSecretState | null;
  } => {
    const shaped = applyTokenShapePatterns(rawLine);
    const exprRes = redactQuotesInRhsExpression(shaped.text, exprStart, stopAtComma, null);
    if (!exprRes.handled) {
      return {
        handled: false,
        newLine: rawLine,
        countDelta: 0,
        nextState: null,
      };
    }
    if (exprRes.nextState !== null || exprRes.nextCursor >= exprRes.newLine.length) {
      return {
        handled: true,
        newLine: exprRes.newLine,
        countDelta: shaped.count + exprRes.countDelta,
        nextState: exprRes.nextState,
      };
    }
    const prefix = exprRes.newLine.slice(0, exprRes.nextCursor);
    const suffix = exprRes.newLine.slice(exprRes.nextCursor);
    if (!suffix.trim()) {
      return {
        handled: true,
        newLine: exprRes.newLine,
        countDelta: shaped.count + exprRes.countDelta,
        nextState: null,
      };
    }
    const suffixRes = isEnvFile ? redactEnvLine(suffix) : redactGeneralCodeLine(suffix, ext);
    return {
      handled: true,
      newLine: `${prefix}${suffixRes.text}`,
      countDelta: shaped.count + exprRes.countDelta + suffixRes.count,
      nextState: suffixRes.nextState,
    };
  };

  for (let idx = 0; idx < rawLines.length; idx++) {
    const lineNo = idx + 1;
    const line = rawLines[idx] ?? '';

    // 1. Handle active multiline block/string states first (pem, quote, backslash, yaml_block)
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
        const tailRes = isEnvFile
          ? redactEnvLine(remainder)
          : redactGeneralCodeLine(remainder, ext);
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
      }
    }

    // 2. Detect start of PEM / Private Key block (takes priority over any pending_* lookahead state)
    if (PEM_BEGIN_RE.test(line)) {
      const beginPos = line.search(PEM_BEGIN_RE);
      const prefixPart =
        beginPos > 0
          ? (isEnvFile
              ? redactEnvLine(line.slice(0, beginPos))
              : redactGeneralCodeLine(line.slice(0, beginPos), ext)
            ).text
          : '';
      markLineRedacted(lineNo, 1);
      redactedLines.push(`${prefixPart}[REDACTED_PRIVATE_KEY]`);
      state = PEM_END_RE.test(line) ? null : { kind: 'pem', counted: true };
      continue;
    }

    // 3. Handle pending lookahead states (pending_rhs, pending_call, pending_env_entry) with full token/comment redaction
    if (state !== null) {
      if (state.kind === 'pending_rhs') {
        const rhsState: Extract<MultilineSecretState, { kind: 'pending_rhs' }> = state;
        const trimmedLine = line.trim();
        if (!trimmedLine || /^(?:\/\/|#|\*)/.test(trimmedLine)) {
          if (rhsState.remainingLines > 1) {
            state = {
              kind: 'pending_rhs',
              operator: rhsState.operator,
              baseIndent: rhsState.baseIndent,
              remainingLines: rhsState.remainingLines - 1,
              ...(rhsState.inParens ? { inParens: true } : {}),
              ...(rhsState.awaitLeadingOp ? { awaitLeadingOp: true } : {}),
            };
            pushRedactedKeepingState(line, lineNo);
            continue;
          }
          state = null;
        } else if (
          rhsState.awaitLeadingOp &&
          !/^(?:\?(?!\.)|:|\+|\|\||\?\?)/.test(trimmedLine)
        ) {
          // Next line does not begin with a continuation operator — fall through cleanly
          state = null;
        } else {
          const indentLen = (line.match(/^(\s*)/)?.[1] ?? '').length;
          if (
            rhsState.operator === ':' &&
            !rhsState.inParens &&
            !rhsState.awaitLeadingOp &&
            indentLen <= rhsState.baseIndent &&
            /^[A-Za-z0-9_.'" -]+\s*:/.test(trimmedLine)
          ) {
            // Dedented back to a sibling YAML/object key — fall through to normal processing
            state = null;
          } else if (rhsState.inParens && /^\)\s*;?\s*(?:\/\/.*|#.*)?$/.test(trimmedLine)) {
            state = null;
          } else {
            const firstNonWs = line.search(/\S/);
            const exprRes =
              firstNonWs >= 0
                ? evalPendingQuotedLine(
                    line,
                    firstNonWs,
                    rhsState.operator === ':' && !rhsState.inParens && !rhsState.awaitLeadingOp,
                  )
                : null;
            if (exprRes && exprRes.handled) {
              if (exprRes.countDelta > 0) {
                markLineRedacted(lineNo, exprRes.countDelta);
              }
              const strippedNew = stripTrailingCodeComment(exprRes.newLine).trim();
              const closesParens = rhsState.inParens && /\)\s*;?\s*$/.test(strippedNew);
              if (exprRes.nextState) {
                state = exprRes.nextState;
              } else if (
                rhsState.inParens &&
                !closesParens &&
                rhsState.remainingLines > 1
              ) {
                state = {
                  kind: 'pending_rhs',
                  operator: rhsState.operator,
                  baseIndent: rhsState.baseIndent,
                  remainingLines: rhsState.remainingLines - 1,
                  inParens: true,
                };
              } else if (
                hasTrailingContinuationOp(strippedNew, ext) &&
                rhsState.remainingLines > 1
              ) {
                state = {
                  kind: 'pending_rhs',
                  operator: rhsState.operator,
                  baseIndent: rhsState.baseIndent,
                  remainingLines: rhsState.remainingLines - 1,
                };
              } else if (
                !strippedNew.endsWith(';') &&
                !strippedNew.endsWith(',') &&
                rhsState.remainingLines > 1
              ) {
                state = {
                  kind: 'pending_rhs',
                  operator: rhsState.operator,
                  baseIndent: rhsState.baseIndent,
                  remainingLines: rhsState.remainingLines - 1,
                  awaitLeadingOp: true,
                };
              } else {
                state = null;
              }
              redactedLines.push(exprRes.newLine);
              continue;
            }
            const strippedOrig = stripTrailingCodeComment(line).trim();
            if (
              !strippedOrig.endsWith(';') &&
              (rhsState.inParens || hasTrailingContinuationOp(strippedOrig, ext)) &&
              rhsState.remainingLines > 1
            ) {
              state = {
                kind: 'pending_rhs',
                operator: rhsState.operator,
                baseIndent: rhsState.baseIndent,
                remainingLines: rhsState.remainingLines - 1,
                ...(rhsState.inParens && !/\)\s*$/.test(strippedOrig)
                  ? { inParens: true }
                  : {}),
              };
              pushRedactedKeepingState(line, lineNo);
              continue;
            }
            const isQuotedCode = ext !== undefined && QUOTED_STRING_CODE_EXTS.has(ext);
            if (!isQuotedCode && rhsState.operator === ':' && indentLen > rhsState.baseIndent) {
              const yamlSplit = trimmedLine.match(/^(.*?)(\s+#.*)?$/);
              const rawYamlVal = (yamlSplit?.[1] ?? trimmedLine).trim();
              const yamlTrailing = yamlSplit?.[2] ?? '';
              if (
                rawYamlVal &&
                !isBenignYamlScalar(rawYamlVal) &&
                !isDynamicOrAlreadyRedacted(rawYamlVal)
              ) {
                const tailRes = yamlTrailing
                  ? redactGeneralCodeLine(yamlTrailing, ext)
                  : { text: '', count: 0 };
                markLineRedacted(lineNo, 1 + tailRes.count);
                state = null;
                redactedLines.push(`${' '.repeat(indentLen)}[REDACTED_SECRET]${tailRes.text}`);
                continue;
              }
            }
            state = null;
          }
        }
      } else if (state.kind === 'pending_call') {
        const callState: Extract<MultilineSecretState, { kind: 'pending_call' }> = state;
        const trimmedLine = line.trim();
        if (!trimmedLine || /^(?:\/\/|#|\*)/.test(trimmedLine)) {
          if (callState.remainingLines > 1) {
            state = {
              kind: 'pending_call',
              stage: callState.stage,
              remainingLines: callState.remainingLines - 1,
            };
            pushRedactedKeepingState(line, lineNo);
            continue;
          }
          state = null;
        } else if (callState.stage === 'await_key') {
          const keyMatch = line.match(SECRET_KEY_FIRST_ARG_LINE_RE);
          if (!keyMatch) {
            state = null;
          } else {
            const keyPrefix = keyMatch[1] ?? '';
            const afterKey = keyMatch[3] ?? '';
            const commaMatch = afterKey.match(
              /^(\s*,\s*(?:(?:value|default)\s*[:=]\s*)?)(.*)$/,
            );
            if (!commaMatch) {
              state = null;
              if (afterKey.includes(')')) {
                pushRedactedKeepingState(line, lineNo);
                continue;
              }
            } else {
              const afterCommaRest = commaMatch[2] ?? '';
              if (/^\s*(?:\/\/.*|#.*)?$/.test(afterCommaRest)) {
                state = {
                  kind: 'pending_call',
                  stage: 'await_val',
                  remainingLines: Math.max(1, callState.remainingLines - 1),
                };
                pushRedactedKeepingState(line, lineNo);
                continue;
              }
              if (/^\s*\)/.test(afterCommaRest)) {
                state = null;
                pushRedactedKeepingState(line, lineNo);
                continue;
              }
              const valStart = keyPrefix.length + (commaMatch[1]?.length ?? 0);
              const exprRes = evalPendingQuotedLine(line, valStart, true);
              if (exprRes.handled) {
                if (exprRes.countDelta > 0) {
                  markLineRedacted(lineNo, exprRes.countDelta);
                }
                state = exprRes.nextState;
                redactedLines.push(exprRes.newLine);
                continue;
              }
              state = null;
            }
          }
        } else {
          // callState.stage === 'await_val'
          if (trimmedLine.startsWith(')')) {
            state = null;
          } else {
            const namedPrefixMatch = line.match(/^(\s*(?:(?:value|default)\s*[:=]\s*)?)/);
            const valStart = namedPrefixMatch?.[1]?.length ?? 0;
            const exprRes = evalPendingQuotedLine(line, valStart, true);
            if (exprRes.handled) {
              if (exprRes.countDelta > 0) {
                markLineRedacted(lineNo, exprRes.countDelta);
              }
              if (exprRes.nextState) {
                state = exprRes.nextState;
              } else if (
                hasTrailingContinuationOp(stripTrailingCodeComment(exprRes.newLine), ext) &&
                callState.remainingLines > 1
              ) {
                state = {
                  kind: 'pending_call',
                  stage: 'await_val',
                  remainingLines: callState.remainingLines - 1,
                };
              } else {
                state = null;
              }
              redactedLines.push(exprRes.newLine);
              continue;
            }
            if (
              !trimmedLine.includes(')') &&
              hasTrailingContinuationOp(stripTrailingCodeComment(line), ext) &&
              callState.remainingLines > 1
            ) {
              state = {
                kind: 'pending_call',
                stage: 'await_val',
                remainingLines: callState.remainingLines - 1,
              };
              pushRedactedKeepingState(line, lineNo);
              continue;
            }
            state = null;
          }
        }
      } else if (state.kind === 'pending_env_entry') {
        const envEntryState: Extract<MultilineSecretState, { kind: 'pending_env_entry' }> = state;
        const trimmedLine = line.trim();
        if (!trimmedLine || /^(?:\/\/|#|\*)/.test(trimmedLine)) {
          if (envEntryState.remainingLines > 1) {
            state = {
              kind: 'pending_env_entry',
              baseIndent: envEntryState.baseIndent,
              remainingLines: envEntryState.remainingLines - 1,
            };
            pushRedactedKeepingState(line, lineNo);
            continue;
          }
          state = null;
        } else {
          const indentLen = (line.match(/^(\s*)/)?.[1] ?? '').length;
          const valLineMatch = line.match(/^(\s*['"`]?(?:value|default)['"`]?\s*:\s*)(.*)$/i);
          if (valLineMatch && indentLen >= envEntryState.baseIndent) {
            const origPrefix = valLineMatch[1] ?? '';
            const valRhs = valLineMatch[2] ?? '';
            const syntheticPrefix = 'api_secret: ';
            const synthRes = redactGeneralCodeLine(`${syntheticPrefix}${valRhs}`, ext);
            if (synthRes.count > 0 || synthRes.nextState !== null) {
              if (synthRes.count > 0) {
                markLineRedacted(lineNo, synthRes.count);
              }
              const rewrittenTail = synthRes.text.startsWith(syntheticPrefix)
                ? synthRes.text.slice(syntheticPrefix.length)
                : valRhs;
              if (synthRes.nextState?.kind === 'yaml_block') {
                state = { kind: 'yaml_block', baseIndent: indentLen };
              } else if (synthRes.nextState?.kind === 'pending_rhs') {
                state = {
                  kind: 'pending_rhs',
                  operator: ':',
                  baseIndent: indentLen,
                  remainingLines: synthRes.nextState.remainingLines,
                };
              } else {
                state = synthRes.nextState;
              }
              redactedLines.push(`${origPrefix}${rewrittenTail}`);
              continue;
            }
            state = null;
          } else if (
            indentLen < envEntryState.baseIndent ||
            /^-\s/.test(trimmedLine) ||
            /^['"`]?valueFrom['"`]?\s*:/i.test(trimmedLine)
          ) {
            state = null;
          } else if (envEntryState.remainingLines > 1) {
            state = {
              kind: 'pending_env_entry',
              baseIndent: envEntryState.baseIndent,
              remainingLines: envEntryState.remainingLines - 1,
            };
            pushRedactedKeepingState(line, lineNo);
            continue;
          } else {
            state = null;
          }
        }
      }
    }

    // 4. Standard line-level & multiline-opening lexical redaction
    const res = isEnvFile ? redactEnvLine(line) : redactGeneralCodeLine(line, ext);
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
export function redactSecrets(
  input: string,
  options?: { isEnvFile?: boolean; ext?: string },
): RedactionResult {
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
  SQL_PARAMETERIZED_BINDING: `// 防御パッチ: 文字列補間クエリを廃止し、プリペアドステートメント（プレースホルダ束縛）を徹底
const rows = await db.query('SELECT id, role FROM users WHERE email = $1', [validatedEmail]);`,
  SSRF_EGRESS_ALLOWLIST: `// 防御パッチ: 接続先ホストの固定 Allowlist 検証 + メタデータ/内部 IP (169.254.169.254, 127.0.0.0/8) 遮断
const parsedUrl = new URL(candidateUrl);
if (parsedUrl.protocol !== 'https:' || !ALLOWED_UPSTREAM_HOSTS.has(parsedUrl.hostname)) {
  throw new Error('Blocked outbound host by egress policy.');
}`,
  CSPRNG_AND_SHA256_CRYPTO: `// 防御パッチ: Math.random / MD5 / SHA-1 を廃止し、暗号論的乱数 (crypto.randomBytes) と SHA-256 以上を使用
import crypto from 'node:crypto';
const capabilityNonce = crypto.randomBytes(32).toString('hex');`,
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
  GITHUB_ACTIONS_SHA_PIN: `# 防御パッチ: pull_request_target・直接式展開を排除し、env 中間変数 + 40桁フルコミット SHA 固定を適用
permissions:
  contents: read
steps:
  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`,
  LOCKFILE_FROZEN_CI: `# 防御パッチ: 暗号学的ロックファイルをリポジトリにコミットし CI で frozen-lockfile を強制
pnpm install --frozen-lockfile`,
} as const);

export type DefensivePatchTemplateId = keyof typeof DEFENSIVE_PATCH_TEMPLATES;
