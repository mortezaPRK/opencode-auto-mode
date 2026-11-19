/**
 * Conservative top-level shell segmentation. Pure and structural: never decides
 * whether a command is safe or authorized, and anything it cannot represent
 * exactly returns `undefined`. At most one leading literal `cd <path>` joined by
 * `&&`, `;` or a newline folds into a caller-resolved cwd.
 */

import { DYNAMIC, STATEFUL } from "./shell-policy.js";

export const MAX_SEGMENTS = 8;

/**
 * Command substitution, parameter expansion, ANSI-C quoting, process
 * substitution and heredocs are never split or interpreted: their contents can
 * hold unquoted operators that are not command separators.
 */
const UNSPLITTABLE = ["$(", "${", "$[", "$'", '$"', "`", "<<", "<(", ">("] as const;

/**
 * Commands and reserved words whose effects outlive the segment, so a segment
 * starting with one is never classified on its own. The persistent builtins
 * (`declare`, `typeset`, `readonly`, ...) are the same set the policy denies.
 */
const STATEFUL_COMMANDS = new Set([
  ...STATEFUL, ...DYNAMIC,
  "cd", "pushd", "popd", "builtin", "command", "env", "sh", "bash", "zsh", "sudo",
]);

/** Words that open or continue a compound command, so the rest is not top-level. */
const RESERVED_WORDS = new Set(["if", "then", "else", "elif", "fi", "for", "while", "until", "do",
  "done", "case", "esac", "select", "in", "function", "!", "[[", "]]", "time", "coproc"]);

/** Parentheses and braces group commands; the separators inside are not top-level. */
const GROUPING = new Set(["(", ")", "{", "}"]);

/** A leading `NAME=value` prefix assigns shell state, including `IFS=`. */
const ASSIGNMENT_PREFIX = /^[A-Za-z_][A-Za-z0-9_]*=/;

/** Shell blanks only: `trim()` would also strip whitespace and blank argument data a shell keeps. */
const TRIM_BLANKS = /^[ \t]+|[ \t]+$/g;
const LEADING_BLANKS = /^[ \t]+/;

/** A segment ending in a blank an odd backslash run escaped cannot be trimmed safely. */
const ESCAPED_TRAILING_BLANK = /(?:^|[^\\])(?:\\\\)*\\[ \t]+$/;

/** Whitespace a shell does not treat as a separator (NBSP, CR, form feed, ...). */
const NON_SHELL_WHITESPACE = /[^\S \t\n]/;

interface Token {
  readonly split: boolean;
  readonly length: number;
}

const ORDINARY: Token = { split: false, length: 0 };
const SKIP_THREE: Token = { split: false, length: 3 };
const SPLIT_ONE: Token = { split: true, length: 1 };
const SPLIT_TWO: Token = { split: true, length: 2 };

/** The only redirection this scanner allows, and only as one exact standalone token. */
const ALLOWED_REDIRECT = "2>&1";

/** True at the start of a shell word: command start, blank, newline or separator. */
function atWordStart(char: string | undefined): boolean {
  return char === undefined || char === " " || char === "\t" || char === "\n" ||
    char === ";" || char === "&" || char === "|";
}

/** Only the exact standalone unquoted `2>&1` token is allowed; every other
 * redirection form (`2>&10`, `2>&1-`, `2>&1''`, `12>&1`) is unresolved. */
function fdRedirectToken(command: string, index: number): Token | undefined {
  const start = index - 1;
  if (start < 0 || command.slice(start, index + 3) !== ALLOWED_REDIRECT) return undefined;
  return atWordStart(command[start - 1]) && atWordStart(command[index + 3]) ? SKIP_THREE : undefined;
}

/** The separator a `;`, newline, `|` or `&` starts; a lone `&` is unresolved. */
function separatorToken(command: string, index: number): Token | undefined {
  const char = command[index];
  if (char === ";" || char === "\n") return SPLIT_ONE;
  const doubled = command[index + 1] === char;
  if (!doubled) return char === "|" ? SPLIT_ONE : undefined;
  return SPLIT_TWO;
}

function tokenAt(command: string, index: number): Token | undefined {
  const char = command[index];
  if (char === "<" || (char !== undefined && GROUPING.has(char))) return undefined;
  if (char === ">") return fdRedirectToken(command, index);
  if (char === "&" || char === "|" || char === ";" || char === "\n") {
    return separatorToken(command, index);
  }
  return ORDINARY;
}

/** Closing quote index; an unterminated quote runs to the end of the command. */
function quotedEnd(command: string, index: number, quote: string): number {
  for (let cursor = index + 1; cursor < command.length; cursor += 1) {
    const char = command[cursor];
    if (char === "\\" && quote === '"') cursor += 1;
    else if (char === quote) return cursor;
  }
  return command.length;
}

/** True when `#` starts a comment word, which a shell reads to the next newline. */
function commentStart(command: string, index: number): boolean {
  if (index === 0) return true;
  const previous = command[index - 1];
  return previous === " " || previous === "\t" || previous === "\n" || previous === ";" ||
    previous === "&" || previous === "|";
}

/** Index after a quoted run or escaped character, or undefined for an unquoted comment. */
function skippedIndex(command: string, index: number): number | undefined {
  const char = command[index];
  if (char === "'" || char === '"') return quotedEnd(command, index, char) + 1;
  if (char === "\\") return index + 2;
  if (char === "#" && commentStart(command, index)) return undefined;
  return index;
}

/** Untrimmed pieces plus the exact separator after each. */
interface ScanResult {
  readonly raw: readonly string[];
  readonly separators: readonly string[];
}

function scanSegments(command: string): ScanResult | undefined {
  const raw: string[] = [];
  const separators: string[] = [];
  let index = 0;
  let start = 0;
  while (index < command.length) {
    const skipped = skippedIndex(command, index);
    if (skipped === undefined) return undefined;
    if (skipped !== index) {
      index = skipped;
      continue;
    }
    const token = tokenAt(command, index);
    if (token === undefined) return undefined;
    if (token.split) {
      raw.push(command.slice(start, index));
      separators.push(command.slice(index, index + token.length));
      start = index + token.length;
    }
    index += Math.max(token.length, 1);
  }
  raw.push(command.slice(start));
  return { raw, separators };
}

function cleanSegments(scanned: ScanResult): string[] | undefined {
  if (scanned.raw.some((segment) => ESCAPED_TRAILING_BLANK.test(segment))) return undefined;
  const segments = scanned.raw.map((segment) => segment.replace(TRIM_BLANKS, ""));
  if (segments.length === 0 || segments.length > MAX_SEGMENTS) return undefined;
  return segments.every((segment) => segment.length > 0) ? segments : undefined;
}

/** Drops leading allowed `2>&1` redirections so they cannot hide the command word. */
function withoutLeadingRedirects(segment: string): string {
  let rest = segment;
  while (rest.startsWith(ALLOWED_REDIRECT) && atWordStart(rest[4])) {
    rest = rest.slice(4).replace(LEADING_BLANKS, "");
  }
  return rest;
}

/** First word with quoting and escapes removed, so a quoted `'cd'` is the same
 * stateful word as `cd`; leading allowed `2>&1` redirections are skipped. */
function firstWord(segment: string): string {
  const rest = withoutLeadingRedirects(segment);
  let word = "";
  let index = 0;
  while (index < rest.length) {
    const char = rest[index];
    if (char === " " || char === "\t") break;
    if (char === "'" || char === '"') {
      const end = quotedEnd(rest, index, char);
      word += rest.slice(index + 1, end);
      index = end + 1;
    } else if (char === "\\") {
      word += rest[index + 1] ?? "";
      index += 2;
    } else {
      word += char;
      index += 1;
    }
  }
  return word.replace(/\\/g, "");
}

/** A stateful, reserved or assigning first word makes the segment unreadable in isolation. */
const unreadableSegment = (segment: string): boolean => {
  const word = firstWord(segment);
  return STATEFUL_COMMANDS.has(word) || RESERVED_WORDS.has(word) || ASSIGNMENT_PREFIX.test(word);
};

/** A split command plus the literal target of one folded leading `cd`. */
export interface ShellSegmentSplit {
  readonly segments: readonly string[];
  readonly leadingCd?: string;
}

/** Redirection metacharacters, grouping and blanks are shell syntax, not a directory name. */
const PLAIN_ARGUMENT = /^[^\s'"\\<>|&;(){}]+$/;
const SINGLE_QUOTED_ARGUMENT = /^'([^']*)'$/;
const DOUBLE_QUOTED_ARGUMENT = /^"([^"\\]*)"$/;
/** Variable, home or glob expansion is not one literal path. */
const EXPANDED_TARGET = /[$~*?[\]`]/;

function literalArgument(text: string): string | undefined {
  const single = SINGLE_QUOTED_ARGUMENT.exec(text);
  if (single !== null) return single[1];
  const double = DOUBLE_QUOTED_ARGUMENT.exec(text);
  if (double !== null) return double[1];
  return PLAIN_ARGUMENT.test(text) ? text : undefined;
}

/** The one literal path of an exact `cd <path>` segment, never an option. */
function cdTarget(segment: string): string | undefined {
  const match = /^cd[ \t]+([\s\S]+)$/.exec(segment);
  if (match === null) return undefined;
  const target = literalArgument(match[1]!.replace(TRIM_BLANKS, ""));
  const unrepresentable = target === undefined || target.length === 0 || target.startsWith("-") ||
    EXPANDED_TARGET.test(target);
  return unrepresentable ? undefined : target;
}

function foldableSeparator(separator: string | undefined): boolean {
  return separator === "&&" || separator === ";" || separator === "\n";
}

/** Syntax this scanner refuses before scanning: expansions, comments and
 * `\`-newline continuations can assemble forms its raw checks would miss. */
function unsupported(command: string): boolean {
  return UNSPLITTABLE.some((marker) => command.includes(marker)) ||
    command.includes("\\\n") || NON_SHELL_WHITESPACE.test(command);
}

/** Folds at most one leading literal `cd` and returns its target for the caller
 * to resolve and confine; anything else stays unresolved. */
export function splitShellSegmentsWithLeadingCd(command: string): ShellSegmentSplit | undefined {
  if (unsupported(command)) return undefined;
  const scanned = scanSegments(command);
  if (scanned === undefined) return undefined;
  const segments = cleanSegments(scanned);
  if (segments === undefined) return undefined;
  const folded = segments.length > 1 && foldableSeparator(scanned.separators[0])
    ? cdTarget(segments[0]!)
    : undefined;
  const remaining = folded === undefined ? segments : segments.slice(1);
  if (remaining.some(unreadableSegment)) return undefined;
  if (folded === undefined) return { segments };
  return { segments: remaining, leadingCd: folded };
}
