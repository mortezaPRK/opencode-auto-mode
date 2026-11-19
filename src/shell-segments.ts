/**
 * Conservative top-level shell segmentation. Pure and structural: never decides
 * whether a command is safe or authorized, and anything it cannot represent
 * exactly returns `undefined`. At most one leading literal `cd <path>` joined by
 * `&&`, `;` or a newline folds into a caller-resolved cwd.
 */

export const MAX_SEGMENTS = 8;

/** Command substitution, ANSI-C quoting, process substitution and heredocs are never split or interpreted. */
const UNSPLITTABLE = ["$(", "$'", "`", "<<", "<(", ">("] as const;

/** Commands whose effects outlive the segment, so a segment starting with one is never classified on its own. */
const STATEFUL_COMMANDS = new Set([
  "cd", "pushd", "popd", "export", "unset", "alias", "unalias", "set", "shopt",
  "source", ".", "eval", "exec", "trap", "umask", "builtin", "command", "env",
  "sh", "bash", "zsh", "xargs", "sudo",
]);

/** A leading `NAME=value` prefix assigns shell state, including `IFS=`. */
const ASSIGNMENT_PREFIX = /^[A-Za-z_][A-Za-z0-9_]*=/;

interface Token {
  readonly split: boolean;
  readonly length: number;
}

const ORDINARY: Token = { split: false, length: 0 };
const SKIP_THREE: Token = { split: false, length: 3 };
const SPLIT_ONE: Token = { split: true, length: 1 };
const SPLIT_TWO: Token = { split: true, length: 2 };

/** Only the exact literal `2>&1` is allowed; every other output redirection is unresolved. */
function fdRedirectToken(command: string, index: number): Token | undefined {
  const earlier = command[index - 2];
  const fdDigit = earlier !== undefined && earlier >= "0" && earlier <= "9";
  return command[index - 1] === "2" && command.slice(index + 1, index + 3) === "&1" && !fdDigit
    ? SKIP_THREE
    : undefined;
}

function tokenAt(command: string, index: number): Token | undefined {
  const char = command[index];
  if (char === "&") return command[index + 1] === "&" ? SPLIT_TWO : undefined;
  if (char === "|") return command[index + 1] === "|" ? SPLIT_TWO : SPLIT_ONE;
  if (char === ";" || char === "\n") return SPLIT_ONE;
  if (char === "<") return undefined;
  if (char === ">") return fdRedirectToken(command, index);
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
    const char = command[index];
    if (char === "'" || char === '"') {
      index = quotedEnd(command, index, char) + 1;
      continue;
    }
    if (char === "\\") {
      index += 2;
      continue;
    }
    const token = tokenAt(command, index);
    if (token === undefined) return undefined;
    if (token.split) {
      raw.push(command.slice(start, index));
      separators.push(command.slice(index, index + token.length));
      start = index + token.length;
    }
    index += token.length === 0 ? 1 : token.length;
  }
  raw.push(command.slice(start));
  return { raw, separators };
}

function cleanSegments(scanned: ScanResult): string[] | undefined {
  const segments = scanned.raw.map((segment) => segment.trim());
  if (segments.length === 0 || segments.length > MAX_SEGMENTS) return undefined;
  return segments.every((segment) => segment.length > 0) ? segments : undefined;
}

const atWordBoundary = (char: string | undefined): boolean =>
  char === undefined || char === " " || char === "\t";

/** Drops leading allowed `2>&1` redirections so they cannot hide the command word. */
function withoutLeadingRedirects(segment: string): string {
  let rest = segment;
  while (rest.startsWith("2>&1") && atWordBoundary(rest[4])) rest = rest.slice(4).trimStart();
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

/** A stateful first word or a leading assignment makes the segment unreadable in isolation. */
const statefulSegment = (segment: string): boolean => {
  const word = firstWord(segment);
  return STATEFUL_COMMANDS.has(word) || ASSIGNMENT_PREFIX.test(word);
};

/** A split command plus the literal target of one folded leading `cd`. */
export interface ShellSegmentSplit {
  readonly segments: readonly string[];
  readonly leadingCd?: string;
}

const PLAIN_ARGUMENT = /^[^\s'"\\]+$/;
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
  const target = literalArgument(match[1]!.trim());
  return target === undefined || target.length === 0 || target.startsWith("-") ||
    EXPANDED_TARGET.test(target) ? undefined : target;
}

function foldableSeparator(separator: string | undefined): boolean {
  return separator === "&&" || separator === ";" || separator === "\n";
}

/** Folds at most one leading literal `cd` and returns its target for the caller
 * to resolve and confine; anything else stays unresolved. */
export function splitShellSegmentsWithLeadingCd(command: string): ShellSegmentSplit | undefined {
  if (UNSPLITTABLE.some((marker) => command.includes(marker))) return undefined;
  const scanned = scanSegments(command);
  if (scanned === undefined) return undefined;
  const segments = cleanSegments(scanned);
  if (segments === undefined) return undefined;
  const folded = segments.length > 1 && foldableSeparator(scanned.separators[0])
    ? cdTarget(segments[0]!)
    : undefined;
  const remaining = folded === undefined ? segments : segments.slice(1);
  if (remaining.some(statefulSegment)) return undefined;
  return folded === undefined ? { segments } : { segments: remaining, leadingCd: folded };
}

