import { basename } from "node:path";
import type { ReviewResult } from "./reviewer.js";
import { isInProject, isProtected, pathOperandPolicy, shellPathSpelling, shellWordNeedsReview } from "./tiers.js";
import type { PathPolicy } from "./path-policy.js";
import { classifyPath } from "./path-policy.js";
import { copyPathMode } from "./shell-copy.js";
import {
  BALANCED_QUOTES, CONTROL_OPERATORS, DYNAMIC, REDIRECT_OPERATORS, SCRIPT_HOSTS, SHELLS, STATEFUL,
  denyCleanPrefix, denyInvocation, hasAmbiguousDescriptorClose, hasAssembledUndecodedSyntax, hasHeredoc,
  hasUndecodedSyntax, heredocMarkers, isLongOption, isReadOnlyInvocation, logicalLines, normalizeContinuations,
  operandRoles, parseShell, rawHeredocScript, resolveExecutable, stripDescriptorPrefixes, capabilityNeedsReview,
} from "./shell-policy.js";

const MAX_COMMAND_CHARS = 4096;
const MAX_COMMAND_BYTES = 65_536;
const WRITE_OPERATORS = new Set([">", ">>", ">|", "&>", "&>>", "<>", ">&"]);
const DYNAMIC_SYNTAX = /\$\(|`|\$\(\s*\(|[<>]\(|\$\[/;
const FORK_BOMB = /^:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/;

interface Segment { words: string[]; globs: boolean[]; homes: boolean[]; write: boolean }
type Verdict = { decision: "deny"; reason: string } | { decision: "allow" | "review" | "ask" };

/** True when the effective executable is a shell, a dynamic builtin, or a stateful builtin. */
function dynamicExecution(words: string[]): boolean {
  const executable = resolveExecutable(words);
  if (executable === undefined) return true;
  if (SHELLS.has(executable.name) || DYNAMIC.has(executable.name) || STATEFUL.has(executable.name)) return true;
  return executable.name === "find" && words.slice(executable.index + 1)
    .some((word) => /^-(?:exec|execdir|ok|okdir|delete)$/.test(word));
}

function analyzeSegment(segment: Segment): Verdict {
  if (!segment.words.length) return segment.write ? { decision: "review" } : { decision: "allow" };
  const command = segment.words[0];
  if (!command || command.includes("$")) return { decision: "ask" };
  // A deny that is already identifiable wins over every uncertainty below, so
  // `sudo id *.txt` stays a mandatory deny instead of becoming a review.
  const blocked = denyInvocation(staticSegmentWords(segment));
  if (blocked !== undefined) return { decision: "deny", reason: blocked };
  if (dynamicExecution(segment.words)) return { decision: "ask" };
  if (capabilityNeedsReview(segment.words)) return { decision: "review" };
  // `isReadOnlyInvocation` refuses any argument an unquoted expansion could turn
  // into several words, so the literal flag policies only judge what will run.
  if (!segment.write && isReadOnlyInvocation(segment.words, segment.globs)) return { decision: "allow" };
  return { decision: "review" };
}

/** Token shapes this module consumes; `parse` returns a wider union. */
type Token = string | { comment: string } | { op: string; pattern?: string };

export interface ParsedShellCommands {
  /** Simple argv lists, excluding redirection operands. */
  segments: Segment[];
  /** Includes redirection targets for filesystem safety checks. */
  operands: string[];
  /** Redirection targets, including glob patterns: these always name a file. */
  redirects: string[];
  /** String tokens no simple command consumed, such as words inside a substitution. */
  leftovers: string[];
  /** False for syntax whose execution cannot be bounded by this parser. */
  complete: boolean;
  compound: boolean;
}
interface ParsedLine { segments: Segment[]; redirects: string[]; leftovers: string[]; complete: boolean }

/** Characters that end an unquoted shell word. JS `\s` is wider than a shell, so the set is explicit. */
const WORD_DELIMITER = /[ \t\n;|&()<>]/;

/**
 * One entry per shell word, true when the word contains an expansion that can
 * turn it into several arguments.
 *
 * `shell-quote` only marks `*` and `?` as globs, but bracket (`[ab]`) and brace
 * (`{a,b}`) expansion, and parameter expansion, change the argument count too.
 * This scan is quote- and escape-aware, so quoted or escaped bracket, brace, and
 * glob markers are not flagged here. `shell-quote` still reports an escaped
 * `*`/`?` as a glob token, which stays conservatively reviewed.
 *
 * A parameter inside double quotes counts as uncertain for the same reason: it
 * stays one word only after expansion, and the value decides both the text and —
 * for `"$@"` — the count. `sort "${X:--oout}" file` writes a file when `X` is
 * unset, `find . "${X:--delete}"` deletes, and `uniq "$@"` can become two
 * operands, while `shell-quote` sees only an empty string. Single quotes and an
 * escaped `\$` are literal and stay safe. Matching the flags by position keeps
 * the raw text out of the parsed logic.
 */
interface WordFact { dynamic: boolean; home: boolean }
interface HomeBinding { trusted: boolean }
interface WordState extends WordFact { present: boolean; homeEnd: number; quote?: "'" | '"' | "$'" }
function wordExpansions(command: string): WordFact[] {
  const expansions: WordFact[] = [];
  const state: WordState = { present: false, dynamic: false, home: false, homeEnd: 0 };
  const flush = () => {
    if (state.present) expansions.push({ dynamic: state.dynamic, home: state.home });
    state.present = false; state.dynamic = false; state.home = false;
  };
  for (let index = 0; index < command.length; index++) {
    const character = command[index];
    if (state.quote) { index = quotedWordCharacter(command, index, state); continue; }
    if (character === "#" && !state.present) {
      const end = command.indexOf("\n", index);
      if (end === -1) break;
      index = end;
      continue;
    }
    if (WORD_DELIMITER.test(character)) { flush(); continue; }
    if (!state.present) startWord(command, index, state);
    state.present = true;
    index = unquotedWordCharacter(command, index, state);
  }
  flush();
  return expansions;
}

function startWord(command: string, index: number, state: WordState): void {
  const prefix = /^(?:~(?=\/|$|[\s;|&()<>])|\$(?:HOME|\{HOME\})(?=\/|$|[\s;|&()<>])|"\$(?:HOME|\{HOME\})(?=\/|"))/.exec(command.slice(index))?.[0];
  state.home = prefix !== undefined;
  state.homeEnd = index + (prefix?.length ?? 0);
  state.dynamic = command[index] === "~" && !state.home;
}

function markExpansion(state: WordState, index: number): void {
  state.dynamic = true;
  state.home = state.home && index < state.homeEnd;
}

function unquotedWordCharacter(command: string, index: number, state: WordState): number {
  const character = command[index];
  if (character === "\\") return index + 1;
  if (character === "'" || character === '"') state.quote = character;
  else if (character === "$" && command[index + 1] === "'") { state.quote = "$'"; return index + 1; }
  else if (/[*?[{$]/.test(character)) markExpansion(state, index);
  return index;
}

function quotedWordCharacter(command: string, index: number, state: WordState): number {
  const character = command[index];
  if (state.quote === "'") {
    if (character === "'") state.quote = undefined;
    return index;
  }
  if (character === "\\") return index + 1;
  if (state.quote === "$'") {
    if (character === "'") state.quote = undefined;
  } else if (character === '"') state.quote = undefined;
  else if (character === "$") markExpansion(state, index);
  return index;
}

/** String tokens that no simple command consumed, such as words inside `$(...)`. */
function leftoverWords(tokens: readonly Token[], consumed: ReadonlySet<number>): string[] {
  return tokens.flatMap((token, index) => {
    if (consumed.has(index)) return [];
    if (typeof token === "string") return [token];
    if ("op" in token && token.op === "glob" && token.pattern !== undefined) return [token.pattern];
    return [];
  });
}

/** Mutable state of one left-to-right token scan over a parsed line. */
interface LineScan {
  segments: Segment[];
  redirects: string[];
  consumed: Set<number>;
  current: Segment;
  redirect?: { write: boolean; op: string };
  uncertainRedirect: boolean;
  wordIndex: number;
  binding: HomeBinding;
}

function newSegment(): Segment {
  return { words: [], globs: [], homes: [], write: false };
}

/** Splits parsed tokens into simple commands, tracking whether the whole line parsed. */
function lineSegments(tokens: readonly Token[], expansions: readonly WordFact[], binding: HomeBinding): ParsedLine {
  const scan: LineScan = {
    segments: [], redirects: [], consumed: new Set(), current: newSegment(),
    uncertainRedirect: false, wordIndex: 0, binding,
  };
  scan.segments.push(scan.current);
  let position = 0;
  for (const token of tokens) {
    if (!consumeToken(scan, token, position++, expansions)) return failedLine(scan, tokens);
  }
  return finishParsedLine({
    segments: scan.segments,
    redirects: scan.redirects,
    leftovers: leftoverWords(tokens, scan.consumed),
    complete: scan.redirect === undefined && !scan.uncertainRedirect,
  }, binding);
}

/** Feeds one token to the scan; false means the token is invalid in this position. */
function consumeToken(scan: LineScan, token: Token, index: number, expansions: readonly WordFact[]): boolean {
  if (typeof token === "string") { consumeStringToken(scan, token, index, expansions); return true; }
  if ("comment" in token) return true;
  if (token.op === "glob" && token.pattern !== undefined) { consumeGlobToken(scan, token.pattern, index, expansions); return true; }
  if (CONTROL_OPERATORS.has(token.op)) return consumeControlToken(scan);
  if (REDIRECT_OPERATORS.has(token.op)) {
    // Descriptor prefixes (`2>` in `2>/dev/null`) are stripped from the source
    // before parsing, so a numeric word here is an operand and must survive.
    scan.redirect = { write: WRITE_OPERATORS.has(token.op), op: token.op };
    return true;
  }
  return false;
}

function failedLine(scan: LineScan, tokens: readonly Token[]): ParsedLine {
  scan.binding.trusted = false;
  return { segments: scan.segments, redirects: scan.redirects, leftovers: leftoverWords(tokens, scan.consumed), complete: false };
}

function nextExpansion(scan: LineScan, expansions: readonly WordFact[]): WordFact {
  return bindHomeWord(expansions[scan.wordIndex++] ?? { dynamic: false, home: false }, scan.current.words, scan.binding);
}

function consumeStringToken(scan: LineScan, token: string, index: number, expansions: readonly WordFact[]): void {
  if (scan.redirect) consumeRedirectTarget(scan, token, expansions);
  else addCommandWord(scan, token, expansions);
  scan.consumed.add(index);
}

function addCommandWord(scan: LineScan, word: string, expansions: readonly WordFact[]): void {
  scan.current.words.push(word);
  addWordFact(scan.current, nextExpansion(scan, expansions));
}

function consumeRedirectTarget(scan: LineScan, word: string, expansions: readonly WordFact[]): void {
  const redirect = scan.redirect!;
  const { target, expanded } = redirectWord(word, nextExpansion(scan, expansions));
  // Heredoc delimiters are quote-removed, not expanded. Their bodies and
  // boundaries remain governed by the dedicated heredoc analyzer.
  scan.uncertainRedirect ||= expanded && !["<<", "<<-"].includes(redirect.op);
  const descriptorClose = target === "-" && [">&", "<&"].includes(redirect.op);
  if (redirect.write && target !== "/dev/null" && !descriptorClose) scan.current.write = true;
  addPathRedirect(scan.redirects, target, redirect.op, expanded);
  scan.redirect = undefined;
}

function consumeGlobToken(scan: LineScan, pattern: string, index: number, expansions: readonly WordFact[]): void {
  if (!scan.redirect) { addGlobWord(scan.current, pattern, nextExpansion(scan, expansions)); scan.consumed.add(index); return; }
  // A glob is still a redirection target, so it never becomes a command word.
  nextExpansion(scan, expansions);
  scan.uncertainRedirect = true;
  scan.redirects.push(pattern);
  scan.consumed.add(index);
  if (scan.redirect.write) scan.current.write = true;
  scan.redirect = undefined;
}

function consumeControlToken(scan: LineScan): boolean {
  // A control operator before the redirection target is invalid syntax.
  if (scan.redirect) return false;
  finishHomeSegment(scan.current, scan.binding);
  scan.current = newSegment();
  scan.segments.push(scan.current);
  return true;
}

/** The same token-to-command representation used by the guard and residual scoring. */
function parsedLine(command: string, binding: HomeBinding = { trusted: true }): ParsedShellCommands {
  const tokens = parseShell(command);
  const parsed = lineSegments(tokens, wordExpansions(stripDescriptorPrefixes(command)), binding);
  return {
    ...parsed,
    operands: tokens.flatMap((token) => typeof token === "string" ? [token] :
      "op" in token && token.op === "glob" && token.pattern !== undefined ? [token.pattern] : []),
    complete: parsed.complete && !hasAmbiguousDescriptorClose(command) && !DYNAMIC_SYNTAX.test(command),
    compound: tokens.some((token) => typeof token !== "string" && "op" in token && CONTROL_OPERATORS.has(token.op)),
  };
}

/**
 * Bounded literal commands only. No heredoc/script interpretation or dynamic
 * expansion is inferred here; callers must retain guardShell's manual floor.
 * `limits.maxChars` lets the pre-ask deny scan parse an oversized command
 * without changing the guard's own manual-approval limit.
 */
export function parseShellCommands(command: string, limits: { maxChars?: number; homeBinding?: HomeBinding } = {}): ParsedShellCommands | undefined {
  const normalized = boundedCommand(command, limits.maxChars ?? MAX_COMMAND_CHARS);
  if (normalized === undefined) return undefined;
  const { lines, certain } = logicalLines(normalized);
  if (certain < lines.length) return undefined;
  return parseLines(lines, requestHomeBinding(limits));
}

/** The continuation-normalized source, or undefined when it cannot be decoded. */
function boundedCommand(command: string, maxChars: number): string | undefined {
  if (!command || command.length > maxChars || hasUndecodedSyntax(command)) return undefined;
  const normalized = normalizeContinuations(command);
  if (hasUndecodedSyntax(normalized) || hasHeredoc(normalized)) return undefined;
  return normalized;
}

function parseLines(lines: readonly string[], binding: HomeBinding): ParsedShellCommands | undefined {
  const result: ParsedShellCommands = { segments: [], operands: [], redirects: [], leftovers: [], complete: true, compound: false };
  try {
    for (const line of lines) {
      if (!line.trim() || line.trim().startsWith("#")) continue;
      if (!BALANCED_QUOTES.test(line)) return undefined;
      mergeParsed(result, parsedLine(line, binding));
    }
  } catch { return undefined; }
  result.compound ||= result.segments.filter((segment) => segment.words.length).length > 1;
  return result;
}

function mergeParsed(result: ParsedShellCommands, parsed: ParsedShellCommands): void {
  result.segments.push(...parsed.segments);
  result.operands.push(...parsed.operands);
  result.redirects.push(...parsed.redirects);
  result.leftovers.push(...parsed.leftovers);
  result.complete &&= parsed.complete;
  result.compound ||= parsed.compound;
}

/**
 * True when one parsed simple command reads or writes a protected path.
 *
 * The command's own grammar decides which words are files, which are data and
 * which are ordinary options. A data word (`grep auth file`'s pattern, a `sed`
 * script, a `jq` filter, a `--grep=` value) is never treated as a path, while a
 * path word is checked with `isProtectedPathOperand` and every other word keeps
 * the generic shell-word check.
 */
export function segmentPathPolicies(segment: { words: readonly string[]; globs?: readonly boolean[]; homes?: readonly boolean[] }, projectDir?: string): PathPolicy[] {
  const roles = operandRoles(segment.words);
  const values = [...roles.pathValueSources, ...roles.paths.map((index) => ({ value: segment.words[index], index }))];
  return values.filter(({ index }) => resolvedWord(segment, index))
    .map(({ value, index }) => segmentOperandPolicy(segment, value, index, roles.paths, projectDir));
}

export function protectedSegment(segment: { words: readonly string[] }, projectDir?: string): boolean {
  if (["ls", "stat"].includes(resolveExecutable(segment.words)?.name ?? "")) return false;
  return segmentPathPolicies(segment, projectDir).some((fact) => fact.kind === "protected");
}

function protectedCommands(parsed: ParsedLine, projectDir?: string): boolean {
  return parsed.redirects.some((target) => isProtected(target, projectDir)) ||
    parsed.segments.some((segment) => protectedSegment(segment, projectDir));
}

export function segmentNeedsPathReview(segment: { words: readonly string[] }, directory?: string): boolean {
  if (segmentPathPolicies(segment, directory).some((fact) => fact.review)) return true;
  const roles = operandRoles(segment.words);
  return segment.words.some((word, index) => !roles.paths.includes(index) && !roles.data.includes(index) &&
    shellWordNeedsReview(word, directory));
}

function analyzeLine(command: string, projectDir: string | undefined, binding: HomeBinding): Verdict {
  if (!command.trim()) return { decision: "allow" };
  if (!BALANCED_QUOTES.test(command)) { binding.trusted = false; return { decision: "ask" }; }
  if (FORK_BOMB.test(command)) return { decision: "deny", reason: "dangerous shell operation" };

  const tokens = tryParseTokens(command, binding);
  if (tokens === undefined) return { decision: "ask" };

  const parsed = parsedLine(command, binding);
  // A redirection always names a file, so its target takes the full path-aware
  // check. Each simple command is judged by its own grammar: a pattern, script
  // or filter is data even when it is spelled like a path, while a file operand
  // keeps the protected-path check. Tokens no command consumed (words inside a
  // substitution) keep the generic shell-word check. None of this depends on the
  // line parsing completely: a deny visible in the literal text must win over the
  // parser uncertainty.
  const blocked = visibleLineDenyText(tokens, parsed, projectDir);
  if (blocked !== undefined) return { decision: "deny", reason: blocked };
  // Bash closes the descriptor and runs the rest of the word as a command
  // (`2>&-sudo id` runs sudo), while shell-quote reads `-sudo` as the redirect
  // target. Neither reading may approve the invocation.
  if (hasAmbiguousDescriptorClose(command) || !parsed.complete || DYNAMIC_SYNTAX.test(command)) return { decision: "ask" };
  return segmentVerdicts(parsed, projectDir);
}

function tryParseTokens(command: string, binding: HomeBinding): Token[] | undefined {
  try { return parseShell(command); }
  catch { binding.trusted = false; return undefined; }
}

/** Denies that are visible in the parsed text, in their precedence order. */
function visibleLineDenyText(tokens: readonly Token[], parsed: ParsedShellCommands, projectDir?: string): string | undefined {
  if (protectedCommands(parsed, projectDir)) return "protected path access";
  // Deny rules that are already visible must win even when later arguments are
  // dynamic (`sudo id $(...)`) and even when the line only parses partially.
  for (const segment of parsed.segments) {
    const blocked = denyInvocation(staticSegmentWords(segment));
    if (blocked !== undefined) return blocked;
  }
  return hasRemoteShellPipe(tokens) ? "remote download piped to a shell" : undefined;
}

function segmentVerdicts(parsed: ParsedShellCommands, projectDir?: string): Verdict {
  let ask = false;
  let review = commandsNeedPathReview(parsed.redirects, parsed.segments, projectDir);
  for (const segment of parsed.segments) {
    const verdict = analyzeSegment(segment);
    if (verdict.decision === "deny") return verdict;
    if (verdict.decision === "ask") ask = true;
    else if (verdict.decision === "review") review = true;
  }
  if (ask) return { decision: "ask" };
  return { decision: review ? "review" : "allow" };
}

/** Analyzes every logical line, keeping deny precedence over ask and review. */
function analyzeLines(command: string, projectDir: string | undefined, binding: HomeBinding): Verdict {
  let ask = false;
  let review = false;
  const { lines, certain } = logicalLines(command);
  // An undecodable header or a body that can move its terminator leaves the
  // script/data split unknown, so nothing past that line may be auto-approved.
  if (certain < lines.length) ask = true;
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const verdict = analyzeLine(trimmed, projectDir, binding);
    if (verdict.decision === "deny") return verdict;
    if (verdict.decision === "ask") ask = true;
    else if (verdict.decision === "review") review = true;
  }
  if (ask) return { decision: "ask" };
  return { decision: review ? "review" : "allow" };
}

interface HeredocBody { lines: string[]; quoted: boolean }
type HeredocMarker = ReturnType<typeof heredocMarkers>[number];

function analyzeHeredoc(command: string, projectDir: string | undefined, binding: HomeBinding): Verdict {
  const lines = command.split("\n");
  const firstLine = lines[0] ?? "";
  const markers = heredocMarkers(firstLine);
  if (!markers.length) return { decision: "ask" };
  const collected = collectBodies(lines, markers);
  if (collected === undefined) return { decision: "ask" };

  // The header line is script, and so is the text after the bodies — but only if
  // the bodies really end where the raw text says. The header is analyzed on its
  // own because its markers have already been consumed above: handing them back
  // to the heredoc scanner would swallow the tail as a second body.
  const header = analyzeLine(firstLine, projectDir, binding);
  if (header.decision === "deny") return header;
  // An unquoted body is matched against its terminator after the shell removes
  // continuations, so a body line ending in a backslash moves the boundary —
  // including the last one, whose `\`-newline joins the terminator line into the
  // body. That has to fail closed before the tail is judged, or a tail that is
  // really body data would deny. A quoted body keeps its backslashes literally.
  if (collected.bodies.some(unstableBoundary)) return { decision: "ask" };
  return heredocTailVerdict(firstLine, lines, collected, header, projectDir, binding);
}

/** Reads every heredoc body in order; undefined when one never terminates. */
function collectBodies(lines: readonly string[], markers: readonly HeredocMarker[]): { bodies: HeredocBody[]; end: number } | undefined {
  const bodies: HeredocBody[] = [];
  let index = 1;
  for (const marker of markers) {
    const body: string[] = [];
    let closed = false;
    while (index < lines.length) {
      const candidate = marker.stripTabs ? lines[index].replace(/^\t+/, "") : lines[index];
      index++;
      if (candidate === marker.delimiter) { closed = true; break; }
      body.push(candidate);
    }
    if (!closed) return undefined;
    bodies.push({ lines: body, quoted: marker.quoted });
  }
  return { bodies, end: index };
}

/** True when a body line's trailing backslash can move the terminator. */
function unstableBoundary(body: HeredocBody): boolean {
  return !body.quoted && body.lines.some((line) => line.endsWith("\\"));
}

/** True when an unquoted body can run a substitution during expansion. */
function expandedBody(body: HeredocBody): boolean {
  return !body.quoted && DYNAMIC_SYNTAX.test(body.lines.join("\n"));
}

/** Judges the tail after the bodies and folds it with the header verdict. */
function heredocTailVerdict(firstLine: string, lines: readonly string[], collected: { bodies: HeredocBody[]; end: number },
  header: Verdict, projectDir: string | undefined, binding: HomeBinding): Verdict {
  // The tail is analyzed as its own script so a further heredoc there is routed
  // the same way, and a blocked command spanning a quoted newline is still seen
  // whole.
  const tail = lines.slice(collected.end).join("\n");
  invalidateHeredocHome(collected.bodies, binding);
  const rest: Verdict = tail ? analyze(tail, projectDir, binding) : { decision: "allow" };
  if (rest.decision === "deny") return rest;
  // Unquoted heredoc bodies undergo command and parameter expansion. That can run
  // a substitution, so it fails closed, but it cannot move the terminator: the
  // tail denied above stays a deny.
  const ask = header.decision === "ask" || rest.decision === "ask" ||
    collected.bodies.some(expandedBody) || headerRunsShell(firstLine);
  if (ask) return { decision: "ask" };
  return { decision: header.decision === "review" || rest.decision === "review" ? "review" : "allow" };
}

/** True when the header's own executable is unbounded, or the header cannot parse. */
function headerRunsShell(firstLine: string): boolean {
  try {
    const words = parseShell(firstLine).filter((token): token is string => typeof token === "string");
    const executable = resolveExecutable(words);
    return executable === undefined || SHELLS.has(executable.name) || SCRIPT_HOSTS.has(executable.name) ||
      DYNAMIC.has(executable.name) || STATEFUL.has(executable.name);
  } catch { return true; }
}

/**
 * True when a recursive or forced `rm` targets the user's home directory or a
 * path outside the project.
 *
 * GNU option parsing accepts abbreviations, so `--recursi` and `--forc` are the
 * same flags as `--recursive` and `--force`. The caller supplies decoded literal
 * operands, including only lexically established home expansions. Shared
 * component resolution preserves symlink/.. behavior. Missing scope and
 * unresolved expansions cannot establish an external deletion; known outside
 * targets still deny independently of later parser uncertainty.
 */
export function recursiveExternalDelete(words: readonly string[], projectDir?: string, worktreeRoot?: string): boolean {
  if (words[0] !== "rm") return false;
  const scan = scanRmArguments(words.slice(1));
  if (!scan.risky || !scan.targets.length) return false;
  return scan.targets.some((target) => establishedExternalTarget(target, projectDir, worktreeRoot));
}

/** Separates recursive/forced flags from operand targets, as `rm` reads them. */
function scanRmArguments(args: readonly string[]): { risky: boolean; targets: string[] } {
  const scan: RmScan = { risky: false, end: false, targets: [] };
  for (const word of args) consumeRmWord(scan, word);
  return { risky: scan.risky, targets: scan.targets };
}

interface RmScan { risky: boolean; end: boolean; targets: string[] }

function consumeRmWord(scan: RmScan, word: string): void {
  if (scan.end || !word.startsWith("-") || word.length <= 1) { scan.targets.push(word); return; }
  if (word === "--") { scan.end = true; return; }
  if (word.startsWith("--")) {
    // Prefix matching covers `--recursi`/`--forc` and other unambiguous prefixes.
    scan.risky ||= isLongOption(word, "--recursive") || isLongOption(word, "--force");
    return;
  }
  scan.risky ||= /^-[^-]*[rRf]/.test(word);
}

/**
 * The literal prefix of a line that precedes syntax this policy does not decode.
 * The marker and everything after it are never inspected, because an undecoded
 * quote or expansion can move word and line boundaries.
 */
function visiblePrefix(line: string): string {
  let cut = line.length;
  for (const opener of ["$'", '$"', "$["]) {
    const index = line.indexOf(opener);
    if (index !== -1 && index < cut) cut = index;
  }
  const whitespace = line.search(/[^\S \t]/);
  if (whitespace !== -1 && whitespace < cut) cut = whitespace;
  return line.slice(0, cut);
}

/** The executable name and effective argv after leading wrappers are removed. */
function effectiveInvocation(words: readonly string[]): { name: string; argv: string[] } {
  const executable = resolveExecutable(words);
  const argv = executable ? words.slice(executable.index) : [...words];
  const name = basename(argv[0] ?? "");
  return { name, argv: [name, ...argv.slice(1)] };
}

/**
 * Mandatory denies visible before the syntax that makes the guard ask.
 *
 * The guard cannot approve text it cannot decode, but a deny it can already see
 * must still win over that manual-approval floor: `cat .env # $'` is still a
 * protected-path read, `sudo id\necho $'x'` still elevates, and `rm -rf
 * /outside # $'` still deletes outside the project. Only the literal prefix of
 * each line is judged; a line that is not certainly script, or whose prefix is
 * not balanced and static, contributes no deny and keeps the ask.
 *
 * The protected-path, blocked-invocation and recursive-delete checks run on
 * whatever the prefix parsed into; `complete` only gates the pipeline shape that
 * needs the whole line. Otherwise a trailing `$(...)` or `$'...'` would erase a
 * deny that is already visible.
 */
export function visibleShellDeny(resources: readonly string[], projectDir?: string, worktreeRoot?: string): string | undefined {
  for (const resource of resources) {
    const homeBinding = { trusted: true };
    // Per-resource cap, not a shared budget: an earlier resource must not spend
    // the bytes that would reveal a deny in a later one.
    const text = resource.slice(0, MAX_COMMAND_BYTES);
    const { lines, certain } = logicalLines(normalizeContinuations(text));
    for (const line of lines.slice(0, certain)) {
      const visible = visiblePrefix(line).trim();
      if (!visible || visible.startsWith("#")) continue;
      const denied = visibleShellLineDeny(visible, projectDir, worktreeRoot, homeBinding);
      if (denied !== undefined) return denied;
    }
  }
  return undefined;
}

/** Mandatory denies visible in one literal, balanced line prefix. */
function visibleShellLineDeny(visible: string, projectDir: string | undefined, worktreeRoot: string | undefined,
  homeBinding: HomeBinding): string | undefined {
  if (FORK_BOMB.test(visible)) return "dangerous shell operation";
  const parsed = parseShellCommands(visible, { maxChars: MAX_COMMAND_BYTES, homeBinding });
  if (parsed === undefined) { homeBinding.trusted = false; return undefined; }
  if (protectedCommands(parsed, projectDir)) return "protected path access";
  const commands = parsed.segments.map((segment) => effectiveInvocation(staticSegmentWords(segment)));
  const blocked = blockedInvocation(commands);
  if (blocked !== undefined) return blocked;
  if (commands.some((command) => recursiveExternalDelete(command.argv, projectDir, worktreeRoot)))
    return "Recursive/force deletion outside the project";
  if (!parsed.complete) return undefined;
  return visibleRemotePipeDeny(visible);
}

function blockedInvocation(commands: readonly { argv: readonly string[] }[]): string | undefined {
  for (const command of commands) {
    const blocked = denyInvocation(command.argv);
    if (blocked !== undefined) return blocked;
  }
  return undefined;
}

function visibleRemotePipeDeny(visible: string): string | undefined {
  try { return hasRemoteShellPipe(parseShell(visible)) ? "remote download piped to a shell" : undefined; }
  catch { return undefined; /* Unknown pipeline shape is review evidence, not a deny. */ }
}

function analyze(command: string, projectDir: string | undefined, binding: HomeBinding): Verdict {
  // A shell separates words only on space, tab, and newline. JS `\s` (and the
  // parser behind it) also matches CR, FF, VT, NBSP, and Unicode spaces, which
  // can move a heredoc boundary or turn a midword hash into a comment, so any of
  // them fails closed before normalization, the deny pass, or parsing.
  //
  // `$[` is the legacy arithmetic expansion: the `<<` inside it is a shift, not
  // a heredoc, so heredoc routing would treat the rest of the script as a body
  // and swallow a trailing command. Extended quoting has the same problem from
  // the other side: `$'...'` lets a backslash escape its own quote, so a quote
  // scan can end the string early and read `<<EOF` as a heredoc, and `$"..."`
  // is a locale quote this parser does not decode. Reject all three on the raw
  // source before normalization or heredoc routing, conservatively including
  // quoted and heredoc data.
  if (hasUndecodedSyntax(command)) return { decision: "ask" };
  // Fail closed on any raw heredoc header that normalization cannot be trusted
  // on: the raw source is the only place its marker and delimiter are still
  // intact. Every header is validated, not just the first, because a continued
  // header after a stable body is the same problem. Each raw line before the
  // ambiguity is certainly script — the header line itself runs before the shell
  // reads its body — so a deny visible there is mandatory; everything after may
  // be data and only reaches manual approval.
  const raw = rawHeredocScript(command);
  if (raw.ambiguous) {
    for (const line of raw.lines) {
      // A line whose own normalization assembles unsupported quoting cannot be
      // parsed safely; its deny is left to manual approval instead of guessed.
      if (hasAssembledUndecodedSyntax(line)) continue;
      // The raw line may still carry a `\`-newline that the shell removes before
      // it forms this header; removing it here only reaches the deny pass, and
      // the header line itself is always script.
      const verdict = analyzeLine(normalizeContinuations(line).trim(), projectDir, binding);
      if (verdict.decision === "deny") return verdict;
    }
    return { decision: "ask" };
  }
  // Normalization removes `\`-newlines, so the shell can parse an unsupported
  // form the raw check above could not see: `sort $`+newline+`'\x2doout'` is
  // `sort -oout` to Bash once the pair is gone. The marker itself is never parsed.
  // A deny in the clean prefix before it is still mandatory, so check that first;
  // only then repeat the gate and fail closed before heredoc routing.
  const normalized = normalizeContinuations(command);
  if (hasUndecodedSyntax(normalized)) {
    const blocked = denyCleanPrefix(normalized);
    if (blocked !== undefined) return { decision: "deny", reason: blocked };
    return { decision: "ask" };
  }
  // `logicalLines` must split on the newlines the shell actually treats as
  // separators, and heredoc bodies stay untouched.
  if (hasHeredoc(normalized)) return analyzeHeredoc(normalized, projectDir, binding);
  if (normalized.includes("\n")) return analyzeLines(normalized, projectDir, binding);
  return analyzeLine(normalized, projectDir, binding);
}

export function guardShell(resources: readonly string[], projectDir?: string): ReviewResult | undefined {
  if (process.platform === "win32") return { decision: "ask", reason: "Shell dialect requires manual approval" };
  if (!withinGuardLimits(resources)) return { decision: "ask", reason: "Shell command exceeds parsing limits" };
  let ask = false;
  let review = false;
  for (const resource of resources) {
    const verdict = analyze(resource, projectDir, { trusted: true });
    if (verdict.decision === "deny") return { decision: "deny", reason: verdict.reason };
    if (verdict.decision === "ask") ask = true;
    else if (verdict.decision === "review") review = true;
  }
  if (ask) return { decision: "ask", reason: "Shell syntax requires further review" };
  return review ? undefined : { decision: "allow", reason: "read-only command" };
}

/** Count and per-resource/aggregate byte caps for one guard invocation. */
function withinGuardLimits(resources: readonly string[]): boolean {
  return resources.length > 0 && resources.length <= 256 &&
    resources.every((resource) => resource.length <= MAX_COMMAND_CHARS) &&
    resources.reduce((sum, resource) => sum + Buffer.byteLength(resource), 0) <= MAX_COMMAND_BYTES;
}

function addPathRedirect(redirects: string[], target: string, operator: string, expanded: boolean): void {
  if (expanded || ["<<", "<<-", "<<<"].includes(operator)) return;
  if ([">&", "<&"].includes(operator) && /^(?:\d+|-)$/.test(target)) return;
  redirects.push(target);
}

function addWordFact(segment: Segment, fact: WordFact): void {
  segment.globs.push(fact.dynamic);
  segment.homes.push(fact.home);
}

function redirectWord(word: string, fact: WordFact): { target: string; expanded: boolean } {
  return { target: shellPathSpelling(word, fact.home), expanded: fact.dynamic && !fact.home };
}

function resolvedWord(segment: { globs?: readonly boolean[]; homes?: readonly boolean[] }, index: number): boolean {
  return !segment.globs?.[index] || segment.homes?.[index] === true;
}

/** Expanded text is not a literal operand even when the parser returns a suffix. */
export function staticSegmentWords(segment: { words: readonly string[]; globs?: readonly boolean[]; homes?: readonly boolean[] }): string[] {
  return segment.words.map((word, index) => !resolvedWord(segment, index) && !/^\/+\*+$/.test(word) ? "" : shellPathSpelling(word, segment.homes?.[index] === true));
}

function commandsNeedPathReview(redirects: string[], segments: Segment[], directory?: string): boolean {
  return redirects.some((target) => pathOperandPolicy(target, directory).review) ||
    segments.some((segment) => segmentNeedsPathReview(segment, directory));
}

/** Associate a download with its pipeline, not an unrelated command in a chain. */
function hasRemoteShellPipe(tokens: readonly Token[]): boolean {
  const state: PipelineProof = { downloaded: false, words: [], uncertain: false };
  for (const token of tokens) {
    if (typeof token === "string") { state.words.push(token); continue; }
    if ("comment" in token) continue;
    const operator = pipelineBoundary(token);
    if (operator) { if (advancePipeline(state, operator)) return true; }
    else state.uncertain = true;
  }
  return !state.uncertain && state.downloaded && shellConsumesInput(state.words);
}

function pipelineBoundary(token: Exclude<Token, string>): string | undefined {
  return "op" in token && CONTROL_OPERATORS.has(token.op) ? token.op : undefined;
}

function pipelineStep(words: string[], operator: string, downloaded: boolean): { denied: boolean; downloaded: boolean } {
  return { denied: downloaded && shellConsumesInput(words),
    downloaded: ["|", "|&"].includes(operator) && remoteDownload(words) };
}

function followsFinalLink(executable: ReturnType<typeof resolveExecutable>, words: readonly string[]): boolean {
  if (!executable) return false;
  if (["rm", "mv"].includes(executable.name)) return false;
  return !(executable.name === "git" && words[executable.index + 1] === "add");
}

function shellConsumesInput(words: readonly string[]): boolean {
  const executable = resolveExecutable(words);
  if (!executable || !SHELLS.has(executable.name)) return false;
  return words.slice(executable.index + 1).every((arg) => /^-(?:[a-bd-mo-zA-Z]+)?$/.test(arg) || arg === "--");
}

/** Only explicit endpoints and understood stdout-fetch flags establish this
 * prohibition; config files, output files and unknown client options review. */
function remoteDownload(words: readonly string[]): boolean {
  const executable = resolveExecutable(words);
  if (!executable || !["curl", "wget"].includes(executable.name)) return false;
  const args = downloadArguments(executable.name, words.slice(executable.index + 1));
  return args !== undefined && args.length > 0 && args.every(remoteEndpoint);
}

function remoteEndpoint(endpoint: string): boolean {
  if (/[$`\s]/.test(endpoint)) return false;
  return /^(?:https?|ftps?|sftp|scp|gopher|dict|ldaps?):\/\//i.test(endpoint) ||
    /^[a-z0-9][a-z0-9.-]*(?::\d+)?(?:\/[^\s$`]*)?$/i.test(endpoint);
}

function stdoutFetchFlag(name: string, arg: string): boolean {
  return name === "curl" ? /^-[fsSL]+$/.test(arg) || ["--fail", "--silent", "--show-error", "--location"].includes(arg)
    : ["-q", "--quiet"].includes(arg);
}

function establishedExternalTarget(target: string, directory?: string, root?: string): boolean {
  if (!directory || !root || !target || /[$`]/.test(target)) return false;
  const destination = classifyPath(target, directory, undefined, false);
  const scope = classifyPath(root, directory);
  if (destination.kind === "unresolved" || scope.kind === "unresolved" || !destination.resolved || !scope.resolved) return false;
  return !isInProject(destination.resolved, scope.resolved);
}

function segmentOperandPolicy(segment: { words: readonly string[]; homes?: readonly boolean[]; globs?: readonly boolean[] }, value: string, index: number, paths: readonly number[], directory?: string): PathPolicy {
  const executable = resolveExecutable(segment.words);
  const follow = executable?.name === "cp" ? copyPathMode(segment.words, index, copyOperands(segment, paths), directory) : followsFinalLink(executable, segment.words);
  if (follow === undefined) return { kind: "unresolved", review: true, reason: "Copy operand mode is unresolved" };
  return pathOperandPolicy(value, directory, follow, segment.homes?.[index]);
}

function downloadArguments(name: string, args: readonly string[]): readonly string[] | undefined {
  const endpoints: string[] = [];
  let stdout = name === "curl";
  let end = false;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (!end && arg === "--") { end = true; continue; }
    if (end || !arg.startsWith("-")) { endpoints.push(arg); continue; }
    const option = downloadOption(name, arg, args[index + 1]);
    if (!option) return undefined;
    index += option.skip;
    stdout ||= option.stdout === true;
  }
  return stdout ? endpoints : undefined;
}

function bindHomeWord(fact: WordFact, words: readonly string[], binding: HomeBinding): WordFact {
  if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(words[0] ?? "")) binding.trusted = false;
  const bound = fact.home && !binding.trusted ? { dynamic: true, home: false } : fact;
  if (fact.dynamic && !fact.home) binding.trusted = false;
  return bound;
}

function finishHomeSegment(segment: Segment, binding: HomeBinding): void {
  if (segment.words.length && !isReadOnlyInvocation(segment.words, segment.globs)) binding.trusted = false;
}

function finishParsedLine(line: ParsedLine, binding: HomeBinding): ParsedLine {
  finishHomeSegment(line.segments.at(-1)!, binding);
  if (!line.complete) binding.trusted = false;
  return line;
}

function requestHomeBinding(limits: { homeBinding?: HomeBinding }): HomeBinding {
  return limits.homeBinding ?? { trusted: true };
}

function addGlobWord(segment: Segment, word: string, fact: WordFact): void {
  segment.words.push(word); addWordFact(segment, { ...fact, dynamic: true, home: false });
}

function invalidateHeredocHome(bodies: { lines: string[]; quoted: boolean }[], binding: HomeBinding): void {
  if (bodies.some((body) => !body.quoted && /[$`]/.test(body.lines.join("\n")))) binding.trusted = false;
}

function copyOperands(segment: { words: readonly string[]; homes?: readonly boolean[]; globs?: readonly boolean[] }, paths: readonly number[]) {
  return paths.map((index) => ({ index, path: resolvedWord(segment, index) ? shellPathSpelling(segment.words[index], segment.homes?.[index] === true) : undefined }));
}

interface PipelineProof { downloaded: boolean; words: string[]; uncertain: boolean }
function advancePipeline(state: PipelineProof, operator: string): boolean {
  const next = state.uncertain ? { denied: false, downloaded: false } : pipelineStep(state.words, operator, state.downloaded);
  state.downloaded = next.downloaded; state.words = []; state.uncertain = false;
  return next.denied;
}

interface DownloadOption { skip: number; stdout?: true }
function downloadOption(name: string, arg: string, next?: string): DownloadOption | undefined {
  if (stdoutFetchFlag(name, arg)) return { skip: 0 };
  if (name === "wget" && arg === "-qO-") return { skip: 0, stdout: true };
  const short = name === "curl" ? "-o" : "-O";
  const long = name === "curl" ? "--output" : "--output-document";
  return outputOption(arg, next, short, long);
}

function outputOption(arg: string, next: string | undefined, short: string, long: string): DownloadOption | undefined {
  if (arg === short || arg === long) return next === "-" ? { skip: 1, stdout: true } : undefined;
  const value = attachedOutput(arg, short, long);
  return value === "-" ? { skip: 0, stdout: true } : undefined;
}

function attachedOutput(arg: string, short: string, long: string): string | undefined {
  if (arg.startsWith(`${long}=`)) return arg.slice(long.length + 1);
  return arg.startsWith(short) ? arg.slice(short.length) : undefined;
}
