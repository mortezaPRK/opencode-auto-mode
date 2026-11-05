import { homedir } from "node:os";
import { basename, resolve } from "node:path";
import type { ReviewResult } from "./reviewer.js";
import { isInProject, isProtected, isProtectedPathOperand, isProtectedShellWord } from "./tiers.js";
import {
  BALANCED_QUOTES, CONTROL_OPERATORS, DYNAMIC, REDIRECT_OPERATORS, SCRIPT_HOSTS, SHELLS, STATEFUL,
  denyCleanPrefix, denyInvocation, hasAmbiguousDescriptorClose, hasAssembledUndecodedSyntax, hasHeredoc,
  hasUndecodedSyntax, heredocMarkers, isLongOption, isReadOnlyInvocation, logicalLines, normalizeContinuations,
  operandRoles, parseShell, rawHeredocScript, resolveExecutable, stripDescriptorPrefixes,
} from "./shell-policy.js";

const MAX_COMMAND_CHARS = 4096;
const MAX_COMMAND_BYTES = 65_536;
const WRITE_OPERATORS = new Set([">", ">>", ">|", "&>", "&>>", "<>", ">&"]);
const DYNAMIC_SYNTAX = /\$\(|`|\$\(\s*\(|[<>]\(|\$\[/;
const FORK_BOMB = /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/;

interface Segment { words: string[]; globs: boolean[]; write: boolean }
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
  const blocked = denyInvocation(segment.words);
  if (blocked !== undefined) return { decision: "deny", reason: blocked };
  if (dynamicExecution(segment.words)) return { decision: "ask" };
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
function wordExpansions(command: string): boolean[] {
  const expansions: boolean[] = [];
  let present = false;
  let expansion = false;
  let wordStart = true;
  let quote: "'" | '"' | "$'" | undefined;
  const flush = () => {
    if (!present) return;
    expansions.push(expansion);
    present = false;
    expansion = false;
  };
  for (let index = 0; index < command.length; index++) {
    const character = command[index];
    if (quote === "'") {
      if (character === "'") quote = undefined;
      continue;
    }
    if (quote === "$'") {
      if (character === "\\") index++;
      else if (character === "'") quote = undefined;
      continue;
    }
    if (quote === '"') {
      if (character === "\\") index++;
      else if (character === '"') quote = undefined;
      else if (character === "$") expansion = true;
      continue;
    }
    if (character === "\\") {
      present = true;
      if (index + 1 < command.length && command[++index] !== "\n") wordStart = false;
      continue;
    }
    if (character === "'" || character === '"' || (character === "$" && command[index + 1] === "'")) {
      present = true;
      wordStart = false;
      if (character === "'" || character === '"') quote = character;
      else { quote = "$'"; index++; }
      continue;
    }
    if (character === "#" && wordStart) {
      const end = command.indexOf("\n", index);
      flush();
      if (end === -1) break;
      index = end;
      wordStart = true;
      continue;
    }
    if (WORD_DELIMITER.test(character)) {
      flush();
      wordStart = true;
      continue;
    }
    if (character === "*" || character === "?" || character === "[" || character === "{" ||
        character === "$") expansion = true;
    present = true;
    wordStart = false;
  }
  flush();
  return expansions;
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

/** Splits parsed tokens into simple commands, tracking whether the whole line parsed. */
function lineSegments(tokens: readonly Token[], expansions: readonly boolean[] = []): ParsedLine {
  const segments: Segment[] = [{ words: [], globs: [], write: false }];
  const redirects: string[] = [];
  const consumed = new Set<number>();
  let current = segments[0];
  let redirect: { write: boolean; op: string } | undefined;
  let uncertainRedirect = false;
  let wordIndex = 0;
  let position = 0;
  const nextExpansion = () => expansions[wordIndex++] ?? false;
  const failed = (): ParsedLine => ({ segments, redirects, leftovers: leftoverWords(tokens, consumed), complete: false });
  for (const token of tokens) {
    const index = position++;
    if (typeof token === "string") {
      if (redirect) {
        const target = token;
        const expanded = nextExpansion();
        // Heredoc delimiters are quote-removed, not expanded. Their bodies and
        // boundaries remain governed by the dedicated heredoc analyzer.
        uncertainRedirect ||= expanded && !["<<", "<<-"].includes(redirect.op);
        const descriptorClose = target === "-" && [">&", "<&"].includes(redirect.op);
        if (redirect.write && target !== "/dev/null" && !descriptorClose)
          current.write = true;
        redirects.push(target);
        consumed.add(index);
        redirect = undefined;
      } else {
        current.words.push(token);
        current.globs.push(nextExpansion());
        consumed.add(index);
      }
      continue;
    }
    if ("comment" in token) continue;
    if (token.op === "glob" && token.pattern !== undefined) {
      if (redirect) {
        // A glob is still a redirection target, so it never becomes a command word.
        nextExpansion();
        uncertainRedirect = true;
        redirects.push(token.pattern);
        consumed.add(index);
        if (redirect.write) current.write = true;
        redirect = undefined;
      } else {
        nextExpansion();
        current.words.push(token.pattern);
        current.globs.push(true);
        consumed.add(index);
      }
      continue;
    }
    if (CONTROL_OPERATORS.has(token.op)) {
      // A control operator before the redirection target is invalid syntax.
      if (redirect) return failed();
      current = { words: [], globs: [], write: false };
      segments.push(current);
      continue;
    }
    if (REDIRECT_OPERATORS.has(token.op)) {
      // Descriptor prefixes (`2>` in `2>/dev/null`) are stripped from the source
      // before parsing, so a numeric word here is an operand and must survive.
      redirect = { write: WRITE_OPERATORS.has(token.op), op: token.op };
      continue;
    }
    return failed();
  }
  return { segments, redirects, leftovers: leftoverWords(tokens, consumed), complete: redirect === undefined && !uncertainRedirect };
}

/** The same token-to-command representation used by the guard and residual scoring. */
function parsedLine(command: string): ParsedShellCommands {
  const tokens = parseShell(command);
  const parsed = lineSegments(tokens, wordExpansions(stripDescriptorPrefixes(command)));
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
export function parseShellCommands(command: string, limits: { maxChars?: number } = {}): ParsedShellCommands | undefined {
  const maxChars = limits.maxChars ?? MAX_COMMAND_CHARS;
  if (!command || command.length > maxChars || hasUndecodedSyntax(command)) return undefined;
  const normalized = normalizeContinuations(command);
  if (hasUndecodedSyntax(normalized) || hasHeredoc(normalized)) return undefined;
  const { lines, certain } = logicalLines(normalized);
  if (certain < lines.length) return undefined;
  const result: ParsedShellCommands = { segments: [], operands: [], redirects: [], leftovers: [], complete: true, compound: false };
  try {
    for (const line of lines) {
      if (!line.trim() || line.trim().startsWith("#")) continue;
      if (!BALANCED_QUOTES.test(line)) return undefined;
      const parsed = parsedLine(line);
      result.segments.push(...parsed.segments);
      result.operands.push(...parsed.operands);
      result.redirects.push(...parsed.redirects);
      result.leftovers.push(...parsed.leftovers);
      result.complete &&= parsed.complete;
      result.compound ||= parsed.compound;
    }
  } catch { return undefined; }
  result.compound ||= result.segments.filter((segment) => segment.words.length).length > 1;
  return result;
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
export function protectedSegment(segment: { words: readonly string[] }, projectDir?: string): boolean {
  const roles = operandRoles(segment.words);
  const data = new Set(roles.data);
  const paths = new Set(roles.paths);
  if (roles.pathValues.some((value) => isProtectedPathOperand(value, projectDir))) return true;
  return segment.words.some((word, index) => {
    if (data.has(index)) return false;
    return paths.has(index) ? isProtectedPathOperand(word, projectDir) : isProtectedShellWord(word, projectDir);
  });
}

function analyzeLine(command: string, projectDir?: string): Verdict {
  if (!command.trim()) return { decision: "allow" };
  if (!BALANCED_QUOTES.test(command)) return { decision: "ask" };
  if (FORK_BOMB.test(command)) return { decision: "deny", reason: "dangerous shell operation" };

  let tokens;
  try { tokens = parseShell(command); }
  catch { return { decision: "ask" }; }

  const { segments, redirects, leftovers, complete } = parsedLine(command);
  // A redirection always names a file, so its target takes the full path-aware
  // check. Each simple command is judged by its own grammar: a pattern, script
  // or filter is data even when it is spelled like a path, while a file operand
  // keeps the protected-path check. Tokens no command consumed (words inside a
  // substitution) keep the generic shell-word check. None of this depends on the
  // line parsing completely: a deny visible in the literal text must win over the
  // manual-approval floor.
  if (redirects.some((target) => isProtected(target, projectDir)) ||
      segments.some((segment) => protectedSegment(segment, projectDir)) ||
      leftovers.some((word) => isProtectedShellWord(word, projectDir)))
    return { decision: "deny", reason: "protected path access" };
  // Deny rules that are already visible must win even when later arguments are
  // dynamic (`sudo id $(...)`) and even when the line only parses partially.
  for (const segment of segments) {
    const blocked = denyInvocation(segment.words);
    if (blocked !== undefined) return { decision: "deny", reason: blocked };
  }
  if (segments.some((segment) => ["curl", "wget"].includes(resolveExecutable(segment.words)?.name ?? "")) &&
      segments.some((segment) => SHELLS.has(resolveExecutable(segment.words)?.name ?? "")) &&
      tokens.some((token) => typeof token !== "string" && "op" in token && ["|", "|&"].includes(token.op)))
    return { decision: "deny", reason: "remote download piped to a shell" };
  // Bash closes the descriptor and runs the rest of the word as a command
  // (`2>&-sudo id` runs sudo), while shell-quote reads `-sudo` as the redirect
  // target. Neither reading may approve the invocation.
  if (hasAmbiguousDescriptorClose(command)) return { decision: "ask" };
  if (!complete || DYNAMIC_SYNTAX.test(command)) return { decision: "ask" };

  let ask = false;
  let review = false;
  for (const segment of segments) {
    const verdict = analyzeSegment(segment);
    if (verdict.decision === "deny") return verdict;
    if (verdict.decision === "ask") ask = true;
    else if (verdict.decision === "review") review = true;
  }
  if (ask) return { decision: "ask" };
  return { decision: review ? "review" : "allow" };
}

/** Analyzes every logical line, keeping deny precedence over ask and review. */
function analyzeLines(command: string, projectDir?: string): Verdict {
  let ask = false;
  let review = false;
  const { lines, certain } = logicalLines(command);
  // An undecodable header or a body that can move its terminator leaves the
  // script/data split unknown, so nothing past that line may be auto-approved.
  if (certain < lines.length) ask = true;
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const verdict = analyzeLine(trimmed, projectDir);
    if (verdict.decision === "deny") return verdict;
    if (verdict.decision === "ask") ask = true;
    else if (verdict.decision === "review") review = true;
  }
  if (ask) return { decision: "ask" };
  return { decision: review ? "review" : "allow" };
}

function analyzeHeredoc(command: string, projectDir?: string): Verdict {
  const lines = command.split("\n");
  const firstLine = lines[0] ?? "";
  const markers = heredocMarkers(firstLine);
  if (!markers.length) return { decision: "ask" };
  let index = 1;
  const bodies: { lines: string[]; quoted: boolean }[] = [];
  for (const marker of markers) {
    const body: string[] = [];
    let closed = false;
    while (index < lines.length) {
      const candidate = marker.stripTabs ? lines[index].replace(/^\t+/, "") : lines[index];
      index++;
      if (candidate === marker.delimiter) { closed = true; break; }
      body.push(candidate);
    }
    if (!closed) return { decision: "ask" };
    bodies.push({ lines: body, quoted: marker.quoted });
  }

  // The header line is script, and so is the text after the bodies — but only if
  // the bodies really end where the raw text says. The header is analyzed on its
  // own because its markers have already been consumed above: handing them back
  // to the heredoc scanner would swallow the tail as a second body.
  const header = analyzeLine(firstLine, projectDir);
  if (header.decision === "deny") return header;
  // An unquoted body is matched against its terminator after the shell removes
  // continuations, so a body line ending in a backslash moves the boundary —
  // including the last one, whose `\`-newline joins the terminator line into the
  // body. That has to fail closed before the tail is judged, or a tail that is
  // really body data would deny. A quoted body keeps its backslashes literally.
  for (const body of bodies) {
    if (body.quoted) continue;
    if (body.lines.some((line) => line.endsWith("\\"))) return { decision: "ask" };
  }
  // The tail is analyzed as its own script so a further heredoc there is routed
  // the same way, and a blocked command spanning a quoted newline is still seen
  // whole.
  const tail = lines.slice(index).join("\n");
  const rest: Verdict = tail ? analyze(tail, projectDir) : { decision: "allow" };
  if (rest.decision === "deny") return rest;
  let ask = header.decision === "ask" || rest.decision === "ask";
  const review = header.decision === "review" || rest.decision === "review";
  // Unquoted heredoc bodies undergo command and parameter expansion. That can run
  // a substitution, so it fails closed, but it cannot move the terminator: the
  // tail denied above stays a deny.
  for (const body of bodies) {
    if (body.quoted) continue;
    if (DYNAMIC_SYNTAX.test(body.lines.join("\n"))) return { decision: "ask" };
  }
  try {
    const words = parseShell(firstLine).filter((token): token is string => typeof token === "string");
    const executable = resolveExecutable(words);
    if (executable === undefined || SHELLS.has(executable.name) || SCRIPT_HOSTS.has(executable.name) ||
        DYNAMIC.has(executable.name) || STATEFUL.has(executable.name)) ask = true;
  } catch { return { decision: "ask" }; }
  if (ask) return { decision: "ask" };
  return { decision: review ? "review" : "allow" };
}

/**
 * True when a recursive or forced `rm` targets the user's home directory or a
 * path outside the project.
 *
 * GNU option parsing accepts abbreviations, so `--recursi` and `--forc` are the
 * same flags as `--recursive` and `--force`. `~` and `~/path` are expanded
 * against the home directory and prefix-matched by containment; the home
 * directory itself is always external, and another user's `~user` cannot be
 * resolved locally, so it also stays external. `$HOME` is not expanded here, and
 * the parser turns an unquoted `$HOME` into an empty word, so both spellings
 * count as the home target.
 */
export function recursiveExternalDelete(words: readonly string[], projectDir?: string, worktreeRoot = projectDir): boolean {
  if (words[0] !== "rm") return false;
  let risky = false;
  let end = false;
  const targets: string[] = [];
  for (const word of words.slice(1)) {
    if (!end && word === "--") { end = true; continue; }
    if (!end && word.startsWith("--")) {
      // Prefix matching covers `--recursi`/`--forc` and other unambiguous prefixes.
      if (isLongOption(word, "--recursive") || isLongOption(word, "--force")) risky = true;
      continue;
    }
    if (!end && word.startsWith("-") && word.length > 1) {
      if (/^-[^-]*[rRf]/.test(word)) risky = true;
      continue;
    }
    targets.push(word);
  }
  if (!risky || targets.length === 0) return false;
  const home = homedir();
  return targets.some((target) => {
    // `$HOME` is not expanded here, and the parser turns an unquoted `$HOME`
    // into an empty word; both spellings name the home directory.
    if (!target || target.startsWith("$HOME") || target.startsWith("${HOME}")) return true;
    if (target.startsWith("~")) {
      // `~` and `~/path` expand against the home directory; another user's
      // `~user` cannot be resolved locally and stays external.
      const expanded = target === "~" || target === "~/" ? home
        : target.startsWith("~/") ? resolve(home, target.slice(2)) : undefined;
      if (expanded === undefined || expanded === home) return true;
      return !projectDir || !worktreeRoot || !isInProject(expanded, worktreeRoot);
    }
    // Without a verified project there is no inside that a delete could be bounded to.
    if (!projectDir || !worktreeRoot) return true;
    return !isInProject(resolve(projectDir, target), worktreeRoot);
  });
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
export function visibleShellDeny(resources: readonly string[], projectDir?: string, worktreeRoot = projectDir): string | undefined {
  for (const resource of resources) {
    // Per-resource cap, not a shared budget: an earlier resource must not spend
    // the bytes that would reveal a deny in a later one.
    const text = resource.slice(0, MAX_COMMAND_BYTES);
    const { lines, certain } = logicalLines(normalizeContinuations(text));
    for (const line of lines.slice(0, certain)) {
      const visible = visiblePrefix(line).trim();
      if (!visible || visible.startsWith("#")) continue;
      if (FORK_BOMB.test(visible)) return "dangerous shell operation";
      const parsed = parseShellCommands(visible, { maxChars: MAX_COMMAND_BYTES });
      if (parsed === undefined) continue;
      if (parsed.redirects.some((target) => isProtected(target, projectDir)) ||
          parsed.segments.some((segment) => protectedSegment(segment, projectDir)) ||
          parsed.leftovers.some((word) => isProtectedShellWord(word, projectDir)))
        return "protected path access";
      const commands = parsed.segments.map((segment) => effectiveInvocation(segment.words));
      for (const command of commands) {
        const blocked = denyInvocation(command.argv);
        if (blocked !== undefined) return blocked;
      }
      if (commands.some((command) => recursiveExternalDelete(command.argv, projectDir, worktreeRoot)))
        return "Recursive/force deletion outside the project";
      if (!parsed.complete) continue;
      if (commands.some((command) => ["curl", "wget"].includes(command.name)) &&
          commands.some((command) => SHELLS.has(command.name))) {
        try {
          if (parseShell(visible).some((token) => typeof token !== "string" && "op" in token &&
              ["|", "|&"].includes(token.op))) return "remote download piped to a shell";
        } catch { /* The prefix parse above already succeeded; treat an unknown pipe shape as no deny. */ }
      }
    }
  }
  return undefined;
}

function analyze(command: string, projectDir?: string): Verdict {
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
      const verdict = analyzeLine(normalizeContinuations(line).trim(), projectDir);
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
  if (hasHeredoc(normalized)) return analyzeHeredoc(normalized, projectDir);
  if (normalized.includes("\n")) return analyzeLines(normalized, projectDir);
  return analyzeLine(normalized, projectDir);
}

export function guardShell(resources: readonly string[], projectDir?: string): ReviewResult | undefined {
  if (process.platform === "win32") return { decision: "ask", reason: "Shell dialect requires manual approval" };
  if (!resources.length || resources.length > 256 || resources.some((resource) => resource.length > MAX_COMMAND_CHARS) ||
      resources.reduce((sum, resource) => sum + Buffer.byteLength(resource), 0) > MAX_COMMAND_BYTES)
    return { decision: "ask", reason: "Shell command exceeds parsing limits" };
  let ask = false;
  let review = false;
  for (const resource of resources) {
    const verdict = analyze(resource, projectDir);
    if (verdict.decision === "deny") return { decision: "deny", reason: verdict.reason };
    if (verdict.decision === "ask") ask = true;
    else if (verdict.decision === "review") review = true;
  }
  if (ask) return { decision: "ask", reason: "Shell syntax requires manual approval" };
  return review ? undefined : { decision: "allow", reason: "read-only command" };
}

