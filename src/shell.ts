import type { ReviewResult } from "./reviewer.js";
import {
  CONTROL_OPERATORS, DYNAMIC, REDIRECT_OPERATORS, SCRIPT_HOSTS, SHELLS, STATEFUL,
  denyInvocation, hasAmbiguousDescriptorClose, hasAssembledUndecodedSyntax, hasHeredoc,
  hasUndecodedSyntax, heredocMarkers, isReadOnlyInvocation, logicalLines, normalizeContinuations, parseShell,
  rawHeredocScript, resolveExecutable, stripDescriptorPrefixes,
} from "./shell-policy.js";

const MAX_COMMAND_CHARS = 4096;
const MAX_COMMAND_BYTES = 65_536;
const BALANCED_QUOTES = /^(?:[^'"\\]|\\[^\r\n]|'[^']*'|"(?:[^"\\]|\\[^\r\n])*")*$/;
const WRITE_OPERATORS = new Set([">", ">>", ">|", "&>", "&>>", "<>"]);
const DYNAMIC_SYNTAX = /\$\(|`|\$\(\s*\(|[<>]\(|\$\[/;
const FORK_BOMB = /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/;

export function shellWords(command: string): string[] | undefined {
  if (!command || command.length > MAX_COMMAND_CHARS || /[$`~\r\n\0{}[\]]/.test(command) ||
      /[^\S \t]/.test(command) || !BALANCED_QUOTES.test(command)) return undefined;
  try {
    const words = parseShell(command);
    return words.length && words.every((word) => typeof word === "string") ? words as string[] : undefined;
  } catch { return undefined; }
}

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

interface ParsedLine { segments: Segment[]; complete: boolean }

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

/** Splits parsed tokens into simple commands, tracking whether the whole line parsed. */
function lineSegments(tokens: readonly Token[], expansions: readonly boolean[] = []): ParsedLine {
  const segments: Segment[] = [{ words: [], globs: [], write: false }];
  let current = segments[0];
  let redirect: { write: boolean } | undefined;
  let wordIndex = 0;
  const nextExpansion = () => expansions[wordIndex++] ?? false;
  for (const token of tokens) {
    if (typeof token === "string") {
      if (redirect) {
        const target = token;
        nextExpansion();
        if (redirect.write && target !== "/dev/null" && !/^\d+$/.test(target) && !target.startsWith("&"))
          current.write = true;
        redirect = undefined;
      } else {
        current.words.push(token);
        current.globs.push(nextExpansion());
      }
      continue;
    }
    if ("comment" in token) continue;
    if (token.op === "glob" && token.pattern !== undefined) {
      if (redirect) {
        // A glob is still a redirection target, so it never becomes a command word.
        nextExpansion();
        if (redirect.write) current.write = true;
        redirect = undefined;
      } else {
        nextExpansion();
        current.words.push(token.pattern);
        current.globs.push(true);
      }
      continue;
    }
    if (CONTROL_OPERATORS.has(token.op)) {
      // A control operator before the redirection target is invalid syntax.
      if (redirect) return { segments, complete: false };
      current = { words: [], globs: [], write: false };
      segments.push(current);
      continue;
    }
    if (REDIRECT_OPERATORS.has(token.op)) {
      // Descriptor prefixes (`2>` in `2>/dev/null`) are stripped from the source
      // before parsing, so a numeric word here is an operand and must survive.
      redirect = { write: WRITE_OPERATORS.has(token.op) };
      continue;
    }
    return { segments, complete: false };
  }
  return { segments, complete: redirect === undefined };
}

function analyzeLine(command: string): Verdict {
  if (!command.trim()) return { decision: "allow" };
  if (!BALANCED_QUOTES.test(command)) return { decision: "ask" };
  if (FORK_BOMB.test(command)) return { decision: "deny", reason: "dangerous shell operation" };

  let tokens;
  try { tokens = parseShell(command); }
  catch { return { decision: "ask" }; }

  const { segments, complete } = lineSegments(tokens, wordExpansions(stripDescriptorPrefixes(command)));
  // Deny rules that are already visible must win even when later arguments are
  // dynamic (`sudo id $(...)`) and even when the line only parses partially.
  for (const segment of segments) {
    const blocked = denyInvocation(segment.words);
    if (blocked !== undefined) return { decision: "deny", reason: blocked };
  }
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
function analyzeLines(command: string): Verdict {
  let ask = false;
  let review = false;
  const { lines, certain } = logicalLines(command);
  // An undecodable header or a body that can move its terminator leaves the
  // script/data split unknown, so nothing past that line may be auto-approved.
  if (certain < lines.length) ask = true;
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const verdict = analyzeLine(trimmed);
    if (verdict.decision === "deny") return verdict;
    if (verdict.decision === "ask") ask = true;
    else if (verdict.decision === "review") review = true;
  }
  if (ask) return { decision: "ask" };
  return { decision: review ? "review" : "allow" };
}

function analyzeHeredoc(command: string): Verdict {
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
  const header = analyzeLine(firstLine);
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
  const rest: Verdict = tail ? analyze(tail) : { decision: "allow" };
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

function analyze(command: string): Verdict {
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
      const verdict = analyzeLine(normalizeContinuations(line).trim());
      if (verdict.decision === "deny") return verdict;
    }
    return { decision: "ask" };
  }
  // Normalization removes `\`-newlines, so the shell can parse an unsupported
  // form the raw check above could not see: `sort $`+newline+`'\x2doout'` is
  // `sort -oout` to Bash once the pair is gone. Repeat the whole gate on the text
  // that is actually routed and parsed, still before any heredoc routing.
  const normalized = normalizeContinuations(command);
  if (hasUndecodedSyntax(normalized)) return { decision: "ask" };
  // `logicalLines` must split on the newlines the shell actually treats as
  // separators, and heredoc bodies stay untouched.
  if (hasHeredoc(normalized)) return analyzeHeredoc(normalized);
  if (normalized.includes("\n")) return analyzeLines(normalized);
  return analyzeLine(normalized);
}

export function guardShell(resources: readonly string[]): ReviewResult | undefined {
  if (process.platform === "win32") return { decision: "ask", reason: "Shell dialect requires manual approval" };
  if (!resources.length || resources.length > 256 || resources.some((resource) => resource.length > MAX_COMMAND_CHARS) ||
      resources.reduce((sum, resource) => sum + Buffer.byteLength(resource), 0) > MAX_COMMAND_BYTES)
    return { decision: "ask", reason: "Shell command exceeds parsing limits" };
  let ask = false;
  let review = false;
  for (const resource of resources) {
    const verdict = analyze(resource);
    if (verdict.decision === "deny") return { decision: "deny", reason: verdict.reason };
    if (verdict.decision === "ask") ask = true;
    else if (verdict.decision === "review") review = true;
  }
  if (ask) return { decision: "ask", reason: "Shell syntax requires manual approval" };
  return review ? undefined : { decision: "allow", reason: "read-only command" };
}

export interface ShellClassification {
  tier: "auto-allow" | "auto-deny" | "review";
  reason: string;
}

/**
 * Static tier classification for shell actions. The shell guard is the single
 * source of truth so the classifier can never allow or deny something the guard
 * would not.
 */
export function classifyShell(resources: readonly string[]): ShellClassification {
  const verdict = guardShell(resources);
  if (verdict?.decision === "deny") return { tier: "auto-deny", reason: verdict.reason };
  if (verdict?.decision === "allow") return { tier: "auto-allow", reason: verdict.reason };
  if (verdict?.decision === "ask") return { tier: "review", reason: "shell syntax requires manual approval" };
  return { tier: "review", reason: "evaluate the entire command as one action" };
}

