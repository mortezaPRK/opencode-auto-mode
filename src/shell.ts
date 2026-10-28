import type { ReviewResult } from "./reviewer.js";
import {
  CONTROL_OPERATORS, DYNAMIC, REDIRECT_OPERATORS, SCRIPT_HOSTS, SHELLS, STATEFUL,
  denyInvocation, hasAmbiguousDescriptorClose, isReadOnlyInvocation, parseShell, resolveExecutable,
} from "./shell-policy.js";

const MAX_COMMAND_CHARS = 4096;
const MAX_COMMAND_BYTES = 65_536;
const BALANCED_QUOTES = /^(?:[^'"\\]|\\[^\r\n]|'[^']*'|"(?:[^"\\]|\\[^\r\n])*")*$/;
const WRITE_OPERATORS = new Set([">", ">>", ">|", "&>", "&>>", "<>"]);
const DYNAMIC_SYNTAX = /\$\(|`|\$\(\s*\(|[<>]\(/;
const FORK_BOMB = /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/;

export function shellWords(command: string): string[] | undefined {
  if (!command || command.length > MAX_COMMAND_CHARS || /[$`~\r\n\0{}[\]]/.test(command) ||
      /[^\S \t]/.test(command) || !BALANCED_QUOTES.test(command)) return undefined;
  try {
    const words = parseShell(command);
    return words.length && words.every((word) => typeof word === "string") ? words as string[] : undefined;
  } catch { return undefined; }
}

interface Segment { words: string[]; write: boolean }
type Verdict = { decision: "deny"; reason: string } | { decision: "allow" | "review" | "ask" };

/** True when the command contains a heredoc marker outside quotes. Heredoc bodies are data. */
function hasHeredoc(command: string): boolean {
  let quote: "'" | '"' | undefined;
  for (let index = 0; index < command.length; index++) {
    const character = command[index];
    if (quote === "'") { if (character === "'") quote = undefined; continue; }
    if (quote === '"') {
      if (character === "\\") { index++; continue; }
      if (character === '"') quote = undefined;
      continue;
    }
    if (character === "'" || character === '"') { quote = character; continue; }
    if (character === "\\") { index++; continue; }
    if (character === "<" && command[index + 1] === "<" && command[index + 2] !== "<") return true;
  }
  return false;
}

interface HeredocMarker { delimiter: string; quoted: boolean; stripTabs: boolean }

/** Reads heredoc markers on one line, ignoring markers inside quoted strings and comments. */
function heredocMarkers(line: string): HeredocMarker[] {
  const markers: HeredocMarker[] = [];
  let quote: "'" | '"' | undefined;
  for (let index = 0; index < line.length; index++) {
    const character = line[index];
    if (quote === "'") { if (character === "'") quote = undefined; continue; }
    if (quote === '"') {
      if (character === "\\") { index++; continue; }
      if (character === '"') quote = undefined;
      continue;
    }
    if (character === "'" || character === '"') { quote = character; continue; }
    if (character === "\\") { index++; continue; }
    if (character === "#" && (index === 0 || /\s/.test(line[index - 1] ?? ""))) break;
    if (character !== "<" || line[index + 1] !== "<" || line[index + 2] === "<") continue;
    let cursor = index + 2;
    const stripTabs = line[cursor] === "-";
    if (stripTabs) cursor++;
    while (line[cursor] === " " || line[cursor] === "\t") cursor++;
    let delimiter = "";
    let quoted = false;
    if (line[cursor] === "'" || line[cursor] === '"') {
      const closing = line[cursor];
      quoted = true;
      cursor++;
      while (cursor < line.length && line[cursor] !== closing) delimiter += line[cursor++];
    } else {
      while (cursor < line.length && /[A-Za-z0-9_]/.test(line[cursor])) delimiter += line[cursor++];
    }
    if (delimiter) markers.push({ delimiter, quoted, stripTabs });
    index = cursor - 1;
  }
  return markers;
}

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
  const blocked = denyInvocation(segment.words);
  if (blocked !== undefined) return { decision: "deny", reason: blocked };
  if (dynamicExecution(segment.words)) return { decision: "ask" };
  if (!segment.write && isReadOnlyInvocation(segment.words)) return { decision: "allow" };
  return { decision: "review" };
}

/** Token shapes this module consumes; `parse` returns a wider union. */
type Token = string | { comment: string } | { op: string; pattern?: string };

interface ParsedLine { segments: Segment[]; complete: boolean }

/** Splits parsed tokens into simple commands, tracking whether the whole line parsed. */
function lineSegments(tokens: readonly Token[]): ParsedLine {
  const segments: Segment[] = [{ words: [], write: false }];
  let current = segments[0];
  let redirect: { write: boolean } | undefined;
  for (const token of tokens) {
    if (typeof token === "string") {
      if (redirect) {
        const target = token;
        if (redirect.write && target !== "/dev/null" && !/^\d+$/.test(target) && !target.startsWith("&"))
          current.write = true;
        redirect = undefined;
      } else current.words.push(token);
      continue;
    }
    if ("comment" in token) continue;
    if (token.op === "glob" && token.pattern !== undefined) {
      if (redirect) {
        // A glob is still a redirection target, so it never becomes a command word.
        if (redirect.write) current.write = true;
        redirect = undefined;
      } else current.words.push(token.pattern);
      continue;
    }
    if (CONTROL_OPERATORS.has(token.op)) {
      // A control operator before the redirection target is invalid syntax.
      if (redirect) return { segments, complete: false };
      current = { words: [], write: false };
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

  const { segments, complete } = lineSegments(tokens);
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

  let ask = false;
  let review = false;
  for (const line of [firstLine, ...lines.slice(index)]) {
    if (!line.trim()) continue;
    const verdict = analyzeLine(line);
    if (verdict.decision === "deny") return verdict;
    if (verdict.decision === "ask") ask = true;
    else if (verdict.decision === "review") review = true;
  }
  for (const body of bodies) {
    // Unquoted heredoc bodies undergo command and parameter expansion.
    if (!body.quoted && DYNAMIC_SYNTAX.test(body.lines.join("\n"))) return { decision: "ask" };
  }
  try {
    const words = parseShell(firstLine).filter((token): token is string => typeof token === "string");
    const executable = resolveExecutable(words);
    if (executable === undefined || SHELLS.has(executable.name) || SCRIPT_HOSTS.has(executable.name) ||
        DYNAMIC.has(executable.name) || STATEFUL.has(executable.name)) return { decision: "ask" };
  } catch { return { decision: "ask" }; }
  if (ask) return { decision: "ask" };
  return { decision: review ? "review" : "allow" };
}

function analyze(command: string): Verdict {
  if (hasHeredoc(command)) return analyzeHeredoc(command);
  if (command.includes("\n")) {
    let ask = false;
    let review = false;
    for (const line of command.split("\n")) {
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
  return analyzeLine(command);
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

