import { parse } from "shell-quote";
import { basename } from "node:path";
import { classify } from "./tiers.js";
import type { ReviewResult } from "./reviewer.js";

const MAX_COMMAND_CHARS = 4096;
const MAX_COMMAND_BYTES = 65_536;
const BALANCED_QUOTES = /^(?:[^'"\\]|\\[^\r\n]|'[^']*'|"(?:[^"\\]|\\[^\r\n])*")*$/;
const CONTROL_OPERATORS = new Set([";", "&&", "||", "|", "|&", "&"]);
const REDIRECT_OPERATORS = new Set([">", ">>", ">&", "<&", "<", "<<", "<<-", "<<<", "<>", ">|", "&>", "&>>"]);
const WRITE_OPERATORS = new Set([">", ">>", ">|", "&>", "&>>", "<>"]);
const SHELLS = new Set(["sh", "bash", "dash", "zsh", "ksh", "fish", "pwsh", "powershell", "cmd"]);
const SCRIPT_HOSTS = new Set(["python", "python3", "node", "perl", "ruby", "php", "awk", "gawk", "lua"]);
const STATEFUL = new Set(["alias", "unalias", "export", "unset", "set", "shopt", "trap", "umask",
  "readonly", "declare", "typeset", "local", "function"]);
const DYNAMIC = new Set(["eval", "source", ".", "exec", "xargs"]);
const DYNAMIC_SYNTAX = /\$\(|`|\$\(\s*\(|[<>]\(/;
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
const WRAPPERS = new Set(["env", "command", "builtin", "exec", "time", "!", "nohup", "setsid", "nice",
  "ionice", "stdbuf", "timeout"]);
const VALUE_OPTIONS = new Set(["-u", "--unset", "-C", "--chdir", "-S", "--split-string", "-a", "--argv0",
  "-n", "--adjustment", "-s", "--signal", "-k", "--kill-after"]);
const READ_ONLY = new Set(["pwd", "whoami", "hostname", "uname", "id", "groups", "ls", "cat", "head", "tail",
  "wc", "date", "echo", "printf", "true", ":", "rg", "grep", "sort", "uniq", "cut", "tr", "jq", "stat", "file",
  "du", "df", "tree", "bat", "which", "type", "sleep", "test", "basename", "dirname", "realpath", "diff"]);

export function shellWords(command: string): string[] | undefined {
  if (!command || command.length > MAX_COMMAND_CHARS || /[$`~\r\n\0{}[\]]/.test(command) ||
      /[^\S \t]/.test(command) || !BALANCED_QUOTES.test(command)) return undefined;
  try {
    const words = parse(command);
    return words.length && words.every((word) => typeof word === "string") ? words as string[] : undefined;
  } catch { return undefined; }
}

interface Segment { words: string[]; write: boolean }
type Verdict = { decision: "deny"; reason: string } | { decision: "allow" | "review" | "ask" };

function blockedCommand(command: string): string | undefined {
  const normalized = shellWords(command);
  const result = classify("shell", [command, ...(normalized ? [normalized.join(" ")] : [])]);
  return result.tier === "auto-deny" ? result.reason : undefined;
}

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

/** Resolves leading assignments and wrapper options to the effective executable. */
function resolveExecutable(words: string[]): { name: string; index: number } | undefined {
  let index = 0;
  while (index < words.length && ASSIGNMENT.test(words[index])) index++;
  while (index < words.length) {
    const name = basename(words[index]);
    if (!WRAPPERS.has(name)) break;
    index++;
    if (name === "timeout") {
      while (index < words.length && words[index].startsWith("-") && words[index] !== "-") {
        const option = words[index].split("=", 1)[0];
        index += VALUE_OPTIONS.has(option) && !words[index].includes("=") ? 2 : 1;
      }
      if (index < words.length) index++;
      continue;
    }
    while (index < words.length) {
      const word = words[index];
      if (word === "--") { index++; break; }
      if (word.startsWith("-") && word !== "-") {
        const option = word.split("=", 1)[0];
        index += VALUE_OPTIONS.has(option) && !word.includes("=") ? 2 : 1;
        continue;
      }
      if (ASSIGNMENT.test(word)) { index++; continue; }
      break;
    }
  }
  return index < words.length ? { name: basename(words[index]), index } : undefined;
}

/** True when the effective executable is a shell, a dynamic builtin, or a stateful builtin. */
function dynamicExecution(words: string[]): boolean {
  const executable = resolveExecutable(words);
  if (executable === undefined) return true;
  if (SHELLS.has(executable.name) || DYNAMIC.has(executable.name) || STATEFUL.has(executable.name)) return true;
  return executable.name === "find" && words.slice(executable.index + 1)
    .some((word) => /^-(?:exec|execdir|ok|okdir|delete)$/.test(word));
}

function isReadOnlyGit(args: string[]): boolean {
  if (args.some((arg) =>
    /^(?:-c|--git-dir|--work-tree|--exec-path|--config-env)(?:=|$)/.test(arg) ||
    arg === "--ext-diff" || arg === "--exec" || arg.startsWith("--output"))) return false;
  const subcommand = args[0];
  if (subcommand === undefined) return false;
  if (["status", "diff", "log", "show", "rev-parse"].includes(subcommand)) return true;
  if (subcommand !== "branch") return false;
  if (args.length === 1) return true;
  return args.slice(1).every((arg) =>
    ["--show-current", "--list", "-a", "-r", "-v", "-vv", "--merged", "--no-merged", "--contains", "--points-at", "--format"]
      .some((safe) => arg === safe || arg.startsWith(`${safe}=`)));
}

function isReadOnlySed(args: string[]): boolean {
  if (args.some((arg) => arg === "-i" || arg.startsWith("--in-place") || arg === "-e" ||
      arg === "--expression" || arg === "-f" || arg === "--file")) return false;
  return args[0] === "-n" && args[1] !== undefined && /^\d+(?:,\d+)?p$/.test(args[1]);
}

function isReadOnlyGh(args: string[]): boolean {
  const [group, subcommand] = args;
  if (group === "label" && subcommand === "list") return true;
  if (group === "api") {
    return !args.some((arg) => arg === "-X" || arg === "--method" || arg.startsWith("-X") ||
      arg.startsWith("--method=") || ["-f", "--field", "-F", "--raw-field", "--input"].includes(arg));
  }
  return new Set(["pr view", "pr list", "pr diff", "pr checks", "issue view", "issue list", "run view",
    "run list", "repo view", "auth status", "status", "search"]).has(`${group} ${subcommand}`);
}

function isReadOnly(words: string[]): boolean {
  const command = basename(words[0]);
  const args = words.slice(1);
  if (READ_ONLY.has(command)) {
    return command !== "date" || !args.some((arg) => arg === "-s" || arg === "--set" || arg.startsWith("--set="));
  }
  if (command === "git") return isReadOnlyGit(args);
  if (command === "find") return !args.some((arg) => /^-(?:fprint|fprint0|fprintf|fls)$/.test(arg));
  if (command === "sed") return isReadOnlySed(args);
  if (command === "gh") return isReadOnlyGh(args);
  if (command === "docker") return args[0] === "logs";
  if (command === "bun")
    return args[0] === "test" || (args[0] === "run" && (args[1] === "lint" || args[1] === "typecheck"));
  return false;
}

function analyzeSegment(segment: Segment): Verdict {
  if (!segment.words.length) return segment.write ? { decision: "review" } : { decision: "allow" };
  const command = segment.words[0];
  if (!command || command.includes("$")) return { decision: "ask" };
  const blocked = blockedCommand(segment.words.join(" "));
  if (blocked !== undefined) return { decision: "deny", reason: blocked };
  if (dynamicExecution(segment.words)) return { decision: "ask" };
  if (!segment.write && isReadOnly(segment.words)) return { decision: "allow" };
  return { decision: "review" };
}

function analyzeLine(command: string): Verdict {
  if (!command.trim()) return { decision: "allow" };
  if (!BALANCED_QUOTES.test(command)) return { decision: "ask" };
  const blocked = blockedCommand(command);
  if (blocked !== undefined) return { decision: "deny", reason: blocked };

  let tokens;
  try { tokens = parse(command); }
  catch { return { decision: "ask" }; }
  const blockedTokens = blockedCommand(tokens.filter((token): token is string => typeof token === "string").join(" "));
  if (blockedTokens !== undefined) return { decision: "deny", reason: blockedTokens };
  if (DYNAMIC_SYNTAX.test(command)) return { decision: "ask" };

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
    if (token.op === "glob") { current.words.push(token.pattern); continue; }
    if (CONTROL_OPERATORS.has(token.op)) {
      current = { words: [], write: false };
      segments.push(current);
      continue;
    }
    if (REDIRECT_OPERATORS.has(token.op)) {
      if (current.words.length && /^\d+$/.test(current.words[current.words.length - 1])) current.words.pop();
      redirect = { write: WRITE_OPERATORS.has(token.op) };
      continue;
    }
    return { decision: "ask" };
  }
  if (redirect) return { decision: "ask" };

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
    const words = parse(firstLine).filter((token): token is string => typeof token === "string");
    const executable = resolveExecutable(words);
    if (executable === undefined || SHELLS.has(executable.name) || SCRIPT_HOSTS.has(executable.name) ||
        DYNAMIC.has(executable.name) || STATEFUL.has(executable.name)) return { decision: "ask" };
  } catch { return { decision: "ask" }; }
  if (ask) return { decision: "ask" };
  return { decision: review ? "review" : "allow" };
}

function analyze(command: string): Verdict {
  if (hasHeredoc(command)) return analyzeHeredoc(command);
  const blocked = blockedCommand(command);
  if (blocked !== undefined) return { decision: "deny", reason: blocked };
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
