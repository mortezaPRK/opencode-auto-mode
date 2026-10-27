import { parse } from "shell-quote";
import { basename } from "node:path";
import { classify } from "./tiers.js";
import type { ReviewResult } from "./reviewer.js";

const MAX_COMMAND_CHARS = 4096;
const MAX_COMMAND_BYTES = 65_536;
const BALANCED_QUOTES = /^(?:[^'"\\]|\\[^\r\n]|'[^']*'|"(?:[^"\\]|\\[^\r\n])*")*$/;
const CONTROL_OPERATORS = new Set([";", "&&", "||", "|", "|&", "&"]);
const REDIRECT_OPERATORS = new Set([">", ">>", ">&", "<&", "<", "<<", "<<<", "<>", ">|", "&>", "&>>"]);
const WRITE_OPERATORS = new Set([">", ">>", ">|", "&>", "&>>", "<>"]);
const SHELLS = new Set(["sh", "bash", "dash", "zsh", "ksh", "fish", "pwsh", "powershell", "cmd"]);
const SCRIPT_HOSTS = new Set(["python", "python3", "node", "perl", "ruby", "php", "awk", "gawk", "lua"]);
const STATEFUL = new Set(["alias", "unalias", "export", "unset", "set", "shopt", "trap", "umask",
  "readonly", "declare", "typeset", "local", "function"]);
const DYNAMIC = new Set(["eval", "source", ".", "exec", "xargs"]);
const DYNAMIC_SYNTAX = /\$\(|`|\$\(\s*\(|[<>]\(/;

function blockedCommand(command: string): string | undefined {
  const normalized = shellWords(command);
  const result = classify("shell", [command, ...(normalized ? [normalized.join(" ")] : [])]);
  return result.tier === "auto-deny" ? result.reason : undefined;
}

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

/** True when any word can execute another shell or builtin dynamically. */
function dynamicExecution(words: string[]): boolean {
  for (let index = 0; index < words.length; index++) {
    const name = basename(words[index]);
    const previous = index > 0 ? basename(words[index - 1]) : undefined;
    const wrapped = index === 0 || previous === "env" || previous === "command" || previous === "time" ||
      previous === "builtin" || previous === "!";
    if (SHELLS.has(name) && (wrapped || words[index + 1] === "-c" || words[index + 1] === "--command")) return true;
    if (DYNAMIC.has(name) && wrapped) return true;
    if (STATEFUL.has(name) && (index === 0 || previous === "builtin" || previous === "command" || previous === "!"))
      return true;
    if (name === "find" && words.slice(1).some((word) => /^-(?:exec|execdir|ok|okdir|delete)$/.test(word)))
      return true;
  }
  return false;
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
  if (!segment.words.length) return { decision: "allow" };
  const command = segment.words[0];
  if (!command || command.includes("$")) return { decision: "ask" };
  const name = basename(command);
  if (DYNAMIC.has(name) || dynamicExecution(segment.words)) return { decision: "ask" };
  if (!segment.write && isReadOnly(segment.words)) return { decision: "allow" };
  return { decision: "review" };
}

function analyzeLine(command: string): Verdict {
  if (!command.trim()) return { decision: "allow" };
  if (!BALANCED_QUOTES.test(command)) return { decision: "ask" };
  const blocked = blockedCommand(command);
  if (blocked !== undefined) return { decision: "deny", reason: blocked };
  if (DYNAMIC_SYNTAX.test(command)) return { decision: "ask" };

  let tokens;
  try { tokens = parse(command); }
  catch { return { decision: "ask" }; }

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

  let review = false;
  for (const segment of segments) {
    const verdict = analyzeSegment(segment);
    if (verdict.decision === "deny" || verdict.decision === "ask") return verdict;
    if (verdict.decision === "review") review = true;
  }
  return { decision: review ? "review" : "allow" };
}

function analyze(command: string): Verdict {
  if (hasHeredoc(command)) {
    const firstLine = command.split("\n", 1)[0];
    const blocked = blockedCommand(firstLine);
    if (blocked !== undefined) return { decision: "deny", reason: blocked };
    if (DYNAMIC_SYNTAX.test(firstLine)) return { decision: "ask" };
    try {
      const words = parse(firstLine).filter((token): token is string => typeof token === "string");
      if (dynamicExecution(words) || (words[0] !== undefined && SCRIPT_HOSTS.has(basename(words[0]))))
        return { decision: "ask" };
    } catch { return { decision: "ask" }; }
    return { decision: "review" };
  }
  if (command.includes("\n")) {
    let review = false;
    for (const line of command.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const verdict = analyzeLine(trimmed);
      if (verdict.decision === "deny" || verdict.decision === "ask") return verdict;
      if (verdict.decision === "review") review = true;
    }
    return { decision: review ? "review" : "allow" };
  }
  return analyzeLine(command);
}

export function guardShell(resources: readonly string[]): ReviewResult | undefined {
  if (process.platform === "win32") return { decision: "ask", reason: "Shell dialect requires manual approval" };
  if (!resources.length || resources.length > 256 || resources.some((resource) => resource.length > MAX_COMMAND_CHARS) ||
      resources.reduce((sum, resource) => sum + Buffer.byteLength(resource), 0) > MAX_COMMAND_BYTES)
    return { decision: "ask", reason: "Shell command exceeds parsing limits" };
  for (const resource of resources) {
    const verdict = analyze(resource);
    if (verdict.decision === "deny") return { decision: "deny", reason: verdict.reason };
    if (verdict.decision === "ask") return { decision: "ask", reason: "Shell syntax requires manual approval" };
  }
  return undefined;
}
