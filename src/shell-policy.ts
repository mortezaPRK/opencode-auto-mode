import { basename } from "node:path";
import { parse } from "shell-quote";

/**
 * Command vocabulary and per-command safety policy for shell approval.
 *
 * Everything here works on parsed words rather than raw command text, so text that
 * merely mentions a dangerous word (a commit message, a search pattern, a heredoc
 * body) is never treated as a dangerous operation.
 */

export const SHELLS = new Set(["sh", "bash", "dash", "zsh", "ksh", "fish", "pwsh", "powershell", "cmd"]);
export const SCRIPT_HOSTS = new Set(["python", "python3", "node", "perl", "ruby", "php", "awk", "gawk", "lua"]);
export const STATEFUL = new Set(["alias", "unalias", "export", "unset", "set", "shopt", "trap", "umask",
  "readonly", "declare", "typeset", "local", "function"]);
export const DYNAMIC = new Set(["eval", "source", ".", "exec", "xargs"]);
export const WRAPPERS = new Set(["env", "command", "builtin", "exec", "time", "!", "nohup", "setsid", "nice",
  "ionice", "stdbuf", "timeout"]);
export const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
export const CONTROL_OPERATORS = new Set([";", "&&", "||", "|", "|&", "&"]);
export const REDIRECT_OPERATORS = new Set([">", ">>", ">&", "<&", "<", "<<", "<<-", "<<<", "<>", ">|", "&>", "&>>"]);

const VALUE_OPTIONS = new Set(["-u", "--unset", "-C", "--chdir", "-S", "--split-string", "-a", "--argv0",
  "-n", "--adjustment", "-s", "--signal", "-k", "--kill-after"]);

const DANGEROUS = "dangerous shell operation";
const FORK_BOMB = /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/;
const MAX_NESTING = 2;

const DENY_EXECUTABLES = new Set(["sudo", "doas", "su", "shutdown", "reboot", "halt", "poweroff"]);

/** Resolves leading assignments and wrapper options to the effective executable. */
export function resolveExecutable(words: readonly string[]): { name: string; index: number } | undefined {
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

function hasLongOption(args: readonly string[], names: readonly string[]): boolean {
  return args.some((arg) => names.some((name) => arg === name || arg.startsWith(`${name}=`)));
}

function hasShortOption(args: readonly string[], letters: string): boolean {
  return args.some((arg) => arg.startsWith("-") && !arg.startsWith("--") &&
    [...arg.slice(1)].some((character) => letters.includes(character)));
}

function isWorldWritableMode(arg: string): boolean {
  const mode = arg.replace(/^[-+]+/, "");
  return mode === "777" || mode === "0777";
}

/** True when `rm` is invoked recursively and forcibly against the filesystem root. */
function isRootWipe(args: readonly string[]): boolean {
  let recursive = false;
  let force = false;
  const targets: string[] = [];
  for (const arg of args) {
    if (arg === "--") continue;
    if (arg.startsWith("--")) {
      if (arg === "--recursive") recursive = true;
      if (arg === "--force") force = true;
      continue;
    }
    if (arg.startsWith("-") && arg.length > 1) {
      if (arg.includes("r") || arg.includes("R")) recursive = true;
      if (arg.includes("f")) force = true;
      continue;
    }
    targets.push(arg);
  }
  if (!recursive || !force || targets.length === 0) return false;
  return targets.every((target) => {
    const trimmed = target.replace(/[/]+$/, "").replace(/\/\*+$/, "");
    return trimmed === "" || trimmed === "/";
  });
}

/** The script a shell or `eval` would run, when invoked non-interactively. */
function scriptArgument(name: string, args: readonly string[]): string | undefined {
  if (name === "eval") return args.length ? args.join(" ") : undefined;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === "--") return undefined;
    if (!arg.startsWith("-") || arg.startsWith("--")) continue;
    if (arg.slice(1).includes("c")) return args[index + 1];
  }
  return undefined;
}

/** Splits a script into simple commands, dropping redirection targets. */
function invocations(command: string): string[][] {
  let tokens;
  try { tokens = parse(command); } catch { return []; }
  const result: string[][] = [];
  let words: string[] = [];
  let skipNext = false;
  for (const token of tokens) {
    if (typeof token === "string") {
      if (!skipNext) words.push(token);
      skipNext = false;
      continue;
    }
    if ("comment" in token) continue;
    if ("op" in token) {
      if (token.op === "glob") {
        if (!skipNext) words.push(token.pattern);
        skipNext = false;
        continue;
      }
      if (CONTROL_OPERATORS.has(token.op) || REDIRECT_OPERATORS.has(token.op)) {
        if (words.length) result.push(words);
        words = [];
        skipNext = REDIRECT_OPERATORS.has(token.op);
      }
    }
  }
  if (words.length) result.push(words);
  return result;
}

function denyScript(command: string, depth: number): string | undefined {
  if (FORK_BOMB.test(command)) return DANGEROUS;
  for (const words of invocations(command)) {
    const reason = denyInvocation(words, depth);
    if (reason !== undefined) return reason;
  }
  return undefined;
}

/**
 * Deny reason for one parsed simple command, or undefined when it is not a
 * dangerous operation. Nested shell scripts are checked recursively.
 */
export function denyInvocation(words: readonly string[], depth = 0): string | undefined {
  if (depth > MAX_NESTING) return undefined;
  const executable = resolveExecutable(words);
  if (executable === undefined) return undefined;
  const args = words.slice(executable.index + 1);
  if (executable.name.startsWith("mkfs")) return DANGEROUS;
  if (DENY_EXECUTABLES.has(executable.name)) return DANGEROUS;
  if (executable.name === "chmod" && args.some(isWorldWritableMode)) return DANGEROUS;
  if (executable.name === "rm" && isRootWipe(args)) return DANGEROUS;
  if (executable.name === "dd" && args.some((arg) => /^of=\/(?:dev|sd|nvme|hd)/.test(arg))) return DANGEROUS;
  if (SHELLS.has(executable.name) || executable.name === "eval") {
    const script = scriptArgument(executable.name, args);
    if (script !== undefined) return denyScript(script, depth + 1);
  }
  return undefined;
}

const POLICIES: Record<string, (args: readonly string[]) => boolean> = {
  // Flags that read a program from a file, run a command, or write output.
  rg: (args) => !hasLongOption(args, ["--pre", "--pre-glob", "--hostname-bin", "--search-zip"]) &&
    !hasShortOption(args, "z"),
  sort: (args) => !hasLongOption(args, ["--output", "--compress-program", "--temporary-directory"]) &&
    !hasShortOption(args, "oT"),
  tree: (args) => !hasLongOption(args, ["--output"]) && !hasShortOption(args, "o"),
  file: (args) => !hasLongOption(args, ["--compile"]) && !hasShortOption(args, "C"),
  bat: (args) => !hasLongOption(args, ["--pager", "--config-file", "--config-dir"]),
  // `uniq INPUT OUTPUT` writes OUTPUT; only a single positional argument is read-only.
  uniq: (args) => args.filter((arg) => !arg.startsWith("-")).length <= 1,
  // A bare argument sets the host name.
  hostname: (args) => args.every((arg) => arg.startsWith("-")) &&
    !hasLongOption(args, ["--file", "--boot"]) && !hasShortOption(args, "F"),
  date: (args) => !hasLongOption(args, ["--set"]) && !hasShortOption(args, "s"),
};

const READ_ONLY = new Set(["pwd", "whoami", "id", "groups", "ls", "cat", "head", "tail", "wc", "echo", "printf",
  "true", ":", "grep", "cut", "tr", "jq", "stat", "du", "df", "which", "type", "basename", "dirname", "realpath",
  "diff", "test", "sleep", "uname"]);

function isReadOnlyGit(args: readonly string[]): boolean {
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

function isReadOnlySed(args: readonly string[]): boolean {
  if (args.some((arg) => arg === "-i" || arg.startsWith("--in-place") || arg === "-e" ||
      arg === "--expression" || arg === "-f" || arg === "--file")) return false;
  return args[0] === "-n" && args[1] !== undefined && /^\d+(?:,\d+)?p$/.test(args[1]);
}

function isReadOnlyGh(args: readonly string[]): boolean {
  const [group, subcommand] = args;
  if (group === "label" && subcommand === "list") return true;
  if (group === "api") {
    return !args.some((arg) => arg === "-X" || arg === "--method" || arg.startsWith("-X") ||
      arg.startsWith("--method=") || ["-f", "--field", "-F", "--raw-field", "--input"].includes(arg));
  }
  return new Set(["pr view", "pr list", "pr diff", "pr checks", "issue view", "issue list", "run view",
    "run list", "repo view", "auth status", "status", "search"]).has(`${group} ${subcommand}`);
}

/**
 * True only when one parsed simple command is read-only. Callers pass an
 * already-split segment, so chaining, redirection and wrappers are handled
 * before this point.
 */
export function isReadOnlyInvocation(words: readonly string[]): boolean {
  const command = basename(words[0] ?? "");
  const args = words.slice(1);
  const policy = POLICIES[command];
  if (policy !== undefined) return policy(args);
  if (READ_ONLY.has(command)) return true;
  if (command === "git") return isReadOnlyGit(args);
  if (command === "find") return !args.some((arg) => /^-(?:fprint|fprint0|fprintf|fls)$/.test(arg));
  if (command === "sed") return isReadOnlySed(args);
  if (command === "gh") return isReadOnlyGh(args);
  if (command === "docker") return args[0] === "logs";
  if (command === "bun")
    return args[0] === "test" || (args[0] === "run" && (args[1] === "lint" || args[1] === "typecheck"));
  return false;
}
