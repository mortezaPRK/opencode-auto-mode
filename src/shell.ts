import { parse } from "shell-quote";
import { basename } from "node:path";
import { classify } from "./tiers.js";
import type { ReviewResult } from "./reviewer.js";

const WRAPPERS = new Set(["env", "command", "builtin", "exec", "eval", "source", ".", "cd", "pushd", "popd",
  "sh", "bash", "dash", "zsh", "ksh", "fish", "pwsh", "powershell", "cmd", "!", "time", "coproc",
  "if", "then", "else", "elif", "fi", "for", "while", "until", "case", "esac", "select", "do", "done", "function",
  "export", "unset", "set", "shopt", "alias", "unalias", "trap", "umask", "exit", "return", "shift", "readonly", "local", "declare", "typeset"]);
const BALANCED_QUOTES = /^(?:[^'"\\]|\\[^\r\n]|'[^']*'|"(?:[^"\\]|\\[^\r\n])*")*$/;

export function shellWords(command: string): string[] | undefined {
  if (!command || command.length > 4096 || /[$`~\r\n\0{}\[\]]/.test(command) ||
      /[^\S \t]/.test(command) || !BALANCED_QUOTES.test(command)) return undefined;
  try {
    const words = parse(command);
    return words.length && words.every((word) => typeof word === "string") ? words as string[] : undefined;
  } catch { return undefined; }
}

export function guardShell(resources: readonly string[]): ReviewResult | undefined {
  if (process.platform === "win32") return { decision: "ask", reason: "Shell dialect requires manual approval" };
  if (!resources.length || resources.length > 256 || resources.some((resource) => resource.length > 4096) ||
      resources.reduce((sum, resource) => sum + Buffer.byteLength(resource), 0) > 65_536)
    return { decision: "ask", reason: "Shell command exceeds parsing limits" };
  let uncertain = false;
  for (const resource of resources) {
    const words = shellWords(resource);
    const result = classify("shell", [resource, ...(words ? [words.join(" ")] : [])]);
    if (result.tier === "auto-deny") return { decision: "deny", reason: result.reason };
    if (!words || words[0].includes("=") || WRAPPERS.has(basename(words[0]))) uncertain = true;
  }
  return uncertain ? { decision: "ask", reason: "Shell syntax requires manual approval" } : undefined;
}
