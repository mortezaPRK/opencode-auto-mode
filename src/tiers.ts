import * as path from "node:path";
import { lstatSync, realpathSync } from "node:fs";

export type Tier = "auto-allow" | "auto-deny" | "review" | "unknown";
export interface Classification { tier: Tier; reason: string }
export interface ClassifyOptions { projectDir?: string; allowInProjectEdits?: boolean }

const READ_ONLY_COMMANDS = new Set(["pwd", "whoami", "hostname", "uname", "id", "groups", "ls", "ls -a", "ls -l", "ls -la", "ls -al", "ls -A"]);
const BLOCKED_SHELL = [
  /\brm\s+-rf?\s+\/(\s|$|\*)/,
  /\bsudo\b/,
  /\bmkfs\./,
  /\bdd\s+if=.*\s+of=\/(dev|sd|nvme|hd)/,
  /\b(shutdown|reboot|halt|poweroff)\b/,
  /:\(\)\s*\{\s*:\s*\|\s*:&\s*\};:/,
  /\bchmod\s+777\b/,
];
const SENSITIVE_PATH = /(?:^|[/\\])(?:\.[^/\\]+|opencode\.jsonc?|id_(?:rsa|dsa|ecdsa|ed25519)|[^/\\]+\.(?:pem|key|p12|pfx)|[^/\\]*(?:credentials|token|secret|password|private.key)[^/\\]*)(?:[/\\]|$)/i;

export function isInProject(target: string, projectDir: string): boolean {
  const resolved = path.resolve(projectDir, target);
  const root = path.resolve(projectDir);
  return resolved === root || resolved.startsWith(`${root}${path.sep}`);
}

function safeTarget(target: string, projectDir: string): boolean {
  try {
    const root = realpathSync(projectDir);
    const resolved = path.resolve(root, target);
    if (!isInProject(resolved, root) || SENSITIVE_PATH.test(resolved)) return false;
    const parts = path.relative(root, resolved).split(path.sep);
    let current = root;
    for (const part of parts) {
      current = path.join(current, part);
      try {
        const stat = lstatSync(current);
        if (stat.isSymbolicLink() || (stat.isFile() && stat.nlink !== 1)) return false;
      }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") return false; }
    }
    return true;
  } catch { return false; }
}

export function classify(action: string, resources: readonly string[], options?: ClassifyOptions): Classification {
  if (action === "shell") {
    for (const command of resources) {
      for (const pattern of BLOCKED_SHELL) {
        if (pattern.test(command)) return { tier: "auto-deny", reason: "dangerous shell operation" };
      }
    }
    if (resources.length > 0 && resources.every((command) => READ_ONLY_COMMANDS.has(command)))
      return { tier: "auto-allow", reason: "read-only command" };
    return { tier: "review", reason: "evaluate the entire command as one action" };
  }
  if (action === "read" || ((action === "edit" || action === "write") && options?.allowInProjectEdits)) {
    if (options?.projectDir && resources.length > 0 && resources.every((target) =>
        target.length > 0 && safeTarget(target, options.projectDir!)))
      return { tier: "auto-allow", reason: "non-sensitive in-project file operation" };
  }
  return { tier: "review", reason: `action '${action}' needs review` };
}
