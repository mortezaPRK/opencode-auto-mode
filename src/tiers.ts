import * as path from "node:path";
import { lstatSync, realpathSync } from "node:fs";
import { classifyShell } from "./shell.js";

export type Tier = "auto-allow" | "auto-deny" | "review" | "unknown";
export interface Classification { tier: Tier; reason: string }
export interface ClassifyOptions { projectDir?: string; allowInProjectEdits?: boolean }

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
        if ((!stat.isFile() && !stat.isDirectory()) || (stat.isFile() && stat.nlink !== 1) ||
            (current === resolved && !stat.isFile())) return false;
      }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") return false; }
    }
    return true;
  } catch { return false; }
}

export function classify(action: string, resources: readonly string[], options?: ClassifyOptions): Classification {
  if (action === "shell") return classifyShell(resources);
  if (action === "read" || ((action === "edit" || action === "write") && options?.allowInProjectEdits)) {
    if (options?.projectDir && resources.length > 0 && resources.every((target) =>
        target.length > 0 && safeTarget(target, options.projectDir!)))
      return { tier: "auto-allow", reason: "non-sensitive in-project file operation" };
  }
  return { tier: "review", reason: `action '${action}' needs review` };
}
