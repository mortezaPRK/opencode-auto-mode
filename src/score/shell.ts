import { isAbsolute } from "node:path";
import { resolvePhysicalDirectory } from "../path-policy.js";
import type { OperationEvidence, PermissionRequest, ReviewResult } from "../reviewer.js";
import { guardShell, visibleShellDeny } from "../shell.js";
import { scanShell, type ShellScan } from "./shell-argv.js";
import { scoreShellBaseline } from "./shell-baseline.js";
import { shellSafetyScore } from "./shell-safety.js";
import { ask, deny, high, type RequestScore } from "./types.js";
import { supportsPosixReview } from "../shell-policy.js";

const EXECUTION_DIRECTORY_KEYS = ["workdir", "cwd", "directory"] as const;
const INVALID_DIRECTORY = /^(?:undefined|null)$/i;
/** Home, command substitution and expansion spellings cannot be verified statically. */
const UNRESOLVABLE_DIRECTORY = /^[~$`]|[$`\0]/;

interface ShellLocation {
  directory?: string;
  unverified: boolean;
}

function directoryValues(value: unknown): string[] {
  if (typeof value === "string") return [value];
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function resolveDirectory(value: string, projectDir?: string): string | undefined {
  const trimmed = value.trim();
  if (!trimmed || INVALID_DIRECTORY.test(trimmed) || UNRESOLVABLE_DIRECTORY.test(trimmed)) return undefined;
  if (!isAbsolute(trimmed) && (projectDir === undefined || !isAbsolute(projectDir))) return undefined;
  // Physical traversal keeps `..` after a symlink selecting the directory the
  // host would actually enter; lexical collapsing would silently change it.
  return resolvePhysicalDirectory(trimmed, projectDir ?? process.cwd());
}

/** Exactly one captured execution directory may become the scoring base;
 * missing, conflicting or unresolvable evidence must not clear statically. */
function shellLocation(operation: OperationEvidence | undefined, projectDir?: string): ShellLocation {
  const values = EXECUTION_DIRECTORY_KEYS.flatMap((key) => directoryValues(operation?.arguments?.[key]))
    .filter((value) => value.trim().length > 0);
  if (values.length === 0) return { unverified: false };
  const resolved = new Set<string>();
  for (const value of values) {
    const directory = resolveDirectory(value, projectDir);
    if (directory === undefined) return { unverified: true };
    resolved.add(directory);
  }
  return resolved.size === 1 ? { directory: [...resolved][0], unverified: false } : { unverified: true };
}

function locatedRequest(request: PermissionRequest, location: ShellLocation): PermissionRequest {
  if (location.directory === undefined || location.directory === request.projectDir) return request;
  return { ...request, projectDir: location.directory };
}

/** Preserve visible denies; parser uncertainty must reach configured reviewers. */
function guardScore(guarded: ReviewResult | undefined, resources: readonly string[],
  projectDir?: string, worktreeRoot?: string): RequestScore | undefined {
  if (guarded?.decision === "deny") return deny(guarded.reason);
  if (guarded?.decision !== "ask") return undefined;
  // The POSIX scanner cannot safely analyze other shell dialects.
  if (process.platform === "win32") return ask(guarded.reason);
  // The parser cannot clear uncertain syntax, but visible dangers still win.
  const blocked = visibleShellDeny(resources, projectDir, worktreeRoot);
  if (blocked !== undefined) return deny(blocked);
  return undefined;
}

/** Scores one shell request: visible denies, safety checks, then residual band. */
export function scoreShellRequest(request: PermissionRequest, worktreeRoot?: string): RequestScore {
  const { resources } = request;
  if (!supportsPosixReview(request.shell)) return { ...high("Shell dialect requires model review"), findings: ["Full raw command retained; POSIX-derived denials not applied"] };
  const location = shellLocation(request.operation, request.projectDir);
  const located = locatedRequest(request, location);
  const guarded = guardShell(resources, located.projectDir);
  const rejected = guardScore(guarded, resources, located.projectDir, worktreeRoot);
  if (rejected) return rejected;
  // A relocated base without the original containment root cannot prove scope.
  if (location.unverified || (located !== request && worktreeRoot === undefined))
    return high("Shell working directory evidence is unresolved; static scope cannot be verified");
  const scan: ShellScan = scanShell(resources);
  const unsafe = shellSafetyScore(scan, located, worktreeRoot);
  if (unsafe) return unsafe;
  if (guarded?.decision === "ask") return high(guarded.reason);
  return scoreShellBaseline(scan, guarded, located.projectDir, worktreeRoot);
}
