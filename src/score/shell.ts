import type { PermissionRequest, ReviewResult } from "../reviewer.js";
import { guardShell, visibleShellDeny } from "../shell.js";
import { scanShell, type ShellScan } from "./shell-argv.js";
import { scoreShellBaseline } from "./shell-baseline.js";
import { shellSafetyScore } from "./shell-safety.js";
import { ask, deny, high, type RequestScore } from "./types.js";
import { supportsPosixReview } from "../shell-policy.js";

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
  const { resources, projectDir } = request;
  if (!supportsPosixReview(request.shell)) return { ...high("Shell dialect requires model review"), findings: ["Full raw command retained; POSIX-derived denials not applied"] };
  const guarded = guardShell(resources, projectDir);
  const rejected = guardScore(guarded, resources, projectDir, worktreeRoot);
  if (rejected) return rejected;
  const scan: ShellScan = scanShell(resources);
  const unsafe = shellSafetyScore(scan, request, worktreeRoot);
  if (unsafe) return unsafe;
  if (guarded?.decision === "ask") return high(guarded.reason);
  return scoreShellBaseline(scan, guarded, projectDir, worktreeRoot);
}
