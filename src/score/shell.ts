import type { PermissionRequest, ReviewResult } from "../reviewer.js";
import { guardShell, visibleShellDeny } from "../shell.js";
import { scanShell, type ShellScan } from "./shell-argv.js";
import { scoreShellBaseline } from "./shell-baseline.js";
import { shellSafetyScore } from "./shell-safety.js";
import { ask, deny, type RequestScore } from "./types.js";

/** Honours a guard deny/ask before the residual scorer runs. */
function guardScore(guarded: ReviewResult | undefined, resources: readonly string[],
  projectDir?: string, worktreeRoot?: string): RequestScore | undefined {
  if (guarded?.decision === "deny") return deny(guarded.reason);
  if (guarded?.decision !== "ask") return undefined;
  // An ask is a manual-approval floor, not a clearance: a deny already visible
  // in the literal prefix must still win before the ask is honored.
  const blocked = visibleShellDeny(resources, projectDir, worktreeRoot);
  if (blocked !== undefined) return deny(blocked);
  return ask(guarded.reason);
}

/** Scores one shell request: guard floor, hard safety checks, then residual band. */
export function scoreShellRequest(request: PermissionRequest, worktreeRoot?: string): RequestScore {
  const { resources, projectDir } = request;
  const guarded = guardShell(resources, projectDir);
  const rejected = guardScore(guarded, resources, projectDir, worktreeRoot);
  if (rejected) return rejected;
  const scan: ShellScan = scanShell(resources);
  const unsafe = shellSafetyScore(scan, request, worktreeRoot);
  if (unsafe) return unsafe;
  return scoreShellBaseline(scan, guarded, projectDir, worktreeRoot);
}
