import type { AutoModeOptions } from "../config.js";
import { classifyPath, isScopedPath, projectRoot, safeTarget } from "../tiers.js";
import { deny, high, low, type RequestScore } from "./types.js";
import { pathFindings } from "../path-policy.js";

/** Tools whose resources are filesystem paths this scorer can verify. */
const FILE_ACTIONS = new Set(["read", "edit", "write", "glob", "grep"]);

export function isFileAction(action: string): boolean {
  return FILE_ACTIONS.has(action);
}

/** Only established stores deny. Configuration and resolution uncertainty review. */
function pathApproval(resources: readonly string[], projectDir?: string): RequestScore | undefined {
  const facts = resources.map((target) => classifyPath(target, projectDir));
  const findings = pathFindings(facts);
  if (facts.some((fact) => fact.kind === "protected")) return { ...deny("Protected path access"), findings };
  if (facts.some((fact) => fact.review)) return { ...high("Path role or resolution requires further review"), findings };
  return undefined;
}

function verifiedWrite(resources: readonly string[], options: AutoModeOptions, projectDir?: string, worktreeRoot?: string): boolean {
  if (!projectDir || !options.allowInProjectEdits) return false;
  return resources.every((target) => safeTarget(target, projectDir, worktreeRoot));
}

function baseline(write: boolean, allowed: boolean): RequestScore {
  if (write) return allowed ? low("Verified in-project file operation") : high("External or unverified file write");
  return allowed ? low("Read-only tool inside the project") : high("Read outside the verified project scope");
}

export function scoreFileAction(action: string, resources: readonly string[], options: AutoModeOptions,
  projectDir?: string, worktreeRoot?: string): RequestScore {
  // A URL is not a filesystem path this scope can verify. None of these tools
  // fetch it, but the resource text must not be scored low as a verified
  // in-project path; shell `file:` handling is separate and unchanged.
  if (resources.some((target) => target.includes("://")))
    return high("URL resource does not establish a filesystem path");
  if (action === "grep" || action === "glob")
    return high("Search patterns do not establish the actual filesystem scope");
  const approval = pathApproval(resources, projectDir);
  if (approval) return approval;
  const write = action === "edit" || action === "write";
  const locationDir = projectDir ?? process.cwd();
  // Read targets follow the same scope rule as writes: an external, tilde or
  // escaping path needs review instead of being auto-approved.
  const scoped = resources.every((target) =>
    isScopedPath(target, locationDir, worktreeRoot ?? projectRoot(locationDir)));
  return baseline(write, write ? verifiedWrite(resources, options, projectDir, worktreeRoot) : scoped);
}
