import { errorKindOf, ReviewFailure } from "./errors.js";
import type { PermissionRequest } from "./reviewer.js";
import type { WorktreeScope } from "./worktree.js";

interface ContextLookups {
  scope(directory: string): Promise<WorktreeScope>;
  branch(directory: string): Promise<{ current?: string; default?: string }>;
  status(directory: string): Promise<readonly unknown[]>;
}

/** Optional metadata failures are missing facts, not permission decisions. */
async function optionalFact<T>(work: () => Promise<T>, signal: AbortSignal): Promise<T | undefined> {
  if (signal.aborted) throw new ReviewFailure("cancelled", "Context lookup interrupted");
  try { return await work(); }
  catch (error) {
    if (signal.aborted || ["cancelled", "deadline"].includes(errorKindOf(error))) throw error;
    return undefined;
  }
}

export async function permissionContext(directory: string, lookups: ContextLookups, signal: AbortSignal):
  Promise<Pick<PermissionRequest, "projectDir" | "worktreeRoot" | "scopeResolution" | "gitState">> {
  if (typeof directory !== "string" || !directory.trim()) throw new ReviewFailure("context", "Session location is unavailable");
  const scope = await optionalFact(() => lookups.scope(directory), signal);
  const location = scope?.directory ?? directory;
  const branch = await optionalFact(() => lookups.branch(location), signal);
  const tree = await optionalFact(() => lookups.status(location), signal);
  return {
    projectDir: location, worktreeRoot: scope?.worktreeRoot,
    scopeResolution: scope === undefined ? "unknown" : undefined,
    gitState: { branch: branch?.current, defaultBranch: branch?.default, clean: tree === undefined ? undefined : tree.length === 0 },
  };
}
