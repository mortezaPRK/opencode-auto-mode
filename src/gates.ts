export interface VcsState {
  branch?: string;
  defaultBranch?: string;
  upstream?: string;
  clean: boolean;
}
export interface VcsGateResult { allowed: boolean; reason: string }

/** Missing VCS facts are not evidence that a destructive operation is safe. */
export function evaluateVcsGate(state?: VcsState): VcsGateResult {
  if (!state?.branch || !state.defaultBranch) return { allowed: false, reason: "VCS branch/default branch unknown" };
  if (state.branch === state.defaultBranch) return { allowed: false, reason: "History changes on the default branch are protected" };
  if (!state.upstream) return { allowed: false, reason: "History changes require an upstream" };
  if (state.clean !== true) return { allowed: false, reason: "History changes require a clean working tree" };
  return { allowed: true, reason: "Non-default branch with upstream and clean working tree" };
}
