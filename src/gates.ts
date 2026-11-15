export interface VcsState {
  branch?: string;
  defaultBranch?: string;
  upstream?: string;
  clean?: boolean;
}
export interface VcsGateResult { allowed: boolean; reason: string; mandatory?: boolean }

/** Missing VCS facts are not evidence that a destructive operation is safe. */
export function evaluateVcsGate(state?: VcsState): VcsGateResult {
  if (state?.clean === false) return { allowed: false, mandatory: true, reason: "History changes require a clean working tree" };
  if (!state?.branch || !state.defaultBranch) return { allowed: false, reason: "VCS branch/default branch unknown" };
  if (state.branch === state.defaultBranch) return { allowed: false, mandatory: true, reason: "History changes on the default branch are protected" };
  if (!state.upstream) return { allowed: false, reason: "VCS upstream unknown" };
  if (state.clean !== true) return { allowed: false, reason: "Working tree status unknown" };
  return { allowed: true, reason: "Non-default branch with upstream and clean working tree" };
}
