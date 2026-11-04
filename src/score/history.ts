import { evaluateVcsGate, type VcsState } from "../gates.js";
import { isLongOption } from "../shell-policy.js";
import { ask, high, type RequestScore } from "./types.js";

const HISTORY_SUBCOMMANDS = new Set(["rebase", "filter-branch", "filter-repo"]);
const FORCE_PUSH_OPTIONS = ["--force", "--force-with-lease", "--force-if-includes", "--delete", "--mirror", "--prune"];

/** GNU option parsing accepts unambiguous abbreviations, so long options are prefix-matched. */
function hasLong(args: readonly string[], name: string): boolean {
  return args.some((arg) => isLongOption(arg, name));
}

function hasAnyLong(args: readonly string[], names: readonly string[]): boolean {
  return names.some((name) => hasLong(args, name));
}

function pushRewritesHistory(args: readonly string[]): boolean {
  if (hasAnyLong(args, FORCE_PUSH_OPTIONS)) return true;
  return args.some((arg) => /^-[^-]*[fd]/.test(arg) || arg.startsWith("+"));
}

function deletesRef(args: readonly string[], shortFlag: RegExp): boolean {
  return hasAnyLong(args, ["--delete"]) || args.some((arg) => shortFlag.test(arg));
}

/** True when a parsed Git invocation rewrites or deletes history. */
export function historyChange(words: readonly string[]): boolean {
  if (words[0] !== "git") return false;
  const args = words.slice(1);
  const first = args[0];
  if (first === "push") return pushRewritesHistory(args);
  if (first === "commit") return hasLong(args, "--amend");
  if (first === "reset") return hasLong(args, "--hard");
  if (first === "branch") return deletesRef(args, /^-[^-]*[dD]/);
  if (first === "tag") return deletesRef(args, /^-[^-]*d/);
  return HISTORY_SUBCOMMANDS.has(first ?? "");
}

/** Git global options alter cwd/config or helper execution, so the subcommand is not trustworthy. */
export function isGitGlobalOption(argv: readonly string[]): boolean {
  return argv[0] === "git" && argv[1]?.startsWith("-") === true;
}

function pushesToDefaultBranch(argv: readonly string[], defaultBranch: string): boolean {
  if (argv[0] !== "git" || argv[1] !== "push") return false;
  return argv.slice(2).some((arg) =>
    arg.replace(/^\+/, "").split(":").pop()?.replace(/^refs\/heads\//, "") === defaultBranch);
}

/** Scores one verified history-changing invocation, or the missing precondition that asks for review. */
export function historyScore(scanned: readonly (readonly string[])[], gitState?: VcsState): RequestScore {
  const gate = evaluateVcsGate(gitState);
  if (!gate.allowed) return ask(gate.reason);
  const defaultBranch = gitState?.defaultBranch;
  if (defaultBranch && scanned.some((argv) => pushesToDefaultBranch(argv, defaultBranch)))
    return ask("Explicit push destination is the default branch");
  return high("History changes satisfy VCS preconditions but still require review");
}
