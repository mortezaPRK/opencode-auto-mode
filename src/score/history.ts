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
  return args.some((arg) => /^-[^-]*[fd]/.test(arg) || arg.startsWith("+") || /^:.+/.test(arg));
}

function deletesRef(args: readonly string[], shortFlag: RegExp): boolean {
  return hasAnyLong(args, ["--delete", "--force"]) || args.some((arg) => shortFlag.test(arg));
}

/**
 * True unless the reset only touches the index/working tree for given paths
 * (`git reset [<commit>] -- <pathspec>...`), which leaves HEAD and the
 * current branch untouched. Any other form (mode flags, or a bare commit
 * argument with no pathspec) moves HEAD.
 */
function resetMovesHead(args: readonly string[]): boolean {
  const rest = args.slice(1);
  if (hasAnyLong(rest, ["--hard", "--soft", "--mixed", "--merge", "--keep"])) return true;
  const dashIndex = rest.indexOf("--");
  if (dashIndex !== -1) return dashIndex === rest.length - 1;
  return rest.filter((arg) => !arg.startsWith("-")).length <= 1;
}

/** `checkout -B`/`switch -C`/`switch --force-create` reset an existing branch before switching to it. */
function forceResetsBranch(args: readonly string[]): boolean {
  const first = args[0];
  if (first === "checkout") return args.some((arg) => /^-[^-]*B/.test(arg));
  if (first === "switch") return hasLong(args, "--force-create") || args.some((arg) => /^-[^-]*C/.test(arg));
  return false;
}

/** True when a parsed Git invocation rewrites or deletes history. */
export function historyChange(words: readonly string[]): boolean {
  if (words[0] !== "git") return false;
  const args = words.slice(1);
  const first = args[0];
  if (first === "push") return pushRewritesHistory(args);
  if (first === "commit") return hasLong(args, "--amend");
  if (first === "reset") return resetMovesHead(args);
  if (first === "branch") return deletesRef(args, /^-[^-]*[dDf]/);
  if (first === "tag") return deletesRef(args, /^-[^-]*[df]/);
  if (first === "checkout" || first === "switch") return forceResetsBranch(args);
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

/** Name of the branch that a force-reset `checkout -B`/`switch -C` would overwrite, if any. */
function forceResetTarget(argv: readonly string[]): string | undefined {
  if (argv[0] !== "git") return undefined;
  const args = argv.slice(1);
  if (!forceResetsBranch(args)) return undefined;
  return args.slice(1).find((arg) => !arg.startsWith("-"));
}

/** Scores one verified history-changing invocation, or the missing precondition that asks for review. */
export function historyScore(scanned: readonly (readonly string[])[], gitState?: VcsState): RequestScore {
  const gate = evaluateVcsGate(gitState);
  if (!gate.allowed) return ask(gate.reason);
  const defaultBranch = gitState?.defaultBranch;
  if (defaultBranch && scanned.some((argv) => pushesToDefaultBranch(argv, defaultBranch)))
    return ask("Explicit push destination is the default branch");
  if (defaultBranch && scanned.some((argv) => forceResetTarget(argv) === defaultBranch))
    return ask("Force-reset target is the default branch");
  return high("History changes satisfy VCS preconditions but still require review");
}
