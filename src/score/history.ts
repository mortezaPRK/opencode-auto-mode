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

/**
 * The force-create option of each branch-switching subcommand, with the short
 * letters that take a value so a bundle like `-bB` is read as `-b B` rather
 * than as a force create.
 */
const FORCE_CREATE: Record<string, { short: string; valueLetters: string; long?: string }> = {
  checkout: { short: "B", valueLetters: "bB" },
  switch: { short: "C", valueLetters: "cC", long: "--force-create" },
};

/** The branch name a short bundle force-creates, or undefined when it creates no branch. */
function shortForceCreate(word: string, option: { short: string; valueLetters: string },
  next: string | undefined): { branch?: string } | undefined {
  const letters = word.slice(1);
  for (let index = 0; index < letters.length; index++) {
    if (!option.valueLetters.includes(letters[index])) continue;
    if (letters[index] !== option.short) return undefined;
    const attached = letters.slice(index + 1);
    return { branch: attached.length ? attached : next };
  }
  return undefined;
}

/** True for a short-option bundle (`-qB`), which is where the force-create letter can appear. */
function isShortBundle(word: string): boolean {
  return word.startsWith("-") && !word.startsWith("--") && word.length > 1;
}

/** The branch name a long force-create option attaches (`=trunk`) or takes from the next word. */
function longForceCreate(word: string, next: string | undefined): string | undefined {
  const separator = word.indexOf("=");
  return separator === -1 ? next : word.slice(separator + 1);
}

/**
 * `checkout -B`/`switch -C`/`switch --force-create` reset an existing branch
 * before switching to it. The branch name is the option's attached value
 * (`-Btrunk`, `--force-create=trunk`) or the following word, so a start point
 * (`HEAD~1`) is never mistaken for the branch; `--` ends option parsing.
 */
function forceCreate(args: readonly string[]): { branch?: string } | undefined {
  const option = FORCE_CREATE[args[0] ?? ""];
  if (option === undefined) return undefined;
  const rest = args.slice(1);
  for (let index = 0; index < rest.length; index++) {
    const word = rest[index];
    if (word === "--") return undefined;
    if (option.long !== undefined && isLongOption(word, option.long))
      return { branch: longForceCreate(word, rest[index + 1]) };
    if (!isShortBundle(word)) continue;
    const created = shortForceCreate(word, option, rest[index + 1]);
    if (created !== undefined) return created;
  }
  return undefined;
}

function forceResetsBranch(args: readonly string[]): boolean {
  return forceCreate(args) !== undefined;
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
  return forceCreate(argv.slice(1))?.branch;
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
