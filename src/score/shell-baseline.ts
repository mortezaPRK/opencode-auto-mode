import { resolve } from "node:path";
import type { ReviewResult } from "../reviewer.js";
import type { ParsedShellCommands } from "../shell.js";
import { isInProject, projectRoot } from "../tiers.js";
import { pathTargets, type ShellScan } from "./shell-argv.js";
import { high, low, medium, type RequestScore } from "./types.js";

/** Writes that never reach a regular file and cannot escape the project. */
const SAFE_DEVICES = new Set(["/dev/null", "/dev/stdout", "/dev/stderr"]);
/** Commands whose subcommands are only gray-band when they stay inside the project. */
const PACKAGE_MANAGERS = new Set(["npm", "pnpm"]);
const INSTALL_SUBCOMMANDS = new Set(["install", "add", "ci"]);
const BUILDERS = new Set(["cargo", "go"]);
const BUILD_SUBCOMMANDS = new Set(["test", "build", "check"]);
const FORGE_SUBCOMMANDS = new Set(["pr", "issue", "repo", "run"]);
const FORGE_READS = new Set(["view", "list", "diff", "checks"]);
const UNSCOPED_INSTALL_FLAGS = /^(?:-g|--global|--prefix|--cwd|--directory)/;
const GIT_GLOBAL_OVERRIDE = /^(?:-c|--git-dir|--work-tree|--exec-path)/;

function operandEscapes(candidate: string, locationDir: string, worktreeRoot: string): boolean {
  if (SAFE_DEVICES.has(candidate)) return false;
  const pathLike = candidate.startsWith("/") || candidate.startsWith("~") ||
    /(?:^|[/\\])\.\.(?:[/\\]|$)/.test(candidate);
  if (!pathLike) return false;
  if (candidate.startsWith("~") || /[$`\0]/.test(candidate)) return true;
  return !isInProject(resolve(locationDir, candidate), worktreeRoot);
}

/**
 * True when a shell operand provably leaves the project scope. Tildes and
 * parameter expansion cannot be resolved statically, so they are never low.
 * Option values (`--output=/outside/file`) are judged as well as the whole word.
 */
function escapesProject(operand: string, locationDir: string, worktreeRoot: string): boolean {
  const candidates = operand.includes("=") ? [operand, ...operand.split("=").slice(1)] : [operand];
  return candidates.some((candidate) => operandEscapes(candidate, locationDir, worktreeRoot));
}

function isInProjectWords(words: readonly string[], projectDir?: string, worktreeRoot?: string): boolean {
  if (!projectDir || !worktreeRoot) return false;
  return !words.some((word) => word.includes("/") && !word.startsWith("--") &&
    !isInProject(resolve(projectDir, word), worktreeRoot));
}

function isMediumGit(words: readonly string[]): boolean {
  return words[1] === "commit" && !words.some((word) => GIT_GLOBAL_OVERRIDE.test(word));
}

function isMediumInstall(words: readonly string[], subcommand?: string): boolean {
  if (!INSTALL_SUBCOMMANDS.has(subcommand ?? "")) return false;
  return words.includes("--ignore-scripts") && !words.some((word) => UNSCOPED_INSTALL_FLAGS.test(word));
}

function isForgeRead(command?: string, words: readonly string[] = []): boolean {
  return command === "gh" && FORGE_SUBCOMMANDS.has(words[1] ?? "") && FORGE_READS.has(words[2] ?? "");
}

function isMediumBun(words: readonly string[], subcommand?: string): boolean {
  return subcommand === "test" || isMediumInstall(words, subcommand);
}

function isMediumInvocation(words: readonly string[]): boolean {
  const [command, subcommand] = words;
  if (command === "git") return isMediumGit(words);
  if (command === "bun") return isMediumBun(words, subcommand);
  if (PACKAGE_MANAGERS.has(command ?? "")) return isMediumInstall(words, subcommand);
  if (BUILDERS.has(command ?? "")) return BUILD_SUBCOMMANDS.has(subcommand ?? "");
  return isForgeRead(command, words);
}

/** Direct in-project runners. Running arbitrary package scripts stays HIGH. */
function mediumShell(words: readonly string[], projectDir?: string, worktreeRoot = projectDir): boolean {
  if (!isInProjectWords(words, projectDir, worktreeRoot)) return false;
  return isMediumInvocation(words);
}

function isBoundedCommand(command: ParsedShellCommands | undefined): boolean {
  return !command?.compound && !command?.segments.some((segment) => segment.write);
}

function wordCount(parsedWords: readonly (readonly string[])[]): number {
  return parsedWords.reduce((total, argv) => total + argv.length, 0);
}

function isBoundedMedium(scan: ShellScan, projectDir?: string, worktreeRoot?: string): boolean {
  return scan.commands.every(isBoundedCommand) &&
    scan.operands.length === wordCount(scan.parsedWords) &&
    scan.effective.every((argv) => mediumShell(argv, projectDir, worktreeRoot));
}

function isReadOnlyEligible(guarded: ReviewResult | undefined, scan: ShellScan): boolean {
  if (guarded?.decision !== "allow") return false;
  return !scan.scanned.some((argv) => ["bun", "gh", "git"].includes(argv[0] ?? ""));
}

function readOnlyScore(scan: ShellScan, projectDir?: string, worktreeRoot?: string): RequestScore {
  // A read-only command still reads whatever its operands or attached option
  // values name. Low risk requires every one to stay inside the evaluated project.
  const locationDir = projectDir ?? process.cwd();
  const scopeRoot = worktreeRoot ?? projectRoot(locationDir);
  if (pathTargets(scan).some((operand) => escapesProject(operand, locationDir, scopeRoot)))
    return high("Shell path operand resolves outside the project");
  return low("Parsed read-only command with protected-path checks");
}

/** Picks the residual band after every deny and ask has been ruled out. */
export function scoreShellBaseline(scan: ShellScan, guarded: ReviewResult | undefined,
  projectDir?: string, worktreeRoot?: string): RequestScore {
  if (isReadOnlyEligible(guarded, scan)) return readOnlyScore(scan, projectDir, worktreeRoot);
  if (isBoundedMedium(scan, projectDir, worktreeRoot))
    return medium("In-project build, test, install without scripts, commit or forge read");
  return high("Shell command has unbounded side effects");
}
