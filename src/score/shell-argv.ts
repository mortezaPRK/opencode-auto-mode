import { basename } from "node:path";
import { operandRoles, resolveExecutable } from "../shell-policy.js";
import { parseShellCommands, type ParsedShellCommands } from "../shell.js";
import { high, type RequestScore } from "./types.js";

/**
 * One shell request parsed once, so every deny, scope and baseline check reads
 * the same argv representation.
 */
export interface ShellScan {
  /** Parsed form of each resource; undefined when the parser refuses the text. */
  commands: (ParsedShellCommands | undefined)[];
  /** Every simple argv list, in resource order. */
  parsedWords: string[][];
  /** `parsedWords` after leading wrappers are removed. */
  effective: string[][];
  /** `effective` with the executable reduced to its basename, as deny checks read it. */
  scanned: string[][];
  /** File operands, excluding command names, options and redirect targets. */
  operands: string[];
}

function effectiveArgv(argv: readonly string[]): string[] {
  const executable = resolveExecutable(argv);
  return executable ? argv.slice(executable.index) : [...argv];
}

function scannedArgv(argv: readonly string[]): string[] {
  return [basename(argv[0] ?? ""), ...argv.slice(1)];
}

export function scanShell(resources: readonly string[]): ShellScan {
  const commands = resources.map((resource) => parseShellCommands(resource));
  const parsedWords = commands.flatMap((command) => command?.segments.map((segment) => segment.words) ?? [])
    .filter((argv) => argv.length);
  const effective = parsedWords.map(effectiveArgv);
  return {
    commands,
    parsedWords,
    effective,
    scanned: effective.map(scannedArgv),
    operands: commands.flatMap((command) => command?.operands ?? []),
  };
}

/**
 * Attached option values (`-m/etc/hosts`, `-f../list`, `-X/path`) are file
 * operands the shell word itself hides; they take the same scope and symlink
 * checks as standalone operands.
 */
function attachedPathValues(commands: readonly (ParsedShellCommands | undefined)[]): string[] {
  return commands.flatMap((command) =>
    command?.segments.flatMap((segment) => operandRoles(segment.words).pathValues) ?? []);
}

/** Every operand that names a file, standalone or attached to an option. */
export function pathTargets(scan: ShellScan): string[] {
  return [...scan.operands, ...attachedPathValues(scan.commands)];
}

function hasWrapperPrelude(argv: readonly string[]): boolean {
  const executable = resolveExecutable(argv);
  if (!executable) return false;
  return argv.slice(0, executable.index).some((word) =>
    word.includes("/") || word.startsWith("-") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(word));
}

export function executableShapeScore(scan: ShellScan): RequestScore | undefined {
  // Effective argv is sufficient for deny checks, not for bounded scope:
  // a repo-controlled wrapper, wrapper options (cwd/output/config), or
  // leading environment assignments can change where a build operates.
  if (scan.parsedWords.some(hasWrapperPrelude)) return high("Wrapper executable or effects require review");
  if (scan.effective.some((argv) => argv[0]?.includes("/"))) return high("Path-qualified executable");
  return undefined;
}
