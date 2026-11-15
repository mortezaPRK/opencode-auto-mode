import { resolveExecutable } from "./shell-policy.js";
import { lstatSync, statSync } from "node:fs";
import { isAbsolute, sep } from "node:path";

export interface CopyOperand { index: number; path?: string }
type Entry = "link" | "directory" | "regular" | "unknown";

const LONG_COPY_FLAGS = new Set(["--no-dereference", "--dereference", "--recursive", "--archive", "--remove-destination",
  "--force", "--interactive", "--no-clobber", "--preserve", "--verbose", "--no-target-directory"]);

/** Only understood zero-arity copy options establish how an operand's final
 * link is consumed. Unknown arity/modes abstain rather than read a referent. */
export function copyPathMode(words: readonly string[], index: number, operands: readonly CopyOperand[], directory = process.cwd()): boolean | undefined {
  const executable = resolveExecutable(words);
  if (!executable) return undefined;
  const args = words.slice(executable.index + 1);
  const end = args.indexOf("--");
  const flags = (end === -1 ? args : args.slice(0, end)).filter((arg) => arg.startsWith("-"));
  if (flags.some((flag) => !knownCopyFlag(flag))) return undefined;
  const mode = sourceMode(flags);
  if (index === operands.at(-1)?.index) return destinationMode(flags, operands, mode, directory);
  const operand = operands.find((item) => item.index === index);
  return entryMode(entryType(operand?.path, directory), mode, flags);
}

function entryMode(entry: Entry, mode: boolean | undefined, flags: readonly string[]): boolean | undefined {
  if (entry === "regular") return true;
  if (entry === "directory") return recursive(flags) ? true : undefined;
  return mode;
}

function recursive(flags: readonly string[]): boolean {
  return flags.some((flag) => ["--recursive", "--archive"].includes(flag) || /^-[^-]*[Rra]/.test(flag));
}

function operandPath(target: string, directory: string): string {
  return isAbsolute(target) ? target : `${directory}${sep}${target}`;
}

function entryType(target: string | undefined, directory: string): Entry {
  if (target === undefined) return "unknown";
  try {
    const stat = lstatSync(operandPath(target, directory));
    if (stat.isSymbolicLink()) return "link";
    if (stat.isDirectory()) return "directory";
    return stat.isFile() ? "regular" : "unknown";
  } catch { return "unknown"; }
}

function destinationMode(flags: readonly string[], operands: readonly CopyOperand[], mode: boolean | undefined, directory: string): boolean | undefined {
  const destination = operands.at(-1)?.path;
  const sources = operands.slice(0, -1).map((operand) => copiedEntry(entryType(operand.path, directory), mode, flags));
  if (!sources.length || sources.includes("unknown")) return undefined;
  if (destinationDirectory(destination, flags, directory)) return true;
  if (flags.includes("--remove-destination")) return false;
  if (sources.every((source) => source === "contents")) return true;
  return sources.length === 1 && sources[0] === "link" ? false : undefined;
}

function copiedEntry(entry: Entry, mode: boolean | undefined, flags: readonly string[]): "contents" | "link" | "unknown" {
  if (entry === "unknown") return "unknown";
  const follows = entryMode(entry, mode, flags);
  if (entry === "link" && follows === false) return "link";
  return follows === true ? "contents" : "unknown";
}

function destinationDirectory(target: string | undefined, flags: readonly string[], directory: string): boolean {
  if (target === undefined || flags.some((flag) => flag === "--no-target-directory" || /^-[^-]*T/.test(flag))) return false;
  try { return statSync(operandPath(target, directory)).isDirectory(); } catch { return false; }
}

function knownCopyFlag(flag: string): boolean {
  return LONG_COPY_FLAGS.has(flag) || /^-[PLHdaRrfpinvT]+$/.test(flag);
}

function sourceMode(flags: readonly string[]): boolean | undefined {
  const modes = flags.flatMap(copyModeValues);
  if (modes.length) return modes.at(-1);
  return flags.some((flag) => flag === "--recursive" || /^-[^-]*[Rr]/.test(flag)) ? undefined : true;
}

function copyModeValues(flag: string): boolean[] {
  if (["--no-dereference", "--archive"].includes(flag)) return [false];
  if (flag === "--dereference") return [true];
  if (flag.startsWith("--")) return [];
  return [...flag.slice(1)].filter((letter) => "PadLH".includes(letter)).map((letter) => "LH".includes(letter));
}
