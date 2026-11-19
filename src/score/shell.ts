import { isAbsolute } from "node:path";
import { resolvePhysicalDirectory } from "../path-policy.js";
import type { OperationEvidence, PermissionRequest, ReviewResult } from "../reviewer.js";
import { guardShell, parseShellCommands, visibleShellDeny } from "../shell.js";
import { scanShell, type ShellScan } from "./shell-argv.js";
import { scoreShellBaseline } from "./shell-baseline.js";
import { shellSafetyScore } from "./shell-safety.js";
import { ask, deny, high, type RequestScore } from "./types.js";
import { supportsPosixReview } from "../shell-policy.js";

const EXECUTION_DIRECTORY_KEYS = ["workdir", "cwd", "directory"] as const;
const INVALID_DIRECTORY = /^(?:undefined|null)$/i;
/** Home, command substitution and expansion spellings cannot be verified statically. */
const UNRESOLVABLE_DIRECTORY = /^[~$`]|[$`\0]/;

interface ShellLocation {
  directory?: string;
  unverified: boolean;
}

function directoryValues(value: unknown): string[] {
  if (typeof value === "string") return [value];
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function resolveDirectory(value: string, projectDir?: string): string | undefined {
  const spelling = value.trim();
  // Whitespace-only or expansion-bearing spellings cannot be verified; the
  // original spelling still resolves because trimming can select another path.
  if (!spelling || INVALID_DIRECTORY.test(spelling) || UNRESOLVABLE_DIRECTORY.test(spelling)) return undefined;
  if (!isAbsolute(value) && (projectDir === undefined || !isAbsolute(projectDir))) return undefined;
  // Physical traversal keeps `..` after a symlink selecting the directory the
  // host would actually enter; lexical collapsing would silently change it.
  return resolvePhysicalDirectory(value, projectDir ?? process.cwd());
}

/** Exactly one captured execution directory may become the scoring base;
 * missing, conflicting or unresolvable evidence must not clear statically. */
function shellLocation(operation: OperationEvidence | undefined, projectDir?: string): ShellLocation {
  const values = EXECUTION_DIRECTORY_KEYS.flatMap((key) => directoryValues(operation?.arguments?.[key]));
  if (values.length === 0) return { unverified: false };
  const resolved = new Set<string>();
  for (const value of values) {
    const directory = resolveDirectory(value, projectDir);
    if (directory === undefined) return { unverified: true };
    resolved.add(directory);
  }
  return resolved.size === 1 ? { directory: [...resolved][0], unverified: false } : { unverified: true };
}

function locatedRequest(request: PermissionRequest, location: ShellLocation): PermissionRequest {
  if (location.directory === undefined || location.directory === request.projectDir) return request;
  return { ...request, projectDir: location.directory };
}

function commandValues(operation: OperationEvidence | undefined): string[] {
  const value = operation?.arguments?.command;
  if (typeof value === "string") return [value];
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function segmentKeys(value: string): Set<string> | undefined {
  const parsed = parseShellCommands(value);
  if (parsed === undefined || !parsed.complete || parsed.segments.length === 0) return undefined;
  return new Set(parsed.segments.map((segment) => JSON.stringify(segment.words)));
}

function sameSegments(left: ReadonlySet<string>, right: ReadonlySet<string>): boolean {
  return left.size === right.size && [...left].every((key) => right.has(key));
}

/** The captured command must name exactly the commands the permission resources
 * describe; missing or conflicting command evidence cannot clear statically. */
function commandEvidenceConflicts(operation: OperationEvidence | undefined, resources: readonly string[]): boolean {
  if (operation === undefined) return false;
  // No captured arguments at all means this request never carried a conflicting
  // command claim; incompleteness still marks captured evidence as lost.
  if (operation.arguments === undefined) return operation.complete === false;
  const commands = commandValues(operation);
  if (commands.length !== 1) return true;
  const [command] = commands;
  if (command === undefined || command.trim().length === 0) return true;
  const captured = segmentKeys(command);
  if (captured === undefined) return true;
  const scored = new Set<string>();
  for (const resource of resources) {
    const keys = segmentKeys(resource);
    if (keys === undefined) return true;
    for (const key of keys) scored.add(key);
  }
  return !sameSegments(captured, scored);
}

/** Preserve visible denies; parser uncertainty must reach configured reviewers. */
function guardScore(guarded: ReviewResult | undefined, resources: readonly string[],
  projectDir?: string, worktreeRoot?: string): RequestScore | undefined {
  if (guarded?.decision === "deny") return deny(guarded.reason);
  if (guarded?.decision !== "ask") return undefined;
  // The POSIX scanner cannot safely analyze other shell dialects.
  if (process.platform === "win32") return ask(guarded.reason);
  // The parser cannot clear uncertain syntax, but visible dangers still win.
  const blocked = visibleShellDeny(resources, projectDir, worktreeRoot);
  if (blocked !== undefined) return deny(blocked);
  return undefined;
}

/** Scores one shell request: visible denies, safety checks, then residual band. */
export function scoreShellRequest(request: PermissionRequest, worktreeRoot?: string): RequestScore {
  const { resources } = request;
  if (!supportsPosixReview(request.shell)) return { ...high("Shell dialect requires model review"), findings: ["Full raw command retained; POSIX-derived denials not applied"] };
  const location = shellLocation(request.operation, request.projectDir);
  const located = locatedRequest(request, location);
  const guarded = guardShell(resources, located.projectDir);
  const rejected = guardScore(guarded, resources, located.projectDir, worktreeRoot);
  if (rejected) return rejected;
  // The parsed resources are the scored command; captured command evidence that
  // is missing or points at different commands cannot grant static clearance.
  if (commandEvidenceConflicts(request.operation, resources))
    return high("Shell command evidence is missing or conflicts with the permission resources");
  // A relocated base without the original containment root cannot prove scope.
  if (location.unverified || (located !== request && worktreeRoot === undefined))
    return high("Shell working directory evidence is unresolved; static scope cannot be verified");
  const scan: ShellScan = scanShell(resources);
  const unsafe = shellSafetyScore(scan, located, worktreeRoot);
  if (unsafe) return unsafe;
  if (guarded?.decision === "ask") return high(guarded.reason);
  return scoreShellBaseline(scan, guarded, located.projectDir, worktreeRoot);
}
