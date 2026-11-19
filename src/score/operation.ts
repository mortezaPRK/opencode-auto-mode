import { classifyPath, pathFindings } from "../path-policy.js";
import type { OperationEvidence } from "../reviewer.js";
import { isScopedPath, projectRoot, safeTarget } from "../tiers.js";
import { deny, high, type RequestScore } from "./types.js";

/** Explicit operation fields that name a filesystem location. Tool names and
 * arbitrary identifiers are deliberately excluded. */
const PATH_FIELDS = ["path", "filePath", "file_path", "root", "directory", "workdir", "cwd"] as const;
/** The producer treats `path` as the effective search scope and `root` as its
 * fallback. Mirror that precedence instead of re-adding the unused fallback. */
const SEARCH_TOOLS = new Set(["grep", "glob"]);
const INVALID_PATH = /^(?:undefined|null)$/i;

/** Any scheme-bearing URL is egress/query evidence, not a filesystem path.
 * The scheme is anchored so paths that merely contain `://` are not hidden. */
const URL_SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;
/** A protocol-relative hostname path is network scope, not a local path. */
const PROTOCOL_RELATIVE = /^\/\/[^/]/;
const nonPath = (target: string): boolean => URL_SCHEME.test(target) || PROTOCOL_RELATIVE.test(target);
const usablePath = (value: string): boolean => value.trim().length > 0 && !INVALID_PATH.test(value.trim());

function stringValues(value: unknown): string[] {
  if (typeof value === "string") return [value];
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function selectedTargets(tool: string | undefined, argumentsValue: Record<string, unknown> | undefined): string[] {
  if (tool === undefined || !SEARCH_TOOLS.has(tool))
    return PATH_FIELDS.flatMap((field) => stringValues(argumentsValue?.[field]));
  const path = stringValues(argumentsValue?.path).filter(usablePath);
  return path.length > 0 ? path : stringValues(argumentsValue?.root).filter(usablePath);
}

function operationTargets(operation: OperationEvidence | undefined, action: string): string[] {
  if (operation === undefined || operation === null) return [];
  const declared = stringValues(operation.targets);
  const selected = selectedTargets(operation.tool ?? action, operation.arguments);
  return [...new Set([...declared, ...selected])].filter((target) => target.length > 0 && !nonPath(target));
}

/** Deny only an established protected store that was selected as an actual
 * operation target. Ambiguous paths remain ordinary review evidence, and
 * metadata, action names and arbitrary identifiers are never treated as paths. */
export function operationPathApproval(operation: OperationEvidence | undefined, action: string, projectDir?: string): RequestScore | undefined {
  const targets = operationTargets(operation, action);
  if (targets.length === 0) return undefined;
  const facts = targets.map((target) => classifyPath(target, projectDir));
  if (!facts.some((fact) => fact.kind === "protected")) return undefined;
  return { ...deny("Protected path access"), findings: pathFindings(facts) };
}

const WRITE_ACTIONS = new Set(["edit", "write"]);
const PATTERN = /[*?]/;

function namesPermissionResource(resources: readonly string[], target: string, projectDir?: string): boolean {
  const resolved = classifyPath(target, projectDir).resolved;
  if (resolved === undefined) return false;
  return resources.some((resource) => !PATTERN.test(resource) && !nonPath(resource) &&
    classifyPath(resource, projectDir).resolved === resolved);
}

function verifiedTarget(target: string, write: boolean, projectDir?: string, worktreeRoot?: string): boolean {
  if (projectDir === undefined) return false;
  if (write) return safeTarget(target, projectDir, worktreeRoot);
  return isScopedPath(target, projectDir, worktreeRoot ?? projectRoot(projectDir));
}

/** A low file score needs every captured target to name a permission resource
 * that stays verified in scope; omitted payloads add no target, so they alone
 * do not block. Conflicting or external targets must not clear statically. */
export function operationScopeApproval(operation: OperationEvidence | undefined, action: string,
  resources: readonly string[], projectDir?: string, worktreeRoot?: string): RequestScore | undefined {
  const targets = operationTargets(operation, action);
  if (targets.length === 0) return undefined;
  const write = WRITE_ACTIONS.has(action);
  const verified = targets.every((target) => namesPermissionResource(resources, target, projectDir) &&
    verifiedTarget(target, write, projectDir, worktreeRoot));
  return verified ? undefined : high("Operation target differs from the verified permission scope");
}
