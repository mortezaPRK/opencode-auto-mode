import { classifyPath, pathFindings } from "../path-policy.js";
import type { OperationEvidence } from "../reviewer.js";
import { deny, type RequestScore } from "./types.js";

/** Explicit operation fields that name a filesystem location. Tool names and
 * arbitrary identifiers are deliberately excluded. */
const PATH_FIELDS = ["path", "filePath", "file_path", "root", "directory", "workdir", "cwd"] as const;

/** Any scheme-bearing URL is egress/query evidence, not a filesystem path.
 * The scheme is anchored so paths that merely contain `://` are not hidden. */
const URL_SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;
/** A protocol-relative hostname path is network scope, not a local path. */
const PROTOCOL_RELATIVE = /^\/\/[^/]/;
const nonPath = (target: string): boolean => URL_SCHEME.test(target) || PROTOCOL_RELATIVE.test(target);

function stringValues(value: unknown): string[] {
  if (typeof value === "string") return [value];
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function operationTargets(operation: OperationEvidence | undefined): string[] {
  if (operation === undefined || operation === null) return [];
  const declared = stringValues(operation.targets);
  const selected = PATH_FIELDS.flatMap((field) => stringValues(operation.arguments?.[field]));
  return [...new Set([...declared, ...selected])].filter((target) => target.length > 0 && !nonPath(target));
}

/** Deny only an established protected store that was selected as an actual
 * operation target. Ambiguous paths remain ordinary review evidence, and
 * metadata, action names and arbitrary identifiers are never treated as paths. */
export function operationPathApproval(operation: OperationEvidence | undefined, projectDir?: string): RequestScore | undefined {
  const targets = operationTargets(operation);
  if (targets.length === 0) return undefined;
  const facts = targets.map((target) => classifyPath(target, projectDir));
  if (!facts.some((fact) => fact.kind === "protected")) return undefined;
  return { ...deny("Protected path access"), findings: pathFindings(facts) };
}
