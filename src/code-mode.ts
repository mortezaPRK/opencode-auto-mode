import { createHash } from "node:crypto";

const MAX_CODE_BYTES = 65_536;
const IDENTITY_PREFIX = "execute:sha256:";
const METADATA_KEY = "opencodeAutoModeCode";

/** Hash the exact UTF-8 program, without normalizing whitespace or punctuation.
 * Native save entries are wildcard patterns: raw JavaScript is never a safe save entry.
 * This identity format intentionally contains neither '*' nor '?'. */
export function codeModeIdentity(code: string): string {
  return `${IDENTITY_PREFIX}${createHash("sha256").update(code, "utf8").digest("hex")}`;
}

function validCode(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0 && Buffer.byteLength(value) <= MAX_CODE_BYTES;
}

/** Build only the Code Mode-specific fields of permission.assert. The caller owns
 * session, agent and source, and must not mutate the executable input afterwards.
 * No native rules or saved approvals are read, migrated, removed, or overwritten.
 * Legacy raw-code rules generally do not match these identities; broad native
 * execute policies (including '*') still do. Raw-code-specific configured policies
 * require a separate native evaluation by the caller; this helper cannot preserve
 * their semantics by passing raw code as a second resource (that breaks Always).
 */
export function codeModePermission(input: unknown) {
  const code = typeof input === "string" ? input : input && typeof input === "object" && !Array.isArray(input)
    ? (input as { code?: unknown }).code : undefined;
  if (!validCode(code)) throw new Error("Code Mode input is missing, unsupported or too large for permission review");
  const identity = codeModeIdentity(code);
  return {
    action: "execute" as const,
    resources: [identity],
    save: [identity],
    metadata: { [METADATA_KEY]: { version: 1, identity, code } },
  };
}

/** Recover reviewer evidence only when metadata is bound to the sole hash resource.
 * Native deny remains final. Native allows are reviewed whenever auto mode is on;
 * there is no reviewNativeAllows option and no legacy bypass. Returned resources
 * are reviewer-local, not host edits.
 * Undefined means an ordinary non-identity execute request; malformed identity
 * requests throw rather than allowing review of an opaque digest or mismatched code.
 */
export function codeModeReviewResources(event: { action: string; resources: readonly string[]; metadata?: Record<string, unknown> }): string[] | undefined {
  if (event.action !== "execute" || !event.resources.some(resource => resource.startsWith(IDENTITY_PREFIX))) return undefined;
  const evidence = event.metadata?.[METADATA_KEY];
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence))
    throw new Error("Code Mode program evidence is unavailable");
  const { version, identity, code } = evidence as { version?: unknown; identity?: unknown; code?: unknown };
  if (version !== 1 || !validCode(code) || event.resources.length !== 1 || identity !== event.resources[0] || identity !== codeModeIdentity(code))
    throw new Error("Code Mode program evidence does not match its permission identity");
  return [code];
}
