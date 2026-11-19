import { createHash } from "node:crypto";
import { normalize } from "node:path";
import { isRecord } from "./guards.js";

/** Structural capture identity of one built-in edit/write call. This is a
 * provenance binding, not permission or proof: the host supplies both sides, so
 * the digest only says the payload fields are the exact ones the factory
 * hashed. It is process-local and gone after serialization. */
export interface EditCaptureIdentity {
  readonly sessionID: string;
  readonly messageID: string;
  readonly callID: string;
  readonly argsSha256: string;
}

/** Immutable edit/write body bound to an original host capture. Bare payload
 * fields are a citation, not authority: callers must revalidate with
 * `verifyCapturedEdit` and compare the separate expected capture. Only
 * `prepareCapturedEdit` can mint one; a clone or round-trip has no provenance. */
export interface EditPayload {
  readonly tool: "edit" | "write";
  readonly path: string;
  readonly oldString?: string;
  readonly newString?: string;
  readonly replaceAll?: boolean;
  readonly content?: string;
  readonly complete: true;
  readonly capture: EditCaptureIdentity;
}

/** Original event shape the host captured for one call. */
export interface CapturedEditEvent {
  readonly tool: "edit" | "write";
  readonly args: Record<string, unknown>;
}

export interface CapturedEditIdentity {
  readonly sessionID: string;
  readonly messageID: string;
  readonly callID: string;
}

type PathField = "path" | "filePath";

interface EditBody {
  readonly tool: "edit" | "write";
  readonly path: string;
  readonly oldString?: string;
  readonly newString?: string;
  readonly replaceAll?: boolean;
  readonly content?: string;
}

interface RecognizedEdit {
  readonly body: EditBody;
  readonly args: Readonly<Record<string, unknown>>;
}

interface PathAlias {
  readonly field: PathField;
  readonly value: string;
}

interface PathAliases {
  readonly path?: string;
  readonly file?: string;
}

interface MintedEdit {
  readonly args: Readonly<Record<string, unknown>>;
}

const MAX_ID_CHARS = 256;
const MAX_PATH_CHARS = 2_048;
const SHA256 = /^[0-9a-f]{64}$/;
const NUL = /\0/;
const WILDCARD = /[*?]/;
const PARENT_COMPONENT = /(?:^|[\\/])\.\.(?:[\\/]|$)/;
const HOME_PREFIX = /^(?:~|\$HOME)(?:[\\/]|$)/;
const NO_KEYS: ReadonlySet<string> = new Set();
const EDIT_ARG_REQUIRED = new Set(["oldString", "newString"]);
const EDIT_ARG_OPTIONAL = new Set(["path", "filePath", "replaceAll"]);
const WRITE_ARG_REQUIRED = new Set(["content"]);
const WRITE_ARG_OPTIONAL = new Set(["path", "filePath"]);
const EDIT_PAYLOAD_REQUIRED =
  new Set(["tool", "path", "oldString", "newString", "complete", "capture"]);
const EDIT_PAYLOAD_OPTIONAL = new Set(["replaceAll"]);
const WRITE_PAYLOAD_REQUIRED = new Set(["tool", "path", "content", "complete", "capture"]);
const CAPTURE_KEYS = new Set(["sessionID", "messageID", "callID", "argsSha256"]);

/** Module-private provenance tokens; never exported or persisted. */
const MINTED = new WeakMap<object, MintedEdit>();

/** Required keys must all be own properties; every other key must be optional. */
function keysMatch(value: Record<string, unknown>, required: ReadonlySet<string>,
  optional: ReadonlySet<string> = NO_KEYS): boolean {
  let requiredSeen = 0;
  for (const key of Object.keys(value)) {
    if (required.has(key)) requiredSeen += 1;
    else if (!optional.has(key)) return false;
  }
  return requiredSeen === required.size;
}

function idText(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= MAX_ID_CHARS &&
    value.trim().length > 0 && !NUL.test(value);
}

/** Shared with the operation-path guard so both checks reject the same shapes.
 * A parent component is rejected before lexical normalization can collapse it,
 * because `link/../file` resolves the link first on the filesystem even though
 * `normalize` would keep only the sibling spelling. */
export function isUsableEditPath(value: string): boolean {
  const trimmed = value.trim();
  return trimmed.length > 0 && trimmed.length <= MAX_PATH_CHARS && !NUL.test(value) &&
    !WILDCARD.test(value) && !PARENT_COMPONENT.test(value) && !HOME_PREFIX.test(trimmed);
}

function usableAlias(value: unknown): string | undefined {
  return typeof value === "string" && isUsableEditPath(value) ? value : undefined;
}

function aliasValues(args: Record<string, unknown>): PathAliases | undefined {
  const hasPath = Object.hasOwn(args, "path");
  const hasFile = Object.hasOwn(args, "filePath");
  const path = hasPath ? usableAlias(args.path) : undefined;
  const file = hasFile ? usableAlias(args.filePath) : undefined;
  if (hasPath && path === undefined) return undefined;
  if (hasFile && file === undefined) return undefined;
  if (!hasPath && !hasFile) return undefined;
  return { path, file };
}

function pathAliasOf(args: Record<string, unknown>): PathAlias | undefined {
  const aliases = aliasValues(args);
  if (aliases === undefined) return undefined;
  const { path, file } = aliases;
  if (path !== undefined && file !== undefined && normalize(path) !== normalize(file))
    return undefined;
  if (path !== undefined) return { field: "path", value: path };
  return file === undefined ? undefined : { field: "filePath", value: file };
}

function editBody(alias: PathAlias, args: Record<string, unknown>): EditBody | undefined {
  const { oldString, newString, replaceAll } = args;
  if (typeof oldString !== "string" || oldString.length === 0 || typeof newString !== "string")
    return undefined;
  if (Object.hasOwn(args, "replaceAll") && typeof replaceAll !== "boolean") return undefined;
  return {
    tool: "edit",
    path: alias.value,
    oldString,
    newString,
    ...(typeof replaceAll === "boolean" ? { replaceAll } : {}),
  };
}

function writeBody(path: string, content: unknown): EditBody | undefined {
  return typeof content === "string" ? { tool: "write", path, content } : undefined;
}

/** Snapshots the mutable source first, then validates and freezes that copy. */
function recognizedArgs(tool: unknown, rawArgs: unknown): RecognizedEdit | undefined {
  if (!isRecord(rawArgs) || (tool !== "edit" && tool !== "write")) return undefined;
  const args = { ...rawArgs };
  const required = tool === "edit" ? EDIT_ARG_REQUIRED : WRITE_ARG_REQUIRED;
  const optional = tool === "edit" ? EDIT_ARG_OPTIONAL : WRITE_ARG_OPTIONAL;
  if (!keysMatch(args, required, optional)) return undefined;
  const alias = pathAliasOf(args);
  if (alias === undefined) return undefined;
  const body = tool === "edit" ? editBody(alias, args) : writeBody(alias.value, args.content);
  return body === undefined ? undefined : { body, args: Object.freeze(args) };
}

function payloadKeys(value: Record<string, unknown>, tool: "edit" | "write"): boolean {
  return tool === "edit"
    ? keysMatch(value, EDIT_PAYLOAD_REQUIRED, EDIT_PAYLOAD_OPTIONAL)
    : keysMatch(value, WRITE_PAYLOAD_REQUIRED);
}

function payloadMatches(value: Record<string, unknown>, body: EditBody): boolean {
  return value.tool === body.tool && value.path === body.path &&
    value.oldString === body.oldString && value.newString === body.newString &&
    value.replaceAll === body.replaceAll && value.content === body.content;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isRecord(value)) {
    const entries = Object.keys(value).sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`);
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

/** Hashes the full frozen original args, never a reconstructed payload body. */
function argsDigest(args: Readonly<Record<string, unknown>>): string {
  return createHash("sha256").update(canonicalJson(args)).digest("hex");
}

function identityOk(value: unknown): value is CapturedEditIdentity {
  return isRecord(value) && idText(value.sessionID) && idText(value.messageID) &&
    idText(value.callID);
}

function freezePayload(body: EditBody, capture: EditCaptureIdentity): EditPayload {
  return Object.freeze({
    tool: body.tool,
    path: body.path,
    ...(body.oldString === undefined ? {} : { oldString: body.oldString }),
    ...(body.newString === undefined ? {} : { newString: body.newString }),
    ...(body.replaceAll === undefined ? {} : { replaceAll: body.replaceAll }),
    ...(body.content === undefined ? {} : { content: body.content }),
    complete: true as const,
    capture,
  });
}

/** Mints the only payload shape the classifier accepts. `consent` must be
 * exactly `true`; the factory never infers consent or sends anything. It hashes
 * the full frozen args, so the real alias and any `replaceAll` stay bound, and
 * rejects extra or missing args rather than trimming them. */
export function prepareCapturedEdit(
  event: CapturedEditEvent,
  identity: CapturedEditIdentity,
  consent: boolean,
): EditPayload | undefined {
  if (consent !== true || !isRecord(event) || !identityOk(identity)) return undefined;
  const recognized = recognizedArgs(event.tool, event.args);
  if (recognized === undefined) return undefined;
  const capture = Object.freeze({
    sessionID: identity.sessionID,
    messageID: identity.messageID,
    callID: identity.callID,
    argsSha256: argsDigest(recognized.args),
  });
  const payload = freezePayload(recognized.body, capture);
  MINTED.set(payload, Object.freeze({ args: recognized.args }));
  return payload;
}

/** Validates a structural capture identity without granting provenance. */
export function readEditCapture(value: unknown): EditCaptureIdentity | undefined {
  if (!isRecord(value) || !keysMatch(value, CAPTURE_KEYS)) return undefined;
  const { sessionID, messageID, callID, argsSha256 } = value;
  if (!idText(sessionID) || !idText(messageID) || !idText(callID)) return undefined;
  if (typeof argsSha256 !== "string" || !SHA256.test(argsSha256)) return undefined;
  return Object.freeze({ sessionID, messageID, callID, argsSha256 });
}

export function sameEditCapture(left: EditCaptureIdentity, right: EditCaptureIdentity): boolean {
  return left.sessionID === right.sessionID && left.messageID === right.messageID &&
    left.callID === right.callID && left.argsSha256 === right.argsSha256;
}

/** Frozen copy of the exact original args of a minted payload, read only from
 * the WeakMap so the real alias and `replaceAll` survive. It carries no
 * provenance and must not be treated as authority. */
export function capturedEditArgs(value: unknown): Readonly<Record<string, string | boolean>> | undefined {
  const payload = verifyCapturedEdit(value);
  if (payload === undefined) return undefined;
  const provenance = MINTED.get(payload);
  if (provenance === undefined) return undefined;
  const args: Record<string, string | boolean> = {};
  for (const [key, item] of Object.entries(provenance.args)) {
    if (typeof item !== "string" && typeof item !== "boolean") return undefined;
    args[key] = item;
  }
  return Object.freeze(args);
}

/**
 * Re-validates a minted payload and recomputes its args digest. Provenance comes
 * only from the WeakMap token, never the caller-supplied digest, so a fake
 * object repeating a correct hash still fails. The recomputation catches a
 * factory bug; it is not proof that the capture happened.
 */
export function verifyCapturedEdit(value: unknown): EditPayload | undefined {
  if (!isRecord(value) || value.complete !== true) return undefined;
  const provenance = MINTED.get(value);
  if (provenance === undefined) return undefined;
  const recognized = recognizedArgs(value.tool, provenance.args);
  if (recognized === undefined || !payloadKeys(value, recognized.body.tool)) return undefined;
  if (!payloadMatches(value, recognized.body)) return undefined;
  const capture = readEditCapture(value.capture);
  if (capture === undefined || argsDigest(provenance.args) !== capture.argsSha256) return undefined;
  // The original frozen object is the only thing carrying the WeakMap token.
  return value as unknown as EditPayload;
}
