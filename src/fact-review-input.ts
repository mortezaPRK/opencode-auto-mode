/** Owned plain snapshot of an untrusted request: own data descriptors are
 * deep-cloned and frozen before use; accessors, exotic prototypes and sparse
 * arrays reject. A minted payload is kept by identity and re-validated. */
import {
  readEditCapture,
  verifyCapturedEdit,
  type EditCaptureIdentity,
  type EditPayload,
} from "./edit-capture.js";
import { MAX_REQUEST_BYTES } from "./guards.js";
import type { PermissionRequest } from "./reviewer.js";

export interface FactReviewSnapshot extends PermissionRequest {
  editPayload?: EditPayload;
  expectedEditCapture?: EditCaptureIdentity;
}

export type FactReviewSnapshotResult =
  | { readonly ok: true; readonly snapshot: FactReviewSnapshot }
  | { readonly ok: false; readonly reason: string };

const INVALID = Symbol("fact-review-invalid");
type Invalid = typeof INVALID;
type Cloned = unknown | Invalid;
type SnapshotOperation = NonNullable<FactReviewSnapshot["operation"]>;
type ContextSnapshot = Omit<FactReviewSnapshot, "action" | "resources">;
type EditBinding = Pick<FactReviewSnapshot, "editPayload" | "expectedEditCapture">;

interface Budget { nodes: number }
interface AuthoritySnapshot { readonly userMessages?: string[]; readonly transcript?: string }
interface PathSnapshot { projectDir?: string; worktreeRoot?: string }
interface ParsedOperation {
  readonly tool?: string;
  readonly access?: SnapshotOperation["access"];
  readonly targets?: readonly string[];
  readonly args?: Record<string, unknown>;
  readonly complete: boolean;
  /** Capture correlation is separate from payload completion and must survive. */
  readonly correlated?: boolean;
}

const MAX_DEPTH = 12;
const MAX_NODES = 4_096;
const MAX_TEXT = MAX_REQUEST_BYTES;
const ACCESS_VALUES: ReadonlySet<NonNullable<SnapshotOperation["access"]>> =
  new Set(["read", "write", "execute", "unknown"]);
const GIT_TEXT_KEYS = ["branch", "defaultBranch", "upstream"] as const;
const failed = (reason: string): FactReviewSnapshotResult => ({ ok: false, reason });
/** Drops undefined properties without invoking getters on our own objects. */
function definedFields<T extends object>(value: T): T {
  return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined)) as T;
}
function plainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
/** Own enumerable data properties only; any accessor rejects the object. */
function dataEntries(value: object): [string, unknown][] | undefined {
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const entries: [string, unknown][] = [];
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (!descriptor.enumerable) continue;
    if (!("value" in descriptor)) return undefined;
    entries.push([key, descriptor.value]);
  }
  return entries.length > MAX_NODES ? undefined : entries;
}
/** Dense string-indexed array with no accessors, holes or symbol properties. */
function denseArray(value: unknown): unknown[] | undefined {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return undefined;
  if (value.length > MAX_NODES || Object.getOwnPropertySymbols(value).length > 0) return undefined;
  if (Object.keys(value).length !== value.length) return undefined;
  const items: unknown[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !("value" in descriptor)) return undefined;
    items.push(descriptor.value);
  }
  return items;
}
function stringArray(value: unknown): string[] | undefined {
  const items = denseArray(value);
  if (items === undefined) return undefined;
  if (!items.every((item) => typeof item === "string" && item.length <= MAX_TEXT)) return undefined;
  return Object.freeze(items) as string[];
}
function optionalText(value: unknown): string | undefined | Invalid {
  return value === undefined ? undefined : typeof value === "string" && value.length <= MAX_TEXT ? value : INVALID;
}
function optionalBoolean(value: unknown): boolean | undefined | Invalid {
  return value === undefined ? undefined : typeof value === "boolean" ? value : INVALID;
}
function accessValue(value: unknown): SnapshotOperation["access"] | Invalid {
  if (value === undefined) return undefined;
  return typeof value === "string" && ACCESS_VALUES.has(value as NonNullable<SnapshotOperation["access"]>)
    ? value as NonNullable<SnapshotOperation["access"]>
    : INVALID;
}
function optionalStrings(value: unknown): string[] | undefined | Invalid {
  return value === undefined ? undefined : stringArray(value) ?? INVALID;
}
function charge(budget: Budget, depth: number): boolean {
  budget.nodes += 1;
  return budget.nodes <= MAX_NODES && depth <= MAX_DEPTH;
}
function cloneArray(value: unknown[], depth: number, budget: Budget): Cloned {
  const items = denseArray(value);
  if (items === undefined) return INVALID;
  const output = items.map((item) => cloneJson(item, depth + 1, budget));
  return output.some((item) => item === INVALID) ? INVALID : Object.freeze(output);
}
function cloneRecord(value: Record<string, unknown>, depth: number, budget: Budget): Cloned {
  if (!plainRecord(value)) return INVALID;
  const entries = dataEntries(value);
  if (entries === undefined) return INVALID;
  const output = entries.map(([key, item]) => [key, cloneJson(item, depth + 1, budget)] as const);
  return output.some(([, item]) => item === INVALID)
    ? INVALID
    : Object.freeze(Object.fromEntries(output));
}
/** Bounded JSON clone; accessors and non-plain sources never reach a read. */
function cloneJson(value: unknown, depth: number, budget: Budget): Cloned {
  if (!charge(budget, depth)) return INVALID;
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") return value.length <= MAX_TEXT ? value : INVALID;
  if (typeof value === "number") return Number.isFinite(value) ? value : INVALID;
  if (typeof value !== "object") return INVALID;
  if (Array.isArray(value)) return cloneArray(value, depth, budget);
  return cloneRecord(value as Record<string, unknown>, depth, budget);
}
function recordSnapshot(value: unknown, budget: Budget): Record<string, unknown> | undefined | Invalid {
  if (value === undefined) return undefined;
  const cloned = cloneJson(value, 0, budget);
  return cloned !== INVALID && plainRecord(cloned) ? cloned : INVALID;
}
/** Exactly one source: valid user messages, or a transcript only when absent. */
function authoritySnapshot(source: Record<string, unknown>): AuthoritySnapshot | Invalid {
  const transcript = optionalText(source.transcript);
  if (transcript === INVALID) return INVALID;
  const messages = source.userMessages;
  if (messages === undefined)
    return transcript === undefined || transcript.trim().length === 0 ? INVALID : { transcript };
  const values = stringArray(messages);
  if (values === undefined) return INVALID;
  if (!values.some((message) => message.trim().length > 0)) return INVALID;
  return { userMessages: values };
}

function pathSnapshot(source: Record<string, unknown>): PathSnapshot | Invalid {
  const projectDir = optionalText(source.projectDir);
  const worktreeRoot = optionalText(source.worktreeRoot);
  if (projectDir === INVALID || worktreeRoot === INVALID) return INVALID;
  return definedFields({ projectDir, worktreeRoot });
}

function operationFields(raw: Record<string, unknown>, budget: Budget): ParsedOperation | Invalid {
  const tool = optionalText(raw.tool);
  const access = accessValue(raw.access);
  const targets = optionalStrings(raw.targets);
  const args = recordSnapshot(raw.arguments, budget);
  const correlated = optionalBoolean(raw.correlated);
  if (tool === INVALID || access === INVALID || targets === INVALID || args === INVALID || correlated === INVALID)
    return INVALID;
  if (typeof raw.complete !== "boolean") return INVALID;
  return { complete: raw.complete, correlated, tool, access, targets, args };
}

function freezeOperation(fields: ParsedOperation): SnapshotOperation {
  const targets = fields.targets === undefined
    ? undefined
    : Object.freeze(fields.targets) as readonly string[];
  return Object.freeze(definedFields({
    complete: fields.complete,
    correlated: fields.correlated,
    tool: fields.tool,
    access: fields.access,
    targets,
    arguments: fields.args,
  })) as SnapshotOperation;
}

function operationSnapshot(value: unknown, budget: Budget): SnapshotOperation | undefined | Invalid {
  if (value === undefined) return undefined;
  if (!plainRecord(value)) return INVALID;
  const entries = dataEntries(value);
  if (entries === undefined) return INVALID;
  const fields = operationFields(Object.fromEntries(entries), budget);
  return fields === INVALID ? INVALID : freezeOperation(fields);
}

function staticAnalysisSnapshot(value: unknown, budget: Budget):
  FactReviewSnapshot["staticAnalysis"] | Invalid {
  const raw = recordSnapshot(value, budget);
  if (raw === undefined || raw === INVALID) return raw;
  if (typeof raw.band !== "string" || typeof raw.reason !== "string") return INVALID;
  if (raw.findings === undefined) return Object.freeze({ band: raw.band, reason: raw.reason });
  const findings = stringArray(raw.findings);
  return findings === undefined
    ? INVALID
    : Object.freeze({ band: raw.band, reason: raw.reason, findings });
}

function gitStateSnapshot(value: unknown, budget: Budget): FactReviewSnapshot["gitState"] | Invalid {
  const raw = recordSnapshot(value, budget);
  if (raw === undefined || raw === INVALID) return raw;
  const texts = GIT_TEXT_KEYS.map((key) => optionalText(raw[key]));
  if (texts.some((item) => item === INVALID)) return INVALID;
  const clean = optionalBoolean(raw.clean);
  if (clean === INVALID) return INVALID;
  const [branch, defaultBranch, upstream] = texts as (string | undefined)[];
  return Object.freeze(definedFields({ branch, defaultBranch, upstream, clean }));
}

/** `echo %TOKEN%` is literal in POSIX shells but expands in cmd.exe, so the
 * requested dialect is safety evidence and must survive the snapshot. */
function shellSnapshot(value: unknown, budget: Budget): FactReviewSnapshot["shell"] | Invalid {
  const raw = recordSnapshot(value, budget);
  if (raw === undefined || raw === INVALID) return raw;
  const platform = optionalText(raw.platform);
  const interpreter = optionalText(raw.interpreter);
  if (platform === INVALID || interpreter === INVALID) return INVALID;
  return Object.freeze(definedFields({ platform, interpreter }));
}

function scopeSnapshot(value: unknown): "unknown" | undefined | Invalid {
  if (value === undefined) return undefined;
  return value === "unknown" ? "unknown" : INVALID;
}

function editBindingSnapshot(source: Record<string, unknown>, budget: Budget): EditBinding | Invalid {
  const binding: EditBinding = {};
  const rawPayload = source.editPayload;
  if (rawPayload !== undefined) {
    if (!plainRecord(rawPayload) || dataEntries(rawPayload) === undefined) return INVALID;
    const payload = verifyCapturedEdit(rawPayload);
    if (payload === undefined || !Object.isFrozen(payload)) return INVALID;
    binding.editPayload = payload;
  }
  const rawExpected = source.expectedEditCapture;
  if (rawExpected !== undefined) {
    const cloned = cloneJson(rawExpected, 0, budget);
    const expected = cloned === INVALID ? undefined : readEditCapture(cloned);
    if (expected === undefined) return INVALID;
    binding.expectedEditCapture = expected;
  }
  return binding;
}

function requestBase(source: Record<string, unknown>): { action: string; resources: string[] } | Invalid {
  if (typeof source.action !== "string") return INVALID;
  const resources = stringArray(source.resources);
  return resources === undefined ? INVALID : { action: source.action, resources };
}

function basicContext(source: Record<string, unknown>, budget: Budget): ContextSnapshot | Invalid {
  const path = pathSnapshot(source);
  if (path === INVALID) return INVALID;
  const authority = authoritySnapshot(source);
  if (authority === INVALID) return INVALID;
  const delegations = optionalStrings(source.delegations);
  if (delegations === INVALID) return INVALID;
  const shell = shellSnapshot(source.shell, budget);
  if (shell === INVALID) return INVALID;
  const analysis = staticAnalysisSnapshot(source.staticAnalysis, budget);
  if (analysis === INVALID) return INVALID;
  return definedFields({ ...path, ...authority, delegations, shell, staticAnalysis: analysis });
}

function extendedContext(source: Record<string, unknown>, budget: Budget): ContextSnapshot | Invalid {
  const git = gitStateSnapshot(source.gitState, budget);
  if (git === INVALID) return INVALID;
  const scope = scopeSnapshot(source.scopeResolution);
  if (scope === INVALID) return INVALID;
  const operation = operationSnapshot(source.operation, budget);
  if (operation === INVALID) return INVALID;
  const edits = editBindingSnapshot(source, budget);
  if (edits === INVALID) return INVALID;
  return definedFields({ ...edits, gitState: git, scopeResolution: scope, operation });
}

function contextSnapshot(source: Record<string, unknown>, budget: Budget): ContextSnapshot | Invalid {
  const basic = basicContext(source, budget);
  if (basic === INVALID) return INVALID;
  const extended = extendedContext(source, budget);
  return extended === INVALID ? INVALID : { ...basic, ...extended };
}

function snapshotFields(source: Record<string, unknown>, budget: Budget): FactReviewSnapshotResult {
  const base = requestBase(source);
  if (base === INVALID) return failed("Fact review request shape is invalid");
  const context = contextSnapshot(source, budget);
  return context === INVALID
    ? failed("Fact review request context is invalid")
    : { ok: true, snapshot: Object.freeze({ ...base, ...context }) };
}

function buildSnapshot(raw: unknown): FactReviewSnapshotResult {
  if (!plainRecord(raw)) return failed("Fact review request is not a plain object");
  const entries = dataEntries(raw);
  return entries === undefined
    ? failed("Fact review request contains accessor properties")
    : snapshotFields(Object.fromEntries(entries), { nodes: 0 });
}

/** Snapshots once; no raw request value is read after this returns. */
export function snapshotFactReviewRequest(raw: unknown): FactReviewSnapshotResult {
  try {
    return buildSnapshot(raw);
  } catch {
    return failed("Fact review request could not be snapshotted");
  }
}
