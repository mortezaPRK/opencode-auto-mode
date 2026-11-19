import { dirname, isAbsolute, normalize, resolve } from "node:path";
import { redactCredentialSyntax, redactHttpBodies } from "./audit.js";
import { isRecord } from "./guards.js";
import { resolvePhysicalPath } from "./path-policy.js";
import type { OperationAccess, OperationEvidence } from "./reviewer.js";

export type { OperationAccess, OperationEvidence } from "./reviewer.js";

/** Exact built-in names only. MCP tool names never imply a capability here. */
const TOOL_ACCESS: Readonly<Record<string, OperationAccess>> = {
  read: "read",
  list: "read",
  ls: "read",
  glob: "read",
  grep: "read",
  todoread: "read",
  skill: "read",
  // Network tools are egress even when they only fetch; access stays unknown
  // so a predicate cannot treat them as local read-only capability.
  webfetch: "unknown",
  websearch: "unknown",
  codesearch: "unknown",
  edit: "write",
  write: "write",
  patch: "write",
  multiedit: "write",
  apply_patch: "write",
  todowrite: "write",
  shell: "execute",
  bash: "execute",
  execute: "execute",
  question: "unknown",
  task: "unknown",
  lsp: "unknown",
  doom_loop: "unknown",
};
const KNOWN_TOOLS = new Set([...Object.keys(TOOL_ACCESS), "external_directory"]);
const WRITE_TOOLS = new Set(["edit", "write", "patch", "multiedit", "apply_patch"]);
const PAYLOAD_TOOLS = new Set(["edit", "write", "patch", "multiedit", "apply_patch"]);
const FILE_TOOLS = new Set(["read", "list", "ls", "edit", "write", "patch", "multiedit", "apply_patch"]);
const SEARCH_TOOLS = new Set(["glob", "grep"]);
const SHELL_TOOLS = new Set(["shell", "bash"]);

/** Only arguments that describe the operation identity or target. File contents,
 * edit replacements and Code Mode source are never duplicated. */
const SELECTED_ARGUMENTS: Readonly<Record<string, readonly string[]>> = {
  read: ["filePath", "path", "offset", "limit"],
  edit: ["filePath", "path", "replaceAll"],
  write: ["filePath", "path"],
  patch: ["filePath", "path"],
  multiedit: ["filePath", "path"],
  apply_patch: ["filePath", "path"],
  glob: ["pattern", "path", "root"],
  grep: ["pattern", "path", "root", "include"],
  list: ["path"],
  ls: ["path"],
  shell: ["command", "workdir", "cwd", "directory"],
  bash: ["command", "workdir", "cwd", "directory"],
  webfetch: ["url", "format"],
  websearch: ["query"],
  codesearch: ["query"],
  execute: [],
};

const MAX_TARGETS = 32;
const MAX_TARGET_CHARS = 2048;
const MAX_TOOL_CHARS = 256;
const MAX_KEY_CHARS = 128;
const MAX_ARGUMENT_DEPTH = 4;
const MAX_ARGUMENT_NODES = 256;
const MAX_ARGUMENT_KEYS = 64;
const MAX_ARRAY_ITEMS = 32;
const MAX_STRING_CHARS = 2048;
const MAX_TOTAL_ARGUMENT_CHARS = 8192;
const MAX_CAPTURE_ENTRIES = 64;
const MAX_IDENTITY_CHARS = 512;
const REDACTED = "[REDACTED]";
const TRUNCATED = "[TRUNCATED]";
const UNSERIALIZABLE = "[UNSERIALIZABLE]";
const HOME_PREFIX = /^(?:~|\$HOME)(?:[\\/]|$)/;
const INVALID_PATH = /^(?:undefined|null)$/i;
/** Scheme and protocol-relative spellings are network arguments, not paths. */
const NETWORK_TARGET = /^(?:[a-z][a-z0-9+.-]*:\/\/|\/\/[^/])/i;
const PARENT_SEGMENT = /(?:^|[\\/])\.\.(?:[\\/]|$)/;

function usableTarget(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0 && !INVALID_PATH.test(value.trim());
}

const SENSITIVE_KEY = /^(?:authorization|proxy[_-]?authorization|auth|cookie|cookies|set[_-]?cookie|header|headers|body|payload|content|contents|data|password|passwd|secret|secrets|token|access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|apikey|private[_-]?key|client[_-]?secret|credential|credentials|env|environment|session[_-]?key)$/i;
const SENSITIVE_FRAGMENT = /(?:^|[_-])(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|credential)(?:$|[_-])/i;
/** Arbitrary MCP payload keys: redact the value and mark the operation incomplete,
 * while common search/query fields remain legitimate literal evidence. */
const PAYLOAD_KEY = /^(?:document|documents|documenttext|text|file|files|filecontent|filecontents|patch|patches|patchtext|diff|diffs|edit|edits|change|changes|newcontent|oldcontent|newtext|oldtext|newstring|oldstring|selection)$/i;

export interface OperationEvent {
  action: string;
  resources: readonly string[];
  metadata?: Record<string, unknown>;
  sessionID?: string;
}

export interface CapturedToolInput {
  readonly tool: string;
  readonly arguments: Record<string, unknown>;
  readonly complete: boolean;
}

export interface OperationEvidenceOptions {
  projectDir?: string;
  capture?: CapturedToolInput;
}

export interface ToolInputStore {
  /** Snapshot bounded, sanitized input immediately; never retain the live host object. */
  capture(event: { sessionID: string; messageID: string; id: string; tool: string; input: unknown }): void;
  get(source: unknown, sessionID: string): CapturedToolInput | undefined;
  release(event: { sessionID: string; messageID?: string; id?: string }): void;
  releaseSource(source: unknown, sessionID: string): void;
  clear(): void;
}

interface SanitizeState {
  nodes: number;
  chars: number;
  incomplete: boolean;
  seen: WeakSet<object>;
}

interface SelectedArguments {
  arguments?: Record<string, unknown>;
  complete: boolean;
}

const state = (): SanitizeState => ({ nodes: 0, chars: 0, incomplete: false, seen: new WeakSet() });

function sensitiveKey(key: string): boolean {
  return SENSITIVE_KEY.test(key) || SENSITIVE_FRAGMENT.test(key) || PAYLOAD_KEY.test(key);
}

function takeCharacters(target: SanitizeState, length: number): boolean {
  if (target.chars + length > MAX_TOTAL_ARGUMENT_CHARS) {
    target.incomplete = true;
    return false;
  }
  target.chars += length;
  return true;
}

/** Every retained string is screened for inline HTTP bodies and recognized
 * credential syntax before it can reach a model prompt. */
function redactRetained(value: string): string {
  return redactCredentialSyntax(redactHttpBodies(value));
}

function boundedString(value: string, target: SanitizeState): string {
  const length = Math.min(value.length, MAX_STRING_CHARS);
  if (length < value.length) target.incomplete = true;
  if (!takeCharacters(target, length)) return TRUNCATED;
  const bounded = value.slice(0, length);
  // Every retained string is screened, not just a built-in shell `command`:
  // unknown/MCP arguments can carry the same inline HTTP body or credentials.
  const redacted = redactRetained(bounded);
  if (redacted !== bounded) target.incomplete = true;
  return redacted;
}

function sanitizeArray(value: readonly unknown[], depth: number, target: SanitizeState): unknown[] {
  if (value.length > MAX_ARRAY_ITEMS) target.incomplete = true;
  return value.slice(0, MAX_ARRAY_ITEMS).map((item) => sanitizeValue(item, depth + 1, target));
}

/** Enumerates keys without reading values, so oversized inputs cannot charge
 * synchronous work for properties that the key bound discards. */
function boundedKeys(value: object, target: SanitizeState): string[] {
  const keys: string[] = [];
  for (const key in value) {
    if (!Object.hasOwn(value, key)) continue;
    if (keys.length === MAX_ARGUMENT_KEYS) {
      target.incomplete = true;
      break;
    }
    keys.push(key);
  }
  return keys;
}

function sanitizeObject(value: object, depth: number, target: SanitizeState): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const key of boundedKeys(value, target)) {
    if (["__proto__", "constructor", "prototype"].includes(key)) {
      target.incomplete = true;
      continue;
    }
    if (key.length > MAX_KEY_CHARS || !takeCharacters(target, key.length)) {
      target.incomplete = true;
      continue;
    }
    if (sensitiveKey(key)) {
      target.incomplete = true;
      result[key] = REDACTED;
      continue;
    }
    result[key] = sanitizeValue((value as Record<string, unknown>)[key], depth + 1, target);
  }
  return result;
}

function sanitizePrimitive(value: unknown, target: SanitizeState): { handled: boolean; value?: unknown } {
  if (value === null || typeof value === "boolean") return { handled: true, value };
  if (typeof value === "number") {
    if (Number.isFinite(value)) return { handled: true, value };
    target.incomplete = true;
    return { handled: true, value: UNSERIALIZABLE };
  }
  if (typeof value === "string") return { handled: true, value: boundedString(value, target) };
  if (typeof value === "object") return { handled: false };
  target.incomplete = true;
  return { handled: true, value: UNSERIALIZABLE };
}

function sanitizeValue(value: unknown, depth: number, target: SanitizeState): unknown {
  target.nodes += 1;
  if (target.nodes > MAX_ARGUMENT_NODES || depth > MAX_ARGUMENT_DEPTH) {
    target.incomplete = true;
    return TRUNCATED;
  }
  const primitive = sanitizePrimitive(value, target);
  if (primitive.handled) return primitive.value;
  if (target.seen.has(value as object)) {
    target.incomplete = true;
    return "[CIRCULAR]";
  }
  target.seen.add(value as object);
  try {
    return Array.isArray(value) ? sanitizeArray(value, depth, target) : sanitizeObject(value as object, depth, target);
  } finally {
    target.seen.delete(value as object);
  }
}

function sanitizeArguments(input: unknown): SelectedArguments {
  if (!isRecord(input)) return { complete: false };
  const target = state();
  try {
    return { arguments: sanitizeObject(input, 0, target), complete: !target.incomplete };
  } catch {
    return { complete: false };
  }
}

function selectArguments(tool: string, input: unknown): SelectedArguments {
  const fields = SELECTED_ARGUMENTS[tool];
  if (fields === undefined) return input === undefined ? { arguments: {}, complete: true } : sanitizeArguments(input);
  if (input === undefined) return { arguments: {}, complete: true };
  if (!isRecord(input)) return tool === "execute" ? { arguments: {}, complete: true } : { complete: false };
  const target = state();
  const result: Record<string, unknown> = {};
  try {
    for (const field of fields) {
      if (!Object.hasOwn(input, field) || input[field] === undefined) continue;
      result[field] = sanitizeValue(input[field], 0, target);
    }
    return { arguments: result, complete: !target.incomplete };
  } catch {
    return { complete: false };
  }
}

function mergeArguments(left: Record<string, unknown> | undefined, right: Record<string, unknown> | undefined): SelectedArguments {
  if (left === undefined && right === undefined) return { complete: true };
  const merged: Record<string, unknown> = { ...left };
  let complete = true;
  for (const [key, value] of Object.entries(right ?? {})) {
    if (Object.hasOwn(merged, key) && JSON.stringify(merged[key]) !== JSON.stringify(value)) complete = false;
    merged[key] = value;
  }
  return { arguments: Object.keys(merged).length === 0 ? undefined : merged, complete };
}

function metadataRecord(metadata: unknown): { value?: Record<string, unknown>; invalid: boolean } {
  if (metadata === undefined) return { invalid: false };
  if (!isRecord(metadata)) return { invalid: true };
  return { value: metadata, invalid: false };
}

function boundedTool(value: string | undefined): { tool?: string; complete: boolean } {
  if (value === undefined) return { complete: true };
  if (value.length === 0 || value.length > MAX_TOOL_CHARS) return { tool: value.slice(0, MAX_TOOL_CHARS), complete: false };
  return { tool: value, complete: true };
}

interface ResolvedTarget {
  target: string;
  complete: boolean;
}

function resolvedSpelling(value: string, projectDir: string | undefined): string {
  if (isAbsolute(value)) return normalize(value);
  if (projectDir !== undefined && isAbsolute(projectDir)) return resolve(projectDir, value);
  return normalize(value);
}

/** Network spellings keep their identity for the scorer's URL filter. A `..`
 * traversal is resolved physically rather than collapsed, so a symlink before
 * it cannot reassign the target; unresolvable traversal keeps the raw spelling. */
function resolveTarget(value: string, projectDir: string | undefined): ResolvedTarget {
  if (NETWORK_TARGET.test(value)) return { target: value, complete: true };
  if (HOME_PREFIX.test(value)) return { target: PARENT_SEGMENT.test(value) ? value : normalize(value), complete: false };
  if (!PARENT_SEGMENT.test(value)) return { target: resolvedSpelling(value, projectDir), complete: true };
  const resolved = resolvePhysicalPath(value, projectDir ?? process.cwd());
  return resolved === undefined ? { target: value, complete: false } : { target: resolved, complete: true };
}

function limitTargets(values: readonly string[], transform: (value: string) => ResolvedTarget): { targets?: string[]; complete: boolean } {
  const targets: string[] = [];
  let complete = values.length <= MAX_TARGETS;
  for (const value of values.slice(0, MAX_TARGETS)) {
    if (!usableTarget(value)) {
      complete = false;
      continue;
    }
    if (HOME_PREFIX.test(value)) complete = false;
    const resolved = transform(value);
    if (!resolved.complete) complete = false;
    if (resolved.target.length > MAX_TARGET_CHARS) complete = false;
    const redacted = redactRetained(resolved.target);
    if (redacted !== resolved.target) complete = false;
    const target = redacted.slice(0, MAX_TARGET_CHARS);
    if (!targets.includes(target)) targets.push(target);
  }
  return { targets: targets.length === 0 ? undefined : targets, complete };
}

function boundedTargets(values: readonly string[], projectDir?: string): { targets?: string[]; complete: boolean } {
  return limitTargets(values, (value) => resolveTarget(value, projectDir));
}

function rawTargets(values: readonly string[]): { targets?: string[]; complete: boolean } {
  return limitTargets(values, (value) => ({ target: value, complete: true }));
}

function stringArgument(args: Record<string, unknown> | undefined, key: string): string | undefined {
  const value = args?.[key];
  return usableTarget(value) ? value : undefined;
}

function metadataPath(value: unknown, projectDir?: string): string | undefined {
  return usableTarget(value) ? resolveTarget(value, projectDir).target : undefined;
}

function capturedExactTargets(args: Record<string, unknown> | undefined, projectDir?: string): string[] {
  return targetValues(args, EXACT_TARGET_KEYS).map((value) => resolveTarget(value, projectDir).target);
}

function externalTargetConflict(metadata: Record<string, unknown> | undefined, args: Record<string, unknown> | undefined,
  projectDir?: string): boolean {
  const captured = capturedExactTargets(args, projectDir);
  if (new Set(captured).size > 1) return true;
  const exact = metadataPath(metadata?.filepath, projectDir);
  if (exact !== undefined && captured.length > 0 && captured[0] !== exact) return true;
  const parent = metadataPath(metadata?.parentDir, projectDir);
  if (parent !== undefined && captured.length === 1 && dirname(captured[0]!) !== parent) return true;
  return false;
}

function permissionCovers(pattern: string, target: string): boolean {
  if (pattern === "*" || HOME_PREFIX.test(pattern)) return false;
  const normalized = normalize(pattern);
  const starSuffix = normalized.endsWith("/**") ? "/**" : normalized.endsWith("/*") ? "/*" : undefined;
  if (starSuffix !== undefined) {
    const root = normalized.slice(0, -starSuffix.length);
    return target === root || target.startsWith(`${root}/`);
  }
  if (normalized.includes("*") || normalized.includes("?")) return false;
  return target === normalized || target.startsWith(`${normalized}/`);
}

function externalScopeContained(resources: readonly string[], metadata: Record<string, unknown> | undefined,
  args: Record<string, unknown> | undefined, projectDir?: string): boolean {
  const exact = [metadataPath(metadata?.filepath, projectDir), ...capturedExactTargets(args, projectDir)]
    .filter((value): value is string => value !== undefined);
  if (exact.length === 0) return false;
  return exact.every((target) => !HOME_PREFIX.test(target) &&
    resources.some((pattern) => permissionCovers(pattern, target)));
}

function searchTarget(args: Record<string, unknown> | undefined, projectDir?: string): { targets?: string[]; complete: boolean } {
  const path = stringArgument(args, "path");
  const root = stringArgument(args, "root");
  const selected = path ?? root;
  // The host may default to the session directory, but that default is not
  // evidence of the actual search scope. Only an explicit path or root proves it.
  if (selected === undefined) return { complete: false };
  return boundedTargets([selected], projectDir);
}

const WORKDIR_KEYS = ["workdir", "cwd", "directory"] as const;

function workdirTargets(args: Record<string, unknown> | undefined, projectDir?: string): { targets?: string[]; complete: boolean } {
  const raw = WORKDIR_KEYS.map((key) => args?.[key]).filter((value): value is string => typeof value === "string" && value.length > 0);
  if (raw.length === 0) return { complete: true };
  const valid = raw.filter(usableTarget);
  if (valid.length === 0) return { complete: false };
  return boundedTargets(valid, projectDir);
}

function operationTargets(action: string, resources: readonly string[], args: Record<string, unknown> | undefined, projectDir?: string):
  { targets?: string[]; complete: boolean } {
  if (SEARCH_TOOLS.has(action)) return searchTarget(args, projectDir);
  if (SHELL_TOOLS.has(action)) return workdirTargets(args, projectDir);
  // Network/query resources are not filesystem operation targets; URL/query
  // evidence remains in arguments and the untouched permission resources.
  if (FILE_TOOLS.has(action)) return rawTargets(resources);
  return { complete: true };
}

function toolMatchesAction(action: string, tool: string): boolean {
  if (action === "edit" || action === "write") return WRITE_TOOLS.has(tool);
  if (action === "shell") return tool === "shell" || tool === "bash";
  if (action === "list") return tool === "list" || tool === "ls";
  return action === tool;
}

function composeOperation(tool: string | undefined, access: OperationAccess, targets: string[] | undefined,
  args: Record<string, unknown> | undefined, complete: boolean): OperationEvidence {
  return {
    ...(tool === undefined ? {} : { tool }),
    access,
    ...(targets === undefined ? {} : { targets }),
    ...(args === undefined ? {} : { arguments: args }),
    complete,
  };
}

function allComplete(checks: readonly boolean[]): boolean {
  return checks.every(Boolean);
}

function capturedArguments(action: string, capture: CapturedToolInput | undefined): Record<string, unknown> | undefined {
  return capture !== undefined && toolMatchesAction(action, capture.tool) ? capture.arguments : undefined;
}

function knownEvidence(event: OperationEvent, metadata: Record<string, unknown> | undefined, metadataInvalid: boolean,
  options: OperationEvidenceOptions): OperationEvidence {
  const selected = selectArguments(event.action, metadata);
  const capture = options.capture;
  const compatible = capture === undefined || toolMatchesAction(event.action, capture.tool);
  const merged = mergeArguments(selected.arguments, capturedArguments(event.action, capture));
  const tool = boundedTool(compatible ? capture?.tool ?? event.action : event.action);
  const targets = operationTargets(event.action, event.resources, merged.arguments, options.projectDir);
  const checks = [!metadataInvalid, selected.complete, tool.complete, targets.complete, merged.complete, !PAYLOAD_TOOLS.has(event.action)];
  if (capture !== undefined) checks.push(compatible, capture.complete);
  return composeOperation(tool.tool, TOOL_ACCESS[event.action] ?? "unknown", targets.targets, merged.arguments, allComplete(checks));
}

function unknownCompleteness(input: unknown, metadataInvalid: boolean, nested: SelectedArguments, merged: SelectedArguments,
  capture: CapturedToolInput | undefined, action: string): boolean {
  if (input === undefined) return capture !== undefined && capture.tool === action && capture.complete;
  const captureComplete = capture === undefined || (capture.tool === action && capture.complete);
  return allComplete([!metadataInvalid, nested.complete, merged.complete, captureComplete]);
}

function unknownArguments(metadata: Record<string, unknown> | undefined, metadataInvalid: boolean, capture: CapturedToolInput | undefined,
  action: string): { arguments?: Record<string, unknown>; mismatch: boolean; complete: boolean } {
  const input = metadata?.input;
  const nested = input === undefined ? { complete: false } : sanitizeArguments(input);
  const compatible = capture !== undefined && capture.tool === action;
  const merged = mergeArguments(nested.arguments, compatible ? capture?.arguments : undefined);
  return {
    arguments: merged.arguments,
    mismatch: capture !== undefined && !compatible,
    complete: unknownCompleteness(input, metadataInvalid, nested, merged, capture, action),
  };
}

function unknownEvidence(event: OperationEvent, metadata: Record<string, unknown> | undefined, metadataInvalid: boolean,
  options: OperationEvidenceOptions): OperationEvidence {
  const selected = unknownArguments(metadata, metadataInvalid, options.capture, event.action);
  const tool = boundedTool(options.capture?.tool === event.action ? options.capture.tool : event.action);
  return composeOperation(tool.tool, "unknown", undefined, selected.arguments,
    !selected.mismatch && tool.complete && selected.complete);
}

const METADATA_TARGET_KEYS = ["filepath", "parentDir"] as const;
const ARGUMENT_TARGET_KEYS = ["filePath", "path", "filepath", "root", "directory", "workdir", "cwd"] as const;
const EXACT_TARGET_KEYS = ["filePath", "filepath", "path"] as const;

function targetValues(record: Record<string, unknown> | undefined, keys: readonly string[]): string[] {
  return keys.map((key) => record?.[key]).filter(usableTarget);
}

function actualTargets(metadata: Record<string, unknown> | undefined, args: Record<string, unknown> | undefined,
  projectDir?: string): { targets?: string[]; complete: boolean } {
  return boundedTargets([...targetValues(metadata, METADATA_TARGET_KEYS), ...targetValues(args, ARGUMENT_TARGET_KEYS)], projectDir);
}

function hasExactTargets(metadata: Record<string, unknown> | undefined, args: Record<string, unknown> | undefined): boolean {
  return targetValues(metadata, ["filepath"]).length > 0 || targetValues(args, EXACT_TARGET_KEYS).length > 0;
}

function externalTargets(capture: CapturedToolInput | undefined, conflict: boolean, metadata: Record<string, unknown> | undefined,
  args: Record<string, unknown> | undefined, projectDir?: string): { targets?: string[]; complete: boolean } {
  if (capture === undefined || conflict) return { targets: undefined, complete: true };
  return actualTargets(metadata, args, projectDir);
}

function accessForTool(tool: string | undefined): OperationAccess {
  return tool === undefined ? "unknown" : TOOL_ACCESS[tool] ?? "unknown";
}

function externalEvidence(event: OperationEvent, metadata: Record<string, unknown> | undefined, metadataInvalid: boolean,
  options: OperationEvidenceOptions): OperationEvidence {
  const capture = options.capture;
  const nested = metadata?.input === undefined ? { complete: true } : sanitizeArguments(metadata.input);
  const merged = mergeArguments(nested.arguments, capture?.arguments);
  const tool = boundedTool(capture?.tool);
  const conflict = externalTargetConflict(metadata, merged.arguments, options.projectDir) ||
    !externalScopeContained(event.resources, metadata, merged.arguments, options.projectDir);
  const targets = externalTargets(capture, conflict, metadata, merged.arguments, options.projectDir);
  const shellWithoutExact = (tool.tool === "shell" || tool.tool === "bash") && !hasExactTargets(metadata, merged.arguments);
  const checks = [!metadataInvalid, capture !== undefined, capture?.complete === true, nested.complete,
    tool.complete, targets.complete, targets.targets !== undefined, merged.complete, !conflict, !shellWithoutExact];
  return composeOperation(tool.tool, accessForTool(tool.tool), targets.targets, merged.arguments, allComplete(checks));
}

/** Selects bounded evidence from untrusted metadata and one exact captured call;
 * never throws and never reads the live host input. */
export function buildOperationEvidence(event: OperationEvent, options: OperationEvidenceOptions = {}): OperationEvidence {
  try {
    const metadata = metadataRecord(event.metadata);
    if (event.action === "external_directory") return externalEvidence(event, metadata.value, metadata.invalid, options);
    if (KNOWN_TOOLS.has(event.action)) return knownEvidence(event, metadata.value, metadata.invalid, options);
    return unknownEvidence(event, metadata.value, metadata.invalid, options);
  } catch {
    return { access: "unknown", complete: false };
  }
}

function validIdentity(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= MAX_IDENTITY_CHARS;
}

function identityKey(sessionID: unknown, messageID: unknown, id: unknown): string | undefined {
  if (!validIdentity(sessionID) || !validIdentity(messageID) || !validIdentity(id)) return undefined;
  return JSON.stringify([sessionID, messageID, id]);
}

function sourceKey(source: unknown, sessionID: unknown): string | undefined {
  if (!isRecord(source) || source.type !== "tool") return undefined;
  return identityKey(sessionID, source.messageID, source.id);
}

interface TrackedCapture {
  value: CapturedToolInput;
  active: number;
}

function releaseTracked(entries: Map<string, TrackedCapture>, key: string | undefined): void {
  if (key === undefined) return;
  const tracked = entries.get(key);
  if (tracked === undefined) return;
  tracked.active -= 1;
  if (tracked.active <= 0) entries.delete(key);
}

/** Process-local, bounded, exact-call input snapshots. The SDK has no
 * tool.execute.error hook; execute.after covers completion and failures that reach
 * it. Entries are evicted oldest-first, so a missed cleanup cannot grow without
 * bound. Outer Code Mode `execute` captures are never stored. */
export function createToolInputStore(maxEntries = MAX_CAPTURE_ENTRIES): ToolInputStore {
  const entries = new Map<string, TrackedCapture>();
  const requested = Number.isFinite(maxEntries) ? Math.floor(maxEntries) : MAX_CAPTURE_ENTRIES;
  const limit = Math.max(1, Math.min(requested, MAX_CAPTURE_ENTRIES));
  return {
    capture(event) {
      if (event.tool === "execute") return;
      const key = identityKey(event.sessionID, event.messageID, event.id);
      if (key === undefined) return;
      const tracked = entries.get(key);
      if (tracked !== undefined) {
        tracked.active += 1;
        tracked.value = { tool: tracked.value.tool, arguments: {}, complete: false };
        return;
      }
      const selected = event.input === undefined && !KNOWN_TOOLS.has(event.tool)
        ? { complete: false }
        : selectArguments(event.tool, event.input);
      const tool = boundedTool(event.tool);
      entries.set(key, {
        active: 1,
        value: {
          tool: tool.tool ?? event.tool.slice(0, MAX_TOOL_CHARS),
          arguments: selected.arguments ?? {},
          complete: tool.complete && selected.complete,
        },
      });
      while (entries.size > limit) entries.delete(entries.keys().next().value as string);
    },
    get(source, sessionID) {
      const key = sourceKey(source, sessionID);
      return key === undefined ? undefined : entries.get(key)?.value;
    },
    release(event) {
      releaseTracked(entries, identityKey(event.sessionID, event.messageID, event.id));
    },
    releaseSource(source, sessionID) {
      releaseTracked(entries, sourceKey(source, sessionID));
    },
    clear() {
      entries.clear();
    },
  };
}
