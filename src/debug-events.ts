import * as fs from "node:fs";
import * as path from "node:path";

/** Unsafe debugging only: payloads are original and may contain secrets. */
export interface DebugEvent {
  ts: string;
  type: string;
  payload: unknown;
  [key: string]: unknown;
}

export interface JsonlOptions {
  path: string;
  /** Zero disables rotation. Rotated files are retained, never overwritten. */
  maxBytes: number;
}
export type DebugLogSetting = JsonlOptions | undefined;
export interface EventLog { readonly sinkPath: string; write(event: DebugEvent): void }
export interface JsonlLog { write(value: unknown): void }

interface DebugVisitState { issues: string[]; ancestors: Set<object> }

function isJsonPrimitive(item: unknown): item is string | number | boolean {
  if (typeof item === "string" || typeof item === "boolean") return true;
  return typeof item === "number" && Number.isFinite(item);
}

/** Object keys plus Error's non-enumerable identity fields. */
function serializableKeys(item: object): Set<string> {
  const keys = new Set(Object.keys(item));
  if (item instanceof Error) {
    for (const key of ["name", "message", "stack", ...Object.getOwnPropertyNames(item)]) keys.add(key);
  }
  return keys;
}

function visitCollection(item: object, location: string, state: DebugVisitState): unknown {
  if (item instanceof Date) return item.toISOString();
  if (Array.isArray(item)) return Array.from(item, (entry, index) => visitDebugValue(entry, `${location}[${index}]`, state));
  if (item instanceof Map) {
    state.issues.push(`${location}: Map represented as entries`);
    return { serializationError: "Map", entries: Array.from(item, ([key, entry], index) => [visitDebugValue(key, `${location}.keys[${index}]`, state), visitDebugValue(entry, `${location}.values[${index}]`, state)]) };
  }
  if (item instanceof Set) {
    state.issues.push(`${location}: Set represented as values`);
    return { serializationError: "Set", values: Array.from(item, (entry, index) => visitDebugValue(entry, `${location}[${index}]`, state)) };
  }
  const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of serializableKeys(item)) {
    try { result[key] = visitDebugValue((item as Record<string, unknown>)[key], `${location}.${key}`, state); }
    catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      state.issues.push(`${location}.${key}: ${message}`);
      result[key] = { serializationError: message };
    }
  }
  for (const key of Object.getOwnPropertySymbols(item)) {
    state.issues.push(`${location}: symbol key ${String(key)} is not JSON-compatible`);
  }
  return result;
}

function visitDebugValue(item: unknown, location: string, state: DebugVisitState): unknown {
  if (item === null || isJsonPrimitive(item)) return item;
  if (typeof item !== "object") {
    state.issues.push(`${location}: ${typeof item} is not JSON-compatible`);
    return { serializationError: typeof item, value: String(item) };
  }
  if (state.ancestors.has(item)) {
    state.issues.push(`${location}: circular reference`);
    return { serializationError: "circular reference" };
  }
  state.ancestors.add(item);
  try { return visitCollection(item, location, state); }
  finally { state.ancestors.delete(item); }
}

function withSerializationIssues(payload: unknown, issues: string[]): unknown {
  if (payload && typeof payload === "object" && !Array.isArray(payload)) {
    // Keep the normal event/decision shape available to replay tools.
    const original = Object.hasOwn(payload, "serializationError")
      ? { originalSerializationError: (payload as Record<string, unknown>).serializationError } : {};
    return { ...payload, ...original, serializationError: issues };
  }
  return { payload, serializationError: issues };
}

/** Preserve JSON data without redaction or bounds; explicitly report non-JSON values. */
export function serializeDebugValue(value: unknown): string {
  const state: DebugVisitState = { issues: [], ancestors: new Set() };
  try {
    const payload = visitDebugValue(value, "$", state);
    if (state.issues.length === 0) return JSON.stringify(payload);
    return JSON.stringify(withSerializationIssues(payload, state.issues));
  } catch (error) {
    return JSON.stringify({ serializationError: error instanceof Error ? error.message : String(error) });
  }
}

/** Opens the sink for append, rejecting FIFOs/devices before the write can block indefinitely. */
function openRegularFileForAppend(file: string): number {
  const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_APPEND | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK, 0o600);
  if (fs.fstatSync(fd).isFile()) return fd;
  fs.closeSync(fd);
  throw new Error("Refusing to write to a non-regular file");
}

/** Opt-in, local-only, best-effort sink. Rotation is controlled by the caller. */
export function createJsonlLog(setting: DebugLogSetting): JsonlLog | undefined {
  if (!setting) return undefined;
  const { path: file, maxBytes } = setting;
  if (!file || !Number.isFinite(maxBytes) || maxBytes < 0) return undefined;
  return {
    write(value) {
      let fd: number | undefined;
      try {
        const line = `${serializeDebugValue(value)}\n`;
        fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
        try {
          const stat = fs.lstatSync(file);
          const size = stat.size;
          if (stat.isFile() && maxBytes > 0 && size > 0 && size + Buffer.byteLength(line) > maxBytes) {
            let sequence = 1;
            while (fs.existsSync(`${file}.${sequence}`)) sequence++;
            // Exclusive link creation prevents a racing writer from replacing an archive.
            fs.linkSync(file, `${file}.${sequence}`);
            fs.unlinkSync(file);
          }
        } catch { /* No file yet, or rotation unavailable: append rather than lose the event. */ }
        fd = openRegularFileForAppend(file);
        fs.fchmodSync(fd, 0o600);
        fs.writeFileSync(fd, line);
      } catch { /* Audit I/O must never fail a permission or tool request. */ }
      finally {
        if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* Best effort. */ } }
      }
    },
  };
}

export function createEventLog(setting: DebugLogSetting): EventLog | undefined {
  const log = createJsonlLog(setting);
  if (!log || setting === undefined) return undefined;
  return { sinkPath: canonicalSinkPath(setting.path), write: log.write };
}

/** Resolve existing ancestors too, so aliases agree before the log is created. */
function canonicalSinkPath(file: string): string {
  let parent = path.resolve(file);
  const suffix: string[] = [];
  for (;;) {
    try { return path.join(fs.realpathSync(parent), ...suffix); }
    catch {
      const next = path.dirname(parent);
      if (next === parent) return path.resolve(file);
      suffix.unshift(path.basename(parent));
      parent = next;
    }
  }
}

type CaptureMember = { unavailable: boolean; start(signal: AbortSignal, isOwner: () => boolean, handoff: boolean, markFailure: () => void): void };
type CaptureEntry = { members: Set<CaptureMember>; owner?: CaptureMember; controller?: AbortController };
const captureRegistryKey = Symbol.for("opencode-auto-mode.debug-capture.v2");
const legacyCaptureRegistryKey = Symbol.for("opencode-auto-mode.debug-capture.v1");
type LegacyCaptureEntry = { members: Set<unknown>; owner?: unknown; controller?: AbortController };
type CaptureGlobals = typeof globalThis & {
  [captureRegistryKey]?: Map<string, CaptureEntry>;
  [legacyCaptureRegistryKey]?: Map<string, LegacyCaptureEntry>;
};

/** Retire v1 state without migrating stale callbacks; returns whether it existed. */
function retireLegacyCapture(shared: CaptureGlobals): boolean {
  const legacy = shared[legacyCaptureRegistryKey];
  if (legacy === undefined) return false;
  // v1 callbacks do not implement failure handoff. Never migrate their stale closures.
  // Detach every owner before aborting: abort listeners can register synchronously.
  const controllers: AbortController[] = [];
  for (const entry of legacy.values()) {
    entry.owner = undefined;
    if (entry.controller) controllers.push(entry.controller);
    entry.controller = undefined;
    entry.members.clear();
  }
  legacy.clear();
  delete shared[legacyCaptureRegistryKey];
  for (const controller of controllers) controller.abort();
  return true;
}

/** Offer ownership to one member; a failed subscription marks it ineligible and retries. */
function activateCaptureMember(group: CaptureEntry, member: CaptureMember, handoff: boolean, retry: () => void): void {
  const controller = new AbortController();
  group.owner = member;
  group.controller = controller;
  const markFailure = () => {
    if (group.owner !== member || controller.signal.aborted) return;
    member.unavailable = true;
    group.owner = undefined;
    group.controller = undefined;
    controller.abort();
    retry();
  };
  try { member.start(controller.signal, () => group.owner === member && !controller.signal.aborted, handoff, markFailure); }
  catch { markFailure(); }
}

/** One server-global subscriber per sink in this JS process, including module reloads.
 * No machine lock or payload deduplication: different processes remain independent.
 */
export function registerGlobalCapture(sinkPath: string, start: CaptureMember["start"]): () => void {
  const shared = globalThis as CaptureGlobals;
  const retiredLegacy = retireLegacyCapture(shared);
  const registry = shared[captureRegistryKey] ??= new Map<string, CaptureEntry>();
  let entry = registry.get(sinkPath);
  if (!entry) { entry = { members: new Set() }; registry.set(sinkPath, entry); }
  const group = entry;
  const member: CaptureMember = { start, unavailable: false };
  group.members.add(member);
  let promoting = false;
  const promote = (handoff: boolean) => {
    if (promoting) return;
    promoting = true;
    try {
      // Failed members stay ineligible until unloaded. Each registration gets one attempt,
      // even when subscribe throws synchronously or every existing stream is already closed.
      while (!group.owner) {
        const next = [...group.members].find((candidate) => !candidate.unavailable);
        if (!next) break;
        activateCaptureMember(group, next, handoff, () => promote(true));
        handoff = true;
      }
    } finally { promoting = false; }
  };
  if (!group.owner) promote(retiredLegacy || group.members.size > 1);
  let disposed = false;
  return () => {
    if (disposed) return;
    disposed = true;
    group.members.delete(member);
    if (group.owner === member) {
      group.owner = undefined;
      const controller = group.controller;
      group.controller = undefined;
      controller?.abort();
      promote(true);
    }
    if (group.members.size === 0) {
      registry.delete(sinkPath);
      if (registry.size === 0) delete shared[captureRegistryKey];
    }
  };
}
