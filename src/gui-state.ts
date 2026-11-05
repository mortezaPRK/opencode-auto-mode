import { MAX_SESSION_ID_CHARS, type AutoModeAction, type AutoModeStatus } from "./rpc.js";

export interface StatusTarget {
  /** Server, session and location fingerprint. */
  key: string;
  sessionID: string;
  ownServer: boolean;
  location: { directory: string; workspaceID?: string };
}

export interface RoutedSession {
  readonly key: string;
  readonly id: string;
  readonly server: { readonly builtin: boolean };
  readonly location: { readonly directory: string; readonly workspaceID?: string } | undefined;
}

/** Shared location fingerprint for routed sessions and server targets. */
export function statusLocationKey(serverKey: string, location: { directory: string; workspaceID?: string }): string {
  return JSON.stringify([serverKey, location.directory, location.workspaceID]);
}

/** Unknown locations must not accidentally query the server's default location. */
export function statusTarget(session: RoutedSession | undefined): StatusTarget | undefined {
  if (session?.location === undefined || !session.id || session.id.length > MAX_SESSION_ID_CHARS || !session.location.directory) return undefined;
  return {
    key: statusLocationKey(session.key, session.location),
    sessionID: session.id,
    ownServer: session.server.builtin,
    location: { ...session.location },
  };
}

export type StatusSource = (target: StatusTarget, signal: AbortSignal) => Promise<AutoModeStatus | undefined>;
export interface StatusLoader {
  (target: StatusTarget | undefined): Promise<void>;
  invalidate(): void;
  dispose(): void;
}

const UNAVAILABLE: AutoModeStatus = {
  enabled: false, mode: "invalid", configError: "status unavailable", errorKind: "status",
  reviewTimeoutMs: 0, reviewing: [], counts: { allow: 0, ask: 0, deny: 0 },
};

const DEFAULT_REQUEST_TIMEOUT_MS = 5_000;

interface AbortableRequest<T> { abort(): void; done: Promise<T> }

/**
 * One deferred, abortable request: timeout, caller abort and disposal reject
 * alike, and the timer is always cleared. Deferral keeps synchronous transport
 * errors on that same cleanup path.
 */
function startAbortableRequest<T>(
  timeoutMs: number,
  abortMessage: string,
  work: (signal: AbortSignal) => Promise<T>,
): AbortableRequest<T> {
  const controller = new AbortController();
  const aborted = new Promise<never>((_, reject) => {
    controller.signal.addEventListener("abort", () => reject(new Error(abortMessage)), { once: true });
  });
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const request = Promise.resolve().then(() => {
    if (controller.signal.aborted) throw new Error(abortMessage);
    return work(controller.signal);
  });
  return {
    abort: () => controller.abort(),
    done: Promise.race([request, aborted]).finally(() => clearTimeout(timer)),
  };
}

/**
 * One abortable request at a time. Selection changes, timeout and disposal
 * cancel it; tokens prevent late replies even if a transport ignores abort.
 * Failed requests immediately replace stale successful status with unavailable.
 */
export function createStatusLoader(
  load: StatusSource,
  apply: (next: AutoModeStatus | undefined, target?: StatusTarget) => void,
  timeoutMs = DEFAULT_REQUEST_TIMEOUT_MS,
): StatusLoader {
  let selected: string | undefined;
  let pending: { request: AbortableRequest<AutoModeStatus | undefined>; done: Promise<void> } | undefined;
  let generation = 0;
  let disposed = false;
  const cancelPending = () => {
    pending?.request.abort();
    pending = undefined;
  };

  const refresh: StatusLoader = Object.assign((target: StatusTarget | undefined): Promise<void> => {
    if (disposed) return Promise.resolve();
    if (selected !== target?.key) {
      selected = target?.key;
      generation++;
      cancelPending();
      apply(undefined);
    }
    if (target === undefined || !target.ownServer) return Promise.resolve();
    if (pending !== undefined) return pending.done;
    const token = generation;
    const request = startAbortableRequest(timeoutMs, "status request aborted", (signal) => load(target, signal));
    const done = request.done.then(
      (next) => { if (!disposed && token === generation) apply(next ?? { ...UNAVAILABLE }, target); },
      () => { if (!disposed && token === generation) apply({ ...UNAVAILABLE }, target); },
    ).finally(() => {
      if (pending?.request === request) pending = undefined;
    });
    pending = { request, done };
    return done;
  }, {
    invalidate() {
      generation++;
      cancelPending();
    },
    dispose() {
      disposed = true;
      generation++;
      cancelPending();
    },
  });
  return refresh;
}

export type ModeSource = (target: StatusTarget, mode: AutoModeAction, signal: AbortSignal) => Promise<AutoModeStatus>;

/** Coalesce repeated clicks per captured session/location; never toggle from stale state. */
export function createModeRunner(
  change: ModeSource,
  apply: (target: StatusTarget, status: AutoModeStatus) => void,
  failure: () => void,
  changed: () => void = () => {},
  timeoutMs = DEFAULT_REQUEST_TIMEOUT_MS,
) {
  const pending = new Map<string, { request: AbortableRequest<AutoModeStatus>; done: Promise<void> }>();
  let disposed = false;
  const limit = Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : DEFAULT_REQUEST_TIMEOUT_MS;
  return {
    pending: (target: StatusTarget) => pending.has(target.key),
    run(target: StatusTarget | undefined, mode: AutoModeAction | undefined): Promise<void> {
      if (disposed || target === undefined || !target.ownServer || mode === undefined) return Promise.resolve();
      const existing = pending.get(target.key);
      if (existing) return existing.done;
      const request = startAbortableRequest(limit, "mode change aborted", (signal) => change(target, mode, signal));
      const done = request.done.then((next) => {
        if (!disposed && next !== undefined) apply(target, next);
      }, () => { if (!disposed) failure(); }).finally(() => {
        if (pending.get(target.key)?.request === request) pending.delete(target.key);
        if (!disposed) changed();
      });
      pending.set(target.key, { request, done });
      changed();
      return done;
    },
    dispose() {
      disposed = true;
      for (const entry of pending.values()) entry.request.abort();
      pending.clear();
    },
  };
}

/** Invalid/unavailable status cannot enable automatic approval. */
export function pillAction(status: AutoModeStatus | undefined): AutoModeAction | undefined {
  switch (status?.mode) {
    case "on": return status.enabled ? "off" : "on";
    case "off": return "on";
    case "paused": return "resume";
    default: return undefined;
  }
}

export function pillLabel(status: AutoModeStatus | undefined): string | undefined {
  if (status === undefined) return undefined;
  switch (status.mode) {
    case "invalid":
      if (status.errorKind === "status" || (status.errorKind === undefined && status.configError === "status unavailable")) return "status unavailable";
      return status.errorKind === "config" ? "Invalid config — review disabled" : "Review unavailable";
    case "paused": return "paused (breaker)";
    case "off": return "off";
    case "on": return status.enabled ? "auto" : "off";
  }
}

/** Invalid configuration must show its bounded error, not a generic on/off pill. */
export function pillDescription(status: AutoModeStatus | undefined): string | undefined {
  if (status?.mode !== "invalid" || status.configError === undefined || status.configError === "status unavailable") return undefined;
  return `${pillLabel(status)}: ${status.configError}`;
}

export function pillTone(status: AutoModeStatus | undefined): "success" | "warning" | "danger" | undefined {
  if (status === undefined) return undefined;
  if (status.mode === "invalid") return "danger";
  if (status.mode === "paused") return "warning";
  return status.mode === "on" && status.enabled ? "success" : undefined;
}

export interface DecisionEvent {
  location: { directory: string; workspaceID?: string };
  data: unknown;
}
export interface ModeNotice {
  message: string;
  kind: "deny" | "breaker";
}

/** No replay/history, raw reasons, saved-approval nags, or unbounded dedup state. */
export function createDecisionNotifier(
  target: () => StatusTarget | undefined,
  show: (notice: ModeNotice) => void,
  now: () => number = Date.now,
): (event: DecisionEvent) => void {
  const seen = new Set<string>();
  let windowStart = 0;
  let shown = 0;
  return (event) => {
    const current = target();
    if (current === undefined || !current.ownServer || event.location.directory !== current.location.directory
      || event.location.workspaceID !== current.location.workspaceID) return;
    if (event.data === null || typeof event.data !== "object") return;
    const data = event.data as Record<string, unknown>;
    if (data.sessionID !== current.sessionID || typeof data.reviewID !== "string" || data.reviewID.length > 256) return;
    const kind = data.stage === "breaker" ? "breaker" : data.decision === "deny" ? "deny" : undefined;
    if (kind === undefined) return;
    const key = JSON.stringify([current.key, data.reviewID, kind]);
    if (seen.has(key)) return;
    seen.add(key);
    if (seen.size > 128) seen.delete(seen.values().next().value!);
    const at = now();
    if (at - windowStart >= 5_000) { windowStart = at; shown = 0; }
    // Cap bursts of deny toasts, but never suppress a new breaker trip.
    if (kind === "deny" && shown >= 4) return;
    shown++;
    show({ kind, message: kind === "breaker" ? "Auto mode paused (breaker)" : "Auto mode denied" });
  };
}

/** One live subscription, rebound when the host replaces its client. */
export function createDecisionSubscription(
  receive: (event: DecisionEvent) => void,
): {
  update(client: object, subscribe: (receive: (event: DecisionEvent) => void, signal: AbortSignal) => () => void): void;
  dispose(): void;
} {
  let current: object | undefined;
  let controller: AbortController | undefined;
  let stop: (() => void) | undefined;
  let disposed = false;
  const disconnect = () => { controller?.abort(); stop?.(); controller = undefined; stop = undefined; };
  return {
    update(client, subscribe) {
      if (disposed || client === current) return;
      disconnect();
      current = client;
      const next = new AbortController();
      controller = next;
      try {
        stop = subscribe((event) => { if (!next.signal.aborted) receive(event); }, next.signal);
      } catch {
        disconnect();
        current = undefined; // Retry at the next poll if the server is unavailable.
      }
    },
    dispose() { disposed = true; disconnect(); current = undefined; },
  };
}
