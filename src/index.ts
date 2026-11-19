import { randomUUID } from "node:crypto";
import { Plugin } from "@opencode/plugin";
import type { Agent } from "@opencode/schema/agent";
import type { Session } from "@opencode/schema/session";
import { DEFAULT_AUDIT_MAX_BYTES, DEFAULT_REVIEW_TIMEOUT_MS, parseOptions, type ClassifierOptions } from "./config.js";
import { reviewRequest, type PermissionRequest, type ReviewResult } from "./reviewer.js";
import { decisionStage } from "./decision.js";
import { runClassifiers } from "./classifier.js";
import { permissionContext } from "./permission-context.js";
import { scoreRequest } from "./score.js";
import { loadGlobalOptions } from "./global-options.js";
import { getWorktreeScope } from "./worktree.js";
import { createAuditLog, defaultAuditPath, type AuditLog } from "./audit.js";
import { createEventLog, registerGlobalCapture, type EventLog } from "./debug-events.js";
import { createModeStore, type FinishDisposition, type FinishOutcome, type ModeState } from "./mode.js";
import { AutoMode, MAX_SESSION_ID_CHARS, type AutoModeDecision, type AutoModeErrorKind, type AutoModeMode, type AutoModeStatus } from "./rpc.js";
import { createStatusTracker, type StatusTracker } from "./status.js";
import { withTimeout } from "./timeout.js";
import { errorKindOf, EvidenceFailure, ReviewFailure } from "./errors.js";
import { codeModePermission, codeModeReviewResources } from "./code-mode.js";
import { scanResultContent, withInjectionWarning } from "./probe.js";

export type { AutoModeOptions } from "./config.js";
const INTERRUPTED_REASON = "Auto-mode review was interrupted; please decide yourself";
const PAUSED_REASON = "Auto mode is paused; please decide yourself";
const INVALID_CONFIG_ACTION = "Auto-mode review is disabled because its configuration is invalid";
const NATIVE_DENY_REASON = "Native permission deny";
const REVIEW_ACTIONS = /^(?:read|edit|write|glob|grep|shell|execute|webfetch|websearch|question|todowrite|skill)$/;
const SAFER_ALTERNATIVE = "Continue with a safer alternative.";
function denialMessage(reason: string): string {
  const trimmed = reason.trim().replace(/[\s.]+$/, "");
  if (trimmed.endsWith(SAFER_ALTERNATIVE.slice(0, -1))) return `${trimmed}.`;
  return trimmed ? `${trimmed}. ${SAFER_ALTERNATIVE}` : SAFER_ALTERNATIVE;
}

type SetupContext = Parameters<Parameters<typeof Plugin.define>[0]["setup"]>[0];
type PluginOptions = ReturnType<typeof parseOptions>;
type ModeStore = ReturnType<typeof createModeStore>;
type RpcHandle = {
  readonly events: { readonly emit: (name: "decision", data: Readonly<Record<string, unknown>>) => Promise<void> };
  dispose(): Promise<void>;
};
type PermissionEvent = Parameters<Parameters<SetupContext["permission"]["hook"]>[1]>[0];
type Score = ReturnType<typeof scoreRequest>;
type Correlation = { reviewID?: string; sessionID?: string; callID?: string; stageIndex?: number };
type Debug = (type: string, data: unknown, correlation?: Correlation) => void;
type Observe = <T>(type: string, input: unknown, work: () => Promise<T>, correlation?: Correlation) => Promise<T>;
type Sdk = <T>(type: string, input: unknown, work: () => Promise<T>, signal?: AbortSignal, correlation?: Correlation) => Promise<T>;

interface Infrastructure {
  ctx: SetupContext;
  options: PluginOptions | undefined;
  configError: string | undefined;
  valid: boolean;
  reviewTimeoutMs: number;
  audit: AuditLog | undefined;
  events: EventLog | undefined;
  instanceID: string;
  debug: Debug;
  observe: Observe;
  sdk: Sdk;
  modes: ModeStore;
}

interface SessionSurface {
  status: StatusTracker;
  running: Map<string, Set<AbortController>>;
  suspended: Set<string>;
  subscriptions: AbortController;
  lifecycle: { stopping: boolean };
  abortSession: (sessionID: string) => void;
  publish: (payload: Record<string, unknown>) => void;
  snapshot: (sessionID?: string) => Promise<AutoModeStatus>;
  setSessionMode: (sessionID: string, mode: "on" | "off", commandSession?: boolean) => Promise<AutoModeStatus>;
  rpc: RpcHandle | undefined;
  nextReviewID: () => number;
}

interface Runtime extends Infrastructure, SessionSurface {
  releaseCapture: (() => void) | undefined;
}

export default Plugin.define({
  id: "opencode-auto-mode",
  setup: async (ctx) => {
    const runtime = await createRuntime(ctx);
    const registrations: { dispose(): unknown }[] = [];
    const cleanup = async () => {
      abandonRuntime(runtime);
      await Promise.allSettled([runtime.rpc, ...registrations].map(async (registration) => registration?.dispose()));
    };
    try { await registerHooks(runtime, registrations); }
    catch (error) { await cleanup(); throw error; }
    return cleanup;
  },
});

/** Plugin setup is staged so each step stays small: parse options and sinks,
 * build the session surface, then register host hooks in their original order. */
async function createRuntime(ctx: SetupContext): Promise<Runtime> {
  const infra = createInfrastructure(ctx);
  const surface = await createSessionSurface(ctx, infra);
  const releaseCapture = startCapture(ctx, infra);
  return { ...infra, ...surface, releaseCapture };
}

function createInfrastructure(ctx: SetupContext): Infrastructure {
  const { options, configError } = loadPluginOptions(ctx.location.directory);
  const valid = options !== undefined;
  const reviewTimeoutMs = options?.reviewTimeoutMs ?? DEFAULT_REVIEW_TIMEOUT_MS;
  const auditSetting = auditSettingFor(options);
  const audit = createAuditLog(auditSetting);
  const events = createEventLog(auditSetting);
  if (events) console.warn("Auto-mode debug logging is unsafe: full prompts, outputs and events may contain secrets. Local audit logging is enabled without redaction.");
  const instanceID = randomUUID();
  const sourceLocation = structuredClone(ctx.location);
  const { debug, observe, sdk } = createObservability(events, instanceID, sourceLocation, reviewTimeoutMs);
  const modes = createModeStore(ctx.storage, async (sessionID) => {
    const info = await observe("session.get", { sessionID }, () => withTimeout(ctx.session.get({ sessionID }), reviewTimeoutMs), { sessionID });
    return info.parentID;
  });
  if (events) debug("configuration", { options, valid, configError, reviewTimeoutMs, captureScope: "SDK-exposed events and observed plugin calls only; invisible host activity is not captured" });
  return { ctx, options, configError, valid, reviewTimeoutMs, audit, events, instanceID, debug, observe, sdk, modes };
}

function loadPluginOptions(directory: string): { options?: PluginOptions; configError?: string } {
  try { return { options: parseOptions(loadGlobalOptions(directory)) }; }
  catch (error) { return { configError: error instanceof Error ? error.message : "Invalid auto-mode configuration" }; }
}

function auditSettingFor(options: PluginOptions | undefined) {
  const auditConfig = options?.audit;
  return auditConfig?.enabled === true
    ? { path: defaultAuditPath(), maxBytes: auditConfig.maxBytes ?? DEFAULT_AUDIT_MAX_BYTES }
    : undefined;
}

function createObservability(events: EventLog | undefined, instanceID: string, sourceLocation: SetupContext["location"], reviewTimeoutMs: number) {
  let callCounter = 0;
  const debug: Debug = (type, data, correlation = {}) => {
    // Local-only, deliberately unredacted. Never forward this data through RPC.
    if (!events) return;
    try { events.write({ ts: new Date().toISOString(), type, instanceID, sourceLocation, ...correlation, payload: data }); } catch { /* best effort */ }
  };
  const observe: Observe = async (type, input, work, correlation = {}) => {
    const envelope = { ...correlation, callID: `call-${instanceID}-${callCounter++}` };
    debug(`${type}.before`, input, envelope);
    try { const result = await work(); debug(`${type}.after`, result, envelope); return result; }
    catch (error) { debug(`${type}.error`, error, envelope); throw error; }
  };
  /** Bounded, observed SDK call: every host/provider lookup shares one deadline shape. */
  const sdk: Sdk = (type, input, work, signal, correlation = {}) =>
    observe(type, input, () => withTimeout(work(), reviewTimeoutMs, signal), correlation);
  return { debug, observe, sdk };
}

async function createSessionSurface(ctx: SetupContext, infra: Infrastructure): Promise<SessionSurface> {
  const status = createStatusTracker();
  const running = new Map<string, Set<AbortController>>();
  // A failed off write must not restore automation in this plugin instance.
  const suspended = new Set<string>();
  const subscriptions = new AbortController();
  const lifecycle = { stopping: false };
  let reviewCounter = 0;
  const abortSession = (sessionID: string) => { for (const controller of running.get(sessionID) ?? []) controller.abort(); };
  const publish = (payload: Record<string, unknown>) => {
    try { void Promise.resolve(rpc?.events.emit("decision", payload)).catch(() => {}); } catch { /* best effort */ }
  };
  const snapshot = createSnapshot({
    valid: infra.valid, configError: infra.configError, reviewTimeoutMs: infra.reviewTimeoutMs,
    status, suspended, modes: infra.modes, debug: infra.debug,
  });
  const setSessionMode = createModeSetter({
    ctx, modes: infra.modes, suspended, valid: infra.valid, reviewTimeoutMs: infra.reviewTimeoutMs,
    debug: infra.debug, observe: infra.observe, stopping: () => lifecycle.stopping, snapshot, abortSession,
  });
  const rpc = await registerRpc(ctx, { snapshot, setSessionMode });
  // Cancellation remains local to every loaded instance, independent of audit ownership.
  startInterruptSubscription(ctx, { subscriptions, abortSession, debug: infra.debug });
  return {
    status, running, suspended, subscriptions, lifecycle, abortSession, publish, snapshot, setSessionMode, rpc,
    nextReviewID: () => reviewCounter++,
  };
}

interface SnapshotDeps {
  valid: boolean;
  configError: string | undefined;
  reviewTimeoutMs: number;
  status: StatusTracker;
  suspended: Set<string>;
  modes: ModeStore;
  debug: Debug;
}

function createSnapshot(deps: SnapshotDeps): (sessionID?: string) => Promise<AutoModeStatus> {
  const sessionView = async (sessionID?: string) => {
    let mode: AutoModeMode = deps.valid ? "on" : "invalid";
    let counts = { allow: 0, ask: 0, deny: 0 };
    let error = deps.configError;
    let errorKind: AutoModeErrorKind | undefined = deps.valid ? undefined : "config";
    if (deps.valid && error === undefined && sessionID) {
      try {
        const state = await withTimeout(deps.modes.get(sessionID), deps.reviewTimeoutMs);
        mode = deps.suspended.has(sessionID) ? "off" : state.mode;
        counts = state.counts;
      } catch (cause) {
        deps.debug("status.error", cause, { sessionID });
        mode = "invalid";
        error = "Auto-mode session storage unavailable";
        errorKind = "storage";
      }
    }
    return { mode, counts, breaker: mode === "paused",
      ...(error === undefined ? {} : { configError: error }),
      ...(errorKind === undefined ? {} : { errorKind }) };
  };
  return async (sessionID?: string) => {
    const view = await sessionView(sessionID);
    return deps.status.snapshot({
      enabled: deps.valid && view.mode === "on", mode: view.mode, counts: view.counts, breaker: view.breaker,
      reviewTimeoutMs: deps.reviewTimeoutMs,
      ...(view.configError === undefined ? {} : { configError: view.configError }),
      ...(view.errorKind === undefined ? {} : { errorKind: view.errorKind }),
      ...(sessionID === undefined ? {} : { sessionID }),
    });
  };
}

interface ModeSetterDeps {
  ctx: SetupContext;
  modes: ModeStore;
  suspended: Set<string>;
  valid: boolean;
  reviewTimeoutMs: number;
  debug: Debug;
  observe: Observe;
  stopping: () => boolean;
  snapshot: (sessionID?: string) => Promise<AutoModeStatus>;
  abortSession: (sessionID: string) => void;
}

function createModeSetter(deps: ModeSetterDeps) {
  const modeMutations = new Map<string, number>();
  const assertChange = (sessionID: string, mode: string) => {
    if (!sessionID || !["on", "off"].includes(mode)) throw new Error("Invalid auto-mode change");
    // Invalid configuration can never enable review. An explicit off may
    // still be persisted for when the configuration is repaired.
    if (mode === "on" && !deps.valid) throw new Error("Auto-mode configuration is invalid; review disabled");
  };
  const beginMutation = (sessionID: string, mode: "on" | "off") => {
    const mutation = (modeMutations.get(sessionID) ?? 0) + 1;
    modeMutations.set(sessionID, mutation);
    // Off wins synchronously, before any await: a review already committing must
    // see the latch and an in-flight review is aborted immediately.
    const addedLatch = mode === "off" && !deps.suspended.has(sessionID);
    if (mode === "off") { deps.suspended.add(sessionID); deps.abortSession(sessionID); }
    return { mutation, addedLatch };
  };
  const assertLocation = async (sessionID: string, commandSession: boolean) => {
    const info = await deps.observe("session.get", { sessionID }, () => withTimeout(deps.ctx.session.get({ sessionID }), deps.reviewTimeoutMs), { sessionID });
    const requested = getWorktreeScope(info.location.directory).directory;
    if (!commandSession && requested !== getWorktreeScope(deps.ctx.location.directory).directory)
      throw new Error("Session location does not match this auto-mode instance");
  };
  const commit = async (sessionID: string, mode: "on" | "off", mutation: number) => {
    try {
      await withTimeout(deps.modes.set(sessionID, mode), deps.reviewTimeoutMs);
      if (mode === "on" && modeMutations.get(sessionID) === mutation) deps.suspended.delete(sessionID);
      return deps.snapshot(sessionID);
    } catch (error) { deps.debug("mode.set.error", error, { sessionID }); throw error; }
  };
  return async (sessionID: string, mode: "on" | "off", commandSession = false) => {
    if (deps.stopping()) throw new Error("Auto-mode plugin is stopping");
    assertChange(sessionID, mode);
    const { mutation, addedLatch } = beginMutation(sessionID, mode);
    const revertOff = () => {
      // A failed validation may undo only the latch this request created, and
      // only when no newer request won. A second failed off must not release
      // an earlier fail-safe latch whose write already failed.
      if (addedLatch && modeMutations.get(sessionID) === mutation) deps.suspended.delete(sessionID);
    };
    try { await assertLocation(sessionID, commandSession); }
    catch (error) { revertOff(); throw error; }
    // An older request whose validation finished late must not overwrite a newer mode.
    if (modeMutations.get(sessionID) !== mutation) return deps.snapshot(sessionID);
    return commit(sessionID, mode, mutation);
  };
}

function statusInput(input: unknown): string | undefined {
  if (!input || typeof input !== "object" || Array.isArray(input) || Object.keys(input).some((key) => key !== "sessionID"))
    throw new Error("Invalid auto-mode status request");
  const { sessionID } = input as { sessionID?: unknown };
  if (sessionID !== undefined && (typeof sessionID !== "string" || sessionID.length < 1 || sessionID.length > MAX_SESSION_ID_CHARS))
    throw new Error("Invalid auto-mode status request");
  return sessionID;
}

function registerRpc(
  ctx: SetupContext,
  handlers: {
    snapshot: (sessionID?: string) => Promise<AutoModeStatus>;
    setSessionMode: (sessionID: string, mode: "on" | "off", commandSession?: boolean) => Promise<AutoModeStatus>;
  },
): Promise<RpcHandle | undefined> {
  const register = async () => ctx.rpc.register(AutoMode, {
    status: async (input) => handlers.snapshot(statusInput(input)),
    setMode: async (input) => {
      if (!input || typeof input !== "object" || Array.isArray(input) || Object.keys(input).some((key) => !["sessionID", "mode"].includes(key)))
        throw new Error("Invalid auto-mode change");
      const { sessionID, mode } = input as { sessionID: string; mode: "on" | "off" | "resume" };
      if (typeof sessionID !== "string" || !sessionID || sessionID.length > MAX_SESSION_ID_CHARS || !["on", "off", "resume"].includes(mode)) throw new Error("Invalid auto-mode change");
      return handlers.setSessionMode(sessionID, mode === "resume" ? "on" : mode);
    },
  });
  // RPC is an optional UX surface.
  return register().catch(() => undefined);
}

function startInterruptSubscription(
  ctx: SetupContext,
  deps: { subscriptions: AbortController; abortSession: (sessionID: string) => void; debug: Debug },
): void {
  void (async () => {
    try {
      for await (const event of ctx.event.subscribe({ types: ["session.execution.interrupted"], signal: deps.subscriptions.signal })) {
        deps.abortSession(event.data.sessionID);
      }
    } catch (error) { if (!deps.subscriptions.signal.aborted) deps.debug("interrupt.subscription.error", error); }
  })();
}

function startCapture(ctx: SetupContext, infra: Infrastructure): (() => void) | undefined {
  if (!infra.events) return undefined;
  return registerGlobalCapture(infra.events.sinkPath, (signal, isOwner, handoff, markFailure) => {
    infra.debug(handoff ? "capture.handoff" : "capture.started", {
      scope: "process-wide server-global stream per canonical sink path",
      ...(handoff ? { reason: "Previous owner unloaded, stream failed, or legacy registry retired; potential SDK subscription setup/dispose gap; no replay guarantee" } : {}),
    });
    void captureLoop(ctx, infra, signal, isOwner, markFailure);
  });
}

async function captureLoop(ctx: SetupContext, infra: Infrastructure, signal: AbortSignal, isOwner: () => boolean, markFailure: () => void): Promise<void> {
  try {
    for await (const event of ctx.event.subscribe({ signal })) {
      // A queued event from the retiring subscriber must not duplicate the new owner.
      if (isOwner()) infra.debug("event", event);
    }
    infra.debug(signal.aborted ? "capture.stopped" : "capture.interrupted", { reason: signal.aborted ? "cleanup or ownership transfer" : "Event subscription ended unexpectedly; capture gap; trying eligible standby owners, or waiting for a new registration" });
  } catch (error) {
    if (!signal.aborted) infra.debug("capture.error", error);
    infra.debug(signal.aborted ? "capture.stopped" : "capture.interrupted", { reason: signal.aborted ? "cleanup or ownership transfer" : "Event subscription failed; capture gap; trying eligible standby owners, or waiting for a new registration" });
  } finally {
    if (!signal.aborted) markFailure();
  }
}

function abandonRuntime(runtime: Runtime): void {
  runtime.lifecycle.stopping = true;
  runtime.subscriptions.abort();
  runtime.releaseCapture?.();
  for (const sessionID of runtime.running.keys()) runtime.abortSession(sessionID);
}

async function registerHooks(runtime: Runtime, registrations: { dispose(): unknown }[]): Promise<void> {
  registrations.push(await runtime.ctx.permission.hook("evaluate", createPermissionEvaluate(runtime)));
  registrations.push(await runtime.ctx.tool.hook("execute.before", (event) => executeBeforeHook(event, {
    valid: runtime.valid, stopped: () => runtime.lifecycle.stopping, debug: runtime.debug,
    assert: (input) => runtime.ctx.permission.assert(input),
  })));
  registrations.push(await runtime.ctx.tool.hook("execute.after", (event) => afterToolCall(event, runtime.debug)));
  registrations.push(await runtime.ctx.command.transform((editor) => editor.add({
    name: "auto-mode", description: "Toggle auto mode or show its status", execute: createAutoModeCommand(runtime),
  })));
}

interface ReviewMeta {
  reviewID: string;
  startedAt: number;
  correlation: Correlation;
}

interface HostOriginal {
  effect: PermissionEvent["effect"];
  message: string | undefined;
}

interface ReviewProgress {
  tracked: boolean;
  score: string | undefined;
  tripped: boolean;
  finalDisposition: FinishDisposition;
  hostCancelled: boolean;
  abandoned: boolean;
}

interface ReviewHandle {
  controller: AbortController;
  signal: AbortSignal;
  release: () => void;
}

type WorkOutcome =
  | { kind: "passthrough" }
  | { kind: "cancelled" }
  | { kind: "reviewed"; result: ReviewResult };

type PreparedRequest = { kind: "cancelled" } | { kind: "ready"; request: PermissionRequest };

function decisionPayload(entry: AutoModeDecision, tripped: boolean) {
  return {
    reviewID: entry.reviewID, sessionID: entry.sessionID,
    action: REVIEW_ACTIONS.test(entry.action) ? entry.action : "tool",
    decision: entry.decision, stage: entry.stage,
    // Reviewer reasons can quote sensitive evidence: keep those local.
    reason: tripped ? "Auto mode paused (breaker)" : `Auto-mode decision: ${entry.decision}`,
    durationMs: entry.durationMs, at: entry.at,
    ...(entry.errorKind === undefined ? {} : { errorKind: entry.errorKind }),
  };
}

function nonAborted(signal: AbortSignal): AbortSignal | undefined {
  return signal.aborted ? undefined : signal;
}

function restoreHostMessage(event: PermissionEvent, original: HostOriginal): void {
  if (original.message === undefined) delete event.message;
  else event.message = original.message;
}

function createPermissionEvaluate(deps: Runtime) {
  return async (event: PermissionEvent): Promise<void> => {
    // Invalid configuration acts disabled: the native effect and message are
    // byte-for-byte untouched, with no mode storage, context, model, audit or
    // debug-capture access and no fail-closed ask.
    const settings = deps.options;
    if (!deps.valid || settings === undefined) return;
    const startedAt = Date.now();
    const reviewID = `review-${deps.instanceID}-${startedAt}-${deps.nextReviewID()}`;
    const correlation = { reviewID, sessionID: event.sessionID };
    deps.debug("permission.evaluate.before", event, correlation);
    const original: HostOriginal = { effect: event.effect, message: event.message };
    try {
      await evaluatePermission(deps, event, settings, { reviewID, startedAt, correlation }, original);
    } catch (error) { deps.debug("permission.evaluate.error", error, correlation); throw error; }
    finally { deps.debug("permission.evaluate.after", event, correlation); }
  };
}

async function evaluatePermission(deps: Runtime, event: PermissionEvent, settings: PluginOptions, meta: ReviewMeta, original: HostOriginal): Promise<void> {
  const hostEffect = original.effect;
  // A runtime value outside the permission union is not a native allow,
  // ask or deny. Leave it completely untouched and never enter review.
  if (hostEffect !== "allow" && hostEffect !== "ask" && hostEffect !== "deny") return;
  // A native deny is final: passive local audit only; no state/context/model access.
  if (hostEffect === "deny") { recordNativeDeny(deps, event, meta, original.message); return; }
  const reviewsNativeAllow = hostEffect === "allow";
  // Explicit off wins synchronously over every later unload/failure path.
  if (deps.suspended.has(event.sessionID)) return;
  if (deps.lifecycle.stopping) {
    event.effect = "ask"; event.message = INTERRUPTED_REASON; return;
  }
  const handle = beginReview(deps, event, meta);
  const progress: ReviewProgress = { tracked: false, score: undefined, tripped: false, finalDisposition: "cancelled", hostCancelled: false, abandoned: false };
  // One predicate for host interruption: our own cleanup abort is not one.
  const cancelledNow = () => progress.hostCancelled || deps.lifecycle.stopping || (!progress.abandoned && handle.signal.aborted);
  const proposed = await proposeReview(deps, settings, event, handle, progress, cancelledNow, meta, reviewsNativeAllow);
  if ("early" in proposed) {
    handle.release();
    // Explicit off restores the host effect. Other cancellation/unload
    // paths fail closed to ask.
    finishEarly(deps, event, proposed.early, progress, hostEffect, meta);
    return;
  }
  let result = proposed.result;
  try { result = await settleReview(deps, settings, event, handle, progress, result, hostEffect, original, meta, cancelledNow); }
  finally { handle.release(); }
  recordReview(deps, event, progress, result, hostEffect, reviewsNativeAllow, meta);
}

function recordNativeDeny(deps: Runtime, event: PermissionEvent, meta: ReviewMeta, message: string | undefined): void {
  try {
    deps.audit?.write({ ts: new Date().toISOString(), reviewID: meta.reviewID, sessionID: event.sessionID,
      ...(event.agent === undefined ? {} : { agent: event.agent }),
      action: event.action, resources: [...event.resources], hostEffect: "deny", decision: "deny",
      stage: "native", reason: message ?? NATIVE_DENY_REASON, durationMs: 0 });
  } catch { /* local auditing is best effort */ }
}

function beginReview(deps: Runtime, event: PermissionEvent, meta: ReviewMeta): ReviewHandle {
  const controller = new AbortController();
  const active = deps.running.get(event.sessionID) ?? new Set<AbortController>();
  active.add(controller);
  deps.running.set(event.sessionID, active);
  const release = () => {
    controller.abort();
    active.delete(controller);
    if (active.size === 0) deps.running.delete(event.sessionID);
  };
  deps.debug("review.setup", { options: deps.options, startedAt: meta.startedAt, deadline: meta.startedAt + deps.reviewTimeoutMs, reviewTimeoutMs: deps.reviewTimeoutMs }, meta.correlation);
  return { controller, signal: controller.signal, release };
}

async function proposeReview(
  deps: Runtime, settings: PluginOptions, event: PermissionEvent, handle: ReviewHandle, progress: ReviewProgress,
  cancelledNow: () => boolean, meta: ReviewMeta, reviewsNativeAllow: boolean,
): Promise<{ early: WorkOutcome } | { result: ReviewResult }> {
  try {
    const proposed = await withTimeout(
      reviewWork(deps, settings, event, handle, progress, cancelledNow, meta, reviewsNativeAllow), deps.reviewTimeoutMs, handle.signal);
    if (proposed.kind !== "reviewed") return { early: proposed };
    return { result: proposed.result };
  } catch (error) {
    deps.debug("review.error", error, meta.correlation);
    const category = errorKindOf(error);
    // Capture host cancellation before our own cleanup aborts the controller.
    progress.hostCancelled = handle.signal.aborted || deps.lifecycle.stopping;
    const result: ReviewResult = { decision: "ask", reason: handle.signal.aborted ? INTERRUPTED_REASON : "Auto-mode review failed or timed out; please decide yourself", stage: "error",
      errorKind: handle.signal.aborted ? "cancelled" : category === "timeout" ? "deadline" : category };
    // The total deadline bounds host lookups too. Stop the abandoned work
    // before waiting for the state commit; it must not start another stage.
    progress.abandoned = true;
    handle.controller.abort();
    return { result };
  }
}

async function reviewWork(
  deps: Runtime, settings: PluginOptions, event: PermissionEvent, handle: ReviewHandle, progress: ReviewProgress,
  cancelledNow: () => boolean, meta: ReviewMeta, reviewsNativeAllow: boolean,
): Promise<WorkOutcome> {
  const state = await deps.observe("mode.get", { sessionID: event.sessionID }, () => deps.modes.get(event.sessionID), meta.correlation);
  const gate = modeGate(deps, event, state, reviewsNativeAllow);
  if (gate) return gate;
  if (cancelledNow()) return { kind: "cancelled" };
  deps.status.start(event.sessionID, meta.reviewID, meta.startedAt);
  progress.tracked = true;
  // Reject oversized host payloads without passing raw metadata/source to a model.
  if (Buffer.byteLength(JSON.stringify({ action: event.action, resources: event.resources, metadata: event.metadata, source: event.source })) > 65_536)
    return { kind: "reviewed", result: { decision: "ask", reason: "Request too large for automatic review", stage: "context" } };
  const prepared = await prepareRequest(deps, event, handle, meta);
  if (prepared.kind === "cancelled") return prepared;
  const scored = await deps.observe("score", prepared.request, async () => scoreRequest(prepared.request, settings), meta.correlation);
  progress.score = scored.band;
  const scoreVerdict = scoreOutcome(scored);
  if (scoreVerdict) return scoreVerdict;
  return { kind: "reviewed", result: await runReviewStages(deps, settings, event, prepared, scored, handle, cancelledNow, meta) };
}

function modeGate(deps: Runtime, event: PermissionEvent, state: ModeState, reviewsNativeAllow: boolean): WorkOutcome | undefined {
  // Explicit off and persisted off return control to the native host.
  if (deps.suspended.has(event.sessionID) || state.mode === "off") return { kind: "passthrough" };
  if (state.mode !== "paused") return undefined;
  // A paused breaker asks for host allows. An existing ask already
  // has its native prompt and needs no synthetic counter.
  if (!reviewsNativeAllow) return { kind: "passthrough" };
  return { kind: "reviewed", result: { decision: "ask", reason: PAUSED_REASON, stage: "mode" } };
}

function scoreOutcome(scored: Score): WorkOutcome | undefined {
  if ("ask" in scored && scored.ask) return { kind: "reviewed", result: { decision: "ask", reason: scored.reason, stage: "score" } };
  if (scored.deny) return { kind: "reviewed", result: { decision: "deny", reason: scored.reason, stage: "score" } };
  return undefined;
}

function reviewResourcesFor(event: PermissionEvent): string[] {
  try { return codeModeReviewResources(event) ?? [...event.resources]; }
  catch (error) { throw new ReviewFailure("context", "Code Mode evidence does not match its permission identity", { cause: error }); }
}

function permissionRequestFor(
  event: { action: string; resources: readonly string[]; agent?: string },
  resources: string[],
  facts: Pick<PermissionRequest, "projectDir" | "worktreeRoot" | "scopeResolution" | "gitState">,
): PermissionRequest {
  return { action: event.action, resources, agent: event.agent, ...facts };
}

async function prepareRequest(deps: Runtime, event: PermissionEvent, handle: ReviewHandle, meta: ReviewMeta): Promise<PreparedRequest> {
  const info = await deps.sdk("session.get", { sessionID: event.sessionID }, () => deps.ctx.session.get({ sessionID: event.sessionID }, { signal: handle.signal }), handle.signal, meta.correlation);
  if (handle.signal.aborted) return { kind: "cancelled" };
  // Same-model reviewer identity is intentionally not restricted or warned:
  // the user chooses the reviewer, and this plugin adds no independence gate.
  const facts = await permissionContext(info.location.directory, {
    scope: (directory) => deps.observe("worktree.scope", { directory }, async () => getWorktreeScope(directory), meta.correlation),
    branch: async (directory) => (await deps.sdk("vcs.get", { location: { directory } }, () => deps.ctx.vcs.get({ location: { directory } }, { signal: handle.signal }), handle.signal, meta.correlation)).data.branch,
    status: async (directory) => (await deps.sdk("vcs.status", { location: { directory } }, () => deps.ctx.vcs.status({ location: { directory } }, { signal: handle.signal }), handle.signal, meta.correlation)).data,
  }, handle.signal);
  if (handle.signal.aborted) return { kind: "cancelled" };
  const request = permissionRequestFor(event, reviewResourcesFor(event), facts);
  if (handle.signal.aborted) return { kind: "cancelled" };
  return { kind: "ready", request };
}

async function runReviewStages(
  deps: Runtime, settings: PluginOptions, event: PermissionEvent, prepared: Extract<PreparedRequest, { kind: "ready" }>,
  scored: Score, handle: ReviewHandle, cancelledNow: () => boolean, meta: ReviewMeta,
): Promise<ReviewResult> {
  const { request } = prepared;
  let transcript: Promise<string> | undefined;
  const authorize = async () => {
    if (cancelledNow()) throw new Error(INTERRUPTED_REASON);
    transcript ??= (async () => {
      // Classifier context is user-only; local debug retains the full response.
      const messages = await deps.sdk("session.context", { sessionID: event.sessionID }, () => deps.ctx.session.context({ sessionID: event.sessionID }, { signal: handle.signal }), handle.signal, meta.correlation);
      const users = messages.filter((message) => message.type === "user").map((message) => message.text);
      if (users.length === 0 || users.some((text) => typeof text !== "string") || Buffer.byteLength(users.join("\n")) > 12_000)
        throw new ReviewFailure("context", "User authorization context is unavailable or oversized");
      return (request.userMessages = users).join("\n");
    })().catch(unavailableAuthorization);
    request.transcript = await transcript;
    if (cancelledNow()) throw new Error(INTERRUPTED_REASON);
  };
  // Observe the native stateless generation boundary, including exact prompts,
  // complete raw responses and errors. This wrapper never modifies model input.
  const native = (stageIndex: number) => ({
    experimental: { generate: {
      text: (input: Parameters<typeof deps.ctx.experimental.generate.text>[0], generation: { signal: AbortSignal }) =>
        deps.sdk("generate.text", input, () => deps.ctx.experimental.generate.text(input, generation), generation.signal, { ...meta.correlation, stageIndex }),
      decisions: (input: Parameters<Parameters<typeof decisionStage>[0]["experimental"]["generate"]["decisions"]>[0], generation: { signal: AbortSignal }) =>
        deps.sdk("generate.decisions", input, () => deps.ctx.experimental.generate.decisions(input as Parameters<typeof deps.ctx.experimental.generate.decisions>[0], generation), generation.signal, { ...meta.correlation, stageIndex }),
    } },
  });
  const stageCall = async <T>(stage: ClassifierOptions, work: (stageIndex: number) => Promise<T>) => {
    const stageIndex = settings.classifiers.indexOf(stage);
    const envelope = { ...meta.correlation, stageIndex };
    deps.debug("classifier.start", stage, envelope);
    try { await authorize(); const outcome = await work(stageIndex); deps.debug("classifier.end", outcome, envelope); return outcome; }
    catch (error) { deps.debug("classifier.error", error, envelope); deps.debug("classifier.end", { error }, envelope); throw error; }
  };
  return runClassifiers(settings.classifiers, request, scored, {
    signal: handle.signal,
    decision: (stage) => stageCall(stage, (index) => decisionStage(native(index), stage, request, handle.signal, (error) => deps.debug("classifier.validation.error", error, { ...meta.correlation, stageIndex: index }))),
    llm: (stage) => stageCall(stage, (index) => reviewRequest(native(index), request, stage.model, handle.signal, stage.timeoutMs ?? deps.reviewTimeoutMs, (error) => deps.debug("classifier.validation.error", error, { ...meta.correlation, stageIndex: index }))),
    onResult: (stage, outcome, stageIndex) => {
      if (stage.type === "static") { deps.debug("classifier.start", stage, { ...meta.correlation, stageIndex }); deps.debug("classifier.end", outcome, { ...meta.correlation, stageIndex }); }
      deps.debug("classifier", { stage, outcome }, { ...meta.correlation, stageIndex });
    },
  });
}

async function settleReview(
  deps: Runtime, settings: PluginOptions, event: PermissionEvent, handle: ReviewHandle, progress: ReviewProgress,
  result: ReviewResult, hostEffect: PermissionEvent["effect"], original: HostOriginal, meta: ReviewMeta, cancelledNow: () => boolean,
): Promise<ReviewResult> {
  let finishPromise: Promise<FinishOutcome> | undefined;
  try {
    // Mode/breaker checks and counters commit atomically. Explicit off wins
    // over every stale proposal; interruption and timeouts fail closed ask.
    // The finish commit repairs a cancelled proposal under its own lock.
    finishPromise = deps.modes.finish(event.sessionID, result.decision, settings.breaker,
      cancelledNow, () => deps.suspended.has(event.sessionID));
    // A signal that aborts while storage is committing settles the host
    // promptly as an ask; the durable repair still completes in order.
    const final = await withTimeout(finishPromise, deps.reviewTimeoutMs, nonAborted(handle.signal));
    await applySettled(deps, event, progress, result, final, hostEffect, original, meta, cancelledNow);
    return result;
  } catch (error) {
    deps.debug("mode.finish.error", error, meta.correlation);
    const failed: ReviewResult = { ...result, errorKind: errorKindOf(error) };
    if (deps.suspended.has(event.sessionID)) {
      progress.finalDisposition = "off";
      event.effect = hostEffect;
      restoreHostMessage(event, original);
    } else {
      progress.finalDisposition = "cancelled";
      event.effect = "ask";
      event.message = cancelledNow()
        ? INTERRUPTED_REASON
        : "Auto-mode session storage unavailable; please decide yourself";
    }
    // The host settles promptly on interruption, but a durable commit may
    // still complete later. Repair it under the session queue once known.
    void finishPromise?.then(async (outcome) => {
      if (outcome.disposition === "off" || outcome.commit === undefined) return;
      const off = deps.suspended.has(event.sessionID);
      // A paused/cancelled outcome already counted the ask this path applies.
      if (!off && outcome.disposition !== "enforced") return;
      try { await deps.modes.revertCancelled(event.sessionID, outcome, off ? "off" : "cancelled"); }
      catch (cause) { deps.debug("mode.revert.error", cause, meta.correlation); }
    }).catch(() => {});
    return failed;
  }
}

async function applySettled(
  deps: Runtime, event: PermissionEvent, progress: ReviewProgress, result: ReviewResult,
  final: FinishOutcome, hostEffect: PermissionEvent["effect"], original: HostOriginal, meta: ReviewMeta, cancelledNow: () => boolean,
): Promise<void> {
  const cancelled = cancelledNow();
  const explicitOff = final.disposition === "off" || deps.suspended.has(event.sessionID);
  // The durable commit may have won the race against a cancellation or
  // off observed only after finish resolved. Repair that commit before
  // exposing its counts; explicit off restores the exact pre-review state.
  await repairLateCommit(deps, event, final, cancelled, explicitOff, meta);
  progress.finalDisposition = explicitOff ? "off" : cancelled ? "cancelled" : final.disposition;
  progress.tripped = !cancelled && !explicitOff && final.tripped;
  applyHostEffect(deps, event, final, cancelled, explicitOff, progress.tripped, hostEffect, original, result);
}

async function repairLateCommit(
  deps: Runtime, event: PermissionEvent, final: FinishOutcome, cancelled: boolean, explicitOff: boolean, meta: ReviewMeta,
): Promise<void> {
  if (final.commit === undefined || (!explicitOff && !(cancelled && final.disposition === "enforced"))) return;
  try { await withTimeout(deps.modes.revertCancelled(event.sessionID, final, explicitOff ? "off" : "cancelled"), deps.reviewTimeoutMs); }
  catch (error) { deps.debug("mode.revert.error", error, meta.correlation); }
}

function applyHostEffect(
  deps: Runtime, event: PermissionEvent, final: FinishOutcome, cancelled: boolean, explicitOff: boolean,
  tripped: boolean, hostEffect: PermissionEvent["effect"], original: HostOriginal, result: ReviewResult,
): void {
  // Recheck after storage settles, immediately before touching the host.
  const applied = applyHostDecision(final, cancelled, explicitOff, hostEffect, original, result);
  event.effect = applied.effect;
  if (applied.message === undefined) delete event.message;
  else event.message = applied.message;
  if (tripped) deps.abortSession(event.sessionID);
}

function applyHostDecision(
  final: FinishOutcome, cancelled: boolean, explicitOff: boolean,
  hostEffect: PermissionEvent["effect"], original: HostOriginal, result: ReviewResult,
): { effect: PermissionEvent["effect"]; message: string | undefined } {
  if (explicitOff) return { effect: hostEffect, message: original.message };
  if (cancelled || final.disposition === "cancelled") return { effect: "ask", message: INTERRUPTED_REASON };
  if (final.decision === "deny") return { effect: final.decision, message: denialMessage(result.reason) };
  if (final.disposition === "paused") return hostEffect === "allow"
    ? { effect: final.decision, message: PAUSED_REASON }
    : { effect: final.decision, message: original.message };
  if (final.decision === "allow" && hostEffect === "allow") return { effect: final.decision, message: original.message };
  return { effect: final.decision, message: result.reason };
}

function finishEarly(deps: Runtime, event: PermissionEvent, early: WorkOutcome, progress: ReviewProgress, hostEffect: PermissionEvent["effect"], meta: ReviewMeta): void {
  const off = deps.suspended.has(event.sessionID);
  progress.finalDisposition = off ? "off" : "cancelled";
  if (early.kind === "cancelled" && !off) {
    event.effect = "ask";
    event.message = INTERRUPTED_REASON;
  }
  if (!progress.tracked) return;
  deps.status.finish({ reviewID: meta.reviewID, sessionID: event.sessionID, action: event.action,
    decision: off ? hostEffect : "ask",
    stage: off ? "off" : "cancelled",
    reason: off ? "Auto mode is off; native permission effect preserved" : INTERRUPTED_REASON,
    durationMs: Date.now() - meta.startedAt, at: Date.now() });
}

type ReviewRecord = Omit<AutoModeDecision, "at" | "errorKind"> & {
  ts: string;
  agent?: string;
  resources: string[];
  hostEffect: PermissionEvent["effect"];
  proposedDecision: ReviewResult["decision"];
  reviewedNativeAllow: boolean;
  disposition: FinishDisposition;
  breaker: boolean;
  score?: string;
  appliedMessage?: string;
  errorKind?: ReviewResult["errorKind"];
};

function buildRecord(event: PermissionEvent, progress: ReviewProgress, result: ReviewResult, hostEffect: PermissionEvent["effect"], reviewsNativeAllow: boolean, meta: ReviewMeta): ReviewRecord {
  return {
    ts: new Date().toISOString(), reviewID: meta.reviewID, sessionID: event.sessionID,
    ...(event.agent === undefined ? {} : { agent: event.agent }),
    action: event.action, resources: [...event.resources], hostEffect, decision: event.effect,
    proposedDecision: result.decision, reviewedNativeAllow: reviewsNativeAllow, disposition: progress.finalDisposition,
    breaker: progress.tripped,
    stage: progress.tripped ? "breaker" : result.stage ?? "unknown",
    ...(progress.score === undefined ? {} : { score: progress.score }),
    reason: result.reason, durationMs: Date.now() - meta.startedAt,
    ...(event.message === undefined ? {} : { appliedMessage: event.message }),
    ...(result.errorKind === undefined ? {} : { errorKind: result.errorKind }),
  };
}

function recordReview(deps: Runtime, event: PermissionEvent, progress: ReviewProgress, result: ReviewResult, hostEffect: PermissionEvent["effect"], reviewsNativeAllow: boolean, meta: ReviewMeta): void {
  const record = buildRecord(event, progress, result, hostEffect, reviewsNativeAllow, meta);
  try { deps.audit?.write(record); } catch { /* local auditing is best effort */ }
  if (!progress.tracked) return;
  const entry = deps.status.finish({ ...record, at: Date.now() });
  // Explicit off is a native passthrough, not a plugin decision event.
  if (progress.finalDisposition !== "off") deps.publish(decisionPayload(entry, progress.tripped));
}

interface CommandDeps {
  ctx: SetupContext;
  valid: boolean;
  configError: string | undefined;
  debug: Debug;
  snapshot: (sessionID?: string) => Promise<AutoModeStatus>;
  setSessionMode: (sessionID: string, mode: "on" | "off", commandSession?: boolean) => Promise<AutoModeStatus>;
}

function createAutoModeCommand(deps: CommandDeps) {
  return async ({ sessionID, prompt }: { sessionID: Session.ID; prompt: { text: string } }): Promise<void> => {
    const argument = prompt.text.trim().replace(/^\/?auto-mode\b\s*/, "").trim();
    if (!["", "on", "off", "status"].includes(argument)) {
      await deps.ctx.session.synthetic({ sessionID, text: "Usage: /auto-mode [on|off|status]" });
      return;
    }
    try {
      if (argument !== "status") await changeMode(deps, sessionID, argument);
      await reportStatus(deps, sessionID);
    } catch (error) {
      deps.debug("command.error", error, { sessionID });
      await deps.ctx.session.synthetic({ sessionID, text: "Could not change auto mode; check /auto-mode status." });
    }
  };
}

async function changeMode(deps: CommandDeps, sessionID: string, argument: string): Promise<void> {
  const current = argument ? undefined : await deps.snapshot(sessionID);
  const target = argument || (current?.mode === "on" ? "off" : "on");
  if (!deps.valid && target === "on") {
    const detail = deps.configError ?? "invalid configuration";
    await deps.ctx.session.synthetic({ sessionID, text: `${INVALID_CONFIG_ACTION}: ${detail}` });
    return;
  }
  await deps.setSessionMode(sessionID, target as "on" | "off", true);
}

async function reportStatus(deps: CommandDeps, sessionID: string): Promise<void> {
  const now = await deps.snapshot(sessionID);
  const detail = now.mode === "invalid" && now.configError !== undefined
    ? now.errorKind === "config" ? ` Review disabled: ${now.configError}` : ` ${now.configError}`
    : "";
  await deps.ctx.session.synthetic({ sessionID, text: `Auto mode: ${now.mode}. Reviewing: ${now.reviewing.length}. Today: ${now.counts.allow} allow, ${now.counts.ask} ask, ${now.counts.deny} deny. Breaker: ${now.breaker ? "paused" : "ready"}.${detail}` });
}

function unavailableAuthorization(error: unknown): never {
  throw new EvidenceFailure("User authorization evidence is unavailable", { cause: error });
}

interface ToolHookEvent {
  tool: string;
  sessionID: Session.ID;
  agent: Agent.ID;
  messageID: string;
  id: string;
  input: unknown;
}

type ToolAssert = (input: {
  sessionID: Session.ID;
  agent?: Agent.ID;
  action: "execute";
  resources: string[];
  save: string[];
  metadata: Record<string, unknown>;
  source: { type: "tool"; messageID: string; id: string };
}) => Promise<void>;

interface ToolHookDeps {
  valid: boolean;
  stopped: () => boolean;
  debug: (type: string, data: unknown) => void;
  assert: ToolAssert;
}

function executeBeforeHook(event: ToolHookEvent, deps: ToolHookDeps): Promise<void> {
  deps.debug("tool.execute.before", event);
  return executeToolCall(event, deps);
}

async function executeToolCall(event: ToolHookEvent, deps: ToolHookDeps): Promise<void> {
  try {
    if (event.tool !== "execute") return;
    // Invalid configuration leaves native execute behavior byte-for-byte untouched.
    if (!deps.valid) return;
    if (deps.stopped()) throw new Error(INTERRUPTED_REASON);
    // Hash identities prevent JavaScript '*'/'?' from widening new saved grants.
    // Actual source remains bound to the identity in metadata for review/display.
    // Existing saved rules are untouched; legacy source-specific grants may re-ask.
    await deps.assert({ ...codeModePermission(event.input), sessionID: event.sessionID, agent: event.agent,
      source: { type: "tool", messageID: event.messageID, id: event.id } });
    if (deps.stopped()) throw new Error(INTERRUPTED_REASON);
  } catch (error) {
    deps.debug("tool.execute.before.error", { event, error });
    throw error;
  }
}

function afterToolCall(event: { status: string; result?: unknown }, debug: Debug): void {
  // Preserve the complete host output/error before adding any UX injection hint.
  debug("tool.execute.after", event);
  try {
    if (event.status !== "completed") return;
    const result = event.result as { content?: unknown };
    if (result?.content !== undefined && scanResultContent(result.content))
      result.content = withInjectionWarning(result.content as string | ReadonlyArray<{ type: string; text?: string }>);
  } catch { /* UX hint only */ }
}
