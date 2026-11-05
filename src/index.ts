import { randomUUID } from "node:crypto";
import { Plugin } from "@opencode/plugin";
import { DEFAULT_AUDIT_MAX_BYTES, DEFAULT_REVIEW_TIMEOUT_MS, parseOptions } from "./config.js";
import { reviewRequest, type PermissionRequest, type ReviewResult } from "./reviewer.js";
import { decisionStage } from "./decision.js";
import { runClassifiers } from "./classifier.js";
import { scoreRequest } from "./score.js";
import { loadGlobalOptions } from "./global-options.js";
import { getWorktreeScope } from "./worktree.js";
import { createAuditLog, defaultAuditPath } from "./audit.js";
import { createEventLog, registerGlobalCapture } from "./debug-events.js";
import { createModeStore, type FinishDisposition, type FinishOutcome } from "./mode.js";
import { AutoMode, MAX_SESSION_ID_CHARS, type AutoModeDecision, type AutoModeErrorKind, type AutoModeMode } from "./rpc.js";
import { createStatusTracker } from "./status.js";
import { withTimeout } from "./timeout.js";
import { errorKindOf, ReviewFailure } from "./errors.js";
import { codeModePermission, codeModeReviewResources } from "./code-mode.js";
import { scanResultContent, withInjectionWarning } from "./probe.js";

export type { AutoModeOptions } from "./config.js";
const INTERRUPTED_REASON = "Auto-mode review was interrupted; please decide yourself";
const PAUSED_REASON = "Auto mode is paused; please decide yourself";
const INVALID_CONFIG_ACTION = "Auto-mode review is disabled because its configuration is invalid";
const NATIVE_DENY_REASON = "Native permission deny";
const REVIEW_ACTIONS = /^(?:read|edit|write|glob|grep|shell|execute|webfetch|websearch|question|todowrite)$/;
const SAFER_ALTERNATIVE = "Continue with a safer alternative.";
function denialMessage(reason: string): string {
  const trimmed = reason.trim().replace(/[\s.]+$/, "");
  if (trimmed.endsWith(SAFER_ALTERNATIVE.slice(0, -1))) return `${trimmed}.`;
  return trimmed ? `${trimmed}. ${SAFER_ALTERNATIVE}` : SAFER_ALTERNATIVE;
}

export default Plugin.define({
  id: "opencode-auto-mode",
  setup: async (ctx) => {
    let options: ReturnType<typeof parseOptions> | undefined;
    let configError: string | undefined;
    try { options = parseOptions(loadGlobalOptions(ctx.location.directory)); }
    catch (error) { configError = error instanceof Error ? error.message : "Invalid auto-mode configuration"; }
    const valid = options !== undefined;
    const reviewTimeoutMs = options?.reviewTimeoutMs ?? DEFAULT_REVIEW_TIMEOUT_MS;
    // Audit and raw debug capture are one opt-in: fixed state path, both sinks,
    // and no work of any kind when disabled.
    const auditConfig = options?.audit;
    const auditSetting = auditConfig?.enabled === true
      ? { path: defaultAuditPath(), maxBytes: auditConfig.maxBytes ?? DEFAULT_AUDIT_MAX_BYTES }
      : undefined;
    const audit = createAuditLog(auditSetting);
    const events = createEventLog(auditSetting);
    if (events) console.warn("Auto-mode debug logging is unsafe: full prompts, outputs and events may contain secrets. Local audit logging is enabled without redaction.");
    const modes = createModeStore(ctx.storage, async (sessionID) => {
      const info = await observe("session.get", { sessionID }, () => withTimeout(ctx.session.get({ sessionID }), reviewTimeoutMs), { sessionID });
      return info.parentID;
    });
    type Correlation = { reviewID?: string; sessionID?: string; callID?: string; stageIndex?: number };
    const instanceID = randomUUID();
    const sourceLocation = structuredClone(ctx.location);
    let callCounter = 0;
    const debug = (type: string, data: unknown, correlation: Correlation = {}) => {
      // Local-only, deliberately unredacted. Never forward this data through RPC.
      if (!events) return;
      try { events.write({ ts: new Date().toISOString(), type, instanceID, sourceLocation, ...correlation, payload: data }); } catch { /* best effort */ }
    };
    const observe = async <T>(type: string, input: unknown, work: () => Promise<T>, correlation: Correlation = {}): Promise<T> => {
      const envelope = { ...correlation, callID: `call-${instanceID}-${callCounter++}` };
      debug(`${type}.before`, input, envelope);
      try { const result = await work(); debug(`${type}.after`, result, envelope); return result; }
      catch (error) { debug(`${type}.error`, error, envelope); throw error; }
    };
    /** Bounded, observed SDK call: every host/provider lookup shares one deadline shape. */
    const sdk = <T>(type: string, input: unknown, work: () => Promise<T>, signal?: AbortSignal, correlation: Correlation = {}) =>
      observe(type, input, () => withTimeout(work(), reviewTimeoutMs, signal), correlation);
    if (events) debug("configuration", { options, valid, configError, reviewTimeoutMs, captureScope: "SDK-exposed events and observed plugin calls only; invisible host activity is not captured" });
    const status = createStatusTracker();
    const running = new Map<string, Set<AbortController>>();
    // A failed off write must not restore automation in this plugin instance.
    const suspended = new Set<string>();
    const subscriptions = new AbortController();
    let stopping = false;
    let reviewCounter = 0;
    let rpc: Awaited<ReturnType<typeof ctx.rpc.register<typeof AutoMode>>> | undefined;
    const abortSession = (id: string) => { for (const controller of running.get(id) ?? []) controller.abort(); };
    const publish = (payload: Record<string, unknown>) => {
      try { void Promise.resolve(rpc?.events.emit("decision", payload)).catch(() => {}); } catch { /* best effort */ }
    };
    const decisionPayload = (entry: AutoModeDecision, tripped: boolean) => ({
      reviewID: entry.reviewID, sessionID: entry.sessionID,
      action: REVIEW_ACTIONS.test(entry.action) ? entry.action : "tool",
      decision: entry.decision, stage: entry.stage,
      // Reviewer reasons can quote sensitive evidence: keep those local.
      reason: tripped ? "Auto mode paused (breaker)" : `Auto-mode decision: ${entry.decision}`,
      durationMs: entry.durationMs, at: entry.at,
      ...(entry.errorKind === undefined ? {} : { errorKind: entry.errorKind }),
    });
    const snapshot = async (sessionID?: string) => {
      let mode: AutoModeMode = valid ? "on" : "invalid";
      let counts = { allow: 0, ask: 0, deny: 0 };
      let breaker = false;
      let error = configError;
      let errorKind: AutoModeErrorKind | undefined = valid ? undefined : "config";
      if (valid && error === undefined && sessionID) {
        try {
          const state = await withTimeout(modes.get(sessionID), reviewTimeoutMs);
          mode = suspended.has(sessionID) ? "off" : state.mode;
          counts = state.counts;
          breaker = mode === "paused";
        } catch (cause) {
          debug("status.error", cause, { sessionID });
          mode = "invalid";
          error = "Auto-mode session storage unavailable";
          errorKind = "storage";
        }
      }
      return status.snapshot({ enabled: valid && mode === "on", mode, counts, breaker, reviewTimeoutMs,
        ...(error === undefined ? {} : { configError: error }), ...(errorKind === undefined ? {} : { errorKind }),
        ...(sessionID === undefined ? {} : { sessionID }) });
    };
    const modeMutations = new Map<string, number>();
    const setSessionMode = async (sessionID: string, mode: "on" | "off", commandSession = false) => {
      if (stopping) throw new Error("Auto-mode plugin is stopping");
      if (!sessionID || !["on", "off"].includes(mode)) throw new Error("Invalid auto-mode change");
      // Invalid configuration can never enable review. An explicit off may
      // still be persisted for when the configuration is repaired.
      if (mode === "on" && !valid) throw new Error("Auto-mode configuration is invalid; review disabled");
      const mutation = (modeMutations.get(sessionID) ?? 0) + 1;
      modeMutations.set(sessionID, mutation);
      // Off wins synchronously, before any await: a review already committing must
      // see the latch and an in-flight review is aborted immediately.
      const addedLatch = mode === "off" && !suspended.has(sessionID);
      if (mode === "off") { suspended.add(sessionID); abortSession(sessionID); }
      const revertOff = () => {
        // A failed validation may undo only the latch this request created, and
        // only when no newer request won. A second failed off must not release
        // an earlier fail-safe latch whose write already failed.
        if (addedLatch && modeMutations.get(sessionID) === mutation) suspended.delete(sessionID);
      };
      let info: Awaited<ReturnType<typeof ctx.session.get>>;
      try {
        info = await observe("session.get", { sessionID }, () => withTimeout(ctx.session.get({ sessionID }), reviewTimeoutMs), { sessionID });
      } catch (error) { revertOff(); throw error; }
      try {
        const requested = getWorktreeScope(info.location.directory).directory;
        if (!commandSession && requested !== getWorktreeScope(ctx.location.directory).directory)
          throw new Error("Session location does not match this auto-mode instance");
      } catch (error) { revertOff(); throw error; }
      // An older request whose validation finished late must not overwrite a newer mode.
      if (modeMutations.get(sessionID) !== mutation) return snapshot(sessionID);
      try {
        await withTimeout(modes.set(sessionID, mode), reviewTimeoutMs);
        if (mode === "on" && modeMutations.get(sessionID) === mutation) suspended.delete(sessionID);
        return snapshot(sessionID);
      } catch (error) { debug("mode.set.error", error, { sessionID }); throw error; }
    };
    const statusInput = (input: unknown): string | undefined => {
      if (!input || typeof input !== "object" || Array.isArray(input) || Object.keys(input).some((key) => key !== "sessionID"))
        throw new Error("Invalid auto-mode status request");
      const { sessionID } = input as { sessionID?: unknown };
      if (sessionID !== undefined && (typeof sessionID !== "string" || sessionID.length < 1 || sessionID.length > MAX_SESSION_ID_CHARS))
        throw new Error("Invalid auto-mode status request");
      return sessionID;
    };
    try { rpc = await ctx.rpc.register(AutoMode, {
      status: async (input) => snapshot(statusInput(input)),
      setMode: async (input) => {
        if (!input || typeof input !== "object" || Array.isArray(input) || Object.keys(input).some((key) => !["sessionID", "mode"].includes(key)))
          throw new Error("Invalid auto-mode change");
        const { sessionID, mode } = input as { sessionID: string; mode: "on" | "off" | "resume" };
        if (typeof sessionID !== "string" || !sessionID || sessionID.length > MAX_SESSION_ID_CHARS || !["on", "off", "resume"].includes(mode)) throw new Error("Invalid auto-mode change");
        return setSessionMode(sessionID, mode === "resume" ? "on" : mode);
      },
    }); }
    catch { /* RPC is an optional UX surface */ }
    // Cancellation remains local to every loaded instance, independent of audit ownership.
    void (async () => {
      try {
        for await (const event of ctx.event.subscribe({ types: ["session.execution.interrupted"], signal: subscriptions.signal })) {
          abortSession(event.data.sessionID);
        }
      } catch (error) { if (!subscriptions.signal.aborted) debug("interrupt.subscription.error", error); }
    })();
    const releaseCapture = events ? registerGlobalCapture(events.sinkPath, (signal, isOwner, handoff, markFailure) => {
      debug(handoff ? "capture.handoff" : "capture.started", {
        scope: "process-wide server-global stream per canonical sink path",
        ...(handoff ? { reason: "Previous owner unloaded, stream failed, or legacy registry retired; potential SDK subscription setup/dispose gap; no replay guarantee" } : {}),
      });
      void (async () => {
        try {
          for await (const event of ctx.event.subscribe({ signal })) {
            // A queued event from the retiring subscriber must not duplicate the new owner.
            if (isOwner()) debug("event", event);
          }
          debug(signal.aborted ? "capture.stopped" : "capture.interrupted", { reason: signal.aborted ? "cleanup or ownership transfer" : "Event subscription ended unexpectedly; capture gap; trying eligible standby owners, or waiting for a new registration" });
        } catch (error) {
          if (!signal.aborted) debug("capture.error", error);
          debug(signal.aborted ? "capture.stopped" : "capture.interrupted", { reason: signal.aborted ? "cleanup or ownership transfer" : "Event subscription failed; capture gap; trying eligible standby owners, or waiting for a new registration" });
        } finally {
          if (!signal.aborted) markFailure();
        }
      })();
    }) : undefined;
    const abandon = () => {
      stopping = true;
      subscriptions.abort();
      releaseCapture?.();
      for (const id of running.keys()) abortSession(id);
    };
    const registrations: { dispose(): unknown }[] = [];
    const cleanup = async () => {
      abandon();
      await Promise.allSettled([rpc, ...registrations].map(async (registration) => registration?.dispose()));
    };
    try {
      registrations.push(await ctx.permission.hook("evaluate", async (event) => {
        // Invalid configuration acts disabled: the native effect and message are
        // byte-for-byte untouched, with no mode storage, context, model, audit or
        // debug-capture access and no fail-closed ask.
        const settings = options;
        if (!valid || settings === undefined) return;
        const startedAt = Date.now();
        const reviewID = `review-${instanceID}-${startedAt}-${reviewCounter++}`;
        const correlation = { reviewID, sessionID: event.sessionID };
        debug("permission.evaluate.before", event, correlation);
        const hostEffect = event.effect;
        const originalMessage = event.message;
        const restoreHostMessage = () => {
          if (originalMessage === undefined) delete event.message;
          else event.message = originalMessage;
        };
        try {
          // A runtime value outside the permission union is not a native allow,
          // ask or deny. Leave it completely untouched and never enter review.
          if (hostEffect !== "allow" && hostEffect !== "ask" && hostEffect !== "deny") return;
          // A native deny is final: passive local audit only; no state/context/model access.
          if (hostEffect === "deny") {
            try {
              audit?.write({ ts: new Date().toISOString(), reviewID, sessionID: event.sessionID,
                ...(event.agent === undefined ? {} : { agent: event.agent }),
                action: event.action, resources: [...event.resources], hostEffect: "deny", decision: "deny",
                stage: "native", reason: event.message ?? NATIVE_DENY_REASON, durationMs: 0 });
            } catch { /* local auditing is best effort */ }
            return;
          }
          const reviewsNativeAllow = hostEffect === "allow";
          // Explicit off wins synchronously over every later unload/failure path.
          if (suspended.has(event.sessionID)) return;
          if (stopping) {
            event.effect = "ask"; event.message = INTERRUPTED_REASON; return;
          }
          const controller = new AbortController();
          const active = running.get(event.sessionID) ?? new Set<AbortController>();
          active.add(controller);
          running.set(event.sessionID, active);
          const signal = controller.signal;
          const release = () => {
            controller.abort();
            active.delete(controller);
            if (active.size === 0) running.delete(event.sessionID);
          };
          debug("review.setup", { options: settings, startedAt, deadline: startedAt + reviewTimeoutMs, reviewTimeoutMs }, correlation);
          let tracked = false;
          let score: string | undefined;
          let result: ReviewResult;
          let tripped = false;
          let finalDisposition: FinishDisposition = "cancelled";
          let hostCancelled = false;
          let abandoned = false;
          // One predicate for host interruption: our own cleanup abort is not one.
          const cancelledNow = () => hostCancelled || stopping || (!abandoned && signal.aborted);
          try {
            type WorkOutcome =
              | { kind: "passthrough" }
              | { kind: "cancelled" }
              | { kind: "reviewed"; result: ReviewResult };
            const work = async (): Promise<WorkOutcome> => {
              const state = await observe("mode.get", { sessionID: event.sessionID }, () => modes.get(event.sessionID), correlation);
              // Explicit off and persisted off return control to the native host.
              if (suspended.has(event.sessionID) || state.mode === "off") return { kind: "passthrough" };
              if (state.mode === "paused") {
                // A paused breaker asks for host allows. An existing ask already
                // has its native prompt and needs no synthetic counter.
                if (!reviewsNativeAllow) return { kind: "passthrough" };
                return { kind: "reviewed", result: { decision: "ask", reason: PAUSED_REASON, stage: "mode" } };
              }
              if (cancelledNow()) return { kind: "cancelled" };
              status.start(event.sessionID, reviewID, startedAt);
              tracked = true;
              // Reject oversized host payloads without passing raw metadata/source to a model.
              if (Buffer.byteLength(JSON.stringify({ action: event.action, resources: event.resources, metadata: event.metadata, source: event.source })) > 65_536)
                return { kind: "reviewed", result: { decision: "ask", reason: "Request too large for automatic review", stage: "context" } };
              const info = await sdk("session.get", { sessionID: event.sessionID }, () => ctx.session.get({ sessionID: event.sessionID }, { signal }), signal, correlation);
              if (signal.aborted) return { kind: "cancelled" };
              // Same-model reviewer identity is intentionally not restricted or warned:
              // the user chooses the reviewer, and this plugin adds no independence gate.
              const scope = await observe("worktree.scope", info.location, async () => getWorktreeScope(info.location.directory), correlation);
              const location = { directory: scope.directory };
              const vcs = await sdk("vcs.get", { location }, () => ctx.vcs.get({ location }, { signal }), signal, correlation);
              if (signal.aborted) return { kind: "cancelled" };
              const tree = await sdk("vcs.status", { location }, () => ctx.vcs.status({ location }, { signal }), signal, correlation);
              if (signal.aborted) return { kind: "cancelled" };
              let reviewResources: string[];
              try { reviewResources = codeModeReviewResources(event) ?? [...event.resources]; }
              catch (error) { throw new ReviewFailure("context", "Code Mode evidence does not match its permission identity", { cause: error }); }
              const request: PermissionRequest = {
                action: event.action, resources: reviewResources, agent: event.agent,
                projectDir: scope.directory, worktreeRoot: scope.worktreeRoot,
                gitState: { branch: vcs.data.branch.current, defaultBranch: vcs.data.branch.default, clean: tree.data.length === 0 },
              };
              if (signal.aborted) return { kind: "cancelled" };
              const scored = await observe("score", request, async () => scoreRequest(request, settings), correlation);
              score = scored.band;
              if ("ask" in scored && scored.ask) return { kind: "reviewed", result: { decision: "ask", reason: scored.reason, stage: "score" } };
              if (scored.deny) return { kind: "reviewed", result: { decision: "deny", reason: scored.reason, stage: "score" } };
              let transcript: Promise<string> | undefined;
              const authorize = async () => {
                if (cancelledNow()) throw new Error(INTERRUPTED_REASON);
                transcript ??= (async () => {
                  // Classifier context is user-only; local debug retains the full response.
                  const messages = await sdk("session.context", { sessionID: event.sessionID }, () => ctx.session.context({ sessionID: event.sessionID }, { signal }), signal, correlation);
                  const users = messages.filter((message) => message.type === "user").map((message) => message.text);
                  if (users.length === 0 || users.some((text) => typeof text !== "string") || Buffer.byteLength(users.join("\n")) > 12_000)
                    throw new ReviewFailure("context", "User authorization context is unavailable or oversized");
                  return users.join("\n");
                })();
                request.transcript = await transcript;
                if (cancelledNow()) throw new Error(INTERRUPTED_REASON);
              };
              // Observe the native stateless generation boundary, including exact prompts,
              // complete raw responses and errors. This wrapper never modifies model input.
              const native = (stageIndex: number) => ({
                experimental: { generate: {
                  text: (input: Parameters<typeof ctx.experimental.generate.text>[0], generation: { signal: AbortSignal }) =>
                    sdk("generate.text", input, () => ctx.experimental.generate.text(input, generation), generation.signal, { ...correlation, stageIndex }),
                  decisions: (input: Parameters<Parameters<typeof decisionStage>[0]["experimental"]["generate"]["decisions"]>[0], generation: { signal: AbortSignal }) =>
                    sdk("generate.decisions", input, () => ctx.experimental.generate.decisions(input as Parameters<typeof ctx.experimental.generate.decisions>[0], generation), generation.signal, { ...correlation, stageIndex }),
                } },
              });
              const stageCall = async <T>(stage: typeof settings.classifiers[number], work: (stageIndex: number) => Promise<T>) => {
                const stageIndex = settings.classifiers.indexOf(stage);
                const envelope = { ...correlation, stageIndex };
                debug("classifier.start", stage, envelope);
                try { await authorize(); const outcome = await work(stageIndex); debug("classifier.end", outcome, envelope); return outcome; }
                catch (error) { debug("classifier.error", error, envelope); debug("classifier.end", { error }, envelope); throw error; }
              };
              const verdict = await runClassifiers(settings.classifiers, request, scored, {
                signal,
                decision: (stage) => stageCall(stage, (index) => decisionStage(native(index), stage, request, signal, (error) => debug("classifier.validation.error", error, { ...correlation, stageIndex: index }))),
                llm: (stage) => stageCall(stage, (index) => reviewRequest(native(index), request, stage.model, signal, stage.timeoutMs ?? reviewTimeoutMs, (error) => debug("classifier.validation.error", error, { ...correlation, stageIndex: index }))),
                onResult: (stage, outcome, stageIndex) => {
                  if (stage.type === "static") { debug("classifier.start", stage, { ...correlation, stageIndex }); debug("classifier.end", outcome, { ...correlation, stageIndex }); }
                  debug("classifier", { stage, outcome }, { ...correlation, stageIndex });
                },
              });
              return { kind: "reviewed", result: verdict };
            };
            const proposed = await withTimeout(work(), reviewTimeoutMs, signal);
            if (proposed.kind !== "reviewed") {
              release();
              // Explicit off restores the host effect. Other cancellation/unload
              // paths fail closed to ask.
              const off = suspended.has(event.sessionID);
              finalDisposition = off ? "off" : "cancelled";
              if (proposed.kind === "cancelled" && !off) {
                event.effect = "ask";
                event.message = INTERRUPTED_REASON;
              }
              if (tracked) status.finish({ reviewID, sessionID: event.sessionID, action: event.action,
                decision: off ? hostEffect : "ask",
                stage: off ? "off" : "cancelled",
                reason: off ? "Auto mode is off; native permission effect preserved" : INTERRUPTED_REASON,
                durationMs: Date.now() - startedAt, at: Date.now() });
              return;
            }
            result = proposed.result;
          } catch (error) {
            debug("review.error", error, correlation);
            const category = errorKindOf(error);
            // Capture host cancellation before our own cleanup aborts the controller.
            hostCancelled = signal.aborted || stopping;
            result = { decision: "ask", reason: signal.aborted ? INTERRUPTED_REASON : "Auto-mode review failed or timed out; please decide yourself", stage: "error",
              errorKind: signal.aborted ? "cancelled" : category === "timeout" ? "deadline" : category };
            // The total deadline bounds host lookups too. Stop the abandoned work
            // before waiting for the state commit; it must not start another stage.
            abandoned = true;
            controller.abort();
          }
          let finishPromise: Promise<FinishOutcome> | undefined;
          try {
            // Mode/breaker checks and counters commit atomically. Explicit off wins
            // over every stale proposal; interruption and timeouts fail closed ask.
            // The finish commit repairs a cancelled proposal under its own lock.
            // A signal that aborts while storage is committing settles the host
            // promptly as an ask; the durable repair still completes in order.
            finishPromise = modes.finish(event.sessionID, result.decision, settings.breaker,
              cancelledNow, () => suspended.has(event.sessionID));
            const final = await withTimeout(finishPromise, reviewTimeoutMs, signal.aborted ? undefined : signal);
            const cancelled = cancelledNow();
            const explicitOff = final.disposition === "off" || suspended.has(event.sessionID);
            // The durable commit may have won the race against a cancellation or
            // off observed only after finish resolved. Repair that commit before
            // exposing its counts; explicit off restores the exact pre-review state.
            if (final.commit !== undefined && (explicitOff || (cancelled && final.disposition === "enforced"))) {
              try {
                await withTimeout(modes.revertCancelled(event.sessionID, final, explicitOff ? "off" : "cancelled"), reviewTimeoutMs);
              } catch (error) { debug("mode.revert.error", error, correlation); }
            }
            finalDisposition = explicitOff ? "off" : cancelled ? "cancelled" : final.disposition;
            tripped = !cancelled && !explicitOff && final.tripped;
            // Recheck after storage settles, immediately before touching the host.
            const applyHost = (): { effect: "allow" | "ask" | "deny"; message: string | undefined } => {
              if (explicitOff) return { effect: hostEffect, message: originalMessage };
              if (cancelled || final.disposition === "cancelled") return { effect: "ask", message: INTERRUPTED_REASON };
              if (final.decision === "deny") return { effect: final.decision, message: denialMessage(result.reason) };
              if (final.disposition === "paused") return hostEffect === "allow"
                ? { effect: final.decision, message: PAUSED_REASON }
                : { effect: final.decision, message: originalMessage };
              if (final.decision === "allow" && hostEffect === "allow") return { effect: final.decision, message: originalMessage };
              return { effect: final.decision, message: result.reason };
            };
            const applied = applyHost();
            event.effect = applied.effect;
            if (applied.message === undefined) delete event.message;
            else event.message = applied.message;
            if (tripped) abortSession(event.sessionID);
          } catch (error) {
            debug("mode.finish.error", error, correlation);
            result = { ...result, errorKind: errorKindOf(error) };
            if (suspended.has(event.sessionID)) {
              finalDisposition = "off";
              event.effect = hostEffect;
              restoreHostMessage();
            } else {
              finalDisposition = "cancelled";
              event.effect = "ask";
              event.message = cancelledNow()
                ? INTERRUPTED_REASON
                : "Auto-mode session storage unavailable; please decide yourself";
            }
            // The host settles promptly on interruption, but a durable commit may
            // still complete later. Repair it under the session queue once known.
            void finishPromise?.then(async (outcome) => {
              if (outcome.disposition === "off" || outcome.commit === undefined) return;
              const off = suspended.has(event.sessionID);
              // A paused/cancelled outcome already counted the ask this path applies.
              if (!off && outcome.disposition !== "enforced") return;
              try { await modes.revertCancelled(event.sessionID, outcome, off ? "off" : "cancelled"); }
              catch (cause) { debug("mode.revert.error", cause, correlation); }
            }).catch(() => {});
          }
          finally {
            release();
          }
          const record = {
            ts: new Date().toISOString(), reviewID, sessionID: event.sessionID,
            ...(event.agent === undefined ? {} : { agent: event.agent }),
            action: event.action, resources: [...event.resources], hostEffect, decision: event.effect,
            proposedDecision: result.decision, reviewedNativeAllow: reviewsNativeAllow, disposition: finalDisposition,
            breaker: tripped,
            stage: tripped ? "breaker" : result.stage ?? "unknown",
            ...(score === undefined ? {} : { score }),
            reason: result.reason, durationMs: Date.now() - startedAt,
            ...(event.message === undefined ? {} : { appliedMessage: event.message }),
            ...(result.errorKind === undefined ? {} : { errorKind: result.errorKind }),
          };
          try { audit?.write(record); } catch { /* local auditing is best effort */ }
          if (tracked) {
            const entry = status.finish({ ...record, at: Date.now() });
            // Explicit off is a native passthrough, not a plugin decision event.
            if (finalDisposition !== "off") publish(decisionPayload(entry, tripped));
          }
        } catch (error) { debug("permission.evaluate.error", error, correlation); throw error; }
        finally { debug("permission.evaluate.after", event, correlation); }
      }));
      registrations.push(await ctx.tool.hook("execute.before", async (event) => {
        debug("tool.execute.before", event);
        try {
          if (event.tool !== "execute") return;
          // Invalid configuration leaves native execute behavior byte-for-byte untouched.
          if (!valid) return;
          if (stopping) throw new Error(INTERRUPTED_REASON);
          // Hash identities prevent JavaScript '*'/'?' from widening new saved grants.
          // Actual source remains bound to the identity in metadata for review/display.
          // Existing saved rules are untouched; legacy source-specific grants may re-ask.
          await ctx.permission.assert({ ...codeModePermission(event.input), sessionID: event.sessionID, agent: event.agent,
            source: { type: "tool", messageID: event.messageID, id: event.id } });
          if (stopping) throw new Error(INTERRUPTED_REASON);
        } catch (error) { debug("tool.execute.before.error", { event, error }); throw error; }
      }));
      registrations.push(await ctx.tool.hook("execute.after", (event) => {
        // Preserve the complete host output/error before adding any UX injection hint.
        debug("tool.execute.after", event);
        try {
          if (event.status !== "completed") return;
          const result = event.result as { content?: unknown };
          if (result?.content !== undefined && scanResultContent(result.content))
            result.content = withInjectionWarning(result.content as string | ReadonlyArray<{ type: string; text?: string }>);
        } catch { /* UX hint only */ }
      }));
      registrations.push(await ctx.command.transform((editor) => editor.add({
        name: "auto-mode", description: "Toggle auto mode or show its status", execute: async ({ sessionID, prompt }) => {
          const argument = prompt.text.trim().replace(/^\/?auto-mode\b\s*/, "").trim();
          if (!["", "on", "off", "status"].includes(argument)) {
            await ctx.session.synthetic({ sessionID, text: "Usage: /auto-mode [on|off|status]" });
            return;
          }
          try {
            if (argument !== "status") {
              const current = argument ? undefined : await snapshot(sessionID);
              const target = argument || (current?.mode === "on" ? "off" : "on");
              if (!valid && target === "on") {
                const detail = configError ?? "invalid configuration";
                await ctx.session.synthetic({ sessionID, text: `${INVALID_CONFIG_ACTION}: ${detail}` });
                return;
              }
              await setSessionMode(sessionID, target as "on" | "off", true);
            }
            const now = await snapshot(sessionID);
            const detail = now.mode === "invalid" && now.configError !== undefined
              ? now.errorKind === "config" ? ` Review disabled: ${now.configError}` : ` ${now.configError}`
              : "";
            await ctx.session.synthetic({ sessionID, text: `Auto mode: ${now.mode}. Reviewing: ${now.reviewing.length}. Today: ${now.counts.allow} allow, ${now.counts.ask} ask, ${now.counts.deny} deny. Breaker: ${now.breaker ? "paused" : "ready"}.${detail}` });
          } catch (error) { debug("command.error", error, { sessionID }); await ctx.session.synthetic({ sessionID, text: "Could not change auto mode; check /auto-mode status." }); }
        },
      })));
    } catch (error) { await cleanup(); throw error; }
    return cleanup;
  },
});
