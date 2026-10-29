import { Plugin } from "@opencode/plugin";
import { createLogger } from "./logger.js";
import { clearConfigError, recordConfigError, recordDecision } from "./state.js";
import { defaultPolicy } from "./policy.js";
import { extractReviewContext } from "./transcript.js";
import { scanResultContent, withInjectionWarning } from "./probe.js";
import { buildStage1Prompt, buildStage2Prompt, parseDecision, parseStage1, withDenySuffix, type PermissionRequest, type ReviewResult, type StageResult } from "./reviewer.js";
import { DEFAULT_REVIEW_TIMEOUT_MS, parseOptions, parseReviewerModel, type ReviewerModelRef } from "./config.js";
import { compositeDecision } from "./classifier.js";
import { decisionStage, DEFAULT_DECISION_TIMEOUT_MS } from "./decisions.js";
import { createAuditLog } from "./audit.js";
import { createOtlpExporter } from "./otlp.js";
import { createTraceExporter, type ClassifierAttempt } from "./traces.js";
import { errorKindOf, ReviewFailure, type ReviewErrorKind } from "./errors.js";
import { withTimeout } from "./timeout.js";
import { AutoMode, type AutoModeDecision } from "./rpc.js";
import { createStatusTracker } from "./status.js";

export type { AutoModeOptions, ClassifierStage, DecisionProvider, DecisionStage, ReviewerModel } from "./config.js";

/** Delivered whenever auto-mode abandons a review: only the user can decide now. */
const INTERRUPTED_REASON = "Auto-mode review was interrupted; please decide yourself";

export default Plugin.define({
  id: "opencode-auto-mode",
  setup: async (ctx) => {
    const log = createLogger("events.log");
    const directory = ctx.location?.directory;
    let configError: string | undefined;
    let options: ReturnType<typeof parseOptions> | undefined;
    try {
      options = parseOptions(ctx.options);
      if (directory !== undefined) clearConfigError(directory);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      configError = detail;
      log.log(`Invalid configuration; automatic approval disabled: ${detail}`);
      if (directory !== undefined) recordConfigError(directory, detail);
    }
    const reviewTimeoutMs = options?.reviewTimeoutMs ?? DEFAULT_REVIEW_TIMEOUT_MS;
    const sinks = [createAuditLog(options?.auditLog), createOtlpExporter(options?.otlp)].filter((sink) => sink !== undefined);
    const traces = createTraceExporter(options?.otlp);
    const counts = new Map<string, number>();
    // Permission evaluations can overlap in one session; keep every active
    // controller so an interruption aborts all of them, not only the newest.
    const running = new Map<string, Set<AbortController>>();
    const subscriptions = new AbortController();
    const status = createStatusTracker();
    let reviewCounter = 0;
    let rpc: Awaited<ReturnType<typeof ctx.rpc.register<typeof AutoMode>>> | undefined;
    try {
      rpc = await ctx.rpc.register(AutoMode, {
        status: async (input) => {
          const { sessionID } = input as { sessionID?: string };
          return status.snapshot({
            enabled: options !== undefined,
            ...(configError === undefined ? {} : { configError }),
            classifiers: options?.classifiers.map((stage) => stage.type) ?? [],
            reviewTimeoutMs,
            ...(sessionID === undefined ? {} : { sessionID }),
          });
        },
        decisions: async (input) => {
          const { limit, sessionID } = input as { limit?: number; sessionID?: string };
          return status.recent(Number.isFinite(limit) ? Math.min(Math.max(Math.trunc(limit!), 1), 50) : 20, sessionID);
        },
      });
    } catch { log.log("Status RPC is unavailable"); }

    // Status events are only a freshness bonus: clients poll `status`, so a
    // slow or failing emit must never keep the permission hook waiting. Start
    // the delivery without awaiting it and observe both a synchronous throw
    // from `emit` and a rejected promise it returns.
    const publish = (payload: Record<string, unknown>) => {
      try {
        void Promise.resolve(rpc?.events.emit("decision", payload)).catch(() => {});
      } catch { /* status delivery is best effort */ }
    };

    const abortSession = (sessionID: string) => {
      const controllers = running.get(sessionID);
      if (controllers === undefined) return;
      for (const controller of controllers) controller.abort();
    };

    // Abandon work for a session as soon as the host interrupts it, so a stale
    // review cannot deliver an approval after the user stopped the turn.
    const subscribe = (ctx.event as { subscribe?: (input: { types: string[]; signal?: AbortSignal }) => AsyncIterable<unknown> } | undefined)?.subscribe;
    if (subscribe) {
      void (async () => {
        try {
          const events = subscribe.call(ctx.event, { types: ["session.execution.interrupted"], signal: subscriptions.signal });
          for await (const event of events) {
            const data = (event as { data?: { sessionID?: unknown } }).data;
            const sessionID = data?.sessionID;
            if (sessionID !== undefined) abortSession(String(sessionID));
          }
        } catch { /* the event stream is best effort */ }
      })();
    }

    // Once abandonment starts, an evaluation the host dispatched earlier may
    // still reach the hook while cleanup is stalled. Record it so the handler
    // never starts review work the interruption subscription can no longer
    // cancel.
    let stopping = false;

    // Stop the event reader and every active review synchronously, before any
    // cleanup is awaited: a stalled disposal must not leave an in-flight review
    // able to deliver an allow instead of the cancellation that becomes `ask`.
    const abandon = () => {
      stopping = true;
      subscriptions.abort();
      for (const controllers of running.values()) {
        for (const controller of controllers) controller.abort();
      }
      running.clear();
    };

    // A cleanup can throw synchronously instead of rejecting. Turn that into a
    // rejection so it cannot skip the cleanups started beside it, escape before
    // the caller awaits them, or replace the original registration error.
    const start = (cleanup: () => unknown): Promise<unknown> => {
      try { return Promise.resolve(cleanup()); } catch (error) { return Promise.reject(error); }
    };

    // Abandon work and start every cleanup before awaiting any of them: a
    // stalled status RPC or hook disposal must not keep the others alive. Their
    // failures settle together and never mask the caller's original error.
    const abandonSetup = async (...cleanups: (() => unknown)[]) => {
      abandon();
      await Promise.allSettled([start(() => rpc?.dispose()), ...cleanups.map((cleanup) => start(cleanup))]);
    };

    const permissionRegistration = await registerHook(
      () => ctx.permission.hook("evaluate", async (event) => {
        if (event.effect !== "ask") return;
        // The host can still dispatch an evaluation it decided to ask about
        // after abandonment started, while a stalled cleanup keeps this hook
        // registered. The interruption subscription is already gone, so never
        // start review work here: leave the ask to the user.
        if (stopping) {
          event.message = INTERRUPTED_REASON;
          return;
        }
        if (!options) {
          event.effect = "ask";
          event.message = "Invalid auto-mode configuration; please decide yourself";
          return;
        }
        const reviewID = `review-${process.pid}-${Date.now()}-${reviewCounter++}`;
        recordDecision({ requestID: reviewID, sessionID: event.sessionID, decision: "reviewing", action: event.action.slice(0, 128), reason: "", at: Date.now() });
        status.start(event.sessionID, reviewID, Date.now());
        const startedAt = Date.now();
        const trace = traces?.begin(startedAt);
        const hostEffect = event.effect;
        const controller = new AbortController();
        const active = running.get(event.sessionID);
        if (active === undefined) running.set(event.sessionID, new Set([controller]));
        else active.add(controller);
        let failure: string | undefined;
        let errorKind: ReviewErrorKind | undefined;
        let expired = false;
        let deadlineTimer: ReturnType<typeof setTimeout> | undefined;
        let pendingAttempt: ClassifierAttempt | undefined;

        const review = (async (): Promise<ReviewResult> => {
          try {
            const signal = controller.signal;
            // A cancelled review must not start host or provider work at all.
            throwIfAborted(signal);
            let info: Awaited<ReturnType<typeof ctx.session.get>> | undefined;
            let lookupError: ReviewErrorKind | undefined;
            try {
              info = await withTimeout(ctx.session.get({ sessionID: event.sessionID }, { signal }), 3_000, signal);
            } catch (error) {
              // The lookup only adds the session model and project directory, so
              // a failure must not fail the review. Keep its category: when the
              // missing session model is what prevents model review, the audit
              // record and spans must still explain that the lookup blocked it.
              lookupError = errorKindOf(error);
            }
            // The session lookup swallow keeps a deadline or interruption from
            // failing the review, but an interrupted lookup must stop here.
            throwIfAborted(signal);
            const request: PermissionRequest = {
              action: event.action, resources: [...event.resources], agent: event.agent,
              projectDir: info?.location?.directory, metadata: event.metadata, source: event.source,
              isDelegation: event.action === "task" || event.action === "subagent",
            };
            let contextLoaded = false;
            let contextComplete = false;
            let contextReason = "User authorization context is unavailable";
            return await compositeDecision(options.classifiers, request, async (stage) => {
              // Fallback stages can be entered after an earlier provider failed
              // and the review was interrupted; never invoke the provider then.
              throwIfAborted(signal);
              if (!contextLoaded) {
                const messages = await withTimeout(ctx.session.context({ sessionID: event.sessionID }, { signal }), 3_000, signal);
                throwIfAborted(signal);
                const context = extractReviewContext(messages);
                request.transcript = context.transcript;
                contextComplete = context.complete;
                contextReason = context.reason ?? contextReason;
                contextLoaded = true;
              }
              if (!contextComplete) {
                errorKind ??= "context";
                return { decision: "ask", reason: contextReason, errorKind: "context" };
              }
              throwIfAborted(signal);
              const policy = defaultPolicy(stage.policy);
              const attemptStartedAt = Date.now();
              let attempt: ClassifierAttempt | undefined;
              if (trace !== undefined) {
                // Register the child span before awaiting the provider so a
                // deadline can export it even when the provider never settles.
                attempt = {
                  index: options.classifiers.indexOf(stage), type: stage.type,
                  model: stage.model ?? (info?.model ? `${info.model.providerID}/${info.model.id}` : undefined),
                  startedAt: attemptStartedAt, durationMs: 0,
                  result: { decision: "abstain", reason: "Review attempt pending", errorKind: "cancelled" },
                };
                trace.attempts.push(attempt);
                pendingAttempt = attempt;
              }
              let outcome: StageResult;
              try {
                outcome = stage.type === "llm" ? await llmDecision(ctx, request, policy, signal, stage.model, info?.model, lookupError) :
                  // A typed provider may ignore its abort signal. Bound the stage
                  // here so an interruption or unload settles as cancelled right
                  // away instead of waiting for the overall review deadline.
                  await withTimeout(decisionStage(stage, request, policy, undefined, signal),
                    stage.timeoutMs ?? DEFAULT_DECISION_TIMEOUT_MS, signal);
              } catch (error) {
                const kind = expired ? "deadline" : errorKindOf(error);
                outcome = { decision: "abstain", reason: `${stage.type} reviewer unavailable`, errorKind: kind };
              }
              if (outcome.errorKind !== undefined) errorKind ??= outcome.errorKind;
              // A deadline or cancellation owns the final cause. Leave the span
              // pending for the finalizer instead of letting the aborted
              // provider overwrite an outcome that was already exported.
              if (attempt !== undefined && pendingAttempt === attempt && !expired && !signal.aborted) {
                pendingAttempt = undefined;
                attempt.durationMs = Date.now() - attemptStartedAt;
                attempt.result = outcome;
              }
              return outcome;
            });
          } catch (error) {
            failure = error instanceof Error ? error.message : String(error);
            errorKind ??= errorKindOf(error);
            return { decision: "ask", reason: "Auto-mode review failed; please decide yourself", stage: "error" };
          }
        })();

        const deadline = new Promise<ReviewResult>((resolve) => {
          deadlineTimer = setTimeout(() => {
            expired = true;
            controller.abort();
            resolve({ decision: "ask", reason: "Auto-mode review deadline exceeded; please decide yourself", stage: "deadline" });
          }, reviewTimeoutMs);
          deadlineTimer.unref?.();
        });

        let result: ReviewResult;
        try {
          result = await Promise.race([review, deadline]);
        } finally {
          if (deadlineTimer !== undefined) clearTimeout(deadlineTimer);
          const controllers = running.get(event.sessionID);
          if (controllers !== undefined) {
            controllers.delete(controller);
            if (controllers.size === 0) running.delete(event.sessionID);
          }
        }

        // The deadline terminated the review even if a provider ignored the abort
        // and recorded a cancellation or an earlier stage failed first.
        if (expired) errorKind = "deadline";
        let decision = result.decision;
        let reason = result.reason;
        // A cancelled review may resolve from a provider that ignored the abort,
        // but it must never approve or deny: only the user can decide now. A
        // cancellation is the termination cause even if a provider failed first.
        if (controller.signal.aborted && !expired) {
          decision = "ask";
          reason = INTERRUPTED_REASON;
          errorKind = "cancelled";
        }
        // Finalize a child span whose provider is still running so the exported
        // trace reports the termination cause without waiting for it.
        if (pendingAttempt !== undefined) {
          const attempt = pendingAttempt;
          pendingAttempt = undefined;
          attempt.durationMs = Date.now() - attempt.startedAt;
          attempt.result = {
            decision: "abstain",
            reason: expired ? "Review deadline exceeded" : "Review cancelled",
            errorKind: expired ? "deadline" : "cancelled",
          };
        }
        // Release any provider request still running after a local timeout.
        // This runs after cancellation normalization so a completed allow/deny
        // is delivered unchanged.
        controller.abort();
        event.effect = decision;
        event.message = decision === "deny" ? withDenySuffix(reason) : reason;
        if (decision === "deny") {
          const count = (counts.get(event.sessionID) ?? 0) + 1;
          if (counts.size >= 256 && !counts.has(event.sessionID)) counts.delete(counts.keys().next().value!);
          counts.set(event.sessionID, count);
          log.log(`Action denied (${count} in session)`);
        }
        const auditRecord = {
          ts: new Date().toISOString(), reviewID, sessionID: event.sessionID, agent: event.agent,
          action: event.action, resources: [...event.resources], hostEffect,
          decision, stage: result.stage ?? "unknown", reason,
          durationMs: Date.now() - startedAt,
          ...(errorKind === undefined ? {} : { error: true, errorKind }),
          ...(failure !== undefined ? { errorDetail: failure } : {}),
          ...(trace ? { traceID: trace.traceID, spanID: trace.spanID } : {}),
        };
        trace?.finish(auditRecord);
        for (const sink of sinks) sink.write(auditRecord);
        recordDecision({ requestID: reviewID, sessionID: event.sessionID, decision: event.effect, reason: "", at: Date.now() });
        const tracked: AutoModeDecision = status.finish({
          reviewID, sessionID: event.sessionID, action: auditRecord.action, decision,
          stage: auditRecord.stage, reason, durationMs: auditRecord.durationMs, at: Date.now(),
          ...(errorKind === undefined ? {} : { errorKind }),
        });
        // Clients also poll `status`; a missed event only costs freshness.
        const payload: Record<string, unknown> = {
          reviewID: tracked.reviewID, sessionID: tracked.sessionID, action: tracked.action,
          decision: tracked.decision, stage: tracked.stage, reason: tracked.reason,
          durationMs: tracked.durationMs, at: tracked.at,
        };
        if (tracked.errorKind !== undefined) payload.errorKind = tracked.errorKind;
        publish(payload);
      }),
      abandonSetup,
    );
    const toolRegistration = await registerHook(
      () => ctx.tool.hook("execute.after", (event) => {
        try {
          if (event.status !== "completed") return;
          const result = event.result as { content?: unknown };
          if (result?.content !== undefined && scanResultContent(result.content))
            result.content = withInjectionWarning(result.content as string | ReadonlyArray<{ type: string; text?: string }>);
        } catch { log.log("Output screening failed"); }
      }),
      async () => {
        // Begin abandoning before awaiting either cleanup: a stalled permission
        // disposal or status RPC must not leave the event subscription and
        // active reviews running, where an in-flight review could deliver an
        // allow instead of the cancellation that normalizes to `ask`. Both
        // cleanups start here and settle together; their failures must not
        // replace the original registration error.
        await abandonSetup(() => permissionRegistration.dispose());
      },
    );
    log.log("Auto-mode loaded");
    return async () => {
      // Start abandonment and both hook disposals together rather than gating
      // them on the optional status service: a stalled RPC disposal must never
      // leave a hook registered after the interruption subscription was
      // aborted, where the host could still start reviews.
      await abandonSetup(
        () => permissionRegistration.dispose(),
        () => toolRegistration.dispose(),
      );
      counts.clear();
      log.log("Auto-mode unloaded");
    };
  },
});

/** Registers a hook, cleaning up partial setup when the host throws or rejects. */
async function registerHook<T>(register: () => Promise<T>, undo: () => Promise<void>): Promise<T> {
  try {
    return await register();
  } catch (error) {
    // A cleanup failure or rejection must not mask the registration error the
    // caller has to see, and must not be reported as an unhandled rejection.
    await Promise.allSettled([undo()]);
    throw error;
  }
}

interface ReviewerContext {
  generate: { text(input: { prompt: string; model?: ReviewerModelRef | null }, request?: { signal?: AbortSignal }): Promise<{ text: string }> };
}

function throwIfAborted(signal: AbortSignal): void {
  if (signal.aborted) throw new ReviewFailure("cancelled", "Review cancelled");
}

async function llmDecision(ctx: ReviewerContext, request: PermissionRequest, policy: ReturnType<typeof defaultPolicy>, signal: AbortSignal, model?: string, sessionModel?: ReviewerModelRef, sessionLookupError?: ReviewErrorKind): Promise<StageResult> {
  const ref = model ? parseReviewerModel(model) : sessionModel;
  if (!ref) return {
    decision: "abstain",
    reason: "Session model is unavailable; configure a reviewer model",
    // Only a failed lookup explains the missing model; an explicit reviewer or
    // a static stage is unaffected and must not inherit the lookup's category.
    ...(sessionLookupError === undefined ? {} : { errorKind: sessionLookupError }),
  };
  const prompt = buildStage1Prompt(request, policy);
  if (Buffer.byteLength(prompt) > 65_536) return { decision: "ask", reason: "Request too large for automatic review" };
  throwIfAborted(signal);
  const triage = await withTimeout(ctx.generate.text({ prompt, model: ref }, { signal }), 30_000, signal);
  if (parseStage1(triage.text) === "allow") return { decision: "allow", reason: "LLM triage approved" };
  // The triage call may settle after an interruption; do not start stage two.
  throwIfAborted(signal);
  const response = await withTimeout(ctx.generate.text({ prompt: buildStage2Prompt(request, policy), model: ref }, { signal }), 30_000, signal);
  // parseDecision reports malformed output structurally, so a valid verdict
  // is never reclassified by comparing its reason text.
  return parseDecision(response.text);
}
