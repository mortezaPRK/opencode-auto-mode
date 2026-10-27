import { Plugin } from "@opencode/plugin";
import { createLogger } from "./logger.js";
import { clearConfigError, recordConfigError, recordDecision } from "./state.js";
import { defaultPolicy } from "./policy.js";
import { extractReviewContext } from "./transcript.js";
import { scanResultContent, withInjectionWarning } from "./probe.js";
import { buildStage1Prompt, buildStage2Prompt, parseDecision, parseStage1, withDenySuffix, UNCLEAR_RESPONSE, type PermissionRequest, type ReviewResult, type StageResult } from "./reviewer.js";
import { DEFAULT_REVIEW_TIMEOUT_MS, parseOptions, parseReviewerModel, type ReviewerModelRef } from "./config.js";
import { compositeDecision } from "./classifier.js";
import { decisionStage } from "./decisions.js";
import { createAuditLog } from "./audit.js";
import { createOtlpExporter } from "./otlp.js";
import { createTraceExporter } from "./traces.js";
import { errorKindOf, type ReviewErrorKind } from "./errors.js";
import { withTimeout } from "./timeout.js";

export type { AutoModeOptions, ClassifierStage, DecisionProvider, DecisionStage, ReviewerModel } from "./config.js";

export default Plugin.define({
  id: "opencode-auto-mode",
  setup: async (ctx) => {
    const log = createLogger("events.log");
    const directory = ctx.location?.directory;
    let options: ReturnType<typeof parseOptions> | undefined;
    try {
      options = parseOptions(ctx.options);
      if (directory !== undefined) clearConfigError(directory);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
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
    let reviewCounter = 0;

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

    const permissionRegistration = await ctx.permission.hook("evaluate", async (event) => {
      if (event.effect !== "ask") return;
      if (!options) {
        event.effect = "ask";
        event.message = "Invalid auto-mode configuration; please decide yourself";
        return;
      }
      const reviewID = `review-${process.pid}-${Date.now()}-${reviewCounter++}`;
      recordDecision({ requestID: reviewID, sessionID: event.sessionID, decision: "reviewing", action: event.action.slice(0, 128), reason: "", at: Date.now() });
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

      const review = (async (): Promise<ReviewResult> => {
        try {
          const signal = controller.signal;
          const info = await withTimeout(ctx.session.get({ sessionID: event.sessionID }, { signal }), 3_000, signal).catch(() => undefined);
          const request: PermissionRequest = {
            action: event.action, resources: [...event.resources], agent: event.agent,
            projectDir: info?.location?.directory, metadata: event.metadata, source: event.source,
            isDelegation: event.action === "task" || event.action === "subagent",
          };
          let contextLoaded = false;
          let contextComplete = false;
          let contextReason = "User authorization context is unavailable";
          return await compositeDecision(options.classifiers, request, async (stage) => {
            if (!contextLoaded) {
              const messages = await withTimeout(ctx.session.context({ sessionID: event.sessionID }, { signal }), 3_000, signal);
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
            const policy = defaultPolicy(stage.policy);
            const attemptStartedAt = Date.now();
            let outcome: StageResult;
            try {
              outcome = stage.type === "llm" ? await llmDecision(ctx, request, policy, signal, stage.model, info?.model) :
                await decisionStage(stage, request, policy, undefined, signal);
            } catch (error) {
              const kind = errorKindOf(error);
              outcome = { decision: "abstain", reason: `${stage.type} reviewer unavailable`, errorKind: kind };
            }
            if (outcome.errorKind !== undefined) errorKind ??= outcome.errorKind;
            trace?.attempts.push({
              index: options.classifiers.indexOf(stage), type: stage.type,
              model: stage.model ?? (info?.model ? `${info.model.providerID}/${info.model.id}` : undefined),
              startedAt: attemptStartedAt, durationMs: Date.now() - attemptStartedAt, result: outcome,
            });
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
      // but it must never approve or deny: only the user can decide now.
      if (controller.signal.aborted && !expired) {
        decision = "ask";
        reason = "Auto-mode review was interrupted; please decide yourself";
        errorKind ??= "cancelled";
      }
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
    });
    const toolRegistration = await ctx.tool.hook("execute.after", (event) => {
      try {
        if (event.status !== "completed") return;
        const result = event.result as { content?: unknown };
        if (result?.content !== undefined && scanResultContent(result.content))
          result.content = withInjectionWarning(result.content as string | ReadonlyArray<{ type: string; text?: string }>);
      } catch { log.log("Output screening failed"); }
    }).catch(async (error) => {
      await permissionRegistration.dispose();
      throw error;
    });
    log.log("Auto-mode loaded");
    return async () => {
      subscriptions.abort();
      for (const controllers of running.values()) {
        for (const controller of controllers) controller.abort();
      }
      running.clear();
      try { await permissionRegistration.dispose(); }
      finally { await toolRegistration.dispose(); counts.clear(); log.log("Auto-mode unloaded"); }
    };
  },
});

interface ReviewerContext {
  generate: { text(input: { prompt: string; model?: ReviewerModelRef | null }, request?: { signal?: AbortSignal }): Promise<{ text: string }> };
}

async function llmDecision(ctx: ReviewerContext, request: PermissionRequest, policy: ReturnType<typeof defaultPolicy>, signal: AbortSignal, model?: string, sessionModel?: ReviewerModelRef): Promise<StageResult> {
  const ref = model ? parseReviewerModel(model) : sessionModel;
  if (!ref) return { decision: "abstain", reason: "Session model is unavailable; configure a reviewer model" };
  const prompt = buildStage1Prompt(request, policy);
  if (Buffer.byteLength(prompt) > 65_536) return { decision: "ask", reason: "Request too large for automatic review" };
  const triage = await withTimeout(ctx.generate.text({ prompt, model: ref }, { signal }), 30_000, signal);
  if (parseStage1(triage.text) === "allow") return { decision: "allow", reason: "LLM triage approved" };
  const response = await withTimeout(ctx.generate.text({ prompt: buildStage2Prompt(request, policy), model: ref }, { signal }), 30_000, signal);
  const decision = parseDecision(response.text);
  return decision.reason === UNCLEAR_RESPONSE ? { ...decision, errorKind: "invalid-output" } : decision;
}
