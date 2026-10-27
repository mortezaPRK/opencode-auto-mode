import { Plugin } from "@opencode/plugin";
import { createLogger } from "./logger.js";
import { clearConfigError, recordConfigError, recordDecision } from "./state.js";
import { defaultPolicy } from "./policy.js";
import { extractReviewContext } from "./transcript.js";
import { scanResultContent, withInjectionWarning } from "./probe.js";
import { buildStage1Prompt, buildStage2Prompt, parseDecision, parseStage1, withDenySuffix, type PermissionRequest, type ReviewResult, type StageResult } from "./reviewer.js";
import { parseOptions, parseReviewerModel, type ReviewerModelRef } from "./config.js";
import { compositeDecision } from "./classifier.js";
import { decisionStage } from "./decisions.js";
import { createAuditLog } from "./audit.js";
import { createOtlpExporter } from "./otlp.js";
import { createTraceExporter } from "./traces.js";

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
    const sinks = [createAuditLog(options?.auditLog), createOtlpExporter(options?.otlp)].filter((sink) => sink !== undefined);
    const traces = createTraceExporter(options?.otlp);
    const counts = new Map<string, number>();
    let reviewCounter = 0;
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
      let failure: string | undefined;
      let result: ReviewResult;
      try {
        const info = await withTimeout(ctx.session.get({ sessionID: event.sessionID }), 3_000).catch(() => undefined);
        const request: PermissionRequest = {
          action: event.action, resources: [...event.resources], agent: event.agent,
          projectDir: info?.location?.directory, metadata: event.metadata, source: event.source,
          isDelegation: event.action === "task" || event.action === "subagent",
        };
        let contextLoaded = false;
        let contextComplete = false;
        let contextReason = "User authorization context is unavailable";
        result = await compositeDecision(options.classifiers, request, async (stage) => {
          if (!contextLoaded) {
            const messages = await withTimeout(ctx.session.context({ sessionID: event.sessionID }), 3_000);
            const context = extractReviewContext(messages);
            request.transcript = context.transcript;
            contextComplete = context.complete;
            contextReason = context.reason ?? contextReason;
            contextLoaded = true;
          }
          if (!contextComplete)
            return { decision: "ask", reason: contextReason };
          const policy = defaultPolicy(stage.policy);
          const attemptStartedAt = Date.now();
          let outcome: StageResult;
          try {
            outcome = stage.type === "llm" ? await llmDecision(ctx, request, policy, stage.model, info?.model) :
              await decisionStage(stage, request, policy);
          } catch {
            outcome = { decision: "abstain", reason: `${stage.type} reviewer unavailable` };
          }
          trace?.attempts.push({
            index: options.classifiers.indexOf(stage), type: stage.type,
            model: stage.model ?? (info?.model ? `${info.model.providerID}/${info.model.id}` : undefined),
            startedAt: attemptStartedAt, durationMs: Date.now() - attemptStartedAt, result: outcome,
          });
          return outcome;
        });
      } catch (error) {
        failure = error instanceof Error ? error.message : String(error);
        result = { decision: "ask", reason: "Auto-mode review failed; please decide yourself", stage: "error" };
      }
      event.effect = result.decision;
      event.message = result.decision === "deny" ? withDenySuffix(result.reason) : result.reason;
      if (result.decision === "deny") {
        const count = (counts.get(event.sessionID) ?? 0) + 1;
        if (counts.size >= 256 && !counts.has(event.sessionID)) counts.delete(counts.keys().next().value!);
        counts.set(event.sessionID, count);
        log.log(`Action denied (${count} in session)`);
      }
      const auditRecord = {
        ts: new Date().toISOString(), reviewID, sessionID: event.sessionID, agent: event.agent,
        action: event.action, resources: [...event.resources], hostEffect,
        decision: result.decision, stage: result.stage ?? "unknown", reason: result.reason,
        durationMs: Date.now() - startedAt, ...(failure !== undefined ? { error: true, errorDetail: failure } : {}),
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
      try { await permissionRegistration.dispose(); }
      finally { await toolRegistration.dispose(); counts.clear(); log.log("Auto-mode unloaded"); }
    };
  },
});

interface ReviewerContext {
  generate: { text(input: { prompt: string; model?: ReviewerModelRef | null }): Promise<{ text: string }> };
}

async function llmDecision(ctx: ReviewerContext, request: PermissionRequest, policy: ReturnType<typeof defaultPolicy>, model?: string, sessionModel?: ReviewerModelRef): Promise<StageResult> {
  const ref = model ? parseReviewerModel(model) : sessionModel;
  if (!ref) return { decision: "abstain", reason: "Session model is unavailable; configure a reviewer model" };
  const prompt = buildStage1Prompt(request, policy);
  if (Buffer.byteLength(prompt) > 65_536) return { decision: "ask", reason: "Request too large for automatic review" };
  const triage = await withTimeout(ctx.generate.text({ prompt, model: ref }), 30_000);
  if (parseStage1(triage.text) === "allow") return { decision: "allow", reason: "LLM triage approved" };
  const response = await withTimeout(ctx.generate.text({ prompt: buildStage2Prompt(request, policy), model: ref }), 30_000);
  return parseDecision(response.text);
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Review timed out")), ms);
    promise.then((value) => { clearTimeout(timer); resolve(value); }, (error) => { clearTimeout(timer); reject(error); });
  });
}
