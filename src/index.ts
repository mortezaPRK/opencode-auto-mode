import { Plugin } from "@opencode/plugin";
import { createLogger } from "./logger.js";
import { recordDecision } from "./state.js";
import { defaultPolicy } from "./policy.js";
import { extractTranscript } from "./transcript.js";
import { scanResultContent, withInjectionWarning } from "./probe.js";
import { buildStage1Prompt, buildStage2Prompt, parseDecision, parseStage1, withDenySuffix, type PermissionRequest, type ReviewResult } from "./reviewer.js";
import { parseOptions, stagesFor, type ReviewerModel } from "./config.js";
import { compositeDecision } from "./classifier.js";
import { providerDecision } from "./providers.js";

export type { AutoModeOptions, ClassifierStage, DecisionProvider, UserRule, ReviewerModel } from "./config.js";

export default Plugin.define({
  id: "opencode-auto-mode",
  setup: async (ctx) => {
    const log = createLogger("events.log");
    let options: ReturnType<typeof parseOptions> | undefined;
    try { options = parseOptions(ctx.options); }
    catch { log.log("Invalid configuration; automatic approval disabled"); }
    const counts = new Map<string, number>();
    let reviewCounter = 0;
    const permissionRegistration = await ctx.permission.hook("evaluate", async (event) => {
      if (event.effect === "deny") return;
      if (!options) {
        event.effect = "ask";
        event.message = "Invalid auto-mode configuration; please decide yourself";
        return;
      }
      if (options.agents && (!event.agent || !options.agents.includes(event.agent))) return;
      if (options.review === "prompts" && event.effect !== "ask") return;
      const reviewID = `review-${process.pid}-${Date.now()}-${reviewCounter++}`;
      recordDecision({ requestID: reviewID, sessionID: event.sessionID, decision: "reviewing", action: event.action.slice(0, 128), reason: "", at: Date.now() });
      let result: ReviewResult;
      try {
        const info = await withTimeout(ctx.session.get({ sessionID: event.sessionID }), 3_000).catch(() => undefined);
        const request: PermissionRequest = {
          action: event.action, resources: [...event.resources], agent: event.agent,
          projectDir: info?.location?.directory, metadata: event.metadata, source: event.source,
          isDelegation: event.action === "task" || event.action === "subagent",
        };
        let contextLoaded = false;
        result = await compositeDecision(stagesFor(options), request, async (stage) => {
          if (!contextLoaded) {
            const messages = await withTimeout(ctx.session.context({ sessionID: event.sessionID }), 3_000);
            request.transcript = extractTranscript(messages);
            contextLoaded = true;
          }
          if (!request.transcript?.startsWith("User messages") || request.transcript.includes("…"))
            return { decision: "ask", reason: "User authorization context is unavailable" };
          const policy = defaultPolicy(options);
          return stage.type === "llm" ? llmDecision(ctx, request, policy, stage.model ?? options?.model) :
            providerDecision(stage, request, policy);
        });
      } catch {
        result = { decision: "ask", reason: "Auto-mode review failed; please decide yourself" };
      }
      event.effect = result.decision;
      event.message = result.decision === "deny" ? withDenySuffix(result.reason) : result.reason;
      if (result.decision === "deny") {
        const count = (counts.get(event.sessionID) ?? 0) + 1;
        if (counts.size >= 256 && !counts.has(event.sessionID)) counts.delete(counts.keys().next().value!);
        counts.set(event.sessionID, count);
        log.log(`Action denied (${count} in session)`);
      }
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
  generate: { text(input: { prompt: string; model?: ReviewerModel | null }): Promise<{ text: string }> };
}

async function llmDecision(ctx: ReviewerContext, request: PermissionRequest, policy: ReturnType<typeof defaultPolicy>, model?: ReviewerModel): Promise<ReviewResult> {
  const prompt = buildStage1Prompt(request, policy);
  if (Buffer.byteLength(prompt) > 65_536) return { decision: "ask", reason: "Request too large for automatic review" };
  const triage = await withTimeout(ctx.generate.text({ prompt, model: model ?? null }), 30_000);
  if (parseStage1(triage.text) === "allow") return { decision: "allow", reason: "LLM triage approved" };
  const response = await withTimeout(ctx.generate.text({ prompt: buildStage2Prompt(request, policy), model: model ?? null }), 30_000);
  return parseDecision(response.text);
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Review timed out")), ms);
    promise.then((value) => { clearTimeout(timer); resolve(value); }, (error) => { clearTimeout(timer); reject(error); });
  });
}
