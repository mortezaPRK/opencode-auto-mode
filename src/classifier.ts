import type { ClassifierOptions } from "./config.js";
import { errorKindOf } from "./errors.js";
import type { PermissionRequest, ReviewResult, StageResult } from "./reviewer.js";
import type { RequestScore } from "./score.js";

export interface ClassifierCallbacks {
  /** Whole-pipeline cancellation/deadline, distinct from each stage's timeout. */
  signal?: AbortSignal;
  decision(stage: Extract<ClassifierOptions, { type: "decision" }>, request: PermissionRequest): Promise<StageResult>;
  llm(stage: Extract<ClassifierOptions, { type: "llm" }>, request: PermissionRequest): Promise<StageResult>;
  onResult?(stage: ClassifierOptions, result: StageResult, index: number): void;
}

/** Configured order is authoritative. The caller applies mandatory deny/ask guards first. */
export async function runClassifiers(stages: readonly ClassifierOptions[], request: PermissionRequest, score: RequestScore, callbacks: ClassifierCallbacks): Promise<ReviewResult> {
  const interrupted = (stage = "classifiers"): ReviewResult => ({
    decision: "ask", reason: "Classifier pipeline interrupted; human review required", stage,
    errorKind: callbacks.signal?.reason instanceof DOMException && callbacks.signal.reason.name === "TimeoutError" ? "deadline" : "cancelled",
  });
  if (callbacks.signal?.aborted) return interrupted();
  // Defensive guard: no configured stage may override mandatory scoring effects.
  if (score.deny || score.ask)
    return { decision: score.deny ? "deny" : "ask", reason: score.reason, stage: "guard" };
  let last: StageResult | undefined;
  for (const [index, stage] of stages.entries()) {
    if (callbacks.signal?.aborted) return interrupted(stage.type);
    let result: StageResult;
    try {
      if (stage.type === "static") {
        const editsDisabled = stage.allowInProjectEdits === false && ["edit", "write"].includes(request.action);
        result = score.band === "low" && !editsDisabled
          ? { decision: "allow", reason: score.reason, stage: "static" }
          : { decision: "abstain", reason: "Static classifier requires further review", stage: "static" };
      } else {
        // Decisions and LLMs see any unresolved band; never silently reorder or insert stages.
        result = stage.type === "decision" ? await callbacks.decision(stage, request) : await callbacks.llm(stage, request);
      }
    } catch (error) {
      result = { decision: "abstain", reason: "Classifier unavailable", stage: stage.type, errorKind: errorKindOf(error) };
    }
    if (callbacks.signal?.aborted) result = interrupted(stage.type);
    try { callbacks.onResult?.(stage, result, index); } catch { /* Observability must not alter a verdict. */ }
    // Observers can synchronously trigger cancellation too; never return a stale allow.
    if (callbacks.signal?.aborted) return interrupted(stage.type);
    if (result.errorKind === "cancelled" || result.errorKind === "deadline") return { ...result, decision: "ask" };
    if (result.decision === "allow" || result.decision === "deny") return result as ReviewResult;
    last = result;
  }
  return { ...last, decision: "ask", reason: last?.reason ?? "No classifier resolved the request", stage: last?.stage ?? "classifiers" };
}
