import type { ClassifierOptions } from "./config.js";
import { errorKindOf, terminalEvidence } from "./errors.js";
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
  const signal = callbacks.signal;
  if (signal?.aborted) return interrupted(signal);
  // Defensive guard: no configured stage may override mandatory scoring effects.
  if (score.deny || score.ask) return guardResult(score);
  request.staticAnalysis = { band: score.band, reason: score.reason, findings: score.findings };
  return runPipeline(stages, request, score, callbacks, signal);
}

function guardResult(score: RequestScore): ReviewResult {
  return { decision: score.deny ? "deny" : "ask", reason: score.reason, stage: "guard" };
}

async function runPipeline(stages: readonly ClassifierOptions[], request: PermissionRequest,
  score: RequestScore, callbacks: ClassifierCallbacks, signal: AbortSignal | undefined): Promise<ReviewResult> {
  let last: StageResult | undefined;
  for (const [index, stage] of stages.entries()) {
    if (signal?.aborted) return interrupted(signal, stage.type);
    const result = await runStage(stage, request, score, callbacks, index);
    // Observers can synchronously trigger cancellation too; never return a stale allow.
    if (signal?.aborted) return interrupted(signal, stage.type);
    if (isTerminal(result)) return { ...result, decision: "ask" };
    if (isDecisive(result)) return result as ReviewResult;
    last = retainRationale(stage.type, result, last);
  }
  return unresolved(last);
}

function isDecisive(result: StageResult): boolean {
  return result.decision === "allow" || result.decision === "deny";
}

function unresolved(last: StageResult | undefined): ReviewResult {
  const reason = last?.reason ?? "No classifier resolved the request";
  const stage = last?.stage ?? "classifiers";
  return { ...last, decision: "ask", reason, stage };
}

function interrupted(signal: AbortSignal | undefined, stage = "classifiers"): ReviewResult {
  return {
    decision: "ask", reason: "Classifier pipeline interrupted; human review required", stage,
    errorKind: signal?.reason instanceof DOMException && signal.reason.name === "TimeoutError" ? "deadline" : "cancelled",
  };
}

async function runStage(stage: ClassifierOptions, request: PermissionRequest, score: RequestScore,
  callbacks: ClassifierCallbacks, index: number): Promise<StageResult> {
  let result: StageResult;
  try {
    result = await executeStage(stage, request, score, callbacks);
  } catch (error) {
    result = { ...terminalEvidence(error), decision: "abstain", reason: "Classifier unavailable", stage: stage.type, errorKind: errorKindOf(error) };
  }
  if (callbacks.signal?.aborted) result = interrupted(callbacks.signal, stage.type);
  try { callbacks.onResult?.(stage, result, index); } catch { /* Observability must not alter a verdict. */ }
  return result;
}

async function executeStage(stage: ClassifierOptions, request: PermissionRequest, score: RequestScore,
  callbacks: ClassifierCallbacks): Promise<StageResult> {
  if (stage.type === "static") return staticResult(stage, request, score);
  // Decisions and LLMs see any unresolved band; never silently reorder or insert stages.
  if (stage.type === "decision") return await callbacks.decision(stage, request);
  return await callbacks.llm(stage, request);
}

function staticResult(stage: Extract<ClassifierOptions, { type: "static" }>, request: PermissionRequest,
  score: RequestScore): StageResult {
  const editsDisabled = stage.allowInProjectEdits === false && ["edit", "write"].includes(request.action);
  return score.band === "low" && !editsDisabled
    ? { decision: "allow", reason: score.reason, stage: "static" }
    : { decision: "abstain", reason: "Static classifier requires further review", stage: "static" };
}

function retainRationale(type: string, result: StageResult, previous?: StageResult): StageResult {
  return type === "static" && previous ? previous : result;
}

function isTerminal(result: StageResult): boolean {
  return result.terminal === true || result.errorKind === "cancelled" || result.errorKind === "deadline";
}
