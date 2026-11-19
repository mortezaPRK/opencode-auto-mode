import { Model } from "@opencode/schema/model";
import type { Generate } from "@opencode/schema/generate";
import { errorKindOf, EvidenceFailure, terminalEvidence, ReviewFailure } from "./errors.js";
import { formatProbability, isProbability, isRecord, MAX_REQUEST_BYTES } from "./guards.js";
import { isOpaqueOperationLoss, type ReviewErrorObserver, type StageResult } from "./reviewer.js";
import { withTimeout } from "./timeout.js";
import {
  buildDecisionEvidence,
  DECISION_AUTHORIZATION_INSTRUCTIONS,
  DECISION_SAFETY_INSTRUCTIONS,
  type DecisionEvidence,
  type DecisionEvidenceRequest,
} from "./decision-evidence.js";

export interface DecisionOptions { model: string; timeoutMs?: number; minConfidence?: number }
export type DecisionInput = Omit<Generate.DecisionRequest, "input"> & { input: readonly { type: "text"; text: string }[] };
export interface DecisionContext {
  experimental: { generate: {
    decisions(input: DecisionInput, options: { signal: AbortSignal }): Promise<unknown>;
  } };
}

export { buildDecisionEvidence, DECISION_AUTHORIZATION_INSTRUCTIONS, DECISION_SAFETY_INSTRUCTIONS };
export type { DecisionEvidence, DecisionEvidenceRequest, OperationEvidence } from "./decision-evidence.js";

const PREDICATES = ["safety", "authorization"] as const;
type Predicate = (typeof PREDICATES)[number];
const DEFAULT_TIMEOUT_MS = 3_000;
const DEFAULT_MIN_CONFIDENCE = 0.9;
const isPredicate = (value: string): value is Predicate => (PREDICATES as readonly string[]).includes(value);

type PredicateAnswer = { type: "predicate"; name: Predicate; probability: number };

function predicateAnswer(value: unknown): value is PredicateAnswer {
  return isRecord(value) && value.type === "predicate" && typeof value.name === "string" &&
    isPredicate(value.name) && isProbability(value.probability);
}

function predicateProbabilities(parsed: unknown): Record<Predicate, number> {
  const answers = isRecord(parsed) ? parsed.answers : undefined;
  if (!Array.isArray(answers) || answers.length !== PREDICATES.length)
    throw new ReviewFailure("invalid-output", "Invalid decision answers");
  const found = new Map<Predicate, number>();
  for (const answer of answers) {
    if (!predicateAnswer(answer) || found.has(answer.name))
      throw new ReviewFailure("invalid-output", "Invalid decision predicate answer");
    found.set(answer.name, answer.probability);
  }
  const safety = found.get("safety");
  const authorization = found.get("authorization");
  if (safety === undefined || authorization === undefined)
    throw new ReviewFailure("invalid-output", "Missing decision predicate answer");
  return { safety, authorization };
}

/** Allow only when both separate predicates clear the configured threshold.
 * Low confidence abstains; the initial decision stage never issues a deny. */
function verdict(parsed: unknown, threshold: number): StageResult {
  const { safety, authorization } = predicateProbabilities(parsed);
  const summary = `safety=${formatProbability(safety)}, authorization=${formatProbability(authorization)}`;
  const below: Predicate[] = [];
  if (safety < threshold) below.push("safety");
  if (authorization < threshold) below.push("authorization");
  if (below.length === 0)
    return { decision: "allow", stage: "decision", reason: `Decision predicates met threshold ${formatProbability(threshold)} (${summary})` };
  return {
    decision: "abstain", stage: "decision",
    reason: `Decision predicates below threshold ${formatProbability(threshold)} for ${below.join(" and ")} (${summary})`,
  };
}

function decisionQuestions(): Generate.DecisionQuestion[] {
  return [
    { type: "predicate", name: "safety", instructions: DECISION_SAFETY_INSTRUCTIONS },
    { type: "predicate", name: "authorization", instructions: DECISION_AUTHORIZATION_INSTRUCTIONS },
  ];
}

function opaqueOperation(evidence: DecisionEvidence, request: DecisionEvidenceRequest): boolean {
  const normalized = { ...request, operation: evidence.operation };
  return isOpaqueOperationLoss(request) || isOpaqueOperationLoss(normalized) ||
    (request.action === "external_directory" && (evidence.operation?.targets?.length ?? 0) === 0);
}

/** Only opaque scope loss and resource-level HTTP-body loss are terminal. Ordinary
 * operation or delegation incompleteness abstains non-terminally so a configured
 * fallback classifier can still review the retained evidence. */
function incomplete(evidence: DecisionEvidence, request: DecisionEvidenceRequest): StageResult | undefined {
  if (evidence.incompleteEvidenceKind === "resources") throw new EvidenceFailure("Incomplete decision evidence");
  if (opaqueOperation(evidence, request)) throw new EvidenceFailure("Opaque operation evidence");
  if (evidence.incompleteEvidenceKind === "shell")
    return {
      decision: "abstain", stage: "decision", errorKind: "context",
      reason: "Decision shell evidence incomplete; abstained before generation",
    };
  if (evidence.incompleteEvidenceKind === "delegations")
    return {
      decision: "abstain", stage: "decision", errorKind: "context",
      reason: "Decision delegation evidence incomplete; abstained before generation",
    };
  if (evidence.incompleteEvidenceKind !== "operation" && evidence.operation?.complete !== false) return undefined;
  return {
    decision: "abstain", stage: "decision", errorKind: "context",
    reason: "Decision operation evidence incomplete; abstained before generation",
  };
}

function limits(options: DecisionOptions): { timeoutMs: number; minConfidence: number } {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const minConfidence = options.minConfidence ?? DEFAULT_MIN_CONFIDENCE;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || !isProbability(minConfidence))
    throw new ReviewFailure("context", "Invalid decision options");
  return { timeoutMs, minConfidence };
}

function decisionInput(options: DecisionOptions, evidence: DecisionEvidence): DecisionInput {
  return {
    model: Model.Ref.parse(options.model),
    input: [{ type: "text", text: JSON.stringify(evidence) }],
    questions: decisionQuestions(),
  };
}

/** A request over the native bound abstains non-terminally: the fallback prompt
 * bounds findings and may still fit, so the predicate evidence is never truncated. */
function requestTooLarge(input: DecisionInput): boolean {
  return Buffer.byteLength(JSON.stringify(input)) > MAX_REQUEST_BYTES;
}

function boundedSignal(signal: AbortSignal | undefined, timeoutMs: number): AbortSignal {
  return signal ? AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]) : AbortSignal.timeout(timeoutMs);
}

function localTimeout(signal: AbortSignal | undefined, bounded: AbortSignal | undefined): boolean {
  return !signal?.aborted && bounded?.aborted === true &&
    bounded.reason instanceof DOMException && bounded.reason.name === "TimeoutError";
}

function failureResult(error: unknown, signal: AbortSignal | undefined, bounded: AbortSignal | undefined): StageResult {
  const errorKind = localTimeout(signal, bounded) ? "timeout" : signal?.aborted ? "cancelled" : errorKindOf(error);
  return { ...terminalEvidence(error), decision: "abstain", stage: "decision", reason: "Decision stage unavailable or returned invalid output", errorKind };
}

/** Native stateless generation only. Unsupported providers and uncertain answers abstain. */
export async function decisionStage(ctx: DecisionContext, options: DecisionOptions, request: DecisionEvidenceRequest, signal?: AbortSignal, onError?: ReviewErrorObserver): Promise<StageResult> {
  let bounded: AbortSignal | undefined;
  try {
    if (signal?.aborted) throw new ReviewFailure("cancelled", "Decision cancelled");
    const { timeoutMs, minConfidence } = limits(options);
    const evidence = buildDecisionEvidence(request);
    const early = incomplete(evidence, request);
    if (early) return early;
    const input = decisionInput(options, evidence);
    if (requestTooLarge(input))
      return {
        decision: "abstain", stage: "decision", errorKind: "context",
        reason: "Decision request exceeds the native size bound; abstained before generation",
      };
    bounded = boundedSignal(signal, timeoutMs);
    const response = await withTimeout(ctx.experimental.generate.decisions(input, { signal: bounded }), timeoutMs, signal);
    return verdict(response, minConfidence);
  } catch (error) {
    try { onError?.(error); } catch { /* Debug collection must not affect permission decisions. */ }
    return failureResult(error, signal, bounded);
  }
}
