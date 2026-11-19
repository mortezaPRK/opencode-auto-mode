import { Model } from "@opencode/schema/model";
import type { Generate } from "@opencode/schema/generate";
import { errorKindOf, EvidenceFailure, terminalEvidence, ReviewFailure } from "./errors.js";
import { AUTHORITY_RULES, reviewEvidence, terminalEvidenceReason, type PermissionRequest, type ReviewErrorObserver, type StageResult } from "./reviewer.js";
import { withTimeout } from "./timeout.js";

export interface DecisionOptions { model: string; timeoutMs?: number; minConfidence?: number }
export type DecisionInput = Omit<Generate.DecisionRequest, "input"> & { input: readonly { type: "text"; text: string }[] };
export interface DecisionContext {
  experimental: { generate: {
    decisions(input: DecisionInput, options: { signal: AbortSignal }): Promise<unknown>;
  } };
}
const MAX_REQUEST_BYTES = 65_536;
const DEFAULT_TIMEOUT_MS = 3_000;
const DEFAULT_MIN_CONFIDENCE = 0.9;
const criteria = {
  allow: "The whole action is safe and authorized for this exact scope.",
  deny: "A prohibition or unsafe action is established; suspicious names or missing facts alone are not sufficient.",
  ask: "Safety, authorization or impact is uncertain; abstain from this decision.",
};
const object = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const probability = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1;
const isChoice = (value: unknown): value is keyof typeof criteria => typeof value === "string" && Object.hasOwn(criteria, value);

type DecisionAnswer = { choice: keyof typeof criteria; confidence: number; probabilities: readonly unknown[] };

function answerOf(parsed: unknown): DecisionAnswer {
  const answers = object(parsed) ? parsed.answers : undefined;
  const answer = Array.isArray(answers) && answers.length === 1 ? answers[0] : undefined;
  if (!object(answer) || answer.name !== "permission" || answer.type !== "choice" || !isChoice(answer.choice) ||
      !probability(answer.confidence) || !Array.isArray(answer.probabilities))
    throw new ReviewFailure("invalid-output", "Invalid decision answer");
  return { choice: answer.choice, confidence: answer.confidence, probabilities: answer.probabilities };
}

function distributionOf(probabilities: readonly unknown[]): Map<keyof typeof criteria, number> {
  const distribution = new Map<keyof typeof criteria, number>();
  for (const entry of probabilities) {
    if (!object(entry) || !isChoice(entry.value) || !probability(entry.probability) || distribution.has(entry.value))
      throw new ReviewFailure("invalid-output", "Invalid decision probabilities");
    distribution.set(entry.value, entry.probability);
  }
  return distribution;
}

function assertConsistent(distribution: Map<keyof typeof criteria, number>, choice: keyof typeof criteria): void {
  const selected = distribution.get(choice);
  const values = [...distribution.values()];
  if (distribution.size !== 3 || selected === undefined || Math.abs(values.reduce((a, b) => a + b, 0) - 1) > 0.01 || selected < Math.max(...values))
    throw new ReviewFailure("invalid-output", "Inconsistent decision probabilities");
}

function verdict(parsed: unknown, threshold: number): StageResult {
  const answer = answerOf(parsed);
  const distribution = distributionOf(answer.probabilities);
  assertConsistent(distribution, answer.choice);
  const selected = distribution.get(answer.choice) ?? 0;
  if (answer.choice === "ask" || answer.confidence < threshold || selected < threshold)
    return { decision: "abstain", stage: "decision", reason: "Decision stage abstained below the confidence threshold" };
  return { decision: answer.choice as "allow" | "deny", stage: "decision", reason: `Decision stage verdict (confidence ${answer.confidence})` };
}

function decisionQuestions(): Generate.DecisionQuestion[] {
  return [{ name: "permission", type: "choice",
    instructions: `Evaluate the whole pending action and its blast radius, including command chains, scripts, deletes, egress and history changes. ${AUTHORITY_RULES} Choose ask when safety, authorization or temporal scope is uncertain.`,
    choices: Object.entries(criteria).map(([value, description]) => ({ value, description })),
  }];
}

function limits(options: DecisionOptions): { timeoutMs: number; minConfidence: number } {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const minConfidence = options.minConfidence ?? DEFAULT_MIN_CONFIDENCE;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || !probability(minConfidence))
    throw new ReviewFailure("context", "Invalid decision options");
  return { timeoutMs, minConfidence };
}

function decisionInput(options: DecisionOptions, evidence: ReturnType<typeof reviewEvidence>): DecisionInput {
  const input: DecisionInput = {
    model: Model.Ref.parse(options.model),
    input: [{ type: "text", text: JSON.stringify(evidence) }],
    questions: decisionQuestions(),
  };
  if (Buffer.byteLength(JSON.stringify(input)) > MAX_REQUEST_BYTES) throw new EvidenceFailure("Decision request too large");
  return input;
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
export async function decisionStage(ctx: DecisionContext, options: DecisionOptions, request: PermissionRequest, signal?: AbortSignal, onError?: ReviewErrorObserver): Promise<StageResult> {
  let bounded: AbortSignal | undefined;
  try {
    if (signal?.aborted) throw new ReviewFailure("cancelled", "Decision cancelled");
    const { timeoutMs, minConfidence } = limits(options);
    // Opaque scope and HTTP-body loss stay terminal for every stage. Ordinary
    // operation incompleteness (for example an omitted edit payload) does not:
    // this stage abstains non-terminally so a configured fallback still reviews.
    if (terminalEvidenceReason(request) !== undefined) throw new EvidenceFailure("Incomplete decision evidence");
    const evidence = reviewEvidence(request);
    if (evidence.incompleteEvidence !== undefined)
      return { decision: "abstain", stage: "decision", reason: "Operation evidence is incomplete; deferring to later classifiers" };
    const input = decisionInput(options, evidence);
    bounded = boundedSignal(signal, timeoutMs);
    const response = await withTimeout(ctx.experimental.generate.decisions(input, { signal: bounded }), timeoutMs, signal);
    return verdict(response, minConfidence);
  } catch (error) {
    try { onError?.(error); } catch { /* Debug collection must not affect permission decisions. */ }
    return failureResult(error, signal, bounded);
  }
}
