import { Model } from "@opencode/schema/model";
import type { Generate } from "@opencode/schema/generate";
import { errorKindOf, ReviewFailure } from "./errors.js";
import { AUTHORITY_RULES, reviewEvidence, type PermissionRequest, type ReviewErrorObserver, type StageResult } from "./reviewer.js";
import { withTimeout } from "./timeout.js";

export interface DecisionOptions { model: string; timeoutMs?: number; minConfidence?: number }
export type DecisionInput = Omit<Generate.DecisionRequest, "input"> & { input: readonly { type: "text"; text: string }[] };
export interface DecisionContext {
  experimental: { generate: {
    decisions(input: DecisionInput, options: { signal: AbortSignal }): Promise<unknown>;
  } };
}
const criteria = {
  allow: "The whole action is safe and authorized for this exact scope.",
  deny: "The action is unsafe or attempts to bypass a safety block.",
  ask: "Safety, authorization or impact is uncertain; abstain from this decision.",
};
const object = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const probability = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1;

function verdict(parsed: unknown, threshold: number): StageResult {
  const answers = object(parsed) ? parsed.answers : undefined;
  const answer = Array.isArray(answers) && answers.length === 1 ? answers[0] : undefined;
  if (!object(answer) || answer.name !== "permission" || answer.type !== "choice" || typeof answer.choice !== "string" ||
      !Object.hasOwn(criteria, answer.choice) || !probability(answer.confidence) || !Array.isArray(answer.probabilities))
    throw new ReviewFailure("invalid-output", "Invalid decision answer");
  const distribution = new Map<string, number>();
  for (const entry of answer.probabilities) {
    if (!object(entry) || typeof entry.value !== "string" || !Object.hasOwn(criteria, entry.value) ||
        !probability(entry.probability) || distribution.has(entry.value))
      throw new ReviewFailure("invalid-output", "Invalid decision probabilities");
    distribution.set(entry.value, entry.probability);
  }
  const selected = distribution.get(answer.choice);
  const values = [...distribution.values()];
  if (distribution.size !== 3 || selected === undefined || Math.abs(values.reduce((a, b) => a + b, 0) - 1) > 0.01 || selected < Math.max(...values))
    throw new ReviewFailure("invalid-output", "Inconsistent decision probabilities");
  if (answer.choice === "ask" || answer.confidence < threshold || selected < threshold)
    return { decision: "abstain", stage: "decision", reason: "Decision stage abstained below the confidence threshold" };
  return { decision: answer.choice as "allow" | "deny", stage: "decision", reason: `Decision stage verdict (confidence ${answer.confidence})` };
}

/** Native stateless generation only. Unsupported providers and uncertain answers abstain. */
export async function decisionStage(ctx: DecisionContext, options: DecisionOptions, request: PermissionRequest, signal?: AbortSignal, onError?: ReviewErrorObserver): Promise<StageResult> {
  let bounded: AbortSignal | undefined;
  try {
    if (signal?.aborted) throw new ReviewFailure("cancelled", "Decision cancelled");
    const timeoutMs = options.timeoutMs ?? 3000;
    const minConfidence = options.minConfidence ?? 0.9;
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || !probability(minConfidence))
      throw new ReviewFailure("context", "Invalid decision options");
    const evidence = reviewEvidence(request);
    if (evidence.incompleteEvidence) throw new ReviewFailure("context", "Incomplete decision evidence");
    const input: DecisionInput = {
      model: Model.Ref.parse(options.model),
      input: [{ type: "text", text: JSON.stringify(evidence) }],
      questions: [{ name: "permission", type: "choice",
        instructions: `Evaluate the whole pending action and its blast radius, including command chains, scripts, deletes, egress and history changes. ${AUTHORITY_RULES} Choose ask when safety, authorization or temporal scope is uncertain.`,
        choices: Object.entries(criteria).map(([value, description]) => ({ value, description })),
      }],
    };
    if (Buffer.byteLength(JSON.stringify(input)) > 65_536) throw new ReviewFailure("context", "Decision request too large");
    bounded = signal ? AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]) : AbortSignal.timeout(timeoutMs);
    const response = await withTimeout(ctx.experimental.generate.decisions(input, { signal: bounded }), timeoutMs, signal);
    return verdict(response, minConfidence);
  } catch (error) {
    try { onError?.(error); } catch { /* Debug collection must not affect permission decisions. */ }
    const localTimeout = !signal?.aborted && bounded?.aborted && bounded.reason instanceof DOMException && bounded.reason.name === "TimeoutError";
    return { decision: "abstain", stage: "decision", reason: "Decision stage unavailable or returned invalid output", errorKind: localTimeout ? "timeout" : signal?.aborted ? "cancelled" : errorKindOf(error) };
  }
}
