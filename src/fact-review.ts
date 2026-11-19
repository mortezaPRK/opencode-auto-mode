/**
 * Certified operation-fact review. A fact is evidence, not permission: the
 * review sees it with `fieldMetadata.authority=false`, and this stage can only
 * allow or abstain, never deny.
 *
 * The fact stage asks `tool_readonly` for an eligible tool call, else one
 * whole-command inspection plus per-segment inspection/`segment_local`, or the
 * unsplittable `operation_kind` → `command_local` fallback; `edit_effect` and
 * `edit_in_project` cover the edit paths, and a structural `delegation` makes no
 * fact call and asks `authorization` alone. Every other certified kind gets one
 * `safety`/`authorization` review. Zero-finding read-only inspections,
 * project-local `shell_segments`, metadata-only `project_edit` and a hash-bound
 * `local_edit` change candidate allow on their facts; callers still apply the
 * mandatory score guards first.
 */
import { createHash } from "node:crypto";
import { Model } from "@opencode/schema/model";
import { DEFAULT_FACT_REVIEW_CONFIDENCE, MIN_FACT_REVIEW_CONFIDENCE } from "./config.js";
import {
  classifyOperationFacts,
  isWriteCapableTool,
  WRITE_TOOL_REFUSAL_REASON,
  type OperationFactOptions,
  type OperationFactResult,
} from "./decision-facts.js";
import type { DecisionContext, DecisionInput } from "./decision.js";
import { buildDecisionEvidence, evidenceLoss, type DecisionEvidence } from "./decision-evidence.js";
import { isEditLike, prepareEditCandidate, type EditCandidate, type EditCaptureIdentity, type EditPayload } from "./edit-fact.js";
import { errorKindOf, ReviewFailure, type ReviewErrorKind } from "./errors.js";
import { snapshotFactReviewRequest, type FactReviewSnapshot } from "./fact-review-input.js";
import {
  CERTIFIED_FACT_FIELD,
  delegationVerdict,
  freshDelegationReviewQuestions,
  freshReviewQuestions,
  isDelegationReviewQuestionFlow,
  isReviewQuestionFlow,
  parseAuthorizationReview,
  parseReview,
  reviewVerdict,
  type CertifiedOperationFact,
  type CertifiedOperationKind,
} from "./fact-verdict.js";
import {
  formatProbability,
  freezeQuestion,
  isProbability,
  isRecord,
  MAX_REQUEST_BYTES,
} from "./guards.js";
import { classifyPath } from "./path-policy.js";
import type { PermissionRequest, StageResult } from "./reviewer.js";
import { isFileAction } from "./score/files.js";
import { checkRequestLimits } from "./score/limits.js";
import { operationPathApproval } from "./score/operation.js";
import { MAX_SEGMENTS } from "./shell-segments.js";
import { withTimeout } from "./timeout.js";

export type { ReviewResult, StageResult } from "./reviewer.js";
export {
  FACT_REVIEW_AUTHORIZATION_QUESTION,
  FACT_REVIEW_SAFETY_QUESTION,
  type CertifiedOperationFact,
  type CertifiedOperationKind,
} from "./fact-verdict.js";

/** Permission request plus host-owned edit bindings. */
export type FactReviewRequest = PermissionRequest & {
  editPayload?: EditPayload;
  expectedEditCapture?: EditCaptureIdentity;
};

export interface FactReviewOptions {
  model: string;
  /** Total budget shared by the fact and review calls, in milliseconds. */
  timeoutMs?: number;
  /** Native threshold; values below 0.8 are rejected before any call. */
  minConfidence?: number;
  /** Opt-in; not consent. Defaults to false. */
  includeEditPayload?: boolean;
}

const DEFAULT_TIMEOUT_MS = 15_000;
const STAGE = "fact-review";
const SHA256_HEX = /^[0-9a-f]{64}$/;
/** One whole-command inspection plus at most one inspection and one
 * `segment_local` call per captured segment. */
const MAX_SEGMENT_FACT_CALLS = 1 + 2 * MAX_SEGMENTS;
/** Review-evidence label for the bounded edit candidate. */
const CHANGE_CONTENT_FIELD = "changeContent";
const LOCAL_EDIT_UNAVAILABLE = "Local edit impact evidence is unavailable before a body-bound safety review";

interface ReviewLimits {
  readonly model: ReturnType<typeof Model.Ref.parse>;
  readonly modelText: string;
  readonly minConfidence: number;
  readonly deadline: number;
}

interface ObservedCall {
  readonly questionNames: readonly string[];
  sourceInputHash?: string;
  servedModel?: string;
}

const sha256 = (text: string): string => createHash("sha256").update(text).digest("hex");

function modelRef(value: string): ReturnType<typeof Model.Ref.parse> {
  try {
    return Model.Ref.parse(value);
  } catch (error) {
    throw new ReviewFailure("context", "Invalid fact review model", { cause: error });
  }
}

function reviewLimits(options: FactReviewOptions): ReviewLimits {
  if (!isRecord(options)) throw new ReviewFailure("context", "Invalid fact review options");
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const minConfidence = options.minConfidence ?? DEFAULT_FACT_REVIEW_CONFIDENCE;
  if (typeof options.model !== "string" || options.model.trim().length === 0 ||
      !Number.isFinite(timeoutMs) || timeoutMs <= 0 ||
      !isProbability(minConfidence) || minConfidence < MIN_FACT_REVIEW_CONFIDENCE)
    throw new ReviewFailure("context", "Invalid fact review options");
  return { model: modelRef(options.model), modelText: options.model, minConfidence, deadline: Date.now() + timeoutMs };
}

function abstain(reason: string, errorKind?: ReviewErrorKind): StageResult {
  return { decision: "abstain", stage: STAGE, reason, ...(errorKind === undefined ? {} : { errorKind }) };
}

/** Essential evidence cannot be reconstructed by a later stage. */
function terminalAbstain(reason: string): StageResult {
  return { ...abstain(reason, "context"), terminal: true };
}

function isDecisionContext(value: unknown): value is DecisionContext {
  if (!isRecord(value) || !isRecord(value.experimental)) return false;
  const generate = value.experimental.generate;
  return isRecord(generate) && typeof generate.decisions === "function";
}

/** File actions carry paths; shell resources are commands, not paths. */
function protectedFileResources(snapshot: FactReviewSnapshot): boolean {
  if (!isFileAction(snapshot.action)) return false;
  return snapshot.resources.some((resource) =>
    classifyPath(resource, snapshot.projectDir).kind === "protected");
}

/** A write-capable tool outside the edit path abstains before any call. */
function writeCapableOutsideEditPath(snapshot: FactReviewSnapshot): boolean {
  return !isEditLike(snapshot) && isWriteCapableTool(snapshot.operation?.tool);
}

function preflight(snapshot: FactReviewSnapshot, ctx: unknown): StageResult | undefined {
  const limit = checkRequestLimits(snapshot.action, snapshot.resources);
  if (limit !== undefined) return abstain(limit.reason, "context");
  if (protectedFileResources(snapshot)) return terminalAbstain("Protected path access");
  const protectedPath = operationPathApproval(snapshot.operation, snapshot.action, snapshot.projectDir);
  if (protectedPath !== undefined) return terminalAbstain(protectedPath.reason);
  if (writeCapableOutsideEditPath(snapshot)) return terminalAbstain(WRITE_TOOL_REFUSAL_REASON);
  if (!isDecisionContext(ctx)) return abstain("Native generation is unavailable", "provider");
  return undefined;
}

type EvidenceSnapshot =
  | { readonly ok: true; readonly evidence: DecisionEvidence; readonly text: string }
  | { readonly ok: false; readonly result: StageResult };

/** Resource or delegation redaction is terminal evidence loss; operation loss
 * stays context because a complete edit payload can still prove the effect.
 * The single `incompleteEvidenceKind` names only the highest-priority loss, so
 * check delegation loss independently: metadata-only edits usually carry a
 * `complete:false` operation, which would otherwise mask a redacted delegation. */
function evidenceSnapshot(snapshot: FactReviewSnapshot): EvidenceSnapshot {
  const evidence = buildDecisionEvidence(snapshot);
  const loss = evidenceLoss(snapshot);
  if (loss.resources || loss.delegations)
    return { ok: false, result: terminalAbstain("Fact review evidence is redacted or incomplete") };
  const text = JSON.stringify(evidence);
  if (Buffer.byteLength(text) > MAX_REQUEST_BYTES)
    return { ok: false, result: abstain("Fact review evidence too large", "context") };
  return { ok: true, evidence, text };
}

function inputText(input: DecisionInput): string | undefined {
  const parts = input.input.filter((part): part is { type: "text"; text: string } => part.type === "text");
  return parts.length === 1 ? parts[0]!.text : undefined;
}

function servedModelOf(value: unknown): string | undefined {
  if (!isRecord(value) || !isRecord(value.native)) return undefined;
  for (const entry of Object.values(value.native)) {
    if (isRecord(entry) && typeof entry.model === "string" && entry.model.trim().length > 0) return entry.model;
  }
  return undefined;
}

/** The provider receives a deeply frozen request; later mutation throws. */
function freezeInput(input: DecisionInput): void {
  for (const part of input.input) Object.freeze(part);
  Object.freeze(input.input);
  for (const question of input.questions) freezeQuestion(question);
  Object.freeze(input.questions);
  Object.freeze(input);
}

interface InputFingerprint {
  readonly text: string | undefined;
  readonly names: readonly string[];
}

function inputFingerprint(input: DecisionInput): InputFingerprint {
  return { text: inputText(input), names: input.questions.map((question) => question.name) };
}

function sameFingerprint(left: InputFingerprint, right: InputFingerprint): boolean {
  return left.text === right.text && left.names.length === right.names.length &&
    left.names.every((name, index) => name === right.names[index]);
}

/** Observe the exact frozen native input and question names the fact stage sent. */
function observeDecisions(ctx: DecisionContext, calls: ObservedCall[]): DecisionContext {
  return {
    experimental: {
      generate: {
        decisions: async (input, options) => {
          freezeInput(input);
          const before = inputFingerprint(input);
          const bytes = JSON.stringify(input);
          const call: ObservedCall = { questionNames: before.names };
          if (before.text !== undefined) call.sourceInputHash = sha256(before.text);
          calls.push(call);
          const response = await ctx.experimental.generate.decisions(input, options);
          if (JSON.stringify(input) !== bytes || !sameFingerprint(before, inputFingerprint(input)))
            throw new ReviewFailure("invalid-output", "Native decision input was mutated");
          call.servedModel = servedModelOf(response);
          return response;
        },
      },
    },
  };
}

/** One recorded fact-stage call shape. */
interface FactCall {
  readonly questionNames: readonly string[];
}

function singleQuestion(call: FactCall | undefined, name: string): boolean {
  return call !== undefined && call.questionNames.length === 1 && call.questionNames[0] === name;
}

/** Per-segment calls: `inspection`, then at most one `segment_local`.
 * `withLocal` separates all-read-only inspection from `shell_segments`. */
function segmentCallsMatch(calls: readonly FactCall[], withLocal: boolean): boolean {
  let index = 0;
  let segments = 0;
  let local = false;
  while (index < calls.length) {
    if (segments >= MAX_SEGMENTS || !singleQuestion(calls[index], "inspection")) return false;
    index += 1;
    segments += 1;
    if (singleQuestion(calls[index], "segment_local")) {
      if (!withLocal) return false;
      local = true;
      index += 1;
    }
  }
  return segments > 0 && local === withLocal;
}

function commandLocalCallFlowMatches(calls: readonly FactCall[]): boolean {
  return calls.length === 3 && singleQuestion(calls[0], "inspection") &&
    singleQuestion(calls[1], "operation_kind") && singleQuestion(calls[2], "command_local");
}

function inspectionCallFlowMatches(calls: readonly FactCall[]): boolean {
  if (singleQuestion(calls[0], "tool_readonly")) return calls.length === 1;
  if (!singleQuestion(calls[0], "inspection")) return false;
  if (calls.length === 2 && singleQuestion(calls[1], "operation_kind")) return true;
  return calls.length === 1 || (calls.length <= MAX_SEGMENT_FACT_CALLS && segmentCallsMatch(calls.slice(1), false));
}

function segmentCallFlowMatches(calls: readonly FactCall[]): boolean {
  return calls.length >= 2 && calls.length <= MAX_SEGMENT_FACT_CALLS &&
    singleQuestion(calls[0], "inspection") && segmentCallsMatch(calls.slice(1), true);
}

const FIXED_FACT_CALLS: Readonly<Partial<Record<CertifiedOperationKind, readonly string[]>>> = Object.freeze({
  delegation: Object.freeze([] as string[]),
  local_edit: Object.freeze(["edit_effect"]),
  project_edit: Object.freeze(["edit_in_project"]),
});

function fixedFactCallsMatch(calls: readonly FactCall[], names: readonly string[]): boolean {
  return calls.length === names.length &&
    names.every((name, index) => singleQuestion(calls[index], name));
}

/** Fact-stage call shape only. */
function factCallFlowMatches(kind: CertifiedOperationKind, calls: readonly FactCall[]): boolean {
  if (kind === "test_run")
    return calls.length === 2 && singleQuestion(calls[0], "inspection") && singleQuestion(calls[1], "operation_kind");
  const fixed = FIXED_FACT_CALLS[kind];
  if (fixed !== undefined) return fixedFactCallsMatch(calls, fixed);
  if (kind === "command_local") return commandLocalCallFlowMatches(calls);
  // A Code Mode program certifies with the same single `tool_readonly` call as an
  // inspection, but `script_readonly` is never fact-only, so it still reviews.
  return kind === "inspection" || kind === "script_readonly"
    ? inspectionCallFlowMatches(calls)
    : segmentCallFlowMatches(calls);
}

/** Zero static findings is enough only because the certified provenance already
 * proves every fact-stage call was read-only. */
function readOnlyInspection(fact: CertifiedOperationFact, snapshot: FactReviewSnapshot): boolean {
  return fact.kind === "inspection" && snapshot.staticAnalysis !== undefined &&
    (snapshot.staticAnalysis.findings?.length ?? 0) === 0;
}

/** Every segment stayed inside the working directory. The `command_local`
 * fallback may write to tempDir outside the project and is never allowed here. */
function projectLocalShellSegments(fact: CertifiedOperationFact, snapshot: FactReviewSnapshot): boolean {
  return fact.kind === "shell_segments" && snapshot.staticAnalysis !== undefined &&
    (snapshot.staticAnalysis.findings?.length ?? 0) === 0;
}

function inspectionAllow(fact: CertifiedOperationFact): StageResult {
  return {
    decision: "allow",
    stage: STAGE,
    reason: `Certified inspection-only fact at native probability ${formatProbability(fact.probability)} (review skipped: read-only)`,
  };
}

/** Project-local shell segments: the certified fact already proved the scope. */
function shellSegmentsAllow(fact: CertifiedOperationFact): StageResult {
  return {
    decision: "allow",
    stage: STAGE,
    reason: `Certified local-only shell segments at native probability ${formatProbability(fact.probability)} (review skipped: project-local)`,
  };
}

/** The certified `edit_in_project` fact already proved the eligibility gate. */
function projectEditAllow(fact: CertifiedOperationFact): StageResult {
  return {
    decision: "allow",
    stage: STAGE,
    reason: `Certified metadata-only project edit fact (project_edit) at native probability ${formatProbability(fact.probability)} (review skipped: in-project edit)`,
  };
}

/** Fact call(s), then exactly one review call; any other question rejects the shape. */
function callFlowMatches(kind: CertifiedOperationKind, calls: readonly ObservedCall[]): boolean {
  const review = calls[calls.length - 1];
  if (review === undefined || !factCallFlowMatches(kind, calls.slice(0, -1))) return false;
  return kind === "delegation"
    ? isDelegationReviewQuestionFlow(review.questionNames)
    : isReviewQuestionFlow(review.questionNames);
}

function factProbability(value: unknown, threshold: number): number | undefined {
  return isProbability(value) && value >= threshold ? value : undefined;
}

function factProvenance(calls: readonly ObservedCall[], kind: CertifiedOperationKind,
  requestedModel: string, evidenceText: string): { sourceInputHash: string; model: string } | undefined {
  if (!factCallFlowMatches(kind, calls)) return undefined;
  const last = calls[calls.length - 1];
  // `delegation` is structural and makes no fact call, so its source input is
  // the normalized evidence that established eligibility, not a native ask.
  const sourceInputHash = kind === "delegation" ? sha256(evidenceText) : last?.sourceInputHash;
  if (sourceInputHash === undefined || !SHA256_HEX.test(sourceInputHash)) return undefined;
  const servedModel = last?.servedModel;
  const model = servedModel !== undefined && servedModel.trim().length > 0 ? servedModel : requestedModel;
  return model.trim().length > 0 ? { sourceInputHash, model } : undefined;
}

function certifyFact(fact: OperationFactResult, calls: readonly ObservedCall[], requestedModel: string,
  threshold: number, evidenceText: string): CertifiedOperationFact | undefined {
  if (fact.kind === "unknown") return undefined;
  const probability = factProbability(fact.probability, threshold);
  if (probability === undefined) return undefined;
  const provenance = factProvenance(calls, fact.kind, requestedModel, evidenceText);
  if (provenance === undefined) return undefined;
  return Object.freeze({
    kind: fact.kind,
    probability,
    ...provenance,
    fieldMetadata: Object.freeze({ authority: false as const }),
  });
}

function factOptions(limits: ReviewLimits, includeEditPayload: boolean | undefined,
  remaining: number): OperationFactOptions {
  return {
    model: limits.modelText,
    timeoutMs: remaining,
    minConfidence: limits.minConfidence,
    includeEditPayload: includeEditPayload === true,
  };
}

interface FactReviewEvidence extends DecisionEvidence {
  changeContent?: EditCandidate["input"];
  certifiedOperationFact: CertifiedOperationFact;
}

function withFact(evidence: DecisionEvidence, fact: CertifiedOperationFact,
  change?: EditCandidate["input"]): string {
  const payload: FactReviewEvidence = {
    ...evidence,
    ...(change === undefined ? {} : { [CHANGE_CONTENT_FIELD]: change }),
    [CERTIFIED_FACT_FIELD]: fact,
  };
  return JSON.stringify(payload);
}

function reviewInput(model: ReturnType<typeof Model.Ref.parse>, text: string,
  questions: DecisionInput["questions"]): DecisionInput {
  const input: DecisionInput = { model, input: [{ type: "text", text }], questions };
  if (Buffer.byteLength(JSON.stringify(input)) > MAX_REQUEST_BYTES)
    throw new ReviewFailure("context", "Fact review request too large");
  return input;
}

function boundedSignal(signal: AbortSignal | undefined, remaining: number): AbortSignal {
  return signal === undefined ? AbortSignal.timeout(remaining) : AbortSignal.any([signal, AbortSignal.timeout(remaining)]);
}

function localTimeout(bounded: AbortSignal | undefined, signal: AbortSignal | undefined): boolean {
  if (signal?.aborted === true || bounded?.aborted !== true) return false;
  const reason: unknown = bounded.reason;
  return typeof reason === "object" && reason !== null &&
    (reason as { name?: unknown }).name === "TimeoutError";
}

function failureResult(error: unknown, signal: AbortSignal | undefined, bounded: AbortSignal | undefined): StageResult {
  const errorKind = signal?.aborted === true ? "cancelled" : localTimeout(bounded, signal) ? "timeout" : errorKindOf(error);
  return abstain("Fact review unavailable or returned invalid output", errorKind);
}

/** One observing context and every call it recorded, in issue order. */
interface ObservedStage {
  readonly ctx: DecisionContext;
  readonly calls: ObservedCall[];
}

function observedStage(ctx: DecisionContext): ObservedStage {
  const calls: ObservedCall[] = [];
  return { ctx: observeDecisions(ctx, calls), calls };
}

type FactOutcome =
  | { readonly ok: true; readonly certified: CertifiedOperationFact }
  | { readonly ok: false; readonly result: StageResult };

async function classifyAndCertify(stage: ObservedStage, options: FactReviewOptions,
  request: FactReviewSnapshot, limits: ReviewLimits, evidenceText: string,
  signal: AbortSignal | undefined): Promise<FactOutcome> {
  const remaining = limits.deadline - Date.now();
  if (remaining <= 0) throw new ReviewFailure("timeout", "Fact review timed out");
  const fact = await classifyOperationFacts(
    stage.ctx,
    factOptions(limits, options.includeEditPayload, remaining),
    request,
    signal,
  );
  if (fact.kind === "unknown") return { ok: false, result: abstain(fact.reason, fact.errorKind) };
  const certified = certifyFact(fact, stage.calls, limits.modelText, limits.minConfidence, evidenceText);
  return certified === undefined
    ? { ok: false, result: abstain("Operation fact provenance is unavailable", "context") }
    : { ok: true, certified };
}

type ChangeContent =
  | { readonly ok: true; readonly value: EditCandidate["input"] }
  | { readonly ok: false; readonly result: StageResult };

/** Rebuilds the candidate from the same snapshot. Its exact bytes already passed
 * the `edit_effect` bounds and privacy screens and are hashed by the fact, so a
 * mismatched candidate never reaches the review. */
function editChangeContent(snapshot: FactReviewSnapshot, options: FactReviewOptions,
  certified: CertifiedOperationFact): ChangeContent {
  const prepared = prepareEditCandidate(snapshot, options.includeEditPayload === true);
  if (!prepared.ok) return { ok: false, result: abstain(LOCAL_EDIT_UNAVAILABLE, "context") };
  const text = JSON.stringify(prepared.candidate.input);
  return sha256(text) === certified.sourceInputHash
    ? { ok: true, value: prepared.candidate.input }
    : { ok: false, result: abstain("Edit change content does not match the certified fact", "context") };
}

type FactForReview =
  | {
    readonly ok: true;
    readonly certified: CertifiedOperationFact;
    readonly evidence: DecisionEvidence;
    readonly change?: EditCandidate["input"];
  }
  | { readonly ok: false; readonly result: StageResult };

async function factForReview(stage: ObservedStage, options: FactReviewOptions,
  snapshot: FactReviewSnapshot, limits: ReviewLimits, signal: AbortSignal | undefined): Promise<FactForReview> {
  const evidence = evidenceSnapshot(snapshot);
  if (!evidence.ok) return { ok: false, result: evidence.result };
  const outcome = await classifyAndCertify(stage, options, snapshot, limits, evidence.text, signal);
  if (!outcome.ok) return { ok: false, result: outcome.result };
  if (outcome.certified.kind !== "local_edit")
    return { ok: true, certified: outcome.certified, evidence: evidence.evidence };
  const change = editChangeContent(snapshot, options, outcome.certified);
  return change.ok
    ? { ok: true, certified: outcome.certified, evidence: evidence.evidence, change: change.value }
    : { ok: false, result: change.result };
}

type ReviewedFact = Extract<FactForReview, { ok: true }>;

interface ReviewPlan {
  readonly questions: DecisionInput["questions"];
  readonly verdict: (response: unknown) => StageResult;
}

/** One review call on the shared deadline, including any bounded change content. */
async function askReview(stage: ObservedStage, fact: ReviewedFact, limits: ReviewLimits,
  signal: AbortSignal | undefined, plan: ReviewPlan): Promise<StageResult> {
  const remaining = limits.deadline - Date.now();
  if (remaining <= 0) throw new ReviewFailure("timeout", "Fact review timed out");
  const bounded = boundedSignal(signal, remaining);
  try {
    const input = reviewInput(limits.model,
      withFact(fact.evidence, fact.certified, fact.change), plan.questions);
    const response = await withTimeout(
      stage.ctx.experimental.generate.decisions(input, { signal: bounded }),
      remaining,
      signal,
    );
    if (!callFlowMatches(fact.certified.kind, stage.calls))
      return abstain("Fact review call flow is invalid", "invalid-output");
    const result = plan.verdict(response);
    return signal?.aborted === true ? abstain("Fact review cancelled", "cancelled") : result;
  } catch (error) {
    return failureResult(error, signal, bounded);
  }
}

/** The full review: `safety` and `authorization`, both required to allow. */
function reviewedFact(stage: ObservedStage, fact: ReviewedFact, limits: ReviewLimits,
  signal: AbortSignal | undefined): Promise<StageResult> {
  return askReview(stage, fact, limits, signal, {
    questions: freshReviewQuestions(),
    verdict: (response) => reviewVerdict(fact.certified, parseReview(response), limits.minConfidence),
  });
}

/** `authorization` alone, because the child's own actions are reviewed separately. */
function delegationReview(stage: ObservedStage, fact: ReviewedFact, limits: ReviewLimits,
  signal: AbortSignal | undefined): Promise<StageResult> {
  return askReview(stage, fact, limits, signal, {
    questions: freshDelegationReviewQuestions(),
    verdict: (response) => delegationVerdict(fact.certified, parseAuthorizationReview(response), limits.minConfidence),
  });
}

function reviewedFactByKind(stage: ObservedStage, fact: ReviewedFact, limits: ReviewLimits,
  signal: AbortSignal | undefined): Promise<StageResult> {
  return fact.certified.kind === "delegation"
    ? delegationReview(stage, fact, limits, signal)
    : reviewedFact(stage, fact, limits, signal);
}

/** Classifies one operation fact, certifies its provenance, then reviews it. */
export async function reviewWithOperationFact(
  ctx: DecisionContext,
  options: FactReviewOptions,
  request: FactReviewRequest,
  signal?: AbortSignal,
): Promise<StageResult> {
  try {
    if (signal?.aborted) return abstain("Fact review cancelled", "cancelled");
    const limits = reviewLimits(options);
    const snapped = snapshotFactReviewRequest(request);
    if (!snapped.ok) return terminalAbstain(snapped.reason);
    const snapshot = snapped.snapshot;
    const blocked = preflight(snapshot, ctx);
    if (blocked !== undefined) return blocked;
    const stage = observedStage(ctx);
    const fact = await factForReview(stage, options, snapshot, limits, signal);
    if (!fact.ok) return fact.result;
    if (readOnlyInspection(fact.certified, snapshot)) return inspectionAllow(fact.certified);
    if (projectLocalShellSegments(fact.certified, snapshot)) return shellSegmentsAllow(fact.certified);
    if (fact.certified.kind === "project_edit") return projectEditAllow(fact.certified);
    return await reviewedFactByKind(stage, fact, limits, signal);
  } catch (error) {
    return failureResult(error, signal, undefined);
  }
}
