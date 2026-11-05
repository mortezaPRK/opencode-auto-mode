import { Model } from "@opencode/schema/model";

export type ReviewerModelRef = { id: string; providerID: string; variant?: string };
export type ClassifierOptions =
  | { type: "static"; allowInProjectEdits?: boolean }
  | { type: "decision"; model: string; timeoutMs?: number; minConfidence?: number }
  | { type: "llm"; model: string; timeoutMs?: number };
export interface BreakerOptions { consecutiveDenies: number; windowDenies: number; windowSize: number }
export interface AuditOptions { enabled: boolean; maxBytes: number }
export interface AutoModeOptions {
  classifiers: ClassifierOptions[];
  /** Resolved scoring compatibility field, derived from static stages; not a public option. */
  allowInProjectEdits: boolean;
  tui: boolean;
  reviewTimeoutMs: number;
  breaker: BreakerOptions;
  audit: AuditOptions;
}

export const DEFAULT_REVIEW_TIMEOUT_MS = 15_000;
export const MAX_REVIEW_TIMEOUT_MS = 120_000;
/** Audited JSONL rotation limit; the debug event sink uses the same 10 MiB cap. */
export const DEFAULT_AUDIT_MAX_BYTES = 10_485_760;
const DEFAULT_BREAKER: BreakerOptions = { consecutiveDenies: 3, windowDenies: 10, windowSize: 50 };

export function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function text(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0 && value.length <= 4096;
}
function only(value: Record<string, unknown>, keys: readonly string[]): void {
  const unknown = Object.keys(value).find((key) => !keys.includes(key));
  if (unknown) throw new Error(`Unknown auto-mode option '${unknown}'`);
}
function invalid(name: string): never { throw new Error(`Invalid auto-mode ${name}`); }
function integer(value: unknown, max: number): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= max;
}
export function parseReviewerModel(value: string): ReviewerModelRef {
  const ref = Model.Ref.parse(value);
  return { id: ref.id, providerID: ref.providerID, ...(ref.variant === undefined ? {} : { variant: ref.variant }) };
}
function model(value: unknown): value is string {
  if (!text(value)) return false;
  try { parseReviewerModel(value); return true; } catch { return false; }
}

/** One configured pipeline stage. Unknown keys are rejected per stage type. */
function parseClassifier(stage: unknown): ClassifierOptions {
  if (!object(stage)) invalid("classifier");
  if (stage.type === "static") {
    only(stage, ["type", "allowInProjectEdits"]);
    if (stage.allowInProjectEdits !== undefined && typeof stage.allowInProjectEdits !== "boolean")
      invalid("static allowInProjectEdits");
    return { type: "static", ...(stage.allowInProjectEdits === undefined ? {} : { allowInProjectEdits: stage.allowInProjectEdits }) };
  }
  if (stage.type !== "decision" && stage.type !== "llm") invalid("classifier type");
  only(stage, stage.type === "decision" ? ["type", "model", "timeoutMs", "minConfidence"] : ["type", "model", "timeoutMs"]);
  if (!model(stage.model)) invalid("classifier model");
  if (stage.timeoutMs !== undefined && !integer(stage.timeoutMs, MAX_REVIEW_TIMEOUT_MS)) invalid("classifier timeoutMs");
  if (stage.type === "decision" && stage.minConfidence !== undefined &&
      (typeof stage.minConfidence !== "number" || !Number.isFinite(stage.minConfidence) ||
        stage.minConfidence < 0 || stage.minConfidence > 1))
    invalid("decision minConfidence");
  return { type: stage.type, model: stage.model,
    ...(stage.timeoutMs === undefined ? {} : { timeoutMs: stage.timeoutMs as number }),
    ...(stage.type === "decision" && stage.minConfidence !== undefined ? { minConfidence: stage.minConfidence as number } : {}) };
}

/** Required, non-empty, and at most one static stage. Exactly one static stage may
 * exist: a second is redundant at best and makes the effective project-edit policy
 * ambiguous. */
function parseClassifiers(value: unknown): ClassifierOptions[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 64) invalid("classifiers");
  const classifiers = value.map(parseClassifier);
  if (classifiers.filter((stage) => stage.type === "static").length > 1) invalid("classifiers");
  return classifiers;
}

function parseBreaker(value: unknown): BreakerOptions {
  if (!object(value)) invalid("breaker");
  only(value, ["consecutiveDenies", "windowDenies", "windowSize"]);
  if (!integer(value.consecutiveDenies, 10_000) || !integer(value.windowDenies, 10_000) ||
      !integer(value.windowSize, 10_000) || value.windowDenies > value.windowSize)
    invalid("breaker thresholds");
  return {
    consecutiveDenies: value.consecutiveDenies,
    windowDenies: value.windowDenies,
    windowSize: value.windowSize,
  };
}

/** Audit settings are an object only; a bare path or boolean was a removed shape. */
function parseAudit(value: unknown): AuditOptions {
  if (!object(value)) invalid("audit");
  only(value, ["enabled", "maxBytes"]);
  if (value.enabled !== undefined && typeof value.enabled !== "boolean") invalid("audit enabled");
  if (value.maxBytes !== undefined && (typeof value.maxBytes !== "number" || !Number.isSafeInteger(value.maxBytes) ||
      value.maxBytes < 0)) invalid("audit maxBytes");
  return {
    enabled: value.enabled === undefined ? false : value.enabled,
    maxBytes: value.maxBytes === undefined ? DEFAULT_AUDIT_MAX_BYTES : value.maxBytes,
  };
}

/** Strict validation only; callers must obtain provenance via loadGlobalOptions,
 * never from the SDK's project-merged ctx.options. */
export function parseOptions(value: unknown): AutoModeOptions {
  if (!object(value)) invalid("options");
  only(value, ["classifiers", "reviewTimeoutMs", "breaker", "tui", "audit"]);
  const classifiers = parseClassifiers(value.classifiers);
  const result: AutoModeOptions = {
    classifiers,
    // In-project edit auto-allow remains the default (owner-approved); a static
    // stage opts out by setting allowInProjectEdits: false.
    allowInProjectEdits: classifiers.some((stage) => stage.type === "static" && stage.allowInProjectEdits !== false),
    tui: true,
    reviewTimeoutMs: DEFAULT_REVIEW_TIMEOUT_MS,
    breaker: { ...DEFAULT_BREAKER },
    audit: { enabled: false, maxBytes: DEFAULT_AUDIT_MAX_BYTES },
  };
  if (value.reviewTimeoutMs !== undefined) {
    if (!integer(value.reviewTimeoutMs, MAX_REVIEW_TIMEOUT_MS)) invalid("reviewTimeoutMs");
    result.reviewTimeoutMs = value.reviewTimeoutMs;
  }
  if (value.tui !== undefined) {
    if (typeof value.tui !== "boolean") invalid("tui");
    result.tui = value.tui;
  }
  if (value.breaker !== undefined) result.breaker = parseBreaker(value.breaker);
  if (value.audit !== undefined) result.audit = parseAudit(value.audit);
  return result;
}
