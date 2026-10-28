import { Model } from "@opencode/schema/model";
import type { ReviewPolicy } from "./policy.js";
import { logsUrl, type OtlpOptions } from "./otlp.js";

export type ReviewerModel = string;
export type ReviewerModelRef = { id: string; providerID: string; variant?: string };
export type DecisionProvider = {
  apiKeyEnv?: string;
  minConfidence?: number;
  timeoutMs?: number;
};

export type DecisionStage = {
  type: "decision";
  model: string;
  endpoint?: string;
  policy?: Partial<ReviewPolicy>;
} & DecisionProvider;

export type ClassifierStage =
  | { type: "static"; allowInProjectEdits?: boolean }
  | DecisionStage
  | { type: "llm"; model?: ReviewerModel; policy?: Partial<ReviewPolicy> };

export interface AutoModeOptions {
  classifiers: ClassifierStage[];
  tui?: boolean;
  auditLog?: boolean | string;
  otlp?: boolean | OtlpOptions;
  reviewTimeoutMs?: number;
}

/** Longest a single review may block the permission prompt, across every stage. */
export const DEFAULT_REVIEW_TIMEOUT_MS = 60_000;
export const MAX_REVIEW_TIMEOUT_MS = 120_000;

export function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function text(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0 && value.length <= 4096;
}

function only(value: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(value).every((key) => keys.includes(key));
}

export function parseReviewerModel(value: string): ReviewerModelRef {
  const ref = Model.Ref.parse(value);
  return {
    id: ref.id,
    providerID: ref.providerID,
    ...(ref.variant === undefined ? {} : { variant: ref.variant }),
  };
}

function model(value: unknown): value is ReviewerModel {
  if (typeof value !== "string" || !text(value)) return false;
  try { parseReviewerModel(value); return true; } catch { return false; }
}

function policy(value: unknown): value is Partial<ReviewPolicy> {
  return object(value) && only(value, ["trusted", "blocks", "exceptions"]) &&
    Object.values(value).every((list) => Array.isArray(list) && list.length <= 256 && list.every(text));
}

export function localEndpoint(value: string): string {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) ||
      !['127.0.0.1', '[::1]'].includes(url.hostname) || url.username || url.password || url.search || url.hash ||
      url.pathname !== '/v1/systemone') throw new Error("Local System One requires a loopback /v1/systemone endpoint");
  return url.href;
}

function otlp(value: unknown): value is OtlpOptions {
  if (!object(value) || !only(value, ["endpoint", "headers", "timeoutMs"])) return false;
  if (value.endpoint !== undefined) {
    if (!text(value.endpoint)) return false;
    try { logsUrl(value.endpoint); } catch { return false; }
  }
  if (value.headers !== undefined && (!object(value.headers) || Object.keys(value.headers).length > 32 ||
      !Object.entries(value.headers).every(([key, header]) => /^[A-Za-z0-9-]{1,128}$/.test(key) && text(header)))) return false;
  return value.timeoutMs === undefined || (typeof value.timeoutMs === "number" && Number.isInteger(value.timeoutMs) &&
    value.timeoutMs >= 1 && value.timeoutMs <= 10_000);
}

export const DECISION_PROVIDERS = ["typesafe-ai", "laya", "openai"] as const;

function decision(value: Record<string, unknown>): value is DecisionStage {
  if (!only(value, ["type", "model", "apiKeyEnv", "minConfidence", "timeoutMs", "endpoint", "policy"])) return false;
  if (value.policy !== undefined && !policy(value.policy)) return false;
  if (!model(value.model)) return false;
  const ref = parseReviewerModel(value.model);
  if (ref.variant !== undefined || !(DECISION_PROVIDERS as readonly string[]).includes(ref.providerID)) return false;
  if (value.apiKeyEnv !== undefined &&
      (typeof value.apiKeyEnv !== "string" || !/^[A-Z_][A-Z0-9_]{0,127}$/.test(value.apiKeyEnv))) return false;
  if (value.minConfidence !== undefined &&
      (typeof value.minConfidence !== "number" || !Number.isFinite(value.minConfidence) ||
       value.minConfidence < 0 || value.minConfidence > 1)) return false;
  if (value.timeoutMs !== undefined &&
      (typeof value.timeoutMs !== "number" || !Number.isInteger(value.timeoutMs) ||
       value.timeoutMs < 1 || value.timeoutMs > 30_000)) return false;
  if (value.endpoint !== undefined) {
    if (ref.providerID !== "laya" || !text(value.endpoint)) return false;
    try { localEndpoint(value.endpoint); } catch { return false; }
  }
  return true;
}

function stage(value: unknown): value is ClassifierStage {
  if (!object(value)) return false;
  if (value.type === "static") return only(value, ["type", "allowInProjectEdits"]) &&
    (value.allowInProjectEdits === undefined || typeof value.allowInProjectEdits === "boolean");
  if (value.type === "llm") return only(value, ["type", "model", "policy"]) &&
    (value.model === undefined || model(value.model)) &&
    (value.policy === undefined || policy(value.policy));
  return value.type === "decision" && decision(value);
}

export function parseOptions(value: unknown): AutoModeOptions {
  if (!object(value)) throw new Error("Invalid auto-mode options");
  if (!only(value, ["classifiers", "tui", "auditLog", "otlp", "reviewTimeoutMs"]))
    throw new Error("Unknown auto-mode option");
  if (value.tui !== undefined && typeof value.tui !== "boolean") throw new Error("Invalid TUI setting");
  if (value.reviewTimeoutMs !== undefined &&
      (typeof value.reviewTimeoutMs !== "number" || !Number.isInteger(value.reviewTimeoutMs) ||
       value.reviewTimeoutMs < 1_000 || value.reviewTimeoutMs > MAX_REVIEW_TIMEOUT_MS))
    throw new Error("Invalid review timeout");
  if (value.auditLog !== undefined && typeof value.auditLog !== "boolean" && !text(value.auditLog))
    throw new Error("Invalid audit log");
  if (value.otlp !== undefined && typeof value.otlp !== "boolean" && !otlp(value.otlp)) throw new Error("Invalid OTLP options");
  if (!Array.isArray(value.classifiers) || value.classifiers.length === 0 ||
      value.classifiers.length > 16 || !value.classifiers.every(stage))
    throw new Error("A valid nonempty classifiers array is required");
  return value as unknown as AutoModeOptions;
}
