import { Model } from "@opencode/schema/model";
import type { PolicyOptions } from "./policy.js";
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
} & DecisionProvider;
export type ClassifierStage =
  | { type: "static"; allowInProjectEdits?: boolean }
  | DecisionStage
  | { type: "llm"; model?: ReviewerModel };
export interface AutoModeOptions extends PolicyOptions {
  keybinds?: { allow?: string; deny?: string };
  auditLog?: boolean | string;
  otlp?: boolean | OtlpOptions;
  classifier?: { stages: ClassifierStage[] };
}

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

function keybinds(value: unknown): value is AutoModeOptions["keybinds"] {
  return object(value) && only(value, ["allow", "deny"]) &&
    Object.values(value).every((keybind) => keybind === undefined || text(keybind));
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
  if (!only(value, ["type", "model", "apiKeyEnv", "minConfidence", "timeoutMs", "endpoint"])) return false;
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
  if (value.type === "llm") return only(value, ["type", "model"]) &&
    (value.model === undefined || model(value.model));
  return value.type === "decision" && decision(value);
}

export function parseOptions(value: unknown): AutoModeOptions {
  if (!object(value)) throw new Error("Invalid auto-mode options");
  if (!only(value, ["classifier", "trusted", "blocks", "exceptions", "keybinds", "auditLog", "otlp"]))
    throw new Error("Unknown auto-mode option");
  for (const key of ["trusted", "blocks", "exceptions"]) {
    if (value[key] !== undefined && (!Array.isArray(value[key]) || value[key].length > 256 || !value[key].every(text)))
      throw new Error(`Invalid ${key}`);
  }
  if (value.keybinds !== undefined && !keybinds(value.keybinds)) throw new Error("Invalid keybinds");
  if (value.auditLog !== undefined && typeof value.auditLog !== "boolean" && !text(value.auditLog))
    throw new Error("Invalid audit log");
  if (value.otlp !== undefined && typeof value.otlp !== "boolean" && !otlp(value.otlp)) throw new Error("Invalid OTLP options");
  if (value.classifier !== undefined && (!object(value.classifier) || !only(value.classifier, ["stages"]) ||
      !Array.isArray(value.classifier.stages) || value.classifier.stages.length === 0 ||
      value.classifier.stages.length > 16 || !value.classifier.stages.every(stage)))
    throw new Error("Invalid classifier stages");
  return value as AutoModeOptions;
}

export function stagesFor(options: AutoModeOptions): ClassifierStage[] {
  return options.classifier?.stages ?? [{ type: "static" }, { type: "llm" }];
}
