import type { PolicyOptions } from "./policy.js";
import type { Decision } from "./reviewer.js";

export type ReviewerModel = { id: string; providerID: string; variant?: string };
export type UserRule = { action: string; resource?: string; decision: Decision };
export type DecisionProvider = {
  model?: string;
  apiKeyEnv?: string;
  minConfidence?: number;
  timeoutMs?: number;
};
export type ClassifierStage =
  | { type: "static"; allowInProjectEdits?: boolean }
  | { type: "rules"; rules: UserRule[] }
  | ({ type: "jev" | "openai-decision" } & DecisionProvider)
  | ({ type: "laya"; endpoint?: string } & DecisionProvider)
  | { type: "llm"; model?: ReviewerModel };
export interface AutoModeOptions extends PolicyOptions {
  model?: ReviewerModel;
  review?: "all" | "prompts";
  agents?: string[];
  allowInProjectEdits?: boolean;
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

function model(value: unknown): value is ReviewerModel {
  return object(value) && only(value, ["id", "providerID", "variant"]) &&
    text(value.id) && text(value.providerID) && (value.variant === undefined || text(value.variant));
}

function rule(value: unknown): value is UserRule {
  return object(value) && only(value, ["action", "resource", "decision"]) && text(value.action) &&
    (value.resource === undefined || text(value.resource)) &&
    typeof value.decision === "string" && ["allow", "deny", "ask"].includes(value.decision);
}

export function localEndpoint(value: string): string {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) ||
      !['127.0.0.1', '[::1]'].includes(url.hostname) || url.username || url.password || url.search || url.hash ||
      url.pathname !== '/v1/systemone') throw new Error("Laya requires a loopback /v1/systemone endpoint");
  return url.href;
}

function stage(value: unknown): value is ClassifierStage {
  if (!object(value)) return false;
  if (value.type === "static") return only(value, ["type", "allowInProjectEdits"]) &&
    (value.allowInProjectEdits === undefined || typeof value.allowInProjectEdits === "boolean");
  if (value.type === "rules") return only(value, ["type", "rules"]) && Array.isArray(value.rules) &&
    value.rules.length <= 256 && value.rules.every(rule);
  if (value.type === "llm") return only(value, ["type", "model"]) &&
    (value.model === undefined || model(value.model));
  if (typeof value.type !== "string" || !["jev", "openai-decision", "laya"].includes(value.type)) return false;
  if (!only(value, value.type === "laya" ?
      ["type", "model", "apiKeyEnv", "minConfidence", "timeoutMs", "endpoint"] :
      ["type", "model", "apiKeyEnv", "minConfidence", "timeoutMs"])) return false;
  if (value.model !== undefined && !text(value.model)) return false;
  if (value.apiKeyEnv !== undefined &&
      (typeof value.apiKeyEnv !== "string" || !/^[A-Z_][A-Z0-9_]{0,127}$/.test(value.apiKeyEnv))) return false;
  if (value.minConfidence !== undefined &&
      (typeof value.minConfidence !== "number" || !Number.isFinite(value.minConfidence) ||
       value.minConfidence < 0 || value.minConfidence > 1)) return false;
  if (value.timeoutMs !== undefined &&
      (typeof value.timeoutMs !== "number" || !Number.isInteger(value.timeoutMs) ||
       value.timeoutMs < 1 || value.timeoutMs > 30_000)) return false;
  if (value.endpoint !== undefined) {
    if (!text(value.endpoint)) return false;
    try { localEndpoint(value.endpoint); } catch { return false; }
  }
  return true;
}

export function parseOptions(value: unknown): AutoModeOptions {
  if (!object(value)) throw new Error("Invalid auto-mode options");
  if (!only(value, ["model", "review", "agents", "allowInProjectEdits", "classifier", "trusted", "blocks", "exceptions", "keybinds"]))
    throw new Error("Unknown auto-mode option");
  if (value.model !== undefined && !model(value.model)) throw new Error("Invalid reviewer model");
  if (value.review !== undefined && value.review !== "all" && value.review !== "prompts")
    throw new Error("Invalid review scope");
  for (const key of ["trusted", "blocks", "exceptions", "agents"]) {
    if (value[key] !== undefined && (!Array.isArray(value[key]) || value[key].length > 256 || !value[key].every(text)))
      throw new Error(`Invalid ${key}`);
  }
  if (value.allowInProjectEdits !== undefined && typeof value.allowInProjectEdits !== "boolean")
    throw new Error("Invalid edit configuration");
  if (value.classifier !== undefined && (!object(value.classifier) || !only(value.classifier, ["stages"]) ||
      !Array.isArray(value.classifier.stages) || value.classifier.stages.length === 0 ||
      value.classifier.stages.length > 16 || !value.classifier.stages.every(stage)))
    throw new Error("Invalid classifier stages");
  return value as AutoModeOptions;
}

export function stagesFor(options: AutoModeOptions): ClassifierStage[] {
  return options.classifier?.stages ?? [
    { type: "static", allowInProjectEdits: options.allowInProjectEdits === true },
    { type: "llm", model: options.model },
  ];
}
