import { Rpc } from "@opencode/plugin/rpc";

export type AutoModeMode = "on" | "off" | "paused" | "invalid";
export type AutoModeAction = "on" | "off" | "resume";
export type AutoModeErrorKind = "config" | "storage" | "status";
export interface AutoModeCounts {
  allow: number;
  ask: number;
  deny: number;
}

/** Shared bounds for the status surface and its RPC schema. */
export const MAX_SESSION_ID_CHARS = 256;
export const MAX_STATUS_ACTION_CHARS = 128;
export const MAX_STATUS_STAGE_CHARS = 64;
export const MAX_STATUS_REASON_CHARS = 200;
export const MAX_STATUS_REVIEWING = 256;

/** Minimal status surface; audit history and reviewer configuration stay server-side. */
export interface AutoModeStatus {
  enabled: boolean;
  mode: AutoModeMode;
  configError?: string;
  errorKind?: AutoModeErrorKind;
  reviewTimeoutMs: number;
  reviewing: { sessionID: string; reviewID: string; startedAt: number }[];
  counts: AutoModeCounts;
  breaker?: boolean;
}

/** A bounded live event, not a retained decision-history surface. */
export interface AutoModeDecision {
  reviewID: string;
  sessionID: string;
  action: string;
  decision: string;
  stage: string;
  reason: string;
  durationMs: number;
  at: number;
  errorKind?: string;
}

const statusSchema = {
  type: "object",
  properties: {
    enabled: { type: "boolean" },
    mode: { type: "string", enum: ["on", "off", "paused", "invalid"] },
    configError: { type: "string", maxLength: MAX_STATUS_REASON_CHARS },
    errorKind: { type: "string", enum: ["config", "storage", "status"] },
    reviewTimeoutMs: { type: "number" },
    reviewing: {
      type: "array",
      maxItems: MAX_STATUS_REVIEWING,
      items: {
        type: "object",
        properties: {
          sessionID: { type: "string" },
          reviewID: { type: "string" },
          startedAt: { type: "number" },
        },
        required: ["sessionID", "reviewID", "startedAt"],
        additionalProperties: false,
      },
    },
    counts: {
      type: "object",
      properties: {
        allow: { type: "integer", minimum: 0 },
        ask: { type: "integer", minimum: 0 },
        deny: { type: "integer", minimum: 0 },
      },
      required: ["allow", "ask", "deny"],
      additionalProperties: false,
    },
    breaker: { type: "boolean" },
  },
  required: ["enabled", "mode", "reviewTimeoutMs", "reviewing", "counts"],
  additionalProperties: false,
} as const;

const decisionSchema = {
  type: "object",
  properties: {
    reviewID: { type: "string" },
    sessionID: { type: "string" },
    action: { type: "string", maxLength: MAX_STATUS_ACTION_CHARS },
    decision: { type: "string", maxLength: MAX_STATUS_STAGE_CHARS },
    stage: { type: "string", maxLength: MAX_STATUS_STAGE_CHARS },
    reason: { type: "string", maxLength: MAX_STATUS_REASON_CHARS },
    durationMs: { type: "number" },
    at: { type: "number" },
    errorKind: { type: "string", maxLength: MAX_STATUS_STAGE_CHARS },
  },
  required: ["reviewID", "sessionID", "action", "decision", "stage", "reason", "durationMs", "at"],
  additionalProperties: false,
} as const;

/** Status plus deliberate, session-scoped mode changes; never permission/config edits. */
export const AutoMode = Rpc.define({
  id: "opencode-auto-mode",
  methods: {
    status: {
      input: {
        type: "object",
        properties: { sessionID: { type: "string", minLength: 1, maxLength: MAX_SESSION_ID_CHARS } },
        additionalProperties: false,
      },
      output: statusSchema,
    },
    setMode: {
      input: {
        type: "object",
        properties: {
          sessionID: { type: "string", minLength: 1, maxLength: MAX_SESSION_ID_CHARS },
          mode: { type: "string", enum: ["on", "off", "resume"] },
        },
        required: ["sessionID", "mode"],
        additionalProperties: false,
      },
      output: statusSchema,
    },
  },
  events: {
    decision: { schema: decisionSchema },
  },
});
