import { Rpc } from "@opencode/plugin/rpc";

/** Bounded status snapshot served to the TUI, the desktop app and external clients. */
export interface AutoModeStatus {
  enabled: boolean;
  configError?: string;
  classifiers: string[];
  reviewTimeoutMs: number;
  reviewing: { sessionID: string; reviewID: string; startedAt: number }[];
  recent: AutoModeDecision[];
}

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
    configError: { type: "string" },
    classifiers: { type: "array", items: { type: "string" } },
    reviewTimeoutMs: { type: "number" },
    reviewing: {
      type: "array",
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
    recent: {
      type: "array",
      items: {
        type: "object",
        properties: {
          reviewID: { type: "string" },
          sessionID: { type: "string" },
          action: { type: "string" },
          decision: { type: "string" },
          stage: { type: "string" },
          reason: { type: "string" },
          durationMs: { type: "number" },
          at: { type: "number" },
          errorKind: { type: "string" },
        },
        required: ["reviewID", "sessionID", "action", "decision", "stage", "reason", "durationMs", "at"],
        additionalProperties: false,
      },
    },
  },
  required: ["enabled", "classifiers", "reviewTimeoutMs", "reviewing", "recent"],
  additionalProperties: false,
} as const;

const decisionSchema = {
  type: "object",
  properties: {
    reviewID: { type: "string" },
    sessionID: { type: "string" },
    action: { type: "string" },
    decision: { type: "string" },
    stage: { type: "string" },
    reason: { type: "string" },
    durationMs: { type: "number" },
    at: { type: "number" },
    errorKind: { type: "string" },
  },
  required: ["reviewID", "sessionID", "action", "decision", "stage", "reason", "durationMs", "at"],
  additionalProperties: false,
} as const;

/**
 * Contract between the server part and its clients. Clients read a snapshot on
 * connect and follow `decision` events afterwards; events are live-only, so the
 * snapshot is the source of truth after a reconnect.
 */
export const AutoMode = Rpc.define({
  id: "opencode-auto-mode",
  methods: {
    status: {
      input: {
        type: "object",
        properties: { sessionID: { type: "string" } },
        additionalProperties: false,
      },
      output: statusSchema,
    },
    decisions: {
      input: {
        type: "object",
        properties: {
          sessionID: { type: "string" },
          limit: { type: "number" },
        },
        additionalProperties: false,
      },
      output: { type: "array", items: decisionSchema },
    },
  },
  events: {
    decision: { schema: decisionSchema },
  },
});
