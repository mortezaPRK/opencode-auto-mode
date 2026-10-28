import type { AutoModeDecision, AutoModeStatus } from "./rpc.js";

const MAX_RECENT = 100;
// Match the audit record bounds so live status and durable history describe
// the same action, not an unbounded copy of the permission event.
const MAX_ACTION_CHARS = 128;
const MAX_STAGE_CHARS = 64;
const MAX_REASON_CHARS = 200;
const MAX_REVIEWING = 256;

function clip(value: string, max = MAX_REASON_CHARS): string {
  // Count code points, not UTF-16 units, so clipping cannot cut a surrogate
  // pair in half.
  const characters = Array.from(value);
  return characters.length > max ? `${characters.slice(0, max - 1).join("")}…` : value;
}

export interface StatusTracker {
  start(sessionID: string, reviewID: string, at: number): void;
  finish(decision: Omit<AutoModeDecision, "reason"> & { reason: string }): AutoModeDecision;
  snapshot(input: { enabled: boolean; configError?: string; classifiers: string[]; reviewTimeoutMs: number; sessionID?: string }): AutoModeStatus;
  recent(limit: number, sessionID?: string): AutoModeDecision[];
}

/**
 * Small in-memory view of AutoMode for clients. It holds no prompts and is
 * bounded in both entries and text so a long session cannot grow it without
 * limit; durable history stays in the audit log.
 */
export function createStatusTracker(): StatusTracker {
  // Keyed by review rather than session: a session can ask about several
  // actions at once, and finishing one must not hide the others.
  const reviewing = new Map<string, { sessionID: string; startedAt: number }>();
  let recent: AutoModeDecision[] = [];

  return {
    start(sessionID, reviewID, at) {
      if (reviewing.size >= MAX_REVIEWING && !reviewing.has(reviewID)) {
        const oldest = reviewing.keys().next().value;
        if (oldest !== undefined) reviewing.delete(oldest);
      }
      reviewing.set(reviewID, { sessionID, startedAt: at });
    },
    finish(decision) {
      reviewing.delete(decision.reviewID);
      const entry: AutoModeDecision = {
        ...decision,
        action: clip(decision.action, MAX_ACTION_CHARS),
        stage: clip(decision.stage, MAX_STAGE_CHARS),
        reason: clip(decision.reason),
      };
      recent = [...recent, entry].slice(-MAX_RECENT);
      return entry;
    },
    snapshot(input) {
      return {
        enabled: input.enabled,
        ...(input.configError === undefined ? {} : { configError: clip(input.configError) }),
        classifiers: input.classifiers,
        reviewTimeoutMs: input.reviewTimeoutMs,
        reviewing: [...reviewing.entries()]
          .filter(([, entry]) => input.sessionID === undefined || entry.sessionID === input.sessionID)
          .map(([reviewID, entry]) => ({ sessionID: entry.sessionID, reviewID, startedAt: entry.startedAt })),
        recent: input.sessionID === undefined ? recent.slice(-20) : recent.filter((entry) => entry.sessionID === input.sessionID).slice(-20),
      };
    },
    recent(limit, sessionID) {
      const matches = sessionID === undefined ? recent : recent.filter((entry) => entry.sessionID === sessionID);
      return matches.slice(-limit);
    },
  };
}
