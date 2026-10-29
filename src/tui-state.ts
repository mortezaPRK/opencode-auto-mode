import type { DecisionRecord } from "./state.js";

/**
 * How long a "reviewing" record keeps the TUI indicator alive. It must exceed
 * the largest configurable review deadline so a slow review stays visible.
 */
export const REVIEW_DISPLAY_WINDOW_MS = 180_000;

export function isReviewing(records: Record<string, DecisionRecord>, sessionID: string | undefined, now = Date.now()): boolean {
  if (!sessionID) return false;
  return Object.values(records).some((record) => record.sessionID === sessionID &&
    record.decision === "reviewing" && now - record.at >= 0 && now - record.at < REVIEW_DISPLAY_WINDOW_MS);
}
