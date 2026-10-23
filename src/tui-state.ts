import type { DecisionRecord } from "./state.js";

export function isReviewing(records: Record<string, DecisionRecord>, sessionID: string | undefined, now = Date.now()): boolean {
  if (!sessionID) return false;
  return Object.values(records).some((record) => record.sessionID === sessionID &&
    record.decision === "reviewing" && now - record.at >= 0 && now - record.at < 90_000);
}
