import {
  MAX_STATUS_ACTION_CHARS,
  MAX_STATUS_REASON_CHARS,
  MAX_STATUS_REVIEWING,
  MAX_STATUS_STAGE_CHARS,
  type AutoModeCounts,
  type AutoModeDecision,
  type AutoModeErrorKind,
  type AutoModeMode,
  type AutoModeStatus,
} from "./rpc.js";

function clip(value: string, max = MAX_STATUS_REASON_CHARS): string {
  // Count code points so clipping cannot split a surrogate pair.
  const characters = Array.from(value);
  return characters.length > max ? `${characters.slice(0, max - 1).join("")}…` : value;
}

function counts(value: AutoModeCounts | undefined): AutoModeCounts {
  // Rebuild exactly three counters so arbitrary stored/transport keys never leak.
  return { allow: value?.allow ?? 0, ask: value?.ask ?? 0, deny: value?.deny ?? 0 };
}

export interface StatusSnapshotInput {
  enabled: boolean;
  mode: AutoModeMode;
  configError?: string;
  errorKind?: AutoModeErrorKind;
  reviewTimeoutMs: number;
  sessionID?: string;
  /** Today's audit counts, supplied by the server rather than accumulated in UI memory. */
  counts?: AutoModeCounts;
  breaker?: boolean;
}

export interface StatusTracker {
  start(sessionID: string, reviewID: string, at: number): void;
  finish(decision: AutoModeDecision): AutoModeDecision;
  snapshot(input: StatusSnapshotInput): AutoModeStatus;
}

/** Bounded active-review tracking. Finished decisions are not retained. */
export function createStatusTracker(): StatusTracker {
  const reviewing = new Map<string, { sessionID: string; startedAt: number }>();

  return {
    start(sessionID, reviewID, at) {
      if (reviewing.size >= MAX_STATUS_REVIEWING && !reviewing.has(reviewID)) {
        const oldest = reviewing.keys().next().value;
        if (oldest !== undefined) reviewing.delete(oldest);
      }
      reviewing.set(reviewID, { sessionID, startedAt: at });
    },
    finish(decision) {
      reviewing.delete(decision.reviewID);
      // Return only the bounded live-decision surface; never retain arbitrary
      // record fields such as removed rule or shadow metadata.
      return {
        reviewID: decision.reviewID,
        sessionID: decision.sessionID,
        action: clip(decision.action, MAX_STATUS_ACTION_CHARS),
        decision: clip(decision.decision, MAX_STATUS_STAGE_CHARS),
        stage: clip(decision.stage, MAX_STATUS_STAGE_CHARS),
        reason: clip(decision.reason),
        durationMs: decision.durationMs,
        at: decision.at,
        ...(decision.errorKind === undefined ? {} : { errorKind: clip(decision.errorKind, MAX_STATUS_STAGE_CHARS) }),
      };
    },
    snapshot(input) {
      return {
        enabled: input.enabled,
        mode: input.mode,
        ...(input.configError === undefined ? {} : { configError: clip(input.configError) }),
        ...(input.errorKind === undefined ? {} : { errorKind: input.errorKind }),
        reviewTimeoutMs: input.reviewTimeoutMs,
        reviewing: [...reviewing.entries()]
          .filter(([, entry]) => input.sessionID === undefined || entry.sessionID === input.sessionID)
          .map(([reviewID, entry]) => ({ sessionID: entry.sessionID, reviewID, startedAt: entry.startedAt })),
        counts: counts(input.counts),
        ...(input.breaker === undefined ? {} : { breaker: input.breaker }),
      };
    },
  };
}
