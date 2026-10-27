import type { AutoModeDecision, AutoModeStatus } from "./rpc.js";

/**
 * Guards the desktop app's status snapshot against slow responses. A status
 * request can outlive the session it was made for: a poll for session A can
 * settle after the user routed B, and two polls for one session can settle out
 * of order. The guard numbers requests so only the newest response for the
 * session that is still routed reaches the panel and the pill.
 */
export interface StatusGuard {
  /** Follow a routed session; true when the snapshot belongs to an earlier selection. */
  select(sessionID: string | undefined): boolean;
  /** Number a request; undefined when the session is no longer selected. */
  begin(sessionID: string): number | undefined;
  /** Whether a response is still the newest request for the selected session. */
  accept(token: number): boolean;
}

export function createStatusGuard(): StatusGuard {
  let selected: string | undefined;
  let issued = 0;
  let newest = 0;

  return {
    select(sessionID) {
      if (sessionID === selected) return false;
      selected = sessionID;
      // Responses to requests for the previous selection are now stale.
      newest = ++issued;
      return true;
    },
    begin(sessionID) {
      if (sessionID !== selected) return undefined;
      return (newest = ++issued);
    },
    accept(token) {
      return token === newest;
    },
  };
}

/** Reads the status of one session, as the RPC client does. */
export type StatusSource = (sessionID: string) => Promise<AutoModeStatus | undefined>;

/**
 * Builds the refresh the desktop app polls with. Switching sessions discards
 * the previous snapshot before the next request starts, so a failed request
 * for the new session cannot leave the old session's decisions on screen. A
 * failed request for the current session keeps its last snapshot, so a server
 * restart does not flash an empty panel.
 */
export function createStatusLoader(
  load: StatusSource,
  apply: (next: AutoModeStatus | undefined) => void,
): (sessionID: string | undefined) => Promise<void> {
  const guard = createStatusGuard();

  return async (sessionID) => {
    if (guard.select(sessionID)) apply(undefined);
    if (sessionID === undefined) return;
    const token = guard.begin(sessionID);
    if (token === undefined) return;
    try {
      const next = await load(sessionID);
      if (guard.accept(token)) apply(next);
    } catch {
      // The server may be restarting; the next poll refreshes this session.
    }
  };
}

export function latest(status: AutoModeStatus | undefined): AutoModeDecision | undefined {
  return status?.recent.at(-1);
}

export function pillLabel(status: AutoModeStatus | undefined): string | undefined {
  if (status === undefined) return undefined;
  if (status.reviewing.length > 0) return "auto-mode reviewing…";
  const last = latest(status);
  if (last === undefined) return undefined;
  if (last.errorKind !== undefined) return `auto-mode ${last.decision}: ${last.errorKind}`;
  return `auto-mode ${last.decision}`;
}
