import type { AutoModeDecision, AutoModeStatus } from "./rpc.js";

/**
 * The routed session as status polling sees it. The RPC client reads the app's
 * own server, so a session on another server has no status to show here, and
 * the selection key must carry the server: two servers can use the same
 * session id.
 */
export interface StatusTarget {
  /** `${server id}\n${session id}`: unique across servers. */
  key: string;
  /** The session id on its own server, the id the status RPC takes. */
  sessionID: string;
  /** Whether the session runs on the app's own server, the one the client reads. */
  ownServer: boolean;
}

/** The session identity the status client needs; the desktop's mounted session satisfies it. */
export interface RoutedSession {
  /** `${server id}\n${session id}`: unique across servers. */
  readonly key: string;
  /** The session's id on its server. */
  readonly id: string;
  /** The session's server. */
  readonly server: { readonly builtin: boolean };
}

/** The status target of a routed session, or undefined while none is routed. */
export function statusTarget(session: RoutedSession | undefined): StatusTarget | undefined {
  return session === undefined
    ? undefined
    : { key: session.key, sessionID: session.id, ownServer: session.server.builtin };
}

/**
 * Guards the desktop app's status snapshot against slow responses. A status
 * request can outlive the session it was made for: a poll for session A can
 * settle after the user routed B, and two polls for one session can settle out
 * of order. The guard numbers requests, invalidates every request made before
 * a selection change, and advances a watermark as responses are accepted, so
 * only the newest response for the selection that is still routed reaches the
 * panel and the pill. Issuing a request never invalidates an earlier response:
 * a poll that takes longer than the polling interval still describes the
 * session it settles for.
 */
export interface StatusGuard {
  /** Follow a selection key; true when the snapshot belongs to an earlier selection. */
  select(key: string | undefined): boolean;
  /** Number a request; undefined when the selection is no longer routed. */
  begin(key: string): number | undefined;
  /** Whether a response is newer than every response already accepted for this selection. */
  accept(token: number): boolean;
}

export function createStatusGuard(): StatusGuard {
  let selected: string | undefined;
  let issued = 0;
  // Highest token issued before the current selection: every token at or below
  // it belongs to a request for an earlier selection, including one the user
  // routed away from and back to.
  let invalidated = 0;
  // Highest token whose response was accepted for the current selection.
  let accepted = 0;

  return {
    select(key) {
      if (key === selected) return false;
      selected = key;
      // Responses to requests for the previous selection are now stale.
      invalidated = issued;
      accepted = 0;
      return true;
    },
    begin(key) {
      if (key !== selected) return undefined;
      return ++issued;
    },
    accept(token) {
      // A response is accepted unless a newer one for this selection already
      // was; accepting it advances the watermark past every older request.
      if (token <= invalidated || token <= accepted) return false;
      accepted = token;
      return true;
    },
  };
}

/** Reads the status of one session, as the RPC client does. */
export type StatusSource = (sessionID: string) => Promise<AutoModeStatus | undefined>;

/**
 * Builds the refresh the desktop app polls with. Switching selections discards
 * the previous snapshot before the next request starts, so a failed request
 * for the new session cannot leave the old session's decisions on screen. A
 * failed request for the current session keeps its last snapshot, so a server
 * restart does not flash an empty panel.
 *
 * A session on another server is never requested: the client reads the app's
 * own server, and the same session id there is a different session.
 */
export function createStatusLoader(
  load: StatusSource,
  apply: (next: AutoModeStatus | undefined) => void,
): (target: StatusTarget | undefined) => Promise<void> {
  const guard = createStatusGuard();

  return async (target) => {
    if (guard.select(target?.key)) apply(undefined);
    if (target === undefined || !target.ownServer) return;
    const token = guard.begin(target.key);
    if (token === undefined) return;
    try {
      const next = await load(target.sessionID);
      if (guard.accept(token)) apply(next);
    } catch {
      // The server may be restarting; the next poll refreshes this session.
    }
  };
}

export function latest(status: AutoModeStatus | undefined): AutoModeDecision | undefined {
  return status?.recent.at(-1);
}

/**
 * What the decisions panel lists for a snapshot. A defined snapshot with
 * nothing reviewing and no decisions yet is still the normal new-session case,
 * so it shows the empty state rather than a blank panel.
 */
export function panelView(status: AutoModeStatus | undefined): "empty" | "entries" {
  return status === undefined || (status.reviewing.length === 0 && status.recent.length === 0)
    ? "empty"
    : "entries";
}

export function pillLabel(status: AutoModeStatus | undefined): string | undefined {
  if (status === undefined) return undefined;
  if (status.reviewing.length > 0) return "auto-mode reviewing…";
  const last = latest(status);
  if (last === undefined) return undefined;
  if (last.errorKind !== undefined) return `auto-mode ${last.decision}: ${last.errorKind}`;
  return `auto-mode ${last.decision}`;
}

/**
 * Whether the pill's notice for the latest decision has expired. A review in
 * progress is always shown; a finished decision stays visible for `noticeMs`
 * after it was recorded.
 *
 * `now` must come from a clock the caller reads reactively and advances on
 * every polling tick, including failed ones: the status loader keeps its
 * previous snapshot when a request fails without applying it, so a notice
 * expired against wall-clock time read only on snapshot changes would never
 * disappear while the server is unreachable.
 */
export function noticeExpired(status: AutoModeStatus | undefined, now: number, noticeMs: number): boolean {
  if (status === undefined || status.reviewing.length > 0) return false;
  const last = latest(status);
  return last !== undefined && now - last.at > noticeMs;
}
