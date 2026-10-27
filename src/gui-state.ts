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
 * of order. The guard numbers requests so only the newest response for the
 * selection that is still routed reaches the panel and the pill.
 */
export interface StatusGuard {
  /** Follow a selection key; true when the snapshot belongs to an earlier selection. */
  select(key: string | undefined): boolean;
  /** Number a request; undefined when the selection is no longer routed. */
  begin(key: string): number | undefined;
  /** Whether a response is still the newest request for the selection. */
  accept(token: number): boolean;
}

export function createStatusGuard(): StatusGuard {
  let selected: string | undefined;
  let issued = 0;
  let newest = 0;

  return {
    select(key) {
      if (key === selected) return false;
      selected = key;
      // Responses to requests for the previous selection are now stale.
      newest = ++issued;
      return true;
    },
    begin(key) {
      if (key !== selected) return undefined;
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

export function pillLabel(status: AutoModeStatus | undefined): string | undefined {
  if (status === undefined) return undefined;
  if (status.reviewing.length > 0) return "auto-mode reviewing…";
  const last = latest(status);
  if (last === undefined) return undefined;
  if (last.errorKind !== undefined) return `auto-mode ${last.decision}: ${last.errorKind}`;
  return `auto-mode ${last.decision}`;
}
