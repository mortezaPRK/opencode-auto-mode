import type { BreakerOptions } from "./config.js";

export type SessionMode = "on" | "off" | "paused";
export type Counts = { allow: number; ask: number; deny: number };
export type ModeState = {
  mode: SessionMode;
  consecutiveDenies: number;
  window: boolean[];
  counts: Counts;
  day: string;
};
export interface ModeStorage {
  get(key: string): Promise<unknown>;
  set(key: string, value: ModeState): Promise<void>;
}
export type FinishDisposition = "enforced" | "off" | "paused" | "cancelled";
/** Exact durable pre/post state for repairing a verdict that lost a cancellation race. */
export interface FinishCommit {
  before: ModeState;
  after: ModeState;
  counted: keyof Counts;
  tripped: boolean;
  reverted?: boolean;
}
export interface FinishOutcome {
  decision: "allow" | "ask" | "deny";
  tripped: boolean;
  /** Why the host effect was or was not replaced by the proposal. */
  disposition: FinishDisposition;
  /** Present for any counted verdict that may need a post-commit repair. */
  commit?: FinishCommit;
}

const zeroCounts = (): Counts => ({ allow: 0, ask: 0, deny: 0 });
const today = () => new Date().toISOString().slice(0, 10);

function fresh(mode: SessionMode = "on"): ModeState {
  return { mode, consecutiveDenies: 0, window: [], counts: zeroCounts(), day: today() };
}
function copyState(state: ModeState): ModeState {
  return {
    mode: state.mode,
    consecutiveDenies: state.consecutiveDenies,
    window: [...state.window],
    counts: { allow: state.counts.allow, ask: state.counts.ask, deny: state.counts.deny },
    day: state.day,
  };
}
function sameCounts(left: Counts, right: Counts): boolean {
  return left.allow === right.allow && left.ask === right.ask && left.deny === right.deny;
}
function sameState(left: ModeState, right: ModeState): boolean {
  return left.mode === right.mode && left.consecutiveDenies === right.consecutiveDenies &&
    left.day === right.day && sameCounts(left.counts, right.counts) &&
    left.window.length === right.window.length && left.window.every((value, index) => value === right.window[index]);
}
function validate(value: unknown): ModeState {
  if (!value || typeof value !== "object") throw new Error("Invalid auto-mode session state");
  const state = value as ModeState;
  const integer = (n: unknown) => Number.isSafeInteger(n) && (n as number) >= 0;
  if (!["on", "off", "paused"].includes(state.mode) || !integer(state.consecutiveDenies) ||
      !Array.isArray(state.window) || state.window.length > 10_000 || state.window.some((v) => typeof v !== "boolean") ||
      !state.counts || ![state.counts.allow, state.counts.ask, state.counts.deny].every(integer) ||
      typeof state.day !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(state.day)) throw new Error("Invalid auto-mode session state");
  // Rebuild exact fields: never retain arbitrary/legacy keys from storage.
  return { mode: state.mode, consecutiveDenies: state.consecutiveDenies, window: [...state.window],
    counts: { allow: state.counts.allow, ask: state.counts.ask, deny: state.counts.deny }, day: state.day };
}

/** Durable state; all reads/updates for one session share a queue, not a stale cache. */
export function createModeStore(storage: ModeStorage, parent: (sessionID: string) => Promise<string | undefined>) {
  const queues = new Map<string, Promise<unknown>>();
  function serial<T>(sessionID: string, work: () => Promise<T>): Promise<T> {
    const previous = queues.get(sessionID) ?? Promise.resolve();
    const next = previous.catch(() => {}).then(work);
    queues.set(sessionID, next);
    void next.finally(() => { if (queues.get(sessionID) === next) queues.delete(sessionID); }).catch(() => {});
    return next;
  }
  const key = (id: string) => `mode:${id}`;
  /** Queue-local read that also persists day rollover and canonical counts. */
  async function read(id: string): Promise<ModeState | undefined> {
    const stored = await storage.get(key(id));
    if (stored === undefined) return undefined;
    const state = validate(stored);
    const current = today();
    const canonical = state.day === current ? state : { ...state, day: current, counts: zeroCounts() };
    if (JSON.stringify(stored) !== JSON.stringify(canonical)) await storage.set(key(id), canonical);
    return canonical;
  }
  async function load(id: string, ancestors: string[] = []): Promise<ModeState> {
    if (ancestors.includes(id) || ancestors.length >= 32) throw new Error("Invalid session parent chain");
    const existing = await serial(id, () => read(id));
    if (existing !== undefined) return existing;
    // Do not hold the child's lock across parent lookup: two concurrent
    // cyclic/hostile chains must reject, rather than deadlocking each other.
    const parentID = await parent(id);
    const inherited = parentID === undefined ? "on" : (await load(parentID, [...ancestors, id])).mode;
    return serial(id, async () => {
      const stored = await read(id);
      if (stored !== undefined) return stored;
      const state = fresh(inherited);
      await storage.set(key(id), state);
      return state;
    });
  }
  async function update<T>(id: string, work: (state: ModeState) => T, reconcile?: (state: ModeState, result: T) => T | undefined): Promise<T> {
    await load(id);
    return serial(id, async () => {
      const state = validate(await storage.get(key(id)));
      const current = today();
      if (state.day !== current) { state.day = current; state.counts = zeroCounts(); }
      let result = work(state);
      await storage.set(key(id), state);
      // A durable write is an await boundary: off/interruption may arrive while
      // the backend is committing. Repair the unenforced verdict under this
      // same lock before exposing its counts to another decision.
      const corrected = reconcile?.(state, result);
      if (corrected !== undefined) {
        result = corrected;
        await storage.set(key(id), state);
      }
      return result;
    });
  }
  return {
    get: load,
    set: (id: string, mode: "on" | "off") => update(id, (state) => {
      state.mode = mode;
      if (mode === "on") { state.consecutiveDenies = 0; state.window = []; }
      return state;
    }),
    /** Checks current mode and cancellation inside the same serialized commit.
     * `cancelled` covers interruption/deadline/unload; `explicitOff` is separate
     * because an explicit off is a native passthrough, not a failed review. */
    finish: (id: string, proposed: "allow" | "ask" | "deny", breaker: BreakerOptions,
      cancelled: () => boolean = () => false, explicitOff: () => boolean = () => false): Promise<FinishOutcome> => {
      type FinishResult = { decision: "allow" | "ask" | "deny"; tripped: boolean; disposition: FinishDisposition; commit?: FinishCommit };
      let before!: ModeState;
      const operation = update<FinishResult>(id, (state): FinishResult => {
        before = copyState(state);
        // Explicit off (or an already-persisted off) returns control to the host
        // without counting a review that was cancelled by that off.
        if (explicitOff() || state.mode === "off")
          return { decision: "ask", tripped: false, disposition: "off" };
        const interrupted = cancelled();
        const decision = interrupted || state.mode !== "on" ? "ask" : proposed;
        const disposition: FinishDisposition = interrupted ? "cancelled" :
          state.mode !== "on" ? "paused" : "enforced";
        state.counts[decision]++;
        let tripped = false;
        // A review that was not enforced cannot freeze the session.
        if (state.mode === "on") {
          state.consecutiveDenies = decision === "deny" ? state.consecutiveDenies + 1 : 0;
          state.window = [...state.window, decision === "deny"].slice(-breaker.windowSize);
          if (state.consecutiveDenies >= breaker.consecutiveDenies || state.window.filter(Boolean).length >= breaker.windowDenies) {
            state.mode = "paused";
            tripped = true;
          }
        }
        const commit: FinishCommit = { before, after: copyState(state), counted: decision, tripped };
        return { decision, tripped, disposition, commit };
      }, (state, result) => {
        // A durable write is an await boundary: off/interruption may arrive while
        // the backend is committing. Explicit off restores the pre-review counts;
        // other cancellations fail closed and are counted as ask instead.
        if (result.disposition === "off") return undefined;
        if (explicitOff()) {
          state.counts = { ...before.counts };
          state.mode = before.mode;
          state.consecutiveDenies = before.consecutiveDenies;
          state.window = [...before.window];
          return { decision: "ask", tripped: false, disposition: "off" as const };
        }
        if (!cancelled() || result.decision === "ask") return undefined;
        state.counts[result.decision]--;
        state.counts.ask++;
        state.mode = before.mode;
        state.consecutiveDenies = before.consecutiveDenies;
        state.window = [...before.window];
        return { decision: "ask", tripped: false, disposition: "cancelled" as const };
      });
      return operation.then(({ decision, tripped, disposition, commit }) =>
        ({ decision, tripped, disposition, ...(commit === undefined ? {} : { commit }) }));
    },
    /** Repairs an enforced commit when the caller observes cancellation/off only
     * after the durable write. Serialized with later reviews; exact pre-state is
     * restored when no newer commit intervened. */
    revertCancelled: (id: string, outcome: FinishOutcome, stop: "cancelled" | "off"): Promise<void> =>
      serial(id, async () => {
        const commit = outcome.commit;
        if (outcome.disposition === "off" || commit === undefined || commit.reverted) return;
        const stored = validate(await storage.get(key(id)));
        // Normalize a rollover before comparing/repairing: yesterday's stored
        // counts must never be resurrected or decremented as today's.
        const currentDay = today();
        const rolled = stored.day !== currentDay;
        const current = rolled ? { ...stored, day: currentDay, counts: zeroCounts() } : stored;
        if (sameState(current, commit.after)) {
          const restored = copyState(commit.before);
          restored.day = current.day;
          if (stop === "cancelled") restored.counts.ask++;
          await storage.set(key(id), restored);
        } else {
          // A newer review committed first, or rollover reset today's counts.
          // Undo only this review's contribution.
          if (stop === "cancelled") {
            if (commit.counted !== "ask") {
              current.counts[commit.counted] = Math.max(0, current.counts[commit.counted] - 1);
              current.counts.ask++;
            } else if (rolled) {
              // The committed ask was erased by the day reset; count the cancellation today.
              current.counts.ask++;
            }
          } else {
            current.counts[commit.counted] = Math.max(0, current.counts[commit.counted] - 1);
          }
          // A stale stored day means no review committed today. Restore the
          // pre-review breaker state only when the raw pre-normalization counts
          // also match the commit: otherwise an identical-shaped newer trip on
          // the stale day would be erased. Never resurrect prior-day counts.
          if (rolled && sameBreaker(current, commit.after) && sameCounts(stored.counts, commit.after.counts)) {
            current.mode = commit.before.mode;
            current.consecutiveDenies = commit.before.consecutiveDenies;
            current.window = [...commit.before.window];
          }
          await storage.set(key(id), current);
        }
        commit.reverted = true;
      }),
  };
}

function sameBreaker(left: ModeState, right: ModeState): boolean {
  return left.mode === right.mode && left.consecutiveDenies === right.consecutiveDenies &&
    left.window.length === right.window.length && left.window.every((value, index) => value === right.window[index]);
}
