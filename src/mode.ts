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
function nonNegativeInteger(n: unknown): boolean {
  return Number.isSafeInteger(n) && (n as number) >= 0;
}
function validCounts(counts: Counts | null | undefined): boolean {
  return counts !== undefined && counts !== null &&
    [counts.allow, counts.ask, counts.deny].every(nonNegativeInteger);
}
function validState(state: ModeState): boolean {
  return ["on", "off", "paused"].includes(state.mode) && nonNegativeInteger(state.consecutiveDenies) &&
    Array.isArray(state.window) && state.window.length <= 10_000 && state.window.every((v) => typeof v === "boolean") &&
    validCounts(state.counts) && typeof state.day === "string" && /^\d{4}-\d{2}-\d{2}$/.test(state.day);
}
function validate(value: unknown): ModeState {
  if (!value || typeof value !== "object" || !validState(value as ModeState)) throw new Error("Invalid auto-mode session state");
  const state = value as ModeState;
  // Rebuild exact fields: never retain arbitrary/legacy keys from storage.
  return { mode: state.mode, consecutiveDenies: state.consecutiveDenies, window: [...state.window],
    counts: { allow: state.counts.allow, ask: state.counts.ask, deny: state.counts.deny }, day: state.day };
}

/** Durable state; all reads/updates for one session share a queue, not a stale cache. */
export function createModeStore(storage: ModeStorage, parent: (sessionID: string) => Promise<string | undefined>) {
  const ctx: ModeContext = { storage, parent, queues: new Map<string, Promise<unknown>>() };
  return {
    get: (id: string, ancestors: string[] = []) => loadState(ctx, id, ancestors),
    set: (id: string, mode: "on" | "off") => updateState(ctx, id, (state) => {
      state.mode = mode;
      if (mode === "on") { state.consecutiveDenies = 0; state.window = []; }
      return state;
    }),
    /** Checks current mode and cancellation inside the same serialized commit.
     * `cancelled` covers interruption/deadline/unload; `explicitOff` is separate
     * because an explicit off is a native passthrough, not a failed review. */
    finish: (id: string, proposed: FinalDecision, breaker: BreakerOptions,
      cancelled: () => boolean = () => false, explicitOff: () => boolean = () => false): Promise<FinishOutcome> =>
      finishReview(ctx, id, proposed, breaker, cancelled, explicitOff),
    /** Repairs an enforced commit when the caller observes cancellation/off only
     * after the durable write. Serialized with later reviews; exact pre-state is
     * restored when no newer commit intervened. */
    revertCancelled: (id: string, outcome: FinishOutcome, stop: "cancelled" | "off"): Promise<void> =>
      revertCommit(ctx, id, outcome, stop),
  };
}

/** Per-store handles shared by every operation on one session's state. */
interface ModeContext {
  storage: ModeStorage;
  parent: (sessionID: string) => Promise<string | undefined>;
  queues: Map<string, Promise<unknown>>;
}
type FinalDecision = "allow" | "ask" | "deny";
type FinishResult = { decision: FinalDecision; tripped: boolean; disposition: FinishDisposition; commit?: FinishCommit };

const modeKey = (id: string) => `mode:${id}`;

/** Serializes work for one session behind its queue entry. */
function serial<T>(ctx: ModeContext, sessionID: string, work: () => Promise<T>): Promise<T> {
  const previous = ctx.queues.get(sessionID) ?? Promise.resolve();
  const next = previous.catch(() => {}).then(work);
  ctx.queues.set(sessionID, next);
  void next.finally(() => { if (ctx.queues.get(sessionID) === next) ctx.queues.delete(sessionID); }).catch(() => {});
  return next;
}

/** Queue-local read that also persists day rollover and canonical counts. */
async function readState(ctx: ModeContext, id: string): Promise<ModeState | undefined> {
  const stored = await ctx.storage.get(modeKey(id));
  if (stored === undefined) return undefined;
  const state = validate(stored);
  const current = today();
  const canonical = state.day === current ? state : { ...state, day: current, counts: zeroCounts() };
  if (JSON.stringify(stored) !== JSON.stringify(canonical)) await ctx.storage.set(modeKey(id), canonical);
  return canonical;
}

async function loadState(ctx: ModeContext, id: string, ancestors: string[] = []): Promise<ModeState> {
  if (ancestors.includes(id) || ancestors.length >= 32) throw new Error("Invalid session parent chain");
  const existing = await serial(ctx, id, () => readState(ctx, id));
  if (existing !== undefined) return existing;
  // Do not hold the child's lock across parent lookup: two concurrent
  // cyclic/hostile chains must reject, rather than deadlocking each other.
  const parentID = await ctx.parent(id);
  const inherited = parentID === undefined ? "on" : (await loadState(ctx, parentID, [...ancestors, id])).mode;
  return serial(ctx, id, async () => {
    const stored = await readState(ctx, id);
    if (stored !== undefined) return stored;
    const state = fresh(inherited);
    await ctx.storage.set(modeKey(id), state);
    return state;
  });
}

async function updateState<T>(ctx: ModeContext, id: string, work: (state: ModeState) => T, reconcile?: (state: ModeState, result: T) => T | undefined): Promise<T> {
  await loadState(ctx, id);
  return serial(ctx, id, async () => {
    const state = validate(await ctx.storage.get(modeKey(id)));
    const current = today();
    if (state.day !== current) { state.day = current; state.counts = zeroCounts(); }
    let result = work(state);
    await ctx.storage.set(modeKey(id), state);
    // A durable write is an await boundary: off/interruption may arrive while
    // the backend is committing. Repair the unenforced verdict under this
    // same lock before exposing its counts to another decision.
    const corrected = reconcile?.(state, result);
    if (corrected !== undefined) {
      result = corrected;
      await ctx.storage.set(modeKey(id), state);
    }
    return result;
  });
}

/** Counts the verdict, applies the breaker and reports the durable commit. */
async function finishReview(ctx: ModeContext, id: string, proposed: FinalDecision, breaker: BreakerOptions,
  cancelled: () => boolean, explicitOff: () => boolean): Promise<FinishOutcome> {
  let before!: ModeState;
  const operation = updateState<FinishResult>(ctx, id, (state): FinishResult => {
    before = copyState(state);
    // Explicit off (or an already-persisted off) returns control to the host
    // without counting a review that was cancelled by that off.
    if (explicitOff() || state.mode === "off")
      return { decision: "ask", tripped: false, disposition: "off" };
    const interrupted = cancelled();
    const decision = interrupted || state.mode !== "on" ? "ask" : proposed;
    const disposition: FinishDisposition = interrupted ? "cancelled" : state.mode !== "on" ? "paused" : "enforced";
    state.counts[decision]++;
    const tripped = applyBreaker(state, decision, breaker);
    const commit: FinishCommit = { before, after: copyState(state), counted: decision, tripped };
    return { decision, tripped, disposition, commit };
  }, (state, result) => {
    // A durable write is an await boundary: off/interruption may arrive while
    // the backend is committing. Explicit off restores the pre-review counts;
    // other cancellations fail closed and are counted as ask instead.
    if (result.disposition === "off") return undefined;
    if (explicitOff()) {
      state.counts = { ...before.counts };
      restoreMode(state, before);
      return { decision: "ask", tripped: false, disposition: "off" as const };
    }
    if (!cancelled() || result.decision === "ask") return undefined;
    state.counts[result.decision]--;
    state.counts.ask++;
    restoreMode(state, before);
    return { decision: "ask", tripped: false, disposition: "cancelled" as const };
  });
  return operation.then(({ decision, tripped, disposition, commit }) =>
    ({ decision, tripped, disposition, ...(commit === undefined ? {} : { commit }) }));
}

/** Counts the verdict and pauses the session when the breaker trips. */
function applyBreaker(state: ModeState, decision: FinalDecision, breaker: BreakerOptions): boolean {
  // A review that was not enforced cannot freeze the session.
  if (state.mode !== "on") return false;
  state.consecutiveDenies = decision === "deny" ? state.consecutiveDenies + 1 : 0;
  state.window = [...state.window, decision === "deny"].slice(-breaker.windowSize);
  if (state.consecutiveDenies >= breaker.consecutiveDenies || state.window.filter(Boolean).length >= breaker.windowDenies) {
    state.mode = "paused";
    return true;
  }
  return false;
}

function restoreMode(state: ModeState, before: ModeState): void {
  state.mode = before.mode;
  state.consecutiveDenies = before.consecutiveDenies;
  state.window = [...before.window];
}

function decrement(counts: Counts, key: keyof Counts): void {
  counts[key] = Math.max(0, counts[key] - 1);
}

function revertCommit(ctx: ModeContext, id: string, outcome: FinishOutcome, stop: "cancelled" | "off"): Promise<void> {
  return serial(ctx, id, async () => {
    const commit = outcome.commit;
    if (outcome.disposition === "off" || commit === undefined || commit.reverted) return;
    const stored = validate(await ctx.storage.get(modeKey(id)));
    // Normalize a rollover before comparing/repairing: yesterday's stored
    // counts must never be resurrected or decremented as today's.
    const currentDay = today();
    const rolled = stored.day !== currentDay;
    const current = rolled ? { ...stored, day: currentDay, counts: zeroCounts() } : stored;
    if (sameState(current, commit.after)) {
      const restored = copyState(commit.before);
      restored.day = current.day;
      if (stop === "cancelled") restored.counts.ask++;
      await ctx.storage.set(modeKey(id), restored);
    } else {
      undoContribution(current, stored, commit, stop, rolled);
      await ctx.storage.set(modeKey(id), current);
    }
    commit.reverted = true;
  });
}

/** Undoes only this review's contribution when a newer commit or rollover intervened. */
function undoContribution(current: ModeState, stored: ModeState, commit: FinishCommit, stop: "cancelled" | "off", rolled: boolean): void {
  if (stop === "cancelled") {
    if (commit.counted !== "ask") {
      decrement(current.counts, commit.counted);
      current.counts.ask++;
    } else if (rolled) {
      // The committed ask was erased by the day reset; count the cancellation today.
      current.counts.ask++;
    }
  } else {
    decrement(current.counts, commit.counted);
  }
  // A stale stored day means no review committed today. Restore the
  // pre-review breaker state only when the raw pre-normalization counts
  // also match the commit: otherwise an identical-shaped newer trip on
  // the stale day would be erased. Never resurrect prior-day counts.
  if (rolled && sameBreaker(current, commit.after) && sameCounts(stored.counts, commit.after.counts)) {
    restoreMode(current, commit.before);
  }
}

function sameBreaker(left: ModeState, right: ModeState): boolean {
  return left.mode === right.mode && left.consecutiveDenies === right.consecutiveDenies &&
    left.window.length === right.window.length && left.window.every((value, index) => value === right.window[index]);
}
