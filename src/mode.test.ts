import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createModeStore, type ModeState } from "./mode.js";

function fixture() {
  const data = new Map<string, ModeState>();
  const storage = { get: async (key: string) => structuredClone(data.get(key)), set: async (key: string, value: ModeState) => { data.set(key, structuredClone(value)); } };
  return { data, storage };
}
const breaker = { consecutiveDenies: 3, windowDenies: 10, windowSize: 50 };
describe("durable session mode", () => {
  it("defaults on, survives reload, and explicitly inherits a parent", async () => {
    const { storage } = fixture();
    const parent = async (id: string) => id === "child" ? "primary" : undefined;
    const mode = createModeStore(storage, parent);
    assert.equal((await mode.get("primary")).mode, "on");
    await mode.set("primary", "off");
    assert.equal((await createModeStore(storage, parent).get("primary")).mode, "off");
    assert.equal((await mode.get("child")).mode, "off");
    await mode.set("child", "on");
    assert.equal((await mode.get("primary")).mode, "off");
  });
  it("serializes concurrent counters and pauses conservatively", async () => {
    const { storage } = fixture();
    const mode = createModeStore(storage, async () => undefined);
    const outcomes = await Promise.all(Array.from({ length: 6 }, () => mode.finish("one", "deny", breaker, () => false)));
    assert.deepEqual(outcomes.map((v) => v.decision), ["deny", "deny", "deny", "ask", "ask", "ask"]);
    assert.deepEqual(outcomes.map((v) => v.disposition), ["enforced", "enforced", "enforced", "paused", "paused", "paused"]);
    const state = await mode.get("one");
    assert.equal(state.mode, "paused");
    assert.deepEqual(state.counts, { allow: 0, deny: 3, ask: 3 });
    await mode.set("one", "on");
    assert.equal((await mode.get("one")).consecutiveDenies, 0);
  });
  it("resets counts when the stored decision day changes", async () => {
    const { data, storage } = fixture();
    const mode = createModeStore(storage, async () => undefined);
    const state = await mode.get("one");
    data.set("mode:one", { ...state, day: "2000-01-01", counts: { allow: 9, ask: 8, deny: 7 } });
    const outcome = await mode.finish("one", "allow", breaker);
    assert.equal(outcome.disposition, "enforced");
    assert.deepEqual((await mode.get("one")).counts, { allow: 1, ask: 0, deny: 0 });
  });
  it("normalizes and persists today's zero counts before returning a stale day", async () => {
    const { data, storage } = fixture();
    const mode = createModeStore(storage, async () => undefined);
    const state = await mode.get("one");
    data.set("mode:one", { ...state, day: "2000-01-01", counts: { allow: 9, ask: 8, deny: 7 } });
    const loaded = await mode.get("one");
    assert.deepEqual(loaded.counts, { allow: 0, ask: 0, deny: 0 });
    assert.equal(loaded.day, new Date().toISOString().slice(0, 10));
    assert.deepEqual(data.get("mode:one")!.counts, { allow: 0, ask: 0, deny: 0 });
    assert.equal(data.get("mode:one")!.day, loaded.day);
  });
  it("rebuilds stored counts as exactly allow, ask and deny", async () => {
    const { data, storage } = fixture();
    const mode = createModeStore(storage, async () => undefined);
    const state = await mode.get("one");
    data.set("mode:one", { ...state, counts: { allow: 1, ask: 2, deny: 3, arbitrary: 99 } as never });
    const loaded = await mode.get("one");
    assert.deepEqual(loaded.counts, { allow: 1, ask: 2, deny: 3 });
    assert.deepEqual((data.get("mode:one") as unknown as { counts: unknown }).counts, { allow: 1, ask: 2, deny: 3 });
  });
  it("trips a rolling window and resets consecutive denies after allows", async () => {
    const { storage } = fixture();
    const mode = createModeStore(storage, async () => undefined);
    const limit = { consecutiveDenies: 3, windowDenies: 2, windowSize: 3 };
    await mode.finish("one", "deny", limit, () => false);
    await mode.finish("one", "allow", limit, () => false);
    assert.equal((await mode.get("one")).consecutiveDenies, 0);
    assert.equal((await mode.finish("one", "deny", limit, () => false)).tripped, true);
  });
  it("cancellation never enforces a verdict or trips the breaker", async () => {
    const { storage } = fixture();
    const mode = createModeStore(storage, async () => undefined);
    for (let i = 0; i < 5; i++) {
      const cancelled = await mode.finish("one", "deny", breaker, () => true);
      assert.equal(cancelled.decision, "ask");
      assert.equal(cancelled.disposition, "cancelled");
    }
    assert.equal((await mode.get("one")).mode, "on");
    assert.equal((await mode.get("one")).counts.deny, 0);
  });
  it("explicit off is a no-count passthrough, while paused asks", async () => {
    const { storage } = fixture();
    const mode = createModeStore(storage, async () => undefined);
    const off = await mode.finish("one", "allow", breaker, () => false, () => true);
    assert.deepEqual(off, { decision: "ask", tripped: false, disposition: "off" });
    assert.deepEqual((await mode.get("one")).counts, { allow: 0, ask: 0, deny: 0 });
    await mode.set("one", "off");
    const storedOff = await mode.finish("one", "deny", breaker);
    assert.equal(storedOff.disposition, "off");
    assert.deepEqual((await mode.get("one")).counts, { allow: 0, ask: 0, deny: 0 });
    await mode.set("one", "on");
    const state = (await mode.get("one")) as ModeState;
    state.mode = "paused";
    await storage.set("mode:one", state);
    const paused = await mode.finish("one", "allow", breaker);
    assert.equal(paused.decision, "ask"); assert.equal(paused.disposition, "paused");
    assert.deepEqual((await mode.get("one")).counts, { allow: 0, ask: 1, deny: 0 });
  });
  it("repairs counts and breaker when cancelled during a durable commit", async () => {
    for (const proposed of ["allow", "deny"] as const) {
      const { storage } = fixture();
      const mode = createModeStore(storage, async () => undefined);
      await mode.get("one");
      const save = storage.set;
      let release!: () => void;
      let writing!: () => void;
      const entered = new Promise<void>((resolve) => { writing = resolve; });
      storage.set = async (key, state) => {
        if (state.counts[proposed] > 0) {
          writing();
          await new Promise<void>((resolve) => { release = resolve; });
        }
        await save(key, state);
      };
      let cancelled = false;
      const pending = mode.finish("one", proposed, { consecutiveDenies: 1, windowDenies: 1, windowSize: 1 }, () => cancelled);
      await entered; cancelled = true; release();
      const result = await pending;
      assert.equal(result.decision, "ask"); assert.equal(result.tripped, false);
      assert.equal(result.disposition, "cancelled");
      assert.deepEqual((await mode.get("one")).counts, { allow: 0, deny: 0, ask: 1 });
      assert.equal((await mode.get("one")).mode, "on");
    }
  });
  it("explicit off during a durable commit restores the pre-review counts", async () => {
    for (const proposed of ["allow", "deny"] as const) {
      const { storage } = fixture();
      const mode = createModeStore(storage, async () => undefined);
      await mode.get("one");
      const save = storage.set;
      let release!: () => void;
      let writing!: () => void;
      const entered = new Promise<void>((resolve) => { writing = resolve; });
      storage.set = async (key, state) => {
        if (state.counts[proposed] > 0) {
          writing();
          await new Promise<void>((resolve) => { release = resolve; });
        }
        await save(key, state);
      };
      let off = false;
      const pending = mode.finish("one", proposed, { consecutiveDenies: 1, windowDenies: 1, windowSize: 1 },
        () => false, () => off);
      await entered; off = true; release();
      const result = await pending;
      assert.deepEqual(result, { decision: "ask", tripped: false, disposition: "off" });
      assert.deepEqual((await mode.get("one")).counts, { allow: 0, deny: 0, ask: 0 });
      assert.equal((await mode.get("one")).mode, "on");
    }
  });
  it("repairs an enforced verdict observed as cancelled after the durable commit", async () => {
    for (const proposed of ["allow", "deny"] as const) {
      const { storage } = fixture();
      const mode = createModeStore(storage, async () => undefined);
      const outcome = await mode.finish("one", proposed, { consecutiveDenies: 1, windowDenies: 1, windowSize: 1 });
      assert.equal(outcome.disposition, "enforced");
      assert.equal(outcome.tripped, proposed === "deny");
      assert.ok(outcome.commit);
      await mode.revertCancelled("one", outcome, "cancelled");
      const state = await mode.get("one");
      assert.deepEqual(state.counts, { allow: 0, ask: 1, deny: 0 });
      assert.equal(state.mode, "on");
      assert.equal(state.consecutiveDenies, 0);
      assert.deepEqual(state.window, []);
      await mode.revertCancelled("one", outcome, "cancelled");
      assert.deepEqual((await mode.get("one")).counts, { allow: 0, ask: 1, deny: 0 });
    }
  });
  it("a delayed repair of an older deny cannot clear a newer breaker trip", async () => {
    const { storage } = fixture();
    const mode = createModeStore(storage, async () => undefined);
    const limit = { consecutiveDenies: 1, windowDenies: 1, windowSize: 1 };
    const older = await mode.finish("one", "deny", limit);
    assert.equal(older.tripped, true);
    await mode.set("one", "on");
    const newer = await mode.finish("one", "deny", limit);
    assert.equal(newer.tripped, true);
    await mode.revertCancelled("one", older, "cancelled");
    const state = await mode.get("one");
    assert.equal(state.mode, "paused");
    assert.equal(state.consecutiveDenies, 1);
    assert.deepEqual(state.window, [true]);
    assert.deepEqual(state.counts, { allow: 0, ask: 1, deny: 1 });
  });
  it("keeps a newer breaker trip when a stale day hides its additional counts", async () => {
    const { data, storage } = fixture();
    const mode = createModeStore(storage, async () => undefined);
    const limit = { consecutiveDenies: 3, windowDenies: 100, windowSize: 50 };
    for (let index = 0; index < 2; index++) await mode.finish("one", "deny", limit);
    const older = await mode.finish("one", "deny", limit);
    assert.equal(older.tripped, true);
    await mode.set("one", "on");
    for (let index = 0; index < 2; index++) await mode.finish("one", "deny", limit);
    const newer = await mode.finish("one", "deny", limit);
    assert.equal(newer.tripped, true);
    data.set("mode:one", { ...structuredClone(data.get("mode:one")!), day: "2000-01-01" });
    await mode.revertCancelled("one", older, "cancelled");
    const stored = data.get("mode:one")!;
    assert.equal(stored.mode, "paused");
    assert.equal(stored.consecutiveDenies, 3);
    assert.deepEqual(stored.window, [true, true, true]);
    assert.deepEqual(stored.counts, { allow: 0, ask: 1, deny: 0 });
  });
  it("normalizes a stale day before repairing a cancellation across midnight", async () => {
    const { data, storage } = fixture();
    const mode = createModeStore(storage, async () => undefined);
    const outcome = await mode.finish("one", "deny", breaker);
    assert.ok(outcome.commit);
    data.set("mode:one", { ...structuredClone(data.get("mode:one")!), day: "2000-01-01", counts: { allow: 9, ask: 8, deny: 7 } });
    await mode.revertCancelled("one", outcome, "cancelled");
    const stored = data.get("mode:one")!;
    assert.equal(stored.day, new Date().toISOString().slice(0, 10));
    assert.deepEqual(stored.counts, { allow: 0, ask: 1, deny: 0 });
  });
  it("restores pre-review breaker fields when a stale day is normalized before repair", async () => {
    const { data, storage } = fixture();
    const mode = createModeStore(storage, async () => undefined);
    const state = await mode.get("one");
    data.set("mode:one", { ...state, consecutiveDenies: 2, window: [true, true] });
    const outcome = await mode.finish("one", "deny", { consecutiveDenies: 3, windowDenies: 100, windowSize: 50 });
    assert.equal(outcome.tripped, true);
    const committed = structuredClone(data.get("mode:one")!);
    assert.equal(committed.mode, "paused");
    data.set("mode:one", { ...committed, day: "2000-01-01" });
    await mode.revertCancelled("one", outcome, "cancelled");
    const stored = data.get("mode:one")!;
    assert.equal(stored.day, new Date().toISOString().slice(0, 10));
    assert.equal(stored.mode, "on");
    assert.equal(stored.consecutiveDenies, 2);
    assert.deepEqual(stored.window, [true, true]);
    assert.deepEqual(stored.counts, { allow: 0, ask: 1, deny: 0 });
  });
  it("restores the exact pre-review state when off arrives after the durable commit", async () => {
    const { data, storage } = fixture();
    const mode = createModeStore(storage, async () => undefined);
    const state = await mode.get("one");
    data.set("mode:one", { ...state, counts: { allow: 4, ask: 2, deny: 1 }, consecutiveDenies: 2, window: [true, false, true] });
    const before = (await mode.get("one")) as ModeState;
    const outcome = await mode.finish("one", "deny", { consecutiveDenies: 1, windowDenies: 1, windowSize: 1 });
    assert.equal(outcome.disposition, "enforced");
    assert.equal((await mode.get("one")).mode, "paused");
    await mode.revertCancelled("one", outcome, "off");
    const restored = await mode.get("one");
    assert.deepEqual(restored.counts, before.counts);
    assert.equal(restored.mode, before.mode);
    assert.equal(restored.consecutiveDenies, before.consecutiveDenies);
    assert.deepEqual(restored.window, before.window);
  });
  it("fails on invalid storage and cyclic ancestry without poisoning its queue", async () => {
    const { data, storage } = fixture();
    const mode = createModeStore(storage, async () => undefined);
    data.set("mode:one", {} as ModeState);
    await assert.rejects(mode.get("one"), /Invalid/);
    data.delete("mode:one");
    assert.equal((await mode.get("one")).mode, "on");
    const cyclic = createModeStore(storage, async (id) => id === "a" ? "b" : id === "b" ? "a" : undefined);
    let timer!: ReturnType<typeof setTimeout>;
    const deadline = new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("cycle deadlocked")), 1_000); timer.unref(); });
    const outcomes = await Promise.race([Promise.allSettled([cyclic.get("a"), cyclic.get("b")]), deadline]).finally(() => clearTimeout(timer));
    assert.ok(outcomes.every((outcome) => outcome.status === "rejected" && /parent chain/.test(String(outcome.reason))));
    assert.equal((await cyclic.get("healthy")).mode, "on");
    data.set("mode:a", await cyclic.get("healthy"));
    assert.equal((await cyclic.get("a")).mode, "on");
  });
});
