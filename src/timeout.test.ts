import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { ReviewFailure } from "./errors.js";
import { withTimeout } from "./timeout.js";

const never = () => new Promise<never>(() => {});
const isCancelled = (error: unknown) => error instanceof ReviewFailure && error.kind === "cancelled";

describe("bounded provider calls", () => {
  it("rejects when the signal aborts and clears its timer", async () => {
    const originalSet = globalThis.setTimeout;
    const originalClear = globalThis.clearTimeout;
    const created: { handle: ReturnType<typeof setTimeout>; ms?: number }[] = [];
    const cleared = new Set<ReturnType<typeof setTimeout>>();
    globalThis.setTimeout = ((handler: () => void, ms?: number, ...args: unknown[]) => {
      const schedule = originalSet as unknown as (callback: () => void, timeout?: number, ...rest: unknown[]) => ReturnType<typeof setTimeout>;
      const handle = schedule(handler, ms, ...args);
      created.push({ handle, ms });
      return handle;
    }) as unknown as typeof globalThis.setTimeout;
    globalThis.clearTimeout = ((handle?: ReturnType<typeof setTimeout>) => {
      if (handle !== undefined) cleared.add(handle);
      originalClear(handle);
    }) as typeof globalThis.clearTimeout;
    try {
      const controller = new AbortController();
      const pending = withTimeout(never(), 30_000, controller.signal);
      controller.abort();
      await assert.rejects(pending, isCancelled);
      const providerTimer = created.find((timer) => timer.ms === 30_000);
      assert.ok(providerTimer, "the provider call must arm its timeout");
      assert.ok(cleared.has(providerTimer.handle), "aborting must clear the pending timeout");
    } finally {
      globalThis.setTimeout = originalSet;
      globalThis.clearTimeout = originalClear;
    }
  });
  it("rejects immediately when the signal is already aborted", async () => {
    const startedAt = Date.now();
    await assert.rejects(withTimeout(never(), 30_000, AbortSignal.abort()), isCancelled);
    assert.ok(Date.now() - startedAt < 250);
  });
  it("consumes an already-rejected provider promise when the signal is aborted", async () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => { unhandled.push(reason); };
    process.on("unhandledRejection", onUnhandled);
    try {
      await assert.rejects(
        withTimeout(Promise.reject(new Error("provider failure")), 30_000, AbortSignal.abort()),
        isCancelled,
      );
      await new Promise((resolve) => setTimeout(resolve, 10));
      assert.deepEqual(unhandled, []);
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }
  });
});
