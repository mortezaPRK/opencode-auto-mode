import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createRoot } from "solid-js";
import gui from "./gui.js";
import type { AutoModeStatus } from "./rpc.js";

const snapshot: AutoModeStatus = { enabled: true, mode: "on", reviewTimeoutMs: 1_000, reviewing: [], counts: { allow: 0, ask: 0, deny: 0 } };
const session = (id: string) => ({ key: `server:${id}`, id, server: { builtin: true }, location: { directory: `/scratch/${id}` } });
const tick = async () => { for (let index = 0; index < 12; index++) await Promise.resolve(); };

describe("GUI composer pill wiring (mock transport only)", () => {
  it("captures input.session, coalesces pending clicks, applies only authoritative replies and reports failures", async () => {
    let current = session("a");
    let pill!: { show(input: { session: ReturnType<typeof session> }): { label: string; title: string; run?: () => void } };
    const calls: { input: unknown; options: { location: unknown; signal: AbortSignal } }[] = [];
    const toasts: unknown[] = [];
    let resolve!: (value: AutoModeStatus) => void;
    let reject!: (error: Error) => void;
    const transport = {
      status: async () => snapshot,
      setMode: (input: unknown, options: { location: unknown; signal: AbortSignal }) => {
        calls.push({ input, options });
        return new Promise<AutoModeStatus>((yes, no) => { resolve = yes; reject = no; });
      },
      events: { on: () => () => {} },
    };
    let dispose!: () => void;
    createRoot((cleanup) => {
      dispose = cleanup;
      gui.setup!({ sessions: { current: () => current }, client: { rpc: () => transport },
        toast: { show: (notice: unknown) => toasts.push(notice) },
        add: (_registry: unknown, value: unknown) => { pill = value as typeof pill; },
      } as unknown as Parameters<NonNullable<typeof gui.setup>>[0]);
    });
    try {
      await tick();
      const first = pill.show({ session: current });
      assert.equal(first.label, "auto");
      assert.equal(first.title, "Auto-mode: off");
      assert.equal(typeof first.run, "function");
      current = session("b");
      first.run!(); first.run!();
      await tick();
      assert.equal(calls.length, 1);
      assert.deepEqual(calls[0].input, { sessionID: "a", mode: "off" });
      assert.deepEqual(calls[0].options.location, { directory: "/scratch/a" });
      assert.equal(pill.show({ session: session("a") }).label, "changing auto mode…");
      assert.equal(pill.show({ session: session("a") }).run, undefined);
      resolve({ ...snapshot, enabled: false, mode: "off" });
      await tick();
      // A's late mutation cannot mark B off.
      assert.equal(pill.show({ session: current }).label, "status unavailable");
      current = session("a");
      const retry = pill.show({ session: current });
      assert.equal(retry.label, "auto"); // No optimistic off update.
      retry.run!();
      await tick();
      reject(new Error("secret server configuration"));
      await tick();
      assert.equal(toasts.length, 1);
      assert.equal(JSON.stringify(toasts).includes("secret"), false);
      assert.equal(pill.show({ session: current }).label, "auto");
      const noLocation = { ...current, location: undefined };
      assert.equal(pill.show({ session: noLocation as unknown as ReturnType<typeof session> }).run, undefined);
      assert.equal(pill.show({ session: noLocation as unknown as ReturnType<typeof session> }).title, "Auto-mode unavailable");
      pill.show({ session: current }).run!();
      await tick();
      assert.equal(pill.show({ session: current }).label, "changing auto mode…");
      resolve({ ...snapshot, enabled: false, mode: "off" });
      await tick();
      assert.equal(pill.show({ session: current }).label, "off");
      assert.equal(pill.show({ session: current }).title, "Auto-mode: on");
      pill.show({ session: current }).run!();
      await tick();
      assert.deepEqual(calls.at(-1)!.input, { sessionID: "a", mode: "on" });
      dispose();
      assert.equal(calls.at(-1)!.options.signal.aborted, true);
      resolve({ ...snapshot, mode: "off" });
      await tick();
      assert.equal(toasts.length, 1);
    } finally { dispose(); }
  });

  it("shows storage failures as review unavailable instead of invalid configuration", async () => {
    const current = session("a");
    let pill!: { show(input: { session: ReturnType<typeof session> }): { label: string; title: string; tone?: string; run?: () => void } };
    const transport = {
      status: async (): Promise<AutoModeStatus> => ({ ...snapshot, enabled: false, mode: "invalid",
        configError: "Auto-mode session storage unavailable", errorKind: "storage" }),
      setMode: async () => snapshot,
      events: { on: () => () => {} },
    };
    let dispose!: () => void;
    createRoot((cleanup) => {
      dispose = cleanup;
      gui.setup!({ sessions: { current: () => current }, client: { rpc: () => transport },
        toast: { show: () => {} },
        add: (_registry: unknown, value: unknown) => { pill = value as typeof pill; },
      } as unknown as Parameters<NonNullable<typeof gui.setup>>[0]);
    });
    try {
      await tick();
      const shown = pill.show({ session: current });
      assert.equal(shown.label, "Review unavailable");
      assert.equal(shown.title, "Auto-mode: Review unavailable: Auto-mode session storage unavailable");
      assert.equal(shown.tone, "danger");
      assert.equal(shown.run, undefined);
    } finally { dispose(); }
  });
  it("shows invalid configuration as review disabled with its error instead of an on/off pill", async () => {
    const current = session("a");
    let pill!: { show(input: { session: ReturnType<typeof session> }): { label: string; title: string; tone?: string; run?: () => void } };
    const transport = {
      status: async (): Promise<AutoModeStatus> => ({ ...snapshot, enabled: false, mode: "invalid", configError: "Unknown classifier type 'mystery'", errorKind: "config" }),
      setMode: async () => snapshot,
      events: { on: () => () => {} },
    };
    let dispose!: () => void;
    createRoot((cleanup) => {
      dispose = cleanup;
      gui.setup!({ sessions: { current: () => current }, client: { rpc: () => transport },
        toast: { show: () => {} },
        add: (_registry: unknown, value: unknown) => { pill = value as typeof pill; },
      } as unknown as Parameters<NonNullable<typeof gui.setup>>[0]);
    });
    try {
      await tick();
      const shown = pill.show({ session: current });
      assert.equal(shown.label, "Invalid config — review disabled");
      assert.equal(shown.title, "Auto-mode: Invalid config — review disabled: Unknown classifier type 'mystery'");
      assert.equal(shown.tone, "danger");
      assert.equal(shown.run, undefined);
    } finally { dispose(); }
  });
});
