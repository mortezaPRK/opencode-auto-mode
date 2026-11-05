import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createDecisionNotifier, createDecisionSubscription, createModeRunner, createStatusLoader, pillAction, pillDescription, pillLabel, pillTone, statusLocationKey, statusTarget, type DecisionEvent, type ModeNotice, type StatusTarget } from "./gui-state.js";
import type { AutoModeStatus } from "./rpc.js";

function target(sessionID = "a", directory = "/project", ownServer = true): StatusTarget {
  return { key: JSON.stringify(["server", sessionID, directory]), sessionID, location: { directory }, ownServer };
}
function status(overrides: Partial<AutoModeStatus> = {}): AutoModeStatus {
  return { enabled: true, mode: "on", reviewTimeoutMs: 15_000, reviewing: [], counts: { allow: 0, ask: 0, deny: 0 }, ...overrides };
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const tick = () => Promise.resolve();

describe("status loader", () => {
  it("passes target location and abort signal and coalesces pending polls", async () => {
    const pending = deferred<AutoModeStatus>();
    const applied: (AutoModeStatus | undefined)[] = [];
    let calls = 0;
    const refresh = createStatusLoader((selected, signal) => {
      calls++;
      assert.deepEqual(selected.location, { directory: "/project" });
      assert.equal(signal.aborted, false);
      return pending.promise;
    }, (next) => applied.push(next));
    const first = refresh(target());
    for (let index = 0; index < 100; index++) assert.equal(refresh(target()), first);
    await tick();
    assert.equal(calls, 1);
    pending.resolve(status());
    await first;
    assert.equal(applied.at(-1)?.mode, "on");
    refresh.dispose();
  });
  it("aborts a moved location and rejects late replies even from an uncooperative source", async () => {
    const requests: ReturnType<typeof deferred<AutoModeStatus>>[] = [];
    const signals: AbortSignal[] = [];
    const applied: (AutoModeStatus | undefined)[] = [];
    const refresh = createStatusLoader((_, signal) => {
      const request = deferred<AutoModeStatus>();
      requests.push(request); signals.push(signal);
      return request.promise;
    }, (next) => applied.push(next));
    const first = refresh(target());
    await tick();
    const second = refresh(target("a", "/worktree"));
    await tick();
    assert.equal(signals[0].aborted, true);
    requests[1].resolve(status({ mode: "off" }));
    await second;
    requests[0].resolve(status());
    await first;
    assert.deepEqual(applied.map((entry) => entry?.mode), [undefined, undefined, "off"]);
    refresh.dispose();
  });
  it("times out a hung request, shows unavailable and permits recovery", async () => {
    let signal!: AbortSignal;
    let hung = true;
    const applied: (AutoModeStatus | undefined)[] = [];
    const refresh = createStatusLoader((_, nextSignal) => {
      signal = nextSignal;
      return hung ? new Promise(() => {}) : Promise.resolve(status());
    }, (next) => applied.push(next), 10);
    await refresh(target());
    assert.equal(signal.aborted, true);
    assert.equal(pillLabel(applied.at(-1)), "status unavailable");
    assert.equal(applied.at(-1)?.enabled, false);
    hung = false;
    await refresh(target());
    assert.equal(pillLabel(applied.at(-1)), "auto");
    refresh.dispose();
  });
  it("does not preserve successful auto after failures or absent snapshots", async () => {
    const applied: (AutoModeStatus | undefined)[] = [];
    let outcome = "ok";
    const refresh = createStatusLoader(async () => {
      if (outcome === "fail") throw new Error("offline");
      return outcome === "ok" ? status() : undefined;
    }, (next) => applied.push(next));
    await refresh(target());
    outcome = "fail";
    await refresh(target());
    assert.equal(pillLabel(applied.at(-1)), "status unavailable");
    outcome = "absent";
    await refresh(target());
    assert.equal(pillLabel(applied.at(-1)), "status unavailable");
    refresh.dispose();
  });
  it("aborts on disposal and never applies or starts new requests afterward", async () => {
    let signal!: AbortSignal;
    const pending = deferred<AutoModeStatus>();
    const applied: (AutoModeStatus | undefined)[] = [];
    let calls = 0;
    const refresh = createStatusLoader((_, nextSignal) => {
      signal = nextSignal; calls++;
      return pending.promise;
    }, (next) => applied.push(next));
    const first = refresh(target());
    await tick();
    refresh.dispose();
    assert.equal(signal.aborted, true);
    pending.resolve(status());
    await first;
    await refresh(target());
    assert.equal(calls, 1);
    assert.deepEqual(applied, [undefined]);
  });
  it("never queries other servers or absent selections and clears previous state", async () => {
    let calls = 0;
    const applied: (AutoModeStatus | undefined)[] = [];
    const refresh = createStatusLoader(async () => { calls++; return status(); }, (next) => applied.push(next));
    await refresh(target());
    await refresh(target("b", "/project", false));
    assert.equal(applied.at(-1), undefined);
    await refresh(undefined);
    assert.equal(calls, 1);
    refresh.dispose();
  });
});

describe("location-aware targets", () => {
  it("requires location and fingerprints directory moves", () => {
    const session = { key: "server\na", id: "a", server: { builtin: true }, location: { directory: "/project" } };
    const initial = statusTarget(session)!;
    assert.deepEqual(initial.location, session.location);
    assert.notEqual(initial.key, statusTarget({ ...session, location: { directory: "/worktree" } })!.key);
    const workspace = statusTarget({ ...session, location: { directory: "/project", workspaceID: "ws" } })!;
    assert.notEqual(initial.key, workspace.key);
    assert.equal(workspace.key, statusLocationKey(session.key, { directory: "/project", workspaceID: "ws" }));
    assert.equal(workspace.location.workspaceID, "ws");
    assert.equal(statusTarget({ ...session, location: undefined }), undefined);
    assert.equal(statusTarget(undefined), undefined);
    assert.equal(statusTarget({ ...session, server: { builtin: false } })!.ownServer, false);
  });
});

function event(overrides: Record<string, unknown> = {}, directory = "/project"): DecisionEvent {
  return { location: { directory }, data: { sessionID: "a", reviewID: "r", decision: "deny", stage: "guard", ...overrides } };
}
describe("bounded deny and breaker notifications", () => {
  it("filters location, session and server; never nags about allow or ask", () => {
    const notices: ModeNotice[] = [];
    let selected: StatusTarget | undefined = target();
    const receive = createDecisionNotifier(() => selected, (notice) => notices.push(notice));
    receive(event({}, "/other"));
    receive({ ...event(), location: { directory: "/project", workspaceID: "other-workspace" } });
    receive(event({ sessionID: "b" }));
    receive(event({ decision: "allow" }));
    receive(event({ decision: "ask" }));
    selected = target("a", "/project", false);
    receive(event());
    selected = undefined;
    receive(event());
    assert.deepEqual(notices, []);
    selected = target();
    receive(event());
    receive(event());
    receive(event({ stage: "breaker" }));
    assert.deepEqual(notices, [
      { kind: "deny", message: "Auto mode denied" },
      { kind: "breaker", message: "Auto mode paused (breaker)" },
    ]);
  });
  it("caps toast bursts but still reports breaker and avoids raw reason text", () => {
    const notices: ModeNotice[] = [];
    let now = 10_000;
    const receive = createDecisionNotifier(() => target(), (notice) => notices.push(notice), () => now);
    for (let index = 0; index < 500; index++) receive(event({ reviewID: `r${index}`, reason: "secret" }));
    assert.equal(notices.length, 4);
    receive(event({ reviewID: "breaker", stage: "breaker" }));
    assert.equal(notices.at(-1)?.kind, "breaker");
    now += 5_000;
    receive(event({ reviewID: "new" }));
    assert.equal(notices.length, 6);
    assert.equal(notices.some((notice) => notice.message.includes("secret")), false);
    assert.ok(notices.at(-1)!.message.length < 100);
  });
  it("ignores malformed event data", () => {
    const notices: ModeNotice[] = [];
    const receive = createDecisionNotifier(() => target(), (notice) => notices.push(notice));
    receive({ location: { directory: "/project" }, data: null });
    receive(event({ reviewID: "x".repeat(500) }));
    receive(event({ reviewID: undefined }));
    assert.equal(notices.length, 0);
  });
});

describe("decision subscriptions", () => {
  it("maintains one listener, rebinds client replacement and aborts disposal", () => {
    const signals: AbortSignal[] = [];
    const handlers: ((event: DecisionEvent) => void)[] = [];
    let stops = 0;
    let received = 0;
    const subscription = createDecisionSubscription(() => received++);
    const subscribe = (handler: (event: DecisionEvent) => void, signal: AbortSignal) => {
      signals.push(signal); handlers.push(handler);
      return () => { stops++; };
    };
    const first = {};
    subscription.update(first, subscribe);
    subscription.update(first, subscribe);
    assert.equal(signals.length, 1);
    handlers[0](event());
    assert.equal(received, 1);
    subscription.update({}, subscribe);
    assert.equal(signals[0].aborted, true);
    assert.equal(stops, 1);
    handlers[0](event());
    assert.equal(received, 1);
    subscription.dispose();
    assert.equal(signals[1].aborted, true);
    assert.equal(stops, 2);
    subscription.update({}, subscribe);
    assert.equal(signals.length, 2);
  });
});

describe("deliberate mode actions", () => {
  it("maps on/off/paused safely and cannot enable invalid status", () => {
    assert.equal(pillAction(status()), "off");
    assert.equal(pillAction(status({ mode: "off", enabled: false })), "on");
    assert.equal(pillAction(status({ mode: "paused", enabled: false })), "resume");
    assert.equal(pillAction(status({ mode: "invalid" })), undefined);
    assert.equal(pillAction(undefined), undefined);
  });
  it("serializes each session independently and clears all pending state on disposal", async () => {
    const requests: ReturnType<typeof deferred<AutoModeStatus>>[] = [];
    const signals: AbortSignal[] = [];
    const applied: string[] = [];
    let failures = 0;
    const runner = createModeRunner((selected, mode, signal) => {
      assert.equal(mode, selected.sessionID === "a" ? "off" : "resume");
      const request = deferred<AutoModeStatus>();
      requests.push(request); signals.push(signal);
      return request.promise;
    }, (selected) => applied.push(selected.sessionID), () => failures++);
    const a = runner.run(target(), "off");
    assert.equal(runner.run(target(), "on"), a);
    const b = runner.run(target("b"), "resume");
    await tick();
    assert.equal(requests.length, 2);
    requests[0].resolve(status({ mode: "off" }));
    await a;
    assert.deepEqual(applied, ["a"]);
    assert.equal(runner.pending(target()), false);
    runner.dispose();
    assert.equal(signals[1].aborted, true);
    assert.equal(runner.pending(target("b")), false);
    requests[1].reject(new Error("offline"));
    await b;
    await runner.run(target(), "on");
    assert.equal(requests.length, 2);
    assert.equal(failures, 0);
  });
  it("bounds a hung mutation, clears pending state and reports failure", async () => {
    let signal!: AbortSignal;
    let failures = 0;
    let changes = 0;
    const runner = createModeRunner((_selected, _mode, nextSignal) => {
      signal = nextSignal;
      return new Promise<AutoModeStatus>(() => {});
    }, () => {}, () => failures++, () => changes++, 10);
    await runner.run(target(), "off");
    assert.equal(signal.aborted, true);
    assert.equal(failures, 1);
    assert.equal(runner.pending(target()), false);
    assert.equal(changes, 2);
    runner.dispose();
  });
  it("does not submit a missing, remote or unsafe action", async () => {
    let calls = 0;
    const runner = createModeRunner(async () => { calls++; return status(); }, () => {}, () => {});
    await runner.run(undefined, "on");
    await runner.run(target("a", "/project", false), "on");
    await runner.run(target(), undefined);
    assert.equal(calls, 0);
    runner.dispose();
  });
});

describe("mode indicator", () => {
  it("labels every mode without decisions, model names, or an expiry", () => {
    assert.equal(pillLabel(undefined), undefined);
    for (const [mode, label] of [
      ["on", "auto"], ["off", "off"], ["paused", "paused (breaker)"],
    ] as const) assert.equal(pillLabel(status({ mode })), label);
    assert.equal(pillLabel(status({ enabled: false })), "off");
  });
  it("makes invalid configuration and its bounded error visible", () => {
    const invalid = status({ mode: "invalid", enabled: false, configError: "Unknown classifier type", errorKind: "config" });
    assert.equal(pillLabel(invalid), "Invalid config — review disabled");
    assert.equal(pillDescription(invalid), "Invalid config — review disabled: Unknown classifier type");
    assert.equal(pillAction(invalid), undefined);
    assert.equal(pillTone(invalid), "danger");
    assert.equal(pillLabel(status({ mode: "invalid", configError: "status unavailable", errorKind: "status" })), "status unavailable");
    assert.equal(pillDescription(status({ mode: "invalid", configError: "status unavailable", errorKind: "status" })), undefined);
    assert.equal(pillDescription(status()), undefined);
  });
  it("distinguishes storage failures from invalid configuration", () => {
    const storage = status({ mode: "invalid", enabled: false, configError: "Auto-mode session storage unavailable", errorKind: "storage" });
    assert.equal(pillLabel(storage), "Review unavailable");
    assert.equal(pillDescription(storage), "Review unavailable: Auto-mode session storage unavailable");
    assert.equal(pillTone(storage), "danger");
    assert.equal(pillLabel(status({ mode: "invalid", enabled: false, configError: "unknown failure" })), "Review unavailable");
  });
  it("uses warning and error tones only for mode state", () => {
    assert.equal(pillTone(undefined), undefined);
    assert.equal(pillTone(status()), "success");
    assert.equal(pillTone(status({ mode: "off" })), undefined);
    assert.equal(pillTone(status({ mode: "paused" })), "warning");
    assert.equal(pillTone(status({ mode: "invalid" })), "danger");
  });
});
