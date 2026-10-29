import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createStatusGuard, createStatusLoader, noticeExpired, panelView, pillLabel, statusTarget, type StatusTarget } from "./gui-state.js";
import type { AutoModeDecision, AutoModeStatus } from "./rpc.js";

const OWN = "sidecar";

function target(sessionID: string, server = OWN, ownServer = server === OWN): StatusTarget {
  return { key: `${server}\n${sessionID}`, sessionID, ownServer };
}

function decision(name: string, overrides: Partial<AutoModeDecision> = {}): AutoModeDecision {
  return {
    reviewID: `review-${name}`, sessionID: "a", action: "shell", decision: name,
    stage: "static", reason: "because", durationMs: 1, at: 1, ...overrides,
  };
}

function status(overrides: Partial<AutoModeStatus> = {}): AutoModeStatus {
  return { enabled: true, classifiers: [], reviewTimeoutMs: 60_000, reviewing: [], recent: [], ...overrides };
}

interface Deferred<T> {
  readonly promise: Promise<T>;
  resolve(value: T): void;
  reject(error: unknown): void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((settle, fail) => { resolve = settle; reject = fail; });
  return { promise, resolve, reject };
}

/** Decisions applied to the panel, with `"cleared"` standing for an undefined snapshot. */
function shown(applied: (AutoModeStatus | undefined)[]): string[] {
  return applied.map((snapshot) => snapshot?.recent.at(-1)?.decision ?? "cleared");
}

describe("status guard", () => {
  it("tracks selection changes and ignores requests for other sessions", () => {
    const guard = createStatusGuard();
    assert.equal(guard.select(undefined), false);
    assert.equal(guard.select("a"), true);
    assert.equal(guard.select("a"), false);
    assert.equal(guard.begin("b"), undefined);
    const request = guard.begin("a");
    assert.notEqual(request, undefined);
    assert.equal(guard.accept(request!), true);
    assert.equal(guard.select("b"), true);
    assert.equal(guard.accept(request!), false);
    assert.equal(guard.begin("a"), undefined);
  });
  it("ignores a session that is routed away and back", () => {
    const guard = createStatusGuard();
    guard.select("a");
    const request = guard.begin("a");
    guard.select("b");
    guard.select("a");
    assert.equal(guard.accept(request!), false);
    const next = guard.begin("a");
    assert.equal(guard.accept(next!), true);
  });
  it("accepts a slow response issued before a newer request", () => {
    const guard = createStatusGuard();
    guard.select("a");
    const slow = guard.begin("a");
    const newer = guard.begin("a");
    // Numbering the newer request must not invalidate the slow response: a
    // poll slower than the interval still describes this session.
    assert.equal(guard.accept(slow!), true);
    assert.equal(guard.accept(newer!), true);
    assert.equal(guard.accept(slow!), false);
  });
  it("drops an older response that settles after a newer one", () => {
    const guard = createStatusGuard();
    guard.select("a");
    const older = guard.begin("a");
    const newer = guard.begin("a");
    assert.equal(guard.accept(newer!), true);
    assert.equal(guard.accept(older!), false);
  });
  it("invalidates every response from before a selection change", () => {
    const guard = createStatusGuard();
    guard.select("a");
    const first = guard.begin("a");
    guard.select("b");
    const second = guard.begin("b");
    assert.equal(guard.accept(first!), false);
    assert.equal(guard.accept(second!), true);
  });
});

describe("status loader", () => {
  it("drops a response for a session the user routed away from", async () => {
    const requests = new Map<string, Deferred<AutoModeStatus | undefined>>();
    const applied: (AutoModeStatus | undefined)[] = [];
    const refresh = createStatusLoader((sessionID) => {
      const request = deferred<AutoModeStatus | undefined>();
      requests.set(sessionID, request);
      return request.promise;
    }, (next) => applied.push(next));

    const first = refresh(target("a"));
    const second = refresh(target("b"));
    requests.get("b")!.resolve(status({ recent: [decision("deny")] }));
    await second;
    // The abandoned request settles last and must not overwrite B.
    requests.get("a")!.resolve(status({ recent: [decision("allow")] }));
    await first;

    assert.deepEqual(shown(applied), ["cleared", "cleared", "deny"]);
  });
  it("keys the same session id on two servers apart", async () => {
    const requests: Deferred<AutoModeStatus | undefined>[] = [];
    const applied: (AutoModeStatus | undefined)[] = [];
    const refresh = createStatusLoader(() => {
      const request = deferred<AutoModeStatus | undefined>();
      requests.push(request);
      return request.promise;
    }, (next) => applied.push(next));

    const first = refresh(target("shared", "server-a", true));
    const second = refresh(target("shared", "server-b", true));
    requests[1]!.resolve(status({ recent: [decision("deny")] }));
    await second;
    requests[0]!.resolve(status({ recent: [decision("allow")] }));
    await first;

    assert.deepEqual(shown(applied), ["cleared", "cleared", "deny"]);
  });
  it("does not read this server's status for a session on another server", async () => {
    const calls: string[] = [];
    const applied: (AutoModeStatus | undefined)[] = [];
    const refresh = createStatusLoader(async (sessionID) => {
      calls.push(sessionID);
      return status({ recent: [decision("allow")] });
    }, (next) => applied.push(next));

    await refresh(target("a"));
    await refresh(target("a", "https://other"));

    assert.deepEqual(calls, ["a"]);
    assert.deepEqual(shown(applied), ["cleared", "allow", "cleared"]);
  });
  it("drops an older poll that settles after a newer one", async () => {
    const requests: Deferred<AutoModeStatus | undefined>[] = [];
    const applied: (AutoModeStatus | undefined)[] = [];
    const refresh = createStatusLoader(() => {
      const request = deferred<AutoModeStatus | undefined>();
      requests.push(request);
      return request.promise;
    }, (next) => applied.push(next));

    const first = refresh(target("a"));
    const second = refresh(target("a"));
    requests[1]!.resolve(status({ recent: [decision("deny")] }));
    await second;
    requests[0]!.resolve(status({ recent: [decision("allow")] }));
    await first;

    assert.deepEqual(shown(applied), ["cleared", "deny"]);
  });
  it("keeps every response from polls that take longer than the interval", async () => {
    const requests: Deferred<AutoModeStatus | undefined>[] = [];
    const applied: (AutoModeStatus | undefined)[] = [];
    const refresh = createStatusLoader(() => {
      const request = deferred<AutoModeStatus | undefined>();
      requests.push(request);
      return request.promise;
    }, (next) => applied.push(next));

    // Polling every 3s while each request takes 4s leaves two in flight.
    const first = refresh(target("a"));
    const second = refresh(target("a"));
    requests[0]!.resolve(status({ recent: [decision("allow")] }));
    await first;
    requests[1]!.resolve(status({ recent: [decision("deny")] }));
    await second;

    assert.deepEqual(shown(applied), ["cleared", "allow", "deny"]);
  });
  it("drops a response for a session the user routed away from and back to", async () => {
    const requests: Deferred<AutoModeStatus | undefined>[] = [];
    const applied: (AutoModeStatus | undefined)[] = [];
    const refresh = createStatusLoader(() => {
      const request = deferred<AutoModeStatus | undefined>();
      requests.push(request);
      return request.promise;
    }, (next) => applied.push(next));

    const first = refresh(target("a"));
    const second = refresh(target("b"));
    const third = refresh(target("a"));
    requests[2]!.resolve(status({ recent: [decision("deny")] }));
    await third;
    requests[0]!.resolve(status({ recent: [decision("allow")] }));
    await first;
    requests[1]!.resolve(status({ recent: [decision("allow")] }));
    await second;

    assert.deepEqual(shown(applied), ["cleared", "cleared", "cleared", "deny"]);
  });
  it("clears the previous session before the next request fails", async () => {
    const requests: Deferred<AutoModeStatus | undefined>[] = [];
    const applied: (AutoModeStatus | undefined)[] = [];
    const refresh = createStatusLoader(() => {
      const request = deferred<AutoModeStatus | undefined>();
      requests.push(request);
      return request.promise;
    }, (next) => applied.push(next));

    const first = refresh(target("a"));
    requests[0]!.resolve(status({ recent: [decision("allow")] }));
    await first;
    const second = refresh(target("b"));
    assert.equal(applied.at(-1), undefined);
    requests[1]!.reject(new Error("server restarting"));
    await second;

    assert.deepEqual(shown(applied), ["cleared", "allow", "cleared"]);
  });
  it("keeps the snapshot when a request for the same session fails", async () => {
    const requests: Deferred<AutoModeStatus | undefined>[] = [];
    const applied: (AutoModeStatus | undefined)[] = [];
    const refresh = createStatusLoader(() => {
      const request = deferred<AutoModeStatus | undefined>();
      requests.push(request);
      return request.promise;
    }, (next) => applied.push(next));

    const first = refresh(target("a"));
    requests[0]!.resolve(status({ recent: [decision("allow")] }));
    await first;
    const second = refresh(target("a"));
    requests[1]!.reject(new Error("server restarting"));
    await second;

    assert.deepEqual(shown(applied), ["cleared", "allow"]);
  });
  it("clears the snapshot when no session is routed", async () => {
    const applied: (AutoModeStatus | undefined)[] = [];
    const refresh = createStatusLoader(async () => status({ recent: [decision("allow")] }), (next) => applied.push(next));

    await refresh(target("a"));
    await refresh(undefined);

    assert.deepEqual(shown(applied), ["cleared", "allow", "cleared"]);
  });
});

describe("status target", () => {
  it("keys the selection by server and session, not by session id", () => {
    assert.deepEqual(
      statusTarget({ key: "sidecar\nshared", id: "shared", server: { builtin: true } }),
      { key: "sidecar\nshared", sessionID: "shared", ownServer: true },
    );
    assert.deepEqual(
      statusTarget({ key: "https://other\nshared", id: "shared", server: { builtin: false } }),
      { key: "https://other\nshared", sessionID: "shared", ownServer: false },
    );
    assert.equal(statusTarget(undefined), undefined);
  });
});

describe("decisions panel", () => {
  it("shows the empty state for a missing or an empty snapshot", () => {
    assert.equal(panelView(undefined), "empty");
    assert.equal(panelView(status()), "empty");
    assert.equal(panelView(status({ reviewing: [{ sessionID: "a", reviewID: "review-1", startedAt: 1 }] })), "entries");
    assert.equal(panelView(status({ recent: [decision("allow")] })), "entries");
  });
  it("shows the empty state after the loader applies a defined empty snapshot", async () => {
    const applied: (AutoModeStatus | undefined)[] = [];
    const refresh = createStatusLoader(async () => status(), (next) => applied.push(next));

    await refresh(target("a"));

    assert.notEqual(applied.at(-1), undefined);
    assert.equal(panelView(applied.at(-1)), "empty");
  });
});

describe("status pill", () => {
  it("labels the pill from the latest decision", () => {
    assert.equal(pillLabel(undefined), undefined);
    assert.equal(pillLabel(status()), undefined);
    assert.equal(pillLabel(status({ reviewing: [{ sessionID: "a", reviewID: "review-1", startedAt: 1 }] })),
      "auto-mode reviewing…");
    assert.equal(pillLabel(status({ recent: [decision("deny")] })), "auto-mode deny");
    assert.equal(pillLabel(status({ recent: [decision("deny", { errorKind: "provider" })] })), "auto-mode deny: provider");
  });
  it("expires the notice after the decision, but never while reviewing", () => {
    const recordedAt = 1_000;
    const decided = status({ recent: [decision("allow", { at: recordedAt })] });
    assert.equal(noticeExpired(undefined, recordedAt + 60_000, 30_000), false);
    assert.equal(noticeExpired(status(), recordedAt + 60_000, 30_000), false);
    assert.equal(noticeExpired(decided, recordedAt, 30_000), false);
    assert.equal(noticeExpired(decided, recordedAt + 30_000, 30_000), false);
    assert.equal(noticeExpired(decided, recordedAt + 30_001, 30_000), true);
    // An active review keeps the pill up regardless of the last decision's age.
    const reviewing = status({
      reviewing: [{ sessionID: "a", reviewID: "review-2", startedAt: recordedAt + 60_000 }],
      recent: decided.recent,
    });
    assert.equal(noticeExpired(reviewing, recordedAt + 60_000, 30_000), false);
  });
  it("expires a snapshot a failed poll keeps on screen", async () => {
    const applied: (AutoModeStatus | undefined)[] = [];
    let failing = false;
    const refresh = createStatusLoader(async () => {
      if (failing) throw new Error("status unavailable");
      return status({ recent: [decision("allow", { at: 1_000 })] });
    }, (next) => applied.push(next));

    await refresh(target("a"));
    failing = true;
    await refresh(target("a"));

    // The failed poll preserved the snapshot instead of applying a new one, so
    // only the reactive clock can retire its notice.
    const kept = applied.at(-1);
    assert.equal(kept?.recent.at(-1)?.decision, "allow");
    assert.equal(noticeExpired(kept, 1_000 + 30_000, 30_000), false);
    assert.equal(noticeExpired(kept, 1_000 + 30_001, 30_000), true);
  });
});
