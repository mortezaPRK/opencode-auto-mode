import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createStatusTracker } from "./status.js";

const base = { enabled: true, mode: "on" as const, reviewTimeoutMs: 15_000 };

describe("status tracker", () => {
  it("moves a session from reviewing to its last decision", () => {
    const status = createStatusTracker();
    status.start("session-a", "review-1", 1000);
    assert.deepEqual(status.snapshot({ ...base, sessionID: "session-a" }).reviewing.map((entry) => entry.reviewID), ["review-1"]);
    status.finish({ reviewID: "review-1", sessionID: "session-a", action: "shell", decision: "deny",
      stage: "shell-guard", reason: "dangerous", durationMs: 3, at: 1003 });
    const snapshot = status.snapshot({ ...base, sessionID: "session-a" });
    assert.deepEqual(snapshot.reviewing, []);
    assert.deepEqual(snapshot.counts, { allow: 0, ask: 0, deny: 0 });
    assert.equal("recent" in snapshot, false);
    assert.equal("classifiers" in snapshot, false);
  });
  it("keeps overlapping reviews in one session until each finishes", () => {
    const status = createStatusTracker();
    status.start("session-a", "review-1", 1000);
    status.start("session-a", "review-2", 1002);
    status.start("session-b", "review-3", 1004);
    assert.deepEqual(
      status.snapshot({ ...base, sessionID: "session-a" }).reviewing.map((entry) => entry.reviewID),
      ["review-1", "review-2"],
    );
    status.finish({ reviewID: "review-1", sessionID: "session-a", action: "shell", decision: "allow",
      stage: "static", reason: "safe", durationMs: 2, at: 1002 });
    assert.deepEqual(
      status.snapshot({ ...base, sessionID: "session-a" }).reviewing.map((entry) => entry.reviewID),
      ["review-2"],
    );
    assert.deepEqual(
      status.snapshot({ ...base, sessionID: "session-b" }).reviewing.map((entry) => entry.reviewID),
      ["review-3"],
    );
    status.finish({ reviewID: "review-2", sessionID: "session-a", action: "shell", decision: "deny",
      stage: "static", reason: "unsafe", durationMs: 2, at: 1004 });
    assert.deepEqual(status.snapshot({ ...base, sessionID: "session-a" }).reviewing, []);
  });
  it("bounds pending reviews", () => {
    const status = createStatusTracker();
    for (let index = 0; index < 300; index++) status.start("session-a", `review-${index}`, index);
    const pending = status.snapshot(base).reviewing;
    assert.equal(pending.length, 256);
    assert.equal(pending.at(-1)!.reviewID, "review-299");
  });
  it("copies server-supplied audit counts and breaker state", () => {
    const tracker = createStatusTracker();
    const counts = { allow: 4, ask: 2, deny: 1 };
    const snapshot = tracker.snapshot({ ...base, counts, mode: "paused", enabled: false, breaker: true });
    assert.deepEqual(snapshot.counts, counts);
    assert.equal(snapshot.breaker, true);
    assert.equal(snapshot.mode, "paused");
    counts.allow = 100;
    assert.equal(snapshot.counts.allow, 4);
  });
  it("rebuilds counts to exactly allow, ask and deny", () => {
    const tracker = createStatusTracker();
    const counts = { allow: 4, ask: 2, deny: 1, arbitrary: 99 } as never;
    const snapshot = tracker.snapshot({ ...base, counts });
    assert.deepEqual(snapshot.counts, { allow: 4, ask: 2, deny: 1 });
  });
  it("bounds a long action and stage before retaining or returning it", () => {
    const status = createStatusTracker();
    status.start("session-a", "review-1", 1000);
    status.start("session-a", "review-2", 1002);
    const action = `custom:${"x".repeat(500)}`;
    const stage = "s".repeat(500);
    const completion = { reviewID: "review-1", sessionID: "session-a", action,
      decision: "ask", stage, reason: "r".repeat(500), durationMs: 1, at: 1003,
      ruleID: "removed-rule", shadow: true } as unknown as Parameters<typeof status.finish>[0];
    const returned = status.finish(completion);
    assert.equal(returned.action.length, 128);
    assert.ok(returned.action.endsWith("…"));
    assert.ok(action.startsWith(returned.action.slice(0, -1)));
    assert.equal(returned.stage.length, 64);
    assert.ok(returned.stage.endsWith("…"));
    assert.ok(returned.reason.length <= 200);
    assert.equal("ruleID" in returned, false);
    assert.equal("shadow" in returned, false);
    const snapshot = status.snapshot({ ...base, sessionID: "session-a" });
    // Finishing removes only that review; there is no retained history.
    assert.deepEqual(snapshot.reviewing.map((entry) => entry.reviewID), ["review-2"]);
    assert.equal("recent" in snapshot, false);
  });
  it("clips a long action without splitting a surrogate pair", () => {
    const status = createStatusTracker();
    const action = `${"a".repeat(126)}😀${"b".repeat(10)}`;
    const entry = status.finish({ reviewID: "review-1", sessionID: "session-a", action,
      decision: "allow", stage: "static", reason: "safe", durationMs: 1, at: 1003 });
    assert.equal(entry.action, `${"a".repeat(126)}😀…`);
    assert.equal(Array.from(entry.action).length, 128);
  });
  it("reports invalid configuration without echoing long errors", () => {
    const status = createStatusTracker();
    const snapshot = status.snapshot({ ...base, enabled: false, mode: "invalid", configError: "e".repeat(400), errorKind: "config" });
    assert.equal(snapshot.enabled, false);
    assert.equal(snapshot.mode, "invalid");
    assert.equal(snapshot.errorKind, "config");
    assert.ok(snapshot.configError!.length <= 200);
    assert.equal("shadow" in snapshot, false);
  });
});
