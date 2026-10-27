import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createStatusTracker } from "./status.js";

const base = { enabled: true, classifiers: ["static", "llm"], reviewTimeoutMs: 60_000 };

describe("status tracker", () => {
  it("moves a session from reviewing to its last decision", () => {
    const status = createStatusTracker();
    status.start("session-a", "review-1", 1000);
    assert.deepEqual(status.snapshot({ ...base, sessionID: "session-a" }).reviewing.map((entry) => entry.reviewID), ["review-1"]);
    status.finish({ reviewID: "review-1", sessionID: "session-a", action: "shell", decision: "deny",
      stage: "shell-guard", reason: "dangerous", durationMs: 3, at: 1003 });
    const snapshot = status.snapshot({ ...base, sessionID: "session-a" });
    assert.deepEqual(snapshot.reviewing, []);
    assert.equal(snapshot.recent[0].decision, "deny");
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
  it("keeps sessions and entries apart and bounded", () => {
    const status = createStatusTracker();
    status.start("session-a", "review-a", 1000);
    status.start("session-b", "review-b", 1000);
    assert.equal(status.snapshot({ ...base, sessionID: "session-b" }).reviewing.length, 1);
    assert.equal(status.snapshot(base).reviewing.length, 2);
    for (let index = 0; index < 150; index++) {
      status.finish({ reviewID: `review-${index}`, sessionID: "session-a", action: "shell",
        decision: "allow", stage: "static", reason: "x".repeat(500), durationMs: 1, at: index });
    }
    const recent = status.recent(20, "session-a");
    assert.equal(recent.length, 20);
    assert.equal(recent.at(-1)!.reviewID, "review-149");
    assert.ok(recent.every((entry) => entry.reason.length <= 200));
    assert.equal(status.recent(500, "session-a").length, 100);
  });
  it("reports configuration state without echoing long errors", () => {
    const status = createStatusTracker();
    const snapshot = status.snapshot({ ...base, enabled: false, configError: "e".repeat(400) });
    assert.equal(snapshot.enabled, false);
    assert.ok(snapshot.configError!.length <= 200);
  });
});
