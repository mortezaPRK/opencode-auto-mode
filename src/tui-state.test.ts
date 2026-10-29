import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { REVIEW_DISPLAY_WINDOW_MS, isReviewing } from "./tui-state.js";
import { MAX_REVIEW_TIMEOUT_MS } from "./config.js";
import type { DecisionRecord } from "./state.js";

const record: DecisionRecord = { requestID: "review-test", sessionID: "active", decision: "reviewing", reason: "", at: 1000 };

describe("passive TUI indicator", () => {
  it("shows only work for the active session", () => {
    assert.equal(isReviewing({ review: record }, "active", 1500), true);
    assert.equal(isReviewing({ review: record }, "other-tab", 1500), false);
    assert.equal(isReviewing({ review: record }, undefined, 1500), false);
  });
  it("outlives the longest configurable review deadline", () => {
    assert.ok(REVIEW_DISPLAY_WINDOW_MS > MAX_REVIEW_TIMEOUT_MS);
  });
  it("disappears on completion and ignores stale records", () => {
    for (const decision of ["allow", "deny", "ask"] as const)
      assert.equal(isReviewing({ review: { ...record, decision } }, "active", 1500), false);
    assert.equal(isReviewing({ review: record }, "active", REVIEW_DISPLAY_WINDOW_MS + 1000), false);
    assert.equal(isReviewing({}, "active", 1500), false);
  });
});
