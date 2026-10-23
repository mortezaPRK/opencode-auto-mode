import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { isReviewing } from "./tui-state.js";
import type { DecisionRecord } from "./state.js";

const record: DecisionRecord = { requestID: "review-test", sessionID: "active", decision: "reviewing", reason: "", at: 1000 };

describe("passive TUI indicator", () => {
  it("shows only work for the active session", () => {
    assert.equal(isReviewing({ review: record }, "active", 1500), true);
    assert.equal(isReviewing({ review: record }, "other-tab", 1500), false);
    assert.equal(isReviewing({ review: record }, undefined, 1500), false);
  });
  it("disappears on completion and ignores stale records", () => {
    for (const decision of ["allow", "deny", "ask"] as const)
      assert.equal(isReviewing({ review: { ...record, decision } }, "active", 1500), false);
    assert.equal(isReviewing({ review: record }, "active", 91_000), false);
    assert.equal(isReviewing({}, "active", 1500), false);
  });
});
