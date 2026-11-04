import { it } from "node:test";
import assert from "node:assert/strict";
import { evaluateVcsGate } from "./gates.js";

it("requires all VCS preconditions, never assumes the default branch", () => {
  const good = { branch: "topic", defaultBranch: "trunk", upstream: "remote/topic", clean: true };
  assert.deepEqual(evaluateVcsGate(good), { allowed: true, reason: "Non-default branch with upstream and clean working tree" });
  for (const state of [undefined, { ...good, branch: undefined }, { ...good, defaultBranch: undefined },
    { ...good, branch: "trunk" }, { ...good, upstream: undefined }, { ...good, clean: false }]) {
    const gate = evaluateVcsGate(state);
    assert.equal(gate.allowed, false);
    assert.equal(gate.reason.length > 0, true);
    assert.equal("ruleID" in gate, false);
  }
});
