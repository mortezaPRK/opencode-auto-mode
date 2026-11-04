import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { runClassifiers, type ClassifierCallbacks } from "./classifier.js";
import type { ClassifierOptions } from "./config.js";
import type { StageResult } from "./reviewer.js";
import { ReviewFailure } from "./errors.js";

const request = { action: "shell", resources: ["git status"] };
const staticStage: ClassifierOptions = { type: "static" };
const decision: ClassifierOptions = { type: "decision", model: "test-provider/decision" };
const llm: ClassifierOptions = { type: "llm", model: "test-provider/reasoning" };
const result = (decision: StageResult["decision"]): StageResult => ({ decision, reason: "test" });
const callbacks = (value: StageResult["decision"]): ClassifierCallbacks => ({ decision: async () => result(value), llm: async () => result(value) });

describe("ordered classifier execution", () => {
  it("static only approves low and unresolved requests ask", async () => {
    const approved = await runClassifiers([staticStage], request, { band: "low", reason: "safe" }, callbacks("deny"));
    assert.equal(approved.decision, "allow");
    assert.equal("ruleID" in approved, false);
    assert.equal(approved.stage, "static");
    for (const band of ["medium", "high"] as const)
      assert.equal((await runClassifiers([staticStage], request, { band, reason: "review" }, callbacks("allow"))).decision, "ask");
    assert.equal((await runClassifiers([], request, { band: "low", reason: "safe" }, callbacks("allow"))).decision, "ask");
  });
  it("preserves configured order and stops at first allow or deny", async () => {
    const calls: string[] = [];
    const cb: ClassifierCallbacks = { decision: async () => { calls.push("decision"); return result("deny"); }, llm: async () => { calls.push("llm"); return result("allow"); } };
    assert.equal((await runClassifiers([llm, staticStage, decision], request, { band: "low", reason: "safe" }, cb)).decision, "allow");
    assert.deepEqual(calls, ["llm"]);
    calls.length = 0;
    assert.equal((await runClassifiers([decision, llm], request, { band: "high", reason: "review" }, cb)).decision, "deny");
    assert.deepEqual(calls, ["decision"]);
  });
  it("runs duplicate native stages on unresolved medium and high; ask and abstain continue", async () => {
    for (const band of ["medium", "high"] as const) {
      let calls = 0;
      const seen: number[] = [];
      const cb: ClassifierCallbacks = { decision: async () => result(++calls === 1 ? "abstain" : "ask"), llm: async () => result("allow"), onResult: (_stage, _result, index) => { seen.push(index); } };
      assert.equal((await runClassifiers([decision, decision, llm], request, { band, reason: "review" }, cb)).decision, "allow");
      assert.equal(calls, 2);
      assert.deepEqual(seen, [0, 1, 2]);
    }
  });
  it("guards cannot be overridden regardless of stages", async () => {
    const cb: ClassifierCallbacks = { decision: async () => { throw new Error("must not call"); }, llm: async () => { throw new Error("must not call"); } };
    for (const effect of [{ deny: true }, { ask: true }]) {
      const reviewed = await runClassifiers([decision, llm, staticStage], request, { band: "low", reason: "mandatory", ...effect }, cb);
      assert.equal(reviewed.decision, "deny" in effect ? "deny" : "ask");
      assert.equal(reviewed.stage, "guard");
      assert.equal("ruleID" in reviewed, false);
    }
  });
  it("honors each static stage's own edit policy", async () => {
    const req = { action: "edit", resources: ["src/main.ts"] };
    assert.equal((await runClassifiers([{ type: "static", allowInProjectEdits: false }], req, { band: "low", reason: "safe" }, callbacks("allow"))).decision, "ask");
    assert.equal((await runClassifiers([{ type: "static", allowInProjectEdits: false }, staticStage], req, { band: "low", reason: "safe" }, callbacks("allow"))).decision, "allow");
  });
  it("thrown cancellation stops before the next LLM", async () => {
    let llmCalls = 0;
    const final = await runClassifiers([decision, llm], request, { band: "high", reason: "review" }, {
      decision: async () => { throw new ReviewFailure("cancelled", "interrupted"); },
      llm: async () => { llmCalls++; return result("allow"); },
    });
    assert.equal(final.decision, "ask");
    assert.equal(final.errorKind, "cancelled");
    assert.equal(llmCalls, 0);
  });
  it("cancelled and whole-pipeline deadline outcomes stop before static", async () => {
    for (const errorKind of ["cancelled", "deadline"] as const) {
      const seen: string[] = [];
      const final = await runClassifiers([decision, staticStage], request, { band: "low", reason: "safe" }, {
        ...callbacks("allow"), decision: async () => ({ ...result("abstain"), errorKind }),
        onResult: (stage) => { seen.push(stage.type); },
      });
      assert.equal(final.decision, "ask");
      assert.equal(final.errorKind, errorKind);
      assert.deepEqual(seen, ["decision"]);
    }
  });
  it("individual stage timeout still advances in configured order", async () => {
    let calls = 0;
    const final = await runClassifiers([decision, llm], request, { band: "high", reason: "review" }, {
      decision: async () => { throw new ReviewFailure("timeout", "stage timed out"); },
      llm: async () => { calls++; return result("allow"); },
    });
    assert.equal(final.decision, "allow");
    assert.equal(calls, 1);
  });
  it("pre-aborted pipeline never starts a classifier or static allow", async () => {
    const controller = new AbortController(); controller.abort();
    let calls = 0;
    for (const stages of [[staticStage], [decision, llm]]) {
      const final = await runClassifiers(stages, request, { band: "low", reason: "safe" }, {
        signal: controller.signal,
        decision: async () => { calls++; return result("allow"); },
        llm: async () => { calls++; return result("allow"); },
      });
      assert.equal(final.decision, "ask");
      assert.equal(final.errorKind, "cancelled");
    }
    assert.equal(calls, 0);
  });
  it("aborting during generation discards stale verdicts and skips later stages", async () => {
    for (const reason of [undefined, new DOMException("Total deadline", "TimeoutError")]) {
      const controller = new AbortController();
      let llmCalls = 0;
      const final = await runClassifiers([decision, llm, staticStage], request, { band: "low", reason: "safe" }, {
        signal: controller.signal,
        decision: async () => { await Promise.resolve(); controller.abort(reason); return result("allow"); },
        llm: async () => { llmCalls++; return result("allow"); },
      });
      assert.equal(final.decision, "ask");
      assert.equal(final.errorKind, reason === undefined ? "cancelled" : "deadline");
      assert.equal(llmCalls, 0);
    }
  });
  it("aborting in a stage observer blocks a static allow", async () => {
    const controller = new AbortController();
    const final = await runClassifiers([staticStage], request, { band: "low", reason: "safe" }, {
      ...callbacks("allow"), signal: controller.signal, onResult: () => { controller.abort(); },
    });
    assert.equal(final.decision, "ask");
    assert.equal(final.errorKind, "cancelled");
  });
  it("exceptions abstain and observer failures do not change verdicts", async () => {
    const cb: ClassifierCallbacks = { decision: async () => { throw new Error("PRIVATE_ERROR"); }, llm: async () => result("deny"), onResult: () => { throw new Error("audit failure"); } };
    assert.equal((await runClassifiers([decision, llm], request, { band: "high", reason: "review" }, cb)).decision, "deny");
    const final = await runClassifiers([decision], request, { band: "high", reason: "review" }, cb);
    assert.equal(final.decision, "ask");
    assert.doesNotMatch(final.reason, /PRIVATE_ERROR/);
  });
});
