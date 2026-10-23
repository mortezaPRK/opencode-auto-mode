import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { compositeDecision } from "./classifier.js";
import { parseOptions, type ClassifierStage } from "./config.js";

const request = { action: "shell", resources: ["touch a", "touch b"] };
const unused = async () => { throw new Error("unexpected reviewer call"); };

describe("composite classifiers", () => {
  it("runs static safety denials before any reviewer", async () => {
    const stages: ClassifierStage[] = [{ type: "static" }, { type: "llm" }];
    assert.equal((await compositeDecision(stages, { action: "shell", resources: ["sudo rm -rf /"] }, unused)).decision, "deny");
  });
  it("falls through on abstention and stops on terminal outcomes", async () => {
    const stages: ClassifierStage[] = [{ type: "decision", model: "typesafe-ai/jev-latest" }, { type: "llm" }];
    const seen: string[] = [];
    const result = await compositeDecision(stages, request, async (stage) => {
      seen.push(stage.type);
      return stage.type === "decision" ? { decision: "abstain", reason: "no confident answer" } : { decision: "allow", reason: "authorized" };
    });
    assert.equal(result.decision, "allow");
    assert.deepEqual(seen, ["decision", "llm"]);
    for (const decision of ["allow", "deny", "ask"] as const) {
      seen.length = 0;
      const terminal = await compositeDecision(stages, request, async (stage) => {
        seen.push(stage.type);
        return { decision, reason: "terminal" };
      });
      assert.equal(terminal.decision, decision);
      assert.deepEqual(seen, ["decision"]);
    }
  });
  it("asks when every stage abstains", async () => {
    const stages: ClassifierStage[] = [{ type: "decision", model: "typesafe-ai/jev-latest" }, { type: "llm" }];
    const result = await compositeDecision(stages, request, async () => ({ decision: "abstain", reason: "no answer" }));
    assert.equal(result.decision, "ask");
    assert.equal(result.stage, "none");
    assert.match(result.reason, /no answer/);
  });
  it("validates policy only on model-based classifiers", () => {
    for (const type of ["llm", "decision"] as const) {
      const model = type === "decision" ? "laya/local" : "provider/model";
      assert.doesNotThrow(() => parseOptions({ classifiers: [{ type, model, policy: { blocks: [], trusted: ["repository"] } }] }));
      for (const policy of [null, [], { unknown: [] }, { blocks: "deny" }, { trusted: [""] }, { exceptions: [1] }])
        assert.throws(() => parseOptions({ classifiers: [{ type, model, policy }] }));
    }
    assert.throws(() => parseOptions({ classifiers: [{ type: "static", policy: { blocks: [] } }] }));
  });
  it("rejects unknown options, stages, and malformed settings", () => {
    for (const value of [null, {}, { classifer: {} }, { classifiers: [] },
      { classifiers: [{ type: "llm", model: { id: "x" } }] },
      { classifiers: [{ type: "llm", model: "model-only" }] },
      { classifiers: [{ type: "decision", model: "typesafe-ai/jev-latest", minConfidence: NaN }] },
      { classifiers: [{ type: "decision", model: "typesafe-ai/jev-latest", endpoint: "http://127.0.0.1/v1/systemone" }] },
      { classifiers: [{ type: "decision", model: "unknown/decision" }] },
      { classifiers: [{ type: "decision", model: "laya/local#high" }] },
      { classifiers: [{ type: "decision", model: "laya/local", endpoint: "http://example.com/v1/systemone" }] },
      { classifiers: [{ type: "decision", model: "laya/local", endpoint: "http://127.0.0.1/v1/systemone?x=y" }] },
      { classifiers: [{ type: "static", allowInProjectEdits: "true" }] },
      { classifiers: [{ type: "unknown" }] },
      { classifiers: [{ type: "static" }], unknown: true },
      { classifiers: [{ type: "static" }], tui: "enabled" }])
      assert.throws(() => parseOptions(value));
    const stages: ClassifierStage[] = [{ type: "static" }, { type: "llm" }];
    assert.deepEqual(parseOptions({ classifiers: stages }).classifiers.map((stage) => stage.type), ["static", "llm"]);
    assert.equal(parseOptions({ classifiers: [{ type: "decision", model: "laya/local" }] }).classifiers[0].type, "decision");
    assert.equal(parseOptions({ classifiers: [{ type: "llm", model: "provider/model#high" }] }).classifiers[0].type, "llm");
    assert.equal(parseOptions({ classifiers: stages, tui: false }).tui, false);
  });
});
