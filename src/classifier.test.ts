import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { compositeDecision } from "./classifier.js";
import { parseOptions, stagesFor, type ClassifierStage } from "./config.js";

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
  it("rejects unknown options, stages, and malformed settings", () => {
    for (const value of [null, { classifer: {} }, { classifier: { stages: [] } },
      { classifier: { stages: [{ type: "llm", model: { id: "x" } }] } },
      { classifier: { stages: [{ type: "llm", model: "model-only" }] } },
      { classifier: { stages: [{ type: "decision", model: "typesafe-ai/jev-latest", minConfidence: NaN }] } },
      { classifier: { stages: [{ type: "decision", model: "typesafe-ai/jev-latest", endpoint: "http://127.0.0.1/v1/systemone" }] } },
      { classifier: { stages: [{ type: "decision", model: "unknown/decision" }] } },
      { classifier: { stages: [{ type: "decision", model: "laya/local#high" }] } },
      { classifier: { stages: [{ type: "decision", model: "laya/local", endpoint: "http://example.com/v1/systemone" }] } },
      { classifier: { stages: [{ type: "decision", model: "laya/local", endpoint: "http://127.0.0.1/v1/systemone?x=y" }] } },
      { classifier: { stages: [{ type: "static", allowInProjectEdits: "true" }] } },
      { classifier: { stages: [{ type: "rules", rules: [] }] } },
      { model: "provider/model" },
      { review: "all" },
      { agents: ["build"] },
      { allowInProjectEdits: true },
      { keybinds: { allow: "a", unknown: "b" } }])
      assert.throws(() => parseOptions(value));
    assert.deepEqual(stagesFor(parseOptions({})).map((stage) => stage.type), ["static", "llm"]);
    assert.equal(parseOptions({ classifier: { stages: [{ type: "decision", model: "laya/local" }] } }).classifier?.stages[0].type, "decision");
    assert.equal(parseOptions({ classifier: { stages: [{ type: "llm", model: "provider/model#high" }] } }).classifier?.stages[0].type, "llm");
    assert.deepEqual(parseOptions({ keybinds: { allow: "ctrl+alt+a" } }).keybinds, { allow: "ctrl+alt+a" });
  });
});
