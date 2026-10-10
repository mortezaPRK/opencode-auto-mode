import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { compositeDecision, matches } from "./classifier.js";
import { parseOptions, stagesFor, type ClassifierStage } from "./config.js";

const request = { action: "shell", resources: ["touch a", "touch b"] };
const unused = async () => { throw new Error("unexpected reviewer call"); };

describe("composite classifiers", () => {
  it("requires coverage of every resource", async () => {
    const stages: ClassifierStage[] = [{ type: "rules", rules: [{ action: "shell", resource: "touch a", decision: "allow" }] }];
    assert.equal((await compositeDecision(stages, request, unused)).decision, "ask");
    stages[0] = { type: "rules", rules: [{ action: "shell", resource: "touch *", decision: "allow" }] };
    assert.equal((await compositeDecision(stages, request, unused)).decision, "allow");
  });
  it("applies all user denies before asks or static allows", async () => {
    const stages: ClassifierStage[] = [
      { type: "static" },
      { type: "rules", rules: [{ action: "shell", decision: "ask" }] },
      { type: "rules", rules: [{ action: "shell", resource: "pwd", decision: "deny" }] },
    ];
    assert.equal((await compositeDecision(stages, { action: "shell", resources: ["pwd"] }, unused)).decision, "deny");
    assert.equal((await compositeDecision(stages, { action: "shell", resources: ["sudo rm -rf /"] }, unused)).decision, "deny");
    assert.equal((await compositeDecision(stages, { action: "shell", resources: [] }, unused)).decision, "ask");
    stages.push({ type: "rules", rules: [{ action: "shell", decision: "deny" }] });
    assert.equal((await compositeDecision(stages, { action: "shell", resources: [] }, unused)).decision, "deny");
  });
  it("falls through on abstention and stops on human escalation", async () => {
    const stages: ClassifierStage[] = [{ type: "jev" }, { type: "llm" }];
    const seen: string[] = [];
    const result = await compositeDecision(stages, request, async (stage) => {
      seen.push(stage.type);
      return stage.type === "jev" ? undefined : { decision: "allow", reason: "authorized" };
    });
    assert.equal(result.decision, "allow");
    assert.deepEqual(seen, ["jev", "llm"]);
    seen.length = 0;
    await compositeDecision(stages, request, async (stage) => { seen.push(stage.type); return { decision: "ask", reason: "uncertain" }; });
    assert.deepEqual(seen, ["jev"]);
  });
  it("anchors wildcard patterns without regular expressions", () => {
    assert.equal(matches("a*b*c", "abbbc"), true);
    assert.equal(matches("a*b", "a"), false);
    assert.equal(matches("a*b", "xab"), false);
    assert.equal(matches("a.*", "abc"), false);
  });
  it("rejects malformed config and unsafe local endpoints", () => {
    for (const value of [null, { classifer: {} }, { classifier: { stages: [] } },
      { classifier: { stages: [{ type: "llm", model: { id: "x" } }] } },
      { classifier: { stages: [{ type: "jev", minConfidence: NaN }] } },
      { classifier: { stages: [{ type: "laya", endpoint: "http://example.com/v1/systemone" }] } },
      { classifier: { stages: [{ type: "laya", endpoint: "http://127.0.0.1/v1/systemone?x=y" }] } },
      { classifier: { stages: [{ type: "static", allowInProjectEdits: "true" }] } }])
      assert.throws(() => parseOptions(value));
    assert.deepEqual(stagesFor(parseOptions({})).map((stage) => stage.type), ["static", "llm"]);
    assert.equal(parseOptions({ classifier: { stages: [{ type: "laya" }] } }).classifier?.stages[0].type, "laya");
    assert.throws(() => parseOptions({ classifier: { stages: [{ type: "rules", rules: [{ action: "shell", decision: ["allow"] }] }] } }));
  });
});
