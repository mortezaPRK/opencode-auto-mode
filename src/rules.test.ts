import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { compositeDecision } from "./classifier.js";
import { parseOptions, type ClassifierStage } from "./config.js";

const unused = async () => { throw new Error("unexpected reviewer call"); };
const rules = (expression: string): ClassifierStage => ({ type: "rules", rules: [{ expression, decision: "allow" }] });
const request = { action: "shell", resources: ["touch a"], agent: "auto", projectDir: "/project" };

describe("CEL rules", () => {
  it("evaluates standard predicates with scalar permission bindings", async () => {
    const expression = 'action == "shell" && agent == "auto" && projectDir == "/project" && !isDelegation && resource.matches("^touch [ab]$")';
    assert.equal((await compositeDecision([rules(expression)], request, unused)).decision, "allow");
    assert.equal((await compositeDecision([rules(expression)], { ...request, resources: ["touch a; rm file"] }, unused)).decision, "ask");
    assert.equal((await compositeDecision([rules('resource in ["pwd", "ls"]')], { ...request, resources: ["pwd", "ls"] }, unused)).decision, "allow");
  });
  it("covers resources with separate allow predicates without authorizing an empty request", async () => {
    const stages: ClassifierStage[] = [{ type: "rules", rules: [
      { expression: 'resource == "touch a"', decision: "allow" },
      { expression: 'resource == "touch b"', decision: "allow" },
    ] }];
    assert.equal((await compositeDecision(stages, { ...request, resources: ["touch a", "touch b"] }, unused)).decision, "allow");
    assert.equal((await compositeDecision(stages, { ...request, resources: ["touch a", "touch c"] }, unused)).decision, "ask");
    assert.equal((await compositeDecision([rules("true")], { ...request, resources: [] }, unused)).decision, "ask");
  });
  it("treats resource contents as data rather than expression source", async () => {
    const malicious = 'pwd\") || true || resource == (\"';
    assert.equal((await compositeDecision([rules('resource == "pwd"')], { ...request, resources: [malicious] }, unused)).decision, "ask");
  });
  it("escalates evaluation errors and nonboolean results before later allows", async () => {
    for (const expression of ['resource', '1', 'unknown == "pwd"', 'resource[999]', 'resource.matches("[")']) {
      const stages: ClassifierStage[] = [rules(expression), { type: "static" }, { type: "llm" }];
      assert.equal((await compositeDecision(stages, { ...request, resources: ["pwd"] }, unused)).decision, "ask");
    }
  });
  it("rejects legacy rules, malformed CEL, loops, and excessive AST depth", () => {
    for (const rule of [
      { action: "shell", resource: "*", decision: "allow" },
      { expression: 'action ==', decision: "allow" },
      { expression: '[1, 2].all(x, x > 0)', decision: "allow" },
      { expression: 'true ? ('.repeat(40) + 'true' + ') : false'.repeat(40), decision: "allow" },
      { expression: 'true', decision: "approve" },
    ]) assert.throws(() => parseOptions({ classifier: { stages: [{ type: "rules", rules: [rule] }] } }));
    assert.doesNotThrow(() => parseOptions({ classifier: { stages: [rules('action == "shell"')] } }));
  });
  it("fails closed on oversized resource input and evaluation counts", async () => {
    const stages: ClassifierStage[] = [rules("true"), { type: "llm" }];
    for (const resources of [["x".repeat(4097)], Array(257).fill("x"), Array(20).fill("😀".repeat(1024))])
      assert.equal((await compositeDecision(stages, { ...request, resources }, unused)).decision, "ask");
    assert.equal((await compositeDecision([{ type: "rules", rules: Array.from({ length: 256 }, () => ({ expression: "true", decision: "allow" as const })) }],
      { ...request, resources: Array(17).fill("pwd") }, unused)).decision, "ask");
  });
  it("preserves static denies when CEL evaluation would fail", async () => {
    assert.equal((await compositeDecision([rules('unknown'), { type: "static" }],
      { ...request, resources: ["sudo rm -rf /"] }, unused)).decision, "deny");
  });
  it("keeps user denies authoritative over failing allow predicates", async () => {
    const stages: ClassifierStage[] = [rules("resource"), { type: "rules", rules: [
      { expression: 'unknown == "pwd"', decision: "deny" },
      { expression: 'resource == "pwd"', decision: "deny" },
    ] }];
    assert.equal((await compositeDecision(stages, { ...request, resources: ["pwd"] }, unused)).decision, "deny");
  });
  it("preserves any resource denial even when other resources fail evaluation", async () => {
    const stages: ClassifierStage[] = [{ type: "rules", rules: [{
      expression: 'resource == "pwd" ? true : unknown', decision: "deny",
    }] }];
    for (const resources of [["pwd", "other"], ["other", "pwd"]])
      assert.equal((await compositeDecision(stages, { ...request, resources }, unused)).decision, "deny");
  });
  it("bounds concurrent evaluation and restores capacity after cleanup", async () => {
    const stages: ClassifierStage[] = [rules("true"), { type: "llm" }];
    const results = await Promise.all(Array.from({ length: 12 }, () => compositeDecision(stages, request, unused)));
    assert.ok(results.some((result) => result.decision === "ask"));
    assert.ok(results.every((result) => ["allow", "ask"].includes(result.decision)));
    assert.equal((await compositeDecision(stages, request, unused)).decision, "allow");
  });
});
