import { it } from "node:test";
import assert from "node:assert/strict";
import { parseOptions } from "./config.js";
import { runClassifiers } from "./classifier.js";
import { scoreRequest } from "./score.js";

const options = parseOptions({ classifiers: [
  { type: "static" }, { type: "decision", model: "test-provider/decision" },
  { type: "llm", model: "test-provider/reviewer" },
] });

it("allows loading skill instructions through static classification without model calls", async () => {
  const request = { action: "skill", resources: ["browser"] };
  const score = scoreRequest(request, options);
  assert.equal(score.band, "low");
  const unexpected = async (): Promise<never> => { throw new Error("Skill loading must not need a model"); };
  const verdict = await runClassifiers(options.classifiers, request, score, { decision: unexpected, llm: unexpected });
  assert.equal(verdict.decision, "allow");
  assert.equal(verdict.stage, "static");
  assert.equal(scoreRequest({ action: "mcp_skill", resources: ["browser"] }, options).band, "high");
});
