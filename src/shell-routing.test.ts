import { it } from "node:test";
import assert from "node:assert/strict";
import { parseOptions } from "./config.js";
import { runClassifiers } from "./classifier.js";
import { scoreRequest } from "./score.js";

const options = parseOptions({ classifiers: [
  { type: "static" }, { type: "decision", model: "test-provider/decision" },
  { type: "llm", model: "test-provider/reviewer" },
] });

it("keeps complex shell evidence intact and lets decision abstention fall through to the LLM", async () => {
  for (const command of ["set -e\nfor file in src/*.ts; do printf '%s\\n' \"$file\"; done",
    "bash -c 'printf ok'", "pwd $(printf ok)", "sh <<'EOF'\nprintf ok\nEOF",
    "echo $'a b'", `printf '%s' '${"x".repeat(5000)}'`, "git -C /project status"]) {
    const request = { action: "shell", resources: [command], projectDir: "/project" };
    const score = scoreRequest(request, options);
    assert.equal(score.band, "high", command);
    assert.equal(score.ask, undefined, command);
    assert.equal(score.deny, undefined, command);
    const calls: string[] = [];
    const verdict = await runClassifiers(options.classifiers, request, score, {
      decision: async (_, evidence) => {
        calls.push("decision"); assert.deepEqual(evidence.resources, [command]);
        return { decision: "abstain", reason: "uncertain" };
      },
      llm: async (_, evidence) => {
        calls.push("llm"); assert.deepEqual(evidence.resources, [command]);
        return { decision: "allow", reason: "safe authorized script" };
      },
    });
    assert.equal(verdict.decision, "allow");
    assert.deepEqual(calls, ["decision", "llm"]);
  }
});

it("leaves unresolved shell uncertainty to the user after classifiers exhaust", async () => {
  const request = { action: "shell", resources: ["bash -c 'printf ok'"] };
  const verdict = await runClassifiers(options.classifiers, request, scoreRequest(request, options), {
    decision: async () => ({ decision: "abstain", reason: "uncertain" }),
    llm: async () => ({ decision: "abstain", reason: "uncertain" }),
  });
  assert.equal(verdict.decision, "ask");
});

it("retains visible secret and destructive-operation denies in complex syntax", () => {
  for (const command of ["cat .env; bash -c pwd", "sudo id $(printf ok)", "rm -rf /outside # $'"]) {
    const score = scoreRequest({ action: "shell", resources: [command], projectDir: "/project" }, options);
    assert.equal(score.deny, true, command);
  }
});

it("keeps unsupported Windows shell dialects at a mandatory ask floor", () => {
  const descriptor = Object.getOwnPropertyDescriptor(process, "platform")!;
  try {
    Object.defineProperty(process, "platform", { value: "win32" });
    const score = scoreRequest({ action: "shell", resources: ["Write-Output ok"] }, options);
    assert.equal(score.band, "high");
    assert.equal(score.ask, true);
    assert.match(score.reason, /dialect/i);
  } finally { Object.defineProperty(process, "platform", descriptor); }
});
