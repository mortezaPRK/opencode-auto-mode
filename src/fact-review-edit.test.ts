import { after, it } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { DecisionContext, DecisionInput } from "./decision.js";
import { prepareCapturedEdit } from "./edit-capture.js";
import {
  reviewWithOperationFact,
  type FactReviewOptions,
  type FactReviewRequest,
} from "./fact-review.js";

type Decisions = DecisionContext["experimental"]["generate"]["decisions"];
type Reply = () => Promise<unknown>;

const options: FactReviewOptions = { model: "test-provider/test-model", timeoutMs: 1_000, minConfidence: 0.9 };
const reply = (payload: unknown): Reply => async () => payload;
const context = (decisions: Decisions): DecisionContext => ({ experimental: { generate: { decisions } } });

interface Pipeline {
  ctx: DecisionContext;
  calls: string[][];
  inputs: DecisionInput[];
}

function pipeline(replies: { inspection: Reply; review: Reply }): Pipeline {
  const calls: string[][] = [];
  const inputs: DecisionInput[] = [];
  const decisions: Decisions = async (input) => {
    const names = input.questions.map((question) => question.name);
    calls.push(names);
    inputs.push(input);
    if (names.includes("edit_effect")) return replies.inspection();
    if (names.includes("authorization")) return replies.review();
    throw new Error("unexpected edit fact-review question");
  };
  return { ctx: context(decisions), calls, inputs };
}

function textOf(input: DecisionInput | undefined): string {
  const part = input?.input[0];
  return part?.type === "text" ? part.text : "";
}

const sha = (text: string): string => createHash("sha256").update(text).digest("hex");

const reviewAnswer = (safety: number, pAllow: number): unknown => ({
  answers: [
    { type: "predicate", name: "safety", probability: safety },
    {
      type: "choice", name: "authorization", choice: "allow",
      probabilities: [{ value: "allow", probability: pAllow }, { value: "review", probability: 1 - pAllow }],
    },
  ],
});

const editReply = (choice: "local_edit" | "other", probability: number): Reply => reply({ answers: [{
  type: "choice", name: "edit_effect", choice,
  probabilities: [
    { value: "local_edit", probability: choice === "local_edit" ? probability : 1 - probability },
    { value: "other", probability: choice === "other" ? probability : 1 - probability },
  ],
}] });

const FIXTURE_ROOT = realpathSync(mkdtempSync(join(tmpdir(), "opencode-fact-review-edit-")));
after(() => rmSync(FIXTURE_ROOT, { recursive: true, force: true }));
const EDIT_PATH = join(FIXTURE_ROOT, "src", "parser.ts");
const CAPTURE = { sessionID: "session-1", messageID: "message-1", callID: "call-1" } as const;

function editRequest(newString = "const a = 2;"): FactReviewRequest {
  const payload = prepareCapturedEdit({
    tool: "edit",
    args: { path: EDIT_PATH, oldString: "const a = 1;", newString },
  }, CAPTURE, true);
  assert.ok(payload, "expected a minted edit payload");
  return {
    action: "edit", resources: [EDIT_PATH], projectDir: FIXTURE_ROOT, worktreeRoot: FIXTURE_ROOT,
    userMessages: ["Implement the parser change."],
    operation: {
      tool: "edit", access: "write", targets: [EDIT_PATH],
      arguments: { path: EDIT_PATH }, complete: false,
    },
    editPayload: payload, expectedEditCapture: payload.capture,
  };
}

it("reviews a certified local_edit with its exact change content and allows at the .9 floor", async () => {
  const fake = pipeline({ inspection: editReply("local_edit", 0.9), review: reply(reviewAnswer(0.9, 0.9)) });
  const result = await reviewWithOperationFact(fake.ctx, { ...options, includeEditPayload: true }, editRequest());
  assert.equal(result.decision, "allow");
  assert.equal(result.stage, "fact-review");
  assert.deepEqual(fake.calls, [["edit_effect"], ["safety", "authorization"]]);
  const factText = textOf(fake.inputs[0]);
  const evidence = JSON.parse(textOf(fake.inputs[1])) as {
    changeContent: { args: Record<string, string>; target: string; tool: string };
    certifiedOperationFact: { kind: string; sourceInputHash: string };
  };
  assert.equal(evidence.changeContent.tool, "edit");
  assert.equal(evidence.changeContent.target, EDIT_PATH);
  assert.equal(evidence.changeContent.args.newString, "const a = 2;");
  assert.equal(JSON.stringify(evidence.changeContent), factText);
  assert.equal(evidence.certifiedOperationFact.kind, "local_edit");
  assert.equal(evidence.certifiedOperationFact.sourceInputHash, sha(factText));
  assert.equal(Object.keys(evidence).at(-1), "certifiedOperationFact");
});

it("keeps the safety gate for a certified local_edit even with clean static analysis", async () => {
  const fake = pipeline({ inspection: editReply("local_edit", 0.95), review: reply(reviewAnswer(0.95, 0.95)) });
  const request: FactReviewRequest = {
    ...editRequest(), staticAnalysis: { band: "low", reason: "Local edit", findings: [] },
  };
  const result = await reviewWithOperationFact(fake.ctx, { ...options, includeEditPayload: true }, request);
  assert.equal(result.decision, "allow");
  assert.deepEqual(fake.calls, [["edit_effect"], ["safety", "authorization"]]);
  assert.doesNotMatch(result.reason, /skipped/);
});

it("abstains when safety stays below the floor for a body-bound edit", async () => {
  const fake = pipeline({ inspection: editReply("local_edit", 0.95), review: reply(reviewAnswer(0.89, 0.95)) });
  const result = await reviewWithOperationFact(fake.ctx, { ...options, includeEditPayload: true }, editRequest());
  assert.equal(result.decision, "abstain");
  assert.equal(result.errorKind, undefined);
  assert.match(result.reason, /safety=0\.890/);
  assert.deepEqual(fake.calls, [["edit_effect"], ["safety", "authorization"]]);
});

it("abstains without any call when the consented edit candidate is missing or truncated", async () => {
  const requests: FactReviewRequest[] = [
    { ...editRequest(), editPayload: undefined, expectedEditCapture: undefined },
    { ...editRequest(), editPayload: undefined },
    editRequest("x".repeat(17_000)),
  ];
  for (const request of requests) {
    const fake = pipeline({ inspection: editReply("local_edit", 0.95), review: reply(reviewAnswer(0.95, 0.95)) });
    const result = await reviewWithOperationFact(fake.ctx, { ...options, includeEditPayload: true }, request);
    assert.equal(result.decision, "abstain");
    assert.equal(result.errorKind, "context");
    assert.equal(result.terminal, undefined);
    assert.equal(fake.calls.length, 0);
  }
  const disabled = pipeline({ inspection: editReply("local_edit", 0.95), review: reply(reviewAnswer(0.95, 0.95)) });
  const off = await reviewWithOperationFact(disabled.ctx, options, editRequest());
  assert.equal(off.decision, "abstain");
  assert.equal(off.errorKind, "context");
  assert.equal(disabled.calls.length, 0);
});

it("abstains when the rebuilt edit change content no longer matches the certified fact", async () => {
  const originalStringify = JSON.stringify;
  let tamper = false;
  const isCandidate = (value: unknown): boolean =>
    typeof value === "object" && value !== null &&
    "args" in value && "target" in value && "tool" in value;
  // Reach the fail-closed hash recheck: the fact call hashes the real candidate,
  // then the rebuild sees different bytes than the certified source input.
  JSON.stringify = ((value: unknown) => {
    const text = originalStringify(value);
    return tamper && isCandidate(value) ? `${text} ` : text;
  }) as typeof JSON.stringify;
  try {
    const fake = pipeline({
      inspection: async () => {
        tamper = true;
        return editReply("local_edit", 0.95)();
      },
      review: reply(reviewAnswer(0.95, 0.95)),
    });
    const result = await reviewWithOperationFact(fake.ctx, { ...options, includeEditPayload: true }, editRequest());
    assert.equal(result.decision, "abstain");
    assert.notEqual(result.decision, "deny");
    assert.equal(result.errorKind, "context");
    assert.match(result.reason, /does not match the certified fact/);
    assert.deepEqual(fake.calls, [["edit_effect"]]);
  } finally {
    JSON.stringify = originalStringify;
  }
});

it("blocks private edit payloads before any review call", async () => {
  const fake = pipeline({ inspection: editReply("local_edit", 0.95), review: reply(reviewAnswer(0.95, 0.95)) });
  const request = editRequest('const password = "fixture-hunter2-secret";');
  const result = await reviewWithOperationFact(fake.ctx, { ...options, includeEditPayload: true }, request);
  assert.equal(result.decision, "abstain");
  assert.equal(result.errorKind, "context");
  assert.equal(fake.calls.length, 0);
});
