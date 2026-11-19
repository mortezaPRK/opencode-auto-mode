import { it } from "node:test";
import assert from "node:assert/strict";
import { ReviewFailure } from "./errors.js";
import {
  delegationVerdict,
  parseAuthorizationReview,
  parseReview,
  reviewVerdict,
  type CertifiedOperationFact,
  type ParsedAuthorization,
  type ParsedReview,
} from "./fact-verdict.js";

const HASH = "a".repeat(64);

const validFact: CertifiedOperationFact = Object.freeze({
  kind: "inspection",
  probability: 0.95,
  sourceInputHash: HASH,
  model: "test-provider/test-model",
  fieldMetadata: Object.freeze({ authority: false }),
});

const validParsed: ParsedReview = Object.freeze({ safety: 0.95, selected: "allow", pAllow: 0.95 });

const forgedFact = (overrides: Record<string, unknown>): CertifiedOperationFact =>
  ({ ...validFact, ...overrides }) as unknown as CertifiedOperationFact;

const forgedParsed = (overrides: Record<string, unknown>): ParsedReview =>
  ({ ...validParsed, ...overrides }) as unknown as ParsedReview;

const vector = (allow: number, review: number): unknown[] => [
  { value: "allow", probability: allow },
  { value: "review", probability: review },
];

function answer(safety: unknown, choice: unknown, probabilities: unknown,
  extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    answers: [
      { type: "predicate", name: "safety", probability: safety },
      { type: "choice", name: "authorization", choice, probabilities, ...extra },
    ],
  };
}

const rejects = (run: () => unknown): void => {
  assert.throws(run, (error: unknown): boolean =>
    error instanceof ReviewFailure && error.kind === "invalid-output");
};

const assertAbstains = (result: ReturnType<typeof reviewVerdict>, errorKind?: string): void => {
  assert.equal(result.decision, "abstain");
  assert.equal(result.stage, "fact-review");
  assert.equal(result.errorKind, errorKind);
};

it("allows only the strong certified fact with strong safety and allow", () => {
  const result = reviewVerdict(validFact, validParsed, 0.9);
  assert.equal(result.decision, "allow");
  assert.equal(result.stage, "fact-review");
  assert.match(result.reason, /fact=inspection@0\.950/);
  assert.match(result.reason, /safety=0\.950/);
  assert.match(result.reason, /allow=0\.950/);
  const segments = reviewVerdict(forgedFact({ kind: "shell_segments" }), validParsed, 0.9);
  assert.equal(segments.decision, "allow");
  assert.match(segments.reason, /fact=shell_segments@0\.950/);
  const commandLocal = reviewVerdict(forgedFact({ kind: "command_local" }), validParsed, 0.9);
  assert.equal(commandLocal.decision, "allow");
  assert.match(commandLocal.reason, /fact=command_local@0\.950/);
});

it("rejects forged, low or non-finite fact probabilities", () => {
  for (const probability of [0.1, 0.8, 0.899999, Number.NaN, Number.POSITIVE_INFINITY, 1.01, "0.95"]) {
    assertAbstains(reviewVerdict(forgedFact({ probability }), validParsed, 0.9), "context");
  }
});

it("rejects thresholds outside the 0.8-1 range or non-finite", () => {
  for (const threshold of [0, 0.79, 0.799999, Number.NaN, Number.POSITIVE_INFINITY, 1.0001, -1]) {
    assertAbstains(reviewVerdict(validFact, validParsed, threshold), "context");
  }
  const lowered = reviewVerdict(forgedFact({ probability: 0.8 }), forgedParsed({ safety: 0.8, pAllow: 0.8 }), 0.8);
  assert.equal(lowered.decision, "allow");
  const boundary: CertifiedOperationFact = forgedFact({ probability: 1 });
  assert.equal(reviewVerdict(boundary, forgedParsed({ safety: 1, pAllow: 1 }), 1).decision, "allow");
});

it("rejects uncertified kinds, authority metadata and malformed provenance", () => {
  const cases: CertifiedOperationFact[] = [
    forgedFact({ kind: "unknown" }),
    forgedFact({ kind: "repository_read" }),
    forgedFact({ fieldMetadata: { authority: true } }),
    forgedFact({ fieldMetadata: undefined }),
    forgedFact({ sourceInputHash: "a".repeat(63) }),
    forgedFact({ sourceInputHash: "A".repeat(64) }),
    forgedFact({ sourceInputHash: "g".repeat(64) }),
    forgedFact({ sourceInputHash: 42 }),
    forgedFact({ model: "" }),
    forgedFact({ model: "   " }),
    forgedFact({ model: 7 }),
  ];
  for (const fact of cases) assertAbstains(reviewVerdict(fact, validParsed, 0.9), "context");
});

it("rechecks parsed probabilities instead of trusting the parser result type", () => {
  const cases: ParsedReview[] = [
    forgedParsed({ safety: Number.NaN }),
    forgedParsed({ safety: 1.01 }),
    forgedParsed({ safety: -0.01 }),
    forgedParsed({ safety: "0.95" }),
    forgedParsed({ pAllow: Number.NaN }),
    forgedParsed({ pAllow: 1.01 }),
    forgedParsed({ pAllow: -0.01 }),
    forgedParsed({ pAllow: "0.95" }),
    forgedParsed({ selected: "maybe" }),
    forgedParsed({ selected: undefined }),
    null as unknown as ParsedReview,
  ];
  for (const parsed of cases) assertAbstains(reviewVerdict(validFact, parsed, 0.9), "invalid-output");
});

it("keeps fact, safety and raw allow floors independent", () => {
  const exact = reviewVerdict(forgedFact({ probability: 0.9 }), forgedParsed({ safety: 0.9, pAllow: 0.9 }), 0.9);
  assert.equal(exact.decision, "allow");
  assertAbstains(reviewVerdict(forgedFact({ probability: 0.9 }), forgedParsed({ safety: 0.9, pAllow: 0.899 }), 0.9));
  assertAbstains(reviewVerdict(forgedFact({ probability: 0.9 }), forgedParsed({ safety: 0.899, pAllow: 0.9 }), 0.9));
  assertAbstains(reviewVerdict(forgedFact({ probability: 0.95 }), forgedParsed({ safety: 0.95, pAllow: 0.95, selected: "review" }), 0.9));
});

it("uses static reasons without echoing request data", () => {
  const marker = "user-private-marker";
  const invalid = reviewVerdict(forgedFact({ model: marker, probability: 0.1 }), validParsed, 0.9);
  assertAbstains(invalid, "context");
  assert.doesNotMatch(invalid.reason, /user-private-marker/);
  const allowed = reviewVerdict(validFact, validParsed, 0.9);
  assert.doesNotMatch(allowed.reason, /test-provider/);
});

it("does not mutate or retain inputs across reused verdict calls", () => {
  const fact = Object.freeze({ ...validFact, fieldMetadata: Object.freeze({ authority: false as const }) });
  const parsed = Object.freeze({ ...validParsed });
  const first = reviewVerdict(fact, parsed, 0.9);
  const second = reviewVerdict(fact, parsed, 0.9);
  assert.equal(first.decision, "allow");
  assert.deepEqual(second, first);
  assert.notEqual(first, second);
  assert.deepEqual(fact, validFact);
  assert.deepEqual(parsed, validParsed);
});

it("parses the native two-answer vector without normalizing probabilities", () => {
  const parsed = parseReview(answer(0.92, "allow", vector(0.95, 0.0500005), { confidence: "bad" }));
  assert.equal(parsed.safety, 0.92);
  assert.equal(parsed.selected, "allow");
  assert.equal(parsed.pAllow, 0.95);
});

it("requires the strict native vector to sum to one within 1e-6", () => {
  rejects(() => parseReview(answer(0.95, "allow", vector(0.904, 0.105))));
  rejects(() => parseReview(answer(0.95, "allow", vector(0.95, 0.050002))));
  const accepted = parseReview(answer(0.95, "allow", vector(0.95, 0.0500005)));
  assert.equal(accepted.pAllow, 0.95);
});

it("requires exactly the two unique typed answers", () => {
  const valid = answer(0.95, "allow", vector(0.95, 0.05));
  const answers = valid.answers as unknown[];
  for (const response of [
    { answers: [answers[0]] },
    { answers: [...answers, { type: "predicate", name: "safety", probability: 0.95 }] },
    { answers: [answers[0], { type: "choice", name: "safety", choice: "allow", probabilities: vector(0.95, 0.05) }] },
    { answers: [{ type: "predicate", name: "authorization", probability: 0.95 }, answers[1]] },
    { answers: [answers[0], { ...answers[1] as object, name: "other" }] },
    { answers: [answers[0], answers[1], answers[1]] },
    { answers: "not-an-array" },
    {},
  ]) rejects(() => parseReview(response));
});

it("rejects malformed safety probabilities", () => {
  for (const safety of [Number.NaN, 1.01, -0.01, Number.POSITIVE_INFINITY, "0.95", undefined])
    rejects(() => parseReview(answer(safety, "allow", vector(0.95, 0.05))));
});

it("rejects malformed authorization choices and distributions", () => {
  rejects(() => parseReview(answer(0.95, "maybe", vector(0.95, 0.05))));
  rejects(() => parseReview(answer(0.95, true, vector(0.95, 0.05))));
  rejects(() => parseReview(answer(0.95, "allow", [{ value: "allow", probability: 0.95 }])));
  rejects(() => parseReview(answer(0.95, "allow", vector(0.5, 0.5).concat({ value: "review", probability: 0 }))));
  rejects(() => parseReview(answer(0.95, "allow", [{ value: "allow", probability: 0.95 }, { value: "allow", probability: 0.05 }])));
  rejects(() => parseReview(answer(0.95, "allow", [{ value: true, probability: 0.95 }, { value: "review", probability: 0.05 }])));
  rejects(() => parseReview(answer(0.95, "allow", [{ value: "allow", probability: 0.95 }, { value: "review", probability: Number.NaN }])));
  rejects(() => parseReview(answer(0.95, "allow", [{ value: "allow", probability: 1.1 }, { value: "review", probability: -0.1 }])));
  rejects(() => parseReview(answer(0.95, "allow", [{ value: "allow", probability: 0.95 }, "review"])));
  rejects(() => parseReview(answer(0.95, "allow", "allow")));
});

it("requires the selected label to match the distribution maximum", () => {
  rejects(() => parseReview(answer(0.95, "allow", vector(0.4, 0.6))));
  const tied = parseReview(answer(0.5, "review", vector(0.5, 0.5)));
  assert.equal(tied.selected, "review");
  assert.equal(tied.pAllow, 0.5);
});

it("ignores an optional malformed confidence when native probabilities exist", () => {
  for (const confidence of [Number.NaN, -5, 12, "bad", undefined]) {
    const extra = confidence === undefined ? {} : { confidence };
    const parsed = parseReview(answer(0.95, "allow", vector(0.95, 0.05), extra));
    assert.equal(parsed.selected, "allow");
    assert.equal(parsed.pAllow, 0.95);
  }
});

const delegationFact = forgedFact({ kind: "delegation", probability: 1 });

const forgedAuthorization = (overrides: Record<string, unknown>): ParsedAuthorization =>
  ({ selected: "allow", pAllow: 0.95, ...overrides }) as unknown as ParsedAuthorization;

it("allows only a certified delegation with raw allow at the floor", () => {
  const allowed = delegationVerdict(delegationFact, { selected: "allow", pAllow: 0.9 }, 0.9);
  assert.equal(allowed.decision, "allow");
  assert.equal(allowed.stage, "fact-review");
  assert.match(allowed.reason,
    /Delegation authorized at native probability 0\.900 \(child actions reviewed separately\)/);
  assertAbstains(delegationVerdict(delegationFact, { selected: "allow", pAllow: 0.899 }, 0.9));
  assertAbstains(delegationVerdict(delegationFact, { selected: "review", pAllow: 0.95 }, 0.9));
});

it("rejects uncertified or non-delegation facts at the delegation verdict", () => {
  const parsed: ParsedAuthorization = { selected: "allow", pAllow: 0.99 };
  assertAbstains(delegationVerdict(forgedFact({ kind: "inspection", probability: 1 }), parsed, 0.9), "context");
  assertAbstains(delegationVerdict(forgedFact({ kind: "delegation", probability: 0.9 }), parsed, 0.95), "context");
  for (const forged of [
    forgedAuthorization({ pAllow: Number.NaN }),
    forgedAuthorization({ pAllow: 1.2 }),
    forgedAuthorization({ selected: "maybe" }),
    null as unknown as ParsedAuthorization,
  ]) assertAbstains(delegationVerdict(delegationFact, forged, 0.9), "invalid-output");
});

it("rejects the delegation shape from the full review verdict", () => {
  assertAbstains(reviewVerdict(delegationFact, forgedParsed({ safety: 0.99, pAllow: 0.99 }), 0.9), "context");
});

it("parses the delegation answer strictly as one authorization choice", () => {
  const one = { answers: [{
    type: "choice", name: "authorization", choice: "allow", probabilities: vector(0.95, 0.05),
  }] };
  assert.deepEqual(parseAuthorizationReview(one), { selected: "allow", pAllow: 0.95 });
  rejects(() => parseAuthorizationReview(answer(0.95, "allow", vector(0.95, 0.05))));
  rejects(() => parseAuthorizationReview({ answers: [] }));
  rejects(() => parseAuthorizationReview({}));
  rejects(() => parseAuthorizationReview({ answers: [
    { type: "choice", name: "authorization", choice: "allow", probabilities: vector(0.4, 0.6) },
  ] }));
});
