import { expect, test } from "bun:test";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const MODEL = { providerID: "fixture", id: "judge" };
const T0 = "2026-01-01T00:00:00.000Z";

function event(type: string, reviewID: string, stageIndex: number | null, payload: unknown, extra: Record<string, unknown> = {}) {
  return {
    ts: T0, type, instanceID: "fixture-instance",
    sourceLocation: { project: { directory: "/tmp/fixture-project" } },
    reviewID, sessionID: "ses_fixture", stageIndex, payload, ...extra,
  };
}

function permission(reviewID: string, action: string, resources: string[], metadata?: unknown, source = { type: "tool", messageID: "msg_1", id: "call_1" }) {
  return event("permission.evaluate.before", reviewID, null, { action, agent: "general", effect: "ask", resources, metadata, source, sessionID: "ses_fixture" });
}

function decisionStart(reviewID: string, stageIndex = 1, minConfidence = 0.9) {
  return event("classifier.start", reviewID, stageIndex, { type: "decision", model: `${MODEL.providerID}/${MODEL.id}`, minConfidence, timeoutMs: 3000 });
}

function decisionBefore(reviewID: string, evidence: unknown, format: "predicate" | "legacy", callID = "call_1", stageIndex = 1) {
  const questions = format === "predicate"
    ? [{ type: "predicate", name: "safety", instructions: "safety" }, { type: "predicate", name: "authorization", instructions: "authorization" }]
    : [{ type: "choice", name: "permission", instructions: "permission", choices: [{ value: "allow" }, { value: "deny" }, { value: "ask" }] }];
  return event("generate.decisions.before", reviewID, stageIndex, {
    model: MODEL, input: [{ type: "text", text: JSON.stringify(evidence) }], questions,
  }, { callID });
}

function decisionAfter(reviewID: string, answers: unknown, callID = "call_1", stageIndex = 1) {
  return event("generate.decisions.after", reviewID, stageIndex, { answers, native: {}, tokens: {} }, { callID });
}

function stageEnd(reviewID: string, decision: string, stageIndex = 1, errorKind?: string) {
  return event("classifier.end", reviewID, stageIndex, { decision, stage: stageIndex === 1 ? "decision" : "reviewer", ...(errorKind === undefined ? {} : { errorKind }) });
}

function llm(reviewID: string) {
  return [
    event("classifier.start", reviewID, 2, { type: "llm", model: "fixture/reviewer" }),
    event("classifier.end", reviewID, 2, { decision: "allow", stage: "reviewer" }),
  ];
}

function final(reviewID: string, decision: string) {
  return { ts: T0, reviewID, sessionID: "ses_fixture", action: "shell", resources: ["true"], decision, stage: "decision", reason: "fixture", durationMs: 1 };
}

const PREDICATE_HIGH = {
  answers: [
    { type: "predicate", name: "safety", probability: 0.96 },
    { type: "predicate", name: "authorization", probability: 0.94 },
  ],
};
const PREDICATE_LOW = {
  answers: [
    { type: "predicate", name: "safety", probability: 0.3 },
    { type: "predicate", name: "authorization", probability: 0.2 },
  ],
};
const LEGACY_ANSWER = {
  answers: [{
    type: "choice", name: "permission", choice: "allow", confidence: 0.5,
    probabilities: [{ value: "allow", probability: 0.5 }, { value: "deny", probability: 0.1 }, { value: "ask", probability: 0.4 }],
  }],
};

function toolCall(messageID: string, id: string, tool: string, input: unknown) {
  return { ts: T0, type: "tool.execute.before", payload: { sessionID: "ses_fixture", messageID, id, tool, input } };
}

function allowRows(): unknown[] {
  return [
    toolCall("msg_1", "call_1", "read", { path: "/tmp/fixture-project/a.ts" }),
    permission("review-allow", "read", ["/tmp/fixture-project/a.ts"], undefined),
    event("classifier.start", "review-allow", 0, { type: "static" }),
    stageEnd("review-allow", "abstain", 0),
    decisionStart("review-allow"),
    decisionBefore("review-allow", { action: "read", resources: ["/tmp/fixture-project/a.ts"], userMessages: ["TOY_SECRET user instruction"], staticAnalysis: { band: "low", reason: "fixture read" } }, "predicate"),
    decisionAfter("review-allow", PREDICATE_HIGH.answers),
    stageEnd("review-allow", "allow"),
    final("review-allow", "allow"),
  ];
}

function lowRows(): unknown[] {
  return [
    toolCall("msg_2", "call_2", "read", { path: "/tmp/fixture-project/b.ts" }),
    permission("review-low", "read", ["/tmp/fixture-project/b.ts"], undefined, { type: "tool", messageID: "msg_2", id: "call_2" }),
    decisionStart("review-low"),
    decisionBefore("review-low", { action: "read", resources: ["/tmp/fixture-project/b.ts"], userMessages: ["TOY_SECRET read b"] }, "predicate", "call_2"),
    decisionAfter("review-low", PREDICATE_LOW.answers, "call_2"),
    stageEnd("review-low", "abstain"),
    ...llm("review-low"), final("review-low", "allow"),
  ];
}

function legacyRows(): unknown[] {
  return [
    toolCall("msg_3", "call_3", "shell", { command: "echo hi" }),
    permission("review-legacy", "shell", ["echo hi"], { input: { command: "echo hi" } }, { type: "tool", messageID: "msg_3", id: "call_3" }),
    decisionStart("review-legacy"),
    decisionBefore("review-legacy", { action: "shell", resources: ["echo hi"], userMessages: ["say hi"] }, "legacy", "call_3"),
    decisionAfter("review-legacy", LEGACY_ANSWER.answers, "call_3"),
    stageEnd("review-legacy", "abstain"),
    ...llm("review-legacy"),
  ];
}

function incompleteRows(): unknown[] {
  return [
    permission("review-incomplete", "external_directory", ["/tmp/outside"], undefined, { type: "tool", messageID: "msg_4", id: "call_4" }),
    decisionStart("review-incomplete"),
    decisionBefore("review-incomplete", { action: "external_directory", resources: ["/tmp/outside"], userMessages: ["outside work"] }, "predicate", "call_4"),
    decisionAfter("review-incomplete", PREDICATE_HIGH.answers, "call_4"),
    stageEnd("review-incomplete", "abstain"), final("review-incomplete", "ask"),
  ];
}

function otherRows(): unknown[] {
  return [
    event("classifier.start", "review-other", 1, { type: "decision", model: "fixture/other", minConfidence: 0.9 }),
    event("generate.decisions.before", "review-other", 1, { model: { providerID: "fixture", id: "other" }, input: [{ type: "text", text: "{}" }], questions: [{ type: "choice" }] }, { callID: "call_other" }),
    event("generate.decisions.after", "review-other", 1, { answers: [] }, { callID: "call_other" }),
  ];
}

function missingRows(): unknown[] {
  return [
    toolCall("msg_5", "call_5", "read", { path: "/tmp/fixture-project/c.ts" }),
    permission("review-missing-after", "read", ["/tmp/fixture-project/c.ts"], undefined, { type: "tool", messageID: "msg_5", id: "call_5" }),
    decisionStart("review-missing-after"),
    decisionBefore("review-missing-after", { action: "read", resources: ["/tmp/fixture-project/c.ts"], userMessages: ["read c"] }, "predicate", "call_5"),
  ];
}

function writeFixture(root: string): string {
  const file = join(root, "audit.jsonl");
  const lines = [...allowRows(), ...lowRows(), ...legacyRows(), ...incompleteRows(), ...otherRows(), ...missingRows()]
    .map((row) => JSON.stringify(row));
  // Duplicate a request identity and include one malformed line.
  lines.push(lines[5]!, lines[6]!, "{not-json}");
  writeFileSync(file, `${lines.join("\n")}\n`);
  return file;
}

function run(args: string[], env: Record<string, string> = {}) {
  return spawnSync(process.execPath, [resolve("scripts/replay-decisions.ts"), ...args], { encoding: "utf8", env: { ...process.env, ...env } });
}

function writeSingleReview(root: string, evidence: unknown): string {
  const file = join(root, "audit.jsonl");
  const rows = [
    toolCall("msg_1", "call_1", "read", { path: "/tmp/fixture-project/a.ts" }),
    permission("review-audit", "read", ["/tmp/fixture-project/a.ts"]),
    decisionStart("review-audit"),
    decisionBefore("review-audit", evidence, "predicate"),
    decisionAfter("review-audit", PREDICATE_HIGH.answers),
    stageEnd("review-audit", "allow"),
  ];
  writeFileSync(file, `${rows.map((row) => JSON.stringify(row)).join("\n")}\n`);
  return file;
}

function fakeCli(root: string): string {
  const fake = join(root, "fake-opencode");
  writeFileSync(fake, [
    "#!/bin/sh",
    'printf "%s" "$4" > "$FAKE_BODY"',
    `printf '%s\\n' '${JSON.stringify({ data: { answers: PREDICATE_HIGH.answers } })}'`,
  ].join("\n"), { mode: 0o755 });
  chmodSync(fake, 0o755);
  return fake;
}

test("dry-run filters the model, joins exact tool input, dedupes, and reports predicate/legacy coverage", () => {
  const root = mkdtempSync(join(tmpdir(), "auto-mode-decisions-"));
  try {
    const input = writeFixture(root);
    const result = run(["--input", input, "--model", "fixture/judge", "--holdout", "0", "--json"]);
    expect(result.status).toBe(0);
    const report = JSON.parse(result.stdout);
    expect(report.mode).toBe("dry-run");
    expect(report.snapshot.files).toBe(1);
    expect(report.snapshot.fingerprint).toHaveLength(16);
    expect(report.prompt.hash).toHaveLength(16);
    expect(report.prompt.questions).toEqual(["safety", "authorization"]);
    expect(report.sources.malformed).toBe(1);
    expect(report.reviews.filteredOut).toBe(1);
    expect(report.reviews.duplicateEvents).toBeGreaterThan(0);
    expect(report.reviews.requests).toBe(5);
    expect(report.formats).toEqual({ legacy: 1, predicate: 4 });
    expect(report.pairing.missingAfter).toBe(1);
    expect(report.evidence.hostJoined).toBe(5);
    expect(report.evidence.operationIncomplete).toBe(1);
    expect(report.evidence.terminal).toBe(1);
    expect(report.evidence.preGeneration).toEqual({ operation: 1 });
    expect(report.predicate.basis).toContain("not a fresh model result");
    expect(report.predicate.outcomes).toEqual({ abstain: 1, allow: 1, "missing-after": 1, terminal: 1 });
    expect(report.legacy.outcomes).toEqual({ abstain: 1 });
    expect(report.recorded.decisions).toEqual({ abstain: 3, allow: 1, none: 1 });
    expect(report.recorded.fallback).toBe(2);
    expect(report.llm.outcomes).toEqual({ allow: 2, none: 3 });
    expect(report.final.decisions).toEqual({ allow: 2, ask: 1, none: 2 });
    expect(report.probabilities.safety?.count).toBe(2);
    expect(report.probabilities.authorization?.count).toBe(2);
    expect(report.actions.read.requests).toBe(3);
    expect(report.actions.read.primary).toBe(3);
    expect(report.actions.read.predicate).toEqual({ abstain: 1, allow: 1, "missing-after": 1 });
    expect(report.actions.shell.legacy).toEqual({ abstain: 1 });
    expect(report.actions.external_directory.predicate).toEqual({ terminal: 1 });
    expect(report.eligibility).toMatchObject({ total: 5, eligible: 4 });
    expect(report.eligibility.readOnly).toMatchObject({ total: 3, eligible: 3 });
    expect(report.eligibility.simpleGrep.eligible).toBe(0);
    expect(report.rebuild).toMatchObject({
      userMessagesRetained: 5, chronologyFallback: 0, resourcesChanged: 0,
      operationTargets: 3, operationArguments: 4,
    });
    expect(report.rebuild.operationAccess).toEqual({ execute: 1, read: 3, unknown: 1 });
    expect(result.stdout).not.toContain("TOY_SECRET");
    expect(result.stdout).not.toContain('"userMessages":');
    expect(result.stdout).not.toContain("oldString");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("live replay uses the authenticated CLI boundary only and prints normalized results", () => {
  const root = mkdtempSync(join(tmpdir(), "auto-mode-decisions-live-"));
  try {
    const input = writeFixture(root);
    const body = join(root, "body.json");
    const fake = join(root, "fake-opencode");
    writeFileSync(fake, [
      "#!/bin/sh",
      'printf "%s" "$4" > "$FAKE_BODY"',
      `printf '%s\\n' '${JSON.stringify({ data: { answers: [{ type: "predicate", name: "safety", probability: 0.97 }, { type: "predicate", name: "authorization", probability: 0.95 }] } })}'`,
    ].join("\n"), { mode: 0o755 });
    chmodSync(fake, 0o755);
    const result = run(["--input", input, "--model", "fixture/judge", "--live", "--limit", "1", "--seed", "7", "--opencode-bin", fake, "--details", "--json"], { FAKE_BODY: body });
    expect(result.status).toBe(0);
    const report = JSON.parse(result.stdout);
    expect(report.mode).toBe("live");
    expect(report.live.selected).toBe(1);
    expect(report.live.sampleFingerprint).toHaveLength(16);
    expect(report.live.modelCalls).toBe(1);
    expect(report.live.modelErrors).toBe(0);
    expect(report.live.statuses).toEqual({ allow: 1 });
    expect(report.live.vsLlm).toBeDefined();
    expect(report.live.actions).toBeDefined();
    expect(report.live.results).toHaveLength(1);
    expect(typeof report.live.results[0].action).toBe("string");
    expect(report.live.results[0].safety).toBe(0.97);
    const sent = JSON.parse(readFileSync(body, "utf8"));
    expect(sent.model).toEqual(MODEL);
    const evidence = JSON.parse(sent.input[0].text);
    expect(evidence.operation).toBeDefined();
    expect(evidence.userMessages).toBeDefined();
    expect(sent.questions.map((question: { name: string }) => question.name)).toEqual(["safety", "authorization"]);
    expect(result.stdout).not.toContain("TOY_SECRET");
    expect(result.stdout).not.toContain('"userMessages":');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("findings-only decision evidence keeps every concrete finding whole", () => {
  const root = mkdtempSync(join(tmpdir(), "auto-mode-findings-"));
  try {
    const findings = Array.from({ length: 20 }, (_, index) => `finding-${index}-${"x".repeat(990)}`);
    const input = writeSingleReview(root, {
      action: "read", resources: ["/tmp/fixture-project/a.ts"], userMessages: ["read a"],
      staticAnalysis: { findings },
    });
    const body = join(root, "body.json");
    const fake = fakeCli(root);
    const result = run(["--input", input, "--model", "fixture/judge", "--live", "--limit", "1",
      "--opencode-bin", fake, "--json"], { FAKE_BODY: body });
    expect(result.status).toBe(0);
    const report = JSON.parse(result.stdout);
    expect(report.live.statuses).toEqual({ allow: 1 });
    const sent = JSON.parse(readFileSync(body, "utf8"));
    const evidence = JSON.parse(sent.input[0].text);
    expect(evidence.staticAnalysis.findings).toEqual(findings);
    expect(evidence.userMessages).toEqual(["read a"]);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("oversized legacy transcript is not used as unbounded chronology fallback", () => {
  const root = mkdtempSync(join(tmpdir(), "auto-mode-oversized-"));
  try {
    const input = writeSingleReview(root, {
      action: "read", resources: ["/tmp/fixture-project/a.ts"], userInstruction: "x".repeat(12_001),
    });
    const dry = run(["--input", input, "--model", "fixture/judge", "--json"]);
    expect(dry.status).toBe(0);
    const dryReport = JSON.parse(dry.stdout);
    expect(dryReport.evidence.missingChronology).toBe(1);
    expect(dryReport.eligibility.eligible).toBe(0);
    expect(dryReport.eligibility.reasons["missing-chronology"]).toBe(1);
    const body = join(root, "body.json");
    const fake = fakeCli(root);
    const live = run(["--input", input, "--model", "fixture/judge", "--live", "--limit", "1",
      "--opencode-bin", fake, "--json"], { FAKE_BODY: body });
    expect(live.status).toBe(0);
    const liveReport = JSON.parse(live.stdout);
    expect(liveReport.live.eligible).toBe(0);
    expect(liveReport.live.selected).toBe(0);
    expect(liveReport.live.modelCalls).toBe(0);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("missing input fails closed instead of selecting a personal path", () => {
  const result = run(["--model", "fixture/judge", "--input", "/tmp/does-not-exist-auto-mode-audit.jsonl"]);
  expect(result.status).not.toBe(0);
  expect(result.stderr).toContain("Audit source does not exist");
});

test("model filter is required instead of defaulting to a personal model", () => {
  const result = run([]);
  expect(result.status).not.toBe(0);
  expect(result.stderr).toContain("--model <provider>/<id> is required");
});
