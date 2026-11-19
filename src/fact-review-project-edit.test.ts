import { after, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { linkSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import type { DecisionContext, DecisionInput } from "./decision.js";
import {
  reviewWithOperationFact,
  type FactReviewOptions,
  type FactReviewRequest,
} from "./fact-review.js";

type Decisions = DecisionContext["experimental"]["generate"]["decisions"];
type Reply = () => Promise<unknown>;

const options: FactReviewOptions = { model: "test-provider/test-model", timeoutMs: 2_000, minConfidence: 0.9 };
const context = (decisions: Decisions): DecisionContext => ({ experimental: { generate: { decisions } } });

interface Pipeline {
  ctx: DecisionContext;
  calls: string[][];
  inputs: DecisionInput[];
}

/** One reply per native call, in issue order; an unexpected extra call fails. */
function pipeline(replies: readonly Reply[]): Pipeline {
  const calls: string[][] = [];
  const inputs: DecisionInput[] = [];
  const decisions: Decisions = async (input) => {
    calls.push(input.questions.map((question) => question.name));
    inputs.push(input);
    const reply = replies[calls.length - 1];
    if (reply === undefined) throw new Error("unexpected edit fact-review question");
    return reply();
  };
  return { ctx: context(decisions), calls, inputs };
}

function textOf(input: DecisionInput | undefined): string {
  const part = input?.input[0];
  return part?.type === "text" ? part.text : "";
}

const projectReply = (choice: boolean, probability: number): Reply => async () => ({
  answers: [{
    type: "choice", name: "edit_in_project", choice,
    probabilities: [
      { value: true, probability: choice ? probability : 1 - probability },
      { value: false, probability: choice ? 1 - probability : probability },
    ],
  }],
});

const ROOT = realpathSync(mkdtempSync(join(tmpdir(), "opencode-project-edit-")));
mkdirSync(join(ROOT, "src"), { recursive: true });
writeFileSync(join(ROOT, "src", "parser.ts"), "const a = 1;\n");
after(() => rmSync(ROOT, { recursive: true, force: true }));
const TARGET = join(ROOT, "src", "parser.ts");
const RELATIVE_TARGET = join("src", "parser.ts");

function request(overrides: Partial<FactReviewRequest> = {}): FactReviewRequest {
  return {
    action: "edit",
    resources: [RELATIVE_TARGET],
    projectDir: ROOT,
    worktreeRoot: ROOT,
    userMessages: ["Implement the parser change."],
    staticAnalysis: { band: "low", reason: "Verified in-project file operation", findings: [] },
    operation: {
      tool: "edit", access: "write", targets: [RELATIVE_TARGET],
      arguments: { path: RELATIVE_TARGET }, complete: false,
    },
    ...overrides,
  };
}

function targetRequest(target: string): FactReviewRequest {
  return request({
    resources: [target],
    operation: { tool: "edit", access: "write", targets: [target], arguments: { path: target }, complete: false },
  });
}

it("allows an ordinary in-project edit from one metadata-only question", async () => {
  const fake = pipeline([projectReply(true, 0.95)]);
  const result = await reviewWithOperationFact(fake.ctx, options, request());
  assert.equal(result.decision, "allow");
  assert.equal(result.stage, "fact-review");
  assert.match(result.reason, /metadata-only project edit/);
  assert.deepEqual(fake.calls, [["edit_in_project"]]);
  assert.deepEqual(JSON.parse(textOf(fake.inputs[0])), {
    tool: "edit", targets: [join("src", "parser.ts")], projectDir: basename(ROOT),
  });
  assert.doesNotMatch(textOf(fake.inputs[0]), /const a = 1/);
});

it("never asks the metadata-only question for external_directory edits", async () => {
  const fake = pipeline([projectReply(true, 0.95)]);
  const result = await reviewWithOperationFact(fake.ctx, options,
    request({ action: "external_directory", resources: [join(ROOT, "*")] }));
  assert.equal(result.decision, "abstain");
  assert.equal(result.errorKind, "context");
  assert.deepEqual(fake.calls, []);
});

it("refuses relative escapes and absolute targets outside the project without a call", async () => {
  for (const target of [join("..", "outside.ts"), join(ROOT, "..", "outside.ts")]) {
    const fake = pipeline([projectReply(true, 0.95)]);
    const result = await reviewWithOperationFact(fake.ctx, options, targetRequest(target));
    assert.equal(result.decision, "abstain", target);
    assert.equal(result.errorKind, "context", target);
    assert.deepEqual(fake.calls, [], target);
  }
});

it("refuses VCS internals, dependency trees and credential targets without a call", async () => {
  for (const target of [
    ".env",
    join(".git", "config"),
    join("node_modules", "pkg", "index.ts"),
    "certs/server.pem",
    "keys/signing.key",
    "id_rsa",
    "id_ed25519",
    "config/credentials.json",
    "config/app.secret.yaml",
    ".npmrc",
    ".netrc",
    ".pgpass",
    ".pypirc",
    "main.tfstate",
    "cert.p12",
    join(".github", "workflows", "ci.yml"),
  ]) {
    const fake = pipeline([projectReply(true, 0.95)]);
    const result = await reviewWithOperationFact(fake.ctx, options, targetRequest(target));
    assert.equal(result.decision, "abstain", target);
    assert.equal(result.errorKind, "context", target);
    assert.deepEqual(fake.calls, [], target);
  }
});

it("refuses hardlinked, FIFO, directory and symlinked targets without a call", async () => {
  const outside = realpathSync(mkdtempSync(join(tmpdir(), "opencode-project-edit-outside-")));
  const linked = join(ROOT, "src", "linked.ts");
  // `mkfifo` is POSIX-only, so the FIFO case is skipped on Windows.
  const fifo = process.platform === "win32" ? undefined : join(ROOT, "src", "pipe.ts");
  const directory = join(ROOT, "src", "folder");
  const symlinkFile = join(ROOT, "src", "alias.ts");
  const symlinkDirectory = join(ROOT, "src", "alias-dir");
  try {
    writeFileSync(join(outside, "secret.ts"), "outside\n");
    linkSync(join(outside, "secret.ts"), linked);
    if (fifo !== undefined) execFileSync("mkfifo", [fifo]);
    mkdirSync(directory);
    symlinkSync(TARGET, symlinkFile);
    symlinkSync(join(ROOT, "src"), symlinkDirectory);
    for (const target of [linked, ...(fifo === undefined ? [] : [fifo]), directory, symlinkFile, join(symlinkDirectory, "parser.ts")]) {
      const fake = pipeline([projectReply(true, 0.95)]);
      const result = await reviewWithOperationFact(fake.ctx, options, targetRequest(target));
      assert.equal(result.decision, "abstain", target);
      assert.equal(result.errorKind, "context", target);
      assert.deepEqual(fake.calls, [], target);
    }
  } finally {
    rmSync(outside, { recursive: true, force: true });
    rmSync(linked, { force: true });
    if (fifo !== undefined) rmSync(fifo, { force: true });
    rmSync(directory, { recursive: true, force: true });
    rmSync(symlinkFile, { force: true });
    rmSync(symlinkDirectory, { recursive: true, force: true });
  }
});

it("refuses multi-path patch tools without a call", async () => {
  for (const tool of ["patch", "multiedit", "apply_patch"]) {
    const fake = pipeline([projectReply(true, 0.95)]);
    const result = await reviewWithOperationFact(fake.ctx, options, request({
      operation: {
        tool, access: "write", targets: [RELATIVE_TARGET],
        arguments: { path: RELATIVE_TARGET }, complete: false,
      },
    }));
    assert.equal(result.decision, "abstain", tool);
    assert.equal(result.errorKind, "context", tool);
    assert.deepEqual(fake.calls, [], tool);
  }
});

it("refuses missing or mismatched captured argument paths without a call", async () => {
  const other = join("src", "other.ts");
  for (const operation of [
    { tool: "edit", access: "write" as const, targets: [RELATIVE_TARGET], complete: false },
    { tool: "edit", access: "write" as const, targets: [RELATIVE_TARGET], arguments: {}, complete: false },
    { tool: "edit", access: "write" as const, targets: [RELATIVE_TARGET], arguments: { path: other }, complete: false },
    {
      tool: "edit", access: "write" as const, targets: [RELATIVE_TARGET],
      arguments: { path: RELATIVE_TARGET, filePath: other }, complete: false,
    },
  ]) {
    const fake = pipeline([projectReply(true, 0.95)]);
    const result = await reviewWithOperationFact(fake.ctx, options, request({ operation }));
    assert.equal(result.decision, "abstain", JSON.stringify(operation));
    assert.equal(result.errorKind, "context", JSON.stringify(operation));
    assert.deepEqual(fake.calls, [], JSON.stringify(operation));
  }
});

it("allows a new file below a safe existing parent chain", async () => {
  const fake = pipeline([projectReply(true, 0.95)]);
  const result = await reviewWithOperationFact(fake.ctx, options, targetRequest(join("src", "new-file.ts")));
  assert.equal(result.decision, "allow");
  assert.deepEqual(fake.calls, [["edit_in_project"]]);
});

it("refuses a resource that names a different canonical target", async () => {
  const fake = pipeline([projectReply(true, 0.95)]);
  const result = await reviewWithOperationFact(fake.ctx, options, request({
    resources: [RELATIVE_TARGET, join("src", "other.ts")],
  }));
  assert.equal(result.decision, "abstain");
  assert.equal(result.errorKind, "context");
  assert.deepEqual(fake.calls, []);
});

it("accepts a filePath alias that names the same canonical target", async () => {
  const fake = pipeline([projectReply(true, 0.95)]);
  const result = await reviewWithOperationFact(fake.ctx, options, request({
    operation: {
      tool: "edit", access: "write", targets: [RELATIVE_TARGET],
      arguments: { filePath: RELATIVE_TARGET }, complete: false,
    },
  }));
  assert.equal(result.decision, "allow");
  assert.deepEqual(fake.calls, [["edit_in_project"]]);
});

it("refuses any static finding and any missing static analysis without a call", async () => {
  for (const staticAnalysis of [
    { band: "high", reason: "Review", findings: ["path: requires review"] },
    undefined,
  ]) {
    const fake = pipeline([projectReply(true, 0.95)]);
    const result = await reviewWithOperationFact(fake.ctx, options, request({ staticAnalysis }));
    assert.equal(result.decision, "abstain");
    assert.equal(result.errorKind, "context");
    assert.deepEqual(fake.calls, []);
  }
});

it("keeps the 0.8 floor boundary for the metadata-only fact", async () => {
  const boundary = pipeline([projectReply(true, 0.8)]);
  const allowed = await reviewWithOperationFact(boundary.ctx, { ...options, minConfidence: 0.8 }, request());
  assert.equal(allowed.decision, "allow");
  assert.deepEqual(boundary.calls, [["edit_in_project"]]);

  const belowBoundary = pipeline([projectReply(true, 0.799)]);
  const abstained = await reviewWithOperationFact(belowBoundary.ctx, { ...options, minConfidence: 0.8 }, request());
  assert.equal(abstained.decision, "abstain");
  assert.equal(belowBoundary.calls.length, 1);

  const belowDefault = pipeline([projectReply(true, 0.899)]);
  const defaulted = await reviewWithOperationFact(belowDefault.ctx, options, request());
  assert.equal(defaulted.decision, "abstain");
  assert.equal(belowDefault.calls.length, 1);
});
