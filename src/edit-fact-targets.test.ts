import { after, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { linkSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { prepareCapturedEdit, type EditPayload } from "./edit-capture.js";
import { prepareEditCandidate, prepareProjectEditCandidate, type EditFactRequest } from "./edit-fact.js";

const ROOT = realpathSync(mkdtempSync(join(tmpdir(), "edit-fact-targets-")));
const OUTSIDE = realpathSync(mkdtempSync(join(tmpdir(), "edit-fact-outside-")));
const ALIAS = join(dirname(ROOT), `edit-fact-alias-${process.pid}`);
const PROJECT = join(ROOT, "packages", "a");
const SIBLING = join(ROOT, "packages", "b");
const IDENTITY = { sessionID: "session-1", messageID: "message-1", callID: "call-1" } as const;

mkdirSync(PROJECT, { recursive: true });
mkdirSync(join(SIBLING, "real"), { recursive: true });
mkdirSync(join(ROOT, ".git"));
writeFileSync(join(OUTSIDE, "parser.ts"), "const a = 1;\n");
writeFileSync(join(PROJECT, "parser.ts"), "const a = 1;\n");
writeFileSync(join(SIBLING, "parser.ts"), "const a = 1;\n");
writeFileSync(join(PROJECT, "hardlinked.ts"), "const a = 1;\n");
linkSync(join(PROJECT, "hardlinked.ts"), join(PROJECT, "linked.ts"));
symlinkSync(join(PROJECT, "parser.ts"), join(PROJECT, ".env"));
symlinkSync(join(SIBLING, "real"), join(SIBLING, "inner"));
symlinkSync(ROOT, ALIAS);
after(() => {
  unlinkSync(ALIAS);
  rmSync(ROOT, { recursive: true, force: true });
  rmSync(OUTSIDE, { recursive: true, force: true });
});

function mint(tool: "edit" | "write", path: string): EditPayload {
  const args = tool === "edit"
    ? { path, oldString: "const a = 1;", newString: "const a = 2;" }
    : { path, content: "const a = 2;\n" };
  const payload = prepareCapturedEdit({ tool, args }, IDENTITY, true);
  assert.ok(payload, `expected a minted ${tool} payload for ${path}`);
  return payload;
}

function fullRequest(tool: "edit" | "write", path: string): EditFactRequest {
  const payload = mint(tool, path);
  return {
    action: tool,
    resources: [path],
    projectDir: PROJECT,
    operation: { tool, access: "write", targets: [path], arguments: { path }, complete: true },
    editPayload: payload,
    expectedEditCapture: payload.capture,
  };
}

function metadataRequest(path: string, args: Record<string, string>,
  overrides: Partial<EditFactRequest> = {}): EditFactRequest {
  return {
    action: "edit",
    resources: [path],
    projectDir: PROJECT,
    worktreeRoot: ROOT,
    operation: { tool: "edit", access: "write", targets: [path], arguments: args, complete: true },
    staticAnalysis: { band: "low", reason: "no findings" },
    ...overrides,
  };
}

function blocksMetadata(request: EditFactRequest, label: string): void {
  const result = prepareProjectEditCandidate(request);
  if (result.ok) assert.fail(label);
}

it("rejects a minted write to an existing non-regular file", { skip: process.platform === "win32" }, () => {
  const fifo = join(PROJECT, "output.ts");
  execFileSync("mkfifo", [fifo]);
  const result = prepareEditCandidate(fullRequest("write", fifo), true);
  assert.equal(result.ok, false, "a FIFO target must not become a one-file edit candidate");
});

it("rejects a minted edit to a hardlinked file", () => {
  const result = prepareEditCandidate(fullRequest("edit", join(PROJECT, "linked.ts")), true);
  assert.equal(result.ok, false, "a target with a second link must not become a one-file edit candidate");
});

it("keeps regular single-link and missing targets eligible for the full payload", () => {
  for (const target of [join(PROJECT, "parser.ts"), join(PROJECT, "newdir", "new.ts")]) {
    const result = prepareEditCandidate(fullRequest("edit", target), true);
    if (!result.ok) assert.fail(`${target}: ${result.reason}`);
  }
});

it("rejects a protected argument alias that canonicalizes onto the same file", () => {
  const target = join(PROJECT, "parser.ts");
  blocksMetadata(metadataRequest(target, { path: join(PROJECT, ".env") }),
    "a .env symlink alias must not ride a parser.ts resource target");
});

it("accepts a target elsewhere in the same checkout from a nested project directory", () => {
  const target = join(SIBLING, "parser.ts");
  const result = prepareProjectEditCandidate(metadataRequest(target, { path: target }));
  assert.ok(result.ok);
  assert.deepEqual(result.candidate.input.targets, ["packages/b/parser.ts"]);
});

it("accepts a missing suffix elsewhere in the same checkout", () => {
  const target = join(SIBLING, "new.ts");
  assert.equal(prepareProjectEditCandidate(metadataRequest(target, { path: target })).ok, true);
});

it("walks components from a symlinked root spelling", () => {
  const target = join(ALIAS, "packages", "b", "parser.ts");
  const result = prepareProjectEditCandidate(metadataRequest(target, { path: target }, {
    projectDir: join(ALIAS, "packages", "a"),
    worktreeRoot: ALIAS,
  }));
  assert.ok(result.ok);
});

it("still rejects targets outside the checkout and symlink components inside it", () => {
  const outside = join(OUTSIDE, "parser.ts");
  blocksMetadata(metadataRequest(outside, { path: outside }), "target outside the declared checkout");
  const inner = join(SIBLING, "inner", "new.ts");
  blocksMetadata(metadataRequest(inner, { path: inner }), "inner symlink below the checkout root");
});
