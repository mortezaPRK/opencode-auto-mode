import { after, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { linkSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, sep } from "node:path";
import { prepareCapturedEdit, type EditPayload } from "./edit-capture.js";
import { prepareEditCandidate, prepareProjectEditCandidate, type EditFactRequest } from "./edit-fact.js";

const ROOT = realpathSync(mkdtempSync(join(tmpdir(), "edit-fact-targets-")));
const OUTSIDE = realpathSync(mkdtempSync(join(tmpdir(), "edit-fact-outside-")));
const DECLARED = realpathSync(mkdtempSync(join(tmpdir(), "edit-fact-declared-")));
const ALIAS = join(dirname(ROOT), `edit-fact-alias-${process.pid}`);
const PROJECT = join(ROOT, "packages", "a");
const PROJECT_ALIAS = join(ROOT, "project-alias");
const SIBLING = join(ROOT, "packages", "b");
const IDENTITY = { sessionID: "session-1", messageID: "message-1", callID: "call-1" } as const;

mkdirSync(PROJECT, { recursive: true });
mkdirSync(join(SIBLING, "real"), { recursive: true });
mkdirSync(join(ROOT, ".git"));
mkdirSync(join(OUTSIDE, "child"), { recursive: true });
mkdirSync(join(DECLARED, "repo", ".git"), { recursive: true });
mkdirSync(join(DECLARED, "outside"), { recursive: true });
writeFileSync(join(OUTSIDE, "parser.ts"), "const a = 1;\n");
writeFileSync(join(OUTSIDE, "child", "parser.ts"), "const a = 1;\n");
writeFileSync(join(DECLARED, "outside", "parser.ts"), "const a = 1;\n");
writeFileSync(join(ROOT, "parser.ts"), "const a = 1;\n");
writeFileSync(join(PROJECT, "parser.ts"), "const a = 1;\n");
writeFileSync(join(SIBLING, "parser.ts"), "const a = 1;\n");
writeFileSync(join(PROJECT, "hardlinked.ts"), "const a = 1;\n");
linkSync(join(PROJECT, "hardlinked.ts"), join(PROJECT, "linked.ts"));
symlinkSync(join(PROJECT, "parser.ts"), join(PROJECT, ".env"));
symlinkSync(join(SIBLING, "real"), join(SIBLING, "inner"));
symlinkSync(join(OUTSIDE, "child"), join(ROOT, "escape"));
symlinkSync(ROOT, join(ROOT, "loop"));
symlinkSync(ROOT, ALIAS);
symlinkSync(PROJECT, PROJECT_ALIAS);
after(() => {
  unlinkSync(ALIAS);
  rmSync(ROOT, { recursive: true, force: true });
  rmSync(OUTSIDE, { recursive: true, force: true });
  rmSync(DECLARED, { recursive: true, force: true });
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
  return relativeRequest(tool, path, PROJECT);
}

function relativeRequest(tool: "edit" | "write", path: string, projectDir: string): EditFactRequest {
  const payload = mint(tool, path);
  return {
    action: tool,
    resources: [path],
    projectDir,
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

it("validates the original relative spelling below a symlinked project directory", () => {
  const blocked = prepareEditCandidate(relativeRequest("edit", "parser.ts", PROJECT_ALIAS), true);
  assert.equal(blocked.ok, false, "relative payload through a symlinked project directory");
  const aliased = prepareEditCandidate(relativeRequest("edit", "parser.ts", join(ALIAS, "packages", "a")), true);
  if (!aliased.ok) assert.fail(aliased.reason);
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

it("rejects parent components in every captured alias and operation target", () => {
  const traversal = [join(PROJECT, "nested"), "..", "parser.ts"].join(sep);
  assert.equal(prepareCapturedEdit({
    tool: "edit", args: { path: traversal, oldString: "const a = 1;", newString: "const a = 2;" },
  }, IDENTITY, true), undefined, "edit path alias");
  assert.equal(prepareCapturedEdit({
    tool: "write", args: { filePath: traversal, content: "const a = 2;\n" },
  }, IDENTITY, true), undefined, "write filePath alias");
  const target = join(PROJECT, "parser.ts");
  const request = fullRequest("edit", target);
  const traversing: EditFactRequest = {
    ...request,
    resources: [traversal],
    operation: { ...request.operation!, targets: [traversal], arguments: { path: traversal } },
  };
  assert.equal(prepareEditCandidate(traversing, true).ok, false, "full payload operation target");
  blocksMetadata(metadataRequest(traversal, { path: traversal }), "metadata operation target");
});

it("rejects a symlinked parent component before lexical normalization", () => {
  const traversal = [join(ROOT, "escape"), "..", "parser.ts"].join(sep);
  assert.equal(prepareCapturedEdit({
    tool: "edit", args: { path: traversal, oldString: "const a = 1;", newString: "const a = 2;" },
  }, IDENTITY, true), undefined, "captured payload");
  blocksMetadata(metadataRequest(traversal, { path: traversal }), "metadata target through a symlinked parent");
});

it("rejects an explicitly uncorrelated capture even with matching targets", () => {
  const target = join(PROJECT, "parser.ts");
  const request = metadataRequest(target, { path: target });
  const uncorrelated: EditFactRequest = {
    ...request,
    operation: { ...request.operation!, correlated: false },
  };
  blocksMetadata(uncorrelated, "an explicitly uncorrelated operation must not become a candidate");
  assert.equal(prepareProjectEditCandidate(request).ok, true, "an omitted correlation stays eligible");
});

it("does not let an unverified worktree root widen the metadata boundary", () => {
  const target = join(DECLARED, "outside", "parser.ts");
  blocksMetadata(metadataRequest(target, { path: target }, {
    projectDir: join(DECLARED, "repo"), worktreeRoot: DECLARED,
  }), "declared ancestor root");
});

it("walks components from the outermost spelling that resolves to the checkout root", () => {
  const looped = join(ROOT, "loop", "parser.ts");
  blocksMetadata(metadataRequest(looped, { path: looped }), "descendant symlink back to the root");
});
