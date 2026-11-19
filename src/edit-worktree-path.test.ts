import { after, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { prepareCapturedEdit, type EditPayload } from "./edit-capture.js";
import { prepareEditCandidate, type EditFactRequest } from "./edit-fact.js";
import type { OperationEvidence } from "./reviewer.js";

const ROOT = realpathSync(mkdtempSync(join(tmpdir(), "edit-worktree-path-")));
const STORAGE = join(ROOT, ".local", "share", "opencode", "worktree");
const PARENT = join(STORAGE, "crisp-star");
const TARGET = join(STORAGE, "feature-stage");
const PLAIN = join(STORAGE, "plain");
const OUTSIDE = join(ROOT, "outside");
const GITDIR = join(ROOT, "metadata", "worktrees", "feature-stage");
const IDENTITY = { sessionID: "session-1", messageID: "message-1", callID: "call-1" } as const;

type Marker = "directory" | "file" | "none";

function repository(path: string, marker: Marker): void {
  mkdirSync(join(path, "src"), { recursive: true });
  if (marker === "directory") mkdirSync(join(path, ".git"));
  if (marker === "file") {
    mkdirSync(GITDIR, { recursive: true });
    writeFileSync(join(path, ".git"), `gitdir: ${GITDIR}\n`);
  }
}

function mint(path: string): EditPayload {
  const payload = prepareCapturedEdit({
    tool: "edit",
    args: { path, oldString: "const a = 1;", newString: "const a = 2;" },
  }, IDENTITY, true);
  assert.ok(payload, `expected a minted payload for ${path}`);
  return payload;
}

function operation(path: string): OperationEvidence {
  return { tool: "edit", access: "write", targets: [path], arguments: { path }, complete: false };
}

function request(path: string, overrides: Partial<EditFactRequest> = {}): EditFactRequest {
  const payload = overrides.editPayload ?? mint(path);
  return {
    action: "edit",
    resources: [path],
    projectDir: PARENT,
    operation: operation(path),
    ...overrides,
    editPayload: payload,
    expectedEditCapture: overrides.expectedEditCapture ?? payload.capture,
  };
}

function accepts(req: EditFactRequest, label: string): void {
  const result = prepareEditCandidate(req, true);
  if (!result.ok) assert.fail(`${label}: ${result.reason}`);
  assert.equal(result.candidate.input.target, req.editPayload?.path, label);
}

function blocks(req: EditFactRequest, label: string): void {
  const result = prepareEditCandidate(req, true);
  if (result.ok) assert.fail(label);
  assert.match(result.reason, /path is protected, ambiguous or unresolved/, label);
}

repository(PARENT, "directory");
repository(TARGET, "file");
repository(PLAIN, "none");
repository(OUTSIDE, "directory");
writeFileSync(join(TARGET, "src", "parser.ts"), "const a = 1;\n");
writeFileSync(join(PARENT, "src", "parser.ts"), "const a = 1;\n");
writeFileSync(join(PLAIN, "src", "parser.ts"), "const a = 1;\n");
writeFileSync(join(OUTSIDE, "src", "parser.ts"), "const a = 1;\n");
after(() => rmSync(ROOT, { recursive: true, force: true }));

it("accepts a target in its own linked worktree despite a dotted storage ancestor", () => {
  const path = join(TARGET, "src", "parser.ts");
  accepts(request(path, { worktreeRoot: PARENT }), "declared session root differs");
  accepts(request(path, { worktreeRoot: TARGET }), "declared target root");
  accepts(request(join(TARGET, "src", "new.ts")), "missing file in existing worktree directory");
  accepts(request(join(TARGET, "newdir", "new.ts")), "missing file below a missing directory");
  accepts(request(join(PARENT, "src", "parser.ts"), { projectDir: TARGET }), "directory marker");
});

it("does not trust a declared root or the no-marker fallback", () => {
  blocks(request(join(PLAIN, "src", "parser.ts"), { worktreeRoot: PLAIN }), "declared plain root");
  blocks(request(join(PLAIN, "src", "parser.ts"), { worktreeRoot: STORAGE }), "declared ancestor root");
});

it("leaves ordinary no-Git project paths unchanged", () => {
  const path = join(PLAIN, "src", "parser.ts");
  accepts(request(path, { projectDir: PLAIN }), "absolute direct path");
  accepts(request(join("src", "parser.ts"), { projectDir: PLAIN }), "relative direct path");
});

it("keeps inner dot names, credential names and protected stores blocked", () => {
  for (const name of [".github/workflows/ci.yml", "auth.json", ".env", "key.pem"])
    blocks(request(join(TARGET, name)), name);
});

it("blocks symlink components below the verified root", () => {
  symlinkSync(join(OUTSIDE, "src"), join(TARGET, "src", "escape"));
  mkdirSync(join(TARGET, "src", "real"), { recursive: true });
  symlinkSync(join(TARGET, "src", "real"), join(TARGET, "src", "inner"));
  blocks(request(join(TARGET, "src", "escape", "parser.ts")), "symlink escape");
  blocks(request(join(TARGET, "src", "inner", "new.ts")), "inner symlink");
});

it("rejects a symlink marker and a linked marker without a real directory", () => {
  const linked = join(STORAGE, "linked-marker");
  mkdirSync(join(linked, "src"), { recursive: true });
  symlinkSync(join(PARENT, ".git"), join(linked, ".git"));
  blocks(request(join(linked, "src", "parser.ts")), "symlink marker");
  const broken = join(STORAGE, "broken-marker");
  mkdirSync(join(broken, "src"), { recursive: true });
  writeFileSync(join(broken, ".git"), `gitdir: ${join(ROOT, "missing")}\n`);
  blocks(request(join(broken, "src", "parser.ts")), "missing linked directory");
});

it("rejects a marker file that is not a gitdir pointer", () => {
  const invalid = join(STORAGE, "invalid-marker");
  mkdirSync(join(invalid, "src"), { recursive: true });
  writeFileSync(join(invalid, ".git"), "not a gitdir pointer\n");
  blocks(request(join(invalid, "src", "parser.ts")), "invalid marker");
});

it("accepts a linked marker whose gitdir pointer is relative to the worktree", () => {
  const linked = join(STORAGE, "relative-marker");
  mkdirSync(join(linked, "src"), { recursive: true });
  writeFileSync(join(linked, ".git"), `gitdir: ${relative(linked, GITDIR)}\n`);
  accepts(request(join(linked, "src", "parser.ts")), "relative linked marker");
});
