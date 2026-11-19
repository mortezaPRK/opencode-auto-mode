import { after, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { prepareCapturedEdit } from "./edit-capture.js";
import { prepareEditCandidate, type EditFactRequest } from "./edit-fact.js";
import type { OperationEvidence } from "./reviewer.js";

const ROOT = realpathSync(mkdtempSync(join(tmpdir(), "edit-fact-action-")));
const SRC = join(ROOT, "src");
const TARGET = join(SRC, "parser.ts");
const IDENTITY = { sessionID: "session-1", messageID: "message-1", callID: "call-1" } as const;

mkdirSync(SRC, { recursive: true });
mkdirSync(join(ROOT, ".git"));
writeFileSync(TARGET, "const a = 1;\n");
after(() => rmSync(ROOT, { recursive: true, force: true }));

function request(tool: "edit" | "write", action: string, operationTool: string | undefined): EditFactRequest {
  const args = tool === "edit"
    ? { path: TARGET, oldString: "const a = 1;", newString: "const a = 2;" }
    : { path: TARGET, content: "const a = 2;\n" };
  const payload = prepareCapturedEdit({ tool, args }, IDENTITY, true);
  assert.ok(payload, `expected a minted ${tool} payload`);
  const operation: OperationEvidence = {
    ...(operationTool === undefined ? {} : { tool: operationTool }),
    access: "write",
    targets: [TARGET],
    arguments: { path: TARGET },
    complete: true,
  };
  return {
    action,
    resources: [TARGET],
    projectDir: ROOT,
    operation,
    editPayload: payload,
    expectedEditCapture: payload.capture,
  };
}

it("accepts a captured write arriving under the edit permission action", () => {
  const result = prepareEditCandidate(request("write", "edit", "write"), true);
  if (!result.ok) assert.fail(result.reason);
  assert.equal(result.candidate.input.tool, "write");
});

it("accepts a captured edit arriving under the write permission action", () => {
  const result = prepareEditCandidate(request("edit", "write", "edit"), true);
  if (!result.ok) assert.fail(result.reason);
  assert.equal(result.candidate.input.tool, "edit");
});

it("falls back to the permission action when the operation names no tool", () => {
  const accepted = prepareEditCandidate(request("edit", "edit", undefined), true);
  if (!accepted.ok) assert.fail(accepted.reason);
  assert.equal(prepareEditCandidate(request("write", "edit", undefined), true).ok, false);
});

it("rejects a payload whose tool contradicts the operation", () => {
  assert.equal(prepareEditCandidate(request("write", "edit", "edit"), true).ok, false, "write payload, edit tool");
  assert.equal(prepareEditCandidate(request("edit", "edit", "write"), true).ok, false, "edit payload, write tool");
});
