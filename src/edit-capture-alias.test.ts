import { after, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { prepareCapturedEdit } from "./edit-capture.js";
import { prepareEditCandidate, type EditCandidate, type EditFactRequest } from "./edit-fact.js";
import type { OperationEvidence } from "./reviewer.js";

const ROOT = realpathSync(mkdtempSync(join(tmpdir(), "edit-capture-alias-")));
const SRC = join(ROOT, "src");
const PATH = join(SRC, "parser.ts");
const IDENTITY = { sessionID: "session-1", messageID: "message-1", callID: "call-1" } as const;

mkdirSync(SRC, { recursive: true });
after(() => rmSync(ROOT, { recursive: true, force: true }));

function editCandidate(args: Record<string, unknown>): EditCandidate {
  const payload = prepareCapturedEdit({ tool: "edit", args }, IDENTITY, true);
  assert.ok(payload, "expected a minted edit payload");
  const operation: OperationEvidence = {
    tool: "edit", access: "write", targets: [PATH], arguments: { ...args }, complete: false,
  };
  const request: EditFactRequest = {
    action: "edit", resources: [PATH], projectDir: ROOT, operation, editPayload: payload,
    expectedEditCapture: payload.capture,
  };
  const result = prepareEditCandidate(request, true);
  if (!result.ok) assert.fail(result.reason);
  return result.candidate;
}

it("forwards the exact captured filePath alias and replaceAll flag", () => {
  const candidate = editCandidate({
    filePath: PATH, oldString: "a", newString: "b", replaceAll: true,
  });
  assert.deepEqual(candidate.input, {
    args: { newString: "b", oldString: "a", replaceAll: true, filePath: PATH },
    target: PATH,
    tool: "edit",
  });
});

it("forwards an explicit false replaceAll instead of dropping it", () => {
  const candidate = editCandidate({
    path: PATH, oldString: "a", newString: "b", replaceAll: false,
  });
  assert.deepEqual(candidate.input.args, {
    newString: "b", oldString: "a", replaceAll: false, path: PATH,
  });
});

it("keeps the approved path-only model body byte-identical", () => {
  const candidate = editCandidate({ path: PATH, oldString: "a", newString: "b" });
  assert.equal(JSON.stringify(candidate.input), JSON.stringify({
    args: { newString: "b", oldString: "a", path: PATH }, target: PATH, tool: "edit",
  }));
});
