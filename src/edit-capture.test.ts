import { it } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  capturedEditArgs,
  prepareCapturedEdit,
  readEditCapture,
  sameEditCapture,
  verifyCapturedEdit,
  type CapturedEditIdentity,
  type EditPayload,
} from "./edit-capture.js";

const PATH = "/repo/src/parser.ts";
const IDENTITY = { sessionID: "session-1", messageID: "message-1", callID: "call-1" };
const sha = (value: string): string => createHash("sha256").update(value).digest("hex");

function mintEdit(args: Record<string, unknown> = { path: PATH, oldString: "a", newString: "b" }): EditPayload {
  const payload = prepareCapturedEdit({ tool: "edit", args }, IDENTITY, true);
  assert.ok(payload, "expected a minted edit payload");
  return payload;
}

it("mints a frozen payload with a canonical edit args digest", () => {
  const payload = mintEdit();
  assert.deepEqual(payload.capture, {
    ...IDENTITY,
    argsSha256: sha(`{"newString":"b","oldString":"a","path":"${PATH}"}`),
  });
  assert.equal(Object.isFrozen(payload), true);
  assert.equal(Object.isFrozen(payload.capture), true);
  assert.equal(Reflect.set(payload, "path", "/repo/other.ts"), false);
  assert.equal(Reflect.set(payload.capture, "argsSha256", "0".repeat(64)), false);
  assert.equal(payload.path, PATH);
  assert.notEqual(verifyCapturedEdit(payload), undefined);
});

it("mints a write payload with a canonical content digest", () => {
  const payload = prepareCapturedEdit({ tool: "write", args: { path: PATH, content: "x" } }, IDENTITY, true);
  assert.ok(payload);
  assert.deepEqual(verifyCapturedEdit(payload)?.capture, payload.capture);
  assert.equal(payload.capture.argsSha256, sha(`{"content":"x","path":"${PATH}"}`));
});

it("mints a filePath edit and keeps the exact original alias in provenance", () => {
  const payload = mintEdit({ filePath: PATH, oldString: "a", newString: "b" });
  assert.equal(payload.path, PATH);
  assert.equal(payload.capture.argsSha256,
    sha(`{"filePath":"${PATH}","newString":"b","oldString":"a"}`));
  assert.notEqual(verifyCapturedEdit(payload), undefined);
  assert.deepEqual(capturedEditArgs(payload), {
    filePath: PATH, oldString: "a", newString: "b",
  });
});

it("mints a filePath write and keeps the exact original alias in provenance", () => {
  const payload = prepareCapturedEdit({
    tool: "write", args: { filePath: PATH, content: "x" },
  }, IDENTITY, true);
  assert.ok(payload);
  assert.equal(payload.capture.argsSha256, sha(`{"content":"x","filePath":"${PATH}"}`));
  assert.deepEqual(capturedEditArgs(payload), { filePath: PATH, content: "x" });
});

it("retains replaceAll and binds the changed flag into the digest", () => {
  const absent = mintEdit();
  const enabled = mintEdit({ path: PATH, oldString: "a", newString: "b", replaceAll: true });
  const disabled = mintEdit({ path: PATH, oldString: "a", newString: "b", replaceAll: false });
  assert.equal(absent.replaceAll, undefined);
  assert.equal(enabled.replaceAll, true);
  assert.equal(disabled.replaceAll, false);
  assert.equal(enabled.capture.argsSha256,
    sha(`{"newString":"b","oldString":"a","path":"${PATH}","replaceAll":true}`));
  assert.equal(new Set([absent, enabled, disabled].map((item) => item.capture.argsSha256)).size, 3);
  assert.deepEqual(capturedEditArgs(enabled), {
    path: PATH, oldString: "a", newString: "b", replaceAll: true,
  });
  assert.deepEqual(capturedEditArgs(disabled), {
    path: PATH, oldString: "a", newString: "b", replaceAll: false,
  });
});

it("accepts both path aliases only when they name the same canonical path", () => {
  const payload = mintEdit({
    path: "/repo/src/./parser.ts", filePath: PATH, oldString: "a", newString: "b",
  });
  assert.equal(payload.path, "/repo/src/./parser.ts");
  assert.deepEqual(capturedEditArgs(payload), {
    path: "/repo/src/./parser.ts", filePath: PATH, oldString: "a", newString: "b",
  });
  assert.equal(prepareCapturedEdit({
    tool: "edit",
    args: { path: PATH, filePath: "/repo/src/other.ts", oldString: "a", newString: "b" },
  }, IDENTITY, true), undefined);
});

it("never mints without exact explicit consent", () => {
  const event = { tool: "edit" as const, args: { path: PATH, oldString: "a", newString: "b" } };
  assert.equal(prepareCapturedEdit(event, IDENTITY, false), undefined);
  assert.equal(prepareCapturedEdit(event, IDENTITY, undefined as unknown as boolean), undefined);
});

it("rejects args that are not the exact recognized edit/write shape", () => {
  const invalid: readonly (readonly ["edit" | "write", string, unknown])[] = [
    ["edit", "missing newString", { path: PATH, oldString: "a" }],
    ["edit", "missing oldString", { path: PATH, newString: "b" }],
    ["edit", "empty oldString", { path: PATH, oldString: "", newString: "b" }],
    ["edit", "content on edit", { path: PATH, oldString: "a", newString: "b", content: "x" }],
    ["edit", "non-boolean replaceAll",
      { path: PATH, oldString: "a", newString: "b", replaceAll: "true" }],
    ["edit", "undefined replaceAll",
      { path: PATH, oldString: "a", newString: "b", replaceAll: undefined }],
    ["edit", "unknown edit field",
      { path: PATH, oldString: "a", newString: "b", extra: true }],
    ["edit", "both aliases absent", { oldString: "a", newString: "b" }],
    ["edit", "conflicting aliases",
      { path: PATH, filePath: "/repo/other.ts", oldString: "a", newString: "b" }],
    ["edit", "non-string filePath", { filePath: 1, oldString: "a", newString: "b" }],
    ["write", "missing content", { path: PATH }],
    ["write", "oldString on write", { path: PATH, content: "x", oldString: "a" }],
    ["write", "spurious field", { path: PATH, content: "x", replaceAll: true }],
    ["write", "unknown write field", { path: PATH, content: "x", extra: true }],
    ["edit", "non-string path", { path: 1, oldString: "a", newString: "b" }],
    ["edit", "wildcard path", { path: "/repo/*.ts", oldString: "a", newString: "b" }],
    ["edit", "home path", { path: "~/parser.ts", oldString: "a", newString: "b" }],
    ["edit", "nul path", { path: "/repo/a\0b", oldString: "a", newString: "b" }],
    ["write", "non-filePath wildcard", { filePath: "/repo/*.ts", content: "x" }],
    ["write", "non-record args", "body"],
  ];
  for (const [tool, label, args] of invalid) {
    const event = { tool, args: args as Record<string, unknown> };
    assert.equal(prepareCapturedEdit(event, IDENTITY, true), undefined, label);
  }
  assert.equal(prepareCapturedEdit(
    { tool: "patch" as unknown as "edit", args: { path: PATH } }, IDENTITY, true,
  ), undefined);
});

it("rejects malformed capture coordinates", () => {
  const event = { tool: "edit" as const, args: { path: PATH, oldString: "a", newString: "b" } };
  const bad: readonly CapturedEditIdentity[] = [
    { ...IDENTITY, sessionID: "" },
    { ...IDENTITY, messageID: "" },
    { ...IDENTITY, callID: "c".repeat(257) },
    { ...IDENTITY, callID: "a\0b" },
  ];
  for (const identity of bad) {
    assert.equal(prepareCapturedEdit(event, identity, true), undefined, identity.callID);
  }
});

it("binds the minted snapshot rather than the mutable source args", () => {
  const args = { path: PATH, oldString: "a", newString: "b", replaceAll: true };
  const payload = prepareCapturedEdit({ tool: "edit", args }, IDENTITY, true);
  assert.ok(payload);
  args.path = "/repo/other.ts";
  args.newString = "tampered";
  args.replaceAll = false;
  assert.equal(payload.path, PATH);
  assert.equal(payload.newString, "b");
  assert.equal(payload.replaceAll, true);
  const original = capturedEditArgs(payload);
  assert.ok(original);
  assert.equal(Object.isFrozen(original), true);
  assert.equal(Reflect.set(original, "path", "/repo/other.ts"), false);
  assert.deepEqual(original, { path: PATH, oldString: "a", newString: "b", replaceAll: true });
  assert.notEqual(verifyCapturedEdit(payload), undefined);
});

it("rejects clones, forged digests and structurally valid non-minted objects", () => {
  const payload = mintEdit();
  assert.equal(verifyCapturedEdit({ ...payload, capture: { ...payload.capture } }), undefined);
  assert.equal(capturedEditArgs({ ...payload, capture: { ...payload.capture } }), undefined);
  const forged = {
    tool: "edit", path: "/repo/other.ts", oldString: "a", newString: "b", complete: true,
    capture: {
      ...payload.capture,
      argsSha256: sha('{"newString":"b","oldString":"a","path":"/repo/other.ts"}'),
    },
  };
  assert.equal(verifyCapturedEdit(forged), undefined);
  assert.equal(verifyCapturedEdit({ ...forged, capture: payload.capture }), undefined);
});

it("validates capture identity shape without granting provenance", () => {
  const payload = mintEdit();
  assert.deepEqual(readEditCapture(payload.capture), payload.capture);
  assert.equal(sameEditCapture(readEditCapture({ ...payload.capture })!, payload.capture), true);
  assert.equal(sameEditCapture({ ...payload.capture, callID: "other" }, payload.capture), false);
  assert.equal(readEditCapture({ ...payload.capture, argsSha256: "ABC" }), undefined);
  assert.equal(readEditCapture({ ...payload.capture, extra: true }), undefined);
});
