import { after, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { classifyOperationFacts, type OperationFactRequest } from "./decision-facts.js";
import type { DecisionContext } from "./decision.js";
import { prepareCapturedEdit, type EditPayload } from "./edit-capture.js";
import { prepareEditCandidate, type EditCandidate, type EditFactRequest } from "./edit-fact.js";
import type { OperationEvidence } from "./reviewer.js";

const ROOT = realpathSync(mkdtempSync(join(tmpdir(), "edit-fact-guards-")));
const SRC = join(ROOT, "src");
const PATH = join(SRC, "parser.ts");
const OTHER = join(SRC, "other.ts");
const WILDCARD = join(ROOT, "*");
const IDENTITY = { sessionID: "session-1", messageID: "message-1", callID: "call-1" } as const;

mkdirSync(SRC, { recursive: true });
after(() => rmSync(ROOT, { recursive: true, force: true }));

function mintEdit(overrides: { path?: string; oldString?: string; newString?: string } = {}): EditPayload {
  const payload = prepareCapturedEdit({
    tool: "edit",
    args: {
      path: overrides.path ?? PATH,
      oldString: overrides.oldString ?? "const a = 1;",
      newString: overrides.newString ?? "const a = 2;",
    },
  }, IDENTITY, true);
  assert.ok(payload, "expected a minted edit payload");
  return payload;
}

function mintWrite(content: string, path = PATH): EditPayload {
  const payload = prepareCapturedEdit({ tool: "write", args: { path, content } }, IDENTITY, true);
  assert.ok(payload, "expected a minted write payload");
  return payload;
}

function operation(overrides: Partial<OperationEvidence> = {}): OperationEvidence {
  return {
    tool: "edit", access: "write", targets: [PATH], arguments: { path: PATH },
    complete: false, ...overrides,
  };
}

function request(overrides: Partial<EditFactRequest> = {}): EditFactRequest {
  const payload = overrides.editPayload ?? mintEdit();
  return {
    action: "edit",
    resources: [PATH],
    projectDir: ROOT,
    operation: operation(),
    ...overrides,
    editPayload: payload,
    expectedEditCapture: overrides.expectedEditCapture ?? payload.capture,
  };
}

function writeRequest(content: string): EditFactRequest {
  const payload = mintWrite(content);
  return request({
    action: "write",
    editPayload: payload,
    operation: operation({ tool: "write", targets: [PATH], arguments: { path: PATH } }),
  });
}

function candidateOf(req: EditFactRequest, label: string): EditCandidate {
  const result = prepareEditCandidate(req, true);
  if (!result.ok) assert.fail(`${label}: ${result.reason}`);
  return result.candidate;
}

function blockedReason(req: EditFactRequest, label: string): string {
  const result = prepareEditCandidate(req, true);
  if (result.ok) assert.fail(label);
  return result.reason;
}

it("rejects the entire target set when any operation target is unusable", () => {
  const invalidTargets: readonly (readonly [string, unknown])[] = [
    ["wildcard", "/repo/*"],
    ["home", "~/parser.ts"],
    ["empty", ""],
    ["nul", "/repo/a\0b"],
    ["non-string", 42],
    ["object", { path: PATH }],
    ["missing", undefined],
  ];
  for (const [label, invalid] of invalidTargets) {
    blockedReason(request({
      operation: operation({ targets: [PATH, invalid] as unknown as string[] }),
    }), label);
  }
});

it("validates every fallback resource when no operation target is present", () => {
  blockedReason(request({
    resources: [PATH, 42] as unknown as string[],
    operation: operation({ targets: undefined }),
  }), "non-string fallback");
  blockedReason(request({
    resources: [PATH, WILDCARD],
    operation: operation({ targets: undefined }),
  }), "wildcard fallback");
  blockedReason(request({
    resources: [PATH, "~/outside.ts"],
    operation: operation({ targets: undefined }),
  }), "home fallback");
  blockedReason(request({
    resources: [],
    operation: operation({ targets: undefined }),
  }), "empty fallback");
  blockedReason(request({
    operation: operation({ targets: "not-an-array" as unknown as string[] }),
  }), "malformed operation targets");
});

it("uses explicit operation targets and ignores a permission boundary", () => {
  candidateOf(request({
    action: "external_directory",
    resources: [WILDCARD],
    operation: operation({ targets: [PATH], arguments: { path: PATH } }),
  }), "external boundary");
  candidateOf(request({
    action: "external_directory",
    resources: [WILDCARD, 42] as unknown as string[],
    operation: operation({ targets: [PATH], arguments: { path: PATH } }),
  }), "malformed boundary is not an actual target");
  blockedReason(request({
    action: "external_directory",
    resources: [WILDCARD],
    operation: operation({ targets: [], arguments: { path: PATH } }),
  }), "boundary cannot be the target");
  blockedReason(request({
    action: "external_directory",
    resources: [WILDCARD],
    operation: operation({ targets: [PATH, WILDCARD], arguments: { path: PATH } }),
  }), "mixed operation targets");
});

it("accepts incomplete body evidence only with a complete target proof", () => {
  candidateOf(request({ operation: operation({ complete: false }) }), "body omission");
  blockedReason(request({
    operation: operation({ complete: false, targets: [PATH, 42] as unknown as string[] }),
  }), "invalid target list is not recovered");
  blockedReason(request({
    action: "external_directory",
    resources: [WILDCARD],
    operation: operation({ complete: false, targets: [] }),
  }), "lost targets are not inferred from a boundary");
});

it("normalizes the full set and accepts only one distinct payload path", () => {
  candidateOf(request({
    operation: operation({
      targets: [PATH, join(SRC, ".", "parser.ts"), join(SRC, "..", "src", "parser.ts")],
    }),
  }), "duplicate normalized target");
  const relative = mintEdit({ path: join("src", "parser.ts") });
  candidateOf(request({
    editPayload: relative,
    resources: [PATH],
    operation: operation({ targets: [join(SRC, ".", "parser.ts")] }),
  }), "relative payload path");
  blockedReason(request({
    operation: operation({ targets: [PATH, OTHER] }),
  }), "two distinct targets");
  blockedReason(request({
    operation: operation({ targets: [OTHER], arguments: { path: OTHER } }),
  }), "different single target");
});

it("requires exact path or filePath argument corroboration", () => {
  candidateOf(request({
    operation: operation({ arguments: { path: PATH, filePath: PATH } }),
  }), "both arguments");
  candidateOf(request({
    operation: operation({ arguments: { filePath: PATH } }),
  }), "filePath only");
  blockedReason(request({
    operation: operation({ arguments: { path: PATH, filePath: OTHER } }),
  }), "one mismatching argument");
  blockedReason(request({
    operation: operation({ arguments: { path: 42 } }),
  }), "non-string argument");
  blockedReason(request({
    operation: operation({ arguments: { path: WILDCARD } }),
  }), "wildcard argument");
  blockedReason(request({
    operation: operation({ arguments: {} }),
  }), "missing argument");
});

it("still requires a minted payload bound to the expected capture", () => {
  const minted = mintEdit();
  blockedReason(request({
    editPayload: { ...minted, capture: { ...minted.capture } },
  }), "clone");
  blockedReason(request({
    editPayload: minted,
    expectedEditCapture: { ...minted.capture, callID: "call-2" },
  }), "capture mismatch");
});

it("rejects protected, ambiguous and unresolved payload paths", () => {
  const protectedPaths = [".env", ".env.local", ".github/workflows/ci.yml", "credentials.json"]
    .map((name) => join(ROOT, name));
  for (const path of protectedPaths) {
    const payload = mintEdit({ path });
    blockedReason(request({
      editPayload: payload,
      resources: [path],
      operation: operation({ targets: [path], arguments: { path } }),
    }), path);
  }
  const fileDir = mkdtempSync(join(tmpdir(), "edit-fact-guards-file-"));
  try {
    const file = join(fileDir, "plain.ts");
    writeFileSync(file, "x");
    const unresolved = join(file, "child.ts");
    const payload = mintEdit({ path: unresolved });
    blockedReason(request({
      projectDir: fileDir,
      editPayload: payload,
      resources: [unresolved],
      operation: operation({ targets: [unresolved], arguments: { path: unresolved } }),
    }), "unresolved path");
  } finally {
    rmSync(fileDir, { recursive: true, force: true });
  }
});

it("keeps the approved payload order and exact source bytes", () => {
  const candidate = candidateOf(request(), "valid edit");
  assert.deepEqual(candidate.input, {
    args: { newString: "const a = 2;", oldString: "const a = 1;", path: PATH },
    target: PATH,
    tool: "edit",
  });
  assert.equal(JSON.stringify(candidate.input), JSON.stringify({
    args: { newString: "const a = 2;", oldString: "const a = 1;", path: PATH },
    target: PATH,
    tool: "edit",
  }));
});

it("blocks prefixed, multiline, JSON-wrapped and escaped request lines", () => {
  const requestLine = ["POST", "/collect", "HTTP/1.1"].join(" ");
  const cases: readonly (readonly [string, string])[] = [
    ["prefixed", `example ${requestLine}`],
    ["multiline", `const before = 1;\n${requestLine}`],
    ["json", JSON.stringify({ request: requestLine })],
    ["escaped", JSON.stringify(JSON.stringify({ request: requestLine }))],
    ["json unicode spaces", '{"request":"POST\\u0020/collect\\u0020HTTP/1.1"}'],
    ["unicode", "example \\u0050OST /collect HTTP/1.1"],
  ];
  for (const [label, content] of cases) blockedReason(writeRequest(content), label);
  blockedReason(request({
    editPayload: mintEdit({ newString: `const before = 1;\n${requestLine}` }),
  }), "edit body");
});

it("blocks JSON-wrapped and escaped credential fields", () => {
  const cases: readonly (readonly [string, string])[] = [
    ["json authorization", JSON.stringify({ authorization: "Bearer fixture-token" })],
    ["escaped authorization", JSON.stringify(JSON.stringify({ authorization: "Bearer fixture-token" }))],
    ["json password", JSON.stringify({ password: "fixture-hunter2" })],
    ["quoted assignment", 'const authorization = "Bearer fixture-token";'],
    ["unicode key", '{"\\u0061uthorization":"Bearer fixture-token"}'],
  ];
  for (const [label, content] of cases) blockedReason(writeRequest(content), label);
});

it("allows ordinary source without a request line or credential field", () => {
  candidateOf(writeRequest("export const method = 'POST';\nexport const path = '/collect';\n"), "ordinary source");
  candidateOf(writeRequest("export const authorization = false;\n"), "ordinary identifier");
});

it("rejects an explicit empty operation target set instead of using resources", async () => {
  candidateOf(request({ operation: operation({ targets: undefined }) }), "absent targets use resources");
  const emptyTargets = (complete: boolean): EditFactRequest => request({
    resources: [PATH],
    operation: operation({ targets: [], arguments: { path: PATH }, complete }),
  });
  blockedReason(emptyTargets(false), "empty explicit targets with incomplete operation");
  blockedReason(emptyTargets(true), "empty explicit targets with complete operation");
  await unknownWithoutProvider(emptyTargets(false), "empty explicit targets");
});

const FACT_OPTIONS = { model: "test-provider/test-model", timeoutMs: 1_000, includeEditPayload: true };

async function unknownWithoutProvider(req: EditFactRequest, label: string): Promise<void> {
  let calls = 0;
  const ctx: DecisionContext = {
    experimental: {
      generate: {
        decisions: () => {
          calls += 1;
          return Promise.resolve(undefined);
        },
      },
    },
  };
  const mutable: OperationFactRequest = { ...req, resources: [...req.resources] };
  const result = await classifyOperationFacts(ctx, FACT_OPTIONS, mutable);
  assert.equal(result.kind, "unknown", label);
  assert.equal(result.errorKind, "context", label);
  assert.equal(calls, 0, label);
}

it("blocks JSON-wrapped, prefixed or credential bodies with zero provider calls", async () => {
  const requestLine = ["POST", "/collect", "HTTP/1.1"].join(" ");
  const bodies: readonly (readonly [string, string])[] = [
    ["json", JSON.stringify({ request: requestLine })],
    ["prefixed", `example ${requestLine}`],
    ["authorization", JSON.stringify({ authorization: "Bearer fixture-token" })],
  ];
  for (const [label, content] of bodies) await unknownWithoutProvider(writeRequest(content), label);
});
