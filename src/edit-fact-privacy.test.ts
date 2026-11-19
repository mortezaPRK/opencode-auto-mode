import { after, it } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { prepareCapturedEdit } from "./edit-capture.js";
import { prepareEditCandidate, type EditFactRequest } from "./edit-fact.js";

const ROOT = realpathSync(mkdtempSync(join(tmpdir(), "edit-fact-privacy-")));
const SRC = join(ROOT, "src");
const TARGET = join(SRC, "parser.ts");
const IDENTITY = { sessionID: "session-1", messageID: "message-1", callID: "call-1" } as const;

mkdirSync(SRC, { recursive: true });
mkdirSync(join(ROOT, ".git"));
writeFileSync(TARGET, "const a = 1;\n");
after(() => rmSync(ROOT, { recursive: true, force: true }));

function request(tool: "edit" | "write", path: string, body: Record<string, string>,
  alias: "path" | "filePath" = "path"): EditFactRequest {
  const payload = prepareCapturedEdit({ tool, args: { [alias]: path, ...body } }, IDENTITY, true);
  assert.ok(payload, `expected a minted ${tool} payload for ${path}`);
  return {
    action: tool,
    resources: [path],
    projectDir: ROOT,
    operation: { tool, access: "write", targets: [path], arguments: { [alias]: path }, complete: true },
    editPayload: payload,
    expectedEditCapture: payload.capture,
  };
}

function blocks(req: EditFactRequest, label: string): void {
  assert.equal(prepareEditCandidate(req, true).ok, false, label);
}

function accepts(req: EditFactRequest, label: string): void {
  const result = prepareEditCandidate(req, true);
  if (!result.ok) assert.fail(`${label}: ${result.reason}`);
}

/** Built from parts so the checkout's own credential scanner stays clean. */
const GITHUB_TOKEN = ["gh", "p_AbCdEfGhIjKlMnOpQrStUvWx"].join("");
const AWS_KEY = ["AK", "IAABCDEFGHIJKLMNOP"].join("");
const PRIVATE_KEY = ["-----BEGIN ", "OPENSSH PRIVATE KEY-----"].join("");
const ASSIGNED_SECRET = ["api_key", " = ", JSON.stringify("abcd1234abcd1234")].join("");

/** Each entry is a body a provider call must never carry. */
const BLOCKED_BODIES: readonly (readonly [string, string])[] = [
  ["cloud token", `const token = "${GITHUB_TOKEN}";`],
  ["aws key", `const id = '${AWS_KEY}';`],
  ["credential assignment", ASSIGNED_SECRET],
  ["secret header", "Authorization: Bearer abcdef1234567890"],
  ["jwt", "const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature';"],
  ["private key", `${PRIVATE_KEY}\nmaterial`],
  ["raw request line", "POST /v1/charges HTTP/1.1\nHost: api.example.com"],
  ["curl body", "curl --data '{\"card\":\"4111111111111111\"}' https://api.example.com"],
  ["json secret field", '{"password":"hunter2hunter2"}'],
  ["escaped json secret", '{\\"api_key\\":\\"value1234\\"}'],
];

const BENIGN_BODIES: readonly (readonly [string, string])[] = [
  ["plain edit pair", "const total = 2;"],
  ["mention of tokens", "export const tokenCount = 3;\n// tokens stay small"],
  ["benign json", '{"count":2,"name":"parser"}'],
];

it("blocks edit strings that carry credentials, HTTP bodies or wrapped secrets", () => {
  for (const [name, body] of BLOCKED_BODIES) {
    blocks(request("edit", TARGET, { oldString: "const a = 1;", newString: body }), `newString: ${name}`);
    blocks(request("edit", TARGET, { oldString: body, newString: "const a = 2;" }), `oldString: ${name}`);
  }
});

it("blocks write content that carries credentials, HTTP bodies or wrapped secrets", () => {
  for (const [name, body] of BLOCKED_BODIES) blocks(request("write", TARGET, { content: body }), name);
});

it("keeps benign edit and write bodies eligible", () => {
  for (const [name, body] of BENIGN_BODIES) {
    accepts(request("edit", TARGET, { oldString: "const a = 1;", newString: body }), `edit: ${name}`);
    accepts(request("write", TARGET, { content: body }), `write: ${name}`);
  }
});

it("blocks a captured path that carries a recognized credential", () => {
  const secret = join(SRC, GITHUB_TOKEN, "parser.ts");
  blocks(request("edit", secret, { oldString: "const a = 1;", newString: "const a = 2;" }), "edit path");
  blocks(request("write", secret, { content: "const a = 2;\n" }, "filePath"), "write filePath alias");
});

it("keeps an ordinary nested captured path eligible", () => {
  const nested = join(SRC, "nested", "parser.ts");
  accepts(request("edit", nested, { oldString: "const a = 1;", newString: "const a = 2;" }), "nested path");
});
