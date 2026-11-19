import { it } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { policyRoots } from "../path-policy.js";
import { parseOptions } from "../config.js";
import { buildOperationEvidence } from "../operation-evidence.js";
import { scoreRequest } from "../score.js";

const options = parseOptions({ classifiers: [{ type: "static" }] });
const mcp = (args: Record<string, unknown>) => ({
  action: "mcp__filesystem__read", resources: ["*"], projectDir: "/repo",
  operation: { access: "unknown" as const, complete: true, arguments: args },
});

it("denies protected stores selected through recognized operation path fields", () => {
  for (const field of ["path", "filePath", "file_path", "root", "directory", "workdir", "cwd"]) {
    const result = scoreRequest(mcp({ [field]: ".env" }), options);
    assert.equal(result.deny, true, field);
    assert.equal(result.reason, "Protected path access", field);
    assert.ok(result.findings?.some((finding) => finding.startsWith("protected:")), field);
  }
});

it("denies supported credential stores selected by an MCP path", () => {
  const target = join(policyRoots().home, ".aws/credentials");
  const result = scoreRequest(mcp({ path: target }), options);
  assert.equal(result.deny, true);
});

it("keeps URLs, protocol-relative paths, ordinary paths and review-only names out of the protected floor", () => {
  for (const target of ["https://example.invalid/.env", "HTTPS://example.invalid/.env",
    "//example.invalid/.env", "src/index.ts", "credentials", ".env.example"]) {
    const result = scoreRequest(mcp({ path: target }), options);
    assert.notEqual(result.deny, true, target);
    assert.equal(result.band, "high", target);
  }
});

it("does not treat a network query as a filesystem operation target", () => {
  const operation = buildOperationEvidence({
    action: "websearch", resources: [".env"], metadata: { query: ".env" },
  });
  assert.equal(Object.hasOwn(operation, "targets"), false);
  const result = scoreRequest({ action: "websearch", resources: [".env"], projectDir: "/repo", operation }, options);
  assert.notEqual(result.deny, true);
  assert.equal(result.band, "high");
});

it("denies protected external-directory targets and ignores URL targets", () => {
  const external = scoreRequest({
    action: "external_directory", resources: ["/outside/*"], projectDir: "/repo",
    operation: { access: "write", complete: true, targets: ["/outside/.env"] },
  }, options);
  assert.equal(external.deny, true);
  const url = scoreRequest({
    action: "external_directory", resources: ["/outside/*"], projectDir: "/repo",
    operation: { access: "write", complete: true, targets: ["https://example.invalid/.env"] },
  }, options);
  assert.notEqual(url.deny, true);
});

it("does not treat metadata or arbitrary identifiers as selected paths", () => {
  const result = scoreRequest({
    action: "mcp__tracker__read", resources: ["*"], projectDir: "/repo",
    metadata: { input: { path: ".env" } },
    operation: { access: "unknown", complete: true, arguments: { issueID: ".env", target: ".env", path: "src/index.ts" } },
  }, options);
  assert.notEqual(result.deny, true);
  assert.equal(result.band, "high");
  const metadataOnly = scoreRequest({
    action: "mcp__tracker__read", resources: ["*"], projectDir: "/repo",
    metadata: { input: { path: ".env" } },
  }, options);
  assert.notEqual(metadataOnly.deny, true);
  assert.equal(metadataOnly.band, "high");
});

it("leaves ordinary operation paths and existing action scoring unchanged", () => {
  const shell = scoreRequest({
    action: "shell", resources: ["pwd"], projectDir: "/repo",
    operation: { access: "execute", complete: true, arguments: { workdir: "src" } },
  }, options);
  assert.equal(shell.deny, undefined);
  assert.equal(shell.band, "low");
  const protectedShell = scoreRequest({
    action: "shell", resources: ["pwd"], projectDir: "/repo",
    operation: { access: "execute", complete: true, arguments: { workdir: ".env" } },
  }, options);
  assert.equal(protectedShell.deny, true);
});
