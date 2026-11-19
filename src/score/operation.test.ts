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

it("honors grep and glob path-over-root precedence without weakening unknown tools", () => {
  for (const action of ["grep", "glob"] as const) {
    const result = scoreRequest({
      action, resources: ["needle"], projectDir: "/repo",
      operation: { tool: action, access: "read", complete: true, targets: ["/repo/src"],
        arguments: { pattern: "needle", path: "src", root: ".env" } },
    }, options);
    assert.notEqual(result.deny, true, action);
    assert.equal(result.band, "high", action);
  }
  const rootOnly = scoreRequest({
    action: "grep", resources: ["needle"], projectDir: "/repo",
    operation: { tool: "grep", access: "read", complete: true, targets: ["/repo/.env"],
      arguments: { pattern: "needle", root: ".env" } },
  }, options);
  assert.equal(rootOnly.deny, true);
  const mcp = scoreRequest({
    action: "mcp__search", resources: ["*"], projectDir: "/repo",
    operation: { tool: "mcp__search", access: "unknown", complete: true, arguments: { path: "src", root: ".env" } },
  }, options);
  assert.equal(mcp.deny, true);
});

it("resolves shell operands against the verified working directory and fails closed on unknown scope", () => {
  for (const command of ["cat shadow", "cat < shadow"]) {
    const result = scoreRequest({
      action: "shell", resources: [command], projectDir: "/repo",
      operation: { tool: "shell", access: "execute", complete: true, targets: ["/etc"],
        arguments: { command, workdir: "/etc" } },
    }, options);
    assert.equal(result.deny, true, command);
    assert.match(result.reason, /protected path access/i, command);
  }
  for (const command of ["cat passwd", "cat < passwd"]) {
    const result = scoreRequest({
      action: "shell", resources: [command], projectDir: "/repo",
      operation: { tool: "shell", access: "execute", complete: true, targets: ["/etc"],
        arguments: { command, workdir: "/etc" } },
    }, options);
    assert.equal(result.deny, undefined, command);
    assert.equal(result.band, "high", command);
  }
  for (const operationArguments of [{ workdir: "/etc", cwd: "/tmp" }, { workdir: "~/outside" }, { workdir: "relative" }]) {
    const result = scoreRequest({
      action: "shell", resources: ["pwd"], projectDir: operationArguments.workdir === "relative" ? undefined : "/repo",
      operation: { tool: "shell", access: "execute", complete: true, arguments: { command: "pwd", ...operationArguments } },
    }, options);
    assert.equal(result.band, "high", JSON.stringify(operationArguments));
    assert.equal(result.deny, undefined, JSON.stringify(operationArguments));
  }
});
