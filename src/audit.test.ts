import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createAuditLog } from "./audit.js";
import plugin from "./index.js";

const record = { ts: "t", reviewID: "r", sessionID: "s", action: "shell", resources: ["x".repeat(2000)], hostEffect: "ask", decision: "allow", stage: "static", reason: "ok", durationMs: 1 };

describe("audit log", () => {
  it("writes truncated JSONL with private permissions", () => {
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "audit-")), "sub", "d.jsonl");
    createAuditLog(file)!.write(record);
    const line = JSON.parse(fs.readFileSync(file, "utf8").trim());
    assert.equal(line.resources[0].length, 512);
    assert.equal(fs.statSync(file).mode & 0o077, 0);
  });
  it("is off unless enabled", () => {
    assert.equal(createAuditLog(undefined), undefined);
    assert.equal(createAuditLog(false), undefined);
  });
  it("records the deciding stage from the plugin hook", async () => {
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "audit-")), "d.jsonl");
    let evaluate!: (event: unknown) => Promise<void>;
    const ctx = {
      options: { auditLog: file, classifiers: [{ type: "static" }] },
      permission: { hook: async (_: string, handler: typeof evaluate) => { evaluate = handler; return { dispose: async () => {} }; } },
      tool: { hook: async () => ({ dispose: async () => {} }) },
      session: { get: async () => ({ location: { directory: "/repo" } }), context: async () => [] },
      generate: { text: async () => ({ text: "" }) },
    };
    await plugin.setup(ctx as unknown as Parameters<typeof plugin.setup>[0]);
    await evaluate({ sessionID: "s1", agent: "auto", action: "shell", resources: ["sudo ls"], effect: "ask" });
    const line = JSON.parse(fs.readFileSync(file, "utf8").trim());
    assert.equal(line.decision, "deny");
    assert.equal(line.stage, "shell-guard");
    assert.equal(line.hostEffect, "ask");
  });
});
