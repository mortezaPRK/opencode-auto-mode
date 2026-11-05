import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createAuditLog, defaultAuditPath, redactHttpBodies } from "./audit.js";
import { DEFAULT_AUDIT_MAX_BYTES } from "./config.js";

const record = { ts: "2026-01-01T00:00:00Z", reviewID: "r", sessionID: "s", action: "shell", resources: ["x".repeat(2000)], hostEffect: "ask", decision: "allow", stage: "score", reason: "ok", durationMs: 1 };

describe("unsafe opt-in audit log", () => {
  it("uses a 10 MiB rotation default and keeps the arbitration fields", () => {
    assert.equal(DEFAULT_AUDIT_MAX_BYTES, 10 * 1024 * 1024);
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-fields-"));
    try {
      const file = path.join(dir, "d.jsonl");
      const arbitration = { ...record, hostEffect: "allow", proposedDecision: "deny" as const,
        reviewedNativeAllow: true, disposition: "enforced", appliedMessage: "unsafe. Continue with a safer alternative." };
      createAuditLog({ path: file, maxBytes: DEFAULT_AUDIT_MAX_BYTES })!.write(arbitration);
      const written = JSON.parse(fs.readFileSync(file, "utf8").trim());
      assert.deepEqual(written, arbitration);
      assert.equal("ruleID" in written, false);
      assert.equal("shadow" in written, false);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
  it("writes every original field without redaction or clipping with private permissions", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-"));
    try {
      const file = path.join(dir, "sub", "d.jsonl");
      const original = { ...record, resources: Array.from({ length: 40 }, () => "PASSWORD=TOY_SECRET".repeat(300)), reason: "y".repeat(3000), arbitraryExtension: ["kept"] };
      createAuditLog({ path: file, maxBytes: DEFAULT_AUDIT_MAX_BYTES })!.write(original);
      assert.deepEqual(JSON.parse(fs.readFileSync(file, "utf8").trim()), original);
      assert.equal(fs.statSync(file).mode & 0o077, 0);
      assert.equal(fs.statSync(path.dirname(file)).mode & 0o077, 0);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
  it("defaults off, requires explicit options, and only accepts an absolute XDG state home", () => {
    const old = process.env.XDG_STATE_HOME;
    try {
      process.env.XDG_STATE_HOME = path.join(os.tmpdir(), "isolated-state");
      assert.ok(defaultAuditPath().startsWith(process.env.XDG_STATE_HOME));
      assert.equal(createAuditLog(undefined), undefined);
      assert.ok(createAuditLog({ path: defaultAuditPath(), maxBytes: 1024 }));
      process.env.XDG_STATE_HOME = "relative-state";
      assert.equal(defaultAuditPath(), path.join(os.homedir(), ".local", "state", "opencode-auto-mode", "decisions.jsonl"));
    } finally { if (old === undefined) delete process.env.XDG_STATE_HOME; else process.env.XDG_STATE_HOME = old; }
  });
  it("retains reviewer HTTP evidence privacy independently", () => {
    for (const argument of ["--data-binary 'TOY_BODY'", '--data-raw="TOY_BODY"', "-dTOY_BODY", "--json '{\"field\":\"TOY_BODY\"}'", "--post-data='TOY_BODY'", "--body-data TOY_BODY"]) {
      const command = `curl https://example.invalid/ ${argument} --header other`;
      for (const value of [command, JSON.stringify({ command }), JSON.stringify(JSON.stringify({ command }))]) {
        assert.doesNotMatch(redactHttpBodies(value), /TOY_BODY/);
        assert.match(redactHttpBodies(value), /REDACTED/);
      }
    }
    assert.equal(redactHttpBodies("echo PASSWORD=TOY_SECRET"), "echo PASSWORD=TOY_SECRET");
  });
  it("omits wget config evidence without changing raw audit records", () => {
    for (const command of ["wget -e post_data=TOY_BODY", "wget -epost_data=TOY_BODY", "wget -qe post_data=TOY_BODY", "env wget -epost_data=TOY_BODY", "sh -c 'wget -e post_data=TOY_BODY'", "sh -c 'wget -qepost_data=TOY_BODY'", "wget --execute post_data=TOY_BODY", "echo $(wget -e post_data=TOY_BODY)"]) {
      for (const value of [command, JSON.stringify({ command })]) {
        assert.doesNotMatch(redactHttpBodies(value), /TOY_BODY/, command);
        assert.match(redactHttpBodies(value), /REDACTED/, command);
      }
    }
    for (const command of ["echo 'wget -e post_data=TOY_BODY'", "printf '%s' 'wget -epost_data=TOY_BODY'", "wget -O example https://example.invalid/"])
      assert.equal(redactHttpBodies(command), command);
  });
  it("recognizes HTTP-client invocations rather than quoted mentions and printf flags", () => {
    for (const command of ["echo curl\nprintf -done", "echo 'curl --data TOY_BODY'", "printf '%s' 'wget --post-data TOY_BODY'", "echo curl --form TOY_BODY", "curl -H '--data TOY_BODY' https://example.invalid/", "curl --header '--data TOY_BODY' https://example.invalid/"]) {
      assert.equal(redactHttpBodies(command), command, command);
      assert.equal(redactHttpBodies(JSON.stringify({ command })), JSON.stringify({ command }));
    }
    for (const command of ["pwd\ncurl --data TOY_BODY https://example.invalid/", "env curl -sSdTOY_BODY https://example.invalid/", "wget --post-data=TOY_BODY https://example.invalid/", "curl --form file=TOY_BODY", "curl -Ffile=TOY_BODY", "curl \\\n --data TOY_BODY", "curl --form-string file=TOY_BODY", "sh -c 'curl -d TOY_BODY'", "echo $(curl -d TOY_BODY)", "sh -c 'cu\"\"rl --da\"\"ta TOY_BODY'", "cu\"\"rl --da\"\"ta TOY_BODY", "wget --body-file=TOY_BODY", "curl -TTOY_BODY"]) {
      assert.doesNotMatch(redactHttpBodies(command), /TOY_BODY/, command);
      assert.match(redactHttpBodies(command), /REDACTED/, command);
    }
  });
});

describe("reviewer evidence redaction regressions", () => {
  it("preserves JSON formatting when no evidence is redacted", () => {
    for (const value of ["[ 1, 2 ]", '{ "command": "pwd", "nested": [ 3, 4 ] }'])
      assert.equal(redactHttpBodies(value), value);
  });
  it("redacts abbreviated wget body options in literal and uncertain syntax", () => {
    for (const command of ["wget --post-d=TOY_BODY https://example.invalid/", "wget --body-d=TOY_BODY https://example.invalid/", "wget --upload-f=TOY_BODY https://example.invalid/", "wget --execut=TOY_BODY", "wget --conf=TOY_CONFIG", "wget --post-d=TOY_BODY $(printf x)", "wget --conf=TOY_CONFIG $(printf x)"]) {
      assert.doesNotMatch(redactHttpBodies(command), /TOY_(?:BODY|CONFIG)/, command);
      assert.match(redactHttpBodies(command), /REDACTED/, command);
    }
  });
});
