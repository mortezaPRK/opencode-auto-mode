import { expect, test } from "bun:test";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

test("replay uses valid 1.1.0 options, skips nondecision events and reports diagnostic-only fidelity", () => {
  const root = mkdtempSync(join(tmpdir(), "auto-mode-replay-"));
  try {
    const input = join(root, "events.jsonl");
    writeFileSync(input, [
      { type: "permission.evaluate.before", payload: { action: "shell", resources: ["pwd"], effect: "ask" } },
      { type: "event", payload: { type: "session.created" } },
      { action: "shell", resources: ["pwd"], decision: "allow", proposedDecision: "allow", stage: "static" },
    ].map(record => JSON.stringify(record)).join("\n"));
    const result = spawnSync(process.execPath, [resolve("scripts/replay.ts"), "--input", input, "--json"], { encoding: "utf8" });
    expect(result.status).toBe(0);
    const records = result.stdout.trim().split("\n").map(line => JSON.parse(line));
    expect(records).toHaveLength(1);
    expect(records[0].line).toBe(3);
    expect(records[0].decision).toBe("allow");
    expect(typeof records[0].stage).toBe("string");
    expect(records[0].ruleID).toBeUndefined();
    expect(records[0].fidelity).toContain("not reconstructed");
    expect(result.stderr).toContain("skipped 2 nondecision records");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("replay rejects malformed input instead of guessing a decision", () => {
  const root = mkdtempSync(join(tmpdir(), "auto-mode-replay-"));
  try {
    const input = join(root, "events.jsonl");
    writeFileSync(input, "{not-json}\n");
    const result = spawnSync(process.execPath, [resolve("scripts/replay.ts"), "--input", input], { encoding: "utf8" });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("Invalid JSON at line 1");
  } finally { rmSync(root, { recursive: true, force: true }); }
});
