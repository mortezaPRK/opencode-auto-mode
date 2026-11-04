import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseJSONC, readUserOwnedFile } from "./user-files.js";

describe("user-owned policy files", () => {
  it("parses JSONC comments and trailing commas without touching strings", () => {
    assert.deepEqual(parseJSONC('{ // header\n "a": "x//y", /* block */ "b": [1,], }'), { a: "x//y", b: [1] });
    assert.throws(() => parseJSONC("{ /* open"), /Unclosed block comment/);
  });

  it("rejects repository policy files and accepts user-owned external ones", () => {
    const base = realpathSync(mkdtempSync(join(tmpdir(), "auto-mode-user-files-")));
    try {
      const repo = join(base, "repo");
      mkdirSync(repo);
      mkdirSync(join(repo, ".git"));
      const inside = join(repo, "policy.jsonc");
      writeFileSync(inside, "{}", { mode: 0o600 });
      assert.throws(() => readUserOwnedFile(inside, repo), /outside the repository/);
      const external = join(base, "config.jsonc");
      writeFileSync(external, '{ "ok": true }', { mode: 0o600 });
      assert.match(readUserOwnedFile(external, repo), /"ok": true/);
    } finally { rmSync(base, { recursive: true, force: true }); }
  });
});
