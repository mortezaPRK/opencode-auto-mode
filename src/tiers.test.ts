import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { classify, isInProject } from "./tiers.js";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync, linkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

describe("classify", () => {
  it("auto-allows safe read-only shell commands", () => {
    for (const command of ["ls -la", "pwd", "whoami"]) {
      assert.equal(classify("shell", [command]).tier, "auto-allow", command);
    }
  });

  it("reviews tool actions without verified file targets", () => {
    for (const action of ["read", "glob", "grep", "websearch"]) {
      assert.equal(classify(action, ["anything"]).tier, "review", action);
    }
  });

  it("auto-denies catastrophic shell patterns", () => {
    for (const command of [
      "rm -rf /",
      "sudo apt install",
      "mkfs.ext4 /dev/sda1",
      "shutdown now",
      "chmod 777 secret",
    ]) {
      assert.equal(classify("shell", [command]).tier, "auto-deny", command);
    }
  });

  it("sends chained or redirected commands to review as one action", () => {
    const result = classify("shell", ["git status && rm -rf /tmp/scratch"]);
    assert.equal(result.tier, "review");
    assert.match(result.reason, /one action/);
  });

  it("sends subagent delegation to review", () => {
    for (const action of ["task", "subagent"]) {
      assert.equal(classify(action, ["do research"]).tier, "review", action);
    }
  });

  it("requires explicit opt-in and rejects sensitive paths and symlinks", () => {
    const root = mkdtempSync(join(tmpdir(), "auto-mode-targets-"));
    try {
      writeFileSync(join(root, "a.ts"), "");
      symlinkSync("/etc", join(root, "linked"));
      linkSync(join(root, "a.ts"), join(root, "hardlinked.ts"));
      const options = { projectDir: root, allowInProjectEdits: true };
      assert.equal(classify("edit", ["a.ts"], { projectDir: root }).tier, "review");
      writeFileSync(join(root, "single.ts"), "");
      assert.equal(classify("edit", ["single.ts"], options).tier, "auto-allow");
      assert.equal(classify("read", ["single.ts"], options).tier, "auto-allow");
      for (const target of [".env", ".npmrc", "id_rsa", "key.pem", ".opencode/opencode.jsonc", ".git/hooks/post-commit", "linked/passwd", "hardlinked.ts", "/etc/passwd"])
        assert.equal(classify("edit", [target], options).tier, "review", target);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  it("reviews shell prefix bypasses and all resources", () => {
    for (const command of ["find . -delete", "git branch -D feature", "git tag -d v1", "env node -e 'x'", "ls\nchmod 700 a", "ls & touch a", "pwd > a", "ls $(touch a)"])
      assert.equal(classify("shell", [command]).tier, "review", command);
    assert.equal(classify("shell", ["ls", "chmod 777 a"]).tier, "auto-deny");
    assert.equal(classify("shell", ["ls", "touch a"]).tier, "review");
    assert.equal(classify("shell", []).tier, "review");
  });

  it("reviews edits when the project directory is unknown", () => {
    assert.equal(classify("edit", ["src/index.ts"]).tier, "review");
  });

  it("reviews network fetch and unknown actions", () => {
    assert.equal(classify("webfetch", ["https://example.com"]).tier, "review");
    assert.equal(classify("launch-missiles", []).tier, "review");
  });
});

describe("isInProject", () => {
  it("accepts the root, children, and relative paths", () => {
    assert.equal(isInProject("/repo", "/repo"), true);
    assert.equal(isInProject("/repo/src/a.ts", "/repo"), true);
    assert.equal(isInProject("src/a.ts", "/repo"), true);
  });

  it("rejects escapes and sibling prefixes", () => {
    assert.equal(isInProject("../etc/passwd", "/repo"), false);
    assert.equal(isInProject("/repo-other/a.ts", "/repo"), false);
    assert.equal(isInProject("/etc/passwd", "/repo"), false);
  });
});
