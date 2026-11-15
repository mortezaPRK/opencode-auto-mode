import { it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, realpathSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseOptions } from "./config.js";
import { runClassifiers } from "./classifier.js";
import { scoreRequest } from "./score.js";
import { guardShell } from "./shell.js";

const options = parseOptions({ classifiers: [
  { type: "static" }, { type: "decision", model: "test-provider/decision" },
  { type: "llm", model: "test-provider/reviewer" },
] });

it("sends Git metadata reads, writes and redirects to review, never static clearance", () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "auto-mode-git-review-")));
  try {
    mkdirSync(join(root, ".git", "hooks"), { recursive: true });
    for (const action of ["read", "edit", "write", "glob", "grep"]) {
      for (const target of [".git", ".git/config", ".git/hooks/pre-commit", join(root, ".git", "HEAD")]) {
        const score = scoreRequest({ action, resources: [target], projectDir: root }, options);
        assert.equal(score.band, "high", target);
        assert.equal(score.ask, undefined, target);
        assert.equal(score.deny, undefined, target);
      }
    }
    for (const command of ["cat .git/HEAD", "cat file > .git/config", "echo x >> .git/config",
      "git --git-dir=.git status", "cat .git/hooks/pre-commit", "cat file://" + root + "/.git/HEAD"]) {
      const score = scoreRequest({ action: "shell", resources: [command], projectDir: root }, options);
      assert.equal(score.band, "high", command);
      assert.equal(score.ask, undefined, command);
      assert.equal(score.deny, undefined, command);
      assert.notEqual(guardShell([command], root)?.decision, "allow", command);
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});

it("lets configured reviewers decide Git metadata access after static abstention", async () => {
  const request = { action: "edit", resources: [".git/hooks/pre-commit"] };
  const calls: string[] = [];
  const verdict = await runClassifiers(options.classifiers, request, scoreRequest(request, options), {
    decision: async () => {
      calls.push("decision");
      return { decision: "abstain", reason: "uncertain" };
    },
    llm: async () => {
      calls.push("llm");
      return { decision: "allow", reason: "authorized hook update" };
    },
  });
  assert.equal(verdict.decision, "allow");
  assert.deepEqual(calls, ["decision", "llm"]);
});

it("retains secret and destructive-operation protections alongside Git metadata", () => {
  for (const command of ["cat .git/.env", "cat .git/config .env",
    "echo x > .git/.env", "cat .git/HEAD; sudo id", "cat .git/HEAD; rm -rf /outside"]) {
    const score = scoreRequest({ action: "shell", resources: [command], projectDir: "/project" }, options);
    assert.equal(score.deny, true, command);
  }
  const score = scoreRequest({ action: "edit", resources: [".git/config", ".env"], projectDir: "/project" }, options);
  assert.equal(score.deny, true);
});

it("does not exempt secret symlink destinations under Git metadata", () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "auto-mode-git-alias-")));
  try {
    mkdirSync(join(root, ".ssh"));
    symlinkSync(join(root, ".ssh"), join(root, ".git"));
    assert.equal(scoreRequest({ action: "read", resources: [".git/config"], projectDir: root }, options).band, "high");
    assert.equal(scoreRequest({ action: "shell", resources: ["cat .git/config"], projectDir: root }, options).deny, undefined);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
