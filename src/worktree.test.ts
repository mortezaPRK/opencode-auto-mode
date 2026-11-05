import { it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getWorktreeScope } from "./worktree.js";

it("discovers actual Git directory and linked-worktree file markers from nested locations", () => {
  const temp = mkdtempSync(join(tmpdir(), "auto-mode-worktree-"));
  const main = join(temp, "main"), linked = join(temp, "linked");
  try {
    execFileSync("git", ["init", "--quiet", main]);
    execFileSync("git", ["-C", main, "-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", "commit", "--quiet", "--allow-empty", "-m", "fixture"]);
    execFileSync("git", ["-C", main, "worktree", "add", "--quiet", "-b", "fixture", linked]);
    for (const root of [main, linked]) {
      const nested = join(root, "src", "nested");
      mkdirSync(nested, { recursive: true });
      assert.deepEqual(getWorktreeScope(nested), { directory: realpathSync(nested), worktreeRoot: realpathSync(root) });
    }
    // A session move must rediscover its current worktree rather than retain main.
    assert.equal(getWorktreeScope(linked).worktreeRoot, realpathSync(linked));
  } finally { rmSync(temp, { recursive: true, force: true }); }
});

it("recognizes Git marker symlinks without changing the worktree boundary", () => {
  const temp = mkdtempSync(join(tmpdir(), "auto-mode-git-alias-"));
  try {
    const source = join(temp, "source"), root = join(temp, "worktree");
    execFileSync("git", ["init", "--quiet", source]);
    mkdirSync(join(root, "nested"), { recursive: true });
    symlinkSync(join(source, ".git"), join(root, ".git"));
    assert.equal(execFileSync("git", ["-C", root, "rev-parse", "--show-toplevel"], { encoding: "utf8" }).trim(), realpathSync(root));
    assert.deepEqual(getWorktreeScope(join(root, "nested")), {
      directory: realpathSync(join(root, "nested")), worktreeRoot: realpathSync(root),
    });
  } finally { rmSync(temp, { recursive: true, force: true }); }
});

it("canonicalizes location aliases, falls back without Git, and validates directories", () => {
  const temp = mkdtempSync(join(tmpdir(), "auto-mode-scope-"));
  try {
    const directory = join(temp, "directory"), alias = join(temp, "alias");
    mkdirSync(directory);
    symlinkSync(directory, alias);
    const canonical = realpathSync(directory);
    assert.deepEqual(getWorktreeScope(alias), { directory: canonical, worktreeRoot: canonical });
    writeFileSync(join(directory, "file"), "");
    assert.throws(() => getWorktreeScope(join(directory, "file")));
    assert.throws(() => getWorktreeScope(join(directory, "missing")));
  } finally { rmSync(temp, { recursive: true, force: true }); }
});
