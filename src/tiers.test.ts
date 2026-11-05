import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { isDataOption } from "./shell-policy.js";
import { hasSymlinkTraversal, isInProject, isProtected, isProtectedPathOperand, isProtectedShellWord, isScopedPath, safeTarget } from "./tiers.js";
import { mkdtempSync, mkdirSync, realpathSync, rmSync, symlinkSync, writeFileSync, linkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

describe("safeTarget", () => {
  it("requires explicit opt-in and rejects sensitive paths and symlinks", () => {
    const root = mkdtempSync(join(tmpdir(), "auto-mode-targets-"));
    try {
      writeFileSync(join(root, "a.ts"), "");
      symlinkSync("/etc", join(root, "linked"));
      assert.equal(safeTarget("a.ts", root), true);
      writeFileSync(join(root, "source.ts"), "");
      linkSync(join(root, "source.ts"), join(root, "hardlinked.ts"));
      writeFileSync(join(root, "single.ts"), "");
      assert.equal(safeTarget("single.ts", root), true);
      for (const target of [".env", ".npmrc", "id_rsa", "key.pem", ".opencode/opencode.jsonc", ".git/hooks/post-commit"])
        assert.equal(safeTarget(target, root), false, target);
      for (const target of ["linked/passwd", "hardlinked.ts", "/etc/passwd"])
        assert.equal(safeTarget(target, root), false, target);
      assert.equal(safeTarget(root, root), false);
      if (process.platform !== "win32") {
        execFileSync("mkfifo", [join(root, "pipe")]);
        assert.equal(safeTarget("pipe", root), false);
      }
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});

it("resolves file targets against the nested location while containing them in the worktree", () => {
  const root = mkdtempSync(join(tmpdir(), "auto-mode-nested-targets-"));
  try {
    mkdirSync(join(root, ".git"));
    const nested = join(root, "src");
    mkdirSync(nested);
    mkdirSync(join(root, "root-only-dir"));
    writeFileSync(join(root, "parent.ts"), "");
    symlinkSync(join(root, "parent.ts"), join(nested, "alias.ts"));
    assert.equal(safeTarget("../parent.ts", nested), true);
    assert.equal(safeTarget("../../outside.ts", nested), false);
    assert.equal(safeTarget("alias.ts", nested), false);
    assert.equal(safeTarget("root-only-dir", nested), true); // New local file, not the root directory.
  } finally { rmSync(root, { recursive: true, force: true }); }
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

describe("isProtected", () => {
  it("keeps absolute in-project paths below a dotted ancestor usable", () => {
    // A project cloned below an unrelated dotted ancestor (`~/.local/share/...`)
    // is not itself sensitive: only dot components below the project root count.
    const temp = realpathSync(mkdtempSync(join(tmpdir(), "auto-mode-dotted-")));
    try {
      const root = join(temp, ".local", "share", "project");
      mkdirSync(join(root, ".git"), { recursive: true });
      mkdirSync(join(root, "src"));
      mkdirSync(join(root, ".ssh"));
      mkdirSync(join(root, ".config"));
      writeFileSync(join(root, "file.txt"), "");
      writeFileSync(join(root, "src", "a.ts"), "");
      writeFileSync(join(root, ".env"), "");
      writeFileSync(join(root, ".ssh", "id_rsa"), "");
      writeFileSync(join(root, ".config", "config.json"), "");
      assert.equal(isProtected(join(root, "file.txt"), root), false);
      assert.equal(isProtected(join(root, "src", "a.ts"), root), false);
      assert.equal(isProtected("file.txt", root), false);
      assert.equal(isProtected(join(root, ".env"), root), true);
      // Named sensitive directories below the root stay protected both by their
      // spelling and by their resolved components.
      assert.equal(isProtected(join(root, ".ssh", "id_rsa"), root), true);
      assert.equal(isProtected(join(root, ".config", "config.json"), root), true);
    } finally { rmSync(temp, { recursive: true, force: true }); }
  });

  it("treats a component the filesystem cannot represent as absent", () => {
    const root = mkdtempSync(join(tmpdir(), "auto-mode-long-name-"));
    try {
      const long = "a".repeat(256);
      assert.equal(hasSymlinkTraversal(long, root), false);
      assert.equal(isProtected(long, root), false);
      assert.equal(isProtected(join(root, long), root), false);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});

describe("isProtectedShellWord", () => {
  it("applies bare keywords only to words that can name a path", () => {
    for (const word of ["auth", "password", "tokens", "secrets", "credentials", "private_key",
      "echo auth", "--grep=auth", "src/tokens.ts", "src/tokenizer.ts", "src/secrets.ts"])
      assert.equal(isProtectedShellWord(word, "/repo"), false, word);
    for (const word of [".env", ".aws/credentials", "~/.ssh/id_rsa", "keys/private_key", "secret/token",
      "signing.pem", "auth.json", "terraform.tfstate", "service-account.json",
      "src/.env", "src/api-token.txt"])
      assert.equal(isProtectedShellWord(word, "/repo"), true, word);
  });

  it("keeps separator-less leading-dot words ordinary except explicit names", () => {
    for (const word of [".name", ".gitignore", ".cache", ".foo", "jq"])
      assert.equal(isProtectedShellWord(word, "/repo"), false, word);
    for (const word of [".env", ".env.local", ".npmrc", "auth.json", "signing.pem", "id_rsa"])
      assert.equal(isProtectedShellWord(word, "/repo"), true, word);
  });

  it("treats data option values as data and path option values as paths", () => {
    for (const word of ["--grep=config/auth", "--format=src/.env", "--regexp=auth", "--exclude=.env",
      "--include=config/auth", "--glob=*auth*", "--reg=config/auth", "--rege=.env", "--regex=.env"])
      assert.equal(isProtectedShellWord(word, "/repo"), false, word);
    for (const word of ["--config=credentials.json", "--file=.env", "--config=credentials",
      "--fil=.env", "--fil=credentials"])
      assert.equal(isProtectedShellWord(word, "/repo"), true, word);
  });

  it("reads a path after a ref colon", () => {
    for (const word of ["HEAD:.env", "HEAD:src/.env", "origin:credentials", "HEAD:keys/private_key"])
      assert.equal(isProtectedShellWord(word, "/repo"), true, word);
    for (const word of ["HEAD:src/main.ts", "HEAD:notes.md", "git@github.com:org/auth",
      "https://example.com/.env"])
      assert.equal(isProtectedShellWord(word, "/repo"), false, word);
  });

  it("skips scheme and scp-style URLs", () => {
    for (const word of ["https://github.com/org/auth", "https://example.com/api/auth",
      "ssh://host/repo/.env", "--url=https://example.com/auth", "git@github.com:org/auth"])
      assert.equal(isProtectedShellWord(word, "/repo"), false, word);
  });

  it("treats file: URLs as local paths", () => {
    for (const word of ["file://$HOME/.ssh/id_rsa", "file://${HOME}/.ssh/id_rsa", "file://~/.ssh/id_rsa",
      "file:///etc/passwd", "file://localhost/etc/passwd", "--config=file:///etc/passwd"])
      assert.equal(isProtectedShellWord(word, "/repo"), true, word);
    for (const word of ["https://example.com/.ssh/id_rsa", "https://example.com/api/auth",
      "file:///repo/src/tokens.ts", "file:notes.txt"])
      assert.equal(isProtectedShellWord(word, "/repo"), false, word);
  });

  it("checks path-shaped option values but not pattern values", () => {
    for (const word of ["--config=credentials.json", "--file=.env", "--output=/etc/passwd", "--src=./.env"])
      assert.equal(isProtectedShellWord(word, "/repo"), true, word);
    for (const word of ["--grep=auth", "--exclude=secrets", "--glob=client_secret", "--max=100"])
      assert.equal(isProtectedShellWord(word, "/repo"), false, word);
  });
});

describe("isProtectedPathOperand", () => {
  it("applies bare names in file positions and extracts attached option values", () => {
    for (const word of ["credentials", "auth", "id_rsa", "signing.pem", ".env", "keys/private_key",
      "secret/token", "-fcredentials", "--file=credentials", "file:///etc/passwd"])
      assert.equal(isProtectedPathOperand(word, "/repo"), true, word);
    for (const word of [".name", ".gitignore", "notes.md", "src/tokens.ts", "https://example.com/auth",
      "git@github.com:org/auth"])
      assert.equal(isProtectedPathOperand(word, "/repo"), false, word);
  });
});

describe("isDataOption", () => {
  it("resolves unambiguous long-option abbreviations", () => {
    for (const option of ["--regexp", "--reg", "--rege", "--regex", "--format", "--label",
      "--exclude", "--glob"])
      assert.equal(isDataOption(option), true, option);
    for (const option of ["--file", "--fil", "--config", "--re", "--f", "--unknown"])
      assert.equal(isDataOption(option), false, option);
  });
});

describe("isScopedPath", () => {
  it("requires lexical containment and rejects tilde or expansion spellings", () => {
    assert.equal(isScopedPath("src/a.ts", "/repo", "/repo"), true);
    assert.equal(isScopedPath("../outside.ts", "/repo", "/repo"), false);
    assert.equal(isScopedPath("/etc/passwd", "/repo", "/repo"), false);
    assert.equal(isScopedPath("~/notes.txt", "/repo", "/repo"), false);
    assert.equal(isScopedPath("$HOME/notes.txt", "/repo", "/repo"), false);
    assert.equal(isScopedPath("", "/repo", "/repo"), false);
  });
});
