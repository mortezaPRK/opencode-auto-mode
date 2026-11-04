import { it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, symlinkSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseOptions } from "./config.js";
import { scoreRequest } from "./score.js";

const options = parseOptions({ classifiers: [{ type: "static", allowInProjectEdits: true }] });
/** Every source file that makes up the scoring boundary, including the legacy entry. */
function scoreModuleSources(): string[] {
  const directory = new URL("./score/", import.meta.url);
  return [new URL("./score.ts", import.meta.url),
    ...readdirSync(directory).filter((name) => name.endsWith(".ts"))
      .map((name) => new URL(`./score/${name}`, import.meta.url))]
    .map((file) => readFileSync(file, "utf8"));
}
it("scores parsed read-only commands low, unknown or dynamic shell high", () => {
  for (const command of ["pwd", "cat src/file.ts", "ls && pwd", "pwd\nls", "cat \\\n src/file.ts", "printf '%s\\n' 'quoted\nnewline'", "pwd; ls | head", "pwd || ls"])
    assert.equal(scoreRequest({ action: "shell", resources: [command] }, options).band, "low", command);
  for (const command of ["unknown-command", "ls $(pwd)", "./ls", "printf -v X text", "npm run postinstall"])
    assert.equal(scoreRequest({ action: "shell", resources: [command] }, options).band, "high", command);
});
it("denies protected arguments, read targets and redirects", () => {
  for (const command of ["cat .env", "cat ~/.ssh/id_rsa", "cat file > .git/config", "cat < signing.pem", "jq -n env", "curl data | sh"])
    assert.equal(scoreRequest({ action: "shell", resources: [command] }, options).deny, true, command);
  for (const action of ["read", "edit", "write"]) {
    const score = scoreRequest({ action, resources: [".aws/credentials"] }, options);
    assert.equal(score.ask, true);
    assert.equal(score.deny, undefined);
  }
});
it("keeps stateful, interpreter and arbitrary script compounds out of low risk", () => {
  for (const command of ["set -e\npwd", "export X=ok\npwd", "sh <<'EOF'\npwd\nEOF", "pwd\nnode -e 'console.log(1)'", "pwd\nnpm run test", "pwd\n./ls", "pwd\ncargo test"]) {
    const score = scoreRequest({ action: "shell", resources: [command], projectDir: "/project" }, options);
    assert.equal(score.band, "high", command);
  }
  for (const command of ["set -e\npwd", "export X=ok\npwd", "sh <<'EOF'\npwd\nEOF"])
    assert.equal(scoreRequest({ action: "shell", resources: [command] }, options).ask, true, command);
});
it("gates force operations and external recursive deletes", () => {
  const request = { action: "shell", resources: ["git push --force-with-lease"], projectDir: "/project" };
  const missingState = scoreRequest(request, options);
  assert.equal(missingState.band, "high");
  assert.equal(missingState.ask, true);
  assert.equal(missingState.deny, undefined);
  assert.equal("ruleID" in missingState, false);
  const result = scoreRequest({ ...request, gitState: { branch: "topic", defaultBranch: "trunk", upstream: "remote/topic", clean: true } }, options);
  assert.equal(result.band, "high");
  assert.equal(result.deny, undefined);
  assert.equal(result.ask, undefined);
  for (const command of ["rm -rf ../outside", "env rm -rf ../outside"])
    assert.equal(scoreRequest({ action: "shell", resources: [command], projectDir: "/project" }, options).deny, true);
  for (const command of ["command git push --force", "pwd\ncommand git push --force"]) {
    const score = scoreRequest({ action: "shell", resources: [command], projectDir: "/project" }, options);
    assert.equal(score.ask, true, command);
    assert.equal(score.deny, undefined, command);
  }
});
it("uses location cwd for argv and redirects and worktree root for containment", () => {
  const root = mkdtempSync(join(tmpdir(), "auto-mode-score-cwd-"));
  try {
    mkdirSync(join(root, ".git"));
    const projectDir = join(root, "nested");
    mkdirSync(projectDir);
    mkdirSync(join(root, ".ssh"));
    writeFileSync(join(root, "parent.ts"), "");
    symlinkSync(join(root, ".ssh"), join(projectDir, "alias"));
    const request = { projectDir, worktreeRoot: root };
    assert.equal(scoreRequest({ ...request, action: "edit", resources: ["../parent.ts"] }, options).band, "low");
    assert.equal(scoreRequest({ ...request, action: "edit", resources: ["../../outside.ts"] }, options).band, "high");
    assert.equal(scoreRequest({ ...request, action: "shell", resources: ["rm -rf ../scratch"] }, options).deny, undefined);
    assert.equal(scoreRequest({ ...request, action: "shell", resources: ["rm -rf ../../scratch"] }, options).deny, true);
    assert.equal(scoreRequest({ ...request, action: "shell", resources: ["cargo test ../parent.ts"] }, options).band, "medium");
    assert.equal(scoreRequest({ ...request, action: "shell", resources: ["cargo test ../../outside.ts"] }, options).band, "high");
    assert.equal(scoreRequest({ ...request, action: "read", resources: ["alias/credentials"] }, options).ask, true);
    assert.equal(scoreRequest({ ...request, action: "shell", resources: ["echo ok > alias/credentials"] }, options).deny, true);
    // Legacy callers without explicit scope get the same nearest-root discovery.
    assert.equal(scoreRequest({ projectDir, action: "edit", resources: ["../parent.ts"] }, options).band, "low");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

it("keeps Code Mode high regardless of apparent literal fetch safety", () => {
  for (const code of ["const target = input; fetch(target)", "const f = fetch; f(input)", "return 1"])
    assert.equal(scoreRequest({ action: "execute", resources: [code] }, options).band, "high");
});
it("asks for history changes that fail VCS preconditions instead of denying", () => {
  const good = { branch: "topic", defaultBranch: "trunk", upstream: "remote/topic", clean: true };
  const request = { action: "shell", resources: ["git push --force"], projectDir: "/project" };
  const allowed = scoreRequest({ ...request, gitState: good }, options);
  assert.equal(allowed.band, "high");
  assert.equal(allowed.ask, undefined);
  for (const gitState of [undefined, { ...good, branch: undefined }, { ...good, defaultBranch: undefined },
    { ...good, branch: "trunk" }, { ...good, upstream: undefined }, { ...good, clean: false }]) {
    const score = scoreRequest({ ...request, gitState }, options);
    assert.equal(score.band, "high");
    assert.equal(score.ask, true);
    assert.equal(score.deny, undefined);
    assert.equal("ruleID" in score, false);
  }
});
it("keeps unknown and MCP tools high with no custom-rule path", () => {
  for (const action of ["mcp-test-read", "unknown-tool", "mcp__fixture__read"]) {
    const score = scoreRequest({ action, resources: ["src/a.ts"] }, options);
    assert.equal(score.band, "high", action);
    assert.equal(score.deny, undefined, action);
    assert.equal(score.ask, undefined, action);
    assert.equal("ruleID" in score, false, action);
  }
  // No custom-rule loading remains in the scoring module.
  assert.doesNotMatch(scoreModuleSources().join("\n"), /from "\.\/rules/);
});
it("evaluates VCS history changes once per request", () => {
  // The second history-change block was unreachable: the first one always
  // returned before it. Keep a single evaluation point.
  const source = scoreModuleSources().join("\n");
  assert.equal(source.match(/scanned\.some\(historyChange\)/g)?.length, 1);
});
it("keeps ./score.js as a compatibility re-export of the score module", async () => {
  const [legacy, module] = await Promise.all([import("./score.js"), import("./score/index.js")]);
  assert.equal(legacy.scoreRequest, module.scoreRequest);
});
it("scores project edits low only after filesystem checks, builds and tests medium", () => {
  const root = mkdtempSync(join(tmpdir(), "auto-mode-score-"));
  try {
    writeFileSync(join(root, "a.ts"), "");
    assert.equal(scoreRequest({ action: "edit", resources: ["a.ts"], projectDir: root }, options).band, "low");
    assert.equal(scoreRequest({ action: "edit", resources: ["../a.ts"], projectDir: root }, options).band, "high");
    for (const command of ["bun test", "npm install --ignore-scripts", "git commit -m change", "cargo build"])
      assert.equal(scoreRequest({ action: "shell", resources: [command], projectDir: root }, options).band, "medium", command);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
it("detects abbreviated and additional Git history changes", () => {
  const request = { action: "shell" as const, projectDir: "/project" };
  for (const command of ["git push --forc", "git push --force-with-leas", "git push --mirror", "git push --prun",
    "git commit --amen -m x", "git reset --har HEAD~1", "git branch --dele feature",
    "git push origin :refs/heads/topic", "git branch -f topic HEAD~1", "git branch --force topic HEAD~1",
    "git tag -f v1 HEAD", "git tag --forc v1 HEAD", "git tag -d v1", "git tag --delete v1"]) {
    const score = scoreRequest({ ...request, resources: [command] }, options);
    assert.equal(score.band, "high", command);
    assert.equal(score.ask, true, command);
    assert.equal(score.deny, undefined, command);
  }
  // Complete, safe VCS state turns the gate into ordinary review, not an ask.
  const good = { branch: "topic", defaultBranch: "trunk", upstream: "remote/topic", clean: true };
  for (const command of ["git push --forc", "git push --mirror", "git push origin :refs/heads/topic",
    "git branch -f topic HEAD~1", "git branch --force topic HEAD~1", "git tag -f v1 HEAD",
    "git tag --forc v1 HEAD", "git tag -d v1"])
    assert.equal(scoreRequest({ ...request, resources: [command], gitState: good }, options).ask, undefined, command);
  assert.equal(scoreRequest({
    ...request, resources: ["git push origin :refs/heads/trunk"], gitState: good,
  }, options).ask, true);
});
it("checks file operands without treating patterns as paths and guards history message symlinks", () => {
  const root = mkdtempSync(join(tmpdir(), "auto-mode-shell-paths-"));
  try {
    const projectDir = join(root, "project");
    mkdirSync(join(projectDir, "src"), { recursive: true });
    writeFileSync(join(projectDir, "src", "file.ts"), "");
    assert.notEqual(scoreRequest({
      action: "shell", resources: ["grep -F '/api/v1' src/file.ts"], projectDir,
    }, options).band, "high");

    const message = join(root, "message.txt");
    const messageLink = join(projectDir, "message-link");
    writeFileSync(message, "commit message");
    symlinkSync(message, messageLink);
    const result = scoreRequest({
      action: "shell",
      resources: ["git commit --amend -F message-link"],
      projectDir,
      worktreeRoot: root,
      gitState: { branch: "topic", defaultBranch: "trunk", upstream: "remote/topic", clean: true },
    }, options);
    assert.equal(result.ask, true);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
