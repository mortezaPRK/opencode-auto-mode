import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execute, prepare, publish } from "./release.mjs";

const temporary = [];
const packageName = "@mortz.prk/opencode-auto-mode";
const version = "0.1.3";

afterEach(() => {
  for (const path of temporary.splice(0)) rmSync(path, { recursive: true, force: true });
});

function git(cwd, ...args) {
  const result = execute("git", args, cwd);
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "opencode-release-test-"));
  temporary.push(root);
  const origin = join(root, "origin.git");
  const cwd = join(root, "checkout");
  git(root, "init", "--bare", "--initial-branch=main", origin);
  git(root, "clone", origin, cwd);
  git(cwd, "config", "user.name", "Test");
  git(cwd, "config", "user.email", "test@example.invalid");
  writeFileSync(join(cwd, "package.json"), JSON.stringify({ name: packageName, version: "0.1.2" }, null, 2) + "\n");
  writeFileSync(join(cwd, "bun.lock"), "locked dependencies\n");
  git(cwd, "add", "package.json", "bun.lock");
  git(cwd, "commit", "-m", "Initial commit");
  git(cwd, "push", "origin", "main");
  return { root, origin, cwd, sourceSha: git(cwd, "rev-parse", "HEAD") };
}

describe("release preparation", () => {
  it("bumps only the manifest, creates an annotated tag, and atomically pushes main and tag", () => {
    const value = fixture();
    const calls = [];
    const outputFile = join(value.root, "outputs");
    const run = (command, args, cwd) => {
      calls.push([command, ...args]);
      return execute(command, args, cwd);
    };
    const result = prepare({ ...value, version, outputFile, run });
    assert.equal(JSON.parse(readFileSync(join(value.cwd, "package.json"), "utf8")).version, version);
    assert.equal(readFileSync(join(value.cwd, "bun.lock"), "utf8"), "locked dependencies\n");
    assert.equal(git(value.cwd, "show", "-s", "--format=%P", result.commit), value.sourceSha);
    assert.equal(git(value.cwd, "cat-file", "-t", `refs/tags/${result.tag}`), "tag");
    assert.equal(git(value.origin, "rev-parse", "refs/heads/main"), result.commit);
    assert.equal(git(value.origin, "rev-parse", `${result.tag}^{commit}`), result.commit);
    assert.ok(calls.some((call) => call.join(" ") === `git push --atomic origin HEAD:refs/heads/main refs/tags/v${version}`));
    assert.equal(readFileSync(outputFile, "utf8"), `commit=${result.commit}\nversion=${version}\ntag=v${version}\n`);
  });

  it("reuses the same release on a full workflow rerun without a second bump or push", () => {
    const value = fixture();
    const first = prepare({ ...value, version });
    git(value.cwd, "reset", "--hard", value.sourceSha);
    const calls = [];
    const run = (command, args, cwd) => {
      calls.push([command, ...args]);
      return execute(command, args, cwd);
    };
    assert.deepEqual(prepare({ ...value, version, run }), first);
    assert.ok(!calls.some((call) => call[0] === "git" && ["commit", "push"].includes(call[1])));
  });

  it("rejects a tag belonging to another commit", () => {
    const value = fixture();
    git(value.cwd, "tag", "-a", `v${version}`, "-m", "Unrelated tag");
    git(value.cwd, "push", "origin", `v${version}`);
    assert.throws(() => prepare({ ...value, version }), /Existing .* does not match/);
    assert.equal(git(value.origin, "rev-parse", "refs/heads/main"), value.sourceSha);
  });

  it("rejects a tag with the right parent and version but different content", () => {
    const value = fixture();
    execute("npm", ["version", version, "--no-git-tag-version", "--ignore-scripts"], value.cwd);
    writeFileSync(join(value.cwd, "unexpected.txt"), "Different release content\n");
    git(value.cwd, "add", ".");
    git(value.cwd, "commit", "-m", "Different release");
    git(value.cwd, "tag", "-a", `v${version}`, "-m", "Different release");
    git(value.cwd, "push", "origin", "main", `v${version}`);
    git(value.cwd, "reset", "--hard", value.sourceSha);
    assert.throws(() => prepare({ ...value, version }), /Existing .* does not match/);
  });

  it("rejects an existing matching tag that has not been pushed to main", () => {
    const value = fixture();
    const first = prepare({ ...value, version });
    git(value.origin, "update-ref", "refs/heads/main", value.sourceSha, first.commit);
    git(value.cwd, "reset", "--hard", value.sourceSha);
    assert.throws(() => prepare({ ...value, version }), /Existing .* does not match/);
  });

  it("rejects main changing after validation", () => {
    const value = fixture();
    writeFileSync(join(value.cwd, "changed.txt"), "Another commit\n");
    git(value.cwd, "add", ".");
    git(value.cwd, "commit", "-m", "Main moved");
    git(value.cwd, "push", "origin", "main");
    const currentMain = git(value.cwd, "rev-parse", "HEAD");
    git(value.cwd, "reset", "--hard", value.sourceSha);
    assert.throws(() => prepare({ ...value, version }), /main advanced/);
    assert.equal(git(value.origin, "rev-parse", "refs/heads/main"), currentMain);
    assert.equal(execute("git", ["rev-parse", "--verify", `refs/tags/v${version}`], value.origin).status, 128);
  });

  it("atomically rejects the tag too if main moves immediately before push", () => {
    const value = fixture();
    const run = (command, args, cwd) => {
      if (command === "git" && args[0] === "push") {
        const tree = git(value.origin, "rev-parse", `${value.sourceSha}^{tree}`);
        const other = execute("git", ["-c", "user.name=Other", "-c", "user.email=other@example.invalid", "commit-tree", tree, "-p", value.sourceSha, "-m", "Concurrent main update"], value.origin);
        assert.equal(other.status, 0, other.stderr);
        git(value.origin, "update-ref", "refs/heads/main", other.stdout.trim());
      }
      return execute(command, args, cwd);
    };
    assert.throws(() => prepare({ ...value, version, run }), /git push --atomic.*failed/);
    assert.equal(execute("git", ["rev-parse", "--verify", `refs/tags/v${version}`], value.origin).status, 128);
  });

  it("rejects invalid versions, a wrong source checkout, and tracked changes", () => {
    const value = fixture();
    assert.throws(() => prepare({ ...value, version: "0.1.3-beta" }), /stable version/);
    assert.throws(() => prepare({ ...value, version, sourceSha: "f".repeat(40) }), /Checkout does not match/);
    writeFileSync(join(value.cwd, "bun.lock"), "changed dependencies\n");
    assert.throws(() => prepare({ ...value, version }), /must be clean/);
  });
});

describe("release publication", () => {
  function publisher(viewResult) {
    const value = fixture();
    writeFileSync(join(value.cwd, "package.json"), JSON.stringify({ name: packageName, version }));
    const calls = [];
    const run = (command, args, cwd) => {
      calls.push([command, ...args]);
      if (command === "git") return execute(command, args, cwd);
      if (args[0] === "view") return typeof viewResult === "function" ? viewResult(value.sourceSha) : viewResult;
      return { status: 0, stdout: `+ ${packageName}@${version}\n`, stderr: "" };
    };
    return { ...value, calls, run, commit: value.sourceSha };
  }

  it("publishes when npm reports E404 for the exact version", () => {
    const value = publisher({ status: 1, stdout: JSON.stringify({ error: { code: "E404" } }), stderr: "npm error E404" });
    assert.equal(publish({ ...value, version }), `+ ${packageName}@${version}`);
    assert.ok(value.calls.some((call) => call.join(" ") === "npm publish --access public --ignore-scripts --registry=https://registry.npmjs.org"));
  });

  it("skips publication only when both published version and gitHead match", () => {
    const value = publisher((commit) => ({ status: 0, stdout: JSON.stringify({ version, gitHead: commit }), stderr: "" }));
    assert.equal(publish({ ...value, version }), "already published");
    assert.ok(!value.calls.some((call) => call[1] === "publish"));
  });

  it("preserves prerelease versions on the existing GitHub release publication path", () => {
    const value = publisher((commit) => ({ status: 0, stdout: JSON.stringify({ version: "0.1.3-beta.1", gitHead: commit }), stderr: "" }));
    writeFileSync(join(value.cwd, "package.json"), JSON.stringify({ name: packageName, version: "0.1.3-beta.1" }));
    assert.equal(publish({ ...value, version: "0.1.3-beta.1" }), "already published");
    assert.ok(value.calls.some((call) => call[2] === `${packageName}@0.1.3-beta.1`));
  });

  it("rejects mismatched or absent npm metadata", () => {
    for (const metadata of [{ version, gitHead: "f".repeat(40) }, { version: "0.1.4", gitHead: "f".repeat(40) }, { version }]) {
      const value = publisher({ status: 0, stdout: JSON.stringify(metadata), stderr: "" });
      assert.throws(() => publish({ ...value, version }), /does not match the prepared release commit/);
      assert.ok(!value.calls.some((call) => call[1] === "publish"));
    }
  });

  it("fails on registry/authentication errors instead of attempting publication", () => {
    for (const result of [{ status: 1, stdout: JSON.stringify({ error: { code: "E401" } }), stderr: "Unauthorized" }, { status: 1, stdout: "", stderr: "Network unavailable" }]) {
      const value = publisher(result);
      assert.throws(() => publish({ ...value, version }), /npm version lookup failed/);
      assert.ok(!value.calls.some((call) => call[1] === "publish"));
    }
  });

  it("rejects a wrong commit or manifest version before querying npm", () => {
    const value = publisher({ status: 1, stdout: "", stderr: "Must not be queried" });
    assert.throws(() => publish({ ...value, version, commit: "f".repeat(40) }), /does not match the prepared release/);
    assert.throws(() => publish({ ...value, version: "0.1.4" }), /does not match the prepared release/);
    assert.ok(!value.calls.some((call) => call[0] === "npm"));
  });
});
