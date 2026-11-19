import { it } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, mkdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { classifyPath, resolvePhysicalDirectory, resolvePhysicalPath, type PolicyRoots } from "./path-policy.js";
import { scoreRequest } from "./score.js";
import { parseOptions } from "./config.js";
import { runClassifiers } from "./classifier.js";

function fixture(run: (root: string, roots: PolicyRoots) => void): void {
  const root = mkdtempSync(join(tmpdir(), "path-policy-"));
  const roots = { home: join(root, "home"), config: join(root, "config"), data: join(root, "data") };
  for (const directory of Object.values(roots)) mkdirSync(directory);
  try { run(root, roots); } finally { rmSync(root, { recursive: true, force: true }); }
}

it("protects supported credential locations, including OpenCode SQLite and exact sidecars", () => {
  fixture((root, roots) => {
    const home = [".ssh/id_rsa", ".ssh/id_ed25519_sk", ".gnupg/private-keys-v1.d/key", ".gnupg/secring.gpg",
      ".aws/credentials", ".aws/sso/cache/item.json", ".aws/cli/cache/item.json", ".netrc", ".git-credentials"];
    const config = ["gh/hosts.yml", "gcloud/application_default_credentials.json", "gcloud/credentials.db", "gcloud/access_tokens.db"];
    for (const target of home) assert.equal(classifyPath(join(roots.home, target), root, roots).kind, "protected", target);
    for (const target of config) assert.equal(classifyPath(join(roots.config, target), root, roots).kind, "protected", target);
    for (const suffix of ["", "-wal", "-shm", "-journal"])
      assert.equal(classifyPath(join(roots.data, `opencode/opencode.db${suffix}`), root, roots).kind, "protected");
    assert.equal(classifyPath(join(roots.data, "opencode/auth.json"), root, roots).kind, "protected");
    const database = join(root, "custom.sqlite");
    assert.equal(classifyPath(`${database}-wal`, root, { ...roots, database }).kind, "protected");
    assert.equal(classifyPath(join(root, "opencode.db"), root, roots).kind, "ordinary");
  });
});

it("does not infer credentials from general configuration, generic names or public material", () => {
  fixture((root, roots) => {
    for (const name of ["auth", "tokens", "secrets", "credentials.json", "service-account.json", "cert.pem", "public.key",
      ".github/workflows/ci.yml", ".git/hooks/pre-commit", ".opencode/config.json", ".npmrc", ".env.example", ".env.production.template"])
      assert.equal(classifyPath(name, root, roots).review, true, name);
    for (const name of [".ssh/config", ".ssh/known_hosts", ".ssh/id_rsa.pub", ".gnupg/pubring.kbx", ".config/editor/settings.json"])
      assert.equal(classifyPath(join(roots.home, name), root, roots).kind, "ordinary", name);
    for (const name of [".env", ".env.local", ".env.production", ".env.example.local"])
      assert.equal(classifyPath(name, root, roots).kind, "protected", name);
    for (const name of [".env.example", ".env.sample", ".env.template", ".env.local.sample", ".environment", ".envrc"])
      assert.equal(classifyPath(name, root, roots).kind, "ordinary", name);
    assert.equal(classifyPath("src/tokens.ts", root, roots).review, false);
  });
});

it("resolves bare aliases and alias/.. without classifying an abandoned directory as an access", () => {
  fixture((root, roots) => {
    mkdirSync(join(roots.home, ".ssh"));
    writeFileSync(join(roots.home, ".ssh/id_rsa"), "fixture");
    symlinkSync(join(roots.home, ".ssh/id_rsa"), join(root, "alias"));
    assert.equal(classifyPath("alias", root, roots).kind, "protected");
    assert.equal(classifyPath("alias", root, roots, false).kind, "unresolved");
    symlinkSync(join(roots.home, ".ssh"), join(root, "directory"));
    assert.equal(classifyPath("directory/../notes", root, roots).kind, "ordinary");
    symlinkSync("missing", join(root, "dangling"));
    symlinkSync("loop", join(root, "loop"));
    for (const name of ["dangling", "loop"]) assert.equal(classifyPath(name, root, roots).kind, "unresolved");
  });
});

it("resolves evidence spellings physically so dot-dot after a symlink keeps its meaning", () => {
  fixture((root) => {
    mkdirSync(join(root, "outside", "child"), { recursive: true });
    symlinkSync(join(root, "outside", "child"), join(root, "alias"));
    const outer = realpathSync(join(root, "outside"));
    assert.equal(resolvePhysicalDirectory("alias/..", root), outer);
    assert.equal(resolvePhysicalPath("alias/../notes", root), join(outer, "notes"));
    // Traversal through an absent component or a non-directory is unverifiable.
    assert.equal(resolvePhysicalDirectory("missing/..", root), undefined);
    writeFileSync(join(root, "file.txt"), "fixture");
    assert.equal(resolvePhysicalDirectory("file.txt", root), undefined);
  });
});

it("routes the reported staging shape to a configured model without executing it", async () => {
  const options = parseOptions({ classifiers: [{ type: "static" }, { type: "llm", model: "fixture/reviewer" }] });
  const request = { action: "shell", projectDir: "/synthetic/checkout",
    resources: ["git add -- .gitignore .github/workflows/ci.yml LICENSE package.json package-lock.json tsconfig.json env.d.ts"] };
  const score = scoreRequest(request, options);
  assert.equal(score.deny, undefined);
  assert.equal(score.ask, undefined);
  let calls = 0;
  const verdict = await runClassifiers(options.classifiers, request, score, {
    decision: async () => { throw new Error("not configured"); },
    llm: async (_stage, evidence) => { calls++; assert.deepEqual(evidence.resources, request.resources); return { decision: "allow", reason: "authorized scope" }; },
  });
  assert.equal(calls, 1);
  assert.equal(verdict.decision, "allow");
});

it("aligns file access, shell content reads and staging while preserving final-link semantics", () => {
  fixture((root) => {
    writeFileSync(join(root, ".env"), "fixture");
    symlinkSync(join(root, ".env"), join(root, "alias"));
    const options = parseOptions({ classifiers: [{ type: "static" }] });
    for (const action of ["read", "edit", "write"])
      assert.equal(scoreRequest({ action, projectDir: root, resources: ["alias"] }, options).deny, true, action);
    for (const command of ["cat alias", "cp alias output", "git add .env", "grep pattern .env", `curl file://${root}/%2eenv`])
      assert.equal(scoreRequest({ action: "shell", projectDir: root, resources: [command] }, options).deny, true, command);
    for (const command of ["git add alias", "rm alias", "mv alias destination", "ls alias", "stat alias", "unknown .env", "echo .env", "grep .env file", "cat <<.env\nfixture\n.env"])
      assert.equal(scoreRequest({ action: "shell", projectDir: root, resources: [command] }, options).deny, undefined, command);
  });
});

it("keeps inaccessible metadata unresolved rather than declaring a secret access", { skip: process.platform === "win32" || process.getuid?.() === 0 }, () => {
  fixture((root, roots) => {
    const directory = join(root, "inaccessible");
    mkdirSync(directory);
    chmodSync(directory, 0);
    try { assert.equal(classifyPath(join(directory, ".env"), root, roots).kind, "unresolved"); }
    finally { chmodSync(directory, 0o700); }
  });
});
