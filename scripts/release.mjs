import { spawnSync } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import process from "node:process";
import console from "node:console";

const packageName = "@mortz.prk/opencode-auto-mode";
const registry = "https://registry.npmjs.org";

export function execute(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, encoding: "utf8" });
  if (result.error) throw result.error;
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

function checked(run, command, args, cwd) {
  const result = run(command, args, cwd);
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed: ${result.stderr || result.stdout}`);
  }
  return result.stdout.trim();
}

function manifest(cwd, version, stable = false) {
  const base = "(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)";
  const suffix = "(?:-[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?";
  if (!new RegExp(`^${base}${stable ? "" : suffix}$`).test(version ?? "")) {
    throw new Error(`RELEASE_VERSION must be ${stable ? "a stable version such as 0.1.3" : "a valid version"}`);
  }
  const value = JSON.parse(readFileSync(resolve(cwd, "package.json"), "utf8"));
  if (value.name !== packageName) throw new Error(`Expected package ${packageName}`);
  return value;
}

function commitSha(value, name) {
  if (!/^[a-f0-9]{40}$/.test(value ?? "")) throw new Error(`${name} must be a full commit SHA`);
}

function outputs(value, outputFile) {
  if (outputFile) {
    appendFileSync(outputFile, Object.entries(value).map(([key, item]) => `${key}=${item}\n`).join(""));
  }
  return value;
}

export function prepare({ version, sourceSha, cwd = process.cwd(), outputFile, run = execute }) {
  manifest(cwd, version, true);
  commitSha(sourceSha, "RELEASE_SOURCE_SHA");
  const git = (...args) => checked(run, "git", args, cwd);
  if (git("rev-parse", "HEAD") !== sourceSha) throw new Error("Checkout does not match RELEASE_SOURCE_SHA");
  if (git("status", "--porcelain", "--untracked-files=no")) throw new Error("Release checkout must be clean");
  git("fetch", "origin", "main", "--tags");
  checked(run, "npm", ["version", version, "--no-git-tag-version", "--ignore-scripts"], cwd);
  if (manifest(cwd, version, true).version !== version) throw new Error("Version bump did not produce RELEASE_VERSION");
  const files = git("diff", "--name-only").split("\n").filter(Boolean);
  if (files.some((file) => !["package.json", "bun.lock"].includes(file))) {
    throw new Error("Version bump changed files outside package.json and bun.lock");
  }
  git("add", "--", "package.json");
  if (run("git", ["ls-files", "--error-unmatch", "bun.lock"], cwd).status === 0) git("add", "--", "bun.lock");
  const tree = git("write-tree");
  const tag = `v${version}`;
  const existing = run("git", ["rev-parse", "--verify", `refs/tags/${tag}`], cwd);
  if (existing.status === 0) {
    const commit = git("rev-parse", `${tag}^{commit}`);
    const parents = git("show", "-s", "--format=%P", commit);
    if (parents !== sourceSha || git("rev-parse", `${commit}^{tree}`) !== tree ||
      run("git", ["merge-base", "--is-ancestor", commit, "origin/main"], cwd).status !== 0) {
      throw new Error(`Existing ${tag} does not match this release run`);
    }
    return outputs({ commit, version, tag }, outputFile);
  }
  if (git("rev-parse", "origin/main") !== sourceSha) {
    throw new Error("main advanced after this run started; start a new release run");
  }
  git("config", "user.name", "github-actions[bot]");
  git("config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com");
  git("commit", "-m", `chore: release ${tag}`);
  const commit = git("rev-parse", "HEAD");
  git("tag", "-a", tag, "-m", `Release ${tag}`);
  git("push", "--atomic", "origin", "HEAD:refs/heads/main", `refs/tags/${tag}`);
  return outputs({ commit, version, tag }, outputFile);
}

export function publish({ version, commit, cwd = process.cwd(), run = execute }) {
  const value = manifest(cwd, version);
  commitSha(commit, "RELEASE_COMMIT");
  if (checked(run, "git", ["rev-parse", "HEAD"], cwd) !== commit || value.version !== version) {
    throw new Error("Publish checkout does not match the prepared release");
  }
  const result = run("npm", ["view", `${packageName}@${version}`, "version", "gitHead", "--json", `--registry=${registry}`], cwd);
  if (result.status === 0) {
    const published = JSON.parse(result.stdout);
    if (published.version !== version || published.gitHead !== commit) {
      throw new Error("Published npm version does not match the prepared release commit");
    }
    return "already published";
  }
  let missing = false;
  try {
    missing = JSON.parse(result.stdout).error?.code === "E404";
  } catch {
    // Non-JSON errors are not evidence that the version is absent.
  }
  if (!missing) throw new Error(`npm version lookup failed: ${result.stderr || result.stdout}`);
  const publication = run("npm", ["publish", "--access", "public", "--ignore-scripts", `--registry=${registry}`], cwd);
  if (publication.status !== 0) throw new Error(`npm publish failed: ${publication.stderr || publication.stdout}`);
  return [publication.stderr.trim(), publication.stdout.trim()].filter(Boolean).join("\n");
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.argv[2] === "prepare") {
      console.log(prepare({ version: process.env.RELEASE_VERSION, sourceSha: process.env.RELEASE_SOURCE_SHA, outputFile: process.env.GITHUB_OUTPUT }));
    } else if (process.argv[2] === "publish") {
      console.log(publish({ version: process.env.RELEASE_VERSION, commit: process.env.RELEASE_COMMIT }));
    } else {
      throw new Error("Usage: node scripts/release.mjs prepare|publish");
    }
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
