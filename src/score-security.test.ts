import { it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, realpathSync, symlinkSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { scoreRequest } from "./score.js";
import { guardShell } from "./shell.js";
import { parseOptions } from "./config.js";
import { runClassifiers } from "./classifier.js";
import { isProtected, isProtectedPathOperand, hasSymlinkTraversal, safeTarget } from "./tiers.js";
const options = parseOptions({ classifiers: [{ type: "static" }] });
// These are pure parser probes: no command is executed.
it("never low-scores attached sed scripts or repo-controlled Git helpers", () => {
  for (const command of ["sed -n 1p -fscript input", "sed -n 1p -e1woutput input", "git diff --textconv", "git status"])
    assert.notEqual(scoreRequest({ action: "shell", resources: [command] }, options).band, "low", command);
});
it("checks destructive segments before complex-syntax escalation", () => {
  for (const command of ["rm -rf /outside && pwd", "rm -rf ~"])
    assert.equal(scoreRequest({ action: "shell", resources: [command], projectDir: "/project" }, options).deny, true, command);
  const forcePush = scoreRequest({ action: "shell", resources: ["git push --force; pwd"], projectDir: "/project" }, options);
  assert.equal(forcePush.band, "high");
  assert.equal(forcePush.ask, true);
  assert.equal(forcePush.deny, undefined);
  assert.equal(scoreRequest({ action: "shell", resources: ["git -C /project push --force"], projectDir: "/project" }, options).ask, true);
  assert.equal(scoreRequest({ action: "shell", resources: ["sudo id $'x'"] }, options).deny, true);
});
it("retains later-command deny precedence and executable qualification for compounds", () => {
  for (const command of ["pwd\ncat .env", "set -e\ncat .env", "pwd && cat .env", "pwd\ncat \\\n .env", "pwd\nenv rm -rf /outside", "pwd\n/usr/bin/rm -rf /outside"]) {
    assert.equal(scoreRequest({ action: "shell", resources: [command], projectDir: "/project" }, options).deny, true, command);
  }
  assert.equal(scoreRequest({ action: "shell", resources: ["pwd\ncommand git push --force"], projectDir: "/project" }, options).ask, true);
  for (const command of ["pwd\n/usr/bin/ls", "pwd; ./ls", "pwd\nenv ./ls"])
    assert.equal(scoreRequest({ action: "shell", resources: [command] }, options).band, "high", command);
  assert.equal(scoreRequest({ action: "shell", resources: ["pwd\ngit -C /project status"] }, options).ask, true);
});
it("never low-scores dash filename writes or expanded input redirects", () => {
  for (const command of ["printf ok > -", "printf ok >> -", "pwd\nprintf ok > -"])
    assert.equal(scoreRequest({ action: "shell", resources: [command] }, options).band, "high", command);
  for (const command of ['cat < "${INPUT:-.env}"', "cat < $INPUT", "pwd; cat < $INPUT"]) {
    const score = scoreRequest({ action: "shell", resources: [command] }, options);
    assert.equal(score.band, "high", command);
    assert.equal(score.ask, true, command);
  }
  // A bracket glob that can only expand to a protected dotfile stays a deny.
  assert.equal(scoreRequest({ action: "shell", resources: ["cat < .[e]nv"] }, options).deny, true);
  assert.equal(scoreRequest({ action: "shell", resources: ["cat < .env"] }, options).deny, true);
  assert.equal(scoreRequest({ action: "shell", resources: ["cat < file\npwd"] }, options).band, "low");
});
it("does not drop wrapper qualification or effects when scoring builds", () => {
  for (const command of ["./env cargo test", "./time cargo test", "env -C /outside cargo test", "env --chdir=/outside cargo test", "time -o /outside/report cargo test", "time --output=/outside/report cargo test", "BUILD_DIR=/outside cargo test"]) {
    assert.equal(scoreRequest({ action: "shell", resources: [command], projectDir: "/project" }, options).band, "high", command);
  }
  for (const command of ["cargo test", "env cargo test", "time cargo test"])
    assert.equal(scoreRequest({ action: "shell", resources: [command], projectDir: "/project" }, options).band, "medium", command);
  assert.equal(scoreRequest({ action: "shell", resources: ["pwd\nls && cat file"] }, options).band, "low");
});
it("search patterns are not file-scope evidence; process environment is protected", () => {
  for (const action of ["glob", "grep"])
    assert.equal(scoreRequest({ action, resources: [".*"] }, options).band, "high");
  assert.equal(scoreRequest({ action: "read", resources: ["/proc/self/environ"] }, options).ask, true);
  assert.equal(scoreRequest({ action: "shell", resources: ["cat /proc/self/environ"] }, options).deny, true);
});
it("rejects tilde edits and resolves protected redirects in request cwd", () => {
  const root = mkdtempSync(join(tmpdir(), "auto-mode-security-"));
  try {
    mkdirSync(join(root, ".ssh"));
    symlinkSync(join(root, ".ssh"), join(root, "alias"));
    assert.equal(safeTarget("~/notes.txt", root), false);
    assert.equal(scoreRequest({ action: "shell", resources: ["echo ok > alias/new-file"], projectDir: root }, options).deny, true);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
it("does not normalize away symlink traversal before containment or protected checks", () => {
  const temp = mkdtempSync(join(tmpdir(), "auto-mode-raw-traversal-"));
  try {
    const root = join(temp, "repo"), outside = join(temp, "outside");
    mkdirSync(root);
    mkdirSync(join(root, ".git"));
    mkdirSync(join(outside, "child"), { recursive: true });
    mkdirSync(join(outside, ".ssh", "child"), { recursive: true });
    writeFileSync(join(outside, "victim.txt"), "external");
    writeFileSync(join(outside, ".ssh", "existing.txt"), "protected");
    symlinkSync(join(outside, "child"), join(root, "alias"));
    symlinkSync(join(outside, ".ssh", "child"), join(root, "protected-alias"));
    const editOptions = parseOptions({ classifiers: [{ type: "static", allowInProjectEdits: true }] });
    for (const suffix of ["victim.txt", "new-file.txt"]) {
      const relative = `alias/../${suffix}`;
      const absolute = `${root}/${relative}`; // Deliberately do not use join: it removes `..`.
      for (const target of [relative, absolute]) {
        assert.equal(safeTarget(target, root), false, target);
        for (const action of ["read", "edit", "write"]) {
          const score = scoreRequest({ action, resources: [target], projectDir: root }, editOptions);
          assert.equal(score.ask, true, `${action} ${target}`);
          assert.notEqual(score.band, "low");
        }
      }
    }
    for (const target of ["protected-alias/../existing.txt", "protected-alias/../new-file.txt"]) {
      assert.equal(isProtected(target, root), true);
      assert.equal(isProtected(`${root}/${target}`, root), true);
      assert.equal(scoreRequest({ action: "read", resources: [target], projectDir: root }, options).ask, true);
      assert.equal(scoreRequest({ action: "shell", resources: [`cat ${target}`], projectDir: root }, options).deny, true);
      assert.equal(scoreRequest({ action: "shell", resources: [`echo ok > ${target}`], projectDir: root }, options).deny, true);
    }
    assert.equal(scoreRequest({ action: "shell", resources: ["cat alias/../victim.txt"], projectDir: root }, options).ask, true);
  } finally { rmSync(temp, { recursive: true, force: true }); }
});

it("asks for force pushes explicitly targeting the default branch", () => {
  const score = scoreRequest({ action: "shell", resources: ["git push --force remote HEAD:trunk"],
    gitState: { branch: "topic", defaultBranch: "trunk", upstream: "remote/topic", clean: true } }, options);
  assert.equal(score.band, "high");
  assert.equal(score.ask, true);
  assert.equal(score.deny, undefined);
});

it("protects dotfiles, repository configuration and credential-bearing names", () => {
  const root = mkdtempSync(join(tmpdir(), "auto-mode-sensitive-"));
  try {
    mkdirSync(join(root, ".github", "workflows"), { recursive: true });
    mkdirSync(join(root, ".vscode"), { recursive: true });
    mkdirSync(join(root, ".husky"), { recursive: true });
    mkdirSync(join(root, ".devcontainer"), { recursive: true });
    mkdirSync(join(root, ".config"), { recursive: true });
    mkdirSync(join(root, "src"), { recursive: true });
    for (const name of ["workflow.yml", "settings.json", "pre-commit", "devcontainer.json", "config.json",
      "auth.json", "id_ed25519", "client_secret.json", "api-token.txt", "passwords.txt", "private-key.pem"]) {
      const directory = name === "workflow.yml" ? join(root, ".github", "workflows")
        : name === "settings.json" ? join(root, ".vscode")
        : name === "pre-commit" ? join(root, ".husky")
        : name === "devcontainer.json" ? join(root, ".devcontainer")
        : name === "config.json" ? join(root, ".config") : root;
      writeFileSync(join(directory, name), "");
    }
    writeFileSync(join(root, ".gitlab-ci.yml"), "");
    writeFileSync(join(root, ".git-credentials"), "");
    for (const target of [".github/workflows/workflow.yml", ".vscode/settings.json", ".husky/pre-commit",
      ".devcontainer/devcontainer.json", ".config/config.json", ".gitlab-ci.yml", ".git-credentials",
      "auth.json", "id_ed25519", "client_secret.json", "api-token.txt", "passwords.txt", "private-key.pem", "api-token"])
      assert.equal(isProtected(target, root), true, target);
    // A source file that merely contains a keyword is not a credential file.
    assert.equal(isProtected("src/tokenizer.ts", root), false);
    for (const target of [".github/workflows/workflow.yml", ".vscode/settings.json", ".config/config.json",
      ".gitlab-ci.yml", ".git-credentials", "id_ed25519", "client_secret.json", "private-key.pem"]) {
      const read = scoreRequest({ action: "read", resources: [target], projectDir: root }, options);
      assert.equal(read.ask, true, target);
      assert.notEqual(read.band, "low", target);
      const edit = scoreRequest({ action: "edit", resources: [target], projectDir: root },
        parseOptions({ classifiers: [{ type: "static", allowInProjectEdits: true }] }));
      assert.equal(edit.ask, true, target);
      assert.notEqual(edit.band, "low", target);
      assert.equal(scoreRequest({ action: "shell", resources: [`cat ${target}`], projectDir: root }, options).deny, true, target);
    }
    // Ordinary project sources stay low.
    writeFileSync(join(root, "src", "main.ts"), "");
    assert.equal(scoreRequest({ action: "read", resources: ["src/main.ts"], projectDir: root }, options).band, "low");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

it("requires low-band reads to resolve inside the project", () => {
  const root = mkdtempSync(join(tmpdir(), "auto-mode-read-scope-"));
  try {
    mkdirSync(join(root, ".git"));
    writeFileSync(join(root, "file.txt"), "");
    assert.equal(scoreRequest({ action: "read", resources: ["file.txt"], projectDir: root }, options).band, "low");
    // The canonical spelling stays low; a path under the `/var` symlink asks for
    // the same symlink reason every absolute target below a link does.
    assert.equal(scoreRequest({ action: "read", resources: [realpathSync(join(root, "file.txt"))], projectDir: root }, options).band, "low");
    for (const target of ["../outside.txt", "~/notes.txt", "$HOME/notes.txt", "`whoami`/notes.txt"])
      assert.equal(scoreRequest({ action: "read", resources: [target], projectDir: root }, options).band, "high", target);
    // `/etc/passwd` is also a protected name, so it asks instead of scoring low.
    const system = scoreRequest({ action: "read", resources: ["/etc/passwd"], projectDir: root }, options);
    assert.equal(system.ask, true);
    assert.notEqual(system.band, "low");
    // Protected names keep their ask even when the path is inside the project.
    assert.equal(scoreRequest({ action: "read", resources: [".env"], projectDir: root }, options).ask, true);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

it("reviews network fetch and search because no host allowlist remains", () => {
  for (const action of ["webfetch", "websearch"]) {
    const score = scoreRequest({ action, resources: ["https://example.invalid/path"] }, options);
    assert.equal(score.band, "high", action);
    assert.equal(score.deny, undefined, action);
    assert.equal(score.ask, undefined, action);
  }
  // Only user interaction stays low without host effects.
  for (const action of ["question", "todowrite"])
    assert.equal(scoreRequest({ action, resources: ["prompt"] }, options).band, "low", action);
});

it("does not hard-deny ordinary words, package names, source files or URLs in shell words", () => {
  const request = { action: "shell" as const, projectDir: "/project" };
  for (const command of ["grep -r auth", "rg auth", "git log --grep=auth", "npm view auth",
    "git clone https://github.com/org/auth", "curl https://example.com/api/auth",
    "cat src/tokens.ts", "echo auth"]) {
    const score = scoreRequest({ ...request, resources: [command] }, options);
    assert.notEqual(score.deny, true, command);
  }
  // Recursive grep now needs review; it is still not a deny for ordinary paths.
  const recursiveGrep = scoreRequest({ ...request, resources: ["grep -r password ."] }, options);
  assert.equal(recursiveGrep.band, "high");
  assert.equal(recursiveGrep.deny, undefined);
  // Path-aware callers keep the full check: a file named `auth` is still
  // sensitive, while a source module that merely contains a keyword is not.
  assert.equal(isProtected("auth", "/project"), true);
  assert.equal(isProtected("src/tokens.ts", "/project"), false);
  assert.equal(isProtected("terraform.tfstate", "/project"), true);
});

it("keeps absolute in-project reads below a dotted ancestor usable", () => {
  const temp = realpathSync(mkdtempSync(join(tmpdir(), "auto-mode-dotted-security-")));
  try {
    const root = join(temp, ".local", "share", "project");
    mkdirSync(join(root, ".git"), { recursive: true });
    writeFileSync(join(root, "file.txt"), "");
    const absolute = join(root, "file.txt");
    assert.equal(isProtected(absolute, root), false);
    assert.equal(scoreRequest({ action: "read", resources: [absolute], projectDir: root }, options).band, "low");
    assert.notEqual(scoreRequest({ action: "shell", resources: [`cat ${absolute}`], projectDir: root }, options).deny, true);
    // Dot components below the project root stay protected.
    writeFileSync(join(root, ".env"), "");
    assert.equal(isProtected(join(root, ".env"), root), true);
    assert.equal(scoreRequest({ action: "read", resources: [join(root, ".env")], projectDir: root }, options).ask, true);
    assert.equal(scoreRequest({ action: "shell", resources: [`cat ${join(root, ".env")}`], projectDir: root }, options).deny, true);
  } finally { rmSync(temp, { recursive: true, force: true }); }
});

it("treats an over-long path component as absent instead of ambiguous", () => {
  const root = mkdtempSync(join(tmpdir(), "auto-mode-long-security-"));
  try {
    mkdirSync(join(root, ".git"));
    const long = "a".repeat(256);
    assert.equal(hasSymlinkTraversal(long, root), false);
    assert.equal(isProtected(long, root), false);
    assert.equal(scoreRequest({ action: "read", resources: [long], projectDir: root }, options).band, "low");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

it("protects key material, infrastructure state and service-account files", () => {
  const root = mkdtempSync(join(tmpdir(), "auto-mode-credential-names-"));
  try {
    mkdirSync(join(root, "keys"));
    mkdirSync(join(root, "secret"));
    mkdirSync(join(root, "src"));
    writeFileSync(join(root, "src", "tokens.ts"), "");
    for (const target of ["keys/private_key", "keys/private-key", "terraform.tfstate",
      "prod.terraform.tfstate.backup", "service-account.json", "secret/token", "secrets.yaml"]) {
      writeFileSync(join(root, target), "");
      assert.equal(isProtected(target, root), true, target);
      assert.equal(scoreRequest({ action: "read", resources: [target], projectDir: root }, options).ask, true, target);
      assert.equal(scoreRequest({ action: "shell", resources: [`cat ${target}`], projectDir: root }, options).deny, true, target);
    }
    // The additions are path-aware: a source module with a keyword stays low.
    assert.equal(isProtected("src/tokens.ts", root), false);
    assert.equal(scoreRequest({ action: "read", resources: ["src/tokens.ts"], projectDir: root }, options).band, "low");
  } finally { rmSync(root, { recursive: true, force: true }); }
});

it("denies bare sensitive names that a command reads as a file", () => {
  const request = { action: "shell" as const, projectDir: "/project" };
  for (const command of ["cat credentials", "cat kubeconfig", "cat auth", "cat secrets", "cat tokens",
    "cat private_key", "cat id_rsa", "rm -f auth", "cp credentials dest", "wc -l kubeconfig",
    "head -n 5 credentials", "sha256sum auth"])
    assert.equal(scoreRequest({ ...request, resources: [command] }, options).deny, true, command);
  // Pattern and ref positions stay data, so the F1 false positives stay fixed.
  for (const command of ["grep -r auth", "rg auth", "git log --grep=auth", "echo auth", "cat src/tokens.ts"]) {
    const score = scoreRequest({ ...request, resources: [command] }, options);
    assert.notEqual(score.deny, true, command);
  }
  const recursiveGrep = scoreRequest({ ...request, resources: ["grep -r password ."] }, options);
  assert.equal(recursiveGrep.band, "high");
  assert.equal(recursiveGrep.deny, undefined);
});

it("protects file: URL paths and path-shaped option values", () => {
  const request = { action: "shell" as const, projectDir: "/project" };
  for (const command of ["curl file://$HOME/.ssh/id_rsa", "curl 'file://$HOME/.ssh/id_rsa'",
    'curl "file://${HOME}/.ssh/id_rsa"', "curl file://~/.ssh/id_rsa", "curl file:///etc/passwd",
    "cat --config=credentials.json file", "cat --file=.env file", "tool --output=/etc/passwd"])
    assert.equal(scoreRequest({ ...request, resources: [command] }, options).deny, true, command);
  // HTTP(S) URLs and pattern values remain non-path data.
  for (const command of ["curl https://example.com/api/auth", "curl https://example.com/.ssh/id_rsa",
    "git log --grep=auth", "grep --exclude=auth file", "open https://example.com/auth"])
    assert.notEqual(scoreRequest({ ...request, resources: [command] }, options).deny, true, command);
  // Protected redirect targets keep their mandatory deny.
  for (const command of ["echo x > .env", "cat < credentials", "echo x >> .git/config", "cat < signing.pem"])
    assert.equal(scoreRequest({ ...request, resources: [command] }, options).deny, true, command);
});

it("places command operands before applying path protection", () => {
  assert.equal(isProtectedPathOperand("credentials", "/project"), true);
  assert.equal(isProtectedPathOperand("id_rsa", "/project"), true);
  assert.equal(isProtectedPathOperand("src/tokens.ts", "/project"), false);
  assert.equal(isProtectedPathOperand("https://example.com/auth", "/project"), false);
  assert.equal(isProtectedPathOperand("file:///etc/passwd", "/project"), true);
  assert.equal(isProtectedPathOperand("file://$HOME/.ssh/id_rsa", "/project"), true);
  assert.equal(isProtectedPathOperand("file://~/.ssh/id_rsa", "/project"), true);
});

it("denies bare sensitive operands of every file-reading command", () => {
  const request = { action: "shell" as const, projectDir: "/project" };
  for (const command of ["diff credentials /dev/null", "sort credentials", "uniq credentials",
    "jq . credentials", "sed -n 1p credentials", "grep --file=credentials credentials",
    "grep -f credentials file", "sed -f credentials file", "jq --rawfile data credentials . file",
    "cat credentials", "rm -f auth"])
    assert.equal(scoreRequest({ ...request, resources: [command] }, options).deny, true, command);
});

it("keeps command data slots and separator-less dot words out of hard denies", () => {
  const request = { action: "shell" as const, projectDir: "/project" };
  for (const command of ["grep -e auth -e password .", "grep --regexp=auth file", "rg -e auth .",
    "jq .name", "git add .gitignore", "grep -A 2 auth file", "grep config/auth file",
    "sed s/.env/.x/p file", "git log --grep=config/auth", "git log --format=src/.env",
    "grep --exclude=.env file", "grep --include=config/auth file", "rg --glob=config/auth .",
    "git log --grep=auth", "echo auth"])
    assert.notEqual(scoreRequest({ ...request, resources: [command] }, options).deny, true, command);
  assert.equal(scoreRequest({ ...request, resources: ["grep -e auth -e password ."] }, options).band, "low");
  assert.equal(scoreRequest({ ...request, resources: ["jq .name"] }, options).band, "low");
  // Recursive grep is review now, but still not a deny for an ordinary path.
  const recursiveGrep = scoreRequest({ ...request, resources: ["grep -r password ."] }, options);
  assert.equal(recursiveGrep.band, "high");
  assert.equal(recursiveGrep.deny, undefined);
  // File slots, redirects, file URLs and path-shaped options keep denying.
  for (const command of ["cat .env", "cat credentials", "git add .env", "echo x > .env",
    "cat < signing.pem", "curl file://$HOME/.ssh/id_rsa", "cat --config=credentials.json file",
    "cat --file=.env file"])
    assert.equal(scoreRequest({ ...request, resources: [command] }, options).deny, true, command);
});

it("parses real option grammar instead of skipping numeric words", () => {
  const request = { action: "shell" as const, projectDir: "/project" };
  // A number after a flag is the pattern, so the following dotfile is a path.
  for (const command of ["grep -v 9 .env", "grep -i 5 .env", "rg -v 9 .env", "grep -ifpats .env",
    "grep -ie5 .env", "grep -gef .env", "grep -Ffcredentials .env", "rg -ie5 credentials",
    "grep --reg=. .env", "grep --rege=. .env", "grep --regex=. .env", "grep --fil=credentials file",
    "jq -e 1 credentials", "jq -r 1 credentials", "jq --tab 1 credentials", "sed -E 1 credentials",
    "cut -d, -f1 credentials", "bat credentials", "git show HEAD:.env", "git commit --file=.env"])
    assert.equal(scoreRequest({ ...request, resources: [command] }, options).deny, true, command);
  // Explicit option tables keep data values and refs out of path protection.
  for (const command of ["grep -A 2 auth file", "rg -m 1 auth src", "rg -t ts auth .",
    "rg --type ts config/auth src", "grep --label x config/auth src", "grep -d skip config/auth src",
    "git checkout -b feat/auth", "git branch feat/auth", "git push origin feat/auth",
    "git commit -m 'fix: handle src/.env'", "git add .gitignore", "grep --reg=auth file"])
    assert.notEqual(scoreRequest({ ...request, resources: [command] }, options).deny, true, command);
  // Recursive grep is review now; ordinary `rg -t ts ...` stays low.
  const recursiveGrep = scoreRequest({ ...request, resources: ["grep -r password ."] }, options);
  assert.equal(recursiveGrep.band, "high");
  assert.equal(recursiveGrep.deny, undefined);
  assert.equal(scoreRequest({ ...request, resources: ["rg -t ts auth ."] }, options).band, "low");
});

it("keeps file-reading options out of the low band", () => {
  const request = { action: "shell" as const, projectDir: "/project" };
  // These commands read a file the option names; they must not be low.
  for (const command of ["jq --run-tests .npmrc", "jq -n -f script.jq", "jq -fscript.jq",
    "jq --from-file=script.jq", "date -f credentials", "date --file credentials",
    "date -fcredentials", "find . -files0-from credentials", "du --files0-from credentials",
    "du --exclude-from credentials", "du -X credentials", "tree --fromfile credentials",
    "tree --fromtabfile credentials"]) {
    const score = scoreRequest({ ...request, resources: [command] }, options);
    assert.notEqual(score.band, "low", command);
  }
  // Files of patterns and ignores are protected paths, not pattern data.
  for (const command of ["grep --exclude-from .npmrc file", "grep --exclude-f id_rsa file",
    "rg --ignore-file .npmrc src", "rg --ignore-file=.npmrc src"])
    assert.equal(scoreRequest({ ...request, resources: [command] }, options).deny, true, command);
  // Ordinary invocations keep their low score.
  for (const command of ["jq .name", "date +%s", "find . -name '*.ts'", "du -sh src", "tree -L 2"])
    assert.equal(scoreRequest({ ...request, resources: [command] }, options).band, "low", command);
});

it("never auto-allows a dangerous indirect file option", () => {
  const request = { action: "shell" as const, projectDir: "/project" };
  // Every command that can read a file named by an option: files-from,
  // exclude-from, ignore-file, file/from-file, fromfile, compile, magic-file,
  // random-source, reference and run-tests, in attached, separate, =,
  // abbreviated-long and bundled-short spellings.
  const dangerous = [
    // grep / rg
    "grep -fcredentials file", "grep -f credentials file", "grep --file=credentials file",
    "grep --fil=credentials file", "grep --exclude-from .npmrc file",
    "grep --exclude-from=.npmrc file", "grep --exclude-f .npmrc file",
    "rg -fcredentials file", "rg --ignore-file .npmrc src", "rg --ignore-file=.npmrc src",
    // sort / wc
    "sort --files0-from credentials", "sort --files0-from=credentials", "sort --files0 credentials",
    "sort --files0-f=credentials", "sort --random-source=credentials file",
    "sort --random-source credentials file", "sort -ocredentials file", "sort -Tcredentials file",
    "wc --files0-from credentials", "wc --files0-from=credentials", "wc --files0 credentials",
    // file
    "file -f credentials", "file -fcredentials", "file --files-from credentials",
    "file --files-from=credentials", "file --files-f credentials", "file -C",
    "file -Ccredentials", "file -nCcredentials", "file --compile", "file --comp",
    "file -m credentials", "file --magic-file=credentials",
    // diff
    "diff -Xcredentials a b", "diff -X credentials a b", "diff --exclude-from credentials a b",
    "diff --exclude-from=credentials a b", "diff --exclude-f credentials a b",
    "diff --from-file=credentials a", "diff --to-file=credentials a",
    // date
    "date -f credentials", "date -fcredentials", "date --file=credentials",
    "date -rcredentials", "date -urcredentials",
    // jq
    "jq -f script.jq", "jq -fscript.jq", "jq --from-file=script.jq", "jq --from=script.jq",
    "jq --run-tests .npmrc", "jq --slurpfile data credentials . file",
    "jq --rawfile data credentials . file", "jq --argfile data credentials . file",
    "jq -Lcredentials file",
    // tree / du / find / bat / hostname / sed / git
    "tree --fromfile credentials", "tree --fromtabfile credentials", "tree --gitfile credentials",
    "tree --gitf=credentials",
    "du --files0-from credentials", "du --exclude-from credentials", "du -X credentials",
    "find . -files0-from credentials", "find . -files0-from=credentials", "find . -files0-f credentials",
    "bat --config-file credentials file", "bat --pager credentials file",
    "hostname -F credentials", "hostname --file credentials",
    "sed -fcredentials file", "sed --file=credentials file",
    "git commit -F credentials", "git commit --file=.env", "git tag -F credentials v1",
  ];
  for (const command of dangerous) {
    const score = scoreRequest({ ...request, resources: [command] }, options);
    assert.notEqual(score.band, "low", command);
    assert.notEqual(guardShell([command], "/project")?.decision, "allow", command);
  }
});

it("keeps ordinary file-reading commands low and allowed", () => {
  const request = { action: "shell" as const, projectDir: "/project" };
  const benign = ["sort file", "sort -u file", "sort -k 2 file", "wc file", "wc -l file",
    "file file.txt", "file -b file", "diff a b", "diff -u a b", "diff -x pattern a b",
    "grep pattern file", "rg pattern .", "rg -g auth .", "jq .name",
    "date +%s", "date -d tomorrow +%s", "date -r build.stamp +%s", "tree -L 2", "tree src",
    "du -sh src", "du -a src", "find . -name '*.ts'", "sed -n 1p file", "bat README.md",
    "hostname -s"];
  for (const command of benign) {
    assert.equal(scoreRequest({ ...request, resources: [command] }, options).band, "low", command);
    assert.equal(guardShell([command], "/project")?.decision, "allow", command);
  }
  // Recursive searches are no longer read-only, but stay non-denies.
  const recursive = scoreRequest({ ...request, resources: ["grep -r auth"] }, options);
  assert.equal(recursive.band, "high");
  assert.equal(recursive.deny, undefined);
});

it("reviews URL resources for file tools instead of scoring them in-project", () => {
  // A URL is not a filesystem path the scope check can verify.
  for (const action of ["read", "edit", "write", "glob", "grep"]) {
    const score = scoreRequest({ action, resources: ["file:///etc/hosts"] }, options);
    assert.equal(score.band, "high", action);
    assert.equal(score.deny, undefined, action);
    assert.equal(score.ask, undefined, action);
  }
  assert.equal(scoreRequest({ action: "read", resources: ["https://example.invalid/etc/hosts"] }, options).band, "high");
  // Ordinary relative and canonical in-project reads keep their low score.
  const root = realpathSync(mkdtempSync(join(tmpdir(), "auto-mode-url-scope-")));
  try {
    mkdirSync(join(root, ".git"));
    writeFileSync(join(root, "file.txt"), "");
    assert.equal(scoreRequest({ action: "read", resources: ["file.txt"], projectDir: root }, options).band, "low");
    assert.equal(scoreRequest({ action: "read", resources: [join(root, "file.txt")], projectDir: root }, options).band, "low");
    assert.equal(scoreRequest({ action: "glob", resources: ["src/**/*.ts"], projectDir: root }, options).band, "high");
  } finally { rmSync(root, { recursive: true, force: true }); }
  // Shell `file:` handling is unchanged: protected local paths deny, HTTP does not.
  assert.equal(scoreRequest({ action: "shell", resources: ["curl file://$HOME/.ssh/id_rsa"], projectDir: "/project" }, options).deny, true);
  assert.notEqual(scoreRequest({ action: "shell", resources: ["curl https://example.com/api/auth"], projectDir: "/project" }, options).deny, true);
});

it("applies project scope and symlink checks to attached option file values", () => {
  const external = { action: "shell" as const, projectDir: "/project" };
  // An attached short-option value (`-m/path`, `-f/path`, `-X/path`, `-L/path`)
  // is a file operand the shell word hides; external spellings must not be low.
  for (const command of ["file -m/etc/hosts /dev/null", "file -m/bin/ls /dev/null",
    "grep -f/etc/hosts /dev/null", "rg -f/etc/hosts .", "diff -X/etc/hosts a b", "jq -L/etc -n 1",
    "file -m../outside/magic", "file -m~/magic /dev/null", "rg -f../outside/patterns .",
    "grep -f~/patterns /dev/null"])
    assert.equal(scoreRequest({ ...external, resources: [command] }, options).band, "high", command);
  // Protected attached values still deny.
  for (const command of ["file -m~/.ssh/id_rsa", "grep -f.aws/credentials file", "diff -X~/.npmrc a b"])
    assert.equal(scoreRequest({ ...external, resources: [command] }, options).deny, true, command);

  const root = realpathSync(mkdtempSync(join(tmpdir(), "auto-mode-attached-scope-")));
  try {
    mkdirSync(join(root, ".git"));
    mkdirSync(join(root, "outside"));
    symlinkSync(join(root, "outside"), join(root, "alias"));
    const request = { action: "shell" as const, projectDir: root };
    // In-project relative and absolute attached values remain low and allowed.
    for (const command of ["file -mmagic.bin /dev/null", "grep -fpatterns /dev/null",
      "rg -fpatterns .", "diff -Xpatterns a b", "jq -Llib -n 1", `jq -L${root}/lib -n 1`]) {
      assert.equal(guardShell([command], root)?.decision, "allow", command);
      assert.equal(scoreRequest({ ...request, resources: [command] }, options).band, "low", command);
    }
    // An in-project spelling that traverses a symlink still needs review.
    const symlinked = scoreRequest({ ...request, resources: ["grep -falias/../patterns /dev/null"] }, options);
    assert.equal(symlinked.band, "high");
    assert.equal(symlinked.ask, true);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

it("applies project scope and symlink checks to attached long-option file values", () => {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "auto-mode-long-attached-scope-")));
  try {
    const root = join(base, "repo");
    const outside = join(base, "outside");
    mkdirSync(root);
    mkdirSync(outside);
    mkdirSync(join(root, ".git"));
    writeFileSync(join(outside, "notes.txt"), "");
    writeFileSync(join(outside, "random"), "");
    writeFileSync(join(root, "other.txt"), "");
    symlinkSync(outside, join(root, "alias"));
    const request = { action: "shell" as const, projectDir: root };
    // Attached long values name files the shell word hides; a symlinked or
    // dot-dot spelling must be reviewed, not scored low.
    for (const command of ["file --magic-file=alias/notes.txt a",
      "sort --random-source=alias/random file.txt", "diff --to-file=alias/notes.txt a",
      "diff --from-file=alias/notes.txt a", "file --magic-file=alias/../outside/notes.txt a"]) {
      const score = scoreRequest({ ...request, resources: [command] }, options);
      assert.equal(score.band, "high", command);
      assert.equal(score.ask, true, command);
    }
    // In-project attached long values remain low and allowed.
    for (const command of ["file --magic-file=magic.bin a", "sort --random-source=random.bin file.txt",
      "diff --to-file=other.txt a", "diff --from-file=other.txt a", "jq --library-path=lib -n 1"]) {
      assert.equal(guardShell([command], root)?.decision, "allow", command);
      assert.equal(scoreRequest({ ...request, resources: [command] }, options).band, "low", command);
    }
    // Protected attached long values still deny.
    for (const command of ["file --magic-file=~/.ssh/id_rsa a", "sort --random-source=.env file",
      "diff --from-file=.npmrc a"])
      assert.equal(scoreRequest({ ...request, resources: [command] }, options).deny, true, command);
    // Data-valued options are never treated as paths.
    for (const command of ["git log --grep=config/auth", "grep --exclude=.env file",
      "grep --include=config/auth src", "rg --glob=config/auth .", "grep --regexp=auth file",
      "diff --label=credentials a b"])
      assert.notEqual(scoreRequest({ ...request, resources: [command] }, options).deny, true, command);
  } finally { rmSync(base, { recursive: true, force: true }); }
});

it("reviews recursive and new-file searches instead of scoring them low", () => {
  const request = { action: "shell" as const, projectDir: "/project" };
  for (const command of ["diff -N . empty", "diff -rN . empty", "diff -urN . empty",
    "diff --new-file . empty", "diff --unidirectional-new-file . empty", "diff -r . empty",
    "grep -r '' .", "grep -R pattern .", "grep --dereference-recursive pattern .",
    "grep -d recurse pattern .", "grep --directories=recurse pattern .",
    "grep -r --include=.env '' .", "rg --hidden pattern .", "rg -u pattern .",
    "rg --no-ignore pattern .", "rg -L pattern .", "rg --follow pattern ."]) {
    const score = scoreRequest({ ...request, resources: [command] }, options);
    assert.equal(score.band, "high", command);
    assert.equal(score.deny, undefined, command);
  }
  // Ordinary non-recursive reads keep their low score.
  for (const command of ["diff a b", "diff -u a b", "grep pattern file", "grep -n pattern file",
    "rg pattern .", "rg -l pattern src"])
    assert.equal(scoreRequest({ ...request, resources: [command] }, options).band, "low", command);
  // A named protected path still denies.
  for (const command of ["diff -N credentials empty", "grep -r '' .env", "rg -u pattern ~/.ssh/id_rsa"])
    assert.equal(scoreRequest({ ...request, resources: [command] }, options).deny, true, command);
});

it("asks for malformed shell requests instead of leaving them to a classifier", async () => {
  const stages = parseOptions({ classifiers: [{ type: "static" }, { type: "llm", model: "test-provider/reasoning" }] }).classifiers;
  for (const resources of [[], Array.from({ length: 257 }, () => "pwd")]) {
    const score = scoreRequest({ action: "shell", resources }, options);
    assert.equal(score.band, "high");
    assert.equal(score.ask, true);
    assert.equal(score.deny, undefined);
    assert.equal(score.reason, "Shell command exceeds parsing limits");
    assert.equal(guardShell(resources)?.decision, "ask");
    let called = false;
    const verdict = await runClassifiers(stages, { action: "shell", resources }, score, {
      decision: async () => { called = true; return { decision: "allow", reason: "classifier allow" }; },
      llm: async () => { called = true; return { decision: "allow", reason: "classifier allow" }; },
    });
    assert.equal(verdict.decision, "ask");
    assert.equal(called, false);
  }
});

it("asks for shell resources beyond the scoring size and prompt bounds", () => {
  // The prompt and per-resource character bound is 65,536; the request byte
  // budget is 262,144. Either failure must keep the guard's manual floor.
  const oversized = "a".repeat(65_537);
  const manyBytes = Array.from({ length: 5 }, () => "a".repeat(60_000));
  for (const resources of [[oversized], manyBytes]) {
    const score = scoreRequest({ action: "shell", resources }, options);
    assert.equal(score.band, "high");
    assert.equal(score.ask, true);
    assert.equal(score.reason, "Shell command exceeds parsing limits");
  }
});

it("keeps non-shell request limit failures high without the manual floor", () => {
  const oversized = "a".repeat(65_537);
  const manyBytes = Array.from({ length: 5 }, () => "a".repeat(60_000));
  for (const action of ["read", "edit", "write", "glob", "grep", "webfetch", "websearch", "execute", "unknown-tool"]) {
    for (const resources of [[], Array.from({ length: 257 }, () => "a.ts"), [oversized], manyBytes]) {
      const score = scoreRequest({ action, resources }, options);
      assert.equal(score.band, "high", action);
      assert.equal(score.ask, undefined, action);
      assert.equal(score.deny, undefined, action);
    }
  }
  for (const action of ["question", "todowrite"])
    assert.equal(scoreRequest({ action, resources: [] }, options).band, "low", action);
});

it("rejects malformed shell before resolving the worktree root", () => {
  const request = { action: "shell", resources: [] as string[] } as { action: string; resources: string[]; worktreeRoot?: string };
  Object.defineProperty(request, "worktreeRoot", { get: () => { throw new Error("worktree lookup"); } });
  assert.equal(scoreRequest(request, options).ask, true);
});
