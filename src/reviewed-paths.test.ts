import { it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { classifyPath, policyRoots, type PolicyRoots } from "./path-policy.js";
import { parseShellCommands, protectedSegment } from "./shell.js";
import { scoreRequest } from "./score.js";
import { parseOptions } from "./config.js";

const options = parseOptions({ classifiers: [{ type: "static" }] });
function fixture(run: (root: string, roots: PolicyRoots) => void): void {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "reviewed-paths-")));
  const roots = { home: join(root, "home"), config: join(root, "config"), data: join(root, "data") };
  for (const dir of Object.values(roots)) mkdirSync(dir);
  const env = { HOME: roots.home, XDG_CONFIG_HOME: roots.config, XDG_DATA_HOME: roots.data, OPENCODE_DB: undefined };
  const previous = Object.fromEntries(Object.keys(env).map((key) => [key, process.env[key]]));
  Object.assign(process.env, env); delete process.env.OPENCODE_DB;
  try { assert.equal(policyRoots().home, roots.home); run(root, roots); } finally {
    for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    rmSync(root, { recursive: true, force: true });
  }
}
function shell(root: string, command: string) { return scoreRequest({ action: "shell", projectDir: root, resources: [command] }, options); }

it("keeps symlinked catalog stores and their canonical resources protected", () => {
  fixture((root, roots) => {
    mkdirSync(join(roots.home, ".aws")); mkdirSync(join(roots.data, "opencode"));
    for (const [name, alias] of [["account-data", join(roots.home, ".aws/credentials")], ["database", join(roots.data, "opencode/opencode.db")]]) {
      const target = join(root, name); writeFileSync(target, "fixture"); symlinkSync(target, alias);
      for (const operand of [alias, target]) assert.equal(classifyPath(operand, root, roots).kind, "protected", operand);
    }
    for (const suffix of ["-wal", "-shm", "-journal"]) {
      assert.equal(classifyPath(join(root, `database${suffix}`), root, roots).kind, "protected");
      assert.equal(classifyPath(join(roots.data, `opencode/opencode.db${suffix}`), root, roots).kind, "protected");
    }
    mkdirSync(join(roots.home, ".gnupg")); mkdirSync(join(root, "key-store"));
    symlinkSync(join(root, "key-store"), join(roots.home, ".gnupg/private-keys-v1.d"));
    assert.equal(classifyPath(join(root, "key-store/item"), root, roots).kind, "protected");
    writeFileSync(join(root, "env-data"), "fixture"); symlinkSync("env-data", join(root, ".env.local"));
    assert.equal(classifyPath(".env.local", root, roots).kind, "protected");
    assert.equal(shell(root, "cat .env.local").deny, true);
    assert.equal(shell(root, "git add .env.local").deny, undefined);
  });
});

it("does not turn impossible traversal or env directories into credential accesses", () => {
  fixture((root, roots) => {
    writeFileSync(join(root, "regular"), "fixture");
    for (const name of ["missing/../.env.local", "regular/../.env.local", "regular/./.env.local", `${"x".repeat(256)}/../.env.local`])
      assert.equal(classifyPath(name, root, roots).kind, "unresolved", name);
    for (const name of [".env", ".env.venv"]) {
      mkdirSync(join(root, name, "lib"), { recursive: true });
      assert.equal(classifyPath(name, root, roots).kind, "ordinary");
      assert.equal(classifyPath(`${name}/lib/module.py`, root, roots).kind, "ordinary");
    }
    assert.equal(classifyPath(".env.production", root, roots).kind, "protected");
  });
});

it("keeps attached file values protected when another argument expands", () => {
  fixture((root) => {
    for (const command of ['grep -f.env.local "$INPUT"', 'grep -f .env.local "$INPUT"', 'grep --file=.env.local "$INPUT"',
      'gh api endpoint --input .env.local -F title="$TITLE"', 'gh api endpoint --input=.env.local -F title="$TITLE"']) {
      const parsed = parseShellCommands(command)!;
      assert.equal(protectedSegment(parsed.segments[0], root), true, command);
      assert.equal(shell(root, command).deny, true, command);
    }
    for (const command of ['grep -f"$INPUT" file', 'grep --file="$INPUT" file'])
      assert.equal(protectedSegment(parseShellCommands(command)!.segments[0], root), false, command);
  });
});

it("uses shell expansion provenance without decoding literal native paths or -- operands", () => {
  fixture((root, roots) => {
    mkdirSync(join(roots.home, ".ssh")); writeFileSync(join(roots.home, ".ssh/id_rsa"), "fixture");
    for (const command of ["cat ~/.ssh/id_rsa", 'cat $HOME/.ssh/id_rsa', 'cat "${HOME}/.ssh/id_rsa"'])
      assert.equal(shell(root, command).deny, true, command);
    for (const command of ["cat '~/.ssh/id_rsa'", "cat \\~/.ssh/id_rsa", "cat '$HOME/.ssh/id_rsa'", "cat -- --file=.env.local", "cat -f~/.ssh/id_rsa"])
      assert.equal(shell(root, command).deny, undefined, command);
    for (const target of ["~/.ssh/id_rsa", "$HOME/.ssh/id_rsa"])
      assert.equal(scoreRequest({ action: "read", projectDir: root, resources: [target] }, options).deny, undefined, target);
  });
});

it("separates git revision operands, format data, and output descriptors", () => {
  fixture((root) => {
    for (const command of ["git show --format=prefix:.env.local HEAD", "git show --date prefix:.env.local HEAD", "git show -- HEAD:.env.local", "git show --unknown prefix:.env.local"])
      assert.equal(shell(root, command).deny, undefined, command);
    for (const command of ["git show HEAD:.env.local", "git show --format=short HEAD:.env.local", "git diff HEAD:.env.local", "echo fixture >& .env"])
      assert.equal(shell(root, command).deny, true, command);
    for (const command of ["echo fixture >&1", "echo fixture >&-", "cat <&0"])
      assert.equal(shell(root, command).deny, undefined, command);
  });
});

it("keeps protected Git revision operands after optional attached-value flags", () => {
  fixture((root) => {
    for (const flag of ["--pretty", "--abbrev", "--format", "--stat", "--decorate", "--color", "--word-diff", "--unified"]) {
      assert.equal(shell(root, `git show ${flag} HEAD:.env.local`).deny, true, flag);
      assert.equal(shell(root, `git show ${flag}=fixture HEAD:.env.local`).deny, true, flag);
      assert.equal(shell(root, `git show ${flag}=prefix:.env.local HEAD`).deny, undefined, flag);
    }
    for (const flag of ["--date", "--encoding"])
      assert.equal(shell(root, `git show ${flag} prefix:.env.local HEAD`).deny, undefined, flag);
  });
});

it("preserves runtime-file designations in bounded final symlink chains", () => {
  fixture((root, roots) => {
    writeFileSync(join(root, "runtime-data"), "fixture");
    symlinkSync("runtime-data", join(root, ".env.runtime")); symlinkSync(".env.runtime", join(root, "env-alias"));
    symlinkSync("env-alias", join(root, "outer-alias"));
    for (const name of [".env.runtime", "env-alias", "outer-alias"]) {
      assert.equal(classifyPath(name, root, roots).kind, "protected", name);
      assert.equal(shell(root, `cat ${name}`).deny, true, name);
      assert.equal(shell(root, `git add ${name}`).deny, undefined, name);
    }
    mkdirSync(join(root, "directory")); symlinkSync("directory", join(root, ".env.directory"));
    symlinkSync(".env.directory", join(root, "directory-alias"));
    assert.equal(classifyPath("directory-alias/ordinary", root, roots).kind, "ordinary");
    symlinkSync("cycle", join(root, ".env.cycle")); symlinkSync(".env.cycle", join(root, "cycle"));
    assert.equal(classifyPath("cycle", root, roots).kind, "unresolved");
  });
});

it("does not substitute the original home after shell binding effects", () => {
  fixture((root, roots) => {
    mkdirSync(join(roots.home, ".ssh")); writeFileSync(join(roots.home, ".ssh/id_rsa"), "fixture");
    for (const command of ['HOME=/synthetic/project; cat "$HOME/.ssh/id_rsa"', 'HOME=/synthetic/project\ncat ~/.ssh/id_rsa',
      'export HOME=/synthetic/project; cat "$HOME/.ssh/id_rsa"', "eval 'HOME=/synthetic/project'; cat ~/.ssh/id_rsa",
      'source setup.sh; cat "$HOME/.ssh/id_rsa"', '. setup.sh; cat ~/.ssh/id_rsa', 'unknown-function; cat ~/.ssh/id_rsa',
      'printf -v HOME replacement; cat ~/.ssh/id_rsa', 'HOME=/synthetic/project; cat < "$HOME/.ssh/id_rsa"',
      'HOME=/synthetic/project\ncat "$HOME/.ssh/id_rsa" # $\'suffix\'']) {
      const score = shell(root, command); assert.equal(score.deny, undefined, command); assert.equal(score.band, "high", command);
    }
    for (const command of ['cat "$HOME/.ssh/id_rsa"', 'pwd; cat ~/.ssh/id_rsa', 'pwd\ncat "$HOME/.ssh/id_rsa"',
      'echo HOME=/synthetic/project; cat ~/.ssh/id_rsa', 'cat ~/.ssh/id_rsa; HOME=/synthetic/project', 'HOME=/synthetic/project; cat .env.local'])
      assert.equal(shell(root, command).deny, true, command);
    assert.equal(scoreRequest({ action: "shell", projectDir: root, resources: ['HOME=/synthetic/project', 'cat "$HOME/.ssh/id_rsa"'] }, options).deny, true);
  });
});
