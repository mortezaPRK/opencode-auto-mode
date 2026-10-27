import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { compositeDecision } from "./classifier.js";
import { guardShell, shellWords } from "./shell.js";

const unused = async () => { throw new Error("unexpected reviewer call"); };
const permissive = [{ type: "llm" as const }];

describe("shell approval guard", () => {
  it("rejects a dangerous tail before any configured reviewer can allow it", async () => {
    for (const resources of [["pwd ; sudo rm -rf"], ["pwd", "sudo rm -rf"], ['"su"do rm -rf'], ["rm '-rf' '/'"],
      ["sudo cat <<'EOF'\nhello\nEOF"]])
      assert.equal((await compositeDecision(permissive, { action: "shell", resources }, unused)).decision, "deny");
  });
  it("does not block read-only command sequences or harmless redirections", () => {
    for (const command of [
      "pwd",
      "pwd && ls",
      "git status --short && git branch --show-current",
      "date +%s ; date +%s",
      "gh label list --limit 100 2>&1",
      "docker logs otel-lgtm --since 10m 2>&1 | grep -iE 'trace|error'",
      "sed -n '210,232p' ~/.config/opencode/opencode.json",
      "gh api repos/x/issues/25 --jq '{\"number,title\"}'",
      "rg TODO src && bun run typecheck",
      "ls -la src",
      "echo done > /dev/null 2>&1",
      "cat /tmp/file",
      "find . -name '*.ts'",
      "pwd &",
    ]) assert.equal(guardShell([command]), undefined, command);
  });
  it("delegates parsed but non-read-only syntax to reviewers instead of asking", () => {
    for (const command of [
      "pwd ; touch marker",
      "pwd && touch marker",
      "pwd | tee marker",
      "pwd > marker",
      "pwd\ntouch marker",
      "touch *.txt",
      "touch {a,b}",
      "touch [ab]",
      "touch ~/marker",
      "VAR=x pwd",
      "env pwd",
      "cd /tmp",
      "exit 0",
      "cat > /tmp/check.ts <<'EOF'\nrm -rf /tmp/data\nEOF",
      "cat <<EOF\nhello\nEOF",
      "./safe\u00a0other",
      "touch a\u000bfoo",
    ]) assert.equal(guardShell([command]), undefined, command);
  });
  it("asks for dynamic or unparseable shell syntax", () => {
    for (const command of [
      "pwd $(touch marker)",
      "pwd `touch marker`",
      "pwd <(touch marker)",
      "pwd $((1 + 1))",
      "cat $(pwd) <<'EOF'\nhello\nEOF",
      "bash -c pwd",
      "! bash -c pwd",
      "time bash -c pwd",
      "sh -c 'touch marker'",
      "touch \"unclosed",
      "touch 'unclosed",
      "touch a\\",
      "eval pwd",
      "source ./x.sh",
      "xargs rm",
      "python <<'EOF'\nprint(1)\nEOF",
      "find . -delete",
      "find . -exec rm {} ;",
      "alias pwd='touch marker'; pwd",
      "alias pwd=whoami",
      "builtin alias pwd='touch marker'; pwd",
      "env bash -c pwd",
      "export PATH=/tmp",
      "set -- pwd",
      "trap touch EXIT",
      "umask 000",
    ]) assert.equal(guardShell([command])?.decision, "ask", command);
  });
  it("accepts literal arguments and delegates safe sequences to reviewers", async () => {
    assert.deepEqual(shellWords('touch "a b"'), ["touch", "a b"]);
    assert.equal(guardShell(["touch file"]), undefined);
    const allowed = await compositeDecision([{ type: "static" }], { action: "shell", resources: ["pwd", "ls"] }, unused);
    assert.equal(allowed.decision, "allow");
    let reviewed = 0;
    const chain = await compositeDecision(permissive, { action: "shell", resources: ["git status && git branch --show-current"] }, async () => {
      reviewed++;
      return { decision: "allow", reason: "authorized" };
    });
    assert.equal(chain.decision, "allow");
    assert.equal(reviewed, 1);
  });
  it("runs before decision and model reviewers", async () => {
    const stages = [{ type: "decision" as const, model: "typesafe-ai/jev-latest" }, { type: "llm" as const }];
    assert.equal((await compositeDecision(stages, { action: "shell", resources: ["pwd $(touch marker)"] }, unused)).decision, "ask");
    assert.equal((await compositeDecision(stages, { action: "shell", resources: ["sudo rm -rf /"] }, unused)).decision, "deny");
    const reviewed = await compositeDecision(stages, { action: "shell", resources: ["pwd > marker"] }, async (stage) => {
      assert.equal(stage.type, "decision");
      return { decision: "allow", reason: "authorized" };
    });
    assert.equal(reviewed.decision, "allow");
  });
});
