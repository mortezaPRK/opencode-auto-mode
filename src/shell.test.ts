import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { compositeDecision } from "./classifier.js";
import { guardShell, shellWords } from "./shell.js";

const unused = async () => { throw new Error("unexpected reviewer call"); };
const permissive = [{ type: "llm" as const }];

describe("shell approval guard", () => {
  it("rejects a dangerous tail before any configured reviewer can allow it", async () => {
    for (const resources of [["pwd ; sudo rm -rf"], ["pwd", "sudo rm -rf"], ['"su"do rm -rf'], ["rm '-rf' '/'"]])
      assert.equal((await compositeDecision(permissive, { action: "shell", resources }, unused)).decision, "deny");
  });
  it("requires manual approval for unsupported shell syntax", async () => {
    for (const command of ["pwd ; touch marker", "pwd && touch marker", "pwd | tee marker", "pwd > marker", "pwd $(touch marker)",
      "pwd `touch marker`", "pwd &", "pwd\ntouch marker", "VAR=x pwd", "env pwd", "bash -c pwd", "! bash -c pwd", "time bash -c pwd", "cd /tmp", "touch *.txt", "touch {a,b}", "touch [ab]", "touch ~/marker", 'touch "unclosed', "touch 'unclosed",
      "touch a\\", "./safe\u00a0other", "touch a\u000bfoo", "export PATH=/tmp", "set -- pwd", "alias pwd=whoami", "trap touch EXIT", "umask 000", "exit 0"])
      assert.equal((await compositeDecision(permissive, { action: "shell", resources: [command] }, unused)).decision, "ask", command);
  });
  it("accepts literal arguments and delegates safe command sequences already parsed by OpenCode", async () => {
    assert.deepEqual(shellWords('touch "a b"'), ["touch", "a b"]);
    assert.equal(guardShell(["touch file"]), undefined);
    assert.equal((await compositeDecision([{ type: "static" }], { action: "shell", resources: ["pwd", "ls"] }, unused)).decision, "allow");
  });
  it("runs before decision and model reviewers", async () => {
    const stages = [{ type: "decision" as const, model: "typesafe-ai/jev-latest" }, { type: "llm" as const }];
    assert.equal((await compositeDecision(stages, { action: "shell", resources: ["pwd > marker"] }, unused)).decision, "ask");
    assert.equal((await compositeDecision(stages, { action: "shell", resources: ["sudo rm -rf /"] }, unused)).decision, "deny");
  });
});
