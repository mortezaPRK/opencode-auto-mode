import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { compositeDecision } from "./classifier.js";
import { escapeLiteralHashes, hasAmbiguousDescriptorClose, normalizeContinuations, stripDescriptorPrefixes } from "./shell-policy.js";
import { guardShell, shellWords } from "./shell.js";

const unused = async () => { throw new Error("unexpected reviewer call"); };
const permissive = [{ type: "llm" as const }];

describe("shell approval guard", () => {
  it("rejects a dangerous tail before any configured reviewer can allow it", async () => {
    for (const resources of [["pwd ; sudo rm -rf"], ["pwd", "sudo rm -rf"], ['"su"do rm -rf'], ["rm '-rf' '/'"],
      ["sudo cat <<'EOF'\nhello\nEOF"], ["pwd; \"su\"do id"], ["pwd; rm '-rf' '/'"],
      ["cat <<'EOF'\ntext\nEOF\nsudo id"]])
      assert.equal((await compositeDecision(permissive, { action: "shell", resources }, unused)).decision, "deny");
  });
  it("allows read-only command sequences and harmless redirections", () => {
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
      "cat <<EOF\nhello\nEOF",
      "cat <<-EOF\n\thello\n\tEOF",
    ]) assert.equal(guardShell([command])?.decision, "allow", command);
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
      "bash -c pwd",
      "! bash -c pwd",
      "time bash -c pwd",
      "sh -c 'touch marker'",
      "env -i sh ./payload.sh",
      "FOO=x eval 'touch marker'",
      "builtin alias pwd='touch marker'; pwd",
      "touch \"unclosed",
      "touch 'unclosed",
      "touch a\\",
      "eval pwd",
      "source ./x.sh",
      "xargs rm",
      "find . -delete",
      "find . -exec rm {} ;",
      "alias pwd='touch marker'; pwd",
      "alias pwd=whoami",
      "env bash -c pwd",
      "export PATH=/tmp",
      "set -- pwd",
      "trap touch EXIT",
      "umask 000",
      "python <<'EOF'\nprint(1)\nEOF",
      "bash <<'EOF'\npwd\nEOF",
      "cat <<EOF\n$(touch marker)\nEOF",
      "cat <<EOF\ntext",
    ]) assert.equal(guardShell([command])?.decision, "ask", command);
  });
  it("keeps deny precedence across lines and resources", () => {
    assert.equal(guardShell(["bash -c pwd", "sudo id"])?.decision, "deny");
    assert.equal(guardShell(["bash -c pwd\nsudo id"])?.decision, "deny");
    assert.equal(guardShell(["pwd $(touch marker)", "sudo id"])?.decision, "deny");
    assert.equal(guardShell(["pwd $(touch marker)\nsudo id"])?.decision, "deny");
    assert.equal(guardShell(["bash -c pwd", "touch marker"])?.decision, "ask");
  });
  it("denies blocked invocations whose quoted argument spans a literal newline", () => {
    for (const command of ["sudo echo 'first\nsecond'", 'sudo echo "first\nsecond"',
      "pwd\nsudo echo 'first\nsecond'\nls", "echo \"first\nsecond\"\nsudo id",
      "sh -c 'sudo echo \"first\nsecond\"'", "eval 'sudo echo \"first\nsecond\"'",
      "cat <<'EOF'\ntext\nEOF\nsudo echo 'first\nsecond'"])
      assert.equal(guardShell([command])?.decision, "deny", command);
    assert.equal(guardShell(["echo 'first\nsecond'"])?.decision, "allow");
  });
  it("denies blocked invocations split by a backslash continuation", () => {
    for (const command of ["sudo echo first \\\nsecond", "pwd; sudo \\\nid", "pwd; s\\\nu\\\ndo id",
      "su\\\ndo id", "pwd; rm -r\\\nf /", "rm -rf \\\n/", "chmod 77\\\n7 secret",
      "chmod 777 2\\\n>/dev/null secret", "mkfs.ext\\\n4 /dev/sda1", "dd of=\\\n/dev/sda",
      "shutdown -\\\nh now", "stdbuf -o L \\\nsudo id", "env -u HOME sudo \\\nid",
      "bash -c 'sudo echo first \\\nsecond'", "bash -c 's\\\nudo id'", "eval 'rm -rf \\\n/'",
      "cat <<'EOF'\ntext\nEOF\nsudo echo first \\\nsecond", "cat <<'EOF'\na \\\nb\nEOF\nsudo \\\nid"])
      assert.equal(guardShell([command])?.decision, "deny", command);
  });
  it("keeps continuations literal where the shell keeps them", () => {
    // Outside quotes, and inside double quotes, the shell removes the pair.
    assert.equal(normalizeContinuations("sudo \\\nid"), "sudo id");
    assert.equal(normalizeContinuations('echo "a \\\nb"'), 'echo "a b"');
    // Single quotes and ANSI-C quoting hold the backslash and newline as data.
    assert.equal(normalizeContinuations("echo 'a \\\nb'"), "echo 'a \\\nb'");
    assert.equal(normalizeContinuations("echo $'a \\\nb'"), "echo $'a \\\nb'");
    // An escaped backslash leaves a newline that still separates commands.
    assert.equal(normalizeContinuations("echo a\\\\\nb"), "echo a\\\\\nb");
    assert.equal(normalizeContinuations("echo a\\\\\\\nb"), "echo a\\\\b");
    // A comment ends at its newline, and heredoc bodies are copied unchanged.
    assert.equal(normalizeContinuations("echo a # comment \\\nsudo id"), "echo a # comment \\\nsudo id");
    assert.equal(normalizeContinuations("cat <<'EOF'\nsudo \\\nid\nEOF"), "cat <<'EOF'\nsudo \\\nid\nEOF");
    assert.equal(normalizeContinuations("cat <<EOF\na \\\nb\nEOF"), "cat <<EOF\na \\\nb\nEOF");
    assert.equal(normalizeContinuations("cat <<'A' <<'B'\na \\\nb\nA\nc \\\nd\nB"),
      "cat <<'A' <<'B'\na \\\nb\nA\nc \\\nd\nB");
    // A here-string has no body, so a following command is still normalized.
    assert.equal(normalizeContinuations("cat <<< 'x' ; sudo \\\nid"), "cat <<< 'x' ; sudo id");
    assert.equal(guardShell(["cat <<< 'x'"])?.decision, "allow");
    assert.equal(guardShell(["cat <<< 'x' ; sudo id"])?.decision, "deny");
    for (const command of ["sudo \\\nid", "echo 'a \\\nb'", "cat <<EOF\na \\\nb\nEOF", "touch 'unclosed \\\nword"])
      assert.equal(normalizeContinuations(normalizeContinuations(command)), normalizeContinuations(command), command);
    for (const command of ["echo a \\\nb", 'echo "a \\\nb"', "echo 'a \\\nb'", "echo $'a \\\nb'",
      "cat <<'EOF'\nsudo \\\nid\nEOF", "cat <<'A' <<'B'\na \\\nb\nA\nc \\\nd\nB"])
      assert.equal(guardShell([command])?.decision, "allow", command);
    // `a\\`+newline leaves a real newline, so the next line is its own command.
    assert.equal(guardShell(["echo a\\\\\nb"]), undefined);
  });
  it("keeps a continued command exactly as dangerous as the command it joins", () => {
    const insert = (command: string, index: number) => `${command.slice(0, index)}\\\n${command.slice(index)}`;
    for (const command of ["sudo id", "su root", "rm -rf /", "rm -r / --no-preserve-root", "chmod 777 secret",
      "mkfs.ext4 /dev/sda1", "dd of=/dev/sda", "shutdown -h now", "bash -c 'sudo id'", "eval 'rm -rf /'"]) {
      assert.equal(guardShell([command])?.decision, "deny", command);
      for (let index = 0; index <= command.length; index++) {
        // A continuation is invisible to the shell, so no split may loosen a deny.
        assert.equal(guardShell([insert(command, index)])?.decision, "deny", insert(command, index));
      }
    }
    for (const command of ["pwd", "echo done", "git status --short", "ls -la src", "date +%s"]) {
      assert.equal(guardShell([command])?.decision, "allow", command);
      for (let index = 0; index <= command.length; index++)
        assert.equal(guardShell([insert(command, index)])?.decision, "allow", insert(command, index));
    }
  });
  it("treats hashes as comments only at the start of a word", () => {
    for (const command of ["echo a#b ; sudo id", "echo a#b; sudo id", "echo a#b && sudo id",
      "echo a#b | sudo id", "echo a#b\nsudo id", "echo 'a\nb'#c ; sudo id",
      'echo "a\nb"#c ; sudo id', "echo a\\ #b ; sudo id", "echo ''#c ; sudo id",
      'echo ""#c ; sudo id', "echo $'a#b' ; sudo id", "echo '#' ; sudo id", 'echo "#" ; sudo id',
      "echo \\# ; sudo id", "VAR=#x sudo id", "echo ${x#y} ; sudo id", "echo $# ; sudo id",
      "echo ${#var} ; sudo id", 'echo "${x#y}" ; sudo id', "echo ${x##*/} ; sudo id",
      "sh -c 'echo a#b ; sudo id'", "eval 'echo a#b ; sudo id'", "bash -c 'echo a#b ; sudo id'",
      "cat <<'EOF'\ntext\nEOF\necho a#b ; sudo id"])
      assert.equal(guardShell([command])?.decision, "deny", command);
    // Quoted, escaped, and quoted-newline hashes stay literal.
    for (const command of ["echo '#'", 'echo "#"', "echo \\#", "echo a#b", "echo 'a#b'", 'echo "a#b"',
      "echo $'a#b'", "echo 'a\nb#c'"])
      assert.equal(guardShell([command])?.decision, "allow", command);
    // A real word-start comment still discards the rest of its line.
    for (const command of ["echo a # comment ; sudo id", "echo a#b # comment ; sudo id",
      "echo 'a\nb' #comment ; sudo id"])
      assert.equal(guardShell([command])?.decision, "allow", command);
  });
  it("feeds parsed read-only commands into the static stage without bypassing model-only pipelines", async () => {
    assert.deepEqual(shellWords('touch "a b"'), ["touch", "a b"]);
    assert.equal(guardShell(["touch file"]), undefined);
    for (const command of ["ls -la src", "sed -n '1,2p' file"]) {
      const allowed = await compositeDecision([{ type: "static" }], { action: "shell", resources: [command] }, unused);
      assert.equal(allowed.decision, "allow", command);
      assert.equal(allowed.stage, "static");
      let reviewed = 0;
      const modelOnly = await compositeDecision([{ type: "llm" }], { action: "shell", resources: [command] }, async () => {
        reviewed++;
        return { decision: "allow", reason: "authorized" };
      });
      assert.equal(modelOnly.decision, "allow");
      assert.equal(reviewed, 1);
    }
    const split = await compositeDecision([{ type: "static" }], { action: "shell", resources: ["pwd", "ls"] }, unused);
    assert.equal(split.decision, "allow");
    let chainReviewed = 0;
    const chain = await compositeDecision(permissive, { action: "shell", resources: ["git status && git branch --show-current"] }, async () => {
      chainReviewed++;
      return { decision: "allow", reason: "authorized" };
    });
    assert.equal(chain.decision, "allow");
    assert.equal(chainReviewed, 1);
  });
  it("requires review when a read-only command is given write or exec flags", () => {
    for (const command of [
      "rg --pre 'sh -c id' x .",
      "rg --pre-glob '*.txt' --pre ./p x .",
      "rg -z pattern file",
      "sort -o /tmp/out file",
      "sort --compress-program=sh file",
      "tree -o /tmp/out",
      "file -C -m /tmp/magic",
      "bat --pager='sh -c id' file",
      "bat --config-file=./evil.toml file",
      "bat --generate-config-file",
      "bat --gen",
      "hostname evil",
      "uniq in.txt out.txt",
    ]) assert.equal(guardShell([command]), undefined, command);
    for (const command of ["rg -n sudo src", "sort -u file", "tree -L 2", "file package.json", "bat README.md",
      "bat --style=numbers README.md", "hostname -s", "uniq -c file"])
      assert.equal(guardShell([command])?.decision, "allow", command);
  });

  it("does not deny commands that only mention dangerous text", () => {
    for (const command of ["rg sudo src", "rg -n 'mkfs.ext4' docs", "cat notes-about-sudo.md",
      "git log --grep=shutdown", 'echo "chmod 777"', "printf '%s\\n' 'rm -rf /'",
      "git commit -m 'explain reboot handling'"])
      assert.notEqual(guardShell([command])?.decision, "deny", command);
    for (const command of ["rg sudo src", "cat notes-about-sudo.md", "git log --grep=shutdown", 'echo "chmod 777"'])
      assert.equal(guardShell([command])?.decision, "allow", command);
  });

  it("still denies dangerous operations hidden in nested shells", () => {
    for (const command of ["bash -c 'rm -rf /'", "sh -lc 'sudo id'", "eval 'chmod 777 x'", "rm -fr /",
      "sh -c 'rm -r / --no-preserve-root'", "sudo -n id", "mkfs.ext4 /dev/sda1"])
      assert.equal(guardShell([command])?.decision, "deny", command);
    // Subshell syntax is not parsed into segments, so it stays a manual approval.
    assert.equal(guardShell(["( sudo id )"])?.decision, "ask");
  });
  it("runs before decision and model reviewers", async () => {    const stages = [{ type: "decision" as const, model: "typesafe-ai/jev-latest" }, { type: "llm" as const }];
    assert.equal((await compositeDecision(stages, { action: "shell", resources: ["pwd $(touch marker)"] }, unused)).decision, "ask");
    assert.equal((await compositeDecision(stages, { action: "shell", resources: ["sudo rm -rf /"] }, unused)).decision, "deny");
    const reviewed = await compositeDecision(stages, { action: "shell", resources: ["pwd > marker"] }, async (stage) => {
      assert.equal(stage.type, "decision");
      return { decision: "allow", reason: "authorized" };
    });
    assert.equal(reviewed.decision, "allow");
  });
});

describe("shell policy edge cases", () => {
  it("reviews abbreviated long options that can write or execute", () => {
    for (const command of ["sort --out=/tmp/out file", "sort --out /tmp/out file", "tree --out=/tmp/out",
      "date --se=2030-01-01"])
      assert.equal(guardShell([command]), undefined, command);
    assert.equal(guardShell(["sort --output=/tmp/out file"]), undefined);
    assert.equal(guardShell(["sort -u file"])?.decision, "allow");
  });

  it("counts every uniq operand after a lone dash or --", () => {
    for (const command of ["uniq - /tmp/out", "uniq -- input.txt -output.txt", "uniq -- -c -d"])
      assert.equal(guardShell([command]), undefined, command);
    for (const command of ["uniq -c file", "uniq -- file", "uniq -"])
      assert.equal(guardShell([command])?.decision, "allow", command);
  });

  it("reviews uniq arguments that macOS treats as an output file", () => {
    for (const command of ["uniq in.txt -out.txt", "uniq in.txt --count", "uniq -z file", "uniq --unknown file"])
      assert.equal(guardShell([command]), undefined, command);
    for (const command of ["uniq -f 2 file", "uniq -f2 file", "uniq -ci file", "uniq --skip-fields 2 file",
      "uniq --count file", "uniq --all-repeated=separate file"])
      assert.equal(guardShell([command])?.decision, "allow", command);
  });

  it("reviews uniq operands that can glob-expand into the output argument", () => {
    for (const command of ["uniq *.txt", "uniq -c *.txt", "uniq -f *.txt", "uniq -- *.txt",
      "uniq in.txt *.txt", "uniq [ab].txt", "uniq {a,b}.txt", "uniq a'b'[c].txt",
      "uniq 2>/dev/null [ab].txt", "uniq $HOME/x", "uniq \\*.txt", "uniq \\?.txt"])
      assert.equal(guardShell([command]), undefined, command);
    // Quoted glob characters (and escaped brackets/braces) are literal operands, so one-operand calls stay read-only.
    for (const command of ["uniq '*.txt'", 'uniq "*.txt"', "uniq -c '*.txt'", "uniq -- '*.txt'",
      "uniq '[ab].txt'", "uniq '{a,b}.txt'", "uniq \\[ab\\].txt", "uniq 2>/dev/null '*.txt'",
      'uniq "$HOME/x"'])
      assert.equal(guardShell([command])?.decision, "allow", command);
  });

  it("reviews bat cache mutations and lessopen preprocessors", () => {
    for (const command of ["bat cache --build", "bat cache --clear", "bat --lessopen file",
      "bat --lessopen='sh -c id' file", "bat cache --bui", "bat cache --cle", "bat --less=less"])
      assert.equal(guardShell([command]), undefined, command);
    for (const command of ["bat README.md", "bat --style=numbers README.md", "bat cache --list"])
      assert.equal(guardShell([command])?.decision, "allow", command);
  });

  it("reviews hostname operands and host-name setting options", () => {
    for (const command of ["hostname -", "hostname -- -review-host", "hostname -b", "hostname -b review-host",
      "hostname --boot", "hostname --boo", "hostname --file /tmp/name", "hostname --fil=/tmp/name",
      "hostname -F /tmp/name"])
      assert.equal(guardShell([command]), undefined, command);
    for (const command of ["hostname", "hostname --", "hostname -s", "hostname -f", "hostname -I"])
      assert.equal(guardShell([command])?.decision, "allow", command);
  });

  it("reviews date invocations that set the clock", () => {
    for (const command of ["date 010100002030", "date -u 010100002030", "date -s '2030-01-01'",
      "date --set=2030-01-01"])
      assert.equal(guardShell([command]), undefined, command);
    for (const command of ["date", "date +%s", "date -u +%Y-%m-%d", "date -d tomorrow +%s",
      "date --date=@0 +%s", "date --iso-8601=seconds", "date -Iseconds", "date -R"])
      assert.equal(guardShell([command])?.decision, "allow", command);
  });

  it("ignores inherited properties when looking up a command policy", async () => {
    for (const command of ["./constructor", "./__proto__", "./toString", "constructor"]) {
      assert.equal(guardShell([command]), undefined, command);
      const result = await compositeDecision([{ type: "static" }], { action: "shell", resources: [command] }, unused);
      assert.equal(result.decision, "ask", command);
    }
  });

  it("denies rm when any target is the filesystem root", () => {
    for (const command of ["rm -rf / /tmp/scratch --no-preserve-root", "rm -rf /tmp/scratch /",
      "rm -rf /* /tmp/scratch", "rm -rf /. /tmp", "rm -r /", "rm -r / --no-preserve-root",
      "rm --recursive /", "rm -R /*"])
      assert.equal(guardShell([command])?.decision, "deny", command);
    for (const command of ["rm -rf /tmp/scratch", "rm -rf ./build", "rm -rf /tmp/*", "rm -f /", "rm /tmp/file"])
      assert.notEqual(guardShell([command])?.decision, "deny", command);
  });

  it("denies chmod only when the mode operand is world-writable", () => {
    for (const command of ["chmod 777 secret", "chmod -R 777 dir", "chmod --changes 0777 file"])
      assert.equal(guardShell([command])?.decision, "deny", command);
    for (const command of ["chmod 600 777", "chmod u+w 777", "chmod --reference=secret 777"])
      assert.notEqual(guardShell([command])?.decision, "deny", command);
  });

  it("keeps a redirection inside the simple command it belongs to", () => {
    assert.equal(guardShell(["bash -c 'rm >/dev/null -rf /'"])?.decision, "deny");
    assert.equal(guardShell(["sh -c 'sudo id > /tmp/log'"])?.decision, "deny");
    assert.equal(guardShell(["sh -c 'echo hi > /tmp/log; rm -rf /'"])?.decision, "deny");
    assert.equal(guardShell(["bash -c '2>/dev/null rm -rf /'"])?.decision, "deny");
    assert.equal(guardShell(["sh -c '2>&1 sudo id'"])?.decision, "deny");
    assert.equal(guardShell(["bash -c 'echo >/dev/null sudo'"])?.decision, "ask");
    assert.equal(guardShell(["bash -c 'echo 2>/dev/null sudo id'"])?.decision, "ask");
  });

  it("parses each wrapper's options before resolving the executable", () => {
    for (const command of ["stdbuf -o L sudo id", "stdbuf -oL sudo id", "stdbuf --output=L sudo id",
      "stdbuf --output L sudo id", "stdbuf --out L sudo id", "stdbuf --o=L sudo id",
      "ionice -c 3 sudo id", "ionice -c3 sudo id", "ionice --class=3 sudo id", "ionice -n 7 sudo id",
      "nice -n 5 sudo id", "nice -5 sudo id", "nice --adjustment=5 sudo id", "timeout -s KILL 5 sudo id",
      "timeout --kill-after=1 5 sudo id", "timeout 5 sudo id", "env -u HOME sudo id", "env --unset=HOME sudo id",
      "env -C /tmp sudo id", "time -f %E sudo id", "setsid -f sudo id", "exec -a name sudo id",
      "sh -c 'stdbuf -o L sudo id'"])
      assert.equal(guardShell([command])?.decision, "deny", command);
    for (const command of ["stdbuf -o0 pwd", "ionice -c3 pwd", "nice -n 5 pwd", "timeout -s KILL 5 pwd",
      "env -u HOME pwd", "time -p pwd", "setsid -w pwd", "nice -5 pwd"])
      assert.equal(guardShell([command]), undefined, command);
    // An unknown wrapper option could consume the executable, so a human decides.
    for (const command of ["stdbuf --unknown sudo id", "env -Q sudo id"])
      assert.equal(guardShell([command])?.decision, "ask", command);
  });

  it("asks for env split-string instead of resolving past its value", () => {
    for (const command of ["env -S 'sudo id'", "env --split-string='sudo id'", "env --split-string 'sudo id'",
      "env --split 'sudo id'", "env -iS 'sudo id'", "env -S pwd", "sh -c \"env -S 'sudo id'\""])
      assert.equal(guardShell([command])?.decision, "ask", command);
  });

  it("escapes only literal hashes that shell-quote would read as comments", () => {
    assert.equal(escapeLiteralHashes("echo a#b ; sudo id"), "echo a\\#b ; sudo id");
    assert.equal(escapeLiteralHashes("echo a # comment ; sudo id"), "echo a # comment ; sudo id");
    assert.equal(escapeLiteralHashes("echo 'a#b' ; sudo id"), "echo 'a#b' ; sudo id");
    assert.equal(escapeLiteralHashes("echo a\\#b ; sudo id"), "echo a\\#b ; sudo id");
    assert.equal(escapeLiteralHashes("echo a\\ #b ; sudo id"), "echo a\\ \\#b ; sudo id");
    assert.equal(escapeLiteralHashes("VAR=#x sudo id"), "VAR=\\#x sudo id");
    assert.equal(escapeLiteralHashes("echo $'a#b' ; sudo id"), "echo $'a#b' ; sudo id");
  });

  it("drops only descriptor prefixes that are adjacent in the source", () => {
    assert.equal(stripDescriptorPrefixes("chmod 777 > /dev/null secret"), "chmod 777 > /dev/null secret");
    assert.equal(stripDescriptorPrefixes("echo 2>/dev/null"), "echo  >/dev/null");
    assert.equal(stripDescriptorPrefixes("echo 12>&1"), "echo  >&1");
    assert.equal(stripDescriptorPrefixes("pwd;2>/dev/null"), "pwd; >/dev/null");
    assert.equal(stripDescriptorPrefixes("true&2>/dev/null sudo id"), "true& >/dev/null sudo id");
    assert.equal(stripDescriptorPrefixes("true &2>>/dev/null rm -r /"), "true & >>/dev/null rm -r /");
    assert.equal(stripDescriptorPrefixes("echo 2 >/dev/null"), "echo 2 >/dev/null");
    assert.equal(stripDescriptorPrefixes('echo "2">/dev/null'), 'echo "2">/dev/null');
    assert.equal(stripDescriptorPrefixes("echo $'2>file'"), "echo $'2>file'");
    assert.equal(stripDescriptorPrefixes("echo $'it\\'s 2>file'"), "echo $'it\\'s 2>file'");
    assert.equal(stripDescriptorPrefixes("echo \\2>/dev/null"), "echo \\2>/dev/null");
    assert.equal(stripDescriptorPrefixes("echo x2>/dev/null"), "echo x2>/dev/null");
    assert.equal(stripDescriptorPrefixes("echo a=2>/dev/null"), "echo a=2>/dev/null");
    for (const command of ["chmod 777 > /dev/null secret", "sh -c 'chmod 777 > /dev/null secret'",
      "eval 'chmod 777 > /dev/null secret'", "chmod 777 >> log secret", "chmod 0777 2>/dev/null secret",
      "chmod 777 < /dev/null secret", "bash -c 'chmod 777 2>/dev/null secret'"])
      assert.equal(guardShell([command])?.decision, "deny", command);
    // A quoted or escaped digit is an argument, not a changed file descriptor.
    for (const command of ['chmod 600 "2">/dev/null secret', "chmod 600 \\2>/dev/null secret"])
      assert.notEqual(guardShell([command])?.decision, "deny", command);
  });

  it("keeps background operators separate from descriptor prefixes", () => {
    for (const command of ["true&2>/dev/null sudo -n id", "true&2>&1 sudo -n id",
      "true &2>>/dev/null rm -r /", "true &1>/dev/null sudo -n id", "true &2>2 chmod 777 secret",
      "true&2>2 chmod 777 secret", "sh -c 'true &2>/dev/null sudo -n id'",
      "eval 'true &2>/dev/null rm -r /'"])
      assert.equal(guardShell([command])?.decision, "deny", command);
    // The background helper must still reach review, never a static allow.
    for (const command of ["true &2>2 chmod777 secret", "true &2>/dev/null bat --generate-config-file",
      "true &2>>/dev/null bat --generate-config-file"])
      assert.equal(guardShell([command]), undefined, command);
  });

  it("asks when an fd close is concatenated with a command word", () => {
    for (const command of ["true;2>&-sudo id", "true&&2>&-sudo id", "true||2>&-sudo id",
      "true|2>&-sudo id", "true&2>&-sudo id", "true\n2>&-sudo id", "true;2<&-sudo id",
      'true;2>&-"sudo" id', "true;2>&-'sudo' id", "true;2>&-\\sudo id",
      "true;2>&-chmod 777 secret", "true;2>&-rm -rf /", "true;2>&-bat --generate-config-file",
      "2>&-sudo id", ">&-sudo id", "sh -c 'true;2>&-sudo id'", "eval 'true;2>&-rm -rf /'"])
      assert.equal(guardShell([command])?.decision, "ask", command);
    assert.equal(hasAmbiguousDescriptorClose("true;2>&-sudo id"), true);
    assert.equal(hasAmbiguousDescriptorClose('true;2>&-"sudo" id'), true);
    assert.equal(hasAmbiguousDescriptorClose("true;2>&-\\sudo id"), true);
    assert.equal(hasAmbiguousDescriptorClose("true;2<&-sudo id"), true);

    // A delimited close keeps its meaning: `2>&-` closes the descriptor.
    for (const command of ["pwd;2>&-", "pwd;2<&-", "pwd;2>&- ls", "pwd;2<&- ls", "pwd;2>&-&&ls",
      "pwd;2>&-||ls", "pwd;2>&-|cat", "pwd;2>&-&", "pwd;2>&->/dev/null", "echo 2>&- done",
      "pwd\n2>&-"])
      assert.equal(guardShell([command])?.decision, "allow", command);
    assert.equal(hasAmbiguousDescriptorClose("true;2>&- id"), false);
    assert.equal(hasAmbiguousDescriptorClose("true;2>&-;id"), false);
    assert.equal(hasAmbiguousDescriptorClose("true;2>&-&&id"), false);
    assert.equal(hasAmbiguousDescriptorClose("true;2>&-|id"), false);

    // Quoted or escaped text is data, not a descriptor or a command.
    for (const command of ['echo "2>&-sudo"', "echo '2>&-sudo'", "echo $'2>&-sudo'",
      "echo 2\\>\\&-sudo", "pwd # 2>&-sudo"])
      assert.equal(guardShell([command])?.decision, "allow", command);
    assert.equal(hasAmbiguousDescriptorClose('echo "2>&-sudo"'), false);
    assert.equal(hasAmbiguousDescriptorClose("echo '2>&-sudo'"), false);
    assert.equal(hasAmbiguousDescriptorClose("echo 2\\>\\&-sudo"), false);
  });

  it("denies identifiable commands before asking about dynamic arguments", () => {
    assert.equal(guardShell(["sudo id $(printf ignored)"])?.decision, "deny");
    assert.equal(guardShell(["sudo shutdown `date`"])?.decision, "deny");
    assert.equal(guardShell(["pwd $(sudo id)"])?.decision, "ask");
    assert.equal(guardShell(["echo $(sudo id)"])?.decision, "ask");
  });

  it("treats a glob redirection target as a write", () => {
    for (const command of ["pwd > *.txt", "pwd > *.txt file"])
      assert.equal(guardShell([command]), undefined, command);
  });

  it("never auto-approves the newly reviewed dangerous operations", () => {
    for (const command of ["env -S 'sudo id'", "env --split-string='sudo id'", "uniq *.txt",
      "uniq [ab].txt", "uniq {a,b}.txt", "uniq in.txt *.txt", "bat cache --build", "bat cache --clear",
      "bat --lessopen file", "hostname -", "hostname -- -review-host", "hostname -b review-host",
      "sudo echo 'first\nsecond'"])
      assert.notEqual(guardShell([command])?.decision, "allow", command);
  });
});
