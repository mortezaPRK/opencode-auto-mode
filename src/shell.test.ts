import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { compositeDecision } from "./classifier.js";
import { escapeLiteralHashes, hasAmbiguousDescriptorClose, logicalLines, normalizeContinuations, parseShell, rawHeredocScript, stripDescriptorPrefixes } from "./shell-policy.js";
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
      "./safe\u00a0other",
      "touch a\u000bfoo",
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
    for (const command of ["echo a \\\nb", 'echo "a \\\nb"', "echo 'a \\\nb'",
      "cat <<'EOF'\nsudo \\\nid\nEOF", "cat <<'A' <<'B'\na \\\nb\nA\nc \\\nd\nB"])
      assert.equal(guardShell([command])?.decision, "allow", command);
    // ANSI-C quoting keeps the continuation literal too, but the guard asks
    // because it does not decode the quoting.
    assert.equal(normalizeContinuations("echo $'a \\\nb'"), "echo $'a \\\nb'");
    assert.equal(guardShell(["echo $'a \\\nb'"])?.decision, "ask");
    // `a\\`+newline leaves a real newline, so the next line is its own command.
    assert.equal(guardShell(["echo a\\\\\nb"]), undefined);
  });
  it("fails closed on heredoc headers and bodies that can move the terminator", () => {
    // Substitutions in an unquoted body, including quotes used as plain data.
    for (const command of ["cat <<EOF\n$(touch marker)\nEOF", "cat <<EOF\n`touch marker`\nEOF",
      "cat <<EOF\n'$(touch marker)'\nEOF", "cat <<-EOF\n$(touch marker)\nEOF",
      "cat <<EOF\n\\$(touch marker)\nEOF"])
      assert.equal(guardShell([command])?.decision, "ask", command);
    // An unquoted body is matched against its terminator after the shell removes
    // continuations, so any `\`-newline there fails closed, even when benign.
    for (const command of ["cat <<EOF\n$\\\n(touch marker)\nEOF", "cat <<EOF\nhello \\\nworld\nEOF",
      "cat <<EOF\n'$\\\n(touch marker)'\nEOF", "cat <<EOF\n\"$\\\n(touch marker)\"\nEOF",
      "cat <<EOF\n`\\\ntouch marker`\nEOF"])
      assert.equal(guardShell([command])?.decision, "ask", command);
    // A continuation in the header can hide, split, or shift the marker.
    for (const command of ["cat \\\n<<EOF\nhello\nEOF", "cat <<\\\nEOF\nhello\nEOF",
      "cat <<-\\\nEOF\nhello\nEOF", "cat <<E\\\nOF\nhello\nEOF", "cat <\\\n<'EOF'\nhello\nEOF",
      "cat <<'A' \\\n<<B\nhello\nA\nworld\nB", "cat \\\n<<'EOF'\n$\\\n(touch marker)\nEOF"])
      assert.equal(guardShell([command])?.decision, "ask", command);
    // A quoted body is data and its header is unambiguous, so continuations in
    // it stay literal and read-only.
    for (const command of ["cat <<'EOF'\n$\\\n(touch marker)\nEOF", 'cat <<"EOF"\n`touch marker`\nEOF',
      "cat <<'EOF'\nsudo \\\nid\nEOF", "cat <<'A' <<'B'\na \\\nb\nA\nc \\\nd\nB"])
      assert.equal(guardShell([command])?.decision, "allow", command);
    for (const command of ["cat <<EOF\nhello\nEOF", "cat <<'EOF'\ntext\nEOF\npwd", "cat <<< 'x'"])
      assert.equal(guardShell([command])?.decision, "allow", command);
    // Differential: for one body, a continued header may never be more
    // permissive than the plain header the guard already handled.
    const rank: Record<string, number> = { allow: 0, review: 1, ask: 2, deny: 3 };
    const bodies = ["$(touch marker)", "$\\\n(touch marker)", "'$\\\n(touch marker)'",
      "`touch marker`", "hello \\\nworld", "\\$(touch marker)", "hello"];
    for (const body of bodies) {
      const plain = guardShell([`cat <<EOF\n${body}\nEOF`]);
      const plainRank = rank[plain?.decision ?? "review"];
      for (const header of ["cat \\\n<<EOF", "cat <<\\\nEOF", "cat <<E\\\nOF", "cat <\\\n<EOF"]) {
        const continued = guardShell([`${header}\n${body}\nEOF`]);
        assert.ok(rank[continued?.decision ?? "review"] >= plainRank, `${header} ${body}`);
      }
    }
  });
  it("never auto-approves a heredoc whose terminator can shift past a command", () => {
    // Family 1: the quoted header is continued, so the marker is only visible
    // after normalization; the body continuation then hides the real terminator
    // and bash runs the tail.
    for (const command of ["cat <<\\\n'EOF'\nx\\\nEOF\nsudo id\nEOF",
      "cat <\\\n<'EOF'\nx\\\nEOF\nsudo id\nEOF"])
      assert.equal(guardShell([command])?.decision, "ask", command);
    // Plain marker, same body: the terminator is visible, so the tail is
    // analyzed as script and denied.
    assert.equal(guardShell(["cat <<'EOF'\nx\\\nEOF\nsudo id\nEOF"])?.decision, "deny");
    // Family 2: an unquoted body terminator joined by a continuation ends the
    // body early in bash, so the tail runs instead of being body data.
    for (const command of ["cat <<EOF\nEO\\\nF\nsudo id\nEOF", "cat <<EOF\nhello\nEO\\\nF\nsudo id\nEOF",
      "cat <<-EOF\nEO\\\nF\nsudo id\nEOF", "cat <<EOF\ntext\nEO\\\nF\nsudo id\nEOF",
      "cat <<\\\nEOF\nEO\\\nF\nsudo id\nEOF"])
      assert.equal(guardShell([command])?.decision, "ask", command);
    // Family 3: a delimiter assembled from quoted and unquoted parts is still
    // the shell's delimiter, so a shorter guess could swallow the tail.
    for (const command of ["cat <<E'OF'\nbody\nEOF\nsudo id\nEOF", "cat <<'EO'F\nbody\nEOF\nsudo id\nEOF",
      "cat <<E\"OF\"\nbody\nEOF\nsudo id\nEOF", "cat <<\\\nE'OF'\nbody\nEOF\nsudo id\nEOF",
      "cat <<-'EOF'X\nbody\nEOF\nsudo id\nEOF"])
      assert.equal(guardShell([command])?.decision, "ask", command);
    // Plain quoted markers keep their deny precedence for the same tail.
    for (const command of ["cat <<'EOF'\nx\nEOF\nsudo id", "sudo cat <<'EOF'\nx\nEOF"])
      assert.equal(guardShell([command])?.decision, "deny", command);
  });
  it("validates every raw heredoc header, not just the first line", () => {
    // The reported command: the stable body for `A` ends, then the second header
    // is continued (`<<\`+newline+`'EOF'`). Normalization joins that header before
    // the scanner sees it, and Bash keeps the backslash in the quoted body, so the
    // raw `EOF` line terminates it and `sudo id` runs as a command.
    const reported = "cat <<'A'\na\nA\ncat <<\\\n'EOF'\nx\\\nEOF\nsudo id\nEOF";
    assert.equal(guardShell([reported])?.decision, "ask");
    assert.notEqual(guardShell([reported])?.decision, "allow");
    // The same boundary shape with a read-only tail is still unknown.
    assert.equal(guardShell(["cat <<'A'\na\nA\ncat <<\\\n'EOF'\nx\\\nEOF\npwd\nEOF"])?.decision, "ask");
    // A command before the ambiguous header is certainly script, so a deny there
    // keeps its precedence instead of being downgraded to the ask.
    assert.equal(guardShell(["cat <<'A'\na\nA\nsudo id\ncat <<\\\n'EOF'\nx\\\nEOF\nEOF"])?.decision, "deny");
    assert.equal(guardShell(["cat <<'A'\na\nA\nsudo cat <<\\\n'EOF'\nx\\\nEOF\nEOF"])?.decision, "deny");
    // The same header text inside a quoted body is data: it must neither move the
    // boundary nor supply a deny.
    assert.equal(guardShell(["cat <<'EOF'\ncat <<\\\n'EOF'\nsudo id\nEOF"])?.decision, "allow");
    // A known tail after a stable quoted body keeps its mandatory deny.
    assert.equal(guardShell(["cat <<'EOF'\nx\nEOF\nsudo id"])?.decision, "deny");
    // The header of an undecodable heredoc is script even when its body contains
    // the split quoting the normalized gate rejects, so the header deny stays.
    assert.equal(guardShell(["cat <<\\EOF; sudo id\n$\\\n'x'\nEOF"])?.decision, "deny");
    // Split quoting on a later line is not parsed for a deny: in Bash it can be
    // quoted data, so that line only contributes the ask.
    assert.equal(guardShell(["pwd\nsort $\\\n'x ; sudo id'\ncat <<\\EOF\nbody\nEOF"])?.decision, "ask");
    // Nested scripts use the same raw header projection.
    assert.equal(guardShell(["sh -c 'cat <<\"A\"\na\nA\ncat <<\\\n\"EOF\"\nx\\\nEOF\nsudo id\nEOF'"])
      ?.decision, "ask");
    assert.equal(guardShell(["sh -c 'pwd\nsudo id\ncat <<\\\n\"EOF\"\nx\\\nEOF\nEOF'"])?.decision, "deny");
    // Nested header text inside a quoted body is still data and never a deny.
    assert.equal(guardShell(["sh -c 'cat <<\"EOF\"\ncat <<\\\n\"EOF\"\nsudo id\nEOF'"])?.decision, "ask");
    // The nested header deny also survives split quoting in its body.
    assert.equal(guardShell(["sh -c 'cat <<\\EOF; sudo id\n$\\\n\"x\"\nEOF'"])?.decision, "deny");
  });
  it("asks for heredoc delimiters the parser cannot decode exactly", () => {
    // A double-quoted delimiter decodes `\\`, `\$`, `` \` `` and `\"`, so the raw
    // text is not the terminator and a tail runs after the decoded one.
    for (const command of ["cat <<\"E\\\\OF\"\nx\nE\\OF\nsudo id\nE\\\\OF",
      "cat <<\"E\\$OF\"\nx\nE$OF\nsudo id\nE\\$OF",
      "cat <<\"E\\`OF\"\nx\nE`OF\nsudo id\nE\\`OF",
      "cat <<\"E\\\"OF\"\nx\nE\"OF\nsudo id\nE\\\"OF"])
      assert.equal(guardShell([command])?.decision, "ask", command);
    // Every marker on a multi-heredoc line is validated.
    for (const command of ["cat <<'A' <<\"E\\\\OF\"\nx\nA\ny\nE\\OF\nsudo id\nE\\\\OF",
      "cat <<\"E\\\\OF\" <<'A'\nx\nE\\OF\nsudo id\nE\\\\OF"])
      assert.equal(guardShell([command])?.decision, "ask", command);
    // Escaped, concatenated, unsupported-word, and unterminated delimiters.
    for (const command of ["cat <<\\EOF\nx\nEOF\nsudo id\nEOF", "cat <<\"EO\"F\nx\nEOF\nsudo id\nEOF",
      "cat <<E\"OF\"\nx\nEOF\nsudo id\nEOF", "cat <<-'E'X\nx\nEOF\nsudo id\nEOF",
      "cat <<\"EOF\nx\nEOF", "cat <<'EOF\nx\nEOF", "cat <<$x\nx\nEOF",
      "cat <<EOF-1\nx\nEOF-1", "cat <<EOF.x\nx\nEOF.x", "cat <<EOF=x\nx\nEOF=x",
      "cat <<EOF#x\nx\nEOF#x", "cat <<''\nx\n", "cat <<\nx\n"])
      assert.equal(guardShell([command])?.decision, "ask", command);
    // Single quotes keep a backslash literal, so the delimiter is faithful and
    // the tail after the terminator is script: deny precedence holds.
    assert.equal(guardShell(["cat <<'E\\OF'\nx\nE\\OF\nsudo id"])?.decision, "deny");
    assert.equal(guardShell(["cat <<'E\\OF'\nx\nE\\OF\npwd"])?.decision, "allow");
    // The supported grammar stays read-only: bare words, one quoted word, and a
    // double-quoted word whose text needs no decoding. `$'...'` text asks.
    for (const command of ["cat <<'EOF'\nx\nEOF", "cat <<\"EOF\"\nx\nEOF",
      "cat <<\"$x\"\nbody\n$x\npwd", "cat <<_EOF_1\nx\n_EOF_1\npwd", "cat <<2\nx\n2\npwd",
      "cat <<- 'EOF'\n\tx\n\tEOF\npwd", "cat <<'A B'\nx\nA B\npwd",
      "cat <<\"'EOF'\"\nx\n'EOF'\npwd"])
      assert.equal(guardShell([command])?.decision, "allow", command);
    assert.equal(guardShell(["cat <<\"$'EOF'\"\nx\n$'EOF'\npwd"])?.decision, "ask");
  });
  it("asks for whitespace a shell does not treat as a word separator", () => {
    // CR, FF, VT, NBSP, U+2028/U+2029, and em space are ordinary word characters
    // to a shell, so they must never be treated as word or heredoc boundaries.
    const controls = ["\r", "\f", "\v", "\u00a0", "\u2028", "\u2029", "\u2003"];
    for (const character of controls) {
      // The delimiter word keeps the character, so the real terminator differs
      // and a body collected on the shortened delimiter would swallow the tail.
      assert.equal(guardShell([`cat <<EOF${character}\nx\nEOF${character}\nsudo id\nEOF`])?.decision,
        "ask", `heredoc ${JSON.stringify(character)}`);
      // The character is midword, so `#` stays literal and the tail still runs.
      assert.equal(guardShell([`echo a${character}#x ;sudo id`])?.decision,
        "ask", `hash ${JSON.stringify(character)}`);
      // The guard rejects the whole command before normalization or parsing.
      assert.equal(guardShell([`pwd${character}`])?.decision, "ask", `plain ${JSON.stringify(character)}`);
      assert.throws(() => parseShell(`echo a${character}b`), /shell whitespace/, JSON.stringify(character));
    }
    // The reported commands: a CR delimiter and a CR before a midword hash.
    assert.equal(guardShell(["cat <<EOF\r\nx\nEOF\r\nsudo id\nEOF"])?.decision, "ask");
    assert.equal(guardShell(["echo a\r#x ;sudo id"])?.decision, "ask");
    // A nested shell script reaches the same parser, which refuses the text.
    assert.equal(guardShell(["sh -c 'echo a\u00a0b'"])?.decision, "ask");
    assert.equal(guardShell(["sh -c 'echo a\u00a0b'", "sudo id"])?.decision, "deny");
    // Space, tab, and newline remain the only word separators.
    for (const command of ["echo a b", "echo a\tb", "pwd\nls"])
      assert.equal(guardShell([command])?.decision, "allow", command);
  });
  it("asks for legacy $[ arithmetic before heredoc routing", () => {
    // The exact report: the `<<` in `$[ 1 << 2 ]` is a left shift, so `2` is not
    // a heredoc terminator and the tail runs. Nothing here may auto-allow.
    for (const command of ["echo $[ 1 << 2 ]\nsudo id\n2", "echo $[ 1 << 2 ]",
      "pwd\necho $[ 1 << 2 ]\nsudo id\n2", "sh -c 'echo $[ 1 << 2 ]'",
      "bash -c 'echo $[ 1 << 2 ]\nsudo id\n2'", "eval 'echo $[ 1 << 2 ]'",
      // Pre-quoted occurrences are conservative too: `$[` never auto-allows.
      "echo '$[ 1 + 1 ]'", "echo \"$[ 1 + 1 ]\"", "echo \\$[ 1 + 1 ]",
      "cat <<'EOF'\n$[ 1 + 1 ]\nEOF", "cat <<EOF\n$[ 1 + 1 ]\nEOF"])
      assert.equal(guardShell([command])?.decision, "ask", command);
    assert.notEqual(guardShell(["echo $[ 1 << 2 ]\nsudo id\n2"])?.decision, "allow");
  });
  it("asks for extended quoting the scanner does not decode", () => {
    // `$'...'` lets a backslash escape its own quote, so the `<<EOF` below is
    // string data and the tail runs; a quote scan that ended the string at the
    // escaped quote read it as a heredoc and swallowed the tail.
    for (const command of ["echo $'a\\\\\\'<<EOF\nx'\nsudo id\nEOF",
      "echo $'a\\\\\\'<<EOF\nx'\npwd\nEOF",
      // A locale quote has the same shape and is not decoded either.
      "echo $\"a<<EOF b\"\nsudo id\nEOF",
      // Ordinary extended quoting asks too, and quoted or heredoc data is
      // conservatively included.
      "echo $'a b'", "echo $'a\\nb'", "echo $\"a b\"", "echo \\$'a b'",
      "cat <<'EOF'\n$'a b'\nEOF", "cat <<EOF\n$'a b'\nEOF"])
      assert.equal(guardShell([command])?.decision, "ask", command);
    // A nested shell form reaches the same raw gate.
    for (const command of ["sh -c \"echo $'a b'\"",
      "bash -c \"echo $'a\\\\\\'<<EOF\nx'\nsudo id\nEOF\""])
      assert.equal(guardShell([command])?.decision, "ask", command);
    assert.equal(guardShell(["sh -c \"echo $'a b'\"", "sudo id"])?.decision, "deny");
    // The same text without extended quoting stays read-only.
    for (const command of ["echo a b", "echo 'a b'", 'echo "a b"'])
      assert.equal(guardShell([command])?.decision, "allow", command);
  });
  it("repeats the undecoded-syntax gates after normalization", () => {
    // The reported command: the raw text has `$`, a `\`-newline, and then a
    // quoted word, so the raw gate sees no ANSI-C quoting. Bash removes the pair
    // and parses `sort $'\x2doout' input`, which is `sort -oout input`, while the
    // guard read the joined word as an operand and fell through to review.
    const reported = "sort $\\\n'\\x2doout' input";
    assert.equal(guardShell([reported])?.decision, "ask");
    assert.notEqual(guardShell([reported])?.decision, "allow");
    for (const command of ["sort $\\\n'\\x2d'\\\n'oout' input",
      'sort $\\\n"-oout" input', "echo $\\\n'a b'", 'echo $\\\n"a b"',
      "echo $\\\n[ 1 + 1 ]", "sort $\\\n'\\x2doout' input ; pwd"])
      assert.equal(guardShell([command])?.decision, "ask", command);
    // A nested shell receives the assembled quoting once its outer `\`-newline is
    // removed, so the outer dynamic shell still has to ask.
    for (const command of ['sh -c "echo $\\\n\'a b\'"',
      'bash -c "sort $\\\n\'\\x2doout\' input"',
      "sh -c 'echo $\\\n\"a b\"'", "sh -c 'sort $\\\n\"-oout\" input'"])
      assert.equal(guardShell([command])?.decision, "ask", command);
    // A mandatory deny on another resource still wins over the new ask.
    assert.equal(guardShell([reported, "sudo id"])?.decision, "deny");
    // Forms that need no decoding keep their previous verdicts, and a quoted
    // heredoc body is data rather than a second gate.
    for (const command of ["sort '\\x2doout' input", 'sort "\\x2doout" input',
      "sort \\$ '\\x2doout' input", "cat <<'EOF'\nsort $\\\n'\\x2doout' input\nEOF"])
      assert.equal(guardShell([command])?.decision, "allow", command);
    assert.equal(guardShell(["sort $ '\\x2doout' input"]), undefined);
    assert.equal(guardShell(["sort '\\x2doout' input ; sudo id"])?.decision, "deny");
  });
  it("keeps a clean-code deny before assembled syntax", () => {
    // `sudo id` is complete, clean script before the later `$`+`\`-newline+`'`
    // form is assembled by normalization. The assembled quote itself is never
    // parsed, but the deny already visible in the prefix is mandatory.
    const assembled = "sort $\\\n'\\x2doout' input";
    assert.equal(guardShell([`sudo id\n${assembled}`])?.decision, "deny");
    assert.equal(guardShell([`rm -rf /\n${assembled}`])?.decision, "deny");
    assert.equal(guardShell([`sudo id ; ${assembled}`])?.decision, "deny");
    assert.equal(guardShell([`sudo id && ${assembled}`])?.decision, "deny");
    // A deny after a stable heredoc body is still clean script, so it keeps its
    // precedence even when the tail contains the assembled form.
    assert.equal(guardShell([`cat <<'EOF'\nx\nEOF\nsudo id\n${assembled}`])?.decision, "deny");
    assert.equal(guardShell([`cat <<'EOF'\nsudo id\nEOF\n${assembled}`])?.decision, "ask");
    // A quoted heredoc body is data, not clean code, so it never becomes a deny.
    assert.equal(guardShell([`cat <<'EOF'\n${assembled}\nsudo id\nEOF`])?.decision, "allow");
    // Nested scripts must not lose the same deny at the deny-pass early return.
    assert.equal(guardShell(['sh -c \'sudo id\nsort $\\\n"x"\''])?.decision, "deny");
    assert.equal(guardShell(['sh -c \'rm -rf /\nsort $\\\n"x"\''])?.decision, "deny");
    assert.equal(guardShell(['sh -c \'sudo id ; sort $\\\n"x"\''])?.decision, "deny");
    // The two reported bypasses keep asking; only the clean prefix can deny.
    assert.equal(guardShell(["cat <<'A'\na\nA\ncat <<\\\n'EOF'\nx\\\nEOF\nsudo id\nEOF"])?.decision, "ask");
    assert.equal(guardShell([assembled])?.decision, "ask");
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
      'echo ""#c ; sudo id', "echo '#' ; sudo id", 'echo "#" ; sudo id',
      "echo \\# ; sudo id", "VAR=#x sudo id", "echo ${x#y} ; sudo id", "echo $# ; sudo id",
      "echo ${#var} ; sudo id", 'echo "${x#y}" ; sudo id', "echo ${x##*/} ; sudo id",
      "sh -c 'echo a#b ; sudo id'", "eval 'echo a#b ; sudo id'", "bash -c 'echo a#b ; sudo id'",
      "cat <<'EOF'\ntext\nEOF\necho a#b ; sudo id"])
      assert.equal(guardShell([command])?.decision, "deny", command);
    // Quoted, escaped, and quoted-newline hashes stay literal.
    for (const command of ["echo '#'", 'echo "#"', "echo \\#", "echo a#b", "echo 'a#b'", 'echo "a#b"',
      "echo 'a\nb#c'"])
      assert.equal(guardShell([command])?.decision, "allow", command);
    // ANSI-C quoting is not decoded, so it asks instead of taking a deny.
    assert.equal(guardShell(["echo $'a#b' ; sudo id"])?.decision, "ask");
    assert.equal(guardShell(["echo $'a#b'"])?.decision, "ask");
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
      "uniq 2>/dev/null [ab].txt", "uniq $HOME/x", "uniq \\*.txt", "uniq \\?.txt",
      // A parameter in double quotes keeps one word only after expansion, and its
      // value decides the operand: `uniq "$HOME/x"` can become `uniq x /y`.
      'uniq "$HOME/x"', 'uniq "$@"', 'uniq "${X:--c}"'])
      assert.equal(guardShell([command]), undefined, command);
    // Quoted glob characters (and escaped brackets/braces) are literal operands, so one-operand calls stay read-only.
    for (const command of ["uniq '*.txt'", 'uniq "*.txt"', "uniq -c '*.txt'", "uniq -- '*.txt'",
      "uniq '[ab].txt'", "uniq '{a,b}.txt'", "uniq \\[ab\\].txt", "uniq 2>/dev/null '*.txt'",
      // Single quotes and an escaped `\$` are literal text, not a parameter.
      "uniq '$.txt'", "uniq '\\$HOME/x'", 'uniq "\\$HOME/x"'])
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
    for (const command of ['echo "2>&-sudo"', "echo '2>&-sudo'",
      "echo 2\\>\\&-sudo", "pwd # 2>&-sudo"])
      assert.equal(guardShell([command])?.decision, "allow", command);
    // ANSI-C quoting asks before the descriptor scan can disagree with the shell.
    assert.equal(guardShell(["echo $'2>&-sudo'"])?.decision, "ask");
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

  it("splits nested scripts into the commands their shell runs", () => {
    // `shell-quote` reads a newline as plain whitespace, so a nested script has to
    // be split into logical commands before the deny pass: otherwise the second
    // line becomes an argument of the first command and the deny is missed.
    for (const command of ["sh -c 'pwd\nsudo id'", "bash -c 'pwd\nrm -rf /'", "eval 'pwd\nsudo id'",
      "sh -c 'pwd\nls\nsudo id'", "sh -lc 'echo first\nsudo id'", "bash -c 'pwd\nrm -r -- /'",
      "sh -c 'pwd # comment\nsudo id'", "sh -c 'echo one; pwd\nchmod 777 secret'",
      "sh -c 'echo \"first\nsecond\" ; sudo id'", "bash -c 'for x in a\nrm -rf /'"])
      assert.equal(guardShell([command])?.decision, "deny", command);
    // A quoted newline is part of one word, so the invocation stays whole instead
    // of splitting into a fragment that no longer names `sudo`.
    assert.equal(guardShell(["sh -c 'sudo echo \"first\nsecond\"'"])?.decision, "deny");
    assert.equal(guardShell(["sh -c 'echo \"first\nsecond\"'"])?.decision, "ask");
    // Nothing dangerous inside still asks: a nested shell needs manual approval.
    for (const command of ["sh -c 'pwd\nls'", "bash -c 'echo \"first\nsecond\"'", "eval 'pwd\npwd'"])
      assert.equal(guardShell([command])?.decision, "ask", command);
    // The deny pass also reaches a dangerous resource behind a nested one.
    assert.equal(guardShell(["sh -c 'pwd'", "sh -c 'sudo id'"])?.decision, "deny");
    assert.equal(guardShell(["sh -c 'pwd'", "pwd"])?.decision, "ask");
  });

  it("excludes nested heredoc bodies from the deny pass", () => {
    // The body of a heredoc is data for the inner shell, so a dangerous word or a
    // `;` inside it is text, not a command. Only the surrounding script is judged.
    for (const command of ["sh -c 'cat <<\"EOF\"\ntext; sudo id\nEOF'",
      "sh -c 'cat <<\"EOF\"\nrm -rf /\nEOF'", "bash -c 'cat <<\"EOF\"\nchmod 777 secret\nEOF'",
      "eval 'cat <<EOF\nsudo id\nEOF'", "sh -c 'cat <<- \"EOF\"\n\tsudo id\n\tEOF'",
      "sh -c 'cat <<\"A\" <<\"B\"\nx\nA\nsudo id\nB'", "sh -c 'cat <<\\EOF\nx\nEOF\nsudo id\nEOF'",
      "sh -c 'cat <<\"EOF\"\nx\nEOF\n'"]
      ) assert.equal(guardShell([command])?.decision, "ask", command);
    // A command after the terminator is script again, so the tail still denies.
    for (const command of ["sh -c 'cat <<\"EOF\"\nx\nEOF\nsudo id'",
      "eval 'cat <<EOF\nx\nEOF\nrm -rf /'", "bash -c 'cat <<-EOF\n\tx\n\tEOF\nshutdown now'",
      "sh -c 'cat <<\"A\" <<\"B\"\nx\nA\ny\nB\nrm -r -- /'"])
      assert.equal(guardShell([command])?.decision, "deny", command);
    // The same shapes outside a nested shell keep their previous verdicts.
    assert.equal(guardShell(["cat <<\"EOF\"\ntext; sudo id\nEOF"])?.decision, "allow");
    assert.equal(guardShell(["cat <<\"EOF\"\nx\nEOF\nsudo id"])?.decision, "deny");
  });

  it("projects a script onto its commands with the shared logical-line scan", () => {
    assert.deepEqual(logicalLines("cat <<'EOF'\nsudo id\nEOF\npwd"),
      { lines: ["cat <<'EOF'", "pwd"], certain: 2 });
    assert.deepEqual(logicalLines("cat <<-'EOF'\n\tsudo id\n\tEOF\nls"),
      { lines: ["cat <<-'EOF'", "ls"], certain: 2 });
    assert.deepEqual(logicalLines("echo a # comment ; sudo id\npwd").lines,
      ["echo a # comment ; sudo id", "pwd"]);
    assert.deepEqual(logicalLines("echo 'a\nb'\nsudo id").lines, ["echo 'a\nb'", "sudo id"]);
    assert.deepEqual(logicalLines("echo a\\\nsudo id").lines, ["echo a\\\nsudo id"]);
    // An undecodable header still leaves its own line script: `cat <<E'OF'; sudo id`
    // runs `sudo id`, but nothing after that line is trusted.
    assert.deepEqual(logicalLines("cat <<E'OF'\nbody\nEOF\nsudo id"),
      { lines: ["cat <<E'OF'", "body", "EOF", "sudo id"], certain: 1 });
    // An unquoted body line ending in a backslash removes its newline, so the
    // terminator can match later: only the header is certain script.
    assert.equal(logicalLines("cat <<EOF\nfoo\\\nEOF\nsudo id\nEOF").certain, 1);
    assert.equal(logicalLines("cat <<'EOF'\nfoo\\\nEOF\nsudo id\nEOF").certain, 3);
    assert.equal(logicalLines("cat <<< 'x' ; sudo id").certain, 1);
    // Bodies are absent from the projection; only the header and tail are script.
    assert.equal(logicalLines("cat <<'EOF'\ntext\nEOF\npwd").lines.some((line) => line.includes("text")), false);
    assert.deepEqual(logicalLines("cat <<'EOF'\nsudo id\nEOF").lines, ["cat <<'EOF'", ""]);
  });
  it("projects raw headers up to the first one it cannot decode", () => {
    // Every header is visited, so a continued later header ends the certain
    // prefix even though the first header is plain.
    assert.deepEqual(rawHeredocScript("cat <<'A'\na\nA\ncat <<\\\n'EOF'\nx\\\nEOF\nsudo id\nEOF"),
      { lines: ["cat <<'A'", "cat <<\\\n'EOF'"], ambiguous: true });
    // A plain header with a stable body does not end it, and the body is data.
    assert.deepEqual(rawHeredocScript("cat <<'EOF'\ncat <<\\\n'EOF'\nsudo id\nEOF"),
      { lines: ["cat <<'EOF'"], ambiguous: false });
    assert.deepEqual(rawHeredocScript("cat <<'EOF'\nx\nEOF\npwd"),
      { lines: ["cat <<'EOF'", "pwd"], ambiguous: false });
    assert.deepEqual(rawHeredocScript("pwd ; sudo id"),
      { lines: ["pwd ; sudo id"], ambiguous: false });
  });

  it("requires review when an unquoted expansion can add arguments", () => {
    // Bash expands one written word into several arguments, so a literal flag
    // policy cannot see the flags that will actually run. `sort
    // --out{put,put}=out` becomes two `--output=out` options and writes a file.
    for (const command of ["sort --out{put,put}=out input", "sort --out{put,put}=out",
      "sort --output{=x} file", "rg -{n,l} pattern file", "bat --pager{,=less} file",
      "date +{a,b}", "tree -{L,o} 2", "file {--compile,-C} /tmp/magic", "hostname {a,b}",
      "hostname --file={/tmp/name}", "cat {a,b}.txt", "ls *.txt", "rg pattern *.ts",
      "wc -l [ab].txt", "printf %s [ab]"])
      assert.equal(guardShell([command]), undefined, command);
    // Quoted glob characters and braces are literal text, so the flag policies
    // still apply to the words that will run and those calls stay allowed. (A
    // quoted *parameter* is uncertain and covered below.)
    for (const command of ["cat '{a,b}.txt'", "ls '*.txt'", "sort '-u' file", "uniq '*.txt'",
      "rg 'a{1,2}' file", "date '+%s'", "bat --style=numbers README.md"])
      assert.equal(guardShell([command])?.decision, "allow", command);
    // An identifiable mandatory deny is decided before the expansion check.
    for (const command of ["sudo id *.txt", "cat {a,b} ; sudo id", "rm -rf / {a,b}",
      "chmod 777 {a,b}", "sort --out{put,put}=out in ; sudo id"])
      assert.equal(guardShell([command])?.decision, "deny", command);
    // A root hidden inside an expansion is not identifiable, so it is only review.
    for (const command of ["rm -rf {/tmp/x,/}", "rm -rf /tmp/{x,/}"])
      assert.equal(guardShell([command]), undefined, command);
  });

  it("ends rm option parsing at a literal double dash", () => {
    // `--` ends option parsing, so `-r` there is a file name and the invocation is
    // not recursive: it cannot remove the root and must reach review, not a deny.
    for (const command of ["rm -- -r /", "rm -- -r -f /", "rm -f -- /", "rm -- -rf /",
      "rm -- / -r", "rm -- --recursive /"])
      assert.equal(guardShell([command]), undefined, command);
    // Recursion written before `--` still applies to every later target.
    for (const command of ["rm -r -- /", "rm -rf -- /", "rm --recursive -- /", "rm -R -- /*",
      "rm -r -- / --no-preserve-root", "rm -fr --tmp -- /"])
      assert.equal(guardShell([command])?.decision, "deny", command);
    // The previous shapes keep their verdicts.
    for (const command of ["rm -rf /", "rm -r /*", "rm --recursive /"])
      assert.equal(guardShell([command])?.decision, "deny", command);
    for (const command of ["rm -rf ./build", "rm -- ./build", "rm -f /tmp/file"])
      assert.notEqual(guardShell([command])?.decision, "deny", command);
  });

  it("treats a double-quoted parameter as an uncertain argument", () => {
    // `shell-quote` drops a parameter it cannot resolve, so `sort "${X:--oout}"
    // input` looked like `sort "" input` and was auto-approved, while Bash expands
    // the default to `-oout` and writes a file. Any unescaped `$` inside double
    // quotes is one uncertain word until it expands, `$@` included: it can become
    // several arguments and change the operand count.
    for (const command of ['sort "${X:--oout}" input', 'find . "${X:--delete}"',
      'uniq "$@"', 'uniq "$HOME/x"', 'rg "${X:---pre=./p}" pattern .',
      'bat "${X:---config-file=/tmp/x}" file', 'hostname "${X:--b}"',
      'tree "${X:---output=/tmp/out}"', 'cat "$file"', 'git log --format="$x"',
      'echo "${X:--n}"', 'rg -n "$pattern" src'])
      assert.equal(guardShell([command]), undefined, command);
    // Single quotes and an escaped `\$` are literal text, and quoted glob
    // characters were already one word, so those keep their read-only verdicts.
    for (const command of ["sort '$X' input", 'sort "\\$X" input', "uniq '\\$HOME/x'",
      'uniq "\\$HOME/x"', "rg '\\$HOME' src", "cat '$HOME'", 'uniq "*.txt"'])
      assert.equal(guardShell([command])?.decision, "allow", command);
    // Raw dynamic syntax still asks, and an identifiable deny still wins.
    for (const command of ['sort "$(echo x)" input', 'pwd "`echo x`"', 'cat "$((1 + 1))"'])
      assert.equal(guardShell([command])?.decision, "ask", command);
    for (const command of ['sudo sort "${X:--oout}" input', 'cat "$x" ; sudo id',
      'find . "${X:--delete}" && sudo id'])
      assert.equal(guardShell([command])?.decision, "deny", command);
  });

  it("fails closed when an unquoted heredoc body can move its terminator", () => {
    // A shell removes a `\`-newline in an unquoted body before matching the
    // terminator, so a body line ending in a backslash swallows the next line —
    // including the line that merely looks like the terminator. The raw text ended
    // the body early and read `sudo id` as a command that never runs.
    for (const command of ["cat <<EOF\nfoo\\\nEOF\nsudo id\nEOF",
      "cat <<EOF\nfoo\\\nbar\nEOF\nsudo id", "cat <<-EOF\n\tfoo\\\n\tEOF\nsudo id\nEOF",
      "sh -c 'cat <<EOF\nfoo\\\nEOF\nsudo id\nEOF'",
      "sh -c 'cat <<-EOF\n\tfoo\\\n\tEOF\npwd'"])
      assert.equal(guardShell([command])?.decision, "ask", command);
    // A quoted body keeps its backslashes, so the terminator cannot move and the
    // tail is still script.
    for (const command of ["cat <<'EOF'\nfoo\\\nEOF\nsudo id\nEOF",
      'cat <<"EOF"\nfoo\\\nEOF\nsudo id', 'sh -c \'cat <<"EOF"\nfoo\\\nEOF\nsudo id\nEOF\''])
      assert.equal(guardShell([command])?.decision, "deny", command);
    // The header is still script, and benign unquoted bodies stay read-only.
    assert.equal(guardShell(["sudo cat <<EOF\nfoo\\\nEOF"])?.decision, "deny");
    for (const command of ["cat <<EOF\nhello\nEOF", "cat <<'EOF'\nfoo\\\nbar\nEOF"])
      assert.equal(guardShell([command])?.decision, "allow", command);
  });

  it("finds the -c script after later shell options", () => {
    // A shell keeps parsing options after `-c`, so its first operand is the
    // script: `sh -c -e '...'` and `sh -c -- '...'` run the quoted string. Taking
    // `-e` or `--` for the script missed the deny entirely.
    for (const command of ["sh -c -e 'pwd\nsudo id'", "sh -c -- 'pwd\nsudo id'",
      "bash -c -x -e 'rm -rf /'", "sh -c -o errexit 'sudo id'", "sh -c -O extglob 'sudo id'",
      "bash -c --noprofile --norc 'sudo id'", "sh -ce 'pwd\nsudo id'", "sh -c -u -- 'chmod 777 x'",
      "bash -c -e -c 'sudo id'"])
      assert.equal(guardShell([command])?.decision, "deny", command);
    // An unknown option could consume the script itself, and a missing script has
    // no commands to check, so both fail closed to manual approval.
    for (const command of ["sh -c -Z 'sudo id'", "sh -c -e", "sh -c -e pwd", "sh -c"])
      assert.equal(guardShell([command])?.decision, "ask", command);
    // Only the first operand is the script; later words are its arguments.
    assert.equal(guardShell(["sh -c 'pwd' -c 'sudo id'"])?.decision, "ask");
  });

  it("denies header commands of a heredoc whose body boundary is unknown", () => {
    // An undecodable delimiter leaves the body boundary unknown, but everything on
    // the header line runs before the body is read: `cat <<\EOF; sudo id` still
    // runs `sudo id`, and the delimiter itself is only a redirection target.
    for (const command of ["sh -c 'cat <<\\EOF; sudo id\nx\nEOF'",
      "bash -c 'cat <<\\EOF; rm -rf /'", "eval 'cat <<\\EOF; chmod 777 x\nbody\nEOF'",
      "sh -c 'cat <<E'\"'\"'OF'\"'\"'; sudo id\nx\nEOF'", "cat <<\\EOF; sudo id\nx\nEOF",
      "cat \\\n<<EOF; sudo id\nx\nEOF"])
      assert.equal(guardShell([command])?.decision, "deny", command);
    // Nothing past the header line is trusted, so body data is never a command.
    for (const command of ["sh -c 'cat <<\\EOF\nsudo id\nEOF'",
      "sh -c 'cat <<\\EOF; pwd\nsudo id\nEOF'", "sh -c 'cat <<\\EOF; echo sudo\nx\nEOF'",
      "cat <<\\EOF\nx\nEOF\nsudo id\nEOF"])
      assert.equal(guardShell([command])?.decision, "ask", command);
  });

  it("keeps the earlier gates ahead of the new verdicts", () => {
    // Deny precedence, dynamic syntax, and parse failures are unchanged.
    assert.equal(guardShell(["sudo echo 'first\nsecond'"])?.decision, "deny");
    assert.equal(guardShell(["pwd $(sudo id)"])?.decision, "ask");
    assert.equal(guardShell(["sh -c 'echo a\u00a0b'"])?.decision, "ask");
    assert.equal(guardShell(["sh -c 'echo $[ 1 << 2 ]'"])?.decision, "ask");
    assert.equal(guardShell(["sh -c \"echo $'a b'\""])?.decision, "ask");
    // Nested continuations, hashes, and descriptor closes keep their gates.
    assert.equal(guardShell(["bash -c 's\\\nudo id'"])?.decision, "deny");
    assert.equal(guardShell(["sh -c 'echo a#b ; sudo id'"])?.decision, "deny");
    assert.equal(guardShell(["sh -c 'true;2>&-sudo id'"])?.decision, "ask");
    assert.equal(guardShell(["sh -c 'stdbuf -o L sudo id'"])?.decision, "deny");
    // Read-only pipelines and permits that do not depend on flags stay allowed.
    for (const command of ["rg TODO src && bun run typecheck", "git status --short", "ls -la src",
      "docker logs otel-lgtm --since 10m 2>&1 | grep -iE 'trace|error'",
      "gh label list --limit 100 2>&1", "find . -name '*.ts'", "uniq -c file", "hostname -s"])
      assert.equal(guardShell([command])?.decision, "allow", command);
  });
});
