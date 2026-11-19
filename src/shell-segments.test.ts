import { it } from "node:test";
import assert from "node:assert/strict";
import { splitShellSegmentsWithLeadingCd } from "./shell-segments.js";

const splits = (command: string, expected: readonly string[]): void => {
  assert.deepEqual(splitShellSegmentsWithLeadingCd(command)?.segments, expected, command);
};

const unresolved = (command: string): void => {
  assert.equal(splitShellSegmentsWithLeadingCd(command), undefined, command);
};

it("splits every top-level separator and trims each segment", () => {
  splits("grep a f; git diff | head\nbun run typecheck", ["grep a f", "git diff", "head", "bun run typecheck"]);
  splits("a && b || c", ["a", "b", "c"]);
  splits("  gofmt -w f.go  ", ["gofmt -w f.go"]);
});

it("keeps quoted operators and redirects inside one segment", () => {
  splits("grep 'a|b; c' f", ["grep 'a|b; c' f"]);
  splits(`grep "x && y || z" f`, [`grep "x && y || z" f`]);
  splits(`grep "it's" f && head -3 g`, [`grep "it's" f`, "head -3 g"]);
  splits(`grep ">" f`, [`grep ">" f`]);
  splits(`grep "<" f`, [`grep "<" f`]);
});

it("rejects stateful first segment words", () => {
  for (const command of [
    "2>&1 cd /tmp; rm -rf .",
    "2>&1 2>&1 export PATH=x",
    "pushd /tmp",
    "popd",
    "export PATH=x; git status",
    "unset PATH",
    "alias ll=ls",
    "unalias ll",
    "set -e",
    "shopt -s nullglob",
    "source ./env",
    ". ./env",
    "eval 'rm -rf /'",
    "exec ls",
    "trap 'x' EXIT",
    "umask 077",
    "builtin cd /tmp",
    "command ls",
    "env FOO=bar git status",
    "sh -c 'x'",
    "bash -c 'x'",
    "zsh -c 'x'",
    "xargs rm",
    "sudo rm -rf /",
  ]) unresolved(command);
});

it("rejects assignment prefixes and quoted stateful words", () => {
  unresolved("FOO=bar bun test");
  unresolved("IFS=, read -r a b");
  unresolved("FOO='bar baz' bun test");
  unresolved("'cd' /tmp");
  unresolved(`"export" PATH=x`);
  unresolved(`c"d" /tmp`);
  unresolved(`\\cd /tmp`);
});

it("still splits ordinary segments that merely mention stateful words", () => {
  splits("git commit -m 'cd /tmp'", ["git commit -m 'cd /tmp'"]);
  splits("grep -n export src/a.ts", ["grep -n export src/a.ts"]);
  splits("./script.sh && git status", ["./script.sh", "git status"]);
});

it("rejects ANSI-C quoting, process substitution and input redirection", () => {
  unresolved("echo $'a\\'; rm -rf /tmp/x; echo b'");
  unresolved("diff <(a) <(b)");
  unresolved("cat >(tee out.log)");
  unresolved("wc < file");
  unresolved("sort <in && head out");
  unresolved("cat <&0");
});

it("allows exactly the 2>&1 redirection", () => {
  splits("bun test 2>&1", ["bun test 2>&1"]);
  splits("go test ./... 2>&1 && git diff --check", ["go test ./... 2>&1", "git diff --check"]);
});

it("rejects output redirection other than 2>&1", () => {
  unresolved("bun test > out.log");
  unresolved("bun test >> out.log");
  unresolved("bun test 2> err.log");
  unresolved("bun test 12>&1");
  unresolved("bun test &> out.log");
});

it("rejects substitution, heredocs and background execution", () => {
  unresolved("echo $(pwd)");
  unresolved("echo `pwd`");
  unresolved("cat <<EOF");
  unresolved("sleep 1 &");
});

it("rejects empty segments and more than eight segments", () => {
  unresolved("");
  unresolved("   ");
  unresolved("grep a f &&");
  unresolved("grep a f;;git diff");
  unresolved("grep a f\n");
  unresolved(Array.from({ length: 9 }, () => "grep a f").join(" && "));
  splits(Array.from({ length: 8 }, () => "grep a f").join(" && "),
    Array.from({ length: 8 }, () => "grep a f"));
});

it("folds one leading literal cd joined by &&, ; or a newline", () => {
  assert.deepEqual(splitShellSegmentsWithLeadingCd("cd /repo/sub && git status && git log -3"),
    { segments: ["git status", "git log -3"], leadingCd: "/repo/sub" });
  assert.deepEqual(splitShellSegmentsWithLeadingCd("cd /repo/sub; ls"),
    { segments: ["ls"], leadingCd: "/repo/sub" });
  assert.deepEqual(splitShellSegmentsWithLeadingCd("cd /repo/sub\nls"),
    { segments: ["ls"], leadingCd: "/repo/sub" });
  assert.deepEqual(splitShellSegmentsWithLeadingCd(`cd '/repo/my dir' && ls`),
    { segments: ["ls"], leadingCd: "/repo/my dir" });
  assert.deepEqual(splitShellSegmentsWithLeadingCd(`cd "/repo/my dir" && ls`),
    { segments: ["ls"], leadingCd: "/repo/my dir" });
  assert.deepEqual(splitShellSegmentsWithLeadingCd("cd .. && git status"),
    { segments: ["git status"], leadingCd: ".." });
});

it("never folds a non-literal, option, option-like, repeated or unjoined cd", () => {
  for (const command of [
    "cd $HOME && ls",
    "cd ~/repo && ls",
    "cd `pwd` && ls",
    "cd /repo/*.ts && ls",
    "cd - && ls",
    "cd --parent && ls",
    "cd && ls",
    "cd    && ls",
    "cd a b && ls",
    "cd a\\ b && ls",
    "cd '' && ls",
    "cd a || ls",
    "cd a | ls",
    "cd a && cd b && ls",
    "cd a; cd b",
    "cd a",
    "cd a &&",
    "cd a; export PATH=x",
    "ls && cd a",
  ]) unresolved(command);
});

it("folds a leading cd instead of returning it as a plain segment", () => {
  assert.deepEqual(splitShellSegmentsWithLeadingCd("cd /repo/sub && git status"),
    { segments: ["git status"], leadingCd: "/repo/sub" });
  assert.deepEqual(splitShellSegmentsWithLeadingCd("cd /repo/sub; ls"),
    { segments: ["ls"], leadingCd: "/repo/sub" });
  assert.deepEqual(splitShellSegmentsWithLeadingCd("grep a f"),
    { segments: ["grep a f"] });
  assert.deepEqual(splitShellSegmentsWithLeadingCd("grep a f; git diff"),
    { segments: ["grep a f", "git diff"] });
});

it("never splits an unterminated quote", () => {
  // The rest of the command stays one opaque segment, so a quoted separator is
  // never mistaken for a second command; a leading cd still fails closed.
  splits("grep 'a; rm -rf /", ["grep 'a; rm -rf /"]);
  splits(`grep "a && rm x`, [`grep "a && rm x`]);
  unresolved("cd 'a && rm x");
});

it("rejects parameter expansion that can hold unquoted operators", () => {
  for (const command of [
    "echo ${MISSING:-a;b}",
    "echo ${x:-a;b} && git status",
    "echo ${#x}",
    "echo ${x/;/}",
    "echo $[1;2]",
    `echo $"x"`,
  ]) unresolved(command);
});

it("rejects persistent builtins that change later segments", () => {
  for (const command of [
    "declare PATH=/tmp; git status",
    "declare -x FOO=bar && git status",
    "typeset -i n=1; git status",
    "readonly FOO=x; git status",
    "readonly PATH",
    "local x=1; git status",
    "function f { pwd; }",
  ]) unresolved(command);
});

it("rejects redirections that only resemble 2>&1", () => {
  for (const command of [
    "echo ok 2>&10",
    "echo ok 2>&1-",
    "echo ok 2>&1''",
    `echo ok 2>&1"x"`,
    "echo ok 2>&1x",
    "echo ok2>&1",
    "echo ok 32>&1",
    "2>&1'' cd /tmp; pwd",
    "2>&1x cd /tmp; pwd",
  ]) unresolved(command);
  splits("bun test 2>&1; git status", ["bun test 2>&1", "git status"]);
  splits("bun test 2>&1&&git status", ["bun test 2>&1", "git status"]);
});

it("rejects grouping and compound-command reserved words", () => {
  for (const command of [
    "{ cd /tmp; pwd; }",
    "{ git status; }",
    "(cd /tmp && pwd)",
    "( pwd )",
    "if true; then pwd; fi",
    "then pwd",
    "else pwd",
    "elif true; then pwd; fi",
    "for f in a b; do pwd; done",
    "while true; do pwd; done",
    "until false; do pwd; done",
    "case x in a) pwd;; esac",
    "select x in a b; do pwd; done",
    "! git status",
    "[[ -f x ]] && git status",
    "]] ; git status",
    "time git status",
    "do pwd",
    "done",
    "esac",
  ]) unresolved(command);
  splits("grep -n '{ cd; }' f", ["grep -n '{ cd; }' f"]);
  splits(`grep -n "( pwd )" f`, [`grep -n "( pwd )" f`]);
});

it("rejects unquoted comments that hide quoting from the scanner", () => {
  for (const command of [
    "echo FIRST # '\necho SECOND",
    "echo hi # trailing",
    "# just a comment",
    "git status # done && rm -rf /tmp/x",
    "echo a;#b",
    "echo a&&#b",
  ]) unresolved(command);
  splits("echo a#b", ["echo a#b"]);
  splits("grep -n '#x' f", ["grep -n '#x' f"]);
});

it("never folds a cd argument containing shell syntax", () => {
  for (const command of [
    "cd 2>&1 && pwd",
    "cd /repo/{a..a} && pwd",
    "cd /repo/*.ts && pwd",
    "cd a&b && pwd",
    "cd a<b && pwd",
    "cd a>b && pwd",
    "cd (x) && pwd",
  ]) unresolved(command);
  // Quoted versions are literal paths, not shell syntax.
  assert.deepEqual(splitShellSegmentsWithLeadingCd(`cd '/repo/{a..a}' && pwd`),
    { segments: ["pwd"], leadingCd: "/repo/{a..a}" });
  assert.deepEqual(splitShellSegmentsWithLeadingCd(`cd '2>&1' && pwd`),
    { segments: ["pwd"], leadingCd: "2>&1" });
});

it("rejects backslash-newline continuations", () => {
  unresolved("echo $\\\n(pwd)");
  unresolved("c\\\nd /tmp; pwd");
  unresolved("ls \\\n&& git status");
  unresolved("echo a\\\r\n; pwd");
});

it("trims only shell blanks and rejects ambiguous whitespace", () => {
  unresolved("printf '%s' name\\ ; pwd");
  unresolved("echo a\u00a0b; pwd");
  unresolved("cd /repo/sub\u00a0 && pwd");
  unresolved("git status; echo a\rb");
  splits("\techo hi\t", ["echo hi"]);
  splits("echo 'a '", ["echo 'a '"]);
});

