import { it } from "node:test";
import assert from "node:assert/strict";
import { isReadOnlyInvocation } from "./shell-policy.js";
import { guardShell } from "./shell.js";

// Synthetic argv only: this file never executes git or a textconv driver.
function reviews(words: string[]): void {
  assert.equal(isReadOnlyInvocation(words), false, words.join(" "));
  // guardShell reports review as undefined, not a deny.
  assert.equal(guardShell([words.join(" ")]), undefined, words.join(" "));
}

function allows(words: string[]): void {
  assert.equal(isReadOnlyInvocation(words), true, words.join(" "));
  assert.equal(guardShell([words.join(" ")])?.decision, "allow", words.join(" "));
}

it("reviews patch-producing commands without explicit driver opt-outs", () => {
  for (const words of [
    ["git", "diff"], ["git", "diff", "-p"],
    ["git", "log", "-p"], ["git", "log", "-c"], ["git", "log", "--cc"],
    ["git", "show"], ["git", "show", "HEAD"], ["git", "show", "--patch", "HEAD"],
    ["git", "show", "HEAD:file.txt", "HEAD"],
    ["git", "log", "--diff-merges=first-parent"], ["git", "log", "--remerge-diff"],
    ["git", "log", "--dd"], ["git", "log", "--diff-merges=separate"],
  ]) reviews(words);
});

it("keeps guaranteed non-patch output read-only", () => {
  for (const words of [
    ["git", "diff", "--stat"], ["git", "diff", "--name-only"],
    ["git", "diff", "--name-status"], ["git", "diff", "--no-patch"], ["git", "diff", "-s"],
    ["git", "diff", "--patch", "--no-patch"], ["git", "diff", "--stat", "--no-patch"],
    ["git", "log"], ["git", "log", "--stat"], ["git", "log", "-s"],
    ["git", "log", "-p", "--no-patch"], ["git", "show", "--stat"],
    ["git", "show", "--stat", "HEAD"], ["git", "show", "--name-only", "HEAD"],
    ["git", "show", "--no-patch", "HEAD"], ["git", "show", "-s", "HEAD"],
    ["git", "show", "--patch", "--no-patch", "HEAD"],
  ]) allows(words);
});

it("requires both opt-outs for diff and only textconv for log and show patches", () => {
  for (const words of [
    ["git", "diff", "--no-textconv"], ["git", "diff", "--no-ext-diff"],
    ["git", "diff", "--no-textconv", "--no-ext-diff"],
    ["git", "log", "-p", "--no-ext-diff"],
    ["git", "log", "-p", "--no-textconv"],
    ["git", "show", "HEAD", "--no-ext-diff"],
    ["git", "show", "HEAD", "--no-textconv"],
  ]) reviews(words);
  for (const words of [
    ["git", "diff", "--no-textconv", "--no-ext-diff", "--submodule=short"],
    ["git", "diff", "-p", "--no-ext-diff", "--no-textconv", "--ignore-submodules=all"],
    ["git", "log", "-p", "--no-textconv", "--submodule=log"],
    ["git", "log", "--no-textconv", "--patch", "--submodule"],
    ["git", "show", "HEAD", "--no-textconv", "--submodule=short"],
    ["git", "show", "--no-textconv", "--patch", "HEAD", "--ignore-submodules"],
  ]) allows(words);
});

it("requires textconv opt-out for show revisions that may name blobs", () => {
  for (const words of [
    ["git", "show", "HEAD:file.txt"], ["git", "show", "HEAD:src/main.ts"],
    ["git", "show", "--format=short", "HEAD:file.txt"],
    ["git", "show", "HEAD:file.txt", "--"],
    ["git", "show", "HEAD:file.txt", "HEAD"],
    ["git", "show", "--", "HEAD:file.txt"],
    ["git", "show", "HEAD^{/fix:}"], ["git", "show", "HEAD@{12:00}"],
    ["git", "show", "HEAD:submodule"],
    ["git", "show", "-p", "HEAD:file.txt"],
  ]) reviews(words);
  for (const words of [
    ["git", "show", "HEAD:file.txt", "--no-textconv", "--submodule=short"],
    ["git", "show", "--format=short", "HEAD:file.txt", "--no-textconv", "--ignore-submodules=all"],
    ["git", "show", "HEAD:file.txt", "--stat"],
    ["git", "show", "-p", "--no-textconv", "--submodule=short", "HEAD:file.txt"],
  ]) allows(words);
});

it("does not let word-diff rendering options select patch output", () => {
  for (const words of [
    ["git", "log", "--word-diff"], ["git", "log", "--word-diff=plain"],
    ["git", "log", "--color-words"], ["git", "log", "--word-diff-regex=."],
    ["git", "log", "--stat", "--word-diff=plain"],
    ["git", "log", "--no-patch", "--word-diff"],
    ["git", "diff", "--stat", "--word-diff=plain"],
    ["git", "diff", "--stat", "--color-words"],
    ["git", "show", "--stat", "HEAD", "--word-diff"],
  ]) allows(words);
  for (const words of [
    ["git", "diff", "--word-diff"],
    ["git", "show", "--word-diff", "HEAD"],
    ["git", "diff", "--word-diff", "--no-textconv", "--no-ext-diff"],
    ["git", "show", "--word-diff", "HEAD", "--no-textconv"],
  ]) reviews(words);
  for (const words of [
    ["git", "diff", "--word-diff", "--no-textconv", "--no-ext-diff", "--submodule=short"],
    ["git", "show", "--word-diff", "HEAD", "--no-textconv", "--submodule=short"],
  ]) allows(words);
});

it("does not let function-context select patch output", () => {
  for (const words of [
    ["git", "log", "--function-context"], ["git", "log", "-W"],
    ["git", "log", "--no-patch", "-W"],
    ["git", "log", "--no-patch", "--function-context"],
    ["git", "log", "--stat", "-W"],
    ["git", "diff", "--stat", "-W"],
    ["git", "diff", "--stat", "--function-context", "--no-ext-diff"],
    ["git", "show", "--stat", "-W", "HEAD"],
  ]) allows(words);
  for (const words of [
    ["git", "diff", "-W"],
    ["git", "show", "-W", "HEAD"],
    ["git", "diff", "-W", "--no-textconv", "--no-ext-diff"],
    ["git", "show", "-W", "HEAD", "--no-textconv"],
  ]) reviews(words);
  for (const words of [
    ["git", "diff", "-W", "--no-textconv", "--no-ext-diff", "--submodule=short"],
    ["git", "show", "-W", "HEAD", "--no-textconv", "--submodule=short"],
  ]) allows(words);
});

it("reviews patch aliases and combined-diff shortcuts", () => {
  for (const words of [
    ["git", "log", "--stat", "--patch-with-stat"],
    ["git", "log", "--stat", "--patch-with-raw"],
    ["git", "log", "--stat", "-u"], ["git", "log", "--stat", "--unified=5"],
    ["git", "log", "--stat", "-U5"],
    ["git", "diff", "--stat", "--binary"],
  ]) reviews(words);
});

it("treats merge options as an implied patch only without a selected format", () => {
  for (const words of [
    ["git", "log", "--stat", "--diff-merges=first-parent"],
    ["git", "log", "--diff-merges=first-parent", "--stat"],
    ["git", "log", "--stat", "-c"], ["git", "log", "-c", "--stat"],
    ["git", "log", "--stat", "--cc"], ["git", "log", "--stat", "--dense-combined"],
    ["git", "log", "--stat", "--dd"], ["git", "log", "--stat", "--remerge-diff"],
    ["git", "log", "-m", "--stat"],
    ["git", "log", "-c", "-m"], ["git", "log", "--diff-merges=first-parent", "-m"],
    ["git", "log", "--remerge-diff", "-m"],
    ["git", "log", "--stat", "--diff-merges=off"],
    ["git", "log", "--stat", "--no-diff-merges"],
    ["git", "log", "--diff-merges=off"],
    ["git", "show", "--stat", "--remerge-diff", "HEAD"],
    ["git", "show", "--stat", "-c", "HEAD"],
    ["git", "log", "--diff-merges=first-parent", "--name-only"],
    ["git", "log", "--diff-merges=first-parent", "--raw"],
    ["git", "log", "--diff-merges=first-parent", "--no-patch"],
  ]) allows(words);
  for (const words of [
    ["git", "log", "--diff-merges=first-parent"],
    ["git", "log", "--diff-merges=separate"],
    ["git", "log", "--diff-merges=combined"],
    ["git", "log", "--diff-merges=dense-combined"],
    ["git", "log", "--diff-merges=remerge"],
    ["git", "log", "--diff-merges=m"],
    ["git", "log", "--remerge-diff"], ["git", "log", "--dd"],
    ["git", "log", "-c"], ["git", "log", "--cc"],
    ["git", "log", "-m", "-c"], ["git", "log", "-m", "--diff-merges=first-parent"],
    ["git", "log", "--diff-merges=first-parent", "-p"],
    ["git", "show", "--diff-merges=first-parent", "HEAD"],
  ]) reviews(words);
  for (const words of [
    ["git", "log", "--diff-merges=first-parent", "--no-textconv", "--submodule=short"],
  ]) allows(words);
});

it("lets exclusive formats override patch output in either order", () => {
  for (const words of [
    ["git", "diff", "--name-only", "--patch"],
    ["git", "diff", "--patch", "--name-only"],
    ["git", "diff", "--name-status", "--patch"],
    ["git", "diff", "--check", "--patch"],
    ["git", "diff", "--patch", "--check"],
    ["git", "diff", "--binary", "--name-only"],
    ["git", "diff", "--name-only", "--patch", "--no-textconv", "--no-ext-diff"],
    ["git", "log", "-p", "--name-only"], ["git", "log", "-p", "--name-status"],
    ["git", "log", "-p", "--check"],
    ["git", "show", "--patch", "--name-only", "HEAD"],
    ["git", "show", "--name-status", "--patch", "HEAD"],
    ["git", "show", "--check", "--patch", "HEAD"],
    ["git", "diff", "--name-only", "--submodule=diff", "--no-textconv", "--no-ext-diff"],
    ["git", "show", "--patch", "--name-only", "HEAD:file.txt"],
  ]) allows(words);
});

it("requires an explicit non-recursive submodule mode for patch output", () => {
  for (const words of [
    ["git", "diff", "--no-textconv", "--no-ext-diff"],
    ["git", "diff", "-p", "--no-textconv", "--no-ext-diff"],
    ["git", "log", "-p", "--no-textconv"],
    ["git", "show", "--no-textconv", "HEAD"],
    ["git", "log", "--diff-merges=first-parent", "--no-textconv"],
    ["git", "diff", "--submodule=diff", "--no-textconv", "--no-ext-diff"],
    ["git", "diff", "--submodule=short", "--submodule=diff", "--no-textconv", "--no-ext-diff"],
    ["git", "diff", "--ignore-submodules=dirty", "--no-textconv", "--no-ext-diff"],
    ["git", "diff", "--ignore-submodules=untracked", "--no-textconv", "--no-ext-diff"],
    ["git", "diff", "--ignore-submodules=all", "--ignore-submodules=none", "--no-textconv", "--no-ext-diff"],
    ["git", "diff", "--ignore-submodules=all", "--ignore-submodules=dirty", "--no-textconv", "--no-ext-diff"],
    ["git", "log", "-p", "--no-textconv", "--submodule=diff"],
    ["git", "show", "--no-textconv", "--submodule=diff", "HEAD"],
    ["git", "show", "--no-textconv", "--ignore-submodules=untracked", "HEAD"],
  ]) reviews(words);
  for (const words of [
    ["git", "diff", "--submodule=short", "--no-textconv", "--no-ext-diff"],
    ["git", "diff", "--submodule=log", "--no-textconv", "--no-ext-diff"],
    ["git", "diff", "--submodule", "--no-textconv", "--no-ext-diff"],
    ["git", "diff", "--ignore-submodules=all", "--no-textconv", "--no-ext-diff"],
    ["git", "diff", "--ignore-submodules", "--no-textconv", "--no-ext-diff"],
    ["git", "diff", "--submodule=diff", "--submodule=short", "--no-textconv", "--no-ext-diff"],
    ["git", "diff", "--ignore-submodules=all", "--submodule=diff", "--no-textconv", "--no-ext-diff"],
    ["git", "diff", "--submodule=diff", "--ignore-submodules=all", "--no-textconv", "--no-ext-diff"],
    ["git", "log", "-p", "--no-textconv", "--submodule=short"],
    ["git", "log", "-p", "--no-textconv", "--submodule=log"],
    ["git", "log", "-p", "--no-textconv", "--submodule"],
    ["git", "log", "-p", "--no-textconv", "--ignore-submodules=all"],
    ["git", "show", "--no-textconv", "--submodule=short", "HEAD"],
    ["git", "show", "--no-textconv", "--ignore-submodules", "HEAD"],
    ["git", "diff", "--stat", "--submodule=diff", "--no-textconv", "--no-ext-diff"],
    ["git", "diff", "--name-only", "--submodule=diff", "--no-textconv", "--no-ext-diff"],
    ["git", "diff", "--check", "--submodule=diff", "--no-textconv", "--no-ext-diff"],
    ["git", "log", "--diff-merges=first-parent", "--no-textconv", "--submodule=short"],
  ]) allows(words);
});

it("keeps patch-formatting-only options inert without patch output", () => {
  for (const words of [
    ["git", "log", "--stat", "--inter-hunk-context=3"],
    ["git", "log", "--stat", "--minimal"], ["git", "log", "--stat", "--patience"],
    ["git", "log", "--stat", "--histogram"], ["git", "log", "--stat", "--anchored=fix"],
    ["git", "log", "--stat", "--diff-algorithm=histogram"],
    ["git", "log", "--stat", "--combined-all-paths"],
    ["git", "log", "--stat", "-m"], ["git", "log", "--stat", "--full-index"],
    ["git", "diff", "--stat", "--inter-hunk-context=3"],
    ["git", "diff", "--stat", "--minimal", "--full-index"],
  ]) allows(words);
});

it("reviews pickaxe filters that can run textconv without patch output", () => {
  for (const words of [
    ["git", "log", "-Sneedle"], ["git", "log", "-Gneedle"], ["git", "log", "-S", "needle"],
    ["git", "log", "--pickaxe-all"], ["git", "log", "--pickaxe-regex"],
    ["git", "diff", "--name-only", "-Gneedle"],
    ["git", "diff", "--stat", "-Sneedle"],
    ["git", "diff", "--name-only", "--pickaxe-all"],
    ["git", "diff", "--name-only", "-Gneedle", "--no-textconv"],
  ]) reviews(words);
  for (const words of [
    ["git", "log", "-Sneedle", "--no-textconv"],
    ["git", "log", "-Gneedle", "--no-textconv"],
    ["git", "diff", "--name-only", "-Gneedle", "--no-textconv", "--no-ext-diff"],
  ]) allows(words);
});

it("requires textconv opt-out for quiet and exit-status probes", () => {
  for (const words of [
    ["git", "log", "-p", "--quiet"], ["git", "log", "--quiet"],
    ["git", "log", "--no-patch", "--exit-code"],
    ["git", "show", "--quiet", "HEAD"],
    ["git", "show", "--no-patch", "--exit-code"],
    ["git", "show", "--stat", "--quiet", "HEAD"],
  ]) reviews(words);
  for (const words of [
    ["git", "log", "-p", "--quiet", "--no-textconv"],
    ["git", "log", "--no-patch", "--exit-code", "--no-textconv"],
    ["git", "show", "--quiet", "HEAD", "--no-textconv"],
    ["git", "show", "--no-patch", "--exit-code", "--no-textconv"],
  ]) allows(words);
});

it("applies last-option semantics to patch suppression", () => {
  for (const words of [
    ["git", "diff", "--patch", "--no-patch"],
    ["git", "diff", "--stat", "--no-patch"],
    ["git", "diff", "--patch", "--no-patch", "--stat"],
    ["git", "log", "-p", "--no-patch"],
    ["git", "show", "--patch", "--no-patch", "HEAD"],
  ]) allows(words);
  for (const words of [
    ["git", "diff", "--no-patch", "--patch"],
    ["git", "diff", "--stat", "--no-patch", "--patch"],
    ["git", "log", "--no-patch", "-p"],
    ["git", "show", "--no-patch", "--patch", "HEAD"],
  ]) reviews(words);
});

it("reviews exit-status probes that can still run diff helpers", () => {
  for (const words of [
    ["git", "diff", "--quiet"],
    ["git", "diff", "--no-patch", "--exit-code"],
    ["git", "diff", "--no-patch", "--name-only", "--exit-code"],
    ["git", "diff", "--quiet", "--stat"],
  ]) reviews(words);
  for (const words of [
    ["git", "diff", "--no-patch", "--exit-code", "--no-textconv", "--no-ext-diff"],
    ["git", "diff", "--stat", "--exit-code"],
    ["git", "diff", "--no-patch", "--stat", "--exit-code"],
    ["git", "diff", "--no-patch", "--raw", "--exit-code"],
    ["git", "diff", "--quiet", "--no-textconv", "--no-ext-diff"],
  ]) allows(words);
});

it("does not accept an option value as a driver opt-out", () => {
  for (const words of [
    ["git", "log", "--grep", "--no-textconv", "-p"],
    ["git", "log", "-p", "--grep", "--no-textconv"],
    ["git", "diff", "--stat-width", "--no-textconv", "--no-ext-diff", "-p"],
  ]) reviews(words);
  for (const words of [
    ["git", "log", "-p", "--grep=fix", "--no-textconv", "--submodule=short"],
    ["git", "log", "-p", "--grep", "fix", "--no-textconv", "--submodule=short"],
    ["git", "diff", "--stat-width", "80", "--no-textconv", "--no-ext-diff", "-p", "--submodule=short"],
  ]) allows(words);
});

it("routes explicit textconv and ext-diff to review for show, log and diff", () => {
  for (const subcommand of ["show", "log", "diff"]) {
    for (const option of ["--textconv", "--ext-diff"]) reviews(["git", subcommand, option]);
  }
});

it("keeps config, exec-path and directory overrides out of read-only classification", () => {
  for (const words of [
    ["git", "-c", "diff.helper.textconv=cat", "diff"],
    ["git", "--config-env=diff.helper.textconv=ENV", "show"],
    ["git", "--exec-path=/tmp/hooks", "log"],
    ["git", "-C", "/tmp", "diff", "--no-textconv", "--no-ext-diff"],
    ["git", "-C", "/tmp", "status"],
    ["git", "--git-dir=/tmp/repo", "show"],
    ["git", "--work-tree=/tmp", "diff"],
    ["git", "diff", "--output=/tmp/out", "--no-textconv", "--no-ext-diff"],
  ]) assert.equal(isReadOnlyInvocation(words), false, words.join(" "));
});

it("keeps ordinary history and status commands at their existing classification", () => {
  for (const words of [
    ["git", "status"], ["git", "status", "--short"], ["git", "rev-parse", "HEAD"],
    ["git", "branch", "--show-current"], ["git", "log", "--oneline", "--stat"],
    ["git", "log", "--grep=fix", "--format=short"], ["git", "show", "--stat", "HEAD"],
    ["git", "show", "--name-only", "HEAD"],
  ]) allows(words);
});
