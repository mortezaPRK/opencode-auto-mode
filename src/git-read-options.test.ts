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
    ["git", "diff"], ["git", "diff", "-p"], ["git", "diff", "--name-only", "--patch"],
    ["git", "log", "-p"], ["git", "log", "-c"], ["git", "log", "--cc"],
    ["git", "show"], ["git", "show", "HEAD"], ["git", "show", "--patch", "HEAD"],
    ["git", "show", "HEAD:file.txt", "HEAD"],
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
    ["git", "log", "-p", "--no-ext-diff"], ["git", "show", "HEAD", "--no-ext-diff"],
  ]) reviews(words);
  for (const words of [
    ["git", "diff", "--no-textconv", "--no-ext-diff"],
    ["git", "diff", "-p", "--no-ext-diff", "--no-textconv"],
    ["git", "log", "-p", "--no-textconv"], ["git", "log", "--no-textconv", "--patch"],
    ["git", "show", "HEAD", "--no-textconv"], ["git", "show", "--no-textconv", "--patch", "HEAD"],
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
    ["git", "show", "HEAD:file.txt", "--no-textconv"],
    ["git", "show", "--format=short", "HEAD:file.txt", "--no-textconv"],
    ["git", "show", "HEAD:file.txt", "--stat"],
    ["git", "show", "-p", "--no-textconv", "HEAD:file.txt"],
  ]) allows(words);
});

it("treats word-diff options as patch-producing", () => {
  for (const words of [
    ["git", "log", "--word-diff"], ["git", "log", "--word-diff=plain"],
    ["git", "log", "--color-words"], ["git", "log", "--word-diff-regex=."],
    ["git", "diff", "--stat", "--word-diff=plain"],
    ["git", "diff", "--stat", "--color-words"],
    ["git", "show", "--stat", "HEAD", "--word-diff"],
    ["git", "log", "--no-patch", "--word-diff"],
  ]) reviews(words);
  for (const words of [
    ["git", "log", "--word-diff", "--no-textconv"],
    ["git", "diff", "--stat", "--word-diff=plain", "--no-textconv", "--no-ext-diff"],
    ["git", "show", "--word-diff", "HEAD", "--no-textconv"],
    ["git", "log", "--word-diff", "--no-patch"],
  ]) allows(words);
});

it("treats function-context as patch-producing", () => {
  for (const words of [
    ["git", "log", "--function-context"], ["git", "log", "-W"],
    ["git", "log", "--no-patch", "-W"],
    ["git", "log", "--no-patch", "--function-context"],
    ["git", "diff", "--stat", "-W"],
    ["git", "diff", "--stat", "--function-context", "--no-ext-diff"],
    ["git", "show", "--stat", "-W", "HEAD"],
  ]) reviews(words);
  for (const words of [
    ["git", "log", "-W", "--no-patch"],
    ["git", "log", "-W", "--no-textconv"],
    ["git", "log", "--function-context", "--no-patch"],
    ["git", "diff", "--stat", "-W", "--no-textconv", "--no-ext-diff"],
    ["git", "show", "--function-context", "HEAD", "--no-textconv"],
  ]) allows(words);
});

it("reviews patch aliases and combined-diff shortcuts", () => {
  for (const words of [
    ["git", "log", "--stat", "--patch-with-stat"],
    ["git", "log", "--stat", "--patch-with-raw"],
    ["git", "log", "--stat", "-u"], ["git", "log", "--stat", "--unified=5"],
    ["git", "log", "--stat", "-U5"],
    ["git", "log", "--stat", "--diff-merges=first-parent"],
    ["git", "log", "--stat", "--remerge-diff"],
    ["git", "diff", "--stat", "--binary"],
  ]) reviews(words);
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
    ["git", "log", "-p", "--grep=fix", "--no-textconv"],
    ["git", "log", "-p", "--grep", "fix", "--no-textconv"],
    ["git", "diff", "--stat-width", "80", "--no-textconv", "--no-ext-diff", "-p"],
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
