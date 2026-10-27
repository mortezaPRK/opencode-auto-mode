import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { clearConfigError, readConfigError, recordConfigError } from "./state.js";

const first = `/tmp/auto-mode-config-a-${process.pid}`;
const second = `/tmp/auto-mode-config-b-${process.pid}`;

describe("config error badge state", () => {
  it("keeps per-location errors and clears only the matching location", () => {
    clearConfigError(first);
    clearConfigError(second);
    recordConfigError(first, "Invalid auto-mode configuration");
    recordConfigError(second, "Invalid auto-mode configuration");
    assert.equal(readConfigError(first)?.message, "Invalid auto-mode configuration");
    assert.equal(readConfigError(second)?.message, "Invalid auto-mode configuration");
    clearConfigError(first);
    assert.equal(readConfigError(first), undefined);
    assert.equal(readConfigError(second)?.message, "Invalid auto-mode configuration");
    clearConfigError(second);
    assert.equal(readConfigError(second), undefined);
    assert.equal(readConfigError(undefined), undefined);
  });
  it("does not overwrite another project's flag", () => {
    const directories = Array.from({ length: 5 }, (_, index) => `/tmp/auto-mode-config-${index}-${process.pid}`);
    for (const directory of directories) clearConfigError(directory);
    for (const directory of directories) recordConfigError(directory, `invalid ${directory}`);
    for (const directory of directories) assert.equal(readConfigError(directory)?.message, `invalid ${directory}`);
    for (const directory of directories) clearConfigError(directory);
  });
  it("replaces the same project's flag and bounds the stored message", () => {
    const directory = `/tmp/auto-mode-config-long-${process.pid}`;
    clearConfigError(directory);
    recordConfigError(directory, "first");
    recordConfigError(directory, "x".repeat(5000));
    assert.equal(readConfigError(directory)?.message.length, 1024);
    recordConfigError(directory, "latest");
    assert.equal(readConfigError(directory)?.message, "latest");
    clearConfigError(directory);
    assert.equal(readConfigError(directory), undefined);
  });
});
