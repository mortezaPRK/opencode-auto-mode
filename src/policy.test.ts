import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { defaultPolicy } from "./policy.js";

describe("defaultPolicy", () => {
  it("ships conservative defaults", () => {
    const policy = defaultPolicy();
    assert.ok(policy.trusted.length > 0);
    assert.ok(policy.blocks.length > 0);
    assert.ok(policy.exceptions.length > 0);
    assert.match(policy.blocks.join("\n"), /exfiltrat/i);
  });

  it("prefers caller overrides", () => {
    const policy = defaultPolicy({
      trusted: ["my org"],
      blocks: ["no deploys on fridays"],
      exceptions: [],
    });
    assert.deepEqual(policy.trusted, ["my org"]);
    assert.deepEqual(policy.blocks, ["no deploys on fridays"]);
    assert.deepEqual(policy.exceptions, []);
  });
  it("defaults omitted lists independently and copies arrays", () => {
    const overrides = { blocks: [] as string[] };
    const policy = defaultPolicy(overrides);
    assert.deepEqual(policy.blocks, []);
    assert.ok(policy.trusted.length > 0);
    assert.ok(policy.exceptions.length > 0);
    const blocks: string[] = policy.blocks;
    blocks.push("local change");
    assert.deepEqual(overrides.blocks, []);
    assert.notDeepEqual(defaultPolicy().blocks, policy.blocks);
  });
});
