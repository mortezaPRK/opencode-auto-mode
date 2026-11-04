import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { AutoMode } from "./rpc.js";

describe("minimal status RPC", () => {
  it("exposes status and a deliberate mode mutation only", () => {
    assert.deepEqual(Object.keys(AutoMode.methods), ["status", "setMode"]);
    assert.deepEqual(Object.keys(AutoMode.methods.status.input.properties), ["sessionID"]);
    assert.deepEqual(AutoMode.methods.status.input.properties.sessionID, { type: "string", minLength: 1, maxLength: 256 });
    assert.equal(AutoMode.methods.status.input.additionalProperties, false);
  });
  it("requires a bounded session and explicit on/off/resume, not implicit toggle", () => {
    const { input, output } = AutoMode.methods.setMode;
    assert.deepEqual(Object.keys(input.properties), ["sessionID", "mode"]);
    assert.deepEqual(input.required, ["sessionID", "mode"]);
    assert.equal(input.additionalProperties, false);
    assert.deepEqual(input.properties.sessionID, { type: "string", minLength: 1, maxLength: 256 });
    assert.deepEqual(input.properties.mode, { type: "string", enum: ["on", "off", "resume"] });
    assert.deepEqual(output, AutoMode.methods.status.output);
  });
  it("requires mode and counts, without reviewer configuration or history", () => {
    const schema = AutoMode.methods.status.output;
    assert.deepEqual(schema.required, ["enabled", "mode", "reviewTimeoutMs", "reviewing", "counts"]);
    assert.deepEqual(schema.properties.mode.enum, ["on", "off", "paused", "invalid"]);
    assert.deepEqual(schema.properties.errorKind.enum, ["config", "storage", "status"]);
    assert.equal("recent" in schema.properties, false);
    assert.equal("classifiers" in schema.properties, false);
    assert.equal("shadow" in schema.properties, false);
    assert.equal(schema.additionalProperties, false);
    assert.equal(schema.properties.reviewing.maxItems, 256);
  });
  it("keeps live decision text bounded and free of rule or shadow fields", () => {
    const fields = AutoMode.events.decision.schema.properties;
    assert.equal(fields.action.maxLength, 128);
    assert.equal(fields.reason.maxLength, 200);
    assert.equal(fields.stage.maxLength, 64);
    assert.equal(fields.errorKind.maxLength, 64);
    assert.equal("ruleID" in fields, false);
    assert.equal("shadow" in fields, false);
  });
});
