import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parseOptions, DEFAULT_REVIEW_TIMEOUT_MS, DEFAULT_AUDIT_MAX_BYTES } from "./config.js";

const model = "test-provider/test-model";
const staticOnly = { classifiers: [{ type: "static" as const }] };
const errorOf = (value: unknown): string => {
  try { parseOptions(value); }
  catch (error) { return error instanceof Error ? error.message : String(error); }
  assert.fail("expected parseOptions to throw");
};

describe("auto-mode options", () => {
  it("requires a non-empty classifier pipeline", () => {
    for (const value of [{}, { classifiers: [] }, { classifiers: undefined }, { classifiers: null },
      { classifiers: {} }, { classifiers: "static" }])
      assert.throws(() => parseOptions(value), /Invalid auto-mode classifiers/);
    assert.deepEqual(parseOptions(staticOnly).classifiers, [{ type: "static" }]);
  });
  it("normalizes the exact public option set and defaults", () => {
    assert.deepEqual(parseOptions(staticOnly), {
      classifiers: [{ type: "static" }],
      allowInProjectEdits: true,
      tui: true,
      reviewTimeoutMs: DEFAULT_REVIEW_TIMEOUT_MS,
      breaker: { consecutiveDenies: 3, windowDenies: 10, windowSize: 50 },
      audit: { enabled: false, maxBytes: DEFAULT_AUDIT_MAX_BYTES },
    });
    assert.equal(DEFAULT_REVIEW_TIMEOUT_MS, 15_000);
    assert.equal(DEFAULT_AUDIT_MAX_BYTES, 10_485_760);
  });
  it("rejects more than one static stage", () => {
    for (const classifiers of [
      [{ type: "static" }, { type: "static" }],
      [{ type: "static", allowInProjectEdits: false }, { type: "decision", model }, { type: "static", allowInProjectEdits: true }],
    ]) assert.throws(() => parseOptions({ classifiers }), /Invalid auto-mode classifiers/);
  });
  it("derives allowInProjectEdits from the single static stage", () => {
    assert.equal(parseOptions({ classifiers: [{ type: "decision", model }] }).allowInProjectEdits, false);
    assert.equal(parseOptions({ classifiers: [{ type: "llm", model }] }).allowInProjectEdits, false);
    assert.equal(parseOptions({ classifiers: [{ type: "static", allowInProjectEdits: false }] }).allowInProjectEdits, false);
    assert.equal(parseOptions({ classifiers: [{ type: "static", allowInProjectEdits: true }] }).allowInProjectEdits, true);
    assert.equal(parseOptions({ classifiers: [{ type: "decision", model }, { type: "static" }] }).allowInProjectEdits, true);
  });
  it("preserves order, duplicate non-static stages and explicit thresholds", () => {
    const classifiers = [
      { type: "decision", model, timeoutMs: 500, minConfidence: 0.8 },
      { type: "static", allowInProjectEdits: false },
      { type: "decision", model },
      { type: "decision", model },
      { type: "llm", model, timeoutMs: 120_000 },
    ];
    assert.deepEqual(parseOptions({ classifiers }).classifiers, classifiers);
  });
  it("rejects malformed classifiers and stages", () => {
    for (const stage of [null, {}, { type: "other" }, { type: "static", model },
      { type: "static", allowInProjectEdits: "yes" }, { type: "static", extra: true },
      { type: "llm" }, { type: "decision" }, { type: "llm", model: "" }, { type: "llm", model: 42 },
      { type: "llm", model: "not-a-model" }, { type: "llm", model, minConfidence: 0.9 },
      { type: "decision", model, endpoint: "http://example.invalid" }, { type: "decision", model, timeoutMs: 0 },
      { type: "decision", model, timeoutMs: 120_001 }, { type: "decision", model, timeoutMs: 1.5 },
      { type: "llm", model, timeoutMs: 120_001 }, { type: "decision", model, minConfidence: NaN },
      { type: "decision", model, minConfidence: -0.1 }, { type: "decision", model, minConfidence: 1.1 },
      { type: "decision", model, minConfidence: "0.9" }])
      assert.throws(() => parseOptions({ classifiers: [stage] }));
    assert.throws(() => parseOptions({ classifiers: Array.from({ length: 65 }, () => ({ type: "decision", model })) }));
    assert.equal(parseOptions({ classifiers: Array.from({ length: 64 }, () => ({ type: "decision", model })) }).classifiers.length, 64);
  });
  it("accepts classifier timeout and confidence boundaries", () => {
    for (const timeoutMs of [1, 120_000])
      assert.equal(parseOptions({ classifiers: [{ type: "decision", model, timeoutMs }] }).classifiers.length, 1);
    for (const minConfidence of [0, 0.5, 1])
      assert.equal(parseOptions({ classifiers: [{ type: "decision", model, minConfidence }] }).classifiers.length, 1);
    assert.equal(parseOptions({ classifiers: [{ type: "llm", model, timeoutMs: 1 }] }).classifiers.length, 1);
  });
  it("validates reviewTimeoutMs in the inclusive 1..120000 range", () => {
    for (const reviewTimeoutMs of [1, 120_000])
      assert.equal(parseOptions({ ...staticOnly, reviewTimeoutMs }).reviewTimeoutMs, reviewTimeoutMs);
    for (const reviewTimeoutMs of [0, -1, 120_001, 1.5, NaN, Infinity, "1000"])
      assert.throws(() => parseOptions({ ...staticOnly, reviewTimeoutMs }), /Invalid auto-mode reviewTimeoutMs/);
  });
  it("parses tui strictly", () => {
    assert.equal(parseOptions({ ...staticOnly, tui: false }).tui, false);
    assert.equal(parseOptions({ ...staticOnly, tui: true }).tui, true);
    for (const tui of ["true", 1, null, {}]) assert.throws(() => parseOptions({ ...staticOnly, tui }), /Invalid auto-mode tui/);
  });
  it("validates breaker thresholds and requires all three fields", () => {
    const breaker = { consecutiveDenies: 1, windowDenies: 1, windowSize: 1 };
    assert.deepEqual(parseOptions({ ...staticOnly, breaker }).breaker, breaker);
    const upper = { consecutiveDenies: 10_000, windowDenies: 10_000, windowSize: 10_000 };
    assert.deepEqual(parseOptions({ ...staticOnly, breaker: upper }).breaker, upper);
    for (const value of [
      { consecutiveDenies: 0, windowDenies: 1, windowSize: 1 },
      { consecutiveDenies: 10_001, windowDenies: 1, windowSize: 1 },
      { consecutiveDenies: 1, windowDenies: 0, windowSize: 1 },
      { consecutiveDenies: 1, windowDenies: 1, windowSize: 0 },
      { consecutiveDenies: 1, windowDenies: 1, windowSize: 10_001 },
      { consecutiveDenies: 1, windowDenies: 1 },
      { consecutiveDenies: 1 },
      {},
      { consecutiveDenies: 1, windowDenies: 3, windowSize: 2 },
      { consecutiveDenies: 1.5, windowDenies: 1, windowSize: 1 },
      null,
      true,
    ]) assert.throws(() => parseOptions({ ...staticOnly, breaker: value }), /Invalid auto-mode/);
    assert.throws(() => parseOptions({ ...staticOnly, breaker: { consecutiveDenies: 1, windowDenies: 1, windowSize: 2, extra: 1 } }),
      /^Error: Unknown auto-mode option 'extra'$/);
  });
  it("accepts only the audit object and normalizes its defaults", () => {
    assert.deepEqual(parseOptions({ ...staticOnly, audit: {} }).audit, { enabled: false, maxBytes: DEFAULT_AUDIT_MAX_BYTES });
    assert.deepEqual(parseOptions({ ...staticOnly, audit: { enabled: true } }).audit, { enabled: true, maxBytes: DEFAULT_AUDIT_MAX_BYTES });
    assert.deepEqual(parseOptions({ ...staticOnly, audit: { maxBytes: 0 } }).audit, { enabled: false, maxBytes: 0 });
    assert.deepEqual(parseOptions({ ...staticOnly, audit: { enabled: false, maxBytes: 1024 } }).audit, { enabled: false, maxBytes: 1024 });
    assert.deepEqual(parseOptions({ ...staticOnly, audit: { maxBytes: Number.MAX_SAFE_INTEGER } }).audit,
      { enabled: false, maxBytes: Number.MAX_SAFE_INTEGER });
    for (const audit of [true, false, "", "audit.jsonl", null, [], 1,
      { enabled: "true" }, { enabled: 1 }, ...[-1, 1.5, Infinity, NaN, Number.MAX_SAFE_INTEGER + 1, "1024"]
        .map((maxBytes) => ({ maxBytes }))])
      assert.throws(() => parseOptions({ ...staticOnly, audit }), /Invalid auto-mode audit/);
    for (const audit of [{ path: "/audit/debug.jsonl" }, { path: "/audit/debug.jsonl", maxBytes: 1024 }, { extra: true }])
      assert.throws(() => parseOptions({ ...staticOnly, audit }), /^Error: Unknown auto-mode option '/);
  });
  it("rejects removed top-level options with plain errors", () => {
    for (const key of ["enabled", "reviewNativeAllows", "shadow", "auditLog", "otlp",
      "performanceTelemetry", "fetchHosts", "rulesPath"]) {
      const message = errorOf({ ...staticOnly, [key]: 1 });
      assert.equal(message, `Unknown auto-mode option '${key}'`);
      assert.doesNotMatch(message, /README|migrat/i);
    }
    assert.equal(errorOf({ ...staticOnly, unsafe: true }), "Unknown auto-mode option 'unsafe'");
  });
  it("keeps exact validation error strings after helper extraction", () => {
    assert.equal(errorOf({ classifiers: [null] }), "Invalid auto-mode classifier");
    assert.equal(errorOf({ classifiers: [{}] }), "Invalid auto-mode classifier type");
    assert.equal(errorOf({ classifiers: [{ type: "llm" }] }), "Invalid auto-mode classifier model");
    assert.equal(errorOf({ classifiers: [{ type: "llm", model, timeoutMs: 0 }] }), "Invalid auto-mode classifier timeoutMs");
    assert.equal(errorOf({ classifiers: [{ type: "decision", model, minConfidence: 2 }] }), "Invalid auto-mode decision minConfidence");
    assert.equal(errorOf({ classifiers: [{ type: "static", allowInProjectEdits: "yes" }] }), "Invalid auto-mode static allowInProjectEdits");
    assert.equal(errorOf({ ...staticOnly, breaker: null }), "Invalid auto-mode breaker");
    assert.equal(errorOf({ ...staticOnly, breaker: { consecutiveDenies: 0, windowDenies: 1, windowSize: 1 } }), "Invalid auto-mode breaker thresholds");
    assert.equal(errorOf({ ...staticOnly, audit: true }), "Invalid auto-mode audit");
    assert.equal(errorOf({ ...staticOnly, audit: { enabled: 1 } }), "Invalid auto-mode audit enabled");
    assert.equal(errorOf({ ...staticOnly, audit: { maxBytes: -1 } }), "Invalid auto-mode audit maxBytes");
  });
  it("rejects non-object options", () => {
    for (const value of [undefined, null, [], "options", 1, true])
      assert.throws(() => parseOptions(value), /Invalid auto-mode options/);
  });
  it("accepts the full supported option set", () => {
    const options = parseOptions({
      classifiers: [{ type: "decision", model, timeoutMs: 3_000, minConfidence: 0.9 }, { type: "llm", model }, { type: "static" }],
      reviewTimeoutMs: 60_000,
      breaker: { consecutiveDenies: 5, windowDenies: 20, windowSize: 100 },
      tui: false,
      audit: { enabled: true, maxBytes: 2048 },
    });
    assert.equal(options.reviewTimeoutMs, 60_000);
    assert.deepEqual(options.breaker, { consecutiveDenies: 5, windowDenies: 20, windowSize: 100 });
    assert.equal(options.tui, false);
    assert.deepEqual(options.audit, { enabled: true, maxBytes: 2048 });
    assert.equal(options.allowInProjectEdits, true);
  });
});
