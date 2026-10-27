import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createTraceExporter, tracesUrl } from "./traces.js";
import { toLogRecord } from "./otlp.js";

const record = { ts: new Date(1000).toISOString(), reviewID: "review-test", sessionID: "session-test", action: "shell",
  resources: ["PRIVATE_RESOURCE"], hostEffect: "ask", decision: "allow", stage: "llm", reason: "PRIVATE_REASON", durationMs: 100 };

describe("review traces", () => {
  it("is opt-in and derives the trace endpoint", () => {
    assert.equal(createTraceExporter(undefined, {}), undefined);
    assert.equal(createTraceExporter(false, {}), undefined);
    assert.equal(createTraceExporter(true, {}), undefined);
    assert.equal(tracesUrl("http://collector:4318"), "http://collector:4318/v1/traces");
    assert.equal(tracesUrl("http://collector:4318/prefix/v1/logs"), "http://collector:4318/prefix/v1/traces");
    assert.throws(() => tracesUrl("file:///x"));
  });
  it("marks failed attempts as errors on the child span", () => {
    const original = globalThis.fetch;
    let payload = "";
    globalThis.fetch = (async (_url, init) => { payload = String(init?.body); return new Response(); }) as typeof fetch;
    try {
      const trace = createTraceExporter(true, { OPENCODE_OTLP_ENDPOINT: "http://collector:4318" })!.begin(1000);
      trace.attempts.push({ index: 0, type: "llm", startedAt: 1000, durationMs: 20,
        result: { decision: "abstain", reason: "reviewer unavailable", errorKind: "timeout" } });
      trace.finish({ ...record, error: true, errorKind: "timeout" });
      const spans = JSON.parse(payload).resourceSpans[0].scopeSpans[0].spans;
      const child = spans[1];
      assert.equal(child.status.code, 2);
      assert.equal(child.attributes.find((x: { key: string }) => x.key === "error.kind").value.stringValue, "timeout");
      assert.equal(spans[0].attributes.find((x: { key: string }) => x.key === "error.kind").value.stringValue, "timeout");
    } finally { globalThis.fetch = original; }
  });
  it("bounds root-span attributes with the shared record sanitizer", () => {
    const original = globalThis.fetch;
    let payload = "";
    globalThis.fetch = (async (_url, init) => { payload = String(init?.body); return new Response(); }) as typeof fetch;
    try {
      const trace = createTraceExporter(true, { OPENCODE_OTLP_ENDPOINT: "http://collector:4318" })!.begin(1000);
      trace.finish({ ...record, action: "a".repeat(500), agent: "b".repeat(500), stage: "c".repeat(500),
        errorKind: "ATTACKER_CONTROLLED" as never });
      const root = JSON.parse(payload).resourceSpans[0].scopeSpans[0].spans[0];
      const attributes = Object.fromEntries(root.attributes.map((entry: { key: string; value: { stringValue?: string } }) =>
        [entry.key, entry.value.stringValue]));
      assert.ok(attributes.action.length <= 128);
      assert.ok(attributes.agent.length <= 128);
      assert.ok(attributes.stage.length <= 64);
      assert.equal(attributes["error.kind"], "provider");
    } finally { globalThis.fetch = original; }
  });
  it("exports a root and fallback children with correlated log IDs", () => {
    const original = globalThis.fetch;
    let payload = "";
    globalThis.fetch = (async (_url, init) => { payload = String(init?.body); return new Response(); }) as typeof fetch;
    try {
      const trace = createTraceExporter(true, { OPENCODE_OTLP_ENDPOINT: "http://collector:4318" })!.begin(1000);
      trace.attempts.push({ index: 0, type: "decision", model: "laya/local", startedAt: 1000, durationMs: 20,
        result: { decision: "abstain", reason: "PRIVATE_PROVIDER_ERROR" } });
      trace.attempts.push({ index: 1, type: "llm", startedAt: 1020, durationMs: 80,
        result: { decision: "allow", reason: "PRIVATE_REASON" } });
      trace.finish(record);
      const spans = JSON.parse(payload).resourceSpans[0].scopeSpans[0].spans;
      assert.equal(spans.length, 3);
      assert.match(trace.traceID, /^[a-f0-9]{32}$/);
      assert.match(trace.spanID, /^[a-f0-9]{16}$/);
      assert.equal(spans[1].parentSpanId, trace.spanID);
      assert.equal(spans[2].traceId, trace.traceID);
      assert.equal(spans[1].attributes.find((x: { key: string }) => x.key === "decision").value.stringValue, "abstain");
      assert.doesNotMatch(payload, /PRIVATE_/);      const log = toLogRecord({ ...record, traceID: trace.traceID, spanID: trace.spanID });
      assert.equal(log.traceId, trace.traceID);
      assert.equal(log.spanId, trace.spanID);
    } finally { globalThis.fetch = original; }
  });
});
