import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createOtlpExporter, logsUrl, toLogRecord } from "./otlp.js";
import { parseOptions } from "./config.js";

const record = { ts: "2026-10-23T10:00:00.000Z", reviewID: "r", sessionID: "s", agent: "build", action: "shell", resources: ["ls"], hostEffect: "ask", decision: "deny", stage: "static", reason: "no", durationMs: 4 };

describe("OTLP exporter", () => {
  it("is off unless configured and has an endpoint", () => {
    assert.equal(createOtlpExporter(undefined, {}), undefined);
    assert.equal(createOtlpExporter(false, { OPENCODE_OTLP_ENDPOINT: "http://x" }), undefined);
    assert.equal(createOtlpExporter(true, {}), undefined);
  });
  it("derives the logs URL and rejects credentials or other schemes", () => {
    assert.equal(logsUrl("http://c:4318"), "http://c:4318/v1/logs");
    assert.equal(logsUrl("http://c:4318/prefix/"), "http://c:4318/prefix/v1/logs");
    assert.throws(() => logsUrl("http://u:p@c"));
    assert.throws(() => logsUrl("file:///x"));
  });
  it("posts a log record with env-derived headers", async () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const original = globalThis.fetch;
    globalThis.fetch = (async (url: string, init: RequestInit) => { calls.push({ url, init }); return new Response(); }) as typeof fetch;
    try {
      createOtlpExporter(true, { OPENCODE_OTLP_ENDPOINT: "http://c:4318", OPENCODE_OTLP_HEADERS: "authorization=Bearer t" })!.write(record);
    } finally { globalThis.fetch = original; }
    assert.equal(calls[0].url, "http://c:4318/v1/logs");
    assert.equal((calls[0].init.headers as Record<string, string>).authorization, "Bearer t");
    const body = JSON.parse(calls[0].init.body as string);
    assert.equal(body.resourceLogs[0].scopeLogs[0].logRecords[0].severityText, "WARN");
  });
  it("never throws when the collector is unreachable", async () => {
    const original = globalThis.fetch;
    globalThis.fetch = (async () => { throw new Error("down"); }) as typeof fetch;
    try { createOtlpExporter({ endpoint: "http://c" }, {})!.write(record); await new Promise((r) => setTimeout(r, 5)); }
    finally { globalThis.fetch = original; }
  });
  it("maps fields to attributes", () => {
    const attrs = toLogRecord(record).attributes;
    assert.deepEqual(attrs.find((a) => a.key === "stage")?.value, { stringValue: "static" });
  });
  it("validates options", () => {
    assert.doesNotThrow(() => parseOptions({ otlp: { endpoint: "http://c:4318", headers: { authorization: "x" }, timeoutMs: 500 }, auditLog: "/tmp/a.jsonl" }));
    assert.throws(() => parseOptions({ otlp: { endpoint: "ftp://c" } }));
    assert.throws(() => parseOptions({ otlp: { bogus: 1 } }));
  });
});
