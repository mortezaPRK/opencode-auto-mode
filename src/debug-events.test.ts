import { describe, it } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createEventLog, createJsonlLog, registerGlobalCapture, serializeDebugValue } from "./debug-events.js";
import { DEFAULT_AUDIT_MAX_BYTES } from "./config.js";

describe("full original debug events", () => {
  it("preserves payloads and repeated non-circular objects without size or field limits", () => {
    const shared = { token: "TOY_SECRET", body: "x".repeat(30_000) };
    const event = { ts: "now", type: "tool.execute.before", payload: { input: shared, repeated: shared, args: Array.from({ length: 100 }, (_, index) => ({ index })) } };
    assert.deepEqual(JSON.parse(serializeDebugValue(event)), event);
  });
  it("captures full Error objects and explicit circular/unsupported serialization diagnostics", () => {
    const failure = new Error("toy failure", { cause: new Error("toy cause") });
    const circular: Record<string, unknown> = { retained: "original" };
    circular.self = circular;
    const result = JSON.parse(serializeDebugValue({ ts: "now", type: "error", payload: { failure, circular, big: 123n, undefinedValue: undefined } }));
    assert.equal(result.type, "error");
    assert.equal(result.payload.failure.message, "toy failure");
    assert.equal(result.payload.failure.cause.message, "toy cause");
    assert.equal(result.payload.failure.stack, failure.stack);
    assert.equal(result.payload.circular.retained, "original");
    assert.equal(result.payload.circular.self.serializationError, "circular reference");
    assert.equal(result.payload.big.value, "123");
    assert.ok(result.serializationError.some((issue: string) => issue.includes("circular reference")));
    assert.ok(result.serializationError.some((issue: string) => issue.includes("bigint")));
  });
  it("marks getter failures without dropping other fields or calling arbitrary toJSON", () => {
    const payload = { kept: "original", get failed() { throw new Error("toy getter error"); }, toJSON() { return "wrong"; } };
    const result = JSON.parse(serializeDebugValue({ ts: "now", type: "event", payload }));
    assert.equal(result.payload.kept, "original");
    assert.equal(result.payload.failed.serializationError, "toy getter error");
    assert.equal(result.payload.toJSON.serializationError, "function");
  });
  it("rotates into sequential retained files without overwriting earlier archives", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "events-"));
    try {
      const file = path.join(dir, "events.jsonl");
      fs.writeFileSync(`${file}.1`, "existing archive\n");
      const log = createEventLog({ path: file, maxBytes: 1 })!;
      for (const type of ["before", "after", "other"]) log.write({ ts: "now", type, payload: { secret: "TOY_SECRET" } });
      assert.equal(fs.readFileSync(`${file}.1`, "utf8"), "existing archive\n");
      assert.equal(JSON.parse(fs.readFileSync(`${file}.2`, "utf8")).type, "before");
      assert.equal(JSON.parse(fs.readFileSync(`${file}.3`, "utf8")).type, "after");
      assert.equal(JSON.parse(fs.readFileSync(file, "utf8")).type, "other");
      assert.equal(fs.statSync(`${file}.2`).mode & 0o077, 0);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
  it("supports unrotated capture and repairs permissive existing file modes", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "events-"));
    try {
      const file = path.join(dir, "events.jsonl");
      fs.writeFileSync(file, "", { mode: 0o666 });
      fs.chmodSync(file, 0o666);
      const log = createEventLog({ path: file, maxBytes: 0 })!;
      log.write({ ts: "now", type: "first", payload: "toy" });
      log.write({ ts: "now", type: "second", payload: "toy" });
      assert.equal(fs.readFileSync(file, "utf8").trim().split("\n").length, 2);
      assert.equal(fs.statSync(file).mode & 0o777, 0o600);
      assert.equal(fs.existsSync(`${file}.1`), false);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
  it("canonicalizes sink aliases before creation and releases only its own registry membership", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "events-owner-"));
    const release: (() => void)[] = [];
    try {
      fs.mkdirSync(path.join(dir, "real"));
      fs.symlinkSync(path.join(dir, "real"), path.join(dir, "alias"));
      const first = createEventLog({ path: path.join(dir, "real", "new", "audit.jsonl"), maxBytes: DEFAULT_AUDIT_MAX_BYTES })!;
      const second = createEventLog({ path: path.join(dir, "alias", "new", "audit.jsonl"), maxBytes: DEFAULT_AUDIT_MAX_BYTES })!;
      assert.equal(first.sinkPath, second.sinkPath);
      const claims: { signal: AbortSignal; isOwner: () => boolean; handoff: boolean }[] = [];
      const start = (signal: AbortSignal, isOwner: () => boolean, handoff: boolean) => { claims.push({ signal, isOwner, handoff }); };
      release.push(registerGlobalCapture(first.sinkPath, start));
      release.push(registerGlobalCapture(second.sinkPath, start));
      assert.equal(claims.length, 1); assert.equal(claims[0].isOwner(), true);
      release[0]();
      assert.equal(claims.length, 2); assert.equal(claims[0].isOwner(), false);
      assert.equal(claims[0].signal.aborted, true); assert.equal(claims[1].handoff, true);
      release[0](); assert.equal(claims[1].isOwner(), true);
      release[1](); assert.equal(claims[1].signal.aborted, true);
      assert.equal(Object.hasOwn(globalThis, Symbol.for("opencode-auto-mode.debug-capture.v2")), false);
      release.push(registerGlobalCapture(first.sinkPath, start));
      assert.equal(claims.length, 3); assert.equal(claims[2].handoff, false);
    } finally { for (const dispose of release) dispose(); fs.rmSync(dir, { recursive: true, force: true }); }
  });
  it("tries each failed member once, contains synchronous throws, and accepts a fresh owner", () => {
    const sink = `capture-failure-fixture-${crypto.randomUUID()}`;
    const release: (() => void)[] = [];
    let attempts = 0;
    let failOwner!: () => void;
    let freshSignal!: AbortSignal;
    try {
      release.push(registerGlobalCapture(sink, (_signal, _isOwner, _handoff, markFailure) => { attempts++; failOwner = markFailure; }));
      for (let i = 0; i < 3; i++) release.push(registerGlobalCapture(sink, () => { attempts++; throw new Error("SYNC_START_FAILURE"); }));
      assert.doesNotThrow(() => failOwner());
      assert.equal(attempts, 4);
      failOwner(); assert.equal(attempts, 4);
      release.push(registerGlobalCapture(sink, (signal, isOwner, handoff) => {
        attempts++; freshSignal = signal;
        assert.equal(isOwner(), true); assert.equal(handoff, true);
      }));
      assert.equal(attempts, 5);
      for (const dispose of release.slice(0, 4)) dispose();
      assert.equal(freshSignal.aborted, false);
    } finally { for (const dispose of release) dispose(); }
  });
  it("retires dead and active legacy owners without migrating three-argument callbacks", () => {
    const legacyKey = Symbol.for("opencode-auto-mode.debug-capture.v1");
    const shared = globalThis as typeof globalThis & { [legacyKey]?: Map<string, { members: Set<unknown>; owner?: unknown; controller?: AbortController }> };
    const sink = `capture-legacy-fixture-${crypto.randomUUID()}`;
    const controller = new AbortController();
    let aborts = 0;
    let legacyStarts = 0;
    const stale = { start: () => { legacyStarts++; } };
    const active = { members: new Set<unknown>([stale]), owner: stale as unknown, controller: controller as AbortController | undefined };
    const dead = { members: new Set<unknown>([stale]), owner: stale as unknown, controller: undefined as AbortController | undefined };
    const legacy = new Map([[sink, dead], [`${sink}-active`, active]]);
    shared[legacyKey] = legacy;
    controller.signal.addEventListener("abort", () => {
      aborts++;
      assert.equal(active.owner, undefined); assert.equal(active.controller, undefined);
      assert.equal(dead.owner, undefined); assert.equal(legacy.size, 0);
    });
    let release: (() => void) | undefined;
    try {
      release = registerGlobalCapture(sink, (signal, isOwner, handoff, markFailure) => {
        assert.equal(signal.aborted, false); assert.equal(isOwner(), true);
        assert.equal(handoff, true); assert.equal(typeof markFailure, "function");
      });
      assert.equal(aborts, 1); assert.equal(controller.signal.aborted, true);
      assert.equal(legacyStarts, 0); assert.equal(Object.hasOwn(shared, legacyKey), false);
      assert.equal(active.members.size, 0); assert.equal(dead.members.size, 0);
    } finally { release?.(); delete shared[legacyKey]; }
  });
  it("keeps the replacement controller when abort synchronously registers a new owner", () => {
    const sink = `capture-reentrant-fixture-${crypto.randomUUID()}`;
    const release: (() => void)[] = [];
    let replacementSignal!: AbortSignal;
    try {
      release.push(registerGlobalCapture(sink, (signal) => {
        signal.addEventListener("abort", () => {
          release.push(registerGlobalCapture(sink, (nextSignal, isOwner) => {
            replacementSignal = nextSignal; assert.equal(isOwner(), true);
          }));
        }, { once: true });
      }));
      release[0]();
      assert.equal(replacementSignal.aborted, false);
      release[1]();
      assert.equal(replacementSignal.aborted, true);
      assert.equal(Object.hasOwn(globalThis, Symbol.for("opencode-auto-mode.debug-capture.v2")), false);
    } finally { for (const dispose of release) dispose(); }
  });
  it("is opt-in, defaults rotation to 10 MiB, rejects invalid rotation options, and isolates I/O failures", () => {
    assert.equal(DEFAULT_AUDIT_MAX_BYTES, 10 * 1024 * 1024);
    assert.equal(createEventLog(undefined), undefined);
    assert.equal(createJsonlLog(undefined), undefined);
    assert.equal(createJsonlLog({ path: "unused", maxBytes: -1 }), undefined);
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "events-"));
    try {
      const file = path.join(dir, "blocker");
      fs.writeFileSync(file, "blocker");
      assert.doesNotThrow(() => createEventLog({ path: path.join(file, "invalid.jsonl"), maxBytes: 1024 })!.write({ ts: "now", type: "test", payload: {} }));
      const symlink = path.join(dir, "link");
      fs.symlinkSync(file, symlink);
      assert.doesNotThrow(() => createEventLog({ path: symlink, maxBytes: 0 })!.write({ ts: "now", type: "test", payload: {} }));
      assert.equal(fs.readFileSync(file, "utf8"), "blocker");
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});
