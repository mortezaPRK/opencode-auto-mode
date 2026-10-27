import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import plugin from "./index.js";

interface Evaluation {
  sessionID: string; agent?: string; action: string; resources: string[];
  effect: "ask" | "allow" | "deny"; message?: string; metadata?: Record<string, unknown>; source?: unknown;
}

async function setup(options: unknown = {}, messages: unknown[] = [{ type: "user", text: "Create a file named a" }], answers = ["BLOCK", "ALLOW: authorized"]) {
  let evaluate!: (event: Evaluation) => Promise<void>;
  let disposed = 0;
  const prompts: string[] = [];
  const models: ({ id: string; providerID: string; variant?: string } | null | undefined)[] = [];
  const interrupts: { data: { sessionID: string } }[] = [];
  const subscriptionSignals: AbortSignal[] = [];
  let wake: (() => void) | undefined;
  let rpcHandlers: Record<string, (input: unknown) => Promise<unknown>> = {};
  const rpcEvents: unknown[] = [];
  async function* subscribe(input: { signal?: AbortSignal }) {
    if (input.signal !== undefined) subscriptionSignals.push(input.signal);
    while (!input.signal?.aborted) {
      if (!interrupts.length) {
        await new Promise<void>((resolve) => {
          wake = resolve;
          input.signal?.addEventListener("abort", () => resolve(), { once: true });
        });
        continue;
      }
      const next = interrupts.shift();
      if (next !== undefined) yield next;
    }
  }
  const ctx = {
    options,
    permission: { hook: async (_: string, handler: typeof evaluate) => { evaluate = handler; return { dispose: async () => { disposed++; } }; } },
    tool: { hook: async () => ({ dispose: async () => { disposed++; } }) },
    session: { get: async () => ({ location: { directory: "/repo" }, model: { providerID: "session-provider", id: "session-model", variant: "high" } }), context: async () => messages },
    event: { subscribe },
    rpc: {
      register: async (_definition: unknown, handlers: typeof rpcHandlers) => {
        rpcHandlers = handlers;
        return { events: { emit: async (_name: string, payload: unknown) => { rpcEvents.push(payload); } }, dispose: async () => { disposed++; } };
      },
    },
    generate: { text: async ({ prompt, model }: { prompt: string; model?: { id: string; providerID: string; variant?: string } | null }) => { prompts.push(prompt); models.push(model); return { text: answers.shift() ?? "ASK: unclear" }; } },
  };
  const cleanup = await plugin.setup(ctx as unknown as Parameters<typeof plugin.setup>[0]);
  return {
    evaluate: (evaluation: Evaluation) => evaluate(evaluation),
    prompts, models, ctx, disposed: () => disposed, subscriptionSignals, rpcEvents,
    status: async (input: unknown = {}) => rpcHandlers.status!(input),
    interrupt: (sessionID = "session-test") => { interrupts.push({ data: { sessionID } }); wake?.(); },
    cleanup: async () => { await cleanup?.(); },
  };
}
function event(effect: Evaluation["effect"] = "ask"): Evaluation {
  return { sessionID: "session-test", agent: "build", action: "shell", resources: ["touch a"], effect };
}
const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
async function waitFor(predicate: () => boolean, timeoutMs = 1_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("timed out waiting for test condition");
    await delay(5);
  }
}
function lastRecord(file: string): Record<string, unknown> {
  return JSON.parse(readFileSync(file, "utf8").trim().split("\n").at(-1)!);
}

interface ExportedSpan {
  status: { code: number };
  attributes: { key: string; value: { stringValue?: string } }[];
}
function exportedSpans(body: string): ExportedSpan[] {
  return JSON.parse(body).resourceSpans[0].scopeSpans[0].spans;
}
function spanValue(span: ExportedSpan, key: string): string | undefined {
  return span.attributes.find((entry) => entry.key === key)?.value.stringValue;
}

/** Captures OTLP exports and, when `hangProvider` is set, holds provider requests open. */
function captureFetch(hangProvider = false) {
  const original = globalThis.fetch;
  const traceBodies: string[] = [];
  let providerCalls = 0;
  let release: ((response: Response) => void) | undefined;
  globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/v1/traces")) { traceBodies.push(String(init?.body)); return Promise.resolve(new Response()); }
    if (url.endsWith("/v1/logs")) return Promise.resolve(new Response());
    providerCalls++;
    return hangProvider ? new Promise<Response>((resolve) => { release = resolve; }) : Promise.resolve(new Response());
  }) as typeof fetch;
  return {
    traceBodies,
    providerCalls: () => providerCalls,
    release: (response: Response) => release?.(response),
    restore: () => { globalThis.fetch = original; },
  };
}

/** Records timer handles so a test can prove cancellation cleared its bounds. */
function trackTimers() {
  const originalSet = globalThis.setTimeout;
  const originalClear = globalThis.clearTimeout;
  const created: { handle: ReturnType<typeof setTimeout>; ms?: number }[] = [];
  const cleared = new Set<ReturnType<typeof setTimeout>>();
  globalThis.setTimeout = ((handler: () => void, ms?: number, ...args: unknown[]) => {
    const schedule = originalSet as unknown as (callback: () => void, timeout?: number, ...rest: unknown[]) => ReturnType<typeof setTimeout>;
    const handle = schedule(handler, ms, ...args);
    created.push({ handle, ms });
    return handle;
  }) as unknown as typeof globalThis.setTimeout;
  globalThis.clearTimeout = ((handle?: ReturnType<typeof setTimeout>) => {
    if (handle !== undefined) cleared.add(handle);
    originalClear(handle);
  }) as typeof globalThis.clearTimeout;
  return {
    created, cleared,
    restore: () => { globalThis.setTimeout = originalSet; globalThis.clearTimeout = originalClear; },
  };
}
const providerAnswer = JSON.stringify({ answers: { permission: {
  type: "choice", choice: "allow", confidence: 0.99, probabilities: { allow: 0.99, deny: 0.005, ask: 0.005 },
} } });

/**
 * A typed provider that never settles and ignores its abort signal must not
 * hold the review until the overall deadline. Cancellation has to settle the
 * review, keep the fallback stage untouched, finalize pending spans, and clear
 * every bound it armed.
 */
async function expectHungTypedReviewCancelled(stop: "interrupt" | "unload"): Promise<void> {
  const directory = mkdtempSync(join(tmpdir(), "automode-hung-"));
  const exports = captureFetch(true);
  const timers = trackTimers();
  try {
    const file = join(directory, "audit.jsonl");
    const host = await setup({
      classifiers: [
        { type: "decision", model: "laya/local", timeoutMs: 7_777 },
        { type: "decision", model: "laya/local" },
      ],
      reviewTimeoutMs: 4_321,
      auditLog: file,
      otlp: { endpoint: "http://collector:4318" },
    });
    const pending = event();
    const startedAt = Date.now();
    const evaluation = host.evaluate(pending);
    await waitFor(() => exports.providerCalls() === 1);
    if (stop === "interrupt") host.interrupt();
    else await host.cleanup();
    await evaluation;
    assert.ok(Date.now() - startedAt < 3_000, "cancellation must not wait for the review deadline");
    assert.equal(pending.effect, "ask");
    assert.match(pending.message!, /interrupted/i);
    assert.equal(exports.providerCalls(), 1, "no fallback provider may start after cancellation");
    assert.equal(host.prompts.length, 0, "no fallback reviewer may start after cancellation");
    const record = lastRecord(file);
    assert.equal(record.error, true);
    assert.equal(record.errorKind, "cancelled");
    assert.equal(exports.traceBodies.length, 1, "the settled review must export its trace once");
    const spans = exportedSpans(exports.traceBodies[0]!);
    assert.equal(spans.length, 2);
    for (const span of spans) {
      assert.equal(span.status.code, 2);
      assert.equal(spanValue(span, "error.kind"), "cancelled");
    }
    for (const ms of [7_777, 4_321]) {
      const timer = timers.created.find((item) => item.ms === ms);
      assert.ok(timer, `the ${ms}ms bound must be armed`);
      assert.ok(timers.cleared.has(timer.handle), `cancellation must clear the ${ms}ms timer`);
    }
    // The provider still settles later; it must not mutate the exported span
    // or produce a second export.
    exports.release(new Response(providerAnswer));
    await delay(10);
    assert.equal(exports.traceBodies.length, 1, "a late provider must not export again");
    assert.equal(spanValue(exportedSpans(exports.traceBodies[0]!)[1]!, "error.kind"), "cancelled");
    if (stop === "interrupt") await host.cleanup();
  } finally {
    timers.restore();
    exports.restore();
    rmSync(directory, { recursive: true, force: true });
  }
}

describe("OpenCode permission hook", () => {
  it("only reviews actions that OpenCode asks about", async () => {
    const host = await setup({ classifiers: [{ type: "llm" }] });
    for (const effect of ["allow", "deny"] as const) {
      const pending = event(effect);
      await host.evaluate(pending);
      assert.equal(pending.effect, effect);
      assert.deepEqual(host.prompts, []);
    }
    await host.evaluate(event());
    assert.equal(host.prompts.length, 2);
    await host.cleanup();
  });
  it("leaves host allow and deny decisions untouched even with invalid configuration", async () => {
    const host = await setup({ classifiers: [] });
    for (const effect of ["allow", "deny"] as const) {
      const pending = event(effect);
      await host.evaluate(pending);
      assert.equal(pending.effect, effect);
    }
    await host.cleanup();
  });
  it("fails closed on malformed options and reviewer failures", async () => {
    const host = await setup({ classifiers: [{ type: "bogus" }] });
    const pending = event();
    await host.evaluate(pending);
    assert.equal(pending.effect, "ask");
    await host.cleanup();
    const failed = await setup({ classifiers: [{ type: "llm" }] });
    failed.ctx.generate.text = async () => { throw new Error("private error"); };
    const request = event();
    await failed.evaluate(request);
    assert.equal(request.effect, "ask");
    assert.doesNotMatch(request.message!, /private error/);
    await failed.cleanup();
  });
  it("falls through to the next model reviewer when one is unavailable", async () => {
    const host = await setup({ classifiers: [{ type: "llm" }, { type: "llm" }] });
    let calls = 0;
    host.ctx.generate.text = async () => {
      if (calls++ === 0) throw new Error("temporary failure");
      return { text: "ALLOW" };
    };
    const pending = event();
    await host.evaluate(pending);
    assert.equal(pending.effect, "allow");
    assert.equal(calls, 2);
    await host.cleanup();
  });
  it("uses the session model for both LLM calls when no reviewer model is set", async () => {
    const host = await setup({ classifiers: [{ type: "llm" }] });
    await host.evaluate(event());
    assert.equal(host.models.length, 2);
    const expected = { providerID: "session-provider", id: "session-model", variant: "high" };
    assert.deepEqual(host.models, [expected, expected]);
    await host.cleanup();
  });
  it("passes a provider/model stage selection to generation", async () => {
    const host = await setup({ classifiers: [{ type: "llm", model: "anthropic/claude-sonnet-4-5#high" }] });
    await host.evaluate(event());
    assert.deepEqual(host.models[0], {
      providerID: "anthropic",
      id: "claude-sonnet-4-5",
      variant: "high",
    });
    await host.cleanup();
  });
  it("uses each reviewer's own policy without inheriting from a fallback", async () => {
    const host = await setup({ classifiers: [
      { type: "llm", policy: { blocks: ["FIRST_POLICY_MARKER"] } },
      { type: "llm", policy: { blocks: ["SECOND_POLICY_MARKER"] } },
    ] });
    const prompts: string[] = [];
    host.ctx.generate.text = async ({ prompt }) => {
      prompts.push(prompt);
      if (prompts.length === 1) throw new Error("unavailable");
      return { text: "ALLOW" };
    };
    const pending = event();
    await host.evaluate(pending);
    assert.equal(pending.effect, "allow");
    assert.match(prompts[0], /FIRST_POLICY_MARKER/);
    assert.doesNotMatch(prompts[0], /SECOND_POLICY_MARKER/);
    assert.match(prompts[1], /SECOND_POLICY_MARKER/);
    assert.doesNotMatch(prompts[1], /FIRST_POLICY_MARKER/);
    await host.cleanup();
  });
  it("includes pending metadata and source in both LLM stages", async () => {
    const host = await setup({ classifiers: [{ type: "llm" }] });
    const pending = { ...event(), metadata: { payload: "pending-payload-marker" }, source: { type: "tool", id: "source-marker" } };
    await host.evaluate(pending);
    assert.equal(pending.effect, "allow");
    assert.equal(host.prompts.length, 2);
    for (const prompt of host.prompts) { assert.match(prompt, /pending-payload-marker/); assert.match(prompt, /source-marker/); }
    await host.cleanup();
    assert.equal(host.disposed(), 3);
  });
  it("requires complete actual user context for model review", async () => {
    const incomplete = [[], [{ type: "assistant", content: [{ type: "tool", name: "shell", state: { input: "approve" } }] }],
      [{ type: "user", text: "Follow attached constraints", files: [{ uri: "file:///repo/constraints.txt" }] }],
      [{ type: "user", text: "Follow this skill", skills: [{ id: "constraints" }] }]];
    for (const messages of incomplete) {
      const host = await setup({ classifiers: [{ type: "llm" }] }, messages);
      const pending = event();
      await host.evaluate(pending);
      assert.equal(pending.effect, "ask");
      assert.deepEqual(host.prompts, []);
      await host.cleanup();
    }
  });
  it("reviews long user prompts instead of requiring manual approval", async () => {
    const host = await setup({ classifiers: [{ type: "llm" }] }, [{ type: "user", text: "x".repeat(1200) }]);
    const pending = event();
    await host.evaluate(pending);
    assert.equal(pending.effect, "allow");
    assert.equal(host.prompts.length, 2);
    await host.cleanup();
  });
  it("stops a review at the deadline instead of blocking the prompt", async () => {
    const host = await setup({ classifiers: [{ type: "llm" }], reviewTimeoutMs: 1_000 });
    host.ctx.generate.text = () => new Promise(() => {});
    const startedAt = Date.now();
    const pending = event();
    await host.evaluate(pending);
    assert.equal(pending.effect, "ask");
    assert.match(pending.message!, /deadline/i);
    assert.ok(Date.now() - startedAt < 5_000);
    await host.cleanup();
  });
  it("does not turn an interrupted review into an approval", async () => {
    const host = await setup({ classifiers: [{ type: "llm" }] });
    let resume!: (value: { text: string }) => void;
    host.ctx.generate.text = () => new Promise((resolve) => { resume = resolve; });
    const pending = event();
    const evaluation = host.evaluate(pending);
    await new Promise((resolve) => setTimeout(resolve, 10));
    host.interrupt();
    await new Promise((resolve) => setTimeout(resolve, 10));
    resume({ text: "ALLOW" });
    await evaluation;
    assert.equal(pending.effect, "ask");
    assert.match(pending.message!, /interrupted/i);
    await host.cleanup();
  });
  it("keeps provider authentication failures categorized as provider", async () => {
    const directory = mkdtempSync(join(tmpdir(), "automode-audit-"));
    try {
      const host = await setup({ classifiers: [{ type: "llm" }], auditLog: join(directory, "audit.jsonl") });
      host.ctx.generate.text = async () => { throw new Error("Invalid API key"); };
      await host.evaluate(event());
      const record = JSON.parse(readFileSync(join(directory, "audit.jsonl"), "utf8").trim().split("\n").at(-1)!);
      assert.equal(record.error, true);
      assert.equal(record.errorKind, "provider");
      assert.doesNotMatch(JSON.stringify(record), /Invalid API key/);
      await host.cleanup();
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });
  it("aborts every overlapping review when the session is interrupted", async () => {
    const host = await setup({ classifiers: [{ type: "llm" }] });
    const resolvers: ((value: { text: string }) => void)[] = [];
    const signals: AbortSignal[] = [];
    host.ctx.generate.text = ((_input: { prompt: string }, request?: { signal?: AbortSignal }) => {
      signals.push(request!.signal!);
      return new Promise((resolve) => { resolvers.push(resolve); });
    }) as typeof host.ctx.generate.text;
    const first = event();
    const second = event();
    const firstRun = host.evaluate(first);
    const secondRun = host.evaluate(second);
    await waitFor(() => signals.length === 2);
    host.interrupt();
    await waitFor(() => signals.every((signal) => signal.aborted));
    for (const resolve of resolvers) resolve({ text: "ALLOW" });
    await Promise.all([firstRun, secondRun]);
    for (const pending of [first, second]) {
      assert.equal(pending.effect, "ask");
      assert.match(pending.message!, /interrupted/i);
    }
    await host.cleanup();
  });
  it("aborts every overlapping review when the plugin unloads", async () => {
    const host = await setup({ classifiers: [{ type: "llm" }] });
    const resolvers: ((value: { text: string }) => void)[] = [];
    const signals: AbortSignal[] = [];
    host.ctx.generate.text = ((_input: { prompt: string }, request?: { signal?: AbortSignal }) => {
      signals.push(request!.signal!);
      return new Promise((resolve) => { resolvers.push(resolve); });
    }) as typeof host.ctx.generate.text;
    const first = event();
    const second = event();
    const runs = [host.evaluate(first), host.evaluate(second)];
    await waitFor(() => signals.length === 2);
    await host.cleanup();
    await waitFor(() => signals.every((signal) => signal.aborted));
    for (const resolve of resolvers) resolve({ text: "ALLOW" });
    await Promise.all(runs);
    for (const pending of [first, second]) {
      assert.equal(pending.effect, "ask");
      assert.match(pending.message!, /interrupted/i);
    }
  });
  it("settles a hung typed reviewer as cancelled when the session is interrupted", async () => {
    await expectHungTypedReviewCancelled("interrupt");
  });
  it("settles a hung typed reviewer as cancelled when the plugin unloads", async () => {
    await expectHungTypedReviewCancelled("unload");
  });
  it("stops before starting a fallback provider with an already-aborted signal", async () => {
    const host = await setup({ classifiers: [{ type: "llm" }, { type: "llm" }], reviewTimeoutMs: 5_000 });
    const signals: AbortSignal[] = [];
    host.ctx.generate.text = ((_input: { prompt: string }, request?: { signal?: AbortSignal }) => {
      signals.push(request!.signal!);
      return new Promise<{ text: string }>(() => {});
    }) as typeof host.ctx.generate.text;
    const pending = event();
    const startedAt = Date.now();
    const evaluation = host.evaluate(pending);
    await waitFor(() => signals.length === 1);
    host.interrupt();
    await evaluation;
    assert.equal(pending.effect, "ask");
    assert.match(pending.message!, /interrupted/i);
    assert.ok(Date.now() - startedAt < 2_000, "an aborted fallback must not wait for its own timeout");
    assert.equal(signals.length, 1, "the fallback provider must never start after cancellation");
    assert.equal(signals[0]!.aborted, true);
    await host.cleanup();
  });
  it("does not deny an interrupted request", async () => {
    const host = await setup({ classifiers: [{ type: "static" }] });
    let release!: () => void;
    host.ctx.session.get = () => new Promise((resolve) => {
      release = () => resolve({ location: { directory: "/repo" }, model: { providerID: "session-provider", id: "session-model", variant: "high" } });
    });
    const pending = { ...event(), resources: ["sudo rm -rf /"] };
    const evaluation = host.evaluate(pending);
    await waitFor(() => release !== undefined);
    host.interrupt();
    await evaluation;
    release();
    assert.equal(pending.effect, "ask");
    assert.match(pending.message!, /interrupted/i);
    await host.cleanup();
  });
  it("does not load context or start a reviewer after an interrupted session lookup", async () => {
    const host = await setup({ classifiers: [{ type: "llm" }] });
    let release!: () => void;
    let contextCalls = 0;
    let generateCalls = 0;
    host.ctx.session.get = () => new Promise((resolve) => {
      release = () => resolve({ location: { directory: "/repo" }, model: { providerID: "session-provider", id: "session-model", variant: "high" } });
    });
    host.ctx.session.context = async () => { contextCalls++; return [{ type: "user", text: "Create a file named a" }]; };
    host.ctx.generate.text = async () => { generateCalls++; return { text: "ALLOW" }; };
    const pending = event();
    const evaluation = host.evaluate(pending);
    await waitFor(() => release !== undefined);
    host.interrupt();
    await evaluation;
    release();
    assert.equal(pending.effect, "ask");
    assert.match(pending.message!, /interrupted/i);
    assert.equal(contextCalls, 0);
    assert.equal(generateCalls, 0);
    await host.cleanup();
  });
  it("reports why a failed session lookup blocked model review", async () => {
    const directory = mkdtempSync(join(tmpdir(), "automode-lookup-"));
    try {
      const file = join(directory, "audit.jsonl");
      const host = await setup({ classifiers: [{ type: "llm" }], auditLog: file });
      host.ctx.session.get = async () => { throw new Error("lookup unavailable"); };
      const pending = event();
      await host.evaluate(pending);
      assert.equal(pending.effect, "ask");
      assert.deepEqual(host.prompts, []);
      const record = lastRecord(file);
      assert.equal(record.decision, "ask");
      assert.equal(record.error, true);
      assert.equal(record.errorKind, "provider");
      assert.doesNotMatch(JSON.stringify(record), /lookup unavailable/);
      await host.cleanup();
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });
  it("keeps an explicitly configured reviewer working when the session lookup fails", async () => {
    const directory = mkdtempSync(join(tmpdir(), "automode-lookup-"));
    try {
      const file = join(directory, "audit.jsonl");
      const host = await setup({ classifiers: [{ type: "llm", model: "anthropic/claude-sonnet-4-5" }], auditLog: file });
      host.ctx.session.get = async () => { throw new Error("lookup unavailable"); };
      const pending = event();
      await host.evaluate(pending);
      assert.equal(pending.effect, "allow");
      assert.equal(host.prompts.length, 2);
      const record = lastRecord(file);
      assert.equal(record.decision, "allow");
      assert.equal(record.error, undefined);
      assert.equal(record.errorKind, undefined);
      await host.cleanup();
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });
  it("keeps static review working when the session lookup fails", async () => {
    const host = await setup({ classifiers: [{ type: "static" }] });
    host.ctx.session.get = async () => { throw new Error("lookup unavailable"); };
    const pending = { ...event(), resources: ["sudo rm -rf /"] };
    await host.evaluate(pending);
    assert.equal(pending.effect, "deny");
    await host.cleanup();
  });
  it("reports cancellation over an earlier provider failure", async () => {
    const directory = mkdtempSync(join(tmpdir(), "automode-cancelled-"));
    try {
      const file = join(directory, "audit.jsonl");
      const host = await setup({ classifiers: [{ type: "llm" }, { type: "llm" }], auditLog: file });
      let calls = 0;
      host.ctx.generate.text = () => {
        calls++;
        return calls === 1 ? Promise.reject(new Error("provider rejected")) : new Promise(() => {});
      };
      const pending = event();
      const evaluation = host.evaluate(pending);
      await waitFor(() => calls === 2);
      host.interrupt();
      await evaluation;
      assert.equal(pending.effect, "ask");
      assert.match(pending.message!, /interrupted/i);
      const record = lastRecord(file);
      assert.equal(record.error, true);
      assert.equal(record.errorKind, "cancelled");
      await host.cleanup();
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });
  it("reports incomplete authorization context as a terminal error", async () => {
    const directory = mkdtempSync(join(tmpdir(), "automode-context-"));
    try {
      const file = join(directory, "audit.jsonl");
      const host = await setup({ classifiers: [{ type: "llm" }], auditLog: file }, []);
      const pending = event();
      await host.evaluate(pending);
      assert.equal(pending.effect, "ask");
      const record = lastRecord(file);
      assert.equal(record.decision, "ask");
      assert.equal(record.error, true);
      assert.equal(record.errorKind, "context");
      await host.cleanup();
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });
  it("reports a valid unclear ask without marking audit or spans as errors", async () => {
    const directory = mkdtempSync(join(tmpdir(), "automode-ask-"));
    const exports = captureFetch();
    try {
      const file = join(directory, "audit.jsonl");
      const host = await setup(
        { classifiers: [{ type: "llm" }], auditLog: file, otlp: { endpoint: "http://collector:4318" } },
        [{ type: "user", text: "Create a file named a" }],
        ["BLOCK", "ASK: Reviewer response unclear"],
      );
      const pending = event();
      await host.evaluate(pending);
      assert.equal(pending.effect, "ask");
      assert.equal(pending.message, "Reviewer response unclear");
      const record = lastRecord(file);
      assert.equal(record.decision, "ask");
      assert.equal(record.error, undefined);
      assert.equal(record.errorKind, undefined);
      assert.equal(exports.traceBodies.length, 1);
      const spans = exportedSpans(exports.traceBodies[0]!);
      assert.equal(spans.length, 2);
      for (const span of spans) {
        assert.equal(span.status.code, 1);
        assert.equal(spanValue(span, "error.kind"), undefined);
      }
      assert.equal(spanValue(spans[1]!, "decision"), "ask");
      await host.cleanup();
    } finally {
      exports.restore();
      rmSync(directory, { recursive: true, force: true });
    }
  });
  it("reports the deadline rather than the cancellation it triggers", async () => {
    const directory = mkdtempSync(join(tmpdir(), "automode-deadline-"));
    try {
      const file = join(directory, "audit.jsonl");
      const host = await setup({ classifiers: [{ type: "llm" }], reviewTimeoutMs: 1_000, auditLog: file });
      host.ctx.generate.text = () => new Promise(() => {});
      const pending = event();
      await host.evaluate(pending);
      assert.equal(pending.effect, "ask");
      assert.match(pending.message!, /deadline/i);
      assert.equal(lastRecord(file).errorKind, "deadline");
      await host.cleanup();
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });
  it("reports the deadline rather than an earlier provider failure", async () => {
    const directory = mkdtempSync(join(tmpdir(), "automode-deadline-"));
    try {
      const file = join(directory, "audit.jsonl");
      const host = await setup({ classifiers: [{ type: "llm" }, { type: "llm" }], reviewTimeoutMs: 1_000, auditLog: file });
      let calls = 0;
      host.ctx.generate.text = () => calls++ === 0 ? Promise.reject(new Error("provider rejected")) : new Promise(() => {});
      const pending = event();
      await host.evaluate(pending);
      assert.equal(pending.effect, "ask");
      assert.match(pending.message!, /deadline/i);
      assert.equal(calls, 2);
      assert.equal(lastRecord(file).errorKind, "deadline");
      await host.cleanup();
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });
  it("exports a pending typed attempt when the review deadline expires", async () => {
    const originalFetch = globalThis.fetch;
    let traceBody: string | undefined;
    let traceRequests = 0;
    let releaseProvider: ((response: Response) => void) | undefined;
    globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/v1/traces")) {
        traceRequests++;
        traceBody = String(init?.body);
        return Promise.resolve(new Response());
      }
      if (url.endsWith("/v1/logs")) return Promise.resolve(new Response());
      return new Promise<Response>((resolve) => { releaseProvider = resolve; });
    }) as typeof fetch;
    try {
      const host = await setup({
        classifiers: [{ type: "decision", model: "laya/local", endpoint: "http://127.0.0.1:8000/v1/systemone" }],
        reviewTimeoutMs: 1_000,
        otlp: { endpoint: "http://collector:4318" },
      });
      const startedAt = Date.now();
      const pending = event();
      await host.evaluate(pending);
      assert.equal(pending.effect, "ask");
      assert.match(pending.message!, /deadline/i);
      assert.ok(Date.now() - startedAt < 5_000);
      assert.ok(traceBody, "the deadline must export the trace");
      const spans = JSON.parse(traceBody!).resourceSpans[0].scopeSpans[0].spans;
      assert.equal(spans.length, 2);
      assert.equal(spans[1].name, "auto_mode.classifier");
      assert.equal(spans[1].attributes.find((attr: { key: string }) => attr.key === "classifier.type").value.stringValue, "decision");
      assert.equal(spans[1].attributes.find((attr: { key: string }) => attr.key === "error.kind").value.stringValue, "deadline");
      assert.equal(spans[1].status.code, 2);
      assert.equal(spans[0].attributes.find((attr: { key: string }) => attr.key === "error.kind").value.stringValue, "deadline");
      releaseProvider?.(new Response(JSON.stringify({ answers: { permission: {
        type: "choice", choice: "allow", confidence: 0.99, probabilities: { allow: 0.99, deny: 0.005, ask: 0.005 },
      } } })));
      await delay(10);
      assert.equal(traceRequests, 1, "a late provider must not export again");
      assert.equal(JSON.parse(traceBody!).resourceSpans[0].scopeSpans[0].spans[1]
        .attributes.find((attr: { key: string }) => attr.key === "error.kind").value.stringValue, "deadline");
      await host.cleanup();
    } finally { globalThis.fetch = originalFetch; }
  });
  it("releases provider calls after a successful decision without changing it", async () => {
    const host = await setup({ classifiers: [{ type: "llm" }] });
    let providerSignal: AbortSignal | undefined;
    host.ctx.generate.text = ((_input: { prompt: string }, request?: { signal?: AbortSignal }) => {
      providerSignal = request?.signal;
      return Promise.resolve({ text: "ALLOW" });
    }) as typeof host.ctx.generate.text;
    const pending = event();
    await host.evaluate(pending);
    assert.equal(pending.effect, "allow");
    assert.ok(providerSignal?.aborted, "the finished review must release its provider signal");
    await host.cleanup();
  });
  it("releases a timed-out decision request without turning it into a cancellation", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = ((_input: string | URL | Request, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(init.signal!.reason), { once: true });
    })) as typeof fetch;
    try {
      const host = await setup({
        classifiers: [{ type: "decision", model: "laya/local", timeoutMs: 20 }],
        reviewTimeoutMs: 5_000,
      });
      let reviewSignal: AbortSignal | undefined;
      host.ctx.session.get = (async (_input: unknown, request?: { signal?: AbortSignal }) => {
        reviewSignal = request?.signal;
        return { location: { directory: "/repo" }, model: { providerID: "session-provider", id: "session-model", variant: "high" } };
      }) as typeof host.ctx.session.get;
      const pending = event();
      await host.evaluate(pending);
      assert.equal(pending.effect, "ask");
      assert.match(pending.message!, /unavailable|no classifier/i);
      assert.ok(reviewSignal?.aborted, "cleanup must abort the review controller after a local timeout");
      await host.cleanup();
    } finally { globalThis.fetch = originalFetch; }
  });
  it("aborts the event subscription when permission hook registration fails", async () => {
    const host = await setup({ classifiers: [{ type: "static" }] });
    host.ctx.permission.hook = async () => { throw new Error("permission registration failed"); };
    await assert.rejects(Promise.resolve(plugin.setup(host.ctx as unknown as Parameters<typeof plugin.setup>[0])));
    assert.equal(host.subscriptionSignals.length, 2);
    assert.equal(host.subscriptionSignals[1]!.aborted, true);
    await host.cleanup();
  });
  it("aborts the subscription and active reviews when tool hook registration fails", async () => {
    const host = await setup({ classifiers: [{ type: "llm" }] });
    let rejectTool!: (error: Error) => void;
    let toolStarted!: () => void;
    const toolRegistration = new Promise<void>((resolve) => { toolStarted = resolve; });
    host.ctx.tool.hook = (() => {
      toolStarted();
      return new Promise((_resolve, reject) => { rejectTool = reject; });
    }) as typeof host.ctx.tool.hook;
    const setupRun = plugin.setup(host.ctx as unknown as Parameters<typeof plugin.setup>[0]);
    await toolRegistration;
    assert.equal(host.subscriptionSignals.length, 2);
    let providerSignal: AbortSignal | undefined;
    host.ctx.generate.text = ((_input: { prompt: string }, request?: { signal?: AbortSignal }) => {
      providerSignal = request?.signal;
      return new Promise<{ text: string }>(() => {});
    }) as typeof host.ctx.generate.text;
    const pending = event();
    const reviewRun = host.evaluate(pending);
    await waitFor(() => providerSignal !== undefined);
    rejectTool(new Error("tool registration failed"));
    await assert.rejects(Promise.resolve(setupRun));
    assert.equal(host.subscriptionSignals[1]!.aborted, true);
    await waitFor(() => providerSignal!.aborted);
    await reviewRun;
    assert.equal(pending.effect, "ask");
    assert.match(pending.message!, /interrupted/i);
    await host.cleanup();
  });
  it("exposes configuration and decisions over RPC without prompts", async () => {
    const host = await setup({ classifiers: [{ type: "static" }, { type: "llm" }], reviewTimeoutMs: 30_000 });
    const before = await host.status({ sessionID: "session-test" }) as { enabled: boolean; classifiers: string[]; recent: unknown[] };
    assert.equal(before.enabled, true);
    assert.deepEqual(before.classifiers, ["static", "llm"]);
    assert.deepEqual(before.recent, []);
    await host.evaluate(event());
    const after = await host.status({ sessionID: "session-test" }) as { recent: { decision: string; reason: string }[] };
    assert.equal(after.recent.length, 1);
    assert.equal(after.recent[0].decision, "allow");
    assert.doesNotMatch(JSON.stringify(after), /Build a feature/);
    assert.equal(host.rpcEvents.length, 1);
    await host.cleanup();
  });
  it("reports an invalid configuration over RPC", async () => {
    const host = await setup({ classifiers: [{ type: "bogus" }] });
    const snapshot = await host.status() as { enabled: boolean; configError?: string };
    assert.equal(snapshot.enabled, false);
    assert.match(snapshot.configError!, /classifiers/i);
    await host.cleanup();
  });
  it("keeps repeated policy denials denied and disposes partial setup", async () => {    const host = await setup({ classifiers: [{ type: "static" }] });
    for (let i = 0; i < 25; i++) {
      const pending = { ...event(), resources: ["sudo rm -rf /"] };
      await host.evaluate(pending); assert.equal(pending.effect, "deny");
    }
    await host.cleanup();
    host.ctx.tool.hook = async () => { throw new Error("setup failed"); };
    await assert.rejects(Promise.resolve(plugin.setup(host.ctx as unknown as Parameters<typeof plugin.setup>[0])));
    assert.equal(host.disposed(), 4);
  });
});
