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
  let wake: (() => void) | undefined;
  async function* subscribe(input: { signal?: AbortSignal }) {
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
    generate: { text: async ({ prompt, model }: { prompt: string; model?: { id: string; providerID: string; variant?: string } | null }) => { prompts.push(prompt); models.push(model); return { text: answers.shift() ?? "ASK: unclear" }; } },
  };
  const cleanup = await plugin.setup(ctx as unknown as Parameters<typeof plugin.setup>[0]);
  return {
    evaluate, prompts, models, ctx, disposed: () => disposed,
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
    assert.equal(host.disposed(), 2);
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
  it("records a bounded failure kind in the audit log", async () => {
    const directory = mkdtempSync(join(tmpdir(), "automode-audit-"));
    try {
      const host = await setup({ classifiers: [{ type: "llm" }], auditLog: join(directory, "audit.jsonl") });
      host.ctx.generate.text = async () => { throw new Error("provider key rejected"); };
      await host.evaluate(event());
      const record = JSON.parse(readFileSync(join(directory, "audit.jsonl"), "utf8").trim().split("\n").at(-1)!);
      assert.equal(record.error, true);
      assert.equal(record.errorKind, "provider");
      assert.doesNotMatch(JSON.stringify(record), /provider key rejected/);
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
  it("reviews nothing further with an already-aborted fallback signal", async () => {
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
    assert.equal(signals.length, 2);
    assert.equal(signals[1]!.aborted, true);
    await host.cleanup();
  });
  it("turns an interrupted denial into a user decision", async () => {
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
  it("keeps repeated policy denials denied and disposes partial setup", async () => {    const host = await setup({ classifiers: [{ type: "static" }] });
    for (let i = 0; i < 25; i++) {
      const pending = { ...event(), resources: ["sudo rm -rf /"] };
      await host.evaluate(pending); assert.equal(pending.effect, "deny");
    }
    await host.cleanup();
    host.ctx.tool.hook = async () => { throw new Error("setup failed"); };
    await assert.rejects(Promise.resolve(plugin.setup(host.ctx as unknown as Parameters<typeof plugin.setup>[0])));
    assert.equal(host.disposed(), 3);
  });
});
