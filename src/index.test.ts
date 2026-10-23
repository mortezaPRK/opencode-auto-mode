import { describe, it } from "node:test";
import assert from "node:assert/strict";
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
  const ctx = {
    options,
    permission: { hook: async (_: string, handler: typeof evaluate) => { evaluate = handler; return { dispose: async () => { disposed++; } }; } },
    tool: { hook: async () => ({ dispose: async () => { disposed++; } }) },
    session: { get: async () => ({ location: { directory: "/repo" }, model: { providerID: "session-provider", id: "session-model", variant: "high" } }), context: async () => messages },
    generate: { text: async ({ prompt, model }: { prompt: string; model?: { id: string; providerID: string; variant?: string } | null }) => { prompts.push(prompt); models.push(model); return { text: answers.shift() ?? "ASK: unclear" }; } },
  };
  const cleanup = await plugin.setup(ctx as unknown as Parameters<typeof plugin.setup>[0]);
  return { evaluate, prompts, models, ctx, cleanup: async () => { await cleanup?.(); }, disposed: () => disposed };
}
function event(effect: Evaluation["effect"] = "ask"): Evaluation {
  return { sessionID: "session-test", agent: "build", action: "shell", resources: ["touch a"], effect };
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
      [{ type: "user", text: "x".repeat(1000) }],
      Array.from({ length: 11 }, () => ({ type: "user", text: "hello" }))];
    for (const messages of incomplete) {
      const host = await setup({ classifiers: [{ type: "llm" }] }, messages);
      const pending = event();
      await host.evaluate(pending);
      assert.equal(pending.effect, "ask");
      assert.deepEqual(host.prompts, []);
      await host.cleanup();
    }
  });
  it("keeps repeated policy denials denied and disposes partial setup", async () => {
    const host = await setup({ classifiers: [{ type: "static" }] });
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
