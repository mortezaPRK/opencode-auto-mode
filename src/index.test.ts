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
  const ctx = {
    options,
    permission: { hook: async (_: string, handler: typeof evaluate) => { evaluate = handler; return { dispose: async () => { disposed++; } }; } },
    tool: { hook: async () => ({ dispose: async () => { disposed++; } }) },
    session: { get: async () => ({ location: { directory: "/repo" } }), context: async () => messages },
    generate: { text: async ({ prompt }: { prompt: string }) => { prompts.push(prompt); return { text: answers.shift() ?? "ASK: unclear" }; } },
  };
  const cleanup = await plugin.setup(ctx as unknown as Parameters<typeof plugin.setup>[0]);
  return { evaluate, prompts, ctx, cleanup: async () => { await cleanup?.(); }, disposed: () => disposed };
}
function event(effect: Evaluation["effect"] = "ask"): Evaluation {
  return { sessionID: "session-test", agent: "auto", action: "shell", resources: ["touch a"], effect };
}

describe("OpenCode permission hook", () => {
  it("preserves host denials even with permissive or invalid configuration", async () => {
    for (const config of [{ classifier: { stages: [{ type: "rules", rules: [{ action: "*", decision: "allow" }] }] } }, { classifier: { stages: [] } }]) {
      const host = await setup(config);
      const pending = event("deny");
      await host.evaluate(pending);
      assert.equal(pending.effect, "deny");
      assert.deepEqual(host.prompts, []);
      await host.cleanup();
    }
  });
  it("fails closed on malformed options and reviewer failures", async () => {
    const host = await setup({ classifier: { stages: [{ type: "bogus" }] } });
    const pending = event("allow");
    await host.evaluate(pending);
    assert.equal(pending.effect, "ask");
    await host.cleanup();
    const failed = await setup({ classifier: { stages: [{ type: "llm" }] } });
    failed.ctx.generate.text = async () => { throw new Error("private error"); };
    const request = event("allow");
    await failed.evaluate(request);
    assert.equal(request.effect, "ask");
    assert.doesNotMatch(request.message!, /private error/);
    await failed.cleanup();
  });
  it("applies configured agent and prompt scope", async () => {
    const host = await setup({ agents: ["auto"], review: "prompts" });
    const build = { ...event("allow"), agent: "build" };
    await host.evaluate(build);
    assert.equal(build.effect, "allow");
    await host.evaluate(event("allow"));
    assert.deepEqual(host.prompts, []);
    await host.cleanup();
  });
  it("includes pending metadata and source in both LLM stages", async () => {
    const host = await setup({ classifier: { stages: [{ type: "llm" }] } });
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
      const host = await setup({ classifier: { stages: [{ type: "llm" }] } }, messages);
      const pending = event("allow");
      await host.evaluate(pending);
      assert.equal(pending.effect, "ask");
      assert.deepEqual(host.prompts, []);
      await host.cleanup();
    }
  });
  it("keeps repeated policy denials denied and disposes partial setup", async () => {
    const host = await setup({ classifier: { stages: [{ type: "rules", rules: [{ action: "shell", decision: "deny" }] }] } });
    for (let i = 0; i < 25; i++) {
      const pending = event(); await host.evaluate(pending); assert.equal(pending.effect, "deny");
    }
    await host.cleanup();
    host.ctx.tool.hook = async () => { throw new Error("setup failed"); };
    await assert.rejects(Promise.resolve(plugin.setup(host.ctx as unknown as Parameters<typeof plugin.setup>[0])));
    assert.equal(host.disposed(), 3);
  });
});
