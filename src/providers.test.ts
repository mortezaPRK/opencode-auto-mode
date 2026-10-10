import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { providerDecision, type ProviderStage } from "./providers.js";
import { defaultPolicy } from "./policy.js";

const request = { action: "shell", resources: ["touch a"], transcript: "User messages: create a" };
const decision = { type: "choice", choice: "allow", confidence: 0.98, probabilities: { allow: 0.98, deny: 0.01, ask: 0.01 } };
function mock(value: unknown): typeof fetch {
  return (async () => new Response(JSON.stringify(value))) as typeof fetch;
}
function systemone(answer: unknown): unknown { return { answers: { permission: answer } }; }

describe("typed providers", () => {
  it("uses the Jev and Laya request contracts", async () => {
    for (const type of ["jev", "laya"] as const) {
      const key = "AUTO_MODE_TEST_KEY";
      process.env[key] = "test-credential";
      try {
        const fetcher = (async (url: string, init: RequestInit) => {
          assert.equal(url, type === "jev" ? "https://api.typesafe.ai/v1/systemone" : "http://127.0.0.1:8000/v1/systemone");
          assert.equal(init.redirect, "error");
          assert.equal((init.headers as Record<string, string>).Authorization, "Bearer test-credential");
          const body = JSON.parse(init.body as string);
          assert.deepEqual(body.state, request);
          assert.equal(body.questions.permission.type, "choice");
          assert.deepEqual(Object.keys(body.questions.permission.criteria), ["allow", "deny", "ask"]);
          if (type === "jev") assert.equal(body.model, "jev-latest");
          return new Response(JSON.stringify(systemone(decision)));
        }) as typeof fetch;
        assert.equal((await providerDecision({ type, apiKeyEnv: key }, request, defaultPolicy(), fetcher))?.decision, "allow");
      } finally { delete process.env[key]; }
    }
  });
  it("uses OpenAI named choices and validates refusals", async () => {
    process.env.AUTO_MODE_TEST_KEY = "test";
    try {
      const fetcher = (async (url: string, init: RequestInit) => {
        assert.equal(url, "https://api.openai.com/v1/decisions");
        const body = JSON.parse(init.body as string);
        assert.deepEqual(JSON.parse(body.input), request);
        assert.equal(body.questions[0].name, "permission");
        assert.deepEqual(body.questions[0].choices.map((c: { value: string }) => c.value), ["allow", "deny", "ask"]);
        return new Response(JSON.stringify({ answers: [{ ...decision, name: "permission", probabilities: Object.entries(decision.probabilities).map(([value, probability]) => ({ value, probability })) }] }));
      }) as typeof fetch;
      const stage: ProviderStage = { type: "openai-decision", apiKeyEnv: "AUTO_MODE_TEST_KEY" };
      assert.equal((await providerDecision(stage, request, defaultPolicy(), fetcher))?.decision, "allow");
      assert.equal((await providerDecision(stage, request, defaultPolicy(), mock({ answers: [{ type: "refusal", name: "permission" }] })))?.decision, "ask");
      assert.equal((await providerDecision(stage, request, defaultPolicy(), mock({ answers: [{ ...decision, name: "other" }] })))?.decision, "ask");
    } finally { delete process.env.AUTO_MODE_TEST_KEY; }
  });
  it("rejects invalid or contradictory answers and oversized bodies", async () => {
    for (const invalid of [null, { ...decision, choice: ["allow"] }, { ...decision, choice: "ALLOW" },
      { ...decision, confidence: "1" }, { ...decision, confidence: 2 },
      { ...decision, probabilities: { allow: 1, deny: 1, ask: 1 } },
      { ...decision, probabilities: { allow: 0.1, deny: 0.9, ask: 0 } },
      { ...decision, probabilities: { allow: 1 } }])
      assert.equal((await providerDecision({ type: "laya" }, request, defaultPolicy(), mock(systemone(invalid))))?.decision, "ask");
    assert.equal((await providerDecision({ type: "laya" }, request, defaultPolicy(), mock({ text: "x".repeat(70_000) })))?.decision, "ask");
    assert.equal((await providerDecision({ type: "laya" }, { ...request, resources: ["x".repeat(70_000)] }, defaultPolicy(), () => { throw new Error("must not fetch"); }))?.decision, "ask");
  });
  it("abstains on low confidence and keeps explicit asks terminal", async () => {
    assert.equal(await providerDecision({ type: "laya" }, request, defaultPolicy(), mock(systemone({ ...decision, confidence: 0.5 }))), undefined);
    assert.equal((await providerDecision({ type: "laya" }, request, defaultPolicy(), mock(systemone({ type: "choice", choice: "ask", confidence: 0.1, probabilities: { ask: 0.5, allow: 0.25, deny: 0.25 } }))))?.decision, "ask");
  });
  it("rejects redirects and times out a local HTTP body", async () => {
    let redirect = true;
    let requests = 0;
    const server = createServer((req, res) => {
      requests++;
      if (redirect) { res.writeHead(302, { location: "/other" }); res.end(); }
      else { res.writeHead(200, { "content-type": "application/json" }); res.write('{"answers":'); }
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    try {
      assert.equal((await providerDecision({ type: "laya", endpoint: `http://127.0.0.1:${address.port}/v1/systemone` }, request, defaultPolicy()))?.decision, "ask");
      assert.equal(requests, 1);
      redirect = false;
      assert.equal((await providerDecision({ type: "laya", endpoint: `http://127.0.0.1:${address.port}/v1/systemone`, timeoutMs: 30 }, request, defaultPolicy()))?.decision, "ask");
    } finally { server.closeAllConnections(); server.close(); }
  });
});
