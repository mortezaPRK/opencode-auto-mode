import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { decisionStage } from "./decisions.js";
import { defaultPolicy } from "./policy.js";

const request = { action: "shell", resources: ["touch a"], transcript: "User messages: create a" };
const decision = { type: "choice", choice: "allow", confidence: 0.98, probabilities: { allow: 0.98, deny: 0.01, ask: 0.01 } };
function mock(value: unknown): typeof fetch {
  return (async () => new Response(JSON.stringify(value))) as typeof fetch;
}
function systemone(answer: unknown): unknown { return { answers: { permission: answer } }; }

describe("typed decisions", () => {
  it("uses one System One request contract for hosted and local models", async () => {
    const localKey = process.env.LAYA_API_KEY;
    delete process.env.LAYA_API_KEY;
    for (const [model, url] of [["typesafe-ai/jev-latest", "https://api.typesafe.ai/v1/systemone"],
      ["laya/local", "http://127.0.0.1:8000/v1/systemone"]] as const) {
      const key = "AUTO_MODE_TEST_KEY";
      process.env[key] = "test-credential";
      try {
        const fetcher = (async (input: string | URL | Request, init?: RequestInit) => {
          assert.equal(String(input), url);
          assert.equal(init?.redirect, "error");
          const authorization = (init?.headers as Record<string, string> | undefined)?.Authorization;
          assert.equal(authorization, model.startsWith("laya/") ? undefined : "Bearer test-credential");
          const body = JSON.parse(init?.body as string);
          assert.deepEqual(body.state, request);
          assert.equal(body.model, model.split("/")[1]);
          assert.equal(body.questions.permission.type, "choice");
          assert.deepEqual(Object.keys(body.questions.permission.criteria), ["allow", "deny", "ask"]);
          return new Response(JSON.stringify(systemone(decision)));
        }) as typeof fetch;
        const stage = model.startsWith("laya/") ? { type: "decision" as const, model } : { type: "decision" as const, model, apiKeyEnv: key };
        assert.equal((await decisionStage(stage, request, defaultPolicy(), fetcher)).decision, "allow");
      } finally { delete process.env[key]; }
    }
    if (localKey !== undefined) process.env.LAYA_API_KEY = localKey;
  });
  it("uses OpenAI named choices and validates refusals", async () => {
    process.env.AUTO_MODE_TEST_KEY = "test";
    try {
      const fetcher = (async (input: string | URL | Request, init?: RequestInit) => {
        assert.equal(String(input), "https://api.openai.com/v1/decisions");
        const body = JSON.parse(init?.body as string);
        assert.deepEqual(JSON.parse(body.input), request);
        assert.equal(body.questions[0].name, "permission");
        assert.deepEqual(body.questions[0].choices.map((c: { value: string }) => c.value), ["allow", "deny", "ask"]);
        return new Response(JSON.stringify({ answers: [{ ...decision, name: "permission", probabilities: Object.entries(decision.probabilities).map(([value, probability]) => ({ value, probability })) }] }));
      }) as typeof fetch;
      const stage = { type: "decision" as const, model: "openai/gpt-6-luna", apiKeyEnv: "AUTO_MODE_TEST_KEY" };
      assert.equal((await decisionStage(stage, request, defaultPolicy(), fetcher)).decision, "allow");
      assert.equal((await decisionStage(stage, request, defaultPolicy(), mock({ answers: [{ type: "refusal", name: "permission" }] }))).decision, "abstain");
      assert.equal((await decisionStage(stage, request, defaultPolicy(), mock({ answers: [{ ...decision, name: "other" }] }))).decision, "abstain");
    } finally { delete process.env.AUTO_MODE_TEST_KEY; }
  });
  it("abstains on invalid or contradictory answers and oversized bodies", async () => {
    for (const invalid of [null, { ...decision, choice: ["allow"] }, { ...decision, choice: "ALLOW" },
      { ...decision, confidence: "1" }, { ...decision, confidence: 2 },
      { ...decision, probabilities: { allow: 1, deny: 1, ask: 1 } },
      { ...decision, probabilities: { allow: 0.1, deny: 0.9, ask: 0 } },
      { ...decision, probabilities: { allow: 1 } }])
      assert.equal((await decisionStage({ type: "decision", model: "laya/local" }, request, defaultPolicy(), mock(systemone(invalid)))).decision, "abstain");
    assert.equal((await decisionStage({ type: "decision", model: "laya/local" }, request, defaultPolicy(), mock({ text: "x".repeat(70_000) }))).decision, "abstain");
    assert.equal((await decisionStage({ type: "decision", model: "laya/local" }, { ...request, resources: ["x".repeat(70_000)] }, defaultPolicy(), () => { throw new Error("must not fetch"); })).decision, "abstain");
  });
  it("reports malformed responses as invalid-output and provider failures as provider", async () => {
    const malformed = await decisionStage({ type: "decision", model: "laya/local" }, request, defaultPolicy(), mock(systemone({ ...decision, confidence: 2 })));
    assert.equal(malformed.decision, "abstain");
    assert.equal(malformed.errorKind, "invalid-output");
    const oversized = await decisionStage({ type: "decision", model: "laya/local" }, request, defaultPolicy(), mock({ text: "x".repeat(70_000) }));
    assert.equal(oversized.errorKind, "invalid-output");
    const unauthorized = await decisionStage({ type: "decision", model: "laya/local" }, request, defaultPolicy(),
      (async () => { throw new Error("Invalid API key"); }) as typeof fetch);
    assert.equal(unauthorized.decision, "abstain");
    assert.equal(unauthorized.errorKind, "provider");
  });
  it("abstains on low-confidence allows and asks on low-confidence denies", async () => {
    assert.equal((await decisionStage({ type: "decision", model: "laya/local" }, request, defaultPolicy(), mock(systemone({ ...decision, confidence: 0.5 })))).decision, "abstain");
    const lowConfidenceDeny = { type: "choice", choice: "deny", confidence: 0.5, probabilities: { deny: 0.5, allow: 0.25, ask: 0.25 } };
    assert.equal((await decisionStage({ type: "decision", model: "laya/local" }, request, defaultPolicy(), mock(systemone(lowConfidenceDeny)))).decision, "ask");
    const explicitAsk = { type: "choice", choice: "ask", confidence: 0.1, probabilities: { ask: 0.5, allow: 0.25, deny: 0.25 } };
    assert.equal((await decisionStage({ type: "decision", model: "laya/local" }, request, defaultPolicy(), mock(systemone(explicitAsk)))).decision, "ask");
  });
  it("abstains when credentials are absent", async () => {
    const key = process.env.TYPESAFE_API_KEY;
    delete process.env.TYPESAFE_API_KEY;
    try {
      const result = await decisionStage({ type: "decision", model: "typesafe-ai/jev-latest" }, request, defaultPolicy(), () => {
        throw new Error("must not fetch");
      });
      assert.equal(result.decision, "abstain");
      assert.equal(result.errorKind, "provider");
    } finally {
      if (key !== undefined) process.env.TYPESAFE_API_KEY = key;
    }
  });
  it("rejects redirects and times out a local HTTP body", async () => {
    let redirect = true;
    let requests = 0;
    const server = createServer((_req, res) => {
      requests++;
      if (redirect) { res.writeHead(302, { location: "/other" }); res.end(); }
      else { res.writeHead(200, { "content-type": "application/json" }); res.write('{"answers":'); }
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address();
    assert.ok(address && typeof address !== "string");
    const endpoint = `http://127.0.0.1:${address.port}/v1/systemone`;
    try {
      assert.equal((await decisionStage({ type: "decision", model: "laya/local", endpoint }, request, defaultPolicy())).decision, "abstain");
      assert.equal(requests, 1);
      redirect = false;
      assert.equal((await decisionStage({ type: "decision", model: "laya/local", endpoint, timeoutMs: 30 }, request, defaultPolicy())).decision, "abstain");
    } finally { server.closeAllConnections(); server.close(); }
  });
});
