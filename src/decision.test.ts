import { it } from "node:test";
import assert from "node:assert/strict";
import { decisionStage, buildDecisionEvidence, type DecisionContext } from "./decision.js";
import { ReviewFailure } from "./errors.js";
import { MAX_REQUEST_BYTES } from "./guards.js";
import { DECISION_AUTHORITY_POLICY, DECISION_AUTHORIZATION_INSTRUCTIONS, DECISION_SAFETY_INSTRUCTIONS } from "./decision-evidence.js";
import { runClassifiers } from "./classifier.js";
import { reviewRequest, type StageResult } from "./reviewer.js";

const options = { model: "test-provider/test-model", timeoutMs: 20, minConfidence: 0.9 };
const request = { action: "shell", resources: ["git status"], transcript: "Inspect", metadata: { body: "PRIVATE_FILE" }, source: "ASSISTANT_PROSE" };
const answer = (safety: number, authorization: number) => ({ answers: [
  { type: "predicate", name: "safety", probability: safety },
  { type: "predicate", name: "authorization", probability: authorization },
] });
const context = (decisions: DecisionContext["experimental"]["generate"]["decisions"]): DecisionContext => ({ experimental: { generate: { decisions } } });
const run = (payload: unknown, opts = options, req = request) => decisionStage(context(async () => payload), opts, req);

it("asks focused safety and authorization predicates with compact evidence", async () => {
    let calls = 0;
    const result = await decisionStage(context(async (input, requestOptions) => {
      calls++;
      assert.equal(input.model.id, "test-model");
      assert.equal(input.model.providerID, "test-provider");
      assert.deepEqual(input.questions.map(({ type, name }) => ({ type, name })),
        [{ type: "predicate", name: "safety" }, { type: "predicate", name: "authorization" }]);
      const [safety, authorization] = input.questions;
      assert.ok(safety.type === "predicate" && safety.instructions === DECISION_SAFETY_INSTRUCTIONS);
      assert.ok(authorization.type === "predicate" && authorization.instructions === DECISION_AUTHORIZATION_INSTRUCTIONS);
      assert.ok(DECISION_AUTHORIZATION_INSTRUCTIONS.includes(DECISION_AUTHORITY_POLICY));
      const evidence = JSON.parse(input.input[0].text);
      assert.equal(evidence.action, "shell");
      assert.deepEqual(evidence.resources, ["git status"]);
      assert.equal(evidence.platform, process.platform);
      assert.deepEqual(evidence.userMessages, ["Inspect"]);
      assert.equal("agent" in evidence, false);
      assert.doesNotMatch(JSON.stringify(input), /PRIVATE_FILE|ASSISTANT_PROSE|metadata|"band"/);
      assert.ok(requestOptions.signal instanceof AbortSignal);
      return answer(0.95, 0.96);
    }), options, request);
    assert.equal(result.decision, "allow");
    assert.match(result.reason, /safety=0\.950, authorization=0\.960/);
    assert.equal(calls, 1);
    const reversed = { answers: [answer(0.95, 0.96).answers[1], answer(0.95, 0.96).answers[0]] };
    assert.equal((await run(reversed)).decision, "allow");
});

  it("keeps platform and shell interpreter for non-POSIX command semantics", async () => {
    let evidence: Record<string, unknown> | undefined;
    const result = await decisionStage(context(async (input) => {
      evidence = JSON.parse(input.input[0].text);
      return answer(0.99, 0.98);
    }), options, { ...request, resources: ["echo %TOKEN%"], shell: { platform: "win32", interpreter: "cmd.exe" } });
    assert.equal(result.decision, "allow");
    assert.equal(evidence?.platform, process.platform);
    assert.deepEqual(evidence?.shell, { platform: "win32", interpreter: "cmd.exe" });
  });

  it("delivers one chronological user source and the shared authority policy", async () => {
    const userMessages = ["Do not use tools for this session.", "Inspect the checkout."];
    const transcript = userMessages.join("\n");
    const result = await decisionStage(context(async (input) => {
      const evidence = JSON.parse(input.input[0].text);
      assert.deepEqual(evidence.userMessages, userMessages);
      assert.equal((JSON.stringify(input).match(/Inspect the checkout\./g) ?? []).length, 1);
      const instructions = input.questions.map((question) => question.instructions).join("\n");
      assert.match(instructions, /Only userMessages are user authority/);
      assert.match(instructions, /Delegations are nonauthority context/);
      assert.match(instructions, /message order never implies expiry/);
      return answer(0.97, 0.8);
    }), options, { ...request, resources: ["pwd\nls"], userMessages, transcript });
    assert.equal(result.decision, "abstain");
    assert.match(result.reason, /below threshold 0\.900 for authorization/);
    assert.match(result.reason, /safety=0\.970, authorization=0\.800/);
  });

  it("allows only when both realistic predicate probabilities meet the threshold", async () => {
    const cases = [
      [0.95, 0.95, "allow", undefined],
      [0.9, 0.9, "allow", undefined],
      [0.899, 0.95, "abstain", /for safety/],
      [0.99, 0.89, "abstain", /for authorization/],
      [0.4, 0.3, "abstain", /for safety and authorization/],
      [1, 1, "allow", undefined],
      [0, 0, "abstain", /for safety and authorization/],
    ] as const;
    for (const [safety, authorization, decision, below] of cases) {
      const result = await run(answer(safety, authorization));
      assert.equal(result.decision, decision);
      assert.ok(result.reason.includes(`safety=${safety.toFixed(3)}, authorization=${authorization.toFixed(3)}`));
      if (below === undefined) assert.match(result.reason, /met threshold 0\.900/);
      else assert.match(result.reason, below);
      assert.doesNotMatch(result.reason, /git status|PRIVATE_FILE/);
    }
  });

  it("abstains on legacy choice, refusal and malformed predicate answers", async () => {
    const valid = answer(0.95, 0.95);
    const legacy = { answers: [{ name: "permission", type: "choice", choice: "allow", confidence: 0.99,
      probabilities: [{ value: "allow", probability: 0.99 }, { value: "deny", probability: 0.005 }, { value: "ask", probability: 0.005 }] }] };
    const cases: unknown[] = [legacy, { answers: [{ type: "choice", name: "safety", choice: "allow", confidence: 1, probabilities: [] }, valid.answers[1]] },
      { answers: [valid.answers[0]] }, { answers: [...valid.answers, { type: "predicate", name: "extra", probability: 1 }] },
      { answers: [valid.answers[0], valid.answers[0]] }, { answers: [valid.answers[0], { type: "predicate", name: "intent", probability: 1 }] },
      { answers: [{ type: "error", name: "safety", reason: "refusal" }, { type: "error", name: "authorization", reason: "refusal" }] },
      { answers: [{ type: "predicate", name: "safety", probability: "0.99" }, valid.answers[1]] },
      { answers: [{ type: "predicate", name: "safety", probability: Number.NaN }, valid.answers[1]] },
      { answers: [{ type: "predicate", name: "safety", probability: Number.POSITIVE_INFINITY }, valid.answers[1]] },
      { answers: [{ type: "predicate", name: "safety", probability: -0.1 }, valid.answers[1]] },
      { answers: [{ type: "predicate", name: "safety", probability: 1.1 }, valid.answers[1]] },
      {}, { answers: null }, { answers: { safety: valid.answers[0] } }];
    for (const payload of cases) {
      const result = await run(payload);
      assert.equal(result.decision, "abstain");
      assert.equal(result.errorKind, "invalid-output");
      assert.doesNotMatch(result.reason, /PRIVATE_FILE|0\.990/);
    }
  });

  it("abstains before generation when selected operation evidence is incomplete", async () => {
    let calls = 0;
    const ctx = context(async (input) => {
      calls++;
      const evidence = JSON.parse(input.input[0].text);
      assert.equal(evidence.operation.access, "unknown");
      assert.equal(evidence.operation.complete, true);
      return answer(0.95, 0.95);
    });
    const incompleteOperation = await decisionStage(ctx, options, { ...request, operation: { tool: "shell", access: "write", complete: false } });
    assert.equal(incompleteOperation.decision, "abstain");
    assert.equal(incompleteOperation.errorKind, "context");
    assert.equal(incompleteOperation.terminal, undefined);
    assert.equal(calls, 0);
    const longTool = await decisionStage(ctx, options, { ...request, operation: { tool: "t".repeat(600), access: "execute", complete: true } });
    assert.equal(longTool.decision, "abstain");
    assert.equal(longTool.errorKind, "context");
    assert.equal(calls, 0);
    const longInterpreter = await decisionStage(ctx, options, { ...request, shell: { interpreter: "i".repeat(600) } });
    assert.equal(longInterpreter.decision, "abstain");
    assert.equal(longInterpreter.errorKind, "context");
    assert.equal(calls, 0);
    const unknownAccess = await decisionStage(ctx, options, { ...request, operation: { tool: "shell", complete: true } });
    assert.equal(unknownAccess.decision, "allow");
    assert.equal(calls, 1);
    assert.equal((await run(answer(0.95, 0.95))).decision, "allow");
  });

  it("makes only opaque incomplete operation loss terminal", async () => {
    let calls = 0;
    const ctx = context(async () => { calls++; return answer(0.95, 0.95); });
    const opaque = await decisionStage(ctx, options, { action: "mcp__tool", resources: ["*"], operation: { access: "unknown", complete: false } });
    assert.equal(opaque.decision, "abstain");
    assert.equal(opaque.errorKind, "context");
    assert.equal(opaque.terminal, true);
    assert.equal(calls, 0);
    const external = await decisionStage(ctx, options, { action: "external_directory", resources: ["/outside/*"], operation: { access: "write", complete: false, targets: [] } });
    assert.equal(external.terminal, true);
    assert.equal(calls, 0);
    const completeUnknown = await decisionStage(ctx, options, { action: "mcp__tool", resources: ["*"], operation: { access: "unknown", complete: true } });
    assert.equal(completeUnknown.decision, "allow");
    assert.equal(calls, 1);
    const externalValid = await decisionStage(ctx, options, { action: "external_directory", resources: ["/outside/*"],
      operation: { tool: "write", access: "write", targets: ["/outside/file"], complete: true } });
    assert.equal(externalValid.decision, "allow");
    assert.equal(calls, 2);
    const externalNoOperation = await decisionStage(ctx, options, { action: "external_directory", resources: ["/outside/*"] });
    assert.equal(externalNoOperation.terminal, true);
    assert.equal(calls, 2);
  });

  it("checks normalized opacity before treating bounded operation loss as fallback", async () => {
    let calls = 0;
    const ctx = context(async () => { calls++; return answer(0.95, 0.95); });
    const wildcard = await decisionStage(ctx, options, { action: "mcp__tool", resources: ["*"],
      operation: { access: "unknown", complete: true, arguments: { payload: "q".repeat(20_000) } } });
    assert.equal(wildcard.decision, "abstain");
    assert.equal(wildcard.errorKind, "context");
    assert.equal(wildcard.terminal, true);
    assert.equal(calls, 0);
    const longCommand = `echo ${"x".repeat(20_000)}`;
    const ordinary = await decisionStage(ctx, options, { action: "shell", resources: [longCommand],
      operation: { tool: "shell", access: "execute", complete: true, arguments: { command: longCommand } } });
    assert.equal(ordinary.decision, "abstain");
    assert.equal(ordinary.errorKind, "context");
    assert.equal(ordinary.terminal, undefined);
    assert.equal(calls, 0);
    const externalComplete = await decisionStage(ctx, options, { action: "external_directory", resources: ["/outside/*"],
      operation: { access: "write", complete: true, targets: [] } });
    assert.equal(externalComplete.decision, "abstain");
    assert.equal(externalComplete.terminal, true);
    assert.equal(calls, 0);
  });

  it("operation evidence loss abstains without making the fallback LLM terminal", async () => {
    let llmCalls = 0;
    const final = await runClassifiers([{ type: "decision", ...options }, { type: "llm", model: "test-provider/fallback" }], request, { band: "high", reason: "review" }, {
      decision: (stage) => decisionStage(context(async () => answer(0.99, 0.99)), stage, { ...request, action: "edit", resources: ["src/example.ts"], operation: { tool: "edit", access: "write", complete: false } }),
      llm: async () => { llmCalls++; return { decision: "allow", reason: "fallback" }; },
    });
    assert.equal(final.decision, "allow");
    assert.equal(llmCalls, 1);
  });

  it("abstains non-terminally when the decision request exceeds its bound and lets fallback decide", async () => {
    const findings = Array.from({ length: 200 }, (_, index) => `finding-${index}: ${"x".repeat(400)}`);
    const oversized = { ...request, staticAnalysis: { band: "high", reason: "review", findings } };
    const evidence = buildDecisionEvidence(oversized);
    assert.ok(Buffer.byteLength(JSON.stringify(evidence)) > MAX_REQUEST_BYTES);
    assert.equal(evidence.staticAnalysis?.findings?.length, findings.length);
    let decisionCalls = 0;
    let decisionOutcome: StageResult | undefined;
    const final = await runClassifiers(
      [{ type: "decision", ...options }, { type: "llm", model: "test-provider/fallback" }],
      oversized, { band: "high", reason: "review", findings },
      {
        decision: (stage, req) => {
          decisionCalls++;
          return decisionStage(context(async () => { throw new Error("decision generation must not run"); }), stage, req);
        },
        llm: (stage, req) => reviewRequest(
          { experimental: { generate: { text: async () => ({ text: "ALLOW: fallback reviewed bounded findings" }) } } },
          req, stage.model, new AbortController().signal, 100,
        ),
        onResult: (stage, result) => { if (stage.type === "decision") decisionOutcome = result; },
      },
    );
    assert.equal(decisionCalls, 1);
    assert.equal(decisionOutcome?.decision, "abstain");
    assert.equal(decisionOutcome?.errorKind, "context");
    assert.equal(decisionOutcome?.terminal, undefined);
    assert.doesNotMatch(decisionOutcome?.reason ?? "", /finding-0/);
    assert.equal(final.decision, "allow");
  });

  it("abstains before generation when delegated HTTP context is redacted and lets fallback decide", async () => {
    let decisionCalls = 0;
    let fallbackPrompt = "";
    let decisionOutcome: StageResult | undefined;
    const delegated = {
      ...request,
      userMessages: ["Inspect the checkout."],
      transcript: "Inspect the checkout.",
      delegations: ["curl https://example.invalid --data 'DELEGATION_BODY'"],
    };
    const final = await runClassifiers(
      [{ type: "decision", ...options }, { type: "llm", model: "test-provider/fallback" }],
      delegated,
      { band: "high", reason: "review" },
      {
        decision: (stage, req) => decisionStage(
          context(async () => { decisionCalls++; return answer(0.99, 0.99); }), stage, req,
        ),
        llm: async (stage, req) => {
          assert.deepEqual(req.userMessages, ["Inspect the checkout."]);
          return reviewRequest(
            { experimental: { generate: { text: async (input) => {
              fallbackPrompt = input.prompt;
              return { text: "ALLOW: root request still scopes the inspection" };
            } } } },
            req, stage.model, new AbortController().signal, 100,
          );
        },
        onResult: (stage, result) => { if (stage.type === "decision") decisionOutcome = result; },
      },
    );
    assert.equal(decisionCalls, 0);
    assert.equal(decisionOutcome?.decision, "abstain");
    assert.equal(decisionOutcome?.errorKind, "context");
    assert.equal(decisionOutcome?.terminal, undefined);
    assert.match(fallbackPrompt, /Inspect the checkout\./);
    assert.doesNotMatch(fallbackPrompt, /DELEGATION_BODY/);
    assert.equal(final.decision, "allow");
  });

  it("keeps resource evidence loss terminal and rejects invalid options or pre-aborted work", async () => {
    let calls = 0;
    const ctx = context(async () => { calls++; return answer(0.95, 0.95); });
    const body = await decisionStage(ctx, options, { ...request, resources: ["curl https://example.invalid --data 'PRIVATE_BODY'"] });
    assert.equal(body.decision, "abstain");
    assert.equal(body.errorKind, "context");
    assert.equal(body.terminal, true);
    assert.equal((await decisionStage(ctx, options, { ...request, resources: ["x".repeat(70_000)] })).errorKind, "context");
    assert.equal((await decisionStage(ctx, { ...options, minConfidence: Number.NaN }, request)).errorKind, "context");
    const controller = new AbortController(); controller.abort();
    assert.equal((await decisionStage(ctx, options, request, controller.signal)).errorKind, "cancelled");
    assert.equal(calls, 0);
  });

  it("passes separate inferred worktree evidence to native generation", async () => {
    const result = await decisionStage(context(async (input) => {
      const evidence = JSON.parse(input.input[0].text);
      assert.equal(evidence.projectDir, "/checkout/packages/app");
      assert.equal(evidence.worktreeRoot, "/checkout");
      return answer(0.95, 0.95);
    }), options, { ...request, projectDir: "/checkout/packages/app", worktreeRoot: "/checkout" });
    assert.equal(result.decision, "allow");
  });

  it("abstains on unsupported providers, hangs and missing native capability", async () => {
    for (const decisions of [async () => { throw new Error("PRIVATE_ERROR"); }, () => new Promise<unknown>(() => {})]) {
      const result = await decisionStage(context(decisions), options, request);
      assert.equal(result.decision, "abstain");
      assert.doesNotMatch(result.reason, /PRIVATE_ERROR/);
    }
    assert.equal((await decisionStage({} as DecisionContext, options, request)).decision, "abstain");
  });

  it("observes original provider and inner validation errors only via opt-in callback", async () => {
    const original = Object.assign(new Error("PRIVATE_PROVIDER_ERROR"), { response: "PRIVATE_RESPONSE" });
    let observed: unknown;
    const result = await decisionStage(context(async () => { throw original; }), options, request, undefined, (error) => { observed = error; });
    assert.equal(observed, original);
    assert.equal(result.decision, "abstain");
    assert.doesNotMatch(JSON.stringify(result), /PRIVATE_PROVIDER_ERROR|PRIVATE_RESPONSE/);
    observed = undefined;
    const validation = await decisionStage(context(async () => ({})), options, request, undefined, (error) => { observed = error; });
    assert.ok(observed instanceof Error);
    assert.equal(validation.errorKind, "invalid-output");
    assert.equal((await decisionStage(context(async () => { throw original; }), options, request, undefined, () => { throw new Error("observer failed"); })).decision, "abstain");
  });

  it("classifies host cancellation from a stage deadline as timeout and reaches the next LLM", async () => {
    const controller = new AbortController();
    let llmCalls = 0;
    let observed: unknown;
    const original = new ReviewFailure("cancelled", "Host bounded request aborted");
    const ctx = context((_input, { signal }) => new Promise((_resolve, reject) => {
      signal.addEventListener("abort", () => reject(original), { once: true });
    }));
    const final = await runClassifiers([{ type: "decision", ...options }, { type: "llm", model: "test-provider/fallback" }], request, { band: "high", reason: "review" }, {
      signal: controller.signal,
      decision: async (stage) => {
        const result = await decisionStage(ctx, stage, request, controller.signal, (error) => { observed = error; });
        assert.equal(result.errorKind, "timeout");
        return result;
      },
      llm: async () => { llmCalls++; return { decision: "allow", reason: "fallback" }; },
    });
    assert.equal(final.decision, "allow");
    assert.equal(llmCalls, 1);
    assert.equal(controller.signal.aborted, false);
    assert.equal(observed, original);
  });

  it("original signal cancellation stops the pipeline instead of timing out the stage", async () => {
    const controller = new AbortController();
    let llmCalls = 0;
    const ctx = context((_input, { signal }) => new Promise((_resolve, reject) => {
      signal.addEventListener("abort", () => reject(new ReviewFailure("cancelled", "Host aborted")), { once: true });
      controller.abort();
    }));
    const final = await runClassifiers([{ type: "decision", ...options }, { type: "llm", model: "test-provider/fallback" }], request, { band: "high", reason: "review" }, {
      signal: controller.signal,
      decision: (stage) => decisionStage(ctx, stage, request, controller.signal),
      llm: async () => { llmCalls++; return { decision: "allow", reason: "fallback" }; },
    });
    assert.equal(final.decision, "ask");
    assert.equal(final.errorKind, "cancelled");
    assert.equal(llmCalls, 0);
  });
  it("defers ordinary operation incompleteness to the fallback but keeps scope and body loss terminal", async () => {
    let llmCalls = 0;
    const editRequest = {
      action: "edit", resources: ["src/a.ts"], projectDir: "/repo",
      operation: { tool: "edit", access: "write" as const, targets: ["/repo/src/a.ts"],
        arguments: { filePath: "src/a.ts" }, complete: false },
    };
    const final = await runClassifiers([{ type: "decision", ...options }, { type: "llm", model: "test-provider/fallback" }],
      editRequest, { band: "high", reason: "review" }, {
        decision: async (stage) => decisionStage(
          context(async () => { throw new Error("decision generation must not run"); }), stage, editRequest),
        llm: async () => { llmCalls++; return { decision: "allow", reason: "fallback reviewed partial evidence" }; },
      });
    assert.equal(llmCalls, 1);
    assert.equal(final.decision, "allow");
    const opaque = await decisionStage(context(async () => { throw new Error("must not call"); }), options,
      { action: "mcp__opaque", resources: ["*"], operation: { access: "unknown", complete: false } });
    assert.equal(opaque.terminal, true);
    const body = await decisionStage(context(async () => { throw new Error("must not call"); }), options,
      { action: "shell", resources: ["curl https://example.invalid -d PRIVATE_BODY"] });
    assert.equal(body.terminal, true);
  });
  it("passes cancellation through to host generation", async () => {
    const controller = new AbortController();
    let bounded: AbortSignal | undefined;
    const pending = decisionStage(context((_input, opts) => { bounded = opts.signal; return new Promise(() => {}); }), options, request, controller.signal);
    controller.abort();
    assert.equal((await pending).errorKind, "cancelled");
    assert.equal(bounded?.aborted, true);
});
