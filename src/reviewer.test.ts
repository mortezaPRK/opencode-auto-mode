import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { buildReviewPrompt, parseDecision, reviewRequest, type ReviewerContext } from "./reviewer.js";
import { ReviewFailure } from "./errors.js";
import { runClassifiers } from "./classifier.js";

const context = (text: ReviewerContext["experimental"]["generate"]["text"]): ReviewerContext => ({ experimental: { generate: { text } } });
const model = ["test-provider", "test-model"].join("/");
const request = { action: "shell", resources: ["git status"], transcript: "Inspect the tree", gitState: { branch: "work", clean: true } };

describe("reviewer deny-gate", () => {
  it("serializes only selected evidence, never metadata/source", () => {
    const prompt = buildReviewPrompt({ ...request, metadata: { content: "PRIVATE_FILE" }, source: "ASSISTANT_PROSE" });
    assert.doesNotMatch(prompt, /PRIVATE_FILE|ASSISTANT_PROSE|metadata/);
    assert.match(prompt, /Inspect the tree/);
    assert.match(prompt, /gitState/);
    assert.doesNotMatch(prompt, /ASK:/);
  });
  it("preserves completed acknowledgment-only chronology and exact pending scope in prompt evidence", () => {
    const transcript = "For the acknowledgment turn only, do not use tools. After I confirm it is complete, run exactly pwd followed by ls.\nThe acknowledgment turn is complete; run the previously authorized commands now.";
    const prompt = buildReviewPrompt({ ...request, resources: ["pwd\nls"], transcript, metadata: { validationOnly: true } });
    const evidence = JSON.parse(prompt.split("\n")[2]);
    assert.equal(evidence.userInstruction, transcript);
    assert.deepEqual(evidence.resources, ["pwd\nls"]);
    assert.doesNotMatch(prompt, /validationOnly/);
    assert.match(prompt, /restriction explicitly limited to an earlier acknowledgment or response-only turn from an ongoing prohibition/);
    assert.match(prompt, /user excerpt clearly establishes that the earlier limited restriction has been fulfilled/);
    assert.match(prompt, /otherwise safe, explicitly authorized pending action/);
    assert.match(prompt, /queued or pending action is not itself authorization/);
  });
  it("preserves ongoing prohibitions and requires review for conflicting or ambiguous temporal scope", () => {
    for (const transcript of [
      "Do not use tools for this session.\nInspect the checkout.",
      "For the acknowledgment turn only, do not use tools.\nInspect the checkout.",
      "Do not use tools for this session.\nRun exactly pwd followed by ls now.",
    ]) {
      const prompt = buildReviewPrompt({ ...request, resources: ["pwd\nls"], transcript });
      assert.equal(JSON.parse(prompt.split("\n")[2]).userInstruction, transcript);
      assert.match(prompt, /Do not assume a restriction has expired from message order alone/);
      assert.match(prompt, /Never reinterpret a persistent or currently applicable prohibition as acknowledgment-only/);
      assert.match(prompt, /never treat the latest message as a blanket override/);
      assert.match(prompt, /Conflicting instructions or ambiguous temporal scope require human review, not a confident allow or deny verdict/);
    }
  });
  it("includes inferred worktree root separately from the evaluated working directory", () => {
    const prompt = buildReviewPrompt({ ...request, projectDir: "/checkout/packages/app", worktreeRoot: "/checkout" });
    assert.match(prompt, /"projectDir":"\/checkout\/packages\/app"/);
    assert.match(prompt, /"worktreeRoot":"\/checkout"/);
    assert.doesNotMatch(buildReviewPrompt(request), /worktreeRoot/);
  });
  it("observes original provider and validation exceptions without exposing details", async () => {
    const original = Object.assign(new Error("PRIVATE_PROVIDER_ERROR"), { response: "PRIVATE_RESPONSE" });
    let observed: unknown;
    const result = await reviewRequest(context(async () => { throw original; }), request, model, new AbortController().signal, 100, (error) => { observed = error; });
    assert.equal(observed, original);
    assert.equal(result.decision, "ask");
    assert.doesNotMatch(JSON.stringify(result), /PRIVATE_PROVIDER_ERROR|PRIVATE_RESPONSE/);
    observed = undefined;
    const validation = await reviewRequest(context(async () => { throw new Error("must not call"); }), request, "", new AbortController().signal, 100, (error) => { observed = error; });
    assert.ok(observed instanceof Error);
    assert.equal(validation.errorKind, "context");
    assert.equal((await reviewRequest(context(async () => { throw original; }), request, model, new AbortController().signal, 100, () => { throw new Error("error observer failed"); })).decision, "ask");
  });
  it("omits inline HTTP bodies from prompts and asks rather than approving incomplete evidence", async () => {
    let calls = 0;
    const ctx = context(async () => { calls++; return { text: "ALLOW: safe" }; });
    for (const resource of [
      "curl https://example.invalid/ --data-binary 'PRIVATE_FILE_CONTENT'",
      JSON.stringify({ command: 'curl https://example.invalid/ --json "PRIVATE_FILE_CONTENT"' }),
      "wget -e post_data=PRIVATE_FILE_CONTENT",
      "wget -epost_data=PRIVATE_FILE_CONTENT",
      "env wget -qe post_data=PRIVATE_FILE_CONTENT",
      "sh -c 'wget -qepost_data=PRIVATE_FILE_CONTENT'",
      JSON.stringify({ command: "wget --execute post_data=PRIVATE_FILE_CONTENT" }),
    ]) {
      const req = { ...request, resources: [resource] };
      assert.doesNotMatch(buildReviewPrompt(req), /PRIVATE_FILE_CONTENT/);
      assert.match(buildReviewPrompt(req), /incompleteEvidence/);
      assert.equal((await reviewRequest(ctx, req, model, new AbortController().signal, 100)).decision, "ask");
    }
    assert.equal(calls, 0);
    const program = "sh -c 'rm -rf /outside'";
    assert.match(buildReviewPrompt({ ...request, resources: [program] }), /rm -rf \/outside/);
  });
  it("reviews literal HTTP-client mentions without marking evidence incomplete", async () => {
    let calls = 0;
    const ctx = context(async () => { calls++; return { text: "ALLOW: safe literal output" }; });
    for (const resource of ["echo curl\nprintf -done", "echo 'curl --data not-a-body'", "printf '%s' 'wget --post-data not-a-body'"]) {
      const req = { ...request, resources: [resource] };
      assert.doesNotMatch(buildReviewPrompt(req), /incompleteEvidence|REDACTED/);
      assert.equal((await reviewRequest(ctx, req, model, new AbortController().signal, 100)).decision, "allow");
    }
    assert.equal(calls, 3);
  });
  it("accepts only allow/deny with one nonempty reason", () => {
    assert.deepEqual(parseDecision("ALLOW: safe"), { decision: "allow", reason: "safe" });
    // A legacy rule-id prefix is presentation text, stripped without being output.
    assert.deepEqual(parseDecision("DENY: [unsafe-delete] Delete is too broad; remove one file instead"),
      { decision: "deny", reason: "Delete is too broad; remove one file instead" });
    assert.deepEqual(parseDecision("ALLOW: [legacy-rule] safe"), { decision: "allow", reason: "safe" });
    for (const text of ["ALLOW", "ASK: unclear", "ALLOW: uncertain", "ALLOW: safe\nextra", "DENY:", "DENY: [only-a-rule]", "```ALLOW: safe```"])
      assert.equal(parseDecision(text).decision, "ask", text);
  });
  it("makes one configured reasoning call", async () => {
    let calls = 0;
    const ctx = context(async (input, options) => {
      calls++;
      assert.equal(input.model.id, "test-model");
      assert.ok(options.signal instanceof AbortSignal);
      return { text: "ALLOW: safe" };
    });
    assert.equal((await reviewRequest(ctx, request, model, new AbortController().signal, 100)).decision, "allow");
    assert.equal(calls, 1);
  });
  it("uses native experimental text even when a deprecated alias is present", async () => {
    let nativeCalls = 0;
    const ctx = {
      ...context(async () => { nativeCalls++; return { text: "ALLOW: native verdict" }; }),
      generate: { text: async () => { throw new Error("Deprecated alias must not be called"); } },
    };
    assert.equal((await reviewRequest(ctx, request, model, new AbortController().signal, 100)).decision, "allow");
    assert.equal(nativeCalls, 1);
  });
  it("fails closed on malformed output, exceptions, hangs and cancellation", async () => {
    const signal = new AbortController().signal;
    for (const text of [async () => ({ text: "oops" }), async () => { throw new Error("PRIVATE_ERROR"); }, () => new Promise<{text: string}>(() => {})]) {
      const result = await reviewRequest(context(text), request, model, signal, 10);
      assert.equal(result.decision, "ask");
      assert.doesNotMatch(result.reason, /PRIVATE_ERROR/);
    }
    const controller = new AbortController(); controller.abort();
    let calls = 0;
    const result = await reviewRequest(context(async () => { calls++; return { text: "ALLOW: safe" }; }), request, model, controller.signal, 100);
    assert.equal(result.errorKind, "cancelled");
    assert.equal(calls, 0);
  });
  it("local reviewer deadline advances to fallback despite a host cancelled exception", async () => {
    const controller = new AbortController();
    let calls = 0;
    const ctx = context((_input, { signal }) => new Promise((_resolve, reject) => {
      signal.addEventListener("abort", () => reject(new ReviewFailure("cancelled", "Host bounded request aborted")), { once: true });
    }));
    const final = await runClassifiers([{ type: "llm", model }, { type: "llm", model }], request, { band: "high", reason: "review" }, {
      signal: controller.signal,
      decision: async () => { throw new Error("must not call"); },
      llm: async () => {
        if (++calls === 2) return { decision: "allow", reason: "fallback" };
        const result = await reviewRequest(ctx, request, model, controller.signal, 10);
        assert.equal(result.errorKind, "timeout");
        return result;
      },
    });
    assert.equal(final.decision, "allow");
    assert.equal(calls, 2);
    assert.equal(controller.signal.aborted, false);
  });
  it("original reviewer signal cancellation stops before fallback", async () => {
    const controller = new AbortController();
    let calls = 0;
    const ctx = context((_input, { signal }) => new Promise((_resolve, reject) => {
      signal.addEventListener("abort", () => reject(new ReviewFailure("cancelled", "Host aborted")), { once: true });
      controller.abort();
    }));
    const final = await runClassifiers([{ type: "llm", model }, { type: "llm", model }], request, { band: "high", reason: "review" }, {
      signal: controller.signal,
      decision: async () => { throw new Error("must not call"); },
      llm: async () => { calls++; return reviewRequest(ctx, request, model, controller.signal, 100); },
    });
    assert.equal(final.decision, "ask");
    assert.equal(final.errorKind, "cancelled");
    assert.equal(calls, 1);
  });
  it("rejects oversized evidence and unconfigured models without calling generation", async () => {
    const ctx = context(async () => { throw new Error("must not call"); });
    assert.equal((await reviewRequest(ctx, { ...request, resources: ["x".repeat(70_000)] }, model, new AbortController().signal, 100)).errorKind, "context");
    assert.equal((await reviewRequest(ctx, request, "", new AbortController().signal, 100)).errorKind, "context");
  });
  it("never exposes raw provider responses in unclear results", async () => {
    const raw = { text: "unclear provider response", native: { debug: "RAW_DEBUG" } };
    const result = await reviewRequest(context(async () => raw), request, model, new AbortController().signal, 100);
    assert.equal(result.decision, "ask");
    assert.doesNotMatch(JSON.stringify(result), /RAW_DEBUG|unclear provider response/);
  });
  it("asks for a reason without rule identifiers and keeps bounded transcripts under the request limit", () => {
    const prompt = buildReviewPrompt({ ...request, transcript: "x".repeat(12_000) });
    assert.doesNotMatch(prompt, /rule-id/);
    assert.match(prompt, /ALLOW: <reason> or DENY: <reason and safer alternative>/);
    assert.ok(Buffer.byteLength(prompt) <= 65_536);
  });
});
