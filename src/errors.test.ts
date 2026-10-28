import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { errorKindOf, ReviewFailure, type ReviewErrorKind } from "./errors.js";

describe("review error categories", () => {
  it("keeps provider timeouts separate from user cancellations", async () => {
    const signal = AbortSignal.timeout(1);
    const reason = await new Promise<unknown>((resolve) => {
      signal.addEventListener("abort", () => resolve(signal.reason), { once: true });
    });
    assert.equal((reason as Error).name, "TimeoutError");
    assert.equal(errorKindOf(reason), "timeout");
    assert.equal(errorKindOf(new DOMException("The operation was aborted.", "AbortError")), "cancelled");
    assert.equal(errorKindOf(new Error("request aborted by user")), "cancelled");
  });
  it("preserves every explicit review failure category", () => {
    const kinds: ReviewErrorKind[] = ["deadline", "timeout", "cancelled", "provider", "invalid-output", "context"];
    for (const kind of kinds) assert.equal(errorKindOf(new ReviewFailure(kind, "bounded")), kind);
  });
  it("classifies malformed output and unknown provider failures", () => {
    assert.equal(errorKindOf(new ReviewFailure("invalid-output", "Invalid decision response")), "invalid-output");
    assert.equal(errorKindOf(new Error("wrapped", { cause: new ReviewFailure("invalid-output", "Invalid decision response") })), "invalid-output");
    assert.equal(errorKindOf(new Error("Invalid API key")), "provider");
    assert.equal(errorKindOf(new Error("Invalid decision response")), "provider");
    assert.equal(errorKindOf(new Error("connection refused")), "provider");
    assert.equal(errorKindOf("not an error"), "provider");
  });
});
