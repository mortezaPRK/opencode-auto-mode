/** Stable, bounded categories for a review that could not reach a confident decision. */
export type ReviewErrorKind = "deadline" | "timeout" | "cancelled" | "provider" | "invalid-output" | "context";

export class ReviewFailure extends Error {
  constructor(readonly kind: ReviewErrorKind, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "ReviewFailure";
  }
}

/** Maps arbitrary thrown values to a bounded category without exposing provider text. */
export function errorKindOf(error: unknown): ReviewErrorKind {
  if (error instanceof ReviewFailure) return error.kind;
  const name = error instanceof Error ? error.name : "";
  const message = error instanceof Error ? error.message : "";
  // AbortSignal.timeout() aborts with a TimeoutError whose message also says
  // "aborted"; a provider's own timeout is not a user interruption.
  if (name === "TimeoutError" ||
      (typeof DOMException === "function" && error instanceof DOMException && error.code === DOMException.TIMEOUT_ERR)) return "timeout";
  if (name === "AbortError" || /abort|cancel/i.test(message)) return "cancelled";
  if (/timeout|timed out/i.test(message)) return "timeout";
  if (/invalid|too large|unexpected/i.test(message)) return "invalid-output";
  return "provider";
}
