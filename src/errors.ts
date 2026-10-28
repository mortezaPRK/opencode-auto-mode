/** Stable, bounded categories for a review that could not reach a confident decision. */
export type ReviewErrorKind = "deadline" | "timeout" | "cancelled" | "provider" | "invalid-output" | "context";

export class ReviewFailure extends Error {
  constructor(readonly kind: ReviewErrorKind, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "ReviewFailure";
  }
}

/** Finds an explicit category even when a provider library wraps our failure. */
function explicitKind(error: unknown): ReviewErrorKind | undefined {
  let current = error;
  for (let depth = 0; depth < 4; depth++) {
    if (current instanceof ReviewFailure) return current.kind;
    if (typeof current !== "object" || current === null) return undefined;
    const cause = (current as { cause?: unknown }).cause;
    if (cause === undefined || cause === current) return undefined;
    current = cause;
  }
  return undefined;
}

/** Maps arbitrary thrown values to a bounded category without exposing provider text. */
export function errorKindOf(error: unknown): ReviewErrorKind {
  // Only ReviewFailure marks malformed reviewer output. Provider text such as
  // "Invalid API key" stays a provider failure even when a wrapper reuses it.
  const explicit = explicitKind(error);
  if (explicit !== undefined) return explicit;
  const name = error instanceof Error ? error.name : "";
  const message = error instanceof Error ? error.message : "";
  // AbortSignal.timeout() aborts with a TimeoutError whose message also says
  // "aborted"; a provider's own timeout is not a user interruption.
  if (name === "TimeoutError" ||
      (typeof DOMException === "function" && error instanceof DOMException && error.code === DOMException.TIMEOUT_ERR)) return "timeout";
  if (name === "AbortError" || /abort|cancel/i.test(message)) return "cancelled";
  if (/timeout|timed out/i.test(message)) return "timeout";
  return "provider";
}
