import { ReviewFailure } from "./errors.js";

/**
 * Bounds a provider promise and rejects it as soon as `signal` aborts.
 *
 * A provider may ignore the signal, so this wrapper settles on its own and
 * clears both its timer and abort listener on every path. Adding a listener to
 * an already-aborted signal never replays the abort, so check `aborted` after
 * subscribing or a cancelled fallback stage would wait for the full timeout.
 */
export function withTimeout<T>(promise: Promise<T>, ms: number, signal?: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const finish = (action: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      action();
    };
    const onAbort = () => finish(() => reject(new ReviewFailure("cancelled", "Review cancelled")));
    const timer = setTimeout(() => finish(() => reject(new ReviewFailure("timeout", "Review timed out"))), ms);
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) {
      onAbort();
      return;
    }
    promise.then((value) => finish(() => resolve(value)), (error) => finish(() => reject(error)));
  });
}
