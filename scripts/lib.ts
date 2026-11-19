import { isRecord } from "../src/guards.js";

export type Json = Record<string, unknown>;
export { isRecord };

/** Manifest- and audit-derived labels can carry newlines, ESC, or other control
 * characters. Human output must stay one inert line, so control characters
 * collapse to spaces before the label is bounded. */
export function printableLabel(value: string): string {
  const cleaned = Array.from(value, (char) => {
    const code = char.codePointAt(0)!;
    return code < 32 || (code >= 127 && code <= 159) ? " " : char;
  }).join("").replace(/\s+/g, " ").trim();
  return cleaned.length > 64 ? `${cleaned.slice(0, 61)}...` : cleaned;
}

export async function mapLimit<T, R>(items: readonly T[], concurrency: number, work: (item: T, index: number) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  const worker = async (): Promise<void> => {
    for (;;) {
      const index = next++;
      if (index >= items.length) return;
      results[index] = await work(items[index]!, index);
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, () => worker()));
  return results;
}

export type ArgFailure =
  | { kind: "unknown-option"; token: string }
  | { kind: "missing-value"; token: string }
  | { kind: "unexpected-value"; token: string }
  | { kind: "unexpected-positional"; token: string };

const QUOTED_TOKEN = /'([^']*)'/;

/** Normalizes node:util parseArgs throws: codes are stable, message wording is runtime-specific. */
export function argFailure(error: unknown): ArgFailure | undefined {
  if (!isRecord(error) || typeof error.code !== "string" || typeof error.message !== "string") return undefined;
  const token = QUOTED_TOKEN.exec(error.message)?.[1];
  if (token === undefined) return undefined;
  if (error.code === "ERR_PARSE_ARGS_UNKNOWN_OPTION") return { kind: "unknown-option", token };
  if (error.code === "ERR_PARSE_ARGS_UNEXPECTED_POSITIONAL") return { kind: "unexpected-positional", token };
  if (error.code !== "ERR_PARSE_ARGS_INVALID_OPTION_VALUE") return undefined;
  const option = token.replace(/\s+<value>$/, "");
  return { kind: error.message.includes("does not take an argument") ? "unexpected-value" : "missing-value", token: option };
}
