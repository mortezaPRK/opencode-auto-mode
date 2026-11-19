import type { Generate } from "@opencode/schema/generate";

/** Shared structural guards, probability parsing and question copying. */
export type ChoiceValue = string | boolean;

/** Native request bound, also capping one accepted text field. */
export const MAX_REQUEST_BYTES = 65_536;
/** Captured edit, script or argument payload bound. */
export const MAX_CAPTURED_BODY_BYTES = 16_384;

export const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

export const isProbability = (value: unknown): value is number =>
  typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1;

export const isChoiceValue = (value: unknown): value is ChoiceValue =>
  typeof value === "string" || typeof value === "boolean";

export const formatProbability = (value: number): string => value.toFixed(3);

function distributionEntry(
  entry: unknown,
  allowed: readonly ChoiceValue[],
  found: Map<ChoiceValue, number>,
): number | undefined {
  if (!isRecord(entry) || !isChoiceValue(entry.value) || !allowed.includes(entry.value) ||
      !isProbability(entry.probability) || found.has(entry.value)) return undefined;
  found.set(entry.value, entry.probability);
  return entry.probability;
}

/** Every allowed value exactly once, each in [0,1], summing to 1 within the
 * tolerance, with `selected` a maximum; undefined rather than renormalized. */
export function probabilityDistribution(
  entries: unknown,
  allowed: readonly ChoiceValue[],
  tolerance: number,
  selected: ChoiceValue,
): Map<ChoiceValue, number> | undefined {
  if (!Array.isArray(entries) || entries.length !== allowed.length) return undefined;
  const found = new Map<ChoiceValue, number>();
  let sum = 0;
  for (const entry of entries) {
    const probability = distributionEntry(entry, allowed, found);
    if (probability === undefined) return undefined;
    sum += probability;
  }
  if (found.size !== allowed.length || Math.abs(sum - 1) > tolerance) return undefined;
  const probability = found.get(selected);
  if (probability === undefined) return undefined;
  return probability >= Math.max(...found.values()) - tolerance ? found : undefined;
}

/** Deep-freezes a question so no caller can change the frozen checks. */
export function freezeQuestion<T extends Generate.DecisionQuestion>(question: T): T {
  const choices: unknown = (question as { choices?: unknown }).choices;
  if (Array.isArray(choices)) {
    for (const choice of choices) if (isRecord(choice)) Object.freeze(choice);
    Object.freeze(choices);
  }
  return Object.freeze(question) as T;
}

/** Fresh question objects per request: a provider hook cannot mutate later calls or checks. */
export function freshQuestion<T extends Generate.ChoiceQuestion>(question: T): T {
  return { ...question, choices: question.choices.map((choice) => ({ ...choice })) } as T;
}
