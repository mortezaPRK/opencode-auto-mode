import { it } from "node:test";
import assert from "node:assert/strict";
import { probabilityDistribution, type ChoiceValue } from "./guards.js";

const ALLOWED: readonly ChoiceValue[] = ["allow", "review"];
const TOLERANCE = 1e-6;

const entry = (value: unknown, probability: unknown): Record<string, unknown> =>
  ({ value, probability });

it("accepts only a complete, normalized distribution with the selected maximum", () => {
  const valid = probabilityDistribution(
    [entry("allow", 0.9), entry("review", 0.1)], ALLOWED, TOLERANCE, "allow");
  assert.deepEqual(valid, new Map<ChoiceValue, number>([["allow", 0.9], ["review", 0.1]]));

  const invalid: readonly (readonly [string, unknown])[] = [
    ["missing label", [entry("allow", 1)]],
    ["extra label", [entry("allow", 0.5), entry("review", 0.4), entry("other", 0.1)]],
    ["duplicate label", [entry("allow", 0.5), entry("allow", 0.5)]],
    ["out of range", [entry("allow", 1.2), entry("review", -0.2)]],
    ["sum too high", [entry("allow", 0.9), entry("review", 0.2)]],
    ["sum too low", [entry("allow", 0.8), entry("review", 0.1)]],
    ["not an array", "allow"],
    ["selected not max", [entry("allow", 0.4), entry("review", 0.6)]],
  ];
  for (const [label, entries] of invalid) {
    assert.equal(probabilityDistribution(entries, ALLOWED, TOLERANCE, "allow"), undefined, label);
  }
});
