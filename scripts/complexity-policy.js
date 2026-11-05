/**
 * Complexity policy shared by ESLint and the legacy ratchet.
 *
 * These are deliberately non-negotiable for new code: small functions with
 * shallow nesting are easier to review and test. Existing violations are
 * tracked in scripts/complexity-baseline.json; they may shrink but not grow.
 */
export const COMPLEXITY_LIMITS = Object.freeze({
  complexity: 10,
  maxLinesPerFunction: 60,
  maxDepth: 4,
});

export const COMPLEXITY_RULES = Object.freeze({
  complexity: ["error", COMPLEXITY_LIMITS.complexity],
  "max-lines-per-function": [
    "error",
    {
      max: COMPLEXITY_LIMITS.maxLinesPerFunction,
      skipBlankLines: true,
      skipComments: true,
      IIFEs: true,
    },
  ],
  "max-depth": ["error", COMPLEXITY_LIMITS.maxDepth],
});

export const COMPLEXITY_RULE_IDS = Object.freeze(
  Object.keys(COMPLEXITY_RULES),
);
