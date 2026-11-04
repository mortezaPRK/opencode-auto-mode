import js from "@eslint/js";
import { defineConfig } from "eslint/config";
import tseslint from "typescript-eslint";
import { COMPLEXITY_RULES } from "./scripts/complexity-policy.js";

export default defineConfig(
  { ignores: ["dist/**"] },
  {
    files: ["**/*.{js,mjs,cjs,ts,tsx,mts,cts}"],
    extends: [js.configs.recommended, tseslint.configs.recommended],
  },
  {
    // New scoring modules and the complexity tooling must meet the strict
    // limits directly. Legacy files are held to a per-function ratchet by
    // scripts/complexity-lint.js, which `bun run lint` also invokes.
    files: [
      "src/score.ts",
      "src/score/**/*.{js,mjs,cjs,ts,tsx,mts,cts}",
      "scripts/complexity*.{js,mjs,cjs,ts,tsx,mts,cts}",
    ],
    rules: COMPLEXITY_RULES,
  },
);
