import js from "@eslint/js";
import { defineConfig } from "eslint/config";
import tseslint from "typescript-eslint";

export default defineConfig(
  { ignores: ["dist/**"] },
  {
    files: ["**/*.{js,mjs,cjs,ts,tsx,mts,cts}"],
    extends: [js.configs.recommended, tseslint.configs.recommended],
  },
  {
    // Keep non-test code small and shallow.
    files: ["**/*.{js,mjs,cjs,ts,tsx,mts,cts}"],
    ignores: ["**/*.test.ts", "**/*.test.tsx"],
    rules: {
      complexity: ["error", 10],
      "max-lines-per-function": [
        "error",
        { max: 60, skipBlankLines: true, skipComments: true, IIFEs: true },
      ],
      "max-depth": ["error", 4],
    },
  },
);
