import js from "@eslint/js";
import { defineConfig } from "eslint/config";
import tseslint from "typescript-eslint";

export default defineConfig({
  ignores: ["dist/**"],
  files: ["**/*.{js,mjs,cjs,ts,tsx,mts,cts}"],
  extends: [js.configs.recommended, tseslint.configs.recommended],
});
