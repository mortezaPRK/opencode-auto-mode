/**
 * Compatibility entry point for `./score.js` imports.
 *
 * Scoring lives in the focused modules under `./score/`; this file deliberately
 * re-exports the public surface instead of carrying implementation, so existing
 * callers and the packaged plugin entry keep the same import path.
 */
export { scoreRequest } from "./score/index.js";
export type { RequestScore } from "./score/types.js";
