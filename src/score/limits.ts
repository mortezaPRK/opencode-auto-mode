import { ask, type RequestScore } from "./types.js";

/** Bounds the scorer accepts before it parses or resolves any request text. */
const MAX_RESOURCES = 256;
const MAX_RESOURCE_CHARS = 65_536;
const MAX_RESOURCE_BYTES = 262_144;
/** User interaction is complete without any resource text. */
const INTERACTIVE_ACTIONS = new Set(["question", "todowrite"]);
/** The guard's existing reason for malformed shell requests; keep one manual floor. */
const SHELL_LIMIT_REASON = "Shell command exceeds parsing limits";

/** Unusable envelopes are terminal, unlike uncertainty about a complete action. */
function limitScore(action: string, reason: string): RequestScore {
  return ask(action === "shell" ? SHELL_LIMIT_REASON : reason);
}

/** Request-level limits shared by every action. */
export function checkRequestLimits(action: string, resources: readonly string[]): RequestScore | undefined {
  if (typeof action !== "string" || !action.trim() || !Array.isArray(resources) || resources.some((resource) => typeof resource !== "string" || !resource.trim()))
    return ask("Malformed permission request");
  if (!resources.length && !INTERACTIVE_ACTIONS.has(action)) return limitScore(action, "Missing request resources");
  if (resources.length > MAX_RESOURCES || resources.some((resource) => resource.length > MAX_RESOURCE_CHARS) ||
      resources.reduce((total, resource) => total + Buffer.byteLength(resource), 0) > MAX_RESOURCE_BYTES)
    return limitScore(action, "Request exceeds scoring limits");
  return undefined;
}
