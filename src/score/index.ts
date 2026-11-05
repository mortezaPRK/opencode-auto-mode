import type { AutoModeOptions } from "../config.js";
import type { PermissionRequest } from "../reviewer.js";
import { projectRoot } from "../tiers.js";
import { isFileAction, scoreFileAction } from "./files.js";
import { checkRequestLimits } from "./limits.js";
import { scoreShellRequest } from "./shell.js";
import { high, low, type RequestScore } from "./types.js";

const NETWORK_ACTIONS = new Set(["webfetch", "websearch"]);
const INTERACTIVE_ACTIONS = new Set(["question", "todowrite"]);

/** The evaluated root comes from the caller when given, else from the location itself. */
function resolveWorktreeRoot(request: PermissionRequest): string | undefined {
  return request.worktreeRoot ?? (request.projectDir ? projectRoot(request.projectDir) : undefined);
}

/** The caller decides which host effects enter review. Native deny is always the
 * caller's responsibility; residual asks and native allows share these guards. */
export function scoreRequest(request: PermissionRequest & { worktreeRoot?: string }, options: AutoModeOptions): RequestScore {
  const { action, resources, projectDir } = request;
  // Reject malformed requests before root discovery touches the filesystem.
  const rejected = checkRequestLimits(action, resources);
  if (rejected) return rejected;
  const worktreeRoot = resolveWorktreeRoot(request);
  if (action === "shell") return scoreShellRequest(request, worktreeRoot);
  if (isFileAction(action)) return scoreFileAction(action, resources, options, projectDir, worktreeRoot);
  // No host allowlist exists, so a URL/query name cannot bound what is fetched.
  if (NETWORK_ACTIONS.has(action)) return high("Network fetch/search has no verified host allowlist");
  if (INTERACTIVE_ACTIONS.has(action)) return low("User interaction without host side effects");
  // JavaScript can hide egress behind aliases, templates and computed URLs.
  // Even literal allowlisted fetches do not prove the rest of the program safe.
  if (action === "execute")
    return high("Code Mode is dynamic execution; outbound hosts cannot be proven statically");
  // MCP names are not a capability declaration. Unknown and MCP tools always
  // stay HIGH: no tool name alone establishes a verified read-only capability.
  return high("Unknown tool capability");
}
