import type { PermissionRequest } from "../reviewer.js";
import { protectedSegment, recursiveExternalDelete, type ParsedShellCommands } from "../shell.js";
import { hasSymlinkTraversal, isProtected, isProtectedShellWord } from "../tiers.js";
import { historyChange, historyScore, isGitGlobalOption } from "./history.js";
import { executableShapeScore, pathTargets, type ShellScan } from "./shell-argv.js";
import { ask, deny, high, type RequestScore } from "./types.js";

function commandTouchesProtected(command: ParsedShellCommands | undefined, projectDir?: string): boolean {
  if (!command) return false;
  return command.segments.some((segment) => protectedSegment(segment, projectDir)) ||
    command.leftovers.some((word) => isProtectedShellWord(word, projectDir));
}

/** A redirection always names a file, so its target takes the full path-aware check. */
function redirectsProtected(commands: readonly (ParsedShellCommands | undefined)[], projectDir?: string): boolean {
  return commands.some((command) => command?.redirects.some((target) => isProtected(target, projectDir)));
}

/** Denies and asks that depend only on the literal parsed command text. */
function literalShellScore(scan: ShellScan, request: PermissionRequest, worktreeRoot?: string): RequestScore | undefined {
  if (scan.scanned.some((argv) => recursiveExternalDelete(argv, request.projectDir, worktreeRoot)))
    return deny("Recursive/force deletion outside the project");
  // Git global options alter cwd/config or helper execution. Do not guess the
  // effective subcommand or let a reviewer lift this uncertainty.
  if (scan.scanned.some(isGitGlobalOption))
    return ask("Git global options require manual approval");
  // A history-rewriting invocation is gated once, against the request's VCS facts.
  if (scan.scanned.some(historyChange)) return historyScore(scan.scanned, request.gitState);
  // No regex fallback. Only the guard's literal, fully parsed representation
  // can establish a low-risk compound; scripts and uncertain syntax stay HIGH.
  if (scan.commands.some((command) => !command?.complete)) return high("Complex or dynamic shell syntax");
  return undefined;
}

/** Protected paths deny; a path that traverses a symlink asks for human review. */
function protectedPathScore(scan: ShellScan, projectDir?: string): RequestScore | undefined {
  // Wrappers do not erase destructive semantics (env rm / command git push).
  // Each simple command is judged by its own grammar, so a pattern/script/filter
  // is data even when spelled like a path, while tokens outside any command keep
  // the generic word check.
  if (redirectsProtected(scan.commands, projectDir) ||
      scan.commands.some((command) => commandTouchesProtected(command, projectDir)))
    return deny("Protected path access");
  if (pathTargets(scan).some((arg) => hasSymlinkTraversal(arg, projectDir)))
    return ask("Symlink traversal requires human approval");
  return undefined;
}

/** Ordered shell safety pipeline: literal denies, then paths, then executable shape. */
export function shellSafetyScore(scan: ShellScan, request: PermissionRequest, worktreeRoot?: string): RequestScore | undefined {
  const literal = literalShellScore(scan, request, worktreeRoot);
  if (literal?.deny || literal?.ask) return literal;
  return protectedPathScore(scan, request.projectDir) ?? literal ?? executableShapeScore(scan);
}
