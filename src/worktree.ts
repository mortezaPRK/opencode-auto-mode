import { realpathSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

export interface WorktreeScope {
  /** Canonical location directory: the base for relative request resources. */
  directory: string;
  /** Nearest Git working tree, not the shared repository of a linked worktree. */
  worktreeRoot: string;
}

/** Stateless discovery: a location move needs no permission mutation or cache invalidation.
 * Relative native grants follow the location; persisted user grants remain untouched.
 * Throws for a missing or non-directory location rather than inventing a scope.
 */
export function getWorktreeScope(location: string): WorktreeScope {
  const directory = realpathSync(resolve(location));
  if (!statSync(directory).isDirectory()) throw new Error("Worktree location must be a directory");
  let current = directory;
  while (true) {
    try {
      const marker = statSync(join(current, ".git"));
      if (marker.isFile() || marker.isDirectory()) return { directory, worktreeRoot: realpathSync(current) };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    const parent = dirname(current);
    if (parent === current) return { directory, worktreeRoot: directory };
    current = parent;
  }
}
