import * as path from "node:path";
import { lstatSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { getWorktreeScope } from "./worktree.js";
import { isDataOption } from "./shell-policy.js";
import { classifyPath, expandPolicyHome, policyRoots, type PathPolicy } from "./path-policy.js";
export { classifyPath } from "./path-policy.js";

export function projectRoot(location: string): string {
  try { return getWorktreeScope(location).worktreeRoot; }
  catch { return path.resolve(location); }
}

/** Compatibility predicate: uncertainty is not an established prohibition. */
export function isProtected(target: string, projectDir?: string): boolean {
  return classifyPath(target, projectDir).kind === "protected";
}

export function hasSymlinkTraversal(target: string, directory = process.cwd()): boolean {
  let current = path.isAbsolute(target) ? path.parse(target).root : directory;
  for (const part of target.split(path.sep).filter(Boolean)) {
    if (part === ".") continue;
    if (part === "..") { current = path.dirname(current); continue; }
    current = path.join(current, part);
    try { if (lstatSync(current).isSymbolicLink()) return true; }
    catch (error) {
      if (!["ENOENT", "ENOTDIR", "ENAMETOOLONG"].includes((error as NodeJS.ErrnoException).code ?? "")) return true;
    }
  }
  return false;
}

const REMOTE_URL = /^(?:[a-z][a-z0-9+.-]*:\/\/|[^/\\@:]+@[^/\\:]+:)/i;
const ordinary: PathPolicy = { kind: "ordinary", review: false, reason: "Non-file data" };

function fileUrlPath(word: string): string | undefined {
  if (!/^file:/i.test(word)) return undefined;
  try { return fileURLToPath(word); } catch { return ""; }
}

export function shellPathSpelling(target: string, expandsHome: boolean): string {
  return expandsHome ? expandPolicyHome(target, policyRoots().home) : target;
}

/** Only call for a grammar-established file operand, not an unknown argument. */
export function pathOperandPolicy(target: string, directory?: string, followFinal = true, expandsHome = false): PathPolicy {
  const word = shellPathSpelling(target, expandsHome);
  const local = fileUrlPath(word);
  if (local !== undefined) return classifyPath(local, directory, undefined, followFinal);
  if (REMOTE_URL.test(word)) return ordinary;
  return classifyPath(word, directory, undefined, followFinal);
}

export function isProtectedPathOperand(target: string, directory?: string): boolean {
  return pathOperandPolicy(target, directory).kind === "protected";
}

/** Unknown roles never prove an access, even if an argument looks secret-like. */
export function isProtectedShellWord(target: string, directory?: string): boolean {
  void target; void directory;
  return false;
}

export function shellWordNeedsReview(target: string, directory?: string): boolean {
  if (target.startsWith("-") && !target.includes("=")) return false;
  const separator = target.indexOf("=");
  if (separator !== -1 && isDataOption(target.slice(0, separator))) return false;
  const value = target.startsWith("-") && separator !== -1 ? target.slice(separator + 1) : target;
  return pathOperandPolicy(value, directory).review;
}

export function isInProject(target: string, projectDir: string): boolean {
  const resolved = path.resolve(projectDir, target);
  const root = path.resolve(projectDir);
  return resolved === root || resolved.startsWith(`${root}${path.sep}`);
}

export function isScopedPath(target: string, locationDir: string, worktreeRoot: string): boolean {
  if (!target || target.startsWith("~") || /[$`\0]/.test(target)) return false;
  const fact = classifyPath(target, locationDir);
  if (fact.kind !== "ordinary" || fact.review || !fact.resolved) return false;
  try { return isInProject(fact.resolved, realpathSync(worktreeRoot)); }
  catch { return false; }
}

export function safeTarget(target: string, locationDir: string, worktreeRoot = projectRoot(locationDir)): boolean {
  if (!isScopedPath(target, locationDir, worktreeRoot)) return false;
  try {
    const root = realpathSync(worktreeRoot);
    const directory = realpathSync(locationDir);
    if (!lstatSync(root).isDirectory() || !lstatSync(directory).isDirectory() || !isInProject(directory, root)) return false;
    const resolved = path.resolve(directory, target);
    let current = root;
    for (const part of path.relative(root, resolved).split(path.sep)) {
      current = path.join(current, part);
      if (!safeComponent(current, resolved)) return false;
    }
    return true;
  } catch { return false; }
}

function safeComponent(current: string, target: string): boolean {
  try {
    const stat = lstatSync(current);
    if (stat.isSymbolicLink() || (!stat.isFile() && !stat.isDirectory())) return false;
    return stat.isFile() ? stat.nlink === 1 : current !== target;
  } catch (error) { return (error as NodeJS.ErrnoException).code === "ENOENT"; }
}
