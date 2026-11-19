import { readFileSync, realpathSync, lstatSync, openSync, fstatSync, closeSync, constants, type Stats } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { isInProject, projectRoot } from "./tiers.js";

/** Index just past the quoted string that starts at `start`. */
function skipString(input: string, start: number): number {
  let i = start + 1;
  while (i < input.length) {
    const c = input[i];
    if (c === "\\") { i += 2; continue; }
    if (c === '"') return i + 1;
    i++;
  }
  return i;
}

/** Index just past the line comment that starts at `start`. */
function skipLineComment(input: string, start: number): number {
  let i = start;
  while (i < input.length && input[i] !== "\n") i++;
  return i + 1;
}

/** Index just past the block comment that starts at `start`. */
function skipBlockComment(input: string, start: number): number {
  const end = input.indexOf("*/", start + 2);
  if (end === -1) throw new Error("Unclosed block comment");
  return end + 2;
}

/** Replace comments with whitespace without changing quoted strings. */
function stripComments(input: string): string {
  let output = "";
  let i = 0;
  while (i < input.length) {
    const c = input[i];
    if (c === '"') {
      const end = skipString(input, i);
      output += input.slice(i, end);
      i = end;
    } else if (c === "/" && input[i + 1] === "/") {
      i = skipLineComment(input, i);
      output += "\n";
    } else if (c === "/" && input[i + 1] === "*") {
      i = skipBlockComment(input, i);
      output += " ";
    } else {
      output += c;
      i++;
    }
  }
  return output;
}

/** Drop commas before a closing brace or bracket, preserving quoted strings. */
function stripTrailingCommas(input: string): string {
  let clean = "";
  let i = 0;
  while (i < input.length) {
    const c = input[i];
    if (c === '"') {
      const end = skipString(input, i);
      clean += input.slice(i, end);
      i = end;
      continue;
    }
    if (c === "," && /^\s*[}\]]/.test(input.slice(i + 1))) { i++; continue; }
    clean += c;
    i++;
  }
  return clean;
}

/** Strip JSONC comments and trailing commas without changing quoted strings. */
export function parseJSONC(input: string): unknown {
  if (Buffer.byteLength(input) > 1_048_576) throw new Error("JSONC exceeds size limit");
  return JSON.parse(stripTrailingCommas(stripComments(input)).replace(/^\uFEFF/, "")) as unknown;
}

function writableByOthers(stat: Stats): boolean {
  return (stat.mode & 0o022) !== 0 && !(stat.isDirectory() && (stat.mode & 0o1000) !== 0);
}

function ownedByAnotherUser(stat: Stats, uid: number | undefined): boolean {
  return uid !== undefined && stat.uid !== uid && stat.uid !== 0;
}

/** Reject a path that resolves inside the evaluated project. */
function assertOutsideProject(lexical: string, canonical: string, root: string): void {
  let canonicalRoot = root;
  try { canonicalRoot = realpathSync(root); } catch { /* still enforce lexical root */ }
  if (isInProject(lexical, root) || isInProject(canonical, canonicalRoot))
    throw new Error("Policy files must be user-owned outside the repository");
}

/** Walk every existing ancestor, rejecting symlinks and unsafe ownership or modes. */
function assertSafeAncestors(filename: string, uid: number | undefined): void {
  let current = filename;
  while (true) {
    const stat = lstatSync(current);
    if (stat.isSymbolicLink()) throw new Error("Policy paths must not contain symlinks");
    if (writableByOthers(stat)) throw new Error("Policy paths must not be writable by other users");
    if (ownedByAnotherUser(stat, uid)) throw new Error("Policy paths must be user-owned or system-owned parents");
    const parent = resolve(current, "..");
    if (parent === current) break;
    current = parent;
  }
}

/** Validate the opened descriptor before reading, then enforce the byte bound. */
function readVerifiedFile(descriptor: number, uid: number | undefined, maxBytes: number): string {
  const stat = fstatSync(descriptor);
  if (!stat.isFile() || stat.nlink !== 1 || stat.size > maxBytes ||
      (uid !== undefined && stat.uid !== uid) || (stat.mode & 0o022) !== 0)
    throw new Error("Policy file must be user-owned, single-linked and not writable by other users");
  const input = readFileSync(descriptor, "utf8");
  if (Buffer.byteLength(input) > maxBytes) throw new Error("Policy file exceeds size limit");
  return input;
}

/** Read policy data without following symlinks or trusting writable parents. */
export function readUserOwnedFile(filename: string, projectDir?: string, maxBytes = 1_048_576): string {
  if (!isAbsolute(filename)) throw new Error("Policy file path must be absolute");
  const lexical = resolve(filename);
  const canonical = realpathSync(lexical);
  assertOutsideProject(lexical, canonical, projectRoot(projectDir ?? process.cwd()));
  const uid = process.getuid?.();
  assertSafeAncestors(lexical, uid);
  const descriptor = openSync(lexical, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try { return readVerifiedFile(descriptor, uid, maxBytes); }
  finally { closeSync(descriptor); }
}
