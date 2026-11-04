import { readFileSync, realpathSync, lstatSync, openSync, fstatSync, closeSync, constants } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { isInProject, projectRoot } from "./tiers.js";

/** Strip JSONC comments and trailing commas without changing quoted strings. */
export function parseJSONC(input: string): unknown {
  if (Buffer.byteLength(input) > 1_048_576) throw new Error("JSONC exceeds size limit");
  let output = "";
  let quoted = false;
  for (let i = 0; i < input.length; i++) {
    const c = input[i];
    if (quoted) {
      output += c;
      if (c === "\\") output += input[++i] ?? "";
      else if (c === '"') quoted = false;
    } else if (c === '"') { quoted = true; output += c; }
    else if (c === "/" && input[i + 1] === "/") {
      while (i < input.length && input[i] !== "\n") i++;
      output += "\n";
    } else if (c === "/" && input[i + 1] === "*") {
      const end = input.indexOf("*/", i + 2);
      if (end === -1) throw new Error("Unclosed block comment");
      output += " "; i = end + 1;
    } else output += c;
  }
  let clean = "";
  quoted = false;
  for (let i = 0; i < output.length; i++) {
    const c = output[i];
    if (quoted) {
      clean += c;
      if (c === "\\") clean += output[++i] ?? "";
      else if (c === '"') quoted = false;
    } else {
      if (c === '"') quoted = true;
      if (c === "," && /^[\s]*[}\]]/.test(output.slice(i + 1))) continue;
      clean += c;
    }
  }
  return JSON.parse(clean.replace(/^\uFEFF/, "")) as unknown;
}
/** Read policy data without following symlinks or trusting writable parents. */
export function readUserOwnedFile(filename: string, projectDir?: string, maxBytes = 1_048_576): string {
  if (!isAbsolute(filename)) throw new Error("Policy file path must be absolute");
  const lexical = resolve(filename);
  const canonical = realpathSync(lexical);
  const root = projectRoot(projectDir ?? process.cwd());
  let canonicalRoot = root;
  try { canonicalRoot = realpathSync(root); } catch { /* still enforce lexical root */ }
  if (isInProject(lexical, root) || isInProject(canonical, canonicalRoot))
    throw new Error("Policy files must be user-owned outside the repository");
  const uid = process.getuid?.();
  let current = lexical;
  while (true) {
    const stat = lstatSync(current);
    if (stat.isSymbolicLink()) throw new Error("Policy paths must not contain symlinks");
    if ((stat.mode & 0o022) !== 0 && !(stat.isDirectory() && (stat.mode & 0o1000) !== 0))
      throw new Error("Policy paths must not be writable by other users");
    if (uid !== undefined && stat.uid !== uid && stat.uid !== 0)
      throw new Error("Policy paths must be user-owned or system-owned parents");
    const parent = resolve(current, "..");
    if (parent === current) break;
    current = parent;
  }
  const descriptor = openSync(lexical, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > maxBytes ||
        (uid !== undefined && stat.uid !== uid) || (stat.mode & 0o022) !== 0)
      throw new Error("Policy file must be user-owned, single-linked and not writable by other users");
    const input = readFileSync(descriptor, "utf8");
    if (Buffer.byteLength(input) > maxBytes) throw new Error("Policy file exceeds size limit");
    return input;
  } finally { closeSync(descriptor); }
}
