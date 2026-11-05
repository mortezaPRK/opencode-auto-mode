import * as path from "node:path";
import { lstatSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { isDataOption } from "./shell-policy.js";
import { getWorktreeScope } from "./worktree.js";

/** Compatibility helper; invalid locations cannot establish a verified file scope. */
export function projectRoot(location: string): string {
  try { return getWorktreeScope(location).worktreeRoot; }
  catch { return path.resolve(location); }
}

/**
 * File extensions that name source or documentation rather than a credential
 * store. A module such as `src/tokens.ts` is ordinary source, and treating a
 * keyword plus one of these extensions as a secret name turns every source
 * search or file read into a hard deny.
 */
const SOURCE_EXTENSION = String.raw`(?:[cm]?[jt]sx?|py|pyi|rb|go|rs|java|kt|kts|cs|php|swift|scala|sh|bash|zsh|fish|lua|pl|pm|vue|svelte|astro|html?|css|scss|sass|less|sql|mdx?)`;

/**
 * Filename-shaped sensitive names.
 *
 * These spellings are unambiguous file references, so they apply to a bare shell
 * word as well as to a path: a dotfile, a key file, or a name that carries a
 * credential keyword and an extension. A credential keyword followed by a source
 * extension is excluded so `tokens.ts` stays a module name.
 */
const SENSITIVE_NAME = new RegExp([
  // Repository, tool, editor, CI and agent configuration directories.
  String.raw`(?:^|[/\\])\.(?:git|opencode|ssh|aws|gnupg|kube|docker|config|github|vscode|husky|devcontainer|idea|gitlab-ci\.yml|git-credentials|password-store|netrc|npmrc|pypirc|env[^/\\]*)(?:[/\\]|$)`,
  // Credential stores and key material that are not hidden directories.
  String.raw`(?:^|[/\\])(?:credentials?\.[^/\\]+|opencode\.json[^/\\]*|auth\.(?:json|ya?ml))(?:[/\\]|$)`,
  String.raw`(?:^|[/\\])id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?(?:[/\\]|$)`,
  String.raw`(?:^|[/\\])[^/\\]+\.(?:pem|key|p12|pfx|jks|keystore)(?:[/\\]|$)`,
  // Files whose own name declares a credential, token, secret or password
  // payload. The keyword must start the component or follow a separator, so a
  // source file such as `tokenizer.ts` is not swept in, and a source extension
  // disqualifies the name.
  String.raw`(?:^|[/\\])(?![^/\\]*\.` + SOURCE_EXTENSION + String.raw`(?:[/\\]|$))(?:[^/\\]*[._-])?(?:credential|token|secret|password|passwd|private[_ -]?key)s?(?![a-z])[^/\\]*\.[^/\\]+(?:[/\\]|$)`,
  // Infrastructure state and cloud service-account key files.
  String.raw`(?:^|[/\\])(?:[^/\\]*[._-])?terraform\.tfstate[^/\\]*(?:[/\\]|$)`,
  String.raw`(?:^|[/\\])(?:[^/\\]*[._-])?service[-_ ]?accounts?\.json(?:[/\\]|$)`,
].join("|"), "i");

/**
 * Bare credential keywords. A word that is only a keyword is as likely to be a
 * search pattern, a package name or a commit message as a file, so shell callers
 * only apply these to a word that can name a path or to a redirect target.
 */
const SENSITIVE_KEYWORD = new RegExp([
  String.raw`(?:^|[/\\])(?:credentials?|kubeconfig|auth)(?:[/\\]|$)`,
  String.raw`(?:^|[/\\])(?:tokens?|secrets?|passwords?|passwd|private[ _-]?keys?|[^/\\]*[._-](?:credential|token|secret|password|passwd|private[_ -]?key)s?)(?:[/\\]|$)`,
].join("|"), "i");

/**
 * Explicit sensitive names, checked both on the spelling supplied by the caller
 * and on each component of the resolved path. This is the narrow set that also
 * applies after resolution, so a project checked out below an unrelated dotted
 * ancestor (for example `~/.local/share/project`) stays usable.
 */
export const SENSITIVE_PATH = new RegExp([SENSITIVE_NAME.source, SENSITIVE_KEYWORD.source].join("|"), "i");

/**
 * Broad lexical protection: any dot-prefixed path component supplied by the
 * caller is sensitive, including dotfiles and dot-directories this module does
 * not name explicitly. `.` and `..` are traversal, not names, and are left to
 * the containment checks.
 */
const DOT_COMPONENT = /(?:^|[/\\])\.(?!\.?(?:[/\\]|$))[^/\\]+(?:[/\\]|$)/;

/** Filesystem errors that mean a component cannot exist, so nothing is hidden there. */
const ABSENT_COMPONENT = ["ENOENT", "ENOTDIR", "ENAMETOOLONG"];

/** Lexical and canonical spellings of the project root a target is compared to. */
function projectRootSpellings(projectDir?: string): string[] {
  const directory = path.resolve(projectDir ?? process.cwd());
  const roots = [directory];
  try {
    const real = realpathSync(directory);
    if (!roots.includes(real)) roots.push(real);
  } catch { /* Unverifiable root keeps the lexical spelling only. */ }
  return roots;
}

/**
 * Sensitive spelling of one candidate.
 *
 * DOT_COMPONENT is applied to the path relative to the project root for an
 * absolute target inside it, so an unrelated dotted ancestor such as
 * `~/.local/share/project` does not mark every file below it. SENSITIVE_PATH is
 * still applied to the whole candidate and, in `isProtected`, to every resolved
 * component: a real `.ssh` or `.config` directory stays protected.
 */
function sensitiveSpelling(candidate: string, roots: readonly string[]): boolean {
  if (SENSITIVE_PATH.test(candidate)) return true;
  if (path.isAbsolute(candidate)) {
    for (const root of roots) {
      if (isInProject(candidate, root)) return DOT_COMPONENT.test(path.relative(root, path.resolve(candidate)));
    }
  }
  return DOT_COMPONENT.test(candidate);
}

/** Inspect components before normalization can erase an alias followed by `..`.
 * Absolute paths also start at their filesystem root, not at the location base.
 */
export function hasSymlinkTraversal(target: string, locationDir = process.cwd()): boolean {
  let current: string;
  try { current = path.isAbsolute(target) ? path.parse(target).root : realpathSync(locationDir); }
  catch { current = path.resolve(locationDir); }
  for (const part of target.split(path.sep).filter(Boolean)) {
    if (part === ".") continue;
    if (part === "..") { current = path.dirname(current); continue; }
    current = path.join(current, part);
    try {
      if (lstatSync(current).isSymbolicLink()) return true;
    } catch (error) {
      // ENAMETOOLONG means the name cannot exist at all, so it hides no alias.
      if (!ABSENT_COMPONENT.includes((error as NodeJS.ErrnoException).code ?? "")) return true;
    }
  }
  return false;
}

/** Check lexical spelling and each resolved component, preserving symlink/.. traversal. */
export function isProtected(target: string, projectDir?: string): boolean {
  const roots = projectRootSpellings(projectDir);
  const candidates = [target, ...target.split("="), ...target.split(":")];
  if (candidates.some((candidate) => sensitiveSpelling(candidate, roots) ||
      /^\/proc\/(?:self|thread-self|\d+)\/(?:environ|mem)(?:$|\/)/.test(candidate))) return true;
  let current: string;
  try { current = path.isAbsolute(target) ? path.parse(target).root : realpathSync(projectDir ?? process.cwd()); }
  catch { return hasSymlinkTraversal(target, path.resolve(projectDir ?? process.cwd())); }
  const protectedPath = (candidate: string) => SENSITIVE_PATH.test(candidate) ||
    /^\/proc\/(?:self|thread-self|\d+)\/(?:environ|mem)(?:$|\/)/.test(candidate);
  if (protectedPath(current)) return true;
  for (const part of target.split(path.sep).filter(Boolean)) {
    if (part === ".") continue;
    current = part === ".." ? path.dirname(current) : path.join(current, part);
    try { current = realpathSync(current); }
    catch (error) {
      // Missing new files are expected; broken aliases and other ambiguous
      // filesystem errors cannot establish that a protected target is absent.
      // ENAMETOOLONG is not ambiguous: no such name can exist.
      try { if (lstatSync(current).isSymbolicLink()) return true; } catch { /* Missing component. */ }
      if (!ABSENT_COMPONENT.includes((error as NodeJS.ErrnoException).code ?? "")) return true;
    }
    if (protectedPath(current)) return true;
  }
  return false;
}

/** A scheme-qualified URL names a remote resource, never a local path. */
const SCHEME_URL = /^[a-z][a-z0-9+.-]*:\/\//i;
/** `user@host:path` is a remote Git/SCP location rather than a local path. */
const SCP_URL = /^[^/\\@:]+@[^/\\:]+:/;
/** `file:` URLs are local reads; every other scheme is remote. */
const FILE_URL = /^file:(?:\/\/)?([\s\S]*)$/i;

/** Expands the leading home spellings this module can decode without a shell. */
function expandHome(word: string): string {
  if (word === "~") return homedir();
  if (word.startsWith("~/")) return `${homedir()}${word.slice(1)}`;
  return word.replace(/^\$(?:HOME(?![A-Za-z0-9_])|\{HOME\})/, homedir());
}

/**
 * The local path a `file:` URL names, or undefined for any other spelling.
 *
 * A URL is not a shell word, so the shell never expands `~`, `$HOME` or
 * `${HOME}` inside it; they are expanded lexically here. A URL authority that
 * is a host (`localhost`, an address, a dotted name) is not part of the path,
 * while a non-host first segment stays in it. Query and fragment are dropped.
 */
function fileUrlPath(word: string): string | undefined {
  const match = FILE_URL.exec(word);
  if (match === null) return undefined;
  const rest = expandHome(match[1].split(/[?#]/, 1)[0]);
  if (rest.startsWith("/")) return rest;
  const slash = rest.indexOf("/");
  const authority = slash === -1 ? rest : rest.slice(0, slash);
  if (slash !== -1 && /^(?:localhost|\[[0-9a-fA-F:.]+\]|[^/]*\.[^/]*)$/.test(authority)) return rest.slice(slash);
  return `/${rest}`;
}

/**
 * The value an option-shaped path operand carries (`-fFILE`, `--file=FILE`).
 * A plain word is returned unchanged, including a bare `-` or `--`.
 */
function operandValue(word: string): string {
  if (word.length <= 1 || !word.startsWith("-")) return word;
  const separator = word.indexOf("=");
  if (separator !== -1) return word.slice(separator + 1);
  return word.startsWith("--") ? word : word.slice(2);
}

/**
 * Protected-path check for an operand a command consumes as a file.
 *
 * The command's own grammar has already established that the word names a file
 * (`cat credentials`), so the bare sensitive names count here even though they
 * are only data in a pattern position. A word with no separator cannot be more
 * than one component, so only the explicit names apply: a leading dot is not a
 * reason to deny `.name`, `.gitignore` or `.cache`. Paths with a separator keep
 * the full check, including resolved components, symlinks and `file:` URLs.
 */
export function isProtectedPathOperand(target: string, projectDir?: string): boolean {
  if (!target) return false;
  const word = operandValue(target);
  const local = fileUrlPath(word);
  if (local !== undefined) return isProtected(local, projectDir);
  if (SCHEME_URL.test(word) || SCP_URL.test(word)) return false;
  return /[/\\]/.test(word) ? isProtected(word, projectDir) : SENSITIVE_PATH.test(word);
}

/**
 * Protected-path check for one parsed shell word that the command grammar did
 * not place in a path or data slot.
 *
 * A shell word is often data — a search pattern (`grep -r auth`), a package name
 * (`npm view auth`), a commit message, or a URL — so bare keywords only count
 * when the word can name a path: it contains a separator or carries a value in
 * an option. A separator-less word is matched against the explicit names only,
 * so `jq .name`, `git add .gitignore` and `echo .foo` stay ordinary words while
 * `.env`, `.npmrc` and `auth.json` stay protected. Filename-shaped names
 * (`signing.pem`) stay protected everywhere, and redirect targets are checked
 * with the full `isProtected` because a redirection always names a file.
 */
export function isProtectedShellWord(target: string, projectDir?: string): boolean {
  if (!target) return false;
  const separator = target.startsWith("-") ? target.indexOf("=") : -1;
  // `--grep=config/auth`, `--format=src/.env` and `--exclude=.env` carry
  // pattern/format data even when the value is spelled like a path.
  if (separator !== -1 && isDataOption(target.slice(0, separator))) return false;
  const local = fileUrlPath(target);
  if (local !== undefined) return isProtected(local, projectDir);
  if (SCHEME_URL.test(target) || SCP_URL.test(target)) return false;
  const candidates = [target, ...target.split("="), ...target.split(":")];
  // A `file:` value is a local path even when it arrives through an option.
  const files = candidates.map(fileUrlPath).filter((candidate): candidate is string => candidate !== undefined);
  if (files.length) return files.some((file) => isProtected(file, projectDir));
  // Any other scheme or an SCP-style location is remote, never a local path.
  if (candidates.some((candidate) => SCHEME_URL.test(candidate) || SCP_URL.test(candidate))) return false;
  if (target.startsWith("-")) {
    if (separator === -1) return false;
    // `--config=credentials.json` and `--file=.env` name files.
    return isProtectedPathOperand(target.slice(separator + 1), projectDir);
  }
  // `git show HEAD:.env` names a file after the colon; schemes and SCP
  // locations were already excluded above.
  if (!target.includes("=") && target.split(":").slice(1).some((part) => isProtectedPathOperand(part, projectDir)))
    return true;
  // A separator-less word is only a file reference when it carries a
  // filename-shaped name; a bare keyword such as `auth` stays data here.
  return /[/\\]/.test(target) ? isProtected(target, projectDir) : SENSITIVE_NAME.test(target);
}

export function isInProject(target: string, projectDir: string): boolean {
  const resolved = path.resolve(projectDir, target);
  const root = path.resolve(projectDir);
  return resolved === root || resolved.startsWith(`${root}${path.sep}`);
}

/**
 * Lexical containment for low-band read operands. Tildes, parameter expansion
 * and NUL cannot be resolved to a project path here, so they are never low;
 * callers keep the protected-path and symlink checks separate. Both the spelling
 * supplied by the caller and the canonical path are accepted, because a scope
 * discovered with `realpath` may differ from a caller's `/var` vs `/private/var`
 * spelling on macOS.
 */
export function isScopedPath(target: string, locationDir: string, worktreeRoot: string): boolean {
  if (!target || target.startsWith("~") || /[$`\0]/.test(target)) return false;
  const directory = path.resolve(locationDir);
  const root = path.resolve(worktreeRoot);
  if (isInProject(directory, root) && isInProject(path.resolve(directory, target), root)) return true;
  try {
    const canonicalDirectory = realpathSync(directory);
    const canonicalRoot = realpathSync(root);
    if (!isInProject(canonicalDirectory, canonicalRoot)) return false;
    const resolved = path.resolve(canonicalDirectory, target);
    let canonical = resolved;
    try { canonical = realpathSync(resolved); } catch { /* New files keep the resolved spelling. */ }
    return isInProject(resolved, canonicalRoot) || isInProject(canonical, canonicalRoot);
  } catch { return false; }
}

export function safeTarget(target: string, locationDir: string, worktreeRoot = projectRoot(locationDir)): boolean {
  if (target.startsWith("~") || /[$`\0]/.test(target)) return false;
  try {
    const root = realpathSync(worktreeRoot);
    const directory = realpathSync(locationDir);
    if (!lstatSync(root).isDirectory() || !lstatSync(directory).isDirectory() || !isInProject(directory, root)) return false;
    if (hasSymlinkTraversal(target, directory)) return false;
    const resolved = path.resolve(directory, target);
    if (!isInProject(resolved, root) || isProtected(target, directory)) return false;
    const parts = path.relative(root, resolved).split(path.sep);
    let current = root;
    for (const part of parts) {
      current = path.join(current, part);
      try {
        const stat = lstatSync(current);
        if ((!stat.isFile() && !stat.isDirectory()) || (stat.isFile() && stat.nlink !== 1) ||
            (current === resolved && !stat.isFile())) return false;
      }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") return false; }
    }
    return true;
  } catch { return false; }
}
