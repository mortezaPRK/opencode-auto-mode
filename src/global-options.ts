import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { object } from "./config.js";
import { parseJSONC, readUserOwnedFile } from "./user-files.js";

interface PackageIdentity { directory: string; name: string }
// Resolve lazily so callers can catch layout failures and disable auto mode.
function packageIdentity(): PackageIdentity {
  const directory = realpathSync(fileURLToPath(new URL("..", import.meta.url)));
  const manifest: unknown = JSON.parse(readFileSync(join(directory, "package.json"), "utf8"));
  if (!object(manifest) || typeof manifest.name !== "string") throw new Error("Invalid plugin package identity");
  return { directory, name: manifest.name };
}
function hasSubstitution(value: string): boolean { return /\{(?:env|file):[^}]*\}/.test(value); }
function rejectSubstitutions(value: unknown): void {
  if (typeof value === "string" && hasSubstitution(value))
    throw new Error("Global auto-mode registration contains unsupported env/file substitution; use concrete selected values in personal configuration");
  if (Array.isArray(value)) value.forEach(rejectSubstitutions);
  else if (object(value)) {
    for (const [key, item] of Object.entries(value)) {
      rejectSubstitutions(key);
      rejectSubstitutions(item);
    }
  }
}

function matchesRegistration(value: string, configFile: string, identity: PackageIdentity): boolean {
  const packageName = identity.name;
  // A package version suffix is allowed, but lookalike package names are not.
  if (value === packageName || value.startsWith(packageName + "@")) return true;
  let local: string;
  if (value.startsWith("file://")) {
    try { local = fileURLToPath(value); } catch { return false; }
  } else if (isAbsolute(value) || value.startsWith("./") || value.startsWith("../")) {
    local = resolve(dirname(configFile), value);
  } else return false;
  try { return realpathSync(local) === identity.directory; } catch { return false; }
}

/** Safety options are read from user-owned global files, never merged SDK data.
 * No registration, duplicate registrations or ambiguous global files fail closed.
 * This function has no configurable path override: XDG_CONFIG_HOME is process
 * environment, not a plugin option a repository registration can replace.
 * SDK env/file substitutions are deliberately unsupported: select concrete
 * values in personal configuration; this loader never expands arbitrary files.
 */
export function loadGlobalOptions(projectDir?: string): unknown {
  const identity = packageIdentity();
  const base = process.env.XDG_CONFIG_HOME || join(homedir(), ".config");
  if (!isAbsolute(base)) throw new Error("XDG_CONFIG_HOME must be absolute");
  const files = [join(base, "opencode", "opencode.json"), join(base, "opencode", "opencode.jsonc")];
  const registrations: unknown[] = [];
  for (const file of files) {
    try { lstatSync(file); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw error;
    }
    const config = parseJSONC(readUserOwnedFile(file, projectDir));
    if (!object(config)) throw new Error("Global OpenCode configuration must be an object");
    if (config.plugins === undefined) continue;
    if (!Array.isArray(config.plugins)) throw new Error("Global plugins must be an array");
    for (const entry of config.plugins) {
      const name = typeof entry === "string" ? entry : object(entry) ? entry.package : undefined;
      if (typeof name !== "string") continue;
      // We cannot establish package identity through substitution without
      // implementing the SDK's expansion. Reject rather than silently skip it.
      if (hasSubstitution(name)) rejectSubstitutions(name);
      if (!matchesRegistration(name, file, identity)) continue;
      rejectSubstitutions(entry);
      if (typeof entry === "string") registrations.push({});
      else {
        if (!object(entry) || Object.keys(entry).some((key) => !["package", "options"].includes(key)))
          throw new Error("Unknown global auto-mode registration fields");
        registrations.push(entry.options ?? {});
      }
    }
  }
  if (registrations.length !== 1)
    throw new Error(registrations.length === 0 ? "Auto-mode is not registered in user-owned global configuration" :
      "Ambiguous auto-mode global registrations");
  return registrations[0];
}
