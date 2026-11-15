import * as path from "node:path";
import { lstatSync, readlinkSync, realpathSync } from "node:fs";
import { homedir } from "node:os";

export interface PolicyRoots { home: string; config: string; data: string; database?: string }
export interface PathPolicy {
  kind: "protected" | "ordinary" | "unresolved";
  review: boolean;
  reason: string;
  resolved?: string;
}
type ResourceType = "directory" | "file" | "other" | "missing";
interface Resolution { resolved?: string; designation?: string; envDesignation?: boolean; type?: ResourceType; symlink: boolean; uncertain: boolean }
interface Store { target: string; subtree?: boolean }

export function policyRoots(): PolicyRoots {
  const home = process.env.HOME || homedir();
  return { home, config: process.env.XDG_CONFIG_HOME || path.join(home, ".config"),
    data: process.env.XDG_DATA_HOME || path.join(home, ".local/share"), database: process.env.OPENCODE_DB };
}

function within(candidate: string, root: string): boolean {
  return candidate === root || candidate.startsWith(`${root}${path.sep}`);
}

/** Supported catalog locations, not arbitrary credential-shaped basenames.
 * OpenCode: https://opencode.ai/docs/cli/providers/#storage and
 * https://opencode.ai/docs/troubleshooting#service-files. Metadata only. */
function storeCatalog(roots: PolicyRoots): Store[] {
  const home = [".netrc", ".git-credentials", ".aws/credentials", ".gnupg/secring.gpg",
    ...["rsa", "dsa", "ecdsa", "ed25519", "ecdsa_sk", "ed25519_sk"].map((key) => `.ssh/id_${key}`)];
  const config = ["gh/hosts.yml", "gcloud/application_default_credentials.json", "gcloud/credentials.db", "gcloud/access_tokens.db"];
  const db = roots.database ? path.resolve(roots.database) : path.join(roots.data, "opencode/opencode.db");
  const canonicalDb = resolveComponents(db, process.cwd(), true).resolved;
  const targets = [...home.map((name) => path.join(roots.home, name)), ...config.map((name) => path.join(roots.config, name)),
    path.join(roots.data, "opencode/auth.json"), ...databaseFiles(db), ...databaseFiles(canonicalDb)];
  return [...targets.map((target) => ({ target })),
    ...[".aws/sso/cache", ".aws/cli/cache", ".gnupg/private-keys-v1.d"].map((name) => ({ target: path.join(roots.home, name), subtree: true }))];
}

function databaseFiles(database?: string): string[] {
  return database ? [database, `${database}-wal`, `${database}-shm`, `${database}-journal`] : [];
}

function knownStore(candidate: string, roots: PolicyRoots): boolean {
  return storeCatalog(roots).some((store) => matchesStore(candidate, store)) || systemStore(candidate) ||
    /^\/proc\/(?:self|thread-self|\d+)\/(?:environ|mem)(?:\/|$)/.test(candidate);
}

function matchesStore(candidate: string, store: Store): boolean {
  const fact = resolveComponents(store.target, process.cwd(), true);
  if (!fact.resolved || fact.uncertain) return false;
  return store.subtree ? within(candidate, fact.resolved) : candidate === fact.resolved;
}

function systemStore(candidate: string): boolean {
  const names = ["/etc/shadow", "/etc/gshadow", ...["rsa", "dsa", "ecdsa", "ed25519"].map((key) => `/etc/ssh/ssh_host_${key}_key`)];
  return names.some((target) => matchesStore(candidate, { target }));
}

/** Only the final file designation is an env store, never an ancestor directory. */
function runtimeEnv(fact: Resolution): boolean {
  if (fact.type === "directory") return false;
  return fact.envDesignation === true || [fact.designation, fact.resolved].some((candidate) => envName(candidate));
}

function envName(candidate?: string): boolean {
  const name = path.basename(candidate ?? "");
  return /^\.env(?:\..+)?$/.test(name) && !/^\.env(?:\.[a-zA-Z0-9_-]+)?\.(?:example|sample|template)$/.test(name);
}

function reviewSpelling(target: string): boolean {
  if (/(?:^|\/)\.(?!\.?(?:\/|$))[^/]+/.test(target)) return true;
  if (/\.(?:[cm]?[jt]sx?|py|go|rs|md)$/.test(target)) return false;
  return /(?:^|\/)(?:auth|tokens?|secrets?|credentials?|kubeconfig|id_(?:rsa|dsa|ecdsa|ed25519))(?:[./_-]|$)/i.test(target) ||
    /(?:private[_-]?key|secret|password|passwd|service[-_]?account|terraform\.tfstate|\.(?:pem|key|p12|pfx|jks|keystore)$)/i.test(target);
}

/** This is only used when shell lexical provenance establishes expansion. */
export function expandPolicyHome(target: string, home: string): string {
  if (target === "~") return home;
  if (target.startsWith("~/")) return `${home}${target.slice(1)}`;
  return target.replace(/^\$(?:HOME(?![A-Za-z0-9_])|\{HOME\})/, home);
}

function uncertain(symlink = false): Resolution { return { symlink, uncertain: true }; }

/** Resolve a component before '..'; absent suffixes can name creations, but
 * traversal through an absent component or a regular file cannot succeed. */
function resolveComponents(target: string, directory: string, followFinal: boolean, depth = 0): Resolution {
  const parts = target.split(path.sep).filter(Boolean);
  let fact: Resolution = { resolved: path.isAbsolute(target) ? path.parse(target).root : directory, type: "directory", symlink: false, uncertain: false };
  for (const [index, part] of parts.entries()) {
    if (!canTraverse(fact, part)) return uncertain(fact.symlink);
    if (part === ".") continue;
    if (part === "..") { fact.resolved = path.dirname(fact.resolved!); continue; }
    const next = path.join(fact.resolved!, part);
    const step = resolveComponent(next, followFinal || index < parts.length - 1, depth);
    fact = { ...step, designation: next, symlink: fact.symlink || step.symlink };
    if (fact.uncertain) return fact;
  }
  return fact;
}

function canTraverse(fact: Resolution, part: string): boolean {
  if (fact.type === "directory") return true;
  return fact.type === "missing" && part !== "." && part !== "..";
}

function resourceType(target: string): ResourceType {
  const stat = lstatSync(target);
  if (stat.isDirectory()) return "directory";
  return stat.isFile() ? "file" : "other";
}

function resolveComponent(target: string, follow: boolean, depth: number): Resolution {
  let symlink = false;
  try {
    symlink = lstatSync(target).isSymbolicLink();
    if (symlink) return resolveLink(target, follow, depth);
    const resolved = realpathSync(target);
    return { resolved, type: resourceType(resolved), symlink, uncertain: false };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT" && !symlink)
      return { resolved: target, type: "missing", symlink, uncertain: false };
    return uncertain(symlink);
  }
}

/** Preserve final-file designations across a bounded link chain. The outer
 * component walker deliberately drops these facts when descending a directory. */
function resolveLink(target: string, follow: boolean, depth: number): Resolution {
  if (!follow || depth >= 32) return uncertain(true);
  const fact = resolveComponents(readlinkSync(target), path.dirname(target), true, depth + 1);
  if (fact.uncertain || fact.type === "missing") return uncertain(true);
  return { ...fact, symlink: true, envDesignation: fact.envDesignation === true || envName(fact.designation) || envName(target) };
}

export function classifyPath(target: string, directory = process.cwd(), roots = policyRoots(), followFinal = true): PathPolicy {
  if (!target || /[\0]/.test(target)) return { kind: "unresolved", review: true, reason: "Path spelling is unresolved" };
  let base: string;
  try { base = realpathSync(directory); } catch { base = path.resolve(directory); }
  const fact = resolveComponents(target, base, followFinal);
  if (fact.uncertain || !fact.resolved) return { kind: "unresolved", review: true, reason: "Path metadata or traversal is unresolved" };
  return resolvedPolicy(fact, target, base, roots);
}

function resolvedPolicy(fact: Resolution, target: string, base: string, roots: PolicyRoots): PathPolicy {
  const resolved = fact.resolved!;
  if (runtimeEnv(fact) || knownStore(resolved, roots))
    return { kind: "protected", review: true, reason: "Known credential store or sensitive process interface", resolved };
  const spelling = path.isAbsolute(target) && within(target, base) ? path.relative(base, target) : target;
  const review = fact.symlink || reviewSpelling(spelling);
  return { kind: "ordinary", review, reason: review ? "Configuration, ambiguous name or symlink requires review" : "No established protected-store role", resolved };
}
