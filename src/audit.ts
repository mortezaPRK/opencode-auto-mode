import * as os from "node:os";
import * as path from "node:path";
import type { ReviewErrorKind } from "./errors.js";
import { createJsonlLog, type DebugLogSetting } from "./debug-events.js";
import { parseShellCommands } from "./shell.js";
import { DYNAMIC, SCRIPT_HOSTS, SHELLS, STATEFUL, normalizeContinuations, resolveExecutable } from "./shell-policy.js";

/** Unsafe, opt-in debugging data. Every original field is retained, including secrets. */
export interface AuditRecord {
  ts: string;
  reviewID: string;
  sessionID: string;
  agent?: string;
  action: string;
  resources: string[];
  /** Actual host effect before arbitration; older raw records may omit it. */
  hostEffect?: string;
  decision: string;
  proposedDecision?: "allow" | "ask" | "deny";
  /** True when the evaluated host effect was a native/saved allow rather than an ask. */
  reviewedNativeAllow?: boolean;
  /** How the applied effect was chosen: enforced, off, paused or cancelled. */
  disposition?: string;
  /** Message left on the host permission after arbitration, including off restores. */
  appliedMessage?: string;
  stage: string;
  reason: string;
  durationMs: number;
  score?: number | string;
  breaker?: boolean;
  errorKind?: ReviewErrorKind;
  [key: string]: unknown;
}

export interface AuditLog { write(record: AuditRecord): void }

/** XDG state must be an absolute path; relative or empty values fall back to home. */
export function defaultAuditPath(): string {
  const configured = process.env.XDG_STATE_HOME;
  const base = configured !== undefined && configured !== "" && path.isAbsolute(configured)
    ? configured
    : path.join(os.homedir(), ".local", "state");
  return path.join(base, "opencode-auto-mode", "decisions.jsonl");
}

const REDACTED = "[REDACTED]";
const HTTP_BODY_OPTION = /^--(?:(?:expand-)?(?:data(?:-[a-z]+)?|json|form(?:-string)?)|post-data|post-file|body-data|body-file|upload-file|execute|config)(?:=|$)/;
const POSSIBLE_HTTP_BODY = /--(?:(?:expand-)?(?:data|json|form)|post-|body-|upload-file|execute|config)/;
const POSSIBLE_SHORT_BODY = /-[^- \t\n]*[dFTKe]/;
const WGET_BODY_OPTIONS = ["--body-data", "--body-file", "--config", "--execute", "--post-data", "--post-file", "--upload-file"];

function isWgetBodyOption(word: string): boolean {
  const option = word.split("=", 1)[0]!;
  if (!option.startsWith("--") || option.length <= 2) return false;
  return WGET_BODY_OPTIONS.filter((name) => name.startsWith(option)).length === 1;
}

function uncertainHttpBodyEvidence(value: string): boolean {
  const literal = normalizeContinuations(value).replace(/['"\\]/g, "");
  const abbreviatedWgetOption = /\bwget\b/.test(literal) &&
    (literal.match(/--[A-Za-z0-9-]+/g) ?? []).some(isWgetBodyOption);
  return /(?:curl|wget)/.test(literal) && (possibleBodySyntax(literal) || abbreviatedWgetOption);
}

/** A hyphen inside a literal long option is not a short-option bundle.
 * Dynamic word boundaries retain the conservative original short-form scan. */
function possibleBodySyntax(literal: string): boolean {
  const withoutLongWords = literal.replace(/--[^ \t\n;|&()]+/g, "");
  return POSSIBLE_HTTP_BODY.test(literal) || POSSIBLE_SHORT_BODY.test(withoutLongWords) ||
    (/[$`]/.test(literal) && POSSIBLE_SHORT_BODY.test(literal));
}

function isHttpBodyOption(word: string, client: string): boolean {
  return HTTP_BODY_OPTION.test(word) || (client === "wget" && isWgetBodyOption(word));
}

function wgetShortOptionBehavior(word: string): "body" | "value" | "other" {
  // -e/--execute supplies wgetrc settings, including post_data; stop at value options.
  for (let letter = 1; letter < word.length; letter++) {
    if (word[letter] === "e") return "body";
    if ("oaOUtTwQDAlIRX".includes(word[letter]!))
      return letter === word.length - 1 ? "value" : "other";
  }
  return "other";
}

function curlShortOptionBehavior(word: string): "body" | "value" | "other" {
  for (let letter = 1; letter < word.length; letter++) {
    if ("dFT".includes(word[letter]!)) return "body";
    if (word[letter] === "K") return "body"; // curl config is not bounded evidence.
    if ("HAeuxowQCrmXbcztEyU".includes(word[letter]!))
      return letter === word.length - 1 ? "value" : "other";
  }
  return "other";
}

function hasHttpBodyOptionEvidence(words: readonly string[], client: string, start: number): boolean {
  const args = words.slice(start);
  for (let index = 0; index < args.length; index++) {
    const word = args[index]!;
    if (word === "--") break;
    if (isHttpBodyOption(word, client)) return true;
    if (/^--(?:header|user-agent|referer|user|proxy|output|url|request|cookie|cookie-jar|config|directory-prefix)$/.test(word)) {
      if (word === "--config") return true;
      index++;
      continue;
    }
    if (!/^-[^-]/.test(word)) continue;
    const behavior = client === "wget" ? wgetShortOptionBehavior(word) : curlShortOptionBehavior(word);
    if (behavior === "body") return true;
    if (behavior === "value") index++;
  }
  return false;
}

interface JsonVisitState { nodes: number; changed: boolean }

function visitJson(entry: unknown, level: number, depth: number, state: JsonVisitState): unknown {
  if (++state.nodes > 4096 || level > 32) { state.changed = true; return REDACTED; }
  if (typeof entry === "string") {
    const redacted = redactHttpBodies(entry, depth + 1);
    if (redacted !== entry) state.changed = true;
    return redacted;
  }
  if (Array.isArray(entry)) return entry.map((item) => visitJson(item, level + 1, depth, state));
  if (entry !== null && typeof entry === "object")
    return Object.fromEntries(Object.entries(entry).map(([key, item]) => [key, visitJson(item, level + 1, depth, state)]));
  return entry;
}

/** Actual literal invocations, not strings merely mentioning an HTTP client. */
function segmentHasHttpBodyEvidence(words: readonly string[], globs: readonly boolean[], value: string): boolean {
  if (!words.length) return false;
  const executable = resolveExecutable(words);
  if (!executable || SHELLS.has(executable.name) || SCRIPT_HOSTS.has(executable.name) ||
      DYNAMIC.has(executable.name) || STATEFUL.has(executable.name) || globs.some(Boolean))
    return uncertainHttpBodyEvidence(value);
  return ["curl", "wget"].includes(executable.name) &&
    hasHttpBodyOptionEvidence(words, executable.name, executable.index + 1);
}

function hasHttpBodyEvidence(value: string): boolean {
  const parsed = parseShellCommands(value);
  // Unknown syntax may hide an invocation (substitution, interpreter, heredoc).
  // With a client and body marker present, omit rather than leak into a model.
  if (!parsed?.complete) return uncertainHttpBodyEvidence(value);
  return parsed.segments.some((segment) => segmentHasHttpBodyEvidence(segment.words, segment.globs, value));
}

/** Evidence privacy helper, independent of the unredacted debugging audit sink. */
export function redactHttpBodies(value: string, depth = 0): string {
  if (/^\s*(?:\[|\{|")/.test(value)) {
    let parsed: unknown;
    try { parsed = JSON.parse(value); } catch { /* Not a serialized JSON value. */ }
    if (parsed !== undefined) {
      if (depth >= 8) return REDACTED;
      const state: JsonVisitState = { nodes: 0, changed: false };
      const visited = visitJson(parsed, 0, depth, state);
      return state.changed ? JSON.stringify(visited) : value;
    }
  }
  return hasHttpBodyEvidence(value) ? "[REDACTED HTTP BODY AND COMMAND EVIDENCE]" : value;
}

/** Literal credential syntax that must not reach model prompts as plain evidence. */
const URL_USERINFO = /((?:[a-z][a-z0-9+.-]*:)?\/\/)[^\s/@]+@/gi;
const CREDENTIAL_PARAM_NAME = /(?:^|[_.-])(?:token|tokens|secrets?|password|passwd|signature|credentials?|api[_-]?key|apikey|key|auth|sig)(?:$|[_.-])/i;
const CREDENTIAL_HEADER = /(^|[^A-Za-z0-9_-])((?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|x-access-token|x-amz-security-token)["']?\s*:\s*["']?)[^"'\r\n]+/gi;
const AUTH_SCHEME = /\b(Bearer\s+)[A-Za-z0-9._~+/=-]{6,}/gi;
const WELL_KNOWN_TOKEN = /\b(?:gh[pousr]_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}|xox[abposr]-[A-Za-z0-9-]{8,}|sk-[A-Za-z0-9_-]{8,}|sk_(?:live|test)_[A-Za-z0-9]{8,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|ya29\.[0-9A-Za-z_-]{8,}|glpat-[A-Za-z0-9_-]{10,}|npm_[A-Za-z0-9]{20,}|pypi-[A-Za-z0-9_-]{20,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b/g;
const QUERY_PARAM = /([?&])([^=&\s#]+)=([^&#\s"']*)/g;
const PARAM_WORD_BOUNDARY = /([a-z0-9])([A-Z])/g;
const PARAM_SEPARATOR = /[^A-Za-z0-9]+/g;
const ENCODED_OCTET = /%[0-9A-Fa-f]{2}/;
const MAX_PARAM_DECODES = 4;

/** Malformed or still-encoded escapes cannot prove a name harmless, so either
 * counts as credential-bearing. */
function decodedParamName(name: string): string | undefined {
  let decoded = name;
  for (let pass = 0; pass < MAX_PARAM_DECODES && ENCODED_OCTET.test(decoded); pass++) {
    try { decoded = decodeURIComponent(decoded); } catch { return undefined; }
  }
  return ENCODED_OCTET.test(decoded) ? undefined : decoded;
}

/** `accessToken`, `access%5Ftoken` and `X-Api-Key` share the snake-case word
 * boundaries the credential-name check understands. */
function credentialParamName(name: string): boolean {
  const decoded = decodedParamName(name);
  if (decoded === undefined) return true;
  return CREDENTIAL_PARAM_NAME.test(decoded.replace(PARAM_WORD_BOUNDARY, "$1_$2").replace(PARAM_SEPARATOR, "_"));
}

function redactQueryCredentials(value: string): string {
  return value.replace(QUERY_PARAM, (match, prefix: string, name: string) =>
    credentialParamName(name) ? `${prefix}${name}=${REDACTED}` : match);
}

/** Screens the literal credential shapes that can survive HTTP-body screening. */
export function redactCredentialSyntax(value: string): string {
  const redacted = value
    .replace(URL_USERINFO, "$1[REDACTED]@")
    .replace(CREDENTIAL_HEADER, "$1$2[REDACTED]")
    .replace(AUTH_SCHEME, "$1[REDACTED]")
    .replace(WELL_KNOWN_TOKEN, REDACTED);
  return redactQueryCredentials(redacted);
}

/** OFF unless explicitly enabled. Records are neither redacted nor truncated. */
export function createAuditLog(setting: DebugLogSetting): AuditLog | undefined {
  return createJsonlLog(setting);
}
