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
const POSSIBLE_HTTP_BODY = /--(?:(?:expand-)?(?:data|json|form)|post-|body-|upload-file|execute|config)|-[^- \t\n]*[dFTKe]/;

/** Actual literal invocations, not strings merely mentioning an HTTP client. */
function hasHttpBodyEvidence(value: string): boolean {
  const parsed = parseShellCommands(value);
  // Unknown syntax may hide an invocation (substitution, interpreter, heredoc).
  // With a client and body marker present, omit rather than leak into a model.
  const uncertainBody = () => {
    const literal = normalizeContinuations(value).replace(/['"\\]/g, "");
    return /(?:curl|wget)/.test(literal) && POSSIBLE_HTTP_BODY.test(literal);
  };
  if (!parsed?.complete) return uncertainBody();
  for (const segment of parsed.segments) {
    if (!segment.words.length) continue;
    const executable = resolveExecutable(segment.words);
    if (!executable || SHELLS.has(executable.name) || SCRIPT_HOSTS.has(executable.name) ||
        DYNAMIC.has(executable.name) || STATEFUL.has(executable.name) || segment.globs.some(Boolean)) {
      if (uncertainBody()) return true;
      continue;
    }
    if (!["curl", "wget"].includes(executable.name)) continue;
    const args = segment.words.slice(executable.index + 1);
    for (let index = 0; index < args.length; index++) {
      const word = args[index];
      if (word === "--") break;
      if (HTTP_BODY_OPTION.test(word)) return true;
      // These common value-taking options make the next word data, not a flag.
      if (/^--(?:header|user-agent|referer|user|proxy|output|url|request|cookie|cookie-jar|config|directory-prefix)$/.test(word)) {
        if (word === "--config") return true; // A config file can supply body options.
        index++;
        continue;
      }
      if (!/^-[^-]/.test(word)) continue;
      if (executable.name === "wget") {
        // -e/--execute supplies wgetrc settings, including post_data. Resolve
        // clustered options only up to the first value-taking option.
        for (let letter = 1; letter < word.length; letter++) {
          if (word[letter] === "e") return true;
          if ("oaOUtTwQDAlIRX".includes(word[letter])) {
            if (letter === word.length - 1) index++;
            break;
          }
        }
        continue;
      }
      for (let letter = 1; letter < word.length; letter++) {
        if ("dFT".includes(word[letter])) return true;
        if (word[letter] === "K") return true; // curl config is not bounded evidence.
        if ("HAeuxowQCrmXbcztEyU".includes(word[letter])) {
          if (letter === word.length - 1) index++;
          break;
        }
      }
    }
  }
  return false;
}

/** Evidence privacy helper, independent of the unredacted debugging audit sink. */
export function redactHttpBodies(value: string, depth = 0): string {
  if (/^\s*(?:\[|\{|")/.test(value)) {
    let parsed: unknown;
    try { parsed = JSON.parse(value); } catch { /* Not a serialized JSON value. */ }
    if (parsed !== undefined) {
      if (depth >= 8) return REDACTED;
      let nodes = 0;
      const visit = (entry: unknown, level: number): unknown => {
        if (++nodes > 4096 || level > 32) return REDACTED;
        if (typeof entry === "string") return redactHttpBodies(entry, depth + 1);
        if (Array.isArray(entry)) return entry.map((item) => visit(item, level + 1));
        if (entry !== null && typeof entry === "object") return Object.fromEntries(Object.entries(entry).map(([key, item]) => [key, visit(item, level + 1)]));
        return entry;
      };
      return JSON.stringify(visit(parsed, 0));
    }
  }
  return hasHttpBodyEvidence(value) ? "[REDACTED HTTP BODY AND COMMAND EVIDENCE]" : value;
}

/** OFF unless explicitly enabled. Records are neither redacted nor truncated. */
export function createAuditLog(setting: DebugLogSetting): AuditLog | undefined {
  return createJsonlLog(setting);
}
