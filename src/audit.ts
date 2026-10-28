import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { ReviewErrorKind } from "./errors.js";

export interface AuditRecord {
  ts: string;
  reviewID: string;
  sessionID: string;
  agent?: string;
  action: string;
  resources: string[];
  hostEffect: string;
  decision: string;
  stage: string;
  reason: string;
  durationMs: number;
  error?: boolean;
  errorKind?: ReviewErrorKind;
  errorDetail?: string;
  traceID?: string;
  spanID?: string;
}

export interface AuditLog { write(record: AuditRecord): void }

const MAX_BYTES = 10 * 1024 * 1024;
const MAX_RESOURCES = 16;
const MAX_RESOURCE_CHARS = 512;
const MAX_REASON_CHARS = 512;
const MAX_ACTION_CHARS = 128;
const MAX_AGENT_CHARS = 128;
const MAX_STAGE_CHARS = 64;
const ERROR_KINDS: readonly ReviewErrorKind[] = ["deadline", "timeout", "cancelled", "provider", "invalid-output", "context"];

export function defaultAuditPath(): string {
  const base = process.env.XDG_STATE_HOME || path.join(os.homedir(), ".local", "state");
  return path.join(base, "opencode-auto-mode", "decisions.jsonl");
}

function clip(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

/**
 * Bounds every exported record. Local audit and OTLP must describe the same
 * payload, so both call this before serialising anything.
 */
export function sanitizeRecord(record: AuditRecord): AuditRecord {
  return {
    ...record,
    action: clip(record.action, MAX_ACTION_CHARS),
    resources: record.resources.slice(0, MAX_RESOURCES).map((resource) => clip(resource, MAX_RESOURCE_CHARS)),
    reason: clip(record.reason, MAX_REASON_CHARS),
    stage: clip(record.stage, MAX_STAGE_CHARS),
    ...(record.agent === undefined ? {} : { agent: clip(record.agent, MAX_AGENT_CHARS) }),
    ...(record.errorKind === undefined ? {} : { errorKind: ERROR_KINDS.includes(record.errorKind) ? record.errorKind : "provider" }),
    ...(record.errorDetail === undefined ? {} : { errorDetail: clip(record.errorDetail, MAX_REASON_CHARS) }),
  };
}

export function createAuditLog(setting: boolean | string | undefined): AuditLog | undefined {
  if (setting === undefined || setting === false) return undefined;
  const file = typeof setting === "string" ? setting : defaultAuditPath();
  return {
    write(record) {
      let fd: number | undefined;
      try {
        fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
        try { if (fs.statSync(file).size > MAX_BYTES) fs.renameSync(file, `${file}.1`); } catch { /* no file yet */ }
        fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_APPEND | fs.constants.O_NOFOLLOW, 0o600);
        fs.writeSync(fd, `${JSON.stringify(sanitizeRecord(record))}\n`);
      } catch {
        // Auditing is best effort and must not interrupt permission review.
      } finally { if (fd !== undefined) fs.closeSync(fd); }
    },
  };
}
