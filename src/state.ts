import * as fs from "node:fs";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { privateFile, STORAGE_DIR } from "./storage.js";

export type DecisionKind = "reviewing" | "allow" | "deny" | "ask";

export interface DecisionRecord {
  requestID: string;
  sessionID: string;
  decision: DecisionKind;
  reason: string;
  at: number;
  action?: string;
  resources?: string[];
}

export const STATE_FILE = path.join(STORAGE_DIR, "state.json");

const MAX_AGE_MS = 10 * 60 * 1000;
const MAX_CONFIG_MESSAGE = 1024;

export interface ConfigErrorRecord {
  directory: string;
  message: string;
}

interface StoredConfigError extends ConfigErrorRecord {
  at: number;
}

function canonicalDirectory(directory: string): string {
  try { return fs.realpathSync.native(directory); }
  catch { return path.resolve(directory); }
}

function configErrorFile(directory: string): string {
  return `config-error-${createHash("sha256").update(directory).digest("hex")}.json`;
}

function readConfigErrorFile(directory: string): StoredConfigError | undefined {
  let fd: number | undefined;
  try {
    fd = privateFile(configErrorFile(directory), false);
    if (fs.fstatSync(fd).size > 4096) return undefined;
    const parsed: unknown = JSON.parse(fs.readFileSync(fd, "utf8"));
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return undefined;
    const record = parsed as Partial<StoredConfigError>;
    if (record.directory !== directory || typeof record.message !== "string" ||
        record.message.length > MAX_CONFIG_MESSAGE || typeof record.at !== "number" || !Number.isFinite(record.at))
      return undefined;
    return { directory: record.directory, message: record.message, at: record.at };
  } catch {
    return undefined;
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}

function writeConfigError(record: StoredConfigError): void {
  let fd: number | undefined;
  const temporary = `config-error-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}.tmp`;
  const target = configErrorFile(record.directory);
  try {
    fd = privateFile(temporary, true);
    fs.writeSync(fd, JSON.stringify(record), 0);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(path.join(STORAGE_DIR, temporary), path.join(STORAGE_DIR, target));
  } catch {
    // Badge state is best effort and must not interrupt permission review.
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    try { fs.rmSync(path.join(STORAGE_DIR, temporary), { force: true }); }
    catch { /* best effort */ }
  }
}

/** Records that the plugin options for a location are unusable, so the TUI can show it. */
export function recordConfigError(directory: string, message: string): void {
  const canonical = canonicalDirectory(directory);
  writeConfigError({ directory: canonical, message: message.slice(0, MAX_CONFIG_MESSAGE), at: Date.now() });
}

export function readConfigError(directory: string | undefined): ConfigErrorRecord | undefined {
  if (directory === undefined) return undefined;
  const canonical = canonicalDirectory(directory);
  const record = readConfigErrorFile(canonical);
  return record === undefined ? undefined : { directory: record.directory, message: record.message };
}

export function clearConfigError(directory: string): void {
  try {
    fs.rmSync(path.join(STORAGE_DIR, configErrorFile(canonicalDirectory(directory))), { force: true });
  } catch { /* best effort */ }
}

export function readDecisions(): Record<string, DecisionRecord> {
  let fd: number | undefined;
  try {
    fd = privateFile("state.json", false);
    if (fs.fstatSync(fd).size > 65_536) return {};
    const raw = fs.readFileSync(fd, "utf8");
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return {};
    return Object.fromEntries(Object.entries(parsed).filter(([id, value]) =>
      id.length < 256 && typeof value === "object" && value !== null &&
      value.requestID === id && typeof value.sessionID === "string" && value.sessionID.length < 256 &&
      typeof value.reason === "string" && value.reason.length <= 4096 &&
      typeof value.at === "number" && Number.isFinite(value.at) &&
      (value.action === undefined || typeof value.action === "string") &&
      (value.resources === undefined || (Array.isArray(value.resources) && value.resources.length <= 256 &&
        value.resources.every((resource: unknown) => typeof resource === "string"))) &&
      ["reviewing", "allow", "deny", "ask"].includes(value.decision))) as Record<string, DecisionRecord>;
  } catch {
    return {};
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}

export function recordDecision(record: DecisionRecord): void {
  const all = readDecisions();
  Object.defineProperty(all, record.requestID, { value: record, enumerable: true, configurable: true });
  const cutoff = Date.now() - MAX_AGE_MS;
  for (const [id, rec] of Object.entries(all)) {
    if (rec.at < cutoff || Object.keys(all).length > 128) delete all[id];
  }
  let fd: number | undefined;
  try {
    const data = JSON.stringify(all);
    if (Buffer.byteLength(data) > 65_536) return;
    fd = privateFile("state.json", true);
    fs.ftruncateSync(fd, 0);
    fs.writeSync(fd, data, 0);
  } catch {
    // Badge state is best effort and must not interrupt permission review.
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}
