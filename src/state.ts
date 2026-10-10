import * as fs from "node:fs";
import * as path from "node:path";
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
  } finally { if (fd !== undefined) fs.closeSync(fd); }
}
