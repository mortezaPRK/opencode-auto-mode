#!/usr/bin/env bun
// Offline static diagnostics only: no database, tool execution, or model requests.
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseOptions } from "../src/config.js";
import { scoreRequest } from "../src/score.js";

const args = process.argv.slice(2);
const option = (name: string) => { const i = args.indexOf(`--${name}`); return i < 0 ? undefined : args[i + 1]; };
if (args.includes("--help")) {
  console.log("Usage: bun scripts/replay.ts --input <audit.jsonl> [--project <root>] [--json]");
  console.log("Repository-checkout tool only; scripts/ is not included in the published package.");
  console.log("Static diagnostics only; skips nondecision events, never reconstructs native or model outcomes. Raw input may contain secrets.");
  process.exit(0);
}
const input = option("input");
if (!input) throw new Error("--input is required; no personal audit path is selected automatically");
const project = option("project");
// A valid 1.1.0 option set for the static scorer. Replay never calls a classifier
// or uses the audit path; the input is read explicitly from --input.
const options = parseOptions({ classifiers: [{ type: "static" }] });
const tally = new Map<string, number>();
let count = 0;
let skipped = 0;
for (const [index, line] of readFileSync(resolve(input), "utf8").split("\n").entries()) {
  if (!line.trim()) continue;
  let value: unknown;
  try { value = JSON.parse(line); }
  catch { throw new Error(`Invalid JSON at line ${index + 1}`); }
  if (!value || typeof value !== "object" || Array.isArray(value)) { skipped++; continue; }
  const envelope = value as Record<string, unknown>;
  // Full-event logs may wrap a decision in payload; permission/tool events with
  // action/resources are not decisions and must not be silently replayed as one.
  const wrapped = envelope.type === "decision" || envelope.type === "auto-mode.decision";
  const record = (wrapped && envelope.payload && typeof envelope.payload === "object" && !Array.isArray(envelope.payload)
    ? envelope.payload : envelope) as Record<string, unknown>;
  if (typeof record.decision !== "string" || typeof record.stage !== "string" ||
      (typeof envelope.type === "string" && !wrapped && envelope.type !== "permission.decision")) { skipped++; continue; }
  if (typeof record.action !== "string" || !Array.isArray(record.resources) || !record.resources.every((resource) => typeof resource === "string"))
    throw new Error(`Invalid decision action/resources at line ${index + 1}`);
  const request = { action: record.action, resources: record.resources as string[], agent: typeof record.agent === "string" ? record.agent : "unknown",
    ...(project === undefined ? {} : { projectDir: resolve(project) }) };
  const score = scoreRequest(request, options);
  const guarded = score.ask === true;
  const decision = guarded ? "ask" : score.deny === true ? "deny" : score.band === "low" ? "allow" : "ask";
  const stage = guarded || score.deny === true ? "static" : score.band === "low" ? "score" : `${score.band}:model-unresolved`;
  const key = `${decision}/${stage}`;
  tally.set(key, (tally.get(key) ?? 0) + 1); count++;
  if (args.includes("--json")) console.log(JSON.stringify({ line: index + 1, sessionID: record.sessionID,
    action: request.action, recordedDecision: record.decision, recordedProposedDecision: record.proposedDecision,
    decision, stage, score: score.band, reason: score.reason,
    fidelity: "static-diagnostics-only; native/model/historical state not reconstructed" }));
}
const summary = `Routed ${count} decision records; skipped ${skipped} nondecision records. Nothing executed or sent to a model.`;
if (args.includes("--json")) console.error(summary);
else {
  console.log(summary);
  console.log("Not a reconstruction of native policies, saved approvals, historical classifiers, reviewer verdicts, VCS state or unexposed events.");
  for (const [key, total] of [...tally].sort((a, b) => b[1] - a[1])) console.log(`${key}: ${total}`);
}
