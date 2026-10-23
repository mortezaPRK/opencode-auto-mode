#!/usr/bin/env bun
// Offline, read-only replay of recorded OpenCode tool calls through the classifier.
// Nothing is executed: the OpenCode database is opened read-only, tools are never run,
// no network calls are made, and the LLM stage is stubbed (reported as "llm?").
import { Database } from "bun:sqlite";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { parse as shellParse } from "shell-quote";
import { parseOptions, stagesFor, type AutoModeOptions } from "../src/config.js";
import { compositeDecision } from "../src/classifier.js";
import type { PermissionRequest, ReviewResult } from "../src/reviewer.js";

const args = process.argv.slice(2);
const flag = (name: string) => args.includes(`--${name}`);
const opt = (name: string) => { const i = args.indexOf(`--${name}`); return i >= 0 ? args[i + 1] : undefined; };
if (flag("help")) {
  console.log(`Usage: bun scripts/replay.ts [--session <id>] [--days 14] [--agent build|any] [--config <opencode.json>]
                          [--db <opencode.db>] [--show 25] [--json]`);
  process.exit(0);
}

const dbPath = opt("db") ?? path.join(os.homedir(), ".local/share/opencode/opencode.db");
const configPath = opt("config") ?? path.join(os.homedir(), ".config/opencode/opencode.json");
const days = Number(opt("days") ?? 14);
const agentFilter = opt("agent") ?? "any";
const show = Number(opt("show") ?? 25);

function stripJsonc(text: string): string {
  let out = "";
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      out += c;
      if (c === "\\") out += text[++i] ?? "";
      else if (c === '"') inString = false;
    } else if (c === '"') { inString = true; out += c; }
    else if (c === "/" && text[i + 1] === "/") { while (i < text.length && text[i] !== "\n") i++; out += "\n"; }
    else if (c === "/" && text[i + 1] === "*") { i += 2; while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++; i++; }
    else out += c;
  }
  return out.replace(/,(\s*[}\]])/g, "$1");
}

function loadOptions(): AutoModeOptions {
  const config = JSON.parse(stripJsonc(fs.readFileSync(configPath, "utf8"))) as { plugins?: unknown[] };
  const entry = (config.plugins ?? []).find((plugin) =>
    typeof plugin === "object" && plugin !== null && /opencode-auto-mode/.test(String((plugin as { package?: string }).package)));
  return parseOptions((entry as { options?: unknown } | undefined)?.options ?? {});
}

function splitShell(command: string): string[] {
  const lines = command.split("\n").map((line) => line.trim()).filter(Boolean);
  if (lines.length > 1) return lines.flatMap(splitShell);
  try {
    const tokens = shellParse(command);
    const segments: string[][] = [[]];
    for (const token of tokens) {
      if (typeof token === "string") segments.at(-1)!.push(token);
      else if ("op" in token && ["&&", "||", ";", "|", "&"].includes(token.op)) segments.push([]);
      else return [command];
    }
    const parts = segments.filter((segment) => segment.length).map((segment) => segment.join(" "));
    return parts.length ? parts : [command];
  } catch { return [command]; }
}

interface Call { sessionID: string; agent: string; tool: string; input: Record<string, unknown>; status: string; at: number; directory?: string }

function toRequest(call: Call): PermissionRequest {
  const str = (key: string) => typeof call.input[key] === "string" ? call.input[key] as string : undefined;
  let action = call.tool;
  let resources: string[] = [];
  if (call.tool === "shell" || call.tool === "bash") { action = "shell"; resources = splitShell(str("command") ?? ""); }
  else if (["read", "edit", "write"].includes(call.tool)) resources = [str("filePath") ?? str("path") ?? ""].filter(Boolean);
  else if (call.tool === "patch") {
    action = "edit";
    resources = [...(str("patchText") ?? "").matchAll(/^\*\*\* (?:Update|Add|Delete) File: (.+)$/gm)].map((m) => m[1].trim());
  } else if (call.tool === "webfetch") resources = [str("url") ?? ""].filter(Boolean);
  else if (call.tool === "grep" || call.tool === "glob") resources = [str("path") ?? str("pattern") ?? ""].filter(Boolean);
  return { action, resources, agent: call.agent, projectDir: call.directory, isDelegation: action === "task" || action === "subagent" };
}

const options = loadOptions();
const stages = stagesFor(options);
const db = new Database(dbPath, { readonly: true });
const cutoff = Date.now() - days * 86_400_000;
const sessionID = opt("session");
const rows = db.query(
  `select m.session_id as sid, m.data as data, m.time_created as at, s.directory as directory
   from session_message m join session_v2 s on s.id = m.session_id
   where m.type = 'assistant' and m.time_created > ?1 and (?2 is null or m.session_id = ?2)
   order by m.time_created`,
).all(cutoff, sessionID ?? null) as { sid: string; data: string; at: number; directory: string }[];

const calls: Call[] = [];
for (const row of rows) {
  const message = JSON.parse(row.data) as { agent?: string; content?: { type: string; name: string; state?: { status?: string; input?: Record<string, unknown> } }[] };
  const agent = message.agent ?? "unknown";
  if (agentFilter !== "any" && agent !== agentFilter) continue;
  for (const part of message.content ?? []) {
    if (part.type !== "tool" || !part.state?.input) continue;
    calls.push({ sessionID: row.sid, agent, tool: part.name, input: part.state.input, status: part.state.status ?? "?", at: row.at, directory: row.directory });
  }
}

const llmStub = async (): Promise<ReviewResult> => ({ decision: "ask", reason: "would reach LLM stage", stage: "llm?" });
const memo = new Map<string, ReviewResult>();
const tally = new Map<string, number>();
const flagged: { call: Call; request: PermissionRequest; result: ReviewResult }[] = [];
for (const call of calls) {
  const request = toRequest(call);
  const memoKey = JSON.stringify([request.action, request.resources, request.projectDir]);
  let result = memo.get(memoKey);
  if (!result) { result = await compositeDecision(stages, request, llmStub); memo.set(memoKey, result); }
  const key = `${result.decision.padEnd(5)} ${result.stage ?? "?"}`;
  tally.set(key, (tally.get(key) ?? 0) + 1);
  if (flag("json")) console.log(JSON.stringify({ session: call.sessionID, tool: call.tool, action: request.action, resources: request.resources, decision: result.decision, stage: result.stage, reason: result.reason, ranAs: call.status }));
  if (result.decision === "deny" || (result.decision === "ask" && result.stage !== "llm?")) flagged.push({ call, request, result });
}
if (flag("json")) process.exit(0);

console.log(`Replayed ${calls.length} tool calls (agent=${agentFilter}, ${sessionID ?? `last ${days} days`}) with ${configPath}`);
console.log(`Stages: ${stages.map((stage) => stage.type).join(" -> ")}   (nothing executed; LLM stage stubbed)\n`);
console.log("decision stage        count   share");
for (const [key, count] of [...tally].sort((a, b) => b[1] - a[1]))
  console.log(`${key.padEnd(18)} ${String(count).padStart(6)}  ${((count / Math.max(calls.length, 1)) * 100).toFixed(1)}%`);
console.log(`\nDeny / non-LLM ask (first ${show} of ${flagged.length}):`);
for (const { call, request, result } of flagged.slice(0, show))
  console.log(`- [${result.decision}/${result.stage}] ${request.action} ${request.resources.join(" ; ").slice(0, 140)}  (ran: ${call.status}) — ${result.reason}`);
