#!/usr/bin/env bun
// Read-only audit replay. Raw rows are untrusted, so they are never executed, printed, or
// copied into this repository; --live only sends rebuilt evidence through the authenticated CLI.
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { closeSync, createReadStream, existsSync, openSync, readdirSync, statSync } from "node:fs";
import { createInterface } from "node:readline";
import { basename, dirname, join, resolve } from "node:path";
import { parseArgs as parseCliArgs, promisify, type ParseArgsOptionsConfig } from "node:util";
import { defaultAuditPath, redactHttpBodies } from "../src/audit.js";
import { codeModeReviewResources } from "../src/code-mode.js";
import { Model } from "@opencode/schema/model";
import { buildDecisionEvidence, decisionStage, DECISION_AUTHORIZATION_INSTRUCTIONS, DECISION_SAFETY_INSTRUCTIONS, type DecisionInput } from "../src/decision.js";
import type { DecisionEvidence, DecisionEvidenceRequest } from "../src/decision-evidence.js";
import { ReviewFailure } from "../src/errors.js";
import { buildOperationEvidence, createToolInputStore, type CapturedToolInput, type ToolInputStore } from "../src/operation-evidence.js";
import { isOpaqueOperationLoss, type OperationEvidence, type StageResult } from "../src/reviewer.js";
import { argFailure, isRecord, mapLimit } from "./lib.js";

const DEFAULT_THRESHOLD = 0.9;
const DEFAULT_HOLDOUT = 0.2;
const DEFAULT_LIMIT = 5;
const DEFAULT_CONCURRENCY = 1;
const MAX_CONCURRENCY = 4;
const DEFAULT_LIVE_TIMEOUT_MS = 20_000;
const MAX_AUDIT_LINE_CHARS = 16 * 1024 * 1024;
const MAX_EVIDENCE_TEXT_CHARS = 256 * 1024;
const MAX_CHRONOLOGY_BYTES = 12_000;
const MAX_PENDING_HOSTS = 512;
const MAX_PENDING_REVIEWS = 4096;
const MAX_TOOL_CAPTURES = 256;
const MAX_DETAIL_ROWS = 200;
const MAX_RECORDED_PLATFORM_CHARS = 64;
const MAX_RECORDED_SHELL_CHARS = 500;
const MAX_RECORDED_TARGETS = 64;
const MAX_RECORDED_TARGET_CHARS = 2_000;
const MAX_PROBLEMS = 8;
const CLI_MAX_BUFFER = 2 * 1024 * 1024;
const DELEGATION_LOSS = "Delegated context was redacted or lost";
/** Audit rows are untrusted; only supported verdict/error categories may reach output. */
const VERDICTS: readonly string[] = ["allow", "deny", "ask", "abstain"];
const ERROR_KINDS: readonly string[] = ["deadline", "timeout", "cancelled", "provider", "invalid-output", "context"];
const UNKNOWN_VALUE = "unknown";

type Counts = Record<string, number>;
type Json = Record<string, unknown>;

interface ModelFilter { providerID: string; id: string; variant?: string }
interface CliOptions {
  inputs: string[];
  rotations?: number;
  model?: ModelFilter;
  threshold?: number;
  holdout: number;
  seed: number;
  live: boolean;
  limit: number;
  concurrency: number;
  liveTimeoutMs: number;
  opencodeBin: string;
  json: boolean;
  details: boolean;
  help: boolean;
}

interface SourceStats {
  files: number;
  lines: number;
  bytes: number;
  parsed: number;
  malformed: number;
  oversized: number;
  skipped: number;
}

interface AuditSource { file: string; name: string; size: number; mtimeMs: number; fd: number }

interface SnapshotReport { capturedAt: string; files: number; bytes: number; fingerprint: string }

interface PromptReport { capturedAt: string; hash: string; questions: string[] }

interface Problem { file: number; line: number; kind: string }

interface StageStart {
  stageIndex: number;
  type: string;
  model?: string;
  minConfidence?: number;
  timeoutMs?: number;
  ts?: string;
}

interface StageEnd {
  decision?: string;
  errorKind?: string;
  stage?: string;
  hasError: boolean;
  ts?: string;
}

interface HostEvent {
  reviewID: string;
  sessionID?: string;
  action: string;
  resources: string[];
  agent?: string;
  metadata?: Json;
  metadataInvalid: boolean;
  source: unknown;
  projectDir?: string;
  capture?: CapturedToolInput;
}

interface FinalRow { decision: string; stage: string; errorKind?: string }

interface BeforeEvent {
  model: string;
  providerID: string;
  id: string;
  variant?: string;
  format: "predicate" | "legacy" | "unknown";
  questions: unknown[];
  evidenceText?: string;
  malformedEvidence: boolean;
}

interface AfterEvent {
  answers?: unknown;
  hasError: boolean;
  callID?: string;
  ts?: string;
}

interface DecisionRequestAudit {
  key: string;
  reviewID: string;
  sessionID?: string;
  stageIndex: number;
  callID?: string;
  ts?: string;
  before: BeforeEvent;
  after?: AfterEvent;
}

interface ReviewState {
  reviewID: string;
  sessionID?: string;
  host?: HostEvent;
  stages: Map<number, StageStart>;
  ends: Map<number, StageEnd>;
  final?: FinalRow;
  requests: Map<string, DecisionRequestAudit>;
}

interface State {
  stats: SourceStats;
  reviews: Map<string, ReviewState>;
  pendingHosts: Map<string, HostEvent>;
  pendingStarts: Map<string, Map<number, StageStart>>;
  toolInputs: ToolInputStore;
  seen: Set<string>;
  problems: Problem[];
  duplicateEvents: number;
  filteredOut: number;
  orphanAfter: number;
  nonDecisionStage: number;
}

interface RecordedOperation {
  /** Bounded target spellings carried by the record. */
  targets?: string[];
  /** True only for a complete record whose targets are bounded canonical evidence. */
  canonical: boolean;
}

interface RecordedEvidence {
  action?: string;
  resources?: string[];
  agent?: string;
  projectDir?: string;
  worktreeRoot?: string;
  scopeResolution?: "unknown";
  platform?: string;
  shell?: { platform?: string; interpreter?: string };
  /** Targets were resolved on the recording host; replay must not re-resolve
   * their spellings under this host's rules or a changed filesystem. */
  operation?: RecordedOperation;
  /** Recorded execution context that cannot be replayed faithfully; the request
   * must abstain before generation instead of substituting the replay host. */
  contextLoss?: "platform" | "shell";
  userMessages?: string[];
  delegations?: string[];
  /** True when the recorded delegation list was dropped (bounds or invalid entries). */
  delegationsLost: boolean;
  transcript?: string;
  staticAnalysis?: { band: string; reason: string; findings?: string[] };
  gitState?: { branch?: string; defaultBranch?: string; clean?: boolean };
}

interface Candidate {
  request: DecisionEvidenceRequest;
  evidence: DecisionEvidence;
  hostJoined: boolean;
  missingHost: boolean;
  missingChronology: boolean;
  operationMissing: boolean;
  metadataInvalid: boolean;
  codeModeError: boolean;
  terminal?: "opaque";
  preGeneration?: "resources" | "platform" | "shell" | "operation" | "delegations" | "too-large";
  bytes: number;
  readOnly: boolean;
  userMessagesRetained: boolean;
  chronologyFallback: boolean;
  resourcesChanged: boolean;
  operationAccess?: string;
  operationTool?: string;
  operationTargets: number;
  operationArguments: number;
}

interface PredicateOutcome {
  status: "allow" | "abstain" | "invalid" | "error" | "missing-after" | "pre-generation" | "terminal" | "after-error";
  errorKind?: string;
  safety?: number;
  authorization?: number;
  calls?: number;
}

interface LegacyOutcome {
  status: "allow" | "deny" | "abstain" | "invalid" | "missing-after" | "after-error";
  confidence?: number;
  selected?: number;
}

interface RequestView {
  key: string;
  reviewID: string;
  sessionID?: string;
  format: "predicate" | "legacy" | "unknown";
  threshold: number;
  stageStartMissing: boolean;
  before: BeforeEvent;
  after?: AfterEvent;
  recordedEnd?: StageEnd;
  llmEnd?: StageEnd;
  final?: FinalRow;
  fallback: boolean;
  candidate: Candidate;
  predicate?: PredicateOutcome;
  legacy?: LegacyOutcome;
  split: "primary" | "holdout";
}

interface LiveResult {
  reviewID: string;
  format: string;
  action: string;
  status: string;
  decision?: string;
  recorded?: string;
  llm?: string;
  errorKind?: string;
  calls: number;
  safety?: number;
  authorization?: number;
}

interface LiveActionSummary { requests: number; primary: number; holdout: number; statuses: Counts }

interface LiveSummary {
  enabled: true;
  sampling: string;
  sampleFingerprint: string;
  eligible: number;
  selected: number;
  readOnlySelected: number;
  sessions: number;
  modelCalls: number;
  modelErrors: number;
  preGeneration: number;
  statuses: Counts;
  comparisons: Counts;
  vsLlm: Counts;
  actions: Record<string, LiveActionSummary>;
  results?: LiveResult[];
}

interface ActionSummary {
  requests: number;
  primary: number;
  holdout: number;
  predicate: Counts;
  legacy: Counts;
  llm: Counts;
  recorded: Counts;
  predicateVsLlm: Counts;
  fallback: number;
}

interface RequestDetail {
  reviewID: string;
  format: RequestView["format"];
  split: RequestView["split"];
  threshold: number;
  action: string;
  predicate: string;
  legacy: string;
  recorded: string;
  llm: string;
  final: string;
  safety?: number;
  authorization?: number;
  confidence?: number;
}

interface DetailsReport { total: number; rows: RequestDetail[] }

interface EligibilityReport {
  total: number;
  eligible: number;
  reasons: Counts;
  readOnly: { total: number; eligible: number; predicate: Counts; llm: Counts };
  simpleGrep: { eligible: number; predicate: Counts; llm: Counts };
}

interface RebuildReport {
  userMessagesRetained: number;
  chronologyFallback: number;
  resourcesChanged: number;
  delegationsRetained: number;
  operationAccess: Counts;
  operationTool: Counts;
  operationTargets: number;
  operationArguments: number;
}

interface SplitSummary {
  requests: number;
  sessions: number;
  predicate: Counts;
  legacy: Counts;
  llm: Counts;
}

interface Report {
  tool: string;
  mode: "dry-run" | "live";
  filter: string;
  sources: SourceStats;
  snapshot: SnapshotReport;
  prompt: PromptReport;
  reviews: {
    requests: number;
    sessions: number;
    duplicateEvents: number;
    filteredOut: number;
    orphanAfter: number;
    nonDecisionStage: number;
  };
  formats: Counts;
  evidence: {
    hostJoined: number;
    missingHost: number;
    operationPresent: number;
    operationComplete: number;
    operationIncomplete: number;
    operationMissing: number;
    metadataInvalid: number;
    codeModeError: number;
    missingChronology: number;
    terminal: number;
    preGeneration: Counts;
    bytes: ReturnType<typeof numericSummary>;
  };
  pairing: {
    afterPresent: number;
    missingAfter: number;
    afterError: number;
    malformedEvidence: number;
    stageStartMissing: number;
    decisionEndMissing: number;
  };
  recorded: {
    decisions: Counts;
    errorKinds: Counts;
    fallback: number;
    llmRan: number;
  };
  predicate: {
    /** Recorded answers re-evaluated against rebuilt evidence; not a fresh model result. */
    basis: string;
    outcomes: Counts;
    below: Counts;
    protocol: Counts;
    vsRecorded: Counts;
  };
  legacy: {
    outcomes: Counts;
    vsRecorded: Counts;
  };
  llm: {
    outcomes: Counts;
    vsPredicate: Counts;
    vsLegacy: Counts;
  };
  final: {
    decisions: Counts;
    vsPredicate: Counts;
    vsLegacy: Counts;
  };
  probabilities: {
    safety: ReturnType<typeof numericSummary>;
    authorization: ReturnType<typeof numericSummary>;
    legacyConfidence: ReturnType<typeof numericSummary>;
    legacySelected: ReturnType<typeof numericSummary>;
    safetyBuckets: Counts;
    authorizationBuckets: Counts;
  };
  thresholds: Counts;
  split: Record<string, SplitSummary>;
  actions: Record<string, ActionSummary>;
  eligibility: EligibilityReport;
  rebuild: RebuildReport;
  problems: Problem[];
  details?: DetailsReport;
  live?: LiveSummary;
  fidelity: string;
}

const execFileAsync = promisify(execFile);

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function finiteNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function probability(value: unknown): number | undefined {
  const number = finiteNumber(value);
  return number !== undefined && number >= 0 && number <= 1 ? number : undefined;
}

function stageIndexValue(value: unknown): number | undefined {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : undefined;
}

/** Verdict and error-category values are untrusted audit text; anything outside
 * the supported enums collapses to one fixed category instead of being printed. */
function enumText(value: unknown, allowed: readonly string[]): string | undefined {
  if (value === undefined) return undefined;
  return typeof value === "string" && allowed.includes(value) ? value : UNKNOWN_VALUE;
}

function stringArray(value: unknown): string[] | undefined {
  return Array.isArray(value) && value.every((item) => typeof item === "string") ? value as string[] : undefined;
}

/** Own-property-safe: untrusted names such as `constructor` or `__proto__` are
 * ordinary count keys, not inherited attributes or prototype writes. */
function bump(counts: Counts, key: string): void {
  Object.defineProperty(counts, key, {
    value: (Object.hasOwn(counts, key) ? counts[key]! : 0) + 1,
    enumerable: true, configurable: true, writable: true,
  });
}

function sortedCounts(counts: Counts): Counts {
  return Object.fromEntries(Object.entries(counts).sort(([left], [right]) => left.localeCompare(right)));
}

// FNV-1a; changing it changes the deterministic holdout and sampling contract.
function hash32(value: string): number {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index++) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

function modelFilter(value: string): ModelFilter {
  let ref: { providerID: string; id: string; variant?: string };
  try { ref = Model.Ref.parse(value); }
  catch { throw new Error("--model must be <provider>/<model>[#variant]"); }
  return { providerID: ref.providerID, id: ref.id, ...(ref.variant === undefined ? {} : { variant: ref.variant }) };
}

function modelText(ref: { providerID: string; id: string; variant?: string }): string {
  return `${ref.providerID}/${ref.id}${ref.variant === undefined ? "" : `#${ref.variant}`}`;
}

function requireModel(options: CliOptions): ModelFilter {
  if (!options.model) throw new Error("--model <provider>/<id> is required");
  return options.model;
}

function modelTextOf(before: BeforeEvent): string {
  return modelText(before);
}

function parseInteger(name: string, value: string | undefined, minimum: number, maximum: number): number {
  const number = Number(value);
  if (!Number.isInteger(number) || number < minimum || number > maximum)
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  return number;
}

function parseRatio(name: string, value: string | undefined): number {
  const number = Number(value);
  if (!Number.isFinite(number) || number < 0 || number > 1)
    throw new Error(`${name} must be a number between 0 and 1`);
  return number;
}

const CLI_OPTIONS = {
  help: { type: "boolean", short: "h" },
  json: { type: "boolean" },
  details: { type: "boolean" },
  live: { type: "boolean" },
  rotations: { type: "string" },
  threshold: { type: "string" },
  holdout: { type: "string" },
  seed: { type: "string" },
  limit: { type: "string" },
  concurrency: { type: "string" },
  "live-timeout-ms": { type: "string" },
  input: { type: "string", multiple: true },
  model: { type: "string" },
  "opencode-bin": { type: "string" },
} as const satisfies ParseArgsOptionsConfig;

function parseCliOptions(args: readonly string[]) {
  return parseCliArgs({ args, strict: true, allowPositionals: true, options: CLI_OPTIONS });
}

function booleanFlag(value: boolean | undefined): boolean {
  return value === true;
}

function integerOr(value: string | undefined, fallback: number, name: string, minimum: number, maximum: number): number {
  return value === undefined ? fallback : parseInteger(name, value, minimum, maximum);
}

function ratioOr(value: string | undefined, fallback: number, name: string): number {
  return value === undefined ? fallback : parseRatio(name, value);
}

function argumentError(error: unknown): Error {
  const failure = argFailure(error);
  if (failure?.kind === "unknown-option") return new Error(`Unknown option: ${failure.token}`);
  if (failure?.kind === "missing-value") return new Error(`${failure.token} requires a value`);
  if (failure?.kind === "unexpected-positional") return new Error(`Unexpected argument: ${failure.token}`);
  if (failure?.kind === "unexpected-value") return new Error(`${failure.token} does not take a value`);
  return error instanceof Error ? error : new Error("Invalid arguments");
}

function parseArgs(args: readonly string[]): CliOptions {
  let parsed: ReturnType<typeof parseCliOptions>;
  try { parsed = parseCliOptions(args); }
  catch (error) { throw argumentError(error); }
  const { values, positionals } = parsed;
  return {
    inputs: [...(values.input ?? []), ...positionals].map((value) => resolve(value)),
    rotations: values.rotations === undefined ? undefined : parseInteger("--rotations", values.rotations, 0, 100000),
    model: values.model === undefined ? undefined : modelFilter(values.model),
    threshold: values.threshold === undefined ? undefined : parseRatio("--threshold", values.threshold),
    holdout: ratioOr(values.holdout, DEFAULT_HOLDOUT, "--holdout"),
    seed: integerOr(values.seed, 0, "--seed", 0, 2 ** 31 - 1),
    live: booleanFlag(values.live),
    limit: integerOr(values.limit, DEFAULT_LIMIT, "--limit", 0, 100),
    concurrency: integerOr(values.concurrency, DEFAULT_CONCURRENCY, "--concurrency", 1, MAX_CONCURRENCY),
    liveTimeoutMs: integerOr(values["live-timeout-ms"], DEFAULT_LIVE_TIMEOUT_MS, "--live-timeout-ms", 1000, 120000),
    opencodeBin: values["opencode-bin"] ?? "opencode",
    json: booleanFlag(values.json),
    details: booleanFlag(values.details),
    help: booleanFlag(values.help),
  };
}

function usage(): string {
  return [
    "Usage: bun scripts/replay-decisions.ts --model <provider>/<id> [options] [audit-file-or-directory ...]",
    "",
    "Default dry-run reads the local audit path and every rotation, builds candidate",
    "compact decision evidence, and prints aggregate results only. It never calls a model.",
    "",
    "Options:",
    `  --input <path>            Audit file or directory; repeatable (default: local audit + rotations)`,
    `  --rotations <n>           Use only the newest n rotated files (default: all)`,
    `  --model <provider>/<id>[#variant]  Exact decision model filter (required)`,
    `  --threshold <0..1>        Fixed evaluation threshold (default: recorded minConfidence or ${DEFAULT_THRESHOLD})`,
    `  --holdout <0..1>          Deterministic session holdout share (default: ${DEFAULT_HOLDOUT})`,
    `  --seed <n>                Holdout/sample seed (default: 0)`,
    `  --live                    Opt-in stateless replay through the authenticated OpenCode CLI`,
    `  --limit <n>               Live replay request cap (default: ${DEFAULT_LIMIT})`,
    `  --concurrency <1..${MAX_CONCURRENCY}>      Live replay concurrency (default: ${DEFAULT_CONCURRENCY})`,
    `  --live-timeout-ms <n>     Per-call CLI timeout (default: ${DEFAULT_LIVE_TIMEOUT_MS})`,
    `  --opencode-bin <path>     OpenCode CLI path (default: opencode; tests/alternate installs)`,
    "  --json                    Print the aggregate report as JSON",
    "  --details                 Include normalized per-request rows (no prompts or evidence)",
    "  --help, -h                Show this help",
    "",
    "Privacy: audit rows are untrusted and may contain secrets. Only aggregate counts",
    "and normalized verdicts are printed. --live sends candidate evidence to the",
    "configured provider through the CLI; it does not use direct credentials or network",
    "code. Raw audit rows are never copied into this repository.",
  ].join("\n");
}

function rotationNumber(name: string, base: string): number | undefined {
  if (!name.startsWith(`${base}.`)) return undefined;
  const suffix = name.slice(base.length + 1);
  return /^\d+$/.test(suffix) ? Number(suffix) : undefined;
}

function filesInDirectory(directory: string, rotations: number | undefined): string[] {
  const active = join(directory, "decisions.jsonl");
  const base = basename(active);
  const rotated: { path: string; number: number }[] = [];
  if (existsSync(directory)) {
    for (const name of readdirSync(directory)) {
      const number = rotationNumber(name, base);
      if (number !== undefined) rotated.push({ path: join(directory, name), number });
    }
  }
  rotated.sort((left, right) => left.number - right.number);
  const selected = rotations === undefined ? rotated : rotated.slice(Math.max(0, rotated.length - rotations));
  return [...selected.map((item) => item.path), ...(existsSync(active) ? [active] : [])];
}

function sourceFiles(options: CliOptions): string[] {
  const sources = options.inputs.length > 0 ? options.inputs : [dirname(defaultAuditPath())];
  const files: string[] = [];
  for (const source of sources) {
    if (!existsSync(source)) {
      if (options.inputs.length > 0) throw new Error(`Audit source does not exist: ${source}`);
      continue;
    }
    if (statSync(source).isDirectory()) files.push(...filesInDirectory(source, options.rotations));
    else files.push(source);
  }
  const unique = [...new Set(files)];
  if (unique.length === 0) throw new Error("No audit files found; pass --input <path>");
  return unique;
}

function fingerprint(keys: readonly string[]): string {
  return createHash("sha256").update(keys.slice().sort().join("\n")).digest("hex").slice(0, 16);
}

function snapshotSources(files: readonly string[]): AuditSource[] {
  return files.map((file) => {
    const stat = statSync(file);
    return { file, name: basename(file), size: stat.size, mtimeMs: stat.mtimeMs, fd: openSync(file, "r") };
  });
}

function closeSources(sources: readonly AuditSource[]): void {
  for (const source of sources) {
    try { closeSync(source.fd); } catch { /* Already closed or unreadable. */ }
  }
}

function snapshotReport(sources: readonly AuditSource[], capturedAt: string): SnapshotReport {
  return {
    capturedAt, files: sources.length,
    bytes: sources.reduce((total, source) => total + source.size, 0),
    fingerprint: fingerprint(sources.map((source) => `${source.name}|${source.size}|${source.mtimeMs}`)),
  };
}

function promptReport(capturedAt: string): PromptReport {
  const questions = ["safety", "authorization"];
  return {
    capturedAt, questions,
    hash: fingerprint([DECISION_SAFETY_INSTRUCTIONS, DECISION_AUTHORIZATION_INSTRUCTIONS]),
  };
}

function ensureState(): State {
  return {
    stats: { files: 0, lines: 0, bytes: 0, parsed: 0, malformed: 0, oversized: 0, skipped: 0 },
    reviews: new Map(), pendingHosts: new Map(), pendingStarts: new Map(),
    toolInputs: createToolInputStore(MAX_TOOL_CAPTURES), seen: new Set(),
    problems: [], duplicateEvents: 0, filteredOut: 0, orphanAfter: 0, nonDecisionStage: 0,
  };
}

function problem(state: State, file: number, line: number, kind: string): void {
  if (state.problems.length < MAX_PROBLEMS) state.problems.push({ file, line, kind });
}

function seenBefore(state: State, key: string): boolean {
  if (state.seen.has(key)) { state.duplicateEvents++; return true; }
  state.seen.add(key);
  return false;
}

function pruneMap<K, V>(map: Map<K, V>, limit: number): void {
  while (map.size > limit) map.delete(map.keys().next().value as K);
}

function ensureReview(state: State, reviewID: string, sessionID: string | undefined): ReviewState {
  const existing = state.reviews.get(reviewID);
  if (existing) {
    existing.sessionID ??= sessionID;
    return existing;
  }
  const review: ReviewState = { reviewID, sessionID, stages: new Map(), ends: new Map(), requests: new Map() };
  const host = state.pendingHosts.get(reviewID);
  if (host) { review.host = host; state.pendingHosts.delete(reviewID); }
  const pending = state.pendingStarts.get(reviewID);
  if (pending) {
    for (const [index, start] of pending) review.stages.set(index, start);
    state.pendingStarts.delete(reviewID);
  }
  state.reviews.set(reviewID, review);
  return review;
}

function rememberHost(state: State, host: HostEvent): void {
  const review = state.reviews.get(host.reviewID);
  if (review) { review.host = host; return; }
  state.pendingHosts.delete(host.reviewID);
  state.pendingHosts.set(host.reviewID, host);
  pruneMap(state.pendingHosts, MAX_PENDING_HOSTS);
}

function pendingStages(state: State, reviewID: string): Map<number, StageStart> {
  const existing = state.pendingStarts.get(reviewID);
  if (existing) return existing;
  const stages = new Map<number, StageStart>();
  state.pendingStarts.set(reviewID, stages);
  pruneMap(state.pendingStarts, MAX_PENDING_REVIEWS);
  return stages;
}

function recordStart(state: State, reviewID: string, stageIndex: number, start: StageStart): void {
  const review = state.reviews.get(reviewID);
  const target = review ? review.stages : pendingStages(state, reviewID);
  const previous = target.get(stageIndex);
  if (previous?.ts !== undefined && start.ts !== undefined && previous.ts > start.ts) return;
  target.set(stageIndex, start);
}

function recordEnd(state: State, reviewID: string, stageIndex: number, end: StageEnd): void {
  const review = state.reviews.get(reviewID);
  if (!review) return;
  const previous = review.ends.get(stageIndex);
  if (previous?.ts !== undefined && end.ts !== undefined && previous.ts > end.ts) return;
  review.ends.set(stageIndex, end);
}

function hostBase(env: Json): { reviewID: string; payload: Json; action: string; resources: string[] } | undefined {
  const payload = isRecord(env.payload) ? env.payload : undefined;
  const reviewID = stringValue(env.reviewID);
  const action = stringValue(payload?.action);
  const resources = stringArray(payload?.resources);
  return payload && reviewID && action && resources ? { reviewID, payload, action, resources } : undefined;
}

function hostLocation(env: Json, payload: Json): { sessionID?: string; projectDir?: string; metadata?: Json; metadataInvalid: boolean } {
  const location = isRecord(env.sourceLocation) ? env.sourceLocation : undefined;
  const project = isRecord(location?.project) ? location.project : undefined;
  return {
    sessionID: stringValue(payload.sessionID),
    metadata: isRecord(payload.metadata) ? payload.metadata : undefined,
    metadataInvalid: payload.metadata !== undefined && !isRecord(payload.metadata),
    projectDir: stringValue(project?.directory) ?? stringValue(location?.directory),
  };
}

function hostFromEnvelope(env: Json, state: State): HostEvent | undefined {
  const base = hostBase(env);
  if (!base) return undefined;
  const location = hostLocation(env, base.payload);
  const source = base.payload.source;
  return {
    reviewID: base.reviewID, action: base.action, resources: base.resources,
    sessionID: location.sessionID, agent: stringValue(base.payload.agent),
    metadata: location.metadata, metadataInvalid: location.metadataInvalid, source,
    projectDir: location.projectDir,
    capture: location.sessionID === undefined ? undefined : state.toolInputs.get(source, location.sessionID),
  };
}

function onPermission(state: State, env: Json): void {
  const host = hostFromEnvelope(env, state);
  if (!host) { state.stats.skipped++; return; }
  const key = `permission.evaluate.before|${host.reviewID}|${stringValue(env.ts) ?? "-"}`;
  if (seenBefore(state, key)) return;
  rememberHost(state, host);
}

function toolIdentity(payload: Json | undefined): { sessionID: string; messageID: string; id: string; tool: string } | undefined {
  const sessionID = stringValue(payload?.sessionID);
  const messageID = stringValue(payload?.messageID);
  const id = stringValue(payload?.id);
  const tool = stringValue(payload?.tool);
  return sessionID && messageID && id && tool ? { sessionID, messageID, id, tool } : undefined;
}

function toolCapture(env: Json): { sessionID: string; messageID: string; id: string; tool: string; input: unknown } | undefined {
  const payload = isRecord(env.payload) ? env.payload : undefined;
  const identity = toolIdentity(payload);
  return payload && identity ? { ...identity, input: payload.input } : undefined;
}

function onToolExecute(state: State, env: Json): void {
  const capture = toolCapture(env);
  if (!capture) return;
  const key = `tool.execute.before|${capture.sessionID}|${capture.messageID}|${capture.id}|${stringValue(env.ts) ?? "-"}`;
  if (seenBefore(state, key)) return;
  state.toolInputs.capture(capture);
}

function toolRelease(env: Json): { sessionID: string; messageID: string; id: string } | undefined {
  const payload = isRecord(env.payload) ? env.payload : undefined;
  const sessionID = stringValue(payload?.sessionID);
  const messageID = stringValue(payload?.messageID);
  const id = stringValue(payload?.id);
  return sessionID && messageID && id ? { sessionID, messageID, id } : undefined;
}

/** Completion releases the exact capture, matching the runtime lifecycle
 * (`src/index.ts` execute.after): a sequentially reused identity is a new call,
 * not an overlap, so its arguments stay available. */
function onToolRelease(state: State, env: Json): void {
  const release = toolRelease(env);
  if (!release) return;
  const key = `tool.execute.after|${release.sessionID}|${release.messageID}|${release.id}|${stringValue(env.ts) ?? "-"}`;
  if (seenBefore(state, key)) return;
  state.toolInputs.release(release);
}

function stageStartFrom(env: Json, stageIndex: number): StageStart | undefined {
  const payload = isRecord(env.payload) ? env.payload : undefined;
  const type = stringValue(payload?.type);
  if (!payload || !type) return undefined;
  return {
    stageIndex, type,
    model: stringValue(payload.model),
    minConfidence: probability(payload.minConfidence),
    timeoutMs: finiteNumber(payload.timeoutMs),
    ts: stringValue(env.ts),
  };
}

function onStageStart(state: State, env: Json): void {
  const reviewID = stringValue(env.reviewID);
  const stageIndex = stageIndexValue(env.stageIndex);
  if (!reviewID || stageIndex === undefined) return;
  const start = stageStartFrom(env, stageIndex);
  if (!start) return;
  const key = `classifier.start|${reviewID}|${stageIndex}|${start.ts ?? "-"}`;
  if (seenBefore(state, key)) return;
  recordStart(state, reviewID, stageIndex, start);
}

function onStageEnd(state: State, env: Json): void {
  const reviewID = stringValue(env.reviewID);
  const stageIndex = stageIndexValue(env.stageIndex);
  const payload = isRecord(env.payload) ? env.payload : undefined;
  if (!reviewID || stageIndex === undefined || !payload) return;
  const key = `classifier.end|${reviewID}|${stageIndex}|${stringValue(env.ts) ?? "-"}`;
  if (seenBefore(state, key)) return;
  recordEnd(state, reviewID, stageIndex, {
    decision: enumText(payload.decision, VERDICTS),
    errorKind: enumText(payload.errorKind, ERROR_KINDS),
    stage: stringValue(payload.stage),
    hasError: payload.decision === undefined,
    ts: stringValue(env.ts),
  });
}

function formatOf(questions: readonly unknown[]): BeforeEvent["format"] {
  const types = questions.map((question) => isRecord(question) ? stringValue(question.type) : undefined);
  const predicates = types.filter((type) => type === "predicate").length;
  const choices = types.filter((type) => type === "choice").length;
  if (predicates > 0 && choices === 0) return "predicate";
  if (choices > 0 && predicates === 0) return "legacy";
  return "unknown";
}

function beforeModel(payload: Json | undefined): { providerID: string; id: string; variant?: string } | undefined {
  const model = isRecord(payload?.model) ? payload.model : undefined;
  const providerID = stringValue(model?.providerID);
  const id = stringValue(model?.id);
  const variant = optionalString(model?.variant);
  return providerID && id ? { providerID, id, ...(variant === undefined || variant.length === 0 ? {} : { variant }) } : undefined;
}

function beforeEvidenceText(payload: Json): string | undefined {
  const input = Array.isArray(payload.input) ? payload.input : [];
  const first = isRecord(input[0]) ? input[0] : undefined;
  return first?.type === "text" && typeof first.text === "string" ? first.text : undefined;
}

function beforeFromEnvelope(env: Json): BeforeEvent | undefined {
  const payload = isRecord(env.payload) ? env.payload : undefined;
  const model = beforeModel(payload);
  if (!payload || !model) return undefined;
  const questions = Array.isArray(payload.questions) ? payload.questions : [];
  const evidenceText = beforeEvidenceText(payload);
  return {
    model: modelText(model), providerID: model.providerID, id: model.id, variant: model.variant,
    format: formatOf(questions), questions, evidenceText,
    malformedEvidence: evidenceObject(evidenceText) === undefined,
  };
}

function decisionBeforeIds(env: Json): { reviewID: string; stageIndex: number; before: BeforeEvent } | undefined {
  const reviewID = stringValue(env.reviewID);
  const stageIndex = stageIndexValue(env.stageIndex);
  const before = beforeFromEnvelope(env);
  return reviewID && stageIndex !== undefined && before ? { reviewID, stageIndex, before } : undefined;
}

function attachPendingHost(review: ReviewState, state: State): void {
  const host = state.pendingHosts.get(review.reviewID);
  if (!host) return;
  review.host ??= host;
  state.pendingHosts.delete(review.reviewID);
}

function matchesFilter(before: BeforeEvent, filter: ModelFilter): boolean {
  return before.providerID === filter.providerID && before.id === filter.id && before.variant === filter.variant;
}

function requestKeyOf(env: Json, stageIndex: number): string {
  return `${stageIndex}|${stringValue(env.callID) ?? stringValue(env.ts) ?? "-"}`;
}

function decisionBefore(state: State, env: Json, filter: ModelFilter): void {
  const ids = decisionBeforeIds(env);
  if (!ids) { state.stats.skipped++; return; }
  if (!matchesFilter(ids.before, filter)) { state.filteredOut++; return; }
  const callID = stringValue(env.callID);
  const key = `generate.decisions.before|${ids.reviewID}|${ids.stageIndex}|${callID ?? stringValue(env.ts) ?? "-"}`;
  if (seenBefore(state, key)) return;
  const review = ensureReview(state, ids.reviewID, stringValue(env.sessionID));
  attachPendingHost(review, state);
  const requestKey = requestKeyOf(env, ids.stageIndex);
  if (review.requests.has(requestKey)) { state.duplicateEvents++; return; }
  review.requests.set(requestKey, {
    key: `${ids.reviewID}|${requestKey}`, reviewID: ids.reviewID,
    sessionID: stringValue(env.sessionID) ?? review.sessionID,
    stageIndex: ids.stageIndex, callID, ts: stringValue(env.ts), before: ids.before,
  });
}

function afterTarget(review: ReviewState, stageIndex: number, callID: string | undefined): DecisionRequestAudit | undefined {
  const requests = [...review.requests.values()].filter((request) => request.stageIndex === stageIndex);
  if (callID !== undefined) return requests.find((request) => request.callID === callID);
  return requests.length === 1 ? requests[0] : undefined;
}

function decisionAfterKey(env: Json): { reviewID: string; stageIndex: number; callID?: string } | undefined {
  const reviewID = stringValue(env.reviewID);
  const stageIndex = stageIndexValue(env.stageIndex);
  return reviewID && stageIndex !== undefined ? { reviewID, stageIndex, callID: stringValue(env.callID) } : undefined;
}

function decisionAfter(state: State, env: Json): void {
  const ids = decisionAfterKey(env);
  const payload = isRecord(env.payload) ? env.payload : undefined;
  if (!ids || !payload) return;
  const key = `generate.decisions.after|${ids.reviewID}|${ids.stageIndex}|${ids.callID ?? stringValue(env.ts) ?? "-"}`;
  if (seenBefore(state, key)) return;
  const review = state.reviews.get(ids.reviewID);
  if (!review) return;
  const target = afterTarget(review, ids.stageIndex, ids.callID);
  if (!target) { state.orphanAfter++; return; }
  if (target.after) { state.duplicateEvents++; return; }
  target.after = { answers: payload.answers, hasError: payload.answers === undefined, callID: ids.callID, ts: stringValue(env.ts) };
}

/** A rejected SDK promise emits `generate.decisions.error` instead of `.after`;
 * pairing it as a failed outcome keeps provider failures out of missing-after. */
function decisionError(state: State, env: Json): void {
  const ids = decisionAfterKey(env);
  if (!ids) return;
  const key = `generate.decisions.error|${ids.reviewID}|${ids.stageIndex}|${ids.callID ?? stringValue(env.ts) ?? "-"}`;
  if (seenBefore(state, key)) return;
  const review = state.reviews.get(ids.reviewID);
  if (!review) return;
  const target = afterTarget(review, ids.stageIndex, ids.callID);
  if (!target) { state.orphanAfter++; return; }
  if (target.after) { state.duplicateEvents++; return; }
  target.after = { hasError: true, callID: ids.callID, ts: stringValue(env.ts) };
}

function onFinal(state: State, env: Json): void {
  const reviewID = stringValue(env.reviewID);
  const decision = enumText(env.decision, VERDICTS);
  const stage = stringValue(env.stage);
  if (!reviewID || decision === undefined || !stage) return;
  const review = state.reviews.get(reviewID);
  if (!review) return;
  review.final = { decision, stage, errorKind: enumText(env.errorKind, ERROR_KINDS) };
}

function decisionEvent(state: State, type: string | undefined, env: Json, filter: ModelFilter): boolean {
  if (type === "generate.decisions.before") { decisionBefore(state, env, filter); return true; }
  if (type === "generate.decisions.after") { decisionAfter(state, env); return true; }
  if (type === "generate.decisions.error") { decisionError(state, env); return true; }
  return false;
}

function dispatch(state: State, env: Json, filter: ModelFilter): void {
  const type = stringValue(env.type);
  if (type === "tool.execute.before") { onToolExecute(state, env); return; }
  if (type === "tool.execute.after") { onToolRelease(state, env); return; }
  if (type === "permission.evaluate.before") { onPermission(state, env); return; }
  if (type === "classifier.start") { onStageStart(state, env); return; }
  if (type === "classifier.end") { onStageEnd(state, env); return; }
  if (decisionEvent(state, type, env, filter)) return;
  if (type === undefined && env.decision !== undefined && env.stage !== undefined) onFinal(state, env);
}

async function readSource(state: State, source: AuditSource, index: number, filter: ModelFilter): Promise<void> {
  if (source.size === 0) return;
  const input = createReadStream(source.file, {
    fd: source.fd, autoClose: false, start: 0, end: source.size - 1, encoding: "utf8",
  });
  const lines = createInterface({ input, crlfDelay: Infinity });
  let lineNumber = 0;
  try {
    for await (const line of lines) {
      lineNumber++;
      state.stats.lines++;
      state.stats.bytes += Buffer.byteLength(line) + 1;
      if (!line.trim()) continue;
      if (line.length > MAX_AUDIT_LINE_CHARS) { state.stats.oversized++; problem(state, index, lineNumber, "oversized-line"); continue; }
      let parsed: unknown;
      try { parsed = JSON.parse(line); }
      catch { state.stats.malformed++; problem(state, index, lineNumber, "invalid-json"); continue; }
      if (!isRecord(parsed)) { state.stats.skipped++; continue; }
      state.stats.parsed++;
      dispatch(state, parsed, filter);
    }
  } finally {
    lines.close();
  }
}

async function readSources(sources: readonly AuditSource[], filter: ModelFilter): Promise<State> {
  const state = ensureState();
  state.stats.files = sources.length;
  try {
    for (const [index, source] of sources.entries()) {
      try { await readSource(state, source, index, filter); }
      catch (error) {
        if (error instanceof Error && error.message.startsWith("ENOENT")) throw new Error(`Audit source missing: ${source.file}`, { cause: error });
        throw error;
      }
    }
  } finally {
    closeSources(sources);
  }
  state.toolInputs.clear();
  return state;
}

function jsonRecord(value: unknown): Json | undefined {
  return isRecord(value) ? value : undefined;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function optionalBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function chronology(value: unknown): string[] | undefined {
  const messages = stringArray(value);
  if (!messages || messages.length === 0) return undefined;
  return Buffer.byteLength(messages.join("\n")) > MAX_CHRONOLOGY_BYTES ? undefined : messages;
}

function boundedTranscript(value: unknown): string | undefined {
  const text = optionalString(value);
  return text === undefined || Buffer.byteLength(text) > MAX_CHRONOLOGY_BYTES ? undefined : text;
}

/** Delegations are neither user authority nor part of userMessages. Anything
 * dropped by bounds or validation is reported as loss so replay can abstain. */
function recordedDelegations(value: unknown): { delegations?: string[]; lost: boolean } {
  if (value === undefined) return { lost: false };
  if (!Array.isArray(value)) return { lost: true };
  const delegations = value.filter((item): item is string => typeof item === "string");
  return {
    ...(delegations.length === 0 ? {} : { delegations }),
    lost: delegations.length !== value.length,
  };
}

function staticAnalysis(value: unknown): RecordedEvidence["staticAnalysis"] {
  const object = jsonRecord(value);
  if (!object) return undefined;
  const reason = optionalString(object.reason) ?? "";
  const findings = stringArray(object.findings);
  if (reason.length === 0 && (findings === undefined || findings.length === 0)) return undefined;
  return {
    band: optionalString(object.band) ?? "unknown", reason,
    ...(findings === undefined || findings.length === 0 ? {} : { findings: [...findings] }),
  };
}

function gitState(value: unknown): RecordedEvidence["gitState"] {
  const object = jsonRecord(value);
  if (!object) return undefined;
  const state = {
    branch: optionalString(object.branch),
    defaultBranch: optionalString(object.defaultBranch),
    clean: optionalBoolean(object.clean),
  };
  return Object.values(state).some((item) => item !== undefined) ? state : undefined;
}

/** The recorded platform must be a bounded, whitespace-free host identifier;
 * otherwise replay would silently substitute the current machine. */
function recordedPlatform(value: unknown): { value?: string; loss: boolean } {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_RECORDED_PLATFORM_CHARS || /\s/.test(value))
    return { loss: true };
  return { value, loss: false };
}

function recordedShellField(value: unknown): { value?: string; loss: boolean } {
  if (value === undefined) return { loss: false };
  if (typeof value !== "string" || value.length > MAX_RECORDED_SHELL_CHARS) return { loss: true };
  return { value, loss: false };
}

function recordedShell(value: unknown): { shell?: RecordedEvidence["shell"]; loss: boolean } {
  if (value === undefined) return { loss: false };
  const object = jsonRecord(value);
  if (!object) return { loss: true };
  const platform = recordedShellField(object.platform);
  const interpreter = recordedShellField(object.interpreter);
  return {
    shell: {
      ...(platform.value === undefined ? {} : { platform: platform.value }),
      ...(interpreter.value === undefined ? {} : { interpreter: interpreter.value }),
    },
    loss: platform.loss || interpreter.loss,
  };
}

function recordedTargets(value: unknown): { targets?: string[]; canonical: boolean } {
  if (!Array.isArray(value)) return { canonical: false };
  const targets = value.slice(0, MAX_RECORDED_TARGETS + 1)
    .filter((item): item is string => typeof item === "string");
  const canonical = targets.length === value.length && targets.length > 0 && targets.length <= MAX_RECORDED_TARGETS &&
    targets.every((target) => target.length > 0 && target.length <= MAX_RECORDED_TARGET_CHARS);
  return { ...(targets.length === 0 ? {} : { targets }), canonical };
}

function recordedOperation(value: unknown): RecordedOperation | undefined {
  if (value === undefined) return undefined;
  const object = jsonRecord(value);
  if (!object) return { canonical: false };
  const targets = recordedTargets(object.targets);
  return { ...(targets.targets === undefined ? {} : { targets: targets.targets }), canonical: targets.canonical && object.complete === true };
}

/** Parsed evidence must be a bounded JSON object; text that fails either check
 * is malformed source data, not merely absent chronology or host context. */
function evidenceObject(text: string | undefined): Json | undefined {
  if (text === undefined || text.length > MAX_EVIDENCE_TEXT_CHARS) return undefined;
  let parsed: unknown;
  try { parsed = JSON.parse(text); }
  catch { return undefined; }
  return jsonRecord(parsed);
}

function recordedEvidence(text: string | undefined): RecordedEvidence | undefined {
  const object = evidenceObject(text);
  if (!object) return undefined;
  const scope = object.scopeResolution === "unknown" ? "unknown" as const : undefined;
  const delegations = recordedDelegations(object.delegations);
  const platform = recordedPlatform(object.platform);
  const shell = recordedShell(object.shell);
  const recordedShellLoss = object.incompleteEvidenceKind === "shell" ? "shell" as const : undefined;
  return {
    action: optionalString(object.action),
    resources: stringArray(object.resources),
    agent: optionalString(object.agent),
    projectDir: optionalString(object.projectDir),
    worktreeRoot: optionalString(object.worktreeRoot),
    scopeResolution: scope,
    platform: platform.value,
    shell: shell.shell,
    operation: recordedOperation(object.operation),
    contextLoss: platform.loss ? "platform" : shell.loss ? "shell" : recordedShellLoss,
    userMessages: chronology(object.userMessages),
    delegations: delegations.delegations,
    delegationsLost: delegations.lost,
    transcript: boundedTranscript(object.userInstruction),
    staticAnalysis: staticAnalysis(object.staticAnalysis),
    gitState: gitState(object.gitState),
  };
}

function requestFromRecorded(recorded: RecordedEvidence | undefined): DecisionEvidenceRequest | undefined {
  if (!recorded?.action || !recorded.resources) return undefined;
  return {
    action: recorded.action, resources: recorded.resources, agent: recorded.agent,
    projectDir: recorded.projectDir, worktreeRoot: recorded.worktreeRoot,
    scopeResolution: recorded.scopeResolution, platform: recorded.platform, shell: recorded.shell,
    userMessages: recorded.userMessages,
    delegations: recorded.delegations,
    transcript: recorded.transcript, staticAnalysis: recorded.staticAnalysis, gitState: recorded.gitState,
  };
}

function hostResources(host: HostEvent): string[] | undefined {
  try { return codeModeReviewResources(host) ?? host.resources; }
  catch { return undefined; }
}

function sameTargets(left: readonly string[] | undefined, right: readonly string[] | undefined): boolean {
  if (left === undefined || right === undefined) return left === right;
  return left.length === right.length && left.every((target, index) => target === right[index]);
}

/** Rebuilt targets follow this host's path rules and current filesystem. A
 * complete recorded list is canonical; otherwise the rebuild must match the
 * recorded targets, and a differing platform can still change resolution. */
function historicalTargets(operation: OperationEvidence, recorded: RecordedEvidence | undefined):
  { targets?: string[]; preGeneration?: "platform" | "operation" } {
  const historical = recorded?.operation;
  if (historical?.canonical === true && historical.targets !== undefined) return { targets: historical.targets };
  if (historical !== undefined && !sameTargets(operation.targets, historical.targets)) return { preGeneration: "operation" };
  if (operation.targets !== undefined && recorded?.platform !== process.platform) return { preGeneration: "platform" };
  return {};
}

interface HostOperation {
  operation: OperationEvidence;
  targetLoss?: "platform" | "operation";
}

function canonicalOperationTargets(recorded: RecordedEvidence | undefined): readonly string[] | undefined {
  const operation = recorded?.operation;
  return operation?.canonical === true ? operation.targets : undefined;
}

function hostOperation(host: HostEvent, recorded: RecordedEvidence | undefined): HostOperation {
  const canonical = canonicalOperationTargets(recorded);
  const operation = buildOperationEvidence(
    { action: host.action, resources: host.resources, metadata: host.metadata, sessionID: host.sessionID },
    {
      projectDir: recorded?.projectDir ?? host.projectDir, capture: host.capture,
      ...(canonical === undefined ? {} : { targets: canonical }),
    },
  );
  const repaired = host.metadataInvalid ? { ...operation, complete: false } : operation;
  const targets = historicalTargets(repaired, recorded);
  return {
    operation: targets.targets === undefined ? repaired : { ...repaired, targets: targets.targets },
    ...(targets.preGeneration === undefined ? {} : { targetLoss: targets.preGeneration }),
  };
}

function hostAgent(host: HostEvent, recorded: RecordedEvidence | undefined): string | undefined {
  return host.agent ?? recorded?.agent;
}

function hostProjectDir(host: HostEvent, recorded: RecordedEvidence | undefined): string | undefined {
  return recorded?.projectDir ?? host.projectDir;
}

function requestFromHost(host: HostEvent, recorded: RecordedEvidence | undefined, resources: string[], operation: OperationEvidence): DecisionEvidenceRequest {
  return {
    action: host.action, resources, agent: hostAgent(host, recorded), projectDir: hostProjectDir(host, recorded),
    worktreeRoot: recorded?.worktreeRoot, scopeResolution: recorded?.scopeResolution,
    platform: recorded?.platform, shell: recorded?.shell,
    userMessages: recorded?.userMessages, delegations: recorded?.delegations,
    transcript: recorded?.transcript,
    staticAnalysis: recorded?.staticAnalysis, gitState: recorded?.gitState, operation,
  };
}

function opaqueOperation(evidence: DecisionEvidence, request: DecisionEvidenceRequest): boolean {
  const normalized = { ...request, operation: evidence.operation };
  return isOpaqueOperationLoss(request) || isOpaqueOperationLoss(normalized) ||
    (request.action === "external_directory" && (evidence.operation?.targets?.length ?? 0) === 0);
}

function resourceLoss(request: DecisionEvidenceRequest): boolean {
  return request.resources.some((resource) => redactHttpBodies(resource) !== resource);
}

/** Recorded delegations dropped by bounds or validation, or redacted on rebuild,
 * are incomplete context: replay abstains before generation instead of narrowing
 * authorization with missing delegated scope. */
function delegationLoss(recorded: RecordedEvidence | undefined, evidence: DecisionEvidence): DecisionEvidence {
  if (recorded?.delegationsLost !== true || evidence.incompleteEvidenceKind !== undefined) return evidence;
  return { ...evidence, incompleteEvidence: DELEGATION_LOSS, incompleteEvidenceKind: "delegations" };
}

function preGenerationOf(evidence: DecisionEvidence, bytes: number, request: DecisionEvidenceRequest,
  contextLoss: RecordedEvidence["contextLoss"], targetLoss?: "platform" | "operation"): Candidate["preGeneration"] {
  if (resourceLoss(request)) return "resources";
  if (contextLoss !== undefined) return contextLoss;
  if (targetLoss !== undefined) return targetLoss;
  if (evidence.incompleteEvidenceKind === "shell") return "shell";
  if (evidence.incompleteEvidenceKind === "delegations") return "delegations";
  if (evidence.operation?.complete === false) return "operation";
  return bytes > 60_000 ? "too-large" : undefined;
}

function missingChronologyOf(recorded: RecordedEvidence | undefined): boolean {
  return recorded === undefined || (recorded.userMessages === undefined && recorded.transcript === undefined);
}

type RebuildFlags = Pick<Candidate, "readOnly" | "userMessagesRetained" | "chronologyFallback" | "resourcesChanged" |
  "operationAccess" | "operationTool" | "operationTargets" | "operationArguments">;

function messageFlags(recorded: RecordedEvidence | undefined, evidence: DecisionEvidence): Pick<RebuildFlags,
  "userMessagesRetained" | "chronologyFallback" | "resourcesChanged"> {
  const hasMessages = evidence.userMessages !== undefined;
  return {
    userMessagesRetained: recorded?.userMessages !== undefined && hasMessages,
    chronologyFallback: recorded?.userMessages === undefined && recorded?.transcript !== undefined && hasMessages,
    resourcesChanged: recorded?.resources !== undefined && JSON.stringify(recorded.resources) !== JSON.stringify(evidence.resources),
  };
}

function operationFlags(evidence: DecisionEvidence): Pick<RebuildFlags,
  "readOnly" | "operationAccess" | "operationTool" | "operationTargets" | "operationArguments"> {
  return {
    readOnly: evidence.operation?.access === "read",
    operationAccess: evidence.operation?.access,
    operationTool: evidence.operation?.tool,
    operationTargets: evidence.operation?.targets?.length ?? 0,
    operationArguments: evidence.operation?.arguments === undefined ? 0 : Object.keys(evidence.operation.arguments).length,
  };
}

function rebuildFlags(recorded: RecordedEvidence | undefined, evidence: DecisionEvidence): RebuildFlags {
  return { ...messageFlags(recorded, evidence), ...operationFlags(evidence) };
}

function missingHostCandidate(recorded: RecordedEvidence | undefined): Candidate {
  const fallback = requestFromRecorded(recorded);
  const evidence: DecisionEvidence = fallback === undefined ? { action: "", resources: [] } : delegationLoss(recorded, buildDecisionEvidence(fallback));
  const bytes = fallback === undefined ? 0 : Buffer.byteLength(JSON.stringify(evidence));
  return {
    request: fallback ?? { action: "", resources: [] }, evidence,
    hostJoined: false, missingHost: true, missingChronology: missingChronologyOf(recorded), operationMissing: true,
    metadataInvalid: false, codeModeError: false,
    preGeneration: fallback === undefined ? undefined : preGenerationOf(evidence, bytes, fallback, recorded?.contextLoss), bytes,
    ...rebuildFlags(recorded, evidence),
  };
}

function codeModeCandidate(host: HostEvent, fallback: DecisionEvidenceRequest | undefined): Candidate {
  return {
    request: fallback ?? { action: "", resources: [] }, evidence: { action: "", resources: [] },
    hostJoined: true, missingHost: false, missingChronology: false, operationMissing: true,
    metadataInvalid: host.metadataInvalid, codeModeError: true, bytes: 0,
    readOnly: false, userMessagesRetained: false, chronologyFallback: false, resourcesChanged: false,
    operationTargets: 0, operationArguments: 0,
  };
}

function candidateFor(review: ReviewState, request: DecisionRequestAudit): Candidate {
  const recorded = recordedEvidence(request.before.evidenceText);
  const fallback = requestFromRecorded(recorded);
  if (!review.host) return missingHostCandidate(recorded);
  const resources = hostResources(review.host);
  if (!resources) return codeModeCandidate(review.host, fallback);
  const rebuilt = hostOperation(review.host, recorded);
  const built = requestFromHost(review.host, recorded, resources, rebuilt.operation);
  const evidence = delegationLoss(recorded, buildDecisionEvidence(built));
  const bytes = Buffer.byteLength(JSON.stringify(evidence));
  return {
    request: built, evidence, hostJoined: true, missingHost: false,
    missingChronology: missingChronologyOf(recorded), operationMissing: evidence.operation === undefined,
    metadataInvalid: review.host.metadataInvalid, codeModeError: false,
    terminal: opaqueOperation(evidence, built) ? "opaque" : undefined,
    preGeneration: preGenerationOf(evidence, bytes, built, recorded?.contextLoss, rebuilt.targetLoss), bytes, ...rebuildFlags(recorded, evidence),
  };
}

function thresholdFor(review: ReviewState, request: DecisionRequestAudit, override: number | undefined): { threshold: number; missing: boolean } {
  if (override !== undefined) return { threshold: override, missing: false };
  const start = review.stages.get(request.stageIndex);
  if (!start) return { threshold: DEFAULT_THRESHOLD, missing: true };
  return { threshold: start.type === "decision" && start.minConfidence !== undefined ? start.minConfidence : DEFAULT_THRESHOLD, missing: false };
}

function llmStageFor(review: ReviewState, decisionStage: number): number | undefined {
  const starts = [...review.stages.entries()].filter(([index, start]) => index > decisionStage && start.type === "llm");
  if (starts.length > 0) return Math.min(...starts.map(([index]) => index));
  const ends = [...review.ends.entries()].filter(([index, end]) => index > decisionStage && end.stage === "reviewer");
  return ends.length === 0 ? undefined : Math.min(...ends.map(([index]) => index));
}

function inHoldout(sessionID: string | undefined, key: string, options: CliOptions): boolean {
  if (options.holdout <= 0) return false;
  return hash32(`${options.seed}|${sessionID ?? key}`) / 0x1_0000_0000 < options.holdout;
}

function viewFor(review: ReviewState, request: DecisionRequestAudit, options: CliOptions): RequestView {
  const threshold = thresholdFor(review, request, options.threshold);
  const llmStage = llmStageFor(review, request.stageIndex);
  const recordedEnd = review.ends.get(request.stageIndex);
  const llmEnd = llmStage === undefined ? undefined : review.ends.get(llmStage);
  const fallback = recordedEnd?.decision === "abstain" && llmEnd !== undefined;
  return {
    key: request.key, reviewID: review.reviewID, sessionID: request.sessionID ?? review.sessionID,
    format: request.before.format, threshold: threshold.threshold,
    stageStartMissing: threshold.missing,
    before: request.before, after: request.after, recordedEnd, llmEnd, final: review.final, fallback,
    candidate: candidateFor(review, request), split: inHoldout(request.sessionID ?? review.sessionID, request.key, options) ? "holdout" : "primary",
  };
}

type PredicateName = "safety" | "authorization";
function predicateEntry(value: unknown): { name: PredicateName; probability: number } | undefined {
  const answer = jsonRecord(value);
  const name = optionalString(answer?.name);
  const probabilityValue = probability(answer?.probability);
  if (!answer || answer.type !== "predicate" || (name !== "safety" && name !== "authorization") || probabilityValue === undefined)
    return undefined;
  return { name, probability: probabilityValue };
}

function predicateAnswers(answers: unknown): { safety: number; authorization: number } | undefined {
  if (!Array.isArray(answers) || answers.length !== 2) return undefined;
  const found = new Map<PredicateName, number>();
  for (const item of answers) {
    const entry = predicateEntry(item);
    if (!entry || found.has(entry.name)) return undefined;
    found.set(entry.name, entry.probability);
  }
  const safety = found.get("safety");
  const authorization = found.get("authorization");
  return safety === undefined || authorization === undefined ? undefined : { safety, authorization };
}

function predicateResult(result: { decision: string; errorKind?: string }, values: { safety: number; authorization: number } | undefined, calls: number): PredicateOutcome {
  if (result.errorKind === "invalid-output") return { status: "invalid", errorKind: result.errorKind, calls };
  if (calls === 0 && result.errorKind === "context") return { status: "pre-generation", errorKind: result.errorKind, calls };
  if (result.errorKind !== undefined) return { status: "error", errorKind: result.errorKind, calls };
  if (result.decision !== "allow" && result.decision !== "abstain") return { status: "error", errorKind: "invalid-output", calls };
  return { status: result.decision, safety: values?.safety, authorization: values?.authorization, calls };
}

function localPredicateOutcome(answers: unknown, threshold: number, calls = 0): PredicateOutcome {
  const values = predicateAnswers(answers);
  if (!values) return { status: "invalid", errorKind: "invalid-output", calls };
  return {
    status: values.safety >= threshold && values.authorization >= threshold ? "allow" : "abstain",
    safety: values.safety, authorization: values.authorization, calls,
  };
}

function correctedEvidence(request: DecisionEvidenceRequest, evidence: DecisionEvidence): DecisionEvidence {
  if (request.action !== "external_directory") return evidence;
  const rest = { ...evidence };
  delete rest.incompleteEvidence;
  delete rest.incompleteEvidenceKind;
  if (resourceLoss(request)) return { ...rest, incompleteEvidence: "Inline HTTP body or remaining arguments omitted; do not approve from partial evidence", incompleteEvidenceKind: "resources" };
  if (evidence.operation?.complete === false) return { ...rest, incompleteEvidence: "Operation evidence is incomplete; do not approve from partial operation evidence", incompleteEvidenceKind: "operation" };
  return rest;
}

async function predicateOutcome(view: RequestView): Promise<PredicateOutcome> {
  if (!view.after) return { status: "missing-after" };
  if (view.after.hasError) return { status: "after-error" };
  if (view.candidate.codeModeError) return { status: "error", errorKind: "context" };
  if (view.candidate.terminal) return { status: "terminal", errorKind: "context" };
  if (view.candidate.preGeneration) return { status: "pre-generation" };
  if (view.candidate.request.action === "external_directory")
    return localPredicateOutcome(view.after.answers, view.threshold);
  let calls = 0;
  const ctx = {
    experimental: { generate: { decisions: async () => { calls++; return { answers: view.after?.answers }; } } },
  };
  const result = await decisionStage(ctx, { model: modelTextOf(view.before), minConfidence: view.threshold, timeoutMs: 3000 }, view.candidate.request);
  return predicateResult(result, predicateAnswers(view.after.answers), calls);
}

type LegacyChoice = "allow" | "deny" | "ask";
function legacyChoice(value: unknown): LegacyChoice | undefined {
  return value === "allow" || value === "deny" || value === "ask" ? value : undefined;
}

function legacyAnswerShape(answer: Json | undefined): { choice: LegacyChoice; confidence: number; probabilities: unknown[] } | undefined {
  const choice = legacyChoice(answer?.choice);
  const confidence = probability(answer?.confidence);
  if (!answer || answer.name !== "permission" || answer.type !== "choice" || choice === undefined ||
      confidence === undefined || !Array.isArray(answer.probabilities)) return undefined;
  return { choice, confidence, probabilities: answer.probabilities };
}

function legacyAnswer(answers: unknown): { choice: LegacyChoice; confidence: number; probabilities: unknown[] } | undefined {
  if (!Array.isArray(answers) || answers.length !== 1) return undefined;
  return legacyAnswerShape(jsonRecord(answers[0]));
}

function legacyDistribution(probabilities: readonly unknown[]): Map<LegacyChoice, number> | undefined {
  const distribution = new Map<LegacyChoice, number>();
  for (const item of probabilities) {
    const entry = jsonRecord(item);
    const value = legacyChoice(entry?.value);
    const probabilityValue = probability(entry?.probability);
    if (!entry || value === undefined || probabilityValue === undefined || distribution.has(value)) return undefined;
    distribution.set(value, probabilityValue);
  }
  return distribution;
}

function legacyOutcomeFrom(answer: { choice: LegacyChoice; confidence: number; probabilities: readonly unknown[] }, threshold: number): LegacyOutcome {
  const distribution = legacyDistribution(answer.probabilities);
  if (!distribution) return { status: "invalid" };
  const selected = distribution.get(answer.choice);
  const values = [...distribution.values()];
  if (distribution.size !== 3 || selected === undefined ||
      Math.abs(values.reduce((total, value) => total + value, 0) - 1) > 0.01 || selected < Math.max(...values))
    return { status: "invalid" };
  if (answer.choice === "ask" || answer.confidence < threshold || selected < threshold)
    return { status: "abstain", confidence: answer.confidence, selected };
  return { status: answer.choice, confidence: answer.confidence, selected };
}

function legacyVerdict(answers: unknown, threshold: number): LegacyOutcome {
  const answer = legacyAnswer(answers);
  return answer === undefined ? { status: "invalid" } : legacyOutcomeFrom(answer, threshold);
}

function legacyOutcome(view: RequestView): LegacyOutcome {
  if (!view.after) return { status: "missing-after" };
  if (view.after.hasError) return { status: "after-error" };
  return legacyVerdict(view.after.answers, view.threshold);
}

function compare(left: string | undefined, right: string | undefined, counts: Counts): void {
  bump(counts, `${left ?? "none"}>${right ?? "none"}`);
}

function numericSummary(values: readonly number[]): { count: number; min: number; p10: number; median: number; p90: number; max: number; mean: number } | undefined {
  const numbers = values.filter((value) => Number.isFinite(value)).sort((left, right) => left - right);
  if (numbers.length === 0) return undefined;
  const at = (fraction: number) => numbers[Math.min(numbers.length - 1, Math.max(0, Math.ceil(fraction * numbers.length) - 1))]!;
  return {
    count: numbers.length,
    min: numbers[0]!, p10: at(0.1), median: at(0.5), p90: at(0.9), max: numbers[numbers.length - 1]!,
    mean: numbers.reduce((total, value) => total + value, 0) / numbers.length,
  };
}

function bucket(value: number): string {
  if (value < 0.5) return "0.00-0.49";
  if (value < 0.9) return "0.50-0.89";
  if (value < 0.95) return "0.90-0.94";
  if (value < 0.99) return "0.95-0.98";
  return "0.99-1.00";
}

function bucketCounts(values: readonly number[]): Counts {
  const counts: Counts = {};
  for (const value of values) bump(counts, bucket(value));
  return counts;
}

function splitSummary(views: readonly RequestView[]): SplitSummary {
  const sessions = new Set(views.map((view) => view.sessionID ?? view.key));
  const predicate: Counts = {};
  const legacy: Counts = {};
  const llm: Counts = {};
  for (const view of views) {
    if (view.predicate) bump(predicate, view.predicate.status);
    if (view.legacy) bump(legacy, view.legacy.status);
    bump(llm, view.llmEnd?.decision ?? (view.llmEnd === undefined ? "none" : "error"));
  }
  return { requests: views.length, sessions: sessions.size, predicate, legacy, llm };
}

function tallyBy<T>(items: readonly T[], key: (item: T) => string): Counts {
  const counts: Counts = {};
  for (const item of items) bump(counts, key(item));
  return sortedCounts(counts);
}

function countWhere<T>(items: readonly T[], condition: (item: T) => boolean): number {
  return items.filter(condition).length;
}

function decisionsOf(views: readonly RequestView[]): Counts {
  return tallyBy(views, (view) => view.recordedEnd?.decision ?? (view.recordedEnd === undefined ? "none" : "error"));
}

function errorKindsOf(views: readonly RequestView[]): Counts {
  return tallyBy(views.flatMap((view) => view.recordedEnd?.errorKind === undefined ? [] : [view.recordedEnd.errorKind]), (kind) => kind);
}

function comparisonCounts(views: readonly RequestView[], include: (view: RequestView) => boolean,
  left: (view: RequestView) => string | undefined, right: (view: RequestView) => string | undefined): Counts {
  const counts: Counts = {};
  for (const view of views) if (include(view)) compare(left(view), right(view), counts);
  return sortedCounts(counts);
}

function predicateBelow(view: RequestView): string[] {
  const predicate = view.predicate!;
  const below: string[] = [];
  const safety = predicate.safety ?? 0;
  const authorization = predicate.authorization ?? 0;
  if (safety < view.threshold) below.push("safety");
  if (authorization < view.threshold) below.push("authorization");
  if (safety < view.threshold && authorization < view.threshold) below.push("both");
  return below;
}

function predicateBelowOf(views: readonly RequestView[]): Counts {
  const counts: Counts = {};
  for (const view of views) {
    if (view.predicate?.status !== "allow" && view.predicate?.status !== "abstain") continue;
    for (const key of predicateBelow(view)) bump(counts, key);
  }
  return sortedCounts(counts);
}

function predicateReport(views: readonly RequestView[]): Report["predicate"] {
  const withPredicate = views.filter((view) => view.predicate !== undefined);
  return {
    basis: "recorded predicate answers re-evaluated against rebuilt candidate evidence; counterfactual, not a fresh model result",
    outcomes: tallyBy(withPredicate, (view) => view.predicate!.status),
    below: predicateBelowOf(views),
    protocol: tallyBy(withPredicate.filter((view) => view.predicate!.status === "allow" || view.predicate!.status === "abstain"),
      (view) => view.predicate!.status),
    vsRecorded: comparisonCounts(views, (view) => view.predicate?.status === "allow" || view.predicate?.status === "abstain",
      (view) => view.predicate?.status, (view) => view.recordedEnd?.decision),
  };
}

function legacyReport(views: readonly RequestView[]): Report["legacy"] {
  const withLegacy = views.filter((view) => view.legacy !== undefined);
  return {
    outcomes: tallyBy(withLegacy, (view) => view.legacy!.status),
    vsRecorded: comparisonCounts(withLegacy, () => true, (view) => view.legacy?.status, (view) => view.recordedEnd?.decision),
  };
}

function llmReport(views: readonly RequestView[]): Report["llm"] {
  return {
    outcomes: tallyBy(views, (view) => view.llmEnd?.decision ?? (view.llmEnd === undefined ? "none" : "error")),
    vsPredicate: comparisonCounts(views, (view) => view.predicate !== undefined,
      (view) => view.predicate?.status, (view) => view.llmEnd?.decision),
    vsLegacy: comparisonCounts(views, (view) => view.legacy !== undefined,
      (view) => view.legacy?.status, (view) => view.llmEnd?.decision),
  };
}

function finalReport(views: readonly RequestView[]): Report["final"] {
  return {
    decisions: tallyBy(views, (view) => view.final?.decision ?? "none"),
    vsPredicate: comparisonCounts(views, (view) => view.predicate !== undefined,
      (view) => view.predicate?.status, (view) => view.final?.decision),
    vsLegacy: comparisonCounts(views, (view) => view.legacy !== undefined,
      (view) => view.legacy?.status, (view) => view.final?.decision),
  };
}

function probabilitiesReport(views: readonly RequestView[]): Report["probabilities"] {
  const safety = views.flatMap((view) => view.predicate?.safety === undefined ? [] : [view.predicate.safety]);
  const authorization = views.flatMap((view) => view.predicate?.authorization === undefined ? [] : [view.predicate.authorization]);
  const confidence = views.flatMap((view) => view.legacy?.confidence === undefined ? [] : [view.legacy.confidence]);
  const selected = views.flatMap((view) => view.legacy?.selected === undefined ? [] : [view.legacy.selected]);
  return {
    safety: numericSummary(safety), authorization: numericSummary(authorization),
    legacyConfidence: numericSummary(confidence), legacySelected: numericSummary(selected),
    safetyBuckets: bucketCounts(safety), authorizationBuckets: bucketCounts(authorization),
  };
}

function evidenceReport(views: readonly RequestView[]): Report["evidence"] {
  const preGeneration = views.flatMap((view) => view.candidate.preGeneration === undefined ? [] : [view.candidate.preGeneration]);
  return {
    hostJoined: countWhere(views, (view) => view.candidate.hostJoined),
    missingHost: countWhere(views, (view) => view.candidate.missingHost),
    operationPresent: countWhere(views, (view) => view.candidate.evidence.operation !== undefined),
    operationComplete: countWhere(views, (view) => view.candidate.evidence.operation?.complete === true),
    operationIncomplete: countWhere(views, (view) => view.candidate.evidence.operation?.complete === false),
    operationMissing: countWhere(views, (view) => view.candidate.operationMissing),
    metadataInvalid: countWhere(views, (view) => view.candidate.metadataInvalid),
    codeModeError: countWhere(views, (view) => view.candidate.codeModeError),
    missingChronology: countWhere(views, (view) => view.candidate.missingChronology),
    terminal: countWhere(views, (view) => view.candidate.terminal !== undefined),
    preGeneration: tallyBy(preGeneration, (kind) => kind),
    bytes: numericSummary(views.map((view) => view.candidate.bytes)),
  };
}

function pairingReport(views: readonly RequestView[]): Report["pairing"] {
  const afterPresent = countWhere(views, (view) => view.after !== undefined);
  return {
    afterPresent, missingAfter: views.length - afterPresent,
    afterError: countWhere(views, (view) => view.after?.hasError === true),
    malformedEvidence: countWhere(views, (view) => view.before.malformedEvidence),
    stageStartMissing: countWhere(views, (view) => view.stageStartMissing),
    decisionEndMissing: countWhere(views, (view) => view.recordedEnd === undefined),
  };
}

function recordedReport(views: readonly RequestView[]): Report["recorded"] {
  return {
    decisions: decisionsOf(views), errorKinds: errorKindsOf(views),
    fallback: countWhere(views, (view) => view.fallback), llmRan: countWhere(views, (view) => view.llmEnd !== undefined),
  };
}

function reviewsReport(state: State, views: readonly RequestView[]): Report["reviews"] {
  return {
    requests: views.length, sessions: new Set(views.map((view) => view.sessionID ?? view.key)).size,
    duplicateEvents: state.duplicateEvents, filteredOut: state.filteredOut, orphanAfter: state.orphanAfter,
    nonDecisionStage: state.nonDecisionStage,
  };
}

function emptyActionSummary(): ActionSummary {
  return {
    requests: 0, primary: 0, holdout: 0, predicate: {}, legacy: {}, llm: {}, recorded: {},
    predicateVsLlm: {}, fallback: 0,
  };
}

function bumpActionOutcomes(summary: ActionSummary, view: RequestView): void {
  if (view.predicate) bump(summary.predicate, view.predicate.status);
  if (view.legacy) bump(summary.legacy, view.legacy.status);
  bump(summary.llm, view.llmEnd?.decision ?? "none");
  bump(summary.recorded, view.recordedEnd?.decision ?? "none");
  if (view.predicate) compare(view.predicate.status, view.llmEnd?.decision, summary.predicateVsLlm);
}

function bumpAction(summary: ActionSummary, view: RequestView): void {
  summary.requests++;
  if (view.split === "primary") summary.primary++; else summary.holdout++;
  if (view.fallback) summary.fallback++;
  bumpActionOutcomes(summary, view);
}

function actionsReport(views: readonly RequestView[]): Record<string, ActionSummary> {
  const actions: Record<string, ActionSummary> = Object.create(null) as Record<string, ActionSummary>;
  for (const view of views) {
    const action = view.candidate.request.action || "unknown";
    const summary = actions[action] ??= emptyActionSummary();
    bumpAction(summary, view);
  }
  return Object.fromEntries(Object.entries(actions).sort(([leftKey, left], [rightKey, right]) =>
    right.requests - left.requests || leftKey.localeCompare(rightKey)));
}

function liveEligible(view: RequestView): boolean {
  return !view.candidate.terminal && !view.candidate.preGeneration && !view.candidate.codeModeError &&
    !view.candidate.missingHost && !view.candidate.missingChronology && view.candidate.bytes > 0;
}

function eligibilityReason(view: RequestView): string | undefined {
  if (view.candidate.terminal) return "terminal";
  if (view.candidate.codeModeError) return "code-mode";
  if (view.candidate.missingHost) return "missing-host";
  if (view.candidate.missingChronology) return "missing-chronology";
  if (view.candidate.preGeneration) return `pre-generation:${view.candidate.preGeneration}`;
  return view.candidate.bytes === 0 ? "no-evidence" : undefined;
}

function eligibilityReport(views: readonly RequestView[]): EligibilityReport {
  const reasons: Counts = {};
  for (const view of views) {
    const reason = eligibilityReason(view);
    if (reason !== undefined) bump(reasons, reason);
  }
  const readOnly = views.filter((view) => view.candidate.readOnly);
  const readOnlyEligible = readOnly.filter(liveEligible);
  const simpleGrep = views.filter((view) => view.candidate.request.action === "grep" &&
    view.candidate.operationTool === "grep" && view.candidate.operationTargets > 0 &&
    view.candidate.operationArguments > 0 && view.candidate.evidence.userMessages?.length === 1);
  const simpleGrepEligible = simpleGrep.filter(liveEligible);
  return {
    total: views.length, eligible: views.filter(liveEligible).length, reasons: sortedCounts(reasons),
    readOnly: {
      total: readOnly.length, eligible: readOnlyEligible.length,
      predicate: tallyBy(readOnlyEligible.filter((view) => view.predicate !== undefined), (view) => view.predicate!.status),
      llm: tallyBy(readOnlyEligible, (view) => view.llmEnd?.decision ?? "none"),
    },
    simpleGrep: {
      eligible: simpleGrepEligible.length,
      predicate: tallyBy(simpleGrepEligible.filter((view) => view.predicate !== undefined), (view) => view.predicate!.status),
      llm: tallyBy(simpleGrepEligible, (view) => view.llmEnd?.decision ?? "none"),
    },
  };
}

function rebuildReport(views: readonly RequestView[]): RebuildReport {
  return {
    userMessagesRetained: countWhere(views, (view) => view.candidate.userMessagesRetained),
    chronologyFallback: countWhere(views, (view) => view.candidate.chronologyFallback),
    resourcesChanged: countWhere(views, (view) => view.candidate.resourcesChanged),
    delegationsRetained: countWhere(views, (view) => view.candidate.evidence.delegations !== undefined),
    operationAccess: tallyBy(views.flatMap((view) => view.candidate.operationAccess === undefined ? [] : [view.candidate.operationAccess]), (access) => access),
    operationTool: tallyBy(views.flatMap((view) => view.candidate.operationTool === undefined ? [] : [view.candidate.operationTool]), (tool) => tool),
    operationTargets: countWhere(views, (view) => view.candidate.operationTargets > 0),
    operationArguments: countWhere(views, (view) => view.candidate.operationArguments > 0),
  };
}

function buildReport(state: State, views: readonly RequestView[], options: CliOptions, filter: ModelFilter,
  snapshot: SnapshotReport, prompt: PromptReport, live?: LiveSummary): Report {
  return {
    tool: "replay-decisions", mode: options.live ? "live" : "dry-run", filter: modelText(filter),
    sources: state.stats, snapshot, prompt, reviews: reviewsReport(state, views),
    formats: tallyBy(views, (view) => view.format), evidence: evidenceReport(views), pairing: pairingReport(views),
    recorded: recordedReport(views), predicate: predicateReport(views), legacy: legacyReport(views),
    llm: llmReport(views), final: finalReport(views), probabilities: probabilitiesReport(views),
    thresholds: tallyBy(views, (view) => String(view.threshold)),
    split: {
      primary: splitSummary(views.filter((view) => view.split === "primary")),
      holdout: splitSummary(views.filter((view) => view.split === "holdout")),
    },
    actions: actionsReport(views), eligibility: eligibilityReport(views), rebuild: rebuildReport(views),
    problems: state.problems, ...(options.details ? { details: detailsReport(views) } : {}),
    ...(live === undefined ? {} : { live }),
    fidelity: "Recorded-audit replay only. The dry-run predicate section replays recorded answers against rebuilt evidence; it is not a fresh model result. LLM verdicts are not ground truth; thresholds are not tuned; config is unchanged.",
  };
}

function sampleEligible(views: readonly RequestView[], limit: number, seed: number): RequestView[] {
  return limit <= 0 ? [] : [...views]
    .sort((left, right) => hash32(`${seed}|${left.key}`) - hash32(`${seed}|${right.key}`) || left.key.localeCompare(right.key))
    .slice(0, limit);
}

async function callDecisionCli(input: DecisionInput, options: CliOptions, signal?: AbortSignal): Promise<unknown> {
  const args = ["api", "experimental.generate.decisions", "--data", JSON.stringify(input)];
  let stdout: string;
  try {
    const result = await execFileAsync(options.opencodeBin, args, {
      encoding: "utf8", maxBuffer: CLI_MAX_BUFFER, timeout: options.liveTimeoutMs, signal,
    });
    stdout = result.stdout;
  } catch (error) {
    if (signal?.aborted) throw new ReviewFailure("timeout", "Decision CLI call cancelled or timed out");
    const killed = isRecord(error) && (error.killed === true || typeof error.signal === "string");
    throw new ReviewFailure(killed ? "timeout" : "provider", killed ? "Decision CLI call timed out" : "Decision CLI call failed");
  }
  return parseCliOutput(stdout);
}

function parseCliOutput(stdout: string): unknown {
  const text = stdout.trim();
  if (!text) throw new ReviewFailure("provider", "Decision CLI returned no output");
  let parsed: unknown;
  try { parsed = JSON.parse(text); }
  catch { throw new ReviewFailure("provider", "Decision CLI returned non-JSON output"); }
  const data = isRecord(parsed) && isRecord(parsed.data) ? parsed.data : parsed;
  if (isRecord(data) && (data._tag !== undefined || (data.kind !== undefined && data.message !== undefined)))
    throw new ReviewFailure("provider", "Decision CLI returned an error");
  return data;
}

interface LiveCall {
  view: RequestView;
  calls: number;
  result: StageResult;
  safety?: number;
  authorization?: number;
}

function liveStatus(result: StageResult): string {
  if (result.errorKind === "invalid-output") return "malformed";
  return result.errorKind ?? result.decision;
}

function recordLive(item: LiveCall, options: CliOptions, statuses: Counts, comparisons: Counts, vsLlm: Counts,
  actions: Record<string, LiveActionSummary>, detail: LiveResult[]): void {
  const status = liveStatus(item.result);
  const action = item.view.candidate.request.action || "unknown";
  const summary = actions[action] ??= { requests: 0, primary: 0, holdout: 0, statuses: {} };
  summary.requests++;
  if (item.view.split === "primary") summary.primary++; else summary.holdout++;
  bump(summary.statuses, status);
  bump(statuses, status);
  compare(item.result.decision, item.view.recordedEnd?.decision, comparisons);
  compare(item.result.decision, item.view.llmEnd?.decision, vsLlm);
  if (options.details) detail.push({
    reviewID: item.view.reviewID, format: item.view.format, action, status,
    decision: item.result.decision, recorded: item.view.recordedEnd?.decision,
    llm: item.view.llmEnd?.decision, errorKind: item.result.errorKind, calls: item.calls,
    safety: item.safety, authorization: item.authorization,
  });
}

function externalDecisionInput(view: RequestView): DecisionInput {
  return {
    model: Model.Ref.parse(modelTextOf(view.before)),
    input: [{ type: "text", text: JSON.stringify(correctedEvidence(view.candidate.request, view.candidate.evidence)) }],
    questions: [
      { type: "predicate", name: "safety", instructions: DECISION_SAFETY_INSTRUCTIONS },
      { type: "predicate", name: "authorization", instructions: DECISION_AUTHORIZATION_INSTRUCTIONS },
    ],
  };
}

function stageFromPredicate(outcome: PredicateOutcome): StageResult {
  if (outcome.status === "allow" || outcome.status === "abstain") {
    return { decision: outcome.status, stage: "decision", reason: "Replayed predicate verdict" };
  }
  return { decision: "abstain", stage: "decision", errorKind: "invalid-output", reason: "Replayed predicate output was invalid" };
}

async function externalLiveCall(view: RequestView, options: CliOptions): Promise<LiveCall> {
  const input = externalDecisionInput(view);
  if (Buffer.byteLength(JSON.stringify(input)) > 65_536) {
    return { view, calls: 0, result: { decision: "abstain", stage: "decision", errorKind: "context", reason: "Decision request too large" } };
  }
  const signal = AbortSignal.timeout(options.liveTimeoutMs);
  try {
    const response = await callDecisionCli(input, options, signal);
    const outcome = localPredicateOutcome(isRecord(response) ? response.answers : undefined, view.threshold, 1);
    return { view, calls: 1, result: stageFromPredicate(outcome), safety: outcome.safety, authorization: outcome.authorization };
  } catch (error) {
    const errorKind = error instanceof ReviewFailure ? error.kind : "provider";
    return { view, calls: 1, result: { decision: "abstain", stage: "decision", errorKind, reason: "Decision CLI failed" } };
  }
}

async function liveReplay(views: readonly RequestView[], options: CliOptions): Promise<LiveSummary> {
  const eligible = views.filter(liveEligible);
  const selected = sampleEligible(eligible, options.limit, options.seed);
  const results = await mapLimit(selected, options.concurrency, async (view): Promise<LiveCall> => {
    if (view.candidate.request.action === "external_directory") return externalLiveCall(view, options);
    let calls = 0;
    let response: unknown;
    const ctx = {
      experimental: { generate: { decisions: async (input: DecisionInput, generation: { signal: AbortSignal }) => {
        calls++;
        response = await callDecisionCli(input, options, generation.signal);
        return response;
      } } },
    };
    const result = await decisionStage(ctx, { model: modelTextOf(view.before), minConfidence: view.threshold, timeoutMs: options.liveTimeoutMs }, view.candidate.request);
    const values = predicateAnswers(isRecord(response) ? response.answers : undefined);
    return { view, calls, result, safety: values?.safety, authorization: values?.authorization };
  });
  const statuses: Counts = {};
  const comparisons: Counts = {};
  const vsLlm: Counts = {};
  const actions: Record<string, LiveActionSummary> = Object.create(null) as Record<string, LiveActionSummary>;
  const detail: LiveResult[] = [];
  let modelCalls = 0, modelErrors = 0, preGeneration = 0;
  for (const item of results) {
    modelCalls += item.calls;
    if (item.calls === 0) preGeneration++;
    if (item.result.errorKind !== undefined) modelErrors++;
    recordLive(item, options, statuses, comparisons, vsLlm, actions, detail);
  }
  return {
    enabled: true, sampling: "deterministic uniform hash across eligible requests",
    sampleFingerprint: fingerprint(selected.map((view) => view.key)),
    eligible: eligible.length, selected: selected.length,
    readOnlySelected: countWhere(selected, (view) => view.candidate.readOnly),
    sessions: new Set(selected.map((view) => view.sessionID ?? view.key)).size,
    modelCalls, modelErrors, preGeneration, statuses: sortedCounts(statuses), comparisons: sortedCounts(comparisons),
    vsLlm: sortedCounts(vsLlm), actions: Object.fromEntries(Object.entries(actions).sort(([left], [right]) => left.localeCompare(right))),
    ...(options.details ? { results: detail } : {}),
  };
}

function formatSummary(summary: ReturnType<typeof numericSummary>): string {
  if (!summary) return "n=0";
  return `n=${summary.count} min=${summary.min.toFixed(3)} p10=${summary.p10.toFixed(3)} median=${summary.median.toFixed(3)} p90=${summary.p90.toFixed(3)} max=${summary.max.toFixed(3)}`;
}

function printCounts(label: string, counts: Counts): void {
  const entries = Object.entries(counts);
  if (entries.length === 0) { console.log(`${label}: none`); return; }
  console.log(`${label}: ${entries.map(([key, value]) => `${key}=${value}`).join(", ")}`);
}

function printSplit(name: string, split: SplitSummary): void {
  console.log(`${name}: requests=${split.requests} sessions=${split.sessions}`);
  printCounts(`  predicate`, split.predicate);
  printCounts(`  legacy`, split.legacy);
  printCounts(`  llm`, split.llm);
}

function inlineCounts(counts: Counts): string {
  return Object.entries(counts).map(([key, value]) => `${key}=${value}`).join(",") || "none";
}

function printActions(actions: Record<string, ActionSummary>): void {
  console.log(`Actions (top ${Math.min(Object.keys(actions).length, 12)} of ${Object.keys(actions).length}):`);
  for (const [action, summary] of Object.entries(actions).slice(0, 12)) {
    console.log(`  ${action}: n=${summary.requests} primary=${summary.primary} holdout=${summary.holdout} predicate=${inlineCounts(summary.predicate)} legacy=${inlineCounts(summary.legacy)} llm=${inlineCounts(summary.llm)} recorded=${inlineCounts(summary.recorded)} fallback=${summary.fallback} predicate-vs-llm=${inlineCounts(summary.predicateVsLlm)}`);
  }
}

function predicateDetail(view: RequestView): string {
  if (view.predicate === undefined) return "-";
  if (view.predicate.safety === undefined) return view.predicate.status;
  return `${view.predicate.status} s=${view.predicate.safety.toFixed(3)} a=${view.predicate.authorization?.toFixed(3)}`;
}

function legacyDetail(view: RequestView): string {
  if (view.legacy === undefined) return "-";
  return view.legacy.confidence === undefined ? view.legacy.status : `${view.legacy.status} c=${view.legacy.confidence.toFixed(3)}`;
}

function detailLine(view: RequestView): string {
  return `${view.reviewID} ${view.format} split=${view.split} threshold=${view.threshold} predicate=${predicateDetail(view)} legacy=${legacyDetail(view)} recorded=${view.recordedEnd?.decision ?? "none"} llm=${view.llmEnd?.decision ?? "none"} final=${view.final?.decision ?? "none"} action=${view.candidate.request.action || "?"}`;
}

function stageDecision(end: StageEnd | undefined): string {
  return end?.decision ?? (end === undefined ? "none" : "error");
}

function detailNumbers(view: RequestView): Pick<RequestDetail, "safety" | "authorization" | "confidence"> {
  const values: Pick<RequestDetail, "safety" | "authorization" | "confidence"> = {};
  if (view.predicate?.safety !== undefined) values.safety = view.predicate.safety;
  if (view.predicate?.authorization !== undefined) values.authorization = view.predicate.authorization;
  if (view.legacy?.confidence !== undefined) values.confidence = view.legacy.confidence;
  return values;
}

function detailOf(view: RequestView): RequestDetail {
  return {
    reviewID: view.reviewID, format: view.format, split: view.split, threshold: view.threshold,
    action: view.candidate.request.action || "unknown",
    predicate: view.predicate === undefined ? "none" : view.predicate.status,
    legacy: view.legacy === undefined ? "none" : view.legacy.status,
    recorded: stageDecision(view.recordedEnd), llm: stageDecision(view.llmEnd),
    final: view.final === undefined ? "none" : view.final.decision,
    ...detailNumbers(view),
  };
}

function detailsReport(views: readonly RequestView[]): DetailsReport {
  return { total: views.length, rows: views.slice(0, MAX_DETAIL_ROWS).map(detailOf) };
}

function printDetails(views: readonly RequestView[]): void {
  console.log(`Details (first ${Math.min(views.length, MAX_DETAIL_ROWS)} of ${views.length}; no prompts or evidence):`);
  for (const view of views.slice(0, MAX_DETAIL_ROWS)) console.log(detailLine(view));
}

function printHuman(report: Report, views: readonly RequestView[], options: CliOptions): void {
  console.log(`Decision replay (${report.mode}) - aggregate only; filter=${report.filter}`);
  console.log(`Snapshot: captured=${report.snapshot.capturedAt} files=${report.snapshot.files} bytes=${report.snapshot.bytes} fingerprint=${report.snapshot.fingerprint}`);
  console.log(`Prompt: captured=${report.prompt.capturedAt} hash=${report.prompt.hash} questions=${report.prompt.questions.join(",")}`);
  console.log(`Sources: files=${report.sources.files} lines=${report.sources.lines} parsed=${report.sources.parsed} malformed=${report.sources.malformed} oversized=${report.sources.oversized} skipped=${report.sources.skipped}`);
  console.log(`Reviews: requests=${report.reviews.requests} sessions=${report.reviews.sessions} duplicates=${report.reviews.duplicateEvents} filtered-out=${report.reviews.filteredOut} orphan-after=${report.reviews.orphanAfter} non-decision-stage=${report.reviews.nonDecisionStage}`);
  printCounts("Formats", report.formats);
  console.log(`Evidence: host-joined=${report.evidence.hostJoined} missing-host=${report.evidence.missingHost} operation-present=${report.evidence.operationPresent} complete=${report.evidence.operationComplete} incomplete=${report.evidence.operationIncomplete} missing=${report.evidence.operationMissing}`);
  console.log(`  metadata-invalid=${report.evidence.metadataInvalid} code-mode-error=${report.evidence.codeModeError} missing-chronology=${report.evidence.missingChronology} terminal-opaque=${report.evidence.terminal}`);
  printCounts("  pre-generation abstain", report.evidence.preGeneration);
  console.log(`  candidate evidence bytes: ${formatSummary(report.evidence.bytes)}`);
  console.log(`Pairing: after=${report.pairing.afterPresent} missing-after=${report.pairing.missingAfter} after-error=${report.pairing.afterError} malformed-evidence=${report.pairing.malformedEvidence} missing-stage-start=${report.pairing.stageStartMissing} missing-decision-end=${report.pairing.decisionEndMissing}`);
  printCounts("Recorded decision stage", report.recorded.decisions);
  printCounts("  recorded error kinds", report.recorded.errorKinds);
  console.log(`  fallback-to-llm=${report.recorded.fallback} llm-ran=${report.recorded.llmRan}`);
  console.log("Predicate replay (recorded answers x rebuilt evidence; NOT a fresh model result):");
  printCounts("  outcomes", report.predicate.outcomes);
  printCounts("  below threshold", report.predicate.below);
  printCounts("  protocol", report.predicate.protocol);
  printCounts("  predicate vs recorded", report.predicate.vsRecorded);
  printCounts("Legacy choice outcomes", report.legacy.outcomes);
  printCounts("  legacy vs recorded", report.legacy.vsRecorded);
  printCounts("LLM outcomes (recorded; not ground truth)", report.llm.outcomes);
  printCounts("  predicate vs LLM", report.llm.vsPredicate);
  printCounts("  legacy vs LLM", report.llm.vsLegacy);
  printCounts("Final applied", report.final.decisions);
  printCounts("  predicate vs final", report.final.vsPredicate);
  console.log(`Probabilities: safety ${formatSummary(report.probabilities.safety)}`);
  console.log(`  authorization ${formatSummary(report.probabilities.authorization)}`);
  console.log(`  legacy confidence ${formatSummary(report.probabilities.legacyConfidence)}`);
  console.log(`  legacy selected ${formatSummary(report.probabilities.legacySelected)}`);
  printCounts("  safety buckets", report.probabilities.safetyBuckets);
  printCounts("  authorization buckets", report.probabilities.authorizationBuckets);
  printCounts("Thresholds", report.thresholds);
  printSplit("Split primary", report.split.primary);
  printSplit("Split holdout", report.split.holdout);
  printActions(report.actions);
  console.log(`Eligibility: total=${report.eligibility.total} eligible=${report.eligibility.eligible} reasons=${inlineCounts(report.eligibility.reasons)}`);
  console.log(`Read-only eligible: total=${report.eligibility.readOnly.total} eligible=${report.eligibility.readOnly.eligible} predicate=${inlineCounts(report.eligibility.readOnly.predicate)} llm=${inlineCounts(report.eligibility.readOnly.llm)}`);
  console.log(`Simple grep eligible: n=${report.eligibility.simpleGrep.eligible} predicate=${inlineCounts(report.eligibility.simpleGrep.predicate)} llm=${inlineCounts(report.eligibility.simpleGrep.llm)}`);
  console.log(`Rebuild: user-messages-retained=${report.rebuild.userMessagesRetained} chronology-fallback=${report.rebuild.chronologyFallback} resources-changed=${report.rebuild.resourcesChanged} delegations-retained=${report.rebuild.delegationsRetained} operation-access=${inlineCounts(report.rebuild.operationAccess)} operation-tools=${inlineCounts(report.rebuild.operationTool)} targets=${report.rebuild.operationTargets} args=${report.rebuild.operationArguments}`);
  if (report.problems.length > 0) console.log(`Problems: ${report.problems.map((item) => `${item.kind}@file${item.file + 1}:${item.line}`).join(", ")}`);
  if (report.live) {
    console.log(`Live: eligible=${report.live.eligible} sampling=${report.live.sampling} sample=${report.live.sampleFingerprint} selected=${report.live.selected} read-only-selected=${report.live.readOnlySelected} sessions=${report.live.sessions} model-calls=${report.live.modelCalls} model-errors=${report.live.modelErrors} pre-generation=${report.live.preGeneration}`);
    printCounts("  live statuses", report.live.statuses);
    printCounts("  live vs recorded", report.live.comparisons);
    printCounts("  live vs LLM", report.live.vsLlm);
    for (const [action, summary] of Object.entries(report.live.actions)) {
      console.log(`  live ${action}: n=${summary.requests} primary=${summary.primary} holdout=${summary.holdout} statuses=${inlineCounts(summary.statuses)}`);
    }
  } else {
    console.log("Live: disabled (dry-run). No model calls made.");
  }
  if (options.details) printDetails(views);
  console.log("Privacy: audit rows are untrusted data; prompts, evidence, and raw audit content are not printed.");
  console.log(`Fidelity: ${report.fidelity}`);
}

function decisionStageRequest(review: ReviewState, request: DecisionRequestAudit): boolean {
  const start = review.stages.get(request.stageIndex);
  return start === undefined || start.type === "decision";
}

async function evaluateViews(state: State, options: CliOptions): Promise<RequestView[]> {
  const views: RequestView[] = [];
  for (const review of state.reviews.values()) {
    for (const request of review.requests.values()) {
      // `generate.decisions` is also used by the fact-review stage; only the
      // recorded decision stage may be evaluated with decision thresholds.
      if (!decisionStageRequest(review, request)) { state.nonDecisionStage++; continue; }
      const view = viewFor(review, request, options);
      if (view.format === "predicate") view.predicate = await predicateOutcome(view);
      if (view.format === "legacy") view.legacy = legacyOutcome(view);
      views.push(view);
    }
  }
  return views.sort((left, right) => left.key.localeCompare(right.key));
}

async function run(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) { console.log(usage()); return; }
  const filter = requireModel(options);
  const capturedAt = new Date().toISOString();
  const sources = snapshotSources(sourceFiles(options));
  const snapshot = snapshotReport(sources, capturedAt);
  const prompt = promptReport(capturedAt);
  const state = await readSources(sources, filter);
  const views = await evaluateViews(state, options);
  const live = options.live ? await liveReplay(views, options) : undefined;
  const report = buildReport(state, views, options, filter, snapshot, prompt, live);
  if (options.json) console.log(JSON.stringify(report, null, 2));
  else printHuman(report, views, options);
}

try {
  await run();
} catch (error) {
  const message = error instanceof Error ? error.message : "Replay failed";
  console.error(`replay-decisions: ${message}`);
  process.exit(1);
}
