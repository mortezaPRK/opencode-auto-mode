#!/usr/bin/env bun
// Read-only evaluator for private decision-candidate manifests; offline unless --live is explicit.
import { execFile } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { parseArgs as parseCliArgs, promisify, type ParseArgsOptionsConfig } from "node:util";
import { isProbability, probabilityDistribution } from "../src/guards.js";
import { argFailure, isRecord, mapLimit, printableLabel } from "./lib.js";
const THRESHOLD = 0.9, TOLERANCE = 1e-6, MAX_LIVE_CALLS = 100, LIVE_CONCURRENCY = 2, LIVE_TIMEOUT_MS = 120_000;
const execFileAsync = promisify(execFile);
type ChoiceValue = string | boolean;
type Expected = "allow" | "review";
type Answer = Record<string, unknown>;
type PredicateQuestion = { type: "predicate"; name: string };
type ChoiceQuestion = { type: "choice"; name: string; choices: readonly { value: ChoiceValue }[] };
type Question = PredicateQuestion | ChoiceQuestion;
export type Evaluation = { accepted: boolean; probabilities: Record<string, number>; error?: string };
export type CaseReport = { key: string; verdict: Expected; expected?: Expected; match?: boolean; probabilities: Record<string, number>; error?: string };
export type Aggregate = { attempted: number; accepted: number; reviewed: number; errors: number; expected: number; matched: number; mismatched: number };
export type Report = { tool: "decision-candidate"; mode: "recorded" | "live"; model: string; threshold: number; aggregate: Aggregate; cases: CaseReport[]; fidelity: string };
type ManifestCase = { key: string; request: Record<string, unknown>; expected?: Expected; response?: unknown };
type ModelRef = { providerID: string; id: string; variant?: string };
export type Options = { input: string; model: ModelRef; modelText: string; live: boolean; threshold: number; report?: string };
const isValue = (v: unknown): v is ChoiceValue => typeof v === "boolean" || typeof v === "string";
const isThreshold = (v: number): boolean => Number.isFinite(v) && v >= THRESHOLD && v <= 1;
function isExpected(v: unknown): v is Expected { return v === "allow" || v === "review"; }
function valueKey(v: ChoiceValue): string { return `${typeof v}:${String(v)}`; }
function unwrapData(value: unknown): unknown {
  return isRecord(value) && "data" in value ? value.data : value;
}

function predicateOrChoice(item: Record<string, unknown>, name: string): Question | undefined {
  if (item.type === "predicate") return { type: "predicate", name };
  if (item.type !== "choice" || !Array.isArray(item.choices) || item.choices.length === 0) return undefined;
  const choices: { value: ChoiceValue }[] = [];
  const seen = new Set<string>();
  for (const choice of item.choices) {
    if (!isRecord(choice) || !isValue(choice.value) || seen.has(valueKey(choice.value))) return undefined;
    seen.add(valueKey(choice.value));
    choices.push({ value: choice.value });
  }
  return { type: "choice", name, choices };
}
function questionsOf(value: unknown): Question[] | undefined {
  if (!Array.isArray(value) || value.length === 0) return undefined;
  const seen = new Set<string>();
  const questions: Question[] = [];
  for (const item of value) {
    if (!isRecord(item) || typeof item.name !== "string" || !item.name || seen.has(item.name)) return undefined;
    const question = predicateOrChoice(item, item.name);
    if (question === undefined) return undefined;
    seen.add(item.name);
    questions.push(question);
  }
  return questions;
}
function answersList(response: unknown): unknown[] | undefined {
  return isRecord(response) && Array.isArray(response.answers) ? response.answers : undefined;
}
function answersOf(response: unknown, questions: readonly Question[]): Map<string, Answer> | undefined {
  const answers = answersList(response);
  if (answers === undefined || answers.length !== questions.length) return undefined;
  const types = new Map(questions.map((q) => [q.name, q.type]));
  const found = new Map<string, Answer>();
  for (const answer of answers) {
    // An unknown name has no expected type; without the has() check an answer
    // with no `type` matches `undefined === undefined` and later throws.
    if (!isRecord(answer) || typeof answer.name !== "string" || !types.has(answer.name) ||
        types.get(answer.name) !== answer.type || found.has(answer.name)) return undefined;
    found.set(answer.name, answer);
  }
  return found.size === questions.length ? found : undefined;
}
function allowProbability(question: ChoiceQuestion, answer: Answer, allow: ChoiceValue): number | undefined {
  if (!isValue(answer.choice)) return undefined;
  const distribution = probabilityDistribution(
    answer.probabilities,
    question.choices.map((choice) => choice.value),
    TOLERANCE,
    answer.choice,
  );
  return distribution?.get(allow);
}
/** Allow conventions are boolean true or the string "allow"; other choice sets
 * fail closed as no-allow-value. This is deliberate, not inferred from a label. */
function allowChoice(question: ChoiceQuestion): ChoiceValue | undefined {
  const values = question.choices.map((c) => c.value);
  return values.includes(true) ? true : values.includes("allow") ? "allow" : undefined;
}
function predicateProbability(answer: Answer): number | undefined {
  return isProbability(answer.probability) ? answer.probability : undefined;
}
function evaluationInput(questionsInput: unknown, response: unknown, threshold: number):
  { questions: Question[]; answers: Map<string, Answer> } | { error: string } {
  if (!isThreshold(threshold)) return { error: "invalid-threshold" };
  const questions = questionsOf(questionsInput);
  if (questions === undefined) return { error: "invalid-questions" };
  const answers = answersOf(response, questions);
  return answers === undefined ? { error: "invalid-answers" } : { questions, answers };
}
/** Strictly gate every question. Confidence is never read; distributions are
 * accepted exactly as returned, never normalized or repaired. */
export function evaluateResponse(questionsInput: unknown, response: unknown, threshold = THRESHOLD): Evaluation {
  const input = evaluationInput(questionsInput, response, threshold);
  if ("error" in input) return { accepted: false, probabilities: {}, error: input.error };
  const probabilities: Record<string, number> = Object.create(null) as Record<string, number>;
  let accepted = true;
  for (const question of input.questions) {
    const answer = input.answers.get(question.name)!;
    let probability: number | undefined;
    if (question.type === "predicate") probability = predicateProbability(answer);
    else {
      const allow = allowChoice(question);
      if (allow === undefined) return { accepted: false, probabilities, error: "no-allow-value" };
      // Choice entries report the desired allow probability, not the selected
      // one; selected === allow and selected-is-max remain enforcement checks.
      probability = allowProbability(question, answer, allow);
      if (answer.choice !== allow) accepted = false;
    }
    if (probability === undefined) return { accepted: false, probabilities, error: "invalid-probability" };
    probabilities[question.name] = probability;
    if (probability < threshold) accepted = false;
  }
  return { accepted, probabilities };
}
function recordedResponse(entry: Record<string, unknown>): unknown {
  return entry.response ?? entry.recordedResponse ?? entry.rawResponse;
}
function manifestCase(entry: unknown, keys: Set<string>): ManifestCase | undefined {
  if (!isRecord(entry) || typeof entry.key !== "string" || !entry.key || keys.has(entry.key) || !isRecord(entry.request)) return undefined;
  if (entry.expected !== undefined && !isExpected(entry.expected)) return undefined;
  keys.add(entry.key);
  return { key: entry.key, request: entry.request, ...(entry.expected === undefined ? {} : { expected: entry.expected }), response: recordedResponse(entry) };
}
function manifestCases(value: unknown): ManifestCase[] | undefined {
  if (!isRecord(value) || !Array.isArray(value.cases)) return undefined;
  const keys = new Set<string>();
  const cases: ManifestCase[] = [];
  for (const entry of value.cases) {
    const parsed = manifestCase(entry, keys);
    if (parsed === undefined) return undefined;
    cases.push(parsed);
  }
  return cases;
}
function errorCase(item: ManifestCase, error: string): CaseReport {
  return { key: item.key, verdict: "review", ...(item.expected ? { expected: item.expected, match: false } : {}), probabilities: {}, error };
}
function evaluationCase(item: ManifestCase, response: unknown, threshold: number): CaseReport {
  const result = evaluateResponse(item.request.questions, unwrapData(response), threshold);
  const verdict = result.accepted ? "allow" : "review";
  return { key: item.key, verdict, ...(item.expected ? { expected: item.expected, match: result.error === undefined && item.expected === verdict } : {}), probabilities: result.probabilities, ...(result.error === undefined ? {} : { error: result.error }) };
}
function aggregateOf(cases: readonly CaseReport[]): Aggregate {
  const accepted = cases.filter((item) => item.verdict === "allow").length;
  const labeled = cases.filter((item) => item.expected !== undefined);
  const matched = labeled.filter((item) => item.match === true).length;
  return { attempted: cases.length, accepted, reviewed: cases.length - accepted, errors: cases.filter((item) => item.error !== undefined).length, expected: labeled.length, matched, mismatched: labeled.length - matched };
}
function buildReport(options: Options, cases: readonly CaseReport[], mode: Report["mode"]): Report {
  return { tool: "decision-candidate", mode, model: options.modelText, threshold: options.threshold, aggregate: aggregateOf(cases), cases: [...cases],
    fidelity: mode === "recorded" ? "Recorded responses only; not a fresh model result. No prompts or raw inputs stored. No threshold or config changes." : "Opt-in live evaluation; requests go to the configured provider, but the report stores no prompts or raw inputs. No threshold or config changes." };
}
function printReport(report: Report): void {
  const a = report.aggregate;
  console.log(`decision-candidate mode=${report.mode} model=${report.model} threshold=${report.threshold.toFixed(3)}`);
  console.log(`attempted=${a.attempted} accepted=${a.accepted} reviewed=${a.reviewed} errors=${a.errors} expected=${a.expected} matched=${a.matched} mismatched=${a.mismatched}`);
  for (const item of report.cases) {
    const probs = Object.entries(item.probabilities).map(([name, value]) => `${printableLabel(name)}=${value.toFixed(3)}`).join(",");
    const match = item.match === undefined ? "-" : item.match ? "yes" : "no";
    console.log(`case ${printableLabel(item.key)} verdict=${item.verdict} expected=${item.expected ?? "-"} match=${match} probs=${probs || "-"}${item.error ? ` error=${item.error}` : ""}`);
  }
  console.log(`fidelity: ${report.fidelity}`);
}
function parseThreshold(value: string | undefined): number | undefined {
  const parsed = value === undefined ? Number.NaN : Number(value);
  return Number.isFinite(parsed) && parsed >= THRESHOLD && parsed <= 1 ? parsed : undefined;
}
export function parseModel(text: string): ModelRef | undefined {
  const end = text.indexOf("/");
  if (end <= 0) return undefined;
  const variantStart = text.indexOf("#", end + 1);
  const id = text.slice(end + 1, variantStart === -1 ? undefined : variantStart);
  const variant = variantStart === -1 ? undefined : text.slice(variantStart + 1);
  if (!id || variant?.includes("#") || (variant !== undefined && !variant)) return undefined;
  return { providerID: text.slice(0, end), id, ...(variant === undefined ? {} : { variant }) };
}

const CLI_OPTIONS = {
  input: { type: "string" },
  model: { type: "string" },
  report: { type: "string" },
  threshold: { type: "string" },
  live: { type: "boolean" },
} as const satisfies ParseArgsOptionsConfig;

function parseCliOptions(argv: readonly string[]) {
  return parseCliArgs({ args: argv, strict: true, allowPositionals: false, options: CLI_OPTIONS });
}

function argumentError(error: unknown): string {
  const failure = argFailure(error);
  if (failure?.kind === "unknown-option" || failure?.kind === "unexpected-positional") return `unknown argument: ${failure.token}`;
  if (failure?.kind === "missing-value") return `missing value for ${failure.token}`;
  if (failure?.kind === "unexpected-value") return `${failure.token} does not take a value`;
  return error instanceof Error ? error.message : "invalid arguments";
}

export function parseArgs(argv: readonly string[]): Options | { error: string } {
  let values: ReturnType<typeof parseCliOptions>["values"];
  try { values = parseCliOptions(argv).values; }
  catch (error) { return { error: argumentError(error) }; }
  if (values.input === undefined) return { error: "--input is required" };
  if (values.model === undefined) return { error: "--model is required" };
  const model = parseModel(values.model);
  if (model === undefined) return { error: "invalid --model" };
  const threshold = values.threshold === undefined ? THRESHOLD : parseThreshold(values.threshold);
  if (threshold === undefined) return { error: "invalid --threshold" };
  const options: Options = { input: values.input, model, modelText: values.model, live: values.live === true, threshold };
  if (values.report !== undefined) options.report = values.report;
  return options;
}
async function callDecision(input: unknown): Promise<unknown> {
  const bin = process.env.OPENCODE_BIN ?? "opencode";
  const { stdout } = await execFileAsync(bin, ["api", "experimental.generate.decisions", "--data", JSON.stringify(input)], { encoding: "utf8", maxBuffer: 1024 * 1024, timeout: LIVE_TIMEOUT_MS });
  const parsed = JSON.parse(stdout) as unknown;
  if (!isRecord(parsed)) return parsed;
  if ("data" in parsed) return parsed.data;
  if (parsed._tag !== undefined || (parsed.kind !== undefined && parsed.message !== undefined)) throw new Error("Decision CLI returned an error");
  return parsed;
}
async function liveCase(item: ManifestCase, options: Options): Promise<CaseReport> {
  try { return evaluationCase(item, await callDecision({ ...item.request, model: options.model }), options.threshold); }
  catch { return errorCase(item, "live-call-failed"); }
}
function parseManifest(text: string): ManifestCase[] | undefined {
  try { return manifestCases(JSON.parse(text) as unknown); } catch { return undefined; }
}
export async function evaluateManifest(options: Options): Promise<Report> {
  const cases = parseManifest(await readFile(options.input, "utf8"));
  if (cases === undefined) throw new Error("Invalid manifest");
  if (options.live && cases.length > MAX_LIVE_CALLS) throw new Error(`--live supports at most ${MAX_LIVE_CALLS} cases`);
  const results = options.live ? await mapLimit(cases, LIVE_CONCURRENCY, (item) => liveCase(item, options))
    : cases.map((item) => item.response === undefined ? errorCase(item, "missing-response") : evaluationCase(item, item.response, options.threshold));
  return buildReport(options, results, options.live ? "live" : "recorded");
}
async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  if ("error" in options) { console.error(`decision-candidate: ${options.error}`); process.exitCode = 2; return; }
  try {
    const report = await evaluateManifest(options);
    printReport(report);
    if (options.report !== undefined) {
      await writeFile(options.report, `${JSON.stringify(report, null, 2)}\n`);
      console.log(`report: ${options.report}`);
    }
  } catch (error) {
    console.error(`decision-candidate: ${error instanceof Error ? error.message : "failed"}`);
    process.exitCode = 1;
  }
}
if (import.meta.main) await main();
