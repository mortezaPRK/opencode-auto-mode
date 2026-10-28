import { Effect } from "effect";
import {
  Evaluation,
  EvaluationClient,
  EvaluationModel,
  EvaluationResponse,
  type EvaluationAnswer,
  type EvaluationInput,
  type EvaluationRoute,
} from "@opencode/ai/experimental";
import { AIError, InvalidProviderOutputError, ModelID } from "@opencode/ai";
import { localEndpoint, parseReviewerModel, type DecisionStage } from "./config.js";
import { buildReviewPrompt, type Decision, type PermissionRequest, type StageResult } from "./reviewer.js";
import type { ReviewPolicy } from "./policy.js";
import { errorKindOf, ReviewFailure } from "./errors.js";

const choices = {
  allow: "The whole action is safe and authorized by the user for this exact scope.",
  deny: "The action violates the supplied policy or attempts to bypass a block.",
  ask: "Authorization, evidence, or impact is uncertain; the human must decide.",
} as const;
const MAX_BYTES = 65_536;
const SYSTEM_ONE_URL = "https://api.typesafe.ai/v1/systemone";
const LOCAL_SYSTEM_ONE_URL = "http://127.0.0.1:8000/v1/systemone";
const OPENAI_URL = "https://api.openai.com/v1/decisions";
const API_KEY_ENV = {
  "typesafe-ai": "TYPESAFE_API_KEY",
  laya: "LAYA_API_KEY",
  openai: "OPENAI_API_KEY",
} as const;

type RuntimeDecisionStage = DecisionStage & { readonly apiKey?: string; readonly signal?: AbortSignal };

/** Per-request abort signal: the stage timeout bound by the overall review deadline. */
function abortSignal(stage: RuntimeDecisionStage): AbortSignal {
  const timeout = AbortSignal.timeout(stage.timeoutMs ?? 10_000);
  return stage.signal === undefined ? timeout : AbortSignal.any([timeout, stage.signal]);
}

function probability(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1;
}

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function answer(value: unknown, stage: RuntimeDecisionStage): StageResult {
  if (!object(value) || value.type !== "choice" || typeof value.choice !== "string" || !Object.hasOwn(choices, value.choice) ||
      !probability(value.confidence) || !object(value.probabilities))
    throw new ReviewFailure("invalid-output", "Invalid decision response");
  const entries = Object.entries(value.probabilities);
  if (entries.length !== 3 || entries.some(([key, value]) => !Object.hasOwn(choices, key) || !probability(value)))
    throw new ReviewFailure("invalid-output", "Invalid decision probabilities");
  const probabilities = value.probabilities as Record<Decision, number>;
  if (Math.abs(Object.values(probabilities).reduce((a, b) => a + b, 0) - 1) > 0.01 ||
      probabilities[value.choice as Decision] < Math.max(...Object.values(probabilities)))
    throw new ReviewFailure("invalid-output", "Inconsistent decision probabilities");
  if (value.choice === "ask") return { decision: "ask", reason: `${stage.model} requested human review` };
  const threshold = stage.minConfidence ?? 0.9;
  if (value.confidence < threshold || probabilities[value.choice as Decision] < threshold) {
    if (value.choice === "deny") return { decision: "ask", reason: `${stage.model} returned a low-confidence deny` };
    return { decision: "abstain", reason: `${stage.model} abstained below the confidence threshold` };
  }
  return { decision: value.choice as Decision, reason: `${stage.model} decision (confidence ${value.confidence})` };
}

function parseJSON(value: string): unknown {
  try { return JSON.parse(value); }
  catch (error) { throw new ReviewFailure("invalid-output", "Decision response is not valid JSON", { cause: error }); }
}

async function readJSON(response: Response): Promise<unknown> {
  if (!response.ok || !response.body) throw new Error("Decision provider failed");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > MAX_BYTES) throw new ReviewFailure("invalid-output", "Decision response too large");
      chunks.push(value);
    }
    return parseJSON(Buffer.concat(chunks).toString("utf8"));
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

function state(request: PermissionRequest): EvaluationInput {
  const value = JSON.parse(JSON.stringify(request)) as EvaluationInput;
  if (Buffer.byteLength(JSON.stringify(value)) > MAX_BYTES) throw new Error("Decision request too large");
  return value;
}

function systemOneEndpoint(stage: RuntimeDecisionStage): string {
  return stage.endpoint === undefined ? LOCAL_SYSTEM_ONE_URL : localEndpoint(stage.endpoint);
}

function evaluationChoice(value: unknown): EvaluationAnswer {
  if (!object(value) || value.type !== "choice" || typeof value.choice !== "string")
    throw new ReviewFailure("invalid-output", "Invalid System One answer");
  if (!object(value.probabilities) || !probability(value.confidence))
    throw new ReviewFailure("invalid-output", "Invalid System One answer");
  return {
    type: "choice",
    choice: value.choice,
    probabilities: value.probabilities as Record<string, number>,
    confidence: value.confidence,
  };
}

function systemOneRoute(stage: RuntimeDecisionStage, modelID: string, url: string, fetcher: typeof fetch): EvaluationRoute {
  return {
    id: "system-one",
    evaluate: (request) => Effect.tryPromise({
      try: async () => {
        const payload = JSON.stringify({ model: modelID, state: request.state, questions: request.questions });
        if (Buffer.byteLength(payload) > MAX_BYTES) throw new Error("Decision request too large");
        const response = await fetcher(url, {
          method: "POST", redirect: "error", signal: abortSignal(stage),
          headers: { "Content-Type": "application/json", ...(stage.apiKey === undefined ? {} : { Authorization: `Bearer ${stage.apiKey}` }) },
          body: payload,
        });
        const parsed = await readJSON(response);
        const value = object(parsed) && object(parsed.answers) ? parsed.answers.permission : undefined;
        return new EvaluationResponse({
          model: ModelID.make(modelID),
          answers: { permission: evaluationChoice(value) },
        });
      },
      catch: (cause) => new AIError({
        reason: new InvalidProviderOutputError({ route: "system-one", message: "System One request failed", cause }),
      }),
    }),
  };
}

async function systemOneDecision(
  stage: RuntimeDecisionStage,
  request: PermissionRequest,
  policy: ReviewPolicy,
  fetcher: typeof fetch,
): Promise<StageResult> {
  const ref = parseReviewerModel(stage.model);
  const key = stage.apiKey;
  if (ref.providerID !== "laya" && !key) throw new Error("Missing decision provider credentials");
  const model = EvaluationModel.make({
    id: ref.id,
    provider: ref.providerID,
    route: systemOneRoute(stage, ref.id, ref.providerID === "laya" ? systemOneEndpoint(stage) : SYSTEM_ONE_URL, fetcher),
  });
  const response = await Effect.runPromise(
    Evaluation.run({
      model,
      state: state(request),
      questions: {
        permission: { type: "choice", instructions: buildReviewPrompt(request, policy), criteria: choices },
      },
    }).pipe(Effect.provide(EvaluationClient.fetchLayer)),
  );
  return answer(response.answers.permission, stage);
}

async function openAIDecision(
  stage: RuntimeDecisionStage,
  request: PermissionRequest,
  policy: ReviewPolicy,
  fetcher: typeof fetch,
): Promise<StageResult> {
  const ref = parseReviewerModel(stage.model);
  if (!stage.apiKey) throw new Error("Missing decision provider credentials");
  const body = {
    model: ref.id,
    input: JSON.stringify(request),
    questions: [{
      name: "permission",
      type: "choice",
      instructions: buildReviewPrompt(request, policy),
      choices: Object.entries(choices).map(([value, description]) => ({ value, description })),
    }],
  };
  const payload = JSON.stringify(body);
  if (Buffer.byteLength(payload) > MAX_BYTES) throw new Error("Decision request too large");
  const response = await fetcher(OPENAI_URL, {
    method: "POST", redirect: "error", signal: abortSignal(stage),
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${stage.apiKey}` },
    body: payload,
  });
  const parsed = await readJSON(response);
  if (!object(parsed) || !Array.isArray(parsed.answers) || parsed.answers.length !== 1 || !object(parsed.answers[0]) ||
      parsed.answers[0].name !== "permission") throw new ReviewFailure("invalid-output", "Invalid OpenAI answer");
  const selected = parsed.answers[0];
  if (selected.type === "refusal") return { decision: "abstain", reason: `${stage.model} declined the decision` };
  if (!Array.isArray(selected.probabilities) || selected.probabilities.length !== 3)
    throw new ReviewFailure("invalid-output", "Invalid OpenAI probabilities");
  const distribution: Record<string, unknown> = {};
  for (const entry of selected.probabilities) {
    if (!object(entry) || typeof entry.value !== "string" || !Object.hasOwn(choices, entry.value) ||
        Object.hasOwn(distribution, entry.value))
      throw new ReviewFailure("invalid-output", "Invalid OpenAI probability entry");
    distribution[entry.value] = entry.probability;
  }
  return answer({ ...selected, probabilities: distribution }, stage);
}

export async function decisionStage(
  input: DecisionStage,
  request: PermissionRequest,
  policy: ReviewPolicy,
  fetcher: typeof fetch = fetch,
  signal?: AbortSignal,
): Promise<StageResult> {
  try {
    const ref = parseReviewerModel(input.model);
    if (!Object.hasOwn(API_KEY_ENV, ref.providerID)) throw new Error("Unsupported decision provider");
    const stage: RuntimeDecisionStage = {
      ...input,
      apiKey: process.env[input.apiKeyEnv ?? API_KEY_ENV[ref.providerID as keyof typeof API_KEY_ENV]],
      signal,
    };
    return ref.providerID === "openai" ? await openAIDecision(stage, request, policy, fetcher) :
      await systemOneDecision(stage, request, policy, fetcher);
  } catch (error) {
    return {
      decision: "abstain",
      reason: `${input.model} unavailable or returned an invalid decision`,
      errorKind: errorKindOf(error),
    };
  }
}
