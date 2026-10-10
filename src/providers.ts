import { object, localEndpoint, type ClassifierStage } from "./config.js";
import { buildReviewPrompt, type PermissionRequest, type ReviewResult, type Decision } from "./reviewer.js";
import type { ReviewPolicy } from "./policy.js";

export type ProviderStage = Extract<ClassifierStage, { type: "jev" | "openai-decision" | "laya" }>;
const choices = {
  allow: "The whole action is safe and authorized by the user for this exact scope.",
  deny: "The action violates the supplied policy or attempts to bypass a block.",
  ask: "Authorization, evidence, or impact is uncertain; the human must decide.",
};
const MAX_BYTES = 65_536;

function probability(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1;
}

function answer(value: unknown, stage: ProviderStage): ReviewResult | undefined {
  if (!object(value) || value.type !== "choice" || typeof value.choice !== "string" || !Object.hasOwn(choices, value.choice) ||
      !probability(value.confidence) || !object(value.probabilities))
    throw new Error("Invalid decision response");
  const entries = Object.entries(value.probabilities);
  if (entries.length !== 3 || entries.some(([key, value]) => !Object.hasOwn(choices, key) || !probability(value)))
    throw new Error("Invalid decision probabilities");
  const probabilities = value.probabilities as Record<Decision, number>;
  if (Math.abs(Object.values(probabilities).reduce((a, b) => a + b, 0) - 1) > 0.01 ||
      probabilities[value.choice as Decision] < Math.max(...Object.values(probabilities)))
    throw new Error("Inconsistent decision probabilities");
  if (value.choice === "ask") return { decision: "ask", reason: `${stage.type} requested human review` };
  if (value.confidence < (stage.minConfidence ?? 0.9) || probabilities[value.choice as Decision] < (stage.minConfidence ?? 0.9))
    return undefined;
  return { decision: value.choice as Decision, reason: `${stage.type} decision (confidence ${value.confidence})` };
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
      if (size > MAX_BYTES) throw new Error("Decision response too large");
      chunks.push(value);
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

export async function providerDecision(
  stage: ProviderStage,
  request: PermissionRequest,
  policy: ReviewPolicy,
  fetcher: typeof fetch = fetch,
): Promise<ReviewResult | undefined> {
  try {
    const openai = stage.type === "openai-decision";
    const endpoint = stage.type === "laya" ? localEndpoint(stage.endpoint ?? "http://127.0.0.1:8000/v1/systemone") :
      openai ? "https://api.openai.com/v1/decisions" : "https://api.typesafe.ai/v1/systemone";
    const key = process.env[stage.apiKeyEnv ?? (openai ? "OPENAI_API_KEY" : stage.type === "jev" ? "TYPESAFE_API_KEY" : "LAYA_API_KEY")];
    if (stage.type !== "laya" && !key) throw new Error("Missing decision provider credentials");
    const instructions = buildReviewPrompt(request, policy);
    const body = openai ? {
      model: stage.model ?? "gpt-6-luna",
      input: JSON.stringify(request),
      questions: [{ name: "permission", type: "choice", instructions,
        choices: Object.entries(choices).map(([value, description]) => ({ value, description })) }],
    } : {
      ...(stage.type === "jev" ? { model: stage.model ?? "jev-latest" } : stage.model ? { model: stage.model } : {}),
      state: request,
      questions: { permission: { type: "choice", instructions, criteria: choices } },
    };
    const payload = JSON.stringify(body);
    if (Buffer.byteLength(payload) > MAX_BYTES) throw new Error("Decision request too large");
    const response = await fetcher(endpoint, {
      method: "POST", redirect: "error", signal: AbortSignal.timeout(stage.timeoutMs ?? 10_000),
      headers: { "Content-Type": "application/json", ...(key ? { Authorization: `Bearer ${key}` } : {}) },
      body: payload,
    });
    const parsed = await readJSON(response);
    if (!object(parsed)) throw new Error("Invalid decision response");
    if (!openai) return answer(object(parsed.answers) ? parsed.answers.permission : undefined, stage);
    if (!Array.isArray(parsed.answers) || parsed.answers.length !== 1 || !object(parsed.answers[0]) ||
        parsed.answers[0].name !== "permission") throw new Error("Invalid OpenAI answer");
    const selected = parsed.answers[0];
    if (selected.type === "refusal") return { decision: "ask", reason: "OpenAI declined the decision" };
    if (!Array.isArray(selected.probabilities) || selected.probabilities.length !== 3)
      throw new Error("Invalid OpenAI probabilities");
    const distribution: Record<string, unknown> = {};
    for (const entry of selected.probabilities) {
      if (!object(entry) || typeof entry.value !== "string" || !Object.hasOwn(choices, entry.value) ||
          Object.hasOwn(distribution, entry.value)) throw new Error("Invalid OpenAI probability entry");
      distribution[entry.value] = entry.probability;
    }
    return answer({ ...selected, probabilities: distribution }, stage);
  } catch {
    return { decision: "ask", reason: `${stage.type} unavailable or returned an invalid decision` };
  }
}
