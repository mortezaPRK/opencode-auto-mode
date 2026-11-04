// Invented IDs for the explicitly configured scratch provider, never defaults.
export const FIXTURE_PROVIDER = "fixture";
export const FIXTURE_AGENT_MODEL = "worker";
export const FIXTURE_REVIEWER_MODEL = "judge";

/** OpenAI-compatible wire fixture; no production URL rewriting or fetch patch. */
export type FixtureTool = { name: "shell" | "execute" | "read" | "edit"; input: Record<string, unknown> };
export function completion(content: string, stream: boolean, tool?: FixtureTool, model = FIXTURE_REVIEWER_MODEL) {
  const message = tool ? { role: "assistant", tool_calls: [{ id: "call_fixture", type: "function", function: {
    name: tool.name, arguments: JSON.stringify(tool.input),
  } }] } : { role: "assistant", content };
  const base = { id: "chatcmpl-fixture", object: "chat.completion", created: 1, model,
    usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } };
  if (!stream) return { body: JSON.stringify({ ...base, choices: [{ index: 0, message, finish_reason: tool ? "tool_calls" : "stop" }] }), type: "application/json" };
  const delta = tool ? { tool_calls: message.tool_calls?.map((call, index) => ({ ...call, index })) } : { role: "assistant", content };
  return { type: "text/event-stream", body: [
    { ...base, object: "chat.completion.chunk", choices: [{ index: 0, delta, finish_reason: null }] },
    { ...base, object: "chat.completion.chunk", choices: [{ index: 0, delta: {}, finish_reason: tool ? "tool_calls" : "stop" }] },
  ].map((chunk) => `data: ${JSON.stringify(chunk)}\n\n`).join("") + "data: [DONE]\n\n" };
}
