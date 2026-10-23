const MAX_USERS = 10;
const MAX_TOOLS = 20;
const MAX_ENTRY_CHARS = 500;
const MAX_TRANSCRIPT_CHARS = 6000;

interface ToolEntry {
  name: string;
  input: unknown;
}

function truncate(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return undefined;
}

function userText(message: unknown): string | undefined {
  const record = asRecord(message);
  if (record?.["type"] !== "user") return undefined;
  const text = record["text"];
  return typeof text === "string" && text.trim() ? text.trim() : undefined;
}

function assistantTools(message: unknown): ToolEntry[] {
  const record = asRecord(message);
  if (record?.["type"] !== "assistant") return [];
  const content = record["content"];
  if (!Array.isArray(content)) return [];
  const tools: ToolEntry[] = [];
  for (const part of content) {
    const entry = asRecord(part);
    if (entry?.["type"] !== "tool") continue;
    const name = entry["name"];
    if (typeof name !== "string" || !name) continue;
    tools.push({ name, input: entry["state"] });
  }
  return tools;
}

function formatTool(tool: ToolEntry): string {
  let detail = "";
  try {
    const state = asRecord(tool.input);
    const input = state?.["input"] ?? tool.input;
    const raw = typeof input === "string" ? input : JSON.stringify(input);
    if (raw) detail = truncate(raw, MAX_ENTRY_CHARS);
  } catch {
    detail = "";
  }
  return detail ? `${tool.name} ${detail}` : tool.name;
}

export interface ReviewContext { transcript: string; complete: boolean }

export function extractReviewContext(messages: unknown[]): ReviewContext {
  const supported = messages.every((message) => {
    const record = asRecord(message);
    if (record?.type !== "user") return true;
    // These attachments carry evidence that the text-only reviewer cannot see.
    return userText(message) !== undefined && ["files", "skills", "agents"].every((key) =>
      record[key] === undefined || (Array.isArray(record[key]) && record[key].length === 0));
  });
  const transcript = extractTranscript(messages);
  return {
    transcript,
    complete: supported && transcript.startsWith("User messages") && !transcript.includes("…"),
  };
}

export function extractTranscript(messages: unknown[]): string {
  const entries: { role: "user" | "tool"; text: string }[] = [];
  for (const message of messages) {
    const text = userText(message);
    if (text !== undefined) entries.push({ role: "user", text: truncate(text, MAX_ENTRY_CHARS) });
    for (const tool of assistantTools(message)) entries.push({ role: "tool", text: formatTool(tool) });
  }
  if (!entries.some((entry) => entry.role === "user")) return "(no prior user messages in this session)";
  let users = 0;
  let tools = 0;
  const recent = entries.slice().reverse().filter((entry) => entry.role === "user" ? ++users <= MAX_USERS : ++tools <= MAX_TOOLS).reverse();
  const incomplete = recent.length < entries.length ? "\n… incomplete session context" : "";
  return truncate(`User messages and prior tool calls (chronological):\n${JSON.stringify(recent)}${incomplete}`, MAX_TRANSCRIPT_CHARS);
}
