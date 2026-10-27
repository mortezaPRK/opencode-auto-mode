const MAX_USERS = 10;
const MAX_TOOLS = 20;
const MAX_ENTRY_CHARS = 500;
const MAX_TRANSCRIPT_CHARS = 6000;

interface ToolEntry {
  name: string;
  input: unknown;
}

interface Entry {
  role: "user" | "tool";
  text: string;
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

function formatTool(tool: ToolEntry): { text: string; truncated: boolean } {
  let detail = "";
  let truncated = false;
  try {
    const state = asRecord(tool.input);
    const input = state?.["input"] ?? tool.input;
    const raw = typeof input === "string" ? input : JSON.stringify(input);
    if (raw) {
      truncated = raw.length > MAX_ENTRY_CHARS;
      detail = truncate(raw, MAX_ENTRY_CHARS);
    }
  } catch {
    detail = "";
  }
  return { text: detail ? `${tool.name} ${detail}` : tool.name, truncated };
}

interface TranscriptData {
  transcript: string;
  users: number;
  userEvidence: boolean;
  userTruncated: boolean;
}

function renderTranscript(entries: Entry[], toolTruncated: boolean): string {
  if (!entries.some((entry) => entry.role === "user")) return "(no prior user messages in this session)";
  let users = 0;
  let tools = 0;
  const recent = entries.slice().reverse().filter((entry) => entry.role === "user" ? ++users <= MAX_USERS : ++tools <= MAX_TOOLS).reverse();
  const notes: string[] = [];
  if (recent.length < entries.length) notes.push("incomplete session context");
  if (toolTruncated) notes.push("some tool details truncated");
  const note = notes.length ? `\n… ${notes.join("; ")}` : "";
  return truncate(`User messages and prior tool calls (chronological):\n${JSON.stringify(recent)}${note}`, MAX_TRANSCRIPT_CHARS);
}

function buildTranscript(messages: unknown[]): TranscriptData {
  const entries: Entry[] = [];
  let users = 0;
  let userEvidence = false;
  let userTruncated = false;
  let toolTruncated = false;
  for (const message of messages) {
    const text = userText(message);
    if (text !== undefined) {
      users++;
      userEvidence = true;
      if (text.length > MAX_ENTRY_CHARS) userTruncated = true;
      entries.push({ role: "user", text: truncate(text, MAX_ENTRY_CHARS) });
    }
    for (const tool of assistantTools(message)) {
      const formatted = formatTool(tool);
      if (formatted.truncated) toolTruncated = true;
      entries.push({ role: "tool", text: formatted.text });
    }
  }
  return { transcript: renderTranscript(entries, toolTruncated), users, userEvidence, userTruncated };
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
  const data = buildTranscript(messages);
  return {
    transcript: data.transcript,
    // Tool detail and tool-count truncation are noted in the transcript but do not hide user evidence.
    complete: supported && data.userEvidence && !data.userTruncated && data.users <= MAX_USERS,
  };
}

export function extractTranscript(messages: unknown[]): string {
  return buildTranscript(messages).transcript;
}
