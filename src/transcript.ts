const MAX_USERS = 10;
const MAX_TOOLS = 20;
const MAX_USER_CHARS = 8_000;
const MAX_ENTRY_CHARS = 500;
const MAX_TRANSCRIPT_BYTES = 12_000;

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

function escapedSize(value: string): number {
  return Buffer.byteLength(JSON.stringify(value));
}

function prefixByEscapedBytes(characters: string[], maxBytes: number): string {
  let low = 0;
  let high = characters.length;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    if (escapedSize(characters.slice(0, middle).join("")) <= maxBytes) low = middle;
    else high = middle - 1;
  }
  return characters.slice(0, low).join("");
}

function suffixByEscapedBytes(characters: string[], maxBytes: number): string {
  let low = 0;
  let high = characters.length;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    if (escapedSize(characters.slice(characters.length - middle).join("")) <= maxBytes) low = middle;
    else high = middle - 1;
  }
  return characters.slice(characters.length - low).join("");
}

/** Clips the head and tail so escaping cannot hide a trailing constraint. */
function clipEscaped(value: string, maxBytes: number): string {
  if (escapedSize(value) <= maxBytes) return value;
  const characters = Array.from(value);
  const marker = "…";
  const budget = Math.max(0, maxBytes - escapedSize(marker));
  const headBudget = Math.floor(budget * 0.6);
  return `${prefixByEscapedBytes(characters, headBudget)}${marker}${suffixByEscapedBytes(characters, budget - headBudget)}`;
}

function clipChars(value: string, max: number): string {
  if (value.length <= max) return value;
  const characters = Array.from(value);
  const head = Math.floor(max * 0.6);
  return `${characters.slice(0, head).join("")}…${characters.slice(characters.length - (max - head)).join("")}`;
}

interface TranscriptData {
  transcript: string;
  userEvidence: boolean;
  missingUserText: boolean;
  notes: string[];
}

function renderTranscript(entries: Entry[], toolTruncated: boolean, userClipped: boolean): { transcript: string; notes: string[] } {
  if (!entries.some((entry) => entry.role === "user")) return { transcript: "(no prior user messages in this session)", notes: [] };
  let users = 0;
  let tools = 0;
  const recent = entries.slice().reverse().filter((entry) => entry.role === "user" ? ++users <= MAX_USERS : ++tools <= MAX_TOOLS).reverse();
  const notes: string[] = [];
  if (recent.length < entries.length) notes.push("older messages omitted");
  if (toolTruncated) notes.push("some tool details truncated");
  if (userClipped) notes.push("latest user message truncated");
  const render = () => `User messages and prior tool calls (chronological):\n${JSON.stringify(recent)}` +
    (notes.length ? `\n… partial session history (${notes.join("; ")})` : "");

  while (Buffer.byteLength(render()) > MAX_TRANSCRIPT_BYTES && recent.length > 1) {
    // Keep at least the latest user message.
    const onlyOneUser = recent.filter((entry) => entry.role === "user").length <= 1;
    const index = onlyOneUser && recent[0].role === "user" ? recent.findIndex((entry) => entry.role === "tool") : 0;
    if (index < 0) break;
    recent.splice(index, 1);
    if (!notes.includes("older messages omitted")) notes.push("older messages omitted");
  }

  const latestUser = [...recent].reverse().find((entry) => entry.role === "user");
  for (let attempt = 0; latestUser !== undefined && Buffer.byteLength(render()) > MAX_TRANSCRIPT_BYTES && attempt < 10; attempt++) {
    if (!notes.includes("latest user message truncated")) notes.push("latest user message truncated");
    const excess = Buffer.byteLength(render()) - MAX_TRANSCRIPT_BYTES;
    latestUser.text = clipEscaped(latestUser.text, Math.max(128, escapedSize(latestUser.text) - excess - 64));
  }
  return { transcript: render(), notes };
}

function buildTranscript(messages: unknown[]): TranscriptData {
  const entries: Entry[] = [];
  let userEvidence = false;
  let missingUserText = false;
  let userClipped = false;
  let toolTruncated = false;
  for (const message of messages) {
    const record = asRecord(message);
    if (record?.type === "user") {
      const text = userText(message);
      if (text === undefined) {
        missingUserText = true;
        continue;
      }
      userEvidence = true;
      const clipped = clipChars(text, MAX_USER_CHARS);
      if (clipped !== text) userClipped = true;
      entries.push({ role: "user", text: clipped });
    }
    for (const tool of assistantTools(message)) {
      const formatted = formatTool(tool);
      if (formatted.truncated) toolTruncated = true;
      entries.push({ role: "tool", text: formatted.text });
    }
  }
  const rendered = renderTranscript(entries, toolTruncated, userClipped);
  return { transcript: rendered.transcript, userEvidence, missingUserText, notes: rendered.notes };
}

export interface ReviewContext { transcript: string; complete: boolean; reason?: string; notes?: string[] }

export function extractReviewContext(messages: unknown[]): ReviewContext {
  const attachment = messages.some((message) => {
    const record = asRecord(message);
    if (record?.type !== "user") return false;
    // These attachments carry evidence that the text-only reviewer cannot see.
    return ["files", "skills", "agents"].some((key) =>
      Array.isArray(record[key]) && record[key].length > 0);
  });
  const data = buildTranscript(messages);
  if (attachment)
    return {
      transcript: data.transcript, complete: false, notes: data.notes,
      reason: "User authorization includes attachments that cannot be reviewed automatically",
    };
  if (data.missingUserText)
    return {
      transcript: data.transcript, complete: false, notes: data.notes,
      reason: "A user message has no text that can be reviewed",
    };
  if (!data.userEvidence)
    return {
      transcript: data.transcript, complete: false, notes: data.notes,
      reason: "No user authorization message is available",
    };
  return { transcript: data.transcript, complete: true, notes: data.notes };
}

export function extractTranscript(messages: unknown[]): string {
  return buildTranscript(messages).transcript;
}
