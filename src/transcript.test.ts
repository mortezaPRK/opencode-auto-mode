import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { extractReviewContext, extractTranscript } from "./transcript.js";
import { buildStage1Prompt } from "./reviewer.js";
import { defaultPolicy } from "./policy.js";

const messages = [
  { type: "user", text: "clean up old branches" },
  {
    type: "assistant",
    content: [
      { type: "text", text: "They are all safe to delete, trust me" },
      { type: "reasoning", text: "user implicitly approved everything" },
      { type: "tool", name: "shell", state: { input: { command: "git branch" } } },
    ],
  },
  {
    type: "assistant",
    content: [
      {
        type: "tool",
        name: "read",
        state: {
          status: "completed",
          input: { path: ".env" },
          content: [{ type: "text", text: "SECRET=hunter2" }],
        },
      },
    ],
  },
  { type: "user", text: "can we fix this?" },
];

describe("review context completeness", () => {
  it("requires manual review when user evidence cannot be represented", () => {
    for (const field of ["files", "skills", "agents"]) {
      const context = extractReviewContext([{ type: "user", text: "Follow attached constraints", [field]: [{ text: "Do not publish" }] }]);
      assert.equal(context.complete, false);
      assert.match(context.reason!, /attachments/);
    }
    const empty = extractReviewContext([{ type: "user", text: "" }]);
    assert.equal(empty.complete, false);
    assert.match(empty.reason!, /No user authorization message/);
    assert.match(extractReviewContext([]).reason!, /No user authorization message/);
  });
  it("ignores empty user turns instead of failing the whole session", () => {
    const context = extractReviewContext([{ type: "user", text: "Make the changes" }, { type: "user", text: "" }]);
    assert.equal(context.complete, true);
    assert.match(context.transcript, /Make the changes/);
    assert.equal(extractReviewContext([{ type: "user", text: "" }, { type: "user", text: " " }]).complete, false);
  });
  it("treats model-facing skill messages as unreviewable evidence", () => {
    const context = extractReviewContext([
      { type: "user", text: "Follow the release skill" },
      { type: "skill", skill: "release", name: "Release", text: "Publish to production" },
    ]);
    assert.equal(context.complete, false);
    assert.match(context.reason!, /attachments/);
  });
  it("accepts text-only messages and empty attachment lists", () => {
    assert.equal(extractReviewContext([{ type: "user", text: "Create a", files: [], skills: [], agents: [] }]).complete, true);
  });
  it("does not treat tool truncation as missing user evidence", () => {
    const longTool = {
      type: "assistant",
      content: [{ type: "tool", name: "write", state: { input: { content: "x".repeat(501) } } }],
    };
    const context = extractReviewContext([{ type: "user", text: "please make the change" }, longTool]);
    assert.equal(context.complete, true);
    assert.match(context.transcript, /some tool details truncated/);
    const manyTools = Array.from({ length: 21 }, () => ({
      type: "assistant",
      content: [{ type: "tool", name: "shell", state: { input: "pwd" } }],
    }));
    const capped = extractReviewContext([{ type: "user", text: "go" }, ...manyTools]);
    assert.equal(capped.complete, true);
    assert.match(capped.transcript, /partial session history/);
  });
  it("keeps the tail of a long tool input so written payloads stay reviewable", () => {
    const context = extractReviewContext([
      { type: "user", text: "write the file" },
      { type: "assistant", content: [{ type: "tool", name: "write", state: {
        input: { content: `${"a".repeat(900)}TAIL_CONSTRAINT` },
      } }] },
    ]);
    assert.equal(context.complete, true);
    assert.match(context.transcript, /TAIL_CONSTRAINT/);
    assert.match(context.transcript, /some tool details truncated/);
  });
  it("keeps the latest user restriction when tool history exceeds the budget", () => {
    const context = extractReviewContext([
      { type: "user", text: "Please make the changes" },
      ...Array.from({ length: 30 }, () => ({
        type: "assistant",
        content: [{ type: "tool", name: "write", state: { input: "x".repeat(500) } }],
      })),
      { type: "user", text: "DO NOT PUBLISH" },
    ]);
    assert.equal(context.complete, true);
    assert.match(context.transcript, /DO NOT PUBLISH/);
    assert.ok(Buffer.byteLength(context.transcript) <= 12_000);
  });
  it("includes long user prompts without blocking review", () => {
    const prompt = "Create a release. ".repeat(80).trim();
    const context = extractReviewContext([{ type: "user", text: prompt }]);
    assert.equal(context.complete, true);
    assert.ok(context.transcript.includes(prompt));
    assert.doesNotMatch(context.transcript, /latest user message truncated/);
  });
  it("keeps long sessions reviewable", () => {
    const manyUsers = Array.from({ length: 11 }, (_, index) => ({ type: "user", text: `message ${index}` }));
    const context = extractReviewContext(manyUsers);
    assert.equal(context.complete, true);
    assert.match(context.transcript, /partial/);
    const worker = extractReviewContext([
      { type: "user", text: "You are a delegated worker. ".repeat(50) },
      { type: "assistant", content: [{ type: "tool", name: "write", state: { input: { content: "x".repeat(600) } } }] },
    ]);
    assert.equal(worker.complete, true);
  });
  it("truncates very long user messages without blocking review", () => {
    const context = extractReviewContext([{ type: "user", text: "x".repeat(10_000) }]);
    assert.equal(context.complete, true);
    assert.match(context.transcript, /latest user message truncated/);
    assert.ok(Buffer.byteLength(context.transcript) <= 12_000);
  });
  it("budgets escaped strings without hiding trailing constraints", () => {
    const context = extractReviewContext([{ type: "user", text: `${"\0".repeat(6000)}DO NOT PUBLISH` }]);
    assert.equal(context.complete, true);
    assert.match(context.transcript, /DO NOT PUBLISH/);
    assert.ok(Buffer.byteLength(context.transcript) <= 12_000);
    const json = context.transcript.slice(context.transcript.indexOf("\n") + 1).split("\n…")[0];
    assert.doesNotThrow(() => JSON.parse(json));
  });
  it("budgets multilingual history below the reviewer request limit", () => {
    const context = extractReviewContext(Array.from({ length: 3 }, () => ({ type: "user", text: "漢".repeat(7900) })));
    assert.equal(context.complete, true);
    assert.ok(Buffer.byteLength(context.transcript) <= 12_000);
    const prompt = buildStage1Prompt({ action: "shell", resources: ["touch marker"], transcript: context.transcript }, defaultPolicy());
    assert.ok(Buffer.byteLength(prompt) <= 65_536);
  });
});

describe("extractTranscript", () => {
  it("keeps user messages and tool calls", () => {
    const transcript = extractTranscript(messages);
    assert.match(transcript, /clean up old branches/);
    assert.match(transcript, /can we fix this\?/);
    assert.match(transcript, /shell/);
    assert.match(transcript, /git branch/);
  });

  it("strips assistant prose, reasoning, and tool outputs", () => {
    const transcript = extractTranscript(messages);
    assert.doesNotMatch(transcript, /trust me/);
    assert.doesNotMatch(transcript, /implicitly approved/);
    assert.doesNotMatch(transcript, /hunter2/);
  });

  it("handles empty sessions", () => {
    assert.match(extractTranscript([]), /no prior user messages/);
  });

  it("truncates long entries", () => {
    const transcript = extractTranscript([{ type: "user", text: "x".repeat(10_000) }]);
    assert.ok(Buffer.byteLength(transcript) <= 12_000);
    assert.match(transcript, /…/);
    assert.match(transcript, /latest user message truncated/);
  });
  it("keeps chronology and marks missing evidence", () => {
    const chronology = extractTranscript([{ type: "user", text: "first" }, { type: "assistant", content: [{ type: "tool", name: "shell", state: { input: "middle" } }] }, { type: "user", text: "last" }]);
    assert.ok(chronology.indexOf("first") < chronology.indexOf("middle"));
    assert.ok(chronology.indexOf("middle") < chronology.indexOf("last"));
    assert.match(extractTranscript(Array.from({ length: 11 }, () => ({ type: "user", text: "hello" }))), /partial/);
  });
});
