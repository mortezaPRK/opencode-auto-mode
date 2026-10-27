import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { extractReviewContext, extractTranscript } from "./transcript.js";

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
    }
    assert.equal(extractReviewContext([{ type: "user", text: "" }]).complete, false);
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
    assert.match(capped.transcript, /incomplete session context/);
  });
  it("still requires untruncated user evidence", () => {
    assert.equal(extractReviewContext([{ type: "user", text: "x".repeat(501) }]).complete, false);
    assert.equal(extractReviewContext(Array.from({ length: 11 }, (_, index) => ({ type: "user", text: `message ${index}` }))).complete, false);
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
    const transcript = extractTranscript([{ type: "user", text: "x".repeat(5000) }]);
    assert.ok(transcript.length < 6500);
    assert.match(transcript, /…/);
  });
  it("keeps chronology and marks missing evidence", () => {
    const chronology = extractTranscript([{ type: "user", text: "first" }, { type: "assistant", content: [{ type: "tool", name: "shell", state: { input: "middle" } }] }, { type: "user", text: "last" }]);
    assert.ok(chronology.indexOf("first") < chronology.indexOf("middle"));
    assert.ok(chronology.indexOf("middle") < chronology.indexOf("last"));
    assert.match(extractTranscript(Array.from({ length: 11 }, () => ({ type: "user", text: "hello" }))), /incomplete/);
  });
});
