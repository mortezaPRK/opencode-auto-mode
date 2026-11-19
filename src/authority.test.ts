import { it } from "node:test";
import assert from "node:assert/strict";
import {
  collectAuthority,
  DEFAULT_AUTHORITY_MAX_BYTES,
  type AuthorityContextMessage,
  type AuthorityLookups,
  type AuthoritySessionInfo,
} from "./authority.js";
import { EvidenceFailure, ReviewFailure } from "./errors.js";

interface Fixture {
  readonly parentID?: string;
  readonly fork?: unknown;
  readonly messages: readonly AuthorityContextMessage[];
}

const user = (text: string): AuthorityContextMessage => ({ type: "user", text });
const userAt = (text: string, created: unknown): AuthorityContextMessage =>
  ({ type: "user", text, time: { created } });
const assistant = (text: string): AuthorityContextMessage => ({ type: "assistant", text });

function adapter(sessions: Readonly<Record<string, Fixture | undefined>>) {
  const calls: string[] = [];
  const lookups: AuthorityLookups = {
    async get(sessionID) {
      calls.push(`get:${sessionID}`);
      const fixture = sessions[sessionID];
      if (fixture === undefined) return undefined;
      return {
        parentID: fixture.parentID,
        fork: fixture.fork as AuthoritySessionInfo["fork"],
      };
    },
    async context(sessionID) {
      calls.push(`context:${sessionID}`);
      const fixture = sessions[sessionID];
      if (fixture === undefined) throw new Error("context unavailable");
      return fixture.messages;
    },
  };
  return { lookups, calls };
}

it("treats every root user message as chronological authority", async () => {
  const { lookups } = adapter({
    root: { messages: [
      user("First request: inspect the failure."),
      assistant("I will inspect it."),
      { type: "system", text: "System note." },
      user("Persistent restriction: never edit release branches."),
    ] },
  });
  const result = await collectAuthority("root", lookups);
  assert.deepEqual(result.userMessages, [
    "First request: inspect the failure.",
    "Persistent restriction: never edit release branches.",
  ]);
  assert.deepEqual(result.delegations, []);
});

it("keeps full child user text as delegation, never authority", async () => {
  const delegation = "You are a subagent. No tools.\nReturn the exact patch.";
  const { lookups } = adapter({
    root: { messages: [user("Implement the change.")] },
    child: { parentID: "root", messages: [user(delegation), assistant("Working.")] },
  });
  const result = await collectAuthority("child", lookups);
  assert.deepEqual(result.userMessages, ["Implement the change."]);
  assert.deepEqual(result.delegations, [{ sessionID: "child", messages: [delegation] }]);
  assert.equal(result.delegations[0]?.messages[0], delegation);
});

it("orders intermediate and current delegation from root to leaf", async () => {
  const { lookups } = adapter({
    root: { messages: [user("Parent request.")] },
    middle: { parentID: "root", messages: [user("Middle delegation.")] },
    current: { parentID: "middle", messages: [user("Current delegation.")] },
  });
  const result = await collectAuthority("current", lookups);
  assert.deepEqual(result.userMessages, ["Parent request."]);
  assert.deepEqual(result.delegations, [
    { sessionID: "middle", messages: ["Middle delegation."] },
    { sessionID: "current", messages: ["Current delegation."] },
  ]);
});

it("excludes future user messages from the root and delegation at the cutoff", async () => {
  const { lookups } = adapter({
    root: { messages: [
      userAt("Root request.", 1_000),
      userAt("Root boundary.", 1_500),
      assistant("Future assistant prose."),
      userAt("Root future restriction.", 1_501),
    ] },
    child: { parentID: "root", messages: [
      userAt("Child request.", 1_200),
      userAt("Child future restriction.", 2_000),
    ] },
  });
  const result = await collectAuthority("child", lookups, { asOf: 1_500 });
  assert.deepEqual(result.userMessages, ["Root request.", "Root boundary."]);
  assert.deepEqual(result.delegations, [
    { sessionID: "child", messages: ["Child request."] },
  ]);
});

it("fails closed when a user authority timestamp is missing or invalid", async () => {
  const missing = adapter({ root: { messages: [user("No timestamp.")] } });
  await assert.rejects(collectAuthority("root", missing.lookups, { asOf: 1 }), (error) =>
    error instanceof EvidenceFailure && /timestamp/i.test(error.message));
  const invalid = adapter({
    root: { messages: [userAt("Root request.", 1)] },
    child: { parentID: "root", messages: [userAt("Bad child timestamp.", Number.NaN)] },
  });
  await assert.rejects(collectAuthority("child", invalid.lookups, { asOf: 2 }), (error) =>
    error instanceof EvidenceFailure && /timestamp/i.test(error.message));
  const invalidCutoff = adapter({ root: { messages: [userAt("Root request.", 1)] } });
  await assert.rejects(
    collectAuthority("root", invalidCutoff.lookups, { asOf: Number.POSITIVE_INFINITY }),
    (error) => error instanceof EvidenceFailure && /cutoff/i.test(error.message),
  );
});

it("rejects fork provenance with or without a parent", async () => {
  const withParent = adapter({
    root: { messages: [user("Root request.")] },
    child: {
      parentID: "root",
      fork: { sessionID: "forked" },
      messages: [user("Copied human history.")],
    },
  });
  await assert.rejects(collectAuthority("child", withParent.lookups), (error) =>
    error instanceof EvidenceFailure &&
    error.message === "Fork authority provenance requires review");
  const withoutParent = adapter({
    forked: {
      fork: { sessionID: "origin", boundary: "message-1" },
      messages: [userAt("Copied human history.", 1_000), userAt("Real follow-up.", 1_500)],
    },
  });
  await assert.rejects(collectAuthority("forked", withoutParent.lookups, { asOf: 2_000 }), (error) =>
    error instanceof EvidenceFailure &&
    error.message === "Fork authority provenance requires review");
  assert.deepEqual(withoutParent.calls, ["get:forked"]);
});

it("accepts live fork:null metadata for a root and child", async () => {
  const root = adapter({
    root: {
      parentID: undefined,
      fork: null,
      messages: [user("Root request.")],
    },
  });
  const rootResult = await collectAuthority("root", root.lookups);
  assert.deepEqual(rootResult.userMessages, ["Root request."]);
  assert.deepEqual(rootResult.delegations, []);
  const child = adapter({
    root: { fork: null, messages: [user("Root request.")] },
    child: { parentID: "root", fork: null, messages: [user("Child delegation.")] },
  });
  const childResult = await collectAuthority("child", child.lookups);
  assert.deepEqual(childResult.userMessages, ["Root request."]);
  assert.deepEqual(childResult.delegations, [
    { sessionID: "child", messages: ["Child delegation."] },
  ]);
});

it("fails closed on a non-string user text or an invalid parent id", async () => {
  const nonStringText = adapter({ root: { messages: [{ type: "user", text: 7 }] } });
  await assert.rejects(collectAuthority("root", nonStringText.lookups), (error) =>
    error instanceof EvidenceFailure && /user message/i.test(error.message));
  for (const parentID of [7, "", null] as unknown[]) {
    const { lookups } = adapter({
      child: { parentID: parentID as string, messages: [user("Child delegation.")] },
    });
    await assert.rejects(collectAuthority("child", lookups), (error) =>
      error instanceof EvidenceFailure && /parent/i.test(error.message));
  }
});

it("rejects malformed non-null fork metadata", async () => {
  for (const fork of ["forked", false, 0]) {
    const { lookups } = adapter({
      root: { fork, messages: [user("Root request.")] },
    });
    await assert.rejects(collectAuthority("root", lookups), (error) =>
      error instanceof EvidenceFailure &&
      error.message === "Fork authority provenance requires review");
  }
});

it("fails closed when active context contains compaction", async () => {
  const root = adapter({
    root: { messages: [
      userAt("Root request.", 1_000),
      { type: "compaction", text: "Compacted history.", time: { created: 3_000 } },
      userAt("Persistent restriction.", 1_200),
    ] },
  });
  await assert.rejects(collectAuthority("root", root.lookups, { asOf: 2_000 }), (error) =>
    error instanceof EvidenceFailure && /compaction/i.test(error.message));
  const delegation = adapter({
    root: { messages: [userAt("Root request.", 1_000)] },
    child: { parentID: "root", messages: [
      userAt("Child request.", 1_200),
      { type: "compaction", text: "Compacted child history." },
    ] },
  });
  await assert.rejects(collectAuthority("child", delegation.lookups), (error) =>
    error instanceof EvidenceFailure && /compaction/i.test(error.message));
});

it("preserves every user text in source order through the cutoff", async () => {
  const first = "First: inspect the failure.";
  const restriction = "Persistent restriction: never edit release/* branches.";
  const pattern = "Do not run /deploy|release/ commands; keep ^this$ text *exactly*.";
  const last = "Final request at the cutoff.";
  const { lookups } = adapter({
    root: { messages: [
      userAt(first, 1_000),
      assistant("Interleaved assistant prose."),
      userAt(restriction, 2_000),
      { type: "system", text: "System note." },
      userAt(pattern, 3_000),
      userAt("Future restriction.", 4_001),
      userAt(last, 4_000),
    ] },
    child: { parentID: "root", messages: [
      userAt("Child restriction: never deploy.", 2_500),
      userAt("Child future restriction.", 4_001),
    ] },
  });
  const result = await collectAuthority("child", lookups, { asOf: 4_000 });
  assert.deepEqual(result.userMessages, [first, restriction, pattern, last]);
  assert.deepEqual(result.delegations, [
    { sessionID: "child", messages: ["Child restriction: never deploy."] },
  ]);
});

it("rejects an exact parent cycle without rereading a session", async () => {
  const { lookups, calls } = adapter({
    a: { parentID: "b", messages: [user("a")] },
    b: { parentID: "a", messages: [user("b")] },
  });
  await assert.rejects(collectAuthority("a", lookups), (error) =>
    error instanceof EvidenceFailure && /cyclic/i.test(error.message));
  assert.deepEqual(calls, ["get:a", "get:b"]);
});

it("bounds the parent chain inclusively at maxDepth", async () => {
  const { lookups } = adapter({
    a: { parentID: "b", messages: [user("a")] },
    b: { parentID: "c", messages: [user("b")] },
    c: { messages: [user("c")] },
  });
  const allowed = await collectAuthority("a", lookups, { maxDepth: 3 });
  assert.deepEqual(allowed.userMessages, ["c"]);
  assert.deepEqual(allowed.delegations.map((entry) => entry.sessionID), ["b", "a"]);
  await assert.rejects(collectAuthority("a", lookups, { maxDepth: 2 }), (error) =>
    error instanceof EvidenceFailure && /deep/i.test(error.message));
});

it("rejects a root without user authority", async () => {
  const proseOnly = adapter({ root: { messages: [assistant("No user input.")] } });
  await assert.rejects(collectAuthority("root", proseOnly.lookups), (error) =>
    error instanceof EvidenceFailure);
  const missingSession = adapter({});
  await assert.rejects(collectAuthority("", missingSession.lookups), (error) =>
    error instanceof EvidenceFailure);
});

it("fails terminally when a parent session or context is missing", async () => {
  const missingParent = adapter({
    child: { parentID: "gone", messages: [user("Child delegation.")] },
  });
  await assert.rejects(collectAuthority("child", missingParent.lookups), (error) =>
    error instanceof EvidenceFailure);
  const missingContext: AuthorityLookups = {
    get: async () => ({}),
    context: async () => { throw new Error("context unavailable"); },
  };
  await assert.rejects(collectAuthority("root", missingContext), (error) =>
    error instanceof EvidenceFailure);
});

it("rejects evidence larger than the byte budget instead of truncating", async () => {
  const exact = "a".repeat(DEFAULT_AUTHORITY_MAX_BYTES);
  const within = await collectAuthority("root", adapter({ root: { messages: [user(exact)] } }).lookups);
  assert.equal(within.userMessages[0], exact);
  const over = adapter({
    root: { messages: [user(exact)] },
    child: { parentID: "root", messages: [user("b")] },
  });
  await assert.rejects(collectAuthority("child", over.lookups), (error) =>
    error instanceof EvidenceFailure && /too large/i.test(error.message));
  const custom = adapter({ root: { messages: [user("12345678901")] } });
  await assert.rejects(collectAuthority("root", custom.lookups, { maxBytes: 10 }), (error) =>
    error instanceof EvidenceFailure && /too large/i.test(error.message));
});

it("honors cancellation before any lookup starts", async () => {
  const controller = new AbortController();
  controller.abort();
  let called = false;
  const lookups: AuthorityLookups = {
    async get() { called = true; return {}; },
    async context() { called = true; return []; },
  };
  await assert.rejects(collectAuthority("root", lookups, { signal: controller.signal }), (error) =>
    error instanceof ReviewFailure && error.kind === "cancelled");
  assert.equal(called, false);
});

it("settles promptly when cancelled during a lookup", async () => {
  const controller = new AbortController();
  const lookups: AuthorityLookups = {
    get: () => new Promise<never>(() => {}),
    context: async () => [],
  };
  const pending = collectAuthority("root", lookups, { signal: controller.signal });
  controller.abort();
  await assert.rejects(pending, (error) =>
    error instanceof ReviewFailure && error.kind === "cancelled");
});

it("handles a lookup that aborts and rejects synchronously", async () => {
  const controller = new AbortController();
  const rejections: unknown[] = [];
  const onUnhandled = (reason: unknown) => { rejections.push(reason); };
  process.on("unhandledRejection", onUnhandled);
  try {
    const lookups: AuthorityLookups = {
      get() {
        controller.abort();
        return Promise.reject(new Error("lookup failed after abort"));
      },
      async context() { return []; },
    };
    await assert.rejects(collectAuthority("root", lookups, { signal: controller.signal }), (error) =>
      error instanceof ReviewFailure && error.kind === "cancelled");
    await new Promise((resolve) => { setImmediate(resolve); });
    assert.deepEqual(rejections, []);
  } finally {
    process.off("unhandledRejection", onUnhandled);
  }
});

it("preserves cancellation before cutoff validation or lookups", async () => {
  const controller = new AbortController();
  controller.abort();
  let called = false;
  const lookups: AuthorityLookups = {
    async get() { called = true; return {}; },
    async context() { called = true; return [user("No timestamp.")]; },
  };
  await assert.rejects(
    collectAuthority("root", lookups, { signal: controller.signal, asOf: 1 }),
    (error) => error instanceof ReviewFailure && error.kind === "cancelled",
  );
  assert.equal(called, false);
});
