import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildOperationEvidence, createToolInputStore } from "./operation-evidence.js";
import { isOpaqueOperationLoss, reviewEvidence, reviewRequest, type ReviewerContext } from "./reviewer.js";
import { scoreRequest } from "./score.js";
import { parseOptions } from "./config.js";

const model = ["test-provider", "test-model"].join("/");
const context = (text: ReviewerContext["experimental"]["generate"]["text"]): ReviewerContext => ({ experimental: { generate: { text } } });

describe("operation evidence selection", () => {
  it("prioritizes the grep path over its root fallback and resolves the effective search scope", () => {
    const evidence = buildOperationEvidence({
      action: "grep", resources: ["needle"], metadata: { pattern: "needle", root: ".", path: "src" },
    }, { projectDir: "/repo" });
    assert.equal(evidence.tool, "grep");
    assert.equal(evidence.access, "read");
    assert.equal(evidence.complete, true);
    assert.deepEqual(evidence.targets, ["/repo/src"]);
    assert.deepEqual(evidence.arguments, { pattern: "needle", path: "src", root: "." });
  });

  it("uses the root only when path is absent", () => {
    const evidence = buildOperationEvidence({
      action: "glob", resources: ["*.ts"], metadata: { pattern: "*.ts", root: "packages/app" },
    }, { projectDir: "/repo" });
    assert.deepEqual(evidence.targets, ["/repo/packages/app"]);
    assert.deepEqual(evidence.arguments, { pattern: "*.ts", root: "packages/app" });
    assert.equal(evidence.complete, true);
  });

  it("marks a search scope incomplete when neither path nor root is evidence", () => {
    const evidence = buildOperationEvidence({
      action: "grep", resources: ["needle"], metadata: { pattern: "needle" },
    }, { projectDir: "/repo" });
    assert.equal(evidence.complete, false);
    assert.equal(Object.hasOwn(evidence, "targets"), false);
  });

  it("treats literal undefined or null search paths as unavailable scope", () => {
    for (const path of ["undefined", "null", " NULL "]) {
      const evidence = buildOperationEvidence({
        action: "glob", resources: ["*.ts"], metadata: { pattern: "*.ts", path },
      }, { projectDir: "/repo" });
      assert.equal(evidence.complete, false, path);
      assert.equal(Object.hasOwn(evidence, "targets"), false, path);
    }
  });

  it("keeps network tools unknown rather than suggesting read-only egress", () => {
    for (const action of ["webfetch", "websearch", "codesearch"])
      assert.equal(buildOperationEvidence({ action, resources: ["https://example.invalid"] }).access, "unknown", action);
  });
});

describe("operation evidence capabilities", () => {
  it("keeps built-in access exact and never infers capability from an MCP-looking name", () => {
    for (const [action, access] of [["read", "read"], ["glob", "read"], ["edit", "write"], ["shell", "execute"]] as const) {
      assert.equal(buildOperationEvidence({ action, resources: ["target"] }, { projectDir: "/repo" }).access, access);
    }
    for (const action of ["mcp__filesystem__read", "server_write", "mcp_grep"]) {
      const evidence = buildOperationEvidence({ action, resources: ["target"], metadata: { input: { path: "target" } } });
      assert.equal(evidence.access, "unknown", action);
      assert.equal(evidence.complete, true, action);
    }
  });

  it("preserves literal MCP arguments and keeps unknown access complete", () => {
    const argumentsValue = { query: "literal search", limit: 5, nested: { flag: true }, items: ["a", "b"] };
    const evidence = buildOperationEvidence({ action: "mcp__search", resources: ["literal search"], metadata: { input: argumentsValue } });
    assert.equal(evidence.tool, "mcp__search");
    assert.equal(evidence.access, "unknown");
    assert.equal(evidence.complete, true);
    assert.deepEqual(evidence.arguments, argumentsValue);
    assert.equal(Object.hasOwn(evidence, "targets"), false);
  });

  it("uses only selected shell workdir as a target, never command-path guesses", () => {
    const evidence = buildOperationEvidence({ action: "shell", resources: ["make"] },
      { projectDir: "/repo", capture: { tool: "shell", arguments: { command: "make -C /outside", workdir: "sub" }, complete: true } });
    assert.deepEqual(evidence.targets, ["/repo/sub"]);
    assert.deepEqual(evidence.arguments, { command: "make -C /outside", workdir: "sub" });
    assert.equal(evidence.complete, true);
  });

  it("never treats network query resources as filesystem operation targets", () => {
    const operation = buildOperationEvidence({ action: "websearch", resources: [".env"], metadata: { query: ".env" } });
    assert.equal(Object.hasOwn(operation, "targets"), false);
    assert.equal(operation.arguments?.query, ".env");
    const options = parseOptions({ classifiers: [{ type: "static" }] });
    assert.equal(scoreRequest({ action: "websearch", resources: [".env"], operation }, options).deny, undefined);
  });

  it("marks unknown tools without argument evidence incomplete", () => {
    const evidence = buildOperationEvidence({ action: "mcp__opaque", resources: ["opaque"] });
    assert.equal(evidence.access, "unknown");
    assert.equal(evidence.complete, false);
    assert.equal(Object.hasOwn(evidence, "arguments"), false);
  });
});

describe("operation evidence privacy and bounds", () => {
  it("redacts credentials, headers and bodies and marks the operation incomplete", () => {
    const evidence = buildOperationEvidence({
      action: "mcp__fetch", resources: ["https://example.invalid"], metadata: { input: {
        url: "https://example.invalid", path: "kept", headers: { Authorization: "Bearer TOP_SECRET" },
        body: "PRIVATE_BODY", token: "TOKEN_VALUE", nested: { client_secret: "CLIENT_SECRET" },
        document: "PRIVATE_DOCUMENT", text: "PRIVATE_TEXT", file: { path: "PRIVATE_FILE" },
        patch: "PRIVATE_PATCH", patchText: "PRIVATE_PATCH_TEXT", edit: { newString: "PRIVATE_EDIT" },
        oldString: "PRIVATE_OLD", newString: "PRIVATE_NEW", query: "legit search", jql: "project = ABC",
      } },
    });
    const serialized = JSON.stringify(evidence);
    assert.doesNotMatch(serialized, /TOP_SECRET|PRIVATE_BODY|TOKEN_VALUE|CLIENT_SECRET|PRIVATE_DOCUMENT|PRIVATE_TEXT|PRIVATE_FILE|PRIVATE_PATCH|PRIVATE_PATCH_TEXT|PRIVATE_EDIT|PRIVATE_OLD|PRIVATE_NEW/);
    const expected: readonly (readonly [string, unknown])[] = [
      ["url", "https://example.invalid"], ["path", "kept"], ["headers", "[REDACTED]"], ["body", "[REDACTED]"],
      ["document", "[REDACTED]"], ["text", "[REDACTED]"], ["file", "[REDACTED]"], ["patch", "[REDACTED]"],
      ["patchText", "[REDACTED]"], ["oldString", "[REDACTED]"], ["newString", "[REDACTED]"],
      ["edit", "[REDACTED]"], ["query", "legit search"], ["jql", "project = ABC"],
    ];
    for (const [key, value] of expected) assert.equal(evidence.arguments?.[key], value, key);
    assert.equal((evidence.arguments?.nested as Record<string, unknown>).client_secret, "[REDACTED]");
    assert.equal(evidence.complete, false);
  });

  it("screens HTTP bodies inside every retained string, including nested MCP arguments", () => {
    const command = "curl https://example.invalid -d PRIVATE_BODY";
    const evidence = buildOperationEvidence({
      action: "mcp__shellish__run", resources: ["*"],
      metadata: { input: { command, script: command, nested: { deeper: command }, steps: [command] } },
    });
    const serialized = JSON.stringify(evidence);
    assert.doesNotMatch(serialized, /PRIVATE_BODY/);
    assert.match(serialized, /\[REDACTED HTTP BODY AND COMMAND EVIDENCE\]/);
    assert.equal(evidence.complete, false);
  });

  it("redacts recognized credential syntax inside retained strings and marks evidence incomplete", () => {
    const githubToken = `ghp_${"a".repeat(36)}`;
    const leafToken = `sk-${"b".repeat(24)}`;
    const credential = {
      user: "password", query: "QUERY_TOKEN", bearer: "BEARER_VALUE",
      cookie: "COOKIE_VALUE", apiKey: "API_KEY_VALUE", signature: "SIGNATURE_VALUE",
    };
    const evidence = buildOperationEvidence({
      action: "mcp__fetch", resources: ["https://example.invalid"], metadata: { input: {
        url: `https://user:${credential.user}@example.invalid/?token=${credential.query}&next=1`,
        command: `curl -H 'Authorization: Bearer ${credential.bearer}' https://example.invalid/`,
        note: `curl -H 'Cookie: session=${credential.cookie}' -H 'X-Api-Key: ${credential.apiKey}' https://example.invalid/`,
        steps: [`echo ${githubToken}`, `echo ${leafToken}`],
        path: `https://example.invalid/?signature=${credential.signature}`,
      } },
    });
    const serialized = JSON.stringify(evidence);
    assert.doesNotMatch(serialized, /password|QUERY_TOKEN|BEARER_VALUE|COOKIE_VALUE|API_KEY_VALUE|SIGNATURE_VALUE|ghp_|sk-/);
    assert.match(serialized, /\[REDACTED\]/);
    assert.equal(evidence.complete, false);
  });

  it("bounds object keys before reading discarded values", () => {
    let discardedReads = 0;
    const input: Record<string, unknown> = {};
    for (let index = 0; index < 70; index++)
      Object.defineProperty(input, `key${index}`, {
        enumerable: true,
        get: () => {
          if (index >= 64) discardedReads += 1;
          return `value${index}`;
        },
      });
    const evidence = buildOperationEvidence({ action: "mcp__note", resources: ["note"], metadata: { input } });
    assert.equal(evidence.complete, false);
    assert.equal(Object.keys(evidence.arguments ?? {}).length, 64);
    assert.equal(discardedReads, 0);
  });

  it("bounds oversized arguments and reports the loss", () => {
    const evidence = buildOperationEvidence({ action: "mcp__note", resources: ["note"], metadata: { input: { note: "x".repeat(3_000) } } });
    assert.equal(evidence.complete, false);
    assert.equal((evidence.arguments?.note as string).length, 2_048);
  });

  it("marks circular, prototype, non-finite and over-deep arguments incomplete", () => {
    const circular: Record<string, unknown> = { label: "loop" };
    circular.self = circular;
    const prototype = JSON.parse('{"__proto__": "polluted", "safe": "kept"}') as Record<string, unknown>;
    const deep = Array.from({ length: 40 }).reduce<Record<string, unknown>>(
      (inner, _, index) => ({ [`level${index}`]: inner }), { leaf: true });
    for (const input of [circular, prototype, { value: Number.NaN }, deep]) {
      const evidence = buildOperationEvidence({ action: "mcp__note", resources: ["note"], metadata: { input } });
      assert.equal(evidence.complete, false, JSON.stringify(Object.keys(input)));
    }
  });
});

describe("operation payload and capture compatibility", () => {
  it("does not merge incompatible captured tool arguments into a built-in action", () => {
    const store = createToolInputStore();
    store.capture({ sessionID: "s", messageID: "m", id: "c", tool: "shell", input: { command: "rm -rf /outside" } });
    const evidence = buildOperationEvidence({ action: "read", resources: ["safe.txt"] },
      { projectDir: "/repo", capture: store.get({ type: "tool", messageID: "m", id: "c" }, "s") });
    assert.equal(evidence.tool, "read");
    assert.equal(evidence.access, "read");
    assert.equal(evidence.complete, false);
    assert.equal(evidence.arguments, undefined);
  });

  it("marks omitted write payloads incomplete instead of approving from a target alone", () => {
    const store = createToolInputStore();
    store.capture({ sessionID: "s", messageID: "m", id: "c", tool: "write",
      input: { filePath: "safe.txt", content: "#!/bin/sh\nrm -rf /outside" } });
    const evidence = buildOperationEvidence({ action: "edit", resources: ["safe.txt"] },
      { projectDir: "/repo", capture: store.get({ type: "tool", messageID: "m", id: "c" }, "s") });
    assert.equal(evidence.tool, "write");
    assert.equal(evidence.access, "write");
    assert.equal(evidence.complete, false);
    assert.equal(evidence.arguments?.content, undefined);
    assert.deepEqual(evidence.arguments, { filePath: "safe.txt" });
  });

  it("retains shell workdir evidence and marks unresolved home or missing exact targets incomplete", () => {
    const store = createToolInputStore();
    store.capture({ sessionID: "s", messageID: "m", id: "c", tool: "shell",
      input: { command: "rm /outside/file.txt", workdir: "/outside" } });
    const evidence = buildOperationEvidence({ action: "external_directory", resources: ["/outside/*"],
      metadata: { filepath: "/outside/file.txt", parentDir: "/outside" } },
    { capture: store.get({ type: "tool", messageID: "m", id: "c" }, "s") });
    assert.deepEqual(evidence.arguments, { command: "rm /outside/file.txt", workdir: "/outside" });
    assert.equal(evidence.complete, true);
    assert.ok(evidence.targets?.includes("/outside"));

    store.capture({ sessionID: "s", messageID: "m", id: "h", tool: "write", input: { filePath: "~/file.txt" } });
    const home = buildOperationEvidence({ action: "external_directory", resources: ["~/*"],
      metadata: { filepath: "~/file.txt", parentDir: "~" } },
    { projectDir: "/repo", capture: store.get({ type: "tool", messageID: "m", id: "h" }, "s") });
    assert.equal(home.complete, false);
    assert.equal(Object.hasOwn(home, "targets"), false);
  });
});

describe("external_directory correlation", () => {
  it("snapshots the exact execute.before input and correlates only the exact call identity", () => {
    const store = createToolInputStore();
    const input = { filePath: "/outside/secret.txt", content: "LIVE_CONTENT" };
    store.capture({ sessionID: "session", messageID: "message", id: "call", tool: "write", input });
    input.filePath = "/mutated/after-capture.txt";
    const capture = store.get({ type: "tool", messageID: "message", id: "call" }, "session");
    assert.equal(capture?.tool, "write");
    assert.deepEqual(capture?.arguments, { filePath: "/outside/secret.txt" });
    const evidence = buildOperationEvidence({
      action: "external_directory", resources: ["/outside/*"], metadata: { filepath: "/outside/secret.txt", parentDir: "/outside" },
    }, { projectDir: "/repo", capture });
    assert.equal(evidence.tool, "write");
    assert.equal(evidence.access, "write");
    assert.deepEqual(evidence.arguments, { filePath: "/outside/secret.txt" });
    assert.deepEqual(evidence.targets, ["/outside/secret.txt", "/outside"]);
    // The omitted write payload keeps the evidence incomplete without dropping
    // its verified targets, so the loss stays non-terminal.
    assert.equal(evidence.complete, false);
    assert.equal(isOpaqueOperationLoss({
      action: "external_directory", resources: ["/outside/*"], operation: evidence,
    }), false);
    assert.equal(store.get({ type: "tool", messageID: "message", id: "other" }, "session"), undefined);
    assert.equal(store.get({ type: "tool", messageID: "message", id: "call" }, "other-session"), undefined);
  });

  it("never claims an exact target without a correlated call and keeps unknown access complete", () => {
    const store = createToolInputStore();
    const missing = buildOperationEvidence({ action: "external_directory", resources: ["/outside/*"],
      metadata: { filepath: "/outside/file.txt", parentDir: "/outside" } });
    assert.equal(missing.tool, undefined);
    assert.equal(missing.access, "unknown");
    assert.equal(missing.complete, false);
    assert.equal(Object.hasOwn(missing, "targets"), false);
    assert.doesNotMatch(JSON.stringify(missing), /glob|wildcard match/);

    store.capture({ sessionID: "s", messageID: "m", id: "c", tool: "mcp__filesystem__write", input: { path: "/outside/file.txt" } });
    const unknown = buildOperationEvidence({ action: "external_directory", resources: ["/outside/*"],
      metadata: { filepath: "/outside/file.txt", parentDir: "/outside" } }, { capture: store.get({ type: "tool", messageID: "m", id: "c" }, "s") });
    assert.equal(unknown.tool, "mcp__filesystem__write");
    assert.equal(unknown.access, "unknown");
    assert.equal(unknown.complete, true);
    assert.deepEqual(unknown.targets, ["/outside/file.txt", "/outside"]);
  });
});

describe("external target verification", () => {
  it("marks external targets incomplete when captured and metadata paths disagree", () => {
    const store = createToolInputStore();
    store.capture({ sessionID: "s", messageID: "m", id: "c", tool: "read", input: { filePath: "/outside/actual.txt" } });
    const evidence = buildOperationEvidence({ action: "external_directory", resources: ["/outside/*"],
      metadata: { filepath: "/outside/other.txt", parentDir: "/outside" } },
    { capture: store.get({ type: "tool", messageID: "m", id: "c" }, "s") });
    assert.equal(evidence.tool, "read");
    assert.equal(evidence.complete, false);
    assert.equal(Object.hasOwn(evidence, "targets"), false);
  });

  it("rejects an exact target outside the permission root and leaves raw external shapes incomplete", () => {
    const store = createToolInputStore();
    store.capture({ sessionID: "s", messageID: "m", id: "c", tool: "write", input: { filePath: "/elsewhere/file.txt" } });
    const outside = buildOperationEvidence({ action: "external_directory", resources: ["/outside/*"],
      metadata: { filepath: "/elsewhere/file.txt", parentDir: "/elsewhere" } },
    { capture: store.get({ type: "tool", messageID: "m", id: "c" }, "s") });
    assert.equal(outside.complete, false);
    assert.equal(Object.hasOwn(outside, "targets"), false);

    const raw = buildOperationEvidence({ action: "external_directory", resources: ["/outside/*"] });
    assert.equal(raw.complete, false);
    assert.equal(raw.access, "unknown");
    assert.equal(Object.hasOwn(raw, "targets"), false);
  });

  it("ignores arbitrary target identifiers when extracting external filesystem targets", () => {
    const store = createToolInputStore();
    store.capture({ sessionID: "s", messageID: "m", id: "c", tool: "mcp__filesystem__write",
      input: { path: "/outside/safe", target: ".env" } });
    const evidence = buildOperationEvidence({ action: "external_directory", resources: ["/outside/*"],
      metadata: { filepath: "/outside/safe", parentDir: "/outside" } },
    { capture: store.get({ type: "tool", messageID: "m", id: "c" }, "s") });
    assert.deepEqual(evidence.targets, ["/outside/safe", "/outside"]);
    assert.equal(evidence.arguments?.target, ".env");
  });
});

describe("tool input capture lifecycle", () => {
  it("marks duplicate active captures for the same call identity incomplete instead of last-writer", () => {
    const store = createToolInputStore();
    const source = { type: "tool", messageID: "m", id: "c" };
    store.capture({ sessionID: "s", messageID: "m", id: "c", tool: "write", input: { filePath: "/outside/one.txt" } });
    store.capture({ sessionID: "s", messageID: "m", id: "c", tool: "write", input: { filePath: "/outside/two.txt" } });
    assert.equal(store.get(source, "s")?.complete, false);
    assert.deepEqual(store.get(source, "s")?.arguments, {});
  });

  it("keeps ambiguity sticky until every active capture for the same identity releases", () => {
    const store = createToolInputStore();
    const source = { type: "tool", messageID: "m", id: "c" };
    const capture = (tool: string) => store.capture({ sessionID: "s", messageID: "m", id: "c", tool, input: { filePath: "/outside/file.txt" } });
    capture("read");
    capture("write");
    store.release({ sessionID: "s", messageID: "m", id: "c" });
    assert.equal(store.get(source, "s")?.complete, false);
    capture("grep");
    store.release({ sessionID: "s", messageID: "m", id: "c" });
    assert.equal(store.get(source, "s")?.complete, false);
    store.release({ sessionID: "s", messageID: "m", id: "c" });
    assert.equal(store.get(source, "s"), undefined);
    capture("read");
    assert.equal(store.get(source, "s")?.complete, true);
  });

  it("does not let an outer execute capture shadow a same-identity inner tool", () => {
    const store = createToolInputStore();
    const source = { type: "tool", messageID: "m", id: "c" };
    store.capture({ sessionID: "s", messageID: "m", id: "c", tool: "execute", input: "return 1;" });
    assert.equal(store.get(source, "s"), undefined);
    store.capture({ sessionID: "s", messageID: "m", id: "c", tool: "read", input: { filePath: "/outside/file.txt" } });
    assert.equal(store.get(source, "s")?.tool, "read");
    assert.equal(store.get(source, "s")?.complete, true);
  });
});

describe("tool input release and bounds", () => {
  it("releases captures on after, source rejection and cleanup", () => {
    const store = createToolInputStore();
    const source = { type: "tool", messageID: "m", id: "c" };
    const capture = (id: string) => store.capture({ sessionID: "s", messageID: "m", id, tool: "read", input: { filePath: "/x" } });
    capture("c");
    assert.notEqual(store.get(source, "s"), undefined);
    store.releaseSource(source, "s");
    assert.equal(store.get(source, "s"), undefined);
    capture("two");
    assert.notEqual(store.get({ type: "tool", messageID: "m", id: "two" }, "s"), undefined);
    store.release({ sessionID: "s", messageID: "m", id: "two" });
    assert.equal(store.get({ type: "tool", messageID: "m", id: "two" }, "s"), undefined);
    capture("three");
    assert.notEqual(store.get({ type: "tool", messageID: "m", id: "three" }, "s"), undefined);
    store.clear();
    assert.equal(store.get({ type: "tool", messageID: "m", id: "three" }, "s"), undefined);
  });

  it("bounds retained captures without stale cross-call binding", () => {
    const store = createToolInputStore(2);
    for (const id of ["one", "two", "three"])
      store.capture({ sessionID: "s", messageID: "m", id, tool: "read", input: { filePath: `/${id}` } });
    assert.equal(store.get({ type: "tool", messageID: "m", id: "one" }, "s"), undefined);
    assert.equal(store.get({ type: "tool", messageID: "m", id: "two" }, "s")?.arguments.filePath, "/two");
    assert.equal(store.get({ type: "tool", messageID: "m", id: "three" }, "s")?.arguments.filePath, "/three");
  });

  it("falls back to the hard capture bound when maxEntries is not finite", () => {
    const store = createToolInputStore(Number.NaN);
    for (let index = 0; index < 65; index++)
      store.capture({ sessionID: "s", messageID: "m", id: `call-${index}`, tool: "read", input: { filePath: `/${index}` } });
    assert.equal(store.get({ type: "tool", messageID: "m", id: "call-0" }, "s"), undefined);
    assert.equal(store.get({ type: "tool", messageID: "m", id: "call-64" }, "s")?.arguments.filePath, "/64");
  });
});

describe("opaque operation loss", () => {
  it("is terminal only for incomplete wildcard or external-without-target evidence", () => {
    assert.equal(isOpaqueOperationLoss({ action: "shell", resources: ["pwd"], operation: { access: "execute", complete: false } }), false);
    assert.equal(isOpaqueOperationLoss({ action: "read", resources: ["file.txt"], operation: { access: "read", complete: false } }), false);
    assert.equal(isOpaqueOperationLoss({ action: "mcp__tool", resources: ["literal"], operation: { access: "unknown", complete: true } }), false);
    assert.equal(isOpaqueOperationLoss({ action: "mcp__tool", resources: ["*"], operation: { access: "unknown", complete: true } }), false);
    assert.equal(isOpaqueOperationLoss({ action: "mcp__tool", resources: ["*"], operation: { access: "unknown", complete: false } }), true);
    assert.equal(isOpaqueOperationLoss({ action: "external_directory", resources: ["/outside/*"], operation: { access: "write", complete: false } }), true);
    assert.equal(isOpaqueOperationLoss({ action: "external_directory", resources: ["/outside/*"] }), true);
    assert.equal(isOpaqueOperationLoss({ action: "external_directory", resources: ["/outside/*"],
      operation: { access: "unknown", complete: true } }), true);
    assert.equal(isOpaqueOperationLoss({ action: "external_directory", resources: ["/outside/*"],
      operation: { access: "write", complete: false, targets: ["/outside/file.txt"] } }), false);
    assert.equal(isOpaqueOperationLoss({ action: "external_directory", resources: ["/outside/*"],
      operation: { access: "unknown", complete: true, targets: ["/outside/file.txt"] } }), false);
    assert.equal(isOpaqueOperationLoss({ action: "unknown", resources: ["*"] }), false);
  });

  it("refuses to call the LLM for an opaque incomplete operation", async () => {
    let calls = 0;
    const ctx = context(async () => { calls++; return { text: "ALLOW: opaque" }; });
    const wildcard = await reviewRequest(ctx, { action: "mcp__opaque", resources: ["*"], operation: { access: "unknown", complete: false } },
      model, new AbortController().signal, 100);
    assert.equal(wildcard.decision, "ask");
    assert.equal(wildcard.terminal, true);
    const external = await reviewRequest(ctx, { action: "external_directory", resources: ["/outside/*"],
      operation: { access: "unknown", complete: false } }, model, new AbortController().signal, 100);
    assert.equal(external.decision, "ask");
    assert.equal(external.terminal, true);
    const externalAbsent = await reviewRequest(ctx, { action: "external_directory", resources: ["/outside/*"] },
      model, new AbortController().signal, 100);
    assert.equal(externalAbsent.decision, "ask");
    assert.equal(externalAbsent.terminal, true);
    assert.equal(calls, 0);
  });

  it("still model-reviews complete unknown wildcard evidence as uncertainty", async () => {
    let calls = 0;
    const ctx = context(async () => { calls++; return { text: "HUMAN_REVIEW: unknown capability" }; });
    const result = await reviewRequest(ctx, {
      action: "mcp__opaque", resources: ["*"], operation: { access: "unknown", complete: true, arguments: { query: "literal" } },
    }, model, new AbortController().signal, 100);
    assert.equal(result.decision, "abstain");
    assert.equal(result.terminal, undefined);
    assert.equal(calls, 1);
  });
});

describe("operation evidence in review prompts", () => {
  it("exposes bounded operation evidence and marks incomplete selected evidence", () => {
    const complete = reviewEvidence({ action: "grep", resources: ["needle"],
      operation: { tool: "grep", access: "read", targets: ["/repo/src"], arguments: { pattern: "needle", path: "src" }, complete: true } });
    assert.equal("incompleteEvidence" in complete, false);
    assert.deepEqual(complete.operation?.targets, ["/repo/src"]);

    const incomplete = reviewEvidence({ action: "mcp__fetch", resources: ["url"],
      operation: { access: "unknown", complete: false, arguments: { headers: "[REDACTED]" } } });
    assert.match(incomplete.incompleteEvidence!, /Operation evidence is incomplete/);
    assert.equal(incomplete.operation?.complete, false);
  });

  it("keeps the LLM fallback for incomplete operation evidence without leaking omitted secrets", async () => {
    let seen = "";
    const ctx = context(async ({ prompt }) => { seen = prompt; return { text: "ALLOW: authorized literal target" }; });
    const result = await reviewRequest(ctx, {
      action: "mcp__fetch", resources: ["https://example.invalid"], transcript: "Fetch the literal target",
      operation: { access: "unknown", complete: false, arguments: { url: "https://example.invalid", headers: "[REDACTED]" } },
    }, model, new AbortController().signal, 100);
    assert.equal(result.decision, "allow");
    assert.match(seen, /incompleteEvidence/);
    assert.match(seen, /"url":"https:\/\/example.invalid"/);
    assert.doesNotMatch(seen, /SECRET|PRIVATE_BODY/);
  });
});

describe("symlink-sensitive and network target spellings", () => {
  it("resolves a symlink followed by dot-dot physically instead of collapsing it lexically", () => {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "auto-mode-target-traversal-")));
    const home = join(root, "home");
    mkdirSync(home);
    const previous = process.env.HOME;
    process.env.HOME = home;
    try {
      mkdirSync(join(home, ".aws"));
      mkdirSync(join(root, "child"));
      writeFileSync(join(root, "child", "credentials"), "fixture");
      symlinkSync(join(root, "child"), join(home, ".aws", "alias"));
      // `.aws/alias/..` selects the external parent, not `.aws`. Lexical
      // collapsing would assert the credential store and force a false deny.
      const path = `${home}/.aws/alias/../credentials`; // Deliberately not join: it removes `..`.
      const evidence = buildOperationEvidence({ action: "grep", resources: ["needle"],
        metadata: { pattern: "needle", path } }, { projectDir: root });
      assert.deepEqual(evidence.targets, [join(root, "credentials")]);
      assert.equal(evidence.complete, true);
      const options = parseOptions({ classifiers: [{ type: "static" }] });
      const score = scoreRequest({ action: "grep", resources: ["needle"], projectDir: root, operation: evidence }, options);
      assert.equal(score.deny, undefined);
      assert.equal(score.band, "high");
    } finally {
      if (previous === undefined) delete process.env.HOME; else process.env.HOME = previous;
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("keeps the raw spelling and marks an unresolvable traversal incomplete", () => {
    const evidence = buildOperationEvidence({ action: "grep", resources: ["needle"],
      metadata: { pattern: "needle", path: "missing/../needle.ts" } }, { projectDir: "/repo" });
    assert.equal(evidence.complete, false);
    assert.deepEqual(evidence.targets, ["missing/../needle.ts"]);
  });

  it("keeps URL spellings as network arguments instead of filesystem targets", () => {
    const options = parseOptions({ classifiers: [{ type: "static" }] });
    for (const path of ["https://example.invalid/.env", "HTTPS://example.invalid/.env", "//example.invalid/.env"]) {
      const evidence = buildOperationEvidence({ action: "grep", resources: ["needle"],
        metadata: { pattern: "needle", path } }, { projectDir: "/repo" });
      assert.deepEqual(evidence.targets, [path], path);
      const score = scoreRequest({ action: "grep", resources: ["needle"], projectDir: "/repo", operation: evidence }, options);
      assert.equal(score.deny, undefined, path);
      assert.equal(score.band, "high", path);
    }
  });
});
