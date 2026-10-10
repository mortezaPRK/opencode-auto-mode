import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { once } from "node:events";
import { randomUUID } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { AutoModeOptions, ClassifierStage } from "../src/config.js";

type Verdict = "allow" | "deny" | "ask";
type Mode = Verdict | "abstain" | "malformed" | "failure" | "timeout";
type Profile = { modes?: Record<string, Mode>; triage?: string; verdict?: string; tool?: string };
const plugin = resolve(process.env.OPENCODE_PLUGIN_PATH ?? fileURLToPath(new URL("..", import.meta.url)));
const binary = process.env.OPENCODE_BINARY ?? "opencode";
const root = mkdtempSync(join(tmpdir(), "auto-mode-opencode-"));
const calls: string[] = [];
const results: { name: string; checks: number }[] = [];
let profile: Profile = {};
let checks = 0;
let caseCount = 0;
for (const dir of ["config/opencode", "data", "cache", "state", "tmp"])
  mkdirSync(join(root, dir), { recursive: true });
symlinkSync(join(plugin, "node_modules"), join(root, "node_modules"), "dir");
const transport = join(root, "transport");
mkdirSync(transport);
writeFileSync(join(transport, "index.ts"), readFileSync(new URL("./transport.ts", import.meta.url)));

function completion(content: string, stream: boolean, tool?: string) {
  const message = tool ? { role: "assistant", tool_calls: [{ id: "call_local_test", type: "function", function: {
    name: "shell", arguments: JSON.stringify({ command: tool, description: "Local integration marker" }),
  } }] } : { role: "assistant", content };
  const base = { id: "chatcmpl-local-test", object: "chat.completion", created: 1, model: "reviewer" };
  if (!stream) return { body: JSON.stringify({ ...base, choices: [{ index: 0, message, finish_reason: tool ? "tool_calls" : "stop" }] }), type: "application/json" };
  const delta = tool ? { tool_calls: message.tool_calls?.map((call, index) => ({ ...call, index })) } : { role: "assistant", content };
  return { type: "text/event-stream", body: [
    { ...base, object: "chat.completion.chunk", choices: [{ index: 0, delta, finish_reason: null }] },
    { ...base, object: "chat.completion.chunk", choices: [{ index: 0, delta: {}, finish_reason: tool ? "tool_calls" : "stop" }] },
  ].map((chunk) => `data: ${JSON.stringify(chunk)}\n\n`).join("") + "data: [DONE]\n\n" };
}

const provider = createServer(async (req, res) => {
  try {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(Buffer.from(chunk));
    const body = JSON.parse(Buffer.concat(chunks).toString());
    const route = req.url!.split("/").at(-1)!;
    if (route === "completions") {
      const prompt = JSON.stringify(body.messages);
      let content = "Ready";
      if (prompt.includes("STAGE 1 TRIAGE")) { calls.push("llm:triage"); content = profile.triage ?? "ALLOW"; }
      else if (prompt.includes("RESPONSE FORMAT")) { calls.push("llm:verdict"); content = profile.verdict ?? "ALLOW: authorized"; }
      const tool = body.tools?.some((t: { function: { name: string } }) => t.function.name === "shell") &&
        !body.messages.some((m: { role: string }) => m.role === "tool") ? profile.tool : undefined;
      const output = completion(content, body.stream === true, tool);
      res.writeHead(200, { "content-type": output.type }); res.end(output.body); return;
    }
    const type = route === "systemone" ? "laya" : route;
    calls.push(type);
    assert.equal(req.headers.authorization, type === "laya" ? undefined : "Bearer local-test-key");
    assert.ok(type === "openai-decision" ? body.questions[0].name === "permission" && body.input : body.questions.permission && body.state);
    const mode = profile.modes?.[type] ?? "abstain";
    if (mode === "timeout") { res.writeHead(200, { "content-type": "application/json" }); res.write("{"); return; }
    if (mode === "failure") { res.writeHead(503); res.end("unavailable"); return; }
    if (mode === "malformed") { res.end(JSON.stringify({ answers: {} })); return; }
    const choice = mode === "abstain" ? "allow" : mode;
    const probabilities = mode === "abstain" ? { allow: 0.4, deny: 0.3, ask: 0.3 } :
      Object.fromEntries(["allow", "deny", "ask"].map((value) => [value, value === choice ? 0.98 : 0.01]));
    const answer = { type: "choice", choice, confidence: mode === "abstain" ? 0.1 : 0.98, probabilities };
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(type === "openai-decision" ? { answers: [{ ...answer, name: "permission",
      probabilities: Object.entries(probabilities).map(([value, probability]) => ({ value, probability })) }] } :
      { answers: { permission: answer } }));
  } catch (error) { res.writeHead(500); res.end(String(error)); }
});
provider.listen(0, "127.0.0.1");
await once(provider, "listening");
const providerAddress = provider.address();
assert.ok(providerAddress && typeof providerAddress !== "string");
const endpoint = `http://127.0.0.1:${providerAddress.port}`;
const globalConfig = {
  update: "disable", share: "disabled", model: "local/reviewer", default_agent: "auto",
  providers: { local: { package: "@ai-sdk/openai-compatible", settings: { baseURL: `${endpoint}/v1`, apiKey: "local-test" }, models: { reviewer: { name: "Local integration model" } } } },
  agents: { auto: { mode: "primary", description: "Automatic review" } },
};
writeFileSync(join(root, "config/opencode/opencode.json"), JSON.stringify(globalConfig));
const portServer = createServer(); portServer.listen(0, "127.0.0.1"); await once(portServer, "listening");
const address = portServer.address(); assert.ok(address && typeof address !== "string");
const port = address.port; await new Promise<void>((done) => portServer.close(() => done()));
const password = randomUUID();
const hostEnv = { ...process.env, OPENCODE_SERVER_PASSWORD: password, OPENCODE_DISABLE_MODELS_FETCH: "true",
  OPENCODE_AUTO_MODE_TEST_ENDPOINT: endpoint, AUTO_MODE_INTEGRATION_API_KEY: "local-test-key",
  OPENCODE_DISABLE_PROJECT_CONFIG: "false", OPENCODE_DISABLE_LOCAL_CONFIG: "false",
  XDG_CONFIG_HOME: join(root, "config"), XDG_DATA_HOME: join(root, "data"), XDG_CACHE_HOME: join(root, "cache"),
  XDG_STATE_HOME: join(root, "state"), TMPDIR: join(root, "tmp") };
for (const key of ["OPENCODE_CONFIG", "OPENCODE_CONFIG_CONTENT", "OPENCODE_CONFIG_DIR", "OPENCODE_SIMULATE", "OPENCODE_DRIVE"])
  delete (hostEnv as Record<string, string | undefined>)[key];
const host = spawn(binary, ["serve", "--hostname", "127.0.0.1", "--port", String(port), "--print-logs", "--log-level", "warn"], {
  cwd: root, env: hostEnv,
  stdio: ["ignore", "pipe", "pipe"],
});
let logs = "";
host.stdout.on("data", (chunk) => { logs += chunk.toString(); });
host.stderr.on("data", (chunk) => { logs += chunk.toString(); });
host.on("error", (error) => { logs += String(error); });
const delay = (ms: number) => new Promise((done) => setTimeout(done, ms));
const base = `http://127.0.0.1:${port}`;
async function api(path: string, body?: unknown) {
  const response = await fetch(`${base}${path}`, {
    method: body === undefined ? "GET" : "POST", signal: AbortSignal.timeout(15_000),
    headers: { authorization: `Basic ${Buffer.from(`opencode:${password}`).toString("base64")}`, "content-type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  if (!response.ok) throw new Error(`${path}: ${response.status} ${await response.text()}`);
  return response.status === 204 ? undefined : response.json();
}
async function until<T>(get: () => Promise<T>, ready: (value: T) => boolean) {
  const deadline = Date.now() + 20_000;
  let last: unknown;
  while (Date.now() < deadline) {
    try { const value = await get(); if (ready(value)) return value; } catch (error) { last = error; }
    if (host.exitCode !== null) throw new Error(`OpenCode exited: ${logs.slice(-3000)}`);
    await delay(50);
  }
  throw new Error(`OpenCode readiness timed out: ${String(last)} ${logs.slice(-2000)}`);
}
function stage(type: string): ClassifierStage {
  if (type === "rules") return { type, rules: [
    { expression: 'action == "shell" && resource == "pwd"', decision: "allow" },
    { expression: 'action == "shell" && resource == "touch denied-file"', decision: "deny" },
  ] };
  if (type === "laya") return { type, endpoint: `${endpoint}/v1/systemone`, timeoutMs: 100 };
  if (type === "jev" || type === "openai-decision") return { type, apiKeyEnv: "AUTO_MODE_INTEGRATION_API_KEY", timeoutMs: 100 };
  return { type } as ClassifierStage;
}
async function fixture(options: AutoModeOptions = {}, permissions: unknown[] = [{ action: "*", resource: "*", effect: "ask" }]) {
  const directory = join(root, `case-${++caseCount}`); mkdirSync(directory);
  writeFileSync(join(directory, "opencode.json"), JSON.stringify({
    permissions,
    plugins: [{ package: transport }, { package: plugin, options: { agents: ["auto"], ...options } }],
  }));
  const query = `?location%5Bdirectory%5D=${encodeURIComponent(directory)}`;
  await until(() => api(`/api/plugin${query}`), (value) => ["opencode-auto-mode", "auto-mode-integration-transport"].every((id) =>
    value.data.some((p: { id: string; state: { status: string } }) => p.id === id && p.state.status === "active")));
  const loaded = (await api(`/api/plugin${query}`)).data.find((p: { id: string }) => p.id === "opencode-auto-mode");
  assert.equal(loaded.features.server, true);
  assert.equal(loaded.features.tui, true);
  const agents = (await api(`/api/agent${query}`)).data;
  for (const id of ["auto", "build", "plan"]) assert.ok(agents.some((agent: { id: string; mode: string }) => agent.id === id && agent.mode === "primary"), `missing ${id}`);
  const session = (await api("/api/session", { agent: "auto", title: "Local integration test", location: { directory }, model: { id: "reviewer", providerID: "local" } })).data;
  await api(`/api/session/${session.id}/prompt`, { text: "Create sample.txt in this project; do not change permissions or affect other directories." });
  await api(`/api/experimental/session/${session.id}/wait`, {});
  const context = (await api(`/api/session/${session.id}/context`)).data;
  assert.ok(context.some((entry: { type: string }) => entry.type === "user"));
  return { directory, sessionID: session.id, query };
}
async function expectPermission(f: Awaited<ReturnType<typeof fixture>>, expected: Verdict, resources = ["touch sample.txt"], agent = "auto", action = "shell") {
  const response = (await api(`/api/session/${f.sessionID}/permission`, { action, resources, agent, metadata: { integration: "pending-input" } })).data;
  assert.equal(response.effect, expected);
  const pending = (await api(`/api/session/${f.sessionID}/permission`)).data;
  assert.equal(pending.some((p: { id: string }) => p.id === response.id), expected === "ask");
  if (expected === "ask") {
    await api(`/api/session/${f.sessionID}/permission/${response.id}/reply`, { decision: "reject" });
    assert.equal((await api(`/api/session/${f.sessionID}/permission`)).data.length, 0);
  }
  checks++;
  return response;
}
async function run(name: string, test: () => Promise<void>) {
  const before = checks;
  profile = {}; calls.length = 0;
  await test();
  results.push({ name, checks: checks - before });
  console.log(`PASS ${name.replace(/\s+/g, " ")} (${checks - before})`);
}

try {
  const info = await until(() => api("/api/info"), (value) => value.version.startsWith("2."));
  console.log(`OpenCode ${info.version}; artifacts ${root}`);
  const types = ["static", "rules", "jev", "openai-decision", "laya", "llm"];
  const combinations = new Map<string, string[]>();
  for (let mask = 1; mask < 64; mask++) {
    const selected = types.filter((_, index) => mask & (1 << index));
    combinations.set(selected.join("+"), selected);
  }
  for (const first of types) for (const second of types)
    if (first !== second) combinations.set(`${first}+${second}`, [first, second]);
  for (const [name, selected] of combinations) await run(name, async () => {
    const f = await fixture({ classifier: { stages: selected.map(stage) } });
    calls.length = 0;
    await expectPermission(f, selected.includes("llm") ? "allow" : "ask");
    const reached = selected.slice(0, selected.includes("llm") ? selected.indexOf("llm") + 1 : undefined)
      .filter((type) => type !== "static" && type !== "rules").map((type) => type === "llm" ? "llm:triage" : type);
    assert.deepEqual(calls, reached, `${name} cascade`);
    calls.length = 0;
    await expectPermission(f, selected.some((type) => ["static", "rules", "llm"].includes(type)) ? "allow" : "ask", ["pwd"]);
    if (selected.includes("rules")) { calls.length = 0; await expectPermission(f, "deny", ["touch denied-file"]); assert.deepEqual(calls, []); }
    if (selected.includes("static")) { calls.length = 0; await expectPermission(f, "deny", ["sudo rm -rf /"]); assert.deepEqual(calls, []); }
  });
  for (const type of ["jev", "openai-decision", "laya"]) {
    for (const mode of ["allow", "deny", "ask", "malformed", "failure", "timeout"] as Mode[]) await run(`${type}:${mode}`, async () => {
      const f = await fixture({ classifier: { stages: [stage(type), stage("llm")] } });
      profile = { modes: { [type]: mode } }; calls.length = 0;
      await expectPermission(f, mode === "allow" || mode === "deny" ? mode : "ask");
      assert.deepEqual(calls, [type]);
    });
  }
  for (const verdict of ["ALLOW: authorized", "DENY: out of scope", "ASK: uncertain", "allowance unavailable", "ALLOW: yes\nDENY: no"]) await run(`llm:${verdict}`, async () => {
    const f = await fixture({ classifier: { stages: [stage("llm")] } });
    profile = { triage: "BLOCK", verdict }; calls.length = 0;
    await expectPermission(f, verdict.startsWith("ALLOW:") && !verdict.includes("\n") ? "allow" : verdict.startsWith("DENY:") ? "deny" : "ask");
    assert.deepEqual(calls, ["llm:triage", "llm:verdict"]);
  });
  await run("default model and default pipeline", async () => {
    const f = await fixture(); calls.length = 0;
    await expectPermission(f, "allow"); assert.deepEqual(calls, ["llm:triage"]);
  });
  await run("host deny and agent scoping", async () => {
    const f = await fixture({ classifier: { stages: [stage("llm")] } }, [
      { action: "*", resource: "*", effect: "ask" }, { action: "shell", resource: "blocked", effect: "deny" },
    ]);
    calls.length = 0; await expectPermission(f, "deny", ["blocked"]); assert.deepEqual(calls, []);
    for (const agent of ["build", "plan"]) { await expectPermission(f, "ask", ["touch sample.txt"], agent); assert.deepEqual(calls, []); }
  });
  await run("invalid configuration", async () => {
    const f = await fixture({ classifier: { stages: [{ type: "invalid" }] } } as unknown as AutoModeOptions);
    calls.length = 0; await expectPermission(f, "ask", ["pwd"]); assert.deepEqual(calls, []);
  });
  await run("all-resource rules and static file boundaries", async () => {
    const f = await fixture({ classifier: { stages: [stage("static"), stage("rules")] } });
    await expectPermission(f, "ask", ["pwd", "touch sample.txt"]);
    await expectPermission(f, "deny", ["pwd", "sudo rm -rf /"]);
    writeFileSync(join(f.directory, "sample.txt"), "sample");
    await expectPermission(f, "allow", ["sample.txt"], "auto", "read");
    await expectPermission(f, "ask", [".env"], "auto", "read");
    await expectPermission(f, "ask", ["sample.txt"], "auto", "edit");
  });
  await run("prompt-only scope and missing credentials", async () => {
    const f = await fixture({ review: "prompts", classifier: { stages: [stage("llm")] } }, [{ action: "*", resource: "*", effect: "allow" }]);
    calls.length = 0; await expectPermission(f, "allow"); assert.deepEqual(calls, []);
    const missing = await fixture({ classifier: { stages: [{ type: "jev", apiKeyEnv: "AUTO_MODE_MISSING_TEST_KEY" }, stage("llm")] } });
    calls.length = 0; await expectPermission(missing, "ask"); assert.deepEqual(calls, []);
  });
  await run("CEL coverage, errors, limits, and ask precedence", async () => {
    const covered = await fixture({ classifier: { stages: [{ type: "rules", rules: [
      { expression: 'resource == "touch a"', decision: "allow" },
      { expression: 'resource == "touch b"', decision: "allow" },
    ] }] } });
    await expectPermission(covered, "allow", ["touch a", "touch b"]);
    await expectPermission(covered, "ask", ["touch a", "touch c"]);
    for (const expression of ['resource', 'unknown == "pwd"', 'action ==', '[1].all(x, x > 0)']) {
      const f = await fixture({ classifier: { stages: [{ type: "rules", rules: [{ expression, decision: "allow" }] }, stage("static"), stage("llm")] } });
      calls.length = 0; await expectPermission(f, "ask", ["pwd"]); assert.deepEqual(calls, []);
    }
    const bounded = await fixture({ classifier: { stages: [{ type: "rules", rules: [{ expression: "true", decision: "allow" }] }, stage("llm")] } });
    calls.length = 0; await expectPermission(bounded, "ask", ["x".repeat(4097)]); assert.deepEqual(calls, []);
    const escalated = await fixture({ classifier: { stages: [stage("llm"), { type: "rules", rules: [{ expression: 'action == "shell"', decision: "ask" }] }] } });
    calls.length = 0; await expectPermission(escalated, "ask"); assert.deepEqual(calls, []);
    const denied = await fixture({ classifier: { stages: [{ type: "rules", rules: [
      { expression: "resource", decision: "allow" },
      { expression: 'resource == "pwd"', decision: "deny" },
    ] }, stage("llm")] } });
    calls.length = 0; await expectPermission(denied, "deny", ["pwd"]); assert.deepEqual(calls, []);
  });
  const toolCases: { name: string; stages: ClassifierStage[]; expected: Verdict; profile: Profile; command?: string; reached?: string[] }[] = [
    { name: "static read-only", stages: [stage("static")], expected: "allow", profile: {}, command: "pwd" },
    { name: "user allow", stages: [{ type: "rules", rules: [{ expression: 'action == "shell"', decision: "allow" }] }], expected: "allow", profile: {} },
    { name: "user deny", stages: [{ type: "rules", rules: [{ expression: 'action == "shell"', decision: "deny" }] }], expected: "deny", profile: {} },
    { name: "CEL predicate", stages: [{ type: "rules", rules: [{ expression: 'agent == "auto" && action == "shell" && resource == "printf integration > tool-result.txt"', decision: "allow" }] }], expected: "allow", profile: {} },
    { name: "CEL invalid result", stages: [{ type: "rules", rules: [{ expression: "resource", decision: "allow" }] }, stage("llm")], expected: "ask", profile: {} },
    { name: "LLM allow", stages: [stage("llm")], expected: "allow", profile: {} },
    { name: "LLM deny", stages: [stage("llm")], expected: "deny", profile: { triage: "BLOCK", verdict: "DENY: out of scope" } },
    { name: "LLM ask", stages: [stage("llm")], expected: "ask", profile: { triage: "BLOCK", verdict: "ASK: uncertain" } },
    { name: "full cascade", stages: types.map(stage), expected: "allow", profile: {}, reached: ["jev", "openai-decision", "laya", "llm:triage"] },
    ...["jev", "openai-decision", "laya"].flatMap((type) => (["allow", "deny", "ask"] as Verdict[]).map((expected) =>
      ({ name: `${type} ${expected}`, stages: [stage(type)], expected, profile: { modes: { [type]: expected } } }))),
  ];
  for (const test of toolCases) await run(`real shell: ${test.name}`, async () => {
    const f = await fixture({ classifier: { stages: test.stages } });
    profile = { ...test.profile, tool: test.command ?? "printf integration > tool-result.txt" };
    calls.length = 0;
    await api(`/api/session/${f.sessionID}/prompt`, { text: "Run the requested local integration shell command once." });
    if (test.expected === "ask") {
      const pending = await until(() => api(`/api/session/${f.sessionID}/permission`), (value) => value.data.length > 0);
      assert.equal(pending.data[0].action, "shell");
      await api(`/api/session/${f.sessionID}/permission/${pending.data[0].id}/reply`, { decision: "reject" });
    }
    await api(`/api/experimental/session/${f.sessionID}/wait`, {});
    const context = (await api(`/api/session/${f.sessionID}/context`)).data;
    const tool = context.flatMap((entry: { content?: unknown[] }) => entry.content ?? []).find((part: { type: string; name: string }) => part.type === "tool" && part.name === "shell");
    assert.ok(tool, "OpenCode must actually call its shell tool");
    assert.equal(tool.state.status, test.expected === "allow" ? "completed" : "error");
    if (!test.command) assert.equal(existsSync(join(f.directory, "tool-result.txt")), test.expected === "allow");
    if (test.reached) assert.deepEqual(calls, test.reached);
    checks++;
  });
  writeFileSync(join(root, "results.json"), JSON.stringify({ version: info.version, combinations: combinations.size, checks, results }, null, 2));
  console.log(`PASS ${checks} permission checks across ${combinations.size} classifier combinations on OpenCode ${info.version}`);
} finally {
  host.kill("SIGTERM");
  await Promise.race([once(host, "exit"), delay(3000)]);
  if (host.exitCode === null) host.kill("SIGKILL");
  provider.closeAllConnections(); await new Promise<void>((done) => provider.close(() => done()));
  writeFileSync(join(root, "host.log"), logs);
}
