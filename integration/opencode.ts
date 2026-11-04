import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { once } from "node:events";
import { randomUUID } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { completion, FIXTURE_PROVIDER, FIXTURE_AGENT_MODEL, FIXTURE_REVIEWER_MODEL, type FixtureTool } from "./transport.js";
import { codeModePermission } from "../src/code-mode.js";
import { codeModeIdentityRegression } from "./code-mode-identity.js";

// Every endpoint/model below is explicitly configured test infrastructure.
// Never patch global fetch or redirect a production provider to a fixture.
type Verdict = "allow" | "deny" | "ask";
type Profile = { reviewer?: string; sameModelReviewer?: boolean; timeout?: boolean; reviewerFailure?: boolean; decision?: Verdict | "low" | "invalid" | "timeout"; tool?: FixtureTool; issued?: boolean };
const plugin = resolve(process.env.OPENCODE_PLUGIN_PATH ?? fileURLToPath(new URL("..", import.meta.url)));
const tempRoot = join(tmpdir(), "opencode"); mkdirSync(tempRoot, { recursive: true });
const root = mkdtempSync(join(realpathSync(tempRoot), "auto-mode-v2-integration-"));
for (const dir of ["home", "config/opencode", "data", "cache", "state", "tmp"])
  mkdirSync(join(root, dir), { recursive: true });
// Release 1.1.0 has one fixed local audit state path, so every enabled case
// shares this sink. Cases filter by session rather than claiming per-case files.
const auditPath = join(root, "state/opencode-auto-mode/decisions.jsonl");
let profile: Profile = {};
const calls: string[] = [];
const results: string[] = [];
let caseCount = 0;
const markers: string[] = [];
const reviewerInputs: string[] = [];
const provider = createServer(async (req, res) => {
  try {
    if (req.url?.startsWith("/marker/")) { markers.push(req.url); res.writeHead(200); res.end("fixture marker"); return; }
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(Buffer.from(chunk));
    const body = JSON.parse(Buffer.concat(chunks).toString());
    if (req.url === "/v1/systemone") {
      calls.push("decision");
      assert.equal(body.model, "decision");
      assert.ok(body.questions.permission && body.state, "native SDK lowered questions/input into decision wire protocol");
      const mode = profile.decision ?? "low";
      if (mode === "timeout") { res.writeHead(200); res.write("{"); return; }
      const choice = mode === "low" || mode === "invalid" ? "allow" : mode;
      const probabilities = mode === "invalid" ? { allow: 0.98, deny: 0.98, ask: 0.98 } :
        mode === "low" ? { allow: 0.4, deny: 0.3, ask: 0.3 } :
        Object.fromEntries(["allow", "deny", "ask"].map((value) => [value, value === choice ? 0.98 : 0.01]));
      res.writeHead(200, { "content-type": "application/json" });
      // Structurally valid native output, but inconsistent probabilities in the
      // invalid case: exercise plugin validation rather than SDK wire rejection.
      res.end(JSON.stringify({ model: "decision", answers: { permission: {
        type: "choice", choice, confidence: mode === "low" ? 0.4 : 0.98, probabilities,
      } } }));
      return;
    }
    assert.equal(req.url, "/v1/chat/completions");
    // One explicitly opted-in case uses the agent model ID as the reviewer so a
    // same-model reviewer can be exercised without inventing a second identity.
    const reviewer = body.model === FIXTURE_REVIEWER_MODEL ||
      (profile.sameModelReviewer === true && body.model === FIXTURE_AGENT_MODEL);
    assert.ok(reviewer || body.model === FIXTURE_AGENT_MODEL, "unexpected fixture model");
    if (reviewer) {
      reviewerInputs.push(JSON.stringify(body.messages));
      calls.push("reviewer");
      if (profile.reviewerFailure) { res.writeHead(400); res.end("fixture deliberate provider error"); return; }
      if (profile.timeout) { res.writeHead(200, { "content-type": "application/json" }); res.write("{"); return; }
    }
    const tool = !reviewer && !profile.issued && profile.tool &&
      body.tools?.some((t: { function: { name: string } }) => t.function.name === profile.tool!.name) ? profile.tool : undefined;
    if (tool) profile.issued = true;
    const output = completion(reviewer ? profile.reviewer ?? "ALLOW: fixture authorized" : "Ready", body.stream === true, tool, body.model);
    res.writeHead(200, { "content-type": output.type }); res.end(output.body);
  } catch { res.writeHead(500); res.end("internal error"); }
});
provider.listen(0, "127.0.0.1");
await once(provider, "listening");
const providerAddress = provider.address();
assert.ok(providerAddress && typeof providerAddress !== "string");
const endpoint = `http://127.0.0.1:${providerAddress.port}`;
const globalConfig = {
  update: "disable", share: "disabled", model: `${FIXTURE_PROVIDER}/${FIXTURE_AGENT_MODEL}`, default_agent: "build",
  providers: { [FIXTURE_PROVIDER]: { package: "@ai-sdk/openai-compatible", settings: { baseURL: `${endpoint}/v1`, apiKey: "fixture-key" },
    models: { [FIXTURE_AGENT_MODEL]: { name: "Invented worker fixture" }, [FIXTURE_REVIEWER_MODEL]: { name: "Invented reviewer fixture" } } },
    "fixture-decision": { package: "@opencode/ai/providers/opencode/decisions",
      settings: { baseURL: `${endpoint}/v1`, apiKey: "fixture-key" },
      models: { decision: { name: "Invented native decision fixture", type: "decision" } } } },
};
const configFile = join(root, "config/opencode/opencode.json");
writeFileSync(configFile, JSON.stringify(globalConfig));
const portServer = createServer();
portServer.listen(0, "127.0.0.1"); await once(portServer, "listening");
const address = portServer.address(); assert.ok(address && typeof address !== "string");
const port = address.port; await new Promise<void>((done) => portServer.close(() => done()));
const password = randomUUID();
const hostEnv: Record<string, string | undefined> = { ...process.env, HOME: join(root, "home"),
  OPENCODE_SERVER_PASSWORD: password, OPENCODE_DISABLE_MODELS_FETCH: "true",
  OPENCODE_DISABLE_PROJECT_CONFIG: "false", OPENCODE_DISABLE_LOCAL_CONFIG: "false",
  XDG_CONFIG_HOME: join(root, "config"), XDG_DATA_HOME: join(root, "data"), XDG_CACHE_HOME: join(root, "cache"),
  XDG_STATE_HOME: join(root, "state"), TMPDIR: join(root, "tmp") };
for (const key of ["OPENCODE_CONFIG", "OPENCODE_CONFIG_CONTENT", "OPENCODE_CONFIG_DIR", "OPENCODE_SIMULATE", "OPENCODE_DRIVE"])
  delete hostEnv[key];
const host = spawn(process.env.OPENCODE_BINARY ?? "opencode", ["serve", "--hostname", "127.0.0.1", "--port", String(port), "--print-logs", "--log-level", "warn"], {
  cwd: root, env: hostEnv, stdio: ["ignore", "pipe", "pipe"],
});
let logs = "";
host.stdout.on("data", (chunk) => { logs += chunk.toString(); });
host.stderr.on("data", (chunk) => { logs += chunk.toString(); });
host.on("error", (error) => { logs += String(error); });
const delay = (ms: number) => new Promise((done) => setTimeout(done, ms));
async function api(path: string, body?: unknown) {
  const response = await fetch(`http://127.0.0.1:${port}${path}`, {
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
    try { const value = await get(); last = value; if (ready(value)) return value; } catch (error) { last = String(error); }
    if (host.exitCode !== null) throw new Error(`OpenCode exited: ${logs.slice(-3000)}`);
    await delay(50);
  }
  throw new Error(`Readiness timed out: ${JSON.stringify(last)} ${logs.slice(-3000)}`);
}
async function fixture(options: Record<string, unknown> = {}, permissions = [{ action: "*", resource: "*", effect: "ask" }], projectOptions?: Record<string, unknown>, globalPermissions?: { action: string; resource: string; effect: string }[], globalPolicies?: { action: string; resource: string; effect: string }[], expectedMode: "on" | "invalid" = "on") {
  const directory = join(root, `case-${++caseCount}`); mkdirSync(directory);
  execFileSync("git", ["init", "--quiet", directory]);
  writeFileSync(join(directory, "opencode.json"), JSON.stringify({ permissions,
    ...(projectOptions === undefined ? {} : { plugins: [{ package: plugin, options: projectOptions }] }),
  }));
  writeFileSync(configFile, JSON.stringify({ ...globalConfig,
    ...(globalPermissions === undefined ? {} : { permissions: globalPermissions }),
    ...(globalPolicies === undefined ? {} : { policies: globalPolicies }),
    plugins: [{ package: plugin, options: { classifiers: [{ type: "static" },
      { type: "llm", model: `${FIXTURE_PROVIDER}/${FIXTURE_REVIEWER_MODEL}` }],
      reviewTimeoutMs: 1000, audit: { enabled: true }, ...options } }],
  }));
  // Sequential cases change only scratch global options. Explicitly target this
  // scratch server; never discover/reload the user's shared background service.
  execFileSync(process.env.OPENCODE_BINARY ?? "opencode", ["reload", "--server", `http://127.0.0.1:${port}`],
    { cwd: root, env: hostEnv, timeout: 15_000 });
  const query = `?location%5Bdirectory%5D=${encodeURIComponent(directory)}`;
  const loaded = await until(() => api(`/api/plugin${query}`), (value) =>
    value.data.some((p: { id: string; state: { status: string } }) => p.id === "opencode-auto-mode" && p.state.status === "active"));
  const entry = loaded.data.find((p: { id: string }) => p.id === "opencode-auto-mode");
  assert.equal(entry.features.server, true); assert.equal(entry.features.tui, true);
  // Inventory activation can race config-watch reload. Wait for this case's
  // expected safety configuration, not just an active previous instance.
  const waitForConfiguration = async () => {
    let consecutive = 0;
    let fingerprint = "";
    return until(async () => {
      const inventory = await api(`/api/plugin${query}`);
      const observed = await api(`/api/rpc/opencode-auto-mode/status${query}`, { input: {} });
      return { plugin: inventory.data.find((p: { id: string }) => p.id === "opencode-auto-mode"), status: observed.output };
    }, value => {
      // Invalid configuration must stay visibly invalid with its parse error;
      // valid configuration must expose the new review timeout.
      const matching = value.plugin?.state.status === "active" && value.status?.mode === expectedMode &&
        (expectedMode === "invalid" ? typeof value.status?.configError === "string" : value.status?.reviewTimeoutMs === 1000);
      const current = JSON.stringify(value);
      consecutive = matching ? current === fingerprint ? consecutive + 1 : 1 : 0;
      fingerprint = current;
      return consecutive >= 3;
    });
  };
  try { await waitForConfiguration(); }
  catch (error) {
    const diagnostic = { case: caseCount, expectedMode, error: String(error) };
    writeFileSync(join(directory, "readiness-retry.json"), JSON.stringify(diagnostic, null, 2));
    console.warn(`Scratch configuration did not settle: ${JSON.stringify(diagnostic)}`);
    // One meaningful retry rebuilds all *loaded* locations after the new case
    // exists. The original CLI reload ran before this case was discovered and
    // can race the asynchronous global watcher. Never restart the live service.
    await api("/api/location/reload", {});
    await waitForConfiguration();
  }
  const session = (await api("/api/session", { agent: "build", title: "V2 fixture", location: { directory },
    model: { id: FIXTURE_AGENT_MODEL, providerID: FIXTURE_PROVIDER } })).data;
  await api(`/api/session/${session.id}/prompt`, { text: "Perform the specifically requested scratch task only." });
  await api(`/api/experimental/session/${session.id}/wait`, {});
  return { directory, auditFile: auditPath, sessionID: session.id, query };
}
type Fixture = Awaited<ReturnType<typeof fixture>>;
async function permission(f: Fixture, resources: string[], action = "shell", metadata: Record<string, unknown> = { integration: true }) {
  return (await api(`/api/session/${f.sessionID}/permission`, { action, resources, save: resources, agent: "build", metadata })).data;
}
function auditRecords(f?: { sessionID?: string }): Record<string, unknown>[] {
  if (!existsSync(auditPath)) return [];
  const records = readFileSync(auditPath, "utf8").trim().split("\n").filter(Boolean).flatMap((line) => {
    try { return [JSON.parse(line) as Record<string, unknown>]; } catch { return []; }
  });
  return f?.sessionID === undefined ? records : records.filter(record => record.sessionID === f.sessionID);
}
async function savedApprovals(f: { query: string }): Promise<{ id: string; action: string; resource: string }[]> {
  const response = await api(`/api/permission/saved${f.query}`);
  return Array.isArray(response) ? response : response.data;
}
type CapturedHostEvent = { id: string; type: string; data: { sessionID?: string; title?: string; location?: { directory: string } } };
function capturedHostEvents(records: Record<string, unknown>[]): CapturedHostEvent[] {
  return records.filter(record => record.type === "event").map(record => record.payload as CapturedHostEvent);
}
async function sharedAuditRegression() {
  // Run first: release 1.1.0 uses one fixed state sink, so the two locations
  // below share it deliberately. This case must start with only two loads.
  const locations = ["shared-owner", "shared-standby"].map(name => {
    const directory = join(root, name); mkdirSync(directory);
    execFileSync("git", ["init", "--quiet", directory]);
    writeFileSync(join(directory, "opencode.json"), JSON.stringify({ permissions: [
      { action: "*", resource: "*", effect: "ask" }, { action: "read", resource: "*", effect: "allow" },
    ] }));
    return { directory, query: `?location%5Bdirectory%5D=${encodeURIComponent(directory)}` };
  });
  writeFileSync(configFile, JSON.stringify({ ...globalConfig, plugins: [{ package: plugin, options: {
    classifiers: [{ type: "static" }], audit: { enabled: true, maxBytes: 10_485_760 },
  } }] }));
  execFileSync(process.env.OPENCODE_BINARY ?? "opencode", ["reload", "--server", `http://127.0.0.1:${port}`],
    { cwd: root, env: hostEnv, timeout: 15_000 });
  const records = () => auditRecords();
  const active = async (query: string) => until(() => api(`/api/plugin${query}`), value =>
    value.data.some((entry: { id: string; state: { status: string } }) => entry.id === "opencode-auto-mode" && entry.state.status === "active"));
  for (const location of locations) await active(location.query);
  const initial = await until(async () => records(), value =>
    value.some(record => record.type === "capture.started") && locations.every(location =>
      value.some(record => record.type === "configuration" && (record.sourceLocation as { directory?: string })?.directory === location.directory)));
  const owner = initial.findLast(record => record.type === "capture.started" || record.type === "capture.handoff")!;
  assert.equal(typeof owner.instanceID, "string");
  assert.ok(locations.some(location => location.directory === (owner.sourceLocation as { directory: string }).directory));
  const sessions: { id: string; title: string; directory: string }[] = [];
  const create = async (directory: string, title: string) => {
    const session = (await api("/api/session", { location: { directory }, agent: "build", title,
      model: { id: FIXTURE_AGENT_MODEL, providerID: FIXTURE_PROVIDER } })).data;
    const observed = await until(async () => capturedHostEvents(records()), events =>
      events.some(event => event.type === "session.created" && event.data.sessionID === session.id));
    const created = observed.filter(event => event.type === "session.created" && event.data.sessionID === session.id);
    assert.equal(created.length, 1, "same shared sink captures each native session.created exactly once, never zero");
    assert.equal(typeof created[0].id, "string", "raw host event ID retained");
    assert.equal(created[0].data.title, title);
    assert.equal(created[0].data.location?.directory, directory);
    sessions.push({ id: session.id, title, directory });
    return session.id as string;
  };
  const first = await create(locations[0].directory, "Shared sink first session");
  await create(locations[1].directory, "Shared sink second session");
  // Explicit off keeps this native read grant a pure pass-through probe even
  // though a valid 1.1.0 configuration reviews native allows while on.
  await api(`/api/rpc/opencode-auto-mode/setMode${locations[0].query}`, { input: { sessionID: first, mode: "off" } });
  const metadata = { secret: "fixture-unredacted-secret", files: [{ patch: "fixture original private content" }], nested: { untouched: [1, "original"] } };
  const resources = ["sample.txt"];
  const response = (await api(`/api/session/${first}/permission`, { action: "read", resources, save: resources, agent: "build", metadata })).data;
  assert.equal(response.effect, "allow");
  const callback = await until(async () => records(), value => value.some(record =>
    record.type === "permission.evaluate.before" && (record.payload as { metadata?: typeof metadata })?.metadata?.secret === metadata.secret));
  const raw = callback.filter(record => record.type === "permission.evaluate.before" &&
    (record.payload as { metadata?: typeof metadata })?.metadata?.secret === metadata.secret);
  assert.equal(raw.length, 1, "location-local native callback is not globally duplicated");
  const payload = raw[0].payload as { effect: string; action: string; sessionID: string; resources: string[]; metadata: unknown };
  assert.equal(payload.effect, "allow"); assert.equal(payload.action, "read"); assert.equal(payload.sessionID, first);
  assert.deepEqual(payload.resources, resources); assert.deepEqual(payload.metadata, metadata, "native callback retains original unsafe payload");
  assert.deepEqual(calls, [], "safe native probe never invokes any generation endpoint");
  // OpenCode 2.2 reload is server-wide, not a selective location-unload API.
  // Its teardown retires the owner and exercises standby ownership transfer.
  const beforeReload = records().length;
  await api("/api/location/reload", {});
  for (const location of locations) await active(location.query);
  const afterReload = await until(async () => records().slice(beforeReload), value =>
    value.some(record => record.type === "capture.handoff" && record.instanceID !== owner.instanceID) &&
    value.some(record => ["capture.started", "capture.handoff"].includes(record.type as string) && record.instanceID !== owner.instanceID));
  assert.ok(afterReload.some(record => record.type === "capture.handoff"), "retiring owner reports handoff rather than silently dropping capture");
  await create(locations[1].directory, "Shared sink after owner reload");
  const all = records();
  const hostEvents = capturedHostEvents(all);
  assert.ok(hostEvents.length > 0, "empty host-event capture is a failure, not deduplication evidence");
  assert.equal(new Set(hostEvents.map(event => event.id)).size, hostEvents.length, "each raw host event ID appears once in the shared sink");
  for (const session of sessions) {
    const events = capturedHostEvents(all).filter(event => event.type === "session.created" && event.data.sessionID === session.id);
    assert.equal(events.length, 1, `exactly one final capture for ${session.title}`);
    assert.equal(new Set(events.map(event => event.id)).size, 1);
  }
  const last = all.find(record => record.type === "event" && (record.payload as CapturedHostEvent)?.type === "session.created" &&
    (record.payload as CapturedHostEvent).data.sessionID === sessions.at(-1)!.id)!;
  assert.notEqual(last.instanceID, owner.instanceID, "fresh session is captured by a successor, not the disposed owner");
  assert.deepEqual(calls, []);
}
async function expectPermission(f: Fixture, expected: Verdict, resources = ["scp sample.txt destination:sample.txt"], action = "shell") {
  const response = await permission(f, resources, action);
  assert.equal(response.effect, expected, `${action}: ${resources.join(";")}`);
  const pending = (await api(`/api/session/${f.sessionID}/permission`)).data;
  assert.equal(pending.some((p: { id: string }) => p.id === response.id), expected === "ask");
  if (expected === "ask") await api(`/api/session/${f.sessionID}/permission/${response.id}/reply`, { decision: "reject" });
  return response;
}
async function toolResult(f: Fixture, name: string) {
  const context = (await api(`/api/session/${f.sessionID}/context`)).data;
  const tool = context.flatMap((entry: { content?: unknown[] }) => entry.content ?? [])
    .filter((part: { type: string; name: string }) => part.type === "tool" && part.name === name).at(-1);
  assert.ok(tool, `real OpenCode must invoke ${name}`);
  return tool;
}
async function status(f: Fixture) {
  const response = await api(`/api/rpc/opencode-auto-mode/status${f.query}`, { input: { sessionID: f.sessionID } });
  const value = response.output;
  assert.ok(typeof value.mode === "string" && value.counts && Array.isArray(value.reviewing));
  assert.ok(["on", "off", "paused", "invalid"].includes(value.mode), `retired mode surfaced: ${value.mode}`);
  assert.equal("history" in value, false); assert.equal("decisions" in value, false);
  assert.equal("shadow" in value, false, "shadow mode is removed from status");
  assert.equal("ruleID" in value, false, "rule IDs are removed from status");
  return value;
}
async function command(f: Fixture, text: string) {
  await api(`/api/session/${f.sessionID}/command`, { name: "auto-mode", text });
}
async function setMode(f: Fixture, mode: "on" | "off" | "resume") {
  return (await api(`/api/rpc/opencode-auto-mode/setMode${f.query}`, { input: { sessionID: f.sessionID, mode } })).output;
}
async function summary(f: Fixture) {
  return (await until(async () => auditRecords(f), records => records.some(record => record.reviewID && typeof record.decision === "string")))
    .findLast(record => record.reviewID && typeof record.decision === "string")!;
}
async function run(name: string, test: () => Promise<void>) {
  if (process.env.OPENCODE_INTEGRATION_FILTER && !name.includes(process.env.OPENCODE_INTEGRATION_FILTER)) return;
  profile = {}; calls.length = 0;
  await test(); results.push(name); console.log(`PASS ${name}`);
}
try {
  const info = await until(() => api("/api/info"), (value) => value.version.startsWith("2."));
  console.log(`OpenCode ${info.version}; scratch artifacts ${root}`);
  await run("shared global audit captures once across two locations and owner reload", sharedAuditRegression);
  for (const [output, expected] of [["ALLOW: fixture authorized", "allow"], ["DENY: fixture forbidden", "deny"],
    ["not a verdict", "ask"], ["ALLOW: yes\nDENY: no", "ask"]] as const) await run(`single reviewer ${expected}: ${output}`, async () => {
    const f = await fixture(); profile.reviewer = output; calls.length = 0;
    await expectPermission(f, expected); assert.deepEqual(calls, ["reviewer"]);
  });
  await run("same-model reviewer is allowed", async () => {
    const f = await fixture({ classifiers: [{ type: "llm", model: `${FIXTURE_PROVIDER}/${FIXTURE_AGENT_MODEL}` }] });
    profile.sameModelReviewer = true; profile.reviewer = "ALLOW: same-model fixture authorized"; calls.length = 0;
    await expectPermission(f, "allow"); assert.deepEqual(calls, ["reviewer"]);
  });
  await run("reviewer timeout remains manual", async () => {
    const f = await fixture(); profile.timeout = true; calls.length = 0;
    await expectPermission(f, "ask"); assert.deepEqual(calls, ["reviewer"]);
  });
  await run("static protected deny and low safe allow", async () => {
    const f = await fixture(); calls.length = 0;
    await expectPermission(f, "deny", ["cat .env"]);
    await expectPermission(f, "ask", [".git/config"], "edit");
    await expectPermission(f, "allow", ["pwd"]); assert.deepEqual(calls, []);
  });
  await run("native deny is final without review", async () => {
    const f = await fixture({}, [{ action: "*", resource: "*", effect: "deny" }]); calls.length = 0;
    await expectPermission(f, "deny", ["cat .env"]); assert.deepEqual(calls, []);
  });
  await run("real reply Always is re-reviewed and denial is enforced", async () => {
    const f = await fixture(); await command(f, "off"); calls.length = 0;
    const first = await permission(f, ["scp sample.txt destination:saved-fixture.txt"]);
    assert.equal(first.effect, "ask");
    await api(`/api/session/${f.sessionID}/permission/${first.id}/reply`, { decision: "always" });
    await command(f, "on"); profile.reviewer = "DENY: saved approval must be re-reviewed";
    await expectPermission(f, "deny", ["scp sample.txt destination:saved-fixture.txt"]);
    assert.deepEqual(calls, ["reviewer"]);
  });
  await run("mode command and status-only RPC", async () => {
    const f = await fixture(); assert.equal((await status(f)).mode, "on");
    await command(f, "off"); assert.equal((await status(f)).mode, "off"); calls.length = 0;
    await expectPermission(f, "ask"); assert.deepEqual(calls, []);
    await command(f, "on"); assert.equal((await status(f)).mode, "on");
    await expectPermission(f, "allow"); assert.deepEqual(calls, ["reviewer"]);
    await command(f, "status");
    await assert.rejects(() => api(`/api/rpc/opencode-auto-mode/decisions${f.query}`, {}));
  });
  await run("session-scoped mode mutation RPC validates input and preserves native effects", async () => {
    const f = await fixture();
    assert.equal((await setMode(f, "off")).mode, "off"); calls.length = 0;
    await expectPermission(f, "ask"); assert.deepEqual(calls, []);
    assert.equal((await setMode(f, "on")).mode, "on");
    await expectPermission(f, "allow"); assert.deepEqual(calls, ["reviewer"]);
    for (const input of [{ mode: "off" }, { sessionID: f.sessionID }, { sessionID: f.sessionID, mode: "paused" }]) {
      await assert.rejects(() => api(`/api/rpc/opencode-auto-mode/setMode${f.query}`, { input }), `invalid mutation input rejected: ${JSON.stringify(input)}`);
      assert.equal((await status(f)).mode, "on", "invalid RPC cannot mutate mode");
    }
    // The real host decodes JSON-schema input before invoking the handler and
    // strips excess keys. additionalProperties:false is not a promise that the
    // original HTTP payload is rejected: the valid mode change still applies.
    const projectFile = join(f.directory, "opencode.json");
    const originalProject = readFileSync(projectFile, "utf8");
    const originalGlobal = readFileSync(configFile, "utf8");
    const stripped = await api(`/api/rpc/opencode-auto-mode/setMode${f.query}`, { input: {
      sessionID: f.sessionID, mode: "off", permissions: [{ action: "*", resource: "*", effect: "allow" }],
      classifiers: [], audit: { enabled: false },
    } });
    assert.equal(stripped.output.mode, "off", "host strips extras and applies the declared session mode");
    assert.equal((await status(f)).mode, "off"); calls.length = 0;
    await expectPermission(f, "ask"); assert.deepEqual(calls, [], "stripped permission extras never grant native access");
    assert.equal(readFileSync(projectFile, "utf8"), originalProject, "RPC never rewrites project permissions/config");
    assert.equal(readFileSync(configFile, "utf8"), originalGlobal, "RPC never rewrites global permissions/config");
    assert.equal((await setMode(f, "on")).mode, "on");
    const other = (await api("/api/session", { agent: "build", title: "Separate mode scope", location: { directory: f.directory },
      model: { id: FIXTURE_AGENT_MODEL, providerID: FIXTURE_PROVIDER } })).data;
    await setMode(f, "off");
    const otherStatus = await api(`/api/rpc/opencode-auto-mode/status${f.query}`, { input: { sessionID: other.id } });
    assert.equal(otherStatus.output.mode, "on", "mode change affects only its target session");
    assert.equal((await setMode(f, "resume")).mode, "on");
    const native = await fixture({}, [{ action: "*", resource: "*", effect: "allow" }]);
    // Host RPC wraps handler defects as rpc.internal instead of exposing the
    // private location-mismatch message. Verify rejection AND unchanged scope.
    await assert.rejects(() => api(`/api/rpc/opencode-auto-mode/setMode${native.query}`, { input: { sessionID: f.sessionID, mode: "off" } }),
      /rpc\.internal/, "RPC cannot change a session owned by another location");
    assert.equal((await status(f)).mode, "on", "foreign RPC cannot change target session mode");
    assert.equal((await status(native)).mode, "on", "foreign RPC cannot change receiving location mode");
    await setMode(native, "off"); calls.length = 0;
    await expectPermission(native, "allow", ["cat .env"]); assert.deepEqual(calls, []);
  });
  for (const mode of ["allow", "deny", "low", "ask", "invalid", "timeout"] as const) await run(`decision confidence routing: ${mode}`, async () => {
    const f = await fixture({ classifiers: [{ type: "static" },
      { type: "decision", model: "fixture-decision/decision", timeoutMs: 100, minConfidence: 0.9 },
      { type: "llm", model: `${FIXTURE_PROVIDER}/${FIXTURE_REVIEWER_MODEL}` }] });
    profile.decision = mode; calls.length = 0;
    await expectPermission(f, mode === "deny" ? "deny" : "allow", ["bun test"]);
    assert.deepEqual(calls, mode === "allow" || mode === "deny" ? ["decision"] : ["decision", "reviewer"]);
  });
  for (const mode of ["invalid", "timeout"] as const) await run(`native decision ${mode} has categorized summary audit`, async () => {
    const f = await fixture({ classifiers: [{ type: "decision", model: "fixture-decision/decision", timeoutMs: 100 }] });
    profile.decision = mode; calls.length = 0;
    await expectPermission(f, "ask", ["bun test"]); assert.deepEqual(calls, ["decision"]);
    const record = await summary(f);
    assert.equal(record.errorKind, mode === "invalid" ? "invalid-output" : "timeout");
    assert.equal(record.stage, "decision"); assert.equal(record.decision, "ask");
  });
  for (const mode of ["invalid", "timeout"] as const) await run(`reviewer ${mode} has categorized summary audit`, async () => {
    const f = await fixture({ classifiers: [{ type: "llm", model: `${FIXTURE_PROVIDER}/${FIXTURE_REVIEWER_MODEL}`, timeoutMs: 100 }] });
    if (mode === "invalid") profile.reviewer = "not a verdict"; else profile.timeout = true;
    calls.length = 0; await expectPermission(f, "ask");
    assert.equal((await summary(f)).errorKind, mode === "invalid" ? "invalid-output" : "timeout");
  });
  await run("invalid config acts disabled and reports invalid status", async () => {
    const variants: { options: Record<string, unknown>; permissions: { action: string; resource: string; effect: string }[] }[] = [
      // Removed options are rejected, not silently ignored.
      { options: { enabled: true }, permissions: [{ action: "*", resource: "*", effect: "allow" }] },
      // classifiers are required and non-empty.
      { options: { classifiers: [] }, permissions: [{ action: "*", resource: "*", effect: "ask" }] },
      // At most one static stage is accepted.
      { options: { classifiers: [{ type: "static" }, { type: "static" }] }, permissions: [{ action: "*", resource: "*", effect: "allow" }] },
      // At most 64 classifier stages are accepted.
      { options: { classifiers: Array.from({ length: 65 }, () => ({ type: "llm", model: `${FIXTURE_PROVIDER}/${FIXTURE_REVIEWER_MODEL}` })) },
        permissions: [{ action: "*", resource: "*", effect: "allow" }] },
      // Audit is object-only; the retired boolean shorthand is invalid.
      { options: { audit: true }, permissions: [{ action: "*", resource: "*", effect: "allow" }] },
    ];
    for (const variant of variants) {
      const f = await fixture(variant.options, variant.permissions, undefined, undefined, undefined, "invalid");
      calls.length = 0;
      await expectPermission(f, variant.permissions[0].effect as Verdict, ["scp sample.txt destination:invalid-config.txt"]);
      assert.deepEqual(calls, [], "invalid config performs zero generation");
      const observed = await status(f);
      assert.equal(observed.mode, "invalid");
      assert.equal(observed.enabled, false, "review is disabled for invalid configuration");
      assert.equal(typeof observed.configError, "string");
      assert.ok(observed.configError.length > 0, "invalid status exposes a configuration error");
    }
  });
  await run("raw audit isolation and one decision among full events", async () => {
    const f = await fixture({ audit: { enabled: true, maxBytes: 10_485_760 } }); calls.length = 0;
    const records = () => auditRecords(f);
    const before = records().filter(record => record.reviewID && typeof record.decision === "string").length;
    await expectPermission(f, "allow");
    const all = await until(() => Promise.resolve(records()), value => value.filter(record => record.reviewID && typeof record.decision === "string").length > before);
    const decisions = all.filter(record => record.reviewID && typeof record.decision === "string");
    assert.equal(decisions.length, before + 1, "this session has exactly one new decision record");
    const record = decisions.at(-1)!; assert.equal(record.action, "shell"); assert.equal(record.decision, "allow");
    assert.equal(record.proposedDecision, "allow"); assert.equal(record.reviewedNativeAllow, false);
    assert.ok(all.some(record => record.type === "permission.evaluate.before"), "raw evaluate event captured");
    assert.ok(f.auditFile.startsWith(root)); assert.equal(record.hostEffect, "ask");
    assert.equal(existsSync(join(root, "home/.local/state/opencode-auto-mode/decisions.jsonl")), false);
  });
  await run("audit default and explicit disabled append nothing; off restores native allow", async () => {
    const recordsFor = (f: Fixture) => auditRecords().filter(record => record.sessionID === f.sessionID ||
      (record.sourceLocation as { directory?: string } | undefined)?.directory === f.directory);
    // Omitted audit uses the default-off policy while review still runs.
    const defaults = await fixture({ audit: undefined }, [{ action: "*", resource: "*", effect: "allow" }]); calls.length = 0;
    await expectPermission(defaults, "allow");
    assert.deepEqual(calls, ["reviewer"], "default audit-off does not disable review");
    assert.deepEqual(recordsFor(defaults), [], "default audit-off writes nothing");
    const f = await fixture({ audit: { enabled: false } }, [{ action: "*", resource: "*", effect: "allow" }]); calls.length = 0;
    // Audit is independent of review: the valid configuration still reviews the
    // native allow, but disabled audit appends no raw records for this location.
    assert.deepEqual(recordsFor(f), [], "disabled audit writes nothing at load");
    await expectPermission(f, "allow");
    assert.deepEqual(calls, ["reviewer"], "audit disabling does not disable review");
    assert.deepEqual(recordsFor(f), [], "disabled audit writes nothing during review");
    await command(f, "off"); calls.length = 0;
    await expectPermission(f, "allow");
    assert.deepEqual(calls, [], "off restores the native allow without generation");
    assert.deepEqual(recordsFor(f), [], "disabled audit writes nothing while off");
  });
  await run("raw metadata is retained and deny message has no rule prefix", async () => {
    const f = await fixture(); profile.reviewer = "DENY: fixture metadata veto"; calls.length = 0;
    const metadata = { integration: true, secret: "fixture-private-credential", files: [{ patch: "fixture private file content" }] };
    const response = await permission(f, ["scp sample.txt destination:raw-metadata.txt"], "shell", metadata);
    assert.equal(response.effect, "deny"); assert.deepEqual(calls, ["reviewer"]);
    const records = auditRecords(f);
    const decision = records.findLast(record => record.reviewID && typeof record.decision === "string");
    assert.ok(decision); assert.equal(decision.decision, "deny"); assert.equal(decision.hostEffect, "ask");
    // The permission response does not echo hook message mutations; assert the
    // actual applied host event and the audit copy of it instead.
    const applied = records.findLast(record => record.type === "permission.evaluate.after")?.payload as { effect?: string; message?: string } | undefined;
    assert.equal(applied?.effect, "deny");
    assert.equal(applied?.message, decision.appliedMessage, "audit applied message matches the host event");
    assert.ok(String(applied?.message).endsWith("Continue with a safer alternative."));
    assert.equal(String(applied?.message).startsWith("["), false, "deny message has no ruleID prefix");
    const captured = records.findLast(record => record.type === "permission.evaluate.before")?.payload as { metadata?: unknown } | undefined;
    assert.deepEqual(captured?.metadata, metadata, "unsafe audit retains original secret/file payloads");
  });
  await run("raw native generation error is observable", async () => {
    const f = await fixture(); profile.reviewerFailure = true;
    await expectPermission(f, "ask");
    const records = auditRecords(f);
    assert.ok(records.some(record => record.type === "generate.text.error"), "full raw error record retained");
    assert.ok(records.some(record => record.reviewID && record.decision === "ask"));
  });
  await run("actual scratch shell execution", async () => {
    const f = await fixture();
    // Nested sh -c is intentionally a mandatory manual ask. Use a direct HIGH
    // write instead so this test exercises a reviewer without bypassing the floor.
    profile.tool = { name: "shell", input: { command: "touch tool-result.txt", description: "Scratch marker" } }; calls.length = 0;
    await api(`/api/session/${f.sessionID}/prompt`, { text: "Run the one scratch shell marker command." });
    await api(`/api/experimental/session/${f.sessionID}/wait`, {});
    const context = (await api(`/api/session/${f.sessionID}/context`)).data;
    const tool = context.flatMap((entry: { content?: unknown[] }) => entry.content ?? []).find((part: { type: string; name: string }) => part.type === "tool" && part.name === "shell");
    assert.ok(tool, "real OpenCode must invoke the shell tool"); assert.equal(tool.state.status, "completed");
    assert.equal(existsSync(join(f.directory, "tool-result.txt")), true);
    assert.deepEqual(calls, ["reviewer"], "actual risky shell uses exactly one reviewer");
    const captured = auditRecords(f).findLast(record => record.type === "permission.evaluate.before")?.payload as { source?: { type?: string; messageID?: string; id?: string } } | undefined;
    assert.equal(captured?.source?.type, "tool"); assert.equal(typeof captured?.source?.messageID, "string");
    assert.equal(typeof captured?.source?.id, "string", "actual native tool source identifiers retained");
  });
  await run("real shell scanner allows parsed multiline commands but interpreter header remains manual", async () => {
    const f = await fixture();
    profile.tool = { name: "shell", input: { command: "pwd\nls", description: "List the scratch directory" } }; calls.length = 0;
    await api(`/api/session/${f.sessionID}/prompt`, { text: "Run the one benign multiline scratch command." });
    await api(`/api/experimental/session/${f.sessionID}/wait`, {});
    assert.equal((await toolResult(f, "shell")).state.status, "completed");
    assert.deepEqual(calls, [], "parsed pure commands use the static classifier, not a manual guard or model");
    const records = auditRecords(f);
    const evaluated = records.filter(record => record.type === "permission.evaluate.before" &&
      (record.payload as { action?: string; source?: { type?: string } })?.action === "shell" &&
      (record.payload as { source?: { type?: string } })?.source?.type === "tool");
    assert.ok(evaluated.length > 0, "scanner resources come from the actual native shell tool");
    const resources = evaluated.flatMap(record => (record.payload as { resources: string[] }).resources);
    assert.ok(resources.some(resource => resource.includes("pwd")) && resources.some(resource => resource.includes("ls")), JSON.stringify(resources));
    assert.ok(records.some(record => record.reviewID && record.stage === "static" && record.decision === "allow"));
    profile.tool = { name: "shell", input: { command: "sh <<'EOF'\npwd\nls\nEOF", description: "Benign interpreter fixture requiring consent" } };
    profile.issued = false; calls.length = 0;
    await api(`/api/session/${f.sessionID}/prompt`, { text: "Attempt the changed benign interpreter command once." });
    const pending = await until(() => api(`/api/session/${f.sessionID}/permission`), value => value.data.some((request: { action: string }) => request.action === "shell"));
    const request = pending.data.find((entry: { action: string }) => entry.action === "shell");
    assert.deepEqual(calls, [], "mandatory interpreter guard never calls the reviewer");
    await api(`/api/session/${f.sessionID}/permission/${request.id}/reply`, { decision: "reject" });
    await api(`/api/experimental/session/${f.sessionID}/wait`, {});
    assert.equal((await toolResult(f, "shell")).state.status, "error");
    const guarded = await summary(f);
    assert.equal(guarded.stage, "score"); assert.equal(guarded.decision, "ask");
  });
  await run("hostile project options cannot replace global safety options", async () => {
    const f = await fixture({ classifiers: [{ type: "static", allowInProjectEdits: false },
      { type: "llm", model: `${FIXTURE_PROVIDER}/${FIXTURE_REVIEWER_MODEL}` }] }, undefined,
      { classifiers: [{ type: "static", allowInProjectEdits: true },
        { type: "llm", model: `${FIXTURE_PROVIDER}/${FIXTURE_AGENT_MODEL}` }], audit: { enabled: false } });
    profile.reviewer = "DENY: global reviewer veto"; calls.length = 0;
    await expectPermission(f, "deny", ["sample.txt"], "edit");
    assert.deepEqual(calls, ["reviewer"]);
    assert.ok(auditRecords(f).some(record => record.reviewID && record.decision === "deny"), "project cannot disable global audit");
  });
  for (const verdict of ["allow", "deny"] as const) await run(`actual execute bridge reviewer ${verdict}`, async () => {
    const f = await fixture(); profile.reviewer = verdict === "allow" ? "ALLOW: fixture authorized" : "DENY: fixture veto";
    const code = `return await fetch(${JSON.stringify(`${endpoint}/marker/${verdict}`)}).then(r => r.text());`;
    profile.tool = { name: "execute", input: { code } };
    reviewerInputs.length = 0; calls.length = 0;
    const before = markers.length;
    await api(`/api/session/${f.sessionID}/prompt`, { text: "Run the requested scratch Code Mode fixture once." });
    await api(`/api/experimental/session/${f.sessionID}/wait`, {});
    const tool = await toolResult(f, "execute");
    assert.equal(tool.state.status, verdict === "allow" ? "completed" : "error");
    const reviews = reviewerInputs.map(raw => {
      const messages = JSON.parse(raw) as { content: string | { text?: string }[] }[];
      const text = messages.map(message => typeof message.content === "string" ? message.content :
        message.content.map(part => part.text ?? "").join("\n")).join("\n");
      const evidenceLine = text.split("\n").find(line => line.startsWith('{"action":"'));
      return evidenceLine ? JSON.parse(evidenceLine) as { action: string; resources: string[] } : undefined;
    }).filter((evidence): evidence is { action: string; resources: string[] } => evidence !== undefined);
    const executeReviews = reviews.filter(evidence => evidence.action === "execute");
    const fetchReviews = reviews.filter(evidence => evidence.action === "webfetch");
    assert.equal(executeReviews.length, 1, "outer execute is reviewed exactly once");
    assert.deepEqual(executeReviews[0].resources, [code], "reviewer receives full exact actual code rather than an opaque hash");
    if (verdict === "allow") {
      assert.deepEqual(calls, ["reviewer", "reviewer"], "outer execute and inner webfetch are both reviewed");
      assert.equal(fetchReviews.length, 1, "inner fetch is reviewed only after the execute is allowed");
      assert.deepEqual(fetchReviews[0].resources, [`${endpoint}/marker/${verdict}`], "inner fetch review receives its actual URL");
    } else {
      assert.deepEqual(calls, ["reviewer"], "denied execute never starts its inner fetch review");
      assert.equal(fetchReviews.length, 0);
    }
    const expected = codeModePermission({ code });
    const captured = auditRecords(f).findLast(record => record.type === "permission.evaluate.before" &&
      (record.payload as { action?: string })?.action === "execute")?.payload as {
      resources: string[]; metadata: unknown; source?: { type?: string; messageID?: string; id?: string };
    } | undefined;
    assert.ok(captured, "actual bridge emits native permission evaluation");
    assert.deepEqual(captured.resources, expected.resources, "native callback retains only the exact hash resource");
    assert.deepEqual(captured.metadata, expected.metadata, "native callback retains hash-bound actual source metadata");
    assert.equal(captured.source?.type, "tool"); assert.equal(typeof captured.source?.messageID, "string");
    assert.equal(typeof captured.source?.id, "string", "bridge retains native tool source identifiers");
    assert.equal(markers.length - before, verdict === "allow" ? 1 : 0, "veto prevents actual code execution");
  });
  await run("pre-existing native execute grant is re-reviewed before execution", async () => {
    const f = await fixture({}, [{ action: "*", resource: "*", effect: "ask" }, { action: "execute", resource: "*", effect: "allow" }]);
    profile.reviewer = "DENY: native execute grant must be re-reviewed";
    profile.tool = { name: "execute", input: { code: `return await fetch(${JSON.stringify(`${endpoint}/marker/native-grant`)}).then(r => r.text());` } };
    calls.length = 0; const before = markers.length;
    await api(`/api/session/${f.sessionID}/prompt`, { text: "Run the specifically native-authorized benign fixture." });
    await api(`/api/experimental/session/${f.sessionID}/wait`, {});
    assert.equal((await toolResult(f, "execute")).state.status, "error");
    assert.equal(markers.length, before, "reviewed native execute denial prevents execution");
    assert.deepEqual(calls, ["reviewer"]);
  });
  await run("native hash identity matcher preserves exact Always and reasks changed literals", async () => {
    await codeModeIdentityRegression({ api, createSession: async () => {
      const f = await fixture(); await command(f, "off"); return f.sessionID;
    } });
    assert.deepEqual(calls, []);
  });
  await run("actual execute saved Always is re-reviewed; rejection never executes", async () => {
    const f = await fixture(); await command(f, "off");
    const code = `const literal = "fixture?*"; return await fetch(${JSON.stringify(`${endpoint}/marker/saved`)}).then(r => r.text());`;
    const execute = async (reply?: "always" | "reject", program = code) => {
      profile.tool = { name: "execute", input: { code: program } }; profile.issued = false;
      await api(`/api/session/${f.sessionID}/prompt`, { text: "Run the scratch Code Mode fixture once." });
      if (reply) {
        const pending = await until(() => api(`/api/session/${f.sessionID}/permission`), value => value.data.length > 0);
        const request = pending.data.find((entry: { action: string }) => entry.action === "execute");
        assert.ok(request, "pending execute permission present");
        const expected = codeModePermission({ code: program });
        assert.deepEqual(request.resources, expected.resources, "bridge supplies exact hash identity");
        const detail = (await api(`/api/session/${f.sessionID}/permission/${request.id}`)).data;
        assert.deepEqual(detail.metadata, expected.metadata, "full actual program remains bound to the hash identity");
        await api(`/api/session/${f.sessionID}/permission/${request.id}/reply`, { decision: reply });
        if (reply === "always") {
          // Mode is off here, so the program's own fetch is a native ask that
          // needs a one-time approval; with review on it is statically allowed.
          const fetchPending = await until(() => api(`/api/session/${f.sessionID}/permission`), value =>
            value.data.some((entry: { action: string }) => entry.action === "webfetch"));
          const fetchRequest = fetchPending.data.find((entry: { action: string }) => entry.action === "webfetch");
          await api(`/api/session/${f.sessionID}/permission/${fetchRequest.id}/reply`, { decision: "once" });
        }
      }
      await api(`/api/experimental/session/${f.sessionID}/wait`, {});
    };
    const before = markers.length; calls.length = 0;
    await execute("reject"); assert.equal(markers.length, before);
    await execute("always"); assert.equal(markers.length, before + 1);
    await command(f, "on"); profile.reviewer = "DENY: saved execute approval must be re-reviewed"; calls.length = 0;
    await execute(); assert.equal(markers.length, before + 1, "re-reviewed saved approval denial prevents execution");
    assert.deepEqual(calls, ["reviewer"]);
    profile.reviewer = "ALLOW: re-reviewed saved execute approval authorized"; calls.length = 0;
    await execute(); assert.equal(markers.length, before + 2, "re-reviewed saved approval allows execution");
    assert.deepEqual(calls, ["reviewer", "reviewer"], "allowed execute and its inner webfetch are both reviewed");
    // Disable only this scratch session to observe native matching directly.
    // A wildcard-containing literal saved with Always must never grant a changed
    // program. Reject the benign variant: no one-time execution approval is used.
    await command(f, "off"); calls.length = 0;
    for (const changed of [code.replace("fixture?*", "fixtureX*"), code.replace("fixture?*", "fixture?expanded")]) {
      await execute("reject", changed);
      assert.equal(markers.length, before + 2, "changed literal reaches native ask and rejection prevents execution");
      assert.deepEqual(calls, [], "native saved matching has no reviewer overlay");
    }
  });
  await run("off preserves native read/edit grants across actual worktree and nested moves", async () => {
    const nativePermissions = [{ action: "*", resource: "*", effect: "ask" },
      { action: "read", resource: "*", effect: "allow" }, { action: "edit", resource: "*", effect: "allow" },
      { action: "read", resource: "/*", effect: "ask" }, { action: "edit", resource: "/*", effect: "ask" },
      { action: "external_directory", resource: "*", effect: "ask" },
      ...["read", "edit"].flatMap(action => [".env*", "*/.env*", ".opencode/*"].map(resource => ({ action, resource, effect: "ask" })))];
    const f = await fixture({}, [], undefined, nativePermissions);
    await command(f, "off");
    writeFileSync(join(f.directory, "sample.txt"), "before\n");
    execFileSync("git", ["-C", f.directory, "add", "sample.txt"]);
    execFileSync("git", ["-C", f.directory, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "Fixture baseline"]);
    const worktree = join(root, `worktree-${caseCount}`);
    execFileSync("git", ["-C", f.directory, "worktree", "add", "--quiet", "-b", `fixture-${caseCount}`, worktree]);
    assert.equal(readFileSync(join(worktree, ".git"), "utf8").startsWith("gitdir:"), true);
    const nested = join(worktree, "nested"); mkdirSync(nested); writeFileSync(join(nested, "sample.txt"), "before\n");
    for (const directory of [f.directory, worktree, nested]) {
      if (directory !== f.directory) { await api(`/api/session/${f.sessionID}/move`, { directory }); await api(`/api/experimental/session/${f.sessionID}/wait`, {}); }
      assert.equal((await api(`/api/session/${f.sessionID}`)).data.location.directory, directory);
      for (const tool of [{ name: "read", input: { path: "sample.txt" } },
        { name: "edit", input: { path: "sample.txt", oldString: "before", newString: "after" } }] as const) {
        profile.tool = tool; profile.issued = false; calls.length = 0;
        await api(`/api/session/${f.sessionID}/prompt`, { text: "Perform the one requested scratch read or edit." });
        await api(`/api/experimental/session/${f.sessionID}/wait`, {});
        assert.equal((await toolResult(f, tool.name)).state.status, "completed");
        assert.deepEqual(calls, [], "off keeps native file grants unreviewed after moves");
      }
      assert.equal(readFileSync(join(directory, "sample.txt"), "utf8"), "after\n");
    }
    calls.length = 0;
    const protectedRequest = await permission(f, [".env"], "read"); assert.equal(protectedRequest.effect, "ask");
    await api(`/api/session/${f.sessionID}/permission/${protectedRequest.id}/reply`, { decision: "reject" });
    const outsidePath = join(root, "outside.txt"); writeFileSync(outsidePath, "private outside fixture");
    profile.tool = { name: "read", input: { path: outsidePath } }; profile.issued = false;
    await api(`/api/session/${f.sessionID}/prompt`, { text: "Attempt the requested outside fixture read once." });
    const outside = await until(() => api(`/api/session/${f.sessionID}/permission`), value => value.data.some((request: { action: string }) => request.action === "external_directory"));
    const external = outside.data.find((request: { action: string }) => request.action === "external_directory");
    assert.equal(typeof external.id, "string", "pending permission list contains the actual external-directory ask");
    const capture = auditRecords(f).findLast(record => record.type === "permission.evaluate.before" &&
      (record.payload as { action?: string } | undefined)?.action === "external_directory")?.payload as { effect?: string } | undefined;
    assert.equal(capture?.effect, "ask", "native outside-directory evaluation is ask, not auto-allow");
    await api(`/api/session/${f.sessionID}/permission/${external.id}/reply`, { decision: "reject" });
    await api(`/api/experimental/session/${f.sessionID}/wait`, {});
    assert.equal((await toolResult(f, "read")).state.status, "error", "outside native directory rejection prevents read");
    assert.deepEqual(calls, []);
  });
  await run("native allow reaches reviewer and deny prevents execution", async () => {
    const f = await fixture({}, [{ action: "*", resource: "*", effect: "allow" }]);
    profile.reviewer = "DENY: fixture native-allow veto"; calls.length = 0;
    profile.tool = { name: "shell", input: { command: "touch native-allow-denied.txt", description: "Scratch native allow denial" } };
    await api(`/api/session/${f.sessionID}/prompt`, { text: "Run the specifically requested scratch marker once." });
    await api(`/api/experimental/session/${f.sessionID}/wait`, {});
    assert.equal((await toolResult(f, "shell")).state.status, "error");
    assert.equal(existsSync(join(f.directory, "native-allow-denied.txt")), false, "reviewer denial prevents the actual tool side effect");
    assert.deepEqual(calls, ["reviewer"]);
    const evaluated = auditRecords(f).findLast(record => record.type === "permission.evaluate.before" &&
      (record.payload as { action?: string }).action === "shell");
    assert.equal((evaluated?.payload as { effect?: string } | undefined)?.effect, "allow", "host presented the native allow to the review hook");
  });
  await run("native allow safe allow and invalid user context", async () => {
    const f = await fixture({}, [{ action: "*", resource: "*", effect: "allow" }]);
    profile.reviewer = "ALLOW: fixture native-allow authorized"; calls.length = 0;
    await expectPermission(f, "allow", ["scp sample.txt destination:native-allow.txt"]);
    assert.deepEqual(calls, ["reviewer"]);
    const empty = (await api("/api/session", { location: { directory: f.directory }, agent: "build", title: "No-context native allow",
      model: { id: FIXTURE_AGENT_MODEL, providerID: FIXTURE_PROVIDER } })).data;
    calls.length = 0;
    const response = await permission({ ...f, sessionID: empty.id }, ["scp sample.txt destination:native-no-context.txt"]);
    assert.equal(response.effect, "ask", "unavailable user context fails closed to ask");
    await api(`/api/session/${empty.id}/permission/${response.id}/reply`, { decision: "reject" });
    assert.deepEqual(calls, [], "context failure happens before any generation");
    const records = await until(async () => auditRecords({ sessionID: empty.id }), value => value.some(record => record.errorKind === "context"));
    assert.equal(records.findLast(record => record.errorKind === "context")?.decision, "ask");
  });
  await run("saved Always is re-reviewed while permission entries stay unchanged", async () => {
    const f = await fixture();
    const resources = ["scp sample.txt destination:native-saved.txt"];
    await command(f, "off");
    const baseline = await savedApprovals(f);
    const first = await permission(f, resources);
    assert.equal(first.effect, "ask");
    await api(`/api/session/${f.sessionID}/permission/${first.id}/reply`, { decision: "always" });
    const saved = await until(() => savedApprovals(f), value => value.length > baseline.length);
    await command(f, "on"); profile.reviewer = "DENY: saved native allow must be re-reviewed"; calls.length = 0;
    await expectPermission(f, "deny", resources);
    assert.deepEqual(calls, ["reviewer"]);
    assert.deepEqual(await savedApprovals(f), saved, "review never deletes, rewrites or narrows saved approvals");
  });
  await run("exact hard tool.use policy denies a plugin-allowed native edit", async () => {
    const target = "fixture-policy-target.txt";
    const f = await fixture({}, [{ action: "*", resource: "*", effect: "allow" }], undefined, undefined,
      [{ action: "tool.use", resource: `edit:${target}`, effect: "deny" }]);
    writeFileSync(join(f.directory, target), "fixture original\n"); calls.length = 0;
    const response = await permission(f, [target], "edit");
    assert.equal(response.effect, "deny", "host policy is final even after the plugin allows the reviewed native allow");
    const evaluated = auditRecords(f).findLast(record => record.type === "permission.evaluate.before" &&
      (record.payload as { action?: string }).action === "edit");
    assert.ok(evaluated, "host invoked the evaluate stage before its final policy decision");
    assert.equal((evaluated.payload as { effect?: string }).effect, "allow");
    assert.equal((await summary(f)).decision, "allow", "plugin allowed the edit before the final policy block");
    assert.deepEqual(calls, [], "static classifier allowed the low-risk edit without a reviewer");
    assert.equal(readFileSync(join(f.directory, target), "utf8"), "fixture original\n");
  });
  await run("mode off passes native allow without a classifier", async () => {
    const f = await fixture({}, [{ action: "*", resource: "*", effect: "allow" }]);
    await command(f, "off"); profile.reviewer = "DENY: mode off must not review"; calls.length = 0;
    await expectPermission(f, "allow", ["scp sample.txt destination:native-off.txt"]);
    assert.deepEqual(calls, []);
  });
  await run("paused breaker asks native allow and passes native ask", async () => {
    const f = await fixture({ breaker: { consecutiveDenies: 1, windowDenies: 1, windowSize: 10 } },
      [{ action: "shell", resource: "*", effect: "allow" }, { action: "*", resource: "*", effect: "ask" }]);
    profile.reviewer = "DENY: fixture trips breaker"; calls.length = 0;
    await expectPermission(f, "deny", ["scp sample.txt destination:native-breaker.txt"]);
    assert.equal((await status(f)).mode, "paused");
    calls.length = 0;
    await expectPermission(f, "ask", ["scp sample.txt destination:native-paused.txt"]);
    await expectPermission(f, "ask", [".git/config"], "edit");
    assert.deepEqual(calls, [], "paused mode never reaches a classifier");
  });
  await run("reviewer timeout resolves native allow to ask", async () => {
    const f = await fixture({ classifiers: [{ type: "static" },
      { type: "llm", model: `${FIXTURE_PROVIDER}/${FIXTURE_REVIEWER_MODEL}`, timeoutMs: 100 }] },
      [{ action: "*", resource: "*", effect: "allow" }]);
    profile.timeout = true; calls.length = 0;
    await expectPermission(f, "ask", ["scp sample.txt destination:native-timeout.txt"]);
    assert.deepEqual(calls, ["reviewer"]);
    const record = await summary(f);
    assert.equal(record.decision, "ask"); assert.equal(record.errorKind, "timeout");
  });
  await run("actual execute bridge reviews native allow before execution", async () => {
    const f = await fixture({}, [{ action: "*", resource: "*", effect: "allow" }]);
    const code = `return await fetch(${JSON.stringify(`${endpoint}/marker/native-bridge`)}).then(r => r.text());`;
    profile.tool = { name: "execute", input: { code } };
    profile.reviewer = "DENY: fixture bridge veto"; profile.issued = false;
    calls.length = 0; const before = markers.length;
    await api(`/api/session/${f.sessionID}/prompt`, { text: "Run the requested scratch Code Mode fixture once." });
    await api(`/api/experimental/session/${f.sessionID}/wait`, {});
    assert.equal((await toolResult(f, "execute")).state.status, "error");
    assert.equal(markers.length, before, "denied native execute never runs its program");
    assert.deepEqual(calls, ["reviewer"]);
    profile.reviewer = "ALLOW: fixture bridge authorized"; profile.issued = false; calls.length = 0;
    await api(`/api/session/${f.sessionID}/prompt`, { text: "Run the same scratch Code Mode fixture after authorization." });
    await api(`/api/experimental/session/${f.sessionID}/wait`, {});
    assert.equal((await toolResult(f, "execute")).state.status, "completed");
    assert.equal(markers.length, before + 1);
    assert.deepEqual(calls, ["reviewer", "reviewer"], "allowed native execute and its inner webfetch are both reviewed");
  });
  writeFileSync(join(root, "results.json"), JSON.stringify({ version: info.version, results }, null, 2));
  console.log(`PASS ${results.length} v2 integration scenarios`);
} finally {
  host.kill("SIGTERM"); await Promise.race([once(host, "exit"), delay(3000)]);
  if (host.exitCode === null) host.kill("SIGKILL");
  provider.closeAllConnections(); await new Promise<void>((done) => provider.close(() => done()));
  writeFileSync(join(root, "host.log"), logs);
}
