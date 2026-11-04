import { it } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, linkSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadGlobalOptions } from "./global-options.js";
import { parseOptions } from "./config.js";

const pluginDirectory = realpathSync(fileURLToPath(new URL("..", import.meta.url)));
const packageName = (JSON.parse(readFileSync(join(pluginDirectory, "package.json"), "utf8")) as { name: string }).name;
const model = "test-provider/test-model";
const defaults = { classifiers: [{ type: "static" }] };
function fixture(run: (root: string, config: string) => void): void {
  const root = mkdtempSync(join(realpathSync(tmpdir()), "auto-mode-global-"));
  const previous = process.env.XDG_CONFIG_HOME;
  process.env.XDG_CONFIG_HOME = root;
  const config = join(root, "opencode", "opencode.jsonc");
  mkdirSync(join(root, "opencode"));
  try { run(root, config); }
  finally {
    if (previous === undefined) delete process.env.XDG_CONFIG_HOME;
    else process.env.XDG_CONFIG_HOME = previous;
    rmSync(root, { recursive: true, force: true });
  }
}
function registration(config: string, name = packageName, options: unknown = defaults): void {
  writeFileSync(config, JSON.stringify({ plugins: [{ package: name, options }] }), { mode: 0o600 });
}
it("loads only global options, ignoring a hostile project re-registration", () => fixture((root, config) => {
  registration(config);
  const project = join(root, "project");
  mkdirSync(project);
  registration(join(project, "opencode.jsonc"), packageName, { classifiers: [{ type: "llm", model }], tui: false });
  assert.deepEqual(loadGlobalOptions(project), defaults);
  assert.equal(parseOptions(loadGlobalOptions(project)).tui, true);
}));
it("supports JSONC, package version suffixes, and exact local package identity", () => fixture((root, config) => {
  writeFileSync(config, `{ // user owned\n "plugins": [{"package": ${JSON.stringify(packageName + "@^2")}, "options": {"classifiers":[{"type":"static"},],},},],}`);
  assert.deepEqual(parseOptions(loadGlobalOptions(join(root, "project"))).classifiers, [{ type: "static" }]);
  registration(config, pluginDirectory, { audit: { enabled: true } });
  assert.deepEqual(loadGlobalOptions(join(root, "project")), { audit: { enabled: true } });
}));
it("fails closed for missing, lookalike and duplicate registrations", () => fixture((root, config) => {
  const project = join(root, "project");
  assert.throws(() => loadGlobalOptions(project), /not registered/);
  registration(config, packageName + "-lookalike");
  assert.throws(() => loadGlobalOptions(project), /not registered/);
  registration(config);
  registration(join(root, "opencode", "opencode.json"));
  assert.throws(() => loadGlobalOptions(project), /Ambiguous/);
}));
it("rejects project-resident globals and global symlinks to project files", () => fixture((root, config) => {
  registration(config);
  assert.throws(() => loadGlobalOptions(root), /outside the repository/);
  rmSync(config);
  const project = join(root, "project");
  mkdirSync(project);
  const malicious = join(project, "options.json");
  registration(malicious);
  symlinkSync(malicious, config);
  assert.throws(() => loadGlobalOptions(project), /outside the repository|symlink/);
}));
it("rejects writable and hardlinked global files and symlink parents", () => fixture((root, config) => {
  const project = join(root, "project");
  registration(config);
  chmodSync(config, 0o666);
  assert.throws(() => loadGlobalOptions(project), /writable/);
  chmodSync(config, 0o600);
  linkSync(config, join(root, "alias"));
  assert.throws(() => loadGlobalOptions(project), /single-linked/);
  rmSync(join(root, "alias"));
  chmodSync(join(root, "opencode"), 0o777);
  assert.throws(() => loadGlobalOptions(project), /writable/);
  chmodSync(join(root, "opencode"), 0o700);
  const alias = join(root, "config-alias");
  symlinkSync(join(root, "opencode"), alias);
  process.env.XDG_CONFIG_HOME = alias;
  mkdirSync(join(root, "opencode", "opencode"));
  registration(join(root, "opencode", "opencode", "opencode.jsonc"));
  assert.throws(() => loadGlobalOptions(project), /symlink/);
}));
it("rejects unresolved substitutions recursively without expanding them", () => fixture((root, config) => {
  const project = join(root, "project");
  for (const options of [
    { classifiers: [{ type: "llm", model: "{env:MODEL}" }] },
    { classifiers: [{ type: "decision", model: "prefix-{file:model}" }] },
    { audit: { enabled: "{env:AUDIT_ENABLED}" } },
    { audit: { maxBytes: "{env:AUDIT_MAX_BYTES}" } },
    { tui: "{env:TUI}" },
    { breaker: { consecutiveDenies: "{env:N}", windowDenies: 2, windowSize: 3 } },
  ]) {
    registration(config, packageName, options);
    assert.throws(() => loadGlobalOptions(project), /unsupported env\/file substitution/);
  }
  registration(config, packageName + "@{env:PLUGIN_VERSION}");
  assert.throws(() => loadGlobalOptions(project), /unsupported env\/file substitution/);
  registration(config, "{file:plugin-registration}");
  assert.throws(() => loadGlobalOptions(project), /unsupported env\/file substitution/);
}));
it("does not accept superseded or unknown schema through global provenance", () => fixture((root, config) => {
  registration(config, packageName, { reviewerModel: "<provider>/<model>" });
  assert.throws(() => parseOptions(loadGlobalOptions(join(root, "project"))), /Unknown auto-mode option 'reviewerModel'/);
  registration(config, packageName, { unsafe: true });
  assert.throws(() => parseOptions(loadGlobalOptions(join(root, "project"))), /Unknown auto-mode option 'unsafe'/);
}));
