import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

// Specific production provider/model families, not a blanket slash ban.
// Fake fixture IDs, package imports, paths and <provider>/<model> are valid.
const productionModel = /\b(?:openai|anthropic|google|google-vertex|opencode|typesafe-ai|deepseek|xai|groq|openrouter)\/(?:gpt[-\w.]*|o[134][\w.-]*|claude[-\w.]*|gemini[-\w.]*|jev[-\w.]*|deepseek[-\w.]*|grok[-\w.]*)/i;
// 1.1.0 has no remote telemetry endpoint option, so a concrete JSON endpoint is
// always treated as private configuration. Placeholders and reserved domains are
// still allowed for documentation.
const personalEndpoint = /https?:\/\/(?:api\.(?:openai\.com|anthropic\.com|typesafe\.ai)|127\.0\.0\.1:(?:8000|8001|4317|3000))(?:[/"'\s]|$)/i;
const literalModelDefault = /(?:reviewerModel|decisionModel)\s*(?:\?\?|\|\|)\s*["'][^<][^"']*["']|DEFAULT_(?:REVIEWER_)?MODEL\s*=\s*["'][^<][^"']*["']/i;
const literalEndpointDefault = /(?:endpoint\s*(?:\?\?|\|\|)|DEFAULT_(?:DECISION_|OTLP_)?ENDPOINT\s*=)\s*["']https?:\/\//i;
// Known credential token families and private-key material are never valid
// documentation examples, even when they look like fixtures.
const credentialToken = /\b(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,}|-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----)/;
// Quoted credential assignments in JSON/JSONC, object literals, and shell-like
// snippets. The key must stand alone so OPENCODE_SERVER_PASSWORD is not matched
// from its suffix; fixture values are checked by concreteCredential below.
const credentialAssignment = /(?<![A-Za-z0-9_])(?:api[_-]?key|apiKey|client[_-]?secret|clientSecret|access[_-]?token|accessToken|auth[_-]?token|authToken|token|password|passwd|secret)\s*[:=]\s*["']([^"'\n]+)["']/gi;
// Allowlist-shaped JSON keys and literal defaults. Any concrete entry is private
// configuration; empty arrays and placeholders remain valid documentation.
const allowlistKey = /"(?:allowlist|allowedHosts|allowHosts|fetchHosts|allowedModels|allowedEndpoints|allowedPaths|hostAllowlist)"\s*:\s*\[([^\]]*)\]/gi;
const literalAllowlistDefault = /(?:DEFAULT_)?(?:ALLOWLIST|ALLOWED_HOSTS|ALLOW_HOSTS|FETCH_HOSTS)\s*=\s*\[([^\]]*)\]/gi;
// JSON examples are checked separately because quoted option values are not
// covered by the literal fallback/constant patterns above.
const jsonModel = /"(?:model|reviewerModel)"\s*:\s*"([^"]+)"/g;
const jsonEndpoint = /"endpoint"\s*:\s*"([^"]+)"/g;
const placeholder = /[<>]|\$\{|^\{(?:env|file):/i;
// Only these documented fixture/test prefixes are exempt from concrete-model
// detection; arbitrary provider IDs are treated as private configuration.
const fixturePrefix = /^(?:fixture|test|fake|mock|example|sample|invented|toy|dummy|stub|scratch)(?:[-_.]|$)/i;
// Same exemption for credential values, extended to any separator-delimited
// fixture word (for example p2-scratch-only or fixture-private-credential).
const fixtureValue = /(?:^|[-_.])(?:fixture|test|fake|mock|example|sample|invented|toy|dummy|stub|scratch)(?:[-_.]|$)/i;
// Uppercase-only names are test constants such as TOY_SECRET, not secrets.
const constantValue = /^[A-Z][A-Z0-9_]*$/;
const genericModel = /^(?:provider|your-provider)\/(?:model|your-model|reviewer-model|decision-model)(?:#[\w.-]+)?$/i;
// Reserved documentation domains and generic placeholders are safe examples;
// other concrete JSON endpoint hosts are treated as private configuration.
const reservedHost = /(?:^|\.)(?:example\.(?:com|net|org)|invalid|test|example)$/i;
function concreteModel(value: string): boolean {
  if (placeholder.test(value) || genericModel.test(value)) return false;
  const [provider, id] = value.split("/", 2);
  return Boolean(provider && id && !fixturePrefix.test(provider) && !fixturePrefix.test(id));
}
function concreteCredential(value: string): boolean {
  const trimmed = value.trim();
  return trimmed.length > 0 && !placeholder.test(trimmed) && !fixtureValue.test(trimmed) && !constantValue.test(trimmed);
}
function concreteAllowlist(body: string): boolean {
  return [...body.matchAll(/["']([^"']+)["']/g)]
    .some((match) => match[1].trim().length > 0 && !placeholder.test(match[1]) && !fixtureValue.test(match[1]));
}
function privateEndpoint(value: string): boolean {
  if (placeholder.test(value)) return false;
  let url: URL;
  try { url = new URL(value); } catch { return false; }
  if (!["http:", "https:"].includes(url.protocol) || reservedHost.test(url.hostname)) return false;
  return true;
}
function files(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? files(path) : /\.(?:tsx?|md|jsonc?)$/.test(entry.name) ? [path] : [];
  });
}
export function personalDefaults(text: string): boolean {
  if ([productionModel, personalEndpoint, credentialToken, literalModelDefault, literalEndpointDefault]
    .some((pattern) => pattern.test(text))) return true;
  for (const match of text.matchAll(credentialAssignment)) if (concreteCredential(match[1])) return true;
  for (const match of text.matchAll(allowlistKey)) if (concreteAllowlist(match[1])) return true;
  for (const match of text.matchAll(literalAllowlistDefault)) if (concreteAllowlist(match[1])) return true;
  for (const match of text.matchAll(jsonModel)) if (concreteModel(match[1])) return true;
  for (const match of text.matchAll(jsonEndpoint)) if (privateEndpoint(match[1])) return true;
  return false;
}
describe("no personal model, endpoint, credential, or allowlist defaults", () => {
  test("allows placeholders, imports, paths and explicit invented fixture IDs", () => {
    expect(personalDefaults('reviewerModel: "<provider>/<model>"; model: "fixture/judge"; import "@opencode/plugin"; /project/file')).toBe(false);
    expect(personalDefaults('baseURL: `http://127.0.0.1:${port}/v1`')).toBe(false);
    expect(personalDefaults(["reviewerModel", "??", JSON.stringify("fixture/judge")].join(" "))).toBe(true);
    expect(personalDefaults(["endpoint", "||", JSON.stringify("https://fixture.invalid")].join(" "))).toBe(true);
  });
  test("checks concrete JSON model and endpoint values without banning fixtures", () => {
    // Build the hypothetical private provider at runtime so this test does not
    // itself carry a complete personal-looking reference.
    const hypotheticalProvider = ["hypothetical", "provider"].join("-");
    const hypotheticalModel = `${hypotheticalProvider}/concrete-model`;
    const hypotheticalEndpoint = ["https://collector", "internal:8200"].join(".");
    const nonStandardLoopback = ["http://127", "0", "0", "1:8200"].join(".");
    expect(personalDefaults(JSON.stringify({ classifiers: [{ type: "llm", model: hypotheticalModel }] }))).toBe(true);
    expect(personalDefaults(JSON.stringify({ reviewerModel: hypotheticalModel }))).toBe(true);
    expect(personalDefaults(JSON.stringify({ endpoint: hypotheticalEndpoint }))).toBe(true);
    expect(personalDefaults(JSON.stringify({ endpoint: nonStandardLoopback }))).toBe(true);
    expect(personalDefaults(`const model = "${hypotheticalModel}";`)).toBe(false);
    expect(personalDefaults(JSON.stringify({ classifiers: [{ type: "llm", model: "<provider>/<model>" }] }))).toBe(false);
    expect(personalDefaults(JSON.stringify({ classifiers: [{ type: "llm", model: "provider/model" }] }))).toBe(false);
    expect(personalDefaults(JSON.stringify({ classifiers: [{ type: "llm", model: "your-provider/your-model" }] }))).toBe(false);
    expect(personalDefaults(JSON.stringify({ endpoint: "<collector-url>" }))).toBe(false);
    expect(personalDefaults('{"endpoint":"${COLLECTOR_URL}"}')).toBe(false);
    expect(personalDefaults(JSON.stringify({ classifiers: [{ type: "llm", model: "fixture/test-model" }] }))).toBe(false);
    expect(personalDefaults(JSON.stringify({ classifiers: [{ type: "llm", model: "test-provider/test-model" }] }))).toBe(false);
    expect(personalDefaults(JSON.stringify({ reviewerModel: "fixture/reviewer-model" }))).toBe(false);
    expect(personalDefaults('{"endpoint":"https://example.invalid/v1/metrics"}')).toBe(false);
    expect(personalDefaults('{"endpoint":"https://collector.example.com"}')).toBe(false);
    const collectorPort = ["http://localhost", "4318/v1/metrics"].join(":");
    const loopbackPort = ["http://127", "0", "0", "1:4318"].join(".");
    expect(personalDefaults(JSON.stringify({ endpoint: collectorPort }))).toBe(true);
    expect(personalDefaults(JSON.stringify({ endpoint: loopbackPort }))).toBe(true);
  });
  test("checks credentials and allowlists without banning fixtures", () => {
    // Build the hypothetical values at runtime so this test file is itself a
    // valid member of the scanned checkout.
    const hypotheticalKey = ["sk", "proj", "A1b2C3d4E5f6G7h8I9j0"].join("-");
    const hypotheticalHost = ["collector", "internal"].join(".");
    expect(personalDefaults(`apiKey: "${hypotheticalKey}"`)).toBe(true);
    expect(personalDefaults(`const apiKey = "${hypotheticalKey}";`)).toBe(true);
    expect(personalDefaults(`authorization: Bearer ${hypotheticalKey}`)).toBe(true);
    expect(personalDefaults(JSON.stringify({ allowlist: [hypotheticalHost] }))).toBe(true);
    expect(personalDefaults(JSON.stringify({ fetchHosts: ["*"] }))).toBe(true);
    expect(personalDefaults(`DEFAULT_ALLOWED_HOSTS = [${JSON.stringify(hypotheticalHost)}]`)).toBe(true);
    expect(personalDefaults('apiKey: "fixture-key"')).toBe(false);
    expect(personalDefaults('apiKey: "fixture"')).toBe(false);
    expect(personalDefaults('password: "TOY_SECRET"')).toBe(false);
    expect(personalDefaults('secret: "RAW_PERMISSION_SECRET"')).toBe(false);
    expect(personalDefaults('OPENCODE_SERVER_PASSWORD: "p2-scratch-only"')).toBe(false);
    expect(personalDefaults(JSON.stringify({ allowlist: ["<host>"] }))).toBe(false);
    expect(personalDefaults(JSON.stringify({ allowlist: [] }))).toBe(false);
    expect(personalDefaults(JSON.stringify({ fetchHosts: ["fixture.invalid"] }))).toBe(false);
  });
  test("scanned checkout sources and docs have no personal defaults", () => {
    // Exact coverage: package metadata, the three maintained root docs, and every
    // maintained source/script/integration .ts, .md, .json, or .jsonc file.
    // Build output, dependencies, lockfiles, and license text are not scanned.
    const paths = ["package.json", "README.md", "README.llm.md", "CONTRIBUTING.md",
      "scripts/dev-reload.sh", ...files("src"), ...files("scripts"), ...files("integration")];
    expect(paths.filter((path) => personalDefaults(readFileSync(path, "utf8")))).toEqual([]);
  });
});
