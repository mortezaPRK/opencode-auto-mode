import console from "node:console";
import { access, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { ESLint } from "eslint";
import tseslint from "typescript-eslint";
import {
  COMPLEXITY_LIMITS,
  COMPLEXITY_RULE_IDS,
  COMPLEXITY_RULES,
} from "./complexity-policy.js";

const BASELINE_VERSION = 2;
const LINT_GLOB = "**/*.{js,mjs,cjs,ts,tsx,mts,cts}";
const DEFAULT_BASELINE = "scripts/complexity-baseline.json";

export function createComplexityEslint(cwd = process.cwd()) {
  return new ESLint({
    cwd,
    overrideConfigFile: true,
    // dist/** is generated and excluded here as well as in eslint.config.js.
    ignorePatterns: ["dist/**", "node_modules/**"],
    overrideConfig: [
      {
        files: [LINT_GLOB],
        languageOptions: {
          parser: tseslint.parser,
          parserOptions: {
            ecmaVersion: "latest",
            sourceType: "module",
            ecmaFeatures: { jsx: true },
          },
        },
        rules: COMPLEXITY_RULES,
      },
    ],
  });
}

function relativeFile(cwd, filePath) {
  const absolute = path.isAbsolute(filePath)
    ? filePath
    : path.resolve(cwd, filePath);
  return path.relative(cwd, absolute).split(path.sep).join("/");
}

function messageMetric(ruleId, message) {
  const patterns = {
    complexity: /complexity of (\d+)/,
    "max-lines-per-function": /too many lines \((\d+)\)/,
    "max-depth": /nested too deeply \((\d+)\)/,
  };
  const match = message.match(patterns[ruleId]);
  if (!match) {
    throw new Error(`Unrecognized ${ruleId} message: ${message}`);
  }
  return Number(match[1]);
}

function messageLabel(ruleId, message) {
  if (ruleId === "max-depth") return "block";
  const named = message.match(
    /\b(?:function|method|getter|setter|constructor)\s+'([^']+)'/i,
  );
  if (named) return named[1];
  if (/arrow function/i.test(message)) return "anonymous-arrow";
  return "anonymous";
}

/**
 * Violation identity is the ESLint-reported function/block start plus its
 * source position. Anonymous arrows, blocks, and repeated function names
 * therefore cannot share an exemption or replace each other in the sorted
 * metric vector.
 */
export function bucketKey(file, ruleId, label, line, column) {
  return `${file}::${ruleId}::${label}@${line}:${column}`;
}

export function parseBucketKey(key) {
  const [file, ruleId, ...parts] = key.split("::");
  const label = parts.join("::");
  const located = label.match(/^(.*)@(\d+):(\d+)$/);
  if (!located) return { file, ruleId, label };
  return {
    file,
    ruleId,
    label: located[1],
    line: Number(located[2]),
    column: Number(located[3]),
  };
}

/**
 * New scoring modules and this tooling must meet the strict limits directly.
 * They are never eligible for a legacy baseline entry.
 */
export function isProtectedPath(file) {
  return (
    file === "src/score.ts" ||
    file.startsWith("src/score/") ||
    file.startsWith("scripts/complexity")
  );
}

export function collectBuckets(results, cwd = process.cwd()) {
  const buckets = {};
  for (const result of results) {
    const file = relativeFile(cwd, result.filePath);
    for (const message of result.messages) {
      if (!message.ruleId || !COMPLEXITY_RULE_IDS.includes(message.ruleId)) {
        continue;
      }
      const key = bucketKey(
        file,
        message.ruleId,
        messageLabel(message.ruleId, message.message),
        message.line,
        message.column,
      );
      (buckets[key] ??= []).push(
        messageMetric(message.ruleId, message.message),
      );
    }
  }
  for (const values of Object.values(buckets)) {
    values.sort((a, b) => b - a);
  }
  return buckets;
}

/**
 * A bucket holds every exceedance for one file/rule/violation identity.
 * Identities include the ESLint-reported start location, so anonymous arrows,
 * duplicate function names, and separate depth blocks never share a bucket.
 * Values are sorted newest-first so improvements can pass without an update.
 * Moving a legacy violation changes its identity and needs a reviewed baseline
 * refresh; adding a different violation can never inherit its exemption.
 *
 * Tests are not exempt from the 60-line function limit: existing long test
 * callbacks are recorded as explicit legacy buckets, and new test callbacks
 * must stay within the same limit. Generated files (dist/**) are excluded.
 */
export function compareBuckets(current, baseline) {
  const failures = [];
  for (const [key, values] of Object.entries(current)) {
    const { file, ruleId, label } = parseBucketKey(key);
    if (isProtectedPath(file)) {
      failures.push({
        type: "protected",
        key,
        file,
        ruleId,
        label,
        baseline: [],
        current: values,
      });
      continue;
    }

    const allowed = baseline.buckets[key] ?? [];
    if (allowed.length === 0) {
      failures.push({
        type: "new",
        key,
        file,
        ruleId,
        label,
        baseline: allowed,
        current: values,
      });
      continue;
    }

    if (values.length > allowed.length) {
      failures.push({
        type: "new",
        key,
        file,
        ruleId,
        label,
        baseline: allowed,
        current: values,
      });
      continue;
    }

    for (let index = 0; index < values.length; index += 1) {
      if (values[index] > allowed[index]) {
        failures.push({
          type: "increased",
          key,
          file,
          ruleId,
          label,
          baseline: allowed,
          current: values,
          index,
        });
      }
    }
  }
  return failures;
}

export function createBaseline(buckets) {
  const safeBuckets = {};
  for (const [key, values] of Object.entries(buckets)) {
    if (!isProtectedPath(parseBucketKey(key).file)) {
      safeBuckets[key] = values;
    }
  }
  return {
    version: BASELINE_VERSION,
    limits: COMPLEXITY_LIMITS,
    buckets: Object.fromEntries(
      Object.entries(safeBuckets).sort(([a], [b]) => a.localeCompare(b)),
    ),
  };
}

export async function readBaseline(filePath) {
  const baseline = JSON.parse(await readFile(filePath, "utf8"));
  if (baseline.version !== BASELINE_VERSION) {
    throw new Error(
      `Unsupported complexity baseline version: ${baseline.version}`,
    );
  }
  for (const [name, value] of Object.entries(COMPLEXITY_LIMITS)) {
    if (baseline.limits?.[name] !== value) {
      throw new Error(
        `Complexity baseline limits are stale for '${name}' (${baseline.limits?.[name]} !== ${value}); update the baseline.`,
      );
    }
  }
  if (!baseline.buckets || typeof baseline.buckets !== "object") {
    throw new Error("Complexity baseline is missing its 'buckets' object.");
  }
  return baseline;
}

export function formatFailure(failure) {
  const location =
    failure.line === undefined ? "" : `:${failure.line}:${failure.column}`;
  const target = `${failure.file}${location} (${failure.ruleId}, ${failure.label})`;
  if (failure.type === "protected") {
    return `${target}: new scoring/tooling code must meet complexity <= ${COMPLEXITY_LIMITS.complexity}, lines <= ${COMPLEXITY_LIMITS.maxLinesPerFunction}, depth <= ${COMPLEXITY_LIMITS.maxDepth}; found ${failure.current.join(", ")}.`;
  }
  if (failure.type === "new") {
    return `${target}: new exceedance ${failure.current.join(", ")} is not in the legacy baseline.`;
  }
  return `${target}: legacy exceedance grew from ${failure.baseline.join(", ")} to ${failure.current.join(", ")}.`;
}

async function baselineExists(filePath) {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

function protectedFailures(buckets) {
  return Object.entries(buckets)
    .filter(([key]) => isProtectedPath(parseBucketKey(key).file))
    .map(([key, values]) => ({
      type: "protected",
      key,
      ...parseBucketKey(key),
      baseline: [],
      current: values,
    }));
}

function safeBuckets(buckets) {
  return Object.fromEntries(
    Object.entries(buckets).filter(
      ([key]) => !isProtectedPath(parseBucketKey(key).file),
    ),
  );
}

function printFailures(failures) {
  for (const failure of failures) {
    console.error(formatFailure(failure));
  }
}

export async function updateBaseline(baselinePath, buckets, cwd = process.cwd()) {
  const protectedViolations = protectedFailures(buckets);
  if (protectedViolations.length > 0) {
    printFailures(protectedViolations);
    throw new Error(
      "Refusing to update the complexity baseline: new scoring/tooling code still exceeds the strict limits.",
    );
  }

  const legacyBuckets = safeBuckets(buckets);
  if (await baselineExists(baselinePath)) {
    const baseline = await readBaseline(baselinePath);
    const failures = compareBuckets(legacyBuckets, baseline);
    if (failures.length > 0) {
      printFailures(failures);
      throw new Error(
        "Refusing to update the complexity baseline: fix new or increased exceedances first.",
      );
    }
  }

  const baseline = createBaseline(legacyBuckets);
  await writeFile(baselinePath, `${JSON.stringify(baseline, null, 2)}\n`);
  console.log(
    `Wrote ${Object.keys(baseline.buckets).length} complexity baseline buckets to ${path.relative(cwd, baselinePath)}.`,
  );
}

async function verifyBaseline(baselinePath, buckets) {
  const baseline = await readBaseline(baselinePath);
  const failures = compareBuckets(buckets, baseline);
  if (failures.length > 0) {
    printFailures(failures);
    throw new Error(
      `${failures.length} complexity violation(s) exceed the legacy baseline.`,
    );
  }
  console.log(
    `Complexity ratchet passed (${Object.keys(baseline.buckets).length} legacy buckets, limits: complexity <= ${COMPLEXITY_LIMITS.complexity}, lines <= ${COMPLEXITY_LIMITS.maxLinesPerFunction}, depth <= ${COMPLEXITY_LIMITS.maxDepth}).`,
  );
}

async function main(argv) {
  const update = argv.includes("--update");
  const baselineFlag = argv.indexOf("--baseline");
  const cwd = process.cwd();
  const baselinePath =
    baselineFlag === -1
      ? path.join(cwd, DEFAULT_BASELINE)
      : path.resolve(cwd, argv[baselineFlag + 1]);
  const eslint = createComplexityEslint(cwd);
  const results = await eslint.lintFiles([LINT_GLOB]);
  const buckets = collectBuckets(results, cwd);

  if (update) {
    await updateBaseline(baselinePath, buckets, cwd);
    return;
  }
  await verifyBaseline(baselinePath, buckets);
}

function isMainModule() {
  return (
    process.argv[1] !== undefined &&
    path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
  );
}

if (isMainModule()) {
  main(process.argv.slice(2)).catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
