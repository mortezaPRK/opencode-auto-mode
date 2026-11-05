import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { ESLint } from "eslint";
import {
  collectBuckets,
  compareBuckets,
  createBaseline,
  createComplexityEslint,
  isProtectedPath,
  parseBucketKey,
  updateBaseline,
} from "./complexity-lint.js";

const eslint = createComplexityEslint(process.cwd());

async function analyze(code, filePath) {
  const [result] = await eslint.lintText(code, {
    filePath,
    warnIgnored: false,
  });
  return collectBuckets([result], process.cwd());
}

function branches(count) {
  return Array.from(
    { length: count },
    (_, index) => `  if (value === ${index}) return ${index};`,
  ).join("\n");
}

function branchy(name, count = 10) {
  return `export function ${name}(value: number) {\n${branches(count)}\n  return -1;\n}\n`;
}

function branchyArrow(name, count = 10) {
  return `const ${name} = (value: number) => {\n${branches(count)}\n  return -1;\n};\n`;
}

function longFunction(name, lines = 62) {
  const statements = Array.from(
    { length: lines },
    (_, index) => `  const value${index} = ${index};`,
  ).join("\n");
  return `export function ${name}() {\n${statements}\n  return 0;\n}\n`;
}

function asBaseline(buckets) {
  return { buckets };
}

function onlyKey(buckets) {
  const keys = Object.keys(buckets);
  assert.equal(keys.length, 1, `expected one bucket, got ${keys.join(", ")}`);
  return keys[0];
}

const simple = "export function simple(value: number) {\n  return value > 0 ? 1 : 0;\n}\n";

const deep = `export function deeplyNested(value: number) {
  if (value) {
    if (value > 1) {
      if (value > 2) {
        if (value > 3) {
          if (value > 4) {
            return 1;
          }
        }
      }
    }
  }
  return 0;
}
`;

const deeper = `export function deeperNested(value: number) {
  if (value) {
    if (value > 1) {
      if (value > 2) {
        if (value > 3) {
          if (value > 4) {
            if (value > 5) {
              return 1;
            }
          }
        }
      }
    }
  }
  return 0;
}
`;

const emptyBaseline = { buckets: {} };

describe("complexity ratchet", () => {
  it("allows new simple functions and files", async () => {
    const buckets = await analyze(simple, "src/new-simple.ts");
    assert.deepEqual(buckets, {});
    assert.deepEqual(compareBuckets(buckets, emptyBaseline), []);
  });

  it("rejects a newly added complex function in a new file", async () => {
    const buckets = await analyze(branchy("newFunction"), "src/new-module.ts");
    const failures = compareBuckets(buckets, emptyBaseline);
    assert.ok(failures.some((failure) => failure.type === "new"));
    assert.ok(
      failures.some(
        (failure) =>
          failure.ruleId === "complexity" &&
          failure.label === "newFunction" &&
          failure.current[0] === 11,
      ),
    );
  });

  it("rejects a newly added complex function in a legacy file", async () => {
    const baselineBuckets = await analyze(branchy("legacy"), "src/legacy.ts");
    const buckets = await analyze(
      `${branchy("legacy")}${branchy("newlyAdded")}`,
      "src/legacy.ts",
    );
    const failures = compareBuckets(buckets, asBaseline(baselineBuckets));
    assert.ok(
      failures.some(
        (failure) => failure.type === "new" && failure.label === "newlyAdded",
      ),
    );
  });
});

describe("legacy complexity ratchet", () => {
  it("rejects an increase in an existing legacy function", async () => {
    const baselineBuckets = await analyze(
      branchy("legacy", 11),
      "src/legacy.ts",
    );
    const buckets = await analyze(branchy("legacy", 12), "src/legacy.ts");
    const failures = compareBuckets(buckets, asBaseline(baselineBuckets));
    assert.equal(failures.length, 1);
    assert.equal(failures[0].type, "increased");
    assert.deepEqual(failures[0].baseline, [12]);
    assert.deepEqual(failures[0].current, [13]);
  });

  it("allows a legacy function to become simpler without a baseline update", async () => {
    const baselineBuckets = await analyze(
      branchy("legacy", 25),
      "src/legacy.ts",
    );
    const buckets = await analyze(branchy("legacy"), "src/legacy.ts");
    assert.deepEqual(compareBuckets(buckets, asBaseline(baselineBuckets)), []);
  });

  it("keeps same-function identity when nonviolating body lines move", async () => {
    const baselineBuckets = await analyze(
      branchy("legacy", 12),
      "src/legacy.ts",
    );
    const moved = branchy("legacy", 12).replace(
      "  if (value === 0)",
      "  const note = 1;\n  if (value === 0)",
    );
    const buckets = await analyze(moved, "src/legacy.ts");
    assert.equal(onlyKey(buckets), onlyKey(baselineBuckets));
    assert.deepEqual(compareBuckets(buckets, asBaseline(baselineBuckets)), []);
  });
});

describe("ambiguous function identities", () => {
  it("rejects a replacement anonymous arrow even when it is simpler", async () => {
    const baselineBuckets = await analyze(
      branchyArrow("legacyArrow", 12),
      "src/arrows.ts",
    );
    const buckets = await analyze(
      `// replacement\n${branchyArrow("legacyArrow", 10)}`,
      "src/arrows.ts",
    );
    const failures = compareBuckets(buckets, asBaseline(baselineBuckets));
    assert.equal(failures.length, 1);
    assert.equal(failures[0].type, "new");
    assert.equal(failures[0].label, "anonymous-arrow");
    assert.deepEqual(failures[0].current, [11]);
  });

  it("separates duplicate named functions and rejects a replacement", async () => {
    const baselineBuckets = await analyze(
      `${branchy("duplicate", 12)}${branchy("duplicate", 10)}`,
      "src/duplicate.ts",
    );
    assert.equal(Object.keys(baselineBuckets).length, 2);
    const buckets = await analyze(
      `// replacement\n${branchy("duplicate", 10)}`,
      "src/duplicate.ts",
    );
    const failures = compareBuckets(buckets, asBaseline(baselineBuckets));
    assert.ok(
      failures.some(
        (failure) =>
          failure.type === "new" &&
          failure.ruleId === "complexity" &&
          failure.label === "duplicate",
      ),
    );
  });
});

describe("legacy function length ratchet", () => {
  it("rejects an increase in an existing legacy long function", async () => {
    const baselineBuckets = await analyze(
      longFunction("legacyLong", 61),
      "src/long.ts",
    );
    const buckets = await analyze(longFunction("legacyLong"), "src/long.ts");
    const failures = compareBuckets(buckets, asBaseline(baselineBuckets));
    assert.equal(failures.length, 1);
    assert.equal(failures[0].type, "increased");
  });

  it("allows an existing legacy long function within its baseline", async () => {
    const buckets = await analyze(longFunction("legacyLong"), "src/long.ts");
    assert.deepEqual(compareBuckets(buckets, asBaseline(buckets)), []);
  });
});

describe("legacy nesting depth ratchet", () => {
  it("allows a legacy nested function at its baseline depth", async () => {
    const buckets = await analyze(deep, "src/legacy-deep.ts");
    assert.deepEqual(compareBuckets(buckets, asBaseline(buckets)), []);
  });

  it("rejects a new depth block even when it replaces a deeper one", async () => {
    const baselineBuckets = await analyze(deeper, "src/legacy-deep.ts");
    const buckets = await analyze(`// replacement\n${deep}`, "src/legacy-deep.ts");
    const failures = compareBuckets(buckets, asBaseline(baselineBuckets));
    assert.equal(failures.length, 1);
    assert.equal(failures[0].type, "new");
    assert.equal(failures[0].ruleId, "max-depth");
    assert.equal(failures[0].label, "block");
    assert.deepEqual(failures[0].current, [5]);
  });

  it("allows a legacy nested function to become shallower", async () => {
    const baselineBuckets = await analyze(deeper, "src/legacy-deep.ts");
    const buckets = await analyze(deep, "src/legacy-deep.ts");
    assert.deepEqual(compareBuckets(buckets, asBaseline(baselineBuckets)), []);
  });
});

describe("complexity limits and protected paths", () => {
  it("rejects a new long function", async () => {
    const buckets = await analyze(longFunction("longNew"), "src/long.ts");
    const failures = compareBuckets(buckets, emptyBaseline);
    assert.ok(
      failures.some(
        (failure) =>
          failure.ruleId === "max-lines-per-function" &&
          failure.label === "longNew",
      ),
    );
  });

  it("rejects a new deeply nested function", async () => {
    const buckets = await analyze(deep, "src/deep.ts");
    const failures = compareBuckets(buckets, emptyBaseline);
    assert.ok(
      failures.some(
        (failure) =>
          failure.ruleId === "max-depth" && failure.label === "block",
      ),
    );
  });
});

describe("protected complexity paths", () => {
  it("never permits src/score modules to be grandfathered", async () => {
    const buckets = await analyze(
      branchy("mediumShell", 12),
      "src/score/shell-baseline.ts",
    );
    const failures = compareBuckets(buckets, asBaseline(buckets));
    assert.equal(failures.length, 1);
    assert.equal(failures[0].type, "protected");
    assert.equal(isProtectedPath("src/score/shell-baseline.ts"), true);
  });

  it("protects the src/score.ts public re-export explicitly", async () => {
    const buckets = await analyze(branchy("mediumShell", 12), "src/score.ts");
    const failures = compareBuckets(buckets, asBaseline(buckets));
    assert.equal(failures.length, 1);
    assert.equal(failures[0].type, "protected");
    assert.equal(isProtectedPath("src/score.ts"), true);
    const config = await new ESLint({ cwd: process.cwd() }).calculateConfigForFile(
      "src/score.ts",
    );
    assert.deepEqual(config.rules?.complexity, [2, 10]);
  });

  it("excludes protected buckets when creating a baseline", () => {
    const baseline = createBaseline({
      "src/legacy.ts::complexity::legacy@1:8": [11],
      "src/score.ts::complexity::mediumShell@1:8": [13],
      "src/score/shell-baseline.ts::complexity::mediumShell@1:8": [13],
      "scripts/complexity-lint.js::complexity::main@300:1": [11],
    });
    assert.deepEqual(Object.keys(baseline.buckets), [
      "src/legacy.ts::complexity::legacy@1:8",
    ]);
  });

  it("keeps bucket keys readable and parses their location", () => {
    assert.deepEqual(parseBucketKey("src/a.ts::complexity::named"), {
      file: "src/a.ts",
      ruleId: "complexity",
      label: "named",
    });
    assert.deepEqual(parseBucketKey("src/a.ts::max-depth::block@3:7"), {
      file: "src/a.ts",
      ruleId: "max-depth",
      label: "block",
      line: 3,
      column: 7,
    });
  });
});

describe("baseline updates", () => {
  it("does not write when protected code still exceeds the limits", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "complexity-update-"));
    try {
      const baselinePath = path.join(dir, "baseline.json");
      const original = `${JSON.stringify(createBaseline({}), null, 2)}\n`;
      await writeFile(baselinePath, original);
      await assert.rejects(
        updateBaseline(
          baselinePath,
          { "src/score.ts::complexity::run@1:1": [11] },
          process.cwd(),
        ),
        /strict limits/,
      );
      assert.equal(await readFile(baselinePath, "utf8"), original);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("does not write when a new exceedance is present", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "complexity-update-"));
    try {
      const baselinePath = path.join(dir, "baseline.json");
      const original = `${JSON.stringify(createBaseline({}), null, 2)}\n`;
      await writeFile(baselinePath, original);
      await assert.rejects(
        updateBaseline(
          baselinePath,
          { "src/legacy.ts::complexity::added@1:1": [11] },
          process.cwd(),
        ),
        /fix new or increased/,
      );
      assert.equal(await readFile(baselinePath, "utf8"), original);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
