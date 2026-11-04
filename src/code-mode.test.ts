import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { codeModeIdentity, codeModePermission, codeModeReviewResources } from "./code-mode.js";

const EXACT_CODE_CASES = [
  ['return "?";', 'return "x";'],
  ['return "*";', 'return "other program";'],
  ['return "https://fixture.invalid/a/b?x=*";', 'return "https://fixture.invalid/a/b?x=x";'],
  ['// first line\nreturn "*?";\n', '// first line\nreturn "xx";\n'],
  ['return /a\\/b/.test("a/b");', 'return /a\\/c/.test("a/b");'],
] as const;

describe("Code Mode exact permission identity", () => {
  for (const [code, changed] of EXACT_CODE_CASES) it(`exact program: ${JSON.stringify(code)}`, () => {
    const request = codeModePermission({ code });
    assert.deepEqual(request.resources, request.save);
    assert.match(request.resources[0], /^execute:sha256:[a-f0-9]{64}$/);
    assert.doesNotMatch(request.resources[0], /[?*]/);
    assert.deepEqual(codeModePermission(code), request);
    assert.notEqual(codeModeIdentity(changed), request.resources[0]);
    assert.deepEqual(codeModeReviewResources(request), [code]);
  });

  it("whitespace, slash and newline changes are not normalized", () => {
    const identities = ["return 1;", "return 1; ", "return 1;\n", "return 1;\r\n", "return 1;//"].map(codeModeIdentity);
    assert.equal(new Set(identities).size, identities.length);
  });

  it("rejects missing, non-string, blank and oversized executable inputs", () => {
    for (const input of [undefined, null, [], { code: 42 }, { code: "" }, { code: " \n" }, "é".repeat(32_769)])
      assert.throws(() => codeModePermission(input));
    assert.doesNotThrow(() => codeModePermission("a".repeat(65_536)));
  });

  it("only verified metadata can restore full reviewer evidence", () => {
    const request = codeModePermission('return "*?";');
    assert.throws(() => codeModeReviewResources({ ...request, metadata: undefined }));
    assert.throws(() => codeModeReviewResources({ ...request, resources: [codeModeIdentity("return 2;")] }));
    assert.throws(() => codeModeReviewResources({ ...request, resources: [...request.resources, "*"] }));
    assert.throws(() => codeModeReviewResources({ ...request, metadata: { opencodeAutoModeCode: { version: 1, identity: request.resources[0], code: "return 2;" } } }));
    assert.equal(codeModeReviewResources({ action: "read", resources: request.resources }), undefined);
    assert.equal(codeModeReviewResources({ action: "execute", resources: ["return 1;"] }), undefined);
  });
});
