import assert from "node:assert/strict";
import { codeModePermission } from "../src/code-mode.js";

/** Run against an already isolated real server, with automation off and an ask
 * baseline. createSession MUST use a fresh project/location each time: native
 * Always entries are location/project-scoped, not confined to a session.
 * Only synthetic permission requests are made; no JavaScript is executed.
 */
export async function codeModeIdentityRegression(harness: {
  createSession(): Promise<string>;
  api(path: string, body?: unknown): Promise<unknown>;
}) {
  type Response = { data: { id: string; effect: string; resources: string[]; metadata?: Record<string, unknown> } };
  const request = async (sessionID: string, input: ReturnType<typeof codeModePermission>) =>
    (await harness.api(`/api/session/${sessionID}/permission`, input) as Response).data;
  const reply = async (sessionID: string, id: string, decision: "always" | "reject") =>
    harness.api(`/api/session/${sessionID}/permission/${id}/reply`, { decision });
  for (const [code, changed] of [
    ['return "?";', 'return "x";'],
    ['return "*";', 'return "other";'],
    ['return "https://fixture.invalid/a/b?x=*";', 'return "https://fixture.invalid/a/b?x=x";'],
    ['// line one\nreturn "*?";\n', '// line one\nreturn "xx";\n'],
  ]) {
    const sessionID = await harness.createSession();
    const input = codeModePermission({ code });
    const first = await request(sessionID, input);
    assert.equal(first.effect, "ask");
    const pending = await harness.api(`/api/session/${sessionID}/permission/${first.id}`) as Response;
    assert.deepEqual(pending.data.resources, input.resources);
    assert.deepEqual(pending.data.metadata, input.metadata, "actual source retained in native permission metadata");
    await reply(sessionID, first.id, "always");
    assert.equal((await request(sessionID, input)).effect, "allow", "identical source uses its native saved approval");
    const different = await request(sessionID, codeModePermission({ code: changed }));
    assert.equal(different.effect, "ask", "changed source cannot match a saved exact identity");
    await reply(sessionID, different.id, "reject");
  }
}
