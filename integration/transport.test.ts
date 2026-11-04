import { expect, test } from "bun:test";
import { completion, FIXTURE_REVIEWER_MODEL } from "./transport.js";

test("wire fixture emits real execute input without a shell wrapper", () => {
  const code = 'const literal = "saved?*";\nreturn literal;';
  const output = completion("", false, { name: "execute", input: { code } });
  const body = JSON.parse(output.body);
  expect(body.model).toBe(FIXTURE_REVIEWER_MODEL);
  const tool = body.choices[0].message.tool_calls[0].function;
  expect(tool.name).toBe("execute");
  expect(JSON.parse(tool.arguments)).toEqual({ code });
});

test("streaming shell fixture supplies exactly its configured tool input", () => {
  const input = { command: "pwd\nls", description: "Scratch multiline command" };
  const output = completion("", true, { name: "shell", input });
  expect(output.type).toBe("text/event-stream");
  const chunk = JSON.parse(output.body.split("\n\n")[0].replace(/^data: /, ""));
  const tool = chunk.choices[0].delta.tool_calls[0].function;
  expect(tool.name).toBe("shell");
  expect(JSON.parse(tool.arguments)).toEqual(input);
  expect(output.body.endsWith("data: [DONE]\n\n")).toBe(true);
});
