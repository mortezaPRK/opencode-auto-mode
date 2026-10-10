const routes = new Map([
  ["https://api.typesafe.ai/v1/systemone", "/jev"],
  ["https://api.openai.com/v1/decisions", "/openai-decision"],
]);
const installed = Symbol.for("opencode-auto-mode.integration.transport");

export default {
  id: "auto-mode-integration-transport",
  setup() {
    const endpoint = process.env.OPENCODE_AUTO_MODE_TEST_ENDPOINT;
    if (!endpoint || new URL(endpoint).hostname !== "127.0.0.1") throw new Error("Missing local test endpoint");
    if (Reflect.get(globalThis, installed)) return;
    const original = globalThis.fetch;
    globalThis.fetch = (input, init) => {
      const url = input instanceof Request ? input.url : String(input);
      const route = routes.get(url);
      return original(route ? `${endpoint}${route}` : input, init);
    };
    Reflect.set(globalThis, installed, true);
  },
};
