/** @jsxImportSource @opentui/solid */
import { createSignal, Show } from "solid-js";
import { Plugin } from "@opencode/plugin/tui";
import { readDecisions } from "./state.js";
import { isReviewing } from "./tui-state.js";

const SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

export default Plugin.define({
  id: "opencode-auto-mode",
  setup: async (ctx) => {
    if (ctx.options.tui === false) return;
    const [reviewing, setReviewing] = createSignal(false);
    const update = () => {
      const route = ctx.ui.router.current();
      setReviewing(isReviewing(readDecisions(), route.type === "session" ? route.sessionID : undefined));
    };
    update();
    const poll = setInterval(update, 250);
    const dispose = ctx.ui.slot({
      append: "app",
      render: () => (
        <Show when={reviewing()}>
          <box position="absolute" top={0} right={0} zIndex={10_000} flexDirection="row" gap={1}>
            <spinner frames={SPINNER_FRAMES} interval={120} color={ctx.theme.text.feedback.warning.base} />
            <text fg={ctx.theme.text.feedback.warning.base}>auto-mode reviewing</text>
          </box>
        </Show>
      ),
    });
    return () => { clearInterval(poll); dispose(); };
  },
});
