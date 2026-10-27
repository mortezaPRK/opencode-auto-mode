/** @jsxImportSource @opentui/solid */
import { createSignal, Show } from "solid-js";
import { Plugin } from "@opencode/plugin/tui";
import { readConfigError, readDecisions } from "./state.js";
import { isReviewing } from "./tui-state.js";

const SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

export default Plugin.define({
  id: "opencode-auto-mode",
  setup: async (ctx) => {
    if (ctx.options.tui === false) return;
    const [reviewing, setReviewing] = createSignal(false);
    const [configError, setConfigError] = createSignal(false);
    let announced = false;
    const update = () => {
      const route = ctx.ui.router.current();
      setReviewing(isReviewing(readDecisions(), route.type === "session" ? route.sessionID : undefined));
      const error = readConfigError(ctx.location?.directory);
      setConfigError(error !== undefined);
      if (error === undefined) announced = false;
      else if (!announced) {
        announced = true;
        ctx.ui.toast.show({
          variant: "error", title: "auto-mode", duration: 10_000,
          message: "Invalid configuration; automatic approval is disabled.",
        });
      }
    };
    update();
    const poll = setInterval(update, 250);
    const dispose = ctx.ui.slot({
      append: "app",
      render: () => (
        <box position="absolute" top={0} right={0} zIndex={10_000} flexDirection="row" gap={1}>
          <Show when={configError()}>
            <text fg={ctx.theme.text.feedback.error.base}>auto-mode: invalid config</text>
          </Show>
          <Show when={reviewing()}>
            <spinner frames={SPINNER_FRAMES} interval={120} color={ctx.theme.text.feedback.warning.base} />
            <text fg={ctx.theme.text.feedback.warning.base}>auto-mode reviewing</text>
          </Show>
        </box>
      ),
    });
    return () => { clearInterval(poll); dispose(); };
  },
});
