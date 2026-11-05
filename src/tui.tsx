/** @jsxImportSource @opentui/solid */
import { createEffect, createSignal, Show } from "solid-js";
import { Plugin } from "@opencode/plugin/tui";
import { AutoMode, type AutoModeStatus } from "./rpc.js";
import { createDecisionNotifier, createDecisionSubscription, createStatusLoader, pillDescription, pillLabel, pillTone, statusLocationKey, type StatusTarget } from "./gui-state.js";

const POLL_MS = 1_000;

export default Plugin.define({
  id: "opencode-auto-mode",
  setup: (ctx) => {
    if (ctx.options.tui === false) return;
    const [status, setStatus] = createSignal<AutoModeStatus | undefined>(undefined);
    const refresh = createStatusLoader(
      (target, signal) => ctx.client.rpc(AutoMode).status({ sessionID: target.sessionID }, {
        location: target.location, signal,
      }) as Promise<AutoModeStatus | undefined>,
      setStatus,
    );
    const target = (): StatusTarget | undefined => {
      const route = ctx.ui.router.current();
      const location = ctx.location ?? ctx.data.location.default();
      return route.type === "session" && location !== undefined
        ? { key: statusLocationKey(route.sessionID, location), sessionID: route.sessionID, ownServer: true, location }
        : undefined;
    };
    const receive = createDecisionNotifier(target, (notice) => {
      ctx.ui.toast.show({ title: "Auto-mode", message: notice.message,
        variant: notice.kind === "deny" ? "error" : "warning", duration: 5_000 });
    });
    const subscription = createDecisionSubscription(receive);
    const update = () => {
      const client = ctx.client;
      subscription.update(client, (handler, signal) => client.rpc(AutoMode).events.on("decision", handler, { signal }));
      void refresh(target());
    };
    const poll = setInterval(update, POLL_MS);
    const dispose = ctx.ui.slot({
      append: "prompt.footer.status",
      render: () => {
        // Router changes refresh immediately, independently of the timer.
        createEffect(update);
        const color = () => {
          const tone = pillTone(status());
          if (tone === "danger") return ctx.theme.text.feedback.error.base;
          if (tone === "warning") return ctx.theme.text.feedback.warning.base;
          return ctx.theme.text.base;
        };
        return (
          <Show when={pillLabel(status())}>
            <text fg={color()}>auto-mode: {pillDescription(status()) ?? pillLabel(status())}</text>
          </Show>
        );
      },
    });
    return () => { clearInterval(poll); refresh.dispose(); subscription.dispose(); dispose(); };
  },
});
