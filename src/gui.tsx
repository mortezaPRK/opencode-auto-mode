/** @jsxImportSource solid-js */
import { createSignal, onCleanup } from "solid-js";
import { ComposerPill, Plugin, createKeyed } from "@opencode/plugin/gui";
import { AutoMode, type AutoModeStatus } from "./rpc.js";
import { createDecisionNotifier, createDecisionSubscription, createModeRunner, createStatusLoader, pillAction, pillDescription, pillLabel, pillTone, statusTarget } from "./gui-state.js";

const POLL_MS = 1_000;

export default Plugin.define({
  setup(ctx) {
    const [status, setStatus] = createSignal<{ key: string; value: AutoModeStatus } | undefined>(undefined);
    const [revision, setRevision] = createSignal(0);
    // The desktop client reads its own server only. Never query that server for
    // a routed session belonging to a different server or an unknown location.
    const target = () => statusTarget(ctx.sessions.current());
    const refresh = createStatusLoader(
      (selected, signal) => ctx.client.rpc(AutoMode).status({ sessionID: selected.sessionID }, {
        location: selected.location, signal,
      }) as Promise<AutoModeStatus | undefined>,
      (value, selected) => {
        if (value === undefined) { setStatus(undefined); return; }
        if (selected !== undefined && target()?.key === selected.key) setStatus({ key: selected.key, value });
      },
    );
    const runner = createModeRunner(
      (selected, mode, signal) => {
        refresh.invalidate(); // An older poll must not overwrite a successful mutation.
        return ctx.client.rpc(AutoMode).setMode({ sessionID: selected.sessionID, mode }, {
          location: selected.location, signal,
        }) as Promise<AutoModeStatus>;
      },
      (selected, value) => {
        if (target()?.key === selected.key) setStatus({ key: selected.key, value });
      },
      () => ctx.toast.show({ title: "Auto-mode", description: "Could not change auto mode. Try again.", variant: "error", duration: 5_000 }),
      () => setRevision((value) => value + 1),
    );
    const receive = createDecisionNotifier(target, (notice) => {
      ctx.toast.show({ title: "Auto-mode", description: notice.message,
        variant: notice.kind === "deny" ? "error" : "default", duration: 5_000 });
    });
    const subscription = createDecisionSubscription(receive);
    const poll = () => {
      const client = ctx.client;
      subscription.update(client, (handler, signal) => client.rpc(AutoMode).events.on("decision", handler, { signal }));
      const selected = target();
      if (selected === undefined || !runner.pending(selected)) void refresh(selected);
    };
    createKeyed(() => target()?.key, poll, { otherwise: poll });
    const timer = setInterval(poll, POLL_MS);
    onCleanup(() => { clearInterval(timer); runner.dispose(); refresh.dispose(); subscription.dispose(); });

    ctx.add(ComposerPill, {
      id: "status",
      order: 20,
      show: (input) => {
        revision();
        const selected = statusTarget(input.session);
        const stored = status();
        const snapshot = selected?.ownServer && stored?.key === selected.key ? stored.value : undefined;
        const action = pillAction(snapshot);
        const pending = selected !== undefined && runner.pending(selected);
        const label = pending ? "changing auto mode…" : pillLabel(snapshot) ?? "status unavailable";
        const description = pillDescription(snapshot);
        return {
          label, tone: pillTone(snapshot),
          title: pending ? "Auto-mode: change pending"
            : description !== undefined ? `Auto-mode: ${description}`
              : action === undefined ? "Auto-mode unavailable" : `Auto-mode: ${action}`,
          // Capture this pill's session/location. Never consult the active route
          // inside a click handler: cached composers and session switches differ.
          run: !pending && action !== undefined && selected?.ownServer
            ? () => { void runner.run(selected, action); } : undefined,
        };
      },
    });
  },
});
