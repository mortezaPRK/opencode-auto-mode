/** @jsxImportSource solid-js */
import { createSignal, onCleanup } from "solid-js";
import { ComposerPill, Plugin, createKeyed, type ComposerPillProps } from "@opencode/plugin/gui";
import { AutoMode, type AutoModeAction, type AutoModeStatus } from "./rpc.js";
import { createDecisionNotifier, createDecisionSubscription, createModeRunner, createStatusLoader, pillAction, pillDescription, pillLabel, pillTone, statusTarget, type StatusTarget } from "./gui-state.js";

const POLL_MS = 1_000;

interface PillState {
  revision: () => void;
  stored: () => { key: string; value: AutoModeStatus } | undefined;
  pending: (target: StatusTarget) => boolean;
  run: (target: StatusTarget, action: AutoModeAction) => Promise<void>;
}

function pillSnapshot(selected: StatusTarget | undefined, stored: { key: string; value: AutoModeStatus } | undefined): AutoModeStatus | undefined {
  if (selected === undefined || !selected.ownServer || stored === undefined || stored.key !== selected.key) return undefined;
  return stored.value;
}

function pillTitle(pending: boolean, description: string | undefined, action: AutoModeAction | undefined): string {
  if (pending) return "Auto-mode: change pending";
  if (description !== undefined) return `Auto-mode: ${description}`;
  if (action === undefined) return "Auto-mode unavailable";
  return `Auto-mode: ${action}`;
}

function pillRun(
  pending: boolean,
  action: AutoModeAction | undefined,
  selected: StatusTarget | undefined,
  run: PillState["run"],
): (() => void) | undefined {
  if (pending || action === undefined || selected === undefined || !selected.ownServer) return undefined;
  // Capture this pill's session/location. Never consult the active route
  // inside a click handler: cached composers and session switches differ.
  const target = selected;
  return () => { void run(target, action); };
}

function pillView(input: ComposerPillProps, state: PillState) {
  state.revision();
  const selected = statusTarget(input.session);
  const snapshot = pillSnapshot(selected, state.stored());
  const action = pillAction(snapshot);
  const pending = selected !== undefined && state.pending(selected);
  const label = pending ? "changing auto mode…" : pillLabel(snapshot) ?? "status unavailable";
  return {
    label, tone: pillTone(snapshot),
    title: pillTitle(pending, pillDescription(snapshot), action),
    run: pillRun(pending, action, selected, state.run),
  };
}

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

    const state: PillState = {
      revision: () => { revision(); },
      stored: status,
      pending: (selected) => runner.pending(selected),
      run: (selected, action) => runner.run(selected, action),
    };
    ctx.add(ComposerPill, {
      id: "status",
      order: 20,
      show: (input) => pillView(input, state),
    });
  },
});
