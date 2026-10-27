/** @jsxImportSource solid-js */
import { createSignal, For } from "solid-js";
import { Command, ComposerPill, Panel, Plugin, createKeyed, type PanelTab } from "@opencode/plugin/gui";
import { AutoMode, type AutoModeDecision, type AutoModeStatus } from "./rpc.js";

const POLL_MS = 3_000;
const NOTICE_MS = 30_000;

const TONE: Record<string, "success" | "warning" | "danger" | undefined> = {
  allow: "success",
  ask: "warning",
  deny: "danger",
};

function latest(status: AutoModeStatus | undefined): AutoModeDecision | undefined {
  return status?.recent.at(-1);
}

function pillLabel(status: AutoModeStatus | undefined): string | undefined {
  if (status === undefined) return undefined;
  if (status.reviewing.length > 0) return "auto-mode reviewing…";
  const last = latest(status);
  if (last === undefined) return undefined;
  if (last.errorKind !== undefined) return `auto-mode ${last.decision}: ${last.errorKind}`;
  return `auto-mode ${last.decision}`;
}

export default Plugin.define({
  i18n: {
    en: {
      "command.open": "Open auto-mode decisions",
      "panel.title": "Auto-mode",
      "panel.empty": "No decisions in this session yet.",
      "panel.disabled": "Auto-mode has no valid configuration; every action is asked.",
      "panel.reviewing": "Reviewing…",
      "pill.title": "Auto-mode decisions",
    },
  },
  setup(ctx) {
    const [status, setStatus] = createSignal<AutoModeStatus | undefined>(undefined);
    let loaded = false;

    const refresh = async () => {
      const session = ctx.sessions.current();
      if (!session) return;
      try {
        const client = ctx.client.rpc(AutoMode);
        setStatus((await client.status({ sessionID: session.id })) as AutoModeStatus | undefined);
        loaded = true;
      } catch {
        // The server may be restarting; keep the last snapshot rather than flashing.
        if (!loaded) setStatus(undefined);
      }
    };

    createKeyed(() => ctx.sessions.current()?.id, () => { void refresh(); });
    const timer = setInterval(() => { void refresh(); }, POLL_MS);

    const tab: PanelTab = {
      id: "decisions",
      get title() { return ctx.t("panel.title"); },
      closable: "compact",
      fallback: true,
    };

    ctx.add(Panel, {
      id: "decisions",
      region: "side",
      mobile: { get title() { return ctx.t("panel.title"); }, order: 60, kind: "menu", icon: "shield" },
      list: (input) => (input.open.includes("decisions") ? [tab] : []),
      render: () => (
        <div style={{ padding: "8px 12px", "font-size": "12px", display: "flex", "flex-direction": "column", gap: "6px" }}>
          {status()?.enabled === false
            ? <div>{ctx.t("panel.disabled")}</div>
            : null}
          {status() === undefined
            ? <div>{ctx.t("panel.empty")}</div>
            : (
              <>
                <For each={[...(status()?.reviewing ?? [])]}>
                  {(entry) => <div>{ctx.t("panel.reviewing")} {entry.reviewID}</div>}
                </For>
                <For each={[...(status()?.recent ?? [])].reverse()}>
                  {(entry) => (
                    <div style={{ display: "flex", "flex-direction": "column", gap: "2px" }}>
                      <span style={{ "font-weight": 600 }}>
                        {entry.decision}{entry.errorKind === undefined ? "" : ` (${entry.errorKind})`} · {entry.action}
                      </span>
                      <span>{entry.reason}</span>
                      <span style={{ opacity: 0.6 }}>
                        {entry.stage} · {Math.round(entry.durationMs)}ms · {new Date(entry.at).toLocaleTimeString()}
                      </span>
                    </div>
                  )}
                </For>
              </>
            )}
        </div>
      ),
    });

    ctx.add(Command, () => ({
      id: "open",
      title: ctx.t("command.open"),
      group: "tools",
      run: () => {
        const session = ctx.sessions.current();
        if (session) ctx.layout.toggle(`${ctx.id}:decisions`, session);
      },
    }));

    ctx.add(ComposerPill, {
      id: "status",
      order: 20,
      show: () => {
        const snapshot = status();
        const label = pillLabel(snapshot);
        if (label === undefined) return undefined;
        const last = latest(snapshot);
        const reviewing = (snapshot?.reviewing.length ?? 0) > 0;
        if (!reviewing && last !== undefined && Date.now() - last.at > NOTICE_MS) return undefined;
        return {
          label,
          tone: reviewing ? "warning" : TONE[last?.decision ?? "allow"],
          title: ctx.t("pill.title"),
          rows: (snapshot?.recent ?? []).slice(-5).reverse().map((entry) => ({
            id: entry.reviewID,
            label: `${entry.decision} · ${entry.action}`,
            tone: TONE[entry.decision],
            detail: entry.reason,
          })),
        };
      },
    });

    return () => clearInterval(timer);
  },
});
