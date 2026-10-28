/** @jsxImportSource solid-js */
import { createSignal, For, onCleanup } from "solid-js";
import { Command, ComposerPill, Panel, Plugin, createKeyed, type PanelTab } from "@opencode/plugin/gui";
import { AutoMode, type AutoModeStatus } from "./rpc.js";
import { createStatusLoader, latest, noticeExpired, panelView, pillLabel, statusTarget } from "./gui-state.js";

const POLL_MS = 3_000;
const NOTICE_MS = 30_000;

const TONE: Record<string, "success" | "warning" | "danger" | undefined> = {
  allow: "success",
  ask: "warning",
  deny: "danger",
};

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
    const refresh = createStatusLoader(
      (sessionID) => ctx.client.rpc(AutoMode).status({ sessionID }) as Promise<AutoModeStatus | undefined>,
      setStatus,
    );
    // `ctx.client` reads the app's own server, so a session on another server
    // has no status here; `session.key` keeps the same session id on two
    // servers apart.
    const target = () => statusTarget(ctx.sessions.current());
    // The pill's notice expiry needs a clock of its own: the loader keeps the
    // previous snapshot when a poll fails without applying it, so a clock read
    // only when the snapshot changes would leave an expired decision on screen
    // while the server is unreachable. Advance it on every tick regardless.
    const [now, setNow] = createSignal(Date.now());
    const poll = () => {
      setNow(Date.now());
      void refresh(target());
    };

    createKeyed(() => target()?.key, poll, { otherwise: poll });
    const timer = setInterval(poll, POLL_MS);
    onCleanup(() => clearInterval(timer));

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
          {panelView(status()) === "empty"
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
        // `now()` is tracked, so the pill disappears on the tick that passes
        // the notice window even if no snapshot arrives after it.
        if (noticeExpired(snapshot, now(), NOTICE_MS)) return undefined;
        const reviewing = (snapshot?.reviewing.length ?? 0) > 0;
        return {
          label,
          tone: reviewing ? "warning" : TONE[latest(snapshot)?.decision ?? "allow"],
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
  },
});
