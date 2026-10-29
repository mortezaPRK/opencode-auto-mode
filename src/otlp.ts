import type { AuditLog, AuditRecord } from "./audit.js";
import { sanitizeRecord } from "./audit.js";

export interface OtlpOptions { endpoint?: string; headers?: Record<string, string>; timeoutMs?: number }

const MAX_TIMEOUT_MS = 10_000;

function parseHeaders(raw: string | undefined): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const pair of (raw ?? "").split(",")) {
    const index = pair.indexOf("=");
    if (index > 0) headers[pair.slice(0, index).trim()] = pair.slice(index + 1).trim();
  }
  return headers;
}

export function logsUrl(base: string): string {
  const url = new URL(base);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) throw new Error("Invalid OTLP endpoint");
  if (!url.pathname.endsWith("/v1/logs")) url.pathname = `${url.pathname.replace(/\/+$/, "")}/v1/logs`;
  return url.href;
}

const attr = (key: string, value: string | number | boolean) => ({
  key,
  value: typeof value === "string" ? { stringValue: value } : typeof value === "boolean" ? { boolValue: value } : { intValue: String(value) },
});

export function toLogRecord(record: AuditRecord) {
  const safe = sanitizeRecord(record);
  const severity = safe.decision === "deny" ? { severityNumber: 13, severityText: "WARN" } : { severityNumber: 9, severityText: "INFO" };
  return {
    timeUnixNano: String(BigInt(Date.parse(safe.ts)) * 1_000_000n),
    ...(safe.traceID === undefined ? {} : { traceId: safe.traceID, spanId: safe.spanID }),
    ...severity,
    body: { stringValue: safe.reason },
    attributes: [
      attr("event.name", "auto_mode.decision"),
      attr("session.id", safe.sessionID),
      attr("review.id", safe.reviewID),
      attr("agent", safe.agent ?? ""),
      attr("action", safe.action),
      attr("resources", safe.resources.join(" ; ")),
      attr("host_effect", safe.hostEffect),
      attr("decision", safe.decision),
      attr("stage", safe.stage),
      attr("duration_ms", safe.durationMs),
      attr("error", safe.error === true),
      ...(safe.errorKind === undefined ? [] : [attr("error.kind", safe.errorKind)]),
      ...(safe.errorDetail === undefined ? [] : [attr("error.detail", safe.errorDetail)]),
    ],
  };
}

/** Exports each decision as an OTLP/HTTP JSON log record. Defaults follow the OpenCode telemetry environment. */
export function createOtlpExporter(setting: boolean | OtlpOptions | undefined, env: NodeJS.ProcessEnv = process.env): AuditLog | undefined {
  if (setting === undefined || setting === false) return undefined;
  const options = setting === true ? {} : setting;
  const base = options.endpoint ?? env.OPENCODE_OTLP_ENDPOINT ?? env.OTEL_EXPORTER_OTLP_ENDPOINT;
  if (!base) return undefined;
  let url: string;
  try { url = logsUrl(base); } catch { return undefined; }
  const headers = { "content-type": "application/json", ...parseHeaders(env.OTEL_EXPORTER_OTLP_HEADERS), ...parseHeaders(env.OPENCODE_OTLP_HEADERS), ...options.headers };
  const timeout = Math.min(options.timeoutMs ?? 3_000, MAX_TIMEOUT_MS);
  return {
    write(record) {
      const body = JSON.stringify({
        resourceLogs: [{
          resource: { attributes: [attr("service.name", "opencode-auto-mode")] },
          scopeLogs: [{ scope: { name: "opencode-auto-mode" }, logRecords: [toLogRecord(record)] }],
        }],
      });
      // Fire and forget: telemetry must never delay or fail a permission review.
      fetch(url, { method: "POST", headers, body, signal: AbortSignal.timeout(timeout), redirect: "error" }).catch(() => {});
    },
  };
}
