import { randomBytes } from "node:crypto";
import type { AuditRecord } from "./audit.js";
import { sanitizeRecord } from "./audit.js";
import type { OtlpOptions } from "./otlp.js";
import type { StageResult } from "./reviewer.js";

export interface ClassifierAttempt {
  index: number;
  type: string;
  model?: string;
  startedAt: number;
  durationMs: number;
  result: StageResult;
}

export interface ReviewTrace {
  traceID: string;
  spanID: string;
  attempts: ClassifierAttempt[];
  finish(record: AuditRecord): void;
}

const attribute = (key: string, value: string | number) => ({
  key,
  value: typeof value === "number" ? { intValue: String(value) } : { stringValue: value },
});
const nano = (ms: number) => String(BigInt(Math.trunc(ms)) * 1_000_000n);

export function tracesUrl(base: string): string {
  const url = new URL(base);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) throw new Error("Invalid OTLP endpoint");
  url.pathname = url.pathname.replace(/\/v1\/(?:logs|traces)\/?$/, "").replace(/\/+$/, "") + "/v1/traces";
  return url.href;
}

function headers(raw: string | undefined): Record<string, string> {
  return Object.fromEntries((raw ?? "").split(",").flatMap((pair) => {
    const index = pair.indexOf("=");
    return index > 0 ? [[pair.slice(0, index).trim(), pair.slice(index + 1).trim()]] : [];
  }));
}

export function createTraceExporter(setting: boolean | OtlpOptions | undefined, env: NodeJS.ProcessEnv = process.env) {
  if (setting === undefined || setting === false) return undefined;
  const options = setting === true ? {} : setting;
  const base = options.endpoint ?? env.OPENCODE_OTLP_ENDPOINT ?? env.OTEL_EXPORTER_OTLP_ENDPOINT;
  if (!base) return undefined;
  let url: string;
  try { url = tracesUrl(base); } catch { return undefined; }
  const requestHeaders = { "content-type": "application/json", ...headers(env.OTEL_EXPORTER_OTLP_HEADERS), ...headers(env.OPENCODE_OTLP_HEADERS), ...options.headers };
  return {
    begin(startedAt: number): ReviewTrace {
      const traceID = randomBytes(16).toString("hex");
      const spanID = randomBytes(8).toString("hex");
      const attempts: ClassifierAttempt[] = [];
      return {
        traceID, spanID, attempts,
        finish(record) {
          // Both log sinks sanitize before serialising; traces are a third sink
          // and must not export unbounded record fields.
          const safe = sanitizeRecord(record);
          const shared = [attribute("review.id", safe.reviewID), attribute("session.id", safe.sessionID)];
          const spans = [{
            traceId: traceID, spanId: spanID, name: "auto_mode.review", kind: 1,
            startTimeUnixNano: nano(startedAt), endTimeUnixNano: nano(startedAt + safe.durationMs),
            attributes: [...shared, attribute("action", safe.action), attribute("agent", safe.agent ?? ""),
              attribute("decision", safe.decision), attribute("stage", safe.stage),
              ...(safe.errorKind === undefined ? [] : [attribute("error.kind", safe.errorKind)])],
            status: { code: safe.error ? 2 : 1 },
          }, ...attempts.map((attempt) => ({
            traceId: traceID, spanId: randomBytes(8).toString("hex"), parentSpanId: spanID,
            name: "auto_mode.classifier", kind: 1,
            startTimeUnixNano: nano(attempt.startedAt), endTimeUnixNano: nano(attempt.startedAt + attempt.durationMs),
            attributes: [...shared, attribute("classifier.index", attempt.index), attribute("classifier.type", attempt.type),
              attribute("model", attempt.model ?? ""), attribute("decision", attempt.result.decision),
              ...(attempt.result.errorKind === undefined ? [] : [attribute("error.kind", attempt.result.errorKind)])],
            status: { code: attempt.result.errorKind === undefined ? 1 : 2 },
          }))];
          const body = JSON.stringify({ resourceSpans: [{
            resource: { attributes: [attribute("service.name", "opencode-auto-mode")] },
            scopeSpans: [{ scope: { name: "opencode-auto-mode" }, spans }],
          }] });
          // Match log export: best effort, independent of permission delivery.
          fetch(url, { method: "POST", headers: requestHeaders, body, redirect: "error",
            signal: AbortSignal.timeout(Math.min(options.timeoutMs ?? 3_000, 10_000)) }).catch(() => {});
        },
      };
    },
  };
}
