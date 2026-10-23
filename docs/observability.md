# Observability

Every review can be recorded locally and exported as an OpenTelemetry log
record. Both are off by default.

```jsonc
{
  "options": {
    "auditLog": true,
    "otlp": true
  }
}
```

Neither setting stores transcripts or metadata. Resources are truncated to 512
characters.

## Audit log

`auditLog: true` appends one JSON line per review to:

```text
$XDG_STATE_HOME/opencode-auto-mode/decisions.jsonl
```

When `XDG_STATE_HOME` is unset, the default is under `~/.local/state`. A string
sets a custom path. The file is created with `0600` permissions and rotates to
`.1` at 10 MB.

Each record contains:

| Field | Meaning |
| --- | --- |
| `ts` | ISO timestamp |
| `reviewID` | Review identifier |
| `sessionID` | OpenCode session |
| `agent` | Agent that requested the action |
| `action` | Permission action, such as `shell` |
| `resources` | Resources passed to the permission check |
| `hostEffect` | OpenCode's decision before the plugin runs |
| `decision` | Final `allow`, `deny`, or `ask` |
| `stage` | `static`, `shell-guard`, `decision`, `llm`, `none`, or `error` |
| `reason` | Human-readable reason |
| `durationMs` | Review duration |
| `error` / `errorDetail` | Present when review failed |

## OTLP export

`otlp: true` sends each decision to an OTLP/HTTP JSON logs endpoint:

```text
<endpoint>/v1/logs
```

The endpoint is resolved from, in order:

1. `options.otlp.endpoint`
2. `OPENCODE_OTLP_ENDPOINT`
3. `OTEL_EXPORTER_OTLP_ENDPOINT`

Headers come from `options.otlp.headers`, `OTEL_EXPORTER_OTLP_HEADERS`, and
`OPENCODE_OTLP_HEADERS`. Use the HTTP port, usually `4318`, not gRPC.

```jsonc
{
  "options": {
    "otlp": {
      "endpoint": "http://127.0.0.1:4318",
      "headers": { "x-collector": "local" },
      "timeoutMs": 3000
    }
  }
}
```

Export is fire-and-forget and never delays or fails a review.

## Verify a review

1. Enable `auditLog` and point `otlp` at a local collector.
2. Trigger an action that OpenCode marks `ask`.
3. Confirm one JSON line appears in `decisions.jsonl`.
4. Confirm the collector receives one `auto_mode.decision` log record.
5. Check that `decision` matches what the TUI showed and that `stage` names the
   stage that decided.

OpenCode service logs are useful when the plugin or a stage fails:

```sh
opencode service status
```

See [Troubleshooting](https://opencode.ai/v2/docs/troubleshooting) for log
locations and service commands.

## Replay recorded sessions

The replay script reads recorded tool calls from the OpenCode database and runs
them through the configured stages. It opens the database read-only, executes
nothing, and makes no network calls. The LLM stage is stubbed and reported as
`llm?`.

```sh
bun scripts/replay.ts [--days 14] [--session ID] [--agent build|any] [--json]
```

Use `--json` for machine-readable output.

## Integration verification

Run the full verification suite before publishing:

```sh
bun test
bun run lint
bun run typecheck
bun run test:integration
```

The integration suite starts a real OpenCode service and local test endpoints.
It prints the artifact directory and writes the service log to `host.log` in
that directory.
