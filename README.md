# OpenCode Auto Mode

Automatic review for OpenCode permission prompts. OpenCode decides which actions
need approval. The plugin reviews only `ask` actions and returns `allow`, `deny`,
or leaves them as `ask`.

## Install

Add the plugin to `~/.config/opencode/opencode.jsonc`, then restart OpenCode:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": ["@mortz.prk/opencode-auto-mode"]
}
```

```sh
opencode service restart
```

## Configure

OpenCode allows everything by default. Add `ask` rules for what you want
reviewed. This is a complete working setup:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "permissions": [
    { "action": "*", "resource": "*", "effect": "ask" }
  ],
  "plugins": [
    {
      "package": "@mortz.prk/opencode-auto-mode",
      "options": {}
    }
  ]
}
```

The default review runs built-in checks and then the session model.

Use OpenCode permissions to narrow the scope. For shell commands and edits only:

```jsonc
{
  "permissions": [
    { "action": "shell", "resource": "*", "effect": "ask" },
    { "action": "edit", "resource": "*", "effect": "ask" }
  ]
}
```

For the `build` agent only:

```jsonc
{
  "agents": {
    "build": {
      "permissions": [{ "action": "*", "resource": "*", "effect": "ask" }]
    }
  }
}
```

Saved **Allow always** approvals bypass the plugin. A configured `deny` always
wins. See [Permissions](https://opencode.ai/v2/docs/permissions).

## Review with an LLM

The default review uses the session model. To choose another model, configure the
review pipeline:

```jsonc
{
  "options": {
    "classifier": {
      "stages": [
        { "type": "static" },
        { "type": "llm", "model": "anthropic/claude-sonnet-4-5" }
      ]
    }
  }
}
```

When an `llm` entry has no `model`, the session model is used. Add more `llm`
entries to try models in order; an entry that errors or abstains lets the next
one run.

## Review with typed decisions

Use a decision model for a fast allow, deny, or ask:

```jsonc
{
  "options": {
    "classifier": {
      "stages": [
        { "type": "static" },
        { "type": "decision", "model": "typesafe-ai/jev-latest" }
      ]
    }
  }
}
```

| Provider | Setup |
| --- | --- |
| `typesafe-ai` | Set `TYPESAFE_API_KEY`. |
| `openai` | Set `OPENAI_API_KEY`. |
| `laya` | Run a loopback `/v1/systemone` service. `LAYA_API_KEY` is optional. |

Decision entries also accept `minConfidence` (default `0.9`), `timeoutMs`,
`apiKeyEnv`, and, for `laya`, `endpoint`.

## Without a model

Use `{ "type": "static", "allowInProjectEdits": true }` as the only review entry.
Built-in checks deny dangerous shell commands, allow common read-only commands,
and allow safe in-project file operations. Anything else remains `ask`.

## Review policy

The reviewer receives three policy lists: `trusted` (the trusted boundary),
`blocks` (actions to deny), and `exceptions` (narrow acceptable cases).

```jsonc
{
  "options": {
    "trusted": ["the repository and its CI configuration"],
    "blocks": ["publish packages", "change production infrastructure"],
    "exceptions": ["run the repository's test and lint scripts"]
  }
}
```

These lists guide model review. They do not replace OpenCode permission rules.

## How it works

1. OpenCode evaluates its permission rules.
2. `allow` and `deny` are returned unchanged.
3. `ask` actions enter the plugin.
4. The shell safety guard runs.
5. The configured review entries run in order.
6. If nothing decides, the action remains `ask`.

A review entry returns one of four outcomes:

| Outcome | Result |
| --- | --- |
| `allow` | Stop and approve |
| `deny` | Stop and reject |
| `ask` | Stop and leave the decision to you |
| `abstain` | Try the next entry |

A low-confidence decision abstains. A low-confidence deny becomes `ask`.
Provider errors, timeouts, refusals, and invalid responses abstain so another
entry can try. Unknown configuration options are rejected.

## Logs and tracing

Audit logs and OTLP export are optional:

```jsonc
{
  "options": {
    "auditLog": true,
    "otlp": true
  }
}
```

`auditLog` writes one JSON line per review to
`$XDG_STATE_HOME/opencode-auto-mode/decisions.jsonl`. `otlp` sends each decision
to an OTLP/HTTP logs endpoint.

Replay recorded tool calls through the configured review without executing
anything:

```sh
bun scripts/replay.ts [--days 14] [--session ID] [--agent build|any] [--json]
```

## TUI

The plugin shows review status in the TUI and provides manual allow and deny
commands. Override the defaults with `keybinds.allow` and `keybinds.deny`; the
defaults are `ctrl+alt+a` and `ctrl+alt+d`.

## Development

```sh
bun install
bun test
bun run lint
bun run typecheck
bun run test:integration
```

The integration suite runs against a real OpenCode service and local model and
decision endpoints. It checks decisions, tool outcomes, audit records, and OTLP
export.

## Credit

Created originally by [Andrew Mellen (mellena1)](https://github.com/mellena1) in
[mellena1/opencode-auto-mode](https://github.com/mellena1/opencode-auto-mode),
also credited as the author in [package.json](package.json). This independent
project retains the original [MIT license](LICENSE).
