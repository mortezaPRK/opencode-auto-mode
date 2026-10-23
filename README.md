# OpenCode Auto Mode

Reviews OpenCode permission prompts automatically. OpenCode decides what needs
approval; the plugin reviews only `ask` actions.

## Install and configure

Add this to `~/.config/opencode/opencode.jsonc`. It asks for permission on every
action and reviews those requests using built-in checks. No model or API key is
needed:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "permissions": [
    { "action": "*", "resource": "*", "effect": "ask" }
  ],
  "plugins": [
    {
      "package": "@mortz.prk/opencode-auto-mode",
      "options": {
        "classifiers": [
          { "type": "static" }
        ]
      }
    }
  ]
}
```

Restart OpenCode after saving:

```sh
opencode service restart
```

There is no default review pipeline, and empty options are invalid. Add at least
one review entry. Built-in checks deny dangerous shell commands, allow common
read-only commands, and leave everything else as `ask`.

The snippets below change parts of that configuration; keep your `classifiers`
list when adding other options.

## Add a typed decision model

```jsonc
{
  "options": {
    "classifiers": [
      { "type": "static" },
      { "type": "decision", "model": "typesafe-ai/jev-latest" }
    ]
  }
}
```

| Provider | Setup |
| --- | --- |
| `typesafe-ai` | Set `TYPESAFE_API_KEY`. |
| `openai` | Set `OPENAI_API_KEY`. |
| `laya` | Run a loopback `/v1/systemone` service. `LAYA_API_KEY` is optional. |

Decision entries accept `minConfidence` (default `0.9`), `timeoutMs`, and
`apiKeyEnv`. `laya` also accepts `endpoint`.

## Add an LLM

Add an `llm` entry after the built-in checks:

```jsonc
{
  "options": {
    "classifiers": [
      { "type": "static" },
      { "type": "llm" }
    ]
  }
}
```

When an `llm` entry has no `model`, the **session model** is used. To choose a
different model:

```jsonc
{ "type": "llm", "model": "anthropic/claude-sonnet-4-5" }
```

## Combine reviewers

Entries run in order. Add as many as you need:

```jsonc
{
  "options": {
    "classifiers": [
      { "type": "static" },
      { "type": "decision", "model": "typesafe-ai/jev-latest" },
      { "type": "llm" }
    ]
  }
}
```

An entry can allow, deny, or ask, which stops the pipeline. If it abstains or
fails, the next entry runs. If nothing decides, the action remains `ask`.

## Use it for specific agents

OpenCode allows everything by default. To review only the `build` agent, set its
permissions and leave global permissions unchanged:

```jsonc
{
  "agents": {
    "build": {
      "permissions": [
        { "action": "*", "resource": "*", "effect": "ask" }
      ]
    }
  }
}
```

## TUI indicator

A passive indicator shows when the plugin is reviewing the current session.
It is enabled by default. Set `tui: false` in plugin options to hide it.
OpenCode's own permission dialog handles manual approvals.

## Review options

Each LLM or typed decision reviewer can have its own policy:

```jsonc
{
  "options": {
    "classifiers": [
      {
        "type": "llm",
        "policy": {
          "trusted": ["the repository and its CI configuration"],
          "blocks": ["publish packages", "change production infrastructure"],
          "exceptions": ["run the repository's test and lint scripts"]
        }
      }
    ]
  }
}
```

`trusted` describes the trusted boundary, `blocks` describes actions to deny, and
`exceptions` describes narrow acceptable cases. Omitted lists use the built-in
policy; an empty list clears that list. Policies are independent between
reviewers and do not apply to static checks or replace OpenCode permissions.

## Auditing

Enable the audit log in plugin options:

```jsonc
{
  "options": {
    "auditLog": true
  }
}
```

Decisions are appended as JSON lines to
`$XDG_STATE_HOME/opencode-auto-mode/decisions.jsonl`. Replay recorded tool calls
without executing anything:

```sh
bun scripts/replay.ts [--days 14] [--session ID] [--agent build|any] [--json]
```

To send decisions through OpenCode's OTLP telemetry, configure OTLP for OpenCode
with its standard environment variables, then enable the plugin flag. This sends
correlated decision logs and review traces, including model reviewer attempts:

```jsonc
{
  "options": {
    "otlp": true
  }
}
```

## Development

```sh
bun install
bun test
bun run lint
bun run typecheck
bun run test:integration
```

## Credit

Created originally by [Andrew Mellen (mellena1)](https://github.com/mellena1) in
[mellena1/opencode-auto-mode](https://github.com/mellena1/opencode-auto-mode),
also credited as the author in [package.json](package.json). This independent
project retains the original [MIT license](LICENSE).
