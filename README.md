# OpenCode Auto Mode

Reviews OpenCode permission prompts automatically. OpenCode decides what needs
approval; the plugin reviews only `ask` actions.

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

## Quick start

The easiest setup is to ask OpenCode for permission on every action, then give
the plugin a review pipeline. This example uses built-in checks only and needs no
model:

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
        "classifier": {
          "stages": [{ "type": "static" }]
        }
      }
    }
  ]
}
```

There is no default review pipeline, and empty options are invalid. Add at least
one review entry. Built-in checks deny dangerous shell commands, allow common
read-only commands, and leave everything else as `ask`.

## Add a typed decision model

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

Decision entries accept `minConfidence` (default `0.9`), `timeoutMs`, and
`apiKeyEnv`. `laya` also accepts `endpoint`.

## Add an LLM

Add an `llm` entry after the built-in checks:

```jsonc
{
  "options": {
    "classifier": {
      "stages": [
        { "type": "static" },
        { "type": "llm" }
      ]
    }
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
    "classifier": {
      "stages": [
        { "type": "static" },
        { "type": "decision", "model": "typesafe-ai/jev-latest" },
        { "type": "llm" }
      ]
    }
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
      "permissions": [{ "action": "*", "resource": "*", "effect": "ask" }]
    }
  }
}
```

## TUI keybindings

The plugin shows review status in the TUI and provides manual allow and deny
commands. Override the defaults in plugin options:

```jsonc
{
  "options": {
    "keybinds": {
      "allow": "ctrl+alt+a",
      "deny": "ctrl+alt+d"
    }
  }
}
```

## Review options

These lists guide model review:

```jsonc
{
  "options": {
    "trusted": ["the repository and its CI configuration"],
    "blocks": ["publish packages", "change production infrastructure"],
    "exceptions": ["run the repository's test and lint scripts"]
  }
}
```

`trusted` describes the trusted boundary, `blocks` describes actions to deny, and
`exceptions` describes narrow acceptable cases. They do not replace OpenCode
permission rules.

## Auditing

Enable the audit log in plugin options:

```jsonc
{ "options": { "auditLog": true } }
```

Decisions are appended as JSON lines to
`$XDG_STATE_HOME/opencode-auto-mode/decisions.jsonl`. Replay recorded tool calls
without executing anything:

```sh
bun scripts/replay.ts [--days 14] [--session ID] [--agent build|any] [--json]
```

To send decisions through OpenCode's OTLP telemetry, configure OTLP for OpenCode
with its standard environment variables, then enable the plugin flag:

```jsonc
{ "options": { "otlp": true } }
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
