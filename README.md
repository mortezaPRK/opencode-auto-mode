# OpenCode Auto Mode

OpenCode Auto Mode reviews permission prompts for OpenCode v2. It can allow,
deny, or ask using built-in safety checks, typed decision models, and an LLM.

OpenCode remains the source of truth for permissions. The plugin only sees
actions that OpenCode has already resolved to `ask`; it never overrides an
`allow` or `deny` decision.

## Requirements

- OpenCode v2 with `@opencode/plugin` 2.0
- An LLM or decision provider if you want model-based review

Built-in safety checks work without a model.

## Install

Add the plugin to your global `~/.config/opencode/opencode.jsonc`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": ["@mortz.prk/opencode-auto-mode"]
}
```

Restart the OpenCode service after changing plugins:

```sh
opencode service restart
```

## Quick start

OpenCode's default policy allows everything. To give the plugin something to
review, add `ask` rules for the actions you want reviewed. For example:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "permissions": [
    { "action": "shell", "resource": "*", "effect": "ask" },
    { "action": "edit", "resource": "*", "effect": "ask" }
  ],
  "plugins": ["@mortz.prk/opencode-auto-mode"]
}
```

With this setup, shell commands and edits reach the plugin. The default pipeline
runs built-in safety checks and then OpenCode's default model. Everything else
keeps OpenCode's normal behavior.

To review every action, use:

```jsonc
{
  "permissions": [{ "action": "*", "resource": "*", "effect": "ask" }]
}
```

## Choose what is reviewed

Use OpenCode permission rules to scope review. Put shared rules at the top level
for every agent, or under an agent for that agent only.

Review everything for every agent:

```jsonc
{
  "permissions": [{ "action": "*", "resource": "*", "effect": "ask" }]
}
```

Review everything for `build` only:

```jsonc
{
  "agents": {
    "build": {
      "permissions": [{ "action": "*", "resource": "*", "effect": "ask" }]
    }
  }
}
```

Review shell commands globally, but allow routine Git inspection and block
pushes before the plugin is consulted:

```jsonc
{
  "permissions": [
    { "action": "shell", "resource": "*", "effect": "ask" },
    { "action": "shell", "resource": "git status *", "effect": "allow" },
    { "action": "shell", "resource": "git diff *", "effect": "allow" },
    { "action": "shell", "resource": "git push *", "effect": "deny" }
  ]
}
```

Saved **Allow always** approvals are durable `allow` rules, so they bypass the
plugin. A configured `deny` always wins.

See [Permissions](https://opencode.ai/v2/docs/permissions) for matching and agent
rules.

## How a review runs

1. OpenCode evaluates its permission rules.
2. `allow` and `deny` are returned unchanged.
3. `ask` actions enter the plugin.
4. The shell safety guard runs before configured stages.
5. Configured stages run in order.
6. If no stage decides, the action remains `ask`.

A stage returns one of four outcomes:

| Outcome | Result |
| --- | --- |
| `allow` | Stop and approve |
| `deny` | Stop and reject |
| `ask` | Stop and leave the decision to you |
| `abstain` | Try the next stage |

A low-confidence allow abstains. A low-confidence deny becomes `ask` instead of
falling through to a possible allow. Provider errors, timeouts, refusals, and
invalid responses abstain so another stage can try.

The default pipeline is:

```jsonc
{ "classifier": { "stages": [{ "type": "static" }, { "type": "llm" }] } }
```

## Stages

### Built-in checks

The `static` stage adds a fast safety pass:

- Denies dangerous shell patterns such as `sudo`, `rm -rf /`, `mkfs`, and
  shutdown commands.
- Allows a small set of read-only shell commands such as `pwd`, `ls`, and
  `whoami`.
- Allows safe in-project file reads and, with `allowInProjectEdits`, in-project
  edits and writes.

```jsonc
{
  "classifier": {
    "stages": [
      { "type": "static", "allowInProjectEdits": true }
    ]
  }
}
```

Unsupported shell syntax and unsafe paths continue to the next stage.

### Typed decision models

A `decision` stage uses a provider/model selector and OpenCode's typed
Evaluation contract:

```jsonc
{
  "classifier": {
    "stages": [
      {
        "type": "decision",
        "model": "typesafe-ai/jev-latest",
        "minConfidence": 0.9
      }
    ]
  }
}
```

| Provider | Setup |
| --- | --- |
| `typesafe-ai` | Set `TYPESAFE_API_KEY`. |
| `openai` | Set `OPENAI_API_KEY`. |
| `laya` | Run a compatible loopback `/v1/systemone` service. Set `endpoint` when it is not `http://127.0.0.1:8000/v1/systemone`; `LAYA_API_KEY` is optional. |

Each stage accepts `apiKeyEnv` to override the credential variable and
`timeoutMs` to change the 10-second default timeout. `endpoint` is only valid
for `laya`.

### LLM reviewer

An `llm` stage uses OpenCode's model selector. The model is optional; without it,
the stage uses OpenCode's default model.

```jsonc
{
  "classifier": {
    "stages": [
      { "type": "llm", "model": "anthropic/claude-sonnet-4-5" }
    ]
  }
}
```

The model selector supports an optional variant:

```jsonc
{ "type": "llm", "model": "openai/gpt-5.2#high" }
```

Repeat `llm` stages to try models in order. A stage that errors or abstains lets
the next stage run:

```jsonc
{
  "classifier": {
    "stages": [
      { "type": "static" },
      { "type": "llm", "model": "anthropic/claude-sonnet-4-5" },
      { "type": "llm", "model": "openai/gpt-5.2#high" }
    ]
  }
}
```

### Combined example

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "permissions": [
    { "action": "shell", "resource": "*", "effect": "ask" },
    { "action": "edit", "resource": "*", "effect": "ask" }
  ],
  "plugins": [
    {
      "package": "@mortz.prk/opencode-auto-mode",
      "options": {
        "classifier": {
          "stages": [
            { "type": "static" },
            {
              "type": "decision",
              "model": "typesafe-ai/jev-latest",
              "minConfidence": 0.9
            },
            { "type": "llm" }
          ]
        },
        "auditLog": true
      }
    }
  ]
}
```

## Review policy

The reviewer receives three policy lists:

- `trusted`: what is inside the trusted boundary.
- `blocks`: actions that should be denied.
- `exceptions`: narrow cases that are acceptable despite a block.

The defaults are suitable for software projects. Replace any list by setting it:

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

## TUI

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

## Observability

Audit logging and OTLP export are optional:

```jsonc
{
  "options": {
    "auditLog": true,
    "otlp": true
  }
}
```

See [Observability](https://github.com/mortezaPRK/opencode-auto-mode/blob/main/docs/observability.md)
for record fields, OTLP setup, replaying recorded sessions, and how to verify a
release.

## Development

```sh
bun install
bun test
bun run lint
bun run typecheck
bun run test:integration
```

The integration suite runs against a real OpenCode service, a local OpenAI-
compatible model server, and local typed-decision endpoints. It checks the
rendered decisions, tool outcomes, and provider request shapes.

See [Releasing](https://github.com/mortezaPRK/opencode-auto-mode/blob/main/docs/releasing.md)
for the npm release workflow.

## Credit

Created originally by [Andrew Mellen (mellena1)](https://github.com/mellena1) in
[mellena1/opencode-auto-mode](https://github.com/mellena1/opencode-auto-mode),
also credited as the author in [package.json](package.json). This independent
project retains the original [MIT license](LICENSE).
