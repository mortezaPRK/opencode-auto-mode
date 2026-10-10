# OpenCode Auto Mode

## What this solves

OpenCode's permission prompts can interrupt routine work. This plugin reviews actions automatically and returns **allow**, **deny**, or **ask**, leaving uncertain decisions to you. Combine built-in checks, your own CEL rules, decision providers, and an LLM reviewer to choose how approvals work.

This is an independently maintained project for OpenCode v2 (`@opencode/plugin` 2.0). **Review applies to all agents by default**, including Build and Plan. An Auto agent is optional; adding one does not limit review unless you also configure `options.agents`.

## Install from GitHub Packages

The package is `@mortezaprk/opencode-auto-mode`. Publishing is configured, but the first release must be published before these registry install steps work.

Add this line to your user `~/.npmrc`:

```ini
@mortezaprk:registry=https://npm.pkg.github.com
```

Authenticate with your GitHub username and a personal access token (classic) with `read:packages`, using the token as the password:

```sh
npm login --scope=@mortezaprk --registry=https://npm.pkg.github.com --auth-type=legacy
```

Keep registry credentials in your user configuration. Add the plugin to your global `~/.config/opencode/opencode.jsonc` using an example below. OpenCode installs the package; no separate project dependency is needed. Restart the service after changing plugins:

```sh
opencode service restart
```

## Configuration examples

### Built-in checks followed by an LLM

This reviews **all agents** because `agents` is omitted. Built-in checks allow supported read-only commands such as `pwd` and block known dangerous shell operations. Other supported actions go to the LLM using OpenCode's default model; uncertain decisions require manual approval.

```json
{
  "plugins": [
    {
      "package": "@mortezaprk/opencode-auto-mode",
      "options": {
        "review": "all"
      }
    }
  ]
}
```

Set `options.model` to `{ "id": "your-model", "providerID": "your-provider" }` to select the reviewer model. `review: "all"` reviews eligible actions even when OpenCode would allow them; `review: "prompts"` reviews only actions already requiring approval. OpenCode's explicit denies remain authoritative.

### Static checks and your own rules, without a model

This also reviews **all agents**. `pwd` passes the static checks, `git status --short` matches the exact CEL allow rule, `curl` matches the deny rule, and edits or writes require your approval. Unmatched actions require manual approval because there is no model stage.

```json
{
  "plugins": [
    {
      "package": "@mortezaprk/opencode-auto-mode",
      "options": {
        "review": "all",
        "classifier": {
          "stages": [
            { "type": "static" },
            {
              "type": "rules",
              "rules": [
                {
                  "expression": "action == 'shell' && command == 'git' && args == ['status', '--short']",
                  "decision": "allow"
                },
                {
                  "expression": "action == 'shell' && command == 'curl'",
                  "decision": "deny"
                },
                {
                  "expression": "action in ['edit', 'write']",
                  "decision": "ask"
                }
              ]
            }
          ]
        }
      }
    }
  ]
}
```

Rules use [Buf's CEL evaluator](https://github.com/bufbuild/cel-es). Available variables are `action`, `resource`, `command`, `args`, `agent`, `projectDir`, and `isDelegation`. For shell resources, `command` is the literal executable and `args` contains its decoded arguments. Every resource must be covered by allow rules within a rules stage. Matching deny rules take precedence across stages, followed by ask rules, before any allow decision. Collection macros are disabled; invalid expressions or evaluation limits require manual approval.

Shell review uses OpenCode's subcommand parsing and a literal-command guard. A permitted `pwd` does not authorize the rest of `pwd ; sudo rm -rf`; the dangerous operation is denied. Unsupported syntax, such as redirects or substitutions, and Windows shells require manual approval.

### Decision providers with an LLM fallback

This reviews **all agents** too. Static checks run first, followed by Jev, OpenAI Decisions, local Laya, and an LLM. Remove or reorder provider stages to suit your setup; you do not need all of them.

```json
{
  "plugins": [
    {
      "package": "@mortezaprk/opencode-auto-mode",
      "options": {
        "review": "all",
        "classifier": {
          "stages": [
            { "type": "static" },
            { "type": "jev", "minConfidence": 0.9 },
            { "type": "openai-decision", "minConfidence": 0.9 },
            { "type": "laya", "endpoint": "http://127.0.0.1:8000/v1/systemone" },
            { "type": "llm" }
          ]
        }
      }
    }
  ]
}
```

| Stage | Setup |
| --- | --- |
| `jev` | Set `TYPESAFE_API_KEY`; default model is `jev-latest`. |
| `openai-decision` | Set `OPENAI_API_KEY`; default model is `gpt-6-luna`. |
| `laya` | Run a compatible local `/v1/systemone` service; optionally set `LAYA_API_KEY`. Only loopback endpoints are accepted. |
| `llm` | Uses OpenCode's default model, or the configured reviewer model. |

A valid provider allow/deny result below `minConfidence` continues to the next stage. An explicit ask, provider error, timeout, or invalid response requires manual approval and stops the pipeline. Export API keys in the environment of the OpenCode service. Provider stages also accept `model`, `apiKeyEnv`, and `timeoutMs`.

## Tips: an optional Auto agent

Add an Auto agent if you want a separate agent for automatic review, then restrict the plugin with `options.agents: ["auto"]`. **Only this example limits review to Auto**; Build, Plan, and other agents retain their normal OpenCode permission behavior.

```json
{
  "agents": {
    "auto": {
      "mode": "primary",
      "description": "Build with automatic permission review"
    }
  },
  "plugins": [
    {
      "package": "@mortezaprk/opencode-auto-mode",
      "options": {
        "review": "all",
        "agents": ["auto"]
      }
    }
  ]
}
```

Select Auto alongside Build and Plan. To review all agents while keeping Auto available, omit `options.agents`.

Keep ordinary OpenCode permission rules requiring approval for sensitive actions so prompts remain available when the plugin is disabled. `trusted`, `blocks`, and `exceptions` replace the corresponding model-review policy lists. Configure these globally. The TUI integration shows review status and provides manual allow/deny commands.

## Credit

Created originally by [Andrew Mellen (mellena1)](https://github.com/mellena1) in [mellena1/opencode-auto-mode](https://github.com/mellena1/opencode-auto-mode), also credited as the author in [package.json](package.json). This independent project retains the original [MIT license](LICENSE).
