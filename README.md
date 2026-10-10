# OpenCode Auto Mode

Automatic permission review for OpenCode v2. Read-only operations can be approved immediately; other actions go to a reviewer that allows, denies, or asks you to decide.

Maintained independently at [mortezaPRK/opencode-auto-mode](https://github.com/mortezaPRK/opencode-auto-mode). Requires OpenCode v2 with the `@opencode/plugin` 2.0 API.

## Install

Clone this repository and install its dependencies:

```sh
git clone https://github.com/mortezaPRK/opencode-auto-mode.git
cd opencode-auto-mode
bun install --frozen-lockfile
```

Add the checkout to your global `~/.config/opencode/opencode.jsonc`, using its absolute path:

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
      "package": "/absolute/path/to/opencode-auto-mode",
      "options": {
        "model": { "id": "your-model", "providerID": "your-provider" },
        "review": "all",
        "agents": ["auto"],
        "allowInProjectEdits": false
      }
    }
  ]
}
```

Omit `model` to use OpenCode's default model. Restart the OpenCode service after changing plugins:

```sh
opencode service restart
```

Select `auto` alongside `plan` and `build`. The configurable classifier feature scopes automatic review to the agent names in `options.agents`.

Releases of `@mortezaprk/opencode-auto-mode` are published to GitHub Packages. Set `@mortezaprk:registry=https://npm.pkg.github.com` in your user npm configuration and authenticate to that registry with a GitHub token granting `read:packages`. Then replace the checkout path with `@mortezaprk/opencode-auto-mode` in the plugin entry.

## Configuration

`review: "all"` reviews eligible actions even when OpenCode would allow them. `review: "prompts"` reviews actions that already require approval. OpenCode's explicit denies remain authoritative.

`classifier.stages` selects an ordered combination of `static`, `rules`, `jev`, `openai-decision`, `laya`, and `llm` classifiers. The default is static checks followed by an LLM reviewer. Rules use [Buf's CEL evaluator](https://github.com/bufbuild/cel-es): `{ "expression": "action == 'shell' && command == 'pwd' && size(args) == 0", "decision": "allow" }`. Expressions can use `action`, `resource`, `command`, `args`, `agent`, `projectDir`, and `isDelegation`; all resources must match allow rules, and deny rules take precedence. Shell resources use OpenCode's command parsing; unsupported syntax and Windows shells require manual approval. Collection macros are disabled, and invalid results or evaluation limits require manual approval. Jev uses `TYPESAFE_API_KEY`, OpenAI Decisions uses `OPENAI_API_KEY`, and local Laya uses the loopback `/v1/systemone` endpoint with an optional `LAYA_API_KEY`.

`trusted`, `blocks`, and `exceptions` replace the corresponding reviewer policy lists. Configure these in your global config. Keep ordinary OpenCode permission rules requiring approval for sensitive actions so manual prompts remain available when the plugin is disabled.

The package's `./tui` entry provides a review indicator and manual allow/deny commands. Automatic decisions can be wrong; actions with unclear authorization should reach the normal permission dialog.

## Development

```sh
bun test
bun run typecheck
```

MIT licensed. Derived from [mellena1/opencode-auto-mode](https://github.com/mellena1/opencode-auto-mode); original copyright attribution is retained in [LICENSE](LICENSE).
