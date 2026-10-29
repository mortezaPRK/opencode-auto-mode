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

OpenCode watches configuration files and reloads plugins after a save, so no
restart is needed. If a change does not take effect, run `/reload` in the TUI to
force a full reload.

There is no default review pipeline, and empty options are invalid. Add at least
one review entry. Built-in checks deny dangerous shell commands, allow common
read-only commands, and send other parsed commands to the configured reviewers.
Dynamic syntax such as command substitution, nested shells, and stateful builtins
still requires manual approval.

The snippets below change parts of that configuration; keep your `classifiers`
list when adding other options.

### How a shell command is classified

Commands are parsed before they are judged, so text that merely mentions a
dangerous word — a commit message, a search pattern, a heredoc body — is not
treated as a dangerous operation. Denials apply to the parsed executable and its
arguments, and nested shells are inspected recursively.

Read-only allowlisting checks the executable **and** its flags. Options that
write files or run programs (`rg --pre`, `sort -o`, `tree -o`, `file -C`,
`bat --pager`, `hostname NAME`, `uniq IN OUT`) are handed to the reviewers
instead of being auto-approved.

A shell result is final when it is `deny` or `ask`: `ask` means manual approval,
even if a model reviewer is configured. Read-only auto-approval is narrower than
the pipeline: for shell actions, the static stage auto-approves only commands the
guard recognizes as read-only. Every other parsed command that is not denied —
including a write such as `pwd > marker` — goes to the configured reviewers, and a
model reviewer may allow it. With no reviewer configured, it stays `ask`.

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

An entry can allow, deny, or ask, which stops the pipeline. An entry that abstains
hands the action to the next entry. If nothing decides, the action remains `ask`.

## Time limit and failures

A review never blocks a permission prompt indefinitely. One deadline covers every
entry in the pipeline, including both model calls of an `llm` entry:

```jsonc
{ "options": { "reviewTimeoutMs": 60000 } }
```

`reviewTimeoutMs` accepts 1000–120000 and defaults to 60000. When the deadline
passes, provider and context requests are aborted and the action is asked with
`Auto-mode review deadline exceeded`. Interrupting a session also abandons its
review, so a stopped turn cannot later receive an automatic approval.

Failures are reported with a bounded cause — `deadline`, `timeout`, `cancelled`,
`provider`, `invalid-output`, or `context` — in the audit log and in OTLP
(`error.kind`), while the user-facing message stays generic.

A typed decision reviewer that is unavailable or returns a malformed response
abstains, so the next entry runs. An `llm` entry behaves differently: a timeout
or provider error abstains, but an unparseable final answer is an `ask` (manual
approval) with `invalid-output`, and the pipeline stops there.

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
Invalid options show `auto-mode: invalid config` in the same place and raise an
error toast when the configuration is loaded. OpenCode's own permission dialog
handles manual approvals.

The indicator window is longer than the maximum review deadline, so a slow
review stays visible until it resolves.

## Desktop app (preview)

OpenCode 2.2.0+ can load the plugin's GUI entry in the desktop app. It adds a
composer pill and an **Auto-mode** side panel showing whether the current session
is being reviewed and how recent actions were decided, plus a command-palette
entry to open the panel.

The GUI only reads state. Every permission decision still comes from the server
part, so disabling the GUI never disables automatic review.

The GUI is loaded from the desktop app's own background server and reads that
server's auto-mode state. If you connect the app to another server, that server's
reviews do not appear in the panel.

The desktop app reads plugins only from the **global** `opencode.json(c)`. If
your TUI configuration lives in `cli.json`, add the package to the global file as
well:

```jsonc
{
  "plugins": [{ "package": "@mortz.prk/opencode-auto-mode", "options": { "classifiers": [{ "type": "static" }] } }]
}
```

Turn the GUI off without removing the plugin in **Settings → Extensions →
Plugins**. The GUI plugin API is experimental and may change between OpenCode
releases; the server and TUI parts do not depend on it.

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

## All plugin options

| Option | Default | Meaning |
| --- | --- | --- |
| `classifiers` | — | Ordered review entries; at least one is required. |
| `reviewTimeoutMs` | `60000` | Deadline for one complete review (1000–120000). |
| `auditLog` | off | `true` writes the default JSONL file; a string sets the path. |
| `otlp` | off | `true` uses OpenCode's OTLP environment; an object sets `endpoint`, `headers`, and `timeoutMs`. |
| `tui` | on | Set `false` to hide the TUI indicator. |

Static entries accept `allowInProjectEdits`. Decision entries accept
`minConfidence`, `timeoutMs`, `apiKeyEnv`, and `endpoint` (loopback `laya` only;
defaults to `http://127.0.0.1:8000/v1/systemone`). OpenCode reloads the plugin
when you save, so option changes apply without a restart; run `/reload` in the
TUI if a change does not take effect. Invalid options disable automatic approval
and are reported in the TUI and over the status RPC.

## Data that leaves the machine

Reviewers see the proposed action, its resources, the session directory, the
requesting agent, the pending permission `metadata` and `source`, and a bounded
transcript of recent user messages and tool inputs (12 KB, with the head and tail
of each tool input). Nothing else about the session is sent.

* A model reviewer receives that material through OpenCode's own session model or
  the `model` you configure.
* A typed decision reviewer receives it at the configured provider endpoint.
* Audit records and OTLP log records keep the action, agent, up to 16 resources,
  a short reason, and, on failure, a short error detail. Both pass the record
  through one sanitizer, which bounds these fields — 128 characters for the
  action and agent, 64 for the stage, 512 for each resource, reason, and error
  detail — but does **not** redact text.
* OTLP exports logs and traces as separate streams (`/v1/logs` and `/v1/traces`).
  Trace root attributes use the same sanitizer, so their action, agent, and stage
  are bounded like the log fields. Each reviewer attempt adds a child span with
  its model and outcome; the `model` attribute is not clipped. Traces do not
  include resources, reasons, or error-detail text.
* Text in every stream is unredacted, including the action and agent. Traces
  carry the action and agent; logs carry those plus resources, reasons, and
  error details. These fields may be sensitive, and resources or reasons can
  contain inline file contents or shell commands, including credentials such as
  an `Authorization` header. Audit JSONL keeps the same unredacted fields as OTLP
  logs. Enable `auditLog` or `otlp` only if you are comfortable storing or
  exporting that material.
* Records do not include the reviewer prompt, the session transcript, or API keys
  configured for providers.

## Platform limits

* Windows always asks for shell actions; the guard only parses POSIX syntax.
* Reviews happen inside the OpenCode server, so a headless or remote TUI behaves
  the same as a local one. The desktop GUI needs OpenCode 2.2.0+.

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
without executing anything (run from a checkout; it reads the OpenCode database
read-only and needs `--config` if your global config is not at a default path):

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
bun run build:gui
bun run test:integration
```

`build:gui` writes `dist/gui-experimental.cjs`, the file the `./gui-experimental`
export points at. It runs automatically before publishing.

## Credit

Created originally by [Andrew Mellen (mellena1)](https://github.com/mellena1) in
[mellena1/opencode-auto-mode](https://github.com/mellena1/opencode-auto-mode),
also credited as the author in [package.json](package.json). This independent
project retains the original [MIT license](LICENSE).
