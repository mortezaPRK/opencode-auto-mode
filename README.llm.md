# OpenCode Auto Mode: AI installation guide

Use this file when an AI agent is installing, auditing, or migrating the plugin
for a user. The human-facing overview is [README.md](README.md). Code changes are
covered by [CONTRIBUTING.md](CONTRIBUTING.md).

Sources of truth checked for this guide:

- [OpenCode V2 configuration](https://opencode.ai/v2/docs/config)
- [OpenCode V2 plugins](https://opencode.ai/v2/docs/build/plugins)
- This repository's `package.json` and `src/` implementation.

## Contract

- Package: `@mortz.prk/opencode-auto-mode` version `1.1.0`.
- Host: OpenCode V2; the checked-in SDK/schema targets OpenCode `2.2.0`.
- Register the package **once** in the user-owned global config:
  `~/.config/opencode/opencode.json(c)` or
  `$XDG_CONFIG_HOME/opencode/opencode.json(c)`. `XDG_CONFIG_HOME`, when set,
  must be absolute.
- The configuration file must be outside the repository, contain no symlink in
  any path component, be user-owned, not group/other-writable, and be a single
  hardlink. System-owned non-writable parents are accepted.
- Do not add the full plugin to project config, `cli.json`, or
  `.opencode/plugins/` as a second registration. A plain package name, a
  version-suffixed name, a local path (absolute or relative to the config file),
  or a `file://` URL that resolves to this package all count as registrations.
- Do not put model endpoints, credentials, production model defaults, or
  allowlists in repository files. They belong in the user's OpenCode provider
  config.
- The plugin reads safety options from its global registration only. It ignores
  project-merged `ctx.options` and rejects duplicate registrations or ambiguous
  global files.
- **Data egress:** a configured `decision` or `llm` stage sends the action and
  resources (including full Code Mode source), agent, project/worktree, git
  state, and up to 12 KB of user messages to that stage's model provider, even
  when audit is disabled. The `static` stage makes no model call.
- Registration strings and option values do **not** support OpenCode
  `{env:...}` or `{file:...}` substitution. Write concrete values after the user
  chooses them.
- Invalid configuration is **passthrough**, not fail-closed. Review stops and
  native OpenCode behavior applies.

## Preflight

1. Confirm the OpenCode version. Install or test against V2, not V1.
2. Locate the global config. Prefer `opencode.jsonc`; OpenCode accepts
   `opencode.json` or `opencode.jsonc`.
3. Verify loader acceptance: the file must be outside the repository, have no
   symlink in any path component, be user-owned, not group/other-writable, and
   be a single hardlink. `XDG_CONFIG_HOME`, when set, must be absolute; when
   unset, the loader uses `~/.config`. Non-writable system-owned parents are
   accepted.
4. Back up the global config before editing it.
5. Inspect `plugins` for an existing registration of
   `@mortz.prk/opencode-auto-mode`. There must be exactly one. A plain package
   name, a version-suffixed name such as
   `@mortz.prk/opencode-auto-mode@1.1.0`, a local path (absolute or relative),
   and a `file://` URL that resolves to this package all count as registrations.
6. If both `opencode.json` and `opencode.jsonc` exist, check both. A matching
   registration in both files is ambiguous and invalid.
7. Confirm the user has provider/model references for any `decision` or `llm`
   stage. Do not invent model IDs or credentials.
8. For a local checkout used in the desktop app, run `bun run build:gui` before
   testing; desktop loads `dist/gui-experimental.cjs`.
9. Preserve every unrelated setting in the file. Add or edit only the plugin
   entry.

The config schema is `https://opencode.ai/config.json`. A global example:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [{
    "package": "@mortz.prk/opencode-auto-mode",
    "options": {
      "classifiers": [
        { "type": "static" },
        { "type": "llm", "model": "<provider>/<reviewer-model>" }
      ],
      "reviewTimeoutMs": 15000,
      "breaker": { "consecutiveDenies": 3, "windowDenies": 10, "windowSize": 50 },
      "tui": true,
      "audit": { "enabled": false, "maxBytes": 10485760 }
    }
  }]
}
```

For a local checkout, use the absolute checkout directory or a `file://` URL as
`package`. It must resolve to this package's real directory. For a published
package, a version suffix such as `@mortz.prk/opencode-auto-mode@1.1.0` is valid.

## Install procedure

1. Edit the chosen global config. Keep exactly one matching plugin entry.
2. Set `options.classifiers` to at least one stage. Start with `static` only when
   no review model is available:

   ```jsonc
   "classifiers": [{ "type": "static" }]
   ```

3. Add a `decision` stage only when the user has a native decision provider:

   ```jsonc
   { "type": "decision", "model": "<provider>/<decision-model>", "minConfidence": 0.9, "timeoutMs": 3000 }
   ```

4. Add an `llm` stage for the explicit reasoning reviewer. `model` is required;
   there is no session-model fallback:

   ```jsonc
   { "type": "llm", "model": "<provider>/<reviewer-model>", "timeoutMs": 5000 }
   ```

5. Save the file. Do not restart OpenCode for a config-only change. Config files
   are watched and reload automatically; `/reload` forces a full reload if the
   plugin does not appear.
6. In a session, run `/auto-mode status`. Expected for a valid install:
   `Auto mode: on` with counts, active reviews, and breaker state.
7. If the command reports `Auto mode: invalid` with `Review disabled: <error>`
   (the desktop pill reads `Invalid config — review disabled`), inspect the
   exact error and fix the option shape. Do not add removed 1.0.x keys. A
   desktop pill reading `Review unavailable` or `status unavailable`, or a
   command that appends a storage/status error without `Review disabled:`, is a
   status/storage read failure, not a configuration error.
8. Exercise a harmless permission request, such as an in-project read the
   configured chain can resolve. Do not test with destructive commands,
   credential files, or production data.

## Options

Unknown keys fail validation. `options` must be an object with only these keys.

| Option | Default | Contract |
| --- | --- | --- |
| `classifiers` | required | Array of 1–64 ordered stages: `static`, `decision`, `llm`. At most one `static`. Missing or empty is invalid. |
| `reviewTimeoutMs` | `15000` | Whole-review deadline. Integer 1–120000. |
| `breaker` | `3 / 10 / 50` | `{consecutiveDenies, windowDenies, windowSize}`. If supplied, all three keys are required; each is an integer 1–10000 and `windowDenies <= windowSize`. |
| `tui` | `true` | Boolean. Shows or hides the TUI indicator. UI-only; `false` does not disable server review. |
| `audit` | `{enabled:false,maxBytes:10485760}` | Object only. `maxBytes: 0` disables rotation. Fixed path; no path option. |

Classifier stages:

| Stage | Shape | Behavior |
| --- | --- | --- |
| `static` | `{type:"static", allowInProjectEdits?: boolean}` | Allows low-risk reads and verified in-project edits. `allowInProjectEdits: false` keeps edit/write actions out of static allows. |
| `decision` | `{type:"decision", model, timeoutMs?, minConfidence?}` | Native `ctx.experimental.generate.decisions` only. Defaults: timeout 3000, confidence 0.9. |
| `llm` | `{type:"llm", model, timeoutMs?}` | Native `ctx.experimental.generate.text` reviewer. `model` is explicit and required. |

Stages run in array order. The first decisive allow or deny stops the chain.
Abstention, low confidence, invalid output, provider errors, and timeouts continue
to the next stage. A chain that cannot decide asks the user. Per-stage timeouts
are bounded by `reviewTimeoutMs`.

## Decision behavior

| State | Native allow | Native ask | Native deny |
| --- | --- | --- | --- |
| On | Reviewed | Reviewed | Final; not reviewed |
| Off | Passthrough | Passthrough | Final |
| Paused breaker | Resolves to `ask` | Native prompt | Final |
| Invalid config | No review; native behavior | No review; native behavior | Final |

- Native deny is always final. Saved **Always** entries are re-reviewed when mode
  is on but are never deleted, narrowed, rewritten, or migrated.
- A valid review that fails, times out, is interrupted, or cannot resolve
  uncertainty resolves to `ask`.
- Mode off restores the original host effect and message.
- A paused breaker resolves a reviewed native allow to `ask`; an existing native
  ask keeps its prompt. Paused mode never automatically allows.
- `/auto-mode on` resumes and resets the breaker.
- Session state is stored through `ctx.storage` and survives plugin reloads.

## Guardrails and Code Mode

Built-in guards are not a policy language and are not user-extensible. They cover
protected repository/config paths, credential paths, risky shell structure,
recursive external deletion, history changes, symlink traversal, project scope,
and ambiguous syntax. Protected shell operands are a hard deny; protected
`read`/`edit` targets and symlink traversal have a mandatory ask floor. `glob` and
`grep` scope is not verified, so static review abstains. `webfetch`, `websearch`,
`execute`, and unknown tools remain HIGH.

Code Mode is bridged in `execute.before` through `ctx.permission.assert`.
Permission resources and save entries use
`execute:sha256:<UTF-8-source-hash>`, the SHA-256 of the exact source. Metadata
only validates that hash identity, and mismatches are rejected. After validation,
the reviewer receives the source as a resource; the source is evidence, not
authorization to execute it. Code Mode stays HIGH because JavaScript can hide
egress behind aliases, templates, and computed URLs. Old raw-code approvals
generally do not match the hash identity; broad native `execute` rules still do.

Coverage is limited to the permission `evaluate` hook and the Code Mode
`execute.before` bridge. The `execute.after` hook only adds a UX warning; it makes
no permission decision. If the plugin is absent, invalid, or disabled, native
behavior applies. Native path grants are not an OS sandbox. Other project plugins
can affect residual effects; only run trusted code.

## Native Auto/YOLO

OpenCode's client-side Auto/YOLO setting can auto-approve asks without a dialog,
including plugin asks. When it is enabled:

- plugin checks still run for requests the host exposes;
- plugin denies still block;
- plugin asks are not an interactive gate;
- the plugin cannot detect, mirror, or change the client switch.

Tell the user to disable client Auto/YOLO if they need prompts. Invalid plugin
configuration also leaves native behavior, including client auto-approval, in
control.

## Audit and replay

Audit is the only plugin-generated telemetry. It is **off by default**, local, and
unsafe. There is no OTLP, metrics, or remote export. Enable it only for temporary
debugging:

```jsonc
"audit": { "enabled": true, "maxBytes": 10485760 }
```

- Fixed path: `$XDG_STATE_HOME/opencode-auto-mode/decisions.jsonl` when
  `XDG_STATE_HOME` is absolute; otherwise
  `~/.local/state/opencode-auto-mode/decisions.jsonl`.
- `audit` is an object only. Booleans, strings, and custom `path` fields are
  invalid.
- Records are unredacted and may contain secrets, credentials, PII, file
  contents, source, user context, full model prompts, and model outputs.
- File mode `0600` and directory mode `0700` are access control, not
  sanitization.
- When a record would exceed `maxBytes`, the active file rotates to a sibling
  archive. Archives are retained; the plugin does not prune or delete them.
  `maxBytes: 0` disables rotation.
- Host-event capture covers only SDK-visible events. The same JSONL also receives
  plugin lifecycle and full model request/response records. Row counts are not
  decision counts.
- `hostEffect` is the effect at the hook; `decision` is the applied plugin
  effect. Neither is necessarily the final execution outcome.
- Never commit, upload, or share audit files without review and redaction. Tests
  must use scratch XDG roots, never personal logs.

Offline replay is a repository-checkout tool because `scripts/` is not in the
published package file list:

```sh
bun scripts/replay.ts --input <audit-jsonl-path> --project <project-root> --json
```

Replay does not execute tools or contact models. It reports current static
routing diagnostics only and cannot reconstruct native policies, saved approvals,
model decisions, historical settings, VCS state, or invisible events.

## Migration from 1.0.x

Back up global config first. The plugin does not rewrite or migrate user files.
A config containing any removed key is invalid and acts disabled.

| Removed setting | Required change |
| --- | --- |
| `enabled` | Remove it. Mode and the required classifier list control review. |
| `reviewNativeAllows` | Remove it. Native allows are always reviewed when mode is on. |
| `shadow` | Remove it. Shadow mode was removed with no replacement. |
| `auditLog` | Replace with `audit: { enabled, maxBytes }`. The path is fixed. |
| `otlp` | Remove it. Remote telemetry was removed. |
| `performanceTelemetry` | Remove it. Metrics export was removed. |
| `fetchHosts` | Remove it. Code Mode stays HIGH. |
| `rulesPath` | Remove it. Custom rules were removed; built-in guards remain. Existing rule files are no longer read. |

| Removed stage key | Required change |
| --- | --- |
| `llm.model` | Now required. There is no implicit session-model fallback. |
| `policy` | Remove it. Custom policy/rules were removed. |
| `endpoint` | Remove it. There is no plugin HTTP adapter or endpoint option. |
| `apiKeyEnv` | Remove it. Credentials belong in provider config. |

After migration, ensure `classifiers` is present and non-empty, with 1–64 stages
and at most one `static`. Preserve saved approvals and native rules; the plugin
does not delete or migrate them. Audit native permission/policy ordering
read-only before changing it.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `Auto mode: invalid` with `Review disabled: <error>`; desktop pill `Invalid config — review disabled` | Exactly one global registration; only the five public option keys; valid classifier shapes and values. Fix the reported error. |
| `Auto-mode is not registered in user-owned global configuration` | Register the package in global `opencode.json(c)`. A project-only registration does not satisfy the loader. |
| `Ambiguous auto-mode global registrations` | Remove duplicate entries across `opencode.json` and `opencode.jsonc`, or duplicate objects in one file. A package name, name with version, local path, and `file://` URL resolving to this package can all collide. |
| `XDG_CONFIG_HOME must be absolute` or a `Policy file`/`Policy path` rejection | Use an absolute `XDG_CONFIG_HOME`; put config outside the repository; remove symlinks; make it user-owned, not group/other-writable, single-hardlinked, and not inside the current project. Non-writable system-owned parents are allowed. |
| `Unknown auto-mode option '<name>'` | Remove removed/unknown keys. Runtime errors do not suggest replacements. |
| Review never uses a model | A static-only chain asks when static abstains. Add a valid `decision` or `llm` stage. |
| Decision stage always abstains | Provider must support native decisions; lower confidence or check provider support. Otherwise remove the stage. |
| No prompts appear | Check client Auto/YOLO and native permissions. Plugin asks can be auto-approved by the client. |
| Desktop pill `Review unavailable` or `status unavailable`; command appends a status/storage error without `Review disabled` | This is not necessarily a config error. Retry, then check session storage and the status RPC. A storage failure during review resolves to `ask`. |
| Review latency too high | Prefer a `static` stage; tune `reviewTimeoutMs` and per-stage timeouts; remove unused model stages. |

## Completion checklist

- [ ] Exactly one global registration exists; no project/`cli.json` duplicate.
- [ ] `classifiers` is valid, ordered, and has at most one `static`.
- [ ] Every `decision`/`llm` model reference is configured in the user's provider
      settings; no credentials or endpoints were added to this repository.
- [ ] `/auto-mode status` reports `Auto mode: on` and no configuration error.
- [ ] A harmless permission request is reviewed, and mode commands respond.
- [ ] Audit remains off unless the user explicitly authorized temporary local
      debugging.
- [ ] The user knows a configured `decision`/`llm` stage sends action and
      resources (including full Code Mode source), agent, project/worktree, git
      state, and up to 12 KB of user messages to that model's provider even with
      audit off.
- [ ] The user knows that native deny remains final, invalid config is
      passthrough, and client Auto/YOLO can suppress plugin asks.
