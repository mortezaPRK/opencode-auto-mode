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
- **Data egress:** a configured `decision`, `fact-review`, or `llm` stage sends
  the action and resources (including full Code Mode source), project/worktree,
  and up to 12 KB of combined root and delegated user text to that stage's model
  provider, even when audit is disabled. The decision stage sends compact
  evidence plus selected operation details. The fact-review stage first sends
  operation-only classification evidence without user authority, then, only for
  a certified fact, the same compact review evidence as the decision stage. The
  llm stage also receives the agent and broader bounded review evidence. The llm
  stage always includes Git state; the decision stage includes it only for
  git-related actions. The `static` stage makes no model call.
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
7. Confirm the user has provider/model references for any `decision`,
   `fact-review`, or `llm` stage. Do not invent model IDs or credentials.
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

4. Add a `fact-review` stage only when explicitly requested and only when the
   provider supports native decision questions of both `choice` and `predicate`
   types. It is experimental, is never added automatically, and is not part of
   the default examples. `minConfidence` accepts `0.8` through `1`, defaults to
   `0.9`, and lower values are rejected:

   ```jsonc
   { "type": "fact-review", "model": "<provider>/<model>", "minConfidence": 0.9, "timeoutMs": 5000 }
   ```

5. Add an `llm` stage for the explicit reasoning reviewer. `model` is required;
   there is no session-model fallback:

   ```jsonc
   { "type": "llm", "model": "<provider>/<reviewer-model>", "timeoutMs": 5000 }
   ```

6. Save the file. Do not restart OpenCode for a config-only change. Config files
   are watched and reload automatically; `/reload` forces a full reload if the
   plugin does not appear.
7. In a session, run `/auto-mode status`. Expected for a valid install:
   `Auto mode: on` with counts, active reviews, and breaker state.
8. If the command reports `Auto mode: invalid` with `Review disabled: <error>`
   (the desktop pill reads `Invalid config — review disabled`), inspect the
   exact error and fix the option shape. Do not add removed 1.0.x keys. A
   desktop pill reading `Review unavailable` or `status unavailable`, or a
   command that appends a storage/status error without `Review disabled:`, is a
   status/storage read failure, not a configuration error.
9. Exercise a harmless permission request, such as an in-project read the
   configured chain can resolve. Do not test with destructive commands,
   credential files, or production data.

## Options

Unknown keys fail validation. `options` must be an object with only these keys.

| Option | Default | Contract |
| --- | --- | --- |
| `classifiers` | required | Array of 1–64 ordered stages: `static`, `decision`, `fact-review`, `llm`. At most one `static`. Missing or empty is invalid. |
| `reviewTimeoutMs` | `15000` | Whole-review deadline. Integer 1–120000. |
| `breaker` | `3 / 10 / 50` | `{consecutiveDenies, windowDenies, windowSize}`. If supplied, all three keys are required; each is an integer 1–10000 and `windowDenies <= windowSize`. |
| `tui` | `true` | Boolean. Shows or hides the TUI indicator. UI-only; `false` does not disable server review. |
| `audit` | `{enabled:false,maxBytes:10485760}` | Object only. `maxBytes: 0` disables rotation. Fixed path; no path option. |

Classifier stages:

| Stage | Shape | Behavior |
| --- | --- | --- |
| `static` | `{type:"static", allowInProjectEdits?: boolean}` | Allows low-risk reads and verified in-project edits. `allowInProjectEdits: false` keeps edit/write actions out of static allows. |
| `decision` | `{type:"decision", model, timeoutMs?, minConfidence?}` | Native `ctx.experimental.generate.decisions` only. Asks `safety` and `authorization` predicates; allows only when **both** probabilities meet `minConfidence`. Defaults: timeout 3000, per-predicate floor 0.9. Never denies; ordinary abstentions continue; terminal loss is incomplete wildcard-only evidence or external directory with no verified target. |
| `fact-review` | `{type:"fact-review", model, timeoutMs?, minConfidence?}` | Experimental and opt-in. Native `choice` fact classification (`inspection`; when it does not clear the floor, including a confident `false`, a splittable shell command is asked `inspection` per segment and `segment_local` only for a segment below the floor, with one leading literal `cd` folded into the confined cwd; all-read-only segments certify `inspection`, otherwise every segment must be local at or above the floor, and an unsplittable command uses `operation_kind`, where `test_run` or `repository_read` certifies). A certified read-only `inspection` or project-local `shell_segments` fact with zero static findings is allowed on the fact alone with no review call. A certified metadata-only `project_edit` from the in-project `edit_in_project` question is also allowed on the fact alone. Every other certified fact gets native `safety` and `authorization` review, including an inspection with any finding or without static analysis, while a complete `subagent`/`task` delegation with a non-empty prompt certifies `delegation` with no fact call and only the frozen `authorization` review (child actions are reviewed separately). Allows only when the certified fact probability, `safety`, and raw `allow` probability all meet `minConfidence` for the full shape, and the fact probability plus raw `allow` for `delegation`; never denies. Defaults: timeout from `reviewTimeoutMs`, floor 0.9; accepts 0.8-1 and rejects lower values. See [Fact review](#fact-review-experimental). |
| `llm` | `{type:"llm", model, timeoutMs?}` | Native `ctx.experimental.generate.text` reviewer. `model` is explicit and required. |

The decision stage receives compact evidence: action and resources, an optional
selected operation (tool, access, targets and selected arguments) from host
metadata and the captured tool call when available, the host platform and
requested shell interpreter (bounded), one chronological root-session
user-message source, concrete static-analysis findings, and git state only for
git-related actions. Raw metadata/source blobs and agent prose are not sent.
Operation evidence is marked incomplete when selection, privacy bounds, or
correlation are lost; shared call identities or skipped outer execute snapshots
can leave the capture unavailable or ambiguous, and it is not guessed. Network
and query values remain literal arguments/resources, not filesystem targets.
Arbitrary payload keys are redacted; common search/query fields remain literal
evidence.

Only root-session user messages are user authority. The plugin follows
`parentID` to the root within 16 sessions, rejects cycles, and reads each
session's metadata and context once. Descendant user prompts are preserved
separately as delegation context in root-to-leaf order; they are nonauthority,
may narrow the local task, and cannot grant authorization, broaden scope, or
revoke a parent restriction. Root and delegation text share a 12,000-byte
budget. Authority is taken at request start (`asOf`); user messages created
after that cut are excluded from root authority and delegation. A non-finite cut
or message timestamp fails closed to **ask**. Non-null `fork` metadata asks
because forked authority provenance is unresolved; only live `fork: null` is not
a fork, and forked user text is never reclassified as delegation. A `compaction`
message in any active root or delegation context is degraded and asks. Missing
root/parent/context evidence, cycles, depth overflow, or oversized text fails
terminally to **ask**; text is not truncated and restrictions are not dropped.
These are correctness rules, not an `80%` claim.

The LLM stage receives bounded review evidence, selected static findings, and
chronological user-message boundaries. It replies with one nonempty `ALLOW:`,
`DENY:`, or `HUMAN_REVIEW:` reason. Intentional human review abstains and
continues configured stages; malformed output remains a separate failure. A
trailing static abstention preserves the last model rationale. This contract does
not guarantee that a model will reason correctly about authorization.

Stages run in array order. The first decisive allow or deny stops the chain.
Abstention, low confidence, invalid output, provider errors, and stage-local timeouts
continue to the next stage. A chain that cannot decide asks the user. Essential
evidence loss, malformed/oversized envelopes, Code Mode identity mismatch,
cancellation, and the total deadline are terminal asks, never fallback allows.
Per-stage timeouts are bounded by `reviewTimeoutMs`.

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

## Decision predicate contract

The decision stage is allow-or-abstain. It asks two separate predicate questions
with the exact names `safety` and `authorization`; they are not claimed to be
statistically independent. It allows only when **both** probabilities meet
`minConfidence`; otherwise it abstains. Malformed output, refusals, missing or
duplicated answers, out-of-range probabilities, provider errors, and timeouts
abstain. It never denies.

`minConfidence` is a probability floor applied separately to each predicate, not
a confidence in a selected label and not a calibrated certainty guarantee. The
default is `0.9`; lowering it is more permissive because both predicates must
still clear it. The plugin does not auto-tune thresholds, rewrite config, or
treat replay agreement as calibration.

Pre-generation abstention is distinct from model abstention. Ordinary incomplete
operation or truncated shell evidence, an oversized request, or a Code Mode
identity mismatch abstains before a model call. Terminal evidence loss is limited
to resource-body redaction, an external directory without a verified target, or
an explicitly incomplete operation whose only resources are `*`; these resolve to
**ask**. Final terminal checks also use the normalized decision evidence, so
normalization loss cannot be bypassed. A complete unknown MCP operation with sanitized
arguments is not terminal: it remains model-reviewed. Unknown capability is not
structurally safe; safety probability must account for it. The LLM may infer
semantics from the exact tool and arguments, but there is no declared
verification. Test runners are not assumed safe by label; assess their actual
effects. Invalid configuration is passthrough, not abstention. An ordinary
abstain continues; a malformed model answer is an `invalid-output` fallback, not
a deny.

Fallback limits: the LLM is a separate reviewer, not ground truth. Its allow does
not prove the decision stage's uncertainty was resolved, and its deny is not a
calibrated label. Recorded audits are evidence of what happened, not correctness
labels. Evaluate disagreements and malformed/error/fallback rates.

## Fact review (experimental)

`fact-review` is an explicit opt-in classifier stage, not a default and never
registered automatically. Add it only when the user asks and their provider
supports native decision questions of both `choice` and `predicate` types. The
plugin does not write global config. Existing defaults and stage order are
unchanged when the stage is absent.

Shape: `{type:"fact-review", model, timeoutMs?, minConfidence?}`. `model` is
required, `timeoutMs` is one whole-stage budget bounded by `reviewTimeoutMs`,
and `minConfidence` defaults to `0.9` and accepts `0.8` through `1`; lower
values are rejected. This is stricter than decision-stage `minConfidence`, which
accepts the full 0-1 probability range. A reported probability is not
calibration, and no accuracy target or dataset statistic is claimed.

Classification is operation-only and runs before review. A non-edit request asks
one `inspection` choice. A complete non-shell, non-file tool call instead asks
one `tool_readonly` choice with its tool name and captured arguments (the
captured script for a Code Mode `execute` call), and `true` at or above the
floor certifies the same read-only `inspection`. If inspection does not clear the floor (including a
confident `false`), a splittable shell command is classified per segment: each
segment asks the same `inspection` choice first, and only a segment below the
floor asks `segment_local`, with one leading literal `cd` folded into the
confined segment cwd; all-read-only segments certify read-only `inspection`,
otherwise every segment must be local at or above the floor. A command that
cannot be split gets one `operation_kind` choice, where `test_run` or
`repository_read` can become a fact. Per-segment questions also receive the
whole command as `fullCommand` context, and an unsplittable command whose
`operation_kind` does not certify gets one `command_local` choice, whose `true`
certifies `command_local` for the full review. A model-derived fact must meet the threshold
and carry its exact source-input hash and a nonempty model label: the
provider-reported served model when the response includes one, otherwise the
configured model reference; unknown, malformed, or unproven facts abstain. User messages, delegations, transcripts,
and static findings are excluded from this classification call.

A certified read-only `inspection` with zero static findings is allowed on the
fact alone: no review call is made. A certified `shell_segments` fact with zero
static findings is likewise project-local and allowed on the fact alone, and
keeps that full review with any finding or without static analysis. A certified
metadata-only `project_edit` from the in-project `edit_in_project` question is
also allowed on the fact alone. Every other certified fact gets the frozen
`safety` and `authorization` review questions, and allow requires the fact
probability, the raw `allow` probability, and `safety` to meet the floor, with
the selected choice `allow`; anything else abstains. A complete `subagent` or
`task` delegation with a non-empty captured `prompt` is certified as
`delegation` without a fact call and gets one review call with only the same
frozen `authorization` question, allowing only when the selected choice is
`allow` and the raw `allow` probability meets the floor; child actions are
reviewed separately. An inspection with any
static finding, or without static analysis, keeps that full review. The stage
never denies.
Mandatory score deny/ask guards run first and cannot be overridden; uncertain
facts, malformed output, provider errors, and stage-local timeouts abstain and
continue to later stages, and a pipeline that nothing decides ends in `ask`.
Cancellation and the whole-review deadline are terminal instead: they stop the
stage chain and resolve to `ask` without running a later classifier. Terminal preflight loss (a protected path, redacted
resources or delegations, or missing root authority) also resolves to `ask`.
The LLM stage is fallback evidence, not ground truth.

When a review call is made, it uses the same compact evidence as the decision
stage, including root authority and delegation context under the existing 12 KB
budget and `asOf` cutoff described in
[Decision predicate contract](#decision-predicate-contract). Root messages remain
the only authority, delegations only narrow, and a non-finite cutoff still fails
closed to `ask`.

No plugin-config key enables edit-body egress. `includeEditPayload` is a host
API option; an unknown plugin option is rejected, and the plugin always passes
`false`. With that default, an `edit` action whose targets all resolve inside
the worktree and outside `.git`, `.jj`, `node_modules` and secret-like names,
with zero static findings, is asked one metadata-only `edit_in_project`
question carrying only the tool, project-relative targets and project name, and
`true` at or above the floor certifies `project_edit` and allows with no review
call; anything else abstains and continues to the next stage. When a host enables `includeEditPayload` and a
consented, host-minted, bounded edit body certifies `local_edit` at or above the
floor, that same body
is included as `changeContent` in the `safety`/`authorization` review, and the
edit is allowed only if the fact, `safety`, and `allow` gates all clear;
otherwise it abstains and continues to the next stage. That body-review
guarantee is scoped to body-captured `local_edit` facts: a metadata-only
`project_edit` can allow without capturing or reviewing the edit body.
Audit remains opt-in and unredacted, with no separate fact-review telemetry.

## Guardrails and Code Mode

Built-in guards are not a policy language and are not user-extensible. They cover
known credential stores, risky shell structure, recursive external deletion,
history changes, symlink traversal, project scope, and ambiguous syntax. Established
credential-store access denies for file tools and grammar-established shell file
operands alike. Runtime `.env` and `.env.*` files are protected; `.env.example`,
`.env.sample`, `.env.template`, and `.env.<environment>.{example,sample,template}`
are reviewed, not assumed safe. Generic auth/key names, dotfiles, ordinary
configuration (including `.github`, `.git`, `.opencode`, editor/CI hooks and
`.npmrc`), and unresolved metadata are review evidence, not proof of credentials.
Known stores include anchored private-key/auth locations and the documented
OpenCode database (including exact SQLite sidecars) or legacy auth file; arbitrary
database basenames are not protected by name alone. Canonical aliases are checked
without reading secret contents; this is not a sandbox or TOCTOU guarantee.
Git global options and complex/dynamic POSIX shell syntax stay
HIGH and reach configured decision/LLM stages; static review abstains instead of
forcing a user prompt. Missing VCS or containment facts reach review rather than
inventing an upstream or clean-tree status. Deliberate history gates for a known
default branch or known dirty tree still require human approval. Powerful capabilities
(preload flags, ordinary API fields, broad environment access or world-write modes)
are not by themselves prohibited actions. Visible established prohibitions still win.
Complete commands beyond the parser's 4096-character limit can reach bounded model
review; unsupported dialects retain their raw text and known platform/interpreter
without applying POSIX-derived denials. Loading a `skill` is LOW because it only loads instructions; subsequent
tool calls are checked independently. `glob` and `grep` scope is not verified,
so static review abstains. `webfetch`, `websearch`,
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
bun scripts/replay.ts --input '<audit-jsonl-path>' --project '<project-root>' --json
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
| Review never uses a model | A static-only chain asks when static abstains. Add a valid `decision`, `fact-review`, or `llm` stage. |
| Decision stage always abstains | Check whether `safety`, `authorization`, or both fall below `minConfidence`; inspect probability distributions and malformed/error counts. Provider must support native predicate decisions. Lowering the floor is more permissive but not calibrated; otherwise remove the stage. |
| Fact-review stage always abstains | Check whether the certified fact probability, `safety`, or raw `allow` probability fell below `minConfidence`; confirm the provider supports native `choice` and `predicate` questions. A `local_edit` needs a host-enabled, consented, bounded body included as `changeContent`; the plugin keeps `includeEditPayload` off, edit bodies are not configurable, and a floor below `0.8` is rejected. Do not treat probabilities as calibration. |
| No prompts appear | Check client Auto/YOLO and native permissions. Plugin asks can be auto-approved by the client. |
| Desktop pill `Review unavailable` or `status unavailable`; command appends a status/storage error without `Review disabled` | This is not necessarily a config error. Retry, then check session storage and the status RPC. A storage failure during review resolves to `ask`. |
| Review latency too high | Prefer a `static` stage; tune `reviewTimeoutMs` and per-stage timeouts; remove unused model stages. |

## Completion checklist

- [ ] Exactly one global registration exists; no project/`cli.json` duplicate.
- [ ] `classifiers` is valid, ordered, and has at most one `static`.
- [ ] Every `decision`/`fact-review`/`llm` model reference is configured in the
      user's provider settings; no credentials or endpoints were added to this
      repository.
- [ ] `/auto-mode status` reports `Auto mode: on` and no configuration error.
- [ ] A harmless permission request is reviewed, and mode commands respond.
- [ ] Audit remains off unless the user explicitly authorized temporary local
      debugging.
- [ ] The user knows a configured `decision`/`fact-review`/`llm` stage sends
      action and resources (including full Code Mode source), agent,
      project/worktree, git state, and up to 12 KB of combined root and
      delegated user text to that model's provider even with audit off.
- [ ] The user knows that native deny remains final, invalid config is
      passthrough, and client Auto/YOLO can suppress plugin asks.
