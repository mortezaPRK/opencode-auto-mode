# Contributing

This repository is the `opencode-auto-mode` plugin for OpenCode V2. Start with
[README.md](README.md) for user setup and [README.llm.md](README.llm.md) for the
AI installation contract. This file covers the codebase, local development, and
review expectations.

## Repository map

| Path | Responsibility |
| --- | --- |
| `src/index.ts` | Plugin entry. Wires the permission `evaluate` hook, Code Mode `execute.before/after`, mode commands, status RPC, audit, and cleanup. |
| `src/config.ts` | Strict public option parsing and defaults. Unknown keys fail. |
| `src/global-options.ts` | Loads safety options from exactly one user-owned global registration. Ignores project-merged `ctx.options`; rejects duplicate registrations and env/file substitution. |
| `src/score.ts`, `src/score/` | `src/score.ts` is the public `scoreRequest` compatibility re-export. Implementation lives under `src/score/` (`index`, `types`, `limits`, `files`, `history`, `shell`, `shell-argv`, `shell-safety`, `shell-baseline`). Hand-written shell, path, credential, VCS, and tool routing guards live in this ownership area. |
| `src/shell.ts`, `src/shell-copy.ts` | Parsed shell guard, operand expansion/copy-mode provenance, protected accesses, deletion containment, and ambiguity routing. |
| `src/shell-policy.ts` | Shell grammar and command policy vocabulary. Large on purpose; it models parser behavior rather than matching raw text. |
| `src/path-policy.ts`, `src/tiers.ts` | Anchored credential-store roles and metadata resolution; shell operand adapters, containment, and safe edit targets. |
| `src/worktree.ts` | Discovers the session's current worktree root and canonical location. |
| `src/gates.ts` | VCS preconditions for history-changing commands. Missing facts fail toward review. |
| `src/classifier.ts` | Ordered classifier pipeline. First decisive allow/deny wins; otherwise ask. |
| `src/authority.ts` | Root user-authority collection: follows the parent chain to the root within 16 sessions, rejects cycles, keeps root user messages as authority and descendant prompts as separate nonauthority delegation context, and enforces the combined 12 KB text budget. Missing, cyclic, overdeep, or oversized evidence is terminal. |
| `src/decision.ts`, `src/decision-evidence.ts` | Native typed decision stage using `ctx.experimental.generate.decisions`, plus the compact evidence builder shared with replay. |
| `src/decision-facts.ts`, `src/edit-capture.ts`, `src/edit-fact.ts` | Opt-in operation-fact classification (`inspection`, shell `test_run`, bounded `local_edit`) and factory-minted edit capture identity; a splittable shell command asks `inspection` per segment with `segment_local` only below the floor and may fold one confined leading literal `cd`. Per-segment asks also carry the whole command as `fullCommand` context, and an unsplittable command whose `operation_kind` does not certify gets one `command_local` ask that can only certify its own `command_local` kind for the full review. A fact is evidence, never permission or consent. |
| `src/fact-review.ts`, `src/fact-review-input.ts`, `src/fact-verdict.ts` | Experimental fact-review stage: frozen request snapshot and preflight, frozen `safety`/`authorization` review questions (a certified read-only `inspection` with zero static findings, and likewise a project-local `shell_segments` fact with zero findings, are allowed on the fact alone without review), certified-fact source hash and model label (the provider-reported served model when the response includes one, otherwise the configured model reference), and strict floor in the `0.8`-`1` range (default `0.9`). Allows or abstains only; never denies. |
| `src/reviewer.ts` | LLM reviewer prompt, evidence filtering, response parsing, and deny-gate behavior. |
| `src/code-mode.ts` | Code Mode SHA-256 identity, save entry, identity validation, and reviewer source resource. |
| `src/mode.ts` | Durable per-session mode, daily counts, breaker window, and cancellation repair. |
| `src/status.ts`, `src/rpc.ts` | Bounded status surface and typed RPC contract (`status`, `setMode`). |
| `src/gui-state.ts`, `src/gui.tsx`, `src/tui.tsx` | Shared UI state plus desktop GUI and terminal UI parts. |
| `src/audit.ts`, `src/debug-events.ts` | Opt-in local JSONL audit and unsafe debug capture, including rotation. |
| `src/user-files.ts` | JSONC parsing and user-owned-file checks. |
| `src/timeout.ts`, `src/errors.ts` | Bounded provider calls and stable error categories. |
| `scripts/replay.ts` | Checkout-only offline audit replay with static diagnostics. |
| `scripts/replay-decisions.ts` | Checkout-only audit-backed decision evaluation: recorded-answer dry-run by default, opt-in `--live` native replay. |
| `scripts/decision-candidate.ts` | Checkout-only recorded/`--live` decision-candidate evaluator. Requires an explicit model and a threshold of at least 0.9, reports raw probability distributions with optional expected values only as comparison labels, and stores no prompts or raw inputs. |
| `scripts/no-personal-defaults.test.ts` | Privacy guard for models, endpoints, credentials, and allowlist-shaped defaults. |
| `scripts/dev-reload.sh` | Optional GUI build plus an explicit `opencode reload` request. Never restarts the live service. |
| `integration/opencode.ts` | Real `opencode serve` integration harness using scratch HOME/XDG roots and fixture providers. |
| `integration/transport.ts`, `integration/code-mode-identity.ts`, `integration/spikes.ts` | Fixture transport, Code Mode identity regression, and isolated host-behavior checks. |
| `.github/workflows/` | PR checks and the manually triggered npm release workflow. |

Tests live next to the source as `*.test.ts`. The server entry is exported through
the package root; `./tui`, `./rpc`, and `./gui-experimental` are separate exports.
`src/.npmignore` excludes test files from the packaged `src` directory.

Documentation is intentionally exactly three root files: `README.md` (human
setup), `README.llm.md` (AI installation), and `CONTRIBUTING.md` (this file). All
three are listed in `package.json` `files` and ship in the npm package. There is
no `docs/` directory; do not recreate one.

## Local development

Prerequisites: Bun for the repository scripts, and OpenCode V2 for integration
tests. CI uses Bun `1.4.3` and Node `24`.

```sh
bun install
bun test
bun run lint
bun run typecheck
bun run build:gui
```

The server part is TypeScript loaded from `src/`; no server build step is needed.
`bun run build:gui` writes `dist/gui-experimental.cjs` and is required before
desktop testing or packaging. `prepublishOnly` builds the GUI automatically.

To dogfood a checkout, register its absolute directory **once** in your global
config, preserving your existing options:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [{
    "package": "/absolute/path/to/opencode-auto-mode",
    "options": {
      "classifiers": [
        { "type": "static" },
        { "type": "llm", "model": "<provider>/<reviewer-model>" }
      ]
    }
  }]
}
```

Do not also register it in project config, `cli.json`, or `.opencode/plugins/`.
The global-options loader requires exactly one matching global registration.
Config files reload automatically. `scripts/dev-reload.sh [--gui]` only requests
`opencode reload`; source/dependency watching and cached server-code replacement
remain unverified. Do not restart a shared live service as a routine edit step.

## Host behavior notes

These were observed against OpenCode `2.2.x`. Re-check them on the eventual
minimum server version before making release claims.

- A configured permission deny can skip `evaluate`, while a `policies` deny can
  still invoke it before the final native block. Do not treat `hostEffect` as the
  final execution outcome.
- The actual `execute` tool does not invoke permission `evaluate`; the plugin's
  `execute.before` bridge is required for Code Mode review.
- Project registrations can merge `ctx.options`; `src/global-options.ts` ignores
  those merged options rather than rejecting them by reading only the user-owned
  global registration. That is a narrow configuration boundary, not a sandbox
  against project plugins.
- Config saves reload plugins. An explicit server reload can pick up a source
  marker, but attribution to the CLI versus automatic watching, and dependency or
  bundle watching, remain unverified.
- Native permission rules were observed as last-match-wins. Put broad asks
  before exceptions. Allows still reach the permission hook.

## Tests

Run the full unit suite after source changes settle:

```sh
bun test
```

Focused checks while touching docs, scripts, or a narrow module:

```sh
bun test src/score.test.ts src/score-security.test.ts src/shell.test.ts
bun test src/fact-review.test.ts src/fact-verdict.test.ts
bun test scripts/no-personal-defaults.test.ts scripts/replay.test.ts scripts/decision-candidate.test.ts scripts/replay-decisions.test.ts
bunx eslint scripts/replay.ts scripts/replay.test.ts scripts/no-personal-defaults.test.ts scripts/decision-candidate.ts scripts/decision-candidate.test.ts scripts/replay-decisions.ts scripts/replay-decisions.test.ts
git diff --check
```

`bun test` includes the co-located unit tests plus the Bun tests under `scripts/`
and `integration/transport.test.ts`. The full real-server suite is separate:

```sh
bun run test:integration
```

It launches `opencode serve` (or `OPENCODE_BINARY`) against a scratch HOME and XDG
config/data/cache/state/tmp roots, starts loopback fixture providers, and sets
`OPENCODE_PLUGIN_PATH` to the checkout under test. Cases rewrite only scratch
configuration and saved approvals. Never use personal config, personal saved
approvals, personal audit logs, production credentials, or production models.

Run `bun run test:integration` after classifier, audit, Code Mode, mode, or
permission-hook changes. It covers allow/deny/invalid/timeout reviewer paths,
protected-path floors, native allow and saved-approval review, mode commands,
breaker behavior, audit isolation, shell execution, hostile project options, and
Code Mode identity/evidence rejection. Last recorded results: 44 scenarios passed
against OpenCode `2.2.5`, and `bun test` reported 396 passing. Record the actual
result of each run rather than assuming a historical count.

`bun run build:gui` verifies the desktop bundle. The privacy guard is part of
`bun test`; run it before packing. It is pattern-based, not a general secret
scanner. Build output, dependencies, lockfiles, and license text are outside its
coverage.

## Complexity limits

`bun run lint` runs ESLint, which enforces these limits on all non-test code:

- cyclomatic complexity **<= 10**;
- **<= 60 nonblank/non-comment lines** per function;
- **max depth <= 4**.

Test files (`*.test.ts`, `*.test.tsx`) are exempt.

## Coding conventions

- TypeScript is strict ESM. Relative imports use the `.js` suffix even from
  `.ts`/`.tsx` sources.
- Tests use `node:test` in `src/` and Bun's `bun:test` in `scripts/` and
  `integration/transport.test.ts`. Match the surrounding file.
- Preserve the safety contract:
  - native `deny` is final and is never reviewed or weakened;
  - invalid configuration performs no review and leaves native behavior in
    place;
  - uncertain, failed, interrupted, or timed-out reviews resolve to `ask`;
  - no default model, endpoint, credential, or allowlist is added;
  - safety options come from the user-owned global registration, not merged
    project options;
  - hand-written guards belong in `scoreRequest`; classifiers must not override
    mandatory score deny/ask effects;
  - fact review is evidence-only: a certified fact and edit-capture identity
    never grant permission; fact-review
    `minConfidence` accepts `0.8`-`1` (default `0.9`), a consented host-minted
    bounded edit body that certifies `local_edit` at or above the floor is
    included as `changeContent` and the edit is allowed only if the fact,
    `safety`, and `allow` gates all clear, a certified read-only `inspection`
    with zero static findings is allowed on the fact alone without a review call,
    an `edit` action whose targets all canonicalize inside the worktree and
    outside `.git`, `.jj`, `node_modules` and secret-like basenames is asked one
    metadata-only `edit_in_project` question and `true` at or above the floor
    certifies `project_edit` and allows without review (`external_directory`,
    escaping targets, static findings and the `write` action keep the prior
    abstain), a complete non-shell, non-file tool call asks one frozen
    `tool_readonly` choice with its tool and arguments (the captured Code Mode
    script for `execute`) and certifies `inspection` on `true` at or above the
    floor while a complete `subagent`/`task` delegation with a non-empty prompt
    certifies `delegation` with no fact call and only the frozen
    `authorization` review (child actions are reviewed separately), every other
    kind and any inspection
    with findings or without static analysis keeps the full
    `safety`/`authorization` review, and edit-body capture remains a host API
    opt-in rather than a config option (`src/index.ts` keeps
    `includeEditPayload` `false`);
  - Code Mode identity is the exact SHA-256 of the source, metadata must validate
    that identity, and the source is supplied to reviewers as a resource.
- Do not reintroduce removed features: shadow mode, custom rules, unconfigured
  mode, rule IDs, performance metrics, OTLP, or remote log export.
- Do not log or commit personal audit data. Audit records are unredacted by
  design and may contain secrets, prompts, and file contents.
- Keep prose in the three docs short and accurate. Prefer verified source
  behavior and linked OpenCode V2 docs over guesses.

## Release checks

Before a release, run on settled source:

```sh
bun install --frozen-lockfile
bun test
bun run lint
bun run typecheck
bun run build:gui
bun run test:integration
bun test scripts/no-personal-defaults.test.ts scripts/replay.test.ts scripts/decision-candidate.test.ts scripts/replay-decisions.test.ts
git diff --check
npm pack --dry-run
```

Confirm the packed file list includes the server and GUI entries plus `README.md`,
`README.llm.md`, and `CONTRIBUTING.md`, that their relative links resolve in the
packed layout, that `scripts/` and `docs/` are absent, and that no personal
models, endpoints, credentials, or allowlists are present. Verify the actual
`npm pack` result rather than assuming the link layout.

Last recorded results: 44 integration scenarios passed against OpenCode `2.2.5`;
the full unit suite also passed (396 tests when the integration run was recorded,
814 on the current tree). Manual desktop acceptance and multi-day dogfood have
not been executed. A green local unit/lint/typecheck/pack run is not a release
readiness claim; record the actual real-server, desktop, and dogfood results
before claiming one.

Do not commit, tag, publish, restart a live service, or change personal
configuration as part of a code change unless the owner has explicitly authorized
that action. The release workflow is manual and requires `main` plus owner
authorization.
