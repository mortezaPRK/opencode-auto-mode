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
| `src/shell.ts` | Parsed shell guard: deny/ask classification, protected operands, recursive deletion, history changes, ambiguity floors. |
| `src/shell-policy.ts` | Shell grammar and command policy vocabulary. Large on purpose; it models parser behavior rather than matching raw text. |
| `src/tiers.ts` | Protected paths, credential names, symlink traversal, project/worktree containment, safe edit targets. |
| `src/worktree.ts` | Discovers the session's current worktree root and canonical location. |
| `src/gates.ts` | VCS preconditions for history-changing commands. Missing facts fail toward review. |
| `src/classifier.ts` | Ordered classifier pipeline. First decisive allow/deny wins; otherwise ask. |
| `src/decision.ts` | Native typed decision stage using `ctx.experimental.generate.decisions`. |
| `src/reviewer.ts` | LLM reviewer prompt, evidence filtering, response parsing, and deny-gate behavior. |
| `src/code-mode.ts` | Code Mode SHA-256 identity, save entry, identity validation, and reviewer source resource. |
| `src/mode.ts` | Durable per-session mode, daily counts, breaker window, and cancellation repair. |
| `src/status.ts`, `src/rpc.ts` | Bounded status surface and typed RPC contract (`status`, `setMode`). |
| `src/gui-state.ts`, `src/gui.tsx`, `src/tui.tsx` | Shared UI state plus desktop GUI and terminal UI parts. |
| `src/audit.ts`, `src/debug-events.ts` | Opt-in local JSONL audit and unsafe debug capture, including rotation. |
| `src/user-files.ts` | JSONC parsing and user-owned-file checks. |
| `src/timeout.ts`, `src/errors.ts` | Bounded provider calls and stable error categories. |
| `scripts/replay.ts` | Checkout-only offline audit replay with static diagnostics. |
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
bun test scripts/no-personal-defaults.test.ts scripts/replay.test.ts
bunx eslint scripts/replay.ts scripts/replay.test.ts scripts/no-personal-defaults.test.ts
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

## Complexity linter

All new or extracted functions must meet these limits:

- cyclomatic complexity **<= 10**;
- **<= 60 nonblank/non-comment lines** per function;
- **max depth <= 4**.

`bun run lint` runs ESLint plus `node scripts/complexity-lint.js`. The linter
applies those limits to all JavaScript/TypeScript and compares each function/rule
exceedance with `scripts/complexity-baseline.json`. Entries are keyed by file,
rule, function label, and function or depth-block start `line:column`; anonymous
arrows, separate depth blocks, and repeated function names therefore each need
their own exemption.
New exceedances and increases over a legacy entry fail. Existing legacy entries may
shrink but not grow. Moving a legacy violation (or lines before it) changes its
identity and is reported as new until the baseline is refreshed in a reviewed
change, so avoid unrelated movement around legacy entries. `src/score.ts`,
`src/score/**`, and `scripts/complexity*` are strict: they cannot be baselined or
exempted and must pass the limits directly. Tests are not exempt from these
limits.

`node scripts/complexity-lint.js --update` records improvements only. All failure
checks run before the file is written, so it refuses without modifying the
baseline while new, increased, or strict scoring/tooling violations exist. Do not
cite a different threshold.

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
bun test scripts/no-personal-defaults.test.ts scripts/replay.test.ts
git diff --check
npm pack --dry-run
```

Confirm the packed file list includes the server and GUI entries plus `README.md`,
`README.llm.md`, and `CONTRIBUTING.md`, that their relative links resolve in the
packed layout, that `scripts/` and `docs/` are absent, and that no personal
models, endpoints, credentials, or allowlists are present. Verify the actual
`npm pack` result rather than assuming the link layout.

Last recorded results: 44 integration scenarios passed against OpenCode `2.2.5`;
the full unit suite also passed (396 tests when recorded, 399 on the current
tree). Manual desktop acceptance and multi-day dogfood have not been executed. A
green local unit/lint/typecheck/pack run is not a release readiness claim; record
the actual real-server, desktop, and dogfood results before claiming one.

Do not commit, tag, publish, restart a live service, or change personal
configuration as part of a code change unless the owner has explicitly authorized
that action. The release workflow is manual and requires `main` plus owner
authorization.
