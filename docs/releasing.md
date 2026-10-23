# Releasing

The release workflow publishes the npm package after tests, lint, and typecheck
pass.

1. Open **Actions → Release npm package → Run workflow**.
2. Select `main`.
3. Choose `patch`, `minor`, or `major` (default: `patch`).
4. Run the workflow.

The workflow:

- increments `package.json`
- checks the npm package contents
- commits and tags the version
- publishes to npm
- creates an immutable GitHub release with generated notes

The same release can be started from the command line:

```sh
gh workflow run publish.yml --repo mortezaPRK/opencode-auto-mode --ref main -f bump=patch
```

Publishing uses the npm trusted publisher for GitHub owner `mortezaPRK`,
repository `opencode-auto-mode`, and workflow filename `publish.yml`. No npm
token or additional personal access token is needed in repository secrets.

GitHub release immutability is enabled in the repository settings. Releases and
tags do not trigger publication; only running this workflow does.
