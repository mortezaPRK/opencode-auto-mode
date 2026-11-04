#!/usr/bin/env bash
set -euo pipefail

# Requests the CLI reload only. Source/server reload semantics are still a spike;
# this helper never restarts a live service or edits personal configuration.
case "${1:-}" in
  "") ;;
  --gui) bun run build:gui ;;
  -h|--help)
    echo 'Usage: scripts/dev-reload.sh [--gui]'
    echo 'Optionally build the GUI, then request opencode reload (no service restart).'
    exit 0
    ;;
  *) echo 'Usage: scripts/dev-reload.sh [--gui]' >&2; exit 2 ;;
esac
if [[ $# -gt 1 ]]; then
  echo 'Only --gui is accepted.' >&2
  exit 2
fi
opencode reload
