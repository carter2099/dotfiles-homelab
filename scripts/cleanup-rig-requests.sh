#!/usr/bin/env bash
# Remove request files in ~/rig-requests older than 14 days.
# Scheduled via systemd timer (cleanup-rig-requests.timer).
set -euo pipefail
export HOME="/home/carter"

START_TS="$(date +%s)"
COUNT=0
REQUESTS_FILE="$(mktemp "${TMPDIR:-/tmp}/cleanup-rig-requests.XXXXXX")"

cleanup() { # shellcheck disable=SC2329
  local status
  status=$?
  rm -f -- "$REQUESTS_FILE"
  return "$status"
}
trap cleanup EXIT

if [[ -d "$HOME/rig-requests" ]]; then
  if ! find "$HOME/rig-requests" -maxdepth 1 -type f -mtime +14 -print0 >"$REQUESTS_FILE"; then
    printf 'failed to enumerate old rig requests\n' >&2
    exit 1
  fi
  while IFS= read -r -d '' f; do
    rm -f -- "$f"
    COUNT=$((COUNT + 1))
  done <"$REQUESTS_FILE"
fi

END_TS="$(date +%s)"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) cleanup-rig-requests removed=$COUNT duration=$((END_TS - START_TS))s" >> "$HOME/digests/cleanup-rig-requests/.runs.log"
