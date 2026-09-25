#!/usr/bin/env bash
# The pending handoff is only a pointer to a WorkflowState-backed run.  A
# legacy pending/file-only marker is rejected rather than trusted.
# Checks ~/agent-state/pending.md — if it exists and is recent (< 30 min since boot),
# resumes the steward runner. Otherwise, no-op.
set -euo pipefail

export HOME="/home/carter"
export PATH="$HOME/.local/bin:$HOME/bin:/usr/local/bin:/usr/bin:/bin"
XDG_RUNTIME_DIR="/run/user/$(id -u)"
export XDG_RUNTIME_DIR

PENDING="$HOME/agent-state/pending.md"

if [ ! -f "$PENDING" ]; then
    echo "[steward-resume] no pending.md — nothing to resume"
    exit 0
fi

RUN_DIR="$(sed -n 's/^\*\*Run dir:\*\* //p' "$PENDING" | sed -n '1p')"
STATE_DB="$(sed -n 's/^\*\*State DB:\*\* //p' "$PENDING" | sed -n '1p')"
if [[ -z "$RUN_DIR" || -z "$STATE_DB" || "$STATE_DB" != "$RUN_DIR/workflow-state.sqlite3" ||
      ! -f "$RUN_DIR/workflow-state.sqlite3" ]]; then
    echo "[steward-resume] pending handoff has no valid WorkflowState DB — removing"
    rm -f -- "$PENDING"
    exit 0
fi

# Check boot recency: if system has been up > 30 min, pending.md is stale
UPTIME_SEC=$(awk '{print int($1)}' /proc/uptime)
if [ "$UPTIME_SEC" -gt 1800 ]; then
    echo "[steward-resume] system up ${UPTIME_SEC}s (>30 min) — pending.md is stale, removing"
    rm -f -- "$PENDING"
    exit 0
fi

echo "[steward-resume] pending.md found, uptime ${UPTIME_SEC}s — resuming steward"
if python3 "$HOME/scripts/steward_runner.py" --resume --run-dir "$RUN_DIR"; then
    # Clean up pending.md after successful resume
    rm -f -- "$PENDING"
    echo "[steward-resume] done"
else
    echo "[steward-resume] resume failed; retaining pending.md" >&2
    exit 1
fi
