#!/bin/bash
# Runs the Hyperliquid Ruby SDK autonomous maintenance cycle via omp + opencode-go/glm-5.3.
# Scheduled via systemd timer (hyperliquid-sdk.timer) Mon/Thu at 4am ET.
# Provider-agnostic: change the --model id to switch providers/models.
#
# Failure alerting: the omp run emails Carter on success itself; any non-zero
# exit fails the unit, and hyperliquid-sdk.service's OnFailure= sends the
# journal excerpt through notify-failure@.service (one alert path for all units).

set -euo pipefail

# systemd user units always provide HOME; resolve from passwd otherwise.
HOME="${HOME:-$(getent passwd "$(id -un)" | cut -d: -f6)}"
export HOME
export PATH="$HOME/.local/bin:$HOME/.rbenv/bin:$HOME/.rbenv/shims:$HOME/.fnm:$HOME/.bun/bin:$PATH"
XDG_RUNTIME_DIR="/run/user/$(id -u)"
export XDG_RUNTIME_DIR
# Timer/manual invocations share one maintenance workspace. Exit cleanly when
# another run owns the lock rather than racing Git state and duplicate emails.
exec 9>"${HYPERLIQUID_SDK_LOCK:-/tmp/hyperliquid-sdk.lock}"
if ! flock -n 9; then
    echo "skip: another Hyperliquid SDK maintenance run is active"
    exit 0
fi

RUN_LOG="$(mktemp /tmp/hyperliquid-sdk-run.XXXXXX.log)"
DEPENDABOT_MANIFEST="$(mktemp /tmp/hyperliquid-dependabot-intake.XXXXXX.json)"
export HYPERLIQUID_DEPENDABOT_MANIFEST="$DEPENDABOT_MANIFEST"
OMP_PATH="${OMP_PATH:-omp}"
STATE_FILE="$HOME/agent-state/hyperliquid-sdk.md"

# Completion marker: the `**Last updated:**` line plus the highest Run History
# number. Every completed run (no-op included) rewrites the state file in its
# Step 11, so an omp session that exits 0 without advancing either one ended
# early and must fail. Prints two lines: last-updated text, max run number.
state_run_marker() {
    [ -f "$STATE_FILE" ] || return 0
    awk '
        /^\*\*Last updated:\*\*/ { updated = $0 }
        /^## / { in_history = ($0 ~ /^## Run History[[:space:]]*$/) }
        in_history && /^\|[[:space:]]*[0-9]+[[:space:]]*\|/ {
            split($0, cell, "|"); run = cell[2] + 0
            if (run > max_run) max_run = run
        }
        END { printf "%s\n%d\n", updated, max_run }
    ' "$STATE_FILE"
}

# Temp files are removed on every exit; failure alerts come from OnFailure=.
on_exit() { # shellcheck disable=SC2329
    rm -f "$RUN_LOG" "$DEPENDABOT_MANIFEST"
}
trap on_exit EXIT

# Sanity check: verify omp and its bun interpreter are reachable
# (exit 127 on omp means PATH issue at execution time)
if ! command -v "$OMP_PATH" &>/dev/null; then
    echo "FATAL: omp not found: $OMP_PATH (PATH=$PATH)" >&2
    exit 1
fi
if ! command -v bun &>/dev/null; then
    echo "FATAL: bun (omp interpreter) not found in PATH=$PATH" >&2
    exit 1
fi
echo "ok: omp at $(command -v "$OMP_PATH"), bun at $(command -v bun)"

# GitHub discovery and Prompt-Guard classification happen outside the model.
# The manifest contains only validated branch metadata; PR titles and bodies
# never enter the agent prompt or tool context. The agent reconciles this intake
# into its regular state queue before scanning upstream and selecting work.
python3 "$HOME/scripts/hyperliquid_dependabot_intake.py" \
    --output "$DEPENDABOT_MANIFEST" \
    2>&1 | tee -a "$RUN_LOG"

PROMPT='/hyperliquid-run'
MARKER_BEFORE="$(state_run_marker)"

"$OMP_PATH" -p \
    --model opencode-go/glm-5.3 \
    --api-key proxy \
    --allow-home \
    --config "$HOME/.omp/agent/headless-override.yml" \
    --tools bash,read,write,edit,grep,glob,lsp,todo \
    -e "$HOME/.config/hyperliquid-agent/omp-dependabot-guard.ts" \
    --session-dir "$HOME/.omp/agent/sessions-automated" \
    "$PROMPT" 2>&1 | tee -a "$RUN_LOG"

# Post-condition: omp exiting 0 is not proof the cycle ran. Fail (OnFailure
# alert + systemd bounded retry) unless the state file's run marker advanced.
# Log via builtins from this long-lived shell: output from a short-lived pipe
# child (tee) can lose its unit attribution and vanish from `journalctl -u`.
MARKER_AFTER="$(state_run_marker)"
updated_before="$(sed -n 1p <<<"$MARKER_BEFORE")"
updated_after="$(sed -n 1p <<<"$MARKER_AFTER")"
run_before="$(sed -n 2p <<<"$MARKER_BEFORE")"
run_after="$(sed -n 2p <<<"$MARKER_AFTER")"
if [ "${run_after:-0}" -gt "${run_before:-0}" ] \
    || { [ -n "$updated_after" ] && [ "$updated_after" != "$updated_before" ]; }; then
    msg="ok: state file advanced (Run History #${run_before:-0} -> #${run_after:-0})"
    printf '%s\n' "$msg"
    printf '%s\n' "$msg" >> "$RUN_LOG"
else
    msg="FATAL: omp exited 0 but $STATE_FILE did not advance (Run History still #${run_after:-0}, '**Last updated:**' unchanged); the session ended before completing the run"
    printf '%s\n' "$msg" >&2
    printf '%s\n' "$msg" >> "$RUN_LOG"
    exit 3
fi
