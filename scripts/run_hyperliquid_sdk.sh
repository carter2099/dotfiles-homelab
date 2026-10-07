#!/bin/bash
# Runs the Hyperliquid Ruby SDK autonomous maintenance cycle via omp + anthropic/claude-opus-5-5:high.
# Scheduled via systemd timer (hyperliquid-sdk.timer) Mon/Thu at 4am ET.
# Provider-agnostic: change the --model id to switch providers/models.
#
# Failure alerting: the omp run emails Carter on success itself; any non-zero
# exit fails the unit, and hyperliquid-sdk.service's OnFailure= sends the
# journal excerpt through notify-failure@.service (one alert path for all units).
#
# Exit codes:
#   0  run completed and every post-condition held (or another run holds the lock)
#   1  pre-flight failure: omp, bun, or the ~/dev/hyperliquid checkout is missing
#   3  omp exited 0 but the state file did not advance (session ended early)
#   4  the checkout is dirty after the run (blocked or unfinished work)
#   5  the run moved HEAD but HEAD is not on origin/dev (unpushed commit), or
#      origin/dev could not be fetched to prove it
#   6  the clone gate failed: a fresh clone of origin/dev is red under
#      `RBENV_VERSION=3.4.10 BUNDLE_FROZEN=true bundle exec rake` (no key)
#   other  omp's own non-zero exit status (pipefail)
# Post-conditions 4-6 run outside the model and have no skip switch; the
# offline verifier (verify-hyperliquid-guard.sh) exercises them against a
# throwaway HOME whose ~/dev/hyperliquid is a fixture repo with a local origin.

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
REPO="$HOME/dev/hyperliquid"
CLONE_DIR=""

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
    if [ -n "$CLONE_DIR" ]; then rm -rf -- "$CLONE_DIR"; fi
}

# Log a line from this long-lived shell to the journal and the run log.
log_line() {
    printf '%s\n' "$1"
    printf '%s\n' "$1" >> "$RUN_LOG"
}

# Log a FATAL line to stderr and the run log, then exit with the given code.
fail_with() {
    printf '%s\n' "$2" >&2
    printf '%s\n' "$2" >> "$RUN_LOG"
    exit "$1"
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
if ! HEAD_BEFORE="$(git -C "$REPO" rev-parse --verify HEAD 2>/dev/null)"; then
    echo "FATAL: $REPO is not a Git checkout with a HEAD commit" >&2
    exit 1
fi
echo "ok: omp at $(command -v "$OMP_PATH"), bun at $(command -v bun), $REPO at ${HEAD_BEFORE:0:12}"

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
    --model anthropic/claude-opus-5-5:high \
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
    log_line "ok: state file advanced (Run History #${run_before:-0} -> #${run_after:-0})"
else
    fail_with 3 "FATAL: omp exited 0 but $STATE_FILE did not advance (Run History still #${run_after:-0}, '**Last updated:**' unchanged); the session ended before completing the run"
fi

# Post-condition 4: the run leaves no staged, unstaged, or untracked changes.
# A dirty tree is a blocked or unfinished run, never a success.
if ! dirty="$(git -C "$REPO" status --porcelain)"; then
    fail_with 4 "FATAL: git status failed in $REPO after the run"
fi
if [ -n "$dirty" ]; then
    fail_with 4 "FATAL: $REPO is dirty after the run:
$dirty"
fi
log_line "ok: $REPO is clean"

# Post-condition 5: if the run moved HEAD (commit or pull), HEAD must be on
# origin/dev. The agent cannot fetch (its guard blocks it); the wrapper can.
# Ancestry, not equality: another pusher (the Dependabot publisher) may advance
# dev during the run; that tip is covered by the clone gate below.
HEAD_AFTER="$(git -C "$REPO" rev-parse --verify HEAD)"
if [ "$HEAD_AFTER" != "$HEAD_BEFORE" ]; then
    if ! git -C "$REPO" fetch --quiet origin dev; then
        fail_with 5 "FATAL: git fetch origin dev failed; cannot prove HEAD ${HEAD_AFTER:0:12} was pushed"
    fi
    origin_dev="$(git -C "$REPO" rev-parse --verify refs/remotes/origin/dev)"
    if ! git -C "$REPO" merge-base --is-ancestor "$HEAD_AFTER" "$origin_dev"; then
        fail_with 5 "FATAL: HEAD ${HEAD_AFTER:0:12} is not on origin/dev (${origin_dev:0:12}); the run left an unpushed commit"
    fi
    log_line "ok: HEAD ${HEAD_BEFORE:0:12} -> ${HEAD_AFTER:0:12} is on origin/dev (${origin_dev:0:12})"
else
    log_line "ok: HEAD unchanged at ${HEAD_AFTER:0:12}"
fi

# Post-condition 6: the pushed tree is green on its own. A fresh clone of
# origin/dev proves committed content and the frozen lockfile (a forgotten
# `git add` or a stale Gemfile.lock fails here) independently of the model's
# claims. No key: the clone gate is the unit/lint gate, not integration.
if ! origin_url="$(git -C "$REPO" remote get-url origin)"; then
    fail_with 6 "FATAL: $REPO has no origin remote to clone"
fi
CLONE_DIR="$(mktemp -d /tmp/hyperliquid-sdk-clone-gate.XXXXXX)"
if ! git clone --quiet --branch dev "$origin_url" "$CLONE_DIR/hyperliquid"; then
    fail_with 6 "FATAL: clone gate could not clone origin/dev from $origin_url"
fi
gate_sha="$(git -C "$CLONE_DIR/hyperliquid" rev-parse --verify HEAD)"
log_line "clone gate: origin/dev ${gate_sha:0:12} in $CLONE_DIR/hyperliquid"
if ! (
    cd "$CLONE_DIR/hyperliquid" \
        && env -u HYPERLIQUID_PRIVATE_KEY -u BUNDLE_GEMFILE -u RUBYOPT \
            RBENV_VERSION=3.4.10 BUNDLE_FROZEN=true bundle exec rake
); then
    fail_with 6 "FATAL: clone gate red: RBENV_VERSION=3.4.10 BUNDLE_FROZEN=true bundle exec rake failed on a fresh clone of origin/dev ${gate_sha:0:12}"
fi
log_line "ok: clone gate green on origin/dev ${gate_sha:0:12}"
