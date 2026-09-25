#!/usr/bin/env bash
# Deterministic, offline verification for the steward package.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-fast}"
if (($# > 1)); then
    printf 'Usage: %s [fast|full|offline]\n' "$0" >&2
    exit 2
fi

case "$MODE" in
    fast|full|offline)
        ;;
    *)
        printf 'Usage: %s [fast|full|offline]\n' "$0" >&2
        exit 2
        ;;
esac

export PYTHONNOUSERSITE=1
export PIP_DISABLE_PIP_VERSION_CHECK=1
# No command in this script performs network access.  The marker is useful to
# child checks and makes accidental online additions obvious in diagnostics.
export STEWARD_OFFLINE=1

run_fast() {
    python3 -m py_compile \
        "$ROOT/scripts/workflow_state.py" \
        "$ROOT/scripts/steward_runner.py" \
        "$ROOT/scripts/steward"/*.py
    PYTHONPATH="$ROOT/scripts${PYTHONPATH:+:$PYTHONPATH}" \
        python3 "$ROOT/scripts/test_workflow_state.py"
    python3 "$ROOT/scripts/test_steward_extract.py"

    command -v shellcheck >/dev/null || {
        printf '%s\n' 'shellcheck is required' >&2
        return 1
    }
    shellcheck \
        "$ROOT/scripts/steward-resume.sh" \
        "$ROOT/scripts/notify-failure.sh" \
        "$ROOT/scripts/verify-steward.sh"
}

run_full() {
    run_fast
    python3 -m unittest discover \
        -s "$ROOT/scripts" \
        -p 'test_steward_*.py' \
        -v
}

case "$MODE" in
    fast|offline)
        run_fast
        ;;
    full)
        run_full
        ;;
esac
printf 'steward verification (%s) complete\n' "$MODE"
