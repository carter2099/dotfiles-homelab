#!/usr/bin/env bash
# Deterministic, offline verification for security-watch.
#   fast: compile, shellcheck, policy/registry load, unit tests
#   full: fast + node2shell fixture replay + unit-file checks
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
PYTHON="${PYTHON:-python3}"
SHELLCHECK="${SHELLCHECK:-shellcheck}"
MODE="${1:-fast}"

usage() {
    printf 'Usage: %s [fast|full|help]\n' "$0"
}

if (($# > 1)); then
    usage >&2
    exit 2
fi

case "$MODE" in
    fast|full)
        ;;
    help|-h|--help)
        usage
        exit 0
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

WORKDIR="$(mktemp -d)"
cleanup() {
    rm -rf -- "$WORKDIR"
}
trap cleanup EXIT

export PYTHONNOUSERSITE=1
export PIP_DISABLE_PIP_VERSION_CHECK=1
# Nothing here touches the network; replay serves recorded fixtures.
export SECURITY_WATCH_OFFLINE=1
export DEPLOY_LOCK_DIR="$WORKDIR/locks"
export SECURITY_WATCH_STATE_DIR="$WORKDIR/state"
export PYTHONPYCACHEPREFIX="$WORKDIR/pycache"

run_fast() {
    "$PYTHON" -m py_compile \
        "$SCRIPT_DIR"/security_watch/*.py \
        "$SCRIPT_DIR/security_watch_runner.py" \
        "$SCRIPT_DIR/deploy_lock.py"

    command -v "$SHELLCHECK" >/dev/null || {
        printf '%s\n' 'shellcheck is required' >&2
        return 1
    }
    "$SHELLCHECK" "$SCRIPT_DIR/verify-security-watch.sh"

    PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" "$PYTHON" - <<'PY'
from security_watch import config, feeds

policy = config.load_policy()
specs = config.load_components()
assert policy.mode in {"shadow", "active"}, policy.mode
assert set(policy.source_intervals) == set(feeds.SOURCES), "source_intervals must name exactly feeds.SOURCES"
assert specs, "components.toml lists no components"
print(f"policy {policy.mode}; {len(specs)} components; {len(policy.source_intervals)} sources")
PY

    "$PYTHON" -m unittest discover -s "$SCRIPT_DIR" -p 'test_security_watch_*.py'
}

run_full() {
    run_fast

    local unit="$ROOT/.config/systemd/user/security-watch.service"
    grep -qxF 'OnFailure=notify-failure@%n.service' "$unit" || {
        printf '%s lacks OnFailure=notify-failure@%%n.service\n' "$unit" >&2
        return 1
    }

    mkdir -p "$WORKDIR/home"
    HOME="$WORKDIR/home" "$PYTHON" "$SCRIPT_DIR/security_watch_runner.py" replay \
        "$SCRIPT_DIR/security_watch/fixtures/node2shell" --json >"$WORKDIR/replay.json"

    "$PYTHON" - "$WORKDIR/replay.json" <<'PY'
import json
import sys

result = json.load(open(sys.argv[1]))
report = result["report"]
findings = {f["key"]: f for f in report["findings"]}

fresh = findings.get("freshrss|CVE-2026-111497")
assert fresh, f"freshrss finding missing: {sorted(findings)}"
assert fresh["urgency"] == "urgent", fresh
assert fresh["kev"] is True, fresh
assert fresh["zero_wire"] == ["node2shell"], fresh
assert "news|CVE-2026-111497" in findings, sorted(findings)
assert not [k for k, f in findings.items() if f["component"] == "host" and f["package"].endswith("/brotli")], \
    "host brotli 1.1.0-2ubuntu0.1 is fixed and must not be a finding"
assert [f for f in findings.values() if f["component"] == "bun" and f["fixed"] == ["1.4.4"]], \
    f"bun finding missing: {sorted(findings)}"
assert report["mode"] == "shadow", report["mode"]
assert report["actions_24h"] == [], report["actions_24h"]
assert len(result["outbox"]) == 1, result["outbox"]
assert result["outbox"][0].startswith("Security watch: 3 still vulnerable"), result["outbox"]
print(f"replay: {len(findings)} findings, outbox {result['outbox'][0]!r}")
PY
}

case "$MODE" in
    fast)
        run_fast
        ;;
    full)
        run_full
        ;;
esac

printf 'SECURITY_WATCH_%s_OK\n' "${MODE^^}"
