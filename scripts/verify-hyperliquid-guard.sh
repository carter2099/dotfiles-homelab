#!/usr/bin/env bash
# Deterministic verification for the shipped Hyperliquid Dependabot guard.
# Usage: verify-hyperliquid-guard.sh [fast|full]
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# The guard is tracked in the same dotfiles checkout (repo root = scripts/..).
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
GUARD_PATH="${HYPERLIQUID_GUARD_PATH:-$REPO_ROOT/.config/hyperliquid-agent/omp-dependabot-guard.ts}"
TEST_PATH="$SCRIPT_DIR/test_hyperliquid_dependabot_guard.ts"
BUN="${BUN:-bun}"
SHELLCHECK="${SHELLCHECK:-shellcheck}"
MODE="${1:-fast}"

usage() {
  printf 'Usage: %s [fast|full]\n' "${BASH_SOURCE[0]}"
}
if (( $# > 1 )); then
  usage >&2
  exit 2
fi

case "$MODE" in
  fast|--fast)
    MODE=fast
    ;;
  full|--full)
    MODE=full
    ;;
  help|--help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

require_tool() {
  local name
  name=$1
  if ! command -v "$name" >/dev/null 2>&1; then
    printf 'FATAL: required tool is unavailable: %s\n' "$name" >&2
    exit 127
  fi
}

if [[ ! -f "$GUARD_PATH" ]]; then
  printf 'FATAL: shipped Hyperliquid guard is missing: %s\n' "$GUARD_PATH" >&2
  exit 1
fi
if [[ ! -f "$TEST_PATH" ]]; then
  printf 'FATAL: guard behavior test is missing: %s\n' "$TEST_PATH" >&2
  exit 1
fi

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/hyperliquid-guard-verify.XXXXXX")"
cleanup() { # shellcheck disable=SC2329
  local status
  status=$?
  rm -rf -- "$WORKDIR"
  return "$status"
}
trap cleanup EXIT

run_shellcheck() {
  "$SHELLCHECK" --shell=bash \
    "$SCRIPT_DIR/cleanup-rig-requests.sh" \
    "$SCRIPT_DIR/run_hyperliquid_sdk.sh" \
    "$SCRIPT_DIR/smoke-test-llm.sh" \
    "$SCRIPT_DIR/update_llama_cpp_remote.sh" \
    "$SCRIPT_DIR/verify-dependabot-intake.sh" \
    "$SCRIPT_DIR/verify-hyperliquid-guard.sh"
}

run_bun_syntax_checks() {
  local syntax_dir
  syntax_dir="$WORKDIR/syntax-check"
  mkdir -p -- "$syntax_dir"
  "$BUN" build "$GUARD_PATH" --target=bun --outfile="$syntax_dir/guard.js"
  "$BUN" build "$TEST_PATH" --target=bun --outfile="$syntax_dir/test.js"
}

run_behavior_check() {
  HYPERLIQUID_GUARD_PATH="$GUARD_PATH" "$BUN" run "$TEST_PATH"
}

run_artifact_check() {
  local artifact artifact_check_dir
  artifact="$WORKDIR/omp-dependabot-guard.js"
  artifact_check_dir="$WORKDIR/artifact-check"
  "$BUN" build "$GUARD_PATH" --target=bun --outfile="$artifact"
  mkdir -p -- "$artifact_check_dir"
  "$BUN" build "$artifact" --target=bun \
    --outfile="$artifact_check_dir/omp-dependabot-guard.js"
  [[ -s "$artifact_check_dir/omp-dependabot-guard.js" ]]
  printf 'verified Bun artifact: %s (%s bytes)\n' "$artifact" "$(wc -c < "$artifact")"
}

# The wrapper must fail when omp exits 0 without the run advancing the state
# file (Run History number or **Last updated:** line), and pass otherwise.
# The wrapper never emails a failure itself: the unit's OnFailure= does, so no
# case may reach the mailer stub. Runs against a throwaway HOME, lock, omp stub,
# intake stub, and mailer stub.
run_wrapper_postcondition_check() {
  local fixture_home fixture_bin case_name expected_rc rc output unit
  unit="$SCRIPT_DIR/../.config/systemd/user/hyperliquid-sdk.service"
  if ! grep -qx 'OnFailure=notify-failure@%n.service' "$unit"; then
    printf 'FATAL: %s must alert failures via OnFailure=notify-failure@%%n.service\n' "$unit" >&2
    return 1
  fi
  fixture_home="$WORKDIR/wrapper-home"
  fixture_bin="$WORKDIR/wrapper-bin"
  mkdir -p -- "$fixture_home/scripts" "$fixture_home/agent-state" "$fixture_bin"

  cat > "$fixture_home/scripts/hyperliquid_dependabot_intake.py" <<'PY'
print("intake fixture: no open Dependabot PRs")
PY
  cat > "$fixture_home/scripts/send_digest.py" <<'PY'
import os
import sys

path = os.path.join(os.environ["HOME"], "emails.log")
with open(path, "a", encoding="utf-8") as log:
    log.write(" ".join(sys.argv[1:]) + "\n")
PY
  cat > "$fixture_bin/omp" <<'BASH'
#!/usr/bin/env bash
set -Eeuo pipefail
state="$HOME/agent-state/hyperliquid-sdk.md"
case "${WRAPPER_FIXTURE_MODE:?}" in
  early-exit)
    echo "omp fixture: session ended before the run"
    ;;
  noop-run)
    sed -i 's/^\*\*Last updated:\*\*.*/**Last updated:** 2026-09-25 (run #75)/' "$state"
    printf '| 75 | 2026-09-25 | No-op run | fixture |\n' >> "$state"
    ;;
  last-updated-only)
    sed -i 's/^\*\*Last updated:\*\*.*/**Last updated:** 2026-09-25 (release)/' "$state"
    ;;
  *)
    exit 64
    ;;
esac
BASH
  chmod 0755 "$fixture_bin/omp"

  for case_name in early-exit noop-run last-updated-only; do
    cat > "$fixture_home/agent-state/hyperliquid-sdk.md" <<'MD'
# Hyperliquid Ruby SDK — Agent State

**Last updated:** 2026-09-24 (run #74)

## Known Gaps

| # | Gap | Status |
|---|---|---|
| 900 | decoy numbered row outside Run History | 🟡 |

## Run History

| Run # | Date | Scope | Outcome |
|---|---|---|---|
| — | — | Initial state file created | — |
| 74 | 2026-09-24 | Dependency batch | fixture |
MD
    rm -f -- "$fixture_home/emails.log"
    rc=0
    output="$(
      HOME="$fixture_home" \
        PATH="$fixture_bin:$PATH" \
        OMP_PATH="$fixture_bin/omp" \
        HYPERLIQUID_SDK_LOCK="$WORKDIR/wrapper.lock" \
        WRAPPER_FIXTURE_MODE="$case_name" \
        bash "$SCRIPT_DIR/run_hyperliquid_sdk.sh" 2>&1
    )" || rc=$?
    expected_rc=0
    [[ "$case_name" == early-exit ]] && expected_rc=3
    if (( rc != expected_rc )); then
      printf 'FATAL: wrapper %s exited %s, expected %s:\n%s\n' \
        "$case_name" "$rc" "$expected_rc" "$output" >&2
      return 1
    fi
    if [[ "$case_name" == early-exit ]]; then
      if [[ "$output" != *"FATAL: omp exited 0 but"*"did not advance"* ]]; then
        printf 'FATAL: early exit did not report the failure:\n%s\n' "$output" >&2
        return 1
      fi
    fi
    if [[ -e "$fixture_home/emails.log" ]]; then
      printf 'FATAL: wrapper %s sent a failure email\n' "$case_name" >&2
      return 1
    fi
    printf 'wrapper post-condition %s: exit %s as expected\n' "$case_name" "$rc"
  done
}

require_tool "$BUN"
require_tool "$SHELLCHECK"
run_shellcheck
run_bun_syntax_checks
run_behavior_check
run_wrapper_postcondition_check
if [[ "$MODE" == full ]]; then
  run_artifact_check
fi
printf 'HYPERLIQUID_GUARD_%s_OK\n' "${MODE^^}"
