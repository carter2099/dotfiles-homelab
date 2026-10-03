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

# Non-secret stand-in for the testnet key; the wrapper's clone gate must unset it.
FIXTURE_FAKE_SIGNING_KEY=fixture-not-a-key
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
# After the state check it must also fail on a dirty checkout (exit 4), on a
# commit that is not on origin/dev (exit 5), and when a fresh clone of
# origin/dev is red (exit 6); the clone gate must run `bundle exec rake` with
# RBENV_VERSION=3.4.10 and BUNDLE_FROZEN=true, without the private key, inside
# a clone of the pushed tip rather than the checkout.
# The wrapper never emails a failure itself: the unit's OnFailure= does, so no
# case may reach the mailer stub. Runs against a throwaway HOME (whose
# ~/dev/hyperliquid is a fixture repo with a local bare origin), lock, omp
# stub, bundle stub, intake stub, and mailer stub.
run_wrapper_postcondition_check() {
  local fixture_home fixture_bin fixture_origin case_name expected_rc expected_msg
  local rc output unit origin_tip bundle_log
  unit="$SCRIPT_DIR/../.config/systemd/user/hyperliquid-sdk.service"
  if ! grep -qx 'OnFailure=notify-failure@%n.service' "$unit"; then
    printf 'FATAL: %s must alert failures via OnFailure=notify-failure@%%n.service\n' "$unit" >&2
    return 1
  fi
  fixture_home="$WORKDIR/wrapper-home"
  fixture_bin="$WORKDIR/wrapper-bin"
  fixture_origin="$WORKDIR/wrapper-origin.git"
  bundle_log="$fixture_home/bundle.log"
  mkdir -p -- "$fixture_home/scripts" "$fixture_home/agent-state" "$fixture_bin"

  # Every git call (verifier, omp stub, wrapper) sees only the fixture HOME's
  # config: no user signing/hooks/aliases leak in, and CI needs no identity.
  fixture_git() {
    HOME="$fixture_home" GIT_CONFIG_NOSYSTEM=1 \
      GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=fixture@example.invalid \
      GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=fixture@example.invalid \
      git "$@"
  }

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
repo="$HOME/dev/hyperliquid"
advance_state() {
  sed -i 's/^\*\*Last updated:\*\*.*/**Last updated:** 2026-09-25 (run #75)/' "$state"
  printf '| 75 | 2026-09-25 | %s | fixture |\n' "$1" >> "$state"
}
commit_file() {
  printf '%s\n' "$2" > "$repo/$1"
  git -C "$repo" add -- "$1"
  git -C "$repo" commit -q -m "fixture: add $1"
}
case "${WRAPPER_FIXTURE_MODE:?}" in
  early-exit)
    echo "omp fixture: session ended before the run"
    ;;
  noop-run)
    advance_state "No-op run"
    ;;
  last-updated-only)
    sed -i 's/^\*\*Last updated:\*\*.*/**Last updated:** 2026-09-25 (release)/' "$state"
    ;;
  pushed-commit)
    advance_state "API gap"
    commit_file feature.rb "feature"
    git -C "$repo" push -q origin dev
    ;;
  pushed-then-origin-advanced)
    advance_state "API gap"
    commit_file feature.rb "feature"
    git -C "$repo" push -q origin dev
    other="$(mktemp -d)"
    git clone -q --branch dev "$(git -C "$repo" remote get-url origin)" "$other/c"
    printf 'publisher\n' > "$other/c/Gemfile.lock"
    git -C "$other/c" add Gemfile.lock
    git -C "$other/c" commit -q -m "fixture: concurrent publisher push"
    git -C "$other/c" push -q origin dev
    rm -rf -- "$other"
    ;;
  dirty-tree)
    advance_state "API gap"
    printf 'unfinished\n' > "$repo/scratch.rb"
    ;;
  unpushed-commit)
    advance_state "API gap"
    commit_file feature.rb "feature"
    ;;
  red-clone-gate)
    advance_state "API gap"
    commit_file RED_GATE "the bundle stub fails when the clone contains this"
    git -C "$repo" push -q origin dev
    ;;
  *)
    exit 64
    ;;
esac
BASH
  chmod 0755 "$fixture_bin/omp"
  # Records how the clone gate invoked it; red iff the cloned tree has RED_GATE.
  cat > "$fixture_bin/bundle" <<'BASH'
#!/usr/bin/env bash
set -Eeuo pipefail
{
  printf 'cwd=%s\n' "$PWD"
  printf 'args=%s\n' "$*"
  printf 'env=RBENV_VERSION:%s BUNDLE_FROZEN:%s signing_key:%s\n' \
    "${RBENV_VERSION:-}" "${BUNDLE_FROZEN:-}" "${HYPERLIQUID_PRIVATE_KEY+present}"
  printf 'sha=%s\n' "$(git rev-parse HEAD)"
} > "$HOME/bundle.log"
[[ "$*" == "exec rake" ]] || exit 64
[[ ! -e RED_GATE ]]
BASH
  chmod 0755 "$fixture_bin/bundle"

  for case_name in early-exit noop-run last-updated-only pushed-commit \
    pushed-then-origin-advanced dirty-tree unpushed-commit red-clone-gate; do
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
    rm -rf -- "$fixture_origin" "${fixture_home:?}/dev"
    fixture_git init -q --bare --initial-branch=dev "$fixture_origin"
    fixture_git init -q --initial-branch=dev "$fixture_home/dev/hyperliquid"
    printf 'fixture\n' > "$fixture_home/dev/hyperliquid/README.md"
    fixture_git -C "$fixture_home/dev/hyperliquid" add README.md
    fixture_git -C "$fixture_home/dev/hyperliquid" commit -q -m "fixture: base"
    fixture_git -C "$fixture_home/dev/hyperliquid" remote add origin "$fixture_origin"
    fixture_git -C "$fixture_home/dev/hyperliquid" push -q -u origin dev
    rm -f -- "$fixture_home/emails.log" "$bundle_log"
    rc=0
    output="$(
      HOME="$fixture_home" \
        GIT_CONFIG_NOSYSTEM=1 \
        GIT_AUTHOR_NAME=fixture GIT_AUTHOR_EMAIL=fixture@example.invalid \
        GIT_COMMITTER_NAME=fixture GIT_COMMITTER_EMAIL=fixture@example.invalid \
        PATH="$fixture_bin:$PATH" \
        OMP_PATH="$fixture_bin/omp" \
        HYPERLIQUID_SDK_LOCK="$WORKDIR/wrapper.lock" \
        HYPERLIQUID_PRIVATE_KEY="${FIXTURE_FAKE_SIGNING_KEY}" \
        WRAPPER_FIXTURE_MODE="$case_name" \
        bash "$SCRIPT_DIR/run_hyperliquid_sdk.sh" 2>&1
    )" || rc=$?
    case "$case_name" in
      early-exit) expected_rc=3 expected_msg="FATAL: omp exited 0 but*did not advance" ;;
      dirty-tree) expected_rc=4 expected_msg="FATAL: *is dirty after the run:*scratch.rb" ;;
      unpushed-commit) expected_rc=5 expected_msg="FATAL: HEAD * is not on origin/dev*unpushed commit" ;;
      red-clone-gate) expected_rc=6 expected_msg="FATAL: clone gate red:" ;;
      *) expected_rc=0 expected_msg="ok: clone gate green on origin/dev" ;;
    esac
    if (( rc != expected_rc )); then
      printf 'FATAL: wrapper %s exited %s, expected %s:\n%s\n' \
        "$case_name" "$rc" "$expected_rc" "$output" >&2
      return 1
    fi
    # shellcheck disable=SC2053 # expected_msg is a deliberate glob pattern
    if [[ "$output" != *$expected_msg* ]]; then
      printf 'FATAL: wrapper %s did not report "%s":\n%s\n' \
        "$case_name" "$expected_msg" "$output" >&2
      return 1
    fi
    # Whenever the clone gate ran, it must have tested the pushed tip in a
    # fresh clone (not the checkout) with the CI-parity environment and no key.
    if (( expected_rc == 0 || expected_rc == 6 )); then
      origin_tip="$(fixture_git --git-dir="$fixture_origin" rev-parse dev)"
      if [[ ! -f "$bundle_log" ]] \
        || ! grep -qx 'args=exec rake' "$bundle_log" \
        || ! grep -qx 'env=RBENV_VERSION:3.4.10 BUNDLE_FROZEN:true signing_key:' "$bundle_log" \
        || ! grep -qx "sha=$origin_tip" "$bundle_log" \
        || grep -q "^cwd=$fixture_home/dev/hyperliquid" "$bundle_log"; then
        printf 'FATAL: wrapper %s clone gate did not run rake on a fresh key-less clone of origin/dev %s:\n%s\n' \
          "$case_name" "$origin_tip" "$(cat "$bundle_log" 2>/dev/null || echo '(bundle never ran)')" >&2
        return 1
      fi
    elif [[ -e "$bundle_log" ]]; then
      printf 'FATAL: wrapper %s ran the clone gate after a failed post-condition\n' "$case_name" >&2
      return 1
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
