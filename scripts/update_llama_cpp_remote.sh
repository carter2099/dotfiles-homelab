#!/usr/bin/env bash
# Runs on gamingrig-linux via `ssh gamingrig bash -s -- <bNNNNN>`.
# Build/install happens without root. Root is used only for the versioned /opt move,
# linker path, symlinks, and service restart. Any post-switch failure restores all four.
set -Eeuo pipefail

TARGET=${1:-}
if [[ ! $TARGET =~ ^b[0-9]+$ ]]; then
  echo "invalid llama.cpp release tag: $TARGET" >&2
  exit 2
fi

SOURCE=$HOME/src/llama.cpp
ORIGIN=https://github.com/ggml-org/llama.cpp.git
WORKTREE=$HOME/src/llama.cpp-worktrees/$TARGET
STAGE=$HOME/src/llama.cpp-staging/$TARGET
PREFIX=/opt/llama.cpp/$TARGET
LD_CONFIG=/etc/ld.so.conf.d/llama-cpp.conf
SERVER_LINK=/usr/local/bin/llama-server
BENCH_LINK=/usr/local/bin/llama-bench
MODELS_URL=http://192.168.4.103:8080/v1/models
READINESS_TIMEOUT=${LLAMA_SWAP_READINESS_TIMEOUT:-90}
READINESS_INTERVAL=${LLAMA_SWAP_READINESS_INTERVAL:-2}
[[ $READINESS_TIMEOUT =~ ^[1-9][0-9]*$ ]]
[[ $READINESS_INTERVAL =~ ^[1-9][0-9]*$ ]]

[[ $(git -C "$SOURCE" remote get-url origin) == "$ORIGIN" ]]
OLD_SERVER=$(readlink -f "$SERVER_LINK")
OLD_BENCH=$(readlink -f "$BENCH_LINK")
[[ $OLD_SERVER =~ ^/opt/llama\.cpp/b[0-9]+/bin/llama-server$ ]]
[[ $OLD_BENCH =~ ^/opt/llama\.cpp/b[0-9]+/bin/llama-bench$ ]]
OLD_LD=$(sudo -n cat "$LD_CONFIG")
SWITCHED=0

wait_for_models() {
  local deadline=$((SECONDS + READINESS_TIMEOUT))
  local remaining probe_timeout sleep_for
  while (( SECONDS < deadline )); do
    remaining=$((deadline - SECONDS))
    probe_timeout=$remaining
    (( probe_timeout > 3 )) && probe_timeout=3
    if sudo -n systemctl is-active --quiet llama-swap.service \
      && curl -fsS --connect-timeout "$probe_timeout" --max-time "$probe_timeout" \
        "$MODELS_URL" >/dev/null 2>&1; then
      return 0
    fi
    remaining=$((deadline - SECONDS))
    (( remaining > 0 )) || break
    sleep_for=$READINESS_INTERVAL
    (( sleep_for > remaining )) && sleep_for=$remaining
    sleep "$sleep_for"
  done
  echo "llama-swap not ready after ${READINESS_TIMEOUT}s" >&2
  return 1
}

cleanup() {
  git -C "$SOURCE" worktree remove --force "$WORKTREE" >/dev/null 2>&1 || true
  rm -rf "$STAGE"
}

rollback() { # shellcheck disable=SC2329
  local rc=$?
  local rollback_failed=0
  trap - ERR
  set +e
  if (( SWITCHED )); then
    sudo -n ln -sfn "$OLD_SERVER" "$SERVER_LINK" || rollback_failed=1
    sudo -n ln -sfn "$OLD_BENCH" "$BENCH_LINK" || rollback_failed=1
    printf '%s\n' "$OLD_LD" | sudo -n tee "$LD_CONFIG" >/dev/null \
      || rollback_failed=1
    sudo -n ldconfig || rollback_failed=1
    sudo -n systemctl restart llama-swap.service || rollback_failed=1
    if (( rollback_failed == 0 )) && wait_for_models; then
      echo "ROLLBACK_OK $OLD_SERVER" >&2
    else
      echo "ROLLBACK_FAILED $OLD_SERVER" >&2
    fi
  fi
  cleanup
  exit "$rc"
}
trap rollback ERR

# Fetch and build as the unprivileged SSH user. Upstream CMake is never run as root.
git -C "$SOURCE" fetch --force --prune --tags origin
git -C "$SOURCE" rev-parse --verify "refs/tags/$TARGET^{commit}" >/dev/null
mkdir -p "$(dirname "$WORKTREE")" "$(dirname "$STAGE")"
git -C "$SOURCE" worktree remove --force "$WORKTREE" >/dev/null 2>&1 || true
rm -rf "$WORKTREE" "$STAGE"
git -C "$SOURCE" worktree add --detach "$WORKTREE" "$TARGET"

cmake -S "$WORKTREE" -B "$WORKTREE/build" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DGGML_CUDA=ON \
  -DCMAKE_CUDA_ARCHITECTURES=120 \
  -DCMAKE_CUDA_COMPILER=/usr/local/cuda-13.2/bin/nvcc \
  -DLLAMA_BUILD_TESTS=OFF \
  -DCMAKE_INSTALL_PREFIX="$STAGE"
cmake --build "$WORKTREE/build" -j "$(nproc)"
cmake --install "$WORKTREE/build"

LD_LIBRARY_PATH="$STAGE/lib" "$STAGE/bin/llama-server" --version >/dev/null
LD_LIBRARY_PATH="$STAGE/lib" "$STAGE/bin/llama-bench" --list-devices | grep -q 'CUDA0:'

# The target is versioned, so the prior prefix remains intact for rollback.
sudo -n rm -rf "$PREFIX"
sudo -n mv "$STAGE" "$PREFIX"
SWITCHED=1
printf '%s\n' "$PREFIX/lib" | sudo -n tee "$LD_CONFIG" >/dev/null
sudo -n ldconfig
sudo -n ln -sfn "$PREFIX/bin/llama-server" "$SERVER_LINK"
sudo -n ln -sfn "$PREFIX/bin/llama-bench" "$BENCH_LINK"
sudo -n systemctl restart llama-swap.service
wait_for_models
[[ $(readlink -f "$SERVER_LINK") == "$PREFIX/bin/llama-server" ]]

trap - ERR
cleanup
echo "UPDATE_OK $TARGET"
