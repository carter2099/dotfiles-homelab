#!/usr/bin/env bash
# Provision the dedicated P7b repair identity, fixed proxy relay, and sandbox.
# Run only after the source commit has been reviewed:
#   sudo bash ~/system-config/steward-worker-provision.sh
# Refresh only the worker's OMP executable (steward P1 after `omp update`):
#   sudo -n bash ~/system-config/steward-worker-provision.sh --omp-only
set -euo pipefail

omp_only=0
case "$#:${1:-}" in
  0:) ;;
  1:--omp-only) omp_only=1 ;;
  *)
    echo "usage: steward-worker-provision.sh [--omp-only]" >&2
    exit 2
    ;;
esac

if [[ ${EUID} -ne 0 ]]; then
  echo "steward-worker-provision: run as root (sudo)" >&2
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
WORKER_HOME=/var/lib/steward-worker
LIBEXEC=/usr/local/libexec/steward-worker
ETC=/etc/steward-worker

# A missing OMP binary is a provisioning error, never a reason to fall back to
# Carter's ~/.bun or ~/.omp state.
OMP_SOURCE=/home/carter/.bun/bin/omp
if [[ ! -x "${OMP_SOURCE}" ]]; then
  echo "steward-worker-provision: missing executable ${OMP_SOURCE}" >&2
  exit 1
fi

if ((omp_only)); then
  # Touch only the OMP executable; worker.py, policy, config, sudoers, and
  # units stay exactly as the last reviewed full provisioning left them.
  if [[ ! -d "${LIBEXEC}" || -L "${LIBEXEC}" ]]; then
    echo "steward-worker-provision: ${LIBEXEC} missing; run full provisioning first" >&2
    exit 1
  fi
  if [[ -f "${LIBEXEC}/omp" && ! -L "${LIBEXEC}/omp" ]] &&
     cmp -s -- "${OMP_SOURCE}" "${LIBEXEC}/omp" &&
     [[ "$(stat -c '%u:%g:%a' -- "${LIBEXEC}/omp")" == 0:0:755 ]]; then
    echo "steward-worker-provision: worker OMP already matches ${OMP_SOURCE}"
    exit 0
  fi
  staged="$(mktemp "${LIBEXEC}/.omp.XXXXXX")"
  trap 'rm -f -- "${staged}"' EXIT
  install -o root -g root -m 0755 "${OMP_SOURCE}" "${staged}"
  mv -f -- "${staged}" "${LIBEXEC}/omp"
  trap - EXIT
  echo "steward-worker-provision: refreshed worker OMP from ${OMP_SOURCE}"
  exit 0
fi

getent group steward-worker >/dev/null || groupadd --system steward-worker
if ! getent passwd steward-worker >/dev/null; then
  useradd --system --home-dir /var/empty --no-create-home \
    --shell /usr/sbin/nologin --gid steward-worker steward-worker
fi
if ! getent passwd steward-proxy >/dev/null; then
  useradd --system --home-dir /var/empty --no-create-home \
    --shell /usr/sbin/nologin --gid steward-worker steward-proxy
fi
usermod --gid steward-worker --home /var/empty --shell /usr/sbin/nologin steward-worker
usermod --gid steward-worker --home /var/empty --shell /usr/sbin/nologin steward-proxy
# Keep both service identities on their non-privileged primary group only.
usermod --groups '' steward-worker
usermod --groups '' steward-proxy
for group in docker lxd sudo; do
  gpasswd --delete steward-worker "${group}" >/dev/null 2>&1 || true
  gpasswd --delete steward-proxy "${group}" >/dev/null 2>&1 || true
done

install -d -o root -g root -m 0755 "${LIBEXEC}"
install -d -o root -g steward-worker -m 0750 "${ETC}"
install -d -o root -g steward-worker -m 0750 "${WORKER_HOME}"
for dir in runs requests; do
  install -d -o root -g steward-worker -m 0710 "${WORKER_HOME}/${dir}"
done
install -d -o root -g root -m 0555 /var/empty
install -d -o root -g root -m 0755 /run/lock
install -o root -g root -m 0600 /dev/null /run/lock/steward-worker.lock

# Install only the audited standalone worker module and OMP executable.  No
# Carter config, auth DB, session history, SSH material, or provider tokens are
# copied to the worker tree.
install -o root -g root -m 0755 "${SCRIPT_DIR}/../scripts/steward/worker.py" \
  "${LIBEXEC}/worker.py"
install -o root -g root -m 0755 "${OMP_SOURCE}" "${LIBEXEC}/omp"
install -d -o root -g root -m 0755 "${LIBEXEC}/bin"
install -o root -g root -m 0755 /home/carter/.bun/bin/bun "${LIBEXEC}/bin/bun"
install -o root -g root -m 0755 "${SCRIPT_DIR}/steward-worker-run" \
  /usr/local/libexec/steward-worker-run
install -o root -g root -m 0755 "${SCRIPT_DIR}/steward-worker-proxy" \
  /usr/local/libexec/steward-worker-proxy
install -o root -g root -m 0644 "${SCRIPT_DIR}/steward-worker-omp-config.yml" \
  "${ETC}/omp-config.yml"
install -o root -g root -m 0644 "${SCRIPT_DIR}/steward-worker-models.yml" \
  "${ETC}/models.yml"
install -o root -g root -m 0644 "${SCRIPT_DIR}/steward-worker-policy.json" \
  "${ETC}/policy.json"
install -o root -g root -m 0644 "${SCRIPT_DIR}/steward-worker@.service" \
  /etc/systemd/system/steward-worker@.service
install -o root -g root -m 0644 "${SCRIPT_DIR}/steward-worker-proxy.service" \
  /etc/systemd/system/steward-worker-proxy.service

# The wildcard is safe because steward-worker-run validates every request,
# source root, file mode, and protocol before starting the fixed unit.  The
# worker identity is not this sudoers principal and cannot invoke it.
cat > /etc/sudoers.d/steward-worker <<'SUDOERS'
# Carter may submit one validated bounded worker request; the helper rejects
# unsafe paths and never executes repository scripts as root.
carter ALL=(root) NOPASSWD: /usr/local/libexec/steward-worker-run *
SUDOERS
chmod 0440 /etc/sudoers.d/steward-worker
chown root:root /etc/sudoers.d/steward-worker

systemctl daemon-reload
systemctl enable --now steward-worker-proxy.service

echo "steward-worker-provision: installed identity, sandbox, proxy, and policy"
echo "steward-worker-provision: run the documented positive/negative smoke commands before enabling P7b"
