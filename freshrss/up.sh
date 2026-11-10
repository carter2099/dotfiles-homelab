#!/usr/bin/env bash
# Build and run the derived FreshRSS image (Dockerfile): the upstream base
# pinned in docker-compose.yml plus a Debian security-update layer.
# SECURITY_REFRESH=<stamp> rebuilds that layer; without it the stamp of the
# last healthy deploy is reused, so a plain rerun never falls back to an
# older cached package set.
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -d ./data ]; then
    echo "FreshRSS data directory is missing: ./data" >&2
    exit 1
fi
refresh_file="${HOME}/.local/state/freshrss/security-refresh"
if [ -z "${SECURITY_REFRESH:-}" ] && [ -f "$refresh_file" ]; then
    SECURITY_REFRESH="$(cat "$refresh_file")"
fi
SECURITY_REFRESH="${SECURITY_REFRESH:-0}"
if ! [[ "$SECURITY_REFRESH" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "invalid SECURITY_REFRESH: $SECURITY_REFRESH" >&2
    exit 1
fi
export SECURITY_REFRESH
mapfile -t bases < <(grep -oE 'freshrss/freshrss:[0-9]+\.[0-9]+\.[0-9]+@sha256:[0-9a-f]{64}' docker-compose.yml)
if [ "${#bases[@]}" -ne 1 ]; then
    echo "expected exactly one freshrss/freshrss:<tag>@sha256 pin in docker-compose.yml, found ${#bases[@]}" >&2
    exit 1
fi
docker compose config --quiet
# The pin is a digest, so a local copy is the same image; the local
# freshrss-local image is never pulled.
docker image inspect "${bases[0]}" >/dev/null 2>&1 || docker pull "${bases[0]}"
docker compose build freshrss
docker compose up -d --remove-orphans
port=30149
for _attempt in $(seq 1 60); do
    if curl --fail --silent --max-time 5 "http://127.0.0.1:${port}/i/" >/dev/null; then
        mkdir -p -m 700 "$(dirname "$refresh_file")"
        printf '%s\n' "$SECURITY_REFRESH" > "$refresh_file"
        docker compose ps
        exit 0
    fi
    sleep 1
done
echo "freshrss container did not become healthy" >&2
docker compose logs --no-color --tail=80 freshrss >&2
exit 1
