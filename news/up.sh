#!/usr/bin/env bash
# Build and run the derived Daily News web image (Dockerfile): the upstream
# nginx base pinned in docker-compose.yml plus an Alpine security-update layer.
# SECURITY_REFRESH=<stamp> rebuilds that layer; without it the stamp of the
# last healthy deploy is reused, so a plain rerun never falls back to an
# older cached package set.
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -L /home/carter/digests/news/current ] || \
   [ ! -f /home/carter/digests/news/current/index.html ]; then
    echo "news site has not been built; run scripts/news_publish.py first" >&2
    exit 1
fi

refresh_file="${HOME}/.local/state/news/security-refresh"
if [ -z "${SECURITY_REFRESH:-}" ] && [ -f "$refresh_file" ]; then
    SECURITY_REFRESH="$(cat "$refresh_file")"
fi
SECURITY_REFRESH="${SECURITY_REFRESH:-0}"
if ! [[ "$SECURITY_REFRESH" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "invalid SECURITY_REFRESH: $SECURITY_REFRESH" >&2
    exit 1
fi
export SECURITY_REFRESH
mapfile -t bases < <(grep -oE 'nginx:[0-9]+\.[0-9]+\.[0-9]+-alpine@sha256:[0-9a-f]{64}' docker-compose.yml)
if [ "${#bases[@]}" -ne 1 ]; then
    echo "expected exactly one nginx:<tag>-alpine@sha256 pin in docker-compose.yml, found ${#bases[@]}" >&2
    exit 1
fi

docker compose config --quiet
# The pin is a digest, so a local copy is the same image; the local
# carter-news-local image is never pulled.
docker image inspect "${bases[0]}" >/dev/null 2>&1 || docker pull "${bases[0]}"
docker compose build web
docker compose up -d --remove-orphans

for _attempt in $(seq 1 20); do
    if curl --fail --silent --show-error http://127.0.0.1:30144/healthz >/dev/null; then
        install -d -m 700 "$(dirname "$refresh_file")"
        printf '%s\n' "$SECURITY_REFRESH" > "$refresh_file"
        docker compose ps
        exit 0
    fi
    sleep 1
done

echo "news container did not become healthy" >&2
docker compose logs --no-color --tail=80 web >&2
exit 1
