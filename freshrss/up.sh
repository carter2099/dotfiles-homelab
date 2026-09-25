#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [ ! -d ./data ]; then
    echo "FreshRSS data directory is missing: ./data" >&2
    exit 1
fi
docker compose config --quiet
docker compose pull
docker compose up -d --remove-orphans
port=30149
for _attempt in $(seq 1 60); do
    if curl --fail --silent --max-time 5 "http://127.0.0.1:${port}/i/" >/dev/null; then
        docker compose ps
        exit 0
    fi
    sleep 1
done
echo "freshrss container did not become healthy" >&2
docker compose logs --no-color --tail=80 freshrss >&2
exit 1
