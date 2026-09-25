#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -L /home/carter/digests/news/current ] || \
   [ ! -f /home/carter/digests/news/current/index.html ]; then
    echo "news site has not been built; run scripts/news_publish.py first" >&2
    exit 1
fi

docker compose config --quiet
docker compose pull
docker compose up -d --remove-orphans

for _attempt in $(seq 1 20); do
    if curl --fail --silent --show-error http://127.0.0.1:30144/healthz >/dev/null; then
        docker compose ps
        exit 0
    fi
    sleep 1
done

echo "news container did not become healthy" >&2
docker compose logs --no-color --tail=80 web >&2
exit 1
