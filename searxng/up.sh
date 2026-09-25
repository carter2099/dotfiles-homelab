#!/usr/bin/env bash
# Start (or update) the local SearXNG metasearch container.
# Loopback-only on 127.0.0.1:8080 — consumed by rpiv-web-tools (pi web_search).
# No Valkey: the bot-detection limiter is disabled, so no sidecar is needed.
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p core-config
# First deploy: seed the runtime settings from the tracked template and bake in a
# real secret_key (keeps the secret out of git; only core-config/ holds it).
if [ ! -f core-config/settings.yml ]; then
  cp settings.yml core-config/settings.yml
  secret="$(openssl rand -hex 16)"
  sed -i "s/REPLACE_AT_DEPLOY/${secret}/g" core-config/settings.yml
  echo "Generated secret_key in core-config/settings.yml (gitignored)"
fi

echo "Pulling latest image..."
docker compose pull
docker compose up -d
# Open WebUI reaches SearXNG as http://searxng:8080 over the shared
# homelab-chat-search network declared in docker-compose.yml. Never attach
# searxng to open-webui's host-access bridge (owui-host/br-owui).
docker compose ps
