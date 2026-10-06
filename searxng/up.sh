#!/usr/bin/env bash
# Start (or update) the local SearXNG metasearch container.
# Loopback-only on 127.0.0.1:8080 — consumed by Open WebUI and OMP web/searxng.
# No Valkey: the bot-detection limiter is disabled, so no sidecar is needed.
set -euo pipefail
cd "$(dirname "$0")"

# Render the tracked settings.yml into the gitignored runtime copy on every run,
# keeping the runtime secret_key (generated once; never stored in git).
# core-config/ is chowned to the container's searxng user, so writes go through
# a one-shot container.
mkdir -p core-config
runtime=core-config/settings.yml
# The template holds exactly one REPLACE_AT_DEPLOY placeholder (server secret);
# the runtime file holds the only quoted 32-hex value.
[ "$(grep -c REPLACE_AT_DEPLOY settings.yml)" -eq 1 ] \
  || { echo "settings.yml must contain exactly one REPLACE_AT_DEPLOY placeholder" >&2; exit 1; }
secret=""
if [ -f "$runtime" ]; then
  secret="$(sed -n 's/^ *[a-z_]*: "\([0-9a-f]\{32\}\)"$/\1/p' "$runtime")"
fi
case "$secret" in
  *$'\n'*) echo "$runtime has more than one quoted 32-hex value; fix it by hand" >&2; exit 1 ;;
esac
if [ -z "$secret" ]; then
  secret="$(openssl rand -hex 16)"
  echo "Generated new server secret for $runtime (gitignored)"
fi
rendered="$(sed "s/REPLACE_AT_DEPLOY/${secret}/" settings.yml)"

config_changed=false
if [ ! -f "$runtime" ] || ! cmp -s <(printf '%s\n' "$rendered") "$runtime"; then
  printf '%s\n' "$rendered" | docker compose run --rm --no-deps -T --entrypoint sh core \
    -c 'cat > /etc/searxng/settings.yml && chown searxng:searxng /etc/searxng/settings.yml && chmod 644 /etc/searxng/settings.yml'
  config_changed=true
  echo "Updated $runtime from settings.yml"
fi

echo "Pulling pinned image..."
docker compose pull
# Open WebUI reaches SearXNG as http://searxng:8080 over the shared
# homelab-chat-search network declared in docker-compose.yml. Never attach
# searxng to open-webui's host-access bridge (owui-host/br-owui).
if [ "$config_changed" = true ]; then
  docker compose up -d --force-recreate
else
  docker compose up -d
fi
docker compose ps
