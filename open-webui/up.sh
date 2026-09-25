#!/usr/bin/env bash
# Start the exact Open WebUI image already pinned and preloaded by /update-openweb-ui.
# Loopback-only on 127.0.0.1:48100, wired to the OpenCode Go endpoint. Public access is via the
# CF tunnel + Cloudflare Access on chat.carter2099.com (see CLAUDE.md "Remote Agent Operations").
set -euo pipefail
cd "$(dirname "$0")"
docker compose up -d
docker compose ps
