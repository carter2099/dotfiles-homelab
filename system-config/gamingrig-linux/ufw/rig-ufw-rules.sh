#!/usr/bin/env bash
# Canonical UFW policy for gamingrig-linux (rig). Idempotent; run with sudo.
# SSH: ThinkPad (192.168.4.92), 192.168.4.100, Carter's Mac (192.168.4.77).
# llama-swap :8080: ThinkPad and 192.168.4.100 only.
# Rollback: sudo ufw disable && sudo ufw --force reset
set -euo pipefail

ufw default deny incoming
ufw default allow outgoing

for src in 192.168.4.92 192.168.4.100 192.168.4.77; do
  ufw allow proto tcp from "$src" to any port 22 comment 'ssh'
done
for src in 192.168.4.92 192.168.4.100; do
  ufw allow proto tcp from "$src" to any port 8080 comment 'llama-swap'
done

ufw --force enable
ufw status verbose
