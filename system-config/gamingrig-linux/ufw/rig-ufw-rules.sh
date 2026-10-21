#!/usr/bin/env bash
# Canonical UFW policy for gamingrig-linux (rig). Idempotent; run with sudo.
# SSH: ThinkPad (192.168.4.92), Carter's Mac (192.168.4.77).
# llama-swap :8080: ThinkPad only.
# Rollback: sudo ufw disable && sudo ufw --force reset
set -euo pipefail

ufw default deny incoming
ufw default allow outgoing

for src in 192.168.4.92 192.168.4.77; do
  ufw allow proto tcp from "$src" to any port 22 comment 'ssh'
done
ufw allow proto tcp from 192.168.4.92 to any port 8080 comment 'llama-swap'

# Retired 2026-10-20: 192.168.4.100 was the ThinkPad's old DHCP lease (it moved
# to .79 on 2026-09-23) and now belongs to another LAN device.
for port in 22 8080; do
  ufw delete allow proto tcp from 192.168.4.100 to any port "$port" || true
done

ufw --force enable
ufw status verbose
