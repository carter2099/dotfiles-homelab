#!/bin/bash
# Inject DOCKER-USER rules to block LAN access to Docker containers
# Allows: localhost, Docker bridge networks
# Drops: everything else (LAN devices on 192.168.x.x, external)
#
# DOCKER-USER sits first in FORWARD — before Docker's per-port ACCEPT rules.
# RETURN = continue processing (let Docker's rules handle it). DROP = deny.

set -e

CHAIN="DOCKER-USER"

# Flush existing rules (idempotent across restarts)
iptables -F "$CHAIN" 2>/dev/null || true

# 1. Allow established/related connections (reply traffic for existing flows)
iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

# 2. Allow from localhost
iptables -A "$CHAIN" -s 127.0.0.0/8 -j RETURN

# 3. Allow from Docker bridge networks (inter-container communication, internet-bound replies)
iptables -A "$CHAIN" -s 172.16.0.0/12 -j RETURN

# 4. Drop everything else (LAN devices, external)
iptables -A "$CHAIN" -j DROP
