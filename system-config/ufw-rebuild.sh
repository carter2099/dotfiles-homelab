#!/bin/bash
# Rebuild UFW firewall rules for homelab (idempotent — safe to re-run).
# Single source of truth: ufw-expected-rules.txt next to this script, one
# `ufw ...` rule per line exactly as printed by `sudo ufw show added`. Parsing
# matches steward P3a (health.py _read_expected_ufw_rules): each line is
# whitespace-trimmed; blank lines and lines starting with # are ignored.
# Before touching anything the file is validated and the script aborts if it has
# no rules, lacks the LAN SSH allow, has a line outside the accepted grammar
# (`ufw <words>` optionally ending in ` comment '<text>'`), or has a rule that
# `ufw --dry-run` rejects. It then adds every expected rule (in file order) and
# refuses to delete anything unless every expected line is now live verbatim.
# Only then are user rules not in the file deleted; it fails if the live rules
# still differ from the file.
# Default policies are Ubuntu defaults: deny incoming, allow outgoing, deny routed
# (see /etc/default/ufw). Docker LAN exposure is handled by docker-user-rules.service.
set -euo pipefail
expected="$(dirname "$(readlink -f "$0")")/ufw-expected-rules.txt"
[ -r "$expected" ] || { echo "missing $expected" >&2; exit 1; }
ssh_rule="ufw allow from 192.168.4.0/22 to any port 22 proto tcp"

echo "=== Ensuring UFW is installed ==="
if ! command -v ufw &>/dev/null; then
    sudo apt-get update && sudo apt-get install -y ufw
fi

# Trim like Python str.strip(); drop blanks and # comments (steward P3a parsing).
normalize() { sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e '/^#/d' -e '/^$/d'; }
expected_rules() { normalize < "$expected"; }
live_rules() { sudo ufw show added | tail -n +2 | normalize; }

# Split one rule line into the argv array `args` (without the leading "ufw").
# No eval: words are [A-Za-z0-9./:,_-]; an optional final comment is single-quoted.
word_re="[A-Za-z0-9./:,_-]+"
rule_re="^ufw(( $word_re)+)( comment '([^']*)')?\$"
parse_rule() { # $1 = rule line; sets args
    [[ $1 =~ $rule_re ]] || return 1
    read -r -a args <<< "${BASH_REMATCH[1]}"
    [ -n "${BASH_REMATCH[3]}" ] && args+=(comment "${BASH_REMATCH[4]}")
    return 0
}

echo "=== Validating $expected ==="
mapfile -t want < <(expected_rules)
((${#want[@]})) || { echo "refusing: $expected has no rules" >&2; exit 1; }
printf '%s\n' "${want[@]}" | grep -qxF -- "$ssh_rule" \
    || { echo "refusing: $expected lacks the LAN SSH rule: $ssh_rule" >&2; exit 1; }
for line in "${want[@]}"; do
    parse_rule "$line" || { echo "refusing: bad line (not \`ufw <words> [comment '...']\`): $line" >&2; exit 1; }
    sudo ufw --dry-run "${args[@]}" >/dev/null \
        || { echo "refusing: ufw --dry-run rejects: $line" >&2; exit 1; }
done

echo "=== Adding expected rules ==="
for line in "${want[@]}"; do
    parse_rule "$line"
    sudo ufw "${args[@]}"
done

missing=$(comm -23 <(printf '%s\n' "${want[@]}" | sort -u) <(live_rules | sort -u))
if [ -n "$missing" ]; then
    printf 'refusing to delete: expected lines not live verbatim (use exact `ufw show added` text):\n%s\n' "$missing" >&2
    exit 1
fi

echo "=== Deleting rules not in $expected ==="
mapfile -t live < <(live_rules)
for line in "${live[@]}"; do
    printf '%s\n' "${want[@]}" | grep -qxF -- "$line" && continue
    parse_rule "$line" || { echo "cannot parse live rule, delete by hand: $line" >&2; exit 1; }
    echo "deleting: $line"
    sudo ufw delete "${args[@]}"
done

echo "=== Enabling UFW ==="
sudo ufw --force enable

if ! diff <(live_rules | sort) <(expected_rules | sort); then
    echo "ERROR: live UFW rules differ from $expected" >&2
    exit 1
fi
echo "=== Current rule set ==="
sudo ufw status verbose
echo "Done: live rules match $expected."
