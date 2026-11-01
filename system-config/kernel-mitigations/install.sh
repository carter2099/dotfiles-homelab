#!/usr/bin/env bash
# Temporary kernel-vulnerability stopgaps for Ubuntu 24.04 hosts (since 2026-11-01).
#
#   CVE-2026-98432  remote pre-auth IPv4 TCP use-after-free.
#                   Mitigation: nftables table `inet cve_2026_98432` dropping IPv4
#                   TCP with IP options, loaded by cve-2026-98432-nft.service.
#                   https://ubuntu.com/security/CVE-2026-98432
#                   https://kb.ciq.com/article/security-advisories/cve-2026-98432-mitigation
#                   Remove when: the running kernel on the host is a fixed one
#                   (noble `linux` >= 6.8.0-149.149, or whatever the USN lists).
#
#   ZDI-CAN-33367   local privilege escalation (no CVE yet), public exploit.
#                   Mitigation: /etc/modprobe.d/zdi-can-33367.conf blocks esp4, esp6,
#                   nlmon, act_pedit.
#                   https://almalinux.org/blog/2026-10-23-zdi-can-33367
#                   https://www.sysdig.com/blog/detecting-and-mitigating-zdi-can-33367-and-five-other-linux-flaws
#                   Remove when: Ubuntu ships a fixed kernel for it (track the
#                   USN/CVE once assigned) and it is running on the host.
#
# Usage:
#   install.sh [apply]                 install + activate both, then verify
#   install.sh remove [nft|modules]    retire one part (or both, the default)
#   install.sh status                  show current state, changes nothing
#
# ThinkPad (tp-server):
#   sudo bash ~/system-config/kernel-mitigations/install.sh
# Gaming rig (gamingrig-linux):
#   scp -r ~/system-config/kernel-mitigations gamingrig-linux:~/
#   ssh -t gamingrig-linux 'sudo bash ~/kernel-mitigations/install.sh apply'
#
# nftables.service must stay disabled: Ubuntu's default /etc/nftables.conf does
# `flush ruleset`, which would wipe the UFW/Docker iptables-nft rules. This
# mitigation uses its own unit and only ever touches its own table.

set -euo pipefail

SCRIPT="$(readlink -f "${BASH_SOURCE[0]}")"
SRC_DIR="$(dirname "$SCRIPT")"

if [[ $EUID -ne 0 ]]; then
	exec sudo bash "$SCRIPT" "$@"
fi

NFT_SRC="$SRC_DIR/cve-2026-98432.nft"
UNIT_SRC="$SRC_DIR/cve-2026-98432-nft.service"
MODPROBE_SRC="$SRC_DIR/zdi-can-33367.conf"

NFT_DST=/etc/nftables.d/cve-2026-98432.nft
UNIT_DST=/etc/systemd/system/cve-2026-98432-nft.service
MODPROBE_DST=/etc/modprobe.d/zdi-can-33367.conf

UNIT=cve-2026-98432-nft.service
TABLE=(inet cve_2026_98432)
MODULES=(esp4 esp6 nlmon act_pedit)

die() {
	echo "ERROR: $*" >&2
	exit 1
}

module_loaded() {
	lsmod | awk -v m="$1" '$1 == m { found = 1 } END { exit !found }'
}

table_present() {
	nft list table "${TABLE[@]}" >/dev/null 2>&1
}

apply() {
	local f mod out state

	for f in "$NFT_SRC" "$UNIT_SRC" "$MODPROBE_SRC"; do
		[[ -f $f ]] || die "missing source file: $f"
	done

	# 1. Validate the ruleset before mutating anything.
	nft -c -f "$NFT_SRC" || die "nft -c rejected $NFT_SRC; nothing changed"

	# 2. Blocking esp4/esp6 would break IPsec.
	if [[ -n "$(ip xfrm state)" || -n "$(ip xfrm policy)" ]]; then
		die "IPsec xfrm state/policy present; blocking esp4/esp6 would break it. Nothing changed."
	fi

	# 3. nftables.service's default config flushes the whole ruleset.
	state="$(systemctl is-enabled nftables.service 2>/dev/null || true)"
	if [[ $state == enabled* ]]; then
		die "nftables.service is $state; its 'flush ruleset' would wipe UFW/Docker rules. Disable it first. Nothing changed."
	fi

	# 4. Install files.
	install -D -m 0644 "$NFT_SRC" "$NFT_DST"
	install -D -m 0644 "$UNIT_SRC" "$UNIT_DST"
	install -D -m 0644 "$MODPROBE_SRC" "$MODPROBE_DST"

	# 5. Unload blocked modules that are already loaded.
	for mod in "${MODULES[@]}"; do
		if module_loaded "$mod"; then
			echo "Unloading $mod"
			modprobe -r "$mod" || die "could not unload $mod (in use?); unload it manually or reboot"
		fi
	done

	# 6. Activate the nft unit (restart so a changed rules file is reloaded).
	systemctl daemon-reload
	systemctl enable "$UNIT"
	systemctl restart "$UNIT"

	# 7. Post-checks.
	out="$(nft list table "${TABLE[@]}")" || die "table ${TABLE[*]} not present after start"
	if ! grep -q 'hdrlength' <<<"$out" || ! grep -qF 'drop comment "CVE-2026-98432 stopgap"' <<<"$out"; then
		die "drop rule missing from table ${TABLE[*]}"
	fi
	systemctl is-active --quiet "$UNIT" || die "$UNIT is not active"
	systemctl is-enabled --quiet "$UNIT" || die "$UNIT is not enabled"
	for mod in "${MODULES[@]}"; do
		out="$(modprobe -n -v "$mod" 2>&1 || true)"
		grep -qF 'install /bin/false' <<<"$out" || die "modprobe does not block $mod"
		! module_loaded "$mod" || die "$mod is still loaded"
	done

	echo "KERNEL_MITIGATIONS_APPLIED kernel=$(uname -r) nft=${TABLE[*]} modules=${MODULES[*]}"
}

remove_nft() {
	if systemctl cat "$UNIT" >/dev/null 2>&1; then
		systemctl disable --now "$UNIT" || true
	fi
	if table_present; then
		nft delete table "${TABLE[@]}"
	fi
	rm -f "$NFT_DST" "$UNIT_DST"
	systemctl daemon-reload
}

remove_modules() {
	rm -f "$MODPROBE_DST"
}

remove() {
	case "${1:-both}" in
		nft) remove_nft ;;
		modules) remove_modules ;;
		both)
			remove_nft
			remove_modules
			;;
		*) die "usage: $0 remove [nft|modules]" ;;
	esac
	echo "KERNEL_MITIGATIONS_REMOVED part=${1:-both} kernel=$(uname -r)"
}

status() {
	local mod out loaded
	echo "kernel: $(uname -r)"
	echo "$UNIT: active=$(systemctl is-active "$UNIT" 2>/dev/null || true) enabled=$(systemctl is-enabled "$UNIT" 2>/dev/null || true)"
	echo "nftables.service enabled=$(systemctl is-enabled nftables.service 2>/dev/null || true)"
	echo "table ${TABLE[*]}:"
	if table_present; then
		nft list table "${TABLE[@]}"
	else
		echo "  absent"
	fi
	echo "modules:"
	for mod in "${MODULES[@]}"; do
		out="$(modprobe -n -v "$mod" 2>&1 || true)"
		loaded=''
		if module_loaded "$mod"; then
			loaded=' [LOADED]'
		fi
		echo "  $mod: ${out//$'\n'/ }$loaded"
	done
}

case "${1:-apply}" in
	apply) apply ;;
	remove) remove "${2:-both}" ;;
	status) status ;;
	*) die "usage: $0 [apply|remove [nft|modules]|status]" ;;
esac
