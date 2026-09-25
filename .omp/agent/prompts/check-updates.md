---
description: Check the homelab for outdated software by reading the steward's latest run artifacts. Report-only, never applies updates. Use when user says "check for updates", "what's outdated", "audit the homelab", "run update check", or wants a system health report.
---

# Check Updates

Read the steward's latest run artifacts to report what was done and what is behind. This is the interactive read-only view, not an auto-apply.

## Step 1: Load latest steward artifacts

```bash
ls -1t ~/digests/steward | head -3
```

Pick the latest dated dir. Read `summary.md`, `01-applied.json`, `07-audit.json` (version-currency section if present), and `08-email.html` text extract.

## Step 2: Summarize steward state

From the artifacts, answer:
- What did the steward apply last night? (apt, Docker, cloudflared, FreshRSS), and did its report-only Open WebUI check find a newer stable release?
- What version-currency findings did the audit flag? (k3s, Go, Node, Ruby, neovim, images)
- Are health checks passing?
- Are any audit sections showing DRIFT/ATTENTION?

## Step 3: Live probes (optional, only if user asks for fresh check)

If the user wants a fresh check (not just the steward report), run:

```bash
apt list --upgradable 2>/dev/null | grep -v "^Listing"
kubectl get deploy -A -o wide 2>/dev/null
docker ps --format '{{.Names}} {{.Image}} {{.Status}}'
test -f /var/run/reboot-required && echo "REBOOT REQUIRED" || echo "No reboot required"
```

Report findings — never apply anything.

## Step 4: Report

Present a short summary: what the steward already handled, what is behind, and what needs human action (if anything). If everything is current, say so.

## Notes

- Report-only. Never installs, upgrades, or restarts anything.
- The nightly steward (`homelab-steward.timer`, 1:00 AM ET) auto-applies apt, Docker engine/plugins, cloudflared, and FreshRSS tag bumps. It reports but never applies Open WebUI releases; use `/update-openweb-ui` for the guarded manual update.
- Custom app deploys use `/deploy-app`. Runtimes (Go/Ruby/Node/k3s distro) are manual.
