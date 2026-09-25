---
description: Diagnose and fix recurring Homelab Steward email failures, noise, or bad checks. Use when user says "fix the steward", "address steward", "steward keeps failing X", or pastes steward email complaints.
---

# Address Steward

Diagnose and fix recurring Homelab Steward issues at the source. Do not paper over symptoms in the email renderer unless the problem is purely presentational.

## Step 1: Load latest run artifacts

```bash
ls -1t ~/digests/steward | head -3
```

Pick the latest dated dir. Read:
- `summary.md` — quick overview
- All `phase_failed` JSON artifacts (files containing `"phase_failed": true`)
- `01-applied.json` — update steps
- `04-heartbeat.json` — system health data
- `07-audit.json` — audit section results
- `07b-fixes.json` — auto-fix outcomes
- `08-email.html` — the rendered email

If the issue is recurring, compare with prior 1-2 day artifacts.

## Step 2: Classify each complaint

- **Real host failure** (service down, disk full, endpoint unreachable) → fix the host issue
- **Steward bug** (PATH missing, KUBECONFIG unset, collector crash, bad email render, noisy audit finding) → fix the Python code in `~/scripts/steward_runner.py`
- **Unit env issue** (missing env vars in `~/.config/systemd/user/homelab-steward.service`) → fix the unit file, then `systemctl --user daemon-reload`
- **Intentional holdback** (version pinned, tool not installed) → confirm and brief the user

## Step 3: Fix at the source

For code fixes in `~/scripts/steward_runner.py`:
- Fix PATH/`user_env()`/`run_capture()` env setup
- Fix collector logic (parsing, error handling)
- Fix email rendering helpers
- Prefer small deterministic fixes (try/except, env var, regex) over spawning more LLM fix agents

For unit/env fixes in `~/.config/systemd/user/homelab-steward.service`:
- Add missing `Environment=` lines
- Run `systemctl --user daemon-reload`

For k3s/manifest issues in `~/k3s/`:
- Fix deployment YAML, then `kubectl apply`

## Step 4: Smoke test the fix

- Re-run the affected helper in isolation (e.g., import and call the collector function)
- For env issues: prove the command works under `user_env()`:
  ```python
  python3 -c "import sys; sys.path.insert(0,'/home/carter/scripts'); from steward_runner import user_env; env = user_env(); print('KUBECONFIG:', env.get('KUBECONFIG'))"
  ```
- For email issues: render HTML from last run's JSON into `/tmp/steward-email-preview.html` and inspect
- Do NOT run a full multi-hour steward unless the user asks

## Step 5: Commit changes

```bash
dotfiles add scripts/steward_runner.py
dotfiles commit -m "steward: <description of fix>"
dotfiles push
```

For unit file changes:
```bash
dotfiles add .config/systemd/user/homelab-steward.service
dotfiles commit -m "steward: fix <env/service>"
dotfiles push
```

For slash command changes (this file):
```bash
dotfiles add .omp/agent/prompts/address-steward.md
dotfiles commit -m "command: address-steward"
dotfiles push
```

## Step 6: Brief the user

Report: root cause, what changed, what to expect in tomorrow's email.

## Rules

- Do not reintroduce the executor.
- Do not rewrite deployed apps' code in prod dirs — use `~/dev/` clones + release.sh.
