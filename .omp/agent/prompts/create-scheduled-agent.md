---
description: Create a new scheduled agent that runs on a systemd timer — recurring maintenance, checks, reports, or any task you want automated. Use when user says "set up a scheduled agent", "automate this to run daily", "I want a cron job for X".
---

# Create Scheduled Agent

Create a scheduled agent that runs `omp -p` on a systemd user timer. One slash command handles every recurring task — maintenance, monitoring, checks, reports, whatever. The plumbing is always the same; only the prompt and schedule differ.

## Required input

Gather these from the user. Ask for anything missing:

- **name** (string): short kebab-case identifier (e.g. `update-check`, `backup-audit`, `ssl-expiry`)
- **schedule** (string): when it runs. Convert user's local time to UTC for `OnCalendar`. Currently EDT = UTC-4.
  - Daily at 6am ET → `*-*-* 10:00:00`
  - Weekdays at 9am ET → `Mon..Fri *-*-* 13:00:00`
  - Weekly Monday 8am ET → `Mon *-*-* 12:00:00`
  - Every 6 hours → `*-*-* 00,06,12,18:00:00`
- **model** (string, default: `opencode-go/deepseek-v4-flash`): the `--model` flag for `omp -p`. Change this to switch providers/models.
- **what it does** (string): natural language description of the agent's task. This becomes the prompt.
- **output** (choice, default: none): 
  - `none` — agent runs silently, logs to `.runs.log`
  - `email` — agent sends an HTML email via `~/scripts/send_digest.py`. Need: subject line, recipient(s), and the prompt must tell the agent to build HTML and call send_digest.py
  - `file` — agent writes results to a file (specify path)
- **timeout** (number, default: 600): seconds before systemd kills the agent

## Files created

All scheduled agents follow the same three-file pattern:

```
~/scripts/run_<name>.sh              # bash wrapper with embedded omp -p prompt
~/.config/systemd/user/<name>.service # oneshot service unit
~/.config/systemd/user/<name>.timer   # calendar timer
```

Plus an optional log directory if the agent writes output:
```
~/digests/<name>/                     # for email-output agents (matches digest pattern)
```

## Steps

### 1. Validate infrastructure

Confirm these exist:
- `omp` on PATH
- `--api-key proxy` (auth handled by opencode-go-proxy on localhost:8082)
- If output is `email`: `~/scripts/send_digest.py` and `~/scripts/.smtp_config`

### 2. Create the run script

Write `~/scripts/run_<name>.sh` (replace hyphens with underscores in filename):

```bash
#!/usr/bin/env bash
# <one-line description>
# Scheduled via systemd timer (<name>.timer).
set -euo pipefail
export HOME="/home/carter"

START_TS="$(date +%s)"

PROMPT='<the prompt — what the agent should do>'

omp -p --model <model> --api-key proxy --allow-home --session-dir ~/.omp/agent/sessions-automated "$PROMPT"
END_TS="$(date +%s)"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) <name> duration=$((END_TS - START_TS))s model=<model-short-name>" >> "$HOME/digests/<name>/.runs.log"
```

If output is not email, the `.runs.log` can go in `~/digests/<name>/` or be omitted for simple agents.

**Quoting rules for the PROMPT string:**
- Wrap in single quotes: `PROMPT='...'`
- If the prompt needs today's date, set `TODAY="$(date +%Y-%m-%d)"` at the top and insert with `'"$TODAY"'` (end single-quote, double-quote variable, restart single-quote)
- If the prompt contains literal single quotes (e.g. `today's`), escape as `'"'"'`
- Same pattern for any other bash variables the prompt needs

**For email-output agents**, the prompt must include explicit instructions to:
1. Build an HTML email body
2. Write it to a temp file
3. Call `python3 /home/carter/scripts/send_digest.py --subject "..." --body-file <path> --to <recipients>`
4. See existing digest scripts for the email pattern (agentic-digest.sh is a good reference)

**Third-party recipients:** these run scripts are tracked in the public dotfiles repo. Never hardcode a third party's email. Instead stash it in `~/scripts/.smtp_config` (e.g. `MY_AGENT_CC=person@example.com`), read it in the script, and inject via `'"$MY_AGENT_CC"'`.

### 3. Create the systemd service

Write `~/.config/systemd/user/<name>.service`:

```ini
[Unit]
Description=<one-line description>

[Service]
Type=oneshot
ExecStart=/home/carter/scripts/run_<name>.sh
TimeoutStartSec=<timeout>
```

### 4. Create the systemd timer

Write `~/.config/systemd/user/<name>.timer`:

```ini
[Unit]
Description=<when it fires, in human terms>

[Timer]
OnCalendar=<oncalendar expression>
Persistent=true

[Install]
WantedBy=timers.target
```

`Persistent=true` ensures a missed run (host was off) fires on next boot.

### 5. Make executable, enable, and start

```bash
chmod +x ~/scripts/run_<name>.sh
systemctl --user daemon-reload
systemctl --user enable --now <name>.timer
```

If output dir needed: `mkdir -p ~/digests/<name>/`

### 6. Track in dotfiles and push

```bash
dotfiles add scripts/run_<name>.sh .config/systemd/user/<name>.service .config/systemd/user/<name>.timer
dotfiles commit -m "scheduled agent: add <name>"
dotfiles push
```

### 7. Report to user

Show:
- Timer status: `systemctl --user status <name>.timer`
- Next fire time: `systemctl --user list-timers <name>.timer`
- Offer a test run: `bash ~/scripts/run_<name>.sh`

## Modifying an existing agent

- **Change the prompt:** edit `~/scripts/run_<name>.sh`, no restart needed
- **Change the schedule:** edit `~/.config/systemd/user/<name>.timer`, then `systemctl --user daemon-reload && systemctl --user restart <name>.timer`
- **Change the model:** edit the `--model` flag in the script
- Always commit changes: `dotfiles add <files> && dotfiles commit -m "..." && dotfiles push`

## Listing all scheduled agents

```bash
systemctl --user list-timers --no-pager
```

## Deleting an agent

```bash
systemctl --user disable --now <name>.timer
rm ~/.config/systemd/user/<name>.{service,timer}
rm ~/scripts/run_<name>.sh
# If it had an output dir:
rm -rf ~/digests/<name>/
systemctl --user daemon-reload
dotfiles add -u  # stage the deletions
dotfiles commit -m "scheduled agent: remove <name>" && dotfiles push
```

## Notes

- All scheduled agents run as the `carter` user via systemd user timers (`loginctl enable-linger` is already enabled — timers survive logout/reboot).
- `TimeoutStartSec` prevents a stuck agent from blocking the timer indefinitely.
- The `.runs.log` pattern gives you a trail of when agents ran and how long they took.
- Agents use the same `omp -p` pattern as the existing digest agents and update-check agent — consistent, debuggable, provider-agnostic.
