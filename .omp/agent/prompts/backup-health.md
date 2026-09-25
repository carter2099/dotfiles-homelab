---
description: Check health of the homelab-backup service — last run status, next scheduled run, R2 bucket contents, and local archive state. Quick mobile-friendly summary.
---

# backup-health

Health check for the homelab-backup systemd timer + R2 upload pipeline.

## Steps

1. **Timer status.** Run `systemctl --user list-timers homelab-backup.timer --no-pager` to show next/last fire time.
2. **Last run result.** Run `systemctl --user status homelab-backup.service --no-pager -l` to check exit status of the most recent run.
3. **Recent logs.** Run `journalctl --user -u homelab-backup.service -n 25 --no-pager` for the last run's output. Look for errors, partial failures, or integrity check issues.
4. **R2 bucket contents.** Load the R2 creds and list remote backups with the binary's `list` subcommand (no aws CLI / rclone is installed on this host):
   ```bash
   set -a && source ~/homelab-backup/.env && set +a
   ~/homelab-backup/homelab-backup list
   ```
   Reports key + parsed date + size, newest-first. Count the objects and note the newest timestamp.
5. **Restore drill status.** Run `systemctl --user list-timers homelab-backup-restore-drill.timer --no-pager` (monthly, 1st 12:00 UTC) and `systemctl --user status homelab-backup-restore-drill.service --no-pager` for the last drill result. Report last drill date + PASS/FAIL.
6. **Local archives.** Run `ls -lht ~/backups/ | head -10` to show recent local backups and sizes.
7. **Disk usage.** Run `du -sh ~/backups/` to report total local backup footprint.

## Report format

Summarize as a short mobile-friendly checklist:

- **Last run:** when, success/failure
- **Next run:** when
- **R2 backups:** count and newest date
- **Restore drill:** last run date + PASS/FAIL
- **Local backups:** count and total size
- **Issues:** any errors, partial target failures, or integrity-check failures (or "none")

Note: if the main run fails, `notify-failure@homelab-backup.service.service` (OnFailure=, at most one email per unit per hour) emails Carter automatically — a health check showing failure means that email was already sent (unless SMTP itself is down).

Keep it concise — this is meant to be glanced at on a phone.
