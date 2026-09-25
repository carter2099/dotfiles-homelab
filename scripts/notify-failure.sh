#!/usr/bin/env bash
# Emailed failure notification for any user unit.
# Wired as OnFailure=notify-failure@%n.service; the template passes the failed
# unit name. Mails the unit's last 60 journal lines through
# ~/scripts/send_digest.py + ~/scripts/.smtp_config (Docker-independent SMTP).
#
# Rate limit: at most one email per unit per hour. Failures inside the window
# are counted and reported in the next email, so a crash-looping service
# (Restart=on-failure passes through "failed" on every crash) cannot storm.
# A unit systemd does not know (e.g. notify-failure@review-test.service) is
# treated as a manual test and the subject is marked TEST.
set -euo pipefail

unit="${1:?usage: notify-failure.sh <unit-name>}"
XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
export XDG_RUNTIME_DIR
RECIPIENT="carter2099@pm.me"
WINDOW_SECONDS=3600
JOURNAL_LINES=60

state_dir="${XDG_STATE_HOME:-$HOME/.local/state}/notify-failure"
mkdir -p "$state_dir"
chmod 0700 "$state_dir"
state_file="$state_dir/$unit"

exec 9>"$state_file.lock"
flock 9

now="$(date +%s)"
last_sent=0
suppressed=0
if [[ -f "$state_file" ]]; then
  read -r last_sent suppressed < "$state_file" || true
fi
if (( now - last_sent < WINDOW_SECONDS )); then
  suppressed=$((suppressed + 1))
  printf '%s %s\n' "$last_sent" "$suppressed" > "$state_file"
  echo "[notify-failure] ${unit}: suppressed (${suppressed} since last email at $(date -u -d "@${last_sent}" +%FT%TZ))"
  exit 0
fi

html_escape() {
  sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
}

ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
host="$(hostname -s)"
load_state="$(systemctl --user show -p LoadState --value -- "$unit" 2>/dev/null || echo unknown)"
if [[ "$load_state" == "not-found" ]]; then
  subject="TEST ${unit} notification test on ${host} ${ts}"
  headline="TEST: ${unit} (not a real unit)"
else
  result="$(systemctl --user show -p Result --value -- "$unit" 2>/dev/null || echo unknown)"
  subject="${unit} FAILED on ${host} ${ts}"
  headline="${unit} FAILED (result: ${result})"
fi
if (( suppressed > 0 )); then
  suppressed_note="${suppressed} further failure(s) of this unit were not emailed since the previous notification (one email per unit per hour)."
else
  suppressed_note=""
fi
logs="$(journalctl --user -u "$unit" --no-pager -n "$JOURNAL_LINES" 2>&1 || echo "(journal unavailable)")"

body_file="$(mktemp --tmpdir notify-failure.XXXXXX.html)"
trap 'rm -f "$body_file"' EXIT
{
  cat <<HTMLEOF
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0; padding:24px; background-color:#f4f4f7; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
<div style="max-width:720px; margin:0 auto; background-color:#ffffff; border-radius:8px; overflow:hidden;">
<div style="background-color:#c62828; padding:24px 32px;">
<h1 style="margin:0; color:#ffffff; font-size:20px; font-weight:600;">$(html_escape <<<"$headline")</h1>
<p style="margin:6px 0 0; color:#ffcdd2; font-size:14px;">$(html_escape <<<"${host} · ${ts}")</p>
</div>
<div style="padding:20px 32px 8px; color:#444; font-size:15px; line-height:1.6;">
<p style="margin:0;">$(html_escape <<<"$suppressed_note")</p>
<p style="margin:8px 0 0;">Investigate on the host:</p>
<pre style="margin:8px 0 0; padding:12px; background:#f5f5f5; border-radius:4px; font-size:13px; color:#333;">$(html_escape <<<"systemctl --user status ${unit}
journalctl --user -u ${unit} --no-pager")</pre>
<h2 style="margin:20px 0 0; color:#1a1a2e; font-size:15px;">Last ${JOURNAL_LINES} journal lines</h2>
</div>
<div style="padding:8px 32px 24px;">
<pre style="margin:0; padding:12px; background:#fafafa; border:1px solid #e8e8ee; border-radius:4px; font-size:12px; color:#333; white-space:pre-wrap; word-break:break-all;">
HTMLEOF
  printf '%s\n' "$logs" | html_escape
  cat <<'HTMLEOF'
</pre>
</div>
</div>
</body>
</html>
HTMLEOF
} > "$body_file"

python3 "$HOME/scripts/send_digest.py" \
  --subject "$subject" \
  --body-file "$body_file" \
  --to "$RECIPIENT"
printf '%s 0\n' "$now" > "$state_file"
echo "[notify-failure] ${unit}: sent to ${RECIPIENT}"
