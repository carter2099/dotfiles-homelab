#!/usr/bin/env bash
# Curate all five categories sequentially, publish the static news site, then
# send one all-category summary email.
# Scheduled by systemd timer (digests-daily.timer) beginning at 2am ET.
#
# Topic curation stays sequential; independent work inside a topic is bounded.

set -euo pipefail

# omp binary (bun) is at ~/.bun/bin/ — not in systemd default PATH
export PATH="$HOME/.local/bin:$HOME/.bun/bin:$PATH"
export HOME="/home/carter"
LOGFILE="$HOME/digests/.digests.log"

# ── Signal trap: log cleanly on termination with current topic ──
_CURRENT_TOPIC_FILE="$HOME/digests/.current-topic"
_cleanup() { # shellcheck disable=SC2329
    local rc=$?
    local topic="(unknown)"
    if [ -f "$_CURRENT_TOPIC_FILE" ]; then
        topic=$(<"$_CURRENT_TOPIC_FILE") || topic="(unknown)"
        rm -f "$_CURRENT_TOPIC_FILE"
    fi
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) SCRIPT TERMINATED (exit=$rc) topic=$topic — incomplete run" | tee -a "$LOGFILE" 2>/dev/null || true
    exit $rc
}
trap _cleanup TERM INT HUP

# Fail before expensive research when an automated code change removes a
# load-bearing runtime symbol or topic contract.
if ! python3 "$HOME/scripts/digest_runner.py" --preflight; then
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) PREFLIGHT FAIL — curation not started" | tee -a "$LOGFILE" || true
    exit 1
fi

# ── Incomplete-run detection ──
# A run is incomplete only if it never wrote ALL DONE. Post-completion lines
# (WARN-ALERT and friends) may legitimately follow ALL DONE, so checking only
# the final log line produced false "Previous run incomplete" warnings
# (digest-quality audit 2026-08-25): compare the last START marker with the
# last ALL DONE instead.
if [ -f "$LOGFILE" ]; then
    LAST_START_LN=$(grep -n " START " "$LOGFILE" 2>/dev/null | tail -1 | cut -d: -f1 || true)
    LAST_DONE_LN=$(grep -n "ALL DONE" "$LOGFILE" 2>/dev/null | tail -1 | cut -d: -f1 || true)
    if [ -n "$LAST_START_LN" ] && { [ -z "$LAST_DONE_LN" ] || [ "$LAST_DONE_LN" -lt "$LAST_START_LN" ]; }; then
        # Extract topic from the most recent SCRIPT TERMINATED line (which must
        # come after the last ALL DONE to belong to the incomplete run)
        topic_hint=""
        if LAST_TERM_LN=$(grep -n "SCRIPT TERMINATED" "$LOGFILE" 2>/dev/null | tail -1 | cut -d: -f1) && \
           [ -n "$LAST_TERM_LN" ] && { [ -z "$LAST_DONE_LN" ] || [ "$LAST_TERM_LN" -gt "$LAST_DONE_LN" ]; }; then
            topic_hint=$(sed -n "${LAST_TERM_LN}p" "$LOGFILE" 2>/dev/null | sed 's/.*topic=\([^ ]*\).*/\1/' || true)
        fi
        if [ -n "$topic_hint" ]; then
            echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) WARNING Previous run interrupted during topic=$topic_hint" | tee -a "$LOGFILE"
        else
            echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) WARNING Previous run incomplete" | tee -a "$LOGFILE"
        fi
    fi
fi

TOPICS=("ai-tech" "agentic-platform" "ai-hardware" "gaming" "world")

for topic in "${TOPICS[@]}"; do
    echo "$topic" > "$_CURRENT_TOPIC_FILE"
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) START $topic" | tee -a "$LOGFILE"
    START_TS=$(date +%s)

    if timeout 14400 python3 "$HOME/scripts/digest_runner.py" "$topic"; then
        END_TS=$(date +%s)
        DURATION=$((END_TS - START_TS))
        echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) DONE  $topic duration=${DURATION}s" | tee -a "$LOGFILE" || true
        # Report editorial-stage degradation in the lifecycle log (digest-quality
        # audit 2026-08-11): a successful run can still have fallen back to a
        # weaker model for proposal/review, which used to be invisible here.
        TODAY=$(date -u +%Y-%m-%d)
        case "$topic" in
            gaming) CATEGORY_DIR="gaming-digest" ;;
            world) CATEGORY_DIR="world-digest" ;;
            *) CATEGORY_DIR="$topic" ;;
        esac
        CURATED="$HOME/digests/$CATEGORY_DIR/$TODAY/06-curated.json"
        if [ -f "$CURATED" ]; then
            DEGRADED=$(python3 -c "import json,sys;d=json.load(open(sys.argv[1]));print('degraded' if d.get('editorial',{}).get('degraded') else 'ok')" "$CURATED" 2>/dev/null || echo ok)
            if [ "$DEGRADED" = "degraded" ]; then
                MODELS=$(python3 -c "import json,sys;d=json.load(open(sys.argv[1]));e=d.get('editorial',{});print('proposal_model=%s review_model=%s review_status=%s' % (e.get('proposal_model',''),e.get('review_model',''),e.get('review_status','')))" "$CURATED" 2>/dev/null || echo "models unknown")
                echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) WARN  $topic editorial degraded $MODELS" | tee -a "$LOGFILE" || true
            fi
        fi
    else
        RC=$?
        END_TS=$(date +%s)
        DURATION=$((END_TS - START_TS))
        echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) FAIL  $topic (exit=$RC) duration=${DURATION}s — continuing" | tee -a "$LOGFILE" || true
    fi
    rm -f "$_CURRENT_TOPIC_FILE"
done

# ── Publish site, then send the single daily email ──
TODAY="$(date -u +%Y-%m-%d)"
echo "publish" > "$_CURRENT_TOPIC_FILE"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) START publish" | tee -a "$LOGFILE"
PUBLISH_START_TS=$(date +%s)
PUBLISH_OUT="$(mktemp)"
if timeout 900 python3 "$HOME/scripts/news_publish.py" --date "$TODAY" | tee "$PUBLISH_OUT"; then
    PUBLISH_END_TS=$(date +%s)
    PUBLISH_DURATION=$((PUBLISH_END_TS - PUBLISH_START_TS))
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) DONE  publish duration=${PUBLISH_DURATION}s" | tee -a "$LOGFILE" || true
    # A section whose run state failed validation was kept from its last durable
    # publication or omitted; surface it where the digest-quality audit looks.
    DEGRADED_SECTIONS=$(python3 -c '
import json, sys
text = open(sys.argv[1]).read()
start = text.rfind("\n{\n")
result = json.loads(text[start + 1:] if start >= 0 else text)
print(" ".join(
    "%s=%s" % (item.get("slug", "?"), str(item.get("action", "?")).replace(" ", "-"))
    for item in result.get("degraded_sections") or []
))' "$PUBLISH_OUT" 2>/dev/null || true)
    if [ -n "$DEGRADED_SECTIONS" ]; then
        echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) WARN  publish degraded sections: $DEGRADED_SECTIONS" | tee -a "$LOGFILE" || true
    fi
    rm -f "$PUBLISH_OUT"
else
    RC=$?
    rm -f "$PUBLISH_OUT"
    PUBLISH_END_TS=$(date +%s)
    PUBLISH_DURATION=$((PUBLISH_END_TS - PUBLISH_START_TS))
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) FAIL  publish (exit=$RC) duration=${PUBLISH_DURATION}s" | tee -a "$LOGFILE" || true
    rm -f "$_CURRENT_TOPIC_FILE"
    exit "$RC"
fi
rm -f "$_CURRENT_TOPIC_FILE"

# Consecutive editorial degradation stays in the lifecycle log. The steward's
# digest-quality audit owns operational follow-up; this run sends no second email.
YESTERDAY="$(date -u -d yesterday +%Y-%m-%d)"
WARN_DAYS="$(grep 'editorial degraded' "$LOGFILE" 2>/dev/null | cut -c1-10 | sort -u || true)"
if printf '%s\n' "$WARN_DAYS" | grep -qx "$YESTERDAY" && \
   printf '%s\n' "$WARN_DAYS" | grep -qx "$TODAY"; then
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) WARN-ALERT editorial degraded on consecutive days (${YESTERDAY}, ${TODAY}); steward review required" | tee -a "$LOGFILE" || true
fi

echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) ALL DONE" | tee -a "$LOGFILE" || true
