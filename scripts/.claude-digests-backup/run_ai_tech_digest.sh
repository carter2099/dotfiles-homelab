#!/usr/bin/env bash
# Spawns a headless Claude agent to research and email the daily AI & tech digest.
# Scheduled via systemd timer (ai-tech-digest.timer).

set -euo pipefail

export HOME="/home/carter"
export PATH="$HOME/.local/bin:$HOME/.rbenv/bin:$HOME/.fnm:$PATH"
export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u)/bus"

PROMPT='You are a daily AI & tech news curator. Your job is to research and email a digest.

## Step 0: Read prior digest summaries and the HTML template

First, read ~/digests/template.html using the Read tool. You MUST use this template exactly for the email HTML — fill in the placeholders and use the story block HTML from the comment at the bottom. Do not invent your own layout or styling.

Then read all .md files in ~/digests/ai-tech/ using the Read tool. These are summaries of stories you have already sent in recent days. Use them to:
- Avoid repeating stories that have already been covered unless there is a meaningful update (new details, growing momentum, follow-up coverage, community reaction, adoption milestones).
- Identify evolving stories worth tracking in the "Recent & Relevant" section.

## Step 1: Research

Use WebSearch to find the most important AI & tech developments. Run at least 5-6 searches across different angles: model releases, agentic platform features, open source projects, major announcements, new developer tools, and notable funding/launches. Prioritize model releases, new agentic platform features, and open source projects.

## Accuracy Rules (apply to every story)

- Only include a story if you found it on a reputable outlet with a clear publication date. If the date is ambiguous or you cannot find a corroborating source, skip it.
- Fresh stories must be from the last 24 hours. Recent & Relevant stories must be from the last 2-7 days. Verify dates before including.
- Never fabricate or extrapolate details. If a search result is vague, move on — do not fill gaps with plausible-sounding information.
- Every story URL must come directly from your search results. Never construct or guess a URL.

## Step 2: Compile the digest

Organize the email into two sections:

**Fresh (last 24 hours):** New stories from today. 6-10 stories.

**Recent & Relevant (past week):** Stories from the past 2-7 days that are still evolving, gaining momentum, or have meaningful new developments since last covered. For each, note what changed or why it'"'"'s still relevant. Only include if there'"'"'s something new to say — do not simply repeat old summaries. 2-5 stories.

Build the HTML by filling in the template you read in Step 0:
- Replace {{DIGEST_TITLE}} with "AI & Tech Digest"
- Replace {{DATE}} with today'"'"'s date
- Replace {{INTRO}} with a 2-3 sentence editorial intro
- Replace {{FRESH_STORIES}} with story blocks using the story block template from the HTML comment
- Replace {{RECENT_STORIES}} with story blocks using the "Recent & Relevant" variant (with the WHY line)
- Each story needs a TITLE, URL, CATEGORY (e.g. Model Releases, Agentic/Agent Platforms, Open Source, Tools & Developer, Industry News), and SUMMARY

## Step 3: Write and send

1. Write the HTML body to /tmp/daily_digest.html
2. Send it: python3 ~/scripts/send_digest.py --subject "AI & Tech Digest — $(date +%Y-%m-%d)" --body-file /tmp/daily_digest.html --to carter2099@pm.me
3. Clean up: rm /tmp/daily_digest.html

## Step 4: Write summary for future runs

Write a concise summary of what you sent to ~/digests/ai-tech/'"$(date +%Y-%m-%d)"'.md in this format:

```
# AI & Tech Digest — YYYY-MM-DD

## Fresh
- **Story title** — one-line summary
- **Story title** — one-line summary

## Recent & Relevant
- **Story title** — one-line summary (why still relevant)
```

Then delete any .md files in ~/digests/ai-tech/ older than 7 days.'

exec claude -p \
  --model claude-sonnet-4-6 \
  --dangerously-skip-permissions \
  --allowedTools "WebSearch Bash Read Write Edit Glob Grep" \
  --no-session-persistence \
  "$PROMPT"
