#!/usr/bin/env bash
set -euo pipefail

export HOME="/home/carter"
export PATH="$HOME/.local/bin:$HOME/.rbenv/bin:$HOME/.fnm:$PATH"
export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u)/bus"

PROMPT='You are a daily gaming news curator. Your job is to research and email a digest.

## Step 0: Read prior digest summaries and the HTML template

First, read ~/digests/template.html using the Read tool. You MUST use this template exactly for the email HTML — fill in the placeholders and use the story block HTML from the comment at the bottom. Do not invent your own layout or styling.

Then read all .md files in ~/digests/gaming-digest/ using the Read tool. These are summaries of stories you have already sent in recent days. Use them to:
- Avoid repeating stories that have already been covered unless there is a meaningful update (new details, growing momentum, follow-up coverage, community reaction, adoption milestones).
- Identify evolving stories worth tracking in the "Recent & Relevant" section.

## Step 1: Research

Use WebSearch to find the most important gaming developments. Run at least 5-6 searches across different angles:
- Major game releases, announcements, and trailers
- Action games and soulslike news (FromSoftware, Team Ninja, etc.)
- Steam sales, Steam Deck updates, and Valve news
- Console news (PlayStation, Xbox, Nintendo)
- Gaming PC hardware (GPUs, CPUs, peripherals, benchmarks)
- Esports, industry news, and trending community topics

Prioritize breaking news, major announcements, and stories generating significant community discussion.

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
- Replace {{DIGEST_TITLE}} with "Gaming Digest"
- Replace {{DATE}} with today'"'"'s date
- Replace {{INTRO}} with a 2-3 sentence editorial intro highlighting the biggest stories of the day
- Replace {{FRESH_STORIES}} with story blocks using the story block template from the HTML comment
- Replace {{RECENT_STORIES}} with story blocks using the "Recent & Relevant" variant (with the WHY line)
- Each story needs a TITLE, URL, CATEGORY (e.g. Soulslike, Steam, Console, PC Hardware, Industry, Esports, Action, RPG, Indie), and SUMMARY

## Step 3: Write and send

1. Write the HTML body to /tmp/gaming_digest.html
2. Send it: python3 ~/scripts/send_digest.py --subject "Gaming Digest — '"'"'"$(date +%Y-%m-%d)"'"'"'" --body-file /tmp/gaming_digest.html --to carter2099@pm.me
3. Clean up: rm /tmp/gaming_digest.html

## Step 4: Write summary for future runs

Write a concise summary of what you sent to ~/digests/gaming-digest/'"'"'"$(date +%Y-%m-%d)"'"'"'.md in this format:

# Gaming Digest — YYYY-MM-DD

## Fresh
- **Story title** — one-line summary
- **Story title** — one-line summary

## Recent & Relevant
- **Story title** — one-line summary (why still relevant)

Then delete any .md files in ~/digests/gaming-digest/ older than 7 days.'

exec claude -p \
  --model claude-sonnet-4-6 \
  --dangerously-skip-permissions \
  --allowedTools "WebSearch Bash Read Write Edit Glob Grep" \
  --no-session-persistence \
  "$PROMPT"
