#!/usr/bin/env bash
# Spawns a headless Claude agent to research and email the daily agentic platform digest.
# Scheduled via systemd timer (agentic-digest.timer).

set -euo pipefail

export HOME="/home/carter"
export PATH="$HOME/.local/bin:$HOME/.rbenv/bin:$HOME/.fnm:$PATH"
export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u)/bus"

PROMPT='You are a daily agentic AI platform news curator. Your job is to research today'"'"'s news and email a digest.

## Step 0: Read prior digest summaries and the HTML template

First, read ~/digests/template.html using the Read tool. You MUST use this template exactly for the email HTML — fill in the placeholders and use the story block HTML from the comment at the bottom. Do not invent your own layout or styling.

Then read all .md files in ~/digests/agentic-platform/ using the Read tool. These are summaries of stories you have already sent in recent days. Use them to:
- Avoid repeating stories that have already been covered unless there is a meaningful update (new details, growing momentum, follow-up coverage, community reaction, adoption milestones).
- Identify evolving stories worth tracking in the "Recent & Relevant" section.

## Step 1: Research

Use WebSearch to find the most important agentic AI platform developments. Run at least 6-8 searches across different angles:
   - Claude agent SDK, Claude Code, Anthropic agent announcements
   - Claude MCP (Model Context Protocol) updates, new MCP servers, MCP ecosystem news
   - Multi-agent orchestration patterns, agent-to-agent coordination
   - AI agent tooling: sandboxed execution, Docker-based agent runtimes, agent skill systems
   - Competitor agentic platforms (OpenAI Codex, Google Jules, etc.) — only major announcements
   - AI-powered software development workflows, AI project management automation
   - Slack/Jira/GitHub/Figma AI integrations relevant to agentic workflows

Prioritize Claude ecosystem news. Include competitor news only when it represents a significant development relevant to production agentic systems.

To guide your sense of relevance, the audience builds and operates an internal agentic platform for a SaaS business. Their stack includes Claude Code agents orchestrated via a Hono API, Slack/Jira webhooks as triggers, MCPs for Slack/Jira/GitHub/Figma, and a multi-agent architecture (manager agent spawning specialized sub-agents for frontend, backend, fullstack review, and QA work on TanStack Start apps). Use this context solely to calibrate which news stories matter most — do not comment on, critique, or suggest changes to this architecture.

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
- Replace {{DIGEST_TITLE}} with "Agentic Platform Digest"
- Replace {{DATE}} with today'"'"'s date
- Replace {{INTRO}} with a 2-3 sentence editorial intro
- Replace {{FRESH_STORIES}} with story blocks using the story block template from the HTML comment
- Replace {{RECENT_STORIES}} with story blocks using the "Recent & Relevant" variant (with the WHY line)
- Each story needs a TITLE, URL, CATEGORY (e.g. Claude Ecosystem, MCP & Tooling, Multi-Agent Patterns, Industry News), and SUMMARY

## Step 3: Write and send

1. Write the HTML body to /tmp/agentic_platform_digest.html
2. Send it: python3 ~/scripts/send_digest.py --subject "Agentic Platform Digest — $(date +%Y-%m-%d)" --body-file /tmp/agentic_platform_digest.html --to carter2099@pm.me soundarajan3@gmail.com
3. Clean up: rm /tmp/agentic_platform_digest.html

## Step 4: Write summary for future runs

Write a concise summary of what you sent to ~/digests/agentic-platform/'"$(date +%Y-%m-%d)"'.md in this format:

```
# Agentic Platform Digest — YYYY-MM-DD

## Fresh
- **Story title** — one-line summary
- **Story title** — one-line summary

## Recent & Relevant
- **Story title** — one-line summary (why still relevant)
```

Then delete any .md files in ~/digests/agentic-platform/ older than 7 days.'

exec claude -p \
  --model claude-sonnet-4-6 \
  --dangerously-skip-permissions \
  --allowedTools "WebSearch Bash Read Write Edit Glob Grep" \
  --no-session-persistence \
  "$PROMPT"
