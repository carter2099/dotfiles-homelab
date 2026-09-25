---
description: Save a note to the ~/notes vault — writes a markdown file with frontmatter, updates INDEX.md, commits and pushes. Use when the user says "save a note", "add to notes", "capture this", "remember this in notes", or similar.
---

# note-save

Capture something worth remembering into the `~/notes/` vault. The vault is a standalone git repo with its own `origin` — not the dotfiles bare repo.

## Required input

- **topic or content** (string): what to save. May be a URL, a paragraph, a chat excerpt, or a rough idea.

## Before writing — always do these

1. **Read `~/notes/INDEX.md`** to see what already exists. Scan for notes on the same topic; if one exists, **update it** instead of creating a duplicate.
2. **Check the topic directory** (`ls ~/notes/<topic>/`) to confirm the existing-note check didn't miss anything.
3. **Verify facts before committing them.** If the user handed you a URL, fetch it; if they're paraphrasing a digest, grep `~/digests/` for the original. Don't write notes from pure recall — the vault is reference material, it has to be right.

## Frontmatter (mandatory)

```markdown
---
title: Short human-readable title
tags: [tag1, tag2, tag3]
source: URL, digest name + date, conversation, book, etc.
created: YYYY-MM-DD
updated: YYYY-MM-DD
---
```

- `created` / `updated` must be **today's absolute date** (check the `currentDate` in context — never use relative dates like "today").
- Tags: lowercase, kebab-case. Reuse existing tags where possible (grep `~/notes/` for prior usage).
- `source`: be specific. `agentic-platform digest (YYYY-MM-DD)` beats `digest`. A URL is ideal.

## File path and naming

- Topic directory at the root of `~/notes/` (e.g. `ai/`, `crypto/`, `homelab/`). Create a new one only if no existing directory fits.
- Nested topic directories are fine when they already exist (e.g. `ai/agents/`).
- Filename: `kebab-case-slug.md`. Match the title conceptually, not verbatim.
- **One idea per note** (atomic). If the user dumps two unrelated things, make two notes.

## Body style

- Lead with the core fact or idea in the first paragraph — someone scanning the vault should get the point without reading to the end.
- Short sections with `##` headers. Bullets over prose for reference material.
- Link related notes with relative paths: `[Other note](../other-topic/other-note.md)`.
- If a fact is load-bearing but not fully verified, say so explicitly (`"schema not verified against live docs"`). Don't launder uncertainty into confident prose.
- Include a `## For Carter` or `## Why this matters` section when the relevance isn't obvious from the facts alone — especially for homelab-adjacent topics.

## Preview before writing

Show the user the full proposed note — path, frontmatter, body — and ask for confirmation before writing. Format:

```
**Path:** ~/notes/<topic>/<slug>.md

---
<full file contents>
---

**INDEX.md entry:** - [Title](topic/slug.md) — one-line hook · tags: tag1, tag2
```

Ask: "Write and push this?" Wait for explicit confirmation ("yes", "go ahead", "write it"). If they want changes, revise and re-preview.

For small/obvious updates to an existing note (fixing a typo, adding a link), the preview can be terser — just the diff.

## Write + INDEX + commit

Once confirmed:

### 1. Write the note file

Use the Write tool at `~/notes/<topic>/<slug>.md`.

### 2. Update `~/notes/INDEX.md`

Add a line under the appropriate section:

```
- [Title](topic/slug.md) — one-line hook that previews the content · tags: tag1, tag2
```

- Keep the line under ~200 characters.
- The one-line hook should tell the reader whether to open the note — concrete facts beat vague teases.
- If a section for this topic doesn't exist in INDEX.md yet, add one (`## Topic Name`) in a sensible place.

### 3. Commit and push

```bash
cd ~/notes && git add <path> INDEX.md && git commit -m "<descriptive message>" && git push
```

Commit message: imperative, describes what the note captures. e.g. `Add note on Claude Code hooks → MCP tool invocation`. For updates: `Update <note> with <what changed>`.

## When updating an existing note

- Read the current file first.
- Bump `updated: YYYY-MM-DD` in frontmatter.
- If the update materially changes what the note is about, update the `title`, `description`, and INDEX.md hook too.
- Preserve existing structure unless the change demands a rewrite.

## Out of scope

- **Don't use this for ephemeral task state.** That's what the TodoWrite tool and `~/agent-state/pending.md` are for.
- **Don't use this for the agent's own auto-memory.** Memory lives in provider-specific locations with its own structure.
- **Don't duplicate AGENTS.md content.** If a fact belongs in repo documentation, propose editing AGENTS.md instead.

## Tips

- If unsure where a note belongs, propose the path in the preview — Carter can redirect.
- Cross-linking is cheap. If a new note relates to an existing one, add a `## Links` or `## See also` section with relative paths.
- For notes sourced from a daily digest, include the digest date so future-you can grep `~/digests/` for the original context.
