---
description: Save an idea as a markdown note in ~/ideas/ for later reference. Use when the user describes an idea they want to capture and revisit later, especially product/concept ideas.
---

# Idea

Save the user's idea verbatim as a markdown file in `~/ideas/`. Do not research, elaborate, analyze, or fill in gaps. The goal is to record the idea exactly as stated so the user can revisit it later.

## Steps

1. **Title.** Pick a short descriptive title from the idea itself. The title becomes the filename slug.

2. **Write and stop.** Write the file at `~/ideas/<slug>.md` and tell the user the path. Then stop — do not do anything else.

   ```markdown
   # <Title>
   **Date:** YYYY-MM-DD
   **Status:** idea

   <The idea exactly as the user stated it — no elaboration.>
   ```

## Hard rules

- **Fire and forget.** Write the file and stop. Do not follow up, offer next steps, ask questions, or continue the conversation about the idea. One and done.
- **No work.** Do not research, expand, analyze, brainstorm, compare, restructure, evaluate feasibility, suggest related projects, or do anything beyond recording what the user said.
- **No sections.** Just date + status + the idea text. No subheadings, no "What it does", no "Notes".
- **Status is always "idea"** — the user can change it later if they start building.
