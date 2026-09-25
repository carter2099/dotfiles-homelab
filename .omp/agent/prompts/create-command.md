---
description: Create a new omp slash command, commit it to dotfiles, and push. Always use this instead of writing prompt files directly.
---

# Create Command

Create a new slash command under `~/.omp/agent/prompts/` and immediately commit it to the dotfiles bare repo so it's backed up to GitHub.

## Step 1: Agree on the command

Before writing anything, confirm with the user:
- **Name**: the slash-command name (e.g. `my-command` → `/my-command`)
- **Description**: one line, used to decide when to invoke the slash command
- **What it does**: enough to write a complete prompt markdown file

## Step 2: Write the prompt file

```
~/.omp/agent/prompts/<name>.md
```

Frontmatter fields:
```
---
description: <one-line description — specific enough to trigger correctly>
---
```

Body: step-by-step instructions the agent will follow when the slash command is invoked. Write it as instructions to yourself, not documentation for a human.

## Step 3: Commit to dotfiles immediately

```bash
dotfiles add -A .omp/agent/prompts/<name>.md
dotfiles commit -m "command: add <name>"
dotfiles push
```

Do not skip this step. Slash commands not in dotfiles are lost if the homelab storage is wiped.

## Step 4: Confirm

Tell the user the slash command is live and tracked. Remind them to invoke it as `/<name>`.
