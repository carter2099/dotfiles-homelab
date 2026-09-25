---
description: "Homelab dev workflow convention: work in ~/dev/, test there, get approval, then release using the project's own idioms. Tech-stack agnostic."
---

# Dev → Test → Release Convention

This slash command establishes the standard workflow for implementing and shipping changes to any homelab project. It is tech-stack agnostic — Rails, Go, React, whatever.

## Core principle

**`~/dev/<repo>`** is the workspace. **`~/<app>/`** (for example, `~/blog/`) is the deployment directory. Never do implementation work in the deployment directory.

---

## Step 1: Set up the workspace

```bash
# Clone if not already present
ls ~/dev/<repo> || git clone git@github.com:carter2099/<repo>.git ~/dev/<repo>
cd ~/dev/<repo>
git checkout main && git pull origin main
```

Install dependencies using the project's conventions (check `AGENTS.md` for the canonical command):
- Rails: `RBENV_VERSION=$(cat .ruby-version 2>/dev/null || echo 3.4.3) bundle install`
- Go: `go mod download`
- Node/React: `npm install` or `pnpm install`

---

## Step 2: Do the work

Implement the change in `~/dev/<repo>`. Read `AGENTS.md` for code quality rules, architecture patterns, and anything project-specific before touching code.

Run tests as you go using the project's test command (canonical source: `AGENTS.md`):
- Rails: `RBENV_VERSION=... bin/rake`
- Go: `go test ./...`
- Node: `npm test`

---

## Step 3: Verify and show the user

Before asking for approval:
1. Run the full test suite — all must pass.
2. Run lint if the project has it (usually included in `bin/rake` for Rails).
3. Show a `git diff --stat` summary of what changed.

**Pause here.** Present the changes and test results. Let the user review, request tweaks, or approve.

Do NOT push or release until the user explicitly approves.

---

## Step 4: Release (after approval)

Once the user approves, release using **the project's own idioms** — do not invent a generic release process. Check in this order:

1. **Project slash command**: Does the repo have a slash command for this? (e.g. delta_neutral has a `/release` command). If yes, invoke it.
2. **`AGENTS.md`**: Look for a "Versioning" or "Release" section with specific instructions.
3. **`release.sh`**: Some repos have a release script — but confirm it's for the *dev* release (version bump + tag), not the deployment script.

For dependency-only changes (bumps), use `/dependabot-release` instead of this command.

---

## Step 5: Deploy (separate step, if applicable)

Deployment is always a separate explicit step — never automatic after a release. If the user wants to deploy after releasing, use the `/deploy-app` command.

---

## Notes

- The `~/dev/<repo>` clone is the source of truth for development. The deployment directory (`~/<app>/`) is managed by `release.sh` pulling from origin — never edit files there directly.
- If `.ruby-version` requests an uninstalled Ruby version, use `RBENV_VERSION=3.4.3` as an override for minor patch differences.
- Non-Rails projects: substitute the appropriate test/lint commands. The workflow (workspace → test → approve → release) is the same regardless of stack.
