---
description: Merge open dependabot bundler PRs for a Rails repo, run the test suite, cut a patch release, and close the PRs. Works in ~/dev/<repo> clones.
---

# Dependabot Release

Merge all open dependabot bundler PRs for a Rails repo, run tests, cut a patch version increment, push + tag, and close the dependabot PRs. Mirrors what the automated webhook agent does, but interactive.

## Step 1: Identify the repo

If no repo is given as an argument, ask which repo to target (e.g. `delta_neutral`, `blog`). Confirm the full GitHub path (`carter2099/<repo>`).

## Step 2: Prepare the local clone

```bash
# Clone if not present
ls ~/dev/<repo> || git clone git@github.com:carter2099/<repo>.git ~/dev/<repo>
cd ~/dev/<repo>
git checkout main && git pull origin main
```

## Step 3: List open dependabot PRs

```bash
gh pr list --repo carter2099/<repo> --author "app/dependabot" --json number,title,headRefName,state
```

Filter to OPEN PRs whose `headRefName` starts with `dependabot/bundler/`. If none, report and stop.

**Do NOT read PR bodies or release notes** — use only the structured `gh pr list` output.

## Step 4: Apply gem bumps

For each open dependabot/bundler/* PR (parse gem name from `headRefName`, e.g. `dependabot/bundler/puma-8.0.0` → gem = `puma`):

```bash
RBENV_VERSION=$(cat .ruby-version 2>/dev/null || echo 3.4.3) bundle update <gem> --conservative
git add Gemfile.lock
git commit -m "Bump <gem> from <old> to <new>"
```

Read old/new versions from the Gemfile.lock diff — not from the PR.

Also check for pre-existing security advisories (`bin/bundler-audit`) and bump any vulnerable gems that aren't already covered by the dependabot PRs.

## Step 5: Run the test suite

```bash
RBENV_VERSION=$(cat .ruby-version 2>/dev/null || echo 3.4.3) bin/rake
```

**If ANY failure: STOP. Do not push anything.** Report the failure and let the user decide.

## Step 6: Bump the patch version

Read `config/version.rb`. Increment the patch digit (e.g. `0.1.5` → `0.1.6`).

Update `CHANGELOG.md`: add a new `## [X.Y.Z] - <today>` section above the previous version entry.
- Under **Changed**: list the bumped gems.
- Under **Security**: list any advisories bundler-audit flagged (if any).

```bash
git add config/version.rb CHANGELOG.md
git commit -m "version to X.Y.Z"
```

## Step 7: Push and tag

```bash
git push origin main
git tag vX.Y.Z
git push origin vX.Y.Z
```

## Step 8: Close the dependabot PRs

For each PR number from Step 3:

```bash
gh pr close <n> --repo carter2099/<repo> --comment "Applied directly in batch release X.Y.Z"
```

## Step 9: Confirm

Report: version bumped from X to Y, N gems updated, PRs closed, tag pushed. Ask if the user wants to deploy now (point them at the `/deploy-app` command).

## Notes

- This is the interactive equivalent of the automated `dependabot-webhook` agent. Same workflow, same rules — no PR bodies, no release notes in the prompt.
- For non-bundler bumps (GitHub Actions, npm), close the PR manually or handle separately.
- The automated agent runs with a narrow permission sandbox. This slash command runs with your full session permissions — exercise the same restraint (no sudo, no deploy within this command).
