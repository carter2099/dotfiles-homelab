---
description: Release the Hyperliquid Ruby SDK — merges dev into main, bumps version, updates CHANGELOG, runs full test suite + integration tests, creates a git tag (triggers GitHub Release), pushes the gem to RubyGems, and verifies GitHub Actions workflows succeed.
---

# hyperliquid-release

Repo: `~/dev/hyperliquid`
Ruby: always use `RBENV_VERSION=3.4.10`

## Operating principles (bake these in — do not ask Carter to repeat them)

- **All tests run.** Unit + rubocop + integration. Don't skip any step.
- **Never write off a test failure silently.** If anything fails — unit, integration, or CI — stop, investigate (read error, check git log for whether the affected code changed in this release window, check `~/agent-state/hyperliquid-sdk.md` "Known Pre-existing Integration Test Failures"), then present the diagnosis to Carter and ask before proceeding. Do not assume "environmental" or "flaky" without evidence.
- **Recommend the version bump — don't ask for it cold.** Before anything else, gather the change summary from git log and pitch major/minor/patch with reasoning. Let Carter confirm or override.
- **Verify CI, don't just trigger it.** After pushing tag + main, watch the `Ruby` and `GitHub Release` workflows to completion. Green on both is a release requirement.

## Step 1: Gather changes and recommend a version bump

```bash
cd ~/dev/hyperliquid
git checkout dev
git pull origin dev
git status     # must be clean; if not, stop and ask
git tag --sort=-v:refname | head -1         # current/previous tag
git log <previous-tag>..HEAD --stat --no-merges
```

Read `lib/hyperliquid/version.rb` for the current version.

Summarize the changes for Carter in this shape:

- New public API (list added classes/methods)
- Bugfixes
- Breaking changes (if any)
- Tooling / scripts (not shipped in the gem)

Then recommend **major / minor / patch** with one-line SemVer reasoning:
- **major**: public API removed or signature-breaking changes
- **minor**: new public API added, no breakage
- **patch**: bugfixes + internal refactors only

Wait for Carter's confirmation (or override) before continuing.

## Step 2: Run full unit test suite on dev

```bash
cd ~/dev/hyperliquid
RBENV_VERSION=3.4.10 bundle exec rake
```

All specs + RuboCop must pass. If anything fails, stop and surface to Carter — do not release with failing unit tests.

## Step 3: Run integration tests on dev

```bash
cd ~/dev/hyperliquid
source ~/.config/hyperliquid-agent/env
RBENV_VERSION=3.4.10 HYPERLIQUID_PRIVATE_KEY=$HYPERLIQUID_PRIVATE_KEY ruby scripts/test_automated.rb
```

If any integration test fails:
1. Re-run the failing test in isolation to capture its exact error.
2. Cross-reference `~/agent-state/hyperliquid-sdk.md` → "Known Pre-existing Integration Test Failures" table.
3. Check `git log <previous-tag>..HEAD -- <relevant lib file>` to see whether this release touched the affected code.
4. Present diagnosis to Carter: what failed, why you think it's not a regression (or that it is), and ask whether to waive or abort. **Never waive unilaterally.**

## Step 4: Merge dev → main

```bash
cd ~/dev/hyperliquid
git checkout main
git pull origin main
git merge --no-ff dev -m "Merge dev into main for release"
```

If there are conflicts, resolve them and confirm with Carter before continuing.

## Step 5: Bump version

Edit `lib/hyperliquid/version.rb` to set the new version string.

## Step 6: Regenerate Gemfile.lock

**Critical — don't skip.** `lib/hyperliquid/version.rb` feeds the `hyperliquid` gemspec, and `Gemfile.lock` pins that version. Bumping the version without regenerating the lockfile will cause CI (`Ruby` workflow) to fail with:

> The gemspecs for path gems changed, but the lockfile can't be updated because frozen mode is set

```bash
cd ~/dev/hyperliquid
RBENV_VERSION=3.4.10 bundle install
```

Confirm the lockfile now shows `hyperliquid (X.Y.Z)` matching the new version.

## Step 7: Update CHANGELOG.md

Prepend a new section below the title line in this format:

```
## [X.Y.Z] - YYYY-MM-DD

### <Section heading — e.g. "New endpoints", "Fixes", "Breaking">

- <human-readable bullet, not raw commit message>
```

Use the change summary from Step 1 — don't re-derive from git log.

## Step 8: Sync CLAUDE.md if needed

`~/dev/hyperliquid/CLAUDE.md` is the canonical source of truth for the repo and should stay current. Right after a `dev → main` merge is a natural checkpoint — review it against what just landed across this release window.

Update CLAUDE.md whenever this release:
- Adds a new pattern, transport, dependency, constant, or convention a future agent reading the repo cold would want to know (new base URL, new signing variant, new test harness file, etc.).
- Changes how something documented in CLAUDE.md actually works (architecture, request flow, signing, numeric conversion, code style, CI, release flow).
- Introduces a new gotcha worth preserving.

Routine additions that fit cleanly into existing patterns (more Info methods, more Exchange actions using the existing signer) generally do **not** need a CLAUDE.md update. Skip rather than churn the file.

If you do edit CLAUDE.md, include it in the next commit (Step 9) — don't commit it separately.

## Step 9: Commit version bump + lockfile

```bash
cd ~/dev/hyperliquid
git add lib/hyperliquid/version.rb Gemfile.lock CHANGELOG.md   # add CLAUDE.md too if updated in Step 8
git commit -m "version to X.Y.Z"
```

## Step 10: Run tests one final time on main

```bash
RBENV_VERSION=3.4.10 bundle exec rake
```

Must pass. If anything broke in the merge, fix it now.

## Step 11: Push main and create tag

```bash
cd ~/dev/hyperliquid
git push origin main
git tag vX.Y.Z
git push origin vX.Y.Z
```

The tag triggers the `GitHub Release` workflow; the main push triggers the `Ruby` workflow.

## Step 12: Verify GitHub Actions workflows succeed

```bash
cd ~/dev/hyperliquid
gh run list --branch main --limit 3
gh run list --workflow "GitHub Release" --limit 3
```

Identify the two new runs (one `Ruby` on main, one `GitHub Release` on vX.Y.Z). Watch each to completion:

```bash
gh run watch <run-id> --exit-status
```

**Both must finish `success`.** If either fails:
- Read the failure log: `gh run view <run-id> --log-failed | tail -80`
- Diagnose the root cause (don't retry blindly — Endler: never blame the computer).
- Fix it in a follow-up commit on dev, merge to main, push. The tag stays as-is (re-tagging is destructive); the fix commit sits on top of the release commit. Re-verify the `Ruby` workflow.
- If `GitHub Release` failed, the tag will need deleting and recreating after the fix — flag to Carter before doing that.

Do not proceed to Step 13 until both workflows are green.

## Step 13: Push gem to RubyGems (requires MFA)

```bash
cd ~/dev/hyperliquid
RBENV_VERSION=3.4.10 bundle exec rake build
```

Then tell Carter: "Gem built at `pkg/hyperliquid-X.Y.Z.gem`. Paste your RubyGems OTP and I'll push, or run `gem push` yourself."

If Carter provides the OTP, run:

```bash
cd ~/dev/hyperliquid
RBENV_VERSION=3.4.10 gem push pkg/hyperliquid-X.Y.Z.gem --otp <OTP>
```

If credentials are missing (`Invalid credentials / 401`), tell Carter: "No RubyGems credentials on this host. Either push from another machine or run `gem signin` here first, then give me a fresh OTP." OTPs expire in ~30s — always ask for a new one after a setup detour.

## Step 14: Sync dev with main

```bash
cd ~/dev/hyperliquid
git checkout dev
git merge main
git push origin dev
```

## Step 15: Update state file

Edit `~/agent-state/hyperliquid-sdk.md`:
- Update **SDK version** to the new version.
- Add a row to **Run History** noting: date, scope, unit test count + rubocop status, integration pass/fail counts (and which were waived), CI status, gem push status.

## Step 16: Confirm to Carter

Report in this shape:
- Released `hyperliquid vX.Y.Z`.
- GitHub Release: ✅ published.
- Ruby CI on main: ✅ green.
- RubyGems: ✅ pushed (or note if deferred).
- State file updated.
