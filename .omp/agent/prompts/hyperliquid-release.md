---
description: Release the Hyperliquid Ruby SDK — merges dev into main, bumps version, updates CHANGELOG, runs full test suite + integration tests, pushes main and waits for green CI, builds the gem, then (atomically, with Carter's OTP) pushes the gem to RubyGems and only then pushes the tag that creates the GitHub Release.
---

# hyperliquid-release

Repo: `~/dev/hyperliquid`
Ruby: always use `RBENV_VERSION=3.4.10`

## Operating principles (bake these in — do not ask Carter to repeat them)

- **All tests run.** Unit + rubocop + integration. Don't skip any step.
- **Never write off a test failure silently.** If anything fails — unit, integration, or CI — stop, investigate (read error, check git log for whether the affected code changed in this release window, check `~/agent-state/hyperliquid-sdk.md` "Known Pre-existing Integration Test Failures"), then present the diagnosis to Carter and ask before proceeding. Do not assume "environmental" or "flaky" without evidence.
- **Recommend the version bump — don't ask for it cold.** Before anything else, gather the change summary from git log and pitch major/minor/patch with reasoning. Let Carter confirm or override.
- **Verify CI, don't just trigger it.** Watch the `Ruby` workflow on main to completion before asking for the OTP, and the `GitHub Release` workflow after the tag push. Green on both is a release requirement.
- **Releases are atomic.** RubyGems and the GitHub Release ship together or not at all. The tag (which triggers the `GitHub Release` workflow) is pushed only after `gem push` succeeds. Never push a `v*` tag, create a GitHub Release, or push the gem before Carter supplies the OTP.

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

## Step 11: Push main and verify the `Ruby` workflow

```bash
cd ~/dev/hyperliquid
git push origin main
gh run list --workflow Ruby --branch main --limit 3
gh run watch <run-id> --exit-status
```

Do **not** create or push the tag here. Identify the `Ruby` run for the release commit (`headSha` = `git rev-parse main`) and watch it to completion; it must finish `success`. If it fails:
- Read the failure log: `gh run view <run-id> --log-failed | tail -80`
- Diagnose the root cause (don't retry blindly — Endler: never blame the computer).
- Fix it in a follow-up commit on dev, merge to main, push, and re-verify. No tag exists yet, so nothing needs deleting.

## Step 12: Sync dev with main

```bash
cd ~/dev/hyperliquid
git checkout dev
git merge --ff-only main
git push origin dev
git checkout main
```

## Step 13: Build the gem

```bash
cd ~/dev/hyperliquid
git ls-files -z | xargs -0 chmod a+r
RBENV_VERSION=3.4.10 bundle exec rake build
tar -xOf pkg/hyperliquid-X.Y.Z.gem data.tar.gz | tar -tvz | grep -- '-rw-------'   # must print nothing
sha256sum pkg/hyperliquid-X.Y.Z.gem
```

RubyGems packages file modes verbatim, and files written by the scheduled
service (UMask=0077) are `0600` (1.9.2 shipped `CHANGELOG.md`, `CLAUDE.md` and
`lib/hyperliquid/version.rb` as `-rw-------`). `chmod a+r` changes no tracked
content (`git status` stays clean). If the `grep` prints anything, stop: fix the
mode, rebuild, and re-check before asking for the OTP.

## Step 14: Ask Carter for the OTP (last step before publishing)

RubyGems OTPs expire in ~30 s, so the OTP request must be the very last thing before `gem push` — everything above (CI green, gem built) is already done. Tell Carter: "Main is at `<sha>`, `Ruby` CI is green, gem built at `pkg/hyperliquid-X.Y.Z.gem` (sha256 `<sum>`). Paste a fresh RubyGems OTP and I'll push the gem, then the tag." If Carter prefers, he can run the push himself; wait for his confirmation that it succeeded before Step 16.

## Step 15: Push the gem to RubyGems

```bash
cd ~/dev/hyperliquid
RBENV_VERSION=3.4.10 gem push pkg/hyperliquid-X.Y.Z.gem --otp <OTP>
```

Confirm success (`Successfully registered gem: hyperliquid (X.Y.Z)`). If the push fails, **stop**: do not tag and do not create a GitHub Release. Report the error. If credentials are missing (`Invalid credentials / 401`), tell Carter: "No RubyGems credentials on this host. Either push from another machine or run `gem signin` here first, then give me a fresh OTP." For an expired/invalid OTP, ask for a new one — always a fresh OTP after any detour.

## Step 16: Push the tag (creates the GitHub Release) and verify

Only after Step 15 succeeded:

```bash
cd ~/dev/hyperliquid
git tag vX.Y.Z main
git push origin vX.Y.Z
gh run list --workflow "GitHub Release" --limit 3
gh run watch <run-id> --exit-status
gh release view vX.Y.Z
```

The `GitHub Release` run for `vX.Y.Z` must finish `success` and the release must exist with the CHANGELOG section as its body. If the workflow fails, diagnose from `gh run view <run-id> --log-failed | tail -80` and flag to Carter before re-running it or touching the tag (the gem is already on RubyGems, so fix forward: never delete the published version).

## Step 17: Update state file

Edit `~/agent-state/hyperliquid-sdk.md`:
- Update **SDK version** to the new version.
- If the `📝 bug` gem-file-mode entry is open and Step 13's mode check printed nothing, mark it ✅ with the version.
- Add a row to **Run History** noting: date, scope, unit test count + rubocop status, integration pass/fail counts (and which were waived), CI status, gem push status, tag/GitHub Release status.

## Step 18: Confirm to Carter

Report in this shape:
- Released `hyperliquid vX.Y.Z`.
- Ruby CI on main: ✅ green.
- RubyGems: ✅ pushed.
- GitHub Release: ✅ published (tag pushed after the gem).
- State file updated.
