---
description: Release the Hyperliquid Ruby SDK — merges dev into main, bumps version, updates CHANGELOG, runs full test suite + integration tests, pushes main and waits for green CI, builds the gem, then (atomically, with Carter's OTP) pushes the gem to RubyGems and only then pushes the tag that creates the GitHub Release.
---

# hyperliquid-release

Repo: `~/dev/hyperliquid`
Ruby: always use `RBENV_VERSION=3.4.10` (plus the required `RBENV_VERSION=3.3.12` leg in Step 2)

## Operating principles (bake these in — do not ask Carter to repeat them)

- **All tests run.** Unit + rubocop + integration. Don't skip any step.
- **Never write off a test failure silently.** If anything fails — unit, integration, or CI — stop, investigate (read the error, check git log for whether the affected code changed in this release window), then present the diagnosis to Carter and ask before proceeding. Do not assume "environmental" or "flaky" without evidence. Only Carter waives; there is no standing waiver list.
- **Recommend the version bump — don't ask for it cold.** Before anything else, gather the change summary from git log and pitch major/minor/patch with reasoning. Let Carter confirm or override.
- **Verify CI, don't just trigger it.** Watch the `Ruby` workflow on main to completion before asking for the OTP, and the `GitHub Release` workflow after the tag push. Green on both is a release requirement.
- **Releases are atomic.** RubyGems and the GitHub Release ship together or not at all. The tag (which triggers the `GitHub Release` workflow) is pushed only after `gem push` succeeds. Never push a `v*` tag, create a GitHub Release, or push the gem before Carter supplies the OTP.

## Step 1: Gather changes and recommend a version bump

```bash
cd ~/dev/hyperliquid
git checkout dev
git pull --ff-only origin dev
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

## Step 2: Run the full unit gates on dev (Ruby 3.4 + clean clone, Ruby 3.3)

```bash
cd ~/dev/hyperliquid
RBENV_VERSION=3.4.10 bundle exec rake verify   # specs + RuboCop, then again in a clean clone of HEAD with BUNDLE_FROZEN=true
RBENV_VERSION=3.3.12 bundle exec rake          # Ruby 3.3 is a required CI leg (`Ruby 3.3`)
```

Both must pass (`0 failures`, no offenses). If anything fails, stop and surface to Carter — do not release with failing unit tests. If the 3.3 run fails only because gems are missing for 3.3.12, run `RBENV_VERSION=3.3.12 bundle install` (no lockfile change; `git status` must stay clean) and rerun it.

## Step 3: Run the strict integration gate on dev

```bash
cd ~/dev/hyperliquid
source ~/.config/hyperliquid-agent/env
HL_GATE_STRICT=1 HYPERLIQUID_PRIVATE_KEY=$HYPERLIQUID_PRIVATE_KEY RBENV_VERSION=3.4.10 bundle exec rake integration
```

The final `INTEGRATION GATE: …` line and `tmp/integration-summary.json` are
authoritative. In strict mode the gate fails on anything other than all PASS
(FAIL, TIMEOUT, NOT_RUN, and also INCONCLUSIVE, SKIPPED, GUARDED, or a wallet
pre-flight/post-flight failure). Copy the `INTEGRATION GATE:` line verbatim
for Step 17.

If the gate is not PASS:
1. List every non-PASS script by name with its status and `result_line` from
   `tmp/integration-summary.json`.
2. For each FAIL/TIMEOUT, re-run that script alone to capture its exact error
   (`HYPERLIQUID_PRIVATE_KEY=$HYPERLIQUID_PRIVATE_KEY RBENV_VERSION=3.4.10 bundle exec ruby scripts/test_NN_name.rb`).
3. Check `git log <previous-tag>..HEAD -- <relevant lib file>` to see whether this release touched the affected code.
4. Present every non-PASS script to Carter by name with your diagnosis (regression or not, and why), and ask whether to waive or abort. **Never waive unilaterally.**

## Step 4: Merge dev → main

```bash
cd ~/dev/hyperliquid
git checkout main
git pull --ff-only origin main
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

Then dry-run the GitHub Release extraction and the version/lockfile
consistency (the awk is the exact `Extract latest changelog section` step of
`.github/workflows/release.yml`; if that step's awk differs from this copy, use
the workflow's):

```bash
cd ~/dev/hyperliquid
v=$(RBENV_VERSION=3.4.10 ruby -Ilib -rhyperliquid/version -e 'print Hyperliquid::VERSION')
awk '
  /^## \[[0-9]/ { count++; if (count == 2) exit }
  count == 1 { print }
' CHANGELOG.md > /tmp/hl-LATEST_CHANGES.md
head -n 1 /tmp/hl-LATEST_CHANGES.md | grep -qxE "## \[${v//./\\.}\] - [0-9]{4}-[0-9]{2}-[0-9]{2}" \
  && [ "$(grep -c '^- ' /tmp/hl-LATEST_CHANGES.md)" -ge 1 ] \
  && [ "$(grep -c "^    hyperliquid ($v)\$" Gemfile.lock)" -eq 1 ] \
  && echo "CHANGELOG OK v=$v" || echo "CHANGELOG CHECK FAILED v=$v"
cat /tmp/hl-LATEST_CHANGES.md && rm /tmp/hl-LATEST_CHANGES.md
```

It must print `CHANGELOG OK v=X.Y.Z` with X.Y.Z the version Carter approved:
the extracted section's first line is `## [X.Y.Z] - YYYY-MM-DD` matching
`Hyperliquid::VERSION`, it has at least one `- ` bullet, and `Gemfile.lock`
pins `    hyperliquid (X.Y.Z)` exactly once. The printed section is the GitHub
Release body; read it. Otherwise fix CHANGELOG/version/lockfile and rerun.

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
sha=$(git rev-parse HEAD); echo "$sha" > /tmp/hl-release-sha; echo "$sha"
gh run list --workflow Ruby --branch main --commit "$sha" --json databaseId,status,conclusion,headSha
gh run watch <databaseId> --exit-status
gh run view <databaseId> --json headSha,conclusion,jobs --jq '{headSha, conclusion, jobs: [.jobs[] | {name, conclusion}]}'
```

Do **not** create or push the tag here. The run is identified by its exact
`headSha` (the `--commit "$sha"` filter; if the list is empty, the run has not
registered yet: wait ~15 s and list again — never pick a run for another SHA).
Watch it to completion. The release requires, from `gh run view`: `headSha` ==
`$sha`, `conclusion` `success`, and both jobs `Ruby 3.3` and `Ruby 3.4`
present with conclusion `success` (a missing, skipped, or cancelled matrix job
is a failure). If it fails:
- Read the failure log: `gh run view <databaseId> --log-failed | tail -80`
- Diagnose the root cause (don't retry blindly — Endler: never blame the computer).
- Fix it in a follow-up commit on dev, merge to main, push, and re-verify (new `$sha`). No tag exists yet, so nothing needs deleting.

## Step 12: Sync dev with main

```bash
cd ~/dev/hyperliquid
git checkout dev
git merge --ff-only main
git push origin dev
git checkout main
```

## Step 13: Build the gem

First, before building, HEAD must be the CI-verified `$sha` from Step 11 and
the tree clean; it must print `BUILD TREE OK <sha>`, otherwise stop — never
build from a tree CI did not verify:

```bash
cd ~/dev/hyperliquid
sha=$(cat /tmp/hl-release-sha)
test "$(git rev-parse HEAD)" = "$sha" && test -z "$(git status --porcelain)" \
  && echo "BUILD TREE OK $sha" || echo "BUILD TREE MISMATCH: HEAD $(git rev-parse HEAD), CI-verified $sha"
```

Then build and check the package:

```bash
cd ~/dev/hyperliquid
git ls-files -z | xargs -0 chmod a+r
RBENV_VERSION=3.4.10 bundle exec rake build
v=X.Y.Z; gem="$HOME/dev/hyperliquid/pkg/hyperliquid-$v.gem"
# every packaged entry world-readable: must print nothing
tar -xOf "$gem" data.tar.gz | tar -tvz | grep -vE '^.{7}r'
# packaged file list == the gemspec allowlist as git tracks it: must print nothing
diff <(tar -xOf "$gem" data.tar.gz | tar -tz | sort) \
     <(git ls-files lib docs README.md CHANGELOG.md LICENSE.txt SECURITY.md | sort)
sha256sum "$gem"
```

RubyGems packages file modes verbatim, and files written by the scheduled
service (UMask=0077) are `0600` (1.9.2 shipped `CHANGELOG.md`, `CLAUDE.md` and
`lib/hyperliquid/version.rb` as `-rw-------`). `chmod a+r` changes no tracked
content (`git status` stays clean). If either check prints anything (an entry
lacking other-read, or a file missing from / extra in the package), stop: fix
the mode or gemspec, rebuild, and re-check.

Then the consumer smoke: install the built gem the way users get it (RubyGems
resolution, no Bundler, no fork pin) into a temp `GEM_HOME` from a directory
outside the repo, load it, and reproduce the Python SDK `createSubAccount`
mainnet signing vector from `spec/hyperliquid/signing/signer_spec.rb` (local
signing only; no request is sent):

```bash
v=X.Y.Z; gem="$HOME/dev/hyperliquid/pkg/hyperliquid-$v.gem"
t=$(mktemp -d); cd "$t"
env -u BUNDLE_GEMFILE -u RUBYOPT GEM_HOME="$t/gems" GEM_PATH="$t/gems" RBENV_VERSION=3.4.10 \
  gem install --no-document "$gem"
env -u BUNDLE_GEMFILE -u RUBYOPT GEM_HOME="$t/gems" GEM_PATH="$t/gems" RBENV_VERSION=3.4.10 ruby -e '
v = ARGV.fetch(0)
require "hyperliquid"
abort "VERSION #{Hyperliquid::VERSION} != #{v}" unless Hyperliquid::VERSION == v
loaded = $LOADED_FEATURES.grep(%r{/hyperliquid\.rb\z}).first
abort "loaded #{loaded}, not the installed gem" unless loaded.start_with?(ENV.fetch("GEM_HOME"))
# Python SDK's public test-vector key 0x0123…0123 (built, not written out, so the dotfiles secret scan stays quiet)
vector_key = "0x" + ("0123456789" * 7)[0, 64]
sig = Hyperliquid::Signing::Signer.new(private_key: (vector_key), testnet: false)
        .sign_l1_action({ type: "createSubAccount", name: "example" }, 0)
want = { r: "0x51096fe3239421d16b671e192f574ae24ae14329099b6db28e479b86cdd6caa7",
         s: "0x0b71f7d293af92d3772572afb8b102d167a7cef7473388286bc01f52a5c5b423", v: 27 }
abort "signature mismatch: #{sig.inspect}" unless sig.slice(:r, :s, :v) == want
puts "CONSUMER SMOKE OK hyperliquid #{v} (rbsecp256k1 #{Gem.loaded_specs["rbsecp256k1"]&.version})"
' "$v"
cd ~/dev/hyperliquid && rm -rf "$t"
```

It must print exactly one `CONSUMER SMOKE OK hyperliquid X.Y.Z (…)` line.
Anything else (install failure, wrong version, a load from anywhere but the
temp `GEM_HOME`, a signature mismatch) stops the release before the OTP:
diagnose and present it to Carter.

## Step 14: Ask Carter for the OTP (last step before publishing)

RubyGems OTPs expire in ~30 s, so the OTP request must be the very last thing before `gem push` — everything above (CI green, gem built and checked, consumer smoke OK) is already done. Tell Carter: "Main is at `<sha>`, `Ruby` CI is green (Ruby 3.3 + 3.4), gem built at `pkg/hyperliquid-X.Y.Z.gem` (sha256 `<sum>`), consumer smoke OK. Paste a fresh RubyGems OTP and I'll push the gem, then the tag." If Carter prefers, he can run the push himself; wait for his confirmation that it succeeded before Step 16.

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
- Add a row to **Run History** noting: date, scope, the rspec summary lines of the Step 2 Ruby 3.4 (`rake verify`) and Ruby 3.3 runs + RuboCop status, the Step 3 strict `INTEGRATION GATE:` line copied verbatim (its pass/guarded/skipped/inconclusive/fail/timeout/not_run counts) plus every non-PASS script by name and whether Carter waived it, the CI run id and its `Ruby 3.3`/`Ruby 3.4` job conclusions, the consumer smoke line, gem push status, tag/GitHub Release status.

## Step 18: Confirm to Carter

Report in this shape:
- Released `hyperliquid vX.Y.Z`.
- Ruby CI on main: ✅ green.
- RubyGems: ✅ pushed.
- GitHub Release: ✅ published (tag pushed after the gem).
- State file updated.
