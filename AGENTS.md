# AGENTS.md

This file provides guidance to omp agents when working on this homelab.

**Maintenance:** Keep this file up to date. When deploying a new app, adding a service, changing ports/IPs, or making any structural changes to the homelab, update the relevant sections here as part of that work. Deep-dive architecture for subsystems lives in `~/notes/docs/homelab/` and `~/notes/journal/` (see "Where the deep dives live" at the bottom) — keep AGENTS.md as the always-loaded operational reference. The ThinkPad remains the sole notes, documentation, infrastructure, and production authority; the gaming rig's development boundary is documented in the linked homelab notes.

## Working principles (Endler tenets)

Carter endorses the tenets in [The Best Programmers](https://endler.dev/2025/best-programmers/). The subset below is the part that applies directly to an LLM assistant and should shape every session.

- **Read the reference.** Prefer official docs (local or web), man pages, and the actual source over recall from training data. When something in this repo is in question, read the file. Training-data recall about APIs, flags, or versions is frequently stale — verify.
- **Read the error message.** Parse errors fully before reacting. The message usually names the cause; skimming past it and guessing wastes Carter's time.
- **Don't guess.** If a fact is load-bearing for the answer or action, verify it with a tool (grep, read, `--help`, a quick script) rather than asserting from memory. This is the single most important one.
- **Say "I don't know."** Uncertainty is fine and useful; confident bullshit is not. If a recommendation rests on something unverified, say so explicitly rather than smoothing it over.
- **Never blame the computer.** "Flaky test," "weird cache," "probably a transient issue" are hypotheses, not conclusions. Bugs have causes — keep investigating until the cause is named, even if the fix is a retry.
- **Keep it simple.** Prefer the smallest change that solves the problem. This reinforces the existing "no gratuitous abstractions / no speculative features" guidance further down in this file.
- **Tune shared local models for general utility.** Use diverse evaluation tasks, neutral prompts, and sealed holdouts. Never encode benchmark answers, rubric fields, named test cases, or product-specific workflows in shared model prompts or runtime messages. Specialized behavior belongs in a separate deployment or profile.

## Scope

Carter wants this agent framed as a **homelab assistant and general personal assistant**, not narrowly as a coding tool. Software engineering is a large part of the work, but non-code help (planning, notes, research, life admin, digests, correspondence drafting, scheduling) is equally in scope and should be treated as first-class.

## Overview

Two-host homelab: the ThinkPad L14 Gen 3 runs the primary Ubuntu services, Docker Compose apps behind a Cloudflare Tunnel to loopback origins, and systemd automation (k3s was retired on 2026-09-25); the dual-boot gaming rig provides Linux AI inference, a focused development center, and Windows gaming.

## Key Practice

Use `notes/` as a knowledge base. You will see this referenced throughout this AGENTS.md.

## Repository Structure

Home directory managed as a bare git repo for dotfiles. Key dirs:
- `blog/` — Rails 8 production checkout/wrappers (canonical source is `~/dev/blog/`)
- `beatz/` — public beat archive deployment checkout
- `beatz-selected/` — read-only audio, starter-selection, and artwork library mounted by the beatz service (not Git-tracked)
- `homelab-backup/` — Go backup service
- `freshrss/` — FreshRSS Docker Compose stack (`data/` is gitignored)
- `k3s/` — retired Kubernetes manifests (k3s stopped/disabled 2026-09-25; removed with the uninstall)
- `dev/` — ThinkPad scratch space for cloned repos, tests, and development; gamingrig-linux uses `/home/carte/dev/<repo>` instead
- `news/` — Daily News nginx deployment configuration and static assets
- `scripts/` — Daily News and steward entrypoints, bounded packages, and verification pipelines
- `notes/` — Agent-maintained knowledge vault (`docs/` for maintained ref, `logs/sessions/` for session history, `journal/` for research/records)
- `digests/` / `backups/` — Automated output archives; `digests/news/{publications,attention,mail}/` is durable Daily News state
- `ideas/` — Unstructured ideas (not maintained)
- `.dotfiles-homelab/` — Bare git repo tracking dotfiles; origin is the **private** `carter2099/dotfiles-homelab-private`
- `.config/nvim/` — live Neovim config and canonical standalone Git repository; ignored by the parent bare repo
## Dev Workflow (`dev/`)

**Hard rule:** On the ThinkPad, always develop application code in `~/dev/<repo>/`. Never edit files in production deploy folders such as `/home/carter/blog/` or `/home/carter/homelab-backup/`; those are deployment artifacts only. If a ThinkPad dev clone does not exist, clone `git@github.com:carter2099/<repo>.git` into `~/dev/<repo>` before changing it. **Explicit exception:** `~/.config/nvim/` is intentionally both the live config and its own canonical standalone Git repository; edit, commit, and push it in place. It has no deploy step and the parent dotfiles repo ignores it.

The gaming rig is a separate development center: work only in `/home/carte/dev/<repo>`, use GitHub as the normal code-transfer boundary, and never deploy production from the rig. Do not place notes, production deploy trees, infrastructure config, or homelab application state there. The only exception is the steward-managed `/home/carte/src/llama.cpp*` serving-build workspace; it is not a general development root and must remain outside normal project work. See [`local-llm-gaming-rig.md`](notes/docs/homelab/local-llm-gaming-rig.md) and [`environment.md`](notes/docs/homelab/environment.md) for the boundary and installed conventions.

The ThinkPad `dev/` directory is for cloning GitHub repos (via SSH: `git@github.com:carter2099/<repo>.git`), running their test suites, making changes, and pushing back. It is **not** tracked by the dotfiles bare repo.

Typical flow:
```bash
cd ~/dev
git clone git@github.com:carter2099/<repo>.git
cd <repo>
bundle install   # or npm install, etc.
bundle exec rspec  # run tests
# make changes, commit, push
```

Note: `.ruby-version` in cloned repos may request a Ruby not installed locally. Check `rbenv versions`; use `RBENV_VERSION=<installed-version>` to override for testing if the patch difference is minor, or `rbenv install <version>` for the exact one.

## Decisions in software: use Jev

When software we build needs a model judgment that code will branch on (classify, route, gate, score, rank, dedupe/match, or verify/guardrail an LLM output), default to TypeSafe's **Jev**, not an LLM plus output parsing. Jev is a "System One" model: you send a state and typed questions; it returns typed answers with calibrated probabilities in about 70–500 ms. Its answers always match the schema. Use an LLM only when the output must be generated text or code, or when the task needs extended multi-step reasoning. Docs: [docs.typesafe.ai](https://docs.typesafe.ai/) (index at `/llms.txt`).
- API: `POST https://api.typesafe.ai/v1/systemone` with `{model, state, questions}`. Question types: `Choice` (one of ≤255 options), `Score` (rubric levels), `Noul` (truth of a statement, 0–1). Choice and Score also return `confidence`.
- Ask atomic gut-check questions. Break compound judgments into several questions (answered in parallel in one request) and combine them in code with explicit weights.
- Gate actions on `confidence` with thresholds scaled to the stakes (act, review, or fall back). A Jev failure or low confidence means "unknown", never a default answer. Pin the model version and bound timeouts and retries.
- Shared client: `~/scripts/jev.py` (pinned `jev-1.13.0`); every caller uses it. `load_client()` returns `None` without a key; `ask(purpose, state, questions)` raises only `JevUnavailable` (`.reason`), and after 3 consecutive failed asks the client fails fast (`breaker_open`). Gate with `jev.gate(confidence)` / `jev.noul_certainty(p)`. Tests inject a fake client or `post`; they never call the API.
- Key: `~/.local/state/typesafe/api-key` (dir 700, file 600, gitignored via `/.local/state/`). Read it at runtime. Never commit, log, or embed it in repos or prompts, and never copy it to the gaming rig.

## Slash commands

User-global commands are file prompts in `~/.omp/agent/prompts/*.md`; the filename determines the slash-command name.

Make sure to track in VCS when adding slash commands.

## Dotfiles Management

```bash
# The 'dotfiles' command manages the bare repo
dotfiles status
dotfiles add <file>
dotfiles commit -m "message"
dotfiles push
```

`dotfiles` is a real command at `~/.local/bin/dotfiles` (tracked in the repo itself), so it
works in any shell — no shell alias needed. In headless/bash sessions where `~/.local/bin` is
not on PATH (e.g. agent tool shells), either `export PATH="$HOME/.local/bin:$PATH"` first or
use the raw form: `/usr/bin/git --git-dir="$HOME/.dotfiles-homelab/" --work-tree="$HOME" ...`.

**⚠️ Always use targeted `dotfiles add <path>` — never bare `dotfiles add -A` or `dotfiles add .`.** Since the work-tree is `$HOME`, an unqualified `add -A` would stage everything in `/home/carter/` that isn't gitignored. Scope adds to the specific file(s) being tracked.

```bash
dotfiles add .zshrc                                 # single file
dotfiles add .config/systemd/user/homelab-steward.* # canonical infrastructure units
dotfiles add .omp/agent/prompts/create-command.md       # command-creation prompt
dotfiles add .omp/agent/prompts/hyperliquid-run.md      # scheduled command prompt
```

The steward's P9b dotfiles phase commits already-tracked modified/deleted paths (`git add -u`) and new files under scripts/, system-config/, .config/systemd/user/, .omp/agent/prompts/, news/, searxng/, open-webui/ and freshrss/ when they are regular text files (no NUL in the first 8 KiB, <= 256 KiB) with no secret-looking name or content. Each candidate diff (<= 12k chars, otherwise held) goes to Jev once: it is committed only when Jev says it is unrelated to every active interactive session with confidence >= 0.9 and a complete change with p >= 0.6; with no active session a finished edit is committed. Jev failure or low confidence holds the path. Other untracked paths are listed in the email's Host drift block and never staged. A deterministic secret scan runs over the staged diff before commit and over a pending commit before any retry push; a hit blocks both. Pushes go only to origin `carter2099/dotfiles-homelab-private`. P9b treats recent unclosed interactive OMP sessions as in-flight ownership evidence and must not stage overlapping paths. A failed post-commit push may be retried only for the exact recorded branch and commit OID; divergence requires inspection.

### Committing and the public showcase

Commit dotfiles with `dotfiles-commit -m "msg" <path>...` (`~/scripts/dotfiles_commit.py`): it stages exactly those paths, blocks on a secret-scan hit (tokens, private keys, credential assignments, secret-looking file names), prints each path's publish scope, commits to the private repo and pushes. `dotfiles-commit --classify <path>...` shows scopes without committing; `dotfiles-commit --publish [--dry-run]` runs the publisher now.

The private repo is published as squashed snapshots (never its history) to the **public** `carter2099/dotfiles-homelab` by the steward's nightly P9c (`~/scripts/steward/showcase.py`, artifact `09c-showcase.json`, email section "Public showcase"). Scope per path, in order: a `private` glob in `~/system-config/dotfiles-publish.toml` (never published: `.ssh/`, `.config/rig-dashboard/env`, `.local/bin/rigwake`, `k3s/`, any env/token/key/credential/database file) → deterministic scan hit = held (never sent to Jev) → `public` glob → recorded decision in `~/system-config/dotfiles-publish-decisions.json` → otherwise Jev decides and only a confident safe answer publishes (recorded as `by: "jev"`). Held paths and Jev failures stay unpublished and are listed in the email. Changes to already-public files pass a Jev credential/personal veto on the changed hunks, else the previous public version stays. Internal IPs, hostnames and firewall/sandbox policy are fine to publish. When adding a new area, add its glob to the policy (`public` or `private`) rather than relying on Jev; to overrule Jev, set the path's entry to `"by": "carter"`. Publisher state and the snapshot mirror live in `~/.local/state/dotfiles-showcase/`.

Practice for agents:
- All home-config commits go to the private repo, preferably via `dotfiles-commit` (it scans and shows each path's publish scope). Never push to `carter2099/dotfiles-homelab` by hand and never rewrite either repo's history; the public repo only ever receives P9c/`--publish` snapshots.
- **Private (never public):** credentials, tokens, keys and env files; SSH client config (`.ssh/`); rig MAC addresses and boot/EFI identifiers (`.local/bin/rigwake`, MAC-bearing files are held by the scan); personal data; OMP session transcripts and `~/.local/state`/`~/.local/share`; the `~/notes` vault, which is its own private repo (`carter2099/notes`) and never enters the dotfiles repos.
- **Public:** scripts, systemd units, Compose files, OMP prompts/config, rig config (`system-config/`), benchmarks, and AGENTS.md. Internal IPs and hostnames are accepted as public.
- **Decision order:** private rule → secret/MAC scan (hold) → public rule → recorded decision → Jev for ambiguous paths → hold when unsure (never publish on a guess).
- **Who changes the rules:** only Carter edits the `private`/`public` globs in `dotfiles-publish.toml`. Agents never widen them; for an ambiguous path they may only record a decision in `dotfiles-publish-decisions.json` (Jev's are written as `by: "jev"`; `by: "carter"` overrides) or propose a glob change to Carter.
- **Nightly:** P9b auto-commits tracked changes and eligible new files to the private repo; P9c then publishes the public snapshot.

**Repo visibility in general:** infrastructure/ops repos are private, apps and libraries are public, and new repos start private unless Carter says otherwise.

## App Deployment Pattern

Detailed deploy runbook at [`~/notes/docs/homelab/deployment.md`](notes/docs/homelab/deployment.md).

**Critical rules (every deploy):**
- **Commit before deploy.** Deployed state normally matches `origin/main`; check `git status` first.
  **Explicit exception:** Steward P1 may mutate and deploy tracked managed-version pins before P9b attempts to commit/push them; even failed or dirty pins can persist if later gates fail, so reconcile against live health and Git immediately. No other dirty-tree deploy is allowed.
- **Orphaned docker-proxy.** Container exit 255 can leave `docker-proxy` holding the port. Fix: `sudo kill <proxy-pid>`, `docker rm <container>`, `bash up.sh`.
- **"Missing feature" = check cache first.** Cloudflare serves stale HTML if origin is down. `curl` the origin before debugging code.
- **Exit 255 is intermittent.** Restart with existing image; don't rebuild.
- **Never run `sudo aa-remove-unknown`.** Can delete AppArmor profiles Docker/containerd depend on.
## Firewall (UFW) and retired k3s

**k3s is retired:** stopped and disabled on 2026-09-25, uninstall pending (put nothing on it; `k`/`kubectl` no longer have a cluster; homelab-backup and the steward no longer depend on it). FreshRSS moved to Docker Compose. Details and rollback: [`k3s.md`](notes/docs/homelab/k3s.md).

**UFW source of truth:** `~/system-config/ufw-expected-rules.txt` lists the exact `sudo ufw show added` lines (`br-owui` 8081 and 8082; 8082 from rig `192.168.4.103`; 22 from `192.168.4.0/22`; the k3s `cni0` rule was removed). Change rules by editing that file and running `sudo bash ~/system-config/ufw-rebuild.sh`, which validates before mutating and deletes only rules not listed. Steward P3a reports drift and never changes UFW.
## App Details

Each app has a reference doc in `~/notes/docs/homelab/`:

- **Blog** (canonical `~/dev/blog/`; transactional deploy via `deploy/deploy.sh` — stop it with TERM, never KILL; production checkout `~/blog/blog/`; `b5cb69b` (0.1.15) deployed 2026-09-23, check with `docker exec blog-web-1 cat config/version.rb`; the steward's P1 `app_deploy` deploys automatically when production is behind a CI-green `origin/main`; Docker loopback-only on 127.0.0.1:33099; public blog.carter2099.com tunnels directly to that origin, with no k3s dependency) → [`blog.md`](notes/docs/homelab/blog.md)
- **Beatz** (public Go music player branded “Beats” in-app, localhost:30142; no Cloudflare Access; media: `~/beatz-selected/`; play history: `~/beatz-data/plays.jsonl`; canonical `~/dev/beatz/`; transactional `release.sh`; commit `8a4a285` deployed healthy; injected-health-failure rollback, restored playback, and unchanged history proved in the isolated recovery VM) → [`beatz.md`](notes/docs/homelab/beatz.md)
- **Homelab Monitor** (public read-only dashboard at monitor.carter2099.com, no Cloudflare Access; canonical `~/dev/homelab-dashboard/` (`carter2099/homelab-dashboard`, private); CI-gated transactional `release.sh`; user unit `homelab-dashboard-collector.service` (no listener) publishes scrubbed `snapshot.json`/`history.json` to `~/.local/share/homelab-dashboard/public/`; read-only nginx container `carter-monitor` on loopback:30148; tunnel config v102; no backup target; commit `7cb4a0d`) → [`homelab-dashboard.md`](notes/docs/homelab/homelab-dashboard.md)
- **Daily News** (public static newspaper UI, localhost:30144, news.carter2099.com; bounded `~/scripts/daily_news/` package; per-run validated SQLite workflow state; priority-ranked front page + five category pages, historical editions, one front-page-headline email, durable data in R2 backup) → [`email-digests.md`](notes/docs/homelab/email-digests.md)
- **Hyperliquid SDK maintenance** (scheduled upstream API + dependency maintenance on `opencode-go/glm-5.3`; the wrapper fails a run that exits 0 without advancing its state file; Dependabot PR metadata is deterministically collected, Prompt-Guard-classified, and reconciled into the regular maintenance queue before later bounded processing; verification: `verify-dependabot-intake.sh full` and `verify-hyperliquid-guard.sh full`; no trading runtime) → [`hyperliquid-sdk.md`](notes/docs/homelab/hyperliquid-sdk.md)
- **Homelab Backup** (canonical `~/dev/homelab-backup/`; transactional `release.sh`; deployed 34-target manifest, schema v2 / `current-v5` (FreshRSS snapshotted through its container, no sudo; `k3s-manifests` dropped); OMP `agent.db`/`models.db`/`history.db` are `sqlite-host` targets snapshotted with `sqlite3 .backup` (30 s busy timeout; `omp-agent-state` excludes `*.db`, `*.db-wal`, `*.db-shm`); coordinated Open WebUI DB/uploads/full Chroma indexes with state-preserving freeze and independent thaw; daily 03:00 UTC → R2; `verify`/`latest`/restore drill check each archive against its own embedded manifest (config drift is only a WARN); units have `TimeoutStartSec` (backup 30 min, drill 1 h) and `OnFailure=notify-failure@%n.service`; verify output is authoritative for target/DB counts; isolated two-boot recovery and saved-data probes passed on 2026-09-06) → [`homelab-backup.md`](notes/docs/homelab/homelab-backup.md)
- **Dependabot Webhook** (Go, localhost:9099; agent model `opencode-go/deepseek-v4.1-flash`; after publishing it closes only PRs whose gem the published `Gemfile.lock` really resolves at or above the PR's target, and comments on the rest; Dependabot security updates are on for blog, hyperliquid and delta_neutral; the blog's bundle-audit vulnerabilities are fixed through this pipeline, not by hand) → [`dependabot-webhook.md`](notes/docs/homelab/dependabot-webhook.md)
- **Open WebUI** (**0.11.4**; the steward's P1 installs the latest stable release every night with snapshot, health gate and rollback (no soak), `/update-openweb-ui` is the manual path; chat frontend + native SearXNG + Weather v2 + local Qwen Image 2.1 generation/editing, localhost:48100; local models via `http://host.docker.internal:8081/v1`, never a host LAN IP; the container sits on Docker network `owui-host` (fixed bridge `br-owui`, 172.31.250.0/24, `host.docker.internal`=172.31.250.1), the only bridge UFW lets reach 8081/8082, plus `homelab-chat-search` for SearXNG; reference editing uses normal saved chats, not Temporary Chat) → [`open-webui.md`](notes/docs/homelab/open-webui.md)
- **Herdr Web Client** (browser title **Herdr Web**; `herdr-web-client.service` on loopback:30145 at remote.carter2099.com; Cloudflare Access is the authentication boundary; separate enabled `herdr-server.service` runs Herdr **0.9.1**, upgraded by live handoff with existing pane processes preserved; hardened browser attachment with explicit **Detach other client and connect**, OSC 52 clipboard copy for selection and terminal yanks, semantic completion toast/chime, Kitty Shift+Enter newline; the steward's P1 `app_deploy` runs `deploy/release.sh` when production is behind a CI-green `origin/main`, and P1 `dependabot_merge` auto-merges its green Dependabot PRs) → [`omp-agent-cli.md`](notes/docs/homelab/omp-agent-cli.md)
- **SearXNG** (search backend, localhost:8080) → [`searxng.md`](notes/docs/homelab/searxng.md)
- **FreshRSS** (RSS reader, Docker Compose in `~/freshrss` (`up.sh`), container `freshrss` on loopback 127.0.0.1:30149, freshrss.carter2099.com via the tunnel; data `~/freshrss/data` (gitignored, backed up); steward P1 bumps the tag@digest pin with rollback) → [`freshrss.md`](notes/docs/homelab/freshrss.md)
- **Cloudflare** (API token, tunnel, DNS; Access-gated hosts: remote, rig, ssh, comfy, chat; remote/rig/chat/comfy ingress also validate the Access JWT at the origin (`originRequest.access`), ssh does not; apex CAA records restrict issuance to the CAs Cloudflare uses) → [`cloudflare.md`](notes/docs/homelab/cloudflare.md)
- **External monitoring** (canonical `~/dev/homelab-monitor/`; local backup/news completion receipts installed; Worker/D1/email deployment and native tunnel notifications remain blocked by missing Cloudflare API permissions) → [`cloudflare.md`](notes/docs/homelab/cloudflare.md)
- **OpenCode Go Proxy** (0.0.0.0:8082, **no client authentication**: clients send the placeholder key `proxy` and the proxy substitutes real account keys, so UFW is the only gate—`br-owui` (Open WebUI) plus the gaming rig's exact `192.168.4.103` source address for rig-local OMP fallback; quota routing from the authenticated OpenCode usage API). The optional direct Zen free-model path is controlled by `free_endpoint_enabled`; it is currently `false`, so all requests go directly through `/zen/go`. `/health` reports the active setting. If opencode-go models fail, check this first → [`opencode-go-proxy.md`](notes/docs/homelab/opencode-go-proxy.md)
- **LLM Proxy** (canonical `~/dev/llm-proxy/`; proxy/dashboard binaries `b22dfcc`, serving config `5d400c9`; transactional `release.sh`; wildcard:8081 with no client auth, so UFW allows 8081 only on `br-owui` and `release.sh` refuses to deploy unless live 8081 rules match the interfaces declared in `~/system-config/ufw-expected-rules.txt`; six reasoning-enabled local entries, including optional `bonsai-2-27b-pq2` at 98,304 context / 2,048 thinking tokens on a separate pinned Prism runtime; existing defaults unchanged; cloud fallback is opt-in via `FALLBACK_ENABLED`, currently `false` and fail-closed—when disabled, fallback requests return 503 without initializing or calling cloud; rig dashboard requires 45 seconds of stable Windows and retries one immediate Linux return within an eight-minute bound) → [`local-llm-gaming-rig.md`](notes/docs/homelab/local-llm-gaming-rig.md)
- **Qwen Image 2.1 / ComfyUI** (canonical `~/dev/llm-proxy/`; direct App Mode at Access-gated `comfy.carter2099.com` through ThinkPad `comfy-web.service`, loopback:30147, transactional `release-comfy.sh`; Create Image plus Edit and Combine presets; Comfy-Org INT8 weights under the research/evaluation-only Qwen license). ComfyUI v0.37.0 runs as hidden llama-swap entry `comfyui_auto`; Open WebUI uses `/upstream/comfyui_auto`. A queue-owned HTTP lease protects renders, including after tab closure; idle WebSockets do not block chat. Reload the Comfy page after a text-model swap. The rig must already be awake in Linux; no image cloud fallback. Raw rig outputs are not in R2 backup, unlike Open WebUI-delivered uploads. Linux DHCP uses MAC identity in `system-config/gamingrig-linux/netplan/60-rig-dhcp-identity.yaml` to retain `192.168.4.103` across Windows/Linux boots → [`local-llm-gaming-rig.md#qwen-image-21`](notes/docs/homelab/local-llm-gaming-rig.md#qwen-image-21)
- **Prompt-Guard Classifier** (canonical `~/dev/prompt-guard/`; immutable model revision and release runtime; transactional `deploy.sh`; localhost:8090) → [`dependabot-webhook.md`](notes/docs/homelab/dependabot-webhook.md)

## Daily News Digests

Five category pipelines begin at 2:00 AM ET via `digests-daily.timer`, publish a priority-ranked front page plus separate sections at `news.carter2099.com`, and send one email containing only the selected front-page headlines and a link to that edition. Editorial significance measures consequence only: `high` requires structured, source-grounded impact evidence, and routine maintenance/deprecations without demonstrated broad impact are downgraded. Observed attention comes from one shared per-edition snapshot of free bulk inventories (GDELT GKG files, publisher sitemaps/RSS, a sampled Bluesky Jetstream replay, Hacker News, Techmeme, Kagi News, Mastodon trending links, Bluesky trends, Wikipedia top pageviews); Jev (shared client `~/scripts/jev.py`, `jev-1.13.0`, key `~/.local/state/typesafe/api-key`) only adjudicates whether a retrieved document reports the same event and answers decomposed importance questions — it never estimates popularity. Each source is scored separately against its own reference scale and weighted by its channel; a source that failed or came back `partial` is left out of every story's blend (never counted as zero) and attention confidence shrinks with the measured share. A measured no-match scores zero attention; a story Jev could not adjudicate, or a run with no source measured, gets confidence-0 attention (importance-only priority). Priority is live: `priority_score` blends editorial significance, Jev importance, and attention. Snapshot source availability, match rate, and Jev status are logged per section in `~/digests/.attention-health.log`; windowed source availability < 0.6, a source incomplete for all five runs of the window, or degraded Jev reports `rec: warn` without gating publication. Deterministic ties use prominence, attention, confidence, scope, significance, date, title, and URL—never discovery order. The front page guarantees one curated lead per section, then fills remaining slots globally at priority ≥65 (max 10). Standfirsts use complete newspaper prose. Published story URLs are normalized to canonical reader-facing publisher domains (e.g. NYT sample hosts such as `monorepo-sample1.nyt.net` map to `www.nytimes.com`). Durable state under `~/digests/news/` is backed up as `daily-news-data`; the public origin is loopback-only `carter-news` on 30144. **Developing and Ongoing** requires high validated significance plus developments on at least two dates. Full architecture: [`email-digests.md`](notes/docs/homelab/email-digests.md).
The first section run collects the snapshot (~40 s, ~0.6 GB mostly GKG) into `~/digests/.attention-snapshot/<edition>/` (not backed up; three editions kept); later sections reuse it; unavailable or `partial` sources get at most three attempts within four hours. Matching is local; Jev calls are batched (8 documents per request), bounded by the phase deadline, and share one client per section, so after three consecutive failed requests every remaining adjudication and importance call fails fast (`breaker_open`). The GDELT DOC API is no longer called.
Snapshot collection plus Jev calls are capped by the 900-second attention allowance per category; `DAILY_NEWS_OFFLINE=1` skips all network and Jev use. `scripts/analyze_daily_news_attention.py` compares applied priority against an editorial-only baseline.
The 2026-09-07 Media Cloud pilot (key in `~/.local/state/daily-news/mediacloud-api-key`) was not adopted. Coverage, sharing, discussion, and interest stay separate channels in the evidence; none is an LLM-inferred popularity score.
The Daily News service is ordered after `homelab-steward.service`; a steward overrun delays rather than overlaps the 2:00 AM digest start.
Reader-facing headlines are always English: Phase 4 preserves English headlines and faithfully translates non-English source headlines. Category pages start with Latest; standfirsts remain publication metadata and are not repeated as an In Brief block or in email. The email lists only the selected front-page headlines and links to that edition.
Models: primary and critic `deepseek-v4.1-flash`; fallback `mimo-v2.5`, kept after the 2026-09-24 `glm-5.3-flash` latency evaluation. Each direct OpenCode Go call sends one `x-opencode-session` UUID and reuses it across that call's bounded retries; `omp -p` calls get stdin `/dev/null`.
One shared five-day recent-coverage ledger (canonical URLs) dedups across all five sections; the front page dedups canonical URLs and same-event stories before choosing section leads, and the email uses the same selection. Developing and Ongoing cards show the newest verified source (`latest_source`) or are withheld. Publishing fails closed: a workflow-state failure keeps the prior durable publication or omits the section, never publishes rendered HTML, and logs `WARN  publish degraded sections` in `~/digests/.digests.log`.
Daily News alone uses an explicit Codex-primary, SearXNG-fallback OMP `web_search` chain via `~/.omp/agent/daily-news-headless.yml`; the shared `~/.omp/agent/headless-override.yml` remains provider-neutral for steward, Hyperliquid, Dependabot, and ad hoc headless runs. SearXNG fallback health is monitored with `categories=news&time_range=day` but does not block successful primary-provider research. An unfiltered general search is not sufficient because the working general engines do not currently honor the day filter.
Phase 1 records search evidence without opening articles; Phase 4 verifies queued sources with the public-HTTPS `read` tool. `digest_runner.py --test` routes mutable caches, attention observations, and search-health logs under `~/digests/test/`, never their production paths.
Each topic run records attempt-owned, hash-validated phase state in `workflow-state.sqlite3`; source/policy mutation aborts at phase boundaries, and stateful publications are accepted only when Phase 8's recorded path/hash/schema match. Run `bash ~/scripts/verify-daily-news.sh full` after changes; GitHub CI (`.github/workflows/scripts-ci.yml`) also runs the four offline verifiers (daily-news, steward, dependabot-intake, hyperliquid-guard) in full mode on every dotfiles push and PR.

`run_all_digests.sh` runs `digest_runner.py --preflight` before any research; missing load-bearing constants/contracts must fail immediately. If an edition is absent, inspect `systemctl --user status digests-daily.service`, then `journalctl --user -u digests-daily.service` and `~/digests/.digests.log`. The 2026-08-27 missed edition was a code regression (`CROSS_DAY_DEDUP_DAYS` removed by an automated audit fix), not an OpenCode subscription failure; 429s on the optional Zen free-model endpoint caused extra fallthrough attempts but did not indicate exhausted Go quota.

## Homelab Steward

Daily maintenance at midnight ET via `homelab-steward.timer` (`~/scripts/steward_runner.py`) on the ThinkPad. Its deterministic remote branch connects only through pinned `gamingrig-linux`: Linux runs the approved apt, Herdr, and OMP maintenance with smoke/rollback and health gates; a Windows skip requires trusted local `llm-proxy` `/health` corroboration (`rig_os=windows`), while offline skip is limited to recognized timeout/refusal/no-route/unreachable transport failures; auth/config/unknown/host-key failures are failures. A required reboot re-arms Linux BootNext, requires a changed boot ID, and polls bounded full readiness/health before reporting reboot, return, or recheck. The steward is never installed on the rig. P7b application fixes run in an isolated `steward-worker` service with no Carter home, credentials, Docker/systemd/sudo, or general network access; validator/judge and review-ref gates passed in the live boundary smoke. SearXNG and Linux llama.cpp releases auto-deploy only after a 7-day upstream soak and attempt rollback when post-update checks fail. The llama helper reports `ROLLBACK_FAILED` when its own recovery validation fails; any failed recovery requires manual inspection. **Safety rules:** never `dist-upgrade` or `aa-remove-unknown`; upgrade Docker only through apt, never manual binary replacement; assert `DockerRootDir=/var/lib/docker` after Docker upgrades; record failures in durable artifacts and email badges rather than aborting later reporting.
Autonomy: P1 applies guarded updates and deploys (latest Open WebUI, blog and herdr-web-client `app_deploy`, canonical OMP) with automatic rollback, and P7b routes every confirmed finding—doc fixes and cleanups are committed with an undo command, code fixes become PRs, and everything else lands in the email's Needs You block.
Steward PRs auto-merge (`gh pr merge --auto --rebase`, never `--admin`) only in blog, hyperliquid, herdr-web-client, and delta_neutral, each gated by an active `steward-auto-merge-gate` ruleset requiring its real CI checks (admin bypass keeps direct pushes, including the Dependabot publisher's, working), `allow_auto_merge`, and 5 green default-branch push runs. The same gate lets P1 `dependabot_merge` queue green, mergeable, non-major Dependabot PRs in those repos, except dependabot/bundler/* in blog and delta_neutral (the dependabot-webhook owns them) and all of hyperliquid (its own agent); major bumps are listed for Carter.
The executable is a thin entrypoint over `~/scripts/steward/`; each run uses attempt-owned, hash-validated SQLite workflow state and a fixed startup source/policy fingerprint. Unexpected source or policy changes abort. P7b changes to fingerprinted executable source are the controlled exception: P7b completes its validated fix artifact, the service re-execs under the new source, validates the exact setup/fixes handoff, and resumes at P8; fingerprinted policy/config changes still fail closed. P1 nested failure packets remain retryable failed state while independent phases continue; P8 SMTP errors fail the phase. Run `bash ~/scripts/verify-steward.sh full` after changes.
P7 caches only a provenance-valid PASS on unchanged evidence; unresolved or inconclusive sections run again rather than carrying a pre-fix result forward. Audit judges refer to steward-owned finding IDs, retry invalid output once, and any remaining judge failure is reported as steward automation trouble rather than an underlying service failure or a task for Carter.
Every steward model call passes an explicit tool set (`_call_omp_p(tools=...)` rejects anything else): `--no-tools` with evidence inlined for P0b, P5, P7 judges, P8 summaries/TL;DR, and the P7b doc-fix re-check; read-only `read,grep,glob` for P7 audit workers and the P3 troubleshooter. P3's LLM only diagnoses (likely cause and next steps); code then offers a fixed fix menu per regressed endpoint (restart the mapped unit/container, Docker, or cloudflared, or none), Jev picks one, and code runs it only at confidence ≥ 0.8 with fixed argv (never a shell; max 1 per endpoint, 3 per night), then re-validates. P9b and P9c use Jev, not an LLM, for their decisions; the steward's Jev evidence is secret-scanned before sending. P3a is report-only: UFW drift against `~/system-config/ufw-expected-rules.txt`, orphaned docker-proxy ports, and the Open WebUI→8082 probe go to the email's Host drift block; it never changes UFW or kills/removes anything.

## Failure alerts

`notify-failure@.service` (`~/scripts/notify-failure.sh`) emails the failed unit's last 60 journal lines, at most one mail per unit per hour with a suppressed count (state `~/.local/state/notify-failure/`). Units reach it via `OnFailure=notify-failure@%n.service`: digests-daily, hyperliquid-sdk, cleanup-rig-requests, dependabot-webhook, homelab-steward, homelab-steward-resume, homelab-backup, homelab-backup-restore-drill, and (as `<unit>.service.d/notify-failure.conf` drop-ins, because release scripts own the base units) llm-proxy, opencode-go-proxy, prompt-guard, comfy-web, rig-dashboard, herdr-web-client. Never wire it or a StartLimit onto herdr-server. Test: `systemctl --user start notify-failure@review-test.service` (unknown unit → TEST subject).

## Agent CLI: omp

The ThinkPad's sole agent CLI is **omp** (`@oh-my-pi/pi-coding-agent`; one canonical standalone binary at `~/.bun/bin/omp`, with `~/.local/bin/omp` a symlink to it—never install a second copy (no `bun add -g` on the ThinkPad), since mixed versions likely corrupted `~/.omp/agent/agent.db` on 2026-09-23; config in `~/.omp/agent/`). Policy: one install per host, always the latest release. Steward P1 snapshots the pre-update binary to `~/.local/state/omp-rollback/omp-<version>` (last two kept) and rolls back by restoring that file (`install -m 755 <snapshot> ~/.bun/bin/omp`); after a successful version change the isolated P7b worker copy `/usr/local/libexec/steward-worker/omp` is re-provisioned from the canonical binary and must report the same version. The gaming rig runs its own single Bun package install for rig-local development, with rig-local OMP state and the safe `omp --allow-home` wrapper; never copy ThinkPad OMP state or credentials. Headless ThinkPad runs (`omp -p`) normally pass `--config ~/.omp/agent/headless-override.yml`; Daily News tool calls use `daily-news-headless.yml`, which preserves the same advisor-off and foreground-only (no async/auto-background) settings while isolating its search-provider chain. What uses omp, auth/models, remote ops, reboot protocol: [`omp-agent-cli.md`](notes/docs/homelab/omp-agent-cli.md).

## Remote Agent Operations

Carter's browser attachment is **Herdr Web Client** (browser title **Herdr Web**) at `remote.carter2099.com`; source is `github.com/carter2099/herdr-web-client` in `~/dev/herdr-web-client`, and production uses `herdr-web-client.service`. It connects to the live Herdr server instead of maintaining a separate web-owned OMP session store. OMP Web and `omp.carter2099.com` were retired on 2026-08-31. SSH details, `XDG_RUNTIME_DIR`, reboot protocol, `~/agent-state/pending.md` startup check: [`omp-agent-cli.md`](notes/docs/homelab/omp-agent-cli.md)

## Persistent Memory (`~/notes/`)

The `~/notes/` vault is the homelab's long-term knowledge base — a standalone git repo of reference notes, session memoirs, and cross-referenced context.

### For agents

**Before starting work on a known topic**, grep the vault for relevant context:
```bash
rg -l "search term" ~/notes/
```
This is opt-in — only do it when past context would materially help the current task. Don't load entire files into context preemptively.

**After significant sessions**, write a brief session memoir. "Significant" means: architectural decisions, system state changes, or context a future agent would need. Routine checks and quick Q&A don't need one.

### Session memory bank (`~/notes/logs/sessions/`)

The steward (P0b, nightly) maintains this bank from interactive omp sessions — it writes
missing memoirs, judges/updates agent-written ones against the source transcript, and
filter-skips test/dead-end sessions (LLM judge, fail-open). Long transcripts are read in
≤24k-char chunks (map, merge, reduce) instead of being truncated; a stale memoir is extended
from the later part of its session, and memoirs carry an `updated:` frontmatter line. P7 audit workers + judges and
the email TL;DR writer receive recent memoirs as context.

Location + format — one compact `.md` per interactive omp session, in a per-day folder:

```
~/notes/logs/sessions/YYYY-MM-DD/<HHMM>-<slug>.md
```

```markdown
---
title: <short topic>
source: <absolute path to the omp session jsonl — REQUIRED>
session_id: <omp session uuid — REQUIRED>
project: <sessions subdir, e.g. - or -dev>
date: YYYY-MM-DD
---
# Session: YYYY-MM-DD HH:MM — <title>
**Topics:** comma-separated list
**Decisions:**
- decision 1
- decision 2
**State changes:**
- what was modified on the system
**Context for next time:** 1-2 sentences a future agent should know
```

Agents writing a memoir during a session MUST include `source:` and `session_id:` — read
them from the session jsonl header (the `{"type":"session"}` line in
`~/.omp/agent/sessions/<project>/<ts>_<uuid>.jsonl`). That's how the steward matches
sessions and judges existing memoirs. Keep the body compact: the source transcript is the
source of truth, the memoir is the pointer + durable context.

**Session dirs:** interactive omp sessions live in `~/.omp/agent/sessions/<project>/`
(project-scoped subdirs). Headless invocations MUST pass
`--session-dir ~/.omp/agent/sessions-automated/` — the steward's session-memory filter
relies on this separation and misses sessions that leak into the wrong dir.

Session memoirs are NOT formal notes — don't use `/note-save` or full frontmatter for them.
They're quick context dumps for cross-session continuity. Formal reference notes use
`/note-save` when the user explicitly asks.

### Vault structure

- `~/notes/INDEX.md` — index of all formal reference notes (maintained by `/note-save`)
- `~/notes/docs/` — maintained reference docs (subsystem architecture and runbooks)
- `~/notes/logs/sessions/` — session memory bank (YYYY-MM-DD/ folders, one compact .md per interactive omp session, frontmatter `source:` pointer; maintained by the steward P0b)
- `~/notes/journal/` — research notes and project records (not maintained)
- The vault is a standalone git repo (not the dotfiles bare repo) — `/note-save` handles commits

## Gaming Rig (Linux inference + focused development / Windows gaming)

The dual-boot rig is the Linux inference/development host and Windows gaming machine. The
ThinkPad remains the sole notes, documentation, infrastructure, and production authority:
develop under `/home/carte/dev/<repo>`, transfer code through GitHub, and never deploy
production, copy authoritative state, or run Kubernetes on the rig.

Rig host security: UFW default-deny inbound; 22/tcp only from 192.168.4.92, .100 and Carter's Mac .77; llama-swap 8080/tcp only from .92 and .100. sshd is key-only via `/etc/ssh/sshd_config.d/10-hardening.conf` (sorts before `50-cloud-init.conf`). Canonical copies: `~/system-config/gamingrig-linux/ufw/rig-ufw-rules.sh` and `~/system-config/gamingrig-linux/sshd_config.d/10-hardening.conf`.

- [`local-llm-gaming-rig.md`](notes/docs/homelab/local-llm-gaming-rig.md) — host topology,
  inference/models, proxy/dashboard, Windows/Apollo driver constraints, boot switching,
  steward maintenance, and the verified isolated recovery path.
- [`environment.md`](notes/docs/homelab/environment.md) — development/tooling conventions,
  canonical configuration map, SSH/trust boundary, serving-build exception, and state
  exclusions.

Reusable local-model comparisons live in `~/dev/local-model-bench/`
(`carter2099/local-model-bench`, private). The frozen EvalScope-led suite covers
instruction following, reasoning, executable Python, and native tool calling;
quality and 30-second latency profiles stay separate. Its rig supervisor uses
temporary servers, stops before steward maintenance, and restores production
without changing serving configuration. Usage and caveats:
[`Reusable local-model benchmark`](notes/docs/homelab/local-llm-gaming-rig.md#reusable-local-model-benchmark).

## Environment

ThinkPad shell zsh (vim bindings), nvim, rbenv, fnm, tmux (Ctrl+Space), git carter2099, `gh`
authed: [`environment.md`](notes/docs/homelab/environment.md). The rig's shell/tooling,
OMP/Herdr, SSH, and state exclusions are documented there too. **Client topology:** Carter
develops from a Mac — `/Users/carterbrown/...` paths are NOT reachable from this session.

## Where the deep dives live

Verbose architecture for subsystems an agent only needs when actively working on them. These are in `~/notes/docs/homelab/` and `~/notes/journal/` (standalone vault repo, grepped on-demand):

- [`hardware.md`](notes/docs/homelab/hardware.md) — hardware specs, network config
- [`local-llm-gaming-rig.md`](notes/docs/homelab/local-llm-gaming-rig.md) — llm-proxy / llama-swap topology, models, env vars, troubleshooting
- [`omp-agent-cli.md`](notes/docs/homelab/omp-agent-cli.md) — omp CLI facts, what uses omp, auth/models, remote ops, reboot protocol
- [`environment.md`](notes/docs/homelab/environment.md) — shell/editor tooling, git/gh, client topology
- [`deployment.md`](notes/docs/homelab/deployment.md) — deploy flow, port-in-use, exit 255, aa-remove-unknown
- [`homelab-dashboard.md`](notes/docs/homelab/homelab-dashboard.md) — public monitor dashboard: sources, security model, release/verify, runbook
- [`freshrss.md`](notes/docs/homelab/freshrss.md) — FreshRSS Docker Compose stack, backup, updates, rollback
- [`k3s.md`](notes/docs/homelab/k3s.md) — k3s retirement record (stopped 2026-09-25, uninstall pending)
- [`email-digests.md`](notes/docs/homelab/email-digests.md) — Daily News significance/attention/priority scoring, front page, standfirsts, R2 backup, delivery, audit/debug
- [`homelab-steward.md`](notes/docs/homelab/homelab-steward.md) — steward phases, session memory, audit/fix loop, work queue, and debugging
- [`homelab-backup.md`](notes/docs/homelab/homelab-backup.md) — 34-target `current-v5` manifest taxonomy (schema v2; older archives verify against their own embedded manifests), coordinated Open WebUI freeze/thaw and restore coverage, strict verify/latest/list, restore drill, retention, release, notify/debug
- [`blog.md`](notes/docs/homelab/blog.md) — Rails 8 blog app
- [`beatz.md`](notes/docs/homelab/beatz.md) — public beat archive player, starter/artwork pools, media library, deploy/runbook
- [`hyperliquid-sdk.md`](notes/docs/homelab/hyperliquid-sdk.md) — automated Hyperliquid SDK maintenance
- [`dependabot-webhook.md`](notes/docs/homelab/dependabot-webhook.md) — Go webhook + Prompt-Guard classifier
- [`open-webui.md`](notes/docs/homelab/open-webui.md) — chat frontend, native SearXNG, Weather v2
- [`searxng.md`](notes/docs/homelab/searxng.md) — metasearch backend, config
- [`cloudflare.md`](notes/docs/homelab/cloudflare.md) — API token, tunnel ingress, DNS
- [`opencode-go-proxy.md`](notes/docs/homelab/opencode-go-proxy.md) — multi-account usage API routing, no client auth / UFW gate

`journal/` contains research notes and project records (not maintained). `logs/sessions/` contains chronological session memoirs.

Grep the vault (`rg -l "term" ~/notes/`) before starting work on a known topic; the `~/notes/INDEX.md` lists all formal notes.

Blast radius: after making changes to any code or functionality, anywhere, ask yourself: What else could these changes have broken? Did the blast radius hit anything we did not verify or test?
