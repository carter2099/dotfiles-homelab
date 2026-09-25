---
description: Deploy a homelab app (blog, hub, stickies) by running its release.sh, then verify the container is healthy. Handles the orphaned docker-proxy recovery recipe automatically.
---

# deploy-app

Deploy one of the self-hosted apps via its standard `release.sh` → `up.sh` pipeline.

## Required input

- **app** (string): one of `blog`, `hub`, `stickies`. (Do not deploy `tbitt` — it's deprecated per `AGENTS.md`.)

## Pre-flight: is a deploy actually warranted?

**Before running anything**, if the user's motivation is "the site looks wrong" / "feature X is missing" / "shows old UI", do *not* assume a redeploy is the fix. Per AGENTS.md's "Missing feature symptom" section, the near-universal cause is a Cloudflare/browser cache hit while origin is down — and a redeploy *extends* the cache-hit window.

Run this check first:

```
docker ps --filter name=<app>                    # container running?
curl -s http://localhost:<port>/ | grep <feature>  # does origin have the feature right now?
```

- Container running **and** origin serves the feature → the user is seeing cached content. Tell them to hard-refresh (Cmd+Shift+R) or purge CF. **Do not redeploy.**
- Container not running → recover (see step 3 below) *without* a full rebuild; the existing image is likely fine.
- Container running but origin missing the feature → then and only then consider a redeploy (and check whether rebuild actually happened — image `CreatedAt` from `docker images <image>` should be recent).

## Per-app ports (for health check)

| app            | exposed port |
|----------------|--------------|
| blog           | 33099        |
| hub            | 13000 (client), 13001 (api) |
| stickies       | check `~/stickies/docker-compose*.yml` |

## Steps

1. **cd to the app.** `cd ~/<app>`.
2. **Run release.** `bash release.sh` and stream output. This does: `git pull`, `docker compose down`, `docker image rm`, then invokes `../up.sh` or local `up.sh`.
3. **If `up.sh` fails with "address already in use":** apply the orphaned-docker-proxy recipe from `AGENTS.md`:
   - `docker ps -a` — confirm the container shows `Exited`.
   - `ps aux | grep docker-proxy` — find proxy PIDs holding the stuck port.
   - `sudo kill <pids>` — free the port.
   - Retry `bash up.sh`.
4. **Verify health.** After `up.sh` returns successfully:
   - `docker ps --filter name=<app>` — confirm container is `Up`.
   - `curl -sI http://localhost:<port>` — confirm HTTP response (2xx or 3xx is fine; 502/404 means the app started but isn't healthy yet, wait 10s and retry once).
5. **Report.** Summarize: new image digest (`docker image inspect <image> --format '{{.Id}}'`), container uptime, last commit deployed (`git -C ~/<app> log -1 --oneline`).

## Known post-deploy failure mode: exit 255 within ~10 min

Containers on this host occasionally exit 255 shortly after a successful deploy — no stack trace, clean logs, typical of OOM or SIGKILL. See AGENTS.md's "Exit 255 is a known intermittent" section. If a user reports issues in the window just after deploy:

1. `docker ps -a --filter name=<app>` — is it Exited?
2. `docker inspect <container> --format '{{.State.OOMKilled}}'` — was it OOM?
3. Recover by killing any orphan `docker-proxy`, `docker rm` the exited container, then `bash up.sh` — **do not rebuild**; the existing image is almost certainly fine.

Do not chalk repeated exit-255s up to code unless you have evidence (crash logs, OOM flag, error traceback). The right response is a fresh container from the existing image.

## Failure modes to surface clearly

- `git pull` fails: app has no remote configured (`git remote -v` empty). Tell the user; do not attempt to add a remote.
- `RAILS_MASTER_KEY` missing (blog, hub): `config/master.key` is required. Don't try to generate one — this is a credential.
- `release.sh` exits non-zero mid-way: do NOT retry blindly. Surface the error, ask how to proceed.

## Non-goals

This command does not build new images, edit code, or push to git. It's strictly "pull + restart with the current state of the local branch". For code changes, edit files in `~/<app>/` directly, commit (if relevant), then run `/deploy-app`.
