---
description: Manually update Open WebUI to the latest stable release now (install-now / fallback path) with a verified offline data snapshot, integrity checks, and automatic rollback. Use only when the user explicitly asks to update Open WebUI.
---

# Update Open WebUI

Update the production Open WebUI deployment in `~/open-webui/`. Protect chats, the admin account, custom model profiles, tools, uploads, and vector data. This is the manual, explicitly invoked path. The homelab steward's P1 `openwebui_update` step already installs the latest stable release automatically each night (no soak period) with its own snapshots, gates, and rollback. Use this command when the automatic step skipped or rolled back, or to update between nightly runs; check the latest steward report first so you don't repeat a failed target blindly.

## Safety contract

- Use an exact stable version tag. Never deploy `main`, `latest`, a prerelease, or an unverified image.
- Do not change or restart production until the current deployment and database pass preflight checks.
- Pull and verify the target image before downtime.
- Before changing the compose pin, create both a SQLite backup and a restorable offline archive of persistent non-cache data.
- Commit and push the exact compose pin before starting the target image. Commit only the compose path so unrelated staged work is never included.
- Treat a migration error, unhealthy container, data-integrity failure, missing baseline record, wrong version, or failed UI smoke check as a failed upgrade. Roll back both the image pin and persistent data.
- Never delete the recovery snapshot after the update. Report its path.
- Never expose `~/open-webui/.env` contents in output or commit it.

## 1. Resolve and review the target

1. Read `~/open-webui/docker-compose.yml` and `~/notes/docs/homelab/open-webui.md`.
2. Parse the current exact tag from `ghcr.io/open-webui/open-webui:<tag>`.
3. Read the official GitHub `releases/latest` API response. Require `draft=false`, `prerelease=false`, and a numeric stable tag. Read its release notes.
4. Check upstream release notes and open issues for migration, startup, database, authentication, or data-loss regressions affecting the path from the current version. If a known issue is unresolved in the target, stop and report it; do not gamble with production data.
5. If current equals target, verify health and report that no update is needed. Do not restart.
6. Confirm `open-webui/docker-compose.yml` has no unrelated local change. Preserve unrelated repository work and never use `dotfiles add -A`, `dotfiles add .`, or an unscoped commit.

## 2. Preflight the current deployment

Require all of these before proceeding:

- `open-webui` is running and Docker reports `healthy`.
- `http://127.0.0.1:48100/api/version` matches the compose pin.
- `PRAGMA quick_check` on `/var/lib/docker/volumes/open-webui_open-webui/_data/webui.db` returns exactly `ok`.
- Record the current image ID, image digest, container start time, Alembic version, database SHA-256, table counts, and primary-key sets or hashes.
- At minimum, preserve invariants for `user`, `auth`, `chat`, `chat_message`, `config`, `model`, `tool`, `file`, `folder`, `knowledge`, and every other existing table. Do not print private row contents.
- Record exact row hashes for custom `model` and `tool` rows so profile/tool corruption is detectable.
- Confirm there is enough free space for the target image and a non-cache copy of the persistent volume.

Create a mode-700 recovery directory:

```text
~/backups/open-webui-upgrades/<UTC timestamp>-<current>-to-<target>/
```

Save preflight metadata there as JSON. Copy the current compose file as `docker-compose.yml.pre` and the secret env file as `.env.pre`, both mode 600. The env copy is recovery material only and must remain untracked.

## 3. Preload the target image

Pull `ghcr.io/open-webui/open-webui:<target>` while the old container is still serving. Verify:

- the image label reports the target version;
- the repository digest exists;
- Docker can inspect the image successfully.

Record the target image ID, digest, and upstream revision in the recovery directory. A pull or identity mismatch ends the run without downtime.

## 4. Create the recovery snapshot

1. While the old container is still running, use SQLite's `.backup` command to create `webui-live.db` in the recovery directory. Verify `PRAGMA integrity_check` on that copy.
2. Stop only the `open-webui` service with Docker Compose. Do not remove the volume.
3. With the database quiesced, run `PRAGMA wal_checkpoint(TRUNCATE)` and then `PRAGMA integrity_check`. The latter must return exactly `ok`.
4. Use SQLite `.backup` again to create `webui-offline.db`.
5. Create `data-critical.tar.gz` from `/var/lib/docker/volumes/open-webui_open-webui/_data/`, preserving ownership, ACLs, and xattrs. Exclude only the rebuildable `cache/` directory and pre-existing `*.bak` files. The archive must include `webui.db`, `uploads/`, `vector_db/`, and any future non-cache persistent paths.
6. Verify the archive can be listed and extracted. Run `PRAGMA integrity_check` against the database extracted from the archive. Compare its table counts and record identities with the preflight baseline.
7. Chown recovery artifacts to Carter, retain mode 600 for secrets/database copies, and write snapshot verification results to JSON.

If any snapshot gate fails, restart the unchanged old container, verify it is healthy, and stop. Do not edit the compose pin.

## 5. Commit the target pin, then deploy

1. Change only the image tag in `~/open-webui/docker-compose.yml`.
2. Stage only `open-webui/docker-compose.yml` in the dotfiles bare repo.
3. Commit only that path, even if other files are already staged:

```bash
~/.local/bin/dotfiles add open-webui/docker-compose.yml
~/.local/bin/dotfiles commit --only -m "open-webui: update to <target>" -- open-webui/docker-compose.yml
~/.local/bin/dotfiles push
```

4. Only after the commit and push succeed, run `docker compose up -d` from `~/open-webui/`.
5. Wait up to three minutes for `running` and `healthy`. Fail immediately if the container exits, restarts repeatedly, or reports unhealthy.
6. Read all container logs since the new start time. Any migration exception, traceback, missing table/column error, or application-startup failure is a rollback trigger. Do not mistake a migration failure followed by process startup for success.

## 6. Verify the upgraded application

All gates are required:

- The running image tag, image ID, `/api/version`, and startup banner all report the target version.
- `/api/config` returns `status: true`, the expected Homelab Chat name, authentication enabled, signup disabled, and the target version.
- Docker remains healthy after startup settles.
- A post-upgrade SQLite `.backup` passes `PRAGMA integrity_check`.
- Every baseline table still exists. No baseline table count decreases. All baseline primary keys for users, auth, chats, chat messages, config, models, tools, files, folders, and knowledge remain present.
- Custom `model` and `tool` row hashes remain unchanged unless the release notes explicitly document a required migration; investigate any difference rather than accepting it.
- The upload and vector-data paths remain present.
- Browser-drive `http://127.0.0.1:48100` and verify the real page renders the Homelab Chat sign-in surface. Do not request or use the user's password. Existing authenticated HTTP activity may provide additional evidence, but never create or delete a chat merely as a smoke test.
- Re-read post-start logs for delayed errors.

Write post-upgrade verification results into the recovery directory.

## 7. Roll back on any failed gate

Rollback is automatic; do not ask whether to protect the data.

1. Stop the target container.
2. Best-effort archive its failed non-cache state for diagnosis.
3. Restore `docker-compose.yml.pre`, commit only that path as `open-webui: roll back to <current>`, and push before restarting the old image.
4. Preserve `cache/`. Move every other current top-level volume entry aside into a timestamped failed-state directory; do not use an unscoped `rm`.
5. Extract `data-critical.tar.gz` back into the volume with its recorded ownership, ACLs, and xattrs. Remove stale `webui.db-wal` and `webui.db-shm` only if they were not part of the verified snapshot.
6. Start the old exact image and require its original version, healthy state, successful database integrity check, and all preflight invariants.
7. Report the failed target, precise failed gate, rollback result, and both recovery paths. Never describe a rolled-back run as updated.

## 8. Report success

Report concisely:

- version transition and exact image digest;
- compose commit hash and push result;
- recovery snapshot path and what it contains;
- database integrity result and critical before/after counts;
- migration-log result, Docker health, API version, and browser smoke result;
- any non-fatal warnings that need follow-up.

Do not remove the old image or recovery snapshot during this command.
