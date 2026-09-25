---
description: Reboot the homelab host safely, writing intent + in-flight task context to ~/agent-state/pending.md first so the next session can pick up. Use this instead of raw `sudo reboot`.
---

# homelab-reboot

Safely reboot the homelab host. The only supported way for this agent to reboot — never call `sudo reboot` directly, because the next session won't know why the machine went down.

## Required input

- **reason** (string): short human-readable explanation (e.g. "kernel update", "docker daemon wedged", "scheduled maintenance"). If the user didn't give one, ask before proceeding.

## Steps

1. **Summarize in-flight work.** Write a short paragraph (2-4 sentences) describing what was being worked on when the reboot was requested — which app, what was the last action, what the user was trying to accomplish. If nothing substantive was in flight, say so explicitly.

2. **Write the state file.** Create `~/agent-state/pending.md` with this structure:

   ```markdown
   # Pending reboot context

   - **Timestamp (UTC):** <output of `date -u -Iseconds`>
   - **Reason:** <reason argument>

   ## In-flight work

   <the summary paragraph>

   ## Next steps

   <if the user specified anything they want the post-reboot session to do, list here; otherwise "Awaiting user"> 
   ```

   Use `date -u -Iseconds` for the timestamp. Overwrite any existing `pending.md`.

3. **Confirm with the user.** Before issuing the reboot, show them the state file contents and ask for explicit confirmation. This is a destructive action — do not skip confirmation, even if the user seems to have already said yes, unless they explicitly said something like "reboot now, no confirmation".

4. **Reboot.** Run `sudo systemctl reboot`. The session will drop immediately. When the user opens a new session, the startup-check in `AGENTS.md` will surface the state file.

## Safety notes

- The passwordless sudoers entry for `reboot` is scoped narrowly. If `sudo systemctl reboot` prompts for a password, the sudoers config wasn't installed — tell the user instead of blocking.
- If a long-running background task is in flight (e.g. a build that's been running for 10+ min), mention that in the confirmation and let the user decide whether to wait.
