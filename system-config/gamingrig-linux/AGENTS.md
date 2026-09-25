# AGENTS.md

Operational guidance for agents working on `gamingrig-linux`.

## Working principles

- **Read the reference.** Prefer official documentation, local source, and live command output over training-data recall.
- **Read the complete error.** Name the failing command, actual cause, and relevant state before changing anything.
- **Do not guess.** Verify every load-bearing path, version, API, host, and service fact.
- **Keep it simple.** Make the smallest durable change; avoid speculative services and second conventions.
- **Fix causes, not symptoms.** Retries, cache clears, and suppressions are not explanations.
- **Protect shared models.** General-purpose model prompts and runtime messages must remain neutral; never encode benchmark answers or product-specific evaluation rubrics.
- **Verify the real behavior.** Run the changed command, program, or workflow. Compilation alone is not completion.

## Host role

This host is Carter's focused Linux development center and AI inference machine:

- Hostname: `gamingrig-linux`
- LAN address: `192.168.4.103`
- User/home: `carte`, `/home/carte`
- OS: Ubuntu Server 24.04 LTS
- GPU: NVIDIA GeForce RTX 5070
- Development root: `/home/carte/dev/<repo>`
- Windows 11 remains available through the established dual-boot controls.

The existing inference role is load-bearing. Preserve `llama-swap`, NVIDIA/CUDA, model
files and caches, the port-8080 model endpoint, EFI boot entries, Linux-primary `BootNext`,
Wake-on-LAN, and boot-switching services. Never restart, rebuild, upgrade, or retune these
incidentally while doing project work.

## ThinkPad authority

The ThinkPad is `thinkpad` / `tp-server`, `192.168.4.92`, user `carter`. Use only:

```bash
ssh thinkpad
```

The alias pins the ThinkPad host key and uses a dedicated key. Never connect with host-key
checking disabled.

The ThinkPad remains the sole authority for:

- `~/notes/` and all homelab reference documentation
- homelab infrastructure (Docker Compose stacks, systemd units, UFW/system config)
- production application state and deploy directories
- scheduled digests, backups, agents, and the homelab steward
- canonical workstation configuration under `~/system-config/gamingrig-linux/`

Never copy or mirror the notes vault, production trees, infrastructure config, OMP
databases/sessions/authentication, Herdr sessions/logs, Cloudflare credentials, or
deployment credentials onto this host. When authoritative homelab context is needed, read
the relevant ThinkPad file over `ssh thinkpad`; update it on the ThinkPad when the task
requires a durable documentation change.

## Development workflow

- Always develop in `/home/carte/dev/<repo>`.
- Clone GitHub repositories over SSH into that directory.
- GitHub is the normal code-transfer boundary: branch, test, commit, and push from the rig;
  pull the committed revision into the ThinkPad's `~/dev/<repo>` before any production
  deployment.
- Never edit ThinkPad production deploy folders from the rig.
- Follow a repository's own `AGENTS.md` in addition to this file.
- Preserve unrelated working-tree changes; they belong to Carter.
- Use targeted commits. Never commit generated caches, credentials, model files, or
  workstation runtime state.
- Run focused validation first, then the repository's required suite once at the end.

Git identity is `carter2099 <carter2099@pm.me>`. GitHub CLI is installed, but its API
authentication is independent of Git-over-SSH authentication; never copy the ThinkPad's
GitHub token here.

## Decisions in software: use Jev

When software we build needs a model judgment that code will branch on (classify, route,
gate, score, rank, dedupe/match, or verify/guardrail an LLM output), default to TypeSafe's
**Jev**, not an LLM plus output parsing. Jev is a "System One" model: you send a state and
typed questions; it returns typed answers with calibrated probabilities in about 70–500 ms.
Its answers always match the schema. Use an LLM only when the output must be generated
text or code, or when the task needs extended multi-step reasoning. Docs:
<https://docs.typesafe.ai/> (index at `/llms.txt`).

- API: `POST https://api.typesafe.ai/v1/systemone` with `{model, state, questions}`.
  Question types: `Choice` (one of ≤255 options), `Score` (rubric levels), `Noul` (truth of
  a statement, 0–1). Choice and Score also return `confidence`.
- Ask atomic gut-check questions. Break compound judgments into several questions (answered
  in parallel in one request) and combine them in code with explicit weights.
- Gate actions on `confidence` with thresholds scaled to the stakes (act, review, or fall
  back). A Jev failure or low confidence means "unknown", never a default answer. Pin the
  model version and bound timeouts and retries.
- Client: `~/scripts/jev.py` on the ThinkPad (`ssh thinkpad cat ~/scripts/jev.py`).
- No key on the rig; tests inject a fake post. The API key lives only on the ThinkPad;
  never copy it here. Ask Carter if live calls from the rig are needed.

## Platform boundary

This machine is not a homelab application host:

- Never install Kubernetes (the ThinkPad's k3s was retired on 2026-09-25), create a
  kubeconfig, or install cluster deployment automation.
- Never deploy the blog, Beats, Daily News, Open WebUI, SearXNG, FreshRSS, proxy
  services, digests, backups, or other homelab applications here.
- Docker and Compose are for development builds and tests only.
- Long-running project services are temporary development processes, not production.

All production applications remain on the ThinkPad.

## Development environment

- Shell: zsh with vim keybindings and completion
- Editor: Neovim
- Multiplexer: tmux, prefix `Ctrl+Space`
- Node: fnm; initial default `v26.8.1`
- Ruby: rbenv; initial version `4.0.6`
- Go: `/usr/local/go`, with user tools under `/home/carte/go/bin`
- Python: system Python plus project-local virtual environments
- Bun: `/home/carte/.bun/bin/bun`
- Docker Engine and Compose: development only

Prefer each repository's pinned runtime files over these host defaults. Do not globally
change a runtime merely to satisfy one project.

## OMP and Herdr

OMP is installed through Bun at `~/.bun/bin/omp`.

- Default: `opencode-go/deepseek-v4-flash`
- Central cloud proxy: `http://192.168.4.92:8082/v1`, placeholder API key `proxy`
- Rig-local model provider: `http://192.168.4.103:8080/v1`
- State and sessions are rig-local under `~/.omp/`; do not copy ThinkPad history or auth.
- Starting `omp` directly in `/home/carte` automatically adds `--allow-home`; subcommands
  do not.

Herdr is installed at `~/.local/bin/herdr`. Its preferences use the One Dark theme,
`Ctrl+Space` prefix, and agent pane labels. Herdr sessions and logs are runtime state, not
configuration to synchronize.

## Configuration maintenance

Canonical workstation files live on the ThinkPad:

```text
/home/carter/system-config/gamingrig-linux/
```

For persistent shell, editor, SSH-client, OMP, Herdr, or agent-policy changes:

1. Change the canonical ThinkPad file.
2. Deploy the corresponding file to `/home/carte`.
3. Preserve ownership and restrictive SSH/config permissions.
4. Verify the deployed behavior on the rig.

Do not edit only the deployed copy. Do not create a separate notes or dotfiles authority on
the rig.

## Maintenance and privilege

`carte` has passwordless sudo by deliberate policy. Use it only for deterministic host
maintenance and never to bypass a project error.

The ThinkPad's nightly homelab steward maintains this Linux installation through the
pinned `gamingrig-linux` alias. It may apply APT, OMP, and Herdr updates and reboot Linux
when `/var/run/reboot-required` exists. It skips the rig when offline, sleeping, or running
Windows; it never wakes or switches the OS for maintenance. Post-update health requires
SSH, a new boot ID after reboot, NVIDIA, `llama-swap`, the model endpoint, disk capacity,
and no failed units.

Do not install a second steward, notes service, Kubernetes node, or production scheduler
on this host.
