---
description: Tail logs for a k3s-hosted service (Traefik or FreshRSS). Thin wrapper around kubectl logs that handles namespace + label lookup so you don't have to remember them on mobile.
---

# k-logs

Tail logs from a k3s service. Saves typing `kubectl logs -n <ns> -l app=<x> --tail=N` on mobile.

## Required input

- **service** (string): one of the live third-party k3s services: `traefik` or `freshrss`.
- **lines** (int, optional): how many lines to tail. Default 100. Cap at 500 for mobile readability.

## Steps

1. **Find the namespace + label.** Run `k get pods -A -l app=<service>` to locate the pod. If the label doesn't match (some charts use `app.kubernetes.io/name`), try `k get pods -A | grep <service>` and infer.
2. **Tail.** `k logs -n <ns> -l <label>=<service> --tail=<lines>`. If multiple pods match (e.g. DaemonSet), the output is interleaved — that's expected.
3. **Report.** Output the tail directly. If it's >500 lines or very noisy, suggest filters (e.g. `| grep ERROR`) rather than dumping.

## When to not use this

- Host-Docker apps (blog, hub, stickies, tbitt) — those are in Docker Compose, not k3s. Use `docker logs <container>` instead.
- When you need to follow logs indefinitely. This slash command is for a one-shot tail. For `-f` follow mode, just call `k logs ... -f` directly; don't invoke `/k-logs`.
