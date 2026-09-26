#!/usr/bin/env python3
"""
Homelab Steward — nightly deterministic Python orchestrator.
Replaces update-check + agents-md-audit. Adds work queue.

Scheduled via homelab-steward.timer. Each phase writes a durable artifact and
validated WorkflowState row; failed rows are never resumable.
"""

import argparse
import hashlib
import html
import json
import os
import re
import shlex
import subprocess
import sys
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── constants ────────────────────────────────────────────────────────

HOME = Path.home()
RUN_DIR_BASE = HOME / "digests" / "steward"
TEMPLATE_PATH = RUN_DIR_BASE / "template.html"
RUNS_LOG = RUN_DIR_BASE / ".runs.jsonl"
GH_API = "https://api.github.com/repos/open-webui/open-webui/releases/latest"
OPENWEBUI_COMPOSE = HOME / "open-webui" / "docker-compose.yml"
DIGEST_SCRIPT = HOME / "scripts" / "send_digest.py"
SESSION_DIR = HOME / ".omp" / "agent" / "sessions-automated"
IDEAS_DIR = HOME / "ideas"
PLANS_DIR = HOME / "plans"
AUTO_PKGS = [
    "docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin",
    "docker-compose-plugin", "cloudflared",
]
ENDPOINTS = {
    "open-webui": "http://127.0.0.1:48100",
    "blog": "http://127.0.0.1:33099",
    "llm-proxy": "http://127.0.0.1:8081/health",
    "searxng": "http://127.0.0.1:8080/search?q=healthcheck&format=json",
    "news": "http://127.0.0.1:30144/healthz",
    "freshrss": "http://127.0.0.1:30149/i/",
}
STEWARD_MODEL = "opencode-go/deepseek-v4.1-flash"
STEWARD_PATH = "/home/carter/.rbenv/shims:/home/carter/.rbenv/versions/4.0.6/bin:/home/carter/.local/bin:/home/carter/.bun/bin:/home/carter/.local/share/fnm:/home/carter/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Resolve fnm default node bin for PATH (if available)
_FNM_NODE_DIRS = sorted(
    (d for d in (HOME / ".local/share/fnm/node-versions").glob("*/installation/bin")
     if (d / "node").exists()),
    key=lambda d: d.stat().st_mtime if d.exists() else 0,
    reverse=True)
if _FNM_NODE_DIRS:
    STEWARD_PATH = f"{_FNM_NODE_DIRS[0]}:{STEWARD_PATH}"
PROXY_HEALTH = "http://localhost:8082/health"
MAX_WORKERS = 3
# P7b fix↔judge loop: re-fix judge-not-ok items up to N times (env override).
FIX_MAX_ITERS = max(1, int(os.environ.get("STEWARD_FIX_MAX_ITERS", "3")))
P7B_REPORT_ONLY_SECTIONS = {"version-currency", "security-posture"}
# P7 audit fan-out is capped separately; P7b already serializes on the worker lock.
AUDIT_MAX_WORKERS = 2

# Finding schema v2: the audit worker proposes, the judge confirms, and
# steward.routing validates every finding against this deterministic table.
FINDING_ACTIONS = (
    "code_fix", "doc_fix", "deploy", "version_update", "cleanup",
    "needs_carter", "report_only",
)
FINDING_SEVERITIES = ("high", "medium", "low")
LOW_DEFAULT_SEVERITY_SECTIONS = {"version-currency", "docs-accuracy"}
DOC_FIX_ROOTS = (HOME / "notes" / "docs",)
DOC_FIX_FILES = (HOME / "AGENTS.md",)
CLEANUP_PATTERNS = ("nltk_data/", ".omp/agent/custom-session-files/")
# Services the P1 app-deploy step may ship when production is behind a
# CI-green origin default branch. The deploy script owns health and rollback.
DEPLOY_REGISTRY = {
    "blog": {
        "repo": HOME / "dev" / "blog",
        "github": "carter2099/blog",
        "production": HOME / "blog" / "blog",
        "deploy": ["bash", str(HOME / "dev" / "blog" / "deploy" / "deploy.sh")],
        "timeout": 1800,
    },
    # release.sh builds the canonical checkout's HEAD, installs the binary and
    # user unit, restarts herdr-web-client.service (never herdr-server), and
    # restores the prior pair if it does not become ready.  The binary reports
    # the source commit it was built from.
    "herdr-web-client": {
        "repo": HOME / "dev" / "herdr-web-client",
        "github": "carter2099/herdr-web-client",
        "version_cmd": [str(HOME / ".local" / "bin" / "herdr-web-client"), "--version"],
        "deploy": ["bash", str(HOME / "dev" / "herdr-web-client" / "deploy" / "release.sh")],
        "timeout": 1800,
    },
}
VERSION_REGISTRY = {"searxng", "llama.cpp", "open-webui"}
# Steward code PRs may auto-merge only for these repos, and only after the
# live branch-protection, auto-merge setting, and recent-CI checks pass.
AUTO_MERGE_CANDIDATES = {"blog", "hyperliquid", "herdr-web-client", "delta_neutral"}
# P1 Dependabot merge: repos whose dependabot/bundler/* PRs belong to the
# dependabot-webhook, and repos whose Dependabot PRs belong to their own agent.
DEPENDABOT_WEBHOOK_BUNDLER_REPOS = {"blog", "delta_neutral"}
DEPENDABOT_AGENT_OWNED_REPOS = {"hyperliquid"}
GITHUB_OWNER = "carter2099"
# Names are matched against both the local checkout name and the GitHub repo
# name (the dotfiles bare repo is ~/.dotfiles-homelab locally).
AUTO_MERGE_EXCLUDED = {
    ".dotfiles-homelab", "dotfiles-homelab-private", "llm-proxy", "opencode-go-proxy",
    "dependabot-webhook", "prompt-guard", "homelab-backup",
}
# P9b pushes only to this private GitHub repository.
DOTFILES_REPO = "carter2099/dotfiles-homelab-private"

# P7b code repairs are delegated to the separately provisioned
# ``steward-worker`` identity.  The helper is root-owned and validates every
# request; this process never falls back to Carter's OMP/home context.
STEWARD_WORKER_HELPER = Path(
    os.environ.get("STEWARD_WORKER_HELPER", "/usr/local/libexec/steward-worker-run")
)
STEWARD_WORKER_POLICY_VERSION = "steward-worker-v1"

PENDING_PATH = HOME / "agent-state" / "pending.md"
DEPENDABOT_UNIT = "dependabot-webhook.service"
UPDATE_MIN_AGE_DAYS = 7
SEARXNG_TAGS_API = (
    "https://hub.docker.com/v2/repositories/searxng/searxng/tags"
    "?page_size=100&ordering=last_updated"
)
LLAMA_CPP_RELEASES_API = (
    "https://api.github.com/repos/ggml-org/llama.cpp/releases?per_page=100"
)
LLAMA_CPP_UPDATE_SCRIPT = HOME / "scripts" / "update_llama_cpp_remote.sh"
 
# Remote gaming-rig maintenance is deliberately isolated from local P1
# mutations.  The SSH config owns the host/IP and known-hosts pin; never
# replace this alias with an address or disable host-key verification.
RIG_SSH_ALIAS = "gamingrig-linux"
RIG_SSH_CONNECT_TIMEOUT = 10
RIG_SSH_COMMAND_TIMEOUT = 120
RIG_REBOOT_WAIT_TIMEOUT = 180
RIG_BOOT_ENTRY = "0001"
RIG_DISK_MAX_PERCENT = 95
RIG_APT_TIMEOUT = 900
RIG_UPDATE_TIMEOUT = 600
RIG_MODEL_ENDPOINT = "http://192.168.4.103:8080/v1/models"
RIG_REQUIRED_MODEL_IDS = (
    "qwen-3.8-27b-iq2",
    "ornith-1.0-35b-q8",
    "ornith-1.0-9b-q6",
    "gemma-4-12b-q6",
    "gemma-4-26b-q8",
    "bonsai-2-27b-pq2",
)
# Resolves to libnvidia-ml.so.<driver version>; readable without the kernel module.
RIG_NVIDIA_ML_LIBRARY = "/usr/lib/x86_64-linux-gnu/libnvidia-ml.so.1"
RIG_REMOTE_PATH = (
    "/home/carte/.rbenv/shims:/home/carte/.bun/bin:/home/carte/.local/bin:"
    "/home/carte/.local/share/fnm:/home/carte/go/bin:"
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

# Session memory (P0b) — interactive omp sessions documented into the notes vault
SESSION_INTERACTIVE_DIR = HOME / ".omp" / "agent" / "sessions"   # interactive: project-scoped subdirs
SESSION_MEMOIR_DIR = HOME / "notes" / "logs" / "sessions"        # memory bank: YYYY-MM-DD/<HHMM>-<slug>.md
SESSION_ACTIVE_MINUTES = 15        # skip sessions still being written (document next night)
SESSION_MEMORY_CONTEXT_DAYS = 2    # P7 workers/judges + TL;DR context window
SESSION_MEMORY_CONTEXT_MAX = 8000  # chars, bounded


SECRET_PATTERNS = [
    re.compile(r".*api-token.*"),
    re.compile(r".*\.env$"),
    re.compile(r".*\.env\..*"),
    re.compile(r".*master\.key$"),
    re.compile(r".*auth\.json$"),
    re.compile(r".*\.pem$"),
    re.compile(r".*id_rsa.*"),
    re.compile(r".*id_ed25519.*"),
    re.compile(r".*\.ovpn$"),
    re.compile(r".*credentials\.json.*"),
    re.compile(r".*\.htpasswd.*"),
]
WORKFLOW_POLICY_VERSION = "steward-policy-p9b-workflow-state-v1"
WORKFLOW_SCHEMA_VERSION = 2

# ── default template ─────────────────────────────────────────────────

DEFAULT_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0; padding:0; background-color:#f4f4f7; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif; color:#2a2a36;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f4f7; padding:24px 0;">
<tr><td align="center">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px; width:100%; background-color:#ffffff; border-radius:10px; overflow:hidden; box-shadow:0 2px 10px rgba(20,20,40,0.06);">
<!-- Header -->
<tr><td style="background-color:#1a1a2e; padding:26px 32px;">
<h1 style="margin:0; color:#ffffff; font-size:20px; font-weight:600; letter-spacing:0.2px;">Homelab Steward</h1>
<p style="margin:6px 0 0; color:#b8b8d0; font-size:13px;">{{DATE}}</p>
</td></tr>
<!-- Summary -->
<tr><td style="padding:22px 32px 14px;">
<p style="margin:0; color:#2a2a36; font-size:14px; line-height:1.55;">{{TLDR}}</p>
</td></tr>
{{TROUBLESHOOT}}
<!-- Updates Applied -->
<tr><td style="padding:18px 32px 0;">
<h2 style="margin:0; padding-left:10px; border-left:3px solid #2e7d32; color:#1a1a2e; font-size:13px; font-weight:700; letter-spacing:0.6px; text-transform:uppercase;">Updates Applied</h2>
</td></tr>
<tr><td style="padding:8px 32px 14px;">{{UPDATES}}</td></tr>
<tr><td style="padding:0 32px;"><hr style="border:none; border-top:1px solid #ececf2; margin:4px 0;"></td></tr>
<!-- Health -->
<tr><td style="padding:18px 32px 0;">
<h2 style="margin:0; padding-left:10px; border-left:3px solid #5b3cc4; color:#1a1a2e; font-size:13px; font-weight:700; letter-spacing:0.6px; text-transform:uppercase;">Health</h2>
</td></tr>
<tr><td style="padding:8px 32px 14px;">{{HEALTH}}</td></tr>
<tr><td style="padding:0 32px;"><hr style="border:none; border-top:1px solid #ececf2; margin:4px 0;"></td></tr>
<!-- Audit &amp; Fixes -->
<tr><td style="padding:18px 32px 0;">
<h2 style="margin:0; padding-left:10px; border-left:3px solid #00838f; color:#1a1a2e; font-size:13px; font-weight:700; letter-spacing:0.6px; text-transform:uppercase;">Audit &amp; Fixes</h2>
</td></tr>
<tr><td style="padding:8px 32px 14px;">{{AUDIT}}</td></tr>
<tr><td style="padding:0 32px;"><hr style="border:none; border-top:1px solid #ececf2; margin:4px 0;"></td></tr>
<!-- Work Queue -->
<tr><td style="padding:18px 32px 0;">
<h2 style="margin:0; padding-left:10px; border-left:3px solid #e65100; color:#1a1a2e; font-size:13px; font-weight:700; letter-spacing:0.6px; text-transform:uppercase;">Work Queue</h2>
</td></tr>
<tr><td style="padding:8px 32px 14px;">{{QUEUE}}</td></tr>
<tr><td style="padding:0 32px;"><hr style="border:none; border-top:1px solid #ececf2; margin:4px 0;"></td></tr>
<!-- Usage -->
<tr><td style="padding:18px 32px 0;">
<h2 style="margin:0; padding-left:10px; border-left:3px solid #37474f; color:#1a1a2e; font-size:13px; font-weight:700; letter-spacing:0.6px; text-transform:uppercase;">OpenCode Go Usage</h2>
</td></tr>
<tr><td style="padding:8px 32px 14px;">{{USAGE}}</td></tr>
<!-- Footer -->
<tr><td style="padding:18px 32px; background-color:#f8f8fb; border-top:1px solid #ececf2;">
<p style="margin:0; color:#7b7b8a; font-size:11px; text-align:center;">{{FOOTER}}</p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>"""

# Configuration and policy constants are intentionally data-only; executable
# helpers live in runtime.py and the bounded phase modules.
