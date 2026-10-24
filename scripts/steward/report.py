"""HTML report rendering, TL;DR generation, and archive handling.

Every report item is triaged once (`_triage`): Needs You holds only extreme items,
everything else still open is Watching, and real changes form one deduplicated list.
The email, its subject, the TL;DR and summary.md all read that triage.
"""
from __future__ import annotations

import sqlite3

from .config import (
    AUTO_PKGS,
    DEFAULT_TEMPLATE,
    DEPENDABOT_UNIT,
    DIGEST_SCRIPT,
    ENDPOINTS,
    FINDING_SEVERITIES,
    FIX_MAX_ITERS,
    GH_API,
    HOME,
    IDEAS_DIR,
    LLAMA_CPP_RELEASES_API,
    LLAMA_CPP_UPDATE_SCRIPT,
    LOW_DEFAULT_SEVERITY_SECTIONS,
    MAX_WORKERS,
    OPENWEBUI_COMPOSE,
    P7B_REPORT_ONLY_SECTIONS,
    PENDING_PATH,
    PLANS_DIR,
    PROXY_HEALTH,
    Path,
    RIG_APT_TIMEOUT,
    RIG_BOOT_ENTRY,
    RIG_DISK_MAX_PERCENT,
    RIG_MODEL_ENDPOINT,
    RIG_REBOOT_WAIT_TIMEOUT,
    RIG_REMOTE_PATH,
    RIG_REQUIRED_MODEL_IDS,
    RIG_SSH_ALIAS,
    RIG_SSH_COMMAND_TIMEOUT,
    RIG_SSH_CONNECT_TIMEOUT,
    RIG_UPDATE_TIMEOUT,
    RUNS_LOG,
    RUN_DIR_BASE,
    SEARXNG_TAGS_API,
    SECRET_PATTERNS,
    SESSION_ACTIVE_MINUTES,
    SESSION_DIR,
    SESSION_INTERACTIVE_DIR,
    SESSION_MEMOIR_DIR,
    SESSION_MEMORY_CONTEXT_DAYS,
    SESSION_MEMORY_CONTEXT_MAX,
    STEWARD_MODEL,
    STEWARD_PATH,
    TEMPLATE_PATH,
    ThreadPoolExecutor,
    UPDATE_MIN_AGE_DAYS,
    WORKFLOW_POLICY_VERSION,
    WORKFLOW_SCHEMA_VERSION,
    _FNM_NODE_DIRS,
    argparse,
    as_completed,
    datetime,
    hashlib,
    html,
    json,
    os,
    re,
    shlex,
    subprocess,
    sys,
    time,
    timedelta,
    timezone,
    urllib,
)
from .runtime import (
    NO_TOOLS,
    READ_ONLY_TOOLS,
    REBOOT_RECORD_NAME,
    atomic_write_text,
    _current_boot_id,
    _own_cgroup_dir,
    _assistant_text_from_message,
    _balanced_json_slice,
    _call_omp_p,
    _date_context,
    _evidence_hash,
    _extract_json,
    _load_prev_artifact,
    _message_error_str,
    _ndjson_looks_like_event_stream,
    _omp_login_probe,
    _reboot_if_needed,
    apt_installed_version,
    apt_upgradable,
    extract_from_ndjson,
    parse_previous_summary,
    prev_workday,
    read_json,
    run,
    run_capture,
    run_capture_ok,
    run_ok,
    user_env,
    write_json,
)
from .audit import (
    AUDIT_SECTIONS,
    _AUDIT_VERDICTS,
    _REAL_VERDICTS,
    _SKIP_SCANNER_FILES,
    _apply_deterministic_audit_guards,
    _audit_artifact_cacheable,
    _audit_collector_1_agents_md,
    _audit_collector_2_versions,
    _audit_collector_3_digest_quality,
    _audit_collector_4_security,
    _audit_collector_5_config_drift,
    _audit_collector_6_notes_resources,
    _audit_collector_7_agent_fleet,
    _audit_collector_8_docs_accuracy,
    _final_audit_verdict,
    _gather_repo_secrets,
    _prepare_audit_worker_packet,
    _run_audit_agent_pair,
    _session_memory_context,
    _validate_audit_judge_packet,
    _validate_prepared_audit_worker_packet,
    phase_7_audit,
)
from .fixes import (
    _confirmed_worker_findings,
    _finding_key,
    _fix_one_section,
    _index_by_finding_key,
    _is_unfixable_note,
    _merge_fixes_applied,
    _p7b_fix_candidates,
    _parse_fix_markdown_table,
    _remaining_after_judge,
    phase_7b_fix,
)
from .dotfiles import DOTFILES_GIT
from .dotfiles import untracked_in_scope as _dotfiles_untracked_in_scope
from .setup import P0B_PROBLEM_ACTIONS
from .updates import _dependabot_merge_undo


def _dotfiles_untracked_paths():
    """Untracked in-scope dotfiles at report time, before tonight's P9b runs.

    Never raises: no dotfiles repo (GitHub CI) means nothing to list.
    """
    if not DOTFILES_GIT.is_dir():
        return []
    try:
        return _dotfiles_untracked_in_scope()
    except Exception as error:
        print(f"  dotfiles untracked scan failed: {error}")
        return []



# ── palette and HTML primitives ──────────────────────────────────────
# Every colour the email uses (the template frame adds #f4f4f7/#ffffff/#b8b8d0).
COLOR = {
    "ink": "#1a1a2e",      # headings, header band
    "text": "#2a2a36",     # body text
    "muted": "#7b7b8a",    # labels, footer, housekeeping
    "faint": "#9aa0b2",    # neutral chips and dots
    "track": "#d0d4de",    # usage bar track
    "rule": "#ececf2",     # section rules
    "code": "#f4f4f7",     # monospace background
    "ok": "#2e7d32",       # all good, What changed
    "danger": "#c62828",   # Needs You, failures
    "warn": "#e65100",     # rollbacks, warnings, Work Queue
    "info": "#1565c0",     # Watching, in progress
    "health": "#5b3cc4",
    "audit": "#00838f",
    "slate": "#37474f",    # usage
    "week": "#0d47a1",
    "month": "#4a148c",
}
_esc = html.escape


def _chip(text, color):
    """Inline rounded status chip."""
    return (
        f'<span style="display:inline-block; padding:1px 8px; border-radius:10px; '
        f'background-color:{color}1f; color:{color}; font-size:11px; font-weight:700; '
        f'letter-spacing:0.6px; text-transform:uppercase; white-space:nowrap;">{text}</span>'
    )


def _dot(level):
    color = {"ok": COLOR["ok"], "warn": COLOR["warn"],
             "danger": COLOR["danger"]}.get(level, COLOR["faint"])
    return (
        f'<span style="display:inline-block; width:7px; height:7px; border-radius:50%; '
        f'background-color:{color}; vertical-align:middle; margin-right:5px; '
        f'font-size:0; line-height:0;">&nbsp;</span>'
    )


def _label(text):
    """Small grey group label inside a section."""
    return (
        f'<p style="margin:10px 0 3px; color:{COLOR["muted"]}; font-size:11px; font-weight:700; '
        f'letter-spacing:0.8px; text-transform:uppercase;">{_esc(text)}</p>'
    )


def _row(inner_html, color=None, margin="0 0 6px"):
    """One 13px report line (inner_html is already escaped)."""
    return (
        f'<p style="margin:{margin}; color:{color or COLOR["text"]}; font-size:13px; '
        f'line-height:1.45;">{inner_html}</p>'
    )


def _code(text):
    return (
        f'<code style="font-family:SFMono-Regular,Menlo,Consolas,monospace; font-size:12px; '
        f'background-color:{COLOR["code"]}; padding:1px 4px; border-radius:3px; '
        f'word-break:break-all;">{_esc(str(text))}</code>'
    )


def _kv_rows(rows):
    """rows: list of (label, value_html). Returns a 2-column nested table."""
    if not rows:
        return ""
    out = ['<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
           f'style="font-size:13px; color:{COLOR["text"]}; border-collapse:collapse;">']
    for label, val in rows:
        out.append(
            '<tr>'
            f'<td width="35%" style="padding:3px 12px 3px 0; vertical-align:top; '
            f'color:{COLOR["muted"]}; font-size:13px;">{label}</td>'
            f'<td style="padding:3px 0; vertical-align:top; color:{COLOR["text"]};">{val}</td>'
            '</tr>'
        )
    out.append('</table>')
    return "".join(out)


def _section(title, color, body):
    """A titled card section with a coloured left bar, followed by a rule."""
    return (
        '<tr><td style="padding:18px 32px 0;">'
        f'<h2 style="margin:0; padding-left:10px; border-left:3px solid {color}; '
        f'color:{COLOR["ink"]}; font-size:13px; font-weight:700; letter-spacing:0.6px; '
        f'text-transform:uppercase;">{_esc(title)}</h2></td></tr>'
        f'<tr><td style="padding:8px 32px 14px;">{body}</td></tr>'
        '<tr><td style="padding:0 32px;"><hr style="border:none; '
        f'border-top:1px solid {COLOR["rule"]}; margin:4px 0;"></td></tr>'
    )


def _plural(count, word, plural=None):
    return f"{count} {word if count == 1 else (plural or word + 's')}"


def _clip(text, limit):
    """Collapse whitespace and cut at a word boundary."""
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0] or text[:limit]
    return cut.rstrip(",;:") + "…"


# ── human names ──────────────────────────────────────────────────────

_SECTION_NAMES = {
    "agents-md-truth": "AGENTS.md accuracy",
    "version-currency": "Version currency",
    "digest-quality": "Daily News quality",
    "security-posture": "Security posture",
    "config-doc-drift": "Config vs docs",
    "notes-resources": "Notes & resources",
    "agent-fleet-review": "Agent fleet",
    "docs-accuracy": "Docs accuracy",
    "dotfiles": "Dotfiles",
    "steward-resolver": "Follow-up on open items",
}

_STEP_NAMES = {
    "omp_update": "omp",
    "openwebui_update": "Open WebUI",
    "openwebui": "Open WebUI",
    "apt_upgrade": "apt",
    "searxng": "SearXNG",
    "freshrss": "FreshRSS",
    "herdr_update": "herdr",
    "llama_cpp": "llama.cpp",
    "worker_omp_refresh": "Steward worker omp",
    "omp_db_repair": "OMP database check",
    "docker_cleanup": "Docker cleanup",
    "docker_settle": "Docker restart",
    "docker_daemon_assert": "Docker daemon check",
    "dependabot_merge": "Dependabot auto-merge",
    "toolchain_node": "Node.js",
    "toolchain_ruby": "Ruby (rbenv global)",
    "toolchain_go_user": "Go (~/.local/go)",
    "toolchain_go_root": "Go (/usr/local/go)",
    "toolchain_nvim": "Neovim",
}

_CHECK_NAMES = {
    "docker_containers": "Containers",
    "llm_fallback": "LLM routing",
    "openwebui_image_match": "Open WebUI image",
    "endpoint_tunnel-health": "Cloudflare tunnel",
}


def _section_name(section):
    section = str(section or "")
    return _SECTION_NAMES.get(section, section.replace("_", " ").replace("-", " "))


def _step_name(step):
    name = str(step.get("step") or "")
    if name == "app_deploy":
        return str(step.get("service") or "app")
    if name.startswith("auto_"):
        return name.removeprefix("auto_")
    return _STEP_NAMES.get(name, name.replace("_", " "))


def _check_label(check):
    name = str(check.get("name") or check.get("endpoint") or "check")
    if name in _CHECK_NAMES:
        return _CHECK_NAMES[name]
    return name.removeprefix("endpoint_").replace("_", " ")


# Internal phase codes and agent names that leak into audit claims.
_JARGON = (
    (r"\bP0b\b", "session notes"),
    (r"\bP1\b", "nightly maintenance"),
    (r"\bP3a?\b", "the regression check"),
    (r"\bP7c\b", "the follow-up check"),
    (r"\bP7b?\b", "the audit"),
    (r"\bP9b\b", "the dotfiles commit"),
    (r"\bP9c\b", "the public mirror"),
    (r"\bJev\b", "the checker"),
)


def _humanize(text):
    """Plain wording: section ids ('digest-quality/finding-1', '(agents-md-truth)')
    become section names; phase codes and agent names become what they do."""
    text = str(text or "")
    text = re.sub(
        r"\b([a-z]+(?:-[a-z]+)+)/finding-\d+\b",
        lambda m: _SECTION_NAMES.get(m.group(1), m.group(1)), text)
    ids = "|".join(re.escape(s) for s in _SECTION_NAMES)
    text = re.sub(rf"\s*\((?:{ids})\)", "", text)
    for pattern, plain in _JARGON:
        text = re.sub(pattern, plain, text)
    return text


def _arrow(pre, post):
    return f"{pre} → {post}"


def _short_sha(value):
    value = str(value or "").strip()
    return value[:7] if re.fullmatch(r"[0-9a-f]{7,40}", value) else (value or "?")


# ── report items ─────────────────────────────────────────────────────
# One item model feeds every block: "needs" (Needs You), "watch" (Watching),
# "change" / "rollback" / "chore" (What changed tonight).

_CHANGE_GROUPS = ("Updates", "Deploys", "Fixes by the steward", "Dependabot", "Housekeeping")
_CHANGE_KINDS = ("change", "rollback", "chore")


def _item(kind, text, *, group="Updates", undo=(), why="", todo="", problem="", command=""):
    """kind: needs | watch | change | rollback | chore.

    needs items carry why/todo (and problem, a short phrase that turns the
    verdict into "Problem: …"); watch items may carry a command shown in
    monospace; changes carry their undo commands for the appendix.
    """
    undo = [undo] if isinstance(undo, str) else list(undo or ())
    return {"kind": kind, "group": group, "text": str(text),
            "undo": [str(u) for u in undo if u], "why": str(why or ""),
            "todo": str(todo or ""), "problem": str(problem or ""), "command": str(command or "")}


_P1_FAILURE_STATUSES = frozenset({"failed", "error", "timeout", "started"})
_RIG_STEPS = ("gamingrig_maintenance", "gamingrig_linux", "gamingrig")
# Earlier runs scanned for the last successful rig maintenance, and the age at
# which a skipped rig moves from Watching to Needs You.
RIG_MAINTENANCE_SCAN_DAYS = 60
RIG_MAINTENANCE_ESCALATE_DAYS = 30
# A failed rollback leaves a service in an unknown state: always Carter's.
_ROLLBACK_UNVERIFIED = re.compile(
    r"(?i)rollback\s+(?:not\s+verified|failed)|ROLLBACK_FAILED|deployment or rollback failed")
_RETRIES = "retries tomorrow"
STEWARD_JOURNAL = "journalctl --user -u homelab-steward.service --since today"


def _p1_phase_failed(applied_data):
    return bool(
        isinstance(applied_data, dict)
        and (
            applied_data.get("phase_failed")
            or applied_data.get("phase_status") == "failed"
        )
    )


def _p1_failure_detail(applied_data):
    if not isinstance(applied_data, dict):
        return "phase returned no result"
    return str(
        applied_data.get("reason")
        or applied_data.get("error")
        or "phase failed before producing step results"
    )[:240]


def _failed_word(status):
    return {"timeout": "timed out", "started": "did not finish",
            "error": "errored"}.get(status, "failed")


def _detail(step, limit=160):
    return _clip(step.get("error") or step.get("reason") or step.get("status") or "", limit)


def _step_failure(step, name=None):
    """A failed P1 step: Needs You when its rollback is unverified, else Watching."""
    name = name or _step_name(step)
    detail = _detail(step)
    if _ROLLBACK_UNVERIFIED.search(str(step.get("error") or step.get("reason") or "")):
        return _item(
            "needs", f"{name} update failed and its rollback could not be verified",
            why=detail,
            todo=(f"Restore {name} by hand: {step['revert']}" if step.get("revert")
                  else f"Check {name} by hand and restore the previous version."),
        )
    return _item("watch", f"{name} {_failed_word(step.get('status'))}: {detail}; {_RETRIES}")


_RIG_GATES = {
    "reboot_required": "reboot check",
    "pre_reboot_boot_id": "boot id before reboot",
    "bootnext": "boot-into-Linux setting",
    "reboot": "reboot",
    "ssh_return": "SSH return after reboot",
    "post_reboot_health": "health after reboot",
}


def _rig_staleness(last_ok):
    """' — last maintained <date> (N nights ago)' from _rig_last_maintained."""
    if not last_ok:
        return ""
    if last_ok.get("date"):
        nights = last_ok["nights"]
        return (f" — last maintained {last_ok['date']} "
                f"({_plural(nights, 'night')} ago)")
    return f" — no successful maintenance in the last {last_ok.get('days')} days of runs"


def _rig_overdue(last_ok):
    """True once the rig has gone RIG_MAINTENANCE_ESCALATE_DAYS without maintenance.

    No success inside the scan window counts as at least the window length.
    """
    if not last_ok:
        return False
    if last_ok.get("date"):
        return last_ok.get("nights", 0) >= RIG_MAINTENANCE_ESCALATE_DAYS
    return True


def _rig_skipped_item(why, last_ok):
    rig = "Gaming rig"
    if not _rig_overdue(last_ok):
        return _item("watch", f"{rig} not maintained tonight ({why}){_rig_staleness(last_ok)}")
    if last_ok.get("date"):
        age = f"{_plural(last_ok['nights'], 'night')} (last on {last_ok['date']})"
    else:
        age = f"more than {last_ok.get('days')} days"
    return _item(
        "needs", f"{rig} has gone {age} without maintenance (tonight: {why})",
        why="It is missing security updates, and herdr, omp and llama.cpp on the inference "
            "host keep drifting from the versions the rest of the homelab runs.",
        todo="Leave the rig booted into Linux overnight so the 04:00 UTC steward run can "
             "maintain it. The steward never wakes the rig or switches its OS, by design.")


def _rig_events(step, last_ok=None):
    """Gaming-rig maintenance as report items (changes, Watching, Needs You)."""
    status = step.get("status", "")
    rig = "Gaming rig"
    if status == "skipped":
        reason = str(step.get("reason") or "")
        if "windows" in reason.lower():
            why = "booted into Windows"
        elif re.search(r"(?i)offline|sleep|no route|unreachable|timed out", reason):
            why = "offline or asleep"
        else:
            why = _clip(reason, 100) or "not attempted"
        return [_rig_skipped_item(why, last_ok)]

    items = []
    reboot_failed = False
    for sub in step.get("substeps", []) or []:
        name = sub.get("step", "")
        sub_status = sub.get("status", "")
        failed = sub_status in _P1_FAILURE_STATUSES
        detail = _detail(sub, 140)
        if name == "apt_upgrade":
            count = sub.get("upgraded_count", 0)
            if count:
                new = sub.get("installed_count", 0)
                items.append(_item("change", f"{rig}: {_plural(count, 'package')} upgraded"
                                   + (f", {new} newly installed" if new else "")))
            if failed:
                items.append(_item("watch", f"{rig} package upgrade {_failed_word(sub_status)}: "
                                   f"{detail}; {_RETRIES}"))
        elif name in ("herdr_update", "omp_update"):
            tool = "herdr" if name == "herdr_update" else "omp"
            pre, post = str(sub.get("pre_version") or ""), str(sub.get("post_version") or "")
            if sub_status == "ok" and pre and post and pre != post:
                items.append(_item("change", f"{rig} {tool} {_arrow(pre, post)}"))
            elif sub_status == "reverted":
                items.append(_item(
                    "rollback", f"{rig} {tool} update rolled back to "
                    f"{sub.get('reverted_to') or 'the previous version'} (post-update check "
                    f"failed); {_RETRIES}"))
            elif failed:
                items.append(_item("watch", f"{rig} {tool} update {_failed_word(sub_status)}: "
                                   f"{detail}; {_RETRIES}"))
        elif name in ("health", "post_reboot_health"):
            after_reboot = name == "post_reboot_health"
            problems = [
                check for check in sub.get("checks", []) or []
                if check.get("status") in (_P1_FAILURE_STATUSES | {"warning"})
            ]
            texts = [
                f"{str(check.get('step') or 'check').replace('_', ' ')}: {_detail(check, 120)}"
                for check in problems
            ]
            if failed and not texts:
                texts = [detail or "health gate failed"]
            for text, check in zip(texts, problems or [{}] * len(texts)):
                if after_reboot and (failed or check.get("status") in _P1_FAILURE_STATUSES):
                    reboot_failed = True
                    items.append(_item(
                        "needs", f"{rig} unhealthy after its reboot ({_RIG_GATES[name]})",
                        why=text,
                        todo="Check the rig over SSH (ssh gamingrig-linux) or at the desk; "
                             "the steward will not reboot it again until it is healthy."))
                else:
                    items.append(_item("watch", f"{rig} health check {text}"))
        elif name == "boot_gpu_ready" and sub_status == "warning":
            items.append(_item("watch", f"{rig}: {_clip(sub.get('reason') or 'reboot deferred', 200)}"))
        elif name == "reboot" and sub_status == "ok":
            if step.get("rebooted") and step.get("post_reboot_health_passed"):
                items.append(_item("change", f"{rig} rebooted; health rechecked after the reboot"))
        elif name == "ssh_return" and failed:
            reboot_failed = True
            items.append(_item(
                "needs", f"{rig} did not come back to Linux after its reboot "
                f"({_RIG_GATES[name]})",
                why=detail,
                todo="Check the rig at the desk: it may be stuck in Windows, the boot menu, "
                     "or powered off."))
        elif name in _RIG_GATES and failed:
            items.append(_item("watch", f"{rig} {_RIG_GATES[name]} {_failed_word(sub_status)}: "
                               f"{detail}; {_RETRIES}"))
    if step.get("rebooted") and not step.get("post_reboot_health_passed") and not reboot_failed:
        items.append(_item(
            "needs", f"{rig} rebooted but its health check after the reboot did not pass",
            todo="Check the rig over SSH (ssh gamingrig-linux) or at the desk."))
    if status in _P1_FAILURE_STATUSES and not any(i["kind"] in ("watch", "needs", "rollback")
                                                  for i in items):
        items.append(_item("watch", f"{rig} maintenance {_failed_word(status)}: "
                           f"{_detail(step)}; {_RETRIES}"))
    return items


def _omp_stale_note(step):
    """Suffix naming OMP sessions that still run a replaced binary."""
    stale = step.get("stale_processes") or {}
    try:
        count = int(stale.get("count") or 0) if isinstance(stale, dict) else 0
    except (TypeError, ValueError):
        count = 0
    if count <= 0:
        return ""
    return (
        f" ({count} running omp session{'s' if count != 1 else ''} still "
        f"use{'s' if count == 1 else ''} the old binary; restart "
        f"{'it' if count == 1 else 'them'})"
    )


_DEPENDABOT_BUMP = re.compile(r"\b[Bb]ump (?P<dep>\S+) from (?P<old>\S+) to (?P<new>\S+?)\.?(?:\s|$)")


def _bump_text(pr):
    title = str(pr.get("title") or "")
    match = _DEPENDABOT_BUMP.search(title)
    what = (f"{match['dep']} {_arrow(match['old'], match['new'])}" if match
            else _clip(title, 80) or "update")
    return f"{what} (#{pr.get('number')})"


def _dependabot_events(step):
    """One What-changed line per repo with queued auto-merges; one Watching line per
    repo with PRs left open (majors and skips)."""
    items = []
    merged = {}
    for pr in step.get("merged") or []:
        if isinstance(pr, dict):
            merged.setdefault(str(pr.get("repo") or "?"), []).append(pr)
    for repo, prs in merged.items():
        items.append(_item(
            "change",
            f"{repo}: {_plural(len(prs), 'update')} set to auto-merge — "
            + "; ".join(_bump_text(pr) for pr in prs),
            group="Dependabot",
            undo=[pr.get("revert") or (_dependabot_merge_undo(pr["url"]) if pr.get("url") else "")
                  for pr in prs],
        ))
    left = {}
    for pr in step.get("needs_carter") or []:
        if isinstance(pr, dict):
            left.setdefault(str(pr.get("repo") or "?"), []).append(
                f"{_bump_text(pr)} is a major update for you to merge")
    for pr in step.get("skipped") or []:
        if isinstance(pr, dict) and pr.get("number") is not None:
            left.setdefault(str(pr.get("repo") or "?"), []).append(
                f"#{pr.get('number')} {_clip(pr.get('reason'), 80)}")
    for repo, reasons in left.items():
        more = f" (+{len(reasons) - 3} more)" if len(reasons) > 3 else ""
        items.append(_item(
            "watch", f"{repo}: {_plural(len(reasons), 'Dependabot PR')} left open — "
            + "; ".join(reasons[:3]) + more))
    if step.get("error"):
        items.append(_item("watch", f"Dependabot auto-merge error: {_clip(step['error'], 200)}"))
    return items


def _toolchain_events(step):
    """A same-line toolchain update: change with undo, Watching for a skipped or
    verified-rolled-back update, Needs You only for an unverified rollback."""
    label = _step_name(step)
    status = step.get("status", "")
    pre, post, target = step.get("pre_version"), step.get("post_version"), step.get("target")
    items = []
    if status == "ok" and pre != post:
        items.append(_item("change", f"{label} {_arrow(pre, post)}", undo=step.get("revert") or ""))
    elif status == "reverted":
        items.append(_item("watch", f"{label} update to {target or '?'} rolled back to {pre} "
                           f"({_detail(step)}); {_RETRIES}"))
    elif status == "warning":
        items.append(_item("watch", f"{label} update not applied — {_detail(step)}; {_RETRIES}"))
    elif status in _P1_FAILURE_STATUSES:
        items.append(_step_failure(step))
    if step.get("pruned"):
        items.append(_item("chore", f"{label}: removed replaced {', '.join(step['pruned'])} "
                           "(kept 7 days for rollback)", group="Housekeeping"))
    return items


def _p1_events(applied, rig_last_ok=None):
    """Every P1 maintenance step as report items, signal only (no-op steps vanish)."""
    applied = applied if isinstance(applied, dict) else {}
    items = []
    reboot = applied.get("host_reboot")
    if reboot:
        items.append(_item("change" if reboot.get("rebooted") else "watch", reboot["text"]))
    if _p1_phase_failed(applied):
        items.append(_item(
            "needs", "Nightly maintenance failed",
            why=_p1_failure_detail(applied),
            todo=f"Read tonight's log ({STEWARD_JOURNAL}), fix the cause, then run "
                 "python3 ~/scripts/steward_runner.py --resume.",
            problem="maintenance failed",
        ))
    for s in applied.get("steps", []) or []:
        if not isinstance(s, dict):
            continue
        name = s.get("step", "")
        status = s.get("status", "")
        label = _step_name(s)
        failed = status in _P1_FAILURE_STATUSES
        pre, post = s.get("pre_version"), s.get("post_version")
        undo = s.get("revert") or ""
        if name in _RIG_STEPS:
            items.extend(_rig_events(s, rig_last_ok))
        elif name == "dependabot_merge":
            items.extend(_dependabot_events(s))
        elif name in ("openwebui_update", "openwebui"):
            pre = pre or s.get("current_tag") or "?"
            latest = s.get("latest_tag") or post or "?"
            newer_skipped = (
                status == "skipped"
                and str(s.get("reason") or "").startswith(("preflight:", "baseline:"))
                and s.get("latest_tag") and s["latest_tag"] != pre
            )
            if status == "ok" and pre != post:
                items.append(_item("change", f"Open WebUI {_arrow(pre, post)}", undo=undo))
            elif status == "rolled_back":
                items.append(_item("rollback", f"Open WebUI update to {latest} rolled back "
                                   f"({_detail(s)}); {_RETRIES}"))
            elif status == "warning" or newer_skipped:
                items.append(_item("watch", f"Open WebUI update to {latest} deferred — "
                                   f"{_detail(s)}"))
            elif failed:
                items.append(_step_failure(s))
        elif name == "app_deploy":
            if status == "ok":
                items.append(_item("change", f"{label} deployed "
                                   f"{_arrow(_short_sha(pre), _short_sha(post))}",
                                   group="Deploys", undo=undo))
            elif status == "rolled_back":
                items.append(_item("rollback", f"{label} deploy failed and was rolled back "
                                   f"({_detail(s)}); {_RETRIES}", group="Deploys"))
            elif failed:
                items.append(_step_failure(s, f"{label} deploy"))
            elif status == "skipped" and re.search(
                    r"(?i)\b(ci|checks?|dirty|fast-forward|branch)\b", _detail(s)):
                items.append(_item("watch", f"{label} deploy waiting — {_detail(s)}"))
        elif name.startswith("toolchain_"):
            items.extend(_toolchain_events(s))
        elif name == "omp_db_repair":
            detail = _clip(s.get("error") or s.get("reason") or "", 400)
            if status == "ok":
                items.append(_item("change", f"OMP database repaired: {detail}",
                                   group="Fixes by the steward"))
            elif status == "warning" and s.get("needs_carter"):
                items.append(_item(
                    "needs", "An OMP database is damaged and cannot be repaired without loss",
                    why=detail,
                    todo="Decide whether to restore it from the nightly backup; the steward "
                         "left it untouched (restoring the pre-repair copy is not safe while "
                         "OMP runs)."))
            elif status == "warning":
                items.append(_item("watch", f"OMP database check: {detail}"))
            elif failed:
                items.append(_step_failure(s))
        elif name == "docker_daemon_assert" and failed:
            items.append(_item(
                "needs", "Docker daemon check failed after tonight's updates",
                why=_detail(s, 300),
                todo="Check `systemctl status docker` and /etc/docker/daemon.json before "
                     "the next run."))
        elif name == "docker_cleanup":
            if status == "ok" and s.get("reason"):
                items.append(_item("chore", f"Docker cleanup: {_clip(s['reason'], 140)}",
                                   group="Housekeeping"))
            elif status == "warning" or failed:
                items.append(_item("watch", f"Docker cleanup {_failed_word(status) if failed else 'incomplete'}: "
                                   f"{_detail(s)}"))
        elif failed:
            items.append(_step_failure(s))
        elif status == "reverted":
            items.append(_item("rollback", f"{label} update rolled back to "
                               f"{s.get('reverted_to') or 'the previous version'}"
                               f" (post-update check failed); {_RETRIES}"))
        elif name == "omp_update" and status == "skipped" and _omp_stale_note(s):
            items.append(_item("watch", f"omp is current{_omp_stale_note(s)}"))
        elif name == "apt_upgrade":
            if s.get("upgraded_count", 0) > 0:
                items.append(_item("change", f"apt: {_plural(s['upgraded_count'], 'package')} upgraded"))
        elif name == "searxng" and status == "ok":
            items.append(_item("change", "SearXNG image refreshed", undo=undo))
        elif name == "freshrss":
            if status == "bumped":
                items.append(_item("change", f"FreshRSS {_arrow(s.get('current_tag'), s.get('latest_tag'))}",
                                   undo=undo))
            elif status == "warning":
                items.append(_item("watch", f"FreshRSS update deferred — {_detail(s)}"))
        elif status in ("ok", "bumped") and (
                (pre and post and pre != post) or undo or name.startswith("auto_")
                or name in ("omp_update", "herdr_update", "llama_cpp", "worker_omp_refresh")):
            pre_text = str(pre or "").replace("omp/", "").replace("herdr ", "")
            post_text = str(post or "").replace("omp/", "").replace("herdr ", "")
            if pre_text and post_text and pre_text != post_text:
                text = f"{label} {_arrow(pre_text, post_text)}"
            elif pre_text and post_text:
                continue  # reinstall of the same version: no change
            else:
                text = f"{label}: {_clip(s.get('reason') or 'done', 140)}"
            if name == "omp_update":
                text += _omp_stale_note(s)
            items.append(_item("change", text, undo=undo))
    if applied.get("phase_status") == "degraded" and not any(
            i["kind"] in ("watch", "needs") for i in items):
        items.append(_item("watch", f"Nightly maintenance finished with problems: "
                           f"{_p1_failure_detail(applied)}"))
    return items


def _rig_last_maintained(run_dir, date_str, max_days=RIG_MAINTENANCE_SCAN_DAYS):
    """Last earlier run whose gaming-rig maintenance succeeded (bounded scan)."""
    try:
        today = datetime.strptime(date_str, "%Y-%m-%d")
    except (TypeError, ValueError):
        return None
    base = Path(run_dir).parent
    for back in range(1, max_days + 1):
        day = (today - timedelta(days=back)).strftime("%Y-%m-%d")
        path = base / day / "01-applied.json"
        if not path.exists():
            continue
        try:
            steps = read_json(path).get("steps") or []
        except (OSError, ValueError, AttributeError):
            continue
        if any(isinstance(s, dict) and s.get("step") in _RIG_STEPS and s.get("status") == "ok"
               for s in steps):
            return {"date": day, "nights": back}
    return {"date": None, "days": max_days}


def _host_reboot_status(run_dir):
    """Render-time outcome of this run's ThinkPad reboot request (None when none).

    Compares the boot id recorded in reboot.json before `systemctl reboot`
    with the current one: a new boot id means the host really restarted.
    """
    path = Path(run_dir) / REBOOT_RECORD_NAME
    if not path.exists():
        return None
    try:
        record = read_json(path)
    except (OSError, ValueError):
        return None
    if not isinstance(record, dict):
        return None
    requested = str(record.get("requested_at") or "")
    match = re.search(r"T(\d{2}:\d{2})", requested)
    hhmm = match.group(1) if match else "?"
    before_boot = str(record.get("boot_id_before") or "")
    now_boot = _current_boot_id()
    kernel_before = str(record.get("kernel_before") or "?")
    kernel_after = run_capture(["uname", "-r"]) or "?"
    rebooted = bool(before_boot and now_boot and before_boot != now_boot)
    if rebooted and kernel_before != kernel_after:
        text = (f"ThinkPad rebooted for kernel update: {_arrow(kernel_before, kernel_after)} "
                f"({hhmm} UTC); run resumed")
    elif rebooted:
        text = f"ThinkPad rebooted (kernel {kernel_after} unchanged) ({hhmm} UTC); run resumed"
    else:
        text = f"ThinkPad reboot requested at {hhmm} UTC but the host did not restart"
    return {"rebooted": rebooted, "text": text, "time": hhmm,
            "kernel_before": kernel_before, "kernel_after": kernel_after}


_STEWARD_WORKFLOW = "homelab-steward"  # workflow.WORKFLOW_NAME (report cannot import workflow)
STEWARD_MEMORY_HIGH_FALLBACK_MIB = 6144  # homelab-steward.service MemoryHigh=6G


def _parse_utc(text):
    """Parse an ISO-8601 timestamp ('Z' or offset; naive = UTC), or None."""
    try:
        parsed = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _workflow_run_created_at(run_dir):
    """When this run started: its workflow_runs.created_at (run_id = run dir date), or None."""
    environment_db = os.environ.get("WORKFLOW_STATE_DB")
    db = Path(environment_db) if environment_db else Path(run_dir) / "workflow-state.sqlite3"
    if not db.is_file():
        return None
    try:
        connection = sqlite3.connect(f"{db.resolve().as_uri()}?mode=ro", uri=True, timeout=5)
        try:
            row = connection.execute(
                "SELECT created_at FROM workflow_runs WHERE workflow = ? AND run_id = ?",
                (_STEWARD_WORKFLOW, Path(run_dir).name),
            ).fetchone()
        finally:
            connection.close()
    except sqlite3.Error:
        return None
    return _parse_utc(row[0]) if row and row[0] else None


def _run_timing(run_dir, elapsed_s, now=None):
    """(duration_s, wall_s) for runs.jsonl; wall_s is None when the start is unknown.

    duration_s is active time. After a reboot resume this process's elapsed time
    misses the pre-reboot segment, so add workflow_runs.created_at -> reboot.json
    requested_at when that request predates this process's start.
    """
    now = now or datetime.now(timezone.utc)
    duration = float(elapsed_s)
    start = _workflow_run_created_at(run_dir)
    try:
        record = read_json(Path(run_dir) / REBOOT_RECORD_NAME)
    except (OSError, ValueError):
        record = None
    requested = _parse_utc(record.get("requested_at")) if isinstance(record, dict) else None
    process_start = now - timedelta(seconds=duration)
    if start and requested and start <= requested <= process_start:
        duration += (requested - start).total_seconds()
    wall = round((now - start).total_seconds()) if start else None
    return round(duration), wall


def _memory_mib(memory):
    """memory.json byte maxima as the *_mib dict runs.jsonl records."""
    return {
        key.replace("_bytes", "_mib"): round(int(value) / 1048576)
        for key, value in (memory if isinstance(memory, dict) else {}).items()
        if key.endswith("_bytes") and isinstance(value, (int, float))
    }


def _read_memory_mib(run_dir):
    try:
        return _memory_mib(read_json(Path(run_dir) / "memory.json"))
    except (OSError, ValueError):
        return {}


def _steward_memory_high_mib(cgroup_dir=None):
    """The steward unit's MemoryHigh in MiB from its cgroup's memory.high (fallback 6 GiB)."""
    cgroup_dir = cgroup_dir if cgroup_dir is not None else _own_cgroup_dir()
    if cgroup_dir is not None:
        try:
            value = int((Path(cgroup_dir) / "memory.high").read_text().strip())
        except (OSError, ValueError):  # "max" means no MemoryHigh
            value = 0
        if value > 0:
            return round(value / 1048576)
    return STEWARD_MEMORY_HIGH_FALLBACK_MIB


def _steward_memory_note(memory_mib, memory_high_mib):
    """(text, warn) for the run's own memory maxima, or None before any sample.

    peak_mib is mostly reclaimable page cache; only anonymous memory over half
    of MemoryHigh is a warning.
    """
    anon = (memory_mib or {}).get("max_anon_mib")
    if anon is None:
        return None
    text = f"{anon} MiB anonymous peak"
    peak = memory_mib.get("peak_mib")
    if peak is not None:
        text += f", {peak} MiB total peak"
    text += f" (MemoryHigh {memory_high_mib} MiB)"
    return text, anon > memory_high_mib / 2



# ── finding routes (07b-fixes.json "routes") ─────────────────────────

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}
# Routes where a fix is already under way (PR merging, nightly step, queued).
_IN_PROGRESS_ROUTES = ("pr_auto_merge", "handled_by_p1", "deferred")
# Routes that may leave Carter a decision; only extreme ones reach Needs You.
_OPEN_ROUTES = ("needs_carter", "report_only", "pr_opened", "failed")


def _finding_severity(item, section):
    severity = str((item or {}).get("severity") or "").strip().lower()
    if severity in FINDING_SEVERITIES:
        return severity
    return "low" if section in LOW_DEFAULT_SEVERITY_SECTIONS else "medium"


def _legacy_route_rows(audit, fixes):
    """Route rows for 07b artifacts written before steward.routing existed.

    The old P7b rejected findings it could not map to a ~/dev file. Those are
    still confirmed problems, so they become needs_carter, never automation
    trouble.
    """
    fix_by = {
        s.get("section"): s
        for s in (fixes or {}).get("sections", []) or []
        if isinstance(s, dict) and s.get("section")
    }
    report_only = {
        s.get("section")
        for s in (fixes or {}).get("report_only", []) or []
        if isinstance(s, dict) and s.get("section")
    }
    rows = []
    for sec in (audit or {}).get("sections", []) or []:
        name = sec.get("name") or "unknown"
        if str(sec.get("verdict") or "").removeprefix("cached-") not in ("DRIFT", "ATTENTION"):
            continue
        fx = fix_by.get(name) or {}
        judge_pass = str(fx.get("judge_verdict") or "").lower() == "pass"
        applied = {
            str(f.get("id")): f
            for f in fx.get("fixes_applied") or []
            if isinstance(f, dict) and f.get("id")
        }
        for index, item in enumerate(sec.get("judge_confirmed") or [], 1):
            if not isinstance(item, dict) or not str(item.get("claim") or "").strip():
                continue
            finding_id = str(item.get("id") or f"finding-{index}")
            fix = applied.get(finding_id) or {}
            row = {
                "section": name,
                "finding_id": finding_id,
                "claim": str(item["claim"]).strip()[:400],
                "severity": _finding_severity(item, name),
                "action": str(item.get("action") or ""),
            }
            if name in report_only:
                row.update(status="report_only", summary="Reported only by policy.")
            elif fix.get("status") == "fixed" and judge_pass:
                row.update(status="done", summary="Fixed automatically.")
            elif fix.get("status") in ("fixed", "failed"):
                row.update(status="failed", detail="the repair was not accepted")
            else:
                row.update(status="needs_carter")
            rows.append(row)
    return rows


def _route_rows(audit, fixes):
    """Per-finding routes (contract rows, or derived legacy rows), most severe first."""
    routes = (fixes or {}).get("routes")
    if isinstance(routes, list):
        rows = [dict(r) for r in routes if isinstance(r, dict)]
    else:
        rows = _legacy_route_rows(audit, fixes)
    for row in rows:
        section = str(row.get("section") or "")
        row["severity"] = _finding_severity(row, section)
        row["label"] = section.replace("_", " ")
    return sorted(rows, key=lambda r: (
        _SEVERITY_RANK[r["severity"]],
        str(r.get("section") or ""),
        str(r.get("finding_id") or ""),
    ))


_RESOLVE_ARTIFACT = "07c-resolve.json"


def _merge_resolution(row, res):
    """Overlay one P7c record on a needs_carter route row."""
    status = res.get("status")
    action = res.get("action") or ""
    reason = str(res.get("reason") or "")
    if status == "done":
        row.update(
            status="done",
            summary=_clip(res.get("summary") or f"Follow-up fix applied: {action}", 300),
            revert=str(res.get("undo") or ""),
            commit=str(res.get("commit") or ""),
            detail="fixed by the follow-up check",
        )
    elif status == "resolved" or (status == "held" and res.get("already_fixed")):
        row.update(status="done", no_change=True, revert="",
                   summary=_clip(f"Already resolved since the audit ({reason})", 300))
    elif status in ("recommended", "dry_run"):
        row["recommended"] = action
        row["approve"] = str(res.get("approve_command") or "")
    elif status == "failed":
        commit = str(res.get("commit") or "")
        row.update(
            status="failed",
            partial=True,
            detail=_clip(f"{action or 'the fix'}"
                         + (f" (commit {commit[:12]})" if commit else "") + f": {reason}", 300),
            revert=str(res.get("undo") or ""),
            commit=commit,
        )


def _apply_resolutions(fixes, resolve):
    """07b routes with the P7c outcomes applied (07b itself is never rewritten).

    Route rows left needs_carter take the resolver's result; tracked dotfiles
    edits outside P9b's allowlist appear only when P7c acted or recommends.
    """
    items = [r for r in (resolve or {}).get("items") or [] if isinstance(r, dict)]
    routes = (fixes or {}).get("routes")
    degraded = (resolve or {}).get("phase_status") in ("degraded", "failed")
    if not (items or degraded) or not isinstance(routes, list):
        return fixes
    by_key = {
        (r.get("section"), r.get("finding_id")): r
        for r in items if r.get("source") == "route"
    }
    merged = []
    for route in routes:
        row = dict(route) if isinstance(route, dict) else route
        if isinstance(row, dict) and row.get("status") == "needs_carter":
            res = by_key.get((row.get("section"), row.get("finding_id")))
            if res:
                _merge_resolution(row, res)
        merged.append(row)
    for res in items:
        if res.get("source") != "dotfiles" or res.get("status") not in (
                "done", "recommended", "dry_run", "failed"):
            continue
        row = {
            "section": "dotfiles", "finding_id": res.get("id"), "claim": res.get("claim"),
            "severity": "low", "action": res.get("action") or "", "status": "needs_carter",
            "summary": "", "detail": "", "decision": "", "revert": "", "pr_url": "",
            "commit": "", "iteration": None,
        }
        _merge_resolution(row, res)
        merged.append(row)
    reason = str((resolve or {}).get("reason") or "")
    if degraded and not reason.startswith("P7c action(s) failed"):
        merged.append({
            "section": "steward-resolver", "finding_id": "p7c", "severity": "low",
            "claim": f"The follow-up check on open audit items did not finish: {_clip(reason, 240)}",
            "action": "", "status": "failed", "summary": "", "detail": "items it did not reach "
            "are listed unchanged", "decision": "", "revert": "", "pr_url": "", "commit": "",
            "iteration": None,
        })
    return {**fixes, "routes": merged}


def _load_fixes_with_resolutions(run_dir):
    fixes = read_json(run_dir / "07b-fixes.json") if (run_dir / "07b-fixes.json").exists() else {"sections": []}
    path = run_dir / _RESOLVE_ARTIFACT
    try:
        resolve = read_json(path) if path.exists() else {}
    except (OSError, ValueError):
        resolve = {}
    return _apply_resolutions(fixes, resolve if isinstance(resolve, dict) else {})


def _route_deferred(row):
    return row.get("status") == "deferred" or (
        row.get("status") == "report_only"
        and str(row.get("summary") or "").startswith("Deferred:"))


def _route_class(row):
    """needs | watch | progress | done | noop — the triage of one finding route.

    Needs You only for: a partly applied follow-up fix, or a finding left for
    Carter (needs_carter / report_only) that is high severity or a security
    finding. Everything else open is Watching.
    """
    status = row.get("status")
    if status == "done":
        if row.get("no_change") or str(row.get("detail") or "").startswith(
                "replacement text already present"):
            return "noop"
        return "done"
    if status in _IN_PROGRESS_ROUTES or _route_deferred(row):
        return "progress"
    if status == "failed":
        return "needs" if row.get("partial") else "watch"
    if status in ("needs_carter", "report_only") and (
            row.get("severity") == "high" or row.get("section") == "security-posture"):
        return "needs"
    return "watch"


def _route_progress_text(row):
    status = row.get("status")
    url = str(row.get("pr_url") or "")
    if _route_deferred(row):
        number = re.search(r"/pull/(\d+)", url)
        if number:
            return f"fix queued behind steward-code PR #{number.group(1)}; raised again next night"
        why = str(row.get("summary") or "").removeprefix("Deferred:").strip().rstrip(".")
        return f"fix queued ({why or 'a fix is already in flight'}); raised again next night"
    if status == "pr_auto_merge":
        number = re.search(r"/pull/(\d+)", url)
        pr = f"PR #{number.group(1)}" if number else "a PR"
        if "dotfiles-homelab-private" in url:
            return (f"fix proposed as steward-code {pr}; it merges after the 24 h objection "
                    "window unless labelled hold")
        return f"fix {pr} merges automatically once its checks pass"
    detail = _clip(row.get("detail"), 120)
    return "nightly maintenance handles this" + (f" ({detail})" if detail else "")


def _route_watch_item(row):
    head = f"{_section_name(row.get('section'))}: {_clip(_humanize(row.get('claim')), 200)}"
    status = row.get("status")
    command = ""
    if _route_class(row) == "progress":
        tail = _route_progress_text(row)
    elif row.get("approve"):
        tail = f"a {row.get('recommended') or 'fix'} is ready; approve it with"
        command = row["approve"]
    elif status == "failed":
        detail = _clip(row.get("detail"), 140)
        tail = "the automatic fix did not land" + (f" ({detail})" if detail else "") + \
            "; raised again next night"
    elif status == "pr_opened":
        tail = "a fix PR is waiting for review"
        command = str(row.get("pr_url") or "")
    elif status == "report_only":
        tail = "noted; never changed automatically"
    elif row.get("decision"):
        tail = f"open question: {_clip(_humanize(row['decision']), 160)}"
    else:
        tail = "no safe automatic fix; raised again if it persists"
    return _item("watch", f"{head} — {tail}", command=command)


def _route_needs_item(row):
    section = _section_name(row.get("section"))
    if row.get("status") == "failed":
        return _item(
            "needs", f"A follow-up fix only partly applied: {_clip(_humanize(row.get('claim')), 160)}",
            why=_clip(row.get("detail"), 240),
            todo="Finish the change by hand or undo it.",
            command=f"undo: {row['revert']}" if row.get("revert") else "",
        )
    why = ("Security finding; never changed automatically." if row.get("section") == "security-posture"
           else f"High-severity {section} finding with no safe automatic fix.")
    if row.get("approve"):
        return _item("needs", _clip(_humanize(row.get("claim")), 220), why=why,
                     todo="A fix is prepared; approve it with:", command=row["approve"])
    todo = (_clip(_humanize(row.get("decision")), 240) if row.get("decision")
            else "Decide how to handle it; nothing was changed automatically.")
    return _item("needs", _clip(_humanize(row.get("claim")), 220), why=why, todo=todo)


def _route_events(audit, fixes):
    items = []
    for row in _route_rows(audit, fixes):
        kind = _route_class(row)
        if kind == "needs":
            items.append(_route_needs_item(row))
        elif kind == "done":
            summary = _humanize(row.get("summary")) or "fixed automatically"
            items.append(_item("change", f"{_section_name(row.get('section'))}: {_clip(summary, 200)}",
                               group="Fixes by the steward", undo=row.get("revert") or ""))
        elif kind in ("watch", "progress"):
            items.append(_route_watch_item(row))
    return items


# ── steward code, public mirror, host drift, session memory ──────────

def _utc_text(value):
    parsed = _parse_utc(value)
    return parsed.strftime("%Y-%m-%d %H:%M UTC") if parsed else str(value or "")


def _steward_code_events(steward_code):
    """Startup steward-code merge + live-tree pickup as report items."""
    if not isinstance(steward_code, dict):
        return []
    items = []
    merge = steward_code.get("merge") if isinstance(steward_code.get("merge"), dict) else {}
    pickup = steward_code.get("pickup") if isinstance(steward_code.get("pickup"), dict) else {}
    status = pickup.get("status")
    reason = _clip(pickup.get("reason"), 200)
    merged = [pr for pr in merge.get("merged") or [] if isinstance(pr, dict)]
    picked = "; live scripts updated and verified" if status == "fast_forwarded" else ""
    for pr in merged:
        title = _clip(_humanize(str(pr.get("title") or "").removeprefix("steward: ")), 140)
        if pr.get("reverted_by"):
            items.append(_item(
                "rollback", f"Steward code: PR #{pr.get('number')} merged, then reverted "
                f"({_clip(pr.get('revert_reason') or 'live update failed its checks', 140)})",
                group="Fixes by the steward"))
        else:
            items.append(_item(
                "change", f"Steward code: PR #{pr.get('number')} merged — {title}{picked}",
                group="Fixes by the steward", undo=pr.get("undo") or ""))
    if status == "fast_forwarded" and not merged:
        commits = [c for c in pickup.get("commits") or [] if isinstance(c, dict)]
        subjects = "; ".join(_clip(c.get("subject"), 80) for c in commits[:3])
        items.append(_item(
            "change", f"Steward code: live scripts updated ({_plural(len(commits), 'commit')}"
            + (f": {subjects}" if subjects else "") + ")",
            group="Fixes by the steward"))
    for pr in merge.get("pending") or []:
        if not isinstance(pr, dict):
            continue
        if pr.get("needs_carter") or "CONFLICTING" in str(pr.get("reason") or ""):
            items.append(_item("watch", f"Steward code PR #{pr.get('number')} not merged: "
                               f"{_clip(pr.get('reason'), 160)}", command=pr.get("url") or ""))
        else:
            due = f"merges after {_utc_text(pr['due'])}" if pr.get("due") else "merges later"
            items.append(_item("watch", f"Steward code PR #{pr.get('number')} waiting — {due} "
                               "unless labelled hold", command=pr.get("url") or ""))
    for pr in merge.get("held") or []:
        if isinstance(pr, dict):
            items.append(_item("watch", f"Steward code PR #{pr.get('number')} held: "
                               f"{_clip(pr.get('reason'), 160)}"))
    errors = [str(e) for e in merge.get("errors") or []]
    if errors or merge.get("status") in ("warning", "failed"):
        items.append(_item("watch", "Steward code merge problem: "
                           + _clip("; ".join(errors) or merge.get("reason") or "", 240)))
    if status == "skipped":
        items.append(_item("watch", f"Steward code update not picked up yet: {reason}; "
                           "tried again at the next start"))
    elif status == "rolled_back":
        items.append(_item("watch", f"Steward code update rolled back after its checks failed: "
                           f"{reason}; the previous scripts are running"))
    elif status == "failed":
        items.append(_item(
            "needs", "Steward code update left the live scripts in an unverified state",
            why=reason or "the live update failed",
            todo="Recover the scripts by hand before the next run:",
            command=pickup.get("manual_recovery") or "",
        ))
    return items


def _omp_login_events(omp_login):
    """P0's omp login probe: a dead login silently fails every scheduled model job."""
    if not isinstance(omp_login, dict):
        return []
    provider = str(omp_login.get("provider") or "anthropic")
    status = omp_login.get("status")
    if status == "dead":
        return [_item(
            "needs", f"The {provider} model login is no longer valid",
            why="omp's stored login was rejected and disabled, so every scheduled model job "
                "fails until it is renewed: this report's audit and summary, Daily News, "
                "Hyperliquid and Dependabot. Audit sections show as incomplete meanwhile.",
            todo="Sign in again from an interactive omp session on the ThinkPad:",
            command=str(omp_login.get("login_command") or f"omp login {provider}"),
            problem="omp login expired",
        )]
    if status == "unknown":
        return [_item("watch", f"Could not check the {provider} model login: "
                      f"{_clip(omp_login.get('detail') or 'probe inconclusive', 160)}")]
    return []


def _public_mirror_events(public):
    """Last night's public dotfiles mirror: held/blocked files and failures."""
    if not public:
        return []
    items = []
    for key, text in (("held", "held back from the public mirror; previous version kept"),
                      ("blocked", "blocked from the public mirror")):
        rows = [r for r in public.get(key) or [] if isinstance(r, dict)]
        if rows:
            paths = ", ".join(str(r.get("path")) for r in rows[:10])
            more = f" (+{len(rows) - 10} more)" if len(rows) > 10 else ""
            items.append(_item("watch", f"{_plural(len(rows), 'file')} {text}",
                               command=paths + more))
    if public.get("phase_failed") or public.get("status") in ("failed", "error"):
        items.append(_item("watch", "Public mirror update failed: "
                           + _clip(public.get("reason") or public.get("error") or "", 200)))
    return items


def _public_mirror_count(public):
    return sum(len([r for r in (public or {}).get(key) or [] if isinstance(r, dict)])
               for key in ("added", "updated", "removed"))


def _host_drift_events(remediation, untracked_dotfiles, prev_dotfiles=None):
    """Report-only host drift, untracked dotfiles, and last night's blocked dotfiles commit."""
    items = []
    ufw = (remediation or {}).get("ufw_drift") or {}
    status = ufw.get("status")
    if status == "drift":
        for rule in ufw.get("missing") or []:
            items.append(_item("watch", "Firewall rule missing from the live firewall",
                               command=rule))
        for rule in ufw.get("extra") or []:
            items.append(_item("watch", "Firewall rule not in the expected list", command=rule))
    elif status and status != "ok":
        items.append(_item("watch", f"Firewall drift check did not run: "
                           f"{_clip(ufw.get('reason') or status, 160)}"))
    for row in (remediation or {}).get("docker_proxy") or []:
        if row.get("action") in {"attention_needed", "error"}:
            items.append(_item(
                "watch", f"Port {row.get('port')} ({row.get('container')}): "
                f"{_clip(row.get('reason') or row.get('error') or row.get('action'), 160)}"))
    probe = (remediation or {}).get("bridge_probe") or {}
    if probe.get("status") == "unreachable":
        items.append(_item("watch", "Open WebUI cannot reach the OpenCode Go proxy "
                           "(host.docker.internal:8082)"))
    if untracked_dotfiles:
        paths = ", ".join(untracked_dotfiles[:10])
        more = f" (+{len(untracked_dotfiles) - 10} more)" if len(untracked_dotfiles) > 10 else ""
        items.append(_item(
            "watch", f"{_plural(len(untracked_dotfiles), 'new dotfile')} not tracked; the "
            "nightly commit only takes vetted text files, add others by hand if wanted",
            command=paths + more))
    prev = prev_dotfiles or {}
    if prev.get("phase_failed") or prev.get("status") in {"secret_blocked", "push_blocked"}:
        hits = ", ".join(f"{f.get('path')}:{f.get('line')}"
                         for f in (prev.get("secret_findings") or [])[:5])
        items.append(_item(
            "watch", "Last dotfiles commit was blocked: "
            + _clip(prev.get("reason") or prev.get("status") or "", 200),
            command=hits))
    return items


def _session_memory_events(p0b):
    """Sessions whose notes could not be written (degraded session-memory phase only)."""
    if not p0b or p0b.get("phase_status") != "degraded":
        return []
    rows = [s for s in (p0b.get("sessions") or [])
            if isinstance(s, dict) and s.get("action") in P0B_PROBLEM_ACTIONS]
    counts = {}
    for s in rows:
        action = str(s.get("action")).replace("_", " ")
        counts[action] = counts.get(action, 0) + 1
    what = ", ".join(f"{n} {action}" for action, n in counts.items()) or "degraded"
    names = ", ".join(Path(str(s.get("path") or "?")).name for s in rows[:10])
    more = f" (+{len(rows) - 10} more)" if len(rows) > 10 else ""
    return [_item("watch", f"Session notes not updated ({what}); earlier notes kept",
                  command=names + more if names else "")]


# ── health ───────────────────────────────────────────────────────────

_CHECK_OK = ("ok", "pass", "skipped", "dry-run")
_CHECK_FAILED = ("fail", "failed", "error")


def _checks(validation):
    return [c for c in (validation or {}).get("checks", []) or [] if isinstance(c, dict)]


def _check_failing(check):
    return str(check.get("status") or "ok") in _CHECK_FAILED


def _health_events(validation, heartbeat, troubleshoot):
    """Health end state: failing checks are Carter's; warnings are Watching."""
    items = []
    heartbeat = heartbeat or {}
    if heartbeat.get("phase_failed"):
        items.append(_item(
            "needs", "The nightly health check did not run",
            why=_clip(heartbeat.get("error") or "unknown error", 200),
            todo=f"Read tonight's log ({STEWARD_JOURNAL}).",
            problem="health check failed"))
    ts = troubleshoot or {}
    regressed = set()
    if ts.get("triggered") and not ts.get("re_validation_healthy"):
        regressed = {str(name) for name in (ts.get("regressed") or {})}
        names = ", ".join(sorted(n.removeprefix("endpoint_") for n in regressed)) or "a service"
        steps = [str(s) for s in ts.get("next_steps") or []]
        items.append(_item(
            "needs", f"{names} still failing after the automatic repair attempts",
            why=_clip(ts.get("diagnosis") or "no diagnosis", 240),
            todo=_clip(steps[0], 240) if steps else "See the regression diagnosis below.",
            problem=f"{names} down"))
    elif ts.get("triggered"):
        fixed = [r for r in ts.get("fix_actions") or [] if isinstance(r, dict) and r.get("executed")]
        names = ", ".join(sorted({str(r.get("endpoint")) for r in fixed}))
        if names:
            items.append(_item("change", f"Recovered {names} automatically after tonight's updates",
                               group="Fixes by the steward"))
    for check in _checks(validation):
        status = str(check.get("status") or "ok")
        if check.get("name") in regressed:
            continue
        label = _check_label(check)
        if status in _CHECK_FAILED:
            items.append(_item(
                "needs", f"{label} check failing",
                why=_clip(check.get("error") or check.get("reason") or status, 200),
                todo=f"Check {label} and its logs; the steward did not fix it.",
                problem=f"{label} failing"))
        elif status not in _CHECK_OK:
            text = ("LLM routing on cloud fallback" if check.get("fallback_active")
                    else f"{label} check: {_clip(check.get('error') or check.get('reason') or status, 160)}")
            items.append(_item("watch", text))
    reboot = heartbeat.get("reboot", {}) or {}
    if reboot.get("needed"):
        items.append(_item("watch", f"ThinkPad reboot pending for kernel {reboot.get('kernel', '?')}"))
    units = heartbeat.get("failed_units", {}) or {}
    failed_units = [str(u).strip() for u in (units.get("user") or []) + (units.get("system") or [])
                    if u and str(u).strip()]
    if failed_units:
        items.append(_item("watch", f"{_plural(len(failed_units), 'systemd unit')} failed",
                           command=", ".join(failed_units)))
    return items


def _health_glance(validation, heartbeat):
    if (heartbeat or {}).get("phase_failed"):
        return "The health check did not run"
    checks = _checks(validation)
    failing = [c for c in checks if _check_failing(c)]
    if failing:
        return f"{len(failing)} failing: " + ", ".join(_check_label(c) for c in failing[:4])
    if not checks:
        return "No checks ran"
    warn = sum(1 for c in checks if str(c.get("status") or "ok") not in _CHECK_OK)
    return f"All {len(checks)} checks passed" + (f" ({_plural(warn, 'warning')})" if warn else "")


def _html_health(validation_data, hb_data, applied_data=None, memory_mib=None,
                 memory_high_mib=None):
    """Health: one line when every check passed, else only the failing checks;
    then one system line.

    memory_mib is the run's own memory.json maxima (_memory_mib); memory_high_mib
    defaults to the steward cgroup's MemoryHigh.
    """
    hb_data = hb_data or {}
    out = []
    if hb_data.get("phase_failed"):
        out.append(_row(_dot("danger") + "Heartbeat failed: "
                        + _esc(str(hb_data.get("error", "unknown error"))), COLOR["danger"]))
    checks = _checks(validation_data)
    flagged = [c for c in checks if str(c.get("status") or "ok") not in _CHECK_OK]
    if checks and not flagged:
        out.append(_row(_dot("ok") + f"All {len(checks)} checks passed"))
    elif flagged:
        rows = []
        for c in flagged:
            failing = _check_failing(c)
            chip = _chip("FAIL", COLOR["danger"]) if failing else _chip("WARN", COLOR["warn"])
            detail = "cloud fallback" if c.get("fallback_active") else \
                _clip(c.get("error") or c.get("reason") or "", 200)
            rows.append((_esc(_check_label(c)), f"{chip} {_esc(detail)}".strip()))
        out.append(_kv_rows(rows))
        others = len(checks) - len(flagged)
        if others:
            out.append(_row(f"{_plural(others, 'other check')} OK", COLOR["muted"], "4px 0 6px"))

    # System line (heartbeat runs after a mid-run ThinkPad reboot, so the run's own
    # reboot record says whether one happened tonight)
    parts = []
    disk = hb_data.get("disk", {}) or {}
    if disk.get("df_root"):
        cols = disk["df_root"].splitlines()[-1].split()
        if len(cols) >= 5:
            parts.append(f"Disk {_esc(cols[4])} used ({_esc(cols[2])}/{_esc(cols[1])})")
    mem_avail = (hb_data.get("memory", {}) or {}).get("available", "")
    if mem_avail:
        parts.append(f"Memory {_esc(str(mem_avail))} free")
    backup = (hb_data.get("backup", {}) or {}).get("last_run", "")
    if backup:
        parts.append(f"Backup {_esc(str(backup))}")
    rb = hb_data.get("reboot", {}) or {}
    host_reboot = (applied_data or {}).get("host_reboot")
    if rb.get("needed"):
        parts.append("Reboot: " + _dot("danger") + _esc(f'Needed — kernel {rb.get("kernel", "?")}'))
    elif host_reboot and host_reboot.get("rebooted"):
        parts.append("Reboot: " + _dot("ok") + _esc(
            f'Rebooted {host_reboot["time"]} UTC — kernel {host_reboot["kernel_after"]}'))
    elif host_reboot:
        parts.append("Reboot: " + _dot("warn") + _esc(
            f'Requested {host_reboot["time"]} UTC — host did not restart'))
    else:
        parts.append("Reboot: Not needed")
    note = _steward_memory_note(
        memory_mib,
        memory_high_mib if memory_high_mib is not None else _steward_memory_high_mib(),
    ) if memory_mib else None
    if note:
        text, warn = note
        if warn:
            parts.append("Steward memory: " + _dot("warn") + _esc(text))
        else:
            parts.append(f"Steward peak {memory_mib['max_anon_mib']} MiB")
    out.append(_row(" · ".join(parts), COLOR["muted"], "6px 0 4px"))

    extra = []
    units = hb_data.get("failed_units", {}) or {}
    failed_units = [str(u).strip() for u in (units.get("user") or []) + (units.get("system") or [])
                    if u and str(u).strip()]
    missing = (hb_data.get("units", {}) or {}).get("missing", [])
    if failed_units or missing:
        cells = [_dot("danger") + _esc(u) for u in failed_units]
        if missing:
            cells.append(_dot("warn") + "missing: " + _esc(", ".join(map(str, missing))))
        extra.append(("Systemd units", " ".join(cells)))
    dns = hb_data.get("dns", {}) or {}
    if dns:
        ok = sum(1 for v in dns.values() if v.get("resolves"))
        if ok != len(dns):
            extra.append(("DNS", _dot("warn") + f"{ok}/{len(dns)} hostnames resolve"))
    tls = hb_data.get("tls_certs", {}) or {}
    expiring = []
    for host, expiry in tls.items():
        match = re.search(r"notAfter=(.+?\d{4})\s", expiry)
        if match:
            try:
                days_left = (datetime.strptime(match.group(1), "%b %d %H:%M:%S %Y %Z")
                             - datetime.now()).days
            except ValueError:
                continue
            if days_left <= 30:
                expiring.append(f'{host.split(".")[0]} ({days_left}d)')
    if expiring:
        extra.append(("TLS expiring", _dot("warn") + _esc(", ".join(expiring))))
    if (hb_data.get("llm_stack", {}) or {}).get("falling_back", False):
        extra.append(("LLM proxy", _dot("warn") + "Cloud fallback"))
    for app, result in (hb_data.get("bundle_audit", {}) or {}).items():
        if "no vulnerabilities" not in str(result):
            extra.append((f"bundle-audit ({_esc(app)})", _dot("warn") + _esc(_clip(str(result), 400))))
    if extra:
        out.append(_kv_rows(extra))
    return "".join(out)


# ── audit ────────────────────────────────────────────────────────────

def _audit_incomplete_summary(payload):
    """Deterministic wording for steward automation failures."""
    label = _section_name(payload["name"])
    verdict = payload.get("verdict", "")
    raw_error = str(payload.get("error") or "").strip()
    short_error = raw_error.split("\n", 1)[0][:180] or verdict
    if verdict == "judge-failed":
        stage = (
            "its judge returned invalid output after the automatic retry"
            if "retry also failed" in raw_error
            else "its judge returned invalid output"
        )
    elif verdict == "worker-failed":
        stage = "its worker could not produce a valid result after the automatic retry"
    else:
        stage = "its evidence collector failed"
    return (
        f"The {label} audit was incomplete because {stage} ({short_error}). "
        f"No underlying problem was established; it runs again next night."
    )


def _audit_unverifiable_summary(payload):
    """Deterministic wording for UNVERIFIABLE sections; zero confirmed findings is not a pass."""
    label = _section_name(payload["name"])
    rejected = payload.get("rejected") or []
    count = len(rejected) or payload.get("n_worker_findings") or 0
    items = []
    for r in rejected[:3]:
        item = _clip(r.get("claim"), 200)
        reason = _clip(r.get("reason"), 160)
        if item and reason:
            item += f" (not verified: {reason})"
        if item:
            items.append(item)
    head = (
        f"The {label} audit could not verify {count} finding(s)"
        if count else f"The {label} audit could not verify its findings"
    )
    if items:
        head += ": " + "; ".join(items)
    if len(rejected) > len(items):
        head += f"; {len(rejected) - len(items)} more"
    error = str(payload.get("error") or "").strip().split("\n", 1)[0][:180]
    if error:
        head += f" ({error})"
    return (
        f"{head}. Nothing was confirmed or ruled out; the section runs again next night."
    )


def _audit_incomplete(verdict):
    base = str(verdict or "").removeprefix("cached-")
    return str(verdict or "").endswith("-failed") or base == "UNVERIFIABLE"


_AUDIT_OUTCOMES = (  # route class -> (chip, colour), most important first
    ("needs", "Needs you", COLOR["danger"]),
    ("watch", "Watching", COLOR["info"]),
    ("progress", "In progress", COLOR["info"]),
    ("done", "Fixed", COLOR["ok"]),
    ("noop", "Already fixed", COLOR["ok"]),
)


def _audit_incomplete_text(sec):
    """Deterministic wording for an incomplete (failed or UNVERIFIABLE) audit section."""
    verdict = str(sec.get("verdict") or "")
    payload = {
        "name": sec.get("name") or "unknown", "verdict": verdict,
        "rejected": [r for r in sec.get("judge_rejected") or [] if isinstance(r, dict)],
        "n_worker_findings": len(sec.get("worker_findings") or []),
        "error": (sec.get("error") or sec.get("worker_error") or sec.get("judge_error") or ""),
    }
    return _humanize(_audit_incomplete_summary(payload) if verdict.endswith("-failed")
                     else _audit_unverifiable_summary(payload))


def _audit_section_outcome(sec, rows):
    """(chip, colour, text) for one non-PASS audit section.

    Routed findings are already shown above (Needs You, What changed, Watching) or
    were already fixed, so their section gets a chip only; a short claim appears
    only for confirmed findings that were never routed.
    """
    if _audit_incomplete(sec.get("verdict")):
        return "Incomplete", COLOR["warn"], _audit_incomplete_text(sec)
    classes = {_route_class(r) for r in rows}
    for kind, chip, color in _AUDIT_OUTCOMES:
        if kind in classes:
            return chip, color, ""
    claims = [f.get("claim") for f in sec.get("judge_confirmed") or [] if isinstance(f, dict)]
    return "Noted", COLOR["muted"], (_clip(_humanize(claims[0]), 120) if claims
                                     else "Findings reviewed; nothing to change.")


def _html_audit(audit_data, fixes_data=None):
    """One line when every section passed; otherwise a compact line per non-PASS section."""
    sections = (audit_data or {}).get("sections", []) or []
    if not sections:
        return _row("No audit results.", COLOR["muted"])
    routes_by_section = {}
    for row in _route_rows(audit_data, fixes_data):
        routes_by_section.setdefault(row.get("section"), []).append(row)
    open_sections = [s for s in sections if s.get("verdict") not in ("PASS", "cached-PASS")]
    if not open_sections:
        return _row(_dot("ok") + f"All {len(sections)} audit sections passed")
    out = []
    for sec in open_sections:
        chip, color, text = _audit_section_outcome(
            sec, routes_by_section.get(sec.get("name"), []))
        detail = (f'<tr><td colspan="2" style="padding:0 0 2px; color:{COLOR["text"]}; '
                  f'font-size:13px; line-height:1.45;">{_esc(text)}</td></tr>' if text else "")
        out.append(
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="font-size:13px; border-collapse:collapse; margin:0 0 6px;">'
            f'<tr><td style="padding:2px 0; color:{COLOR["ink"]}; font-weight:700;">'
            f'{_esc(_section_name(sec.get("name")))}</td>'
            f'<td align="right" style="padding:2px 0; white-space:nowrap;">{_chip(chip, color)}</td></tr>'
            f'{detail}</table>'
        )
    passed = len(sections) - len(open_sections)
    if passed:
        out.append(_row(f"{_plural(passed, 'other section')} passed", COLOR["muted"]))
    return "".join(out)


def _audit_incomplete_sections(audit):
    return [sec for sec in (audit or {}).get("sections", []) or []
            if _audit_incomplete(sec.get("verdict"))]


def _audit_incomplete_events(audit):
    return [_item("watch", f"Audit incomplete — {_audit_incomplete_text(sec)}")
            for sec in _audit_incomplete_sections(audit)]


# ── triage ───────────────────────────────────────────────────────────

def _triage(applied, audit, fixes, *, steward_code=None, validation=None, heartbeat=None,
            troubleshoot=None, remediation=None, untracked_dotfiles=None, prev_dotfiles=None,
            public=None, p0b=None, rig_last_ok=None, omp_login=None):
    """Every report item, triaged once.

    Needs You is only for extreme items: a service still failing (P3 could not
    fix it, heartbeat failed, a check failing at report time); an unverified
    rollback, Docker daemon failure, unrepairable OMP DB or a rig unhealthy
    after reboot; a dead omp model login; a steward-code pickup left unverified
    or a partly applied follow-up fix; a high-severity or security audit finding
    left for Carter;
    or the whole maintenance phase failing. Everything else still open is
    Watching. Changes are deduplicated and numbered for the undo appendix.
    """
    items = (
        _health_events(validation, heartbeat, troubleshoot)
        + _p1_events(applied, rig_last_ok)
        + _route_events(audit, fixes)
        + _steward_code_events(steward_code)
        + _omp_login_events(omp_login)
        + _public_mirror_events(public)
        + _host_drift_events(remediation, untracked_dotfiles, prev_dotfiles)
        + _session_memory_events(p0b)
        + _audit_incomplete_events(audit)
    )
    seen = set()
    needs, watching, changes = [], [], []
    for item in items:
        key = (item["kind"], item["group"], item["text"], item["command"])
        if key in seen:
            continue
        seen.add(key)
        if item["kind"] == "needs":
            needs.append(item)
        elif item["kind"] == "watch":
            watching.append(item)
        else:
            changes.append(item)
    needs.sort(key=lambda i: not i["problem"])
    changes.sort(key=lambda i: _CHANGE_GROUPS.index(i["group"]))
    undo = []
    for item in changes:
        if item["undo"]:
            undo.append(item)
            item["ref"] = len(undo)
    triaged = {
        "needs": needs, "watching": watching, "changes": changes, "undo": undo,
        "health": _health_glance(validation, heartbeat),
        "audit_incomplete": [_section_name(s.get("name")) for s in _audit_incomplete_sections(audit)],
        "public_published": _public_mirror_count(public),
    }
    triaged["verdict"] = _verdict(triaged)
    return triaged


def _change_counts(changes):
    """(total, 'x updates, y deploys, z fixes') over real changes (no housekeeping)."""
    real = [c for c in changes if c["kind"] == "change" and c["group"] != "Housekeeping"]
    counts = {}
    for c in real:
        word = {"Deploys": "deploy", "Fixes by the steward": "fix"}.get(c["group"], "update")
        counts[word] = counts.get(word, 0) + 1
    words = {"update": ("update", "updates"), "deploy": ("deploy", "deploys"),
             "fix": ("fix", "fixes")}
    text = ", ".join(_plural(counts[w], *words[w]) for w in ("update", "deploy", "fix") if w in counts)
    return len(real), text


def _verdict(triaged):
    """(level, text): level ok | needs | problem."""
    needs = triaged["needs"]
    problems = [i["problem"] for i in needs if i["problem"]]
    if problems:
        more = f" (+{len(needs) - 1} more)" if len(needs) > 1 else ""
        return "problem", f"Problem: {problems[0]}{more}"
    if needs:
        return "needs", f"Needs you ({len(needs)})"
    return "ok", "All good"


def _subject(date_str, triaged):
    total, _ = _change_counts(triaged["changes"])
    return (f"Homelab Steward {date_str} — {triaged['verdict'][1]}"
            + (f" · {_plural(total, 'change')}" if total else ""))


# ── email blocks ─────────────────────────────────────────────────────

def _html_banner(triaged):
    level, verdict = triaged["verdict"]
    color = COLOR["ok"] if level == "ok" else COLOR["danger"]
    headline = {"ok": "All good — nothing needs you",
                "needs": f"Needs you: {len(triaged['needs'])}"}.get(level, verdict)
    total, breakdown = _change_counts(triaged["changes"])
    changes = (f"{_plural(total, 'change')} tonight: {breakdown}" if total
               else "No changes tonight")
    needs = (f"{_plural(len(triaged['needs']), 'item')} below" if triaged["needs"] else "Nothing")
    glance = "".join(
        f'<tr><td width="22%" style="padding:2px 10px 2px 0; color:{COLOR["muted"]}; '
        f'font-size:13px; vertical-align:top;">{label}</td>'
        f'<td style="padding:2px 0; color:{COLOR["text"]}; font-size:13px;">{_esc(value)}</td></tr>'
        for label, value in (("Health", triaged["health"]), ("Changes", changes),
                             ("Needs you", needs))
    )
    return (
        '<tr><td style="padding:22px 32px 4px;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'style="background-color:{color}1f; border-left:4px solid {color}; border-radius:6px;">'
        '<tr><td style="padding:12px 16px;">'
        f'<p style="margin:0 0 6px; color:{color}; font-size:16px; font-weight:700;">'
        f'{_esc(headline)}</p>'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'style="border-collapse:collapse;">{glance}</table>'
        '</td></tr></table></td></tr>'
    )


def _html_needs_you(needs):
    if not needs:
        return ""
    rows = []
    for item in needs:
        parts = [f'<strong>{_esc(item["text"])}</strong>']
        if item["why"]:
            parts.append(_esc(item["why"]))
        todo = _esc(item["todo"]) + (f" {_code(item['command'])}" if item["command"] else "")
        if todo:
            parts.append(f'<strong>What to do:</strong> {todo}')
        rows.append(_row("<br>".join(parts), margin="0 0 10px"))
    return _section("Needs you", COLOR["danger"], "".join(rows))


def _html_changes(changes):
    if not changes:
        return ""
    out = []
    group = None
    for item in changes:
        if item["group"] != group:
            group = item["group"]
            if group != "Housekeeping":
                out.append(_label(group))
        ref = (f'<sup style="font-size:10px;"><a href="#undo-{item["ref"]}" '
               f'style="color:{COLOR["muted"]}; text-decoration:none;">[{item["ref"]}]</a></sup>'
               if item.get("ref") else "")
        color = {"rollback": COLOR["warn"], "chore": COLOR["muted"]}.get(item["kind"])
        out.append(_row(_esc(item["text"]) + ref, color, "0 0 4px"))
    return _section("What changed tonight", COLOR["ok"], "".join(out))


def _html_watching(watching):
    if not watching:
        return ""
    rows = [
        _row(_esc(item["text"]) + (f"<br>{_code(item['command'])}" if item["command"] else ""),
             margin="0 0 6px")
        for item in watching
    ]
    return _section("Watching — no action needed", COLOR["info"], "".join(rows))


def _html_troubleshoot(troubleshoot):
    """P3 regression diagnosis (only when it triggered)."""
    if not (troubleshoot or {}).get("triggered"):
        return ""
    if troubleshoot.get("re_validation_healthy"):
        chip, color = "Recovered", COLOR["ok"]
    elif troubleshoot.get("agent_status") == "diagnosed":
        chip, color = "Needs you", COLOR["danger"]
    else:
        chip, color = "Undiagnosed", COLOR["danger"]
    body = [_row(f'{_chip(chip, color)} <strong>Likely cause:</strong> '
                 f'{_esc(str(troubleshoot.get("diagnosis") or "unknown"))}')]
    steps = [str(s) for s in troubleshoot.get("next_steps") or []]
    if steps:
        body.append(_label("Suggested next steps"))
        body.extend(_row(f"{n}. {_esc(s)}", margin="0 0 4px") for n, s in enumerate(steps, 1))
    fixes = [r for r in troubleshoot.get("fix_actions") or [] if isinstance(r, dict)]
    if fixes:
        body.append(_label("Automatic repair attempts"))
    for r in fixes:
        endpoint = _esc(str(r.get("endpoint", "?")))
        conf = r.get("confidence")
        conf_text = f"confidence {conf:.2f}" if isinstance(conf, (int, float)) else "no answer"
        if r.get("executed"):
            text = (f"<strong>{endpoint}</strong>: ran {_esc(str(r.get('choice')))} "
                    f"({conf_text}, exit {_esc(str(r.get('exit_code')))}) → "
                    f"{_esc(str(r.get('outcome', 'not re-validated')))}")
        else:
            choice = f"chose {_esc(str(r.get('choice')))}, " if r.get("choice") else ""
            text = (f"<strong>{endpoint}</strong>: no action ({choice}{conf_text}; "
                    f"{_esc(str(r.get('reason', '')))})")
        body.append(_row(text, margin="0 0 4px"))
    return _section("Regression diagnosis", color, "".join(body))


def _html_queue(queue_data):
    """Work queue: ideas, plans, status reconciles, inconsistencies ("" when all are empty)."""
    queue_data = queue_data or {}
    ideas = queue_data.get("ideas", {}) or {}
    plans = queue_data.get("plans", {}) or {}
    inconsistencies = queue_data.get("inconsistencies", []) or []
    reconcile = queue_data.get("status_reconcile", {}) or {}
    out = []

    outstanding = ideas.get("outstanding", [])
    if outstanding:
        out.append(_label(f"Ideas outstanding ({len(outstanding)})"))
        out.append(_kv_rows([
            (f'{idea.get("age_days", "?")}d',
             _esc(str(idea.get("heading", "") or idea.get("file", ""))))
            for idea in outstanding[:10]
        ]))

    plan_groups = [
        ("Draft", plans.get("draft", []), COLOR["info"]),
        ("Approved", plans.get("approved", []), COLOR["ok"]),
        ("Implementing", plans.get("implementing", []), COLOR["warn"]),
        ("Done this week", plans.get("done_this_week", []), COLOR["faint"]),
    ]
    plan_rows = [
        (_chip(label, color), _esc(str(item.get("heading", item.get("file", "")) or "")))
        for label, items, color in plan_groups for item in items[:5]
    ]
    if plan_rows:
        out.append(_label("Plans"))
        out.append(_kv_rows(plan_rows))

    applied = [
        a for a in (reconcile.get("applied") or [])
        if a.get("status") in ("updated", "dry_run")
    ]
    if applied:
        out.append(_label(f"Status updates ({len(applied)})"))
        rows = []
        for a in applied[:8]:
            label = a.get("new_status") or a.get("would_set") or a.get("status")
            detail = a.get("file", "?")
            reason = a.get("reason") or ""
            if reason:
                detail = f"{detail} — {reason[:100]}"
            rows.append((_chip(_esc(str(label)), COLOR["ok"]), _esc(detail)))
        out.append(_kv_rows(rows))

    if inconsistencies:
        out.append(_label("Inconsistencies"))
        out.append(_kv_rows([(_esc(str(inc["type"])), _esc(str(inc["detail"])[:200]))
                             for inc in inconsistencies]))
    return "".join(out)


def _usage_fresh(usage_data):
    return any(a.get("usage_fresh") for a in (usage_data or {}).get("accounts", []) or [])


def _html_usage(usage_data):
    """OpenCode Go usage bars for accounts with fresh usage ("" when none is fresh).

    Windows match opencode-go-proxy / ocusage: rolling is 5h (not 24h).
    Each row shows reset_in when the proxy provides it.
    """
    out = []
    for acct in (usage_data or {}).get("accounts", []) or []:
        if not acct.get("usage_fresh"):
            continue
        out.append(
            f'<p style="margin:0 0 3px; font-size:13px;">'
            f'<strong style="color:{COLOR["ink"]};">{_esc(str(acct.get("name", "?")))}</strong> '
            f'<span style="color:{COLOR["muted"]}; font-size:13px;">{_esc(str(acct.get("tier", "?")))}</span></p>'
        )
        rows = (
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="font-size:13px; border-collapse:collapse; margin-bottom:10px;">'
        )
        for label, pct_key, reset_key, color in [
            ("5h", "rolling_pct", "rolling_reset_in", COLOR["ink"]),
            ("7d", "weekly_pct", "weekly_reset_in", COLOR["week"]),
            ("30d", "monthly_pct", "monthly_reset_in", COLOR["month"]),
        ]:
            try:
                pct = float(acct.get(pct_key, 0))
            except (TypeError, ValueError):
                pct = 0.0
            fill_color = COLOR["danger"] if pct >= 90 else color
            reset_in = (acct.get(reset_key) or "").strip()
            pct_cell = f"{pct:.0f}%"
            if reset_in:
                pct_cell += (
                    f' <span style="color:{COLOR["muted"]}; font-weight:400; font-size:12px;">'
                    f'· reset {_esc(reset_in)}</span>'
                )
            rows += (
                '<tr>'
                f'<td width="18%" style="padding:3px 0; color:{COLOR["muted"]}; '
                f'vertical-align:middle;">{label}</td>'
                f'<td width="42%" style="padding:3px 0; vertical-align:middle;">'
                f'{_mini_bar(pct, fill_color)}</td>'
                f'<td align="right" width="40%" style="padding:3px 0; color:{COLOR["text"]}; '
                f'font-weight:600; vertical-align:middle; white-space:nowrap;">{pct_cell}</td>'
                '</tr>'
            )
        out.append(rows + '</table>')
    return "".join(out)


def _mini_bar(pct, color=COLOR["slate"]):
    """Inline 0-100% horizontal bar, email-safe via nested table cells. Min fill 2% when pct>0."""
    try:
        w = max(0.0, min(100.0, float(pct)))
    except (TypeError, ValueError):
        w = 0.0
    fill_w = max(w, 2.0) if w > 0 else 0.0
    return (
        '<table role="presentation" cellpadding="0" cellspacing="0" width="100%" '
        'style="border-collapse:collapse;"><tr>'
        f'<td width="{fill_w:.0f}%" style="background-color:{color}; height:5px; '
        f'line-height:5px; font-size:0;">&nbsp;</td>'
        f'<td width="{100-fill_w:.0f}%" style="background-color:{COLOR["track"]}; height:5px; '
        f'line-height:5px; font-size:0;">&nbsp;</td>'
        '</tr></table>'
    )


def _html_footer(triaged, usage, run_dir, dry_run=False):
    """Reference: numbered undo commands, mirror count, usage note, run dir."""
    out = []
    para = f'margin:0 0 6px; color:{COLOR["muted"]}; font-size:12px; line-height:1.5;'
    if triaged["undo"]:
        out.append(f'<p style="{para} font-weight:700; text-transform:uppercase; '
                   'letter-spacing:0.8px;">Undo</p>')
        for item in triaged["undo"]:
            commands = "<br>".join(_code(u) for u in item["undo"])
            out.append(
                f'<p style="{para}"><a name="undo-{item["ref"]}" id="undo-{item["ref"]}"></a>'
                f'[{item["ref"]}] {_esc(_clip(item["text"], 90))}<br>{commands}</p>'
            )
    if triaged["public_published"]:
        out.append(f'<p style="{para}">Public mirror: published '
                   f'{_plural(triaged["public_published"], "changed file")}</p>')
    if not _usage_fresh(usage):
        why = "proxy unreachable" if (usage or {}).get("proxy_error") else "proxy dormant"
        out.append(f'<p style="{para}">OpenCode Go usage unavailable ({why})</p>')
    engine = "steward_runner.py (dry-run)" if dry_run else "steward_runner.py"
    out.append(
        f'<p style="margin:8px 0 0; color:{COLOR["muted"]}; font-size:11px; text-align:center;">'
        f'carter2099.com · Generated {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")} · '
        f'{engine} · run dir: {_esc(str(run_dir))}</p>'
    )
    return "".join(out)


# ── TL;DR ────────────────────────────────────────────────────────────

def _build_tldr_facts(triaged):
    """Typed end-state facts for the TL;DR (model input and deterministic fallback)."""
    return {
        "action_needed": bool(triaged["needs"]),
        "needs_you": [
            {"id": f"n{index}", "what": item["text"], "why": item["why"], "todo": item["todo"]}
            for index, item in enumerate(triaged["needs"], 1)
        ],
        "changes": [c["text"] for c in triaged["changes"] if c["kind"] != "chore"],
        "watching": [w["text"] for w in triaged["watching"]],
        "audit_incomplete": triaged["audit_incomplete"],
    }


_TLDR_RETRY_WORDS = re.compile(
    r"(?i)\b(retr(?:y|ies|ied|ying)|try(?:ing)? again|automation trouble|malformed)\b"
)
# The banner already states the verdict, health and change counts.
_TLDR_BANNER_RESTATEMENT = re.compile(
    r"(?i)\ball good\b|\bnothing (?:else )?(?:needs|requires) (?:you|carter|him)\b"
    r"|\bno action (?:is )?needed\b|\bneeds you\s*[:(]"
    r"|\b(?:\d+|one|two|three|four|five|six|seven|eight|nine|ten)\s+"
    r"(?:changes?|updates?|deploys?|fixes|fix|items?)\b"
)
TLDR_MAX_WORDS = 60
TLDR_MAX_SENTENCES = 3


def _tldr_payload(facts, date_str):
    """Model input: Needs You items with ids, the notable changes and Watching items."""
    needs = facts["needs_you"][:6]
    payload = {
        "date": date_str,
        "needs_you": needs,
        "more_needs_you_not_listed": max(0, len(facts["needs_you"]) - len(needs)),
        "changes": facts["changes"][:8],
        "watching": facts["watching"][:6],
        "audit_incomplete": facts["audit_incomplete"][:4],
    }
    return payload, needs


def _tldr_has_news(facts):
    """Whether anything beyond the banner's verdict, health and counts is worth a summary."""
    return bool(facts["needs_you"] or facts["changes"] or facts["watching"]
                or facts["audit_incomplete"])


def _tldr_violations(packet, *, action_needed, lead_ids, need_ids, retry_allowed):
    """Structural contradictions between the model's summary and its facts."""
    if not isinstance(packet, dict):
        return ["the reply was not a JSON object"]
    violations = []
    summary = str(packet.get("summary") or "").strip()
    if len(summary) < 20:
        violations.append("summary is missing or shorter than one sentence")
    if summary.startswith("{") and '"type"' in summary[:80]:
        violations.append("summary contains raw event-stream text")
    if _TLDR_BANNER_RESTATEMENT.search(summary):
        violations.append("summary restates the banner (verdict or counts); say what is "
                          "notable instead")
    if len(summary.split()) > TLDR_MAX_WORDS:
        violations.append(f"summary must be at most {TLDR_MAX_WORDS} words")
    if len(re.findall(r"[.!?](?:\s|$)", summary)) > TLDR_MAX_SENTENCES:
        violations.append(f"summary must be at most {TLDR_MAX_SENTENCES} sentences")
    if packet.get("action_needed") is not action_needed:
        violations.append(
            f"action_needed must be {'true' if action_needed else 'false'} for these facts"
        )
    mentioned = {str(x) for x in packet.get("mentioned_ids") or [] if x}
    unknown = sorted(mentioned - set(need_ids))
    if unknown:
        violations.append(
            "mentioned_ids names ids that are not in the facts: " + ", ".join(unknown)
        )
    if lead_ids:
        if str(packet.get("lead_id") or "") not in lead_ids:
            violations.append(
                "the summary must open with what needs Carter (" + ", ".join(lead_ids) + ")"
            )
        missing = [i for i in lead_ids if i not in mentioned]
        if missing:
            violations.append("every listed needs_you item must be mentioned: " + ", ".join(missing))
    if not retry_allowed and _TLDR_RETRY_WORDS.search(summary):
        violations.append(
            "no audit check was incomplete tonight, so nothing may be described as retried, "
            "malformed, or automation trouble"
        )
    return violations


def _tldr_prompt(date_str, payload, session_memory):
    return (
        f"You are the Homelab Steward writing the top-of-email summary for {date_str}.\n\n"
        f"FACTS (end state after tonight's run):\n{json.dumps(payload, indent=2)}\n\n"
        "Recent session memory (context only; never report it as tonight's news):\n"
        f"{session_memory}\n\n"
        f"Write 1 to {TLDR_MAX_SENTENCES} short plain-English sentences for Carter, at most "
        f"{TLDR_MAX_WORDS} words in total. A banner directly above already shows the verdict "
        "(all good / needs you / problem), service health and the number of changes, so never "
        "restate them: no \"all good\", no \"nothing needs you\", no counts of changes, updates "
        "or watched items. Say what is most notable instead:\n"
        "1. If needs_you is non-empty, open with what needs Carter and why (at most three "
        "items, then how many more).\n"
        "2. needs_you items are real open problems: never call one automation trouble or "
        "malformed, and never say it will be retried. Only audit_incomplete entries are the "
        "steward's own trouble and may be described as running again.\n"
        "3. Then the change(s) that matter most (a notable version, a fix, a rollback) and, "
        "if any, the watched item worth knowing about and why it is being watched. Skip "
        "routine bumps; the email lists every change.\n"
        "No bullet lists, markdown, step ids, badge words, or artifact names.\n\n"
        "Return ONLY a fenced JSON object:\n"
        '```json\n{"action_needed": false, "lead_id": "", "mentioned_ids": [], '
        '"summary": "1-3 sentences"}\n```\n'
        "action_needed is true exactly when needs_you is non-empty. lead_id is the id of the "
        "needs_you item your first sentence is about (empty when needs_you is empty). "
        "mentioned_ids lists every needs_you id your summary mentions."
    )


def _build_tldr(triaged, date_str, session_memory=""):
    """Model-written end-state TL;DR, checked against the facts it was given.

    A contradiction gets one corrected rewrite, then the deterministic summary.
    Returns HTML-safe text; "" when the banner already says everything.
    """
    facts = _build_tldr_facts(triaged)
    if not _tldr_has_news(facts):
        return ""
    payload, needs = _tldr_payload(facts, date_str)
    rules = {
        "action_needed": facts["action_needed"],
        "lead_ids": [n["id"] for n in needs][:3],
        "need_ids": [n["id"] for n in needs],
        "retry_allowed": bool(facts["audit_incomplete"]),
    }
    prompt = _tldr_prompt(date_str, payload, session_memory)
    try:
        packet = _extract_json(
            _call_omp_p(prompt, model=STEWARD_MODEL, timeout=90, mode="json", tools=NO_TOOLS), "tldr"
        )
        violations = _tldr_violations(packet, **rules)
        if violations:
            print("  TLDR contradicted its facts: " + "; ".join(violations))
            retry = (
                f"{prompt}\n\nYour previous answer broke these rules:\n- "
                + "\n- ".join(violations)
                + f"\nPrevious answer: {json.dumps(packet)[:1500]}\n"
                "Return a corrected JSON object."
            )
            packet = _extract_json(
                _call_omp_p(retry, model=STEWARD_MODEL, timeout=90, mode="json", tools=NO_TOOLS),
                "tldr-retry",
            )
            violations = _tldr_violations(packet, **rules)
            if violations:
                raise ValueError("; ".join(violations))
        summary_text = str(packet["summary"]).strip()
        if summary_text.startswith("```"):
            summary_text = re.sub(r"^```(?:\w+)?\n?", "", summary_text)
            summary_text = re.sub(r"\n?```$", "", summary_text).strip()
    except Exception as error:
        print(f"  TLDR model summary rejected: {error}")
        summary_text = _tldr_deterministic(facts)

    safe = html.escape(summary_text)
    safe = re.sub(r"\n\n+", "<br><br>", safe)
    return safe.replace("\n", " ")


def _tldr_deterministic(facts):
    """Fallback summary: only what the banner does not already say ("" if nothing)."""
    parts = []
    needs = facts.get("needs_you") or []
    if needs:
        top = needs[:3]
        rest = len(needs) - len(top)
        parts.append("; ".join(_clip(n["what"], 120) for n in top)
                     + (f" (plus {rest} more)" if rest else "") + ".")
    if facts.get("audit_incomplete"):
        parts.append("Audit incomplete for " + ", ".join(facts["audit_incomplete"][:3])
                     + "; it runs again next night.")
    return " ".join(parts)


# ── P8: render + send ────────────────────────────────────────────────

def _read_artifact(run_dir, name, default):
    path = Path(run_dir) / name
    return read_json(path) if path.exists() else default


def _report_inputs(run_dir, setup_data):
    """Load every artifact the report reads and triage it (shared by P8 and P9)."""
    date_str = setup_data["date"]
    applied = _read_artifact(run_dir, "01-applied.json", {"steps": []})
    host_reboot = _host_reboot_status(run_dir)
    if host_reboot:
        applied["host_reboot"] = host_reboot
    # P3 re-validates after its fix menu; that result is the report-time state.
    validation = (_read_artifact(run_dir, "02b-validation.json", None)
                  or _read_artifact(run_dir, "02-validation.json", {"checks": []}))
    troubleshoot = _read_artifact(run_dir, "03-troubleshoot.json", {})
    heartbeat = _read_artifact(run_dir, "04-heartbeat.json", {})
    queue = _read_artifact(run_dir, "05-queue.json", {})
    audit = _read_artifact(run_dir, "07-audit.json", {"sections": []})
    fixes = _load_fixes_with_resolutions(run_dir)
    try:
        prev_date = prev_workday(datetime.strptime(date_str, "%Y-%m-%d")).strftime("%Y-%m-%d")
        prev_dotfiles = _load_prev_artifact(run_dir, prev_date, "09b-dotfiles.json") or {}
        # P9c runs after P8, so the email reports the previous run's mirror.
        public = _load_prev_artifact(run_dir, prev_date, "09c-public-dotfiles.json") or {}
    except ValueError:
        prev_dotfiles, public = {}, {}
    rig_skipped = any(isinstance(s, dict) and s.get("step") in _RIG_STEPS
                      and s.get("status") == "skipped" for s in applied.get("steps") or [])
    omp_login = setup_data.get("omp_login")
    if isinstance(omp_login, dict) and omp_login.get("status") in ("dead", "unknown"):
        # P0 may be cached from before a fix (--resume after `omp login`), and P0's own
        # probe may be the call whose refresh fails (omp disables the credential only
        # afterwards): re-probe so a login that is dead now is Needs You and a renewed one
        # is quiet. An inconclusive recheck keeps P0's verdict.
        recheck = _omp_login_probe()
        if recheck["status"] in ("ok", "dead"):
            omp_login = recheck
    triaged = _triage(
        applied, audit, fixes,
        steward_code=setup_data.get("steward_code"),
        omp_login=omp_login,
        validation=validation,
        heartbeat=heartbeat,
        troubleshoot=troubleshoot,
        remediation=_read_artifact(run_dir, "03a-remediation.json", {}),
        untracked_dotfiles=_dotfiles_untracked_paths(),
        prev_dotfiles=prev_dotfiles,
        public=public,
        p0b=_read_artifact(run_dir, "00b-session-memory.json", {}),
        rig_last_ok=_rig_last_maintained(run_dir, date_str) if rig_skipped else None,
    )
    return {
        "applied": applied, "validation": validation, "troubleshoot": troubleshoot,
        "heartbeat": heartbeat, "queue": queue, "audit": audit, "fixes": fixes,
        "triaged": triaged,
    }


_TLDR_ROW = re.compile(r"<tr><td[^>]*>\s*<p[^>]*>\{\{TLDR\}\}</p>\s*</td></tr>\n?")


def phase_8_render_send(run_dir, setup_data, dry_run=False):
    """Phase 8: render HTML from all artifacts and send email."""
    print("[P8] render + send")

    date_str = setup_data["date"]
    usage = setup_data.get("usage", {})
    data = _report_inputs(run_dir, setup_data)
    triaged = data["triaged"]

    tldr = _build_tldr(triaged, date_str, session_memory=_session_memory_context())

    queue_html = _html_queue(data["queue"])
    usage_html = _html_usage(usage)
    sections = "".join([
        _html_needs_you(triaged["needs"]),
        _html_troubleshoot(data["troubleshoot"]),
        _html_changes(triaged["changes"]),
        _html_watching(triaged["watching"]),
        _section("Health", COLOR["health"], _html_health(
            data["validation"], data["heartbeat"], data["applied"],
            # The sampler persists memory.json every ~60 s and finally only before
            # P9, so the email shows the samples persisted by P8 time.
            memory_mib=_read_memory_mib(run_dir),
        )),
        _section("Audit", COLOR["audit"], _html_audit(data["audit"], data["fixes"])),
        _section("Work queue", COLOR["warn"], queue_html) if queue_html else "",
        _section("OpenCode Go usage", COLOR["slate"], usage_html) if usage_html else "",
    ])

    if not TEMPLATE_PATH.exists():
        atomic_write_text(TEMPLATE_PATH, DEFAULT_TEMPLATE)
    template = TEMPLATE_PATH.read_text()
    if not tldr:
        # Nothing beyond the banner to say: drop the whole summary row, not just its text.
        template = _TLDR_ROW.sub("", template)
    page = (
        template
        .replace("{{DATE}}", date_str)
        .replace("{{BANNER}}", _html_banner(triaged))
        .replace("{{TLDR}}", tldr)
        .replace("{{SECTIONS}}", sections)
        .replace("{{FOOTER}}", _html_footer(triaged, usage, run_dir, dry_run))
    )

    email_path = run_dir / "08-email.html"
    atomic_write_text(email_path, page)
    print(f"[P8] rendered -> {email_path}")

    subject = _subject(date_str, triaged)

    if dry_run:
        print(f"  DRY RUN — would send: {subject}")
    else:
        try:
            run([
                "python3", str(DIGEST_SCRIPT),
                "--subject", subject,
                "--body-file", str(email_path),
                "--to", "carter2099@pm.me",
            ], timeout=60)
            print(f"  sent: {subject}")
        except Exception as error:
            # A rendered report is not a successful phase if delivery failed.
            # Let the workflow record a failed, retryable attempt.
            raise RuntimeError(f"email send failed: {error}") from error
    return {"subject": subject, "email_path": str(email_path)}


# ── P9: archive ──────────────────────────────────────────────────────


def phase_9_archive(run_dir, setup_data, elapsed_s):
    """Phase 9: write summary.md, append runs.jsonl, prune old dirs."""
    print("[P9] archive")

    date_str = setup_data["date"]
    usage = setup_data.get("usage", {})

    data = _report_inputs(run_dir, setup_data)
    applied, audit, triaged = data["applied"], data["audit"], data["triaged"]

    # Build summary.md (mirrors the email's triage)
    lines = [
        f"# Steward Report — {date_str}",
        f"**Engine:** steward_runner.py",
        f"**Verdict:** {triaged['verdict'][1]}",
        "",
        "## Update Status",
    ]
    if any(isinstance(s, dict) and s.get("dry_run") for s in applied.get("steps", [])):
        lines.append("- Dry run — no mutations")
    if _p1_phase_failed(applied):
        lines.append(f"- Maintenance: FAILED — {_p1_failure_detail(applied)}")
    elif applied.get("phase_status") == "degraded":
        lines.append(f"- Maintenance: DEGRADED — {_p1_failure_detail(applied)}")
    for item in triaged["changes"]:
        lines.append(f"- {item['text']}" + (" (rolled back)" if item["kind"] == "rollback" else ""))
    memory_mib = _read_memory_mib(run_dir)
    memory_note = _steward_memory_note(memory_mib, _steward_memory_high_mib())
    if memory_note:
        text, warn = memory_note
        lines.append(f"- Steward memory: {text}"
                     + (" — anonymous memory above 50% of MemoryHigh" if warn else ""))

    lines += ["", "## Needs You"]
    for item in triaged["needs"]:
        lines.append(f"- {item['text']}" + (f" — {item['why']}" if item["why"] else "")
                     + (f" — What to do: {item['todo']}" if item["todo"] else "")
                     + (f" {item['command']}" if item["command"] else ""))
    if not triaged["needs"]:
        lines.append("- Nothing")

    lines += ["", "## Watching"]
    for item in triaged["watching"]:
        lines.append(f"- {item['text']}" + (f": {item['command']}" if item["command"] else ""))
    if not triaged["watching"]:
        lines.append("- Nothing")

    lines += ["", "## Validation", f"- {triaged['health']}"]

    lines += ["", "## Audit"]
    sections = audit.get("sections", []) or []
    open_sections = [s for s in sections if s.get("verdict") not in ("PASS", "cached-PASS")]
    for sec in open_sections:
        lines.append(f"- {_section_name(sec.get('name'))}: {sec.get('verdict')}")
    if sections and not open_sections:
        lines.append(f"- All {len(sections)} sections passed")

    md_content = "\n".join(lines) + "\n"
    atomic_write_text(run_dir / "summary.md", md_content)

    # Append runs.jsonl
    n_sections_fired = sum(
        1 for s in sections
        if s.get("verdict") not in ("cached-PASS", "dry-run-collector-only")
    )
    n_judge_rejected = sum(len(s.get("judge_rejected", [])) for s in sections)
    route_counts = {}
    for row in _route_rows(audit, data["fixes"]):
        route_counts[row.get("status")] = route_counts.get(row.get("status"), 0) + 1
    now = datetime.now(timezone.utc)
    duration_s, wall_s = _run_timing(run_dir, elapsed_s, now=now)
    runs_entry = {
        "ts": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "duration_s": duration_s,
        **({"wall_s": wall_s} if wall_s is not None else {}),
        "maintenance_status": applied.get("phase_status", "unknown"),
        **(
            {"maintenance_failure": _p1_failure_detail(applied)}
            if _p1_phase_failed(applied)
            else {}
        ),
        "applied": sum(1 for s in applied.get("steps", []) if s.get("status") in ("ok", "bumped")),
        "usage_accounts": len(usage.get("accounts", [])),
        "sections_fired": n_sections_fired,
        "judge_rejections": n_judge_rejected,
        "routes": route_counts,
        **({"memory": memory_mib} if memory_mib else {}),
    }
    with open(RUNS_LOG, "a") as f:
        f.write(json.dumps(runs_entry) + "\n")

    # Prune run dirs >30 days
    cutoff = datetime.now() - timedelta(days=30)
    for d in RUN_DIR_BASE.iterdir():
        if d.is_dir() and len(d.name) == 10:  # YYYY-MM-DD
            try:
                d_date = datetime.strptime(d.name, "%Y-%m-%d")
                if d_date < cutoff:
                    import shutil
                    shutil.rmtree(d)
                    print(f"  pruned: {d.name}")
            except ValueError:
                pass

    # Prune headless session dirs (sessions-automated/) older than 14 days.
    # Headless transcripts are unbounded otherwise; interactive sessions are
    # excluded here (steward's session-memory phase handles those read-only).
    cutoff = datetime.now() - timedelta(days=14)
    for d in SESSION_DIR.iterdir():
        if d.is_dir():
            try:
                mtime = datetime.fromtimestamp(d.stat().st_mtime)
                if mtime < cutoff:
                    import shutil
                    shutil.rmtree(d)
                    print(f"  pruned session: {d.name}")
            except OSError:
                pass

    print(f"[P9] done -> {run_dir / 'summary.md'}")
