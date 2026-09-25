"""HTML report rendering, TL;DR generation, and archive handling."""
from __future__ import annotations

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
    atomic_write_text,
    _assistant_text_from_message,
    _balanced_json_slice,
    _call_omp_p,
    _date_context,
    _evidence_hash,
    _extract_json,
    _load_prev_artifact,
    _message_error_str,
    _ndjson_looks_like_event_stream,
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
from .dotfiles import untracked_in_scope as _dotfiles_untracked_in_scope
from .setup import P0B_PROBLEM_ACTIONS


def _dotfiles_untracked_paths():
    """Untracked in-scope dotfiles at report time, before tonight's P9b runs."""
    try:
        return _dotfiles_untracked_in_scope()
    except Exception as error:
        print(f"  dotfiles untracked scan failed: {error}")
        return []


def _html_host_drift(remediation, untracked_dotfiles, prev_dotfiles=None):
    """Report-only P3a drift, untracked dotfiles, and last night's blocked P9b."""
    esc = html.escape
    items = []
    ufw = (remediation or {}).get("ufw_drift") or {}
    status = ufw.get("status")
    if status == "drift":
        for rule in ufw.get("missing") or []:
            items.append(f"UFW rule missing: <code>{esc(rule)}</code>")
        for rule in ufw.get("extra") or []:
            items.append(f"UFW rule not in expected list: <code>{esc(rule)}</code>")
    elif status and status != "ok":
        items.append(f"UFW drift check: {esc(str(ufw.get('reason') or status))}")
    for row in (remediation or {}).get("docker_proxy") or []:
        if row.get("action") in {"attention_needed", "error"}:
            items.append(
                f"Port {esc(str(row.get('port')))} ({esc(str(row.get('container')))}): "
                f"{esc(str(row.get('reason') or row.get('error') or row.get('action')))}"
            )
    probe = (remediation or {}).get("bridge_probe") or {}
    if probe.get("status") == "unreachable":
        items.append("Open WebUI cannot reach host.docker.internal:8082 (opencode-go-proxy)")
    if untracked_dotfiles:
        shown = ", ".join(f"<code>{esc(p)}</code>" for p in untracked_dotfiles[:40])
        more = f" (+{len(untracked_dotfiles) - 40} more)" if len(untracked_dotfiles) > 40 else ""
        items.append(
            "Untracked dotfiles before tonight's P9b (it commits only gated new text files "
            f"under its auto-commit roots; add others manually if wanted): {shown}{more}"
        )
    prev = prev_dotfiles or {}
    if prev.get("phase_failed") or prev.get("status") in {"secret_blocked", "push_blocked"}:
        hits = "; ".join(
            f"{f.get('path')}:{f.get('line')} ({f.get('rule')})"
            for f in (prev.get("secret_findings") or [])[:10]
        )
        items.append(
            f"Last dotfiles commit/push ({esc(str(prev.get('status')))}): "
            f"{esc(str(prev.get('reason') or ''))[:400]}"
            + (f" — {esc(hits)}" if hits else "")
        )
    if not items:
        return ""
    li = "".join(f"<li>{item}</li>" for item in items)
    return (
        '<tr><td style="padding:16px 32px 8px;">'
        '<h2 style="margin:0; color:#e65100; font-size:15px; font-weight:700;">'
        'Host drift (report only)</h2></td></tr>'
        '<tr><td style="padding:8px 32px 16px;">'
        f'<ul style="margin:0; padding-left:20px; color:#555; font-size:12px;">{li}</ul>'
        '</td></tr>'
        '<tr><td style="padding:0 32px;"><hr style="border:none; border-top:1px solid #e8e8ee; margin:8px 0;"></td></tr>'
    )


def _chip(text, color):
    """Inline rounded status chip."""
    return (
        f'<span style="display:inline-block; padding:1px 8px; border-radius:10px; '
        f'background-color:{color}1f; color:{color}; font-size:10px; font-weight:700; '
        f'letter-spacing:0.6px; text-transform:uppercase; white-space:nowrap;">{text}</span>'
    )


def _dot(level):
    color = {"ok": "#2e7d32", "warn": "#e65100",
             "danger": "#c62828", "muted": "#9aa0b2"}.get(level, "#9aa0b2")
    return (
        f'<span style="display:inline-block; width:7px; height:7px; border-radius:50%; '
        f'background-color:{color}; vertical-align:middle; margin-right:5px; '
        f'font-size:0; line-height:0;">&nbsp;</span>'
    )


def _sub_header(label):
    return (
        f'<p style="margin:12px 0 3px; color:#7b7b8a; font-size:10px; font-weight:700; '
        f'letter-spacing:0.8px; text-transform:uppercase;">{label}</p>'
    )


def _kv_rows(rows):
    """rows: list of (label, value_html). Returns a 2-column nested table."""
    if not rows:
        return ""
    out = ['<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
           'style="font-size:13px; color:#2a2a36; border-collapse:collapse;">']
    for label, val in rows:
        out.append(
            '<tr>'
            f'<td width="40%" style="padding:4px 12px 4px 0; vertical-align:top; '
            f'color:#7b7b8a; font-size:12px;">{label}</td>'
            f'<td style="padding:4px 0; vertical-align:top; color:#2a2a36;">{val}</td>'
            '</tr>'
        )
    out.append('</table>')
    return "".join(out)


def _badge(verdict):
    """Return an HTML status chip for an audit verdict."""
    palette = {
        "PASS": "#2e7d32",
        "DRIFT": "#c62828",
        "ATTENTION": "#e65100",
        "UNVERIFIABLE": "#9aa0b2",
        "collector-failed": "#c62828",
        "worker-failed": "#c62828",
        "dry-run-collector-only": "#9aa0b2",
    }
    label = verdict
    if verdict == "dry-run-collector-only":
        label = "collector-only · dry-run"
    elif verdict == "collector-failed":
        label = "collector failed"
    elif verdict == "worker-failed":
        label = "worker failed"
    color = palette.get(verdict, "#9aa0b2")
    if verdict.startswith("cached-"):
        base = verdict.removeprefix("cached-")
        color = {"PASS": "#2e7d32", "DRIFT": "#c62828",
                 "ATTENTION": "#e65100"}.get(base, "#9aa0b2")
        return _chip(f"CACHED {base}", color)
    return _chip(label, color)

def _html_gamingrig_update(step):
    """Render only actionable gaming-rig changes and failures."""
    lines = []
    host = html.escape(str(step.get("host") or RIG_SSH_ALIAS))
    status = step.get("status", "")
    if status == "skipped":
        reason = html.escape(str(step.get("reason") or "not attempted"))
        return (
            f'<p style="margin:0 0 4px; color:#e65100; font-size:13px;">'
            f'{host}: SKIPPED — {reason}</p>'
        )

    def row(text, color="#2a2a36"):
        lines.append(
            f'<p style="margin:0 0 4px; color:{color}; font-size:13px;">'
            f'{text}</p>'
        )

    for sub in step.get("substeps", []) or []:
        name = sub.get("step", "")
        sub_status = sub.get("status", "")
        if name == "apt_upgrade":
            count = sub.get("upgraded_count", 0)
            if count:
                row(f'{host} apt: {html.escape(str(count))} packages upgraded')
            if sub_status in _P1_FAILURE_STATUSES:
                row(
                    f'{host} apt: {_p1_status_label(sub_status)} — '
                    f'{html.escape(str(sub.get("error") or sub.get("reason") or ""))}',
                    "#c62828",
                )
        elif name == "herdr_update":
            if sub_status == "ok":
                row(
                    f'{host} herdr: '
                    f'{html.escape(str(sub.get("pre_version", "?")))} -> '
                    f'{html.escape(str(sub.get("post_version", "?")))}'
                )
            elif sub_status in _P1_FAILURE_STATUSES:
                row(
                    f'{host} herdr: {_p1_status_label(sub_status)} — '
                    f'{html.escape(str(sub.get("error") or sub.get("reason") or ""))}',
                    "#c62828",
                )
        elif name == "omp_update":
            if sub_status == "ok":
                row(
                    f'{host} omp: '
                    f'{html.escape(str(sub.get("pre_version", "?")))} -> '
                    f'{html.escape(str(sub.get("post_version", "?")))}'
                )
            elif sub_status == "reverted":
                row(
                    f'{host} omp: update rolled back to '
                    f'{html.escape(str(sub.get("reverted_to", "?")))} '
                    '(post-update check failed)',
                    "#e65100",
                )
            elif sub_status in _P1_FAILURE_STATUSES:
                row(
                    f'{host} omp: {_p1_status_label(sub_status)} — '
                    f'{html.escape(str(sub.get("error") or sub.get("reason") or ""))}',
                    "#c62828",
                )
        elif name in ("health", "post_reboot_health"):
            check_failures = []
            for check in sub.get("checks", []) or []:
                check_status = check.get("status", "")
                if check_status in (_P1_FAILURE_STATUSES | {"warning"}):
                    detail = check.get("error") or check.get("reason") or check_status
                    check_failures.append(
                        f'{check.get("step", "check")}: {detail}'
                    )
            if name == "post_reboot_health" and sub_status in _P1_FAILURE_STATUSES:
                row(
                    f'{host} post_reboot_health: {_p1_status_label(sub_status)} — '
                    f'{html.escape(str(sub.get("error") or "health gate failed"))}',
                    "#c62828",
                )
            for failure in check_failures:
                color = "#e65100" if "warning" in failure else "#c62828"
                row(
                    f'{host} {html.escape(failure.split(":", 1)[0])}: '
                    f'{html.escape(failure.split(":", 1)[1].strip() if ":" in failure else failure)}',
                    color,
                )
            if sub_status in _P1_FAILURE_STATUSES and not check_failures:
                row(
                    f'{host} health: {_p1_status_label(sub_status)} — '
                    f'{html.escape(str(sub.get("error") or sub.get("reason") or sub_status))}',
                    "#c62828",
                )
        elif name == "reboot" and sub_status == "ok":
            if step.get("rebooted") and step.get("post_reboot_health_passed"):
                row(f'{host}: rebooted; Linux SSH return and post-reboot health were validated')
            elif step.get("rebooted"):
                row(f'{host}: rebooted; post-reboot health gate did not pass', "#e65100")
            elif step.get("reboot_requested"):
                row(f'{host}: reboot requested; Linux SSH return was not validated', "#e65100")
        elif name in (
            "reboot_required", "pre_reboot_boot_id", "bootnext",
            "reboot", "ssh_return",
        ) and sub_status in _P1_FAILURE_STATUSES:
            row(
                f'{host} {html.escape(name)}: {_p1_status_label(sub_status)} — '
                f'{html.escape(str(sub.get("error") or sub.get("reason") or sub_status))}',
                "#c62828",
            )

    if status in _P1_FAILURE_STATUSES and not lines:
        row(
            f'{host}: {_p1_status_label(status)} — {html.escape(str(step.get("error") or ""))}',
            "#c62828",
        )
    return "\n".join(lines)

_P1_FAILURE_STATUSES = frozenset({"failed", "error", "timeout", "started"})


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

def _p1_status_label(status):
    return {
        "timeout": "TIMED OUT",
        "started": "STARTED (INCOMPLETE)",
        "error": "ERROR",
        "reverted": "ROLLED BACK",
    }.get(status, "FAILED")


def _p1_phase_failure_row(applied_data):
    return (
        '<p style="margin:0 0 4px; color:#c62828; font-size:13px;">'
        '<strong>Maintenance: FAILED</strong> — '
        f'{html.escape(_p1_failure_detail(applied_data))}</p>'
    )

def _p1_line(text, color="#2a2a36"):
    """One escaped update/status row."""
    return (
        f'<p style="margin:0 0 4px; color:{color}; font-size:13px;">'
        f'{html.escape(str(text))}</p>'
    )


def _short_sha(value):
    value = str(value or "").strip()
    return value[:7] if re.fullmatch(r"[0-9a-f]{7,40}", value) else (value or "?")


def _openwebui_update_text(step):
    """(text, color) for an Open WebUI update row; ("", "") when there is no signal."""
    status = str(step.get("status") or "")
    pre = step.get("pre_version") or step.get("current_tag") or "?"
    post = step.get("post_version") or "?"
    latest = step.get("latest_tag") or post
    detail = str(step.get("error") or step.get("reason") or "")[:160]
    if status == "ok" and pre != post:
        return f"open-webui: {pre} -> {post}", "#2a2a36"
    if status == "rolled_back":
        return f"open-webui: update to {latest} rolled back — {detail}", "#e65100"
    if status in _P1_FAILURE_STATUSES:
        return f"open-webui: {_p1_status_label(status)} — {detail}", "#c62828"
    return "", ""


def _app_deploy_text(step):
    """(text, color) for an app-deploy row; ("", "") when there is no signal."""
    status = str(step.get("status") or "")
    service = step.get("service") or "app"
    detail = str(step.get("error") or step.get("reason") or "")[:160]
    if status == "ok":
        return (
            f"{service}: deployed {_short_sha(step.get('pre_version'))} -> "
            f"{_short_sha(step.get('post_version'))}",
            "#2a2a36",
        )
    if status == "rolled_back":
        return f"{service} deploy failed and rolled back — {detail}", "#c62828"
    if status in _P1_FAILURE_STATUSES:
        return f"{service} deploy: {_p1_status_label(status)} — {detail}", "#c62828"
    if status == "skipped" and re.search(r"(?i)\b(ci|checks?|dirty|fast-forward|branch)\b", detail):
        return f"{service}: deploy waiting — {detail}", "#7b7b8a"
    return "", ""


def _dependabot_merge_lines(step):
    """[(text, color)] for the Dependabot auto-merge step: merges, majors, errors."""
    lines = []
    for pr in step.get("merged") or []:
        lines.append((f"dependabot: {pr.get('repo')}#{pr.get('number')} auto-merge queued — "
                      f"{str(pr.get('title') or '')[:120]}", "#2a2a36"))
    for pr in step.get("needs_carter") or []:
        lines.append((f"dependabot: {pr.get('repo')}#{pr.get('number')} needs Carter "
                      f"({pr.get('reason')}) — {str(pr.get('title') or '')[:120]}", "#e65100"))
    if step.get("error"):
        lines.append((f"dependabot auto-merge: {str(step['error'])[:200]}", "#c62828"))
    skipped = [pr for pr in step.get("skipped") or [] if pr.get("number") is not None]
    if skipped:
        reasons = "; ".join(
            f"{pr.get('repo')}#{pr.get('number')}: {str(pr.get('reason') or '')[:80]}"
            for pr in skipped[:6]
        )
        more = f" (+{len(skipped) - 6} more)" if len(skipped) > 6 else ""
        lines.append((f"dependabot: {len(skipped)} PR(s) left open — {reasons}{more}", "#7b7b8a"))
    return lines


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


def _html_updates(applied_data):
    """Render update steps — signal only, no no-op greys."""
    steps = applied_data.get("steps", [])
    if not steps:
        if _p1_phase_failed(applied_data):
            return _p1_phase_failure_row(applied_data)
        if applied_data.get("dry_run"):
            return '<p style="margin:0; color:#888; font-size:13px;">Dry run — no mutations applied.</p>'
        return '<p style="margin:0; color:#888; font-size:13px;">No update steps executed.</p>'

    lines = []
    for s in steps:
        name = s.get("step", "")
        status = s.get("status", "")
        # gamingrig_maintenance owns its own nested signal rendering; do not
        # collapse a no-op remote health pass into a generic "ok" row.
        if name in ("gamingrig_maintenance", "gamingrig_linux", "gamingrig"):
            rendered = _html_gamingrig_update(s)
            if rendered:
                lines.append(rendered)

        elif name == "llama_cpp":
            pre = s.get("pre_version")
            post = s.get("post_version")
            if status == "ok" and pre != post:
                lines.append(
                    f'<p style="margin:0 0 4px; color:#2a2a36; font-size:13px;">'
                    f'llama.cpp: {html.escape(str(pre or "?"))} -> '
                    f'{html.escape(str(post or "?"))}</p>'
                )
            elif status == "reverted":
                lines.append(
                    f'<p style="margin:0 0 4px; color:#e65100; font-size:13px;">'
                    f'llama.cpp: update rolled back to '
                    f'{html.escape(str(s.get("reverted_to") or "?"))}</p>'
                )
            elif status in _P1_FAILURE_STATUSES:
                lines.append(
                    f'<p style="margin:0 0 4px; color:#c62828; font-size:13px;">'
                    f'llama.cpp: {_p1_status_label(status)} — '
                    f'{html.escape(str(s.get("error") or s.get("reason") or ""))}</p>'
                )

        # apt_upgrade: show only if upgrades happened or failed
        elif name == "apt_upgrade":

            n = s.get("upgraded_count", 0)
            if n > 0:
                lines.append(f'<p style="margin:0 0 4px; color:#2a2a36; font-size:13px;">'
                             f'apt: {n} packages upgraded</p>')
            elif status in _P1_FAILURE_STATUSES:
                lines.append(f'<p style="margin:0 0 4px; color:#c62828; font-size:13px;">'
                             f'apt: {_p1_status_label(status)} — '
                             f'{html.escape(str(s.get("error") or s.get("reason") or ""))}</p>')

        # auto_* packages: show only ok or failed
        elif name.startswith("auto_"):
            pkg = name.replace("auto_", "")
            if status == "ok":
                lines.append(f'<p style="margin:0 0 4px; color:#2a2a36; font-size:13px;">'
                             f'{pkg}: {s.get("pre_version","?")} -> {s.get("post_version","?")}</p>')
            elif status in _P1_FAILURE_STATUSES:
                lines.append(f'<p style="margin:0 0 4px; color:#c62828; font-size:13px;">'
                             f'{pkg}: {_p1_status_label(status)} — '
                             f'{html.escape(str(s.get("error") or s.get("reason") or ""))}</p>')

        # Open WebUI: guarded automatic update (soak, data gates, image+data rollback).
        elif name in ("openwebui_update", "openwebui"):
            text, color = _openwebui_update_text(s)
            if text:
                lines.append(_p1_line(text, color))

        elif name == "app_deploy":
            text, color = _app_deploy_text(s)
            if text:
                lines.append(_p1_line(text, color))

        elif name == "dependabot_merge":
            lines.extend(_p1_line(text, color) for text, color in _dependabot_merge_lines(s))

        elif name == "worker_omp_refresh":
            if status == "ok":
                lines.append(_p1_line(
                    f"steward worker omp: {s.get('pre_version') or '?'} -> "
                    f"{s.get('post_version') or '?'}"
                ))
            elif status in _P1_FAILURE_STATUSES:
                lines.append(_p1_line(
                    f"steward worker omp: {_p1_status_label(status)} — "
                    f"{s.get('error') or s.get('reason') or ''}",
                    "#c62828",
                ))

        # freshrss: show only bumped/reverted/failed/error
        elif name == "freshrss":
            if status == "bumped":
                lines.append(f'<p style="margin:0 0 4px; color:#2a2a36; font-size:13px;">'
                             f'freshrss: {s.get("current_tag")} -> {s.get("latest_tag")}</p>')
            elif status in _P1_FAILURE_STATUSES | {"reverted"}:
                lines.append(f'<p style="margin:0 0 4px; color:#c62828; font-size:13px;">'
                             f'freshrss: {_p1_status_label(status)} — '
                             f'{html.escape(str(s.get("error") or s.get("reason") or ""))}</p>')

        # herdr: show only bumped or failed/error
        elif name == "herdr_update":
            pre = str(s.get("pre_version", "?")).replace("herdr ", "")
            post = str(s.get("post_version", "?")).replace("herdr ", "")
            if status == "ok":
                lines.append(f'<p style="margin:0 0 4px; color:#2a2a36; font-size:13px;">'
                             f'herdr: {pre} -> {post}</p>')
            elif status in _P1_FAILURE_STATUSES:
                lines.append(f'<p style="margin:0 0 4px; color:#c62828; font-size:13px;">'
                             f'herdr: {_p1_status_label(status)} — '
                             f'{html.escape(str(s.get("error") or s.get("reason") or ""))}</p>')

        # omp: show only updated, reverted, or failed/error
        elif name == "omp_update":
            pre = str(s.get("pre_version", "?")).replace("omp/", "")
            post = str(s.get("post_version", "?")).replace("omp/", "")
            if status == "ok":
                lines.append(_p1_line(f"omp: {pre} -> {post}{_omp_stale_note(s)}"))
            elif status == "skipped" and _omp_stale_note(s):
                lines.append(_p1_line(f"omp: current{_omp_stale_note(s)}", "#7b7b8a"))
            elif status == "reverted":
                lines.append(f'<p style="margin:0 0 4px; color:#e65100; font-size:13px;">'
                             f'omp: update rolled back to {s.get("reverted_to","?")} '
                             f'(post-update check failed)</p>')
            elif status in _P1_FAILURE_STATUSES:
                lines.append(f'<p style="margin:0 0 4px; color:#c62828; font-size:13px;">'
                             f'omp: {_p1_status_label(status)} — '
                             f'{html.escape(str(s.get("error") or s.get("reason") or ""))}</p>')

        # searxng: show only updated or failed/error
        elif name == "searxng":
            if status == "ok":
                lines.append(f'<p style="margin:0 0 4px; color:#2a2a36; font-size:13px;">'
                             f'searxng: pulled latest :latest image</p>')
            elif status in _P1_FAILURE_STATUSES:
                lines.append(f'<p style="margin:0 0 4px; color:#c62828; font-size:13px;">'
                             f'searxng: {_p1_status_label(status)} — '
                             f'{html.escape(str(s.get("error") or s.get("reason") or ""))}</p>')

        # Generic fallback: show any step with real change/failure
        else:
            if status in ("ok", "bumped"):
                lines.append(f'<p style="margin:0 0 4px; color:#2a2a36; font-size:13px;">'
                             f'{name}: ok</p>')
            elif status in _P1_FAILURE_STATUSES:
                lines.append(f'<p style="margin:0 0 4px; color:#c62828; font-size:13px;">'
                             f'{name}: {_p1_status_label(status)} — '
                             f'{html.escape(str(s.get("error") or s.get("reason") or ""))}</p>')
    if _p1_phase_failed(applied_data):
        lines.append(_p1_phase_failure_row(applied_data))
    elif applied_data.get("phase_status") == "degraded":
        lines.append(
            '<p style="margin:0 0 4px; color:#e65100; font-size:13px;">'
            '<strong>Maintenance: DEGRADED</strong> — '
            f'{html.escape(_p1_failure_detail(applied_data))}</p>'
        )

    return "\n".join(lines) if lines else '<p style="margin:0; color:#888; font-size:13px;">No updates tonight.</p>'





def _mini_bar(pct, color="#37474f"):
    """Inline 0-100% horizontal bar, email-safe via nested table cells.
    Track is darker (#d0d4de). Min fill 2% when pct>0."""
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
        f'<td width="{100-fill_w:.0f}%" style="background-color:#d0d4de; height:5px; '
        f'line-height:5px; font-size:0;">&nbsp;</td>'
        '</tr></table>'
    )


def _html_health(validation_data, hb_data, applied_data=None):
    """Merged update/validation health section with system status."""
    out = []

    if _p1_phase_failed(applied_data):
        out.append(
            '<p style="margin:0 0 4px; color:#c62828; font-size:13px;">'
            f'{_dot("danger")}Maintenance failed: '
            f'{html.escape(_p1_failure_detail(applied_data))}</p>'
        )

    # If heartbeat phase failed, show the error and retain the maintenance
    # failure above instead of replacing it with a generic health packet.
    if hb_data.get("phase_failed"):
        err = hb_data.get("error", "unknown error")
        out.append(
            f'<p style="margin:0; color:#c62828; font-size:13px;">'
            f'{_dot("danger")}Heartbeat failed: {html.escape(str(err))}</p>'
        )
        return "".join(out)

    # ── A. Checks table ──
    checks = validation_data.get("checks", [])
    check_rows = []
    for c in checks:
        name = c.get("name", "")
        status = c.get("status", "")

        # Normalize label
        label_map = {
            "docker_containers": "Containers",
            "llm_fallback": "LLM routing",
            "openwebui_image_match": "open-webui image",
        }
        label = label_map.get(name, name)
        if name.startswith("endpoint_"):
            svc = name.replace("endpoint_", "")
            label = {"tunnel-health": "CF tunnel"}.get(svc, svc)

        if status == "ok":
            chip = _chip("OK", "#2e7d32")
            detail = ""
            # Add compact detail for endpoints
            if name.startswith("endpoint_"):
                svc = name.replace("endpoint_", "")
                if svc == "tunnel-health":
                    detail = f'{c.get("active_connections", "?")} connectors'
                else:
                    code = c.get("http_code", "?")
                    detail = f'HTTP {code}'
            elif name == "llm_fallback":
                fb = c.get("fallback_active", False)
                chip = _chip("OK", "#2e7d32") if not fb else _chip("FAIL", "#c62828")
                detail = "local" if not fb else "cloud fallback"
                label = "LLM routing"
            check_rows.append((label, f'{chip} {detail}'.strip()))
        elif status in ("fail", "error"):
            chip = _chip("FAIL", "#c62828")
            detail = c.get("error", c.get("status", ""))
            check_rows.append((label, f'{chip} {detail}'.strip()))
        elif status == "warning":
            chip = _chip("WARN", "#e65100")
            check_rows.append((label, chip))

    if check_rows:
        out.append(_sub_header("Checks"))
        out.append(_kv_rows(check_rows))

    # ── B. System status (from heartbeat, no trends) ──
    sys_rows = []

    # Failed systemd units
    uf = hb_data.get("failed_units", {}) or {}
    user_f = [x for x in uf.get("user", []) if x and str(x).strip()]
    sys_f = [x for x in uf.get("system", []) if x and str(x).strip()]
    cleared = [c for c in (uf.get("cleared") or []) if c]
    missing = (hb_data.get("units", {}) or {}).get("missing", [])
    if user_f or sys_f or missing or cleared:
        parts = []
        for u in user_f:
            parts.append(_dot("danger") + html.escape(str(u).strip()))
        for u in sys_f:
            parts.append(_dot("danger") + html.escape(str(u).strip()))
        if missing:
            parts.append(_dot("warn") + "missing: " + html.escape(", ".join(map(str, missing))))
        if cleared and not (user_f or sys_f):
            # Only mention clears when nothing is still failed — avoids noise
            clr = ", ".join(
                html.escape(str(c.get("unit") or c)) for c in cleared[:4]
            )
            parts.append(_dot("ok") + f"cleared stale: {clr}")
        sys_rows.append(("Systemd units", " ".join(parts)))

    # Reboot
    rb = hb_data.get("reboot", {}) or {}
    sys_rows.append(("Reboot",
        (_dot("danger") + f'Needed — kernel {rb.get("kernel","?")}' if rb.get("needed")
         else _dot("ok") + "Not needed")))

    # Disk
    disk = hb_data.get("disk", {}) or {}
    if disk.get("df_root"):
        parts = disk["df_root"].splitlines()[-1].split()
        if len(parts) >= 5:
            used_pct = parts[4]
            sys_rows.append(("Disk", f'{used_pct} used ({parts[2]}/{parts[1]})'))

    # Memory
    mem = hb_data.get("memory", {}) or {}
    mem_avail = mem.get("available", "")
    if mem_avail:
        sys_rows.append(("Memory", mem_avail))

    # Backup
    bt = (hb_data.get("backup", {}) or {}).get("last_run", "")
    if bt:
        sys_rows.append(("Last backup", bt))

    # DNS — only if not all ok
    dns = hb_data.get("dns", {}) or {}
    if dns:
        ok = sum(1 for v in dns.values() if v.get("resolves"))
        total = len(dns)
        if ok != total:
            sys_rows.append(("DNS", _dot("warn") + f'{ok}/{total} hostnames resolve'))

    # TLS — only if any cert expires within 30 days
    tls = hb_data.get("tls_certs", {}) or {}
    if tls:
        now_dt = datetime.now()
        expiring = []
        for host, expiry in tls.items():
            dm = re.search(r"notAfter=(.+?\d{4})\s", expiry)
            if dm:
                try:
                    exp_date = datetime.strptime(dm.group(1), "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp_date - now_dt).days
                    if days_left <= 30:
                        expiring.append(f'{host.split(".")[0]} ({days_left}d)')
                except ValueError:
                    pass
        if expiring:
            sys_rows.append(("TLS expiring", _dot("warn") + ", ".join(expiring)))

    # LLM routing (from heartbeat)
    fb = (hb_data.get("llm_stack", {}) or {}).get("falling_back", False)
    if fb:
        sys_rows.append(("LLM proxy", _dot("warn") + "Cloud fallback"))

    # bundle-audit — only when vulnerabilities (or a check error) are reported
    ba = hb_data.get("bundle_audit", {}) or {}
    for app, result in ba.items():
        if "no vulnerabilities" not in str(result):
            sys_rows.append((f"bundle-audit ({app})",
                             _dot("warn") + html.escape(_clip(str(result), 400))))

    if sys_rows:
        out.append(_sub_header("System status"))
        out.append(_kv_rows(sys_rows))

    return "".join(out) if out else '<p style="margin:0; color:#888; font-size:13px;">All health checks passed.</p>'


# ── finding routes (07b-fixes.json "routes") ─────────────────────────

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}
# Routes that leave a confirmed problem with Carter.
_NEEDS_CARTER_ROUTES = ("needs_carter", "failed", "pr_opened")
# Routes where the steward is still acting (PR merging, nightly step).
_IN_PROGRESS_ROUTES = ("pr_auto_merge", "handled_by_p1")


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


def _route_needs_carter(row):
    """Whether a route leaves Carter something to do.

    Report-only means "never changed automatically", not "unimportant": a
    report-only finding above low severity is still Carter's to act on.
    """
    status = row.get("status")
    return status in _NEEDS_CARTER_ROUTES or (
        status == "report_only" and row.get("severity") != "low"
    )


def _clip(text, limit):
    """Collapse whitespace and cut at a word boundary."""
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0] or text[:limit]
    return cut.rstrip(",;:") + "…"


def _route_outcome_text(row):
    """One plain phrase saying what happened to a finding."""
    status = row.get("status")
    detail = _clip(row.get("detail"), 160)
    if status == "needs_carter":
        decision = _clip(row.get("decision"), 200)
        if decision:
            return f"needs Carter: {decision}"
        return "needs Carter: no automatic fix route" + (f" ({detail})" if detail else "")
    if status == "failed":
        return "the automatic fix failed" + (f": {detail}" if detail else "")
    if status == "pr_opened":
        return "a fix PR is waiting for Carter's review" + (
            f": {row['pr_url']}" if row.get("pr_url") else "")
    if status == "pr_auto_merge":
        return "a fix PR will merge automatically once its checks pass"
    if status == "handled_by_p1":
        return "nightly maintenance handles this" + (f" ({detail})" if detail else "")
    if status == "done":
        return _clip(row.get("summary"), 160) or "fixed automatically"
    if status == "report_only":
        return ("needs Carter: reported only, never changed automatically"
                if _route_needs_carter(row) else "noted; low priority")
    return str(status or "unknown")


def _route_section_summary(rows, findings):
    """Deterministic section summary when the summary model fails."""
    if not rows:
        return f"{len(findings)} finding(s) reviewed." if findings else "Section reviewed."
    top = rows[0]
    text = f"{_clip(top.get('claim'), 220)} Outcome: {_route_outcome_text(top)}."
    if len(rows) > 1:
        text += f" {len(rows) - 1} more finding(s) in this section."
    return text


def _section_route_chip(verdict, rows):
    """Badge describing a section's end state after routing."""
    base = str(verdict or "").removeprefix("cached-")
    if str(verdict).endswith("-failed") or base == "UNVERIFIABLE":
        return _chip("Audit incomplete", "#e65100")
    failed = sum(1 for r in rows if r.get("status") == "failed")
    if failed:
        return _chip(f"{failed} fix failed", "#c62828")
    needs = [r for r in rows if _route_needs_carter(r)]
    if needs:
        high = any(r.get("severity") == "high" for r in needs)
        return _chip(
            f"{len(needs)} need{'s' if len(needs) == 1 else ''} you",
            "#c62828" if high else "#e65100",
        )
    in_progress = sum(1 for r in rows if r.get("status") in _IN_PROGRESS_ROUTES)
    if in_progress:
        return _chip(f"{in_progress} in progress", "#1565c0")
    done = sum(1 for r in rows if r.get("status") == "done")
    if done:
        return _chip(f"{done} fixed", "#2e7d32")
    if rows:
        return _chip(f"{len(rows)} FYI", "#9aa0b2")
    return _chip("reviewed", "#9aa0b2")


def _section_findings_text(sec, date_str):
    """Flatten confirmed findings for summarizer input (digest-stale filtered)."""
    confirmed = sec.get("judge_confirmed", []) or sec.get("confirmed_findings", []) or []
    claims = []
    for f in confirmed:
        claim = (f.get("claim") or f.get("evidence") or "").strip()
        if not claim:
            continue
        if sec.get("name") == "digest-quality":
            dates_in_claim = re.findall(r"20\d{2}-\d{2}-\d{2}", claim)
            if dates_in_claim:
                has_recent = any(
                    (datetime.strptime(d, "%Y-%m-%d")
                     >= datetime.strptime(date_str, "%Y-%m-%d") - timedelta(days=2))
                    for d in dates_in_claim
                )
                if not has_recent:
                    continue
        claims.append(claim[:240])
    return claims


def _audit_incomplete_summary(payload):
    """Deterministic wording for steward automation failures."""
    label = payload["name"].replace("_", " ")
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
        f"No underlying {label} problem was established; the steward will retry automatically "
        "on the next run."
    )


def _summarize_audit_sections(section_payloads):
    """One LLM call → {section_name: summary_text}. Falls back per-section."""
    if not section_payloads:
        return {}

    compact = []
    for p in section_payloads:
        rows = p.get("routes") or []
        compact.append({
            "name": p["name"],
            "findings": [
                {
                    "finding": _clip(r.get("claim"), 240),
                    "severity": r.get("severity"),
                    "outcome": _route_outcome_text(r),
                }
                for r in rows[:12]
            ] or [{"finding": f} for f in p["findings"][:12]],
        })

    prompt = (
        "You summarize Homelab Steward audit results for a nightly email.\n\n"
        "For EACH section below, write 1-3 plain-English sentences a human can skim: what is "
        "wrong and what happened to it, using each finding's outcome as given. Put "
        "high-severity findings first.\n"
        "An outcome starting 'needs Carter' is a real, confirmed problem that is still open. "
        "Say plainly that it needs Carter. Never call it automation trouble or malformed, and "
        "never say it will be retried.\n"
        "No badge jargon (DRIFT/ATTENTION). No bullet lists. No filenames unless load-bearing.\n\n"
        f"SECTIONS:\n{json.dumps(compact, indent=2)}\n\n"
        "Return ONLY fenced JSON:\n"
        '```json\n'
        '{"summaries": {"section-name": "one to three sentences", "...": "..."}}\n'
        "```"
    )

    try:
        raw = _call_omp_p(prompt, model=STEWARD_MODEL, timeout=120, mode="json", tools=NO_TOOLS)
        packet = _extract_json(raw, "audit-section-summaries")
        summaries = packet.get("summaries") or {}
        if not isinstance(summaries, dict):
            raise ValueError("summaries not a dict")
        # Normalize keys to bare section names
        out = {}
        for p in section_payloads:
            name = p["name"]
            text = summaries.get(name) or summaries.get(name.replace("_", " "))
            if isinstance(text, str) and text.strip():
                out[name] = text.strip()
        if out:
            return out
    except Exception as e:
        print(f"  audit section summary LLM failed: {e}")

    return {
        p["name"]: _route_section_summary(p.get("routes") or [], p["findings"])
        for p in section_payloads
    }


def _html_audit(audit_data, fixes_data=None):
    """Render audit sections: model-written summaries plus route-outcome badges."""
    sections = audit_data.get("sections", []) or []
    if not sections:
        return '<p style="margin:0; color:#9aa0b2; font-size:13px;">No audit results.</p>'

    routes_by_section = {}
    for row in _route_rows(audit_data, fixes_data):
        routes_by_section.setdefault(row.get("section"), []).append(row)

    date_str = datetime.now().strftime("%Y-%m-%d")
    payloads = []
    for sec in sections:
        verdict = sec.get("verdict", "UNKNOWN")
        if verdict in ("PASS", "cached-PASS"):
            continue
        name = sec.get("name", "unknown") or "unknown"
        payloads.append({
            "name": name,
            "verdict": verdict,
            "findings": _section_findings_text(sec, date_str),
            "routes": routes_by_section.get(name, []),
            "error": (
                sec.get("error")
                or sec.get("worker_error")
                or sec.get("judge_error")
                or ""
            ).strip(),
        })

    if not payloads:
        return '<p style="margin:0; color:#888; font-size:13px;">All audit sections clear.</p>'

    summaries = _summarize_audit_sections([
        p for p in payloads if not p["verdict"].endswith("-failed")
    ])

    out = []
    for p in payloads:
        name = p["name"]
        display = name.replace("_", " ")
        chip = _section_route_chip(p["verdict"], p["routes"])
        out.append(
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="font-size:13px; border-collapse:collapse; margin:0 0 12px;">'
            f'<tr><td style="padding:3px 0; color:#1a1a2e; font-weight:700;">{html.escape(display)}</td>'
            f'<td align="right" style="padding:3px 0; white-space:nowrap;">{chip}</td></tr>'
        )
        if p["verdict"].endswith("-failed"):
            summary = _audit_incomplete_summary(p)
        else:
            summary = summaries.get(name) or _route_section_summary(p["routes"], p["findings"])
        out.append(
            f'<tr><td colspan="2" style="padding:4px 4px 2px 0; color:#3a3a4a; '
            f'font-size:12px; line-height:1.45;">{html.escape(summary)}</td></tr>'
        )
        out.append('</table>')

    return "".join(out)


def _html_queue(queue_data):
    """Render work queue as grouped tables."""
    ideas = queue_data.get("ideas", {}) or {}
    plans = queue_data.get("plans", {}) or {}
    inconsistencies = queue_data.get("inconsistencies", []) or []
    reconcile = queue_data.get("status_reconcile", {}) or {}
    out = []

    # Ideas
    outstanding = ideas.get("outstanding", [])
    if outstanding:
        out.append(_sub_header(f'Ideas outstanding ({len(outstanding)})'))
        idea_rows = []
        for idea in outstanding[:10]:
            age = idea.get("age_days", "?")
            heading = idea.get("heading", "") or idea.get("file", "")
            idea_rows.append((f'{age}d', heading))
        out.append(_kv_rows(idea_rows))
    else:
        out.append('<p style="margin:0; color:#9aa0b2; font-size:13px;">No open ideas.</p>')

    # Plans
    plan_groups = [
        ("Draft", plans.get("draft", []), "#1565c0"),
        ("Approved", plans.get("approved", []), "#2e7d32"),
        ("Implementing", plans.get("implementing", []), "#e65100"),
        ("Done this week", plans.get("done_this_week", []), "#9aa0b2"),
    ]
    non_empty = [(label, items, color) for label, items, color in plan_groups if items]
    if non_empty:
        plan_rows = []
        for label, items, color in non_empty:
            for item in items[:5]:
                detail = item.get("heading", item.get("file", "")) or ""
                plan_rows.append((_chip(label, color), detail))
        out.append(_sub_header("Plans"))
        out.append(_kv_rows(plan_rows))

    # Status reconciles applied this run
    applied = [
        a for a in (reconcile.get("applied") or [])
        if a.get("status") in ("updated", "dry_run")
    ]
    if applied:
        out.append(_sub_header(f'Status updates ({len(applied)})'))
        rows = []
        for a in applied[:8]:
            label = a.get("new_status") or a.get("would_set") or a.get("status")
            detail = a.get("file", "?")
            reason = a.get("reason") or ""
            if reason:
                detail = f"{detail} — {reason[:100]}"
            rows.append((_chip(str(label), "#2e7d32"), detail))
        out.append(_kv_rows(rows))

    # Inconsistencies
    if inconsistencies:
        out.append(_sub_header("Inconsistencies"))
        inc_rows = []
        for inc in inconsistencies:
            inc_rows.append((inc["type"], inc["detail"][:200]))
        out.append(_kv_rows(inc_rows))

    return "".join(out) if out else \
        '<p style="margin:0; color:#9aa0b2; font-size:13px;">Queue empty.</p>'


def _html_usage(usage_data):
    """Render OpenCode Go usage report with higher contrast bars.

    Windows match opencode-go-proxy / ocusage: rolling is 5h (not 24h).
    Each row shows reset_in when the proxy provides it.
    """
    accounts = usage_data.get("accounts", []) or []
    out = []
    for acct in accounts:
        name = acct.get("name", "?")
        tier = acct.get("tier", "?")
        extra_parts = [tier]
        if not acct.get("usage_fresh"):
            extra_parts.append("usage API stale")
        extra = " · ".join(extra_parts)
        out.append(
            f'<p style="margin:0 0 3px; font-size:13px;">'
            f'<strong style="color:#1a1a2e;">{html.escape(str(name))}</strong> '
            f'<span style="color:#9aa0b2; font-size:12px;">{html.escape(extra)}</span></p>'
        )
        rows = (
            '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            'style="font-size:12px; border-collapse:collapse; margin-bottom:10px;">'
        )
        for label, pct_key, reset_key, color in [
            ("5h", "rolling_pct", "rolling_reset_in", "#1a1a2e"),
            ("7d", "weekly_pct", "weekly_reset_in", "#0d47a1"),
            ("30d", "monthly_pct", "monthly_reset_in", "#4a148c"),
        ]:
            pct = acct.get(pct_key, 0)
            try:
                pct = float(pct)
            except (TypeError, ValueError):
                pct = 0.0
            fill_color = "#c62828" if pct >= 90 else color
            reset_in = (acct.get(reset_key) or "").strip()
            pct_cell = f"{pct:.0f}%"
            if reset_in:
                pct_cell += (
                    f' <span style="color:#9aa0b2; font-weight:400; font-size:11px;">'
                    f'· reset {html.escape(reset_in)}</span>'
                )
            rows += (
                '<tr>'
                f'<td width="18%" style="padding:3px 0; color:#7b7b8a; font-size:12px; '
                f'vertical-align:middle;">{label}</td>'
                f'<td width="42%" style="padding:3px 0; vertical-align:middle;">'
                f'{_mini_bar(pct, fill_color)}</td>'
                f'<td align="right" width="40%" style="padding:3px 0; color:#2a2a36; '
                f'font-weight:600; vertical-align:middle; white-space:nowrap;">{pct_cell}</td>'
                '</tr>'
            )
        rows += '</table>'
        out.append(rows)
    if usage_data.get("proxy_error"):
        out.append(
            f'<p style="margin:6px 0 0; color:#c62828; font-size:12px;">'
            f'{_dot("danger")}Proxy unreachable: '
            f'{html.escape(str(usage_data["proxy_error"]))}</p>'
        )
    if not out:
        out.append('<p style="margin:0; color:#9aa0b2; font-size:13px;">No usage data.</p>')
    return "".join(out)


def _tldr_collect_gamingrig_updates(step):
    """Flatten nested gaming-rig changes/failures for the TLDR."""
    updates = []
    n_failed = 0
    host = step.get("host") or RIG_SSH_ALIAS
    emitted_failure = False
    if step.get("status") == "skipped":
        updates.append(
            f"{host} skipped: {str(step.get('reason') or 'not attempted')[:140]}"
        )
        return updates, n_failed

    for sub in step.get("substeps", []) or []:
        name = sub.get("step", "")
        status = sub.get("status", "")
        if name == "apt_upgrade":
            count = sub.get("upgraded_count", 0)
            if count:
                updates.append(f"{host} apt: {count} packages upgraded")
            if status in _P1_FAILURE_STATUSES:
                n_failed += 1
                emitted_failure = True
                updates.append(
                    f"{host} apt {_p1_status_label(status).lower()}: "
                    f"{str(sub.get('error') or '')[:120]}"
                )
        elif name == "herdr_update":
            if status == "ok":
                pre = str(sub.get("pre_version") or "")
                post = str(sub.get("post_version") or "")
                if pre and post and pre != post:
                    updates.append(f"{host} herdr: {pre} -> {post}")
            elif status in _P1_FAILURE_STATUSES:
                n_failed += 1
                emitted_failure = True
                updates.append(
                    f"{host} herdr {_p1_status_label(status).lower()}: "
                    f"{str(sub.get('error') or '')[:120]}"
                )
        elif name == "omp_update":
            if status == "ok":
                pre = str(sub.get("pre_version") or "")
                post = str(sub.get("post_version") or "")
                if pre and post and pre != post:
                    updates.append(f"{host} omp: {pre} -> {post}")
            elif status == "reverted":
                n_failed += 1
                emitted_failure = True
                updates.append(
                    f"{host} omp update rolled back to "
                    f"{sub.get('reverted_to') or '?'} (post-update check failed)"
                )
            elif status in _P1_FAILURE_STATUSES:
                n_failed += 1
                emitted_failure = True
                updates.append(
                    f"{host} omp {_p1_status_label(status).lower()}: "
                    f"{str(sub.get('error') or '')[:120]}"
                )
        elif name in ("health", "post_reboot_health"):
            check_failures = []
            for check in sub.get("checks", []) or []:
                check_status = check.get("status", "")
                if check_status in (_P1_FAILURE_STATUSES | {"warning"}):
                    if check_status in _P1_FAILURE_STATUSES:
                        n_failed += 1
                        emitted_failure = True
                    detail = check.get("error") or check.get("reason") or check_status
                    check_failures.append(
                        f"{host} {check.get('step') or 'health'} "
                        f"{check_status}: {str(detail)[:120]}"
                    )
            if name == "post_reboot_health" and status in _P1_FAILURE_STATUSES:
                if check_failures:
                    updates.append(
                        f"{host} post_reboot_health "
                        f"{_p1_status_label(status).lower()}: "
                        f"{str(sub.get('error') or 'health gate failed')[:120]}"
                    )
                else:
                    n_failed += 1
                    emitted_failure = True
                    updates.append(
                        f"{host} post_reboot_health "
                        f"{_p1_status_label(status).lower()}: "
                        f"{str(sub.get('error') or '')[:120]}"
                    )
            updates.extend(check_failures)
            if (
                status in _P1_FAILURE_STATUSES
                and not (sub.get("checks") or [])
                and name != "post_reboot_health"
            ):
                n_failed += 1
                emitted_failure = True
                updates.append(
                    f"{host} health {_p1_status_label(status).lower()}: "
                    f"{str(sub.get('error') or '')[:120]}"
                )
        elif name in (
            "reboot_required", "pre_reboot_boot_id", "bootnext",
            "reboot", "ssh_return",
        ) and status in _P1_FAILURE_STATUSES:
            n_failed += 1
            updates.append(
                f"{host} {name} {_p1_status_label(status).lower()}: "
                f"{str(sub.get('error') or sub.get('reason') or status)[:120]}"
            )
        elif name == "reboot" and status == "ok":
            if step.get("rebooted") and step.get("post_reboot_health_passed"):
                updates.append(f"{host} rebooted and Linux health was rechecked")
            elif step.get("rebooted"):
                updates.append(f"{host} rebooted; post-reboot health gate did not pass")
            elif step.get("reboot_requested"):
                updates.append(
                    f"{host} reboot requested; Linux SSH return was not validated"
                )

    if step.get("status") in _P1_FAILURE_STATUSES and not emitted_failure:
        n_failed += 1
        updates.append(
            f"{host} maintenance {_p1_status_label(step.get('status')).lower()}: "
            f"{str(step.get('error') or '')[:120]}"
        )
    return updates, n_failed


def _tldr_collect_gamingrig_failures(step):
    """Return remote apply failures for TLDR health and Carter's action list."""
    host = step.get("host") or RIG_SSH_ALIAS
    failures = []
    for sub in step.get("substeps", []) or []:
        name = sub.get("step") or "maintenance"
        status = sub.get("status", "")
        if name in ("health", "post_reboot_health"):
            checks = sub.get("checks") or []
            check_failures = [
                check for check in checks
                if check.get("status") in _P1_FAILURE_STATUSES
            ]
            for check in check_failures:
                detail = check.get("error") or check.get("reason") or check.get("status")
                failures.append(
                    f"{host} {name}/{check.get('step') or 'check'}: {str(detail)[:180]}"
                )
            if status in _P1_FAILURE_STATUSES and not check_failures:
                failures.append(
                    f"{host} {name}: "
                    f"{str(sub.get('error') or 'health gate failed')[:180]}"
                )
        elif status in (_P1_FAILURE_STATUSES | {"reverted"}):
            failures.append(
                f"{host} {name}: "
                f"{str(sub.get('error') or sub.get('reason') or status)[:180]}"
            )
    if step.get("status") in _P1_FAILURE_STATUSES and not failures:
        failures.append(
            f"{host} maintenance: "
            f"{str(step.get('error') or step.get('reason') or 'failed')[:180]}"
        )
    return failures


def _tldr_collect_updates(applied):
    """Real local changes plus actionable remote-maintenance signals."""
    updates = []
    n_failed = 0
    for s in applied.get("steps", []) or []:
        step = s.get("step", "")
        if step in ("gamingrig_maintenance", "gamingrig_linux", "gamingrig"):
            rig_updates, rig_failed = _tldr_collect_gamingrig_updates(s)
            updates.extend(rig_updates)
            n_failed += rig_failed
            continue

        status = s.get("status", "")
        if step == "llama_cpp":
            pre = s.get("pre_version")
            post = s.get("post_version")
            if status == "ok" and pre != post:
                updates.append(f"llama.cpp: {pre or '?'} -> {post or '?'}")
            elif status == "reverted":
                n_failed += 1
                updates.append(
                    f"llama.cpp update rolled back to "
                    f"{s.get('reverted_to') or '?'}"
                )
            elif status in _P1_FAILURE_STATUSES:
                n_failed += 1
                updates.append(
                    f"llama.cpp failed: {str(s.get('error') or s.get('reason') or '')[:120]}"
                )
            continue

        if status in _P1_FAILURE_STATUSES:
            n_failed += 1
            updates.append(
                f"{step} {_p1_status_label(status).lower()}: "
                f"{str(s.get('error') or s.get('reason') or '')[:80]}"
            )
            continue
        if step == "apt_upgrade" and s.get("upgraded_count", 0) > 0:
            updates.append(f"apt: {s['upgraded_count']} packages upgraded")
        elif step.startswith("auto_") and status == "ok":
            pre, post = s.get("pre_version", "?"), s.get("post_version", "?")
            pkg = step.replace("auto_", "")
            if pre != post:
                updates.append(f"{pkg}: {pre} -> {post}")
        elif step in ("openwebui_update", "openwebui"):
            text, _ = _openwebui_update_text(s)
            if text:
                if status == "rolled_back":
                    n_failed += 1
                updates.append(text)
        elif step == "app_deploy" and status in ("ok", "rolled_back"):
            if status == "rolled_back":
                n_failed += 1
            updates.append(_app_deploy_text(s)[0])
        elif step == "dependabot_merge":
            updates.extend(
                text for text, color in _dependabot_merge_lines(s) if color == "#2a2a36")
        elif step == "worker_omp_refresh" and status == "ok":
            updates.append(
                f"steward worker omp: {s.get('pre_version') or '?'} -> "
                f"{s.get('post_version') or '?'}"
            )
        elif step == "freshrss" and status == "bumped":
            updates.append(f"freshrss: {s.get('current_tag')} -> {s.get('latest_tag')}")
        elif step == "herdr_update" and status == "ok":
            pre = str(s.get("pre_version", "")).replace("herdr ", "")
            post = str(s.get("post_version", "")).replace("herdr ", "")
            if pre and post and pre != post:
                updates.append(f"herdr: {pre} -> {post}")
        elif step == "omp_update" and status == "ok":
            pre = str(s.get("pre_version", "")).replace("omp/", "")
            post = str(s.get("post_version", "")).replace("omp/", "")
            if pre and post and pre != post:
                updates.append(f"omp: {pre} -> {post}{_omp_stale_note(s)}")
        elif step == "omp_update" and status == "skipped" and _omp_stale_note(s):
            updates.append(f"omp{_omp_stale_note(s)}")
        elif step == "omp_update" and status == "reverted":
            updates.append(f"omp update rolled back to {s.get('reverted_to','?')} "
                           f"(post-update check failed)")
        elif step == "searxng" and status == "ok":
            updates.append("searxng: pulled latest image")
    apply_failures = _tldr_collect_apply_failures(applied)
    if apply_failures:
        updates.insert(0, apply_failures[0])
        if n_failed == 0:
            n_failed = len(apply_failures)
    elif (applied or {}).get("phase_status") == "degraded":
        updates.insert(
            0,
            f"P1 maintenance degraded: {_p1_failure_detail(applied)}",
        )
    return updates, n_failed

def _tldr_collect_apply_failures(applied):
    """Return one deterministic local maintenance failure for TLDR health."""
    if _p1_phase_failed(applied):
        return [f"P1 maintenance failed: {_p1_failure_detail(applied)}"]
    failures = []
    for step in (applied or {}).get("steps", []) or []:
        if not isinstance(step, dict):
            continue
        name = step.get("step") or "maintenance"
        if name in ("gamingrig_maintenance", "gamingrig_linux", "gamingrig"):
            continue
        status = str(step.get("status") or "").lower()
        if status in _P1_FAILURE_STATUSES:
            detail = step.get("error") or step.get("reason") or status
            failures.append(f"{name} {_p1_status_label(status)}: {str(detail)[:180]}")
    return failures

def _tldr_collect_health(heartbeat, validation=None):
    """End-state host issues (empty list = healthy)."""
    issues = []
    if heartbeat.get("phase_failed"):
        issues.append(f"heartbeat failed: {str(heartbeat.get('error', ''))[:80]}")
    rb = heartbeat.get("reboot", {}) or {}
    if rb.get("needed"):
        issues.append("reboot needed")
    if (heartbeat.get("llm_stack", {}) or {}).get("falling_back", False):
        issues.append("LLM on cloud fallback")
    for c in (validation or {}).get("checks", []) or []:
        if not isinstance(c, dict):
            continue
        st = str(c.get("status") or "ok")
        if st in ("ok", "pass", "skipped", "dry-run"):
            continue
        name = c.get("name") or c.get("endpoint") or "check"
        issues.append(f"{name}: {st}")
    return issues


def _tldr_audit_end_state(audit, fixes):
    """Classify the audit end state per finding route (see steward.routing)."""
    incomplete = []
    for sec in (audit or {}).get("sections", []) or []:
        name = sec.get("name") or "unknown"
        verdict = str(sec.get("verdict") or "")
        base = verdict.removeprefix("cached-")
        if verdict.endswith("-failed") or base in ("collector-failed", "worker-failed"):
            error = (
                sec.get("error") or sec.get("worker_error") or sec.get("judge_error") or verdict
            )
            incomplete.append({
                "section": name, "label": name.replace("_", " "), "note": str(error)[:180],
            })
        elif base == "UNVERIFIABLE":
            incomplete.append({
                "section": name, "label": name.replace("_", " "),
                "note": "audit could not establish a conclusion",
            })

    rows = _route_rows(audit, fixes)
    open_items = [
        {**row, "manual": row.get("status") in ("needs_carter", "report_only")}
        for row in rows if _route_needs_carter(row)
    ]
    in_progress = [r for r in rows if r.get("status") in _IN_PROGRESS_ROUTES]
    done = [r for r in rows if r.get("status") == "done"]
    notes = [r for r in rows if r.get("status") == "report_only" and not _route_needs_carter(r)]
    open_sections = {r.get("section") for r in open_items + in_progress + notes}
    cleared = []
    for name in dict.fromkeys(r.get("section") for r in done):
        if name not in open_sections:
            cleared.append({
                "section": name,
                "label": str(name).replace("_", " "),
                "fixed": sum(1 for r in done if r.get("section") == name),
            })
    return {
        "open": open_items,
        "in_progress": in_progress,
        "done": done,
        "notes": notes,
        "cleared": cleared,
        "incomplete": incomplete,
    }


def _build_tldr_facts(applied, audit, queue, fixes, heartbeat, validation=None):
    """Typed end-state facts for the TL;DR (model input and deterministic fallback)."""
    updates, n_failed_apply = _tldr_collect_updates(applied)
    apply_failures = _tldr_collect_apply_failures(applied)
    rig_apply_failures = []
    for step in applied.get("steps", []) or []:
        if step.get("step") in ("gamingrig_maintenance", "gamingrig_linux", "gamingrig"):
            rig_apply_failures.extend(_tldr_collect_gamingrig_failures(step))
    health_issues = (
        apply_failures
        + rig_apply_failures
        + _tldr_collect_health(heartbeat, validation)
    )
    audit_state = _tldr_audit_end_state(audit, fixes)

    plans = (queue or {}).get("plans", {}) or {}
    carter_items = [
        f"maintenance apply failure — {failure}" for failure in apply_failures
    ] + [
        f"gaming-rig apply failure — {failure}" for failure in rig_apply_failures
    ]
    for step in applied.get("steps", []) or []:
        if step.get("status") == "rolled_back" and step.get("step") in (
            "app_deploy", "openwebui_update",
        ):
            text = (
                _app_deploy_text(step) if step.get("step") == "app_deploy"
                else _openwebui_update_text(step)
            )[0]
            carter_items.append(f"update rolled back — {text}")
        if step.get("step") == "dependabot_merge":
            carter_items.extend(
                f"major Dependabot bump — {pr.get('repo')}#{pr.get('number')}: "
                f"{pr.get('title')} {pr.get('url') or ''}".strip()
                for pr in step.get("needs_carter") or []
            )
    for item in plans.get("approved", []) or []:
        carter_items.append(f"approved plan: {item.get('heading') or item.get('file') or '?'}")
    for item in plans.get("implementing", []) or []:
        age = item.get("age_days")
        label = item.get("heading") or item.get("file") or "?"
        if age is not None and age > 2:
            carter_items.append(f"stale implementing plan ({age}d): {label}")

    needs_carter = list(carter_items) + [
        f"{o['severity']} — {o['label']}: {_clip(o.get('claim'), 200)} "
        f"({_route_outcome_text(o)})"
        for o in audit_state["open"]
    ]

    return {
        "health_ok": not health_issues,
        "health_issues": health_issues,
        "apply_failures": apply_failures,
        "rig_apply_failures": rig_apply_failures,
        "updates": updates,
        "n_failed_apply": n_failed_apply,
        "carter_items": carter_items,
        "audit_open": audit_state["open"],
        "audit_in_progress": audit_state["in_progress"],
        "audit_done": audit_state["done"],
        "audit_notes": audit_state["notes"],
        "audit_cleared": audit_state["cleared"],
        "audit_incomplete": audit_state["incomplete"],
        "n_sections_cleared": len(audit_state["cleared"]),
        "n_sections_open": len({o["section"] for o in audit_state["open"]}),
        "n_sections_incomplete": len(audit_state["incomplete"]),
        "n_real_fixes": len(audit_state["done"]),
        "ideas_outstanding": (queue or {}).get("ideas", {}).get("total_outstanding", 0) or 0,
        "plans_approved": len(plans.get("approved") or []),
        "needs_carter": needs_carter,
    }


_TLDR_RETRY_WORDS = re.compile(
    r"(?i)\b(retr(?:y|ies|ied|ying)|try(?:ing)? again|automation trouble|malformed)\b"
)


def _tldr_payload(facts, date_str):
    """Model input: typed lists, most severe first, stable ids for open problems."""
    problems = [
        {
            "id": f"p{index}",
            "severity": row["severity"],
            "area": row["label"],
            "problem": _clip(row.get("claim"), 300),
            "status": _route_outcome_text(row),
        }
        for index, row in enumerate(facts["audit_open"][:8], 1)
    ]
    payload = {
        "date": date_str,
        "health_issues": facts["health_issues"][:6],
        "problems_needing_carter": problems,
        "more_problems_not_listed": max(0, len(facts["audit_open"]) - len(problems)),
        "other_items_for_carter": facts["carter_items"][:6],
        "fixes_in_progress": [
            {"area": r["label"], "problem": _clip(r.get("claim"), 160),
             "status": _route_outcome_text(r)}
            for r in facts["audit_in_progress"][:4]
        ],
        "done_automatically": [
            {"area": r["label"], "what": _route_outcome_text(r)}
            for r in facts["audit_done"][:6]
        ],
        "low_priority_notes": [
            {"area": r["label"], "note": _clip(r.get("claim"), 160)}
            for r in facts["audit_notes"][:4]
        ],
        "audit_checks_incomplete": [
            {"area": item["label"], "detail": _clip(item.get("note"), 120)}
            for item in facts["audit_incomplete"][:4]
        ],
        "updates": facts["updates"][:6],
        "plans_approved": facts["plans_approved"],
    }
    return payload, problems


def _tldr_violations(packet, *, action_needed, high_ids, problem_ids, retry_allowed):
    """Structural contradictions between the model's summary and its facts."""
    if not isinstance(packet, dict):
        return ["the reply was not a JSON object"]
    violations = []
    summary = str(packet.get("summary") or "").strip()
    if len(summary) < 20:
        violations.append("summary is missing or shorter than one sentence")
    if summary.startswith("{") and '"type"' in summary[:80]:
        violations.append("summary contains raw event-stream text")
    if packet.get("action_needed") is not action_needed:
        violations.append(
            f"action_needed must be {'true' if action_needed else 'false'} for these facts"
        )
    mentioned = {str(x) for x in packet.get("mentioned_ids") or [] if x}
    unknown = sorted(mentioned - set(problem_ids))
    if unknown:
        violations.append(
            "mentioned_ids names ids that are not in the facts: " + ", ".join(unknown)
        )
    if high_ids:
        if str(packet.get("lead_id") or "") not in high_ids:
            violations.append(
                "the summary must open with a high-severity problem ("
                + ", ".join(high_ids) + ")"
            )
        missing = [i for i in high_ids if i not in mentioned]
        if missing:
            violations.append(
                "every high-severity problem must be mentioned: " + ", ".join(missing)
            )
    if not retry_allowed and _TLDR_RETRY_WORDS.search(summary):
        violations.append(
            "no audit check was incomplete tonight, so nothing may be described as retried, "
            "malformed, or automation trouble"
        )
    return violations


def _tldr_prompt(date_str, payload, session_memory):
    return (
        f"You are the Homelab Steward writing the top-of-email summary for {date_str}.\n\n"
        "FACTS (end state after tonight's run; every list is already sorted most severe "
        f"first):\n{json.dumps(payload, indent=2)}\n\n"
        "Recent session memory (context only; never report it as tonight's news):\n"
        f"{session_memory}\n\n"
        "Write 2-4 short plain-English sentences for Carter, under 90 words in total:\n"
        "1. If health_issues, problems_needing_carter, or other_items_for_carter is "
        "non-empty, open with the most severe of them: say plainly what is wrong and what it "
        "affects. Name at most three problems, most severe first, and give the count of the "
        "rest.\n"
        "2. Every entry in problems_needing_carter is a real, confirmed problem that is still "
        "open. Never describe one as automation trouble or malformed, and never say it will "
        "be retried.\n"
        "3. Only entries in audit_checks_incomplete are the steward's own automation "
        "trouble; only those may be described as retried automatically.\n"
        "4. Then, briefly, what changed tonight (updates, done_automatically, "
        "fixes_in_progress). low_priority_notes go last, only if space allows.\n"
        "5. If nothing needs Carter, say the host is in good shape, then what changed.\n"
        "No bullet lists, markdown, badge words (DRIFT, ATTENTION), or artifact names.\n\n"
        "Return ONLY a fenced JSON object:\n"
        '```json\n{"action_needed": true, "lead_id": "p1", "mentioned_ids": ["p1"], '
        '"summary": "two to four sentences"}\n```\n'
        "action_needed is true when anything needs Carter. lead_id is the id of the problem "
        "your first sentence is about (empty if it is not about a listed problem). "
        "mentioned_ids lists every problem id your summary mentions."
    )


def _build_tldr(applied, audit, queue, fixes, heartbeat, date_str, session_memory="",
                validation=None):
    """Model-written end-state TL;DR, checked against the facts it was given.

    The model gets typed lists: problems for Carter, incomplete audits, and
    changes. Its declared structure is validated; a contradiction gets one
    corrected rewrite, then the deterministic summary. Returns HTML-safe text.
    """
    facts = _build_tldr_facts(applied, audit, queue, fixes, heartbeat, validation)
    payload, problems = _tldr_payload(facts, date_str)
    rules = {
        "action_needed": bool(problems or facts["carter_items"] or facts["health_issues"]),
        "high_ids": [p["id"] for p in problems if p["severity"] == "high"][:3],
        "problem_ids": [p["id"] for p in problems],
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
    """Fallback summary: what needs Carter first (most severe first), then changes."""
    parts = []
    if facts.get("health_issues"):
        parts.append("Health issues: " + "; ".join(facts["health_issues"][:4]) + ".")
    open_rows = facts.get("audit_open") or []
    if open_rows:
        top = open_rows[:3]
        rest = len(open_rows) - len(top)
        parts.append(
            "Needs you: " + "; ".join(_clip(r.get("claim"), 160) for r in top)
            + (f" (plus {rest} more)" if rest else "") + "."
        )
    other = [
        item for item in facts.get("carter_items") or []
        if not item.startswith(("maintenance apply failure", "gaming-rig apply failure"))
    ]
    if other:
        parts.append("Also for you: " + "; ".join(other[:3]) + ".")
    incomplete = [item["label"] for item in facts.get("audit_incomplete") or []]
    changes = []
    if facts.get("audit_in_progress"):
        n = len(facts["audit_in_progress"])
        changes.append(f"{n} fix{'es' if n != 1 else ''} in progress.")
    if facts.get("audit_done"):
        n = len(facts["audit_done"])
        changes.append(f"{n} finding{'s' if n != 1 else ''} fixed automatically.")
    if incomplete:
        changes.append(
            "Audit incomplete: " + ", ".join(incomplete[:3])
            + "; the steward will retry automatically."
        )
    if facts.get("updates"):
        changes.append("Updates: " + "; ".join(facts["updates"][:3]) + ".")
    elif facts.get("n_failed_apply"):
        changes.append(f"{facts['n_failed_apply']} update step(s) failed.")
    if not parts and not changes:
        return "Quiet night — host healthy, nothing needs you."
    if not parts:
        parts.append("Host healthy; nothing needs you.")
    return " ".join(parts + changes)


def _html_session_memory(p0b):
    """P0b sessions whose memoir could not be written or updated (degraded phase only)."""
    if not p0b or p0b.get("phase_status") != "degraded":
        return ""
    esc = html.escape
    rows = [s for s in (p0b.get("sessions") or [])
            if isinstance(s, dict) and s.get("action") in P0B_PROBLEM_ACTIONS]
    items = [esc(str(p0b.get("reason") or "degraded"))[:400]]
    items += [
        f"{esc(str(s.get('action')))}: <code>{esc(Path(str(s.get('path') or '?')).name)}</code>"
        f" ({esc(str(s.get('reason') or s.get('error') or ''))[:200]})"
        for s in rows[:20]
    ]
    if len(rows) > 20:
        items.append(f"+{len(rows) - 20} more")
    li = "".join(f"<li>{item}</li>" for item in items)
    return (
        '<tr><td style="padding:16px 32px 8px;">'
        '<h2 style="margin:0; color:#e65100; font-size:15px; font-weight:700;">'
        'Session memory degraded (memoirs left unchanged)</h2></td></tr>'
        '<tr><td style="padding:8px 32px 16px;">'
        f'<ul style="margin:0; padding-left:20px; color:#555; font-size:12px;">{li}</ul>'
        '</td></tr>'
    )


def _html_showcase(showcase):
    """Last P9c public-showcase run: published and held paths with reasons."""
    if not showcase:
        return ""
    esc = html.escape
    status = str(showcase.get("status") or ("failed" if showcase.get("phase_failed") else "unknown"))
    summary = (
        f"Status <strong>{esc(status)}</strong> · {int(showcase.get('published_count') or 0)} files public"
        f" in {esc(str(showcase.get('repo') or 'carter2099/dotfiles-homelab'))}"
    )
    if showcase.get("reason") or showcase.get("error"):
        summary += f" — {esc(str(showcase.get('reason') or showcase.get('error')))[:400]}"
    items = [summary]
    groups = (
        ("Published (new)", "added"),
        ("Published (changed)", "updated"),
        ("Removed from public", "removed"),
        ("Held (not published; decide or fix)", "held"),
        ("Blocked by Jev veto", "blocked"),
    )
    for label, key in groups:
        rows = [r for r in (showcase.get(key) or []) if isinstance(r, dict)]
        if not rows:
            continue
        shown = "; ".join(
            f"<code>{esc(str(r.get('path')))}</code> ({esc(str(r.get('reason') or ''))[:160]})"
            for r in rows[:25]
        )
        more = f" (+{len(rows) - 25} more)" if len(rows) > 25 else ""
        items.append(f"{label}: {shown}{more}")
    if showcase.get("decisions_recorded"):
        items.append("Jev decisions recorded: " + ", ".join(
            f"<code>{esc(str(p))}</code>" for p in showcase["decisions_recorded"][:25]
        ))
    li = "".join(f"<li>{item}</li>" for item in items)
    return (
        '<tr><td style="padding:16px 32px 8px;">'
        '<h2 style="margin:0; color:#1565c0; font-size:15px; font-weight:700;">'
        'Public showcase (last P9c run)</h2></td></tr>'
        '<tr><td style="padding:8px 32px 16px;">'
        f'<ul style="margin:0; padding-left:20px; color:#555; font-size:12px;">{li}</ul>'
        '</td></tr>'
        '<tr><td style="padding:0 32px;"><hr style="border:none; border-top:1px solid #e8e8ee; margin:8px 0;"></td></tr>'
    )


def _html_actions(audit, fixes, applied):
    """Top-of-email "Needs You" and "Done Automatically" rows ("" when both are empty)."""
    rows = _route_rows(audit, fixes)
    needs = [r for r in rows if _route_needs_carter(r)]
    done = [r for r in rows if r.get("status") == "done"]
    in_progress = [r for r in rows if r.get("status") in _IN_PROGRESS_ROUTES]
    p1_done = [
        s for s in (applied or {}).get("steps", []) or []
        if isinstance(s, dict) and s.get("revert") and s.get("status") == "ok"
    ]
    if not (needs or done or in_progress or p1_done):
        return ""

    def block(title, color, items):
        return (
            '<tr><td style="padding:14px 32px 0;">'
            f'<h2 style="margin:0; padding-left:10px; border-left:3px solid {color}; '
            'color:#1a1a2e; font-size:13px; font-weight:700; letter-spacing:0.6px; '
            f'text-transform:uppercase;">{title}</h2></td></tr>'
            f'<tr><td style="padding:8px 32px 10px;">{"".join(items)}</td></tr>'
        )

    def item(text_html, detail="", color="#2a2a36"):
        extra = (
            f'<br><span style="color:#7b7b8a; font-size:12px;">{html.escape(detail)}</span>'
            if detail else ""
        )
        return (
            f'<p style="margin:0 0 6px; color:{color}; font-size:13px; line-height:1.45;">'
            f'{text_html}{extra}</p>'
        )

    out = []
    if needs:
        items = []
        for r in needs[:10]:
            color = {"high": "#c62828", "medium": "#e65100"}.get(r["severity"], "#7b7b8a")
            items.append(item(
                f'{_chip(r["severity"], color)} <strong>{html.escape(r["label"])}</strong>: '
                f'{html.escape(_clip(r.get("claim"), 260))}',
                _route_outcome_text(r),
            ))
        if len(needs) > 10:
            items.append(item(html.escape(f"…and {len(needs) - 10} more in the audit below.")))
        out.append(block("Needs You", "#c62828", items))
    if done or in_progress or p1_done:
        items = []
        for r in done:
            items.append(item(
                f'<strong>{html.escape(r["label"])}</strong>: '
                f'{html.escape(_route_outcome_text(r))}',
                f"Undo: {r['revert']}" if r.get("revert") else "",
            ))
        for s in p1_done:
            label = s.get("service") or s.get("step")
            items.append(item(
                f"<strong>{html.escape(str(label))}</strong>: updated "
                f"{html.escape(_short_sha(s.get('pre_version')))} -> "
                f"{html.escape(_short_sha(s.get('post_version')))}",
                f"Undo: {s['revert']}",
            ))
        for r in in_progress:
            items.append(item(
                f'<strong>{html.escape(r["label"])}</strong>: '
                f'{html.escape(_route_outcome_text(r))}',
                r.get("pr_url") or "",
                "#1565c0",
            ))
        out.append(block("Done Automatically", "#2e7d32", items))
    out.append(
        '<tr><td style="padding:0 32px;"><hr style="border:none; '
        'border-top:1px solid #ececf2; margin:4px 0;"></td></tr>'
    )
    return "".join(out)



def phase_8_render_send(run_dir, setup_data, dry_run=False):
    """Phase 8: render HTML from all artifacts and send email."""
    print("[P8] render + send")

    date_str = setup_data["date"]
    usage = setup_data.get("usage", {})

    # Load all phase data
    applied = read_json(run_dir / "01-applied.json") if (run_dir / "01-applied.json").exists() else {"steps": []}
    validation = read_json(run_dir / "02-validation.json") if (run_dir / "02-validation.json").exists() else {"checks": []}
    troubleshoot = read_json(run_dir / "03-troubleshoot.json") if (run_dir / "03-troubleshoot.json").exists() else None
    heartbeat = read_json(run_dir / "04-heartbeat.json") if (run_dir / "04-heartbeat.json").exists() else {}
    queue = read_json(run_dir / "05-queue.json") if (run_dir / "05-queue.json").exists() else {}
    fixes = read_json(run_dir / "07b-fixes.json") if (run_dir / "07b-fixes.json").exists() else {"sections": []}
    audit = read_json(run_dir / "07-audit.json") if (run_dir / "07-audit.json").exists() else {"sections": []}

    # Phase failures anywhere in the pipeline (each artifact records phase_failed)
    phase_failures = []
    for art in sorted(run_dir.glob("0*.json")):
        try:
            if read_json(art).get("phase_failed"):
                phase_failures.append(art.name)
        except Exception:
            pass

    # Build TLDR (end-state after P7b, not pre-fix process counts)
    tldr = _build_tldr(
        applied, audit, queue, fixes, heartbeat, date_str,
        session_memory=_session_memory_context(),
        validation=validation,
    )

    # Troubleshoot section
    troubleshoot_html = ""
    if troubleshoot and troubleshoot.get("triggered"):
        ts_status = troubleshoot.get("agent_status", "unknown")
        diagnosis = html.escape(str(troubleshoot.get("diagnosis", "")))
        steps = troubleshoot.get("next_steps") or []
        if troubleshoot.get("re_validation_healthy"):
            badge = '<span style="color:#2e7d32; font-weight:700;">RECOVERED</span>'
            color = "#2e7d32"
        elif ts_status == "diagnosed":
            badge = '<span style="color:#e65100; font-weight:700;">NEEDS CARTER</span>'
            color = "#e65100"
        else:
            badge = '<span style="color:#c62828; font-weight:700;">UNDIAGNOSED</span>'
            color = "#c62828"
        steps_html = ""
        if steps:
            steps_html = (
                '<p style="margin:0 0 4px; color:#666; font-size:12px;">Suggested next steps:</p>'
                '<ul style="margin:0; padding-left:20px; color:#555; font-size:12px;">'
                + "".join(f"<li>{html.escape(str(s))}</li>" for s in steps)
                + "</ul>"
            )
        fix_rows = [r for r in troubleshoot.get("fix_actions") or [] if isinstance(r, dict)]
        fix_items = []
        for r in fix_rows:
            endpoint = html.escape(str(r.get("endpoint", "?")))
            conf = r.get("confidence")
            conf_text = f"Jev confidence {conf:.2f}" if isinstance(conf, (int, float)) else "no Jev answer"
            if r.get("executed"):
                fix_items.append(
                    f"<li><strong>{endpoint}</strong>: ran {html.escape(str(r.get('choice')))} "
                    f"({conf_text}, exit {html.escape(str(r.get('exit_code')))}) &rarr; "
                    f"{html.escape(str(r.get('outcome', 'not re-validated')))}</li>")
            else:
                choice = f"Jev chose {html.escape(str(r.get('choice')))}, " if r.get("choice") else ""
                fix_items.append(
                    f"<li><strong>{endpoint}</strong>: no action ({choice}{conf_text}; "
                    f"{html.escape(str(r.get('reason', '')))})</li>")
        fix_html = ""
        if fix_items:
            fix_html = (
                '<p style="margin:8px 0 4px; color:#666; font-size:12px;">Fix menu (steward code, not the agent):</p>'
                '<ul style="margin:0; padding-left:20px; color:#555; font-size:12px;">'
                + "".join(fix_items) + "</ul>")
        changed = any(r.get("executed") for r in fix_rows)
        heading = "Regression diagnosis and fix menu" if changed else "Regression diagnosis (no changes made)"
        troubleshoot_html = (
            '<tr><td style="padding:16px 32px 8px;">'
            f'<h2 style="margin:0; color:{color}; font-size:15px; font-weight:700;">'
            f'{heading} {badge}</h2>'
            '</td></tr>'
            '<tr><td style="padding:8px 32px 16px;">'
            f'<p style="margin:0 0 8px; color:#444; font-size:13px;"><strong>Likely cause:</strong> {diagnosis}</p>'
            f'{steps_html}{fix_html}'
            '</td></tr>'
            '<tr><td style="padding:0 32px;"><hr style="border:none; border-top:1px solid #e8e8ee; margin:8px 0;"></td></tr>'
        )

    remediation = read_json(run_dir / "03a-remediation.json") if (run_dir / "03a-remediation.json").exists() else {}
    try:
        prev_date = prev_workday(datetime.strptime(date_str, "%Y-%m-%d")).strftime("%Y-%m-%d")
        prev_dotfiles = _load_prev_artifact(run_dir, prev_date, "09b-dotfiles.json") or {}
    except ValueError:
        prev_dotfiles = {}
    troubleshoot_html += _html_host_drift(remediation, _dotfiles_untracked_paths(), prev_dotfiles)
    try:
        prev_date = prev_workday(datetime.strptime(date_str, "%Y-%m-%d")).strftime("%Y-%m-%d")
        prev_showcase = _load_prev_artifact(run_dir, prev_date, "09c-showcase.json") or {}
    except ValueError:
        prev_showcase = {}
    troubleshoot_html += _html_showcase(prev_showcase)
    p0b_path = run_dir / "00b-session-memory.json"
    troubleshoot_html += _html_session_memory(read_json(p0b_path) if p0b_path.exists() else {})

    # Footer
    engine = "steward_runner.py (dry-run)" if dry_run else "steward_runner.py"
    footer = (f"carter2099.com · Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · "
              f"{engine} · run dir: {run_dir}")

    # Build template
    if not TEMPLATE_PATH.exists():
        atomic_write_text(TEMPLATE_PATH, DEFAULT_TEMPLATE)
    template = TEMPLATE_PATH.read_text()

    actions_html = _html_actions(audit, fixes, applied)
    if "{{ACTIONS}}" not in template:
        template = template.replace("{{TROUBLESHOOT}}", "{{ACTIONS}}{{TROUBLESHOOT}}", 1)

    html = (
        template
        .replace("{{DATE}}", date_str)
        .replace("{{TLDR}}", tldr)
        .replace("{{ACTIONS}}", actions_html)
        .replace("{{UPDATES}}", _html_updates(applied))
        .replace("{{TROUBLESHOOT}}", troubleshoot_html)
        .replace("{{HEALTH}}", _html_health(validation, heartbeat, applied))
        .replace("{{AUDIT}}", _html_audit(audit, fixes))
        .replace("{{QUEUE}}", _html_queue(queue))
        .replace("{{USAGE}}", _html_usage(usage))
        .replace("{{FOOTER}}", footer)
    )

    email_path = run_dir / "08-email.html"
    atomic_write_text(email_path, html)
    print(f"[P8] rendered -> {email_path}")

    # Build subject
    subject = f"Homelab Steward {date_str}"

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

    # Load key artifacts for summary
    applied = read_json(run_dir / "01-applied.json") if (run_dir / "01-applied.json").exists() else {}
    validation = read_json(run_dir / "02-validation.json") if (run_dir / "02-validation.json").exists() else {}
    audit = read_json(run_dir / "07-audit.json") if (run_dir / "07-audit.json").exists() else {}
    queue = read_json(run_dir / "05-queue.json") if (run_dir / "05-queue.json").exists() else {}
    fixes = read_json(run_dir / "07b-fixes.json") if (run_dir / "07b-fixes.json").exists() else {"sections": []}


    # Build summary.md
    lines = [
        f"# Steward Report — {date_str}",
        f"**Engine:** steward_runner.py",
        "",
        "## Update Status",
    ]
    if _p1_phase_failed(applied):
        lines.append(f"- Maintenance: FAILED — {_p1_failure_detail(applied)}")
    elif applied.get("phase_status") == "degraded":
        lines.append(f"- Maintenance: DEGRADED — {_p1_failure_detail(applied)}")
    for s in applied.get("steps", []):
        if s.get("dry_run"):
            lines.append("- Dry run — no mutations")
            break
        name = s.get("step", "")
        status = s.get("status", "")
        if name in ("gamingrig_maintenance", "gamingrig_linux", "gamingrig"):
            for update in _tldr_collect_gamingrig_updates(s)[0]:
                lines.append(f"- {update}")
            continue

        if name == "llama_cpp":
            for update in _tldr_collect_updates({"steps": [s]})[0]:
                lines.append(f"- {update}")
            continue

        if name.startswith("auto_"):
            pkg = name.replace("auto_", "")
            if status == "ok":
                lines.append(f"- {pkg}: {s.get('pre_version')} -> {s.get('post_version')}")
            elif status == "skipped":
                lines.append(f"- {pkg}: already current ({s.get('pre_version')})")
            else:
                lines.append(f"- {pkg}: {_p1_status_label(status)}")
        elif name in ("openwebui_update", "openwebui"):
            text, _ = _openwebui_update_text(s)
            if text:
                lines.append(f"- {text}")
            elif status in ("current", "skipped"):
                lines.append(
                    f"- open-webui: {s.get('reason') or 'current'} "
                    f"({s.get('pre_version') or s.get('current_tag')})"
                )
        elif name == "app_deploy":
            text, _ = _app_deploy_text(s)
            if text:
                lines.append(f"- {text}")
        elif name == "dependabot_merge":
            lines.extend(f"- {text}" for text, _ in _dependabot_merge_lines(s))
        elif name == "worker_omp_refresh" and status == "ok":
            lines.append(
                f"- steward worker omp: {s.get('pre_version')} -> {s.get('post_version')}"
            )

    lines.append("")
    lines.append("## Validation")
    ep_ok = all(c.get("status") == "ok" for c in validation.get("checks", [])
                if c.get("name", "").startswith("endpoint_"))
    lines.append(f"- Endpoints: {'all passed' if ep_ok else 'SOME FAILED'}")

    lines.append("")
    lines.append("## Audit")
    for sec in audit.get("sections", []):
        lines.append(f"- {sec['name']}: {sec['verdict']}")

    routes = _route_rows(audit, fixes)
    if routes:
        lines.append("")
        lines.append("## Findings")
        for row in routes:
            lines.append(
                f"- [{row['severity']}] {row['label']}: {_route_outcome_text(row)} — "
                f"{_clip(row.get('claim'), 140)}"
            )

    lines.append("")
    lines.append("## Queue")
    lines.append(f"- Plans approved: {len(queue.get('plans', {}).get('approved', []))}")

    md_content = "\n".join(lines) + "\n"
    atomic_write_text(run_dir / "summary.md", md_content)

    # Append runs.jsonl
    n_sections_fired = sum(
        1 for s in audit.get("sections", [])
        if s.get("verdict") not in ("cached-PASS", "dry-run-collector-only")
    )
    n_judge_rejected = sum(
        len(s.get("judge_rejected", [])) for s in audit.get("sections", [])
    )
    route_counts = {}
    for row in routes:
        route_counts[row.get("status")] = route_counts.get(row.get("status"), 0) + 1
    try:
        memory = read_json(run_dir / "memory.json")
    except (OSError, ValueError):
        memory = {}
    memory_mib = {
        key.replace("_bytes", "_mib"): round(int(value) / 1048576)
        for key, value in (memory if isinstance(memory, dict) else {}).items()
        if key.endswith("_bytes") and isinstance(value, (int, float))
    }
    runs_entry = {
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "duration_s": round(elapsed_s),
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

