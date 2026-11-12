"""Urgent email channel for security-watch.

``urgent_items`` selects what deserves an email; ``send_urgent`` dedupes against the
notification journal and sends ONE HTML email per call through ``scripts/send_digest.py``.
``policy.urgent_max_per_day`` caps EMAILS per rolling 24 h (counted in the kv log
``EMAIL_LOG_KEY``); each email carries every new item, the ``MAX_RENDERED`` most important
rendered in full.  Failed actions come from the journal (24 h), so an item held back by
the cap or a send failure goes out later.

Every email is written for a reader who wants the system-level picture:

* it opens with the bottom line: which urgent issues are open in the homelab right now
  (``open_issues``), or that none are;
* each item names the affected service, says in plain English what the flaw lets an
  attacker do and what that means for this service, and carries a STATUS decided by code,
  never by a model: STILL VULNERABLE, FIX IN PROGRESS, COULD NOT VERIFY, AUTOMATIC FIX
  FAILED, AUTOMATIC FIXES PAUSED, FIXED (a complete rescan of the running service no longer
  finds the flaw) or NOT EXPLOITABLE HERE (a not-affected check on the running service
  passed), plus what happens next;
* an issue that was emailed gets a follow-up FIXED or NOT EXPLOITABLE HERE email once that
  is verified, so the last word on every alert is a confirmation;
* CVE ids, package versions and advisory ids stay in one small Details line.

Only the two plain-English sentences ("What it is", "What it means here") may come from a
no-tools model call (``explainer``), computed for rendered items only and cached per
finding; without a model, or when it fails, they fall back to the advisory text.
"""

from __future__ import annotations

import hashlib
import html
import re
import sys
import time
from datetime import datetime, timedelta
from typing import Any, Callable

from security_watch import act, model

FAILED_ACTION_STATUSES = ("failed", "rolled_back", "unverified")
MAX_RENDERED = 25
EMAIL_LOG_KEY = "urgent_email_log"     # kv: ISO send times of urgent emails (pruned to 8 days)
EMAIL_LOG_RETENTION = timedelta(days=8)
CONFIRM_WINDOW = timedelta(days=7)      # emailed issues resolved this recently get a FIXED email

# Item statuses (code-decided), most pressing first.
STATUS_VULNERABLE = "STILL VULNERABLE"
STATUS_FIX_FAILED = "AUTOMATIC FIX FAILED"
STATUS_PAUSED = "AUTOMATIC FIXES PAUSED"
STATUS_UNVERIFIED = "COULD NOT VERIFY"
STATUS_IN_PROGRESS = "FIX IN PROGRESS"
STATUS_CHECK = "CHECK NEEDED"
STATUS_HEADS_UP = "HEADS-UP"
STATUS_STOPGAP = "STOPGAP CAN BE REMOVED"
STATUS_FIXED = "FIXED"
STATUS_SAFE = "NOT EXPLOITABLE HERE"
STATUS_UNFLAGGED = "NO LONGER FLAGGED"
_STATUS_ORDER = (STATUS_VULNERABLE, STATUS_FIX_FAILED, STATUS_PAUSED, STATUS_UNVERIFIED, STATUS_IN_PROGRESS,
                 STATUS_CHECK, STATUS_UNFLAGGED, STATUS_HEADS_UP, STATUS_STOPGAP, STATUS_FIXED, STATUS_SAFE)
_STATUS_COLOR = {STATUS_VULNERABLE: "#b00020", STATUS_FIX_FAILED: "#b00020", STATUS_PAUSED: "#b00020",
                 STATUS_UNVERIFIED: "#b26a00", STATUS_IN_PROGRESS: "#b26a00", STATUS_CHECK: "#b26a00",
                 STATUS_UNFLAGGED: "#b26a00", STATUS_HEADS_UP: "#555555", STATUS_STOPGAP: "#1b5e20",
                 STATUS_FIXED: "#1b5e20", STATUS_SAFE: "#1b5e20"}

# Render order: remediation failures/breaker, then KEV/Zero Wire findings, then leads,
# then other findings, then confirmations; severity breaks ties inside a group.
RANK_OPERATIONAL = 0
RANK_CURATED_FINDING = 1
RANK_SIGNAL = 2
RANK_FINDING = 3
RANK_CONFIRMATION = 4
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}

_EXPOSURE_TEXT = {
    "public": "anyone on the internet can reach it",
    "access": "it is on the internet behind the Cloudflare Access login",
    "lan": "only devices on the home network can reach it",
    "loopback": "only programs on the ThinkPad itself can reach it",
    "none": "it accepts no network connections",
}
_FAILED_WORDS = {"failed": "failed",
                 "rolled_back": "failed and was rolled back to the previous version",
                 "unverified": "finished, but a rescan still finds the flaw"}
_RETRY = "The watcher retries every 15 minutes and emails you FIXED once the running service is verified clean."

# Plain-language explanations (the only model-written text).
EXPLAIN_KV = "notify_explanations"      # kv: {finding key: {digest, flaw, risk_here, at}}
EXPLAIN_KEEP = timedelta(days=30)
EXPLAIN_MAX_CALLS = 12                  # model calls per email
EXPLAIN_TIMEOUT = 120
EXPLAIN_MIN_SECONDS = 150               # skip the model when less tick budget than this is left
_EXPLAIN_CLIP = 400
EXPLAIN_PROMPT = """You explain one security issue to the owner of a small homelab, in plain English.
He is technical but wants the functional picture (what an attacker could do to his service), not internals.

Facts verified by his vulnerability watcher (use only these):
- Service: @SERVICE@ — @DESCRIPTION@
- Who can reach it: @EXPOSURE@
- Untrusted input it handles: @UNTRUSTED@
- Vulnerable software: @PACKAGE@
- Severity: @SEVERITY@. Known to be exploited in the wild (CISA KEV): @KEV@.
- Advisory text: @ADVISORY@
- The watcher's finding on whether this service uses the vulnerable code: @REACH@

Reply with only a JSON object {"flaw": "...", "risk_here": "..."}:
- "flaw": one sentence saying what an attacker can do with this flaw, as effects (for example knock the
  service offline, run their own code on it, read private data, bypass a login), not parser or memory
  internals. No CVE ids, no version numbers.
- "risk_here": one sentence saying what that would mean for this service, given who can reach it and
  the watcher's finding. If the finding says the vulnerable code is not loaded or not reachable, say so
  plainly; if it was not assessed, say it is not yet known whether the service uses that code.
  Never say whether it is fixed: the watcher reports that separately.
"""


def _log(message: str) -> None:
    print(f"security-watch: notify: {message}", file=sys.stderr)


def _spec(specs: Any, component_id: str):
    if isinstance(specs, dict):
        return specs.get(component_id)
    for spec in specs or ():
        if spec.id == component_id:
            return spec
    return None


def _has_runtime(store, name: str) -> bool:
    for inv in store.inventories():
        for pkg in inv.packages:
            if pkg.ecosystem == model.RUNTIME_ECOSYSTEM and pkg.name == name:
                return True
    return False


def service_name(spec, component_id: str) -> str:
    """What Carter calls the service (components.toml ``name``), else its id."""
    return str(spec.get("name") or "") if spec is not None and spec.get("name") else component_id


def _short(name: str) -> str:
    return re.sub(r"\s*\([^)]*\)\s*$", "", name) or name


def _when(value: Any) -> str:
    dt = value if isinstance(value, datetime) else model.parse_iso(value)
    return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else "an unknown time"


def _sentence(text: str) -> str:
    text = " ".join(str(text or "").split()).strip()
    return text if not text or text[-1] in ".!?" else text + "."


def _exposure(spec) -> str:
    return _EXPOSURE_TEXT.get(spec.exposure, f"exposure {spec.exposure}") if spec else "its exposure is unknown"


def _details(f: model.Finding) -> list[str]:
    pkg = f.package
    parts = [f"{pkg.ecosystem}/{pkg.name} {pkg.version}" + (f" ({pkg.binary})" if pkg.binary else ""),
             "fixed in " + (", ".join(f.fixed_versions) if f.fixed_versions else "no release yet")]
    ids = list(f.cves) + [a for a in f.advisory_ids if a not in f.cves]
    if ids:
        parts.append(", ".join(ids))
    if f.severity:
        parts.append(f"severity {f.severity}")
    if f.kev:
        parts.append("CISA KEV")
    if f.zero_wire:
        parts.append("Zero Wire: " + ", ".join(f.zero_wire))
    if f.reach and f.reach.verdict != "unknown":
        parts.append(f"reachability {f.reach.verdict} ({f.reach.method})")
    return ["; ".join(parts)]


def _target(action: dict) -> str:
    text = " ".join(str(action.get("target") or action.get("playbook") or "a fix").split())
    return text if len(text) <= 160 else text[:159].rstrip(", ") + "…"


def _covering(actions: list[dict], key: str) -> dict | None:
    rows = [a for a in actions if key in (a.get("finding_keys") or [])]
    return max(rows, key=lambda a: int(a.get("id") or 0)) if rows else None


def _assessment(f: model.Finding, not_affected, ok: bool):
    for entry, verdict in not_affected or ():
        if entry.component == f.component_id and set(entry.cves) & set(f.cves) and verdict.ok == ok:
            return entry, verdict
    return None


# --- status of an open urgent finding ------------------------------------------------------

def _open_status(f: model.Finding, spec, actions: list[dict], refused, not_affected) -> tuple[str, str, str]:
    """(status, "Status" text, "Next" text) for an open urgent finding; decided by code only."""
    name = _short(service_name(spec, f.component_id))
    action = _covering(actions, f.key)
    if action is not None and action.get("status") in ("running", "pending"):
        step = f" Current step: {_sentence(action['detail'])}" if action.get("detail") else ""
        return (STATUS_IN_PROGRESS,
                f"The watcher is fixing it now ({_target(action)}).{step}",
                "You get a FIXED email once a rescan of the running service confirms the fix.")
    failing = _assessment(f, not_affected, ok=False)
    if failing is not None:
        entry, verdict = failing
        return (STATUS_UNVERIFIED,
                f"Checked on {entry.verified} and found not exploitable here: {_sentence(entry.reason)} "
                f"The automatic re-check failed ({_sentence(verdict.detail)}), so until it passes again "
                f"{name} is treated as vulnerable.",
                "The check re-runs every 15 minutes; you get a NOT EXPLOITABLE HERE email when it passes.")
    if f.reach is not None and f.reach.verdict == "reachable":
        status_text = f"Vulnerable and exploitable: {_sentence(f.reach.summary)}"
    else:
        status_text = (f"Vulnerable: {name} runs the affected {f.package.name} {f.package.version}, and "
                       f"{_exposure(spec)}. Whether it actually uses the vulnerable code has not been "
                       "established yet.")
    if action is not None and action.get("status") in FAILED_ACTION_STATUSES:
        status_text += (f" The last automatic attempt (action #{action['id']}) "
                        f"{_FAILED_WORDS.get(action['status'], action['status'])}.")
    if spec is None:
        return STATUS_VULNERABLE, status_text, "Needs you: this component is not in components.toml; fix it by hand."
    pb_id, why, _alert = act.selection(f, spec)
    if not f.fix_available:
        nxt = "No fixed version exists yet. The watcher checks for one every 15 minutes"
        nxt += (" and applies it automatically; you get a FIXED email when the running service is clean."
                if pb_id else f"; there is no automatic fix path ({_sentence(why)[:-1]}), so it will need you.")
        return STATUS_VULNERABLE, status_text, nxt
    if pb_id is None:
        return STATUS_VULNERABLE, status_text, f"Needs you: there is no automatic fix ({_sentence(why)[:-1]})."
    refusal = None
    if refused is not None:
        group = [r for r in refused if r.component_id == f.component_id and r.playbook == pb_id]
        refusal = (next((r for r in group if f.key in r.finding_keys), None)
                   or next((r for r in group if not r.finding_keys), None))
    if refusal is not None:
        return STATUS_VULNERABLE, status_text, f"The automatic fix did not run: {_sentence(refusal.reason)} {_RETRY}"
    return STATUS_VULNERABLE, status_text, f"The automatic fix has not run yet. {_RETRY}"


def open_issues(findings: list[model.Finding], store, specs, now: datetime, *, act_result=None,
                not_affected=None) -> list[str]:
    """One line per open urgent finding ("<service>: <status> (<what>)"); [] when none."""
    urgent = [f for f in findings if f.urgency == model.URGENCY_URGENT and f.status != "fixed"]
    if not urgent:
        return []
    actions = _recent_actions(store, now)
    refused = list(act_result.refused) if act_result is not None else None
    lines = []
    for f in sorted(urgent, key=lambda f: (f.component_id, f.key)):
        spec = _spec(specs, f.component_id)
        status, _, _ = _open_status(f, spec, actions, refused, not_affected)
        lines.append(f"{service_name(spec, f.component_id)}: {status.lower()} "
                     f"({f.package.name}, {f.cves[0] if f.cves else f.group})")
    return lines


def _recent_actions(store, now: datetime) -> list[dict]:
    rows = [*store.actions_since(now - timedelta(hours=24)), *store.active_actions()]
    return list({a["id"]: a for a in rows}.values())


# --- items --------------------------------------------------------------------------------

def _finding_rank(f: model.Finding) -> tuple:
    return (RANK_CURATED_FINDING if (f.kev or f.zero_wire) else RANK_FINDING,
            _SEVERITY_RANK.get(f.severity, len(_SEVERITY_RANK)))


def _finding_item(f: model.Finding, spec, actions: list[dict], refused, not_affected) -> dict:
    status, status_text, nxt = _open_status(f, spec, actions, refused, not_affected)
    return {
        "dedupe": f"finding:{f.key}",
        # A finding that reopened after a fix has a new first_seen: notified again.
        "since": f.first_seen,
        "status": status,
        "title": service_name(spec, f.component_id),
        "sections": [("Status", status_text), ("Next", nxt)],
        "details": _details(f),
        "kind": "finding",
        "rank": _finding_rank(f),
        "explain": (f, spec, "What it is", "What it means here"),
    }


def _installed(store, f: model.Finding, resolved_at: datetime) -> tuple[list[str] | None, str]:
    """(versions of the finding's package seen by the scan that closed it, evidence phrase);
    falls back to the current inventory when it is complete, else (None, why not)."""
    resolution = store.finding_resolution(f.key)
    if resolution is not None:
        return list(resolution.get("installed") or []), f"seen by the complete rescan at {_when(resolved_at)}"
    inv = store.get_inventory(f.component_id)
    if inv is None or inv.status != "ok":
        return None, (inv.reason if inv is not None and inv.reason else "no complete inventory")
    return sorted({p.version for p in inv.packages
                   if p.ecosystem == f.package.ecosystem and p.name == f.package.name}), \
        f"flaw gone in the complete rescan at {_when(resolved_at)}; version from the inventory of {_when(inv.collected_at)}"


def _resolved_item(f: model.Finding, spec, store, actions: list[dict], resolved_at: datetime,
                   not_affected) -> dict:
    """FIXED only when the closing scan saw a different (or no) version of the package; the
    same version still installed means the advisory data changed, not the homelab."""
    name = _short(service_name(spec, f.component_id))
    pkg = f.package
    installed, source = _installed(store, f, resolved_at)
    ids = ", ".join(list(f.cves) + [a for a in f.advisory_ids if a not in f.cves]) or f.group
    labels = ("What it is", None)
    if installed is not None and pkg.version not in installed:
        change = (f"{pkg.name} {pkg.version} was replaced by {', '.join(installed)}" if installed
                  else f"{pkg.name} {pkg.version} has been removed")
        action = _covering(actions, f.key)
        how = (f"Fixed automatically by the watcher: {_target(action)} "
               f"(action #{action['id']})." if action is not None and action.get("status") in ("verified", "done")
               else "Fixed outside the watcher (the nightly steward update, the Dependabot pipeline or a manual "
                    "deploy).")
        status = STATUS_FIXED
        text = f"Fixed and verified in the homelab: the running {name} no longer has the flaw; {change} ({source}). {how}"
        nxt = "Nothing to do."
        labels = ("What it was", None)
    elif installed is not None:
        passing = _assessment(f, not_affected, ok=True)
        if passing is not None:
            status = STATUS_SAFE
            text = (f"Not exploitable in the homelab: {_sentence(passing[0].reason)} A check on the running service "
                    f"proves this every 15 minutes. Nothing changed on {name}: it still runs {pkg.name} "
                    f"{pkg.version}, and the vulnerability data stopped listing it as affected at "
                    f"{_when(resolved_at)}.")
            nxt = "Nothing to do."
        else:
            status = STATUS_UNFLAGGED
            text = (f"Not fixed by any change in the homelab: {name} still runs {pkg.name} {pkg.version}. The watcher "
                    f"stopped flagging it at {_when(resolved_at)} because the vulnerability data changed: the "
                    "advisory no longer lists this version as affected, or the issue no longer meets the alert "
                    "rules.")
            if not f.fix_available:
                text += (" No fixed version had been published, so the flaw may still be present: the watcher only "
                         "tracks an unfixed issue while it is marked as actively exploited.")
            nxt = f"Nothing is required. To double-check, look up {ids}."
    else:
        status = STATUS_UNFLAGGED
        text = (f"A complete rescan of the running {name} at {_when(resolved_at)} no longer found it, but the "
                f"installed {pkg.name} version cannot be shown now ({_sentence(source)[:-1]}), so this is not a "
                "confirmed fix.")
        nxt = f"Nothing is required; the next complete scan of {name} raises it again if the flaw is still there."
    return {
        "dedupe": f"resolved:{f.key}",
        "since": model.iso(resolved_at),
        "status": status,
        "title": service_name(spec, f.component_id),
        "sections": [("Status", text), ("Next", nxt)],
        "details": _details(f),
        "kind": "resolved",
        "rank": (RANK_CONFIRMATION, 0),
        "explain": (f, spec, *labels),
    }


def _safe_item(f: model.Finding, spec, entry) -> dict:
    pkg = f.package
    fixed = f" (fixed in {', '.join(f.fixed_versions)})" if f.fixed_versions else ""
    return {
        "dedupe": f"safe:{f.key}",
        "since": f.first_seen,
        "status": STATUS_SAFE,
        "title": service_name(spec, f.component_id),
        "sections": [("Status", f"Not exploitable in the homelab: {_sentence(entry.reason)} A check on the running "
                                "service proves this every 15 minutes and is passing; if it ever fails, the issue is "
                                "treated as vulnerable again and you get a new email."),
                     ("Next", f"Nothing to do. The unused {pkg.name} {pkg.version} is still installed{fixed}; "
                              "it is replaced by the next update of this service.")],
        "details": _details(f),
        "kind": "safe",
        "rank": (RANK_CONFIRMATION, 1),
        "explain": (f, spec, "What it is", None),
    }


def _signal_item(sig: model.Signal, kind: str, status: str, title: str, status_text: str, nxt: str) -> dict:
    details = [d for d in (sig.summary, f"Source: {sig.url}" if sig.url else "") if d]
    return {
        "dedupe": f"signal:{sig.source}:{sig.key}",
        "status": status,
        "title": title,
        "sections": [("Status", status_text), ("Next", nxt)],
        "details": details,
        "kind": kind,
        "rank": (RANK_SIGNAL, len(_SEVERITY_RANK)),
    }


def urgent_items(findings: list[model.Finding], new_signals: list[model.Signal], store, policy,
                 specs, now: datetime, *, stopgaps=None, act_result=None, not_affected=None) -> list[dict]:
    """Items for the urgent email; each ``{dedupe, status, title, sections, details, kind, rank}``
    (finding-based items also carry ``since`` and ``explain``).

    * every open urgent finding (``finding:<key>``), with its code-decided status: journaled
      actions covering it, else ``act_result`` (this tick's ``act.ActResult``; None when the
      act phase did not run) and ``not_affected`` (this tick's assessment verdicts);
    * FIXED confirmations (``resolved:<key>``) for emailed findings resolved within
      ``CONFIRM_WINDOW``, and NOT EXPLOITABLE HERE confirmations (``safe:<key>``) for emailed
      findings a passing not-affected check made low;
    * failed/rolled back/unverified actions of the last 24 h (``action:<id>:<status>``), an
      open breaker, PHP pre-announcements for a deployed PHP, vendor-breach and CVE-less Zero
      Wire leads, and stopgaps that became removable (``stopgap-removable:<id>``).
    """
    items: list[dict] = []
    actions = _recent_actions(store, now)
    refused = list(act_result.refused) if act_result is not None else None
    for f in findings:
        if f.urgency == model.URGENCY_URGENT and f.status != "fixed":
            items.append(_finding_item(f, _spec(specs, f.component_id), actions, refused, not_affected))
        elif f.status != "fixed" and store.notified_at(f"finding:{f.key}") is not None:
            passing = _assessment(f, not_affected, ok=True)
            if passing is not None:
                items.append(_safe_item(f, _spec(specs, f.component_id), passing[0]))
    resolved = []
    # Fixes credited to the watcher can predate the resolution by days (PR, CI, deploy).
    fix_actions: list[dict] | None = None
    for f in store.findings_resolved_since(now - CONFIRM_WINDOW):
        resolved_at = store.finding_resolved_at(f.key)
        emailed = store.notified_at(f"finding:{f.key}")
        if resolved_at is None or emailed is None or emailed > resolved_at:
            continue
        sent = store.notified_at(f"resolved:{f.key}")
        if sent is not None and sent >= resolved_at:
            continue   # already confirmed: skip the inventory reads
        if fix_actions is None:
            fix_actions = store.actions_since(now - CONFIRM_WINDOW - timedelta(days=2))
        resolved.append(_resolved_item(f, _spec(specs, f.component_id), store, fix_actions, resolved_at,
                                       not_affected))
    items.extend(reversed(resolved))   # newest resolution first

    php_running: bool | None = None
    stale_before = now - timedelta(hours=policy.urgent_window_hours)
    for sig in new_signals:
        published = model.parse_iso(sig.published)
        if published is not None and published < stale_before:
            continue  # a lead first seen late (e.g. on a source's first poll) is not news
        hint = sig.urgency_hint
        if hint == "pre-announcement":
            if php_running is None:
                php_running = _has_runtime(store, "php")
            if php_running:
                items.append(_signal_item(
                    sig, "pre-announcement", STATUS_HEADS_UP, f"PHP security release announced: {sig.title}",
                    "The PHP project has announced an upcoming security release. FreshRSS runs PHP; nothing in the "
                    "homelab is known to be affected until the release names its fixes.",
                    "The watcher updates FreshRSS when a fixed image ships and emails you if it cannot."))
        elif hint == "vendor-breach":
            items.append(_signal_item(
                sig, "vendor-breach", STATUS_CHECK, f"Vendor breach: {sig.title}",
                "A vendor the homelab depends on appears on a ransomware leak site. The watcher cannot tell what "
                "data was taken.",
                "Needs you: review credentials and integrations with that vendor (rotate keys if in doubt)."))
        elif sig.source == "zero_wire" and hint == "needs-attention" and not sig.cves:
            items.append(_signal_item(
                sig, "manual-check", STATUS_CHECK, f"Actively exploited issue without a CVE: {sig.title}",
                "Cloudflare's Zero Wire flags an issue that needs attention but names no CVE, so the watcher cannot "
                "match it against what the homelab runs.",
                "Needs you: read the briefing and check whether any homelab service uses the affected software."))

    for row in store.actions_since(now - timedelta(hours=24)):
        status = str(row.get("status") or "")
        if status not in FAILED_ACTION_STATUSES:
            continue
        component = row.get("component_id") or "?"
        undo = f" If production misbehaves, undo it: {row['undo']}" if row.get("undo") else ""
        items.append({
            "dedupe": f"action:{row.get('id')}:{status}",
            "status": STATUS_FIX_FAILED,
            "title": service_name(_spec(specs, component), component),
            "sections": [("Status", f"The watcher tried to fix a vulnerability automatically "
                                    f"({_target(row)}) and the attempt "
                                    f"{_FAILED_WORDS.get(status, status)}: {_sentence(row.get('detail') or 'no detail')}"),
                         ("Next", f"Needs you: check the service and the open issue.{undo}")],
            "details": [f"action #{row.get('id')}; playbook {row.get('playbook', '?')} on {component}; status {status}"],
            "kind": "action",
            "rank": (RANK_OPERATIONAL, 0),
        })

    breaker = store.breaker() or {}
    if breaker.get("open"):
        items.append({
            "dedupe": f"breaker:{breaker.get('since') or ''}",
            "status": STATUS_PAUSED,
            "title": "All automatic security fixes",
            "sections": [("Status", f"After a fix that failed or could not be verified, the watcher stopped making "
                                    f"automatic fixes anywhere in the homelab since {_when(breaker.get('since'))}: "
                                    f"{_sentence(breaker.get('reason') or 'unknown reason')} "
                                    "It still scans and emails."),
                         ("Next", "Needs you: inspect the failed fix, then resume automatic fixes with "
                                  "python3 ~/scripts/security_watch_runner.py breaker-reset")],
            "details": [],
            "kind": "breaker",
            "rank": (RANK_OPERATIONAL, 0),
        })

    if stopgaps:
        from security_watch import report  # lazy: report imports this module
        for row in report.stopgap_rows(store, stopgaps):
            if row["status"] != "removable":
                continue
            spec = _spec(specs, row["component"])
            name = service_name(spec, row["component"])
            nxt = (f"Remove the temporary protection: {row['remove'] or '(no remove command recorded)'}; then "
                   "delete its entry from scripts/security_watch/stopgaps.toml.")
            if row["doc"]:
                nxt += f" Record it in {row['doc']}."
            items.append({
                "dedupe": f"stopgap-removable:{row['id']}",
                "status": STATUS_STOPGAP,
                "title": name,
                "sections": [("Status", f"The real fix is running: every issue the temporary protection "
                                        f"\"{row['description'] or row['id']}\" covered ({', '.join(row['cves'])}) is "
                                        f"fixed on {_short(name)}, confirmed by a complete rescan."),
                             ("Next", nxt)],
                "details": [f"stopgap {row['id']} since {row.get('since') or '?'}"],
                "kind": "stopgap-removable",
                "rank": (RANK_CONFIRMATION, 2),
            })

    seen: set[str] = set()
    unique = []
    for item in items:
        if item["dedupe"] not in seen:
            seen.add(item["dedupe"])
            unique.append(item)
    return unique


def _rank(item: dict) -> tuple:
    return tuple(item.get("rank") or (RANK_FINDING, len(_SEVERITY_RANK)))


# --- plain-language explanation (the only model-written text) -----------------------------

def _fallback_explanation(f: model.Finding, spec) -> tuple[str, str]:
    kind = f"known {f.severity + ' ' if f.severity else ''}security flaw"
    flaw = (f"{f.package.name} has a {kind}: {_sentence(f.summary)}" if f.summary
            else f"{f.package.name} has a {kind}; the advisory gives no description.")
    if f.reach is not None and f.reach.verdict in ("reachable", "not_reachable") and f.reach.summary:
        risk = _sentence(f.reach.summary)
    else:
        risk = (f"{_short(service_name(spec, f.component_id))} runs the affected version and {_exposure(spec)}; "
                "whether it uses the vulnerable code is not yet known.")
    return flaw, risk


def _explain_prompt(f: model.Finding, spec, advisory: str) -> str:
    reach = "not assessed yet"
    if f.reach is not None and f.reach.summary and f.reach.summary != "deferred":
        reach = f"{f.reach.verdict}: {f.reach.summary}"
    values = {
        "@SERVICE@": _short(service_name(spec, f.component_id)),
        "@DESCRIPTION@": (spec.description if spec else "") or "no description",
        "@EXPOSURE@": _exposure(spec),
        "@UNTRUSTED@": (spec.untrusted_input if spec else "") or "none declared",
        "@PACKAGE@": f"{f.package.name} {f.package.version}",
        "@SEVERITY@": f.severity or "unknown",
        "@KEV@": "yes" if f.kev else "no",
        "@ADVISORY@": advisory or f.summary or "none",
        "@REACH@": reach,
    }
    return re.sub("|".join(re.escape(k) for k in values), lambda m: values[m.group(0)], EXPLAIN_PROMPT)


def _clean(value: Any) -> str:
    text = " ".join(str(value or "").split())
    return text if 10 <= len(text) <= _EXPLAIN_CLIP else ""


def omp_explainer(deadline: float | None = None) -> Callable[[str], str]:
    """No-tools ``omp -p`` call (steward runtime) for ``send_urgent(explainer=...)``."""
    def call(prompt: str) -> str:
        from steward import runtime
        return runtime._call_omp_p(prompt, timeout=EXPLAIN_TIMEOUT, mode="json", tools=runtime.NO_TOOLS,
                                   deadline=deadline)
    return call


class _Explainer:
    def __init__(self, store, now: datetime, call: Callable[[str], str] | None, deadline: float | None):
        self.store, self.now, self.call, self.deadline = store, now, call, deadline
        self.cache = dict(store.get_kv(EXPLAIN_KV, {}) or {})
        self.calls = 0
        self.dirty = False

    def __call__(self, f: model.Finding, spec) -> tuple[str, str]:
        from security_watch import reach
        prompt = _explain_prompt(f, spec, reach.advisory_summary(f, self.store))
        digest = hashlib.sha256(prompt.encode()).hexdigest()[:16]
        hit = self.cache.get(f.key)
        if isinstance(hit, dict) and hit.get("digest") == digest and hit.get("flaw") and hit.get("risk_here"):
            return hit["flaw"], hit["risk_here"]
        fallback = _fallback_explanation(f, spec)
        if self.call is None or self.calls >= EXPLAIN_MAX_CALLS:
            return fallback
        if self.deadline is not None and self.deadline - time.monotonic() < EXPLAIN_MIN_SECONDS:
            return fallback
        from steward import resolver, runtime
        if resolver.secret_reason(prompt):
            return fallback
        self.calls += 1
        try:
            packet = runtime._extract_json(self.call(prompt), "notify-explain")
        except Exception as exc:  # noqa: BLE001 - explanation is optional; status never depends on it
            _log(f"{f.key}: explanation failed: {type(exc).__name__}: {str(exc)[:200]}")
            return fallback
        flaw = _clean(packet.get("flaw")) if isinstance(packet, dict) else ""
        risk = _clean(packet.get("risk_here")) if isinstance(packet, dict) else ""
        if not flaw or not risk or resolver.secret_reason(f"{flaw}\n{risk}"):
            return fallback
        self.cache[f.key] = {"digest": digest, "flaw": flaw, "risk_here": risk, "at": model.iso(self.now)}
        self.dirty = True
        return flaw, risk

    def save(self) -> None:
        if not self.dirty:
            return
        floor = self.now - EXPLAIN_KEEP
        kept = {k: v for k, v in self.cache.items()
                if isinstance(v, dict) and (model.parse_iso(v.get("at")) or self.now) >= floor}
        self.store.set_kv(EXPLAIN_KV, kept)


# --- render / send ------------------------------------------------------------------------

def _counts(items: list[dict]) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for item in items:
        status = item.get("status") or "UPDATE"
        counts[status] = counts.get(status, 0) + 1
    order = {s: i for i, s in enumerate(_STATUS_ORDER)}
    return sorted(counts.items(), key=lambda kv: order.get(kv[0], len(order)))


def subject_line(items: list[dict]) -> str:
    """"Security watch: 1 still vulnerable, 1 fixed — <service of the most pressing item>"."""
    counts = ", ".join(f"{n} {status.lower()}" for status, n in _counts(items))
    order = {s: i for i, s in enumerate(_STATUS_ORDER)}
    lead = min(items, key=lambda i: (order.get(i.get("status") or "", len(order)), _rank(i)))
    subject = f"Security watch: {counts} — {_short(str(lead.get('title') or ''))}"
    return subject if len(subject) <= 200 else subject[:199] + "…"


def _bottom_line(open_now: list[str] | None) -> str:
    if open_now is None:
        return ""
    if not open_now:
        return "<p><b>Bottom line: no urgent security issue is open in the homelab right now.</b></p>"
    rows = "".join(f"<li>{html.escape(line)}</li>" for line in open_now)
    return (f"<p><b>Bottom line: {len(open_now)} urgent issue{'s are' if len(open_now) != 1 else ' is'} still open "
            f"in the homelab:</b></p><ul>{rows}</ul>")


def render_html(items: list[dict], now: datetime, *, more: int = 0, open_now: list[str] | None = None) -> str:
    parts = ["<html><body style=\"font-family: sans-serif; font-size: 14px; max-width: 760px;\">"]
    bottom = _bottom_line(open_now)
    if bottom:
        parts.append(bottom)
    parts.append(f"<p style=\"color:#555\">This email: "
                 f"{html.escape(', '.join(f'{n} {s.lower()}' for s, n in _counts(items)))} "
                 f"(checked {html.escape(_when(now))}).</p>")
    for item in items:
        status = item.get("status") or "UPDATE"
        color = _STATUS_COLOR.get(status, "#333333")
        parts.append(f"<h3 style=\"margin-bottom:4px\"><span style=\"color:{color}\">{html.escape(status)}</span>"
                     f" — {html.escape(str(item.get('title') or ''))}</h3>")
        for label, text in item.get("sections") or ():
            parts.append(f"<p style=\"margin:4px 0\"><b>{html.escape(label)}:</b> {html.escape(str(text))}</p>")
        details = [d for d in item.get("details") or () if d]
        if details:
            parts.append("<p style=\"margin:4px 0;color:#777;font-size:12px\">Details: "
                         + html.escape(" | ".join(details)) + "</p>")
    if more:
        parts.append(f"<p>+{more} more in tonight's steward report</p>")
    parts.append("<p style=\"color:#777;font-size:12px\">Full state: python3 ~/scripts/security_watch_runner.py "
                 "status</p>")
    parts.append("</body></html>")
    return "\n".join(parts)


def _email_log(store) -> list[str]:
    return [str(at) for at in (store.get_kv(EMAIL_LOG_KEY, []) or []) if at]


def emails_since(store, since: datetime) -> int:
    """Urgent emails sent at or after ``since`` (not items)."""
    return sum(1 for at in _email_log(store) if (model.parse_iso(at) or since) >= since)


def _record_email(store, now: datetime) -> None:
    floor = now - EMAIL_LOG_RETENTION
    log = [at for at in _email_log(store) if (model.parse_iso(at) or now) >= floor]
    log.append(model.iso(now))
    store.set_kv(EMAIL_LOG_KEY, log)


def _default_send() -> Callable[[str, str, list[str]], Any]:
    import send_digest  # scripts/ is on sys.path (the runner inserts it)
    return send_digest.send


def _unsent(store, item: dict) -> bool:
    """Never notified, or last notified before the item's ``since`` (a reopened finding)."""
    sent = store.notified_at(item["dedupe"])
    if sent is None:
        return True
    since = model.parse_iso(item.get("since"))
    return since is not None and sent < since


def send_urgent(items: list[dict], *, store, policy, now: datetime, send: Callable | None = None,
                open_now: list[str] | None = None, explainer: Callable[[str], str] | None = None,
                deadline: float | None = None) -> bool:
    """One email with every item not notified before, unless the daily EMAIL cap is reached.

    Renders the ``MAX_RENDERED`` most pressing items; only rendered items are recorded as
    notified, so the rest stay eligible for a later email.  ``open_now`` (``open_issues``)
    is the bottom line; ``explainer`` writes the plain-language lines of rendered finding
    items (None: advisory-text fallback).  True when an email went out.
    """
    fresh = [item for item in items if _unsent(store, item)]
    if not fresh:
        return False
    sent_24h = emails_since(store, now - timedelta(hours=24))
    if sent_24h >= policy.urgent_max_per_day:
        _log(f"daily cap of {policy.urgent_max_per_day} urgent emails reached; "
             f"{len(fresh)} item(s) wait for the report")
        return False
    ordered = sorted(fresh, key=_rank)   # stable: ties keep selection order
    rendered = ordered[:MAX_RENDERED]
    more = len(ordered) - len(rendered)
    explain = _Explainer(store, now, explainer, deadline)
    for index, item in enumerate(rendered):
        if item.get("explain"):
            finding, spec, flaw_label, risk_label = item["explain"]
            flaw, risk = explain(finding, spec)
            lead = [(flaw_label, flaw)] + ([(risk_label, risk)] if risk_label else [])
            rendered[index] = {**item, "sections": [*lead, *item.get("sections", [])]}
    explain.save()
    subject = subject_line(ordered)
    body = render_html(rendered, now, more=more, open_now=open_now)
    sender = send or _default_send()
    sender(subject, body, [policy.recipient])
    _record_email(store, now)
    for item in rendered:
        store.record_notification(item["dedupe"], subject, now)
    _log(f"sent urgent email {sent_24h + 1}/{policy.urgent_max_per_day} in 24h: "
         f"{len(rendered)} item(s) rendered, {more} more in the report")
    return True
