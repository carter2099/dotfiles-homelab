"""report.json (schema 1) for the steward's nightly email.

Built from the store after every tick and written atomically to
``config.report_path()``.  The steward's report.py is the only reader.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from security_watch import config, feeds, model, notify

SCHEMA = 1
_URGENCY_RANK = {model.URGENCY_URGENT: 0, model.URGENCY_NORMAL: 1, model.URGENCY_LOW: 2}
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}
_NOT_EXECUTED = ("proposed", "refused")


def _iso(value: Any) -> str | None:
    if value is None or isinstance(value, str):
        return value or None
    return model.iso(value)


def _spec(specs: Any, component_id: str):
    if isinstance(specs, dict):
        return specs.get(component_id)
    for spec in specs or ():
        if spec.id == component_id:
            return spec
    return None


def finding_row(f: model.Finding, specs: Any) -> dict:
    spec = _spec(specs, f.component_id)
    reach = None
    if f.reach is not None:
        reach = {"verdict": f.reach.verdict, "p": f.reach.p, "method": f.reach.method,
                 "summary": f.reach.summary}
    return {
        "key": f.key,
        "component": f.component_id,
        "exposure": spec.exposure if spec else "",
        "package": f"{f.package.ecosystem}/{f.package.name}",
        "version": f.package.version,
        "fixed": list(f.fixed_versions),
        "fix_available": bool(f.fix_available),
        "cves": list(f.cves),
        "advisories": list(f.advisory_ids),
        "kev": bool(f.kev),
        "zero_wire": list(f.zero_wire),
        "severity": f.severity,
        "summary": f.summary,
        "reach": reach,
        "urgency": f.urgency,
        "reasons": list(f.reasons),
        "first_seen": f.first_seen,
        "status": f.status,
    }


def _sort_key(f: model.Finding):
    return (_URGENCY_RANK.get(f.urgency, 3), _SEVERITY_RANK.get(f.severity, 4), f.key)


def _sources(store, now: datetime) -> list[dict]:
    week = now - timedelta(days=7)
    rows = []
    for name, spec in feeds.SOURCES.items():
        st = store.source_state(name) or {}
        rows.append({
            "name": name,
            "tier": spec.tier,
            "last_success": _iso(st.get("last_success")),
            "last_error": st.get("last_error") or "",
            "consecutive_failures": int(st.get("consecutive_failures") or 0),
            "ok_rate_7d": store.source_ok_rate(name, week),
        })
    return rows


def _actions(store, since: datetime) -> tuple[list[dict], list[dict]]:
    executed, proposed = [], []
    for a in store.actions_since(since):
        status = a.get("status") or ""
        if status == "proposed":
            plan = a.get("plan") or {}
            proposed.append({
                "component": a.get("component_id") or "",
                "playbook": a.get("playbook") or "",
                "target": a.get("target") or plan.get("target") or "",
                "steps": list(plan.get("steps") or []),
                "undo": a.get("undo") or plan.get("undo") or "",
                "since": _iso(a.get("started_at")),
            })
        elif status not in _NOT_EXECUTED:
            executed.append({
                "id": a.get("id"),
                "playbook": a.get("playbook") or "",
                "component": a.get("component_id") or "",
                "mode": a.get("mode") or "",
                "status": status,
                "target": a.get("target") or "",
                "detail": a.get("detail") or "",
                "undo": a.get("undo") or "",
                "started_at": _iso(a.get("started_at")),
                "finished_at": _iso(a.get("finished_at")),
            })
    return executed, proposed


def _refused(store, since: datetime) -> list[dict]:
    rows = []
    for r in store.refusals_since(since):
        rows.append({
            "component": r.get("component_id") or r.get("component") or "",
            "playbook": r.get("playbook") or "",
            "reason": r.get("reason") or "",
            "alert": bool(r.get("alert", True)),
            "since": _iso(r.get("since") or r.get("first_seen") or r.get("recorded_at") or r.get("at")),
        })
    return rows


def _leads(store, since: datetime) -> list[dict]:
    lead_sources = {name for name, spec in feeds.SOURCES.items() if spec.tier == model.TIER_LEAD}
    rows = []
    for sig, first_seen, _changed in store.signals_since(since):
        is_lead = sig.source in lead_sources or (sig.source == "zero_wire" and not sig.cves)
        if not is_lead:
            continue
        rows.append({"source": sig.source, "title": sig.title, "url": sig.url,
                     "urgency_hint": sig.urgency_hint, "first_seen": first_seen})
    rows.sort(key=lambda r: r["first_seen"] or "", reverse=True)
    return rows


def _resolved(store, since: datetime) -> list[dict]:
    rows = []
    for f in store.findings_resolved_since(since):
        resolved_at = store.finding_resolved_at(f.key)
        rows.append({"key": f.key, "component": f.component_id, "resolved_at": _iso(resolved_at)})
    return rows


_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _covers(stopgap, finding: model.Finding) -> bool:
    return finding.component_id == stopgap.component and bool(set(finding.cves) & set(stopgap.cves))


def stopgap_rows(store, stopgaps) -> list[dict]:
    """Stopgap status from the store.

    active: a covered finding (component + CVE intersection) is open.
    removable: covered findings were seen, every one is fixed (resolved_at set) and the
    component was scanned completely in the last scan (kv "last_complete").
    unverified: anything else (no covered finding ever seen, or the fix is not yet
    confirmed by a complete scan).
    """
    open_findings = store.open_findings()
    resolved = [f for f in store.findings_resolved_since(_EPOCH)
                if f.status == "fixed" and store.finding_resolved_at(f.key) is not None]
    complete = set(store.get_kv("last_complete", []) or [])
    rows = []
    for sg in stopgaps:
        if any(_covers(sg, f) for f in open_findings):
            status = "active"
        elif any(_covers(sg, f) for f in resolved) and sg.component in complete:
            status = "removable"
        else:
            status = "unverified"
        rows.append({"id": sg.id, "component": sg.component, "cves": list(sg.cves),
                     "description": sg.description, "since": sg.since, "remove": sg.remove,
                     "doc": sg.doc, "status": status})
    return rows



def shadow_metrics(store, policy, sources: list[dict], breaker: dict, now: datetime) -> dict:
    since = store.first_run_at()
    days = round(max((now - since).total_seconds(), 0.0) / 86400, 2) if since else 0.0
    rates = [s["ok_rate_7d"] if s["ok_rate_7d"] is not None else 0.0 for s in sources]
    ok_rate = round(min(rates), 4) if rates else 0.0
    urgent_sent = notify.emails_since(store, now - timedelta(days=7))
    criteria = []
    if days < policy.shadow_min_days:
        criteria.append(f"shadow for {days:g} of {policy.shadow_min_days} days")
    if ok_rate < policy.shadow_min_source_ok_rate:
        worst = [s["name"] for s, r in zip(sources, rates) if r < policy.shadow_min_source_ok_rate]
        criteria.append(f"lowest source ok-rate over 7 days {ok_rate:.2f} < "
                        f"{policy.shadow_min_source_ok_rate:.2f} ({', '.join(worst)})")
    if breaker.get("open"):
        criteria.append(f"breaker open: {breaker.get('reason') or 'unknown'}")
    return {
        "since": _iso(since),
        "days": float(days),
        "source_ok_rate": float(ok_rate),
        "urgent_sent_7d": int(urgent_sent),
        "eligible": not criteria,
        "criteria": criteria,
    }


def not_affected_rows(not_affected) -> list[dict]:
    """One row per verified not-affected assessment with this tick's verdict."""
    return [{"id": entry.id, "component": entry.component, "cves": list(entry.cves),
             "reason": entry.reason, "verified": entry.verified, "ok": bool(verdict.ok),
             "detail": verdict.detail}
            for entry, verdict in not_affected]


def build_report(store, policy, specs, scan_result, act_result, tick: dict, now: datetime, *,
                 stopgaps=None, not_affected=None) -> dict:
    """report.json schema 1.  ``tick`` = {"started", "finished", "outcome"} (datetime or ISO).

    ``stopgaps`` defaults to ``config.load_stopgaps()``.  ``not_affected`` is the
    ``[(NotAffected, Verdict)]`` list from this tick (``None`` -> no assessments).
    """
    if stopgaps is None:
        stopgaps = config.load_stopgaps()
    day = now - timedelta(hours=24)
    breaker_state = store.breaker() or {}
    breaker = {"open": bool(breaker_state.get("open")), "reason": breaker_state.get("reason") or "",
               "since": _iso(breaker_state.get("since"))}
    sources = _sources(store, now)
    findings = sorted(store.open_findings(), key=_sort_key)
    if scan_result is not None:
        unknown = list(scan_result.unknown)
    else:
        unknown = list(store.get_kv("last_unknown", []) or [])
    executed, proposed = _actions(store, day)
    return {
        "schema": SCHEMA,
        "generated_at": model.iso(now),
        "mode": policy.mode,
        "breaker": breaker,
        "sources": sources,
        "findings": [finding_row(f, specs) for f in findings],
        "unknown": [{"component": u.get("component", ""), "reason": u.get("reason", "")} for u in unknown],
        "actions_24h": executed,
        # Proposals only describe shadow mode; once active they were never applied and would mislead.
        "proposed": proposed if policy.mode == "shadow" else [],
        "refused": _refused(store, day),
        "leads_24h": _leads(store, day),
        "resolved_24h": _resolved(store, day),
        "shadow": shadow_metrics(store, policy, sources, breaker, now),
        "stopgaps": stopgap_rows(store, stopgaps),
        "not_affected": not_affected_rows(not_affected or ()),
        "last_tick": {"started": _iso(tick.get("started")), "finished": _iso(tick.get("finished")),
                      "outcome": tick.get("outcome") or "ok"},
    }


def write_report(data: dict):
    from workflow_state import atomic_write_json
    path = config.report_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    return atomic_write_json(path, data)
