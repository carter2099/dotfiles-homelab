"""Urgent email channel for security-watch.

``urgent_items`` selects what deserves an immediate email; ``send_urgent`` dedupes
against the notification journal and sends ONE plain HTML email per call through
``scripts/send_digest.py``.  ``policy.urgent_max_per_day`` caps EMAILS per rolling
24 h (counted in the kv log ``EMAIL_LOG_KEY``); each email carries every new item,
the ``MAX_RENDERED`` most severe rendered in full.
"""

from __future__ import annotations

import html
import sys
from datetime import datetime, timedelta
from typing import Any, Callable, Iterable

from security_watch import model

FAILED_ACTION_STATUSES = ("failed", "rolled_back", "unverified")
MAX_RENDERED = 25
EMAIL_LOG_KEY = "urgent_email_log"     # kv: ISO send times of urgent emails (pruned to 8 days)
EMAIL_LOG_RETENTION = timedelta(days=8)

# Render order: remediation failures/breaker, then KEV/Zero Wire findings, then leads,
# then other findings; severity breaks ties inside a group.
RANK_OPERATIONAL = 0
RANK_CURATED_FINDING = 1
RANK_SIGNAL = 2
RANK_FINDING = 3
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}


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


def _finding_item(f: model.Finding, specs: Any) -> dict:
    spec = _spec(specs, f.component_id)
    exposure = spec.exposure if spec else "?"
    pkg = f.package
    lines = [
        f"Component: {f.component_id} (exposure: {exposure})",
        f"Package: {pkg.ecosystem}/{pkg.name} {pkg.version}" + (f" ({pkg.binary})" if pkg.binary else ""),
        "Fixed in: " + (", ".join(f.fixed_versions) if f.fixed_versions else "no fix published yet"),
    ]
    if f.cves:
        lines.append("CVEs: " + ", ".join(f.cves))
    if f.advisory_ids:
        lines.append("Advisories: " + ", ".join(f.advisory_ids))
    flags = []
    if f.kev:
        flags.append("CISA KEV")
    if f.zero_wire:
        flags.append("Zero Wire: " + ", ".join(f.zero_wire))
    if f.severity:
        flags.append(f"severity {f.severity}")
    if flags:
        lines.append("Signals: " + "; ".join(flags))
    if f.reach:
        p = f" p={f.reach.p:.2f}" if f.reach.p is not None else ""
        lines.append(f"Reachability: {f.reach.verdict} ({f.reach.method}{p}) {f.reach.summary}".rstrip())
    if f.reasons:
        lines.append("Why urgent: " + "; ".join(f.reasons))
    if f.summary:
        lines.append(f.summary)
    return {
        "dedupe": f"finding:{f.key}",
        "title": f"{f.group} in {f.component_id} ({pkg.name} {pkg.version})",
        "lines": lines,
        "kind": "finding",
        "rank": (RANK_CURATED_FINDING if (f.kev or f.zero_wire) else RANK_FINDING,
                 _SEVERITY_RANK.get(f.severity, len(_SEVERITY_RANK))),
    }


def _signal_item(sig: model.Signal, kind: str, title: str, extra: Iterable[str] = ()) -> dict:
    lines = list(extra)
    if sig.summary:
        lines.append(sig.summary)
    if sig.url:
        lines.append(f"Source: {sig.url}")
    return {
        "dedupe": f"signal:{sig.source}:{sig.key}",
        "title": title,
        "lines": lines,
        "kind": kind,
        "rank": (RANK_SIGNAL, len(_SEVERITY_RANK)),
    }


def _action_rows(act_result) -> list[dict]:
    if act_result is None:
        return []
    return list(getattr(act_result, "executed", []) or []) + list(getattr(act_result, "advanced", []) or [])


def urgent_items(findings: list[model.Finding], new_signals: list[model.Signal], act_result, store, policy,
                 specs, now: datetime, *, stopgaps=None) -> list[dict]:
    """Items that justify an immediate email; each ``{dedupe, title, lines, kind, rank}``.

    ``stopgaps`` (config.Stopgap list, default none): a stopgap whose status is
    "removable" is an item once (dedupe ``stopgap-removable:<id>``).
    """
    items: list[dict] = []
    for f in findings:
        if f.urgency == model.URGENCY_URGENT and f.status != "fixed":
            items.append(_finding_item(f, specs))

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
                items.append(_signal_item(sig, "pre-announcement", f"PHP pre-announcement: {sig.title}", [
                    "A deployed component runs PHP; watch for the release and update as soon as it lands.",
                ]))
        elif hint == "vendor-breach":
            items.append(_signal_item(sig, "vendor-breach", f"Vendor breach: {sig.title}", [
                "A vendor the homelab depends on appears on a ransomware leak site; review credentials "
                "and integrations with that vendor.",
            ]))
        elif sig.source == "zero_wire" and hint == "needs-attention" and not sig.cves:
            items.append(_signal_item(sig, "manual-check", f"Zero Wire needs attention (no CVE): {sig.title}", [
                "No CVE is named, so nothing can be matched automatically: check manually.",
            ]))

    for row in _action_rows(act_result):
        status = str(row.get("status") or "")
        if status not in FAILED_ACTION_STATUSES:
            continue
        component = row.get("component") or row.get("component_id") or "?"
        lines = [
            f"Playbook: {row.get('playbook', '?')} on {component}",
            f"Target: {row.get('target', '')}",
            f"Status: {status}",
        ]
        if row.get("detail"):
            lines.append(f"Detail: {row['detail']}")
        if row.get("undo"):
            lines.append(f"Undo: {row['undo']}")
        items.append({
            "dedupe": f"action:{row.get('id')}:{status}",
            "title": f"Remediation {status}: {row.get('playbook', '?')} on {component}",
            "lines": lines,
            "kind": "action",
            "rank": (RANK_OPERATIONAL, 0),
        })

    breaker = store.breaker() or {}
    if breaker.get("open"):
        items.append({
            "dedupe": f"breaker:{breaker.get('since') or ''}",
            "title": "Remediation breaker opened",
            "lines": [
                f"Reason: {breaker.get('reason') or 'unknown'}",
                f"Since: {breaker.get('since') or 'unknown'}",
                "No playbook runs until it is reset: python3 ~/scripts/security_watch_runner.py breaker-reset",
            ],
            "kind": "breaker",
            "rank": (RANK_OPERATIONAL, 0),
        })

    if stopgaps:
        from security_watch import report  # lazy: report imports this module
        for row in report.stopgap_rows(store, stopgaps):
            if row["status"] != "removable":
                continue
            lines = [
                f"Component: {row['component']}; CVEs: {', '.join(row['cves'])}",
                "Every covered finding is fixed and the last scan of this component was complete.",
                f"Remove with: {row['remove'] or '(no remove command recorded)'}",
                "Then delete its entry from scripts/security_watch/stopgaps.toml.",
            ]
            if row["description"]:
                lines.insert(1, f"Stopgap: {row['description']}")
            if row["doc"]:
                lines.append(f"Doc: {row['doc']}")
            items.append({
                "dedupe": f"stopgap-removable:{row['id']}",
                "title": f"Stopgap removable: {row['id']}",
                "lines": lines,
                "kind": "stopgap-removable",
                "rank": (RANK_OPERATIONAL, 1),
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


def render_html(items: list[dict], now: datetime, *, more: int = 0) -> str:
    total = len(items) + more
    parts = [
        "<html><body style=\"font-family: sans-serif; font-size: 14px;\">",
        f"<p>security-watch found {total} new urgent item(s) at {html.escape(model.iso(now) or '')}.</p>",
    ]
    for item in items:
        parts.append(f"<h3>{html.escape(item['title'])}</h3>")
        parts.append("<ul>")
        for line in item.get("lines", []):
            parts.append(f"<li>{html.escape(str(line))}</li>")
        parts.append("</ul>")
    if more:
        parts.append(f"<p>+{more} more in tonight's steward report</p>")
    parts.append("<p>Full state: python3 ~/scripts/security_watch_runner.py status</p>")
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


def send_urgent(items: list[dict], *, store, policy, now: datetime, send: Callable | None = None) -> bool:
    """One email with every item not notified before, unless the daily EMAIL cap is reached.

    Renders the ``MAX_RENDERED`` most severe items; only rendered items are recorded as
    notified, so the rest stay eligible for a later email.  True when an email went out.
    """
    fresh = [item for item in items if store.notified_at(item["dedupe"]) is None]
    if not fresh:
        return False
    sent_24h = emails_since(store, now - timedelta(hours=24))
    if sent_24h >= policy.urgent_max_per_day:
        _log(f"daily cap of {policy.urgent_max_per_day} urgent emails reached; "
             f"{len(fresh)} urgent item(s) wait for the report")
        return False
    ordered = sorted(fresh, key=_rank)   # stable: ties keep selection order
    rendered = ordered[:MAX_RENDERED]
    more = len(ordered) - len(rendered)
    subject = f"Security watch: {len(ordered)} urgent — {rendered[0]['title']}"
    if len(subject) > 200:
        subject = subject[:199] + "…"
    body = render_html(rendered, now, more=more)
    sender = send or _default_send()
    sender(subject, body, [policy.recipient])
    _record_email(store, now)
    for item in rendered:
        store.record_notification(item["dedupe"], subject, now)
    _log(f"sent urgent email {sent_24h + 1}/{policy.urgent_max_per_day} in 24h: "
         f"{len(rendered)} item(s) rendered, {more} more in the report")
    return True
