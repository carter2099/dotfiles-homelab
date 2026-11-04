"""Match deployed inventories against issuer records and prioritize the findings.

``scan`` turns inventories into findings (OSV for package ecosystems; php.net,
nodejs.org and GitHub repository advisories for runtimes).  Anything that could not
be checked becomes an ``unknown`` entry and keeps the component out of
``complete`` so its open findings are never closed on missing data.
"""

from __future__ import annotations

import sys
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Sequence

from security_watch import config, feeds, resolve
from security_watch.config import ComponentSpec
from security_watch.model import (
    URGENCY_LOW, URGENCY_NORMAL, URGENCY_URGENT, Finding, Inventory, Package, parse_iso,
)

SUMMARY_MAX = 500
FETCH_WORKERS = 16
_monotonic = time.monotonic   # deadline clock (tests patch this)
_SEVERITY_RANK = {"": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    unknown: list[dict] = field(default_factory=list)     # [{"component", "reason"}]
    complete: set[str] = field(default_factory=set)       # components scanned completely (safe to close findings)
    stats: dict = field(default_factory=dict)


def _log(message: str) -> None:
    print(f"security-watch: scan: {message}", file=sys.stderr)


def _clip(text: str, limit: int = SUMMARY_MAX) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _union(into: list[str], items) -> None:
    for item in items:
        if item and item not in into:
            into.append(item)


class _Collector:
    """Builds findings keyed ``component|group`` and tracks unknown/failed components."""

    def __init__(self, kev: set[str], zero_wire: dict[str, list[dict]]):
        self.kev = kev
        self.zero_wire = zero_wire
        self.findings: dict[str, Finding] = {}
        self.unknown: list[dict] = []
        self.failed: set[str] = set()

    def add_unknown(self, component: str, reason: str, *, incomplete: bool = True) -> None:
        entry = {"component": component, "reason": reason}
        if entry not in self.unknown:
            self.unknown.append(entry)
        if incomplete:
            self.failed.add(component)

    def slugs(self, cves: list[str]) -> list[str]:
        out: list[str] = []
        for cve in cves:
            for item in self.zero_wire.get(cve) or []:
                slug = item.get("slug") if isinstance(item, dict) else None
                if slug and slug not in out:
                    out.append(slug)
        return out

    def add(self, component: str, group: str, package: Package, *, advisory_ids: list[str],
            cves: list[str], fixed: list[str], severity: str = "", summary: str = "",
            kev: bool = False) -> bool:
        """Add or merge one record's finding; returns False when it was dropped
        (no fix and neither KEV nor Zero Wire names one of its CVEs)."""
        kev = kev or any(cve in self.kev for cve in cves)
        slugs = self.slugs(cves)
        if not fixed and not kev and not slugs:
            return False
        key = f"{component}|{group}"
        existing = self.findings.get(key)
        if existing is None:
            self.findings[key] = Finding(
                key=key, component_id=component, group=group, package=package,
                advisory_ids=list(dict.fromkeys(advisory_ids)), cves=list(dict.fromkeys(cves)),
                fixed_versions=list(dict.fromkeys(fixed)), fix_available=bool(fixed),
                severity=severity, kev=kev, zero_wire=slugs, summary=_clip(summary),
            )
            return True
        same_package = (existing.package.ecosystem, existing.package.name, existing.package.version) == \
            (package.ecosystem, package.name, package.version)
        if same_package:
            _union(existing.fixed_versions, fixed)
        elif fixed and not existing.fix_available:
            # One finding carries one package: prefer the package that has a fix.
            existing.package = package
            existing.fixed_versions = list(dict.fromkeys(fixed))
        existing.fix_available = bool(existing.fixed_versions)
        _union(existing.advisory_ids, advisory_ids)
        _union(existing.cves, cves)
        _union(existing.zero_wire, slugs)
        existing.kev = existing.kev or kev
        if _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK.get(existing.severity, 0):
            existing.severity = severity
        if not existing.summary and summary:
            existing.summary = _clip(summary)
        return True


# --- OSV packages ---------------------------------------------------------------

def _expired(deadline: float | None) -> bool:
    return deadline is not None and _monotonic() >= deadline


def _fetch_records(need: list[str], keep: dict[str, set[str] | None], *, store, fetch, now,
                   deadline: float | None) -> tuple[dict[str, dict | None], dict[str, str], set[str]]:
    """Fetch ``need`` concurrently (network only in worker threads); trim and cache on
    this thread.  Returns (records, errors, ids never submitted before the deadline)."""
    records: dict[str, dict | None] = {}
    errors: dict[str, str] = {}
    position = 0
    if not need:
        return records, errors, set()
    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
        inflight: dict[Future, str] = {}
        while position < len(need) or inflight:
            while position < len(need) and len(inflight) < FETCH_WORKERS * 2 and not _expired(deadline):
                vuln_id = need[position]
                position += 1
                inflight[pool.submit(resolve.fetch_vuln, vuln_id, fetch=fetch)] = vuln_id
            if not inflight:
                break
            done, _ = wait(inflight, return_when=FIRST_COMPLETED)
            for future in done:
                vuln_id = inflight.pop(future)
                try:
                    raw = future.result()
                    record = None if raw is None else resolve.trim_record(raw, keep.get(vuln_id))
                except Exception as exc:  # noqa: BLE001 - one record failing never aborts the scan
                    _log(f"OSV record {vuln_id} unavailable: {exc}")
                    errors[vuln_id] = str(exc)
                    continue
                records[vuln_id] = record
                if record is not None:
                    try:
                        store.osv_put(vuln_id, record, now)
                    except Exception as exc:  # noqa: BLE001 - the record is still usable this pass
                        _log(f"cannot cache OSV record {vuln_id}: {exc}")
    return records, errors, set(need[position:])


def _scan_osv(inventories: list[Inventory], col: _Collector, *, store, fetch, now, stats: dict,
              deadline: float | None) -> None:
    packages: list[tuple[str, Package]] = []
    for inv in inventories:
        unsupported = set()
        for pkg in inv.packages:
            if pkg.is_runtime:
                continue
            if not resolve.is_osv_ecosystem(pkg.ecosystem):
                unsupported.add(pkg.ecosystem)
                continue
            packages.append((inv.component_id, pkg))
        for eco in sorted(unsupported):
            col.add_unknown(inv.component_id, f"ecosystem {eco} is not supported by OSV")
    stats["osv_packages"] = len(packages)
    if not packages:
        return
    components = sorted({comp for comp, _ in packages})
    if _expired(deadline):
        for comp in components:
            col.add_unknown(comp, "OSV scan pending: tick deadline reached before querybatch")
        return
    try:
        hits = resolve.querybatch([pkg for _, pkg in packages], fetch=fetch)
    except Exception as exc:  # noqa: BLE001 - any OSV failure -> unknown, never clean
        _log(f"OSV querybatch failed: {exc}")
        stats["osv_errors"] = stats.get("osv_errors", 0) + 1
        for comp in components:
            col.add_unknown(comp, f"OSV unavailable: querybatch: {exc}")
        return
    stats["osv_queries"] = len(hits)
    modified: dict[str, str] = {}
    ecosystems: dict[str, set[str]] = {}
    for pkg, pairs in hits.items():
        for vuln_id, mod in pairs:
            if mod > modified.get(vuln_id, ""):
                modified[vuln_id] = mod
            else:
                modified.setdefault(vuln_id, mod)
            ecosystems.setdefault(vuln_id, set()).add(pkg.ecosystem)
    records: dict[str, dict | None] = {}
    need: list[str] = []
    keep: dict[str, set[str] | None] = {}
    for vuln_id in sorted(modified):
        try:
            cached = store.osv_get(vuln_id)
        except Exception as exc:  # noqa: BLE001 - a bad cache row just means refetch
            _log(f"cannot read cached OSV record {vuln_id}: {exc}")
            cached = None
        if resolve.cache_valid(cached, now=now, modified=modified[vuln_id] or None,
                               keep_ecosystems=ecosystems[vuln_id]):
            records[vuln_id] = cached[0]
            continue
        need.append(vuln_id)
        keep[vuln_id] = resolve.widen_ecosystems(cached[0] if cached else None, ecosystems[vuln_id])
    stats["osv_cached"] = len(records)
    fetched, errors, pending = _fetch_records(need, keep, store=store, fetch=fetch, now=now, deadline=deadline)
    records.update(fetched)
    stats["osv_fetched"] = len(fetched)
    stats["osv_pending"] = len(pending)
    stats["osv_records"] = sum(1 for r in records.values() if r is not None)
    stats["osv_errors"] = stats.get("osv_errors", 0) + len(errors)
    failed_ids: dict[str, list[str]] = {}
    pending_ids: dict[str, set[str]] = {}
    for comp, pkg in packages:
        for vuln_id, _ in hits.get(pkg, []):
            if vuln_id in errors:
                failed_ids.setdefault(comp, [])
                if vuln_id not in failed_ids[comp]:
                    failed_ids[comp].append(vuln_id)
                continue
            if vuln_id in pending:
                pending_ids.setdefault(comp, set()).add(vuln_id)
                continue
            record = records.get(vuln_id)
            if record is None:
                continue
            try:
                if not resolve.matches_package(record, pkg.ecosystem, pkg.name):
                    continue
                cves = resolve.cves_of(record)
                col.add(
                    comp, resolve.group_of(record), pkg, advisory_ids=[vuln_id], cves=cves,
                    fixed=resolve.fixed_versions(record, pkg.ecosystem, pkg.name),
                    severity=resolve.severity_of(record),
                    summary=str(record.get("summary") or record.get("details") or ""),
                )
            except Exception as exc:  # noqa: BLE001 - never raise for a single bad record
                _log(f"bad OSV record {vuln_id}: {exc}")
                col.add_unknown(comp, f"bad OSV record {vuln_id}: {exc}")
    for comp, ids in failed_ids.items():
        first = ids[0]
        more = f" (+{len(ids) - 1} more)" if len(ids) > 1 else ""
        col.add_unknown(comp, f"OSV unavailable: {first}: {errors[first]}{more}")
    for comp, ids in pending_ids.items():
        col.add_unknown(comp, f"OSV records pending: {len(ids)} not yet fetched")


# --- runtimes -------------------------------------------------------------------

def _php_branches(data: Any) -> dict[str, dict]:
    """Accept both {"8.4": {...}} and php.net's nested {"8": {"8.4": {...}}}."""
    out: dict[str, dict] = {}
    for key, value in (data or {}).items() if isinstance(data, dict) else ():
        if isinstance(value, dict) and "version" in value:
            out[str(key)] = value
        elif isinstance(value, dict):
            for sub, entry in value.items():
                if isinstance(entry, dict) and "version" in entry:
                    out[str(sub)] = entry
    return out


def _bare(version: str) -> str:
    version = str(version or "").strip()
    return version[1:] if version[:1] in ("v", "V") else version


def _check_php(comp: str, pkg: Package, col: _Collector, store) -> None:
    branches = _php_branches(feeds.php_active(store))
    if not branches:
        col.add_unknown(comp, "no php.net active-release data yet")
        return
    installed = _bare(pkg.version)
    parts = installed.split(".")
    branch = ".".join(parts[:2])
    entry = branches.get(branch)
    if entry is None:
        col.add_unknown(comp, f"php {installed}: branch {branch} is not an active php.net release branch",
                        incomplete=False)
        return
    latest = _bare(entry.get("version", ""))
    tags = [str(t).lower() for t in entry.get("tags") or []]
    if latest and resolve.version_lt(installed, latest) and "security" in tags:
        col.add(comp, f"PHP-{latest}", pkg, advisory_ids=[f"PHP-{latest}"], cves=[], fixed=[latest],
                summary=f"PHP {latest} is a security release on the {branch} branch (installed {installed})")


def _check_node(comp: str, pkg: Package, col: _Collector, store) -> None:
    index = feeds.node_index(store) or []
    if not index:
        col.add_unknown(comp, "no nodejs.org release data yet")
        return
    installed = _bare(pkg.version)
    major = installed.split(".")[0]
    same = [e for e in index if isinstance(e, dict) and _bare(e.get("version", "")).split(".")[0] == major]
    newer = [e for e in same if resolve.version_lt(installed, _bare(e.get("version", "")))]
    security = [_bare(e["version"]) for e in newer if e.get("security")]
    if not security:
        return
    first = min(security, key=lambda v: _VersionKey(v))
    newest = max((_bare(e["version"]) for e in newer), key=lambda v: _VersionKey(v))
    col.add(comp, f"NODE-{first}", pkg, advisory_ids=[f"NODE-{first}"], cves=[], fixed=[newest],
            summary=f"Node.js {first} is a security release on the v{major} line (installed {installed}; latest {newest})")


class _VersionKey:
    def __init__(self, version: str):
        self.version = version

    def __lt__(self, other: "_VersionKey") -> bool:
        return resolve.version_lt(self.version, other.version)


def _ghsa_of(sig) -> str:
    for alias in getattr(sig, "aliases", ()) or ():
        if str(alias).startswith("GHSA-"):
            return str(alias)
    key = str(getattr(sig, "key", ""))
    return key.rsplit("#", 1)[-1] if "#" in key else key


def _check_repo(comp: str, pkg: Package, repo: str, col: _Collector, store) -> None:
    state = store.source_state("github_advisories") or {}
    if not state.get("last_success"):
        col.add_unknown(comp, f"GitHub advisories for {repo} not fetched yet")
        return
    installed = _bare(pkg.version)
    for sig in feeds.repo_advisories(store, repo):
        cves = sorted({c for c in sig.cves if c}, key=resolve.cve_sort_key)
        ghsa = _ghsa_of(sig)
        for adv in sig.packages:
            if not adv.vulnerable_range or not resolve.in_github_range(installed, adv.vulnerable_range):
                continue
            col.add(comp, cves[0] if cves else ghsa, pkg, advisory_ids=[ghsa], cves=cves,
                    fixed=[_bare(v) for v in adv.fixed if v], kev=bool(sig.kev),
                    summary=sig.summary or sig.title)


def _scan_runtimes(inv: Inventory, spec: ComponentSpec | None, col: _Collector, store) -> None:
    repo = spec.get("advisory_repo") if spec else None
    spec_runtime = spec.get("runtime") if spec else None
    for pkg in inv.packages:
        if not pkg.is_runtime or not pkg.version:
            continue
        checked = False
        try:
            if pkg.name == "php":
                _check_php(inv.component_id, pkg, col, store)
                checked = True
            elif pkg.name == "node":
                _check_node(inv.component_id, pkg, col, store)
                checked = True
            if repo and (not spec_runtime or spec_runtime == pkg.name):
                _check_repo(inv.component_id, pkg, repo, col, store)
                checked = True
        except Exception as exc:  # noqa: BLE001 - a bad feed entry must not abort the scan
            _log(f"{inv.component_id}: runtime check for {pkg.name} failed: {exc}")
            col.add_unknown(inv.component_id, f"runtime check for {pkg.name} failed: {exc}")
            continue
        if not checked:
            col.add_unknown(inv.component_id, f"no advisory feed for {pkg.name}", incomplete=False)


# --- entry points ------------------------------------------------------------------

def scan(inventories: list[Inventory], specs: dict[str, ComponentSpec], *, store, fetch, now,
         deadline: float | None = None) -> ScanResult:
    """``deadline`` is a ``time.monotonic()`` value: once passed, no further OSV record
    fetches are submitted and affected components are reported pending (not complete);
    later ticks continue from the record cache."""
    stats: dict[str, Any] = {"components": len(inventories), "osv_errors": 0}
    col = _Collector(set(feeds.kev_cves(store) or ()), feeds.zero_wire_index(store) or {})
    scanned: list[Inventory] = []
    for inv in inventories:
        if inv.status in ("ok", "partial"):
            scanned.append(inv)
        if inv.status != "ok":
            col.add_unknown(inv.component_id, inv.reason or f"inventory status {inv.status}")
    stats["packages"] = sum(len(inv.packages) for inv in scanned)
    _scan_osv(scanned, col, store=store, fetch=fetch, now=now, stats=stats, deadline=deadline)
    for inv in scanned:
        _scan_runtimes(inv, specs.get(inv.component_id), col, store)
    complete = {inv.component_id for inv in inventories
                if inv.status == "ok" and inv.component_id not in col.failed}
    findings = sorted(col.findings.values(), key=lambda f: f.key)
    stats.update(findings=len(findings), unknown=len(col.unknown), complete=len(complete))
    return ScanResult(findings=findings, unknown=col.unknown, complete=complete, stats=stats)


_SERIOUS = ("critical", "high")
_EXPOSED = ("public", "access")


def prioritize(findings: list[Finding], specs: dict[str, ComponentSpec], policy, *, store, now,
               stopgaps: Sequence[config.Stopgap] | None = None) -> None:
    """Set urgency and reasons in place (run after reachability).

    urgent: affected AND (CISA KEV, or a Zero Wire item that needs attention -- both
            with no time window and regardless of the reach verdict -- or reachable
            with critical/high severity first seen within ``urgent_window_hours``).
    normal: affected AND fix available AND not judged unreachable AND (critical/high
            severity or a public/access surface).
    low:    everything else.
    A finding covered by a stopgap (same component, a shared CVE) is capped at normal
    and its first reason names the stopgap.  ``stopgaps=None`` loads the ledger.
    """
    if stopgaps is None:
        stopgaps = config.load_stopgaps()
    zero_wire = feeds.zero_wire_index(store) or {}
    window = timedelta(hours=policy.urgent_window_hours)
    for finding in findings:
        _rate(finding, specs.get(finding.component_id), policy, zero_wire=zero_wire, window=window, now=now)
        covering = next((gap for gap in stopgaps if gap.component == finding.component_id
                         and set(gap.cves) & set(finding.cves)), None)
        if covering is not None:
            if finding.urgency == URGENCY_URGENT:
                finding.urgency = URGENCY_NORMAL
            finding.reasons = [f"stopgap active: {covering.id} since {covering.since}"] + finding.reasons


def _rate(finding: Finding, spec: ComponentSpec | None, policy, *, zero_wire: dict, window: timedelta,
          now) -> None:
    exposure = spec.exposure if spec is not None else ""
    reach = finding.reach
    verdict = reach.verdict if reach else "unknown"
    serious = finding.severity in _SERIOUS

    intel: list[str] = []
    if finding.kev:
        intel.append("CISA KEV")
    for slug in finding.zero_wire:
        statuses = {item.get("status") for cve in finding.cves for item in zero_wire.get(cve) or []
                    if isinstance(item, dict) and item.get("slug") == slug}
        if "Needs attention" in statuses:
            intel.append(f"Zero Wire: {slug} (Needs attention)")
    reachable_note = ""
    if verdict == "reachable":
        how = f"p={reach.p:.2f}" if reach.p is not None else f"per {reach.method}"
        reachable_note = f"reachable ({how})" + (f", {finding.severity}" if finding.severity else "")
    not_reachable_note = f"not reachable per {reach.method}" if verdict == "not_reachable" else ""
    first_seen = parse_iso(finding.first_seen)
    recent = first_seen is None or now - first_seen <= window

    if finding.status != "affected":
        finding.urgency = URGENCY_LOW
        finding.reasons = [f"status {finding.status}"]
        return
    if intel or (reachable_note and serious and recent):
        finding.urgency = URGENCY_URGENT
        reasons = list(intel)
        if reachable_note:
            reasons.append(reachable_note)
        if not_reachable_note:
            reasons.append(not_reachable_note)
        finding.reasons = reasons
        return
    if finding.fix_available and verdict != "not_reachable" and (serious or exposure in _EXPOSED):
        reasons = ["fix available" + (f", {finding.severity}" if serious else "")]
        if exposure in _EXPOSED:
            reasons.append(f"{exposure} surface")
        if reachable_note:
            reasons.append(reachable_note)
            if serious:
                reasons.append(f"first seen more than {policy.urgent_window_hours}h ago")
        finding.urgency = URGENCY_NORMAL
        finding.reasons = reasons
        return
    finding.urgency = URGENCY_LOW
    if not_reachable_note:
        finding.reasons = [not_reachable_note]
    elif not finding.fix_available:
        finding.reasons = ["no fix available"]
    else:
        finding.reasons = [f"fix available, {finding.severity or 'unrated'} severity on a "
                           f"{exposure or 'unregistered'} component"]
