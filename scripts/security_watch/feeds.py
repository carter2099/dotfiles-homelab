"""Vulnerability feed adapters for security-watch.

Each source is a poll function ``(state, fetch, policy, now) -> (signals, new_state)``
that raises on failure.  ``poll_due`` decides which sources are due, isolates their
failures, stores emitted signals and keeps each source's state in the store.

Key-value data a source maintains (KEV catalog, Zero Wire index, release indexes) is
exchanged through the reserved ``"_kv"`` entry of the state dict: ``poll_due`` loads
the keys listed in ``SourceSpec.kv_keys`` into ``state["_kv"]`` before polling, and
writes every entry of the returned ``new_state["_kv"]`` with ``store.set_kv`` after a
successful poll.  ``"_kv"`` is never persisted as source state.
"""

from __future__ import annotations

import html
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Callable
from urllib.parse import quote, urlsplit

from security_watch import model, net
from security_watch.config import Policy
from security_watch.model import AdvisoryPackage, Signal, TIER_CURATED, TIER_ISSUER, TIER_LEAD

Fetch = Callable[..., Any]
PollFn = Callable[[dict, Fetch, Policy, datetime], tuple[list[Signal], dict]]

FIRST_RUN_WINDOW = timedelta(days=30)
DEFAULT_INTERVAL = 3600
SUMMARY_MAX = 1000
KV = "_kv"

ZERO_WIRE_URL = "https://radar.cloudflare.com/security/zero-wire/rss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GO_VULNDB = "https://vuln.go.dev"
GO_DL_URL = "https://go.dev/dl/?mode=json"
GITHUB_ADVISORIES_URL = ("https://api.github.com/repos/{repo}/security-advisories"
                         "?per_page=20&sort=updated&direction=desc&state=published")
USN_URL = "https://ubuntu.com/security/notices.json?limit=20&order=newest"
DSA_URL = "https://www.debian.org/security/dsa.rdf"
# news.php.net 302-redirects here; HTTPS works on news-web (it fails on news.php.net).
PHP_ANNOUNCE_URL = "https://news-web.php.net/group.php?group=php.announce&format=rss"
PHP_ACTIVE_URL = "https://www.php.net/releases/active.php"
NODE_INDEX_URL = "https://nodejs.org/dist/index.json"
ONECRL_URL = ("https://firefox.settings.services.mozilla.com/v1/buckets/security-state/"
              "collections/onecrl/changeset?_expected=0")
RANSOMWARE_URL = "https://api.ransomware.live/v2/recentvictims"

GO_DETAIL_LIMIT = 20
LINK_LIMIT = 20
USN_RELEASE = "noble"
USN_ECOSYSTEM = "Ubuntu:24.04:LTS"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
CVE_EXACT_RE = re.compile(r"^CVE-\d{4}-\d+$")
HREF_RE = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")
DSA_RE = re.compile(r"\b(DSA-\d+(?:-\d+)?)\b")
PHP_PRE_RE = re.compile(r"upcoming|critical|security release", re.IGNORECASE)
PHP_RELEASED_RE = re.compile(r"released", re.IGNORECASE)
ZERO_WIRE_STATUSES = ("Needs attention", "Reference")
ZERO_WIRE_EXCLUDED_HOSTS = frozenset({"radar.cloudflare.com", "dash.cloudflare.com", "blog.cloudflare.com"})

CONTENT_NS = "{http://purl.org/rss/1.0/modules/content/}encoded"
RSS1_NS = "{http://purl.org/rss/1.0/}"
DC_DATE = "{http://purl.org/dc/elements/1.1/}date"


class PartialFailure(Exception):
    """A poll stored some results but part of the source failed (e.g. one GitHub repo)."""

    def __init__(self, reason: str, signals: list[Signal], state: dict):
        super().__init__(reason)
        self.signals = signals
        self.state = state


# --- helpers -----------------------------------------------------------------

def _log(message: str) -> None:
    print(f"security-watch: feeds: {message}", file=sys.stderr)


def _get(fetch: Fetch, url: str, *, timeout: float = 30):
    return fetch(url, timeout=timeout)


def _json(resp) -> Any:
    return json.loads(resp.body)


def _xml(resp) -> ET.Element:
    return ET.fromstring(resp.body)


def plain_text(value: str | None, limit: int = SUMMARY_MAX) -> str:
    """Strip HTML tags/entities, collapse whitespace and clip to ``limit`` chars."""
    if not value:
        return ""
    text = html.unescape(TAG_RE.sub(" ", value))
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def parse_date(value: Any) -> datetime | None:
    """ISO-8601, RFC 822, ``2026-11-03`` or ``21 Oct 2026`` -> aware UTC datetime."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        parsed = None
    if parsed is None:
        try:
            parsed = parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError):
            parsed = None
    if parsed is None:
        for fmt in ("%d %b %Y", "%d %B %Y"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _floor(state: dict, now: datetime) -> datetime:
    """Items older than the floor are never emitted; set once on the first run."""
    floor = model.parse_iso(state.get("floor"))
    return floor if floor else now - FIRST_RUN_WINDOW


def _after_floor(published: datetime | None, floor: datetime) -> bool:
    return published is None or published >= floor


def _with_floor(state: dict, now: datetime, **extra) -> dict:
    new_state = {"floor": model.iso(_floor(state, now))}
    new_state.update(extra)
    return new_state


def _dedupe(values) -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for value in values:
        if value:
            seen.setdefault(value, None)
    return tuple(seen)


def _version_key(version: str) -> tuple:
    parts = re.split(r"[.\-]", version)
    return tuple((0, int(p)) if p.isdigit() else (-1, p) for p in parts)


# --- Zero Wire (curated) -----------------------------------------------------

def _zero_wire_links(content: str) -> tuple[str, ...]:
    links = []
    for raw in HREF_RE.findall(content or ""):
        href = html.unescape(raw).strip()
        parts = urlsplit(href)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            continue
        if parts.hostname.lower() in ZERO_WIRE_EXCLUDED_HOSTS:
            continue
        links.append(href)
    return _dedupe(links)[:LINK_LIMIT]


def poll_zero_wire(state, fetch, policy, now):
    root = _xml(_get(fetch, ZERO_WIRE_URL))
    signals: list[Signal] = []
    index: dict[str, list[dict]] = {}
    for item in root.iter("item"):
        url = (item.findtext("link") or "").strip()
        slug = urlsplit(url).path.rstrip("/").rsplit("/", 1)[-1]
        if not slug:
            continue
        title = (item.findtext("title") or "").strip()
        guid = (item.findtext("guid") or "").strip() or slug
        categories = [(c.text or "").strip() for c in item.findall("category")]
        content = item.findtext(CONTENT_NS) or ""
        cves = _dedupe([c for c in categories if CVE_EXACT_RE.match(c)] + CVE_RE.findall(content))
        status = next((c for c in categories if c in ZERO_WIRE_STATUSES), "")
        published = parse_date(item.findtext("pubDate"))
        signals.append(Signal(
            source="zero_wire", key=slug, version=guid, title=title, url=url, tier=TIER_CURATED,
            published=model.iso(published), cves=cves,
            urgency_hint="needs-attention" if status == "Needs attention" else "",
            summary=plain_text(item.findtext("description")), links=_zero_wire_links(content),
        ))
        for cve in cves:
            index.setdefault(cve, []).append({"slug": slug, "status": status, "title": title, "url": url})
    return signals, {"items": len(signals), KV: {"zero_wire_index": index}}


# --- CISA KEV (curated) ------------------------------------------------------

def poll_cisa_kev(state, fetch, policy, now):
    data = _json(_get(fetch, KEV_URL, timeout=60))
    vulns = data.get("vulnerabilities") or []
    if not isinstance(vulns, list):
        raise ValueError("KEV catalog has no vulnerabilities list")
    catalog = str(data.get("catalogVersion") or "")
    all_cves = sorted({v.get("cveID") for v in vulns if v.get("cveID")})
    kv = {"kev_cves": all_cves}
    cursor = state.get("cursor")
    if state and catalog and catalog == state.get("catalog_version"):
        return [], {"catalog_version": catalog, "cursor": cursor, KV: kv}
    since = cursor or (now - FIRST_RUN_WINDOW).date().isoformat()
    signals = []
    latest = cursor or ""
    for v in vulns:
        cve, added = v.get("cveID"), str(v.get("dateAdded") or "")
        if not cve:
            continue
        latest = max(latest, added)
        if added < since:
            continue
        name = v.get("vulnerabilityName") or f"{v.get('vendorProject', '')} {v.get('product', '')}".strip()
        summary = " ".join(filter(None, [
            v.get("shortDescription"),
            f"Known ransomware use: {v['knownRansomwareCampaignUse']}." if v.get("knownRansomwareCampaignUse") else "",
            f"Required action: {v['requiredAction']}" if v.get("requiredAction") else "",
            f"Due {v['dueDate']}." if v.get("dueDate") else "",
        ]))
        signals.append(Signal(
            source="cisa_kev", key=cve, version=added, title=f"{cve}: {name}",
            url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search={quote(cve)}",
            tier=TIER_CURATED, published=model.iso(parse_date(added)), cves=(cve,), kev=True,
            summary=plain_text(summary),
        ))
    return signals, {"catalog_version": catalog, "cursor": latest or since, KV: kv}


# --- Go vulndb (issuer) ------------------------------------------------------

def poll_go_vulndb(state, fetch, policy, now):
    db = _json(_get(fetch, f"{GO_VULNDB}/index/db.json"))
    db_modified = str(db.get("modified") or "")
    if state and db_modified and db_modified == state.get("db_modified"):
        return [], {"db_modified": db_modified}
    entries = _json(_get(fetch, f"{GO_VULNDB}/index/vulns.json", timeout=60))
    if not isinstance(entries, list):
        raise ValueError("Go vulndb index is not a list")
    previous = (state.get(KV) or {}).get("go_vulndb_modified") or {}
    first = not previous
    cutoff = now - FIRST_RUN_WINDOW
    current: dict[str, str] = {}
    changed = []
    for entry in entries:
        vuln_id, modified = entry.get("id"), str(entry.get("modified") or "")
        if not vuln_id:
            continue
        current[vuln_id] = modified
        if previous.get(vuln_id) == modified:
            continue
        if first:
            when = parse_date(modified)
            if when is None or when < cutoff:
                continue
        changed.append(entry)
    changed.sort(key=lambda e: str(e.get("modified") or ""), reverse=True)
    signals = []
    for n, entry in enumerate(changed):
        vuln_id = entry["id"]
        aliases = tuple(str(a) for a in entry.get("aliases") or ())
        summary = ""
        if n < GO_DETAIL_LIMIT:
            try:
                record = _json(_get(fetch, f"{GO_VULNDB}/ID/{quote(vuln_id)}.json"))
                summary = plain_text(record.get("summary") or record.get("details"))
            except Exception as exc:  # detail is optional; the index entry is the signal
                _log(f"go_vulndb: detail {vuln_id} skipped: {exc}")
        signals.append(Signal(
            source="go_vulndb", key=vuln_id, version=str(entry.get("modified") or ""),
            title=f"{vuln_id}: {summary}" if summary else vuln_id,
            url=f"https://pkg.go.dev/vuln/{vuln_id}", tier=TIER_ISSUER,
            published=model.iso(parse_date(entry.get("modified"))),
            cves=tuple(a for a in aliases if CVE_EXACT_RE.match(a)), aliases=aliases, summary=summary,
        ))
    return signals, {"db_modified": db_modified, KV: {"go_vulndb_modified": current}}


# --- Go releases (issuer) ----------------------------------------------------

def poll_go_releases(state, fetch, policy, now):
    releases = _json(_get(fetch, GO_DL_URL))
    stable = sorted(
        {str(r["version"]).removeprefix("go") for r in releases if r.get("stable") and r.get("version")},
        key=_version_key, reverse=True)
    if not stable:
        raise ValueError("go.dev/dl lists no stable release")
    seen = set(state.get("seen") or ())
    signals = [Signal(
        source="go_releases", key=f"go{v}", version=v, title=f"Go {v} released",
        url=f"https://go.dev/doc/devel/release#go{v}", tier=TIER_ISSUER,
        summary=f"Go {v} is a current stable release.",
    ) for v in stable if v not in seen]
    return signals, {"seen": sorted(seen | set(stable), key=_version_key, reverse=True), KV: {"go_stable": stable}}


# --- GitHub repository advisories (issuer) ----------------------------------

def _github_signal(repo: str, adv: dict) -> Signal | None:
    ghsa = adv.get("ghsa_id")
    if not ghsa:
        return None
    packages = []
    for vuln in adv.get("vulnerabilities") or ():
        pkg = vuln.get("package") or {}
        if not pkg.get("name"):
            continue
        patched = vuln.get("patched_versions") or ""
        packages.append(AdvisoryPackage(
            ecosystem=str(pkg.get("ecosystem") or ""), name=str(pkg["name"]),
            vulnerable_range=str(vuln.get("vulnerable_version_range") or ""),
            fixed=tuple(p.strip() for p in str(patched).split(",") if p.strip()),
        ))
    cve = adv.get("cve_id")
    summary = adv.get("summary") or ""
    if adv.get("severity"):
        summary = f"{summary} (severity: {adv['severity']})"
    return Signal(
        source="github_advisories", key=f"{repo}#{ghsa}", version=str(adv.get("updated_at") or ""),
        title=f"{repo} {ghsa}: {adv.get('summary') or ''}".strip(), url=str(adv.get("html_url") or ""),
        tier=TIER_ISSUER, published=model.iso(parse_date(adv.get("published_at"))),
        cves=(cve,) if cve else (), aliases=(ghsa,), packages=tuple(packages), summary=plain_text(summary),
    )


def poll_github_advisories(state, fetch, policy, now):
    floor = _floor(state, now)
    signals, errors = [], []
    for repo in policy.upstream_repos:
        try:
            advisories = _json(_get(fetch, GITHUB_ADVISORIES_URL.format(repo=repo)))
            if not isinstance(advisories, list):
                raise ValueError("advisory list expected")
        except Exception as exc:
            errors.append(f"{repo}: {exc}")
            continue
        for adv in advisories:
            sig = _github_signal(repo, adv)
            if sig and _after_floor(parse_date(adv.get("updated_at")), floor):
                signals.append(sig)
    new_state = _with_floor(state, now)
    if errors:
        if len(errors) == len(policy.upstream_repos):
            raise RuntimeError("; ".join(errors))
        raise PartialFailure("; ".join(errors), signals, new_state)
    return signals, new_state


# --- Ubuntu USN (issuer) -----------------------------------------------------

def poll_ubuntu_usn(state, fetch, policy, now):
    data = _json(_get(fetch, USN_URL))
    notices = data.get("notices") if isinstance(data, dict) else None
    if not isinstance(notices, list):
        raise ValueError("USN response has no notices list")
    floor = _floor(state, now)
    signals = []
    for notice in notices:
        usn = notice.get("id")
        published = parse_date(notice.get("published"))
        if not usn or not _after_floor(published, floor):
            continue
        cve_ids = notice.get("cves_ids") or [
            c.get("id") if isinstance(c, dict) else c for c in notice.get("cves") or ()]
        packages = tuple(
            AdvisoryPackage(USN_ECOSYSTEM, str(p["name"]), fixed=(str(p["version"]),))
            for p in (notice.get("release_packages") or {}).get(USN_RELEASE) or ()
            if p.get("is_source") and p.get("name") and p.get("version"))
        summary = " ".join(filter(None, [notice.get("summary"), notice.get("description")]))
        signals.append(Signal(
            source="ubuntu_usn", key=usn, version=str(notice.get("published") or ""),
            title=f"{usn}: {notice.get('title') or ''}".strip(),
            url=f"https://ubuntu.com/security/notices/{usn}", tier=TIER_ISSUER,
            published=model.iso(published), cves=_dedupe(str(c) for c in cve_ids if c),
            packages=packages, summary=plain_text(summary),
        ))
    return signals, _with_floor(state, now)


# --- Debian DSA (lead) -------------------------------------------------------

def poll_debian_dsa(state, fetch, policy, now):
    root = _xml(_get(fetch, DSA_URL))
    floor = _floor(state, now)
    signals = []
    for item in root.iter(f"{RSS1_NS}item"):
        title = (item.findtext(f"{RSS1_NS}title") or "").strip()
        match = DSA_RE.search(title)
        if not match:
            continue
        date_text = (item.findtext(DC_DATE) or "").strip()
        published = parse_date(date_text)
        if not _after_floor(published, floor):
            continue
        dsa = match.group(1)
        signals.append(Signal(
            source="debian_dsa", key=dsa, version=date_text or dsa, title=title,
            url=(item.findtext(f"{RSS1_NS}link") or "").strip(), tier=TIER_LEAD,
            published=model.iso(published),
            links=(f"https://security-tracker.debian.org/tracker/{dsa}",),
        ))
    return signals, _with_floor(state, now)


# --- php.announce (lead) -----------------------------------------------------

def poll_php_announce(state, fetch, policy, now):
    root = _xml(_get(fetch, PHP_ANNOUNCE_URL))
    floor = _floor(state, now)
    signals = []
    for item in root.iter("item"):
        url = (item.findtext("link") or "").strip()
        title = (item.findtext("title") or "").strip()
        if not url:
            continue
        pub_text = (item.findtext("pubDate") or "").strip()
        published = parse_date(pub_text)
        if not _after_floor(published, floor):
            continue
        pre = bool(PHP_PRE_RE.search(title)) and not PHP_RELEASED_RE.search(title)
        signals.append(Signal(
            source="php_announce", key=url, version=model.iso(published) or pub_text or url, title=title,
            url=url, tier=TIER_LEAD, published=model.iso(published),
            urgency_hint="pre-announcement" if pre else "",
            summary=plain_text(item.findtext("description")),
        ))
    return signals, _with_floor(state, now)


# --- PHP releases (issuer) ---------------------------------------------------

def poll_php_releases(state, fetch, policy, now):
    data = _json(_get(fetch, PHP_ACTIVE_URL))
    if not isinstance(data, dict):
        raise ValueError("active.php is not an object")
    floor = _floor(state, now)
    active: dict[str, dict] = {}
    for branches in data.values():
        if not isinstance(branches, dict):
            continue
        for branch, info in branches.items():
            if isinstance(info, dict) and info.get("version"):
                active[branch] = {"version": str(info["version"]), "date": str(info.get("date") or ""),
                                  "tags": [str(t) for t in info.get("tags") or ()]}
    if not active:
        raise ValueError("active.php lists no branches")
    signals = []
    for branch in sorted(active, key=_version_key, reverse=True):
        info = active[branch]
        published = parse_date(info["date"])
        if not _after_floor(published, floor):
            continue
        version, tags = info["version"], info["tags"]
        signals.append(Signal(
            source="php_releases", key=f"php-{version}", version=version,
            title=f"PHP {version} released" + (" (security)" if "security" in tags else ""),
            url=f"https://www.php.net/ChangeLog-{branch.split('.')[0]}.php#{version}", tier=TIER_ISSUER,
            published=model.iso(published),
            summary=f"PHP {branch} branch: {version} ({info['date']}); tags: {', '.join(tags) or 'none'}.",
        ))
    return signals, _with_floor(state, now, **{KV: {"php_active": active}})


# --- Node.js releases (issuer) -----------------------------------------------

def poll_node_releases(state, fetch, policy, now):
    data = _json(_get(fetch, NODE_INDEX_URL, timeout=60))
    if not isinstance(data, list):
        raise ValueError("node index is not a list")
    index = [{"version": str(r["version"]).removeprefix("v"), "date": str(r.get("date") or ""),
              "security": bool(r.get("security")), "lts": r.get("lts") or False}
             for r in data if r.get("version")]
    index.sort(key=lambda r: _version_key(r["version"]), reverse=True)
    floor = _floor(state, now)
    signals = []
    for rel in index:
        if not rel["security"]:
            continue
        published = parse_date(rel["date"])
        if not _after_floor(published, floor):
            continue
        version = rel["version"]
        lts = f" LTS {rel['lts']}" if rel["lts"] else ""
        signals.append(Signal(
            source="node_releases", key=f"node-{version}", version=version,
            title=f"Node.js {version}{lts} security release",
            url=f"https://nodejs.org/en/blog/release/v{version}", tier=TIER_ISSUER,
            published=model.iso(published),
            summary=f"Node.js v{version}{lts} released {rel['date']} as a security release.",
        ))
    return signals, _with_floor(state, now, **{KV: {"node_index": index}})


# --- Mozilla OneCRL (lead) ---------------------------------------------------

def poll_onecrl(state, fetch, policy, now):
    cursor = state.get("cursor")
    url = ONECRL_URL if cursor is None else f"{ONECRL_URL}&_since={int(cursor)}"
    data = _json(_get(fetch, url))
    timestamp = data.get("timestamp")
    if not isinstance(timestamp, int):
        raise ValueError("OneCRL changeset has no timestamp")
    if cursor is None:
        return [], {"cursor": timestamp}
    signals = []
    for change in data.get("changes") or ():
        modified = change.get("last_modified")
        if (not change.get("id") or change.get("deleted") or not change.get("enabled")
                or not isinstance(modified, int) or modified <= int(cursor)):
            continue
        details = change.get("details") or {}
        bug = str(details.get("bug") or "")
        title = details.get("name") or (f"OneCRL revocation ({bug})" if bug else "OneCRL revocation")
        signals.append(Signal(
            source="onecrl", key=str(change["id"]), version=str(modified), title=str(title),
            url=bug if bug.startswith("http") else "", tier=TIER_LEAD,
            published=model.iso(datetime.fromtimestamp(modified / 1000, timezone.utc)),
            summary=plain_text(details.get("why")),
        ))
    return signals, {"cursor": max(timestamp, int(cursor))}


# --- ransomware.live (lead) --------------------------------------------------

def _vendor_for(victim: dict, vendors) -> str | None:
    haystack = f"{victim.get('victim') or ''}\n{victim.get('domain') or ''}".lower()
    for vendor in vendors:
        for needle in vendor.get("match") or ():
            if needle and str(needle).lower() in haystack:
                return str(vendor.get("name") or needle)
    return None


def poll_ransomware_live(state, fetch, policy, now):
    victims = _json(_get(fetch, RANSOMWARE_URL))
    if not isinstance(victims, list):
        raise ValueError("recentvictims is not a list")
    floor = _floor(state, now)
    signals = []
    for victim in victims:
        url = victim.get("url")
        vendor = _vendor_for(victim, policy.vendors)
        published = parse_date(victim.get("discovered") or victim.get("attackdate"))
        if not url or not vendor or not _after_floor(published, floor):
            continue
        name, group = victim.get("victim") or "", victim.get("group") or ""
        description = plain_text(victim.get("description"), 300)
        summary = " ".join(filter(None, [
            f"Vendor {vendor}: victim {name!s} ({victim.get('domain') or 'no domain'}) listed by {group}.",
            description]))
        signals.append(Signal(
            source="ransomware_live", key=str(url), version=str(victim.get("discovered") or url),
            title=f"{vendor}: {name} listed by {group}", url=str(url), tier=TIER_LEAD,
            published=model.iso(published), urgency_hint="vendor-breach", summary=plain_text(summary),
        ))
    return signals, _with_floor(state, now)


# --- registry ----------------------------------------------------------------

@dataclass(frozen=True)
class SourceSpec:
    name: str
    tier: str
    poll: PollFn
    kv_keys: tuple[str, ...] = ()   # kv entries loaded into state["_kv"] before polling


SOURCES: dict[str, SourceSpec] = {spec.name: spec for spec in (
    SourceSpec("zero_wire", TIER_CURATED, poll_zero_wire),
    SourceSpec("cisa_kev", TIER_CURATED, poll_cisa_kev),
    SourceSpec("go_vulndb", TIER_ISSUER, poll_go_vulndb, ("go_vulndb_modified",)),
    SourceSpec("go_releases", TIER_ISSUER, poll_go_releases),
    SourceSpec("github_advisories", TIER_ISSUER, poll_github_advisories),
    SourceSpec("ubuntu_usn", TIER_ISSUER, poll_ubuntu_usn),
    SourceSpec("debian_dsa", TIER_LEAD, poll_debian_dsa),
    SourceSpec("php_announce", TIER_LEAD, poll_php_announce),
    SourceSpec("php_releases", TIER_ISSUER, poll_php_releases),
    SourceSpec("node_releases", TIER_ISSUER, poll_node_releases),
    SourceSpec("onecrl", TIER_LEAD, poll_onecrl),
    SourceSpec("ransomware_live", TIER_LEAD, poll_ransomware_live),
)}


@dataclass
class PollResult:
    new: list[Signal]
    updated: list[Signal]
    health: dict[str, str]   # "ok" | "not-due" | "failed: <reason>"


def _is_due(source_state: dict, interval: int, now: datetime, force: bool) -> bool:
    if force:
        return True
    last = model.parse_iso(source_state.get("last_attempt"))
    return last is None or now - last >= timedelta(seconds=interval)


def _error_text(exc: BaseException) -> str:
    text = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
    return " ".join(text.split())[:300]


def _store_signals(store, signals: list[Signal], now, result: PollResult) -> None:
    for sig in signals:
        outcome = store.upsert_signal(sig, now)
        if outcome == "new":
            result.new.append(sig)
        elif outcome == "updated":
            result.updated.append(sig)


def _persisted(state: dict) -> dict:
    return {k: v for k, v in state.items() if k != KV}


def _cursor_text(state: dict) -> str | None:
    cursor = state.get("cursor")
    return None if cursor is None else str(cursor)


def poll_due(store, policy, *, now, fetch=net.fetch, only: set[str] | None = None,
             force: bool = False) -> PollResult:
    result = PollResult(new=[], updated=[], health={})
    for name, spec in SOURCES.items():
        if only is not None and name not in only:
            continue
        source_state = store.source_state(name)
        interval = policy.source_intervals.get(name, DEFAULT_INTERVAL)
        if not _is_due(source_state, interval, now, force):
            result.health[name] = "not-due"
            continue
        old_state = dict(source_state.get("state") or {})
        poll_state = dict(old_state)
        if spec.kv_keys:
            poll_state[KV] = {key: store.get_kv(key) for key in spec.kv_keys}
        try:
            signals, new_state = spec.poll(poll_state, fetch, policy, now)
        except PartialFailure as exc:
            _store_signals(store, exc.signals, now, result)
            reason = _error_text(exc)
            store.record_source(name, ok=False, now=now, error=reason, state=_persisted(exc.state),
                                cursor=_cursor_text(exc.state))
            result.health[name] = f"failed: {reason}"
            _log(f"{name}: partial failure: {reason}")
            continue
        except Exception as exc:  # isolate: one broken feed never stops the others
            reason = _error_text(exc)
            store.record_source(name, ok=False, now=now, error=reason)
            result.health[name] = f"failed: {reason}"
            _log(f"{name}: failed: {reason}")
            continue
        _store_signals(store, signals, now, result)
        for key, value in (new_state.get(KV) or {}).items():
            store.set_kv(key, value)
        persisted = _persisted(new_state)
        store.record_source(name, ok=True, now=now, state=persisted, cursor=_cursor_text(persisted))
        result.health[name] = "ok"
    return result


# --- accessors ---------------------------------------------------------------

def kev_cves(store) -> set[str]:
    return set(store.get_kv("kev_cves", []) or [])


def zero_wire_index(store) -> dict[str, list[dict]]:
    return dict(store.get_kv("zero_wire_index", {}) or {})


def php_active(store) -> dict:
    return dict(store.get_kv("php_active", {}) or {})


def node_index(store) -> list[dict]:
    return list(store.get_kv("node_index", []) or [])


def go_stable(store) -> list[str]:
    return list(store.get_kv("go_stable", []) or [])


def repo_advisories(store, repo: str) -> list[Signal]:
    prefix = f"{repo}#"
    return [sig for sig in store.all_signals("github_advisories") if sig.key.startswith(prefix)]
