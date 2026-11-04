"""Issuer-record resolution through OSV (https://osv.dev).

Only structured OSV/GitHub records reach actions: this module turns inventoried
packages into OSV record ids (querybatch), fetches and caches the records, and
extracts the facts actions key on (fixed versions per ecosystem/package, CVE
aliases, severity, independent issuer sources).
"""

from __future__ import annotations

import math
import re
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence
from urllib.parse import quote

from security_watch import config, net
from security_watch.model import Package

QUERYBATCH_URL = f"{config.OSV_API}/v1/querybatch"
VULN_URL = f"{config.OSV_API}/v1/vulns/"
BATCH_SIZE = 500
MAX_PAGES = 50

# OSV ecosystems (base name before the first ":").  A querybatch containing an
# unknown ecosystem fails as a whole ("invalid ecosystem", HTTP 400).
OSV_ECOSYSTEMS = frozenset({
    "AlmaLinux", "Alpine", "Android", "Bitnami", "CRAN", "Chainguard", "Debian", "GHC",
    "GIT", "Go", "Hackage", "Hex", "Linux", "Mageia", "Maven", "MinimOS", "NuGet",
    "OSS-Fuzz", "Packagist", "Photon OS", "Pub", "PyPI", "Red Hat", "Rocky Linux",
    "RubyGems", "SUSE", "SwiftURL", "Ubuntu", "Wolfi", "crates.io", "npm", "openSUSE",
    "openEuler", "Azure Linux", "Echo",
})

_CVE_RE = re.compile(r"(?:[A-Z]+-)?(CVE-(\d{4})-(\d{4,}))")
_SEVERITY_RANK = {"": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SEVERITY_WORDS = {
    "critical": "critical", "high": "high", "important": "high", "medium": "medium",
    "moderate": "medium", "low": "low", "negligible": "low",
}


def _log(message: str) -> None:
    print(f"security-watch: resolve: {message}", file=sys.stderr)


def is_osv_ecosystem(ecosystem: str) -> bool:
    return ecosystem.split(":", 1)[0] in OSV_ECOSYSTEMS


def normalize_name(ecosystem: str, name: str) -> str:
    """PEP 503 normalization for PyPI names; other ecosystems compare verbatim."""
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name


def query_version(ecosystem: str, version: str) -> str:
    """Version as OSV expects it: Go versions without a leading "go"/"v"."""
    if ecosystem == "Go":
        if version.startswith("go"):
            version = version[2:]
        if version.startswith("v"):
            version = version[1:]
    return version


def _query(pkg: Package) -> dict:
    return {"package": {"ecosystem": pkg.ecosystem, "name": normalize_name(pkg.ecosystem, pkg.name)},
            "version": query_version(pkg.ecosystem, pkg.version)}


def _vulns_of(result: Any) -> list[tuple[str, str]]:
    if not isinstance(result, dict):
        raise ValueError("querybatch result is not an object")
    out = []
    for item in result.get("vulns") or []:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            out.append((item["id"], str(item.get("modified") or "")))
    return out


def querybatch(packages: Sequence[Package], *, fetch) -> dict[Package, list[tuple[str, str]]]:
    """Map each OSV-ecosystem package to its (record id, modified) pairs.

    Runtime-ecosystem packages, packages without a version and ecosystems OSV does
    not know are skipped (absent from the result).  Raises on any OSV failure.
    """
    groups: dict[str, tuple[dict, list[Package]]] = {}
    for pkg in packages:
        if pkg.is_runtime or not pkg.version or not pkg.name or not is_osv_ecosystem(pkg.ecosystem):
            continue
        query = _query(pkg)
        key = f"{query['package']['ecosystem']}\0{query['package']['name']}\0{query['version']}"
        groups.setdefault(key, (query, []))[1].append(pkg)
    results: dict[Package, list[tuple[str, str]]] = {}
    items = list(groups.values())
    for start in range(0, len(items), BATCH_SIZE):
        chunk = items[start:start + BATCH_SIZE]
        data = net.post_json(QUERYBATCH_URL, {"queries": [q for q, _ in chunk]}, fetch=fetch)
        batch = data.get("results") if isinstance(data, dict) else None
        if not isinstance(batch, list) or len(batch) != len(chunk):
            raise ValueError("querybatch returned a malformed results list")
        for (query, pkgs), result in zip(chunk, batch):
            found = _vulns_of(result)
            token = result.get("next_page_token")
            pages = 0
            while token:
                pages += 1
                if pages > MAX_PAGES:
                    raise ValueError(f"querybatch paging exceeded {MAX_PAGES} pages")
                page = net.post_json(QUERYBATCH_URL, {"queries": [dict(query, page_token=token)]}, fetch=fetch)
                page_results = page.get("results") if isinstance(page, dict) else None
                if not isinstance(page_results, list) or len(page_results) != 1:
                    raise ValueError("querybatch page returned a malformed results list")
                found.extend(_vulns_of(page_results[0]))
                token = page_results[0].get("next_page_token")
            unique: dict[str, str] = {}
            for vuln_id, modified in found:
                if vuln_id not in unique or modified > unique[vuln_id]:
                    unique[vuln_id] = modified
            for pkg in pkgs:
                results[pkg] = list(unique.items())
    return results


def _parse_ts(value: Any) -> datetime | None:
    """OSV timestamps carry nanoseconds; trim to microseconds before parsing."""
    if not isinstance(value, str) or not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


TRIMMED_KEY = "_ecosystems"     # trimmed records: sorted list of kept affected ecosystems
RELATED_MAX = 50
DETAILS_MAX = 2000
_SPECIFIC_KEYS = ("priority", "urgency", "severity")
_EVENT_KEYS = ("introduced", "fixed", "last_affected", "limit")


def _specific(data: Any) -> dict | None:
    if not isinstance(data, dict):
        return None
    kept = {k: data[k] for k in _SPECIFIC_KEYS if k in data}
    return kept or None


def trim_record(record: dict, ecosystems: set[str] | None) -> dict:
    """Keep only what matching, fixed versions, CVEs, severity and summaries need.

    Drops every ``versions`` enumeration, GIT ranges, and (when ``ecosystems`` is
    given) affected entries of other ecosystems; the kept ecosystem set is recorded
    under ``TRIMMED_KEY`` so the cache can tell when a wider set is needed.
    """
    out: dict[str, Any] = {}
    for key in ("id", "modified", "published", "summary", "severity"):
        if key in record:
            out[key] = record[key]
    for key in ("aliases", "upstream"):
        if isinstance(record.get(key), list):
            out[key] = list(record[key])
    if isinstance(record.get("related"), list):
        out["related"] = list(record["related"][:RELATED_MAX])
    if isinstance(record.get("details"), str):
        out["details"] = record["details"][:DETAILS_MAX]
    db = _specific(record.get("database_specific"))
    if db:
        out["database_specific"] = db
    affected = []
    for entry in record.get("affected") or []:
        if not isinstance(entry, dict) or not isinstance(entry.get("package"), dict):
            continue
        package = entry["package"]
        if ecosystems is not None and package.get("ecosystem") not in ecosystems:
            continue
        kept: dict[str, Any] = {"package": {k: package[k] for k in ("ecosystem", "name") if k in package}}
        ranges = []
        for rng in entry.get("ranges") or []:
            if not isinstance(rng, dict) or rng.get("type") == "GIT":
                continue
            events = [{k: e[k] for k in _EVENT_KEYS if k in e}
                      for e in rng.get("events") or [] if isinstance(e, dict)]
            ranges.append({"type": rng.get("type"), "events": [e for e in events if e]})
        kept["ranges"] = ranges
        for field_name in ("ecosystem_specific", "database_specific"):
            specific = _specific(entry.get(field_name))
            if specific:
                kept[field_name] = specific
        affected.append(kept)
    out["affected"] = affected
    if ecosystems is not None:
        out[TRIMMED_KEY] = sorted(ecosystems)
    return out


def kept_ecosystems(record: dict) -> set[str] | None:
    """Ecosystems a cached record was trimmed to; None = all ecosystems kept."""
    kept = record.get(TRIMMED_KEY)
    return set(kept) if isinstance(kept, list) else None


def widen_ecosystems(cached: dict | None, wanted: set[str] | None) -> set[str] | None:
    """Ecosystems to keep when (re)caching: the union of what was cached and what is wanted."""
    if wanted is None:
        return None
    have = kept_ecosystems(cached) if cached is not None else set()
    return None if have is None else have | wanted


def cache_valid(cached: tuple[dict, datetime] | None, *, now, modified: str | None = None,
                max_age: timedelta = timedelta(days=7), keep_ecosystems: set[str] | None = None) -> bool:
    """Whether a cached (record, fetched_at) can be served.

    With ``modified`` (querybatch) the record stays valid until a newer ``modified``
    appears; without it the record expires after ``max_age``.  A record trimmed to
    fewer ecosystems than requested is never valid.
    """
    if cached is None:
        return False
    record, fetched_at = cached
    have = kept_ecosystems(record)
    if have is not None and (keep_ecosystems is None or not keep_ecosystems <= have):
        return False
    if modified:
        wanted, current = _parse_ts(modified), _parse_ts(record.get("modified"))
        if wanted is not None:
            return current is not None and wanted <= current
    return now - fetched_at <= max_age


def fetch_vuln(vuln_id: str, *, fetch) -> dict | None:
    """Network only (thread-safe, no Store access): the raw OSV record, 404 -> None."""
    try:
        record = net.get_json(VULN_URL + quote(vuln_id, safe=""), fetch=fetch)
    except net.FetchError as exc:
        if getattr(exc, "status", None) == 404:
            return None
        raise
    if not isinstance(record, dict) or record.get("id") != vuln_id:
        raise ValueError(f"OSV returned a malformed record for {vuln_id}")
    return record


def get_vuln(vuln_id: str, *, store, fetch, now, modified: str | None = None,
             max_age: timedelta = timedelta(days=7), keep_ecosystems: set[str] | None = None) -> dict | None:
    """One trimmed OSV record, served from the store cache while ``cache_valid``.

    404 -> None; other failures raise.  The stored/returned record is
    ``trim_record(raw, keep_ecosystems ∪ previously kept ecosystems)``.
    """
    cached = store.osv_get(vuln_id)
    if cache_valid(cached, now=now, modified=modified, max_age=max_age, keep_ecosystems=keep_ecosystems):
        return cached[0]
    raw = fetch_vuln(vuln_id, fetch=fetch)
    if raw is None:
        return None
    record = trim_record(raw, widen_ecosystems(cached[0] if cached else None, keep_ecosystems))
    store.osv_put(vuln_id, record, now)
    return record


def resolve_cve(cve: str, *, store, fetch, now) -> list[dict]:
    """Records that exist for a CVE: the CVE record and the Ubuntu/Debian/Alpine ones.

    A record that cannot be fetched is skipped (logged), so callers counting issuer
    sources only ever see fewer sources, never more.
    """
    records = []
    for vuln_id in (cve, f"UBUNTU-{cve}", f"DEBIAN-{cve}", f"ALPINE-{cve}"):
        try:
            record = get_vuln(vuln_id, store=store, fetch=fetch, now=now)
        except Exception as exc:  # noqa: BLE001 - one source failing must not hide the others
            _log(f"cannot fetch {vuln_id}: {exc}")
            continue
        if record is not None:
            records.append(record)
    return records


def _affected(record: dict, ecosystem: str, name: str) -> list[dict]:
    wanted = normalize_name(ecosystem, name)
    out = []
    for entry in record.get("affected") or []:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package") or {}
        if not isinstance(package, dict) or package.get("ecosystem") != ecosystem:
            continue
        if normalize_name(ecosystem, str(package.get("name") or "")) == wanted:
            out.append(entry)
    return out


def matches_package(record: dict, ecosystem: str, name: str) -> bool:
    return bool(_affected(record, ecosystem, name))


def fixed_versions(record: dict, ecosystem: str, name: str) -> list[str]:
    """All ``fixed`` events of ECOSYSTEM/SEMVER ranges for this package, in order."""
    out: list[str] = []
    for entry in _affected(record, ecosystem, name):
        for rng in entry.get("ranges") or []:
            if not isinstance(rng, dict) or rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            for event in rng.get("events") or []:
                fixed = event.get("fixed") if isinstance(event, dict) else None
                if isinstance(fixed, str) and fixed and fixed not in out:
                    out.append(fixed)
    return out


def cve_sort_key(cve: str) -> tuple[int, int]:
    match = _CVE_RE.fullmatch(cve)
    return (int(match.group(2)), int(match.group(3))) if match else (10**9, 10**12)


def cves_of(record: dict) -> list[str]:
    """CVE ids named by the record id, aliases, upstream and related (lowest first)."""
    names = [record.get("id")]
    for field in ("aliases", "upstream", "related"):
        names.extend(record.get(field) or [])
    cves = set()
    for name in names:
        if isinstance(name, str):
            match = _CVE_RE.fullmatch(name.strip())
            if match:
                cves.add(match.group(1))
    return sorted(cves, key=cve_sort_key)


def group_of(record: dict) -> str:
    cves = cves_of(record)
    return cves[0] if cves else str(record.get("id") or "")


def _roundup(value: float) -> float:
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


_CVSS3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def cvss3_base_score(vector: str) -> float | None:
    """CVSS v3.x base score from a vector string; None when it cannot be parsed."""
    if not vector.startswith("CVSS:3."):
        return None
    try:
        metrics = dict(part.split(":", 1) for part in vector.split("/")[1:])
        changed = metrics["S"] == "C"
        av = _CVSS3["AV"][metrics["AV"]]
        ac = _CVSS3["AC"][metrics["AC"]]
        ui = _CVSS3["UI"][metrics["UI"]]
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[metrics["PR"]]
        c, i, a = (_CVSS3["CIA"][metrics[k]] for k in ("C", "I", "A"))
        if metrics["S"] not in ("U", "C"):
            return None
    except (KeyError, ValueError):
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    total = 1.08 * (impact + exploitability) if changed else impact + exploitability
    return _roundup(min(total, 10.0))


def _score_severity(score: float) -> str:
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low" if score > 0 else ""


def _word_severity(value: Any) -> str:
    return _SEVERITY_WORDS.get(str(value or "").strip().lower(), "")


def _max_severity(values: list[str]) -> str:
    return max(values, key=lambda s: _SEVERITY_RANK.get(s, 0), default="")


def severity_of(record: dict) -> str:
    """Highest of: database_specific.severity, ecosystem_specific priority/urgency/
    severity, distro severity words, and CVSS v3 base scores (numeric or vector)."""
    found: list[str] = []
    db = record.get("database_specific")
    if isinstance(db, dict):
        found.append(_word_severity(db.get("severity")))
    for entry in record.get("affected") or []:
        if not isinstance(entry, dict):
            continue
        for field in ("ecosystem_specific", "database_specific"):
            data = entry.get(field)
            if isinstance(data, dict):
                for key in ("priority", "urgency", "severity"):
                    found.append(_word_severity(data.get(key)))
    for item in record.get("severity") or []:
        if not isinstance(item, dict):
            continue
        score = str(item.get("score") or "").strip()
        word = _word_severity(score)
        if word:
            found.append(word)
            continue
        try:
            found.append(_score_severity(float(score)))
            continue
        except ValueError:
            pass
        base = cvss3_base_score(score)
        if base is not None:
            found.append(_score_severity(base))
    return _max_severity(found)


def independent_sources_naming(records: Sequence[dict], ecosystem: str, name: str, version: str) -> int:
    """Distinct issuer databases (record id prefix: DEBIAN, UBUNTU, GHSA, GO, ...) whose
    fixed versions for this ecosystem/package include exactly ``version``."""
    prefixes = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        vuln_id = str(record.get("id") or "")
        if vuln_id and version in fixed_versions(record, ecosystem, name):
            prefixes.add(vuln_id.split("-", 1)[0].upper())
    return len(prefixes)


def _version_parts(version: str) -> tuple[tuple, tuple]:
    text = version.strip()
    if text.startswith("go"):
        text = text[2:]
    if text[:1] in ("v", "V"):
        text = text[1:]
    text = text.split("+", 1)[0]
    main, _, pre = text.partition("-")
    nums = []
    for part in main.split("."):
        digits = re.match(r"\d+", part)
        nums.append(int(digits.group(0)) if digits else 0)
    while len(nums) > 1 and nums[-1] == 0:
        nums.pop()
    pre_parts = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in re.split(r"[.-]", pre) if p) if pre else ()
    return tuple(nums), pre_parts


def version_lt(a: str, b: str) -> bool:
    """Dotted numeric comparison for runtime/semver-ish versions ("v1.2.3", "go1.27.3",
    "1.4.4-beta.1"); a pre-release sorts before its release."""
    (num_a, pre_a), (num_b, pre_b) = _version_parts(a), _version_parts(b)
    if num_a != num_b:
        return num_a < num_b
    if pre_a and not pre_b:
        return True
    if pre_b and not pre_a:
        return False
    return pre_a < pre_b


_RANGE_RE = re.compile(r"^(>=|<=|==|!=|>|<|=)?\s*(\S+)$")


def in_github_range(version: str, expr: str) -> bool:
    """Whether ``version`` satisfies a GitHub advisory range like ">= 1.0.21, < 1.4.4"."""
    clauses = [c.strip() for c in (expr or "").split(",") if c.strip()]
    if not clauses or not version:
        return False
    for clause in clauses:
        match = _RANGE_RE.match(clause)
        if not match:
            return False
        op, bound = match.group(1) or "=", match.group(2)
        lt, gt = version_lt(version, bound), version_lt(bound, version)
        ok = {
            ">=": not lt, ">": gt, "<=": not gt, "<": lt,
            "=": not lt and not gt, "==": not lt and not gt, "!=": lt or gt,
        }[op]
        if not ok:
            return False
    return True
