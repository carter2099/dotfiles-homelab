"""Source-backed Daily News contracts: URLs, dates, and dedup."""
from __future__ import annotations

import hashlib
import json
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit

import requests
from workflow_state import atomic_write_json

from .attention import canonicalize_publisher_url, normalize_editorial_significance
from .catalog import (
    CROSS_DAY_DEDUP_DAYS,
    HTML_FETCH_HEADERS,
    REFERENCED_URLS_SCHEMA_VERSION,
    REFERENCED_URL_SKIP_HOSTS,
    REFERENCED_URL_SKIP_SEGMENTS,
    REFERENCED_URL_TIMEOUT,
    TOPICS,
)

_TRACKING_QUERY_KEYS = {
    "fbclid", "gclid", "mc_cid", "mc_eid", "ref_src",
}

def normalize_url(url: str) -> str:
    """Return a stable dedup/cache key while preserving case-sensitive URL paths."""
    raw = (url or "").strip()
    if not raw:
        return ""
    candidate = raw if "://" in raw else f"https://{raw}"
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return raw.lower().rstrip("/")
    host = (parts.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    if not host:
        return raw.lower().rstrip("/")
    try:
        port = parts.port
    except ValueError:
        return raw.lower().rstrip("/")
    if port and not ((parts.scheme == "http" and port == 80)
                     or (parts.scheme == "https" and port == 443)):
        host = f"{host}:{port}"
    path = parts.path.rstrip("/")
    query = [
        (key, value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if not key.lower().startswith("utm_")
        and key.lower() not in _TRACKING_QUERY_KEYS
    ]
    query.sort()
    suffix = f"?{urlencode(query, doseq=True)}" if query else ""
    return f"{host}{path}{suffix}"

# Index-page markers derived from September 2026 research URLs. A path segment
# naming an archive, a `month`/`page/<n>` pagination segment, a month/page
# index query, or a path that ends at a bare date is a listing of many
# articles, never one article (digest-quality audit 2026-09-29: ai-hardware
# 09-28 published https://www.techpowerup.com/news-archive?month=0927 as a
# Fresh story). `?p=` is deliberately absent: WordPress uses it for single
# post IDs (gematsu.com/?p=1035212).
_LISTING_PATH_SEGMENTS = frozenset({"archive", "archives", "news-archive", "news-archives"})
_LISTING_QUERY_KEYS = frozenset({"month", "year", "page", "paged"})
_YEAR_SEGMENT = re.compile(r"(?:19|20)\d{2}")
_MONTH_SEGMENT = re.compile(
    r"0?[1-9]|1[0-2]|jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec"
)
_DAY_SEGMENT = re.compile(r"0?[1-9]|[12]\d|3[01]")

def _ends_at_date(segments: list[str]) -> bool:
    """True when the path ends with year/month[/day] and no article slug."""
    for tail in (3, 2):
        if len(segments) < tail:
            continue
        date_parts = segments[-tail:]
        if (
            _YEAR_SEGMENT.fullmatch(date_parts[0])
            and _MONTH_SEGMENT.fullmatch(date_parts[1])
            and (tail == 2 or _DAY_SEGMENT.fullmatch(date_parts[2]))
        ):
            return True
    return False

def is_listing_url(url: str) -> bool:
    """True when a URL points at a section/date archive listing, not an article.

    Search results sometimes surface Guardian daily archives with a real
    article's title, e.g. https://www.theguardian.com/technology/2026/aug/18/all
    — fetching that page returns the section listing ("Technology | The
    Guardian") and the article URL never exists. Those listings must never be
    selected into Fresh (digest-quality audit 2026-08-21: world-digest entries
    on 08-20 and 08-21 were the same two Guardian .../all pages, canonicalizing
    to /us/technology).
    Archive indexes (`/news-archive?month=0927`), pagination
    (`?page=3`, `/page/2`, `/changelog/month/09-2026`), and bare-date paths
    (`/2026/09/28`) are listings too.
    """
    try:
        parts = urlsplit((url or "").strip())
    except ValueError:
        return False
    segments = [s.lower() for s in parts.path.split("/") if s]
    if segments and segments[-1] == "all":
        return True
    if any(segment in _LISTING_PATH_SEGMENTS for segment in segments):
        return True
    if "month" in segments[:-1]:
        return True
    if any(
        segment == "page" and following.isdigit()
        for segment, following in zip(segments, segments[1:])
    ):
        return True
    if any(
        key.lower() in _LISTING_QUERY_KEYS
        for key, _ in parse_qsl(parts.query, keep_blank_values=True)
    ):
        return True
    return _ends_at_date(segments)

_ASSET_CDN_URL_HOSTS = {
    "assets.theregister.com",
}

def is_asset_cdn_url(url: str) -> bool:
    """True when a URL is hosted on a publisher's sibling asset CDN.

    Such hosts serve images/static assets, never articles, so a link to them
    is dead even though the host resolves. Candidate articles must resolve on
    the publisher's article host (e.g. www.theregister.com).
    """
    raw = (url or "").strip()
    if not raw:
        return False
    try:
        host = (urlsplit(raw).hostname or "").lower()
    except ValueError:
        return False
    return host in _ASSET_CDN_URL_HOSTS or any(
        host.endswith(f".{cdn}") for cdn in _ASSET_CDN_URL_HOSTS
    )

# Hard-paywalled publishers the Phase 4 reader cannot open. Phase 3 swaps each
# such URL for another research finding on the same story, or drops the story,
# so none of them consumes a fetch slot. Add a domain only on fetch-failure
# evidence from 04-fetch-summaries.json that names a paywall or wall-level
# block (September 2026: washingtonpost.com 11/12 failed with timeouts or a
# metered page; theinformation.com 4/5 returned HTTP 403 paywall). Keep
# bot-blocked outlets that mostly fetch (apnews.com 9/67, arstechnica.com
# 6/13, both intermittent 403s) out of this set.
HARD_PAYWALL_DOMAINS = frozenset({
    "theinformation.com",
    "washingtonpost.com",
})

def hard_paywall_domain(url: str) -> str | None:
    """Return the hard-paywall domain serving ``url`` (any subdomain), else None."""
    raw = (url or "").strip()
    if not raw:
        return None
    try:
        host = (urlsplit(raw if "://" in raw else f"https://{raw}").hostname or "").lower()
    except ValueError:
        return None
    for domain in HARD_PAYWALL_DOMAINS:
        if host == domain or host.endswith(f".{domain}"):
            return domain
    return None

def load_cross_topic_urls(
    topic: dict,
    run_dir: Path,
    *,
    digests_dir: Path | None = None,
) -> set[str]:
    """Load URLs already selected by earlier topics for this run date."""
    blocked: set[str] = set()
    if digests_dir is None:
        try:
            from . import runtime
            root = (
                runtime.TEST_ROOT
                if runtime.TEST_MODE and runtime.TEST_ROOT is not None
                else runtime.DIGESTS_DIR
            )
        except ImportError:  # pragma: no cover - direct utility use
            root = Path.home() / "digests"
    else:
        root = digests_dir
    current_category = topic["category"]
    for config in TOPICS.values():
        if config["category"] == current_category:
            continue
        curated_path = root / config["category"] / run_dir.name / "06-curated.json"
        try:
            data = json.loads(curated_path.read_text())
        except (FileNotFoundError, json.JSONDecodeError, TypeError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        for story in data.get("fresh", []):
            normalized = coverage_key(story.get("url", ""))
            if normalized:
                blocked.add(normalized)
        # Same-event dedup: later topics also block the canonical/related links
        # recorded from earlier topics' selected stories, so the same event
        # under a different URL is not curated twice (digest-quality audit
        # 2026-08-26). Only schema-version-matched records merge.
        referenced_path = (
            root / config["category"] / run_dir.name / "referenced-urls.json"
        )
        try:
            ref_data = json.loads(referenced_path.read_text())
            if ref_data.get("schema_version") == REFERENCED_URLS_SCHEMA_VERSION:
                for entry in ref_data.get("stories", []):
                    for url in entry.get("referenced_urls", []):
                        normalized = coverage_key(url)
                        if normalized:
                            blocked.add(normalized)
        except (FileNotFoundError, json.JSONDecodeError, TypeError, ValueError):
            pass
    return blocked

class _HrefCollector(HTMLParser):
    """Collect the hrefs of <a> tags from one article page (dedup record)."""

    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        for key, value in attrs:
            if key == "href" and value:
                self.hrefs.append(value)

def collect_referenced_urls(page_url: str) -> list[str]:
    """Best-effort fetch of one article page; return normalized outbound links.

    Feeds the cross-topic same-event dedup record. Conservative filters keep
    only plausible article/canonical-source links: same-host navigation and
    related-story links, social/utility hosts, and obvious non-article paths
    never enter the record. Never raises — link collection is auxiliary to
    curation and must not fail a topic run.
    """
    try:
        resp = requests.get(
            page_url, headers=HTML_FETCH_HEADERS, timeout=REFERENCED_URL_TIMEOUT
        )
        resp.raise_for_status()
    except requests.RequestException:
        return []
    if len(resp.content) > 2_000_000 or not resp.text:
        return []
    parser = _HrefCollector()
    try:
        parser.feed(resp.text)
    except Exception:
        return []
    page_host = (urlsplit(page_url).hostname or "").lower()
    if page_host.startswith("www."):
        page_host = page_host[4:]
    seen: set[str] = set()
    out: list[str] = []
    for href in parser.hrefs:
        try:
            absolute = urljoin(page_url, href.strip())
        except ValueError:
            continue
        parts = urlsplit(absolute)
        if parts.scheme not in ("http", "https"):
            continue
        host = (parts.hostname or "").lower()
        if host.startswith("www."):
            host = host[4:]
        if not host or host == page_host:
            continue
        if host in REFERENCED_URL_SKIP_HOSTS:
            continue
        if is_listing_url(absolute) or is_asset_cdn_url(absolute):
            continue
        segments = [s for s in parts.path.strip("/").split("/") if s]
        if not segments or not any(re.search(r"[a-zA-Z]", s) for s in segments):
            continue
        if any(s.lower() in REFERENCED_URL_SKIP_SEGMENTS for s in segments):
            continue
        normalized = normalize_url(absolute)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        out.append(normalized)
        if len(out) >= 20:
            break
    return out

def record_referenced_urls(
    topic: dict,
    fresh: list[dict],
    run_dir: Path,
) -> None:
    """Record canonical/related links from each selected story for later topics.

    Written to <run_dir>/referenced-urls.json (REFERENCED_URLS_SCHEMA_VERSION);
    load_cross_topic_urls merges these into later topics' blocked set so the
    same event under a different URL is not curated twice (digest-quality audit
    2026-08-26: the OpenAI Jalapeño announcement ran in ai-tech via TechCrunch
    and in ai-hardware via the OpenAI page). Best-effort: a failed fetch simply
    contributes no links and never fails the run.
    """
    output_path = run_dir / "referenced-urls.json"
    if not fresh:
        try:
            output_path.unlink()
        except OSError:
            pass
        return
    with ThreadPoolExecutor(max_workers=2) as pool:
        records = list(pool.map(
            lambda s: {
                "url": s.get("url", ""),
                "referenced_urls": collect_referenced_urls(s.get("url", "")),
            },
            fresh,
        ))
    data = {
        "schema_version": REFERENCED_URLS_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "stories": records,
    }
    atomic_write_json(output_path, data)
    total = sum(len(r["referenced_urls"]) for r in records)
    print(f"  [dedup] recorded {total} referenced link(s) across {len(fresh)} "
          "selected story(s) for cross-topic same-event blocking")

def coverage_key(url: str) -> str:
    """Canonical dedup key: publisher canonicalization, then URL normalization."""
    return normalize_url(canonicalize_publisher_url(url or ""))

def load_recent_coverage_ledger(digests_root: Path, today: date, days: int) -> set[str]:
    """Collect canonical URLs any section covered in the previous `days` days.

    One ledger spans every category so a story cannot repeat under a different
    section the next day (2026-09-16/17: Salesforce AIforce ran in AI & Tech
    and then Agents). Per category and day it reads:
      1. <category>/<date>/06-curated.json — structured fresh URLs
         (authoritative; run dirs are auto-cleaned after 14 days);
      2. <category>/<date>/referenced-urls.json — canonical/source links the
         covered articles cited, so the same event under another URL is blocked;
      3. <category>/<date>.md — archived Phase 9 Markdown links, only when the
         structured curated artifact is missing or unreadable.
    """
    covered: set[str] = set()

    def add(url: str) -> None:
        key = coverage_key(url)
        if key:
            covered.add(key)

    for config in TOPICS.values():
        digest_dir = digests_root / config["category"]
        for offset in range(1, days + 1):
            day_str = (today - timedelta(days=offset)).isoformat()
            structured = False
            curated = digest_dir / day_str / "06-curated.json"
            try:
                data = json.loads(curated.read_text())
                if isinstance(data, dict):
                    for story in data.get("fresh", []):
                        if isinstance(story, dict):
                            add(story.get("url", ""))
                    structured = True
            except (FileNotFoundError, json.JSONDecodeError, TypeError, ValueError):
                pass
            referenced = digest_dir / day_str / "referenced-urls.json"
            try:
                ref_data = json.loads(referenced.read_text())
                if ref_data.get("schema_version") == REFERENCED_URLS_SCHEMA_VERSION:
                    for entry in ref_data.get("stories", []):
                        add(entry.get("url", ""))
                        for url in entry.get("referenced_urls", []):
                            add(url)
            except (FileNotFoundError, json.JSONDecodeError, TypeError, ValueError, AttributeError):
                pass
            if structured:
                continue
            md_file = digest_dir / f"{day_str}.md"
            if md_file.exists():
                for match in re.finditer(r"\[[^\]]*\]\((https?://[^)\s]+)\)", md_file.read_text()):
                    add(match.group(1))
    return covered

def parse_date(date_str: str | None) -> datetime | None:
    """Parse a date string into a UTC-aware datetime. Returns None on failure."""
    if not date_str or not isinstance(date_str, str):
        return None
    for fmt in ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S", "%B %d, %Y", "%b %d, %Y"]:
        try:
            dt = datetime.strptime(date_str.strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None

def candidate_fresh_date(candidate: dict, today: date | None = None) -> datetime | None:
    """Return the best publication date for a candidate.

    Prefers Phase 4's independently confirmed date; falls back to Phase 1's
    published date. A date_confirmed that is in the future (e.g. an event or
    conference date pulled from the article rather than its publication date)
    is not a valid publication date, so it falls back to date_published
    (digest-quality audit 2026-08-17: ai-hardware dropped the fresh 08-17 Hot
    Chips preview because date_confirmed was the 08-24 conference start date).
    None when neither parses (Phase 5 passed the story through for LLM judgment
    rather than dropping it).
    """
    if today is None:
        today = datetime.now(timezone.utc).date()
    confirmed = parse_date((candidate.get("date_confirmed") or "").strip())
    if confirmed is not None and confirmed.date() <= today:
        return confirmed
    return parse_date((candidate.get("date_published") or "").strip())

def is_fresh_eligible(candidate: dict, yesterday: date, today: date | None = None) -> bool:
    """True when a candidate may legitimately appear under "Fresh — Last 24 Hours".

    A candidate with a parseable publication date is fresh-eligible only when
    that date is within the last 24h (>= yesterday) and not in the future
    (<= today). A candidate with no parseable date is kept, mirroring Phase 5's
    pass-through for undetermined dates. This deterministic gate is the
    backstop against the editorial model or critic placing older stories
    under Fresh (digest-quality audit 2026-08-12) and against
    future-dated candidates shipping under Fresh (digest-quality audit
    2026-08-14: a 2026-10-15-dated story rendered under "Fresh — Last 24 Hours"
    in the 2026-08-12 ai-tech digest).
    """
    if today is None:
        today = datetime.now(timezone.utc).date()
    fresh_date = candidate_fresh_date(candidate, today)
    if fresh_date is None:
        return True
    return yesterday <= fresh_date.date() <= today
