"""Source-backed Daily News contracts: URLs, dates, dedup, and tracking."""
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
    COOL_AFTER_DAYS,
    HTML_FETCH_HEADERS,
    DEVELOPING_STORY_RULES,
    DEVELOPMENT_HISTORY_CAP,
    FOLLOWUP_STORY_CAP,
    MIN_DEVELOPMENT_DAYS,
    PRUNE_AFTER_DAYS,
    REFERENCED_URLS_SCHEMA_VERSION,
    REFERENCED_URL_SKIP_HOSTS,
    REFERENCED_URL_SKIP_SEGMENTS,
    REFERENCED_URL_TIMEOUT,
    RESURFACE_CAP_DAYS,
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

def is_listing_url(url: str) -> bool:
    """True when a URL points at a section/date archive listing, not an article.

    Search results sometimes surface Guardian daily archives with a real
    article's title, e.g. https://www.theguardian.com/technology/2026/aug/18/all
    — fetching that page returns the section listing ("Technology | The
    Guardian") and the article URL never exists. Those listings must never be
    selected into Fresh or Ongoing or enter stories-in-flight (digest-quality
    audit 2026-08-21: world-digest ongoing entries on 08-20 and 08-21 were
    the same two Guardian .../all pages, canonicalizing to /us/technology).
    """
    path = urlsplit((url or "").strip()).path.rstrip("/")
    return path.lower().endswith("/all")

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
        for story in data.get("fresh", []) + data.get("ongoing", []):
            for url in _curated_story_urls(story):
                normalized = coverage_key(url)
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
    ongoing: list[dict],
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
    stories = fresh + ongoing
    if not stories:
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
            stories,
        ))
    data = {
        "schema_version": REFERENCED_URLS_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "stories": records,
    }
    atomic_write_json(output_path, data)
    total = sum(len(r["referenced_urls"]) for r in records)
    print(f"  [dedup] recorded {total} referenced link(s) across {len(stories)} "
          "selected story(s) for cross-topic same-event blocking")

def coverage_key(url: str) -> str:
    """Canonical dedup key: publisher canonicalization, then URL normalization."""
    return normalize_url(canonicalize_publisher_url(url or ""))

def _curated_story_urls(story: dict) -> list[str]:
    """URLs a curated story occupied: its displayed link and tracker identity."""
    return [story.get("url", ""), story.get("tracker_url", "")]

def load_recent_coverage_ledger(digests_root: Path, today: date, days: int) -> set[str]:
    """Collect canonical URLs any section covered in the previous `days` days.

    One ledger spans every category so a story cannot repeat under a different
    section the next day (2026-09-16/17: Salesforce AIforce ran in AI & Tech
    and then Agents). Per category and day it reads:
      1. <category>/<date>/06-curated.json — structured fresh+ongoing URLs
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
                    for story in data.get("fresh", []) + data.get("ongoing", []):
                        if isinstance(story, dict):
                            for url in _curated_story_urls(story):
                                add(url)
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

def consecutive_surfaced_days(digest_dir: Path, url: str, today: date) -> int:
    """How many consecutive prior digest days (ending yesterday) surfaced `url`.

    Same per-day sources as load_recent_coverage_ledger, limited to this
    section: the run dir's 06-curated.json (authoritative; an ongoing card
    matches by its displayed link or tracker identity) and the archived
    <date>.md fallback.
    """
    normalized = normalize_url(url)
    days = 0
    day = today - timedelta(days=1)
    while True:
        day_str = day.isoformat()
        appeared = False
        curated = digest_dir / day_str / "06-curated.json"
        if curated.exists():
            try:
                data = json.loads(curated.read_text())
                for story in data.get("fresh", []) + data.get("ongoing", []):
                    if normalized in {
                        normalize_url(candidate) for candidate in _curated_story_urls(story)
                    }:
                        appeared = True
                        break
            except (json.JSONDecodeError, ValueError):
                appeared = False
        else:
            md_file = digest_dir / f"{day_str}.md"
            if md_file.exists():
                appeared = any(
                    normalize_url(m.group(1)) == normalized
                    for m in re.finditer(
                        r"\[[^\]]*\]\((https?://[^)\s]+)\)", md_file.read_text()
                    )
                )
        if not appeared:
            break
        days += 1
        day -= timedelta(days=1)
    return days

def enforce_ongoing_resurface_cap(
    proposal: dict,
    stories_in_flight: dict,
    digest_dir: Path,
    today: date | None = None,
) -> tuple[list[str], list[dict]]:
    """Cool a qualified story after too many evidence-free resurfacings.

    Displaying a story never advances evidence-backed activity. The cap still
    bounds consecutive repetition before the five-day inactivity rule: after
    RESURFACE_CAP_DAYS appearances, the next selection is dropped and receives
    an administrative cooled status. Only a selected, source-linked material
    development resets the counter.
    """
    warnings: list[str] = []
    ops: list[dict] = []
    today = today or datetime.now(timezone.utc).date()
    story_by_url = {
        normalize_url(story.get("url", "")): story
        for story in stories_in_flight.get("stories", [])
    }
    # Evidence-backed update ops (validation already requires same-story
    # evidence) count as genuine development and reset the cap.
    evidenced_urls = {
        normalize_url(op.get("story_url", ""))
        for op in proposal.get("story_state_proposals", [])
        if op.get("operation") == "update" and op.get("evidence_candidate_ids")
    }
    kept: list[dict] = []
    for selection in proposal.get("selected_ongoing", []):
        url = normalize_url(selection.get("story_url", ""))
        prior_days = consecutive_surfaced_days(digest_dir, url, today)
        if prior_days >= RESURFACE_CAP_DAYS and url not in evidenced_urls:
            story = story_by_url.get(url)
            warnings.append(
                f"cooled recurring ongoing story surfaced {prior_days + 1} "
                "consecutive days without an evidence-backed development"
            )
            if story is not None:
                ops.append({
                    "operation": "update",
                    "story_url": story.get("url", ""),
                    "evidence_candidate_ids": [],
                    "latest_dev": story.get("latest_dev", ""),
                    "editorial_significance": story.get("editorial_significance", "medium"),
                    "status": "cooled",
                })
            continue
        kept.append(selection)
    if ops:
        proposal["selected_ongoing"] = kept
    return warnings, ops

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
    backstop against the editorial model or critic placing ongoing-window
    stories under Fresh (digest-quality audit 2026-08-12) and against
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

def story_development_dates(story: dict) -> set[str]:
    """Return distinct evidence-backed UTC dates for a tracked story.

    Legacy tracker entries have no evidence history. Treat only first_seen as
    evidence; last_updated may contain an old evidence-free display touch.
    """
    dates: set[str] = set()
    developments = story.get("developments", [])
    if isinstance(developments, list):
        for development in developments:
            if not isinstance(development, dict):
                continue
            parsed = parse_date(development.get("date"))
            if parsed is not None:
                dates.add(parsed.date().isoformat())
    if dates:
        return dates
    initial = parse_date(story.get("first_seen") or story.get("last_updated"))
    return {initial.date().isoformat()} if initial is not None else set()

def has_validated_high_significance(story: dict) -> bool:
    """True only when a high label carries accepted structured evidence."""
    return (
        story.get("editorial_significance") == "high"
        and isinstance(story.get("significance_evidence"), dict)
        and story.get("significance_validation", {}).get("status") == "accepted"
    )

def normalize_story_tracking(story: dict, today: date | None = None) -> dict:
    """Migrate one tracker entry to auditable evidence and significance fields."""
    if today is None:
        today = datetime.now(timezone.utc).date()
    normalize_editorial_significance(story)
    if story.get("url"):
        story["url"] = canonicalize_publisher_url(story["url"])
    if not parse_date(story.get("first_seen")):
        fallback = parse_date(story.get("last_updated"))
        story["first_seen"] = (
            fallback.date().isoformat() if fallback is not None else today.isoformat()
        )

    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    developments = story.get("developments", [])
    if isinstance(developments, list):
        for development in developments:
            if not isinstance(development, dict):
                continue
            parsed = parse_date(development.get("date"))
            url = str(development.get("url", "")).strip()
            if parsed is None:
                continue
            item = (parsed.date().isoformat(), url)
            if item in seen:
                continue
            seen.add(item)
            normalized.append({"date": item[0], "url": item[1]})

    if not normalized:
        normalized.append({
            "date": story["first_seen"],
            "url": str(story.get("url", "")).strip(),
        })
    normalized.sort(key=lambda item: (item["date"], item["url"]))
    story["developments"] = normalized[-DEVELOPMENT_HISTORY_CAP:]
    story["last_updated"] = max(item["date"] for item in normalized)
    return story

def is_developing_story(story: dict) -> bool:
    """True only for validated-high stories with evidence on multiple days."""
    return (
        has_validated_high_significance(story)
        and len(story_development_dates(story)) >= MIN_DEVELOPMENT_DAYS
    )

def tracker_display_source(story: dict) -> dict | None:
    """Return the headline, link, and date that supplied the latest summary.

    A Developing and Ongoing card must show the source of its newest summary
    (2026-09-21/22: "House approves Russia sanctions bill, sending it to
    Trump" sat above a summary saying the bill had been signed). Evidence-backed
    updates record `latest_source`; it is valid only while it matches a
    development on the newest evidence date. A record whose newest evidence is
    the tracked article itself displays that article. Anything else cannot
    prove which source supplied its summary and returns None (withheld).
    """
    dated = [
        (parsed.date().isoformat(), coverage_key(development.get("url", "")))
        for development in story.get("developments", [])
        if isinstance(development, dict)
        and (parsed := parse_date(development.get("date"))) is not None
    ]
    root = coverage_key(story.get("url", ""))
    if dated:
        newest = max(day for day, _ in dated)
        newest_urls = {url for day, url in dated if day == newest}
    else:
        newest_urls = {root}
    source = story.get("latest_source")
    if (
        isinstance(source, dict)
        and str(source.get("title", "")).strip()
        and coverage_key(source.get("url", "")) in newest_urls
    ):
        return {
            "title": str(source["title"]).strip(),
            "url": str(source.get("url", "")).strip(),
            "date": str(source.get("date", "")).strip(),
        }
    if root and newest_urls == {root} and str(story.get("title", "")).strip():
        return {"title": str(story["title"]).strip(), "url": story.get("url", ""), "date": ""}
    return None

def recover_latest_source(story: dict, digest_dir: Path) -> bool:
    """Backfill `latest_source` for a legacy record from its evidence run.

    Records written before `latest_source` existed still name the article
    behind their newest evidence in `developments`. When exactly one article
    supplied that date's evidence and the section's run for that date selected
    it under Fresh, the run's curated entry proves the headline, link, and
    publication date. Anything less stays unproven. Returns True on recovery.
    """
    if tracker_display_source(story) is not None:
        return False
    dated: dict[str, set[str]] = {}
    for development in story.get("developments", []):
        if not isinstance(development, dict):
            continue
        parsed = parse_date(development.get("date"))
        url = str(development.get("url", "")).strip()
        if parsed is not None and url:
            dated.setdefault(parsed.date().isoformat(), set()).add(url)
    if not dated:
        return False
    newest = max(dated)
    if len({coverage_key(url) for url in dated[newest]}) != 1:
        return False
    evidence_key = coverage_key(next(iter(dated[newest])))
    try:
        curated = json.loads((digest_dir / newest / "06-curated.json").read_text())
        fresh = curated.get("fresh", [])
    except (OSError, json.JSONDecodeError, ValueError, AttributeError):
        return False
    for entry in fresh if isinstance(fresh, list) else []:
        if (
            isinstance(entry, dict)
            and coverage_key(entry.get("url", "")) == evidence_key
            and str(entry.get("title", "")).strip()
        ):
            published = candidate_fresh_date(entry, date.fromisoformat(newest))
            story["latest_source"] = {
                "title": str(entry["title"]).strip(),
                "url": str(entry.get("url", "")).strip(),
                "date": published.date().isoformat() if published is not None else "",
            }
            return True
    return False

def build_developing_followup_angle(
    stories_in_flight: dict | None,
    today: date | None = None,
) -> dict | None:
    """Build one bounded research angle for material tracker follow-ups."""
    if not stories_in_flight:
        return None
    if today is None:
        today = datetime.now(timezone.utc).date()
    tracked = [
        story for story in stories_in_flight.get("stories", [])
        if story.get("status", "active") in ("active", "cooled")
        and has_validated_high_significance(story)
        and story.get("first_seen") != today.isoformat()
        and not is_listing_url(story.get("url", ""))
        and not is_asset_cdn_url(story.get("url", ""))
    ]
    tracked = sorted(
        tracked, key=lambda story: story.get("last_updated", ""), reverse=True
    )[:FOLLOWUP_STORY_CAP]
    if not tracked:
        return None

    context = [{
        "title": story.get("title", ""),
        "story_url": story.get("url", ""),
        "latest_confirmed_development": story.get("latest_dev", ""),
        "first_seen": story.get("first_seen", ""),
        "last_evidence_date": story.get("last_updated", ""),
        "status": story.get("status", "active"),
    } for story in tracked]
    prompt = (
        "Search specifically for material developments from the last 24 hours in "
        "the high-significance tracked stories below. Search each story; zero results "
        "is a valid and preferable answer when nothing materially changed.\n\n"
        f"{DEVELOPING_STORY_RULES}\n"
        "Return only articles that report a new material fact after the supplied "
        "last_evidence_date. Exclude recaps, explainers, opinions, reactions without "
        "new action, and articles connected only by a broad theme. Each returned "
        "finding must include `develops_story_url`, copied exactly from the matching "
        "`story_url` below. Never invent a relationship or URL.\n\n"
        f"Tracked stories:\n{json.dumps(context, indent=2)}"
    )
    return {"id": "developing-followups", "prompt": prompt, "optional": True}
