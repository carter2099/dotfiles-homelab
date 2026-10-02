#!/usr/bin/env python3
"""Build and publish the static daily news site from curated digest artifacts."""

from __future__ import annotations

import argparse
import html
import hashlib
import os
import json
import re
import shutil
import sqlite3
import uuid
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from html.parser import HTMLParser
from itertools import groupby
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit

from daily_news.catalog import RANKING_SCHEMA_VERSION, TOPICS
from daily_news.copy import fallback_standfirst, validate_standfirst
from daily_news.contracts import coverage_key, is_fresh_eligible
from daily_news.runtime import DIGESTS_DIR
from daily_news.attention import (
    EDITORIAL_POINTS,
    canonicalize_publisher_url,
    normalize_editorial_significance,
    priority_sort_key,
)
from send_digest import send as smtp_send
from workflow_state import WorkflowState

HOME = Path.home()
NEWS_DIR = DIGESTS_DIR / "news"
PUBLICATIONS_DIR = NEWS_DIR / "publications"
RELEASES_DIR = NEWS_DIR / "releases"
CURRENT_SITE = NEWS_DIR / "current"
ASSET_DIR = HOME / "news" / "assets"
BASE_URL = "https://news.carter2099.com"
SUMMARY_RECIPIENT = "carter2099@pm.me"
TOPIC_ORDER = tuple(TOPICS)
PUBLICATION_SCHEMA_VERSION = 2
FRONT_PAGE_MAX_STORIES = 10
FRONT_PAGE_SECONDARY_THRESHOLD = 65.0
# Same-event matching on the front page (see _same_event).
EVENT_CORPUS_DAYS = 30
EVENT_MIN_TOKEN_OVERLAP = 0.25
# Two shared words ("Trump", "meet") describe a topic, not one event.
EVENT_MIN_SHARED_TOKENS = 3
# Workflow state shipped in a13e452 (2026-09-01 20:30 UTC); every run directory
# from the next edition onward must carry validated state. Only older run
# directories may use the raw legacy import path.
WORKFLOW_STATE_REQUIRED_FROM = "2026-09-02"


class PublicationStateError(RuntimeError):
    """A stateful run's publication cannot be proven from its workflow state."""


class LegacyDigestParser(HTMLParser):
    """Extract the stable Fresh story fields from the historical email HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        # None before the first section heading, then "fresh" or "skipped".
        self.section: str | None = None
        self.title = ""
        self.standfirst = ""
        self.fresh: list[dict[str, str]] = []
        self._h1: list[str] | None = None
        self._h2: list[str] | None = None
        self._p: list[str] | None = None
        self._p_had_story_link = False
        self._a: list[str] | None = None
        self._a_href = ""
        self._span: list[str] | None = None
        self._current_story: dict[str, str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = dict(attrs)
        if tag == "h1":
            self._h1 = []
        elif tag == "h2":
            self._h2 = []
        elif tag == "p":
            self._p = []
            self._p_had_story_link = False
        elif tag == "a" and self.section == "fresh":
            self._a = []
            self._a_href = attrs_dict.get("href") or ""
            self._p_had_story_link = True
        elif tag == "span" and self._current_story is not None:
            self._span = []

    def handle_data(self, data: str) -> None:
        for target in (self._h1, self._h2, self._p, self._a, self._span):
            if target is not None:
                target.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "h1" and self._h1 is not None:
            self.title = _clean_text("".join(self._h1))
            self._h1 = None
        elif tag == "h2" and self._h2 is not None:
            heading = _clean_text("".join(self._h2)).casefold()
            if "fresh" in heading:
                self.section = "fresh"
            elif "ongoing" in heading or "recent" in heading or "relevant" in heading:
                # Historical multi-day sections are not migrated.
                self.section = "skipped"
                self._current_story = None
            self._h2 = None
        elif tag == "a" and self._a is not None and self.section == "fresh":
            story = {
                "title": _clean_text("".join(self._a)),
                "url": self._a_href,
            }
            host = urlsplit(self._a_href).hostname
            if host:
                story["source_domain"] = host.removeprefix("www.")
            self.fresh.append(story)
            self._current_story = story
            self._a = None
            self._a_href = ""
        elif tag == "span" and self._span is not None:
            if self._current_story is not None:
                category = _clean_text("".join(self._span)).lstrip("· ")
                if category:
                    self._current_story["category"] = category
            self._span = None
        elif tag == "p" and self._p is not None:
            text = _clean_text("".join(self._p))
            if self.section is None:
                if self.title and len(text) >= 40 and "carter2099.com" not in text:
                    self.standfirst = self.standfirst or text
            elif (
                self._current_story is not None
                and not self._p_had_story_link
                and text
                and not self._current_story.get("summary")
            ):
                self._current_story["summary"] = text
            self._p = None
            self._p_had_story_link = False


def _clean_text(value: Any) -> str:
    return " ".join(str(value or "").split())


def _valid_date(value: str) -> bool:
    try:
        date.fromisoformat(value)
        return bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", value))
    except ValueError:
        return False


def _safe_url(value: Any) -> str:
    candidate = _clean_text(value)
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return candidate


def _public_story(story: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_editorial_significance(dict(story))
    result: dict[str, Any] = {}
    for key in (
        "title", "source_domain", "date_published", "date_confirmed", "summary",
        "category", "editorial_significance", "author", "event",
        "priority_explanation",
    ):
        value = _clean_text(normalized.get(key))
        if value:
            result[key] = value
    for key in ("significance_evidence", "significance_validation"):
        if isinstance(normalized.get(key), dict):
            result[key] = dict(normalized[key])
    url = _safe_url(canonicalize_publisher_url(normalized.get("url")))
    if url:
        result["url"] = url
    try:
        result["priority_score"] = round(float(
            normalized.get(
                "priority_score",
                EDITORIAL_POINTS[normalized["editorial_significance"]],
            )
        ), 1)
    except (TypeError, ValueError):
        result["priority_score"] = EDITORIAL_POINTS[normalized["editorial_significance"]]
    attention = normalized.get("attention")
    if isinstance(attention, dict):
        result["attention"] = {
            key: attention.get(key)
            for key in (
                "schema_version", "provider", "status", "attention_now",
                "digest_prominence", "confidence", "age_bucket",
                "normalized_signals", "evidence",
            )
            if attention.get(key) is not None
        }
    return result


def _topic_for_slug(slug: str) -> tuple[str, dict[str, Any]]:
    for key in TOPIC_ORDER:
        topic = TOPICS[key]
        if topic["web_slug"] == slug:
            return key, topic
    raise KeyError(slug)


def _empty_publication(topic: dict[str, Any], issue_date: str) -> dict[str, Any]:
    return {
        "schema_version": PUBLICATION_SCHEMA_VERSION,
        "ranking_schema_version": RANKING_SCHEMA_VERSION,
        "date": issue_date,
        "slug": topic["web_slug"],
        "title": topic["web_title"],
        "source_category": topic["category"],
        "status": "unavailable",
        "notice": "",
        "standfirst": "No section was published for this category on this date.",
        "fresh": [],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _normalize_publication(
    raw: dict[str, Any], topic: dict[str, Any], issue_date: str,
) -> dict[str, Any]:
    publication = _empty_publication(topic, issue_date)
    publication.update({
        "ranking_schema_version": (
            raw.get("ranking_schema_version")
            if isinstance(raw.get("ranking_schema_version"), int)
            else 1
        ),
        "status": _clean_text(raw.get("status")) or "published",
        "notice": _clean_text(raw.get("notice")),
        "standfirst": _clean_text(raw.get("standfirst") or raw.get("intro")),
        "generated_at": _clean_text(raw.get("generated_at"))
        or datetime.now(timezone.utc).isoformat(),
    })
    publication["fresh"] = [
        item for item in (
            _public_story(story) for story in raw.get("fresh", []) if isinstance(story, dict)
        ) if item.get("title") and item.get("url")
    ]
    publication["fresh"].sort(key=priority_sort_key, reverse=True)
    valid_standfirst, _ = validate_standfirst(
        publication["standfirst"], publication["fresh"],
    )
    if not valid_standfirst:
        publication["standfirst"] = fallback_standfirst(publication["fresh"])
    return publication


def _is_current_publication(
    raw: object,
    topic: dict[str, Any],
    issue_date: str,
) -> bool:
    return (
        isinstance(raw, dict)
        and raw.get("schema_version") == PUBLICATION_SCHEMA_VERSION
        and raw.get("ranking_schema_version") == RANKING_SCHEMA_VERSION
        and raw.get("date") == issue_date
        and raw.get("slug") == topic["web_slug"]
        and raw.get("source_category") == topic["category"]
        and isinstance(raw.get("fresh"), list)
    )


def _within_edition_window(
    raw: dict[str, Any], topic: dict[str, Any], issue_date: str,
) -> dict[str, Any]:
    """Drop Fresh stories whose best date is outside the edition's 24h window.

    Curation enforces the same gate; publishing rechecks it against the
    edition date so a stale or future-dated story can never ship as Fresh.
    """
    fresh = raw.get("fresh")
    if not isinstance(fresh, list):
        return raw
    edition = date.fromisoformat(issue_date)
    yesterday = edition - timedelta(days=1)
    kept: list[Any] = []
    for story in fresh:
        if isinstance(story, dict) and not is_fresh_eligible(story, yesterday, edition):
            print(
                f"[publish] {topic['web_slug']} {issue_date}: dropped Fresh story outside "
                f"the edition window: {_clean_text(story.get('title'))[:120]}"
            )
            continue
        kept.append(story)
    return {**raw, "fresh": kept}


def _publication_from_run(
    topic: dict[str, Any], issue_date: str, run_dir: Path,
) -> dict[str, Any] | None:
    """Load a run's publication; stateful runs raise instead of falling back."""
    publication_path = run_dir / "publication.json"
    configured_db = os.environ.get("WORKFLOW_STATE_DB")
    state_db = Path(configured_db) if configured_db else run_dir / "workflow-state.sqlite3"
    if state_db.exists():
        try:
            state = WorkflowState(
                run_dir, "daily-news", run_id=run_dir.name, db_path=state_db
            )
            record = state.phase_record("archive")
        except sqlite3.Error as error:
            raise PublicationStateError(f"workflow state is unreadable: {error}") from error
        if record is None:
            raise PublicationStateError("archive phase has no workflow-state record")
        if record.get("status") != "succeeded":
            raise PublicationStateError(
                f"archive phase status is {record.get('status')!r}, not 'succeeded'"
            )
        if (
            int(record.get("schema_version", 0)) != PUBLICATION_SCHEMA_VERSION
            or not record.get("resume_valid")
            or Path(str(record.get("artifact_path", ""))).resolve(strict=False)
            != publication_path.resolve(strict=False)
        ):
            raise PublicationStateError(
                "archive record schema/path/validity does not match publication.json"
            )
        try:
            payload = publication_path.read_bytes()
        except OSError as error:
            raise PublicationStateError(f"publication.json is unreadable: {error}") from error
        if hashlib.sha256(payload).hexdigest() != record.get("artifact_hash"):
            raise PublicationStateError("publication.json does not match its recorded hash")
        try:
            raw = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PublicationStateError(f"publication.json is not valid JSON: {error}") from error
        if not _is_current_publication(raw, topic, issue_date):
            raise PublicationStateError(
                "publication.json is not a current-schema publication for this date/section"
            )
        return _normalize_publication(
            _within_edition_window(raw, topic, issue_date), topic, issue_date
        )
    if issue_date >= WORKFLOW_STATE_REQUIRED_FROM:
        raise PublicationStateError(
            "workflow state is missing for a run created after workflow-state adoption"
        )

    # Only runs created before workflow-state adoption may use legacy files.
    if publication_path.exists():
        try:
            raw = json.loads(publication_path.read_text())
            if isinstance(raw, dict):
                return _normalize_publication(
                    _within_edition_window(raw, topic, issue_date), topic, issue_date
                )
        except (json.JSONDecodeError, OSError):
            pass
    curated_path = run_dir / "06-curated.json"
    if not curated_path.exists():
        return None
    try:
        curated = json.loads(curated_path.read_text())
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(curated, dict):
        return None

    standfirst = ""
    standfirst_path = run_dir / "07-standfirst.json"
    legacy_intro_path = run_dir / "07-intro.json"
    source_path = standfirst_path if standfirst_path.exists() else legacy_intro_path
    if source_path.exists():
        try:
            copy_raw = json.loads(source_path.read_text())
            if isinstance(copy_raw, dict):
                standfirst = _clean_text(
                    copy_raw.get("standfirst") or copy_raw.get("intro")
                )
        except (json.JSONDecodeError, OSError):
            pass
    raw = {
        "status": "published" if curated.get("fresh") else "empty",
        "standfirst": standfirst,
        "fresh": curated.get("fresh", []),
        "generated_at": datetime.fromtimestamp(
            curated_path.stat().st_mtime, timezone.utc
        ).isoformat(),
    }
    return _normalize_publication(
        _within_edition_window(raw, topic, issue_date), topic, issue_date
    )


def _publication_from_legacy_html(
    topic: dict[str, Any], issue_date: str, archive_path: Path,
) -> dict[str, Any] | None:
    try:
        parser = LegacyDigestParser()
        parser.feed(archive_path.read_text())
    except (OSError, UnicodeError):
        return None
    if not parser.fresh:
        return None
    raw = {
        "status": "published",
        "standfirst": parser.standfirst,
        "fresh": parser.fresh,
        "generated_at": datetime.fromtimestamp(
            archive_path.stat().st_mtime, timezone.utc
        ).isoformat(),
    }
    return _normalize_publication(raw, topic, issue_date)


def _source_dates(digest_dir: Path) -> set[str]:
    dates: set[str] = set()
    if not digest_dir.exists():
        return dates
    for child in digest_dir.iterdir():
        name = child.stem if child.is_file() and child.suffix == ".html" else child.name
        if _valid_date(name):
            dates.add(name)
    return dates


def collect_source_publication(
    digests_dir: Path, topic: dict[str, Any], issue_date: str,
) -> dict[str, Any] | None:
    """Return a section's publication, or None when it has no source.

    Raises PublicationStateError when a run exists but its state cannot prove
    the publication. Editions from workflow-state adoption onward never read
    the rendered HTML archive: it may predate the final validated run.
    """
    digest_dir = digests_dir / topic["category"]
    run_dir = digest_dir / issue_date
    archive_path = digest_dir / f"{issue_date}.html"
    if issue_date >= WORKFLOW_STATE_REQUIRED_FROM:
        if not run_dir.is_dir():
            if archive_path.exists():
                print(
                    f"[publish] {topic['web_slug']} {issue_date}: run directory missing; "
                    "rendered HTML archive is not a publication source"
                )
            return None
        return _publication_from_run(topic, issue_date, run_dir)
    run_publication = _publication_from_run(topic, issue_date, run_dir)
    if run_publication is not None:
        return run_publication
    if archive_path.exists():
        return _publication_from_legacy_html(topic, issue_date, archive_path)
    return None


def _finalize_published_runs(
    digests_dir: Path,
    issue_date: str,
    date_editions: dict[str, dict[str, Any]],
) -> list[str]:
    """Finalize interrupted workflow runs whose artifacts were just published.

    Publish-recovery (digest-quality audit 2026-09-03): when an edition is
    built from a run whose phases were interrupted (SIGTERM or a crash left
    phase rows 'running'), record those rows as 'aborted' and mark the run
    'succeeded' with completed_at once its validated artifacts go live,
    instead of leaving tracker rows stuck in 'running' forever.
    """
    finalized: list[str] = []
    for key in TOPIC_ORDER:
        topic = TOPICS[key]
        slug = topic["web_slug"]
        if slug not in date_editions:
            continue
        run_dir = digests_dir / topic["category"] / issue_date
        configured_db = os.environ.get("WORKFLOW_STATE_DB")
        state_db = (
            Path(configured_db) if configured_db else run_dir / "workflow-state.sqlite3"
        )
        if not state_db.exists():
            continue
        state = WorkflowState(
            run_dir, "daily-news", run_id=run_dir.name, db_path=state_db
        )
        if state.finalize_published():
            finalized.append(slug)
    return finalized


def _atomic_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    temporary.replace(path)


def _durable_publication(
    destination: Path, topic: dict[str, Any], issue_date: str,
) -> dict[str, Any] | None:
    """The previously imported current-schema publication, if one exists."""
    try:
        raw = json.loads(destination.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if not _is_current_publication(raw, topic, issue_date):
        return None
    return _normalize_publication(raw, topic, issue_date)


def sync_publications(
    digests_dir: Path = DIGESTS_DIR,
    publications_dir: Path = PUBLICATIONS_DIR,
    degraded: list[dict[str, str]] | None = None,
) -> dict[str, dict[str, dict[str, Any]]]:
    """Import every available topic/date into the durable publication archive.

    An issue date's archives are frozen once that day's summary mail was sent:
    the mailed edition is the shipped truth, and later re-syncs (manual
    re-runs, --skip-email rebuilds) must not overwrite it (digest-quality
    audit 2026-08-26: the 2026-08-25 publications were regenerated at
    19:58-20:40Z after mail went out at 15:42Z, diverging the durable archive
    from the emailed edition). Only a schema-version mismatch regenerates a
    frozen archive (schema migration).

    A run whose workflow state cannot prove its publication never falls back
    to other files. The section keeps its previously validated durable
    publication when one exists, otherwise it is omitted (rendered as
    unavailable); either way the decision is logged and appended to
    `degraded` for the caller.
    """
    publications_dir.mkdir(parents=True, exist_ok=True)
    mail_dir = publications_dir.parent / "mail"
    all_dates: set[str] = set()
    for key in TOPIC_ORDER:
        all_dates.update(_source_dates(digests_dir / TOPICS[key]["category"]))

    editions: dict[str, dict[str, dict[str, Any]]] = {}
    for issue_date in sorted(all_dates):
        frozen = (mail_dir / f"{issue_date}.sent.json").exists()
        date_editions: dict[str, dict[str, Any]] = {}
        for key in TOPIC_ORDER:
            topic = TOPICS[key]
            destination = publications_dir / issue_date / f"{topic['web_slug']}.json"
            if frozen and destination.exists():
                try:
                    raw = json.loads(destination.read_text())
                except (OSError, json.JSONDecodeError):
                    raw = None
                if isinstance(raw, dict) and (
                    raw.get("schema_version") == PUBLICATION_SCHEMA_VERSION
                ):
                    date_editions[topic["web_slug"]] = _normalize_publication(
                        raw, topic, issue_date
                    )
                    continue
            try:
                publication = collect_source_publication(digests_dir, topic, issue_date)
            except PublicationStateError as error:
                kept = _durable_publication(destination, topic, issue_date)
                action = "kept durable publication" if kept is not None else "omitted section"
                print(
                    f"[publish DEGRADED] {topic['web_slug']} {issue_date}: {error}; {action}"
                )
                if degraded is not None:
                    degraded.append({
                        "date": issue_date,
                        "slug": topic["web_slug"],
                        "reason": str(error),
                        "action": action,
                    })
                if kept is not None:
                    date_editions[topic["web_slug"]] = kept
                continue
            if publication is None:
                # No source remains (for example, a cleaned run directory):
                # the durable copy validated at import is the section's record.
                kept = _durable_publication(destination, topic, issue_date)
                if kept is not None:
                    date_editions[topic["web_slug"]] = kept
                continue
            _atomic_json(destination, publication)
            date_editions[topic["web_slug"]] = publication
        if date_editions:
            editions[issue_date] = date_editions

    manifest = {
        "schema_version": PUBLICATION_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dates": [
            {
                "date": issue_date,
                "categories": [
                    TOPICS[key]["web_slug"] for key in TOPIC_ORDER
                    if TOPICS[key]["web_slug"] in editions[issue_date]
                ],
            }
            for issue_date in sorted(editions, reverse=True)
        ],
    }
    _atomic_json(publications_dir / "manifest.json", manifest)
    return editions


def load_publications(
    publications_dir: Path = PUBLICATIONS_DIR,
) -> dict[str, dict[str, dict[str, Any]]]:
    editions: dict[str, dict[str, dict[str, Any]]] = {}
    if not publications_dir.exists():
        return editions
    for date_dir in sorted(publications_dir.iterdir()):
        if not date_dir.is_dir() or not _valid_date(date_dir.name):
            continue
        date_editions: dict[str, dict[str, Any]] = {}
        for path in date_dir.glob("*.json"):
            try:
                _, topic = _topic_for_slug(path.stem)
                raw = json.loads(path.read_text())
                if isinstance(raw, dict):
                    date_editions[path.stem] = _normalize_publication(
                        raw, topic, date_dir.name
                    )
            except (KeyError, OSError, json.JSONDecodeError):
                continue
        if date_editions:
            editions[date_dir.name] = date_editions
    return editions


def _edition_date(issue_date: str) -> str:
    parsed = date.fromisoformat(issue_date)
    return parsed.strftime("%A, %B %-d, %Y")


_AP_MONTHS = (
    "Jan.", "Feb.", "March", "April", "May", "June",
    "July", "Aug.", "Sept.", "Oct.", "Nov.", "Dec.",
)
_ROMAN_NUMERALS = (
    (1000, "M"), (900, "CM"), (500, "D"), (400, "CD"), (100, "C"), (90, "XC"),
    (50, "L"), (40, "XL"), (10, "X"), (9, "IX"), (5, "V"), (4, "IV"), (1, "I"),
)
NAMEPLATE_FONT = "fonts/unifrakturmaguntia-normal.woff2"
# Font references in news.css, relative to the stylesheet, quoted or not.
_CSS_FONT_URL = re.compile(r"""url\(\s*(["']?)(fonts/[^"')\s]+)\1\s*\)""")
DATELINE_MOTTO = "Five sections · One edition"
NEW_TAB_TEXT = '<span class="visually-hidden"> (opens in a new tab)</span>'
# Drawn rather than the U+2197 glyph, which mobile browsers render as an emoji.
EXTERNAL_ARROW = (
    '<svg class="external" viewBox="0 0 12 12" aria-hidden="true" focusable="false">'
    '<path d="M2.5 9.5 9.5 2.5M4 2.5h5.5V8"/></svg>'
)
BYLINE_SEPARATOR = '<span aria-hidden="true"> · </span>'
ATTRIBUTION_HTML = (
    'Updated daily after curation completes. Attention signals from '
    '<a href="https://www.gdeltproject.org/" target="_blank" rel="noopener noreferrer">GDELT</a>, '
    '<a href="https://news.kagi.com/" target="_blank" rel="noopener noreferrer">Kagi News</a> '
    '(<a href="https://creativecommons.org/licenses/by-nc/4.0/" target="_blank" '
    'rel="noopener noreferrer">CC BY-NC 4.0</a>), Hacker News, Bluesky, Mastodon, '
    'Techmeme, Wikimedia, and publisher feeds.'
)


def _count_text(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


def _short_date(value: Any) -> str:
    """AP-style month and day for a byline, e.g. "Sept. 30"."""
    try:
        parsed = date.fromisoformat(_clean_text(value)[:10])
    except ValueError:
        return ""
    return f"{_AP_MONTHS[parsed.month - 1]} {parsed.day}"


def _roman(number: int) -> str:
    result = ""
    for value, numeral in _ROMAN_NUMERALS:
        count, number = divmod(number, value)
        result += numeral * count
    return result


def _edition_number(issue_date: str, dates: list[str]) -> str:
    """Masthead volume (one per calendar year since the first edition) and issue number."""
    volume = int(issue_date[:4]) - int(dates[-1][:4]) + 1
    return f"Vol. {_roman(volume)} · No. {len(dates) - dates.index(issue_date)}"


def _kicker(story: dict[str, Any], section_title: str = "", section_href: str = "") -> str:
    parts = []
    if section_title and section_href:
        parts.append(
            f'<a class="kicker-section" href="{html.escape(section_href, quote=True)}">'
            f'{html.escape(section_title)}</a>'
        )
    if story.get("category"):
        parts.append(
            f'<span class="kicker-category">{html.escape(str(story["category"]))}</span>'
        )
    return f'<p class="kicker">{"".join(parts)}</p>' if parts else ""


def _byline(story: dict[str, Any]) -> str:
    parts = []
    if story.get("source_domain"):
        parts.append(f'<span class="source">{html.escape(str(story["source_domain"]))}</span>')
    published = _clean_text(story.get("date_confirmed") or story.get("date_published"))
    label = _short_date(published)
    if label:
        parts.append(
            f'<time datetime="{html.escape(published[:10], quote=True)}">{label}</time>'
        )
    return f'<p class="byline">{BYLINE_SEPARATOR.join(parts)}</p>' if parts else ""


def _render_story(
    story: dict[str, Any],
    *,
    lead: bool = False,
    level: int = 3,
    section_title: str = "",
    section_href: str = "",
) -> str:
    title = html.escape(str(story.get("title", "")))
    url = html.escape(_safe_url(story.get("url")), quote=True)
    summary = html.escape(_clean_text(story.get("summary")))
    priority = html.escape(str(story.get("priority_score", "")), quote=True)
    significance = html.escape(str(story.get("editorial_significance", "")), quote=True)
    classes = "story story--lead" if lead else "story"
    summary_html = f'<p class="story-summary">{summary}</p>' if summary else ""
    return (
        f'<article class="{classes}" data-priority="{priority}" '
        f'data-significance="{significance}">'
        f'{_kicker(story, section_title, section_href)}'
        f'<h{level} class="story-title"><a href="{url}" target="_blank" '
        f'rel="noopener noreferrer">{title}{EXTERNAL_ARROW}'
        f'{NEW_TAB_TEXT}</a></h{level}>'
        f'{_byline(story)}{summary_html}'
        '</article>'
    )


def _category_nav(issue_date: str, active_slug: str) -> str:
    front_current = ' aria-current="page"' if active_slug == "front-page" else ""
    links = [f'<li><a href="/{issue_date}/"{front_current}>Front Page</a></li>']
    for key in TOPIC_ORDER:
        topic = TOPICS[key]
        slug = topic["web_slug"]
        current = ' aria-current="page"' if slug == active_slug else ""
        links.append(
            f'<li><a href="/{issue_date}/{slug}/"{current}>'
            f'{html.escape(topic["web_title"])}</a></li>'
        )
    return (
        '<nav class="section-nav" aria-label="News sections">'
        f'<ul class="shell">{"".join(links)}</ul></nav>'
    )


def _date_options(dates: list[str], issue_date: str) -> str:
    return "".join(
        f'<option value="{candidate}"{" selected" if candidate == issue_date else ""}>'
        f'{html.escape(_edition_date(candidate))}</option>'
        for candidate in dates
    )


def _truncate_description(text: str) -> str:
    return text[:157] + "…" if len(text) > 160 else text


def _page_description(publication: dict[str, Any]) -> str:
    return _truncate_description(_clean_text(publication.get("standfirst")))


def _page_head(
    title: str, description: str, canonical: str, assets: dict[str, str], *, script: bool = True,
) -> str:
    script_tag = (
        f'\n  <script src="{assets["news.js"]}" defer></script>' if script else ""
    )
    return f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>{html.escape(title)}</title>
  <meta name="description" content="{html.escape(description, quote=True)}">
  <link rel="canonical" href="{html.escape(canonical, quote=True)}">
  <link rel="icon" href="data:,">
  <link rel="preload" href="{assets[NAMEPLATE_FONT]}" as="font" type="font/woff2" crossorigin>
  <link rel="stylesheet" href="{assets["news.css"]}">{script_tag}
</head>'''


def _masthead(
    issue_date: str, dates: list[str], active_slug: str, ear_label: str, ear_text: str,
) -> str:
    front = active_slug == "front-page"
    plate_link = f'<a href="/{issue_date}/">Daily News</a>'
    nameplate = (
        f'<h1 class="nameplate">{plate_link}'
        '<span class="visually-hidden"> — Front Page</span></h1>'
        if front else f'<p class="nameplate">{plate_link}</p>'
    )
    return f'''<header class="masthead masthead--{"front" if front else "inside"}">
  <div class="shell">
    <div class="masthead-top">
      <p class="ear ear--left"><span class="ear-label">{html.escape(ear_label)}</span><span>{html.escape(ear_text)}</span></p>
      {nameplate}
      <div class="ear ear--right edition-controls">
        <label for="edition-date">Edition</label>
        <select id="edition-date" data-category="{html.escape(active_slug, quote=True)}">{_date_options(dates, issue_date)}</select>
        <a class="archive-link" href="/archive/">Archive</a>
      </div>
    </div>
    <div class="dateline">
      <span class="dateline-vol">{_edition_number(issue_date, dates)}</span>
      <time class="dateline-date" datetime="{issue_date}">{html.escape(_edition_date(issue_date))}</time>
      <span class="dateline-motto">{DATELINE_MOTTO}</span>
    </div>
  </div>
  {_category_nav(issue_date, active_slug)}
</header>'''


def _edition_pagination(
    label: str, noun: str, issue_date: str, dates: list[str], path: str = "",
) -> str:
    date_index = dates.index(issue_date)
    newer = dates[date_index - 1] if date_index > 0 else None
    older = dates[date_index + 1] if date_index + 1 < len(dates) else None
    older_link = (
        f'<a class="edition-link edition-link--older" href="/{older}/{path}" rel="prev">'
        f'<span>Older {noun}</span><strong>{html.escape(_edition_date(older))}</strong></a>'
        if older else '<span></span>'
    )
    newer_link = (
        f'<a class="edition-link edition-link--newer" href="/{newer}/{path}" rel="next">'
        f'<span>Newer {noun}</span><strong>{html.escape(_edition_date(newer))}</strong></a>'
        if newer else '<span></span>'
    )
    return f'<nav class="edition-pagination" aria-label="{label}">{older_link}{newer_link}</nav>'


def _footer(note_html: str, link_href: str, link_text: str) -> str:
    return f'''<footer class="site-footer"><div class="shell">
  <p class="footer-plate" aria-hidden="true">Daily News</p>
  <p class="footer-note">{note_html}</p>
  <a class="footer-link" href="{link_href}">{link_text}</a>
</div></footer>'''


def render_category_page(
    publication: dict[str, Any],
    issue_date: str,
    dates: list[str],
    editions: dict[str, dict[str, dict[str, Any]]],
    assets: dict[str, str],
) -> str:
    slug = publication["slug"]
    title = publication["title"]
    fresh = publication["fresh"]
    count_text = _count_text(len(fresh), "story", "stories")
    notice = ""
    if publication.get("notice"):
        notice = f'<aside class="edition-notice">{html.escape(publication["notice"])}</aside>'
    if publication["status"] == "unavailable":
        notice = '<aside class="edition-notice">No edition was published for this category on this date.</aside>'

    if fresh:
        lead = _render_story(fresh[0], lead=True)
        remaining = "".join(_render_story(story) for story in fresh[1:])
        fresh_html = lead + (
            f'<div class="story-grid ruled-grid">{remaining}</div>' if remaining else ""
        )
    else:
        fresh_html = '<p class="empty-state">No fresh stories were selected for this edition.</p>'

    slug_attr = html.escape(slug, quote=True)
    head = _page_head(
        f"{title} — {_edition_date(issue_date)}",
        _page_description(publication),
        f"{BASE_URL}/{issue_date}/{slug}/",
        assets,
    )
    return f'''{head}
<body class="page-section page-section--{slug_attr}">
<a class="skip-link" href="#content">Skip to stories</a>
{_masthead(issue_date, dates, slug, "Section", f"{title} · {count_text}")}
<main id="content" class="shell section-main">
  <header class="section-head">
    <p class="section-eyebrow"><span>Section</span><time datetime="{issue_date}">{html.escape(_edition_date(issue_date))}</time></p>
    <h1 class="section-title">{html.escape(title)}</h1>
    <p class="section-count">{count_text}</p>
  </header>
  {notice}
  <section class="latest" aria-labelledby="latest-heading">
    <h2 class="rule-heading" id="latest-heading">Latest <span>Last 24 hours</span></h2>
    {fresh_html}
  </section>
  {_edition_pagination("Adjacent editions", "edition", issue_date, dates, f"{slug}/")}
</main>
{_footer(ATTRIBUTION_HTML, "/archive/", "Browse all editions")}
</body>
</html>
'''


_EVENT_STOPWORDS = frozenset(
    "the and for with that this from into over under its their his her new says said "
    "will has have are was were been after about more than what when where which while "
    "who why how amid also can could would should may might now just first launch "
    "launches launched announces announced announce unveils unveiled reveals report "
    "reports update updates today week year years day days one two three four five six "
    "seven eight nine ten million billion percent".split()
)

EventFrequency = tuple[Counter, int]


def _event_tokens(text: Any) -> set[str]:
    tokens: set[str] = set()
    for token in re.findall(r"[A-Za-z0-9]+", _clean_text(text)):
        token = token.casefold()
        if len(token) < 3 or token in _EVENT_STOPWORDS:
            continue
        if len(token) > 4 and token.endswith("s"):
            token = token[:-1]
        tokens.add(token)
    return tokens


def _story_event_tokens(story: dict[str, Any]) -> set[str]:
    return _event_tokens(story.get("title")) | _event_tokens(story.get("event"))


def _frequency_of(publications: Iterable[dict[str, Any]]) -> EventFrequency:
    counts: Counter = Counter()
    documents = 0
    for publication in publications:
        for story in publication.get("fresh", []):
            counts.update(_story_event_tokens(story))
            documents += 1
    return counts, documents


def event_frequency(
    editions: dict[str, dict[str, dict[str, Any]]], issue_date: str,
) -> EventFrequency:
    """Token document frequency over the EVENT_CORPUS_DAYS ending at issue_date."""
    edition = date.fromisoformat(issue_date)
    start = edition - timedelta(days=EVENT_CORPUS_DAYS)
    return _frequency_of(
        publication
        for day, date_editions in editions.items()
        if _valid_date(day) and start <= date.fromisoformat(day) <= edition
        for publication in date_editions.values()
    )


def _same_event(
    first: dict[str, Any], second: dict[str, Any], frequency: EventFrequency,
) -> bool:
    """True for the same canonical article or the same distinctive news event.

    Different publishers covering one event share a rare headline anchor (for
    example "Googlebook") plus at least three words and a meaningful share of
    title/event vocabulary. An anchor is rare when at most ~1% of the recent
    corpus uses it, so company names and generic terms never merge distinct
    stories on their own.
    """
    first_key = coverage_key(first.get("url", ""))
    if first_key and first_key == coverage_key(second.get("url", "")):
        return True
    first_tokens = _story_event_tokens(first)
    second_tokens = _story_event_tokens(second)
    if not first_tokens or not second_tokens:
        return False
    shared = first_tokens & second_tokens
    if len(shared) < EVENT_MIN_SHARED_TOKENS:
        return False
    if len(shared) / min(len(first_tokens), len(second_tokens)) < EVENT_MIN_TOKEN_OVERLAP:
        return False
    counts, documents = frequency
    rare_limit = max(2, documents // 100)
    anchors = _event_tokens(first.get("title")) & _event_tokens(second.get("title"))
    return any(counts[token] <= rare_limit for token in anchors)


def _front_page_sections(
    date_editions: dict[str, dict[str, Any]],
    frequency: EventFrequency | None = None,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """Remove same-event duplicates, then guarantee one lead per section.

    Deduplication runs before any section lead is chosen: the highest-priority
    copy of an event survives, and a section whose best story duplicates it
    falls back to its next story (2026-09-22: Googlebook led both AI Hardware
    and World). Remaining slots are filled globally above a priority floor.
    """
    if frequency is None:
        frequency = _frequency_of(date_editions.values())
    sections: list[dict[str, Any]] = []
    stories: list[dict[str, Any]] = []
    for key in TOPIC_ORDER:
        topic = TOPICS[key]
        publication = date_editions.get(topic["web_slug"])
        if publication is None:
            continue
        sections.append({
            "slug": topic["web_slug"],
            "title": topic["web_title"],
            "stories": [],
        })
        stories.extend(
            {
                **story,
                "_section_slug": topic["web_slug"],
                "_section_title": topic["web_title"],
            }
            for story in publication["fresh"]
        )

    def duplicates(story: dict[str, Any], other: dict[str, Any]) -> bool:
        # Curation already separated stories within one section; across
        # sections both canonical URLs and distinctive events collapse.
        if story["_section_slug"] == other["_section_slug"]:
            key = coverage_key(story.get("url", ""))
            return bool(key) and key == coverage_key(other.get("url", ""))
        return _same_event(story, other, frequency)

    kept: list[dict[str, Any]] = []
    candidates_by_slug: dict[str, list[dict[str, Any]]] = {
        section["slug"]: [] for section in sections
    }
    for story in sorted(stories, key=priority_sort_key, reverse=True):
        if any(duplicates(story, other) for other in kept):
            continue
        kept.append(story)
        candidates_by_slug[story["_section_slug"]].append(story)

    secondary_pool: list[dict[str, Any]] = []
    for section in sections:
        candidates = candidates_by_slug[section["slug"]]
        if not candidates:
            continue
        # One already-curated story represents every section with coverage.
        section["stories"].append(candidates[0])
        for story in candidates[1:]:
            if float(story.get("priority_score", 0.0) or 0.0) >= FRONT_PAGE_SECONDARY_THRESHOLD:
                secondary_pool.append(story)

    section_by_slug = {section["slug"]: section for section in sections}
    remaining_slots = max(
        0,
        FRONT_PAGE_MAX_STORIES - sum(len(section["stories"]) for section in sections),
    )
    for story in sorted(secondary_pool, key=priority_sort_key, reverse=True):
        if remaining_slots == 0:
            break
        if not _safe_url(story.get("url")):
            continue
        section_by_slug[story["_section_slug"]]["stories"].append(story)
        remaining_slots -= 1

    selected = [
        story for section in sections for story in section["stories"]
    ]
    lead = max(selected, key=priority_sort_key, default=None)
    return lead, sections


def render_front_page(
    date_editions: dict[str, dict[str, Any]],
    issue_date: str,
    dates: list[str],
    assets: dict[str, str],
    frequency: EventFrequency | None = None,
) -> str:
    if frequency is None:
        frequency = _frequency_of(date_editions.values())
    lead, sections = _front_page_sections(date_editions, frequency)
    selected = [story for section in sections for story in section["stories"]]
    if lead is not None:
        lead_html = _render_story(
            lead,
            lead=True,
            level=2,
            section_title=str(lead["_section_title"]),
            section_href=f"/{issue_date}/{lead['_section_slug']}/",
        )
        description_text = _clean_text(lead.get("summary"))
    else:
        lead_html = '<p class="empty-state">No front-page stories were selected.</p>'
        description_text = "The highest-priority stories from each Daily News section."

    # Section index: name, story count, and the section's top headline only
    # when that story (or its event) is not already on the front page.
    index_items = []
    for key in TOPIC_ORDER:
        topic = TOPICS[key]
        slug = topic["web_slug"]
        publication = date_editions.get(slug)
        if publication is None:
            continue
        fresh = publication["fresh"]
        headline = ""
        if fresh and not any(_same_event(fresh[0], shown, frequency) for shown in selected):
            headline = f'<p>{html.escape(_clean_text(fresh[0].get("title")))}</p>'
        index_items.append(
            f'<li><a class="inside-section" href="/{issue_date}/{slug}/">'
            f'{html.escape(topic["web_title"])}</a>'
            f'<span class="inside-count">{_count_text(len(fresh), "story", "stories")}</span>'
            f'{headline}</li>'
        )

    tiles = []
    lead_url = _safe_url(lead.get("url")) if lead else ""
    for section in sections:
        stories = [
            story for story in section["stories"]
            if _safe_url(story.get("url")) != lead_url
        ]
        if not stories:
            continue
        slug = html.escape(section["slug"], quote=True)
        title = html.escape(section["title"])
        href = f"/{issue_date}/{slug}/"
        secondary = ""
        if len(stories) > 1:
            items = "".join(
                f'<li><a href="{html.escape(_safe_url(story.get("url")), quote=True)}" '
                f'target="_blank" rel="noopener noreferrer">'
                f'{html.escape(_clean_text(story.get("title")))}{NEW_TAB_TEXT}</a>'
                + (
                    f' <span class="source">{html.escape(str(story["source_domain"]))}</span>'
                    if story.get("source_domain") else ""
                )
                + '</li>'
                for story in stories[1:]
            )
            secondary = (
                f'<div class="more-headlines"><h4 class="more-label">Also in {title}</h4>'
                f'<ul>{items}</ul></div>'
            )
        total = len(date_editions[section["slug"]]["fresh"])
        noun = "story" if total == 1 else "stories"
        tiles.append(
            f'<section class="front-section front-section--{slug}" aria-labelledby="front-{slug}">'
            f'<h2 class="section-flag" id="front-{slug}"><a href="{href}">{title}</a></h2>'
            f'{_render_story(stories[0])}{secondary}'
            f'<a class="section-jump" href="{href}">All {total} {title} {noun}'
            '<span aria-hidden="true"> →</span></a>'
            '</section>'
        )
    tiles_html = f'<div class="front-sections ruled-grid">{"".join(tiles)}</div>' if tiles else ""

    ear_text = (
        f'{_count_text(len(tiles), "section", "sections")} · '
        f'{_count_text(len(selected), "top story", "top stories")}'
    )
    head = _page_head(
        f"Front Page — {_edition_date(issue_date)}",
        _truncate_description(description_text),
        f"{BASE_URL}/{issue_date}/",
        assets,
    )
    return f'''{head}
<body class="page-front">
<a class="skip-link" href="#content">Skip to stories</a>
{_masthead(issue_date, dates, "front-page", "Front Page", ear_text)}
<main id="content" class="shell front-main">
  <div class="front-top">
    <section class="front-lead" aria-label="Lead story">{lead_html}</section>
    <aside class="inside-index" aria-labelledby="inside-heading">
      <h2 id="inside-heading" class="rail-heading">Inside This Edition</h2>
      <ol class="inside-list">{"".join(index_items)}</ol>
    </aside>
  </div>
  {tiles_html}
  {_edition_pagination("Adjacent front pages", "front page", issue_date, dates)}
</main>
{_footer(ATTRIBUTION_HTML, "/archive/", "Browse all editions")}
</body>
</html>
'''


def render_archive_page(
    dates: list[str], editions: dict[str, dict[str, dict[str, Any]]], assets: dict[str, str],
) -> str:
    months = []
    for month, month_dates in groupby(dates, key=lambda issue_date: issue_date[:7]):
        entries = []
        for issue_date in month_dates:
            links = [f'<li><a href="/{issue_date}/">Front Page</a></li>']
            for key in TOPIC_ORDER:
                topic = TOPICS[key]
                slug = topic["web_slug"]
                if slug in editions.get(issue_date, {}):
                    links.append(
                        f'<li><a href="/{issue_date}/{slug}/">'
                        f'{html.escape(topic["web_title"])}</a></li>'
                    )
            parsed = date.fromisoformat(issue_date)
            entries.append(
                f'<li class="archive-entry"><time datetime="{issue_date}">'
                f'<span class="visually-hidden">{html.escape(_edition_date(issue_date))}</span>'
                f'<span class="archive-day" aria-hidden="true">{parsed.day}</span>'
                f'<span class="archive-weekday" aria-hidden="true">{parsed:%A}</span></time>'
                f'<ul class="archive-links">{"".join(links)}</ul></li>'
            )
        label = date.fromisoformat(f"{month}-01").strftime("%B %Y")
        months.append(
            f'<section class="archive-month" aria-labelledby="m-{month}">'
            f'<h2 class="archive-month-title" id="m-{month}">{label} '
            f'<span>{_count_text(len(entries), "edition", "editions")}</span></h2>'
            f'<ol class="archive-list ruled-grid">{"".join(entries)}</ol></section>'
        )
    span = (
        f"{date.fromisoformat(dates[-1]):%B %-d, %Y} – {date.fromisoformat(dates[0]):%B %-d, %Y}"
    )
    head = _page_head(
        "Archive — Daily News",
        "Previous daily news editions by date and category.",
        f"{BASE_URL}/archive/",
        assets,
        script=False,
    )
    return f'''{head}
<body class="page-archive">
<a class="skip-link" href="#content">Skip to editions</a>
<header class="masthead masthead--inside masthead--archive">
  <div class="shell">
    <div class="masthead-top">
      <p class="nameplate"><a href="/">Daily News</a></p>
    </div>
    <div class="dateline">
      <span class="dateline-vol">Past coverage</span>
      <span class="dateline-date">{span}</span>
      <span class="dateline-motto"><a href="/">Latest edition</a></span>
    </div>
  </div>
</header>
<main id="content" class="shell archive-main">
  <header class="section-head">
    <p class="section-eyebrow"><span>Index</span><span>{_count_text(len(dates), "daily edition", "daily editions")}</span></p>
    <h1 class="section-title">Edition Archive</h1>
  </header>
  {"".join(months)}
</main>
{_footer("Five focused sections, one daily edition.", "/", "Latest news")}
</body>
</html>
'''


def _write_page(root: Path, relative: str, content: str) -> None:
    path = root / relative / "index.html"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def _hashed_name(name: str, content: bytes) -> str:
    path = Path(name)
    digest = hashlib.sha256(content).hexdigest()[:12]
    return str(path.with_name(f"{path.stem}.{digest}{path.suffix}"))


def _install_assets(asset_dir: Path, target: Path) -> dict[str, str]:
    """Write content-hashed stylesheet, script and fonts into ``target``.

    Returns the logical asset name (``news.css``, ``fonts/<file>.woff2``) mapped
    to its hashed ``/assets/`` URL. Licenses and the speculation rules keep their
    names because nothing caches them for long.
    """
    (target / "fonts").mkdir(parents=True)
    manifest: dict[str, str] = {}

    def install(name: str, content: bytes) -> None:
        hashed = _hashed_name(name, content)
        (target / hashed).write_bytes(content)
        manifest[name] = f"/assets/{hashed}"

    for font in sorted((asset_dir / "fonts").glob("*.woff2")):
        install(f"fonts/{font.name}", font.read_bytes())
    if NAMEPLATE_FONT not in manifest:
        raise ValueError(f"nameplate font {asset_dir / NAMEPLATE_FONT} does not exist")

    def hashed_font_url(match: re.Match[str]) -> str:
        name = match.group(2)
        if name not in manifest:
            raise ValueError(f"news.css references missing font {asset_dir / name}")
        return f'url("{manifest[name].removeprefix("/assets/")}")'

    css = _CSS_FONT_URL.sub(
        hashed_font_url, (asset_dir / "news.css").read_bytes().decode("utf-8")
    )
    install("news.css", css.encode("utf-8"))
    install("news.js", (asset_dir / "news.js").read_bytes())
    for license_file in sorted((asset_dir / "fonts").glob("OFL-*.txt")):
        shutil.copy(license_file, target / "fonts" / license_file.name)
    shutil.copy(asset_dir / "speculationrules.json", target / "speculationrules.json")
    return manifest


def build_site(
    editions: dict[str, dict[str, dict[str, Any]]],
    news_dir: Path = NEWS_DIR,
    asset_dir: Path = ASSET_DIR,
) -> Path:
    if not editions:
        raise ValueError("no news publications are available")
    dates = sorted(editions, reverse=True)
    build_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    release = news_dir / "releases" / build_id
    try:
        assets = _install_assets(asset_dir, release / "assets")
    except BaseException:
        # A half-written release must not displace a good rollback in retention.
        shutil.rmtree(release, ignore_errors=True)
        raise

    for issue_date in dates:
        date_editions = editions[issue_date]
        for key in TOPIC_ORDER:
            topic = TOPICS[key]
            slug = topic["web_slug"]
            publication = date_editions.get(slug) or _empty_publication(topic, issue_date)
            page = render_category_page(publication, issue_date, dates, editions, assets)
            _write_page(release, f"{issue_date}/{slug}", page)
        _write_page(
            release,
            issue_date,
            render_front_page(
                date_editions, issue_date, dates, assets, event_frequency(editions, issue_date)
            ),
        )

    latest = dates[0]
    for key in TOPIC_ORDER:
        topic = TOPICS[key]
        slug = topic["web_slug"]
        category_dates = [d for d in dates if slug in editions[d]]
        if not category_dates:
            continue
        category_date = category_dates[0]
        page = render_category_page(
            editions[category_date][slug], category_date, dates, editions, assets
        )
        _write_page(release, slug, page)

    (release / "index.html").write_text(
        render_front_page(
            editions[latest], latest, dates, assets, event_frequency(editions, latest)
        )
    )
    _write_page(release, "archive", render_archive_page(dates, editions, assets))
    (release / "404.html").write_text(
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta name="color-scheme" content="light dark">'
        '<title>Page not found — Daily News</title><link rel="icon" href="data:,">'
        f'<link rel="stylesheet" href="{assets["news.css"]}">'
        '</head><body class="error-page"><main><p class="eyebrow">404</p><h1>Page not found</h1>'
        '<p>The edition or category you requested does not exist.</p><a href="/">Latest news</a>'
        '</main></body></html>'
    )
    _atomic_json(release / "build.json", {
        "built_at": datetime.now(timezone.utc).isoformat(),
        "latest_date": latest,
        "dates": len(dates),
        "pages": len(dates) * len(TOPIC_ORDER) + len(TOPIC_ORDER) + len(dates) + 3,
    })

    current = news_dir / "current"
    temporary_link = news_dir / f".current-{uuid.uuid4().hex}"
    temporary_link.symlink_to(Path("releases") / build_id)
    temporary_link.replace(current)

    releases = sorted(
        (path for path in (news_dir / "releases").iterdir() if path.is_dir()),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for old_release in releases[2:]:
        shutil.rmtree(old_release)
    return release


def render_headline_email(
    issue_date: str,
    editions: dict[str, dict[str, Any]],
    base_url: str = BASE_URL,
    frequency: EventFrequency | None = None,
) -> str:
    lead, sections = _front_page_sections(editions, frequency)
    lead_url = _safe_url(lead.get("url")) if lead is not None else ""
    front_page_stories = [lead] if lead is not None else []
    front_page_stories.extend(
        story
        for section in sections
        for story in section["stories"]
        if _safe_url(story.get("url")) != lead_url
    )
    headline_items = "".join(
        '<li style="margin:0 0 12px;padding-left:2px;color:#171716;'
        'font:700 18px/1.35 Georgia,serif;">'
        f'<a href="{html.escape(base_url, quote=True)}/{issue_date}/{story["_section_slug"]}/" '
        'style="color:#171716;text-decoration:underline;">'
        f'{html.escape(_clean_text(story.get("title")))}</a></li>'
        for story in front_page_stories
    )
    headline_list = (
        '<ul style="margin:0 0 22px;padding-left:22px;">'
        f"{headline_items}</ul>"
        if headline_items
        else (
            '<p style="margin:0 0 20px;color:#444b54;'
            'font:15px/1.65 Arial,sans-serif;">'
            "No front-page stories were selected.</p>"
        )
    )
    today_link = f"{base_url}/{issue_date}/"
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;background:#f3f4f6;color:#171716;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3f4f6;padding:24px 10px;"><tr><td align="center">
<table role="presentation" width="620" cellpadding="0" cellspacing="0" style="width:100%;max-width:620px;background:#ffffff;border:1px solid #d7dbe0;">
<tr><td style="padding:30px;border-top:4px solid #171716;">
  <p style="margin:0 0 7px;color:#626a73;font:600 11px/1.3 Arial,sans-serif;text-transform:uppercase;letter-spacing:1.2px;">{html.escape(_edition_date(issue_date))}</p>
  <h1 style="margin:0 0 16px;color:#171716;font:700 32px/1.05 Georgia,serif;">Today’s headlines</h1>
  {headline_list}
  <a href="{html.escape(today_link, quote=True)}" style="display:inline-block;background:#171716;color:#ffffff;padding:10px 15px;font:700 13px/1 Arial,sans-serif;text-decoration:none;">Open the front page</a>
</td></tr>
<tr><td style="padding:18px 30px;border-top:1px solid #d7dbe0;color:#626a73;font:12px/1.5 Arial,sans-serif;">news.carter2099.com</td></tr>
</table></td></tr></table></body></html>'''




def send_headline_email_once(
    issue_date: str,
    editions: dict[str, dict[str, Any]],
    news_dir: Path = NEWS_DIR,
    *,
    send_func: Callable[[str, str, list[str]], Any] = smtp_send,
    recipient: str = SUMMARY_RECIPIENT,
    base_url: str = BASE_URL,
    frequency: EventFrequency | None = None,
) -> bool:
    marker = news_dir / "mail" / f"{issue_date}.sent.json"
    if marker.exists():
        print(f"[mail] already sent for {issue_date}; skipping")
        return False
    body = render_headline_email(
        issue_date, editions, base_url=base_url, frequency=frequency
    )
    subject = f"Daily News — {date.fromisoformat(issue_date).strftime('%B %-d, %Y')}"
    send_func(subject, body, [recipient])
    _atomic_json(marker, {
        "sent_at": datetime.now(timezone.utc).isoformat(),
        "date": issue_date,
        "recipient": recipient,
        "subject": subject,
    })
    return True


def publish(
    issue_date: str,
    *,
    digests_dir: Path = DIGESTS_DIR,
    news_dir: Path = NEWS_DIR,
    asset_dir: Path = ASSET_DIR,
    send_email: bool = True,
    send_func: Callable[[str, str, list[str]], Any] = smtp_send,
) -> dict[str, Any]:
    if not _valid_date(issue_date):
        raise ValueError(f"invalid publication date: {issue_date}")
    publications_dir = news_dir / "publications"
    degraded: list[dict[str, str]] = []
    editions = sync_publications(digests_dir, publications_dir, degraded)
    if issue_date not in editions:
        raise RuntimeError(f"no curated digest artifacts found for {issue_date}")

    release = build_site(editions, news_dir, asset_dir)
    print(f"[site] activated {release.name} ({len(editions)} dates)")

    # A section kept from its durable publication after a state failure is not
    # evidence that the current run finished; never promote that run.
    finalized = _finalize_published_runs(
        digests_dir,
        issue_date,
        {
            slug: publication
            for slug, publication in editions[issue_date].items()
            if not any(
                item["date"] == issue_date and item["slug"] == slug for item in degraded
            )
        },
    )
    if finalized:
        print(
            f"[state] finalized {len(finalized)} interrupted run(s): "
            f"{', '.join(sorted(finalized))}"
        )

    mailed = False
    if send_email:
        mailed = send_headline_email_once(
            issue_date,
            editions[issue_date],
            news_dir,
            send_func=send_func,
            frequency=event_frequency(editions, issue_date),
        )
        print(f"[mail] {'sent' if mailed else 'unchanged'}")

    return {
        "date": issue_date,
        "release": str(release),
        "dates": len(editions),
        "categories": len(editions[issue_date]),
        "email_sent": mailed,
        "degraded_sections": [
            item for item in degraded if item["date"] == issue_date
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Publish curated digest artifacts as the daily news web application"
    )
    parser.add_argument(
        "--date", default=datetime.now(timezone.utc).date().isoformat(),
        help="UTC digest date (YYYY-MM-DD)",
    )
    parser.add_argument("--skip-email", action="store_true", help="Build without sending email")
    args = parser.parse_args()
    result = publish(args.date, send_email=not args.skip_email)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
