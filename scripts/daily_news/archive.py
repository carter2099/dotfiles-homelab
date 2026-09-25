"""Daily News archive and deterministic rendering phases 7 through 9."""
from __future__ import annotations

import copy
import html
import json
import re
import shutil
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from workflow_state import WorkflowState, atomic_write_json, atomic_write_text
from . import runtime
from .catalog import *
from .contracts import (
    normalize_editorial_significance,
    normalize_story_tracking,
    recover_latest_source,
)
from .copy import (
    generate_section_standfirst,
    standfirst_story_fingerprint,
    validate_standfirst,
)

def render_story_block(story: dict, *, ongoing: bool = False) -> str:
    url = html.escape(str(story.get("url", "")), quote=True)
    title = html.escape(str(story.get("title", "")))
    category = html.escape(str(story.get("category", "")))
    summary = html.escape(str(story.get("summary", "")))
    why = ""
    if ongoing:
        why_text = html.escape(str(story.get("why_still_relevant", "")))
        why = (
            '\n    <p style="margin:2px 0 0; color:#7c6bbf; font-size:13px; '
            f'font-style:italic;">↳ {why_text}</p>'
        )
    return (
        "<tr>\n"
        '  <td style="padding:8px 32px;">\n'
        '    <p style="margin:0 0 2px;">\n'
        f'      <a href="{url}" style="color:#1a1a2e; font-size:15px; '
        f'font-weight:600; text-decoration:none;">{title}</a>\n'
        f'      <span style="color:#999; font-size:12px; font-weight:400;">'
        f" · {category}</span>\n"
        "    </p>\n"
        f'    <p style="margin:0; color:#555; font-size:14px; '
        f'line-height:1.5;">{summary}</p>{why}\n'
        "  </td>\n"
        "</tr>"
    )

def empty_section_block(message: str) -> str:
    return (
        '<tr><td style="padding:8px 32px; color:#777; font-size:14px;">'
        f"{html.escape(message)}</td></tr>"
    )

def render_digest_html(
    topic: dict,
    fresh: list[dict],
    ongoing: list[dict],
    standfirst: str,
    *,
    notice: str = "",
    issue_date: date | None = None,
) -> str:
    template = runtime.TEMPLATE_PATH.read_text()
    template = re.sub(
        r"\n<!--\nSTORY BLOCK TEMPLATE[\s\S]*?-->\s*$", "\n", template
    )
    standfirst_text = f"{notice} {standfirst}".strip()
    fresh_html = "\n".join(
        render_story_block(story) for story in fresh
    ) or empty_section_block("No fresh stories selected today.")
    ongoing_html = "\n".join(
        render_story_block(story, ongoing=True) for story in ongoing
    ) or empty_section_block("No developing or ongoing stories selected today.")
    display_date = issue_date or datetime.now(timezone.utc).date()
    replacements = {
        "{{DIGEST_TITLE}}": html.escape(str(topic["title"])),
        "{{DATE}}": html.escape(display_date.strftime("%B %d, %Y")),
        "{{INTRO}}": html.escape(standfirst_text),
        "{{FRESH_STORIES}}": fresh_html,
        "{{ONGOING_STORIES}}": ongoing_html,
    }
    rendered = template
    for placeholder, value in replacements.items():
        rendered = rendered.replace(placeholder, value)
    return rendered

@runtime.track_phase_failure("write-html")
def phase_7_write(
    topic: dict,
    fresh: list[dict],
    ongoing: list[dict],
    run_dir: Path,
    *,
    notice: str = "",
) -> str:
    """Generate the approved standfirst, then render archival HTML deterministically."""
    output_path = run_dir / "digest.html"
    issue_date = runtime.issue_date_for_run(run_dir)
    story_fingerprint = standfirst_story_fingerprint(fresh + ongoing)
    phase_inputs = runtime.phase_inputs(
        "write-html", topic=topic,
        upstream={"stories": runtime.canonical_fingerprint(fresh + ongoing)},
        policy={
            "standfirst_fingerprint": story_fingerprint,
            "notice": notice,
            "issue_date": issue_date.isoformat(),
        },
    )
    state, cached = runtime.begin_or_load_text_phase(
        run_dir, "write-html", inputs=phase_inputs, artifact_path=output_path,
        schema_version=STANDFIRST_PROMPT_VERSION,
    )
    if cached is not None:
        print(f"  [skip] Phase 7 output validated: {output_path}")
        return cached

    print(f"  [run ] write_html — {len(fresh)} fresh, {len(ongoing)} ongoing")
    started = time.time()
    standfirst = generate_section_standfirst(topic, fresh, ongoing, run_dir)
    rendered = render_digest_html(
        topic,
        fresh,
        ongoing,
        standfirst,
        notice=notice,
        issue_date=issue_date,
    )
    runtime.complete_phase_text(
        state,
        "write-html",
        output_path,
        rendered,
        outcome="empty" if not fresh and not ongoing else "succeeded",
        reason="no selected stories for HTML render" if not fresh and not ongoing else None,
    )
    if not fresh and not ongoing:
        runtime.write_phase_status(
            output_path,
            status="empty",
            reason="no selected stories for HTML render",
            inputs=phase_inputs,
        )
    elapsed = time.time() - started
    print(f"  [done] write_html — deterministic render, {len(rendered)} chars "
          f"({elapsed:.0f}s)")
    return rendered

def public_story(story: dict, *, ongoing: bool = False) -> dict:
    """Return only source-backed fields safe to publish on the news site."""
    fields = (
        "title", "url", "source_domain", "date_published", "date_confirmed",
        "summary", "category", "editorial_significance", "significance_evidence",
        "significance_validation", "author", "event", "priority_score",
        "priority_explanation",
    )
    normalized = normalize_editorial_significance(copy.deepcopy(story))
    public = {
        key: normalized.get(key)
        for key in fields
        if normalized.get(key) is not None
    }
    attention = normalized.get("attention")
    if isinstance(attention, dict):
        public["attention"] = {
            key: attention.get(key)
            for key in (
                "schema_version", "provider", "status", "attention_now",
                "digest_prominence", "confidence", "age_bucket",
                "normalized_signals", "evidence",
            )
            if attention.get(key) is not None
        }
    if ongoing and normalized.get("why_still_relevant"):
        public["why_still_relevant"] = normalized["why_still_relevant"]
    return public

def load_validated_standfirst(
    topic: dict,
    fresh: list[dict],
    ongoing: list[dict],
    run_dir: Path,
) -> str:
    """Load the exact standfirst artifact owned by its succeeded state row."""

    stories = fresh + ongoing
    story_fingerprint = standfirst_story_fingerprint(stories)
    inputs = runtime.phase_inputs(
        "standfirst",
        topic=topic,
        upstream={"stories": runtime.canonical_fingerprint(stories)},
        policy={"prompt_version": STANDFIRST_PROMPT_VERSION},
    )
    payload = WorkflowState(
        run_dir, runtime.WORKFLOW_NAME, run_id=run_dir.name
    ).load_json(
        "standfirst",
        inputs=inputs,
        artifact_path=run_dir / "07-standfirst.json",
        schema_version=STANDFIRST_PROMPT_VERSION,
        validator=lambda value: (
            isinstance(value, dict)
            and value.get("story_fingerprint") == story_fingerprint
            and validate_standfirst(value.get("standfirst", ""), stories)[0]
        ),
    )
    if payload is None:
        raise RuntimeError("validated standfirst state is unavailable")
    return str(payload["standfirst"])


@runtime.track_phase_failure("archive")
def phase_8_archive(
    topic: dict,
    rendered_html: str,
    stories_in_flight: dict,
    run_dir: Path,
    digest_dir: Path,
    fresh: list[dict] | None = None,
    ongoing: list[dict] | None = None,
    *,
    notice: str = "",
    archive_daily: bool = True,
) -> Path:
    """Archive the topic and write its stable, public publication artifact.

    No email is sent here. The all-topic publisher consumes publication.json
    after every category finishes, updates the site, and sends one summary email.
    """
    today_str = runtime.issue_date_for_run(run_dir).isoformat()
    fresh = fresh or []
    ongoing = ongoing or []
    standfirst = load_validated_standfirst(topic, fresh, ongoing, run_dir)
    publication_path = run_dir / "publication.json"
    sif_path = digest_dir / "stories-in-flight.json"
    phase_inputs = runtime.phase_inputs(
        "archive", topic=topic,
        upstream={
            "rendered_html": runtime.canonical_fingerprint(rendered_html),
            "stories_in_flight": runtime.canonical_fingerprint(stories_in_flight),
            "fresh": runtime.canonical_fingerprint(fresh),
            "ongoing": runtime.canonical_fingerprint(ongoing),
            "standfirst": runtime.canonical_fingerprint(standfirst),
        },
        policy={"ranking_schema": RANKING_SCHEMA_VERSION, "archive_daily": archive_daily, "notice": notice},
    )
    state, cached = runtime.begin_or_load_phase(
        run_dir, "archive", inputs=phase_inputs, artifact_path=publication_path,
        schema_version=2, validator=lambda value: isinstance(value, dict),
    )
    if cached is not None:
        runtime.atomic_write_json(sif_path, stories_in_flight)
        return publication_path

    curated_src = run_dir / "06-curated.json"
    if curated_src.exists():
        runtime.atomic_write_text(
            run_dir / "curated_copy.json",
            curated_src.read_text(encoding="utf-8"),
        )
    else:
        print("  [WARN] 06-curated.json missing — curated_copy.json not written")

    archive_path = (
        digest_dir / f"{today_str}.html"
        if archive_daily and not runtime.TEST_MODE
        else run_dir / "digest.html"
    )
    if archive_daily and not runtime.TEST_MODE:
        latest_html = digest_dir / ".daily_digest.html"
        runtime.atomic_write_text(latest_html, rendered_html)
        runtime.atomic_write_text(archive_path, rendered_html)
    else:
        runtime.atomic_write_text(archive_path, rendered_html)
    print(f"  [done] archived HTML → {archive_path}")

    # The standfirst was loaded from its validated workflow-state snapshot
    # before this phase began.
    publication = {
        "schema_version": 2,
        "ranking_schema_version": RANKING_SCHEMA_VERSION,
        "date": today_str,
        "slug": topic["web_slug"],
        "title": topic["web_title"],
        "source_category": topic["category"],
        "status": "degraded" if notice else ("published" if fresh or ongoing else "empty"),
        "notice": notice,
        "standfirst": standfirst,
        "fresh": [public_story(story) for story in fresh],
        "ongoing": [public_story(story, ongoing=True) for story in ongoing],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    archive_outcome = "empty" if not fresh and not ongoing else ("degraded" if notice else "succeeded")
    archive_reason = (
        "no selected stories for publication"
        if archive_outcome == "empty"
        else notice
        if archive_outcome == "degraded"
        else None
    )
    runtime.atomic_write_json(sif_path, stories_in_flight)
    print("  [done] stories-in-flight updated")
    runtime.complete_phase_json(
        state,
        "archive",
        publication_path,
        publication,
        outcome=archive_outcome,
        reason=archive_reason,
    )
    if not fresh and not ongoing:
        runtime.write_phase_status(
            publication_path,
            status="empty",
            reason="no selected stories for publication",
            inputs=phase_inputs,
        )
    print(f"  [done] publication artifact → {publication_path}")

    return publication_path

@runtime.track_phase_failure("summary")
def phase_9_summary(topic: dict, fresh: list[dict], ongoing: list[dict],
                    run_dir: Path, digest_dir: Path) -> None:
    """Phase 9: Write the .md summary for future dedup.

    One LLM call, lightweight. Output is retained in the run and topic archives.
    """
    today_str = runtime.issue_date_for_run(run_dir).isoformat()
    output_path = run_dir / "summary.md"
    digest_md_path = digest_dir / f"{today_str}.md"
    publication_url = f"https://news.carter2099.com/{today_str}/{topic['web_slug']}/"
    phase_inputs = runtime.phase_inputs(
        "summary", topic=topic,
        upstream={"fresh": runtime.canonical_fingerprint(fresh), "ongoing": runtime.canonical_fingerprint(ongoing)},
        policy={"publication_url": publication_url},
    )
    state, cached = runtime.begin_or_load_text_phase(
        run_dir, "summary", inputs=phase_inputs, artifact_path=output_path, schema_version=1,
    )
    if cached is not None:
        print(f"  [skip] Phase 9 output validated: {output_path}")
        return

    print(f"  [run ] summary_md")
    t0 = time.time()

    if not fresh and not ongoing:
        # Empty digest: never send empty data to the LLM. The hard "every story
        # MUST include its URL" constraint makes it fabricate placeholder
        # stories with example.com URLs. Write an honest summary directly.
        md_output = (
            f"# {topic['title']} — {today_str}\n"
            f"**Published at:** {publication_url}\n\n"
            "## Fresh\n"
            "- No stories published in the last 24 hours.\n\n"
            "## Developing and Ongoing\n"
            "- No developing or ongoing stories reported.\n\n"
            "## Coverage Gaps\n"
            f"- No {topic['title']} stories were published or aggregated "
            "in the last 24 hours.\n"
        )
        runtime.complete_phase_text(
            state,
            "summary",
            output_path,
            md_output,
            outcome="empty",
            reason="no selected stories",
        )
        runtime.atomic_write_text(digest_md_path, md_output)
        runtime.write_phase_status(output_path, status="empty", reason="no selected stories", inputs=phase_inputs)
        elapsed = time.time() - t0
        print(f"  [done] summary_md — empty digest, direct summary ({elapsed:.0f}s)")
        return

    fresh_json = json.dumps(fresh, indent=2)
    ongoing_json = json.dumps(ongoing, indent=2)

    system = (
        "You are writing a concise markdown summary of today's published digest for "
        "archival and future deduplication. Write the entire summary in English and keep "
        "the supplied English story titles unchanged. Output ONLY the markdown, no "
        "explanations."
    )

    user = (
        f"Write a markdown summary of today's {topic['title']} in this exact format:\n\n"
        f"# {topic['title']} — {today_str}\n"
        f"**Published at:** {publication_url}\n\n"
        "## Fresh\n"
        "- [Story title](URL) — one-line summary\n"
        "- [Story title](URL) — one-line summary\n\n"
        "## Developing and Ongoing\n"
        "- [Story title](URL) — one-line summary (latest material development)\n\n"
        "## Coverage Gaps\n"
        "- Any notable stories or angles that were missed today\n\n"
        "IMPORTANT: Every story MUST include its URL as a markdown link `[title](URL)`. "
        "This is used by the dedup system in future runs. Never omit the URL.\n\n"
        f"## Fresh Stories Data\n\n{fresh_json}\n\n"
        f"## Developing and Ongoing Stories Data\n\n{ongoing_json}"
    )

    try:
        raw = runtime._call_llm_proxy(system, user, model=runtime.MODEL)
        md_output = re.sub(r"^```(?:markdown)?\s*\n?", "", raw.strip())
        md_output = re.sub(r"\n?```\s*$", "", md_output)
        runtime.complete_phase_text(state, "summary", output_path, md_output + "\n")
        elapsed = time.time() - t0
        print(f"  [done] summary_md — {len(md_output)} chars ({elapsed:.0f}s)")
    except Exception as e:
        elapsed = time.time() - t0
        print(f"  [FAIL] summary_md — {e} ({elapsed:.0f}s)")
        # Fallback: write minimal summary from structured data
        lines = [
            f"# {topic['title']} — {today_str}",
            f"**Published at:** {publication_url}",
            "",
            "## Fresh",
        ]
        for s in fresh[:10]:
            lines.append(f"- [{s.get('title', '?')}]({s.get('url', '#')}) — {s.get('summary', '')[:100]}")
        lines.append("")
        lines.append("## Developing and Ongoing")
        for s in ongoing[:5]:
            lines.append(f"- [{s.get('title', '?')}]({s.get('url', '#')}) — {s.get('summary', '')[:100]}")
        runtime.complete_phase_text(
            state,
            "summary",
            output_path,
            "\n".join(lines) + "\n",
            outcome="degraded",
            reason=f"LLM summary failed: {str(e)[:500]}",
        )

    if output_path.exists():
        runtime.atomic_write_text(digest_md_path, output_path.read_text(encoding="utf-8"))

def prune_and_cool_stories(
    stories: list[dict],
    today: date | None = None,
) -> tuple[list[dict], int, int]:
    """Cool on evidence inactivity; prune only cooled, inactive stories."""
    if today is None:
        today = datetime.now(timezone.utc).date()
    kept: list[dict] = []
    auto_cooled = 0
    auto_pruned = 0

    for story in stories:
        normalize_story_tracking(story, today)
        last_date = datetime.strptime(story["last_updated"], "%Y-%m-%d").date()
        inactive_age = (today - last_date).days
        status = story.get("status", "active")

        if status == "active" and inactive_age >= COOL_AFTER_DAYS:
            story["status"] = "cooled"
            status = "cooled"
            auto_cooled += 1

        # Active stories may run longer than seven days when real developments
        # continue. Only cooled stories with seven evidence-free days expire.
        if status == "cooled" and inactive_age >= PRUNE_AFTER_DAYS:
            auto_pruned += 1
            continue

        kept.append(story)

    return kept, auto_cooled, auto_pruned

def load_and_prune_stories_in_flight(
    digest_dir: Path, evidence_dir: Path | None = None,
) -> dict:
    """Load, migrate, cool, and prune the cross-day story tracker.

    Two deterministic rules:
    1. AUTO-COOL: active story with no evidence-backed development for
       COOL_AFTER_DAYS becomes cooled and leaves Developing and Ongoing.
    2. AUTO-PRUNE: cooled story with no evidence-backed development for
       PRUNE_AFTER_DAYS is removed. An actively developing story is not removed
       merely because its first report is old.

    A selected, source-linked fresh development can revive a cooled story.
    Legacy records without `latest_source` recover it from the section's run
    artifacts under `evidence_dir` (default `digest_dir`) when provable.
    """
    path = digest_dir / "stories-in-flight.json"
    if not path.exists():
        return {"stories": []}

    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, ValueError):
        return {"stories": []}

    kept, auto_cooled, auto_pruned = prune_and_cool_stories(data.get("stories", []))

    if auto_cooled > 0:
        print(f"  Auto-cooled {auto_cooled} stale stories "
              f"(>= {COOL_AFTER_DAYS}d without evidence)")
    if auto_pruned > 0:
        print(f"  Auto-pruned {auto_pruned} cooled stories "
              f"(>= {PRUNE_AFTER_DAYS}d without evidence)")

    recovered = sum(
        1 for story in kept
        if isinstance(story, dict)
        and recover_latest_source(story, evidence_dir or digest_dir)
    )
    if recovered:
        print(f"  Recovered latest-source provenance for {recovered} tracked story(s)")

    data["stories"] = kept
    return data

def cleanup_old_artifacts(digest_dir: Path, max_age_days: int = 14):
    """Remove run directories older than max_age_days."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    for child in digest_dir.iterdir():
        if child.is_dir() and child.name != "stories-in-flight":
            try:
                date = datetime.strptime(child.name, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                if date < cutoff:
                    shutil.rmtree(child)
                    print(f"  Cleaned up old run dir: {child.name}")
            except (ValueError, OSError):
                pass

def archive_stub_attempt(run_dir: Path) -> None:
    """Preserve the failed attempt's phase artifacts instead of deleting them.

    Stub/fallback retries used to unlink every 0*-*.json in the run dir, so a
    fallback rerun left no JSON trail of the original failure. Move the
    attempt's artifacts into a timestamped stub-attempt-* subdirectory instead
    (digest-quality audit 2026-08-13).
    """
    archive = run_dir / f"stub-attempt-{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}"
    archive.mkdir(exist_ok=True)
    for p in run_dir.glob("0*-*.json"):
        shutil.move(str(p), str(archive / p.name))
    print(f"  [retry] Preserved failed attempt artifacts → {archive.name}")

def cleanup_stub_attempts(run_dir: Path) -> None:
    """Remove archived stub-attempt subdirectories after a fully successful run.

    The archived partial attempt is only useful while the run may fail; once
    the final run completes, keeping it makes the run dir look like a partial
    run and double-counts artifacts in audits (digest-quality audit 2026-08-24:
    both audit-window ai-tech days carried stub-attempt-* debris).
    """
    for child in run_dir.iterdir():
        if child.is_dir() and child.name.startswith("stub-attempt-"):
            shutil.rmtree(child)
            print(f"  [cleanup] Removed archived stub attempt: {child.name}")
