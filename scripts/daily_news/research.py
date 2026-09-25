"""Daily News research phases 1 through 5."""
from __future__ import annotations

import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import jev as jev_api

from . import attention, attention_match, attention_sources
from .attention import (
    SCHEMA_VERSION as ATTENTION_SCHEMA_VERSION,
    priority_sort_key,
)
from .catalog import *
from .contracts import *
from .runtime import *
from . import runtime

_UPSTREAM_OUTAGE: bool = False
_RESEARCH_FAILURES: list[str] = []
_RESEARCH_SUCCESSES: int = 0

def refetch_article_date(url: str, title: str) -> str | None:
    """Re-fetch an article to independently extract its publication date.

    Uses a lightweight omp -p call that only extracts the date from the page
    (no summary, no analysis). Returns date string (YYYY-MM-DD) or None on failure.
    """
    system = (
        "You are extracting a publication date from a news article. "
        "Fetch the page, find the visible publication date (article header, "
        "byline, or metadata), and output ONLY the date. Do not summarize. "
        "Be quick.\n\n"
        "Output a JSON object wrapped in ```json fences:\n"
        '{"date_confirmed": "YYYY-MM-DD"}\n\n'
        "If no publication date is visible anywhere on the page, use empty string."
    )
    prompt = (
        f"Fetch this article: {url}\n\n"
        "Extract ONLY the publication date from the page. Output the JSON."
    )
    try:
        raw = runtime._call_omp_p(prompt, model=runtime.MODEL, timeout=600,
                         append_system=system)
        result = runtime._extract_json(raw, f"date-refetch:{title[:40]}")
        dc = (result.get("date_confirmed") or "").strip()
        return dc if dc else None
    except Exception:
        return None

def batch(items: list[Any], size: int = BATCH_SIZE) -> list[list[Any]]:
    """Split items into batches of at most `size`."""
    return [items[i:i + size] for i in range(0, len(items), size)]

@runtime.track_phase_failure("research")
def phase_1_research(
    topic: dict,
    run_dir: Path,
    stories_in_flight: dict | None = None,
) -> list[dict]:
    """Phase 1: Run broad discovery plus bounded tracked-story follow-ups.

    Each research angle gets its own omp call and uses web search. Returns the
    merged findings with their originating angle preserved.
    """
    global _UPSTREAM_OUTAGE, _RESEARCH_FAILURES, _RESEARCH_SUCCESSES
    _RESEARCH_FAILURES = []
    _RESEARCH_SUCCESSES = 0
    _UPSTREAM_OUTAGE = False

    output_path = run_dir / "01-research-raw.json"
    phase_inputs = runtime.phase_inputs(
        "research", topic=topic,
        upstream={"stories_in_flight": runtime.canonical_fingerprint(stories_in_flight or {})},
        policy={"angles": topic.get("research_angles", []), "model": runtime._effective_model(runtime.MODEL)},
    )
    state, cached = runtime.begin_or_load_phase(
        run_dir, "research", inputs=phase_inputs, artifact_path=output_path,
        schema_version=1, validator=lambda value: isinstance(value, list),
    )
    if cached is not None:
        return cached

    rubric = editorial_significance_rubric_text(topic)
    angles = list(topic["research_angles"])
    followup_angle = build_developing_followup_angle(stories_in_flight)
    if followup_angle is not None:
        angles.append(followup_angle)

    system_prompt = (
        "You are a research assistant for a daily newspaper. Search the web for recent "
        "news events and report source-grounded findings in structured JSON. "
        "Write every finding, title, summary, and reason in English regardless of the "
        "source article's language. Translate non-English headlines into concise, idiomatic English.\n\n"
        "IMPORTANT: Do NOT use read to open articles during discovery. Only use "
        "web_search to find stories by their titles and URLs. The articles will be "
        "read later by a separate process. Your job is discovery, not deep reading.\n\n"
        "PREFER PRIMARY SOURCES: Link directly to the original article on the publisher's "
        "site (e.g. techcrunch.com, theverge.com, arstechnica.com, reuters.com). "
        "Avoid news aggregators, roundup sites, and link-blog posts — find the real "
        "source behind the story.\n\n"
        "Use web_search with 2-3 different queries to find stories from the last 24 hours. "
        "After searching, output your findings as a JSON array wrapped in ```json fences. "
        "Each finding must have these fields:\n"
        '  {"title": "...", "url": "...", "source_domain": "...", '
        '"date_published": "YYYY-MM-DD or empty if unknown from search snippet", '
        '"summary": "1-sentence summary from search result", '
        '"category": "...", "editorial_significance": "high|medium|low", '
        '"significance_evidence": {"basis": "binding_policy_or_law|'
        'broad_public_consequence|major_conflict_or_disaster|major_financial_scale|'
        'major_product_or_platform_shift|security_or_safety_incident|'
        'widespread_mandatory_migration", "affected_scope": "broad|sector|niche", '
        '"impact": "source-grounded factual sentence"}, '
        '"event": "concise canonical statement of what happened", '
        '"event_terms": ["2-4 distinctive English names or phrases that must all identify '
        'this event"]}\n'
        "Event terms are for deterministic coverage measurement. Generate terms and aliases, "
        "but never estimate popularity, virality, audience interest, or an attention score. "
        "A tracked-story follow-up must also include `develops_story_url` exactly "
        "as supplied by that angle; otherwise omit that field.\n\n"
        "Never construct URLs — only use URLs that appeared in web_search results. "
        "Target 5-8 findings for a broad angle. For a tracked-story follow-up, zero "
        "is valid when nothing materially changed. Be quick — search, compile, output JSON.\n\n"
        f"{rubric}"
    )

    def _research_one(angle: dict) -> list[dict]:
        global _RESEARCH_SUCCESSES  # += below rebinds; must be global here too
        label = f"research:{angle['id']}"
        print(f"  [run ] {label}")
        t0 = time.time()
        def _attempt() -> list[dict]:
            raw = runtime._call_omp_p(angle["prompt"], model=runtime.MODEL, timeout=runtime.RESEARCH_TIMEOUT,
                             append_system=system_prompt)
            return runtime._extract_json(raw, f"{label} output")

        try:
            findings = _attempt()
            failure_msg = None
        except Exception as e:
            # Per-angle retry: a failed extraction must not silently drop this
            # angle — previously the whole section was lost whenever a sibling
            # angle produced findings (the run-level fallback retry at the
            # digest level only fires when ALL angles yield zero findings).
            # Retry once with the same model.
            print(f"  [retry] {label} — attempt 1 failed: {e}; retrying once")
            check_search_health(f"retry-{angle['id']}")
            try:
                findings = _attempt()
                failure_msg = None
            except Exception as e2:
                findings = []
                failure_msg = str(e2)

        if isinstance(findings, list):
            for finding in findings:
                if isinstance(finding, dict):
                    finding.setdefault("research_angle_id", angle["id"])

        elapsed = time.time() - t0
        if findings:
            print(f"  [done] {label} — {len(findings)} findings in {elapsed:.0f}s")
            _RESEARCH_SUCCESSES += 1
        elif angle.get("optional") and failure_msg is None:
            print(f"  [done] {label} — no material developments in {elapsed:.0f}s")
        else:
            if failure_msg is None:
                # HTTP 200 but empty broad discovery is degraded rather than a
                # trustworthy "nothing happened" result. The optional follow-up
                # angle above is the exception: no material movement is expected.
                failure_msg = "empty research results (LLM returned no findings)"
            print(f"  [FAIL] {label} — {failure_msg} ({elapsed:.0f}s)")
            check_search_health(f"fail-{angle['id']}")
            _RESEARCH_FAILURES.append(failure_msg)
        return findings

    with ThreadPoolExecutor(max_workers=runtime.MAX_PARALLEL_RESEARCH) as pool:
        per_angle = list(pool.map(_research_one, angles))
    findings = [finding for angle_findings in per_angle for finding in angle_findings]

    # Filter out non-dict artifacts (LLMs sometimes produce stray strings)
    artifacts = [f for f in findings if not isinstance(f, dict)]
    findings = [f for f in findings if isinstance(f, dict)]
    if artifacts:
        print(f"  Filtered {len(artifacts)} non-dict artifact(s): {artifacts}")

    # Detect upstream outage: all angles failed with connectivity errors,
    # OR all HTTP 200 calls returned empty findings (degraded LLM stage).
    if not findings and _RESEARCH_FAILURES and _RESEARCH_SUCCESSES == 0:
        err_msg = " ".join(_RESEARCH_FAILURES).lower()
        if any(kw in err_msg for kw in ["502", "503", "connection refused",
                                         "connection reset", "upstream",
                                         "timeout", "econnrefused",
                                         "empty research results"]):
            _UPSTREAM_OUTAGE = True
            print(f"  *** UPSTREAM OUTAGE: All {len(_RESEARCH_FAILURES)} research angle(s) "
                  f"failed (connectivity errors or empty LLM results)")

    research_outcome = (
        "degraded" if not findings and _UPSTREAM_OUTAGE
        else "empty" if not findings
        else "succeeded"
    )
    research_reason = (
        "all research angles failed with upstream errors"
        if research_outcome == "degraded"
        else "research returned no findings"
        if research_outcome == "empty"
        else None
    )
    runtime.complete_phase_json(
        state,
        "research",
        output_path,
        findings,
        outcome=research_outcome,
        reason=research_reason,
    )
    if not findings:
        runtime.write_phase_status(
            output_path, status="empty",
            reason="research returned no findings",
            inputs=phase_inputs,
        )
    print(f"  Phase 1 done: {len(findings)} total findings")
    return findings

@runtime.track_phase_failure("judge-research")
def phase_2_judge_research(topic: dict, findings: list[dict], run_dir: Path,
                           stories_in_flight: dict | None = None) -> tuple[list[dict], list[dict]]:
    """Phase 2: Python date pre-tagging + batched LLM judge.

    1. Python parses date_published → tags each finding as fresh, older, or too_old.
       too_old findings are dropped without touching the LLM.
    2. Exact tracked-story links from the dedicated follow-up angle are validated.
       The judge admits only material new developments; unchanged recaps stay deduped.
    3. Findings are split into batches of BATCH_SIZE.
    4. Each batch gets one LLM call with topic rules and editorial-significance rubric.
    5. Python restores source metadata and enforces cross-batch dedup.

    Before any judging, the shared recent-coverage ledger removes findings any
    section covered in the previous CROSS_DAY_DEDUP_DAYS days (canonical story
    and referenced URLs). Tracked developments re-enter only through the
    dedicated follow-up path with a new article URL.

    Returns (fresh_findings, ongoing_findings).
    """
    output_path = run_dir / "02-research-judged.json"
    today = runtime.issue_date_for_run(run_dir)
    # run_dir is <digests root>/<category>/<run>; the ledger spans every category.
    recent_coverage = load_recent_coverage_ledger(
        run_dir.parent.parent, today, CROSS_DAY_DEDUP_DAYS
    )
    phase_inputs = runtime.phase_inputs(
        "judge-research", topic=topic,
        upstream={
            "findings": runtime.canonical_fingerprint(findings),
            "stories_in_flight": runtime.canonical_fingerprint(stories_in_flight or {}),
            "covered_urls": sorted(recent_coverage),
        },
        policy={
            "issue_date": today.isoformat(),
            "judgment_rules": topic.get("judgment_rules", ""),
            "model": runtime._effective_model(runtime.MODEL),
        },
    )
    state, cached = runtime.begin_or_load_phase(
        run_dir, "judge-research", inputs=phase_inputs, artifact_path=output_path,
        schema_version=1, validator=lambda value: isinstance(value, dict),
    )
    if cached is not None:
        return cached.get("fresh", []), cached.get("ongoing", [])

    print(f"  [run ] judge_research — {len(findings)} findings to evaluate")
    t0 = time.time()

    # ── Step 1: Python date pre-tagging ──
    yesterday = today - timedelta(days=1)
    ongoing_cutoff_date = today - timedelta(days=5)
    for finding in findings:
        normalize_editorial_significance(finding)
        if finding.get("url"):
            finding["url"] = canonicalize_publisher_url(finding["url"])

    pre_tagged: list[dict] = []
    too_old_count = 0
    tracker_by_url = {
        normalize_url(story.get("url", "")): story
        for story in (stories_in_flight or {}).get("stories", [])
        if normalize_url(story.get("url", ""))
    }
    invalid_followup_count = 0
    ledger_rejected: list[dict] = []

    for f in findings:
        if f.get("research_angle_id") == "developing-followups":
            tracked_url = normalize_url(f.get("develops_story_url", ""))
            tracked_story = tracker_by_url.get(tracked_url)
            if tracked_story is None or not has_validated_high_significance(tracked_story):
                invalid_followup_count += 1
                continue
            f["develops_story_url"] = tracked_story.get("url", "")
        else:
            # Only the bounded follow-up angle may assert a cross-day story link.
            # This prevents a broad research result from inventing a relationship.
            f.pop("develops_story_url", None)

        if coverage_key(f.get("url", "")) in recent_coverage:
            ledger_rejected.append({"finding": f, "reason": "already_covered_previous_day"})
            continue
        pub_date = parse_date(f.get("date_published"))
        if pub_date is None:
            too_old_count += 1
            continue
        pub_calendar_date = pub_date.date()
        if pub_calendar_date >= yesterday:
            f["date_tag"] = "fresh"
            pre_tagged.append(f)
        elif pub_calendar_date >= ongoing_cutoff_date:
            f["date_tag"] = "ongoing"
            pre_tagged.append(f)
        else:
            too_old_count += 1

    print(f"  Date pre-tag: {sum(1 for f in pre_tagged if f['date_tag'] == 'fresh')} fresh, "
          f"{sum(1 for f in pre_tagged if f['date_tag'] == 'ongoing')} older, "
          f"{too_old_count} too_old, {invalid_followup_count} invalid follow-up (dropped), "
          f"{len(ledger_rejected)} covered by a section in the previous "
          f"{CROSS_DAY_DEDUP_DAYS} days (dropped)")

    if not pre_tagged:
        print(f"  [done] judge_research — all findings too old or no date")
        output = {"fresh": [], "ongoing": [], "rejected": ledger_rejected, "status": "empty",
                  "reason": "no date-valid research findings"}
        runtime.complete_phase_json(
            state,
            "judge-research",
            output_path,
            output,
            outcome="empty",
            reason=output["reason"],
        )
        runtime.write_phase_status(output_path, status="empty", reason=output["reason"], inputs=phase_inputs)
        return [], []


    # Build tracker context only from roots that still satisfy the full evidence
    # contract. Legacy label-only highs must not suppress normal fresh research.
    sif_context = ""
    eligible_tracker_by_url = {
        url: story
        for url, story in tracker_by_url.items()
        if has_validated_high_significance(story)
    }
    if eligible_tracker_by_url:
        tracked_context = [{
            "title": story.get("title", ""),
            "story_url": story.get("url", ""),
            "latest_confirmed_development": story.get("latest_dev", ""),
            "editorial_significance": story.get("editorial_significance", "medium"),
            "last_evidence_date": story.get("last_updated", ""),
            "status": story.get("status", "active"),
        } for story in eligible_tracker_by_url.values()]
        sif_context = (
            "## Tracked stories\n"
            "A finding with `develops_story_url` came from the dedicated follow-up "
            "search. Approve it only when it reports a material new fact after the "
            "tracked story's last evidence date, and preserve `develops_story_url` "
            "exactly. Reject recaps, commentary, or broad-theme connections. A finding "
            "about a tracked topic without that exact field is not a vetted follow-up; "
            "reject it as `already_tracked_in_sif` rather than re-adding it.\n\n"
            f"{DEVELOPING_STORY_RULES}\n"
            + json.dumps(tracked_context, indent=2) + "\n\n"
        )

    # ── Step 2: Batch LLM calls ──
    rubric = editorial_significance_rubric_text(topic)
    batches = batch(pre_tagged, BATCH_SIZE)
    print(f"  Batched into {len(batches)} LLM call(s) ({BATCH_SIZE}/batch)")

    all_approved: list[dict] = []
    all_rejected: list[dict] = []

    system = (
        "You are a strict newspaper editor filtering research findings against quality "
        "rules. Be harsh — a false positive is worse than a false negative.\n\n"
        "You will receive a JSON array of research findings and a set of rules. "
        "For each finding, evaluate every rule. Preserve source fields, especially "
        "`research_angle_id`, `develops_story_url`, `date_tag`, `event`, `event_terms`, "
        "URL, and publication date. You may adjust `editorial_significance` based only "
        "on consequence. Every `high` finding must include structured "
        "`significance_evidence` with an allowed basis, broad/sector affected scope, and "
        "a factual impact sentence grounded in the supplied title/summary. Routine "
        "deprecations, patches, renames, or migration notices are not high without "
        "documented widespread disruption or affected scale. Never estimate popularity "
        "or attention.\n\n"
        "Output a JSON object with two arrays wrapped in ```json fences:\n"
        '  {\n'
        '    "approved": [<findings that pass all quality checks>],\n'
        '    "rejected": [{"finding": ..., "reason": "..."}, ...]\n'
        '  }\n'
    )

    for batch_idx, batch_items in enumerate(batches):
        batch_json = json.dumps(batch_items, indent=2)
        user = (
            f"{sif_context}"
            f"## Rules\n\n{topic['judgment_rules']}\n\n"
            f"## Editorial Significance Rubric\n\n{rubric}\n\n"
            f"## Findings to evaluate (batch {batch_idx + 1}/{len(batches)})\n\n"
            f"{batch_json}\n\n"
            "Evaluate each finding against every rule. Output the approved and "
            "rejected arrays in ```json fences. Include a clear reason for each rejection."
        )

        try:
            raw = runtime._call_llm_proxy(system, user, model=runtime.MODEL)
            result = runtime._extract_json(raw, f"judge_research batch {batch_idx + 1}")
            batch_approved = result.get("approved", [])
            batch_rejected = result.get("rejected", [])
            # Normalize: LLM sometimes returns bare strings instead of dicts
            batch_approved = [f if isinstance(f, dict) else {"title": str(f)} for f in batch_approved]
            batch_rejected = [r if isinstance(r, dict) else {"finding": {"title": str(r)}, "reason": "unknown"} for r in batch_rejected]
            all_approved.extend(batch_approved)
            all_rejected.extend(batch_rejected)
            print(f"  Batch {batch_idx + 1}: {len(batch_approved)} approved, {len(batch_rejected)} rejected")
            for finding in batch_approved:
                normalize_editorial_significance(finding)
        except Exception as e:
            print(f"  [FAIL] judge_research batch {batch_idx + 1} — {e}, treating all as approved")
            all_approved.extend(batch_items)

    # ── Step 3: Restore source metadata, then enforce deterministic dedup ──
    seen_urls: set[str] = set()
    deduped_approved: list[dict] = []
    dedup_rejected: list[dict] = []
    original_by_url = {
        normalize_url(f.get("url", "")): f for f in pre_tagged
        if normalize_url(f.get("url", ""))
    }

    for f in all_approved:
        url = normalize_url(f.get("url", ""))
        source = original_by_url.get(url)
        if source is not None:
            for field in (
                "date_tag", "research_angle_id", "develops_story_url",
                "event", "event_terms", "significance_evidence",
            ):
                if field in source:
                    f[field] = source[field]
                else:
                    f.pop(field, None)
        tracked_url = normalize_url(f.get("develops_story_url", ""))
        if (
            f.get("research_angle_id") == "developing-followups"
            and (
                tracked_url not in tracker_by_url
                or not has_validated_high_significance(tracker_by_url[tracked_url])
            )
        ):
            dedup_rejected.append({"finding": f, "reason": "invalid_followup_link"})
        elif url and url in seen_urls:
            dedup_rejected.append({"finding": f, "reason": "crossbatch_duplicate"})
        elif coverage_key(f.get("url", "")) in recent_coverage:
            dedup_rejected.append({"finding": f, "reason": "already_covered_previous_day"})
        else:
            if url:
                seen_urls.add(url)
            deduped_approved.append(f)

    dedup_rejected = ledger_rejected + dedup_rejected
    if dedup_rejected:
        n_cross_day = sum(1 for r in dedup_rejected
                          if r.get("reason") == "already_covered_previous_day")
        nbatch = len(dedup_rejected) - n_cross_day
        if nbatch:
            print(f"  Cross-batch dedup: removed {nbatch} duplicates")
        if n_cross_day:
            print(f"  Recent-coverage dedup: removed {n_cross_day} stories any section "
                  "covered on previous days")

    # Split by date_tag
    fresh = [f for f in deduped_approved if f.get("date_tag") == "fresh"]
    ongoing = [f for f in deduped_approved if f.get("date_tag") == "ongoing"]

    elapsed = time.time() - t0
    print(f"  [done] judge_research — {len(fresh)} fresh, {len(ongoing)} ongoing, "
          f"{len(all_rejected) + len(dedup_rejected)} rejected ({elapsed:.0f}s)")
    for r in all_rejected[:5]:
        finding = r.get("finding", {}) if isinstance(r, dict) else {}
        reason = r.get("reason", "unspecified") if isinstance(r, dict) else "unknown"
        title = finding.get('title', '?') if isinstance(finding, dict) else str(finding)[:60]
        print(f"    ✗ {title[:60]}: {reason}")
    if len(all_rejected) > 5:
        print(f"    ... and {len(all_rejected) - 5} more rejected")

    output = {"fresh": fresh, "ongoing": ongoing, "rejected": all_rejected + dedup_rejected,
              "status": "ok" if fresh or ongoing else "empty",
              "reason": "" if fresh or ongoing else "no findings passed research judgment"}
    runtime.complete_phase_json(
        state,
        "judge-research",
        output_path,
        output,
        outcome="empty" if not fresh and not ongoing else "succeeded",
        reason=output["reason"] if not fresh and not ongoing else None,
    )
    if not fresh and not ongoing:
        runtime.write_phase_status(output_path, status="empty", reason=output["reason"], inputs=phase_inputs)
    return fresh, ongoing

def _attention_snapshot(issue_date, offline: bool) -> dict:
    """The edition's shared inventory snapshot; offline runs and store failures stay explicit."""
    names = attention_sources.SOURCES
    if offline:
        reason = {"status": "skipped", "reason": "DAILY_NEWS_OFFLINE=1", "rows": 0}
        now = datetime.now(timezone.utc).isoformat()
        return {"id": "offline", "window_start": now, "window_end": now, "built_at": now,
                "elapsed_seconds": 0.0, "sources": {name: dict(reason) for name in names}, "rows": []}
    try:
        return attention_sources.load_or_build_snapshot(runtime.ATTENTION_SNAPSHOT_DIR, issue_date)
    except Exception as error:  # noqa: BLE001 - attention is optional; the phase continues
        now = datetime.now(timezone.utc).isoformat()
        failure = {"status": "unavailable", "rows": 0, "error": " ".join(str(error).split())[:240]}
        return {"id": "unavailable", "window_start": now, "window_end": now, "built_at": now,
                "elapsed_seconds": 0.0, "sources": {name: dict(failure) for name in names}, "rows": []}


@runtime.track_phase_failure("attention")
def phase_2b_attention(
    topic: dict,
    fresh: list[dict],
    ongoing: list[dict],
    run_dir: Path,
) -> tuple[list[dict], list[dict]]:
    """Measure observed attention and Jev importance without asking an LLM for popularity."""
    output_path = run_dir / "02b-attention.json"
    issue_date = runtime.issue_date_for_run(run_dir)
    section = topic["web_slug"]
    started = time.time()
    deadline = time.monotonic() + attention.ATTENTION_STAGE_BUDGET_SECONDS
    offline = os.environ.get("DAILY_NEWS_OFFLINE") == "1"
    snapshot = _attention_snapshot(issue_date, offline)
    phase_inputs = runtime.phase_inputs(
        "attention", topic=topic,
        upstream={
            "fresh": runtime.canonical_fingerprint(fresh),
            "ongoing": runtime.canonical_fingerprint(ongoing),
            "snapshot": snapshot["id"],
        },
        policy={
            "attention_schema": ATTENTION_SCHEMA_VERSION,
            "attention_budget_seconds": attention.ATTENTION_STAGE_BUDGET_SECONDS,
            "jev_model": jev_api.MODEL,
            "snapshot_schema": attention_sources.SNAPSHOT_SCHEMA_VERSION,
        },
    )
    state, cached = runtime.begin_or_load_phase(
        run_dir, "attention", inputs=phase_inputs, artifact_path=output_path,
        schema_version=ATTENTION_SCHEMA_VERSION, validator=lambda value: isinstance(value, dict),
    )
    if cached is not None:
        return cached.get("fresh", []), cached.get("ongoing", [])

    print(
        f"  [run ] attention — {len(fresh)} fresh event(s); snapshot {snapshot['id']} "
        f"({'reused' if snapshot.get('reused') else 'collected'}, {len(snapshot['rows'])} rows)"
    )
    client = None if offline else jev_api.load_client(deadline=deadline)
    window_end = datetime.fromisoformat(snapshot["window_end"])
    # Only fully collected sources are scored; a failed or partial one is left out of every
    # story's blend, never read as zero attention for the stories it happened to miss.
    measured_sources = frozenset(
        name for name in attention.section_sources(section)
        if (snapshot["sources"].get(name) or {}).get("status") == "ok"
    )
    excluded_sources = {
        name: (snapshot["sources"].get(name) or {}).get("status", "unavailable")
        for name in attention.section_sources(section) if name not in measured_sources
    }
    section_reason = "offline" if offline else "jev_unavailable" if client is None else None
    evidence: list[dict] = [{"unavailable_reason": section_reason} for _ in fresh]
    adjudication_error = ""
    unadjudicated = 0
    if section_reason is None and fresh:
        index = attention_match.Index(snapshot["rows"])
        documents = [attention_match.retrieve(item, index) for item in fresh]
        adjudicator = attention_match.Adjudicator(client)
        failed = adjudicator.adjudicate(list(zip(fresh, documents)))
        adjudication_error, unadjudicated = adjudicator.error, len(failed)
        sample_fraction = (snapshot["sources"].get("jetstream") or {}).get("sample_fraction")
        evidence = [
            {"unavailable_reason": "adjudication_failed"} if position in failed
            else attention_match.measure(
                item, item_documents, index,
                window_end_s=int(window_end.timestamp()), sample_fraction=sample_fraction,
            )
            for position, (item, item_documents) in enumerate(zip(fresh, documents))
        ]
    references = attention.reference_scales(
        attention.load_reference_history(runtime.ATTENTION_ARCHIVE_DIR, section, issue_date)
    )
    importance, importance_failures = attention.assess_importance(
        fresh + ongoing, client, section_label=topic["web_title"],
    )
    scored_fresh, observations = attention.score_attention(
        fresh, section=section, evidence=evidence, importance=importance[:len(fresh)],
        measured_sources=measured_sources, references=references, window_end=window_end,
    )
    scored_ongoing = attention.score_ongoing(ongoing, section=section, importance=importance[len(fresh):])

    if client is None:
        jev = {"status": "unconfigured" if not offline else "offline"}
    else:
        jev = {
            **client.usage(),
            "status": "degraded" if unadjudicated or importance_failures else "ok",
            "error": adjudication_error,
            "unadjudicated_stories": unadjudicated,
            "importance_failures": importance_failures,
        }
    statuses = [row["attention"]["status"] for row in observations]
    attention_artifact = {
        "schema_version": ATTENTION_SCHEMA_VERSION,
        "provider": attention.PROVIDER,
        "section": section,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "snapshot": {
            **{key: snapshot.get(key) for key in (
                "id", "window_start", "window_end", "built_at", "elapsed_seconds", "sources",
            )},
            "reused": bool(snapshot.get("reused")),
        },
        "budget_seconds": attention.ATTENTION_STAGE_BUDGET_SECONDS,
        "budget_scope": attention.ATTENTION_BUDGET_SCOPE,
        "elapsed_seconds": round(time.time() - started, 3),
        "references": references,
        "jev": jev,
        "excluded_sources": excluded_sources,
        "available": sum(status in {"ok", "no_matches"} for status in statuses),
        "unavailable": sum(status == "unavailable" for status in statuses),
        "matched": sum(status == "ok" for status in statuses),
        "observations": observations,
    }
    output = {
        **attention_artifact,
        "fresh": scored_fresh,
        "ongoing": scored_ongoing,
    }
    attention_unavailable = int(output.get("unavailable") or 0)
    attention_outcome = (
        "empty" if not fresh and not ongoing
        else "degraded" if attention_unavailable or jev.get("status") == "degraded"
        else "succeeded"
    )
    attention_reason = (
        "no candidates for attention"
        if attention_outcome == "empty"
        else f"{attention_unavailable} attention observation(s) unavailable; Jev {jev.get('status')}"
        if attention_outcome == "degraded"
        else None
    )
    runtime.complete_phase_json(
        state,
        "attention",
        output_path,
        output,
        outcome=attention_outcome,
        reason=attention_reason,
    )
    if not fresh and not ongoing:
        runtime.write_phase_status(output_path, status="empty", reason="no candidates for attention", inputs=phase_inputs)

    archive_path = runtime.ATTENTION_ARCHIVE_DIR / issue_date.isoformat() / f"{section}.json"
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    runtime.atomic_write_json(archive_path, attention_artifact)
    runtime.check_attention_health(attention_artifact, label=f"attention-{section}")
    print(
        f"  [done] attention — {attention_artifact['matched']} matched, "
        f"{attention_artifact['available'] - attention_artifact['matched']} measured zero, "
        f"{attention_artifact['unavailable']} unavailable"
        f"{f'; left out {sorted(excluded_sources)}' if excluded_sources else ''}; Jev {jev.get('status')} "
        f"({time.time() - started:.0f}s)"
    )
    return scored_fresh, scored_ongoing

@runtime.track_phase_failure("rank")
def phase_3_rank(
    topic: dict,
    fresh: list[dict],
    ongoing: list[dict],
    stories_in_flight: dict,
    run_dir: Path,
) -> tuple[list[dict], list[dict]]:
    """Phase 3: Deterministic priority ranking with caps.

    Pool A: Fresh findings
      - Sort by final product priority (editorial significance + observed attention)
      - Cap: FRESH_CAP (12)

    Pool B: Older articles (2-5 days old from Phase 2)
      - Sort by editorial-only priority, then publication recency
      - Cap: ONGOING_CAP (5)

    Pool C: qualified developing stories — does NOT enter Phase 4
      - Requires high editorial significance and evidence-backed movement on 2+ UTC dates
      - Sort by last_updated descending and cap at SIF_CAP (3)
      - Passed directly to Phase 6 with its evidence history and latest development

    Returns (phase_4_queue, sif_candidates).
    Phase 4 queue = Pool A + Pool B, with fresh first.
    """
    output_path = run_dir / "03-urls-ranked.json"
    other_topic_urls = load_cross_topic_urls(topic, run_dir)
    phase_inputs = runtime.phase_inputs(
        "rank", topic=topic,
        upstream={
            "fresh": runtime.canonical_fingerprint(fresh),
            "ongoing": runtime.canonical_fingerprint(ongoing),
            "stories_in_flight": runtime.canonical_fingerprint(stories_in_flight),
            "cross_topic_urls": sorted(other_topic_urls),
        },
        policy={"ranking_schema": RANKING_SCHEMA_VERSION},
    )
    state, cached = runtime.begin_or_load_phase(
        run_dir, "rank", inputs=phase_inputs, artifact_path=output_path,
        schema_version=RANKING_SCHEMA_VERSION, validator=lambda value: isinstance(value, dict),
    )
    if cached is not None:
        return cached.get("phase_4_queue", []), cached.get("sif_candidates", [])

    fresh = [normalize_editorial_significance(item) for item in fresh]
    ongoing = [normalize_editorial_significance(item) for item in ongoing]

    # Tag each finding with source_verdict for downstream phases
    for f in fresh:
        f["source_verdict"] = "fresh"
    for o in ongoing:
        o["source_verdict"] = "ongoing"

    # Remove stories already selected by an earlier topic before any article fetch.
    # The exact blocked set is part of the phase input fingerprint above.
    cross_topic_rejected = [
        {**item, "rejection_reason": "already selected by another digest today"}
        for item in fresh + ongoing
        if coverage_key(item.get("url", "")) in other_topic_urls
    ]
    eligible_fresh = [
        item for item in fresh
        if coverage_key(item.get("url", "")) not in other_topic_urls
    ]
    eligible_ongoing = [
        item for item in ongoing
        if coverage_key(item.get("url", "")) not in other_topic_urls
    ]
    # URL-host validation: a candidate whose URL sits on a publisher asset CDN
    # (e.g. assets.theregister.com) is not an article and must never reach
    # fetch or curation (digest-quality audit 2026-08-24: research invented
    # assets.theregister.com article links that 405'd; the tracker echoed them
    # in the daily Ongoing email for five days).
    asset_cdn_rejected = [
        item for item in eligible_fresh + eligible_ongoing
        if is_asset_cdn_url(item.get("url", ""))
    ]
    eligible_fresh = [
        item for item in eligible_fresh
        if not is_asset_cdn_url(item.get("url", ""))
    ]
    eligible_ongoing = [
        item for item in eligible_ongoing
        if not is_asset_cdn_url(item.get("url", ""))
    ]
    if asset_cdn_rejected:
        print(f"  [Phase 3 URL-host] rejected {len(asset_cdn_rejected)} "
              "asset-CDN URL(s) (not article hosts) before fetch")

    # Product priority combines editorial consequence with observed attention.
    pool_a = sorted(
        eligible_fresh,
        key=priority_sort_key,
        reverse=True,
    )[:FRESH_CAP]

    pool_b = sorted(
        eligible_ongoing,
        key=priority_sort_key,
        reverse=True,
    )[:ONGOING_CAP]

    # Pool C is the only source for the rendered Developing and Ongoing section.
    # Every candidate must already have high editorial significance and
    # evidence-backed movement on multiple dates, and must prove which source
    # supplied its latest summary so the card's headline/link match it.
    active_sif = []
    for story in stories_in_flight.get("stories", []):
        display = tracker_display_source(story)
        if (
            story.get("status") == "active"
            and is_developing_story(story)
            and display is not None
            and coverage_key(story.get("url", "")) not in other_topic_urls
            and coverage_key(display["url"]) not in other_topic_urls
            and not is_listing_url(story.get("url", ""))
            and not is_asset_cdn_url(story.get("url", ""))
        ):
            active_sif.append(story)
    pool_c = sorted(
        active_sif, key=lambda s: s.get("last_updated", ""), reverse=True
    )[:SIF_CAP]
    withheld = [
        story.get("url", "")
        for story in stories_in_flight.get("stories", [])
        if story.get("status") == "active"
        and is_developing_story(story)
        and tracker_display_source(story) is None
    ]
    if withheld:
        print(f"  [Phase 3 provenance] withheld {len(withheld)} tracked story(s) whose "
              "latest summary has no recorded source headline")

    phase_4_queue = pool_a + pool_b
    for item in phase_4_queue:
        item["ranking_schema_version"] = RANKING_SCHEMA_VERSION

    output = {
        "ranking_schema_version": RANKING_SCHEMA_VERSION,
        "phase_4_queue": phase_4_queue,
        "sif_candidates": pool_c,
        "pool_a": pool_a,
        "pool_b": pool_b,
        "cross_topic_rejected": cross_topic_rejected,
        "status": "ok" if phase_4_queue or pool_c else "empty",
        "reason": "" if phase_4_queue or pool_c else "no eligible URLs",
    }
    runtime.complete_phase_json(
        state,
        "rank",
        output_path,
        output,
        outcome="empty" if not phase_4_queue and not pool_c else "succeeded",
        reason=output["reason"] if not phase_4_queue and not pool_c else None,
    )
    if not phase_4_queue and not pool_c:
        runtime.write_phase_status(output_path, status="empty", reason=output["reason"], inputs=phase_inputs)
    print(f"  Phase 3 done: Pool A={len(pool_a)} fresh, Pool B={len(pool_b)} older, "
          f"Pool C={len(pool_c)} developing SIF → {len(phase_4_queue)} total for fetch")
    return phase_4_queue, pool_c

@runtime.track_phase_failure("fetch-summaries")
def phase_4_fetch(topic: dict, findings: list[dict], run_dir: Path) -> list[dict]:
    """Fetch and summarize articles with a shared cache and two-worker bound."""
    output_path = run_dir / "04-fetch-summaries.json"
    phase_inputs = runtime.phase_inputs(
        "fetch-summaries", topic=topic,
        upstream={"queue": runtime.canonical_fingerprint(findings)},
        policy={"ranking_schema": RANKING_SCHEMA_VERSION, "model": runtime._effective_model(runtime.MODEL)},
    )
    state, cached = runtime.begin_or_load_phase(
        run_dir, "fetch-summaries", inputs=phase_inputs, artifact_path=output_path,
        schema_version=RANKING_SCHEMA_VERSION, validator=lambda value: isinstance(value, list),
    )
    if cached is not None:
        return cached
    if not findings:
        runtime.complete_phase_json(
            state,
            "fetch-summaries",
            output_path,
            [],
            outcome="empty",
            reason="rank phase produced no fetch queue",
        )
        runtime.write_phase_status(output_path, status="empty", reason="rank phase produced no fetch queue", inputs=phase_inputs)
        return []
    pruned_cache_entries = runtime._prune_article_cache()
    if pruned_cache_entries:
        print(f"  [cache] pruned {pruned_cache_entries} expired/invalid entry(s)")

    system_prompt = (
        "You are a research assistant. Read ONE article with the read tool and produce a "
        "topic-neutral, detailed factual summary. Do not search. Write the summary and "
        "key_details in English even when the article is in another language. Return "
        "`title` in English: keep an English headline verbatim, and faithfully translate "
        "a non-English headline without adding facts or commentary.\n\n"
        "Output one JSON object in ```json fences with these fields:\n"
        '  {"title": "English article title", "url": "the URL you read", '
        '"date_confirmed": "YYYY-MM-DD or empty if not found in article", '
        '"author": "author name or empty", '
        '"summary": "2-4 sentence detailed summary capturing the main points", '
        '"key_details": ["bullet point 1", "bullet point 2", ...], '
        '"fetch_success": true|false}\n\n'
        "If the page fails to load or is not an article, set fetch_success=false "
        "and explain briefly in the summary field."
    )

    def _fetch_one(finding: dict) -> dict:
        url = finding.get("url", "")
        title = finding.get("title", "unknown")
        label = f"fetch:{title[:50]}"
        source = finding.get("source_verdict", "?")
        cached = runtime._load_article_cache(url, model=runtime.MODEL)
        if cached is not None:
            print(f"  [cache] [{source}] {label}")
            return {**finding, **cached, "url": url, "cache_hit": True}

        print(f"  [run ] [{source}] {label}")
        started = time.time()

        def _attempt(extra: str = "") -> dict:
            prompt = (
                f"Fetch this article: {url}\n\n"
                f"Title from research: {title}\n\n"
                "Use read to open the article. Then output your summary as JSON "
                "wrapped in ```json fences."
                f"{extra}"
            )
            raw = runtime._call_omp_p(
                prompt, model=runtime.MODEL, timeout=runtime.FETCH_TIMEOUT,
                append_system=system_prompt,
            )
            result = runtime._extract_json(raw, f"{label} output")
            if not isinstance(result, dict):
                raise ValueError(
                    f"fetch output is not a JSON object (got {type(result).__name__})")
            result["url"] = url
            return result

        try:
            result = _attempt()
        except Exception as first_error:
            # Retry once: model output sometimes truncates mid-JSON (no closing
            # fence) or comes back empty, which previously dropped the story
            # from the digest entirely. A fresh attempt with explicit brevity
            # instructions usually completes within the output limit.
            print(f"  [retry] {label} — attempt 1 failed: {first_error}; retrying once")
            try:
                result = _attempt(
                    "\n\nIMPORTANT: your previous response was truncated or invalid. "
                    "Output ONLY the complete JSON object in ```json fences, closed "
                    "properly. Keep the summary to 2-3 sentences and key_details to "
                    "at most 4 short bullets so the response is short enough to finish."
                )
            except Exception as error:
                elapsed = time.time() - started
                print(f"  [FAIL] {label} — {error} ({elapsed:.0f}s)")
                return {
                    **finding,
                    "fetch_success": False,
                    "summary": f"Fetch failed: {str(error)[:100]}",
                    "key_details": [],
                    "date_confirmed": "",
                    "author": "",
                    "cache_hit": False,
                }
        try:
            runtime._save_article_cache(url, result, model=runtime.MODEL)
        except OSError as cache_error:
            print(f"  [cache warn] {label} — {cache_error}")
        elapsed = time.time() - started
        status = "✓" if result.get("fetch_success", True) else "✗"
        print(f"  [done] {label} — {status} ({elapsed:.0f}s)")
        return {**finding, **result, "url": url, "cache_hit": False}

    workers = min(runtime.MAX_PARALLEL_FETCH, max(1, len(findings)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(_fetch_one, findings))

    successful = sum(1 for result in results if result.get("fetch_success", True))
    fetch_outcome = (
        "empty" if not results
        else "degraded" if successful == 0
        else "succeeded"
    )
    fetch_reason = (
        "all fetches produced no summaries"
        if fetch_outcome == "empty"
        else "all article fetches failed"
        if fetch_outcome == "degraded"
        else None
    )
    runtime.complete_phase_json(
        state,
        "fetch-summaries",
        output_path,
        results,
        outcome=fetch_outcome,
        reason=fetch_reason,
    )
    if not results:
        runtime.write_phase_status(output_path, status="empty", reason="all fetches produced no summaries", inputs=phase_inputs)
    cache_hits = sum(1 for result in results if result.get("cache_hit"))
    print(f"  Phase 4 done: {successful}/{len(results)} fetches successful, "
          f"{cache_hits} cache hit(s), concurrency={workers}")
    return results

@runtime.track_phase_failure("judge-summaries")
def phase_5_judge_summaries(topic: dict, summaries: list[dict], run_dir: Path) -> list[dict]:
    """Phase 5: Python date validation + batched LLM judge of summary accuracy.

    1. Python validates date_confirmed against calendar thresholds,
       cross-referencing with source_verdict (set by Phase 3):
       - date >= yesterday → ok (fresh, as expected)
       - date 2-5 days old + source_verdict=ongoing → ok (legitimate Pool B)
       - date 2-5 days old + source_verdict=fresh → drop (Phase 1/2 misclassified)
       - date >5 days old → auto-drop regardless
       - date missing → targeted re-fetch for date extraction, then re-check
    2. Surviving summaries go through batched LLM judge for faithfulness
       and completeness (date already verified, not re-checked).
    3. Python merges results.
    """
    output_path = run_dir / "05-summaries-judged.json"
    phase_inputs = runtime.phase_inputs(
        "judge-summaries", topic=topic,
        upstream={"summaries": runtime.canonical_fingerprint(summaries)},
        policy={"ranking_schema": RANKING_SCHEMA_VERSION, "model": runtime._effective_model(runtime.MODEL)},
    )
    state, cached = runtime.begin_or_load_phase(
        run_dir, "judge-summaries", inputs=phase_inputs, artifact_path=output_path,
        schema_version=RANKING_SCHEMA_VERSION, validator=lambda value: isinstance(value, list),
    )
    if cached is not None:
        return cached

    to_judge = [s for s in summaries if s.get("fetch_success", True)]
    failed = [s for s in summaries if not s.get("fetch_success", True)]

    if not to_judge:
        print("  Phase 5: no successful fetches to judge")
        runtime.complete_phase_json(
            state,
            "judge-summaries",
            output_path,
            summaries,
            outcome="skipped",
            reason="no successful fetches to judge",
        )
        runtime.write_phase_status(output_path, status="empty", reason="no successful fetches to judge", inputs=phase_inputs)
        return summaries

    print(f"  [run ] judge_summaries — {len(to_judge)} summaries to evaluate")
    t0 = time.time()

    # ── Step 1: Python date validation ──
    # Uses date_confirmed from Phase 4's actual article fetch — an independent
    # source from Phase 1's date_published. Cross-references with source_verdict
    # (set by Phase 3) to avoid penalizing legitimate ongoing articles.
    # Re-fetches only when date_confirmed is missing.
    now = datetime.now(timezone.utc)
    today = now.date()
    yesterday = today - timedelta(days=1)
    stale_cutoff = today - timedelta(days=5)

    validated: list[dict] = []
    date_dropped: list[dict] = []
    need_refetch: list[dict] = []

    for s in to_judge:
        dc = (s.get("date_confirmed") or "").strip()
        parsed = parse_date(dc)
        source = s.get("source_verdict", "fresh")
        if parsed is not None:
            d = parsed.date()
            if d >= yesterday:
                validated.append(s)
            elif d >= stale_cutoff and source == "ongoing":
                # Legitimate ongoing article — was intentionally included in Pool B
                validated.append(s)
            elif d >= stale_cutoff and source == "fresh":
                # Phase 1/2 tagged as fresh but Phase 4's fetch shows it's 2-5d old
                age = (today - d).days
                s["judge_verdict"] = "drop"
                s["judge_issues"] = [f"date_mismatch: tagged fresh but confirmed {dc} is {age}d old"]
                date_dropped.append(s)
            else:
                age = (today - d).days
                s["judge_verdict"] = "drop"
                s["judge_issues"] = [f"date_stale: confirmed {dc} is {age}d old (>5d cutoff)"]
                date_dropped.append(s)
        else:
            need_refetch.append(s)

    # Re-fetch dates for articles where Phase 4 didn't extract one
    if need_refetch:
        print(f"  Date validation: {len(need_refetch)} article(s) need date re-fetch")
        for s in need_refetch:
            url = s.get("url", "")
            title = s.get("title", "unknown")
            label = f"date-refetch:{title[:40]}"
            print(f"  [run ] {label}")
            t_refetch = time.time()
            try:
                refetched = refetch_article_date(url, title)
                elapsed = time.time() - t_refetch
                source = s.get("source_verdict", "fresh")
                if refetched:
                    s["date_confirmed"] = refetched
                    parsed = parse_date(refetched)
                    if parsed:
                        d = parsed.date()
                        if d >= yesterday:
                            validated.append(s)
                            print(f"  [done] {label} → {refetched} (fresh) ({elapsed:.0f}s)")
                        elif d >= stale_cutoff and source == "ongoing":
                            validated.append(s)
                            print(f"  [done] {label} → {refetched} (ok, ongoing) ({elapsed:.0f}s)")
                        elif d >= stale_cutoff and source == "fresh":
                            age = (today - d).days
                            s["judge_verdict"] = "drop"
                            s["judge_issues"] = [f"date_mismatch: tagged fresh but confirmed {refetched} is {age}d old"]
                            date_dropped.append(s)
                            print(f"  [done] {label} → {refetched} (mismatch, auto-dropped) ({elapsed:.0f}s)")
                        else:
                            age = (today - d).days
                            s["judge_verdict"] = "drop"
                            s["judge_issues"] = [f"date_stale: confirmed {refetched} is {age}d old (>5d cutoff)"]
                            date_dropped.append(s)
                            print(f"  [done] {label} → {refetched} (stale, auto-dropped) ({elapsed:.0f}s)")
                    else:
                        validated.append(s)
                        print(f"  [done] {label} → unparseable, passing to LLM ({elapsed:.0f}s)")
                else:
                    validated.append(s)
                    print(f"  [done] {label} → no date found, passing to LLM ({elapsed:.0f}s)")
            except Exception as e:
                elapsed = time.time() - t_refetch
                print(f"  [FAIL] {label} — {e} ({elapsed:.0f}s), passing to LLM")
                validated.append(s)

    # Hygiene (digest-quality audit 2026-08-29): every surviving candidate must
    # carry a parseable date_confirmed. When neither Phase 4's fetch nor the
    # Phase 5 re-fetch confirms a publication date, fall back explicitly to
    # Phase 1's date_published instead of shipping null. ai-tech 08-29 shipped
    # Hunyuan Hy4 and GLM-5.3 with date_confirmed=null; priority_sort_key's
    # `date_confirmed or date_published` fallback kept ranking deterministic,
    # but the null field is a schema-hygiene gap.
    for s in validated:
        dc = (s.get("date_confirmed") or "").strip()
        if not dc or parse_date(dc) is None:
            s["date_confirmed"] = (s.get("date_published") or "").strip()

    print(f"  Date validation: {len(validated)} pass, "
          f"{len(date_dropped)} auto-dropped (stale/mismatch), {len(need_refetch)} refetched")

    # ── Step 2: LLM judge (date pre-validated, no speculative DATE_CHECK) ──
    if validated:
        batches = batch(validated, BATCH_SIZE)
        print(f"  Batched into {len(batches)} LLM call(s) ({BATCH_SIZE}/batch)")
    else:
        batches = []

    system = (
        "You are a strict editor verifying AI-written summaries. You receive article "
        "summaries and judge whether each is accurate and faithful to what the article "
        "likely contains.\n\n"
        "NOTE: Publication dates have ALREADY been independently verified by fetching "
        "each article and extracting its visible publication date. Do NOT re-check dates.\n\n"
        "For each summary, evaluate:\n"
        "1. FAITHFULNESS: Does the summary contain plausible facts, or does it read "
        "like hallucinated/generic filler? Signs of hallucination: vague claims without "
        "specifics, details that seem wrong for the source, overly confident statements "
        "that sound made up.\n"
        "2. COMPLETENESS: Does the summary capture what the article is actually about? "
        "A summary that misses the main point is unhelpful.\n"
        "3. OVERALL: verdict = 'keep' | 'fix' (minor issues, note them) | 'drop' "
        "(unrecoverable — hallucinated, wrong, or empty)\n\n"
        "Output a JSON array of judgments wrapped in ```json fences, one per summary:\n"
        '  [{"url": "...", "verdict": "keep|fix|drop", "issues": ["issue 1", ...], '
        '"fixed_summary": "if fix, corrected summary, else empty"}, ...]\n\n'
        "Be suspicious. Summaries that sound too generic or lack specific names, "
        "numbers, or concrete claims are likely hallucinated — drop them."
    )

    all_judgments: list[dict] = []

    for batch_idx, batch_items in enumerate(batches):
        batch_json = json.dumps(batch_items, indent=2)
        user = (
            f"## Summaries to judge (batch {batch_idx + 1}/{len(batches)})\n\n"
            f"{batch_json}\n\n"
            "Judge each summary. Output a JSON array of judgments in ```json fences. "
            "Err on the side of dropping questionable summaries."
        )

        try:
            raw = runtime._call_llm_proxy(system, user, model=runtime.MODEL)
            judgments = runtime._extract_json(raw, f"judge_summaries batch {batch_idx + 1}")
            if not isinstance(judgments, list):
                judgments = [judgments]
            all_judgments.extend(judgments)
            print(f"  Batch {batch_idx + 1}: {len(judgments)} judgments received")
        except Exception as e:
            print(f"  [FAIL] judge_summaries batch {batch_idx + 1} — {e}, keeping all in batch")
            for summary in batch_items:
                all_judgments.append({"url": summary.get("url", ""), "verdict": "keep", "issues": [], "fixed_summary": ""})

    # ── Step 3: Apply judgments ──
    judged_map = {j.get("url", ""): j for j in all_judgments}
    results = []
    for s in summaries:
        url = s.get("url", "")
        # Preserve pre-set verdicts from date validation (already dropped)
        if s.get("judge_verdict"):
            results.append(s)
            continue
        j = judged_map.get(url, {})
        verdict = j.get("verdict", "keep")
        if s.get("fetch_success") is False:
            # A failed fetch is a hard drop, but record WHY so the drop is
            # auditable instead of silent (digest-quality audit 2026-08-19:
            # ai-tech shipped an empty Fresh section and 05-summaries-judged.json
            # showed fetch_success=false with empty judge_issues).
            verdict = "drop"
            issues = ["fetch_failed: article could not be fetched/summarized as confirmed"]
        else:
            issues = j.get("issues", [])
            if verdict == "fix" and j.get("fixed_summary"):
                s["summary"] = j["fixed_summary"]
        s["judge_verdict"] = verdict
        s["judge_issues"] = issues
        results.append(s)


    kept = sum(1 for r in results if r.get("judge_verdict") == "keep")
    fixed = sum(1 for r in results if r.get("judge_verdict") == "fix")
    dropped = sum(1 for r in results if r.get("judge_verdict") == "drop")
    elapsed = time.time() - t0
    print(f"  [done] judge_summaries — {kept} keep, {fixed} fix, {dropped} drop ({elapsed:.0f}s)")
    for r in results:
        if r.get("judge_verdict") in ("fix", "drop"):
            issues = "; ".join(r.get("judge_issues", ["unspecified"]))
            print(f"    {r['judge_verdict']} {r.get('title', '?')[:60]}: {issues[:120]}")

    runtime.complete_phase_json(
        state,
        "judge-summaries",
        output_path,
        results,
        outcome="empty" if not results else "succeeded",
        reason="summary judge returned no results" if not results else None,
    )
    if not results:
        runtime.write_phase_status(output_path, status="empty", reason="summary judge returned no results", inputs=phase_inputs)
    return results
