"""Daily News research phases 1 through 5."""
from __future__ import annotations

import json
import os
import re
import time
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import jev as jev_api

from . import attention, attention_match, attention_sources
from .attention import (
    SCHEMA_VERSION as ATTENTION_SCHEMA_VERSION,
    canonicalize_publisher_url,
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
def phase_1_research(topic: dict, run_dir: Path) -> list[dict]:
    """Phase 1: Run broad discovery across the topic's research angles.

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
        "HARD PAYWALLS: the article reader cannot open "
        f"{', '.join(sorted(HARD_PAYWALL_DOMAINS))}. When one of them reports a "
        "story, cite another outlet's article on the same event instead; if no "
        "other outlet has it, leave the story out.\n\n"
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
        "but never estimate popularity, virality, audience interest, or an attention score.\n\n"
        "Never construct URLs — only use URLs that appeared in web_search results. "
        "Target 5-8 findings. Be quick — search, compile, output JSON.\n\n"
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
        else:
            if failure_msg is None:
                # HTTP 200 but empty discovery is degraded rather than a
                # trustworthy "nothing happened" result.
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
def phase_2_judge_research(topic: dict, findings: list[dict], run_dir: Path) -> list[dict]:
    """Phase 2: Python date pre-tagging + batched LLM judge.

    1. Python parses date_published; findings published before yesterday (or
       undated) are dropped as stale without touching the LLM.
    2. Findings are split into batches of BATCH_SIZE.
    3. Each batch gets one LLM call with topic rules and editorial-significance rubric.
    4. Python resolves each approval to its source finding (keeping only the
       judge's editorial_significance), records unresolvable approvals, and
       enforces cross-batch dedup.

    Before any judging, the shared recent-coverage ledger removes findings any
    section covered in the previous CROSS_DAY_DEDUP_DAYS days (canonical story
    and referenced URLs).

    Returns the fresh findings.
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
        return cached.get("fresh", [])

    print(f"  [run ] judge_research — {len(findings)} findings to evaluate")
    t0 = time.time()

    # ── Step 1: Python date pre-tagging ──
    yesterday = today - timedelta(days=1)
    for finding in findings:
        normalize_editorial_significance(finding)
        if finding.get("url"):
            finding["url"] = canonicalize_publisher_url(finding["url"])

    pre_tagged: list[dict] = []
    too_old_count = 0
    ledger_rejected: list[dict] = []

    for f in findings:
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
        else:
            too_old_count += 1

    print(f"  Date pre-tag: {len(pre_tagged)} fresh, {too_old_count} too_old, "
          f"{len(ledger_rejected)} covered by a section in the previous "
          f"{CROSS_DAY_DEDUP_DAYS} days (dropped)")

    if not pre_tagged:
        print(f"  [done] judge_research — all findings too old or no date")
        output = {"fresh": [], "rejected": ledger_rejected, "status": "empty",
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
        return []

    # ── Step 2: Batch LLM calls ──
    # Each finding carries a run-local id through the judge so Step 3 restores
    # metadata from the finding itself, never from another finding that shares
    # its URL (digest-quality audit 2026-09-29: two ai-hardware 09-28 findings
    # shared a TechPowerUp archive URL and one's event metadata shipped on the
    # other when the restore was keyed by URL alone).
    for index, finding in enumerate(pre_tagged):
        finding["finding_id"] = f"f{index}"
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
        "`finding_id`, `research_angle_id`, `date_tag`, `event`, `event_terms`, "
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
            # Approvals may come back as bare finding_id strings; Step 3
            # resolves every shape to a source finding.
            batch_rejected = [r if isinstance(r, dict) else {"finding": {"title": str(r)}, "reason": "unknown"} for r in batch_rejected]
            all_approved.extend(batch_approved)
            all_rejected.extend(batch_rejected)
            print(f"  Batch {batch_idx + 1}: {len(batch_approved)} approved, {len(batch_rejected)} rejected")
        except Exception as e:
            print(f"  [FAIL] judge_research batch {batch_idx + 1} — {e}, treating all as approved")
            all_approved.extend(batch_items)

    # ── Step 3: Resolve approvals to source findings, then deterministic dedup ──
    # Every approval becomes a deep copy of exactly one source finding; the
    # judge's only kept change is editorial_significance. Resolution: a bare
    # string equal to a finding_id; a dict's known finding_id, unless its URL is
    # another source finding's URL (ambiguous); else a URL exactly one source
    # finding carries. A finding without a valid id on a URL several source
    # findings share cannot be told apart, so it is rejected rather than given
    # another finding's event or terms. Nothing approved disappears without a
    # recorded reason (agentic-platform 2026-10-05: three approvals with
    # judge-altered URLs and no date_tag vanished between the judge and `fresh`).
    seen_urls: set[str] = set()
    fresh: list[dict] = []
    dedup_rejected: list[dict] = []
    unresolved: list[dict] = []
    original_by_id = {f["finding_id"]: f for f in pre_tagged}
    originals_by_url: dict[str, list[dict]] = {}
    for f in pre_tagged:
        if normalize_url(f.get("url", "")):
            originals_by_url.setdefault(normalize_url(f.get("url", "")), []).append(f)

    for item in all_approved:
        judged = item if isinstance(item, dict) else {}
        source = None
        if isinstance(item, str):
            source = original_by_id.get(item.strip())
        elif judged:
            judged_url = normalize_url(str(judged.get("url") or ""))
            same_url = originals_by_url.get(judged_url, [])
            finding_id = judged.get("finding_id")
            source = original_by_id.get(finding_id) if isinstance(finding_id, str) else None
            if source is not None:
                if same_url and judged_url != normalize_url(source.get("url", "")):
                    unresolved.append({"finding": item, "reason": "ambiguous_judge_output"})
                    continue
            elif len(same_url) == 1:
                source = same_url[0]
            elif len(same_url) > 1:
                dedup_rejected.append({"finding": item, "reason": "unidentified_shared_url"})
                continue
        if source is None:
            unresolved.append({"finding": item, "reason": "unmatched_judge_output"})
            continue
        f = deepcopy(source)
        significance = judged.get("editorial_significance") or judged.get("importance")
        if significance:
            f["editorial_significance"] = significance
            normalize_editorial_significance(f)
        url = normalize_url(f.get("url", ""))
        if url and url in seen_urls:
            dedup_rejected.append({"finding": f, "reason": "crossbatch_duplicate"})
        elif coverage_key(f.get("url", "")) in recent_coverage:
            dedup_rejected.append({"finding": f, "reason": "already_covered_previous_day"})
        else:
            if url:
                seen_urls.add(url)
            fresh.append(f)

    for f in pre_tagged + all_approved + fresh + [
        r.get("finding") for r in all_rejected + dedup_rejected + unresolved
        if isinstance(r, dict)
    ]:
        if isinstance(f, dict):
            f.pop("finding_id", None)

    if unresolved:
        print(f"  [WARN] judge_research — {len(unresolved)} approved item(s) could not be "
              "matched to a source finding")
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
    dedup_rejected += unresolved

    elapsed = time.time() - t0
    print(f"  [done] judge_research — {len(fresh)} fresh, "
          f"{len(all_rejected) + len(dedup_rejected)} rejected ({elapsed:.0f}s)")
    for r in all_rejected[:5]:
        finding = r.get("finding", {}) if isinstance(r, dict) else {}
        reason = r.get("reason", "unspecified") if isinstance(r, dict) else "unknown"
        title = finding.get('title', '?') if isinstance(finding, dict) else str(finding)[:60]
        print(f"    ✗ {title[:60]}: {reason}")
    if len(all_rejected) > 5:
        print(f"    ... and {len(all_rejected) - 5} more rejected")

    output = {"fresh": fresh, "rejected": all_rejected + dedup_rejected,
              "status": "ok" if fresh else "empty",
              "reason": "" if fresh else "no findings passed research judgment"}
    runtime.complete_phase_json(
        state,
        "judge-research",
        output_path,
        output,
        outcome="succeeded" if fresh else "empty",
        reason=None if fresh else output["reason"],
    )
    if not fresh:
        runtime.write_phase_status(output_path, status="empty", reason=output["reason"], inputs=phase_inputs)
    return fresh

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
def phase_2b_attention(topic: dict, fresh: list[dict], run_dir: Path) -> list[dict]:
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
        return cached.get("fresh", [])

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
        fresh, client, section_label=topic["web_title"],
    )
    scored_fresh, observations = attention.score_attention(
        fresh, section=section, evidence=evidence, importance=importance,
        measured_sources=measured_sources, references=references, window_end=window_end,
    )

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
    }
    attention_unavailable = int(output.get("unavailable") or 0)
    attention_outcome = (
        "empty" if not fresh
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
    if not fresh:
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
    return scored_fresh

# A research finding is the same story as a paywalled candidate when they share
# a normalized event term and their title+event wording overlaps this much.
# Calibrated on September 2026 01-research-raw.json pairs: at or above it every
# pair sharing a term described one event; below it pairs diverged.
PAYWALL_ALTERNATE_MIN_OVERLAP = 0.3

# Another outlet's version of a queued story Phase 4 may fetch when the
# primary URL fails (2026-10-01: AP and Axios 403'd on the day's top story
# while Guardian/SiliconANGLE versions were fetchable).
FETCH_ALTERNATE_LIMIT = 2

def _story_terms(finding: dict) -> set[str]:
    return {
        " ".join(attention_match.toks(term))
        for term in finding.get("event_terms") or []
        if attention_match.toks(term)
    }

def _story_tokens(finding: dict) -> set[str]:
    return set(attention_match.toks(
        f"{finding.get('title', '')} {finding.get('event') or ''}"
    ))

def _same_story_overlap(candidate: dict, other: dict) -> float:
    """Title+event token Jaccard when two findings share an event term, else 0."""
    if not _story_terms(candidate) & _story_terms(other):
        return 0.0
    left, right = _story_tokens(candidate), _story_tokens(other)
    union = left | right
    return len(left & right) / len(union) if union else 0.0

def _fetchable_alternate_url(url: str) -> str:
    """Canonical URL when it may replace a paywalled one, else empty."""
    url = canonicalize_publisher_url(url or "")
    if not url or hard_paywall_domain(url) or is_asset_cdn_url(url) or is_listing_url(url):
        return ""
    return url

def _research_alternates(research_findings: list[dict]) -> list[dict]:
    """Research findings whose canonical URL may stand in for another outlet's."""
    alternates = []
    for finding in research_findings:
        url = _fetchable_alternate_url(finding.get("url", "")) if isinstance(finding, dict) else ""
        if url:
            alternates.append({**finding, "url": url})
    return alternates

def _alternate_candidates(item: dict, research_alternates: list[dict], blocked_keys: set[str]) -> list[dict]:
    """Ordered other-outlet versions of ``item``'s story.

    Research findings for the same story come first (best overlap first, ties
    keep research order), then the item's Phase 2b ``same_event_urls`` in
    order. Every entry is fetchable, on another registrable domain than the
    item, outside ``blocked_keys`` and unique by coverage key.
    """
    own_domain = attention_match.registrable_domain(item.get("url", ""))
    seen: set[str] = set()

    def usable(url: str) -> bool:
        if not url:
            return False
        key = coverage_key(url)
        if key in blocked_keys or key in seen:
            return False
        if own_domain and attention_match.registrable_domain(url) == own_domain:
            return False
        seen.add(key)
        return True

    scored = [(_same_story_overlap(item, alternate), alternate) for alternate in research_alternates]
    scored = sorted(
        (pair for pair in scored if pair[0] >= PAYWALL_ALTERNATE_MIN_OVERLAP),
        key=lambda pair: pair[0], reverse=True,
    )
    candidates: list[dict] = []
    for overlap, alternate in scored:
        url = alternate["url"]
        if not usable(url):
            continue
        entry = {
            "url": url,
            "title": alternate.get("title") or item.get("title", ""),
            "source_domain": alternate.get("source_domain") or attention_match.registrable_domain(url),
            "origin": "research",
            "overlap": round(overlap, 3),
        }
        for field in ("date_published", "summary"):
            if alternate.get(field):
                entry[field] = alternate[field]
        candidates.append(entry)
    same_event = ((item.get("attention") or {}).get("evidence") or {}).get("same_event_urls") or []
    for entry in same_event:
        url = _fetchable_alternate_url(entry.get("url", "")) if isinstance(entry, dict) else ""
        if not usable(url):
            continue
        candidates.append({
            "url": url,
            "title": entry.get("title") or item.get("title", ""),
            "source_domain": entry.get("domain") or attention_match.registrable_domain(url),
            "origin": f"attention:{entry.get('source', '')}",
            "overlap": None,
        })
    return candidates

def resolve_hard_paywalls(
    candidates: list[dict],
    research_findings: list[dict],
    blocked_keys: set[str],
) -> tuple[list[dict], list[dict], list[dict]]:
    """Keep hard-paywalled candidates away from Phase 4.

    Each candidate on HARD_PAYWALL_DOMAINS takes, in order: the research
    finding that best matches its story, else the first of its Phase 2b
    ``same_event_urls`` (publisher articles Jev judged to report the same
    event). Without either, the candidate is dropped. An alternate URL is
    fetchable, substitutes at most once, never duplicates a URL already ranked
    on its own, and never has a blocked coverage key.
    Returns (kept, substituted, dropped); the last two are audit records.
    """
    taken = {coverage_key(item.get("url", "")) for item in candidates} | set(blocked_keys)
    alternates = _research_alternates(research_findings)

    kept: list[dict] = []
    substituted: list[dict] = []
    dropped: list[dict] = []
    for item in candidates:
        domain = hard_paywall_domain(item.get("url", ""))
        if domain is None:
            kept.append(item)
            continue
        options = _alternate_candidates(item, alternates, taken)
        if not options:
            dropped.append({
                **item,
                "rejection_reason": (
                    f"hard-paywalled source ({domain}); no fetchable research "
                    "finding or same-event attention URL for the story"
                ),
            })
            continue
        best = options[0]
        replacement = {key: best[key] for key in ("url", "title", "source_domain")}
        if best["origin"] == "research":
            replacement["date_published"] = best.get("date_published") or item.get("date_published", "")
            replacement["summary"] = best.get("summary") or item.get("summary", "")
        taken.add(coverage_key(replacement["url"]))
        kept.append({**item, **replacement, "paywall_substituted_from": item.get("url", "")})
        substituted.append({
            "paywall_domain": domain,
            "original_url": item.get("url", ""),
            "original_title": item.get("title", ""),
            "alternate_url": replacement["url"],
            "alternate_title": replacement["title"],
            "alternate_origin": best["origin"],
            "overlap": best["overlap"],
        })
    return kept, substituted, dropped

def assign_fetch_alternates(
    queue: list[dict],
    research_findings: list[dict],
    blocked_keys: set[str],
) -> None:
    """Give each queue item up to FETCH_ALTERNATE_LIMIT ordered ``fetch_alternates``.

    Alternates follow the paywall-swap rules and never point at any queue
    item's own URL; Phase 4 tries them only when the primary fetch fails.
    """
    alternates = _research_alternates(research_findings)
    blocked = set(blocked_keys) | {coverage_key(item.get("url", "")) for item in queue}
    for item in queue:
        item["fetch_alternates"] = _alternate_candidates(item, alternates, blocked)[:FETCH_ALTERNATE_LIMIT]

@runtime.track_phase_failure("rank")
def phase_3_rank(
    topic: dict,
    fresh: list[dict],
    run_dir: Path,
    research_findings: list[dict] | None = None,
) -> list[dict]:
    """Phase 3: Deterministic priority ranking with a cap.

    Pool A: Fresh findings
      - Sort by final product priority (editorial significance + observed attention)
      - Cap: FRESH_CAP (12)

    Before the cap, a candidate on a hard-paywalled domain takes the URL of a
    fetchable ``research_findings`` entry for the same story, else one of its
    Jev-judged same-event attention URLs, or is dropped; both outcomes are
    recorded in the artifact. After the cap, each queue item carries ordered
    ``fetch_alternates`` (same sources and rules) for Phase 4 fetch failures.

    Returns the Phase 4 queue (Pool A).
    """
    output_path = run_dir / "03-urls-ranked.json"
    other_topic_urls = load_cross_topic_urls(topic, run_dir)
    research_findings = research_findings or []
    # Paywall alternates come from raw research and the attention snapshot, so
    # they must clear the previous-days coverage ledger Phase 2 applied.
    recent_coverage = load_recent_coverage_ledger(
        run_dir.parent.parent, runtime.issue_date_for_run(run_dir), CROSS_DAY_DEDUP_DAYS,
    )
    phase_inputs = runtime.phase_inputs(
        "rank", topic=topic,
        upstream={
            "fresh": runtime.canonical_fingerprint(fresh),
            "cross_topic_urls": sorted(other_topic_urls),
            "research_findings": runtime.canonical_fingerprint(research_findings),
            "covered_urls": sorted(recent_coverage),
        },
        policy={
            "ranking_schema": RANKING_SCHEMA_VERSION,
            "hard_paywall_domains": sorted(HARD_PAYWALL_DOMAINS),
            "fetch_alternate_limit": FETCH_ALTERNATE_LIMIT,
        },
    )
    state, cached = runtime.begin_or_load_phase(
        run_dir, "rank", inputs=phase_inputs, artifact_path=output_path,
        schema_version=RANKING_SCHEMA_VERSION, validator=lambda value: isinstance(value, dict),
    )
    if cached is not None:
        return cached.get("phase_4_queue", [])

    fresh = [normalize_editorial_significance(item) for item in fresh]

    # Tag each finding with source_verdict for downstream phases
    for f in fresh:
        f["source_verdict"] = "fresh"

    # Remove stories already selected by an earlier topic before any article fetch.
    # The exact blocked set is part of the phase input fingerprint above.
    cross_topic_rejected = [
        {**item, "rejection_reason": "already selected by another digest today"}
        for item in fresh
        if coverage_key(item.get("url", "")) in other_topic_urls
    ]
    eligible_fresh = [
        item for item in fresh
        if coverage_key(item.get("url", "")) not in other_topic_urls
    ]
    # URL-host validation: a candidate whose URL sits on a publisher asset CDN
    # (e.g. assets.theregister.com) is not an article and must never reach
    # fetch or curation (digest-quality audit 2026-08-24: research invented
    # assets.theregister.com article links that 405'd).
    asset_cdn_rejected = [
        item for item in eligible_fresh
        if is_asset_cdn_url(item.get("url", ""))
    ]
    eligible_fresh = [
        item for item in eligible_fresh
        if not is_asset_cdn_url(item.get("url", ""))
    ]
    if asset_cdn_rejected:
        print(f"  [Phase 3 URL-host] rejected {len(asset_cdn_rejected)} "
              "asset-CDN URL(s) (not article hosts) before fetch")

    # Hard paywalls never reach Phase 4: swap in a fetchable same-story URL or
    # drop the story before the cap, so it frees its slot
    # (September 2026: 11 of 12 washingtonpost.com fetches failed).
    eligible_fresh, paywall_substituted, paywall_dropped = resolve_hard_paywalls(
        eligible_fresh,
        research_findings,
        other_topic_urls | recent_coverage,
    )
    if paywall_substituted or paywall_dropped:
        print(f"  [Phase 3 paywall] {len(paywall_substituted)} story(s) moved to a "
              f"fetchable source, {len(paywall_dropped)} dropped before fetch")

    # Product priority combines editorial consequence with observed attention.
    pool_a = sorted(
        eligible_fresh,
        key=priority_sort_key,
        reverse=True,
    )[:FRESH_CAP]

    phase_4_queue = pool_a
    for item in phase_4_queue:
        item["ranking_schema_version"] = RANKING_SCHEMA_VERSION
    # Phase 4 falls back to these when a primary fetch fails; they clear the
    # same blocked keys as the paywall swap.
    assign_fetch_alternates(phase_4_queue, research_findings, other_topic_urls | recent_coverage)

    output = {
        "ranking_schema_version": RANKING_SCHEMA_VERSION,
        "phase_4_queue": phase_4_queue,
        "pool_a": pool_a,
        "cross_topic_rejected": cross_topic_rejected,
        "paywall_substituted": paywall_substituted,
        "paywall_dropped": paywall_dropped,
        "status": "ok" if phase_4_queue else "empty",
        "reason": "" if phase_4_queue else "no eligible URLs",
    }
    runtime.complete_phase_json(
        state,
        "rank",
        output_path,
        output,
        outcome="succeeded" if phase_4_queue else "empty",
        reason=None if phase_4_queue else output["reason"],
    )
    if not phase_4_queue:
        runtime.write_phase_status(output_path, status="empty", reason=output["reason"], inputs=phase_inputs)
    print(f"  Phase 3 done: Pool A={len(pool_a)} fresh → {len(phase_4_queue)} total for fetch")
    return phase_4_queue

@runtime.track_phase_failure("fetch-summaries")
def phase_4_fetch(topic: dict, findings: list[dict], run_dir: Path) -> list[dict]:
    """Fetch and summarize articles with a shared cache and two-worker bound.

    A failed primary fetch falls back to the item's ``fetch_alternates`` (one
    attempt each, at most FETCH_ALTERNATE_LIMIT waves) unless another record
    already fetched the same story.
    """
    output_path = run_dir / "04-fetch-summaries.json"
    phase_inputs = runtime.phase_inputs(
        "fetch-summaries", topic=topic,
        upstream={"queue": runtime.canonical_fingerprint(findings)},
        policy={
            "ranking_schema": RANKING_SCHEMA_VERSION,
            "model": runtime._effective_model(runtime.MODEL),
            "fetch_alternate_limit": FETCH_ALTERNATE_LIMIT,
        },
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

    def _summarize(url: str, title: str, label: str, extra: str = "") -> dict:
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

    def _save_cache(url: str, result: dict, label: str) -> None:
        try:
            runtime._save_article_cache(url, result, model=runtime.MODEL)
        except OSError as cache_error:
            print(f"  [cache warn] {label} — {cache_error}")

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
        try:
            result = _summarize(url, title, label)
        except Exception as first_error:
            # Retry once: model output sometimes truncates mid-JSON (no closing
            # fence) or comes back empty, which previously dropped the story
            # from the digest entirely. A fresh attempt with explicit brevity
            # instructions usually completes within the output limit.
            print(f"  [retry] {label} — attempt 1 failed: {first_error}; retrying once")
            try:
                result = _summarize(
                    url, title, label,
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
        _save_cache(url, result, label)
        elapsed = time.time() - started
        status = "✓" if result.get("fetch_success", True) else "✗"
        print(f"  [done] {label} — {status} ({elapsed:.0f}s)")
        return {**finding, **result, "url": url, "cache_hit": False}

    def _fetch_alternate(job: tuple[dict, dict]) -> tuple[dict | None, str]:
        """One attempt at another outlet's version: (record, "") or (None, reason)."""
        finding, alternate = job
        url = alternate["url"]
        label = f"fetch-alt:{alternate.get('title', '')[:50]}"
        result = runtime._load_article_cache(url, model=runtime.MODEL)
        cache_hit = result is not None
        if not cache_hit:
            try:
                result = _summarize(url, alternate.get("title") or "unknown", label)
            except Exception as error:
                return None, str(error)[:200]
            if not result.get("fetch_success", True):
                return None, str(result.get("summary") or "fetch_success=false")[:200]
            _save_cache(url, result, label)
        replacement = {key: alternate[key] for key in ("url", "title", "source_domain")}
        if alternate.get("date_published"):
            replacement["date_published"] = alternate["date_published"]
        return {
            **finding,
            **replacement,
            **result,
            "url": url,
            "cache_hit": cache_hit,
            "fetch_substituted_from": finding.get("url", ""),
            "fetch_alternate_origin": alternate.get("origin", ""),
        }, ""

    def _fetched(record: dict) -> bool:
        return bool(record.get("fetch_success", True))

    def _covered_by(record: dict, others: list[dict]) -> bool:
        return any(
            _same_story_overlap(record, other) >= PAYWALL_ALTERNATE_MIN_OVERLAP for other in others
        )

    workers = min(runtime.MAX_PARALLEL_FETCH, max(1, len(findings)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(_fetch_one, findings))

        # Substitution pass: a failed primary tries another outlet's version of
        # its story, in queue order, without fetching one story twice.
        claimed = {coverage_key(finding.get("url", "")) for finding in findings}
        claimed |= {coverage_key(record.get("url", "")) for record in results if _fetched(record)}
        next_alternate = [0] * len(findings)
        tried: dict[int, list[dict]] = {}
        pending = [index for index, record in enumerate(results) if not _fetched(record)]

        # Story matching uses the queued finding: a failed fetch's title is
        # whatever the model echoed back.
        def _skip_if_covered(index: int) -> bool:
            if not _covered_by(findings[index], [other for other in results if _fetched(other)]):
                return False
            results[index]["fetch_alternate_skipped"] = "same story already fetched"
            print(f"  [alt skip] {findings[index].get('title', '')[:50]} — same story already fetched")
            return True

        for _wave in range(FETCH_ALTERNATE_LIMIT):
            jobs: list[tuple[int, dict]] = []
            deferred: list[int] = []
            for index in pending:
                if _skip_if_covered(index):
                    continue
                if _covered_by(findings[index], [findings[other] for other, _ in jobs]):
                    # A same-story item is trying an alternate this wave.
                    deferred.append(index)
                    continue
                alternates = findings[index].get("fetch_alternates") or []
                while next_alternate[index] < len(alternates):
                    alternate = alternates[next_alternate[index]]
                    next_alternate[index] += 1
                    key = coverage_key(alternate["url"])
                    if key not in claimed:
                        claimed.add(key)
                        jobs.append((index, alternate))
                        break
            if not jobs:
                pending = []
                break
            outcomes = list(pool.map(
                _fetch_alternate, [(findings[index], alternate) for index, alternate in jobs],
            ))
            pending = deferred
            for (index, alternate), (record, reason) in zip(jobs, outcomes):
                if record is not None:
                    results[index] = record
                    print(f"  [alt done] {findings[index].get('title', '')[:50]} — "
                          f"{findings[index].get('url', '')} → {alternate['url']} ({alternate.get('origin', '')})")
                else:
                    tried.setdefault(index, []).append({"url": alternate["url"], "reason": reason})
                    pending.append(index)
            pending.sort()
        # Items left after the last wave may now be covered by a substitution.
        for index in pending:
            _skip_if_covered(index)
        for index, attempts in tried.items():
            if not _fetched(results[index]):
                results[index]["fetch_alternates_tried"] = attempts
                print(f"  [alt FAIL] {findings[index].get('title', '')[:50]} — "
                      f"{len(attempts)} alternate(s) failed; story dropped")
    for record in results:
        record.pop("fetch_alternates", None)

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

    1. Python validates date_confirmed against calendar thresholds:
       - date >= yesterday → ok (fresh, as expected)
       - date 2-5 days old → drop (Phase 1/2 misclassified it as fresh)
       - date >5 days old → auto-drop
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
    # source from Phase 1's date_published. Re-fetches only when
    # date_confirmed is missing.
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
        if parsed is not None:
            d = parsed.date()
            if d >= yesterday:
                validated.append(s)
            elif d >= stale_cutoff:
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
                if refetched:
                    s["date_confirmed"] = refetched
                    parsed = parse_date(refetched)
                    if parsed:
                        d = parsed.date()
                        if d >= yesterday:
                            validated.append(s)
                            print(f"  [done] {label} → {refetched} (fresh) ({elapsed:.0f}s)")
                        elif d >= stale_cutoff:
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
