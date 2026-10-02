"""Daily News editorial phase 6 curation."""
from __future__ import annotations

import copy
import hashlib
import json
import re
import subprocess
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import runtime
from .catalog import *
from .contracts import *
from .attention import normalize_editorial_significance, priority_sort_key

def editorial_candidate_id(candidate: dict) -> str:
    identity = normalize_url(candidate.get("url", "")) or candidate.get("title", "")
    return f"candidate-{hashlib.sha256(identity.encode()).hexdigest()[:12]}"

def clean_editorial_text(value: Any, fallback: str = "", limit: int = 1200) -> str:
    source = value if isinstance(value, str) and value.strip() else fallback
    text = " ".join(source.split()) if isinstance(source, str) else ""
    if len(text) <= limit:
        return text
    clipped = text[:limit + 1].rsplit(" ", 1)[0].rstrip(" ,;:-")
    return f"{clipped}…"

def summarize_model_error(error: Exception) -> str:
    if isinstance(error, subprocess.TimeoutExpired):
        return f"timed out after {error.timeout}s"
    return " ".join(str(error).split())[:500]

def prepare_editorial_candidates(
    summaries: list[dict],
    blocked_urls: set[str],
) -> tuple[list[dict], list[dict]]:
    kept = [item for item in summaries if item.get("judge_verdict") in ("keep", "fix")]
    rejected = [item for item in summaries if item.get("judge_verdict") == "drop"]
    seen: set[str] = set()
    eligible: list[dict] = []
    for item in kept:
        normalized = normalize_url(item.get("url", ""))
        if not normalized or normalized in seen or coverage_key(item.get("url", "")) in blocked_urls:
            continue
        seen.add(normalized)
        candidate = normalize_editorial_significance(copy.deepcopy(item))
        candidate["candidate_id"] = editorial_candidate_id(candidate)
        eligible.append(candidate)

    eligible = sorted(
        eligible,
        key=priority_sort_key,
        reverse=True,
    )
    return eligible[:15], rejected

def validate_editorial_proposal(
    proposal: dict,
    candidates: list[dict],
    blocked_urls: set[str] | None = None,
    *,
    issue_date: date | None = None,
) -> tuple[dict, list[str]]:
    """Validate model IDs and return a bounded, source-backed proposal."""
    if not isinstance(proposal, dict):
        raise ValueError("editorial proposal must be a JSON object")

    blocked = blocked_urls or set()
    warnings: list[str] = []
    today = issue_date or datetime.now(timezone.utc).date()
    yesterday = today - timedelta(days=1)
    candidate_by_id = {
        candidate["candidate_id"]: candidate
        for candidate in candidates
        if candidate.get("candidate_id")
    }

    fresh: list[dict] = []
    selected_ids: set[str] = set()
    raw_fresh = proposal.get("selected_fresh", [])
    if not isinstance(raw_fresh, list):
        warnings.append("selected_fresh was not a list")
        raw_fresh = []
    for item in raw_fresh:
        if not isinstance(item, dict):
            warnings.append("ignored non-object fresh selection")
            continue
        candidate_id = item.get("candidate_id", "")
        source = candidate_by_id.get(candidate_id)
        if source is None:
            warnings.append(f"ignored unknown candidate_id {candidate_id!r}")
            continue
        normalized = normalize_url(source.get("url", ""))
        if coverage_key(source.get("url", "")) in blocked:
            warnings.append(f"ignored cross-topic duplicate {candidate_id}")
            continue
        if is_listing_url(source.get("url", "")):
            # A section/date archive page is not an article (digest-quality
            # audit 2026-08-21: Guardian /all listing URLs were selected as
            # world stories).
            warnings.append(f"dropped listing URL fresh selection {candidate_id}")
            continue
        if is_asset_cdn_url(source.get("url", "")):
            # A publisher asset-CDN host is not an article host; the link is
            # dead on arrival (digest-quality audit 2026-08-24:
            # assets.theregister.com research links 405'd).
            warnings.append(f"dropped asset-CDN fresh selection {candidate_id}")
            continue
        if candidate_id in selected_ids:
            warnings.append(f"ignored duplicate fresh selection {candidate_id}")
            continue
        if not is_fresh_eligible(source, yesterday):
            # Deterministic freshness gate: a candidate older than yesterday
            # must never ship under "Fresh — Last 24 Hours", even when the
            # model selected it and the critic missed it (digest-quality audit
            # 2026-08-12: ai-hardware + agentic-platform shipped stale stories
            # under Fresh), and a future-dated candidate must not either
            # (digest-quality audit 2026-08-14: a 2026-10-15-dated story shipped
            # under Fresh). The candidate is treated as unselected.
            stale_date = candidate_fresh_date(source)
            kind = "future-dated" if stale_date.date() > yesterday else "stale"
            warnings.append(
                f"dropped {kind} fresh selection {candidate_id} "
                f"(best date {stale_date.date().isoformat()} is outside the 24h window)"
            )
            continue
        selected_ids.add(candidate_id)
        fresh.append({
            "candidate_id": candidate_id,
            "rank": len(fresh) + 1,
            "editorial_summary": clean_editorial_text(
                item.get("editorial_summary", item.get("summary")),
                source.get("summary", ""),
            ),
            "selection_reason": clean_editorial_text(
                item.get("selection_reason", item.get("reason")), limit=400
            ),
        })
        if len(fresh) == 7:
            if len(raw_fresh) > 7:
                warnings.append("capped selected_fresh at 7")
            break

    domains: dict[str, int] = {}
    for item in fresh:
        source = candidate_by_id[item["candidate_id"]]
        domain = source.get("source_domain") or urlsplit(source.get("url", "")).hostname or ""
        domains[domain] = domains.get(domain, 0) + 1
    concentrated = sorted(domain for domain, count in domains.items() if domain and count > 2)
    if concentrated:
        warnings.append(f"source concentration above 2: {', '.join(concentrated)}")
        # Enforce the cap: keep the two highest-ranked candidates per over-limit
        # domain and drop the lower-ranked same-source selections, so a
        # single-source Fresh section can no longer ship (digest-quality audit
        # 2026-08-14: ai-tech shipped 5 TechCrunch stories, ai-hardware 4 Data
        # Center Dynamics stories). `fresh` is already in rank order.
        capped: list[dict] = []
        per_domain: dict[str, int] = {}
        for item in fresh:
            source = candidate_by_id[item["candidate_id"]]
            domain = source.get("source_domain") or urlsplit(source.get("url", "")).hostname or ""
            if domain in concentrated:
                if per_domain.get(domain, 0) >= 2:
                    warnings.append(
                        f"dropped fresh selection {item['candidate_id']} "
                        f"(source concentration cap: max 2 per domain)"
                    )
                    continue
                per_domain[domain] = per_domain.get(domain, 0) + 1
            capped.append(item)
        fresh = capped
    if (
        any(is_fresh_eligible(candidate, yesterday) for candidate in candidates)
        and not fresh
    ):
        warnings.append("proposal selected no valid fresh stories")

    selected_sources = [candidate_by_id[item["candidate_id"]] for item in fresh]
    selected_domains = sorted({
        source.get("source_domain")
        or urlsplit(source.get("url", "")).hostname
        or "unknown"
        for source in selected_sources
    })
    selected_categories = sorted({
        source.get("category", "Uncategorized")
        for source in selected_sources
    })
    if selected_sources:
        balance_summary = (
            f"Validated selection: {len(fresh)} fresh; "
            f"{len(selected_domains)} source domain(s); categories: "
            f"{', '.join(selected_categories)}."
        )
    else:
        balance_summary = "Validated selection: no publishable fresh stories."

    return {
        "selected_fresh": fresh,
        "rejected": proposal.get("rejected", []),
        "gaps": clean_editorial_text(proposal.get("gaps"), limit=800),
        "balance_summary": balance_summary,
    }, warnings

def raw_editorial_proposal(candidates: list[dict]) -> dict:
    """Build a source-only last-resort proposal after both curation models fail."""
    return {
        "selected_fresh": [
            {
                "candidate_id": candidate["candidate_id"],
                "rank": index,
                "editorial_summary": candidate.get("summary", ""),
                "selection_reason": "deterministic fallback",
            }
            for index, candidate in enumerate(candidates[:7], 1)
        ],
        "rejected": [],
        "gaps": "Curation models unavailable; source-ranked fallback used.",
        "balance_summary": "",
    }

def apply_editorial_patches(
    proposal: dict,
    review: dict,
) -> tuple[dict, list[dict], list[str]]:
    """Apply only the critic's bounded list operations; validation follows."""
    patched = copy.deepcopy(proposal)
    applied: list[dict] = []
    warnings: list[str] = []
    changes = review.get("changes", [])
    if not isinstance(changes, list):
        return patched, applied, ["critic changes was not a list"]

    def replace_by_candidate_id(items: list[dict], value: str, replacement: dict) -> bool:
        for index, item in enumerate(items):
            if item.get("candidate_id", "") == value:
                items[index] = replacement
                return True
        return False

    for change in changes[:20]:
        if not isinstance(change, dict):
            warnings.append("ignored non-object critic change")
            continue
        operation = change.get("operation")
        item = change.get("item")
        changed = False
        if operation == "remove_fresh":
            candidate_id = change.get("candidate_id", "")
            before = len(patched["selected_fresh"])
            patched["selected_fresh"] = [
                entry for entry in patched["selected_fresh"]
                if entry.get("candidate_id") != candidate_id
            ]
            changed = len(patched["selected_fresh"]) != before
        elif operation == "add_fresh" and isinstance(item, dict):
            patched["selected_fresh"].append(item)
            changed = True
        elif operation == "replace_fresh" and isinstance(item, dict):
            changed = replace_by_candidate_id(
                patched["selected_fresh"], change.get("candidate_id", ""), item,
            )
        elif operation == "move_fresh":
            candidate_id = change.get("candidate_id", "")
            position = change.get("position")
            if isinstance(position, int) and position >= 1:
                matches = [
                    entry for entry in patched["selected_fresh"]
                    if entry.get("candidate_id") == candidate_id
                ]
                if matches:
                    patched["selected_fresh"] = [
                        entry for entry in patched["selected_fresh"]
                        if entry.get("candidate_id") != candidate_id
                    ]
                    patched["selected_fresh"].insert(
                        min(position - 1, len(patched["selected_fresh"])), matches[0]
                    )
                    changed = True
        if changed:
            applied.append(change)
        else:
            warnings.append(f"ignored invalid critic operation {operation!r}")
    return patched, applied, warnings

def materialize_editorial_selection(
    proposal: dict,
    candidates: list[dict],
) -> list[dict]:
    candidate_by_id = {
        candidate["candidate_id"]: candidate for candidate in candidates
    }
    fresh: list[dict] = []
    for selection in proposal["selected_fresh"]:
        source = copy.deepcopy(candidate_by_id[selection["candidate_id"]])
        source.update({
            "rank": len(fresh) + 1,
            "summary": selection["editorial_summary"],
            "selection_reason": selection["selection_reason"],
        })
        fresh.append(source)
    return fresh

def model_attempts(*models: str) -> list[tuple[str, str]]:
    attempts: list[tuple[str, str]] = []
    seen: set[str] = set()
    for requested in models:
        effective = runtime._effective_model(requested)
        if effective not in seen:
            seen.add(effective)
            attempts.append((requested, effective))
    return attempts

def normalize_critic_verdict(verdict: object) -> object:
    """Canonicalize critic verdict strings. Models occasionally phrase the
    approve-with-changes verdict as 'approve_with_these_changes' or with
    spaces/case variants; those are semantically valid (digest-quality audit
    2026-08-31: mimo-v2.5 returned 'approve_with_these_changes', which failed
    the strict parse and degraded the whole review to unavailable). Unknown
    strings pass through unchanged and still fail closed at the call site."""
    if not isinstance(verdict, str):
        return verdict
    normalized = " ".join(verdict.strip().lower().split()).replace(" ", "_")
    if normalized == "approve_with_these_changes":
        return "approve_with_changes"
    return normalized

@runtime.track_phase_failure("curate")
def phase_6_curate(
    topic: dict,
    summaries: list[dict],
    run_dir: Path,
) -> list[dict]:
    """Propose, validate, and independently review the fresh selection."""
    output_path = run_dir / "06-curated.json"
    issue_date = runtime.issue_date_for_run(run_dir)
    blocked_urls = load_cross_topic_urls(topic, run_dir)
    phase_inputs = runtime.phase_inputs(
        "curate", topic=topic,
        upstream={
            "summaries": runtime.canonical_fingerprint(summaries),
            "cross_topic_urls": sorted(blocked_urls),
        },
        policy={
            "issue_date": issue_date.isoformat(),
            "ranking_schema": RANKING_SCHEMA_VERSION,
            "model": runtime._effective_model(runtime.MODEL),
        },
    )
    state, cached = runtime.begin_or_load_phase(
        run_dir, "curate", inputs=phase_inputs, artifact_path=output_path,
        schema_version=RANKING_SCHEMA_VERSION, validator=lambda value: isinstance(value, dict),
    )
    if cached is not None:
        cached_fresh = cached.get("fresh", [])
        record_referenced_urls(topic, cached_fresh, run_dir)
        return cached_fresh

    started = time.time()
    today_str = issue_date.isoformat()
    candidates, dropped = prepare_editorial_candidates(summaries, blocked_urls)
    # Deterministic freshness gate: only candidates within the last 24h (or
    # with undetermined dates) may populate the Fresh section. When none are
    # eligible, an empty Fresh section is the honest outcome and must not be
    # treated as a model/critic failure (digest-quality audit 2026-08-12).
    yesterday = issue_date - timedelta(days=1)
    fresh_eligible = [
        candidate for candidate in candidates
        if is_fresh_eligible(candidate, yesterday)
    ]
    print(f"  [6a prep] {len(candidates)} candidates, "
          f"{len(blocked_urls)} cross-topic URL(s) blocked")
    if not candidates:
        empty_proposal = {
            "selected_fresh": [],
            "rejected": [],
            "gaps": "No vetted stories were available.",
            "balance_summary": "No editorial selection was possible.",
        }
        output = {
            "status": "empty",
            "ranking_schema_version": RANKING_SCHEMA_VERSION,
            "fresh": [],
            "gaps": empty_proposal["gaps"],
            "balance_summary": empty_proposal["balance_summary"],
            "editorial": {
                "proposal_status": "empty",
                "proposal_model": "",
                "review_status": "not_run",
                "review_model": "",
                "degraded": False,
            },
        }
        runtime.atomic_write_json(run_dir / "06a-editorial-proposal.json", {
            "status": "empty",
            "model": "",
            "errors": [],
            "validation_warnings": [],
            "proposal": empty_proposal,
        })
        runtime.atomic_write_json(run_dir / "06b-editorial-review.json", {
            "status": "not_run",
            "model": "",
            "errors": [],
            "review": {"verdict": "not_run", "changes": []},
            "applied_changes": [],
            "validation_warnings": [],
        })
        runtime.atomic_write_json(run_dir / "06c-editorial-final.json", {
            "proposal": empty_proposal,
            "output": output,
            "validation_warnings": [],
        })
        runtime.complete_phase_json(
            state,
            "curate",
            output_path,
            output,
            outcome="empty",
            reason="no vetted stories for curation",
        )
        runtime.write_phase_status(
            output_path, status="empty",
            reason="no vetted stories for curation",
            inputs=phase_inputs,
        )
        record_referenced_urls(topic, [], run_dir)
        return []

    system = (
        "You are the lead editor of a daily newspaper section. Make one coherent "
        "proposal from vetted candidates. Selection and source/topic balance are "
        "interdependent. "
        "Treat the deterministic `priority_score` as the primary ranking signal; never "
        "alter or invent attention, confidence, or priority values. Do not write a "
        "section standfirst.\n\n"
        "Select 5-7 fresh stories when enough good candidates exist. "
        "Every selection must use an exact candidate_id supplied. Write concise newspaper "
        "copy that leads with facts; never refer to a digest, edition, candidate list, "
        "ranking process, or the reader. Write all prose in English regardless of source "
        "language; keep the supplied English story titles unchanged.\n\n"
        "Output one JSON object in ```json fences:\n"
        '{"selected_fresh":[{"candidate_id":"...","rank":1,'
        '"editorial_summary":"2-3 factual sentences","selection_reason":"..."}],'
        '"rejected":[{"candidate_id":"...","reason":"..."}],'
        '"gaps":"...","balance_summary":"..."}'
    )
    user = (
        f"## Date\n{today_str}\n\n"
        f"## Vetted candidates\n{json.dumps(candidates, indent=2)}\n\n"
        f"## Editorial significance rubric\n{editorial_significance_rubric_text(topic)}\n\n"
        f"## Dropped summaries; never select\n"
        f"{json.dumps([{'title': item.get('title'), 'url': item.get('url'), 'reason': item.get('judge_issues', [])} for item in dropped], indent=2)}"
    )

    proposal: dict | None = None
    proposal_model = ""
    proposal_warnings: list[str] = []
    proposal_errors: list[str] = []
    freshness_hint = ""
    for requested_model, effective_model in model_attempts(runtime.MODEL, runtime.MODEL_FALLBACK):
        # Retry the primary once before falling back to a weaker model: a single
        # truncated/malformed response or transient transport error used to
        # degrade the whole editorial stage to the fallback model (digest-quality
        # audit 2026-08-11: world proposal fell back after one extraction error).
        attempts = 2 if effective_model == runtime._effective_model(runtime.MODEL) else 1
        attempt = 0
        while attempt < attempts:
            attempt += 1
            try:
                raw = runtime._call_llm_proxy(
                    system, user + freshness_hint, model=requested_model,
                    timeout=runtime.EDITORIAL_TIMEOUT,
                )
                parsed = runtime._extract_json(raw, f"editorial proposal ({effective_model})")
                validated, warnings = validate_editorial_proposal(
                    parsed,
                    candidates,
                    blocked_urls,
                    issue_date=issue_date,
                )
                if fresh_eligible and not validated["selected_fresh"]:
                    if not freshness_hint:
                        # All fresh picks fell outside the last-24h window (or
                        # none were selected) while fresh-eligible candidates
                        # exist. Retry this model once with the freshness window
                        # reinforced instead of failing straight through to raw
                        # fallback (digest-quality audit 2026-08-14:
                        # agentic-platform shipped deterministic raw fallback
                        # with no critic review).
                        freshness_hint = (
                            "\n\n## Freshness window reminder\n"
                            "Your previous proposal was rejected because it "
                            "selected no valid fresh stories. \"Fresh — Last 24 "
                            "Hours\" may only contain stories whose best "
                            "publication date (date_confirmed, else "
                            "date_published) is yesterday or today (UTC) — "
                            "never older or future-dated. Fresh-eligible "
                            "candidates exist in the supplied list; re-select "
                            "5-7 fresh stories from them."
                        )
                        attempt -= 1
                        raise ValueError(
                            "model selected no valid fresh stories; retrying "
                            "with reinforced freshness hint"
                        )
                    raise ValueError("model selected no valid fresh stories")
                proposal = validated
                proposal_model = effective_model
                proposal_warnings = warnings
                break
            except Exception as error:
                error_summary = summarize_model_error(error)
                proposal_errors.append(f"{effective_model}: {error_summary}")
                print(f"  [6b retry] editorial proposal failed with "
                      f"{effective_model}: {error_summary}")
        if proposal is not None:
            break

    proposal_status = "model"
    if proposal is None:
        proposal_status = "raw_fallback"
        proposal = raw_editorial_proposal(candidates)
        proposal, proposal_warnings = validate_editorial_proposal(
            proposal,
            candidates,
            blocked_urls,
            issue_date=issue_date,
        )
        print("  [6b degraded] both curation models failed; using source-ranked fallback")

    runtime.atomic_write_text(run_dir / "06a-editorial-proposal.json", json.dumps({
        "status": proposal_status,
        "model": proposal_model,
        "errors": proposal_errors,
        "validation_warnings": proposal_warnings,
        "proposal": proposal,
    }, indent=2))


    final_proposal = proposal
    review_status = "skipped_raw_fallback"
    review_model = ""
    review_errors: list[str] = []
    review_warnings: list[str] = []
    review_result: dict = {"verdict": "not_run", "changes": []}
    applied_changes: list[dict] = []
    if proposal_status == "model":
        critic_system = (
            "You are the independent critic for a daily newspaper section. Review the "
            "selection and source/topic balance. Return bounded changes only; never "
            "rewrite the whole proposal. "
            "The deterministic `priority_score` owns ranking: move a story only to correct "
            "a clear ordering violation and never estimate or alter attention. "
            "Check for a missed higher-priority candidate, source concentration, and "
            "stale material. "
            "Write all notes and reasoning in English.\n\n"
            "Allowed operations: remove_fresh, add_fresh, replace_fresh, move_fresh. "
            "add/replace operations put the proposed object in item. "
            "remove/replace/move identify candidate_id. move_fresh also supplies "
            "a one-based position. Output JSON: "
            '{"verdict":"approve|approve_with_changes|reject","changes":[],'
            '"notes":"..."}'
        )
        critic_user = (
            f"## Candidates\n{json.dumps(candidates, indent=2)}\n\n"
            f"## Proposal\n{json.dumps(proposal, indent=2)}\n\n"
            f"## Deterministic warnings\n{json.dumps(proposal_warnings, indent=2)}"
        )
        critic_models = (runtime.MODEL_REVIEWER, runtime.MODEL_FALLBACK)
        critic_rejected = False
        for requested_model, effective_model in model_attempts(*critic_models):
            # Retry each critic model once: the primary against a transient
            # proxy 500 (degraded review on 2026-08-11) and the fallback
            # against the same class of error (digest-quality audit 2026-08-31:
            # deepseek-v4-flash 500 + read timeout left the fallback a single
            # shot). An authoritative reject is not retried.
            attempts = 2
            for _ in range(attempts):
                try:
                    raw = runtime._call_llm_proxy(
                        critic_system, critic_user, model=requested_model,
                        timeout=runtime.EDITORIAL_TIMEOUT,
                    )
                    parsed_review = runtime._extract_json(raw, f"editorial critic ({effective_model})")
                    if not isinstance(parsed_review, dict):
                        raise ValueError("critic output must be a JSON object")
                    review_result = parsed_review
                    verdict = normalize_critic_verdict(parsed_review.get("verdict"))
                    if verdict not in ("approve", "approve_with_changes", "reject"):
                        raise ValueError(f"unknown critic verdict {verdict!r}")
                    parsed_review["verdict"] = verdict
                    if verdict == "reject":
                        critic_rejected = True
                        raise ValueError("critic rejected the editorial proposal")
                    patched, applied, patch_warnings = apply_editorial_patches(
                        proposal, parsed_review
                    )
                    validated, validation_warnings = validate_editorial_proposal(
                        patched,
                        candidates,
                        blocked_urls,
                        issue_date=issue_date,
                    )
                    if fresh_eligible and not validated["selected_fresh"]:
                        raise ValueError("critic changes removed every valid fresh story")
                    final_proposal = validated
                    review_result = parsed_review
                    applied_changes = applied
                    review_warnings = patch_warnings + validation_warnings
                    review_model = effective_model
                    review_status = "reviewed"
                    break
                except Exception as error:
                    error_summary = summarize_model_error(error)
                    review_errors.append(f"{effective_model}: {error_summary}")
                    print(f"  [6d retry] editorial critic failed with "
                          f"{effective_model}: {error_summary}")
                    if critic_rejected:
                        break  # authoritative reject: try the next model
            if review_status == "reviewed":
                break
        if review_status != "reviewed":
            if critic_rejected:
                final_proposal = raw_editorial_proposal(candidates)
                final_proposal, fallback_warnings = validate_editorial_proposal(
                    final_proposal,
                    candidates,
                    blocked_urls,
                    issue_date=issue_date,
                )
                review_warnings.extend(fallback_warnings)
                review_status = "rejected_fallback"
                print("  [6d degraded] critic rejected proposal; using source-ranked fallback")
            else:
                review_status = "unavailable"
                print("  [6d degraded] critic unavailable; using validated editorial proposal")

    runtime.atomic_write_json(run_dir / "06b-editorial-review.json", {
        "status": review_status,
        "model": review_model,
        "errors": review_errors,
        "review": review_result,
        "applied_changes": applied_changes,
        "validation_warnings": review_warnings,
    })

    fresh = materialize_editorial_selection(final_proposal, candidates)
    # Hygiene assertion (digest-quality audit 2026-08-29): every curated fresh
    # story must carry date_confirmed; Phase 5 backfills it from date_published
    # when the fetch could not confirm one, so a miss here is a regression.
    # Backfill defensively and persist the warning in 06c's validation warnings
    # for auditability.
    hygiene_warnings: list[str] = []
    for story in fresh:
        if not (story.get("date_confirmed") or "").strip():
            story["date_confirmed"] = (story.get("date_published") or "").strip()
            hygiene_warnings.append(
                "date_confirmed missing on curated fresh story; backfilled from "
                f"date_published ({story['date_confirmed'] or 'none'}): "
                f"{story.get('url', '?')}"
            )
    if hygiene_warnings:
        review_warnings.extend(hygiene_warnings)
    fresh.sort(key=priority_sort_key, reverse=True)
    for rank, item in enumerate(fresh, 1):
        item["rank"] = rank
    output = {
        "ranking_schema_version": RANKING_SCHEMA_VERSION,
        "fresh": fresh,
        "gaps": final_proposal["gaps"],
        "balance_summary": final_proposal["balance_summary"],
        "editorial": {
            "proposal_status": proposal_status,
            "proposal_model": proposal_model,
            "review_status": review_status,
            "review_model": review_model,
            "degraded": (
                proposal_status != "model"
                # Compare against the primary model, not runtime._effective_model(runtime.MODEL):
                # a whole-run fallback sets MODEL_OVERRIDE, which made the
                # effective comparison self-consistent and hid the degradation
                # (digest-quality audit 2026-08-13).
                or proposal_model != runtime.MODEL
                or review_status != "reviewed"
            ),
        },
    }
    runtime.atomic_write_json(run_dir / "06c-editorial-final.json", {
        "proposal": final_proposal,
        "output": output,
        # Final validation warnings (proposal + critic review) so the shipped
        # selection's drops/caps are auditable from the final artifact.
        "validation_warnings": proposal_warnings + review_warnings,
    })
    editorial_degraded = bool(output["editorial"]["degraded"])
    runtime.complete_phase_json(
        state,
        "curate",
        output_path,
        output,
        outcome="degraded" if editorial_degraded else "succeeded",
        reason=(
            f"proposal={proposal_status}/{proposal_model}; review={review_status}/{review_model}"
            if editorial_degraded
            else None
        ),
    )
    elapsed = time.time() - started
    print(f"  [done] curate — {len(fresh)} fresh, "
          f"review={review_status} ({elapsed:.0f}s)")
    # Record canonical/related links from the selected stories so later topics
    # block the same event under a different URL (digest-quality audit 2026-08-26).
    record_referenced_urls(topic, fresh, run_dir)
    return fresh
