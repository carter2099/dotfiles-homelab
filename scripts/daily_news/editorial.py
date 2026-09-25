"""Daily News editorial phase 6 and stories-in-flight curation."""
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
    sif_candidates: list[dict],
    stories_in_flight: dict,
    blocked_urls: set[str] | None = None,
    *,
    issue_date: date | None = None,
) -> tuple[dict, list[str]]:
    """Validate model IDs/transitions and return a bounded, source-backed proposal."""
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
    tracker_by_url = {
        normalize_url(story.get("url", "")): story
        for story in stories_in_flight.get("stories", [])
        if normalize_url(story.get("url", ""))
    }
    ongoing_by_url = {
        normalize_url(story.get("url", "")): story
        for story in sif_candidates
        if normalize_url(story.get("url", ""))
        and coverage_key(story.get("url", "")) not in blocked
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
            # A section/date archive page is not an article; rejecting the
            # selection also keeps it out of stories-in-flight (digest-quality
            # audit 2026-08-21: Guardian /all listing URLs entered the world
            # tracker and resurfaced as ongoing on consecutive days).
            warnings.append(f"dropped listing URL fresh selection {candidate_id}")
            continue
        if is_asset_cdn_url(source.get("url", "")):
            # A publisher asset-CDN host is not an article host; the link is
            # dead on arrival (digest-quality audit 2026-08-24:
            # assets.theregister.com research links 405'd and resurfaced in
            # the tracker). Rejecting the selection also keeps it out of
            # stories-in-flight.
            warnings.append(f"dropped asset-CDN fresh selection {candidate_id}")
            continue
        if candidate_id in selected_ids:
            warnings.append(f"ignored duplicate fresh selection {candidate_id}")
            continue
        if not is_fresh_eligible(source, yesterday):
            # Deterministic freshness gate: an ongoing-window (2-5 day old)
            # candidate must never ship under "Fresh — Last 24 Hours", even
            # when the model selected it and the critic missed it (digest-quality
            # audit 2026-08-12: ai-hardware + agentic-platform shipped stale
            # stories under Fresh), and a future-dated candidate must not either
            # (digest-quality audit 2026-08-14: a 2026-10-15-dated story shipped
            # under Fresh). The candidate is treated as unselected, so it also
            # gets no tracker add/update.
            stale_date = candidate_fresh_date(source)
            kind = "future-dated" if stale_date.date() > yesterday else "stale"
            warnings.append(
                f"dropped {kind} fresh selection {candidate_id} "
                f"(best date {stale_date.date().isoformat()} is outside the 24h window)"
            )
            continue
        selected_ids.add(candidate_id)
        declared_related = normalize_url(source.get("develops_story_url", ""))
        requested_related = normalize_url(item.get("related_story_url", ""))
        related = ""
        if declared_related:
            target = tracker_by_url.get(declared_related)
            if target is None or not has_validated_high_significance(target):
                warnings.append(
                    f"removed invalid developing-story link from {candidate_id}"
                )
            else:
                related = declared_related
                if requested_related and requested_related != declared_related:
                    warnings.append(
                        f"replaced mismatched related story on {candidate_id}"
                    )
        elif requested_related:
            # Only Phase 1's dedicated follow-up search may establish a
            # cross-article story relationship.
            warnings.append(f"removed unverified related story from {candidate_id}")
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
            "related_story_url": tracker_by_url[related].get("url", "") if related else None,
        })
        if len(fresh) == 7:
            if len(raw_fresh) > 7:
                warnings.append("capped selected_fresh at 7")
            break

    ongoing: list[dict] = []
    selected_ongoing: set[str] = set()
    fresh_urls = {
        normalize_url(candidate_by_id[item["candidate_id"]].get("url", ""))
        for item in fresh
    }
    # A Fresh follow-up already reports its tracked story's newest development;
    # the same story's older ongoing card must not ship beside it.
    fresh_followup_roots = {
        normalize_url(item["related_story_url"])
        for item in fresh if item.get("related_story_url")
    }
    raw_ongoing = proposal.get("selected_ongoing", [])
    if not isinstance(raw_ongoing, list):
        warnings.append("selected_ongoing was not a list")
        raw_ongoing = []
    for item in raw_ongoing:
        if not isinstance(item, dict):
            warnings.append("ignored non-object ongoing selection")
            continue
        normalized = normalize_url(item.get("story_url", item.get("url", "")))
        if is_listing_url(item.get("story_url", item.get("url", ""))):
            warnings.append(f"ignored listing URL ongoing story {normalized!r}")
            continue
        if is_asset_cdn_url(item.get("story_url", item.get("url", ""))):
            warnings.append(f"ignored asset-CDN ongoing story {normalized!r}")
            continue
        source = ongoing_by_url.get(normalized)
        if source is None:
            warnings.append(f"ignored unknown ongoing story {normalized!r}")
            continue
        if source.get("status", "active") != "active" or not is_developing_story(source):
            warnings.append(
                f"ignored unqualified developing story {normalized!r}"
            )
            continue
        if normalized in selected_ongoing or normalized in fresh_urls:
            warnings.append(f"ignored duplicate ongoing story {normalized}")
            continue
        if normalized in fresh_followup_roots:
            warnings.append(
                f"ignored ongoing story superseded by its fresh follow-up {normalized}"
            )
            continue
        selected_ongoing.add(normalized)
        ongoing.append({
            "story_url": source.get("url", ""),
            "rank": len(ongoing) + 1,
            "summary": clean_editorial_text(
                item.get("summary"), source.get("latest_dev", "")
            ),
            "why_still_relevant": clean_editorial_text(
                item.get("why_still_relevant"), source.get("latest_dev", ""), 600
            ),
        })
        if len(ongoing) == 3:
            if len(raw_ongoing) > 3:
                warnings.append("capped selected_ongoing at 3")
            break

    related_by_candidate_id = {
        item["candidate_id"]: normalize_url(item.get("related_story_url", ""))
        for item in fresh
    }
    state_proposals: list[dict] = []
    raw_state = proposal.get(
        "story_state_proposals", proposal.get("state_proposals", [])
    )
    if not isinstance(raw_state, list):
        warnings.append("story_state_proposals was not a list")
        raw_state = []
    for item in raw_state:
        if not isinstance(item, dict):
            warnings.append("ignored non-object state proposal")
            continue
        operation = item.get("operation")
        evidence = item.get("evidence_candidate_ids", [])
        if not isinstance(evidence, list):
            evidence = []
        evidence = [
            candidate_id for candidate_id in evidence
            if candidate_id in selected_ids
        ]
        latest_dev = clean_editorial_text(item.get("latest_dev"), limit=800)

        if operation == "add":
            candidate_id = item.get("candidate_id", "")
            if candidate_id not in selected_ids:
                warnings.append(
                    f"ignored tracker add for unselected candidate {candidate_id!r}")
                continue
            source = candidate_by_id[candidate_id]
            if related_by_candidate_id.get(candidate_id):
                warnings.append(
                    f"ignored tracker add for linked development {candidate_id}"
                )
                continue
            if not has_validated_high_significance(source):
                warnings.append(
                    f"ignored unvalidated-high tracker add for {candidate_id}"
                )
                continue
            if normalize_url(source.get("url", "")) in tracker_by_url:
                warnings.append(f"ignored tracker add for existing story {candidate_id}")
                continue
            if (
                is_listing_url(source.get("url", ""))
                or is_asset_cdn_url(source.get("url", ""))
            ):
                warnings.append(f"ignored invalid-URL tracker add for {candidate_id}")
                continue
            state_proposals.append({
                "operation": "add",
                "candidate_id": candidate_id,
                "evidence_candidate_ids": [candidate_id],
                "latest_dev": latest_dev or source.get("summary", ""),
                "editorial_significance": "high",
                "status": "active",
            })
        elif operation == "update":
            normalized = normalize_url(item.get("story_url", ""))
            source = tracker_by_url.get(normalized)
            if (
                source is None
                or not has_validated_high_significance(source)
                or not evidence
                or not latest_dev
                or is_listing_url(item.get("story_url", ""))
                or is_asset_cdn_url(item.get("story_url", ""))
            ):
                warnings.append(
                    f"ignored unsupported tracker update for {normalized!r}")
                continue
            # Cross-article evidence is safe only when the dedicated follow-up
            # research declared the exact tracker URL and the selected Fresh
            # item retained that validated relationship. This admits genuine
            # multi-day developments without reopening broad-theme overwrites.
            linked_evidence = [
                candidate_id for candidate_id in evidence
                if (
                    normalize_url(candidate_by_id[candidate_id].get("url", ""))
                    == normalized
                    or related_by_candidate_id.get(candidate_id) == normalized
                )
            ]
            if not linked_evidence:
                warnings.append(
                    f"ignored unlinked tracker update for {normalized!r}")
                continue
            state_proposals.append({
                "operation": "update",
                "story_url": source.get("url", ""),
                "evidence_candidate_ids": linked_evidence,
                "latest_dev": latest_dev,
                "editorial_significance": "high",
                "status": "active",
            })
        else:
            warnings.append(f"ignored unknown state operation {operation!r}")

    # State continuity must not depend on model bookkeeping. Every selected
    # high-significance root story gets one initial evidence record; every vetted
    # follow-up gets an evidence-backed update. Follow-up articles never become
    # duplicate root tracker entries.
    added_candidate_ids = {
        op["candidate_id"] for op in state_proposals if op["operation"] == "add"
    }
    updated_story_urls = {
        normalize_url(op.get("story_url", ""))
        for op in state_proposals if op["operation"] == "update"
    }
    for selection in fresh:
        candidate_id = selection["candidate_id"]
        source = candidate_by_id[candidate_id]
        related = related_by_candidate_id.get(candidate_id, "")
        if related and related not in updated_story_urls:
            tracked = tracker_by_url[related]
            state_proposals.append({
                "operation": "update",
                "story_url": tracked.get("url", ""),
                "evidence_candidate_ids": [candidate_id],
                "latest_dev": selection["editorial_summary"],
                "editorial_significance": "high",
                "status": "active",
            })
            updated_story_urls.add(related)
        elif (
            not related
            and source.get("editorial_significance") == "high"
            and candidate_id not in added_candidate_ids
            and normalize_url(source.get("url", "")) not in tracker_by_url
        ):
            state_proposals.append({
                "operation": "add",
                "candidate_id": candidate_id,
                "evidence_candidate_ids": [candidate_id],
                "latest_dev": selection["editorial_summary"],
                "editorial_significance": "high",
                "status": "active",
            })
            added_candidate_ids.add(candidate_id)

    # The two-story send floor may use only stories that independently satisfy
    # the same Developing and Ongoing contract. Content volume never overrides
    # editorial significance or multi-day evidence; a thin section is not padded
    # with a one-off article.
    if len(fresh) + len(ongoing) < 2:
        selected_urls = {
            normalize_url(candidate_by_id[item["candidate_id"]].get("url", ""))
            for item in fresh
        } | {
            normalize_url(item["story_url"]) for item in ongoing
        }
        filler_pool = sorted(
            (story for story in sif_candidates
             if story.get("status", "active") == "active"
             and is_developing_story(story)
             and not is_listing_url(story.get("url", ""))
             and not is_asset_cdn_url(story.get("url", ""))
             and normalize_url(story.get("url", "")) not in selected_urls
             and normalize_url(story.get("url", "")) not in fresh_followup_roots),
            key=lambda story: story.get("last_updated", ""), reverse=True,
        )
        while filler_pool and len(fresh) + len(ongoing) < 2 and len(ongoing) < 3:
            story = filler_pool.pop(0)
            story_url = normalize_url(story.get("url", ""))
            ongoing.append({
                "story_url": story.get("url", ""),
                "rank": len(ongoing) + 1,
                "summary": story.get("latest_dev", story.get("title", "")),
                "why_still_relevant": (
                    "High-impact story with material developments confirmed on "
                    "multiple days; the latest verified development remains active."
                ),
            })
            selected_ongoing.add(story_url)


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
    # A source-concentration drop also removes that candidate's tracker
    # evidence. Persistent state must describe only stories that actually ship.
    final_selected_ids = {item["candidate_id"] for item in fresh}
    filtered_state: list[dict] = []
    for operation in state_proposals:
        if operation["operation"] == "add":
            if operation["candidate_id"] in final_selected_ids:
                filtered_state.append(operation)
            continue
        evidence = [
            candidate_id for candidate_id in operation.get("evidence_candidate_ids", [])
            if candidate_id in final_selected_ids
        ]
        if not evidence:
            continue
        filtered_state.append({**operation, "evidence_candidate_ids": evidence})
    state_proposals = filtered_state
    if (
        any(is_fresh_eligible(candidate, yesterday) for candidate in candidates)
        and not fresh
    ):
        warnings.append("proposal selected no valid fresh stories")

    selected_sources = [
        candidate_by_id[item["candidate_id"]]
        for item in fresh
    ] + [
        ongoing_by_url[normalize_url(item["story_url"])]
        for item in ongoing
    ]
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
            f"Validated selection: {len(fresh)} fresh, "
            f"{len(ongoing)} developing/ongoing; "
            f"{len(selected_domains)} source domain(s); categories: "
            f"{', '.join(selected_categories)}."
        )
    else:
        balance_summary = (
            "Validated selection: no publishable fresh or developing stories."
        )

    return {
        "selected_fresh": fresh,
        "selected_ongoing": ongoing,
        "story_state_proposals": state_proposals,
        "rejected": proposal.get("rejected", []),
        "gaps": clean_editorial_text(proposal.get("gaps"), limit=800),
        "balance_summary": balance_summary,
    }, warnings

def raw_editorial_proposal(
    candidates: list[dict],
    sif_candidates: list[dict],
) -> dict:
    """Build a source-only last-resort proposal after both curation models fail."""
    selected_fresh = [
        {
            "candidate_id": candidate["candidate_id"],
            "rank": index,
            "editorial_summary": candidate.get("summary", ""),
            "selection_reason": "deterministic fallback",
            "related_story_url": None,
        }
        for index, candidate in enumerate(candidates[:7], 1)
    ]
    return {
        "selected_fresh": selected_fresh,
        "selected_ongoing": [
            {
                "story_url": story.get("url", ""),
                "rank": index,
                "summary": story.get("latest_dev", ""),
                "why_still_relevant": story.get("latest_dev", ""),
            }
            for index, story in enumerate(sif_candidates[:3], 1)
        ],
        # Keep only high-significance root stories as follow-up candidates. A
        # selected follow-up article updates its linked root during validation
        # and must never become a second root entry.
        "story_state_proposals": [
            {
                "operation": "add",
                "candidate_id": selection["candidate_id"],
                "evidence_candidate_ids": [selection["candidate_id"]],
                "latest_dev": candidate.get("summary", ""),
                "editorial_significance": "high",
                "status": "active",
            }
            for selection, candidate in zip(selected_fresh, candidates[:7])
            if candidate.get("editorial_significance") == "high"
            and not candidate.get("develops_story_url")
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

    def replace_by(items: list[dict], key: str, value: str, replacement: dict) -> bool:
        for index, item in enumerate(items):
            current = item.get(key, "")
            matches = (
                normalize_url(current) == normalize_url(value)
                if key == "story_url" else current == value
            )
            if matches:
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
            changed = replace_by(
                patched["selected_fresh"], "candidate_id",
                change.get("candidate_id", ""), item,
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
        elif operation == "remove_ongoing":
            story_url = change.get("story_url", "")
            before = len(patched["selected_ongoing"])
            patched["selected_ongoing"] = [
                entry for entry in patched["selected_ongoing"]
                if normalize_url(entry.get("story_url", "")) != normalize_url(story_url)
            ]
            changed = len(patched["selected_ongoing"]) != before
        elif operation == "add_ongoing" and isinstance(item, dict):
            patched["selected_ongoing"].append(item)
            changed = True
        elif operation == "replace_ongoing" and isinstance(item, dict):
            changed = replace_by(
                patched["selected_ongoing"], "story_url",
                change.get("story_url", ""), item,
            )
        elif operation == "remove_state":
            index = change.get("index")
            if isinstance(index, int) and 0 <= index < len(patched["story_state_proposals"]):
                patched["story_state_proposals"].pop(index)
                changed = True
        elif operation == "add_state" and isinstance(item, dict):
            patched["story_state_proposals"].append(item)
            changed = True
        elif operation == "replace_state" and isinstance(item, dict):
            index = change.get("index")
            if isinstance(index, int) and 0 <= index < len(patched["story_state_proposals"]):
                patched["story_state_proposals"][index] = item
                changed = True
        if changed:
            applied.append(change)
        else:
            warnings.append(f"ignored invalid critic operation {operation!r}")
    return patched, applied, warnings

def _verified_source_record(source: dict, today: date) -> dict:
    """Headline, link, and best publication date of one verified candidate."""
    published = candidate_fresh_date(source, today)
    return {
        "title": source.get("title", ""),
        "url": source.get("url", ""),
        "date": published.date().isoformat() if published is not None else "",
    }

def apply_story_state_proposals(
    stories_in_flight: dict,
    proposal: dict,
    candidates: list[dict],
    today_str: str,
) -> dict:
    """Apply validated operations while preserving auditable evidence history."""
    updated = copy.deepcopy(stories_in_flight)
    stories = updated.setdefault("stories", [])
    parsed_today = parse_date(today_str)
    today = (
        parsed_today.date() if parsed_today is not None
        else datetime.now(timezone.utc).date()
    )
    for story in stories:
        normalize_story_tracking(story, today)
    candidate_by_id = {
        candidate["candidate_id"]: candidate
        for candidate in candidates if candidate.get("candidate_id")
    }
    story_by_url = {
        normalize_url(story.get("url", "")): story
        for story in stories
        if normalize_url(story.get("url", ""))
    }
    for operation in proposal.get("story_state_proposals", []):
        if operation["operation"] == "add":
            source = candidate_by_id.get(operation["candidate_id"])
            if source is None or not has_validated_high_significance(source):
                continue
            normalized = normalize_url(source.get("url", ""))
            if normalized in story_by_url:
                continue
            story = {
                "title": source.get("title", ""),
                "url": source.get("url", ""),
                "category": source.get("category", ""),
                "status": "active",
                "latest_dev": operation.get("latest_dev", source.get("summary", "")),
                "last_updated": today_str,
                "editorial_significance": "high",
                "significance_evidence": copy.deepcopy(
                    source.get("significance_evidence", {})
                ),
                "significance_validation": copy.deepcopy(
                    source.get("significance_validation", {})
                ),
                "first_seen": today_str,
                "developments": [{
                    "date": today_str,
                    "url": source.get("url", ""),
                }],
                "latest_source": _verified_source_record(source, today),
            }
            stories.append(story)
            story_by_url[normalized] = story
            continue

        if operation["operation"] != "update":
            continue
        story = story_by_url.get(normalize_url(operation.get("story_url", "")))
        if story is None:
            continue
        evidence_sources = [
            candidate_by_id[candidate_id]
            for candidate_id in operation.get("evidence_candidate_ids", [])
            if candidate_id in candidate_by_id
        ]
        if not evidence_sources:
            # Evidence-free updates are administrative only (for example,
            # deterministic cooling). They never fabricate a development date
            # or extend the evidence-backed activity window.
            story["status"] = operation.get("status", story.get("status", "active"))
            continue
        story["developments"].extend({
            "date": today_str,
            "url": source.get("url", ""),
        } for source in evidence_sources)
        # Headline, link, date, and summary move together to the newest
        # verified source, so the card never pairs an old headline with a newer
        # development (2026-09-21/22 Russia sanctions card).
        latest = max(
            enumerate(evidence_sources),
            key=lambda pair: (_verified_source_record(pair[1], today)["date"], pair[0]),
        )[1]
        story["latest_source"] = _verified_source_record(latest, today)
        story["latest_dev"] = (
            operation["latest_dev"] if len(evidence_sources) == 1
            else latest.get("summary", "") or operation["latest_dev"]
        )
        story["editorial_significance"] = "high"
        story["status"] = operation.get("status", "active")
        normalize_story_tracking(story, today)
    return updated

def materialize_editorial_selection(
    proposal: dict,
    candidates: list[dict],
    stories_in_flight: dict,
) -> tuple[list[dict], list[dict]]:
    candidate_by_id = {
        candidate["candidate_id"]: candidate for candidate in candidates
    }
    story_by_url = {
        normalize_url(story.get("url", "")): story
        for story in stories_in_flight.get("stories", [])
    }
    fresh: list[dict] = []
    for selection in proposal["selected_fresh"]:
        source = copy.deepcopy(candidate_by_id[selection["candidate_id"]])
        source.update({
            "rank": len(fresh) + 1,
            "summary": selection["editorial_summary"],
            "selection_reason": selection["selection_reason"],
            "related_story_url": selection["related_story_url"],
        })
        fresh.append(source)

    ongoing: list[dict] = []
    for selection in proposal["selected_ongoing"]:
        tracked = story_by_url[normalize_url(selection["story_url"])]
        source = copy.deepcopy(tracked)
        source["tracker_url"] = tracked.get("url", "")
        display = tracker_display_source(tracked)
        if display is not None:
            source["title"] = display["title"]
            source["url"] = display["url"]
            if display["date"]:
                source["date_published"] = display["date"]
        source.update({
            "rank": len(ongoing) + 1,
            "summary": selection["summary"],
            "why_still_relevant": selection["why_still_relevant"],
        })
        ongoing.append(source)
    return fresh, ongoing

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
    sif_candidates: list[dict],
    stories_in_flight: dict,
    run_dir: Path,
) -> tuple[list[dict], dict, list[dict]]:
    """Propose, validate, independently review, then apply editorial state changes."""
    output_path = run_dir / "06-curated.json"
    issue_date = runtime.issue_date_for_run(run_dir)
    blocked_urls = load_cross_topic_urls(topic, run_dir)
    phase_inputs = runtime.phase_inputs(
        "curate", topic=topic,
        upstream={
            "summaries": runtime.canonical_fingerprint(summaries),
            "sif_candidates": runtime.canonical_fingerprint(sif_candidates),
            "stories_in_flight": runtime.canonical_fingerprint(stories_in_flight),
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
        cached_ongoing = cached.get("ongoing", [])
        record_referenced_urls(topic, cached_fresh, cached_ongoing, run_dir)
        return (
            cached_fresh,
            cached.get("stories_in_flight", stories_in_flight),
            cached_ongoing,
        )

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
    def _displayable(story: dict) -> bool:
        display = tracker_display_source(story)
        return display is not None and coverage_key(display["url"]) not in blocked_urls

    sif_candidates = [
        story for story in sif_candidates
        if coverage_key(story.get("url", "")) not in blocked_urls
        and story.get("status", "active") == "active"
        and is_developing_story(story)
        and _displayable(story)
        and not is_listing_url(story.get("url", ""))
        and not is_asset_cdn_url(story.get("url", ""))
    ]
    print(f"  [6a prep] {len(candidates)} candidates, {len(sif_candidates)} SIF, "
          f"{len(blocked_urls)} cross-topic URL(s) blocked")
    if not candidates and not sif_candidates:
        empty_proposal = {
            "selected_fresh": [],
            "selected_ongoing": [],
            "story_state_proposals": [],
            "rejected": [],
            "gaps": "No vetted stories or qualified developing stories were available.",
            "balance_summary": "No editorial selection was possible.",
        }
        output = {
            "status": "empty",
            "ranking_schema_version": RANKING_SCHEMA_VERSION,
            "fresh": [],
            "ongoing": [],
            "stories_in_flight": stories_in_flight,
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
            reason="no vetted or qualified stories for curation",
        )
        runtime.write_phase_status(
            output_path, status="empty",
            reason="no vetted or qualified stories for curation",
            inputs=phase_inputs,
        )
        record_referenced_urls(topic, [], [], run_dir)
        return [], stories_in_flight, []

    system = (
        "You are the lead editor of a daily newspaper section. Make one coherent "
        "proposal from vetted candidates and qualified developing stories. Selection, "
        "source/topic balance, story connections, and state proposals are interdependent. "
        "Treat the deterministic `priority_score` as the primary ranking signal; never "
        "alter or invent attention, confidence, or priority values. Do not write a "
        "section standfirst and do not replace the tracker.\n\n"
        f"{DEVELOPING_STORY_RULES}\n"
        "Select 5-7 fresh stories when enough good candidates exist. Select zero to "
        "three Developing and Ongoing stories only from the supplied qualified SIF "
        "candidates; zero is correct when none adds value. Never fill an ongoing quota. "
        "Every selection must use an exact candidate_id or story_url supplied. For a "
        "Fresh candidate carrying `develops_story_url`, copy that exact URL into "
        "`related_story_url` and propose an evidence-backed update of that tracked "
        "story. No other cross-article connection is allowed. Add only selected, "
        "high-significance root candidates to the tracker. `why_still_relevant` must "
        "name the latest material development, never merely say the item is still "
        "relevant, recent, unresolved, or the latest commentary. Write concise newspaper "
        "copy that leads with facts; never refer to a digest, edition, candidate list, "
        "ranking process, or the reader. Write all prose in English regardless of source "
        "language; keep the supplied English story titles unchanged.\n\n"
        "Output one JSON object in ```json fences:\n"
        '{"selected_fresh":[{"candidate_id":"...","rank":1,'
        '"editorial_summary":"2-3 factual sentences","selection_reason":"...",'
        '"related_story_url":null}],'
        '"selected_ongoing":[{"story_url":"...","rank":1,'
        '"summary":"what the story is","why_still_relevant":"what changed"}],'
        '"story_state_proposals":[{"operation":"add|update",'
        '"candidate_id":"for add","story_url":"for update",'
        '"evidence_candidate_ids":["..."],"latest_dev":"...",'
        '"editorial_significance":"high|medium|low","status":"active|cooled"}],'
        '"rejected":[{"candidate_id":"...","reason":"..."}],'
        '"gaps":"...","balance_summary":"..."}'
    )
    user = (
        f"## Date\n{today_str}\n\n"
        f"## Vetted candidates\n{json.dumps(candidates, indent=2)}\n\n"
        f"## Qualified Developing and Ongoing candidates\n"
        f"{json.dumps(sif_candidates, indent=2)}\n\n"
        f"## Full tracker for connections and proposed updates\n"
        f"{json.dumps(stories_in_flight, indent=2)}\n\n"
        f"## Editorial significance rubric\n{editorial_significance_rubric_text(topic)}\n\n"
        f"## Developing-story contract\n{DEVELOPING_STORY_RULES}\n"
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
                    sif_candidates,
                    stories_in_flight,
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
        proposal = raw_editorial_proposal(candidates, sif_candidates)
        proposal, proposal_warnings = validate_editorial_proposal(
            proposal,
            candidates,
            sif_candidates,
            stories_in_flight,
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
            "selection, source/topic balance, developing-story links, and persistent "
            "state proposals. Return bounded changes only; never rewrite the whole proposal. "
            "The deterministic `priority_score` owns ranking: move a story only to correct "
            "a clear ordering violation and never estimate or alter attention. Enforce the "
            "Developing and Ongoing contract strictly: remove anything merely old, still "
            "relevant, one-off, or unsupported by material developments on multiple dates. "
            "Check for a missed higher-priority candidate, unsupported connections, source "
            "concentration, stale material, and state changes without selected evidence. "
            "Write all notes and reasoning in English.\n\n"
            f"{DEVELOPING_STORY_RULES}\n"
            "Allowed operations: remove_fresh, add_fresh, replace_fresh, move_fresh, "
            "remove_ongoing, add_ongoing, replace_ongoing, remove_state, add_state, "
            "replace_state. add/replace operations put the proposed object in item. "
            "remove/replace/move fresh identifies candidate_id; ongoing identifies "
            "story_url; state operations use a zero-based index. move_fresh also supplies "
            "a one-based position. Output JSON: "
            '{"verdict":"approve|approve_with_changes|reject","changes":[],'
            '"notes":"..."}'
        )
        critic_user = (
            f"## Candidates\n{json.dumps(candidates, indent=2)}\n\n"
            f"## SIF candidates\n{json.dumps(sif_candidates, indent=2)}\n\n"
            f"## Current tracker\n{json.dumps(stories_in_flight, indent=2)}\n\n"
            f"## Proposal\n{json.dumps(proposal, indent=2)}\n\n"
            f"## Deterministic warnings\n{json.dumps(proposal_warnings, indent=2)}\n\n"
            f"## Developing-story contract\n{DEVELOPING_STORY_RULES}"
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
                        sif_candidates,
                        stories_in_flight,
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
                final_proposal = raw_editorial_proposal(candidates, sif_candidates)
                final_proposal, fallback_warnings = validate_editorial_proposal(
                    final_proposal,
                    candidates,
                    sif_candidates,
                    stories_in_flight,
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

    # The resurface cap bounds repetition even before evidence inactivity reaches
    # the five-day auto-cool threshold. Its evidence-free update is administrative:
    # state application changes status only and never advances last_updated.
    cap_warnings, cap_ops = enforce_ongoing_resurface_cap(
        final_proposal, stories_in_flight, run_dir.parent
    )
    if cap_warnings:
        for warning in cap_warnings:
            print(f"  [6c resurface] {warning}")
        review_warnings.extend(cap_warnings)
    if cap_ops:
        final_proposal["story_state_proposals"] = (
            final_proposal.get("story_state_proposals", []) + cap_ops
        )

    updated_sif = apply_story_state_proposals(
        stories_in_flight, final_proposal, candidates, today_str
    )
    fresh, ongoing = materialize_editorial_selection(
        final_proposal, candidates, updated_sif
    )
    # Hygiene assertion (digest-quality audit 2026-08-29): every curated fresh
    # story must carry date_confirmed; Phase 5 backfills it from date_published
    # when the fetch could not confirm one, so a miss here is a regression.
    # Backfill defensively and persist the warning in 06c's validation warnings
    # for auditability. Tracker-sourced ongoing stories carry evidence dates
    # (first_seen/developments), not publication dates, so they are exempt.
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
        "ongoing": ongoing,
        "stories_in_flight": updated_sif,
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
    print(f"  [done] curate — {len(fresh)} fresh, {len(ongoing)} ongoing, "
          f"review={review_status} ({elapsed:.0f}s)")
    # Record canonical/related links from the selected stories so later topics
    # block the same event under a different URL (digest-quality audit 2026-08-26).
    record_referenced_urls(topic, fresh, ongoing, run_dir)
    return fresh, updated_sif, ongoing
