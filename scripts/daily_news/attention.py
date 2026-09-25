#!/usr/bin/env python3
"""Observable news-attention scoring and product priority for Daily News candidates.

Attention comes only from measured inventories (press coverage, link sharing,
community discussion, public interest, editorial curation). The research LLM
may supply canonical event terms; Jev may decide whether an observed document
reports the same event and answer decomposed importance gut-checks. Neither
ever estimates popularity. Editorial significance remains a separate input.
"""

from __future__ import annotations

import copy
import json
import math
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from jev import JevUnavailable

SCHEMA_VERSION = 7
PROVIDER = "Daily News attention snapshot"

# Attention is optional. The phase allowance bounds snapshot collection plus
# Jev calls; local matching and scoring are not interrupted.
ATTENTION_STAGE_BUDGET_SECONDS = 15 * 60.0
MAX_ATTENTION_STAGE_BUDGET_SECONDS = ATTENTION_STAGE_BUDGET_SECONDS
ATTENTION_BUDGET_SCOPE = (
    "snapshot collection plus Jev adjudication and importance calls; "
    "local matching, scoring, and artifact writes are not interrupted"
)

EDITORIAL_POINTS = {
    "high": 100.0,
    "medium": 60.0,
    "low": 25.0,
}

HIGH_SIGNIFICANCE_BASES = {
    "binding_policy_or_law",
    "broad_public_consequence",
    "major_conflict_or_disaster",
    "major_financial_scale",
    "major_product_or_platform_shift",
    "security_or_safety_incident",
    "widespread_mandatory_migration",
}

IMPACT_SCOPE_POINTS = {
    "broad": 2.0,
    "sector": 1.0,
    "niche": 0.0,
}

CHANNEL_WEIGHTS = {"press": 0.40, "social": 0.25, "community": 0.15, "interest": 0.10, "curation": 0.10}
CHANNEL_SOURCES = {
    "press": ("gkg", "panel"),
    "social": ("jetstream", "mastodon"),
    "community": ("hn",),
    "interest": ("bsky_trends", "wikipedia"),
    "curation": ("techmeme", "kagi"),
}
# Each source is scored on its own and carries an equal share of its channel's weight, so a
# source that failed can be left out of every story's blend without distorting the others.
SOURCE_WEIGHTS = {
    source: CHANNEL_WEIGHTS[channel] / len(sources)
    for channel, sources in CHANNEL_SOURCES.items()
    for source in sources
}
_TECH_CHANNELS = ("press", "social", "community", "curation")
_GENERAL_CHANNELS = ("press", "social", "interest", "curation")
SECTION_CHANNELS = {
    "ai-tech": _TECH_CHANNELS,
    "agents": _TECH_CHANNELS,
    "ai-hardware": _TECH_CHANNELS,
    "gaming": _GENERAL_CHANNELS,
    "world": _GENERAL_CHANNELS,
}
# Source magnitude that maps to 100 until a section has enough measured history. From the
# 2026-09-24 live run over all five sections: the 90th percentile of matched candidates'
# non-zero magnitudes where 11+ matched; for sparsely matched sources (Mastodon, Techmeme,
# Bluesky trends, Wikipedia) the 90th percentile of the same formula over the whole inventory.
DEFAULT_REFERENCE = {
    "gkg": 4.12, "panel": 2.51, "jetstream": 5.93, "mastodon": 6.16, "hn": 9.12,
    "bsky_trends": 9.14, "wikipedia": 10.03, "techmeme": 5.14, "kagi": 3.99,
}
REFERENCE_PERCENTILE = 0.90
REFERENCE_MIN_SAMPLES = 20
REFERENCE_HISTORY_DAYS = 30
# Confidence scales with the share of the section's source weight that was measured, so fewer
# measured sources give attention proportionally less say for every story alike.
MATCH_CONFIDENCE = 0.85
# Retrieval can miss paraphrased coverage, so a measured zero is less certain than a match.
NO_MATCH_CONFIDENCE = 0.55

IMPORTANCE_QUESTIONS: dict[str, dict[str, Any]] = {
    "scope": {
        "type": "score",
        "instructions": "Who is directly affected by the development reported in `story`?",
        "criteria": [
            "A single company, product team, or small group of people",
            "One community of users or customers, or one local area",
            "A whole industry sector or a large user or developer community",
            "A country's population or a major national market",
            "People in many countries",
        ],
    },
    "consequence": {
        "type": "score",
        "instructions": "How consequential is the development reported in `story` for its field or for "
                        "society over the next year?",
        "criteria": [
            "Negligible: no lasting effect",
            "Minor: a small or short-lived effect",
            "Notable: a meaningful effect within its field",
            "Major: a significant effect across its field or a country",
            "Historic: a lasting effect on many countries or a whole industry",
        ],
    },
    "routine": {
        "type": "noul",
        "instructions": "Is `story` routine maintenance news such as a changelog, patch notes, a minor version "
                        "release, a pricing tweak, a deprecation notice, or a scheduled content update?",
    },
    "binding": {
        "type": "noul",
        "instructions": "Does `story` report a binding government action such as a law, regulation, court "
                        "ruling, sanction, or official decision?",
    },
    "harm": {
        "type": "noul",
        "instructions": "Does `story` report deaths, injuries, a disaster, armed conflict, or a serious "
                        "security or safety incident?",
    },
    "first": {
        "type": "noul",
        "instructions": "Does `story` report a first-of-its-kind development rather than an incremental change?",
    },
    "opinion": {
        "type": "noul",
        "instructions": "Is `story` opinion, commentary, or analysis rather than a report of a new development?",
    },
}
IMPORTANCE_WORKERS = 6
IMPORTANCE_EDITORIAL_WEIGHT = 0.65
IMPORTANCE_JEV_WEIGHT = 0.35
PRIORITY_IMPORTANCE_WEIGHT = 0.60
PRIORITY_ATTENTION_WEIGHT = 0.40

_STOPWORDS = {
    "about", "after", "again", "against", "amid", "among", "and", "are",
    "before", "being", "between", "could", "does", "from", "have", "how",
    "into", "just", "more", "new", "not", "over", "says", "than", "that",
    "their", "they", "this", "through", "under", "what", "when", "where",
    "which", "who", "why", "with", "will", "would", "your",
}


def _clean_text(value: Any) -> str:
    return " ".join(str(value or "").split())


def canonicalize_publisher_url(url: str) -> str:
    """Rewrite publisher sample/test hosts to their canonical reader domain.

    NYT test infra (e.g. monorepo-sample1.nyt.net) serves real article content
    but is not a reader-facing domain; the fetched page's canonical/og:url
    points at www.nytimes.com with the identical path. Map any *.nyt.net host
    so published URLs always use the canonical publisher domain.
    """
    raw = (url or "").strip()
    if not raw or "://" not in raw:
        return raw
    try:
        parts = urlsplit(raw)
    except ValueError:
        return raw
    host = (parts.hostname or "").lower()
    if host != "nyt.net" and not host.endswith(".nyt.net"):
        return raw
    suffix = parts.path or "/"
    if parts.query:
        suffix = f"{suffix}?{parts.query}"
    return f"https://www.nytimes.com{suffix}"


def normalize_editorial_significance(item: dict[str, Any]) -> dict[str, Any]:
    """Migrate the old `importance` field and enforce the editorial label."""
    legacy = item.pop("importance", None)
    value = _clean_text(item.get("editorial_significance") or legacy).lower()
    item["editorial_significance"] = value if value in EDITORIAL_POINTS else "medium"
    return item

def _significance_tokens(value: Any) -> set[str]:
    return {
        token.casefold()
        for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9'-]*", _clean_text(value))
        if len(token) >= 3 and token.casefold() not in _STOPWORDS
    }


def _downgrade_high(item: dict[str, Any], reason: str) -> dict[str, Any]:
    item["editorial_significance"] = "medium"
    item["significance_validation"] = {
        "status": "downgraded",
        "from": "high",
        "to": "medium",
        "reason": reason,
    }
    return item


def enforce_editorial_significance(item: dict[str, Any]) -> dict[str, Any]:
    """Require source-grounded impact evidence before accepting `high`."""
    normalize_editorial_significance(item)
    if item["editorial_significance"] != "high":
        item.setdefault("significance_validation", {
            "status": "accepted",
            "reason": "high-significance gate not required",
        })
        return item

    evidence = item.get("significance_evidence")
    if not isinstance(evidence, dict):
        return _downgrade_high(item, "missing structured significance evidence")
    basis = _clean_text(evidence.get("basis")).lower()
    scope = _clean_text(evidence.get("affected_scope")).lower()
    impact = _clean_text(evidence.get("impact"))
    if basis not in HIGH_SIGNIFICANCE_BASES:
        return _downgrade_high(item, "unsupported high-significance basis")
    if scope not in {"broad", "sector"}:
        return _downgrade_high(item, "high significance requires broad or sector scope")
    if len(impact) < 30:
        return _downgrade_high(item, "impact evidence is missing or too vague")

    source_text = " ".join([
        _clean_text(item.get("title")),
        _clean_text(item.get("summary")),
        " ".join(
            _clean_text(detail)
            for detail in item.get("key_details", [])
            if isinstance(detail, str)
        ),
    ])
    impact_tokens = _significance_tokens(impact)
    source_tokens = _significance_tokens(source_text)
    required_overlap = min(3, len(impact_tokens))
    if required_overlap == 0 or len(impact_tokens & source_tokens) < required_overlap:
        return _downgrade_high(item, "impact evidence is not grounded in source facts")
    source_numbers = set(re.findall(r"\b\d[\d,.]*%?\b", source_text))
    impact_numbers = set(re.findall(r"\b\d[\d,.]*%?\b", impact))
    if not impact_numbers.issubset(source_numbers):
        return _downgrade_high(item, "impact evidence introduced unsupported numbers")

    maintenance_change = bool(re.search(
        r"\b(deprecat\w*|renam\w*|remov(?:e|ed|al)|patch(?:es)?|"
        r"release notes?|minor update|version bump)\b",
        source_text,
        re.IGNORECASE,
    ))
    high_impact_exception = basis in {
        "binding_policy_or_law",
        "security_or_safety_incident",
    }
    demonstrated_scale = bool(re.search(
        r"\b(all|every|millions?|thousands?|widely used|critical|outage|"
        r"data loss|no replacement|breaking existing|mandatory|deadline)\b|"
        r"\b\d[\d,.]*\s*(users?|customers?|organizations?|systems?)\b",
        source_text,
        re.IGNORECASE,
    ))
    if maintenance_change and not high_impact_exception and not demonstrated_scale:
        return _downgrade_high(
            item,
            "routine maintenance or deprecation lacks demonstrated broad impact",
        )

    item["significance_validation"] = {
        "status": "accepted",
        "reason": f"{basis} with {scope} affected scope",
    }
    return item


def _sanitize_term(value: Any) -> str:
    term = _clean_text(value)
    term = re.sub(r"[^\w\s.+#&/'-]", " ", term, flags=re.UNICODE)
    term = _clean_text(term).strip("-/'")
    return term[:64]


def _terms_are_sufficient(terms: list[str]) -> bool:
    return (
        len(terms) >= 2
        or (
            len(terms) == 1
            and len(re.findall(r"\w+", terms[0], flags=re.UNICODE)) >= 3
        )
    )


def event_terms(candidate: dict[str, Any]) -> list[str]:
    """Return bounded event identifiers for measurement, never a score."""
    supplied = candidate.get("event_terms")
    terms: list[str] = []
    if isinstance(supplied, list):
        for value in supplied:
            term = _sanitize_term(value)
            if (
                term
                and not (
                    " " not in term
                    and term.casefold() in _STOPWORDS
                )
                and term.casefold()
                not in {existing.casefold() for existing in terms}
            ):
                terms.append(term)
            if len(terms) == 4:
                break
    if _terms_are_sufficient(terms):
        return terms

    source = _clean_text(candidate.get("event") or candidate.get("title"))
    tokens = re.findall(r"[A-Za-z0-9][A-Za-z0-9.+#&'-]*", source)
    while tokens and tokens[0].casefold() in {"a", "an", "the"}:
        tokens.pop(0)
    phrase = _sanitize_term(" ".join(tokens[:4]))
    return [phrase] if len(phrase.split()) >= 3 else terms

def event_term_source(candidate: dict[str, Any]) -> str:
    supplied = candidate.get("event_terms")
    if isinstance(supplied, list):
        cleaned = [
            term for term in (_sanitize_term(value) for value in supplied)
            if term and not (" " not in term and term.casefold() in _STOPWORDS)
        ]
        if _terms_are_sufficient(cleaned):
            return "model_terms"
    return "title_fallback"


def _age_bucket(age_hours: float | None) -> str:
    if age_hours is None:
        return "unknown"
    if age_hours <= 1:
        return "0-1h"
    if age_hours <= 3:
        return "1-3h"
    if age_hours <= 6:
        return "3-6h"
    if age_hours <= 12:
        return "6-12h"
    return "12-24h"


def _numeric(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def priority_sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
    """Deterministic tie-breakers; never fall back to discovery order."""
    attention = item.get("attention")
    attention = attention if isinstance(attention, dict) else {}
    evidence = item.get("significance_evidence")
    evidence = evidence if isinstance(evidence, dict) else {}
    date_value = re.sub(
        r"\D", "", _clean_text(item.get("date_confirmed") or item.get("date_published"))
    )
    return (
        _numeric(item.get("priority_score")),
        _numeric(attention.get("digest_prominence")),
        _numeric(attention.get("attention_now")),
        _numeric(attention.get("confidence")),
        IMPACT_SCOPE_POINTS.get(_clean_text(evidence.get("affected_scope")).lower(), 0.0),
        EDITORIAL_POINTS.get(
            _clean_text(item.get("editorial_significance")).lower(), 0.0
        ),
        int(date_value[:8]) if len(date_value) >= 8 else 0,
        _clean_text(item.get("title")).casefold(),
        _clean_text(item.get("url")).casefold(),
    )


# ---------------------------------------------------------------- source scoring

# Sources observed at one moment (trend lists, front pages, daily batches) have no
# final-six-hours view; their full measurement also stands for "now".
_POINT_IN_TIME_SOURCES = frozenset({"mastodon", "bsky_trends", "wikipedia", "techmeme", "kagi"})


def source_magnitudes(measures: dict[str, float]) -> dict[str, float]:
    """Log-damped per-source magnitudes from observed measures (0 means nothing observed)."""
    m = {key: max(0.0, _numeric(value)) for key, value in measures.items()}

    def press(source: str) -> float:
        return math.log1p(m.get(f"{source}_groups", 0.0)) + 0.5 * math.log1p(m.get(f"{source}_domains", 0.0))

    return {
        "gkg": press("gkg"),
        "panel": press("panel"),
        "jetstream": math.log1p(m.get("bsky_sharers_est", 0.0)),
        "mastodon": math.log1p(m.get("mastodon_accounts", 0.0)),
        "hn": math.log1p(m.get("hn_points", 0.0)) + 0.5 * math.log1p(m.get("hn_comments", 0.0)),
        "bsky_trends": math.log1p(m.get("trend_posts", 0.0)),
        "wikipedia": math.log1p(m.get("wiki_spike_views", 0.0)),
        "techmeme": 2.0 * m.get("techmeme_weight", 0.0) + math.log1p(m.get("techmeme_more", 0.0)),
        "kagi": math.log1p(m.get("kagi_domains", 0.0)),
    }


def reference_scales(history: dict[str, list[float]]) -> dict[str, float]:
    """Per-source magnitude mapped to 100: the 90th percentile of recent non-zero history."""
    scales: dict[str, float] = {}
    for source, default in DEFAULT_REFERENCE.items():
        values = sorted(value for value in history.get(source, []) if value > 0)
        if len(values) >= REFERENCE_MIN_SAMPLES:
            position = min(len(values) - 1, int(REFERENCE_PERCENTILE * (len(values) - 1) + 0.5))
            scales[source] = round(max(values[position], 0.5), 3)
        else:
            scales[source] = default
    return scales


def load_reference_history(archive_dir: Path, section: str, edition: date) -> dict[str, list[float]]:
    """Magnitudes of measured sources from this section's prior 30 editions."""
    history: dict[str, list[float]] = {source: [] for source in SOURCE_WEIGHTS}
    for offset in range(1, REFERENCE_HISTORY_DAYS + 1):
        path = archive_dir / (edition - timedelta(days=offset)).isoformat() / f"{section}.json"
        try:
            artifact = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if not isinstance(artifact, dict) or int(artifact.get("schema_version") or 0) < SCHEMA_VERSION:
            continue
        for row in artifact.get("observations") or []:
            magnitudes = row.get("magnitudes") if isinstance(row, dict) else None
            if not isinstance(magnitudes, dict):
                continue
            for source in history:
                value = _numeric(magnitudes.get(source))
                if value > 0:
                    history[source].append(value)
    return history


def _blend(scores: dict[str, float]) -> float:
    weight = sum(SOURCE_WEIGHTS[source] for source in scores)
    if weight <= 0:
        return 0.0
    return round(sum(SOURCE_WEIGHTS[source] * value for source, value in scores.items()) / weight, 1)


def section_sources(section: str) -> tuple[str, ...]:
    """Every inventory an attention measurement for ``section`` can use."""
    channels = SECTION_CHANNELS.get(section, _GENERAL_CHANNELS)
    return tuple(source for channel in channels for source in CHANNEL_SOURCES[channel])


def measured_attention(
    evidence: dict[str, Any],
    *,
    section: str,
    measured_sources: frozenset[str] | set[str],
    references: dict[str, float],
    window_end: datetime,
    first_seen: int | None = None,
) -> tuple[dict[str, Any], dict[str, float]]:
    """Blend the sources that were fully collected; returns (attention, measured magnitudes).

    A source that failed or came back partial is left out of every story's blend
    rather than counted as zero, and confidence shrinks with the measured share.
    """
    applicable = section_sources(section)
    measured = [source for source in applicable if source in measured_sources]
    measures = evidence.get("measures") or {}
    recent = evidence.get("recent") or {}
    all_magnitudes = source_magnitudes(measures)
    recent_magnitudes = source_magnitudes(recent)
    magnitudes = {source: all_magnitudes[source] for source in measured}
    base = {
        "schema_version": SCHEMA_VERSION,
        "provider": PROVIDER,
        "evidence": {
            "sources_measured": measured,
            "sources_excluded": [source for source in applicable if source not in measured_sources],
            "measures": measures,
            "recent": recent,
            "adjudication": evidence.get("adjudication") or {},
        },
    }
    if not measured:
        base["evidence"]["unavailable_reason"] = "no_source_measured"
        return {**base, "status": "unavailable", "attention_now": 50.0, "digest_prominence": 50.0,
                "confidence": 0.0, "age_bucket": "unknown", "normalized_signals": {}}, {}

    def scale(source: str, value: float) -> float:
        reference = references.get(source) or DEFAULT_REFERENCE[source]
        return round(min(100.0, 100.0 * value / reference), 1)

    coverage = sum(SOURCE_WEIGHTS[source] for source in measured) / sum(
        SOURCE_WEIGHTS[source] for source in applicable
    )
    scores = {source: scale(source, magnitudes[source]) for source in measured}
    now_scores = {
        source: scores[source] if source in _POINT_IN_TIME_SOURCES else scale(source, recent_magnitudes[source])
        for source in measured
    }
    if not any(value > 0 for value in scores.values()):
        return {**base, "status": "no_matches", "attention_now": 0.0, "digest_prominence": 0.0,
                "confidence": round(NO_MATCH_CONFIDENCE * coverage, 2), "age_bucket": "unknown",
                "normalized_signals": scores}, magnitudes
    age_hours = (
        max(0.0, (window_end.timestamp() - first_seen) / 3600) if first_seen is not None else None
    )
    return {**base, "status": "ok", "attention_now": _blend(now_scores), "digest_prominence": _blend(scores),
            "confidence": round(MATCH_CONFIDENCE * coverage, 2), "age_bucket": _age_bucket(age_hours),
            "normalized_signals": scores}, magnitudes


def neutral_attention(section: str, reason: str) -> dict[str, Any]:
    """Confidence-zero attention that leaves ranking to importance alone."""
    return {
        "schema_version": SCHEMA_VERSION,
        "provider": PROVIDER,
        "status": "out_of_scope" if reason == "out_of_scope" else "unavailable",
        "attention_now": 50.0,
        "digest_prominence": 50.0,
        "confidence": 0.0,
        "age_bucket": "over-24h" if reason == "out_of_scope" else "unknown",
        "normalized_signals": {},
        "evidence": {
            "sources": list(section_sources(section)),
            "unavailable_reason": reason,
        },
    }


# ---------------------------------------------------------------- Jev importance

def importance_from_answers(answers: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Combine atomic Jev judgments in code; weights live here, not in a prompt."""
    consequence = float(answers["consequence"]["score"]) / 4.0
    scope = float(answers["scope"]["score"]) / 4.0
    nouls = {key: float(answers[key]["noul"]) for key in ("routine", "binding", "harm", "first", "opinion")}
    raw = (
        consequence * (0.4 + 0.6 * scope)
        + 0.10 * max(nouls["binding"], nouls["harm"])
        + 0.05 * nouls["first"]
        - 0.25 * nouls["routine"]
        - 0.15 * nouls["opinion"]
    )
    confidence = (float(answers["consequence"]["confidence"]) + float(answers["scope"]["confidence"])) / 2.0
    return {
        "score": round(100.0 * min(1.0, max(0.0, raw)), 1),
        "confidence": round(confidence, 2),
        "answers": {
            "consequence": round(float(answers["consequence"]["score"]), 2),
            "scope": round(float(answers["scope"]["score"]), 2),
            **{key: round(value, 2) for key, value in nouls.items()},
        },
    }


def assess_importance(
    items: list[dict[str, Any]],
    client: Any,
    *,
    section_label: str,
) -> tuple[list[dict[str, Any] | None], int]:
    """Jev importance per item; returns (importance, failed assessments).

    A story whose assessment failed keeps ``None``: its importance stays at its
    editorial points, neither raised nor lowered by Jev.
    """
    if client is None or not items:
        return [None] * len(items), 0

    def one(item: dict[str, Any]) -> dict[str, Any] | None:
        state = {"story": {
            "section": section_label,
            "headline": _clean_text(item.get("title")),
            "summary": _clean_text(item.get("summary") or item.get("event"))[:1200],
            "source": _clean_text(item.get("source_domain")),
        }}
        try:
            answers = client.ask("news.importance", state, IMPORTANCE_QUESTIONS)
        except JevUnavailable:  # Jev is optional; missing importance uses editorial only
            return None
        return importance_from_answers(answers)

    with ThreadPoolExecutor(IMPORTANCE_WORKERS) as pool:
        results = list(pool.map(one, items))
    return results, sum(result is None for result in results)


# ---------------------------------------------------------------- product priority

def importance_score(significance: str, importance: dict[str, Any] | None) -> float:
    editorial = EDITORIAL_POINTS.get(significance, EDITORIAL_POINTS["medium"])
    if not importance:
        return editorial
    weight = IMPORTANCE_JEV_WEIGHT * float(importance["confidence"])
    return round(
        (IMPORTANCE_EDITORIAL_WEIGHT * editorial + weight * float(importance["score"]))
        / (IMPORTANCE_EDITORIAL_WEIGHT + weight),
        1,
    )


def blended_priority(significance: str, importance: dict[str, Any] | None, attention: dict[str, Any]) -> float:
    """Confidence-weighted blend of importance (editorial + Jev) and observed attention."""
    base = importance_score(significance, importance)
    weight = PRIORITY_ATTENTION_WEIGHT * float(attention.get("confidence") or 0.0)
    return round(
        (PRIORITY_IMPORTANCE_WEIGHT * base + weight * float(attention.get("digest_prominence") or 0.0))
        / (PRIORITY_IMPORTANCE_WEIGHT + weight),
        1,
    )


def _explain(significance: str, importance: dict[str, Any] | None, attention: dict[str, Any]) -> str:
    parts = [f"{significance.title()} editorial significance"]
    if importance:
        parts.append(f"Jev importance {importance['score']:.0f} (confidence {importance['confidence']:.2f})")
    status = attention.get("status")
    excluded = (attention.get("evidence") or {}).get("sources_excluded") or []
    if status == "ok":
        sources = [source for source, value in (attention.get("normalized_signals") or {}).items() if value > 0]
        parts.append(
            f"observed attention {attention['digest_prominence']:.0f} from {', '.join(sources)} "
            f"(confidence {attention['confidence']:.2f})"
        )
    elif status == "no_matches":
        parts.append("no matching coverage, sharing, or discussion was observed in the edition window")
    elif status == "out_of_scope":
        parts.append("attention applies only to events first observed in the edition window")
    else:
        parts.append("observed attention was unavailable, so it does not affect priority")
    if excluded and status in ("ok", "no_matches"):
        parts.append(f"{', '.join(excluded)} not collected in full and left out")
    return "; ".join(parts) + "."


def apply_priority(
    item: dict[str, Any],
    *,
    measurement: dict[str, Any],
    importance: dict[str, Any] | None,
) -> dict[str, Any]:
    """Attach attention, Jev importance, and the blended product priority."""
    significance = item["editorial_significance"]
    if importance:
        item["jev_importance"] = importance
    item["attention"] = measurement
    item["priority_score"] = blended_priority(significance, importance, measurement)
    item["priority_explanation"] = _explain(significance, importance, measurement)
    return item


def score_attention(
    candidates: list[dict[str, Any]],
    *,
    section: str,
    evidence: list[dict[str, Any]],
    importance: list[dict[str, Any] | None],
    measured_sources: frozenset[str] | set[str],
    references: dict[str, float],
    window_end: datetime,
    observed_at: datetime | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Score fresh candidates; returns (scored items, durable observation rows).

    Evidence carrying ``unavailable_reason`` (offline, no Jev key, or a failed
    adjudication for that story) gives confidence-zero attention: the story ranks
    on importance alone, neither boosted nor penalized by attention.
    """
    observed = observed_at or datetime.now(timezone.utc)
    scored = [enforce_editorial_significance(copy.deepcopy(item)) for item in candidates]
    observations: list[dict[str, Any]] = []
    for item, found, judged in zip(scored, evidence, importance):
        if found.get("unavailable_reason"):
            attention, magnitudes = neutral_attention(section, found["unavailable_reason"]), {}
        else:
            attention, magnitudes = measured_attention(
                found, section=section, measured_sources=measured_sources, references=references,
                window_end=window_end, first_seen=found.get("first_seen"),
            )
        apply_priority(item, measurement=attention, importance=judged)
        observations.append({
            "title": item.get("title", ""),
            "url": item.get("url", ""),
            "editorial_significance": item["editorial_significance"],
            "priority_score": item["priority_score"],
            "jev_importance": judged,
            "attention": attention,
            "magnitudes": {source: round(value, 4) for source, value in magnitudes.items()},
            "samples": found.get("samples") or [],
            "observed_at": observed.isoformat(),
        })
    return scored, observations


def score_ongoing(
    items: list[dict[str, Any]],
    *,
    section: str,
    importance: list[dict[str, Any] | None],
) -> list[dict[str, Any]]:
    """Older candidates rank on importance; attention applies only to the edition window."""
    scored = [normalize_editorial_significance(copy.deepcopy(item)) for item in items]
    for item, judged in zip(scored, importance):
        apply_priority(item, measurement=neutral_attention(section, "out_of_scope"), importance=judged)
    return scored


# ---------------------------------------------------------------- offline analysis

def _analysis_duration(value: Any) -> float | None:
    """Normalize an optional measured duration for offline analysis output."""
    if value is None:
        return None
    try:
        duration = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(duration):
        return None
    return round(max(0.0, duration), 3)


def _analysis_identity(item: dict[str, Any]) -> str:
    url = _clean_text(item.get("url"))
    title = _clean_text(item.get("title"))
    return url or title or "(untitled candidate)"


def _analysis_rank_indices(items: list[dict[str, Any]]) -> dict[int, int]:
    """Rank items with the production tie-breakers and no input-order fallback."""
    return {
        index: rank
        for rank, index in enumerate(
            sorted(
                range(len(items)),
                key=lambda index: (
                    priority_sort_key(items[index]),
                    _analysis_identity(items[index]).casefold(),
                ),
                reverse=True,
            ),
            start=1,
        )
    }


def analyze_attention_artifact(
    artifact: dict[str, Any],
    *,
    phase_elapsed_seconds: float | int | None = None,
    run_elapsed_seconds: float | int | None = None,
) -> dict[str, Any]:
    """Compare recorded priorities with an editorial-only baseline offline.

    This consumes an existing ``02b-attention.json`` payload only.  It performs
    no provider or model calls and reports measured attention status, score
    deltas, deterministic rank changes for the applied priority, and (when
    supplied) phase/runtime attribution from durable workflow state.
    """
    if not isinstance(artifact, dict):
        raise TypeError("attention artifact must be a JSON object")

    raw_observations = artifact.get("observations")
    observations = (
        [row for row in raw_observations if isinstance(row, dict)]
        if isinstance(raw_observations, list)
        else []
    )
    raw_fresh = artifact.get("fresh")
    fresh = (
        [item for item in raw_fresh if isinstance(item, dict)]
        if isinstance(raw_fresh, list)
        else []
    )
    items = [copy.deepcopy(item) for item in (fresh or observations)]

    baseline: list[dict[str, Any]] = []
    recorded: list[dict[str, Any]] = []
    statuses: list[str] = []
    delta_rows: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        normalize_editorial_significance(item)
        observation = observations[index] if index < len(observations) else {}
        measured = observation.get("attention") if isinstance(observation.get("attention"), dict) else {}
        status = _clean_text(
            measured.get("status") or (item.get("attention") or {}).get("status") or "unavailable"
        ).lower()
        statuses.append(status)

        significance = item["editorial_significance"]
        baseline_item = copy.deepcopy(item)
        baseline_item["priority_score"] = EDITORIAL_POINTS[significance]
        baseline_item["attention"] = {"digest_prominence": 0.0, "attention_now": 0.0, "confidence": 0.0}
        baseline.append(baseline_item)

        recorded_item = copy.deepcopy(item)
        recorded_item["priority_score"] = (
            _numeric(item.get("priority_score"))
            if item.get("priority_score") is not None
            else EDITORIAL_POINTS[significance]
        )
        recorded.append(recorded_item)

        baseline_score = EDITORIAL_POINTS[significance]
        delta_rows.append({
            "title": _clean_text(item.get("title")),
            "url": _clean_text(item.get("url")),
            "editorial_significance": significance,
            "attention_status": status,
            "editorial_only_priority": baseline_score,
            "recorded_priority": _numeric(recorded_item["priority_score"]),
            "priority_delta": round(_numeric(recorded_item["priority_score"]) - baseline_score, 1),
        })

    baseline_ranks = _analysis_rank_indices(baseline)
    recorded_ranks = _analysis_rank_indices(recorded)
    for index, row in enumerate(delta_rows):
        row["editorial_only_rank"] = baseline_ranks[index]
        row["recorded_rank"] = recorded_ranks[index]
        row["rank_delta"] = baseline_ranks[index] - recorded_ranks[index]

    candidate_count = len(items)
    available = sum(status in {"ok", "no_matches"} for status in statuses)
    unavailable = sum(status == "unavailable" for status in statuses)
    status_counts: dict[str, int] = {}
    for status in statuses:
        status_counts[status] = status_counts.get(status, 0) + 1

    def order(ranks: dict[int, int], population: list[dict[str, Any]]) -> list[str]:
        return [_analysis_identity(population[index])
                for index, _rank in sorted(ranks.items(), key=lambda pair: pair[1])]

    baseline_order = order(baseline_ranks, baseline)
    recorded_order = order(recorded_ranks, recorded)
    top_n = min(5, candidate_count)

    def comparison(key: str, rank_key: str, ordering: list[str]) -> dict[str, Any]:
        deltas = [float(row[key]) for row in delta_rows]
        rank_deltas = [int(row[rank_key]) for row in delta_rows]
        return {
            "mean": round(
                sum(EDITORIAL_POINTS.get(row["editorial_significance"], 60.0) + float(row[key])
                    for row in delta_rows) / candidate_count, 2,
            ) if candidate_count else 0.0,
            "mean_delta": round(sum(deltas) / candidate_count, 2) if candidate_count else 0.0,
            "score_changed": sum(abs(delta) > 0.05 for delta in deltas),
            "promoted": sum(delta > 0 for delta in rank_deltas),
            "demoted": sum(delta < 0 for delta in rank_deltas),
            "rank_unchanged": sum(delta == 0 for delta in rank_deltas),
            "top_n_overlap": len(set(baseline_order[:top_n]) & set(ordering[:top_n])) if top_n else 0,
            "order": ordering,
        }

    summary: dict[str, Any] = {
        "schema_version": 3,
        "provider": artifact.get("provider", PROVIDER),
        "observed_at": artifact.get("observed_at", ""),
        "coverage": {
            "candidates": candidate_count,
            "available": available,
            "unavailable": unavailable,
            "coverage_rate": round(available / candidate_count, 3) if candidate_count else 0.0,
            "status_counts": dict(sorted(status_counts.items())),
            "budget_seconds": _analysis_duration(artifact.get("budget_seconds")),
            "budget_scope": artifact.get("budget_scope"),
            "snapshot_sources": {
                name: (meta or {}).get("status")
                for name, meta in sorted(((artifact.get("snapshot") or {}).get("sources") or {}).items())
            },
            "jev": artifact.get("jev") or {},
        },
        "priority": {
            "editorial_only_mean": round(
                sum(EDITORIAL_POINTS.get(row["editorial_significance"], 60.0) for row in delta_rows)
                / candidate_count, 2,
            ) if candidate_count else 0.0,
            "top_n": top_n,
            "editorial_only_order": baseline_order,
            "recorded": comparison("priority_delta", "rank_delta", recorded_order),
            "rank_changes": delta_rows,
        },
    }

    phase_seconds = _analysis_duration(phase_elapsed_seconds)
    if phase_seconds is None:
        phase_seconds = _analysis_duration(artifact.get("elapsed_seconds"))
    run_seconds = _analysis_duration(run_elapsed_seconds)
    if phase_seconds is not None or run_seconds is not None:
        runtime: dict[str, Any] = {
            "attention_stage_seconds": phase_seconds,
            "total_run_seconds": run_seconds,
        }
        if phase_seconds is not None and run_seconds is not None:
            runtime["other_phase_seconds"] = round(max(0.0, run_seconds - phase_seconds), 3)
            runtime["attention_share"] = round(
                phase_seconds / run_seconds, 3
            ) if run_seconds > 0 else 0.0
        summary["runtime"] = runtime
    return summary
