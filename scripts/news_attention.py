#!/usr/bin/env python3
"""Public Daily News attention-scoring owner.

Implementation lives in :mod:`daily_news.attention`; this stable module path is
kept for callers that use the historical script name.
"""
from daily_news.attention import (  # noqa: F401
    ATTENTION_BUDGET_SCOPE,
    ATTENTION_STAGE_BUDGET_SECONDS,
    EDITORIAL_POINTS,
    MAX_ATTENTION_STAGE_BUDGET_SECONDS,
    SCHEMA_VERSION,
    analyze_attention_artifact,
    blended_priority,
    canonicalize_publisher_url,
    enforce_editorial_significance,
    event_term_source,
    event_terms,
    normalize_editorial_significance,
    priority_sort_key,
    score_attention,
    score_ongoing,
)


__all__ = (
    "ATTENTION_BUDGET_SCOPE",
    "ATTENTION_STAGE_BUDGET_SECONDS",
    "EDITORIAL_POINTS",
    "MAX_ATTENTION_STAGE_BUDGET_SECONDS",
    "SCHEMA_VERSION",
    "analyze_attention_artifact",
    "blended_priority",
    "canonicalize_publisher_url",
    "enforce_editorial_significance",
    "event_term_source",
    "event_terms",
    "normalize_editorial_significance",
    "priority_sort_key",
    "score_attention",
    "score_ongoing",
)
