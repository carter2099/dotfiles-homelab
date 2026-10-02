"""Cohesive Daily News pipeline modules.

Public owners are intentionally explicit: topic policy lives in ``catalog``,
source contracts in ``contracts``, OMP/cache plumbing in ``runtime``, research
phases in ``research``, curation in ``editorial``, copy in ``copy``, and
archive/render phases in ``archive``.
"""

from .catalog import (
    BATCH_SIZE,
    CROSS_DAY_DEDUP_DAYS,
    EDITORIAL_SIGNIFICANCE_RUBRIC_SHARED,
    EDITORIAL_SIGNIFICANCE_RUBRIC_SPECIFIC,
    FRESH_CAP,
    RANKING_SCHEMA_VERSION,
    REFERENCED_URLS_SCHEMA_VERSION,
    REFERENCED_URL_TIMEOUT,
    STANDFIRST_PROMPT_VERSION,
    TOPICS,
    editorial_significance_rubric_text,
)
from .contracts import (
    candidate_fresh_date,
    coverage_key,
    is_asset_cdn_url,
    is_fresh_eligible,
    is_listing_url,
    load_cross_topic_urls,
    load_recent_coverage_ledger,
    normalize_url,
    parse_date,
    record_referenced_urls,
)
from .runtime import (
    ARTICLE_CACHE_DIR,
    ATTENTION_ARCHIVE_DIR,
    ATTENTION_HEALTH_LOG_PATH,
    ATTENTION_SNAPSHOT_DIR,
    DIGESTS_DIR,
    DIGEST_OMP_CONFIG,
    DIGEST_OMP_SANDBOX,
    HEALTH_LOG_PATH,
    MODEL,
    MODEL_FALLBACK,
    MODEL_REVIEWER,
    TEST_LABEL,
    TEST_MODE,
    check_search_health,
    configure_test_mode,
)
from .research import (
    batch,
    phase_1_research,
    phase_2_judge_research,
    phase_2b_attention,
    phase_3_rank,
    phase_4_fetch,
    phase_5_judge_summaries,
    refetch_article_date,
)
from .editorial import (
    apply_editorial_patches,
    clean_editorial_text,
    editorial_candidate_id,
    materialize_editorial_selection,
    phase_6_curate,
    prepare_editorial_candidates,
    raw_editorial_proposal,
    validate_editorial_proposal,
)
from .copy import (
    fallback_standfirst,
    first_complete_sentence,
    generate_section_standfirst,
    model_attempts,
    standfirst_story_fingerprint,
    validate_standfirst,
)
from .archive import (
    archive_stub_attempt,
    cleanup_old_artifacts,
    cleanup_stub_attempts,
    empty_section_block,
    phase_7_write,
    phase_8_archive,
    phase_9_summary,
    public_story,
    render_digest_html,
    render_story_block,
)
from .workflow import run_digest, validate_runtime_contract

__all__ = (
    "TOPICS",
    "DIGESTS_DIR",
    "run_digest",
    "validate_runtime_contract",
    "phase_1_research",
    "phase_2_judge_research",
    "phase_2b_attention",
    "phase_3_rank",
    "phase_4_fetch",
    "phase_5_judge_summaries",
    "phase_6_curate",
    "phase_7_write",
    "phase_8_archive",
    "phase_9_summary",
    "normalize_url",
    "validate_editorial_proposal",
    "validate_standfirst",
)
