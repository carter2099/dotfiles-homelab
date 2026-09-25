#!/usr/bin/env python3
"""Focused behavioral fixtures for digest dedup, cache, editorial, and rendering."""
from __future__ import annotations

import copy
import gzip
import json
import os
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from daily_news import archive, attention, attention_sources, catalog, contracts, copy as copy_module, editorial, research, runtime, workflow  # noqa: E402
import jev  # noqa: E402


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)

def validated_high_fields() -> dict:
    return {
        "editorial_significance": "high",
        "significance_evidence": {
            "basis": "binding_policy_or_law",
            "affected_scope": "sector",
            "impact": "A binding decision materially affects the documented sector.",
        },
        "significance_validation": {
            "status": "accepted",
            "reason": "binding_policy_or_law with sector affected scope",
        },
    }


def test_url_normalization() -> None:
    normalized = contracts.normalize_url(
        "HTTPS://www.Example.com/Case-Sensitive/?utm_source=x&b=2&a=1#fragment"
    )
    check(normalized == "example.com/Case-Sensitive?a=1&b=2", normalized)

def test_referenced_url_collection_uses_catalog_filters() -> None:
    class FakeResponse:
        text = """
        <a href="/same-site-story">same site</a>
        <a href="https://twitter.com/example/status/1">social</a>
        <a href="https://source.example/privacy">utility</a>
        <a href="https://source.example/news/verified-story?utm_source=page">source</a>
        """
        content = text.encode()

        def raise_for_status(self) -> None:
            return None

    with patch("daily_news.contracts.requests.get", return_value=FakeResponse()):
        referenced = contracts.collect_referenced_urls(
            "https://publisher.example/articles/primary"
        )

    check(
        referenced == ["source.example/news/verified-story"],
        f"referenced URLs were not filtered: {referenced!r}",
    )



def test_search_health_uses_fresh_news_path() -> None:
    """Health must exercise the time-filtered news path used for discovery."""
    class FakeResponse:
        def __init__(self, results: list[dict]) -> None:
            self._results = results

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {
                "results": self._results,
                "unresponsive_engines": [["startpage news", "Suspended: CAPTCHA"]],
            }

    class FakeCompleted:
        stdout = ""
        stderr = "ERROR:searx.engines one recent engine failure\n"

    request: dict = {}

    def fresh_get(url, params=None, timeout=None):
        request.update({"url": url, "params": params, "timeout": timeout})
        return FakeResponse([{"engines": ["bing news", "reuters"]}])

    with tempfile.TemporaryDirectory() as temporary, \
         patch("daily_news.runtime.requests.get", side_effect=fresh_get), \
         patch("daily_news.runtime.subprocess.run", return_value=FakeCompleted()), \
         patch("daily_news.runtime.HEALTH_LOG_PATH", Path(temporary) / "health.jsonl"):
        status = runtime.check_search_health("test-fresh")

    check(request["params"]["categories"] == "news", request)
    check(request["params"]["time_range"] == "day", request)
    check(request["params"]["language"] == "en", request)
    check(status["engines_working"] == ["bing news", "reuters"], status)
    check(status["recent_errors"] == 1, status)
    check(status["ok"], status)

    with tempfile.TemporaryDirectory() as temporary, \
         patch("daily_news.runtime.requests.get", return_value=FakeResponse([])), \
         patch("daily_news.runtime.subprocess.run", return_value=FakeCompleted()), \
         patch("daily_news.runtime.HEALTH_LOG_PATH", Path(temporary) / "health.jsonl"):
        empty_status = runtime.check_search_health("test-empty")

    check(empty_status["recommendation"] == "warn", empty_status)
    check(not empty_status["ok"], empty_status)


def test_tool_omp_uses_digest_specific_config() -> None:
    """Tool-using digest calls must not alter every headless OMP consumer."""
    class FakeCompleted:
        returncode = 0
        stdout = "ok"
        stderr = ""

    with patch("daily_news.runtime._effective_model", return_value="provider/model"), \
         patch("daily_news.runtime.subprocess.run", return_value=FakeCompleted()) as run:
        result = runtime._call_omp_p("search once", append_system="system")

    command = run.call_args.args[0]
    config_index = command.index("--config") + 1
    check(command[config_index] == str(runtime.DIGEST_OMP_CONFIG), command)
    check("headless-override.yml" not in command[config_index], command)
    check(result == "ok", result)


def test_research_prompts_do_not_request_article_reads() -> None:
    for topic_name, topic in catalog.TOPICS.items():
        for angle in topic["research_angles"]:
            prompt_text = angle["prompt"].lower()
            label = f"{topic_name}/{angle['id']}"
            check("web_fetch" not in prompt_text, f"{label} requests unavailable web_fetch")
            check("use read" not in prompt_text, f"{label} reads articles during discovery")


def test_test_mode_isolates_mutable_shared_state() -> None:
    with tempfile.TemporaryDirectory() as temporary, patch.multiple(
        runtime,
        TEST_MODE=False,
        ARTICLE_CACHE_DIR=Path("/production/article-cache"),
        ATTENTION_SNAPSHOT_DIR=Path("/production/attention-snapshot"),
        ATTENTION_ARCHIVE_DIR=Path("/production/attention"),
        HEALTH_LOG_PATH=Path("/production/search-health.log"),
        ATTENTION_HEALTH_LOG_PATH=Path("/production/attention-health.log"),
    ):
        root = Path(temporary)
        runtime.configure_test_mode(root)
        check(runtime.TEST_MODE, "test mode was not enabled")
        check(
            runtime.ARTICLE_CACHE_DIR == root / ".article-cache",
            "test article cache escaped the test root",
        )
        check(
            runtime.ATTENTION_SNAPSHOT_DIR == root / ".attention-snapshot",
            "test attention snapshot escaped the test root",
        )
        check(
            runtime.ATTENTION_ARCHIVE_DIR == root / "news" / "attention",
            "test attention archive escaped the test root",
        )
        check(
            runtime.HEALTH_LOG_PATH == root / ".search-health.log",
            "test health log escaped the test root",
        )
        check(
            runtime.ATTENTION_HEALTH_LOG_PATH == root / ".attention-health.log",
            "test attention health log escaped the test root",
        )


def test_attention_health_monitors_source_availability_and_jev() -> None:
    """Attention health records snapshot source availability, match rate, and Jev status."""
    artifact = {
        "schema_version": 7,
        "provider": "Daily News attention snapshot",
        "snapshot": {"id": "abc", "sources": {
            "gkg": {"status": "ok"}, "hn": {"status": "ok"}, "panel": {"status": "ok"},
            "jetstream": {"status": "unavailable"}, "techmeme": {"status": "skipped"},
        }},
        "jev": {"status": "ok", "requests": 4, "input_tokens": 900, "failures": 0},
        "observations": [
            {"title": "loud", "attention": {"status": "ok"}},
            {"title": "quiet", "attention": {"status": "no_matches"}},
        ],
    }
    with tempfile.TemporaryDirectory() as temporary, patch(
        "daily_news.runtime.ATTENTION_HEALTH_LOG_PATH",
        Path(temporary) / "attention-health.log",
    ) as log_path:
        status = runtime.check_attention_health(artifact, label="test")
        check(status["ok"] and status["recommendation"] == "ok", status)
        check(status["source_availability"] == 0.75, status)
        check(status["matched"] == 1 and status["no_matches"] == 1 and status["match_rate"] == 0.5, status)
        check(status["window_availability"] == 0.75, status)
        lines = log_path.read_text().splitlines()
        check(len(lines) == 1 and json.loads(lines[0])["kind"] == "attention", lines)

    degraded = {**artifact, "snapshot": {"id": "def", "sources": {
        "gkg": {"status": "unavailable"}, "hn": {"status": "unavailable"}, "panel": {"status": "ok"},
    }}}
    prior = {"kind": "attention", "timestamp": "2026-09-24T06:00:00+00:00", "source_availability": 0.2,
             "recommendation": "warn", "ok": False}
    with tempfile.TemporaryDirectory() as temporary, patch(
        "daily_news.runtime.ATTENTION_HEALTH_LOG_PATH",
        Path(temporary) / "attention-health.log",
    ) as log_path:
        log_path.write_text(json.dumps(prior) + "\n")
        status = runtime.check_attention_health(degraded, label="degraded")
        check(not status["ok"] and status["recommendation"] == "warn", status)
        check(status["window_availability"] == round((1 / 3 + 0.2) / 2, 3), status)
        check(status["degradation"] == {"sources": True, "persistent_sources": [], "jev": False}, status)
        jev_down = runtime.check_attention_health(
            {**artifact, "jev": {"status": "degraded"}}, label="jev")
        check(jev_down["degradation"]["jev"], jev_down)

    # One source incomplete in every run of the window is flagged even though availability stays high.
    panel_down = {**artifact, "snapshot": {"id": "p", "sources": {
        "gkg": {"status": "ok"}, "hn": {"status": "ok"}, "jetstream": {"status": "ok"},
        "mastodon": {"status": "ok"}, "panel": {"status": "partial"},
    }}}
    with tempfile.TemporaryDirectory() as temporary, patch(
        "daily_news.runtime.ATTENTION_HEALTH_LOG_PATH",
        Path(temporary) / "attention-health.log",
    ):
        for run in range(runtime.ATTENTION_HEALTH_WINDOW_RUNS):
            status = runtime.check_attention_health(panel_down, label=f"run-{run}")
            last = run == runtime.ATTENTION_HEALTH_WINDOW_RUNS - 1
            check(status["persistent_source_failures"] == (["panel"] if last else []), (run, status))
        check(status["recommendation"] == "warn" and status["window_availability"] == 0.8, status)


def test_article_cache_contract() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        cache_dir = Path(temporary)
        now = datetime(2026, 8, 10, 12, tzinfo=timezone.utc)
        result = {
            "title": "Cached title",
            "url": "https://example.com/story",
            "summary": "Cached factual summary.",
            "fetch_success": True,
        }
        runtime._save_article_cache(
            "https://example.com/story?utm_source=test",
            result,
            model=runtime.MODEL,
            cache_dir=cache_dir,
            now=now,
        )
        hit = runtime._load_article_cache(
            "https://www.example.com/story",
            model=runtime.MODEL,
            cache_dir=cache_dir,
            now=now + timedelta(hours=1),
        )
        check(hit == result, f"cache hit={hit!r}")
        wrong_model = runtime._load_article_cache(
            "https://example.com/story",
            model=runtime.MODEL_FALLBACK,
            cache_dir=cache_dir,
            now=now + timedelta(hours=1),
        )
        check(wrong_model is None, "cache crossed model contract")
        stale = runtime._load_article_cache(
            "https://example.com/story",
            model=runtime.MODEL,
            cache_dir=cache_dir,
            now=now + timedelta(hours=25),
        )
        check(stale is None, "stale cache entry was reused")
        removed = runtime._prune_article_cache(
            cache_dir=cache_dir, now=now + timedelta(hours=25)
        )
        check(removed == 1, f"expired cache entries removed={removed}")
        check(not list(cache_dir.glob("*.json")), "expired cache file remained")


def test_cross_topic_dedup_precedes_fetch_queue() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        run_dir = root / "ai-tech" / "2026-08-10"
        run_dir.mkdir(parents=True)
        other_category = catalog.TOPICS["gaming"]["category"]
        other_dir = root / other_category / "2026-08-10"
        other_dir.mkdir(parents=True)
        duplicate = "https://example.com/shared?utm_source=gaming"
        (other_dir / "06-curated.json").write_text(json.dumps({
            "fresh": [{"url": duplicate}],
            "ongoing": [],
        }))
        fresh = [
            {
                "title": "Duplicate",
                "url": "https://www.example.com/shared",
                "editorial_significance": "high",
                "date_published": "2026-08-10",
            },
            {
                "title": "Unique",
                "url": "https://example.com/unique",
                "editorial_significance": "medium",
                "date_published": "2026-08-10",
            },
        ]
        with patch.object(runtime, "DIGESTS_DIR", root):
            queue, _ = research.phase_3_rank(
                catalog.TOPICS["ai-tech"], fresh, [], {"stories": []}, run_dir
            )
        check([item["title"] for item in queue] == ["Unique"], f"queue={queue!r}")
        artifact = json.loads((run_dir / "03-urls-ranked.json").read_text())
        check(len(artifact["cross_topic_rejected"]) == 1, "skip was not audited")


def test_cross_topic_same_event_referenced_url_dedup() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        run_dir = root / "ai-tech" / "2026-08-26"
        run_dir.mkdir(parents=True)
        other = root / catalog.TOPICS["gaming"]["category"] / "2026-08-26"
        other.mkdir(parents=True)
        (other / "06-curated.json").write_text(json.dumps({
            "fresh": [{
                "url": "https://techcrunch.com/2026/08/25/openai-jalapeno-chip",
            }],
            "ongoing": [],
        }))
        (other / "referenced-urls.json").write_text(json.dumps({
            "schema_version": catalog.REFERENCED_URLS_SCHEMA_VERSION,
            "generated_at": "2026-08-27T00:00:00+00:00",
            "stories": [{
                "url": "https://techcrunch.com/2026/08/25/openai-jalapeno-chip",
                "referenced_urls": [
                    "https://openai.com/index/jalapeno-inference-chip/",
                ],
            }],
        }))
        fresh = [
            {
                "title": "Same event via source page",
                "url": "https://openai.com/index/jalapeno-inference-chip/",
                "editorial_significance": "high",
                "date_published": "2026-08-25",
            },
            {
                "title": "Unique story",
                "url": "https://example.com/unique",
                "editorial_significance": "medium",
                "date_published": "2026-08-25",
            },
        ]
        with patch.object(runtime, "DIGESTS_DIR", root):
            queue, _ = research.phase_3_rank(
                catalog.TOPICS["ai-tech"], fresh, [], {"stories": []}, run_dir
            )
        check(
            [item["title"] for item in queue] == ["Unique story"],
            f"queue={queue!r}",
        )
        artifact = json.loads((run_dir / "03-urls-ranked.json").read_text())
        check(
            len(artifact["cross_topic_rejected"]) == 1,
            "same-event source-page URL not blocked",
        )


def test_rank_resume_fingerprint_includes_cross_topic_urls() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        run_dir = root / catalog.TOPICS["ai-tech"]["category"] / "2026-08-26"
        run_dir.mkdir(parents=True)
        candidate = {
            "title": "Shared event",
            "url": "https://example.com/shared-event",
            "editorial_significance": "medium",
            "date_published": "2026-08-26",
        }
        with patch.object(runtime, "DIGESTS_DIR", root):
            first, _ = research.phase_3_rank(
                catalog.TOPICS["ai-tech"],
                [copy.deepcopy(candidate)],
                [],
                {"stories": []},
                run_dir,
            )
            check(len(first) == 1, first)

            other_dir = (
                root
                / catalog.TOPICS["gaming"]["category"]
                / run_dir.name
            )
            other_dir.mkdir(parents=True)
            (other_dir / "06-curated.json").write_text(json.dumps({
                "fresh": [{"url": candidate["url"]}],
                "ongoing": [],
            }))
            second, _ = research.phase_3_rank(
                catalog.TOPICS["ai-tech"],
                [copy.deepcopy(candidate)],
                [],
                {"stories": []},
                run_dir,
            )
        check(not second, "rank reused cache after cross-topic URL set changed")


def test_phase_two_cross_day_dedup_window_contract() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        today = datetime.now(timezone.utc).date().isoformat()
        run_dir = root / "ai-tech" / today
        run_dir.mkdir(parents=True)
        finding = {
            "title": "Fresh verified event",
            "url": "https://example.com/fresh-event",
            "source_domain": "example.com",
            "date_published": today,
            "summary": "A source-grounded event occurred today.",
            "category": "Research",
            "editorial_significance": "medium",
            "event": "Fresh verified event occurs",
            "event_terms": ["Fresh verified", "event occurs"],
        }
        judged = {
            "approved": [finding],
            "rejected": [],
        }
        with patch(
            "daily_news.runtime._call_llm_proxy",
            return_value=json.dumps(judged),
        ):
            fresh, ongoing = research.phase_2_judge_research(
                catalog.TOPICS["ai-tech"],
                [finding],
                run_dir,
                {"stories": []},
            )
        check(catalog.CROSS_DAY_DEDUP_DAYS == 5, catalog.CROSS_DAY_DEDUP_DAYS)
        check(len(fresh) == 1 and not ongoing, (fresh, ongoing))


def test_phase_two_rejects_unvalidated_legacy_followup() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        today = datetime.now(timezone.utc).date().isoformat()
        run_dir = root / "world-digest" / today
        run_dir.mkdir(parents=True)
        root_url = "https://example.com/legacy-root"
        tracker = {
            "stories": [{
                "title": "Legacy high without evidence",
                "url": root_url,
                "editorial_significance": "high",
                "status": "active",
                "first_seen": "2026-08-20",
                "developments": [
                    {"date": "2026-08-20", "url": root_url},
                    {"date": "2026-08-21", "url": "https://example.com/update"},
                ],
            }]
        }
        finding = {
            "title": "Claimed legacy follow-up",
            "url": "https://example.com/new-update",
            "date_published": today,
            "summary": "A claimed update.",
            "editorial_significance": "high",
            "research_angle_id": "developing-followups",
            "develops_story_url": root_url,
        }
        with patch("daily_news.runtime._call_llm_proxy") as call:
            fresh, ongoing = research.phase_2_judge_research(
                catalog.TOPICS["world"], [finding], run_dir, tracker
            )
        check(not fresh and not ongoing, (fresh, ongoing))
        check(not call.called, "unvalidated legacy root reached the LLM judge")

def test_recent_coverage_ledger_blocks_other_section_repeats() -> None:
    """A story any section covered recently cannot re-enter another section.

    Regression for 2026-09-16/17: Salesforce's AIforce release ran in AI & Tech
    and again the next day in Agents because each section only read its own
    history. Canonical story URLs and recorded referenced URLs both count.
    """
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        today = "2026-09-17"
        run_dir = root / catalog.TOPICS["agentic-platform"]["category"] / today
        run_dir.mkdir(parents=True)
        prior = root / catalog.TOPICS["ai-tech"]["category"] / "2026-09-16"
        prior.mkdir(parents=True)
        aiforce = (
            "https://www.salesforce.com/ap/news/press-releases/2026/09/16/"
            "sg-salesforce-unveils-aiforce/?bc=OTH&utm_source=newsletter"
        )
        (prior / "06-curated.json").write_text(json.dumps({
            "fresh": [{"url": aiforce}],
            "ongoing": [],
        }))
        (prior / "referenced-urls.json").write_text(json.dumps({
            "schema_version": catalog.REFERENCED_URLS_SCHEMA_VERSION,
            "generated_at": "2026-09-16T08:00:00+00:00",
            "stories": [{
                "url": aiforce,
                "referenced_urls": ["https://investor.salesforce.com/aiforce-release"],
            }],
        }))
        # A category whose run directory was already cleaned still counts
        # through its archived Markdown summary.
        world_dir = root / catalog.TOPICS["world"]["category"]
        world_dir.mkdir(parents=True)
        (world_dir / "2026-09-14.md").write_text(
            "## Fresh\n- [Older world story](https://example.org/world/older-story/)\n"
        )
        # Coverage outside the window is not blocked.
        stale = root / catalog.TOPICS["gaming"]["category"] / "2026-09-10"
        stale.mkdir(parents=True)
        (stale / "06-curated.json").write_text(json.dumps({
            "fresh": [{"url": "https://example.net/outside-window"}],
            "ongoing": [],
        }))

        def finding(title: str, url: str) -> dict:
            return {
                "title": title,
                "url": url,
                "source_domain": "example.com",
                "date_published": today,
                "summary": f"{title} summary.",
                "category": "Platforms",
                "editorial_significance": "medium",
                "event": title,
                "event_terms": [title, "event"],
            }

        findings = [
            finding(
                "Salesforce unveils AIforce",
                "https://salesforce.com/ap/news/press-releases/2026/09/16/"
                "sg-salesforce-unveils-aiforce?bc=OTH",
            ),
            finding("AIforce investor release", "https://investor.salesforce.com/aiforce-release/"),
            finding("Older world story", "https://www.example.org/world/older-story"),
            finding("Outside window story", "https://example.net/outside-window"),
            finding("Genuinely new agent story", "https://example.com/new-agent-story"),
        ]
        with patch(
            "daily_news.runtime._call_llm_proxy",
            return_value=json.dumps({"approved": copy.deepcopy(findings), "rejected": []}),
        ):
            fresh, ongoing = research.phase_2_judge_research(
                catalog.TOPICS["agentic-platform"], copy.deepcopy(findings), run_dir,
                {"stories": []},
            )
        check(
            sorted(item["title"] for item in fresh)
            == ["Genuinely new agent story", "Outside window story"],
            f"recently covered stories re-entered another section: {fresh!r}",
        )
        check(not ongoing, ongoing)


def test_ongoing_card_follows_latest_verified_development() -> None:
    """An evidence-backed update replaces the displayed headline/link together.

    Regression for 2026-09-21/22: the World card still read "House approves
    Russia sanctions bill, sending it to Trump" above a summary saying Trump had
    signed it. Unprovable legacy records are withheld, and a fresh follow-up
    never ships beside its own stale ongoing card.
    """
    root_url = "https://apnews.com/article/house-russia-sanctions"
    followup_url = "https://www.aljazeera.com/news/2026/9/19/trump-signs-russia-sanctions"
    tracker = {"stories": [{
        "title": "House approves Russia sanctions bill, sending it to Trump",
        "url": root_url,
        "category": "Policy",
        "latest_dev": "The House approved the sanctions bill.",
        "status": "active",
        **validated_high_fields(),
        "first_seen": "2026-09-17",
        "developments": [
            {"date": "2026-09-17", "url": root_url},
            {"date": "2026-09-18", "url": root_url},
        ],
    }]}
    candidates, _ = editorial.prepare_editorial_candidates([{
        "title": "Trump signs Russia sanctions bill into law",
        "url": followup_url,
        "source_domain": "aljazeera.com",
        "summary": "Trump signed the Russia sanctions bill into law on Sept. 19.",
        "category": "Policy",
        **validated_high_fields(),
        "date_published": "2026-09-19",
        "date_confirmed": "2026-09-19",
        "develops_story_url": root_url,
        "source_verdict": "fresh",
        "judge_verdict": "keep",
    }], set())
    followup_id = candidates[0]["candidate_id"]
    proposal = {
        "selected_fresh": [{
            "candidate_id": followup_id,
            "editorial_summary": "Trump signed the Russia sanctions bill into law.",
            "related_story_url": root_url,
        }],
        "selected_ongoing": [{
            "story_url": root_url,
            "summary": "The House approved the sanctions bill.",
            "why_still_relevant": "Awaiting signature.",
        }],
        "story_state_proposals": [],
    }
    validated, _ = editorial.validate_editorial_proposal(
        proposal, candidates, tracker["stories"], tracker,
        issue_date=datetime(2026, 9, 20, tzinfo=timezone.utc).date(),
    )
    check(len(validated["selected_fresh"]) == 1, validated)
    check(
        validated["selected_ongoing"] == [],
        f"fresh follow-up shipped beside its stale ongoing card: {validated['selected_ongoing']!r}",
    )
    updated = editorial.apply_story_state_proposals(
        tracker, validated, candidates, "2026-09-20"
    )

    next_day = {
        "selected_fresh": [],
        "selected_ongoing": [{
            "story_url": root_url,
            "rank": 1,
            "summary": "Trump signed the Russia sanctions bill into law.",
            "why_still_relevant": "The bill became law on Sept. 19.",
        }],
    }
    _, ongoing = editorial.materialize_editorial_selection(next_day, [], updated)
    card = ongoing[0]
    check(
        card["title"] == "Trump signs Russia sanctions bill into law",
        f"ongoing card kept its first headline: {card['title']!r}",
    )
    check(card["url"] == followup_url, card["url"])
    check(card.get("date_published") == "2026-09-19", card)
    check(
        "signed" in updated["stories"][0]["latest_dev"],
        updated["stories"][0]["latest_dev"],
    )

    legacy = copy.deepcopy(tracker["stories"][0])
    legacy["url"] = "https://apnews.com/article/legacy-root"
    legacy["developments"] = [
        {"date": "2026-09-17", "url": legacy["url"]},
        {"date": "2026-09-20", "url": "https://example.com/unattributed-update"},
    ]
    legacy["latest_dev"] = "A newer development from an unrecorded source."
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        run_dir = root / catalog.TOPICS["world"]["category"] / "2026-09-21"
        run_dir.mkdir(parents=True)
        with patch.object(runtime, "DIGESTS_DIR", root):
            _, pool_c = research.phase_3_rank(
                catalog.TOPICS["world"], [], [],
                {"stories": [updated["stories"][0], legacy]}, run_dir,
            )
    check(
        [contracts.normalize_url(story["url"]) for story in pool_c]
        == [contracts.normalize_url(root_url)],
        f"unprovable tracker record reached Developing and Ongoing: {pool_c!r}",
    )

    # A pre-latest_source record (the real 2026-09-22 shape) recovers its
    # headline from the run that selected its newest evidence article; a
    # record whose evidence run is gone stays withheld.
    today = datetime.now(timezone.utc).date()
    evidence_day = (today - timedelta(days=1)).isoformat()
    recoverable = copy.deepcopy(tracker["stories"][0])
    recoverable["developments"] = [
        {"date": (today - timedelta(days=3)).isoformat(), "url": root_url},
        {"date": evidence_day, "url": followup_url},
    ]
    recoverable["latest_dev"] = "Trump signed the Russia sanctions bill into law."
    orphan = copy.deepcopy(recoverable)
    orphan["url"] = "https://apnews.com/article/orphan-root"
    orphan["developments"] = [
        {"date": (today - timedelta(days=3)).isoformat(), "url": orphan["url"]},
        {"date": evidence_day, "url": "https://example.com/unselected-update"},
    ]
    with tempfile.TemporaryDirectory() as temporary:
        digest_dir = Path(temporary) / catalog.TOPICS["world"]["category"]
        (digest_dir / evidence_day).mkdir(parents=True)
        (digest_dir / evidence_day / "06-curated.json").write_text(json.dumps({
            "fresh": [{
                "title": "Trump signs Russia sanctions bill into law",
                "url": followup_url,
                "date_confirmed": evidence_day,
            }],
            "ongoing": [],
        }))
        (digest_dir / "stories-in-flight.json").write_text(
            json.dumps({"stories": [recoverable, orphan]})
        )
        loaded = archive.load_and_prune_stories_in_flight(digest_dir)
    displays = [contracts.tracker_display_source(story) for story in loaded["stories"]]
    check(
        displays[0] is not None
        and displays[0]["title"] == "Trump signs Russia sanctions bill into law"
        and displays[0]["url"] == followup_url,
        f"legacy record did not recover its newest source: {displays!r}",
    )
    check(displays[1] is None, f"unprovable legacy record was displayed: {displays!r}")


def test_runtime_preflight_fails_closed_on_missing_symbol() -> None:
    workflow.validate_runtime_contract()
    with patch.object(catalog, "CROSS_DAY_DEDUP_DAYS", None):
        raised = False
        try:
            workflow.validate_runtime_contract()
        except RuntimeError as error:
            raised = "CROSS_DAY_DEDUP_DAYS" in str(error)
        check(raised, "preflight accepted a missing cross-day dedup contract")

    with tempfile.TemporaryDirectory() as temporary:
        missing_config = Path(temporary) / "missing-digest-config.yml"
        with patch.object(runtime, "DIGEST_OMP_CONFIG", missing_config):
            raised = False
            try:
                workflow.validate_runtime_contract()
            except RuntimeError as error:
                raised = "DIGEST_OMP_CONFIG" in str(error)
            check(raised, "preflight accepted a missing digest OMP config")

        wrong_config = Path(temporary) / "wrong-digest-config.yml"
        wrong_config.write_text(
            "providers:\n  webSearchOrder:\n    - searxng\n"
            "searxng:\n  endpoint: http://localhost:8080\n  categories: general,news\n"
        )
        with patch.object(runtime, "DIGEST_OMP_CONFIG", wrong_config):
            raised = False
            try:
                workflow.validate_runtime_contract()
            except RuntimeError as error:
                raised = "webSearchOrder" in str(error)
            check(raised, "preflight accepted the wrong search-provider order")

        localized_config = Path(temporary) / "localized-digest-config.yml"
        localized_config.write_text(
            "providers:\n  webSearchOrder:\n    - codex\n    - searxng\n"
            "searxng:\n  endpoint: http://localhost:8080\n"
            "  categories: general,news\n  language: en\n"
        )
        with patch.object(runtime, "DIGEST_OMP_CONFIG", localized_config):
            raised = False
            try:
                workflow.validate_runtime_contract()
            except RuntimeError as error:
                raised = "language must remain unset" in str(error)
            check(raised, "preflight accepted a forced search language")


def test_phase_inputs_include_actual_code_hashes() -> None:
    baseline = runtime.phase_inputs("contract-test", upstream={"value": 1})
    check(len(baseline["code_hash"]) == 64, baseline)
    for path in (
        Path(runtime.__file__).resolve(),
        runtime.DIGEST_OMP_CONFIG,
        runtime.DIGEST_OMP_SANDBOX,
        runtime.TEMPLATE_PATH,
    ):
        check(str(path) in baseline["code_hashes"], (path, baseline))
    real_hash = runtime.file_sha256

    def changed_hash(path) -> str:
        if Path(path).resolve() == Path(runtime.__file__).resolve():
            return "0" * 64
        return real_hash(path)

    with patch.object(runtime, "file_sha256", changed_hash):
        raised = False
        try:
            runtime.phase_inputs("contract-test", upstream={"value": 1})
        except RuntimeError as error:
            raised = "changed during the run" in str(error)
    check(raised, "mid-run code change did not abort resumable phase")


def test_empty_phase_has_explicit_durable_outcome() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        run_dir = Path(temporary) / "2026-09-01"
        artifact = run_dir / "empty.json"
        inputs = {"code_hash": "stable", "upstream": []}
        state, cached = runtime.begin_or_load_phase(
            run_dir,
            "empty-contract",
            inputs=inputs,
            artifact_path=artifact,
            schema_version=1,
            validator=lambda value: isinstance(value, dict),
        )
        check(cached is None, cached)
        runtime.complete_phase_json(
            state,
            "empty-contract",
            artifact,
            {"items": [], "reason": "no input"},
            outcome="empty",
            reason="no input",
        )
        record = state.phase_record("empty-contract")
        check(record["status"] == "succeeded", record)
        check(record["completion_outcome"] == "empty", record)
        check(record["completion_reason"] == "no input", record)
        _, resumed = runtime.begin_or_load_phase(
            run_dir,
            "empty-contract",
            inputs=inputs,
            artifact_path=artifact,
            schema_version=1,
            validator=lambda value: isinstance(value, dict),
        )
        check(resumed == {"items": [], "reason": "no input"}, resumed)


class _PhaseJev:
    """Deterministic Jev stand-in: relations by headline, fixed importance answers."""

    def ask(self, purpose: str, state: dict, questions: dict) -> dict:
        if "story" in state:
            return {
                "consequence": {"type": "score", "score": 3.0, "confidence": 0.8},
                "scope": {"type": "score", "score": 3.0, "confidence": 0.8},
                **{key: {"type": "noul", "noul": 0.0}
                   for key in ("routine", "binding", "harm", "first", "opinion")},
            }
        return {
            key: {"type": "score", "score": 2.0 if "Quasar" in state["items"][int(key[5:])]["headline"] else 0.0,
                  "confidence": 0.9}
            for key in questions
        }

    def usage(self) -> dict:
        return {"model": "jev-test", "requests": 1, "input_tokens": 10, "failures": 0}


def _write_snapshot(root: Path, edition: str, rows: list[dict], statuses: dict[str, str] | None = None) -> None:
    now = datetime.now(timezone.utc)
    snapshot = {
        "schema_version": attention_sources.SNAPSHOT_SCHEMA_VERSION,
        "id": "fixture-snapshot",
        "window_start": (now - timedelta(hours=30)).isoformat(),
        "window_end": now.isoformat(),
        "built_at": now.isoformat(),
        "elapsed_seconds": 1.0,
        # A non-ok fixture source has used every attempt, so the phase never retries it over the network.
        "sources": {name: {"status": status, "rows": 0,
                           **({"attempts": attention_sources.MAX_SOURCE_ATTEMPTS} if status != "ok" else {})}
                    for name, status in ((name, (statuses or {}).get(name, "ok"))
                                         for name in attention_sources.SOURCES)},
        "rows": rows,
    }
    path = root / edition / "snapshot.json.gz"
    path.parent.mkdir(parents=True)
    path.write_bytes(gzip.compress(json.dumps(snapshot).encode()))


def test_attention_phase_persists_durable_observations() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        run_dir = root / "run" / "2026-08-25"
        run_dir.mkdir(parents=True)
        fresh = [{
            "title": "Acme ships Quasar 9 accelerator",
            "event": "Acme released the Quasar 9 accelerator.",
            "event_terms": ["Quasar 9 accelerator", "Acme Quasar 9"],
            "url": "https://acme.example/quasar-9",
            "editorial_significance": "medium",
        }]
        ongoing = [{
            "title": "Older event",
            "url": "https://example.com/older",
            "editorial_significance": "high",
        }]
        now_s = int(datetime.now(timezone.utc).timestamp())
        rows = [
            {"src": "gkg", "t": now_s - 3600, "domain": f"outlet{i}.example",
             "url": f"https://outlet{i}.example/q9", "title": f"Quasar 9 accelerator review number {i}"}
            for i in range(3)
        ] + [{"src": "gkg", "t": now_s - 3600, "domain": "other.example",
              "url": "https://other.example/x", "title": "Acme accelerator earnings call"}] + [
            {"src": "gkg", "t": now_s - 60 * i, "domain": f"local{i}.example",
             "url": f"https://local{i}.example/story-{i}", "title": f"Council agenda item {i} on roads"}
            for i in range(300)
        ]
        _write_snapshot(root / "snapshot", "2026-08-25", rows)
        with (
            patch.dict(os.environ, {"DAILY_NEWS_OFFLINE": ""}),
            patch.object(runtime, "ATTENTION_SNAPSHOT_DIR", root / "snapshot"),
            patch.object(runtime, "ATTENTION_ARCHIVE_DIR", root / "attention"),
            patch.object(runtime, "ATTENTION_HEALTH_LOG_PATH", root / "attention-health.log"),
            patch("jev.load_client", return_value=_PhaseJev()),
        ):
            scored_fresh, scored_ongoing = research.phase_2b_attention(
                catalog.TOPICS["ai-tech"], fresh, ongoing, run_dir
            )
        story = scored_fresh[0]
        check((run_dir / "02b-attention.json").exists(), "run attention artifact missing")
        durable = json.loads((root / "attention" / "2026-08-25" / "ai-tech.json").read_text())
        observation = durable["observations"][0]
        check(observation["attention"]["status"] == "ok", observation)
        check(story["attention"] == observation["attention"], (story, observation))
        check(
            story["priority_score"]
            == attention.blended_priority("medium", story["jev_importance"], observation["attention"]),
            (story, observation),
        )
        check(scored_ongoing[0]["attention"]["status"] == "out_of_scope", scored_ongoing)
        check(
            scored_ongoing[0]["priority_score"]
            == attention.importance_score("high", scored_ongoing[0]["jev_importance"]),
            scored_ongoing,
        )
        check(observation["attention"]["evidence"]["measures"]["gkg_domains"] == 3, observation)
        check(durable["snapshot"]["id"] == "fixture-snapshot" and "rows" not in durable["snapshot"], durable)
        check(durable["jev"]["status"] == "ok" and durable["excluded_sources"] == {}, durable)
        health = json.loads((root / "attention-health.log").read_text().splitlines()[-1])
        check(health["matched"] == 1 and health["source_availability"] == 1.0, health)


def test_attention_phase_leaves_out_failed_sources_and_unadjudicated_stories() -> None:
    class RelationsDownFor(_PhaseJev):
        def ask(self, purpose: str, state: dict, questions: dict) -> dict:
            if "candidate" in state and "Quasar" in state["candidate"]["headline"]:
                raise jev.JevUnavailable("server", "HTTP 503")
            return super().ask(purpose, state, questions)

    fresh = [
        {"title": "Acme ships Quasar 9 accelerator", "url": "https://acme.example/quasar-9",
         "event_terms": ["Quasar 9 accelerator"], "editorial_significance": "medium"},
        {"title": "Beta opens Nova 2 foundry", "url": "https://beta.example/nova-2",
         "event_terms": ["Nova 2 foundry"], "editorial_significance": "medium"},
    ]
    now_s = int(datetime.now(timezone.utc).timestamp())
    rows = [{"src": "gkg", "t": now_s - 3600, "domain": f"outlet{i}.example",
             "url": f"https://outlet{i}.example/q9", "title": f"Quasar 9 accelerator review number {i}"}
            for i in range(3)] + [
        {"src": "gkg", "t": now_s - 60 * i, "domain": f"local{i}.example",
         "url": f"https://local{i}.example/story-{i}", "title": f"Council agenda item {i} on roads"}
        for i in range(300)
    ]

    def run_phase(statuses: dict[str, str], client: _PhaseJev) -> tuple[list[dict], dict]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "run" / "2026-08-25"
            run_dir.mkdir(parents=True)
            _write_snapshot(root / "snapshot", "2026-08-25", rows, statuses)
            with (
                patch.dict(os.environ, {"DAILY_NEWS_OFFLINE": ""}),
                patch.object(runtime, "ATTENTION_SNAPSHOT_DIR", root / "snapshot"),
                patch.object(runtime, "ATTENTION_ARCHIVE_DIR", root / "attention"),
                patch.object(runtime, "ATTENTION_HEALTH_LOG_PATH", root / "attention-health.log"),
                patch("jev.load_client", return_value=client),
            ):
                scored, _ = research.phase_2b_attention(catalog.TOPICS["ai-tech"], fresh, [], run_dir)
            return scored, json.loads((root / "attention" / "2026-08-25" / "ai-tech.json").read_text())

    complete, _ = run_phase({}, _PhaseJev())
    panel_partial, durable = run_phase({"panel": "partial"}, _PhaseJev())
    check(durable["excluded_sources"] == {"panel": "partial"}, durable["excluded_sources"])
    quasar = panel_partial[0]["attention"]
    check(quasar["status"] == "ok" and "panel" not in quasar["normalized_signals"], quasar)
    check(quasar["evidence"]["sources_excluded"] == ["panel"], quasar)
    # The covered story keeps its measured press; the failed panel counts as nothing, not zero.
    check(quasar["digest_prominence"] > complete[0]["attention"]["digest_prominence"], (quasar, complete[0]))

    scored, durable = run_phase({}, RelationsDownFor())
    quasar, nova = scored
    check(quasar["attention"]["status"] == "unavailable", quasar)
    check(quasar["attention"]["evidence"]["unavailable_reason"] == "adjudication_failed", quasar)
    check(quasar["priority_score"] == attention.importance_score("medium", quasar["jev_importance"]), quasar)
    check(nova["attention"]["status"] == "no_matches", nova)
    check(durable["jev"]["status"] == "degraded" and durable["jev"]["unadjudicated_stories"] == 1, durable["jev"])


def test_offline_attention_phase_never_reaches_the_network() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        run_dir = root / "run" / "2026-08-25"
        run_dir.mkdir(parents=True)
        fresh = [{"title": "Offline event", "url": "https://example.com/offline",
                  "editorial_significance": "low"}]
        with (
            patch.dict(os.environ, {"DAILY_NEWS_OFFLINE": "1"}),
            patch.object(runtime, "ATTENTION_SNAPSHOT_DIR", root / "snapshot"),
            patch.object(runtime, "ATTENTION_ARCHIVE_DIR", root / "attention"),
            patch.object(runtime, "ATTENTION_HEALTH_LOG_PATH", root / "attention-health.log"),
            patch("daily_news.attention_sources.collect_snapshot",
                  side_effect=AssertionError("offline runs must not collect")),
            patch("jev.load_client", side_effect=AssertionError("offline runs must not call Jev")),
        ):
            scored_fresh, _ = research.phase_2b_attention(
                catalog.TOPICS["world"], fresh, [], run_dir
            )
        check(scored_fresh[0]["priority_score"] == attention.EDITORIAL_POINTS["low"], scored_fresh)
        durable = json.loads((root / "attention" / "2026-08-25" / "world.json").read_text())
        check(durable["observations"][0]["attention"]["status"] == "unavailable", durable)
        check(durable["jev"]["status"] == "offline", durable["jev"])
        check(not (root / "snapshot").exists(), "offline runs must not create a snapshot store")


def test_phase_three_uses_product_priority() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        run_dir = root / "ai-tech" / "2026-08-25"
        run_dir.mkdir(parents=True)
        fresh = [
            {
                "title": "High consequence, quieter coverage",
                "url": "https://example.com/consequence",
                "editorial_significance": "high",
                "priority_score": 76.0,
                "date_published": "2026-08-25",
            },
            {
                "title": "Medium consequence, attention breakout",
                "url": "https://example.com/breakout",
                "editorial_significance": "medium",
                "priority_score": 89.0,
                "date_published": "2026-08-25",
            },
        ]
        with patch.object(runtime, "DIGESTS_DIR", root):
            queue, _ = research.phase_3_rank(
                catalog.TOPICS["ai-tech"], fresh, [], {"stories": []}, run_dir
            )
        check(
            [item["title"] for item in queue]
            == [
                "Medium consequence, attention breakout",
                "High consequence, quieter coverage",
            ],
            queue,
        )
        artifact = json.loads((run_dir / "03-urls-ranked.json").read_text())
        check(
            artifact["ranking_schema_version"] == catalog.RANKING_SCHEMA_VERSION,
            artifact,
        )


def test_phase_four_concurrency_and_shared_cache() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        cache_dir = root / "cache"
        (root / "run-one").mkdir()
        (root / "run-two").mkdir()
        findings = [
            {
                "title": f"Story {index}",
                "url": f"https://example.com/{index}",
                "source_verdict": "fresh",
            }
            for index in range(3)
        ]
        active = 0
        maximum = 0
        lock = threading.Lock()

        fetch_system_prompts: list[str] = []

        def fake_omp(prompt: str, **kwargs: object) -> str:
            nonlocal active, maximum
            url = prompt.split("Fetch this article: ", 1)[1].splitlines()[0]
            fetch_system_prompts.append(str(kwargs.get("append_system", "")))
            with lock:
                active += 1
                maximum = max(maximum, active)
            time.sleep(0.05)
            with lock:
                active -= 1
            return json.dumps({
                "title": f"Fetched {url.rsplit('/', 1)[-1]}",
                "url": url,
                "date_confirmed": "2026-08-10",
                "author": "",
                "summary": "A detailed factual summary.",
                "key_details": ["detail"],
                "fetch_success": True,
            })

        with patch.object(runtime, "ARTICLE_CACHE_DIR", cache_dir), patch.object(
            runtime, "_call_omp_p", side_effect=fake_omp
        ) as mocked:
            first = research.phase_4_fetch(
                catalog.TOPICS["ai-tech"], findings, root / "run-one"
            )
            second = research.phase_4_fetch(
                catalog.TOPICS["gaming"], findings, root / "run-two"
            )
        check(maximum == 2, f"expected concurrency 2, saw {maximum}")
        check(mocked.call_count == 3, f"cache did not suppress calls: {mocked.call_count}")
        check(
            all("Return `title` in English" in prompt for prompt in fetch_system_prompts),
            fetch_system_prompts,
        )
        check([item["url"] for item in first] == [item["url"] for item in findings],
              "concurrency changed output order")
        check(all(item["cache_hit"] for item in second), "second topic missed shared cache")



def test_phase_five_backfills_date_confirmed_from_date_published() -> None:
    """A candidate whose Phase 4 fetch and Phase 5 re-fetch could not confirm a
    publication date must still carry date_confirmed, backfilled explicitly from
    date_published — never null (digest-quality audit 2026-08-29: ai-tech
    shipped Hunyuan Hy4 and GLM-5.3 with date_confirmed=null)."""
    with tempfile.TemporaryDirectory() as temporary:
        run_dir = Path(temporary) / "ai-tech" / "2026-08-29"
        run_dir.mkdir(parents=True)
        summaries = [
            {
                "title": "Unconfirmed date story",
                "url": "https://a.example/story",
                "source_domain": "a.example",
                "summary": "Verified factual summary.",
                "date_published": "2026-08-28",
                "date_confirmed": "",
                "source_verdict": "fresh",
                "fetch_success": True,
            },
            {
                "title": "Confirmed date story",
                "url": "https://b.example/story",
                "source_domain": "b.example",
                "summary": "Verified factual summary.",
                "date_published": "2026-08-29",
                "date_confirmed": "2026-08-29",
                "source_verdict": "fresh",
                "fetch_success": True,
            },
        ]
        judgments = json.dumps([
            {"url": "https://a.example/story", "verdict": "keep", "issues": [], "fixed_summary": ""},
            {"url": "https://b.example/story", "verdict": "keep", "issues": [], "fixed_summary": ""},
        ])
        with patch("daily_news.research.refetch_article_date", return_value=None), \
             patch("daily_news.runtime._call_llm_proxy", return_value=judgments):
            results = research.phase_5_judge_summaries(
                catalog.TOPICS["ai-tech"], summaries, run_dir
            )
        by_url = {r["url"]: r for r in results}
        unconfirmed = by_url["https://a.example/story"]
        check(unconfirmed["date_confirmed"] == "2026-08-28",
              f"unconfirmed date was not backfilled: {unconfirmed['date_confirmed']!r}")
        check(unconfirmed["judge_verdict"] == "keep", unconfirmed)
        confirmed = by_url["https://b.example/story"]
        check(confirmed["date_confirmed"] == "2026-08-29",
              f"confirmed date was overwritten: {confirmed['date_confirmed']!r}")


def test_cached_curation_regenerates_referenced_url_sidecar() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        run_dir = Path(temporary) / "ai-tech" / "2026-08-26"
        run_dir.mkdir(parents=True)
        topic = catalog.TOPICS["ai-tech"]
        summaries: list[dict] = []
        sif_candidates: list[dict] = []
        tracker = {"stories": []}
        blocked_urls = contracts.load_cross_topic_urls(topic, run_dir)
        inputs = runtime.phase_inputs(
            "curate",
            topic=topic,
            upstream={
                "summaries": runtime.canonical_fingerprint(summaries),
                "sif_candidates": runtime.canonical_fingerprint(sif_candidates),
                "stories_in_flight": runtime.canonical_fingerprint(tracker),
                "cross_topic_urls": sorted(blocked_urls),
            },
            policy={
                "issue_date": run_dir.name,
                "ranking_schema": catalog.RANKING_SCHEMA_VERSION,
                "model": runtime._effective_model(runtime.MODEL),
            },
        )
        state = runtime.WorkflowState(
            run_dir, runtime.WORKFLOW_NAME, run_id=run_dir.name
        )
        state.begin_phase(
            "curate",
            inputs=inputs,
            artifact_path=run_dir / "06-curated.json",
            schema_version=catalog.RANKING_SCHEMA_VERSION,
        )
        cached_story = {
            "title": "Cached selection",
            "url": "https://example.com/cached-selection",
            "summary": "Verified cached summary.",
        }
        state.complete_json(
            "curate",
            {
                "fresh": [cached_story],
                "stories_in_flight": tracker,
                "ongoing": [],
            },
        )
        sidecar = run_dir / "referenced-urls.json"
        check(not sidecar.exists(), "sidecar unexpectedly preexisted")
        with patch(
            "daily_news.contracts.collect_referenced_urls",
            return_value=["example.com/source"],
        ):
            fresh, _, _ = editorial.phase_6_curate(
                topic, summaries, sif_candidates, tracker, run_dir
            )
        check(fresh == [cached_story], fresh)
        sidecar_data = json.loads(sidecar.read_text())
        check(sidecar_data["stories"][0]["url"] == cached_story["url"], sidecar_data)


def test_phase_six_backfills_missing_date_confirmed_on_curated_fresh() -> None:
    """A curated fresh story that somehow still lacks date_confirmed must be
    backfilled from date_published and flagged in 06c's validation warnings
    (digest-quality audit 2026-08-29)."""
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        run_dir = root / "ai-tech" / "2026-08-29"
        run_dir.mkdir(parents=True)
        fresh_day = "2026-08-28"
        summary = {
            "title": "Fresh story without confirmed date",
            "url": "https://example.com/fresh-unconfirmed",
            "source_domain": "example.com",
            "summary": "Verified fresh summary.",
            "category": "Research",
            **validated_high_fields(),
            "date_published": fresh_day,
            "source_verdict": "fresh",
            "judge_verdict": "keep",
        }
        candidate_id = editorial.editorial_candidate_id(summary)
        proposal = {
            "selected_fresh": [{
                "candidate_id": candidate_id,
                "editorial_summary": "Verified fresh summary.",
                "selection_reason": "Fresh impact.",
                "related_story_url": None,
            }],
            "selected_ongoing": [],
            "story_state_proposals": [{
                "operation": "add",
                "candidate_id": candidate_id,
                "evidence_candidate_ids": [candidate_id],
                "latest_dev": "Verified fresh summary.",
                "editorial_significance": "high",
                "status": "active",
            }],
            "rejected": [],
            "gaps": "",
            "balance_summary": "One lead story.",
        }
        responses = [
            json.dumps(proposal),
            json.dumps({"verdict": "approve", "changes": [], "notes": "OK"}),
        ]
        with patch.object(runtime, "DIGESTS_DIR", root), patch.object(
            runtime, "_call_llm_proxy", side_effect=responses
        ):
            fresh, _, _ = editorial.phase_6_curate(
                catalog.TOPICS["ai-tech"], [summary], [], {}, run_dir
            )
        check(len(fresh) == 1, f"fresh story was not curated: {fresh}")
        check(fresh[0]["date_confirmed"] == fresh_day,
              f"date_confirmed not backfilled: {fresh[0].get('date_confirmed')!r}")
        final = json.loads((run_dir / "06c-editorial-final.json").read_text())
        check(
            any("date_confirmed" in warning for warning in final["validation_warnings"]),
            final["validation_warnings"],
        )


def editorial_fixture(issue_date: str | None = None) -> tuple[list[dict], list[dict], dict]:
    # Phase-oriented fixtures derive freshness from the immutable run date;
    # pure proposal tests default to the current date.
    base_date = (
        datetime.fromisoformat(issue_date).date()
        if issue_date is not None
        else datetime.now(timezone.utc).date()
    )
    fresh_day = (base_date - timedelta(days=1)).isoformat()
    candidates, _ = editorial.prepare_editorial_candidates([
        {
            "title": "Primary story",
            "url": "https://example.com/primary",
            "source_domain": "example.com",
            "summary": "Primary verified summary.",
            "category": "Research",
            **validated_high_fields(),
            "date_published": fresh_day,
            "source_verdict": "fresh",
            "judge_verdict": "keep",
        },
        {
            "title": "Secondary story",
            "url": "https://second.example/story",
            "source_domain": "second.example",
            "summary": "Secondary verified summary.",
            "category": "Policy",
            "editorial_significance": "medium",
            "date_published": fresh_day,
            "source_verdict": "fresh",
            "judge_verdict": "keep",
        },
    ], set())
    tracker = {"stories": [{
        "title": "Existing narrative",
        "url": "https://example.com/existing",
        "category": "Research",
        "latest_dev": "Previous development.",
        "status": "active",
        **validated_high_fields(),
        "first_seen": "2026-08-08",
        "last_updated": "2026-08-09",
        "developments": [
            {"date": "2026-08-08", "url": "https://example.com/existing"},
            {"date": "2026-08-09", "url": "https://example.com/existing-update"},
        ],
    }]}
    return candidates, tracker["stories"], tracker


def test_editorial_validation_and_state_application() -> None:
    candidates, sif_candidates, tracker = editorial_fixture()
    first_id = candidates[0]["candidate_id"]
    # A candidate carrying the tracked story's own URL is legitimate update
    # evidence; a different-story candidate is not (digest-quality audit
    # 2026-08-22: ai-hardware's memory-prices story was overwritten with the
    # related KOSPI story's development).
    same_story = {
        **candidates[0],
        "title": "Existing narrative update",
        "url": "https://example.com/existing",
        "candidate_id": "candidate-same-story",
    }
    candidates.append(same_story)
    same_story_id = same_story["candidate_id"]
    proposal = {
        "selected_fresh": [
            {"candidate_id": same_story_id, "editorial_summary": "Approved summary."},
            {"candidate_id": "candidate-unknown", "editorial_summary": "Bad."},
            {"candidate_id": same_story_id, "editorial_summary": "Duplicate."},
            {"candidate_id": first_id, "editorial_summary": "Cross-story source."},
        ],
        "selected_ongoing": [],
        "story_state_proposals": [
            {
                "operation": "update",
                "story_url": "https://example.com/existing",
                "evidence_candidate_ids": [same_story_id],
                "latest_dev": "New verified development.",
                "editorial_significance": "high",
                "status": "active",
            },
            {
                "operation": "update",
                "story_url": "https://example.com/existing",
                "evidence_candidate_ids": ["candidate-unknown"],
                "latest_dev": "Unsupported.",
            },
            {
                "operation": "update",
                "story_url": "https://example.com/existing",
                "evidence_candidate_ids": [first_id],
                "latest_dev": "Related story development.",
            },
        ],
    }
    validated, warnings = editorial.validate_editorial_proposal(
        proposal, candidates, sif_candidates, tracker
    )
    check(len(validated["selected_fresh"]) == 2, validated)
    check(len(validated["story_state_proposals"]) == 2, validated)
    update_ops = [
        op for op in validated["story_state_proposals"]
        if op["operation"] == "update"
    ]
    check(len(update_ops) == 1, validated["story_state_proposals"])
    check(
        validated["balance_summary"]
        == "Validated selection: 2 fresh, 0 developing/ongoing; "
           "1 source domain(s); categories: Research.",
        validated["balance_summary"],
    )
    check(any("unknown candidate_id" in warning for warning in warnings), warnings)
    check(
        any("unlinked tracker update" in warning for warning in warnings),
        warnings,
    )
    original = json.loads(json.dumps(tracker))
    updated = editorial.apply_story_state_proposals(
        tracker, validated, candidates, "2026-08-10"
    )
    check(tracker == original, "state application mutated its input")
    check(updated["stories"][0]["latest_dev"] == "New verified development.", updated)
    check(updated["stories"][0]["last_updated"] == "2026-08-10", updated)
    check(
        contracts.story_development_dates(updated["stories"][0])
        == {"2026-08-08", "2026-08-09", "2026-08-10"},
        updated["stories"][0],
    )


def test_editorial_critic_patch_contract() -> None:
    candidates, _, tracker = editorial_fixture()
    proposal = {
        "selected_fresh": [
            {"candidate_id": candidates[0]["candidate_id"]},
            {"candidate_id": candidates[1]["candidate_id"]},
        ],
        "selected_ongoing": [],
        "story_state_proposals": [],
    }
    patched, applied, warnings = editorial.apply_editorial_patches(proposal, {
        "changes": [{
            "operation": "move_fresh",
            "candidate_id": candidates[1]["candidate_id"],
            "position": 1,
        }],
    })
    check(patched["selected_fresh"][0]["candidate_id"] == candidates[1]["candidate_id"],
          patched)
    check(len(applied) == 1 and not warnings, (applied, warnings))
    check(tracker["stories"], "fixture tracker unexpectedly empty")


def test_editorial_drops_stale_fresh_selection() -> None:
    """A stale Fresh pick cannot enter either output or tracker evidence."""
    candidates, sif_candidates, tracker = editorial_fixture()
    stale_day = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%d")
    stale = copy.deepcopy(candidates[0])
    stale["date_published"] = stale_day
    stale["date_confirmed"] = stale_day
    stale["date_tag"] = "ongoing"
    stale["source_verdict"] = "ongoing"
    candidates = [stale, copy.deepcopy(candidates[1])]
    proposal = {
        "selected_fresh": [
            {"candidate_id": candidate["candidate_id"]} for candidate in candidates
        ],
        "selected_ongoing": [],
        "story_state_proposals": [{
            "operation": "add",
            "candidate_id": stale["candidate_id"],
            "evidence_candidate_ids": [stale["candidate_id"]],
            "latest_dev": "Prices still climbing.",
            "editorial_significance": "high",
            "status": "active",
        }],
    }
    validated, warnings = editorial.validate_editorial_proposal(
        proposal, candidates, sif_candidates, tracker
    )
    check(len(validated["selected_fresh"]) == 1, validated["selected_fresh"])
    check(
        validated["selected_fresh"][0]["candidate_id"] == candidates[1]["candidate_id"],
        validated["selected_fresh"],
    )
    check(any("stale fresh selection" in warning for warning in warnings), warnings)
    # The qualified developing story may fill the thin digest, but display is
    # not evidence and therefore creates no tracker update.
    check(validated["story_state_proposals"] == [],
          validated["story_state_proposals"])
    updated = editorial.apply_story_state_proposals(
        tracker, validated, candidates, "2026-08-10"
    )
    check(
        not any(story.get("url") == stale["url"] for story in updated["stories"]),
        "stale-dropped candidate entered the tracker",
    )
    check(
        updated["stories"][0]["last_updated"] == "2026-08-09",
        "displaying a story fabricated an evidence date",
    )


def test_freshness_gate_rejects_future_dates() -> None:
    """The last-24h freshness window has an upper bound: a future-dated
    candidate must never pass _is_fresh_eligible (digest-quality audit
    2026-08-14: a 2026-10-15-dated story rendered under "Fresh — Last 24 Hours"
    in the 2026-08-12 ai-tech digest)."""
    yesterday = datetime(2026, 8, 13, tzinfo=timezone.utc).date()
    today = datetime(2026, 8, 14, tzinfo=timezone.utc).date()
    future = {"date_confirmed": "2026-10-15", "date_published": "2026-08-12"}
    check(not contracts.is_fresh_eligible(future, yesterday, today),
          "future-dated candidate passed the freshness gate")
    fresh = {"date_confirmed": "2026-08-13"}
    check(contracts.is_fresh_eligible(fresh, yesterday, today),
          "yesterday-dated candidate must stay fresh-eligible")
    same_day = {"date_confirmed": "2026-08-14"}
    check(contracts.is_fresh_eligible(same_day, yesterday, today),
          "today-dated candidate must stay fresh-eligible")
    stale = {"date_confirmed": "2026-08-10"}
    check(not contracts.is_fresh_eligible(stale, yesterday, today),
          "stale candidate passed the freshness gate")
    undated = {"date_confirmed": "", "date_published": ""}
    check(contracts.is_fresh_eligible(undated, yesterday, today),
          "undated candidate must pass through")


def test_freshness_gate_ignores_future_event_date_confirmed() -> None:
    """A date_confirmed in the future (an event/conference date pulled from the
    article) must not override a fresh date_published. The Hot Chips 08-17
    preview shipped its conference start date (08-24) as date_confirmed, which
    the previous preference logic treated as the best date and dropped as
    future-dated even though it was published within the 24h window
    (digest-quality audit 2026-08-17: ai-hardware shipped zero fresh stories)."""
    yesterday = datetime(2026, 8, 16, tzinfo=timezone.utc).date()
    today = datetime(2026, 8, 17, tzinfo=timezone.utc).date()
    fresh_event = {"date_published": "2026-08-17", "date_confirmed": "2026-08-24"}
    check(contracts.is_fresh_eligible(fresh_event, yesterday, today),
          "future event date_confirmed dropped a fresh-eligible candidate")
    # Regression guard: keep the genuine future-dated (publication) rejection.
    genuine_future = {"date_published": "2026-10-15", "date_confirmed": ""}
    check(not contracts.is_fresh_eligible(genuine_future, yesterday, today),
          "genuine future-dated publication must still be rejected")


def test_editorial_caps_source_concentration() -> None:
    """Fresh selection is capped at 2 stories per source domain: lower-ranked
    same-source candidates are dropped with a warning instead of shipping a
    single-source Fresh section (digest-quality audit 2026-08-14: ai-tech
    shipped 5 TechCrunch stories, ai-hardware 4 Data Center Dynamics stories)."""
    fresh_day = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    candidates, _ = editorial.prepare_editorial_candidates([
        {
            "title": f"TechCrunch story {index}",
            "url": f"https://techcrunch.com/{index}",
            "source_domain": "techcrunch.com",
            "summary": f"Verified summary {index}.",
            "category": "Research",
            "editorial_significance": "high" if index == 0 else "medium",
            "date_published": fresh_day,
            "source_verdict": "fresh",
            "judge_verdict": "keep",
        }
        for index in range(3)
    ] + [
        {
            "title": "Other story",
            "url": "https://other.example/story",
            "source_domain": "other.example",
            "summary": "Verified other summary.",
            "category": "Policy",
            "editorial_significance": "medium",
            "date_published": fresh_day,
            "source_verdict": "fresh",
            "judge_verdict": "keep",
        },
    ], set())
    proposal = {
        "selected_fresh": [
            {"candidate_id": candidate["candidate_id"]}
            for candidate in candidates
        ],
        "selected_ongoing": [],
        "story_state_proposals": [],
        "gaps": "",
        "balance_summary": "",
    }
    validated, warnings = editorial.validate_editorial_proposal(
        proposal, candidates, [], {"stories": []}
    )
    selected = validated["selected_fresh"]
    domains = {
        candidate["candidate_id"]: candidate["source_domain"]
        for candidate in candidates
    }
    techcrunch_count = sum(
        1 for item in selected if domains[item["candidate_id"]] == "techcrunch.com"
    )
    check(len(selected) == 3, f"expected 3 fresh after cap, got {len(selected)}")
    check(techcrunch_count == 2, f"techcrunch count after cap: {techcrunch_count}")
    check(any("source concentration above 2" in warning for warning in warnings),
          warnings)
    check(any("source concentration cap" in warning for warning in warnings),
          warnings)


def test_editorial_proposal_retries_with_freshness_hint() -> None:
    """A model proposal whose fresh picks were all dropped by the freshness gate
    is retried once with the window reinforced instead of dropping straight to
    raw fallback (digest-quality audit 2026-08-14: agentic-platform shipped
    deterministic raw fallback with no critic review)."""
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        run_dir = root / "agentic-platform" / "2026-08-14"
        run_dir.mkdir(parents=True)
        fresh_day = "2026-08-13"
        stale_day = "2026-08-09"

        def build(title: str, url: str, day: str, significance: str) -> dict:
            return {
                "title": title,
                "url": url,
                "source_domain": "example.com",
                "summary": f"{title} verified summary.",
                "category": "Research",
                "editorial_significance": significance,
                "date_published": day,
                "date_confirmed": day,
                "date_tag": "fresh" if day == fresh_day else "ongoing",
                "source_verdict": "fresh" if day == fresh_day else "ongoing",
                "judge_verdict": "keep",
            }

        stale_a = build("Stale story A", "https://example.com/stale-a", stale_day, "high")
        stale_b = build("Stale story B", "https://example.com/stale-b", stale_day, "medium")
        fresh_c = build("Fresh story C", "https://example.com/fresh-c", fresh_day, "medium")
        summaries = [stale_a, stale_b, fresh_c]
        stale_a_id = editorial.editorial_candidate_id(stale_a)
        stale_b_id = editorial.editorial_candidate_id(stale_b)
        fresh_c_id = editorial.editorial_candidate_id(fresh_c)

        stale_only = {
            "selected_fresh": [
                {"candidate_id": stale_a_id},
                {"candidate_id": stale_b_id},
            ],
            "selected_ongoing": [],
            "story_state_proposals": [],
            "gaps": "",
            "balance_summary": "",
        }
        fresh_proposal = {
            "selected_fresh": [{
                "candidate_id": fresh_c_id,
                "rank": 1,
                "editorial_summary": "Reviewed factual summary.",
                "selection_reason": "Only fresh-eligible candidate.",
                "related_story_url": None,
            }],
            "selected_ongoing": [],
            "story_state_proposals": [{
                "operation": "add",
                "candidate_id": fresh_c_id,
                "evidence_candidate_ids": [fresh_c_id],
                "latest_dev": "Reviewed factual summary.",
                "editorial_significance": "high",
                "status": "active",
            }],
            "rejected": [],
            "gaps": "",
            "balance_summary": "One fresh story.",
        }
        responses: list[object] = [
            json.dumps(stale_only),
            json.dumps(fresh_proposal),
            json.dumps({"verdict": "approve", "changes": [], "notes": "Sound."}),
        ]

        def fake_call(*_: object, **__: object) -> str:
            value = responses.pop(0)
            if isinstance(value, Exception):
                raise value
            return str(value)

        with patch.object(runtime, "DIGESTS_DIR", root), patch.object(
            runtime, "_call_llm_proxy", side_effect=fake_call
        ):
            fresh, _, ongoing = editorial.phase_6_curate(
                catalog.TOPICS["agentic-platform"], summaries, [], {"stories": []}, run_dir
            )
        check(len(fresh) == 1, f"expected 1 fresh after hint retry, got {fresh}")
        check(fresh[0]["url"] == "https://example.com/fresh-c", fresh)
        check(not ongoing, ongoing)
        check(not responses, f"unused model responses: {responses!r}")
        proposal_artifact = json.loads(
            (run_dir / "06a-editorial-proposal.json").read_text()
        )
        check(proposal_artifact["status"] == "model", proposal_artifact["status"])
        check(len(proposal_artifact["errors"]) == 1, proposal_artifact["errors"])
        check(
            "reinforced freshness hint" in proposal_artifact["errors"][0],
            proposal_artifact["errors"],
        )
        artifact = json.loads((run_dir / "06c-editorial-final.json").read_text())
        check(
            artifact["output"]["editorial"]["review_status"] == "reviewed",
            artifact,
        )
        check(
            artifact["output"]["editorial"]["proposal_model"] == runtime.MODEL,
            artifact,
        )
        check(
            "validation_warnings" in artifact,
            "06c must persist validation warnings for auditability",
        )


def test_critic_fresh_removal_honored_when_all_candidates_stale() -> None:
    """A critic that removes the last stale fresh story must be honored, not
    converted to review=unavailable with the invalid placement retained
    (digest-quality audit 2026-08-12: ai-hardware shipped a 2d-old RTX story
    under Fresh because the 'removed every valid fresh story' guard fired)."""
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        run_dir = root / "ai-hardware" / "2026-08-12"
        run_dir.mkdir(parents=True)
        stale_day = "2026-08-10"
        summary = {
            "title": "RTX 50-series price spike",
            "url": "https://example.com/rtx-prices",
            "source_domain": "example.com",
            "summary": "Prices up as much as 39%.",
            "category": "GPUs",
            "editorial_significance": "high",
            "date_published": stale_day,
            "date_confirmed": stale_day,
            "date_tag": "ongoing",
            "source_verdict": "ongoing",
            "judge_verdict": "keep",
        }
        candidate_id = editorial.editorial_candidate_id(summary)
        proposal = {
            "selected_fresh": [{
                "candidate_id": candidate_id,
                "rank": 1,
                "editorial_summary": "Prices spiked 39%.",
                "selection_reason": "Consumer impact.",
                "related_story_url": None,
            }],
            "selected_ongoing": [],
            "story_state_proposals": [{
                "operation": "add",
                "candidate_id": candidate_id,
                "evidence_candidate_ids": [candidate_id],
                "latest_dev": "Prices spiked 39%.",
                "editorial_significance": "high",
                "status": "active",
            }],
            "rejected": [],
            "gaps": "",
            "balance_summary": "One lead story.",
        }
        responses: list[object] = [
            RuntimeError("primary unavailable"),
            RuntimeError("primary unavailable (retry)"),
            json.dumps(proposal),
            json.dumps({"verdict": "approve_with_changes", "changes": [{
                "operation": "remove_fresh",
                "candidate_id": candidate_id,
            }], "notes": "Sole candidate is outside the 24h freshness window."}),
        ]

        def fake_call(*_: object, **__: object) -> str:
            value = responses.pop(0)
            if isinstance(value, Exception):
                raise value
            return str(value)

        with patch.object(runtime, "DIGESTS_DIR", root), patch.object(
            runtime, "_call_llm_proxy", side_effect=fake_call
        ):
            fresh, updated, _ = editorial.phase_6_curate(
                catalog.TOPICS["ai-hardware"], [summary], [], {}, run_dir
            )
        check(fresh == [], f"stale story shipped under Fresh: {fresh}")
        artifact = json.loads((run_dir / "06-curated.json").read_text())
        check(
            artifact["editorial"]["review_status"] == "reviewed",
            artifact["editorial"],
        )
        review_artifact = json.loads(
            (run_dir / "06b-editorial-review.json").read_text()
        )
        check(not review_artifact["errors"], review_artifact["errors"])
        # The stale story was not selected for anything, so it is not tracked.
        check(
            not any(
                story.get("url") == summary["url"]
                for story in updated.get("stories", [])
            ),
            updated,
        )
        check(not responses, f"unused model responses: {responses!r}")


def test_critic_emptying_valid_fresh_still_fails_closed() -> None:
    """The 'removed every valid fresh story' guard must still fire when
    genuinely fresh candidates exist, so a broken critic cannot empty the
    digest; the validated proposal is retained."""
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        run_dir = root / "ai-tech" / "2026-08-12"
        run_dir.mkdir(parents=True)
        candidates, _, tracker = editorial_fixture(run_dir.name)
        summaries = [
            {key: value for key, value in candidate.items() if key != "candidate_id"}
            for candidate in candidates
        ]
        proposal = {
            "selected_fresh": [
                {"candidate_id": candidates[0]["candidate_id"], "rank": 1,
                 "editorial_summary": "Fresh story one.", "selection_reason": "Top.",
                 "related_story_url": None},
                {"candidate_id": candidates[1]["candidate_id"], "rank": 2,
                 "editorial_summary": "Fresh story two.", "selection_reason": "Second.",
                 "related_story_url": None},
            ],
            "selected_ongoing": [],
            "story_state_proposals": [],
            "rejected": [],
            "gaps": "",
            "balance_summary": "Two fresh stories.",
        }
        responses: list[object] = [
            json.dumps(proposal),
            json.dumps({"verdict": "approve_with_changes", "changes": [
                {"operation": "remove_fresh",
                 "candidate_id": candidates[0]["candidate_id"]},
                {"operation": "remove_fresh",
                 "candidate_id": candidates[1]["candidate_id"]},
            ], "notes": "Removing all fresh."}),
        ]

        def fake_call(*_: object, **__: object) -> str:
            value = responses.pop(0)
            if isinstance(value, Exception):
                raise value
            return str(value)

        with patch.object(runtime, "DIGESTS_DIR", root), patch.object(
            runtime, "_call_llm_proxy", side_effect=fake_call
        ):
            fresh, _, _ = editorial.phase_6_curate(
                catalog.TOPICS["ai-tech"], summaries, [], tracker, run_dir
            )
        artifact = json.loads((run_dir / "06-curated.json").read_text())
        check(artifact["editorial"]["review_status"] == "unavailable", artifact)
        check(len(fresh) == 2, f"valid fresh stories were lost: {fresh}")


def test_phase_six_fallback_and_review_chain() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        run_dir = root / "ai-tech" / "2026-08-10"
        run_dir.mkdir(parents=True)
        candidates, _, tracker = editorial_fixture(run_dir.name)
        summaries = [
            {key: value for key, value in candidate.items() if key != "candidate_id"}
            for candidate in candidates
        ]
        selected_id = candidates[0]["candidate_id"]
        proposal = {
            "selected_fresh": [{
                "candidate_id": selected_id,
                "rank": 1,
                "editorial_summary": "Reviewed factual summary.",
                "selection_reason": "Highest product priority.",
                "related_story_url": None,
            }],
            "selected_ongoing": [],
            "story_state_proposals": [{
                "operation": "add",
                "candidate_id": selected_id,
                "evidence_candidate_ids": [selected_id],
                "latest_dev": "Reviewed factual summary.",
                "editorial_significance": "high",
                "status": "active",
            }],
            "rejected": [],
            "gaps": "",
            "balance_summary": "One lead story.",
        }
        responses: list[object] = [
            RuntimeError("primary unavailable"),
            RuntimeError("primary unavailable (retry)"),
            json.dumps(proposal),
            json.dumps({"verdict": "approve", "changes": [], "notes": "Sound."}),
        ]

        def fake_call(*_: object, **__: object) -> str:
            value = responses.pop(0)
            if isinstance(value, Exception):
                raise value
            return str(value)

        with patch.object(runtime, "DIGESTS_DIR", root), patch.object(
            runtime, "_call_llm_proxy", side_effect=fake_call
        ):
            fresh, updated, ongoing = editorial.phase_6_curate(
                catalog.TOPICS["ai-tech"], summaries, [], tracker, run_dir
            )
        check(len(fresh) == 1 and not ongoing, (fresh, ongoing))
        check(len(updated["stories"]) == 2, updated)
        artifact = json.loads((run_dir / "06-curated.json").read_text())
        check(artifact["editorial"]["proposal_model"] == runtime.MODEL_FALLBACK, artifact)
        check(artifact["editorial"]["review_status"] == "reviewed", artifact)
        check(
            artifact["editorial"]["degraded"] is True,
            "fallback-model proposal must be flagged degraded (digest-quality audit)",
        )
        check(not responses, f"unused model responses: {responses!r}")


def test_editorial_proposal_retries_primary_before_fallback() -> None:
    """A single primary proposal failure must be retried, not degrade to fallback."""
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        run_dir = root / "ai-tech" / "2026-08-10"
        run_dir.mkdir(parents=True)
        candidates, _, tracker = editorial_fixture(run_dir.name)
        summaries = [
            {key: value for key, value in candidate.items() if key != "candidate_id"}
            for candidate in candidates
        ]
        selected_id = candidates[0]["candidate_id"]
        proposal = {
            "selected_fresh": [{
                "candidate_id": selected_id,
                "rank": 1,
                "editorial_summary": "Retried primary summary.",
                "selection_reason": "Highest product priority.",
                "related_story_url": None,
            }],
            "selected_ongoing": [],
            "story_state_proposals": [{
                "operation": "add",
                "candidate_id": selected_id,
                "evidence_candidate_ids": [selected_id],
                "latest_dev": "Retried primary summary.",
                "editorial_significance": "high",
                "status": "active",
            }],
            "rejected": [],
            "gaps": "",
            "balance_summary": "One lead story.",
        }
        responses: list[object] = [
            RuntimeError("Could not extract JSON from editorial proposal (primary). Raw text: ```json {"),
            json.dumps(proposal),
            json.dumps({"verdict": "approve", "changes": [], "notes": "Sound."}),
        ]

        def fake_call(*_: object, **__: object) -> str:
            value = responses.pop(0)
            if isinstance(value, Exception):
                raise value
            return str(value)

        with patch.object(runtime, "DIGESTS_DIR", root), patch.object(
            runtime, "_call_llm_proxy", side_effect=fake_call
        ):
            fresh, _, ongoing = editorial.phase_6_curate(
                catalog.TOPICS["ai-tech"], summaries, [], tracker, run_dir
            )
        check(len(fresh) == 1 and not ongoing, (fresh, ongoing))
        artifact = json.loads((run_dir / "06-curated.json").read_text())
        check(
            artifact["editorial"]["proposal_model"] == runtime.MODEL,
            artifact,
        )
        check(
            artifact["editorial"]["degraded"] is False,
            artifact["editorial"],
        )
        check(
            len(artifact["editorial"]["proposal_model"]) > 0,
            "proposal model missing",
        )
        check(not responses, f"unused model responses: {responses!r}")
        proposal_artifact = json.loads(
            (run_dir / "06a-editorial-proposal.json").read_text()
        )
        check(len(proposal_artifact["errors"]) == 1, proposal_artifact["errors"])


def test_editorial_critic_retries_primary_after_transient_error() -> None:
    """A transient primary critic error (proxy 500) must be retried once."""
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        run_dir = root / "ai-tech" / "2026-08-10"
        run_dir.mkdir(parents=True)
        candidates, _, tracker = editorial_fixture(run_dir.name)
        summaries = [
            {key: value for key, value in candidate.items() if key != "candidate_id"}
            for candidate in candidates
        ]
        selected_id = candidates[0]["candidate_id"]
        proposal = {
            "selected_fresh": [{
                "candidate_id": selected_id,
                "rank": 1,
                "editorial_summary": "Reviewed factual summary.",
                "selection_reason": "Highest product priority.",
                "related_story_url": None,
            }],
            "selected_ongoing": [],
            "story_state_proposals": [{
                "operation": "add",
                "candidate_id": selected_id,
                "evidence_candidate_ids": [selected_id],
                "latest_dev": "Reviewed factual summary.",
                "editorial_significance": "high",
                "status": "active",
            }],
            "rejected": [],
            "gaps": "",
            "balance_summary": "One lead story.",
        }
        responses: list[object] = [
            json.dumps(proposal),
            RuntimeError("deepseek-v4.1-flash: 500 Server Error: Internal Server Error for url: http://localhost:8082/v1/chat/completions"),
            json.dumps({"verdict": "approve", "changes": [], "notes": "Sound on retry."}),
        ]

        def fake_call(*_: object, **__: object) -> str:
            value = responses.pop(0)
            if isinstance(value, Exception):
                raise value
            return str(value)

        with patch.object(runtime, "DIGESTS_DIR", root), patch.object(
            runtime, "_call_llm_proxy", side_effect=fake_call
        ):
            fresh, _, _ = editorial.phase_6_curate(
                catalog.TOPICS["ai-tech"], summaries, [], tracker, run_dir
            )
        check(len(fresh) == 1, (fresh,))
        artifact = json.loads((run_dir / "06-curated.json").read_text())
        check(
            artifact["editorial"]["review_model"] == runtime.MODEL_REVIEWER,
            artifact,
        )
        check(artifact["editorial"]["review_status"] == "reviewed", artifact)
        check(not responses, f"unused model responses: {responses!r}")
        review_artifact = json.loads(
            (run_dir / "06b-editorial-review.json").read_text()
        )
        check(len(review_artifact["errors"]) == 1, review_artifact["errors"])


def test_critic_fallback_verdict_spelling_normalized() -> None:
    """A semantically valid but non-canonical fallback critic verdict
    ('approve_with_these_changes') must not degrade review to unavailable
    (digest-quality audit 2026-08-31: world shipped review_status=unavailable
    because mimo-v2.5's verdict failed the strict parse)."""
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        run_dir = root / "world" / "2026-08-31"
        run_dir.mkdir(parents=True)
        candidates, _, tracker = editorial_fixture(run_dir.name)
        summaries = [
            {key: value for key, value in candidate.items() if key != "candidate_id"}
            for candidate in candidates
        ]
        selected_id = candidates[0]["candidate_id"]
        proposal = {
            "selected_fresh": [{
                "candidate_id": selected_id,
                "rank": 1,
                "editorial_summary": "Reviewed factual summary.",
                "selection_reason": "Highest product priority.",
                "related_story_url": None,
            }],
            "selected_ongoing": [],
            "story_state_proposals": [],
            "rejected": [],
            "gaps": "",
            "balance_summary": "One lead story.",
        }
        responses: list[object] = [
            json.dumps(proposal),
            RuntimeError("deepseek-v4.1-flash: 500 Server Error: Internal Server Error for url: http://localhost:8082/v1/chat/completions"),
            RuntimeError("deepseek-v4.1-flash: HTTPConnectionPool(host='localhost', port=8082): Read timed out. (read timeout=300)"),
            RuntimeError("mimo-v2.5: 500 Server Error: Internal Server Error for url: http://localhost:8082/v1/chat/completions"),
            json.dumps({"verdict": "approve_with_these_changes", "changes": [], "notes": "Approved."}),
        ]

        def fake_call(*_: object, **__: object) -> str:
            value = responses.pop(0)
            if isinstance(value, Exception):
                raise value
            return str(value)

        with patch.object(runtime, "DIGESTS_DIR", root), patch.object(
            runtime, "_call_llm_proxy", side_effect=fake_call
        ):
            fresh, _, _ = editorial.phase_6_curate(
                catalog.TOPICS["world"], summaries, [], tracker, run_dir
            )
        check(len(fresh) == 1, (fresh,))
        artifact = json.loads((run_dir / "06-curated.json").read_text())
        check(
            artifact["editorial"]["review_model"] == runtime.MODEL_FALLBACK,
            artifact,
        )
        check(artifact["editorial"]["review_status"] == "reviewed", artifact)
        check(not responses, f"unused model responses: {responses!r}")
        review_artifact = json.loads(
            (run_dir / "06b-editorial-review.json").read_text()
        )
        check(
            review_artifact["review"]["verdict"] == "approve_with_changes",
            review_artifact,
        )
        check(len(review_artifact["errors"]) == 3, review_artifact["errors"])
        check(
            all("unknown critic verdict" not in error for error in review_artifact["errors"]),
            review_artifact["errors"],
        )


def test_critic_rejection_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        run_dir = root / "ai-tech" / "2026-08-10"
        run_dir.mkdir(parents=True)
        candidates, _, tracker = editorial_fixture(run_dir.name)
        summaries = [
            {key: value for key, value in candidate.items() if key != "candidate_id"}
            for candidate in candidates
        ]
        selected_id = candidates[0]["candidate_id"]
        proposal = {
            "selected_fresh": [{
                "candidate_id": selected_id,
                "editorial_summary": "Proposed summary.",
            }],
            "selected_ongoing": [],
            "story_state_proposals": [{
                "operation": "add",
                "candidate_id": selected_id,
                "evidence_candidate_ids": [selected_id],
                "latest_dev": "Proposed summary.",
                "editorial_significance": "high",
                "status": "active",
            }],
        }
        responses = [
            json.dumps(proposal),
            json.dumps({"verdict": "reject", "changes": []}),
            json.dumps({"verdict": "reject", "changes": []}),
        ]
        with patch.object(runtime, "DIGESTS_DIR", root), patch.object(
            runtime, "_call_llm_proxy", side_effect=responses
        ):
            fresh, updated, _ = editorial.phase_6_curate(
                catalog.TOPICS["ai-tech"], summaries, [], tracker, run_dir
            )
        artifact = json.loads((run_dir / "06-curated.json").read_text())
        check(len(fresh) == 2, "critic rejection did not use source-ranked fallback")
        # Rejected state cannot apply. The deterministic fallback records only
        # selected high-significance roots; medium one-offs are not follow-up
        # candidates for Developing and Ongoing.
        check(
            not any(
                story.get("latest_dev") == "Proposed summary."
                for story in updated["stories"]
            ),
            "rejected state proposal was applied",
        )
        today = run_dir.name
        added = {
            story.get("url"): story
            for story in updated["stories"]
            if story.get("first_seen") == today
        }
        check(
            set(added) == {"https://example.com/primary"},
            f"fallback tracked non-high fresh stories: {added}",
        )
        check(
            all(
                story.get("last_updated") == today
                and story.get("editorial_significance") == "high"
                and len(story.get("developments", [])) == 1
                for story in added.values()
            ),
            added,
        )
        check(
            artifact["editorial"]["review_status"] == "rejected_fallback",
            artifact,
        )


def test_standfirst_boundary_and_deterministic_render() -> None:
    stories = [{"title": "Safe <Title>", "summary": "Verified 12% result."}]
    valid, _ = copy_module.validate_standfirst(
        "Verified results reached 12%. The source-backed change reshapes the market.",
        stories,
    )
    check(valid, "source-backed newspaper standfirst was rejected")
    valid, reason = copy_module.validate_standfirst(
        "Verified results reached 99%. The change reshapes the market.", stories
    )
    check(not valid and "99" in reason, reason)
    valid, reason = copy_module.validate_standfirst(
        "Today’s digest leads with the verified 12% result. Read on for details.",
        stories,
    )
    check(not valid and "meta language" in reason, reason)
    valid, reason = copy_module.validate_standfirst(
        "Verified results reached 12% while the market", stories
    )
    check(not valid and "mid-sentence" in reason, reason)
    fallback = copy_module.fallback_standfirst(
        [{"summary": "A verified change occurred. Additional detail follows."}], []
    )
    check(fallback == "A verified change occurred.", fallback)
    abbreviation_sentence = (
        "The U.S. military struck two tankers. Further details followed."
    )
    check(
        copy_module.first_complete_sentence(abbreviation_sentence)
        == "The U.S. military struck two tankers.",
        abbreviation_sentence,
    )
    garbled = (
        "The U.S. Nepal's Foreign Ministry said 324 foreign nationals were "
        "rescued and 590 from 39 countries remained missing after the Aug."
    )
    check(copy_module.first_complete_sentence(garbled) == "", garbled)
    valid, reason = copy_module.validate_standfirst(garbled, [])
    check(not valid and "abbreviation period" in reason, reason)
    fallback = copy_module.fallback_standfirst(
        [
            {
                "title": "Flood rescue remains incomplete",
                "summary": garbled,
            },
            {
                "title": "Evacuations continue",
                "summary": (
                    "Emergency crews moved residents to safer ground. "
                    "Officials opened more shelters."
                ),
            },
        ],
        [],
    )
    check(
        fallback == "Emergency crews moved residents to safer ground.",
        fallback,
    )
    clipped = editorial.clean_editorial_text("word " * 300, limit=80)
    check(clipped.endswith("word…") and len(clipped) <= 81, clipped)

    fresh = [{
        "title": "Safe <Title>",
        "url": "https://example.com/story?a=1&b=2",
        "category": "Research",
        "summary": "Verified & reviewed.",
    }]
    ongoing = [{
        "title": "Ongoing",
        "url": "https://example.com/ongoing",
        "category": "Policy",
        "summary": "Existing summary.",
        "why_still_relevant": "New evidence.",
    }]
    rendered = archive.render_digest_html(
        {"title": "Test Section"}, fresh, ongoing, "Verified source-backed standfirst."
    )
    check("Safe &lt;Title&gt;" in rendered, "title was not escaped")
    check('href="https://example.com/story?a=1&amp;b=2"' in rendered,
          "URL was not safely rendered")
    check("↳ New evidence." in rendered, "ongoing rationale missing")
    check("{{FRESH_STORIES}}" not in rendered, "template placeholder remained")
    check("STORY BLOCK TEMPLATE" not in rendered, "template instructions leaked")
    check(
        "Developing and Ongoing" in rendered,
        "rendered section label did not match the editorial contract",
    )


def test_tracker_updates_require_material_evidence() -> None:
    """Rendering is not evidence; an exact source-linked follow-up is."""
    candidates, sif_candidates, tracker = editorial_fixture()
    proposal = {
        "selected_fresh": [{"candidate_id": candidates[1]["candidate_id"]}],
        "selected_ongoing": [{
            "story_url": "https://example.com/existing",
            "summary": "Established multi-day development.",
            "why_still_relevant": "Latest verified action remains in effect.",
        }],
        "story_state_proposals": [],
    }
    validated, _ = editorial.validate_editorial_proposal(
        proposal, candidates, sif_candidates, tracker
    )
    check(validated["story_state_proposals"] == [],
          validated["story_state_proposals"])
    original = json.loads(json.dumps(tracker))
    displayed = editorial.apply_story_state_proposals(
        tracker, validated, candidates, "2026-08-10"
    )
    check(tracker == original, "state application mutated its input")
    check(displayed["stories"][0]["last_updated"] == "2026-08-09",
          displayed["stories"][0])

    # A new article may update a tracked root only when the dedicated research
    # path declared the exact relationship. The candidate URL may differ.
    followup = {
        **candidates[0],
        "title": "Existing narrative materially advances",
        "url": "https://news.example.com/existing-action",
        "candidate_id": "candidate-linked-followup",
        "develops_story_url": "https://example.com/existing",
    }
    candidates.append(followup)
    with_update = {
        "selected_fresh": [{
            "candidate_id": followup["candidate_id"],
            "editorial_summary": "Officials took a new, verified action.",
            "related_story_url": "https://example.com/existing",
        }],
        "selected_ongoing": [{
            "story_url": "https://example.com/existing",
            "summary": "The tracked story now includes the official action.",
            "why_still_relevant": "Officials took a new action today.",
        }],
        "story_state_proposals": [],
    }
    validated, _ = editorial.validate_editorial_proposal(
        with_update, candidates, sif_candidates, tracker
    )
    update_ops = [
        op for op in validated["story_state_proposals"]
        if op["operation"] == "update"
    ]
    check(len(update_ops) == 1, validated["story_state_proposals"])
    check(
        update_ops[0]["evidence_candidate_ids"] == [followup["candidate_id"]],
        update_ops,
    )
    updated = editorial.apply_story_state_proposals(
        tracker, validated, candidates, "2026-08-10"
    )
    story = updated["stories"][0]
    check(story["latest_dev"] == "Officials took a new, verified action.", story)
    check(
        contracts.story_development_dates(story)
        == {"2026-08-08", "2026-08-09", "2026-08-10"},
        story,
    )


def test_developing_section_requires_significance_and_multiple_dates() -> None:
    """One-off and non-high stories never qualify, regardless of age/touches."""
    candidates, _, _ = editorial_fixture()
    one_off = {
        "title": "Single announcement",
        "url": "https://tracker.example/announcement",
        "category": "Industry",
        "latest_dev": "The original announcement.",
        "status": "active",
        "editorial_significance": "high",
        "first_seen": "2026-08-20",
        # A legacy display touch must not count as evidence.
        "last_updated": "2026-08-24",
    }
    medium_multiday = {
        "title": "Repeated but not important",
        "url": "https://tracker.example/medium",
        "category": "Industry",
        "latest_dev": "A second minor update.",
        "status": "active",
        "editorial_significance": "medium",
        "first_seen": "2026-08-20",
        "last_updated": "2026-08-22",
        "developments": [
            {"date": "2026-08-20", "url": "https://tracker.example/medium"},
            {"date": "2026-08-22", "url": "https://news.example/medium-update"},
        ],
    }
    qualified = {
        "title": "Important story with real movement",
        "url": "https://tracker.example/qualified",
        "category": "Policy",
        "latest_dev": "Officials issued a binding decision.",
        "status": "active",
        **validated_high_fields(),
        "first_seen": "2026-08-20",
        "last_updated": "2026-08-22",
        "developments": [
            {"date": "2026-08-20", "url": "https://tracker.example/qualified"},
            {"date": "2026-08-22", "url": "https://news.example/binding-decision"},
        ],
    }
    unsupported_high = {
        "title": "High label without evidence",
        "url": "https://tracker.example/unsupported-high",
        "category": "Policy",
        "latest_dev": "A second update occurred.",
        "status": "active",
        "editorial_significance": "high",
        "first_seen": "2026-08-20",
        "last_updated": "2026-08-22",
        "developments": [
            {"date": "2026-08-20", "url": "https://tracker.example/unsupported-high"},
            {"date": "2026-08-22", "url": "https://news.example/unsupported-update"},
        ],
    }
    tracker = {"stories": [one_off, medium_multiday, unsupported_high, qualified]}
    proposal = {
        "selected_fresh": [
            {"candidate_id": candidates[0]["candidate_id"]},
            {"candidate_id": candidates[1]["candidate_id"]},
        ],
        "selected_ongoing": [
            {"story_url": story["url"], "summary": story["latest_dev"],
             "why_still_relevant": story["latest_dev"]}
            for story in tracker["stories"]
        ],
        "story_state_proposals": [],
    }
    validated, warnings = editorial.validate_editorial_proposal(
        proposal, candidates, tracker["stories"], tracker
    )
    check(
        [item["story_url"] for item in validated["selected_ongoing"]]
        == [qualified["url"]],
        validated["selected_ongoing"],
    )
    check(
        sum("unqualified developing story" in warning for warning in warnings) == 3,
        warnings,
    )


def test_followup_research_targets_prior_high_significance_stories() -> None:
    today = datetime(2026, 8, 25, tzinfo=timezone.utc).date()
    stories = {
        "stories": [
            {
                "title": "Prior high story",
                "url": "https://tracker.example/high",
                **validated_high_fields(),
                "status": "active",
                "first_seen": "2026-08-24",
                "last_updated": "2026-08-24",
            },
            {
                "title": "Prior medium story",
                "url": "https://tracker.example/medium",
                "editorial_significance": "medium",
                "status": "active",
                "first_seen": "2026-08-24",
                "last_updated": "2026-08-24",
            },
            {
                "title": "Same-day high story",
                "url": "https://tracker.example/today",
                **validated_high_fields(),
                "status": "active",
                "first_seen": "2026-08-25",
                "last_updated": "2026-08-25",
            },
        ]
    }
    angle = contracts.build_developing_followup_angle(stories, today)
    check(angle is not None, "high-priority prior story was not scheduled")
    prompt = angle["prompt"]
    check("https://tracker.example/high" in prompt, prompt)
    check("https://tracker.example/medium" not in prompt, prompt)
    check("https://tracker.example/today" not in prompt, prompt)


def test_tracker_retention_uses_evidence_inactivity() -> None:
    today = datetime(2026, 8, 25, tzinfo=timezone.utc).date()
    active_long_running = {
        "title": "Long-running active crisis",
        "url": "https://tracker.example/active",
        "editorial_significance": "high",
        "status": "active",
        "first_seen": "2026-08-01",
        "last_updated": "2026-08-24",
        "developments": [
            {"date": "2026-08-01", "url": "https://tracker.example/active"},
            {"date": "2026-08-24", "url": "https://news.example/latest-action"},
        ],
    }
    inactive_active = {
        "title": "Recently stalled story",
        "url": "https://tracker.example/stalled",
        "editorial_significance": "high",
        "status": "active",
        "first_seen": "2026-08-10",
        "last_updated": "2026-08-20",
        "developments": [
            {"date": "2026-08-10", "url": "https://tracker.example/stalled"},
            {"date": "2026-08-20", "url": "https://news.example/stalled-update"},
        ],
    }
    expired_cooled = {
        "title": "Expired cooled story",
        "url": "https://tracker.example/expired",
        "editorial_significance": "high",
        "status": "cooled",
        "first_seen": "2026-08-01",
        "last_updated": "2026-08-10",
        "developments": [
            {"date": "2026-08-10", "url": "https://tracker.example/expired"},
        ],
    }
    kept, cooled, pruned = archive.prune_and_cool_stories(
        [active_long_running, inactive_active, expired_cooled], today
    )
    kept_by_url = {story["url"]: story for story in kept}
    check(active_long_running["url"] in kept_by_url, kept)
    check(kept_by_url[inactive_active["url"]]["status"] == "cooled", kept)
    check(expired_cooled["url"] not in kept_by_url, kept)
    check((cooled, pruned) == (1, 1), (cooled, pruned))


def test_ongoing_resurface_cap_cools_recurring_story() -> None:
    """An Ongoing story surfaced on many consecutive days without an
    evidence-backed development must be dropped and cooled, so the digest
    cannot repeat the same story day after day (digest-quality audit
    2026-08-22: the 404 Media rare-books story ran in ai-tech and OpenAI's
    PORTS-Pike story in ai-hardware on five consecutive days 08-18→08-22 with
    paraphrased summaries of the same facts)."""
    from datetime import date as date_cls
    story_url = "https://example.com/recurring"
    tracker = {"stories": [{
        "title": "Recurring story",
        "url": story_url,
        "category": "Research",
        "latest_dev": "No new development.",
        "status": "active",
        "editorial_significance": "medium",
        "first_seen": "2026-08-18",
        "last_updated": "2026-08-21",
    }]}
    proposal = {
        "selected_fresh": [],
        "selected_ongoing": [{
            "story_url": story_url,
            "summary": "Same facts as yesterday.",
            "why_still_relevant": "Still the lead.",
        }],
        "story_state_proposals": [],
    }
    today = date_cls(2026, 8, 22)
    with tempfile.TemporaryDirectory() as temporary:
        digest_dir = Path(temporary)
        # Days 08-18..08-21 all surfaced the story → this run would be day 5.
        for day in range(18, 22):
            curated_dir = digest_dir / f"2026-08-{day:02d}"
            curated_dir.mkdir()
            (curated_dir / "06-curated.json").write_text(json.dumps({
                "fresh": [],
                "ongoing": [{"url": story_url, "title": "Recurring story"}],
            }))
        warnings, ops = contracts.enforce_ongoing_resurface_cap(
            proposal, tracker, digest_dir, today
        )
        check(proposal["selected_ongoing"] == [], proposal["selected_ongoing"])
        check(
            any("consecutive days" in warning for warning in warnings), warnings
        )
        check(
            len(ops) == 1
            and ops[0]["operation"] == "update"
            and ops[0]["story_url"] == story_url
            and ops[0]["status"] == "cooled"
            and ops[0]["latest_dev"] == "No new development.",
            ops,
        )

        # A gap in the run resets the counter: 4 days total but not consecutive
        # means the story is not capped.
        gap_dir = Path(temporary) / "gap"
        gap_dir.mkdir()
        for day in (18, 19, 21):  # 08-20 missing
            curated_dir = gap_dir / f"2026-08-{day:02d}"
            curated_dir.mkdir()
            (curated_dir / "06-curated.json").write_text(json.dumps({
                "fresh": [],
                "ongoing": [{"url": story_url}],
            }))
        check(
            contracts.consecutive_surfaced_days(gap_dir, story_url, today) == 1,
            contracts.consecutive_surfaced_days(gap_dir, story_url, today),
        )

        # An evidence-backed update op (a real development) resets the cap.
        evidenced = {
            "selected_fresh": [],
            "selected_ongoing": [{
                "story_url": story_url,
                "summary": "Same facts as yesterday.",
                "why_still_relevant": "Still the lead.",
            }],
            "story_state_proposals": [{
                "operation": "update",
                "story_url": story_url,
                "evidence_candidate_ids": ["candidate-x"],
                "latest_dev": "New development.",
                "editorial_significance": "medium",
                "status": "active",
            }],
        }
        warnings, ops = contracts.enforce_ongoing_resurface_cap(
            evidenced, tracker, digest_dir
        )
        check(len(evidenced["selected_ongoing"]) == 1, evidenced["selected_ongoing"])
        check(warnings == [] and ops == [], (warnings, ops))


def test_editorial_floor_and_publication_artifact() -> None:
    """The editorial floor rejects filler and Phase 8 publishes stable local data."""
    candidates, sif_candidates, tracker = editorial_fixture()
    low_one_off = {
        "title": "Low-priority one-off",
        "url": "https://second.example/one-off",
        "category": "Policy",
        "latest_dev": "Only one minor report.",
        "status": "active",
        "editorial_significance": "low",
        "first_seen": "2026-08-10",
        "last_updated": "2026-08-10",
    }
    second_sif = {
        "title": "Second qualified developing story",
        "url": "https://second.example/ongoing",
        "category": "Policy",
        "latest_dev": "A binding second development.",
        "status": "active",
        **validated_high_fields(),
        "first_seen": "2026-08-09",
        "last_updated": "2026-08-10",
        "developments": [
            {"date": "2026-08-09", "url": "https://second.example/ongoing"},
            {"date": "2026-08-10", "url": "https://news.example/second-action"},
        ],
    }
    sif_candidates.extend([low_one_off, second_sif])

    # 1 fresh + 0 ongoing → floor uses the newest qualified story only.
    proposal = {
        "selected_fresh": [{"candidate_id": candidates[0]["candidate_id"]}],
        "selected_ongoing": [],
        "story_state_proposals": [],
    }
    validated, warnings = editorial.validate_editorial_proposal(
        proposal, candidates, sif_candidates, tracker
    )
    filled = {item["story_url"] for item in validated["selected_ongoing"]}
    check(filled == {"https://second.example/ongoing"},
          validated["selected_ongoing"])
    check(
        len(validated["selected_fresh"]) + len(validated["selected_ongoing"]) == 2,
        validated,
    )
    check(
        all(item["why_still_relevant"] for item in validated["selected_ongoing"]),
        validated["selected_ongoing"],
    )

    # Floor does not add a second story once two are selected.
    both = {
        "selected_fresh": [
            {"candidate_id": candidates[0]["candidate_id"]},
            {"candidate_id": candidates[1]["candidate_id"]},
        ],
        "selected_ongoing": [{
            "story_url": "https://example.com/existing",
            "summary": "Summarized.",
            "why_still_relevant": "Relevant.",
        }],
        "story_state_proposals": [],
    }
    validated, _ = editorial.validate_editorial_proposal(
        both, candidates, sif_candidates, tracker
    )
    check(len(validated["selected_ongoing"]) == 1, validated["selected_ongoing"])

    # 0 fresh + 0 ongoing and an empty pool remains honestly empty.
    empty_validated, _ = editorial.validate_editorial_proposal(
        {"selected_fresh": [], "selected_ongoing": [], "story_state_proposals": []},
        candidates, [], {"stories": []}, set(),
    )
    check(not empty_validated["selected_fresh"] and not empty_validated["selected_ongoing"],
          empty_validated)

    with tempfile.TemporaryDirectory() as temporary:
        digest_dir = Path(temporary) / "world-digest"
        run_dir = digest_dir / f"{datetime.now():%Y-%m-%d}"
        digest_dir.mkdir(parents=True)
        run_dir.mkdir()
        (run_dir / "06-curated.json").write_text(json.dumps({"fresh": [], "ongoing": []}))
        fresh_story = {
            "title": "First",
            "url": "https://example.com/a",
            "summary": "First source-backed summary explains a consequential verified policy change.",
            "category": "Policy",
            "editorial_significance": "high",
            "priority_score": 91.5,
            "priority_explanation": "High significance and broad observed coverage.",
            "candidate_id": "private-editorial-id",
        }
        ongoing_story = {
            "title": "Second",
            "url": "https://example.com/b",
            "summary": "Second source-backed summary.",
            "editorial_significance": "high",
            "priority_score": 100.0,
            "why_still_relevant": "A material development occurred today.",
            "selection_reason": "private editorial reasoning",
        }
        stories = [fresh_story, ongoing_story]
        standfirst = fresh_story["summary"]
        story_fingerprint = copy_module.standfirst_story_fingerprint(stories)
        standfirst_inputs = runtime.phase_inputs(
            "standfirst",
            topic=catalog.TOPICS["world"],
            upstream={"stories": runtime.canonical_fingerprint(stories)},
            policy={"prompt_version": catalog.STANDFIRST_PROMPT_VERSION},
        )
        standfirst_state = runtime.WorkflowState(
            run_dir, runtime.WORKFLOW_NAME, run_id=run_dir.name
        )
        standfirst_state.begin_phase(
            "standfirst",
            inputs=standfirst_inputs,
            artifact_path=run_dir / "07-standfirst.json",
            schema_version=catalog.STANDFIRST_PROMPT_VERSION,
        )
        standfirst_state.complete_json(
            "standfirst",
            {
                "prompt_version": catalog.STANDFIRST_PROMPT_VERSION,
                "story_fingerprint": story_fingerprint,
                "standfirst": standfirst,
                "status": "fixture",
                "model": "",
                "errors": [],
            },
        )

        with patch("daily_news.runtime.subprocess.run") as subprocess_run:
            publication_path = archive.phase_8_archive(
                catalog.TOPICS["world"],
                "<html>archive</html>",
                {"stories": []},
                run_dir,
                digest_dir,
                fresh=[fresh_story],
                ongoing=[ongoing_story],
            )
        check(not subprocess_run.called, "topic archive attempted to send email")
        check((digest_dir / f"{datetime.now():%Y-%m-%d}.html").exists(),
              "daily HTML archive missing")
        publication = json.loads(publication_path.read_text())
        check(publication["slug"] == "world", publication)
        check(publication["schema_version"] == 2, publication)
        check(publication["standfirst"] == standfirst, publication["standfirst"])
        check(len(publication["fresh"]) + len(publication["ongoing"]) == 2, publication)
        check("candidate_id" not in publication["fresh"][0], publication["fresh"][0])
        check("selection_reason" not in publication["ongoing"][0], publication["ongoing"][0])
        check(publication["ongoing"][0]["why_still_relevant"].startswith("A material"),
              publication["ongoing"][0])


def test_listing_urls_rejected() -> None:
    """Section/date archive URLs (Guardian .../all) must never be selected into
    Fresh or Ongoing or enter the tracker (digest-quality audit 2026-08-21:
    world-digest ongoing entries on 08-20 and 08-21 were the same two Guardian
    .../all pages, which fetch as the section listing, not an article)."""
    listing = "https://www.theguardian.com/technology/2026/aug/18/all"
    check(contracts.is_listing_url(listing), listing)
    check(contracts.is_listing_url(listing + "?utm_source=x"), "query-suffixed listing")
    check(not contracts.is_listing_url("https://www.theguardian.com/world/article"),
          "normal article flagged")
    check(not contracts.is_listing_url("https://example.com/all-about-x"),
          "prefix segment flagged")

    fresh_day = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    candidates, _ = editorial.prepare_editorial_candidates([
        {
            "title": "OpenAI listing page",
            "url": listing,
            "source_domain": "theguardian.com",
            "summary": "Search result title on the listing page.",
            "category": "Technology",
            "editorial_significance": "high",
            "date_published": fresh_day,
            "source_verdict": "fresh",
            "judge_verdict": "keep",
        },
    ], set())
    tracker_listing = {
        "title": "Tracked listing",
        "url": listing,
        "category": "Technology",
        "latest_dev": "Development.",
        "status": "active",
        "editorial_significance": "medium",
        "first_seen": "2026-08-18",
        "last_updated": "2026-08-19",
    }
    proposal = {
        "selected_fresh": [
            {"candidate_id": candidates[0]["candidate_id"]},
        ],
        "selected_ongoing": [{
            "story_url": listing,
            "summary": "Still listed.",
            "why_still_relevant": "Resurfacing identically.",
        }],
        "story_state_proposals": [{
            "operation": "update",
            "story_url": listing,
            "evidence_candidate_ids": [candidates[0]["candidate_id"]],
            "latest_dev": "Updated.",
            "editorial_significance": "medium",
            "status": "active",
        }],
    }
    validated, warnings = editorial.validate_editorial_proposal(
        proposal, candidates, [tracker_listing],
        {"stories": [tracker_listing]}, set(),
    )
    check(validated["selected_fresh"] == [], validated["selected_fresh"])
    check(validated["selected_ongoing"] == [], validated["selected_ongoing"])
    check(validated["story_state_proposals"] == [], validated["story_state_proposals"])
    check(any("listing URL fresh selection" in warning for warning in warnings), warnings)
    check(any("listing URL ongoing story" in warning for warning in warnings), warnings)

    # The floor must not fill a thin digest with a listing URL either.
    floor_proposal = {
        "selected_fresh": [], "selected_ongoing": [], "story_state_proposals": []
    }
    validated, _ = editorial.validate_editorial_proposal(
        floor_proposal, candidates, [tracker_listing],
        {"stories": [tracker_listing]}, set(),
    )
    check(validated["selected_ongoing"] == [], validated["selected_ongoing"])


def test_stub_retry_preserves_failed_attempt_artifacts() -> None:
    """Stub/fallback retries archive the failed attempt's phase JSON instead of deleting it."""
    with tempfile.TemporaryDirectory() as temporary:
        run_dir = Path(temporary)
        names = ["01-research-raw.json", "03-urls-ranked.json", "06-curated.json"]
        for name in names:
            (run_dir / name).write_text(json.dumps({"attempt": 1, "name": name}))
        archive.archive_stub_attempt(run_dir)
        archived = sorted(p.name for p in run_dir.glob("stub-attempt-*/*.json"))
        check(archived == names, f"archived={archived}")
        check(not list(run_dir.glob("0*-*.json")), "failed attempt artifacts not preserved")


def test_stub_attempts_cleaned_after_success() -> None:
    """Archived stub-attempt subdirs are removed once the final run completes so
    audits don't double-count partial runs (digest-quality audit 2026-08-24)."""
    with tempfile.TemporaryDirectory() as temporary:
        run_dir = Path(temporary)
        stub = run_dir / "stub-attempt-20260823-080644-765214"
        stub.mkdir()
        (stub / "01-research-raw.json").write_text("{}")
        keep = run_dir / "06-curated.json"
        keep.write_text("{}")
        archive.cleanup_stub_attempts(run_dir)
        check(not stub.exists(), "stub-attempt dir not removed")
        check(keep.exists(), "final-run artifact was removed")


def test_asset_cdn_urls_rejected() -> None:
    """Publisher asset-CDN hosts (assets.theregister.com) must never be selected
    into Fresh or Ongoing or enter the tracker; they are not article hosts
    (digest-quality audit 2026-08-24: research invented assets.theregister.com
    links that 405'd and resurfaced in the tracker for five days)."""
    cdn = "https://assets.theregister.com/2026/08/19/20262/?td=keepreading&utm_source=openai"
    check(contracts.is_asset_cdn_url(cdn), cdn)
    check(contracts.is_asset_cdn_url(cdn + "?x=1"), "query-suffixed asset CDN")
    check(not contracts.is_asset_cdn_url(
        "https://www.theregister.com/systems/2026/08/19/story/1"),
        "article host flagged")

    fresh_day = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    candidates, _ = editorial.prepare_editorial_candidates([
        {
            "title": "Baidu chips",
            "url": cdn,
            "source_domain": "theregister.com",
            "summary": "Baidu chip demand rising.",
            "category": "AI Infrastructure",
            "editorial_significance": "high",
            "date_published": fresh_day,
            "source_verdict": "fresh",
            "judge_verdict": "keep",
        },
    ], set())
    tracker_cdn = {
        "title": "Tracked asset-CDN story",
        "url": cdn,
        "category": "AI Infrastructure",
        "latest_dev": "Development.",
        "status": "active",
        "editorial_significance": "medium",
        "first_seen": "2026-08-20",
        "last_updated": "2026-08-20",
    }
    proposal = {
        "selected_fresh": [
            {"candidate_id": candidates[0]["candidate_id"]},
        ],
        "selected_ongoing": [{
            "story_url": cdn,
            "summary": "Still developing.",
            "why_still_relevant": "Resurfacing identically.",
        }],
        "story_state_proposals": [{
            "operation": "update",
            "story_url": cdn,
            "evidence_candidate_ids": [candidates[0]["candidate_id"]],
            "latest_dev": "Updated.",
            "editorial_significance": "medium",
            "status": "active",
        }],
    }
    validated, warnings = editorial.validate_editorial_proposal(
        proposal, candidates, [tracker_cdn],
        {"stories": [tracker_cdn]}, set(),
    )
    check(validated["selected_fresh"] == [], validated["selected_fresh"])
    check(validated["selected_ongoing"] == [], validated["selected_ongoing"])
    check(validated["story_state_proposals"] == [], validated["story_state_proposals"])
    check(any("asset-CDN fresh selection" in warning for warning in warnings), warnings)
    check(any("asset-CDN ongoing story" in warning for warning in warnings), warnings)

    # The floor must not fill a thin digest with an asset-CDN URL either.
    floor_proposal = {
        "selected_fresh": [], "selected_ongoing": [], "story_state_proposals": []
    }
    validated, _ = editorial.validate_editorial_proposal(
        floor_proposal, candidates, [tracker_cdn],
        {"stories": [tracker_cdn]}, set(),
    )
    check(validated["selected_ongoing"] == [], validated["selected_ongoing"])


def test_proxy_5xx_retry_with_backoff() -> None:
    """A transient proxy 503 must reuse one OpenCode session ID while retrying
    with backoff before the editorial stage falls back (digest-quality audit
    2026-08-24: both Mimo calls 503'd and the proposal skipped the critic)."""
    class FakeResponse:
        def __init__(self, status_code: int, body: dict | None = None) -> None:
            self.status_code = status_code
            self._body = body

        def raise_for_status(self) -> None:
            if self.status_code >= 400:
                raise requests.HTTPError(f"{self.status_code} Server Error")

        def json(self) -> dict:
            return self._body

    import requests  # noqa: PLC0415

    calls = []
    sleeps = []

    def fake_post(url, json=None, headers=None, timeout=None):
        calls.append((url, dict(headers or {})))
        if len(calls) <= 2:
            return FakeResponse(503)
        return FakeResponse(200, {"choices": [{"message": {"content": "reviewed ok"}}]})

    with patch("daily_news.runtime.requests.post", side_effect=fake_post), \
         patch("daily_news.runtime._detect_model_provider",
               return_value={"provider": "opencode-go",
                             "chat_url": "http://proxy.test/v1/chat/completions"}), \
         patch("daily_news.runtime.time.sleep", side_effect=lambda s: sleeps.append(s)):
        content = runtime._call_llm_proxy("system", "user", model=runtime.MODEL_FALLBACK)
        check(content == "reviewed ok", content)
        check(len(calls) == 3, f"503 was not retried: {len(calls)} calls")
        check(len(sleeps) == 2, f"backoff sleeps={sleeps}")
        check(sleeps == [runtime.PROXY_5XX_BACKOFF_SECONDS,
                         runtime.PROXY_5XX_BACKOFF_SECONDS * 2], sleeps)
        session_ids = [
            headers.get("x-opencode-session") for _, headers in calls
        ]
        check(all(session_ids), f"missing OpenCode session header: {session_ids}")
        check(len(set(session_ids)) == 1,
              f"retry changed OpenCode session ID: {session_ids}")
        first_session_id = session_ids[0]
        uuid.UUID(first_session_id)

    # Exhausted 5xx retries still propagate so the stage-level fallback can act.
    calls.clear()
    def always_503(url, json=None, headers=None, timeout=None):
        calls.append((url, dict(headers or {})))
        return FakeResponse(503)

    with patch("daily_news.runtime.requests.post",
               side_effect=always_503), \
         patch("daily_news.runtime._detect_model_provider",
               return_value={"provider": "opencode-go",
                             "chat_url": "http://proxy.test/v1/chat/completions"}), \
         patch("daily_news.runtime.time.sleep"):
        raised = False
        try:
            runtime._call_llm_proxy("system", "user", model=runtime.MODEL_FALLBACK)
        except requests.HTTPError:
            raised = True
        check(raised, "exhausted 503 did not raise")
        check(len(calls) == runtime.PROXY_5XX_RETRIES + 1,
              f"503 retried {len(calls)} times")
        retry_session_ids = [
            headers.get("x-opencode-session") for _, headers in calls
        ]
        check(len(set(retry_session_ids)) == 1,
              f"exhausted retries changed session ID: {retry_session_ids}")
        check(retry_session_ids[0] != first_session_id,
              "separate proxy calls reused one global session ID")


def main() -> None:
    tests = [
        test_url_normalization,
        test_search_health_uses_fresh_news_path,
        test_referenced_url_collection_uses_catalog_filters,
        test_tool_omp_uses_digest_specific_config,
        test_research_prompts_do_not_request_article_reads,
        test_test_mode_isolates_mutable_shared_state,
        test_attention_health_monitors_source_availability_and_jev,
        test_article_cache_contract,
        test_cross_topic_dedup_precedes_fetch_queue,
        test_cross_topic_same_event_referenced_url_dedup,
        test_rank_resume_fingerprint_includes_cross_topic_urls,
        test_phase_two_cross_day_dedup_window_contract,
        test_phase_two_rejects_unvalidated_legacy_followup,
        test_recent_coverage_ledger_blocks_other_section_repeats,
        test_ongoing_card_follows_latest_verified_development,
        test_runtime_preflight_fails_closed_on_missing_symbol,
        test_phase_inputs_include_actual_code_hashes,
        test_empty_phase_has_explicit_durable_outcome,
        test_attention_phase_persists_durable_observations,
        test_attention_phase_leaves_out_failed_sources_and_unadjudicated_stories,
        test_offline_attention_phase_never_reaches_the_network,
        test_phase_three_uses_product_priority,
        test_phase_four_concurrency_and_shared_cache,
        test_phase_five_backfills_date_confirmed_from_date_published,
        test_cached_curation_regenerates_referenced_url_sidecar,
        test_phase_six_backfills_missing_date_confirmed_on_curated_fresh,
        test_editorial_validation_and_state_application,
        test_editorial_critic_patch_contract,
        test_editorial_drops_stale_fresh_selection,
        test_freshness_gate_rejects_future_dates,
        test_freshness_gate_ignores_future_event_date_confirmed,
        test_editorial_caps_source_concentration,
        test_editorial_proposal_retries_with_freshness_hint,
        test_critic_fresh_removal_honored_when_all_candidates_stale,
        test_critic_emptying_valid_fresh_still_fails_closed,
        test_phase_six_fallback_and_review_chain,
        test_stub_retry_preserves_failed_attempt_artifacts,
        test_editorial_proposal_retries_primary_before_fallback,
        test_editorial_critic_retries_primary_after_transient_error,
        test_critic_fallback_verdict_spelling_normalized,
        test_critic_rejection_fails_closed,
        test_standfirst_boundary_and_deterministic_render,
        test_tracker_updates_require_material_evidence,
        test_developing_section_requires_significance_and_multiple_dates,
        test_followup_research_targets_prior_high_significance_stories,
        test_tracker_retention_uses_evidence_inactivity,
        test_ongoing_resurface_cap_cools_recurring_story,
        test_editorial_floor_and_publication_artifact,
        test_listing_urls_rejected,
        test_stub_attempts_cleaned_after_success,
        test_asset_cdn_urls_rejected,
        test_proxy_5xx_retry_with_backoff,
    ]
    for test in tests:
        test()
        print(f"OK  {test.__name__}")
    print("ALL PASSED")


if __name__ == "__main__":
    main()
