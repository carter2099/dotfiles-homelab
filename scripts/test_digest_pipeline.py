#!/usr/bin/env python3
"""Focused behavioral fixtures for digest dedup, cache, editorial, and rendering."""
from __future__ import annotations

import contextlib
import copy
import gzip
import io
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
            queue = research.phase_3_rank(catalog.TOPICS["ai-tech"], fresh, run_dir)
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
            queue = research.phase_3_rank(catalog.TOPICS["ai-tech"], fresh, run_dir)
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
            first = research.phase_3_rank(
                catalog.TOPICS["ai-tech"], [copy.deepcopy(candidate)], run_dir,
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
            }))
            second = research.phase_3_rank(
                catalog.TOPICS["ai-tech"], [copy.deepcopy(candidate)], run_dir,
            )
        check(not second, "rank reused cache after cross-topic URL set changed")


def test_phase_two_cross_day_dedup_window_contract() -> None:
    """Fresh-window findings reach the judge; older findings are stale.

    A finding published before yesterday (here three days ago) never reaches
    the LLM judge and never comes back as a story.
    """
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        today_date = datetime.now(timezone.utc).date()
        today = today_date.isoformat()
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
        older = {
            **finding,
            "title": "Three-day-old event",
            "url": "https://example.com/older-event",
            "date_published": (today_date - timedelta(days=3)).isoformat(),
            "event": "Three-day-old event occurs",
            "event_terms": ["Three-day-old", "older event"],
        }
        judged = {
            "approved": [finding],
            "rejected": [],
        }
        with patch(
            "daily_news.runtime._call_llm_proxy",
            return_value=json.dumps(judged),
        ) as call:
            fresh = research.phase_2_judge_research(
                catalog.TOPICS["ai-tech"],
                [copy.deepcopy(finding), copy.deepcopy(older)],
                run_dir,
            )
        check(catalog.CROSS_DAY_DEDUP_DAYS == 5, catalog.CROSS_DAY_DEDUP_DAYS)
        check([item["title"] for item in fresh] == ["Fresh verified event"], fresh)
        check(
            not any(older["url"] in str(args) for args in call.call_args_list),
            "a finding published before the fresh window reached the judge",
        )

        stale_dir = root / "stale" / "ai-tech" / today
        stale_dir.mkdir(parents=True)
        with patch("daily_news.runtime._call_llm_proxy") as call:
            stale_only = research.phase_2_judge_research(
                catalog.TOPICS["ai-tech"], [copy.deepcopy(older)], stale_dir,
            )
        check(stale_only == [], stale_only)
        check(not call.called, "a stale-only batch reached the LLM judge")
        artifact = json.loads((stale_dir / "02-research-judged.json").read_text())
        check(artifact["fresh"] == [] and artifact["status"] == "empty", artifact)


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
            fresh = research.phase_2_judge_research(
                catalog.TOPICS["agentic-platform"], copy.deepcopy(findings), run_dir,
            )
        check(
            sorted(item["title"] for item in fresh)
            == ["Genuinely new agent story", "Outside window story"],
            f"recently covered stories re-entered another section: {fresh!r}",
        )


def _shared_url_findings(today: str) -> tuple[str, list[dict]]:
    """Two distinct raw findings the research model attributed to one URL."""
    url = "https://www.techpowerup.com/350844/shared-roundup"

    def finding(title: str, event: str, terms: list[str], basis: str) -> dict:
        return {
            "title": title,
            "url": url,
            "source_domain": "techpowerup.com",
            "date_published": today,
            "summary": f"{title} summary.",
            "category": "Consumer & Edge",
            "research_angle_id": "consumer-edge",
            "editorial_significance": "medium",
            "event": event,
            "event_terms": terms,
            "significance_evidence": {
                "basis": basis, "affected_scope": "sector", "impact": f"{event} impact.",
            },
        }

    return url, [
        finding("Community Mod Brings DLSS 5 to AMD Radeon GPUs",
                "Community developers ported DLSS 5 neural rendering to Radeon",
                ["DLSS 5 on AMD", "DLSS-NR-on-AMD"], "major_product_or_platform_shift"),
        finding("Thermal Grizzly and Noctua Launch WireView Pro II",
                "Thermal Grizzly and Noctua released the WireView Pro II",
                ["WireView Pro II", "Thermal Grizzly WireView"], "security_or_safety_incident"),
    ]


def _judge_batch_reply(approve_title: str, drop_ids: bool):
    """Fake Phase 2 judge: echoes one finding as approved (event prose garbled,
    as the model may), rejects the rest, optionally losing finding_id."""
    def reply(system: str, user: str, model: str | None = None) -> str:
        start = user.index("## Findings to evaluate")
        batch_json = user[user.index("[", start):user.index("\n\nEvaluate each finding")]
        items = json.loads(batch_json)
        approved, rejected = [], []
        for item in items:
            if drop_ids:
                item.pop("finding_id", None)
            if item["title"] == approve_title:
                item["event"] = "model-rewritten event"
                approved.append(item)
            else:
                rejected.append({"finding": item, "reason": "low significance"})
        return json.dumps({"approved": approved, "rejected": rejected})
    return reply


def test_phase_two_shared_url_findings_keep_their_own_metadata() -> None:
    """Two raw findings sharing one URL must each keep their own event metadata.

    Regression for ai-hardware 2026-09-28: the DLSS-on-AMD and WireView Pro II
    findings shared a TechPowerUp URL; Phase 2 restored metadata keyed by URL
    alone, so the approved DLSS story shipped WireView's event, event_terms,
    and significance_evidence.
    """
    with tempfile.TemporaryDirectory() as temporary:
        today = datetime.now(timezone.utc).date().isoformat()
        run_dir = Path(temporary) / catalog.TOPICS["ai-hardware"]["category"] / today
        run_dir.mkdir(parents=True)
        url, findings = _shared_url_findings(today)
        dlss = findings[0]
        with patch("daily_news.runtime._call_llm_proxy",
                   side_effect=_judge_batch_reply(dlss["title"], drop_ids=False)):
            fresh = research.phase_2_judge_research(
                catalog.TOPICS["ai-hardware"], copy.deepcopy(findings), run_dir,
            )
        check([item["title"] for item in fresh] == [dlss["title"]], fresh)
        story = fresh[0]
        for field in ("event", "event_terms", "significance_evidence"):
            check(story[field] == dlss[field],
                  f"{field} restored from the other finding sharing {url}: {story[field]!r}")
        check("finding_id" not in story, "run-local finding_id leaked into the artifact")


def test_phase_two_drops_unidentified_shared_url_finding() -> None:
    """A judged finding that lost its finding_id and shares its URL with another
    source finding cannot be matched to its own metadata, so it is dropped;
    a lost id on a URL only one finding carries still restores by URL."""
    with tempfile.TemporaryDirectory() as temporary:
        today = datetime.now(timezone.utc).date().isoformat()
        run_dir = Path(temporary) / catalog.TOPICS["ai-hardware"]["category"] / today
        run_dir.mkdir(parents=True)
        _, findings = _shared_url_findings(today)
        with patch("daily_news.runtime._call_llm_proxy",
                   side_effect=_judge_batch_reply(findings[0]["title"], drop_ids=True)):
            fresh = research.phase_2_judge_research(
                catalog.TOPICS["ai-hardware"], copy.deepcopy(findings), run_dir,
            )
        check(fresh == [], f"unidentifiable shared-URL finding survived: {fresh!r}")
        judged = json.loads((run_dir / "02-research-judged.json").read_text())
        check(any(r.get("reason") == "unidentified_shared_url" for r in judged["rejected"]),
              judged["rejected"])

        unique = copy.deepcopy(findings[0])
        unique["url"] = "https://www.techpowerup.com/350997/unique-story"
        run_dir = Path(temporary) / "unique" / catalog.TOPICS["ai-hardware"]["category"] / today
        run_dir.mkdir(parents=True)
        with patch("daily_news.runtime._call_llm_proxy",
                   side_effect=_judge_batch_reply(unique["title"], drop_ids=True)):
            fresh = research.phase_2_judge_research(
                catalog.TOPICS["ai-hardware"], [copy.deepcopy(unique)], run_dir,
            )
        check([item["event"] for item in fresh] == [unique["event"]], fresh)


def _judge_source_findings(today: str) -> list[dict]:
    """Three distinct raw findings, each on its own URL."""
    def finding(slug: str, title: str, significance: str) -> dict:
        return {
            "title": title,
            "url": f"https://example.com/agents/{slug}",
            "source_domain": "example.com",
            "date_published": today,
            "summary": f"{title} summary.",
            "category": "Platforms",
            "research_angle_id": "platforms",
            "editorial_significance": significance,
            "event": f"{title} event",
            "event_terms": [title, slug],
            "significance_evidence": {
                "basis": "major_product_or_platform_shift",
                "affected_scope": "sector",
                "impact": f"{title} impact.",
            },
        }
    return [
        finding("checkpoint-issues", "LangGraph checkpoint issue cluster", "medium"),
        finding("thinkingbox-bench", "ThinkingBox-Bench benchmark blog", "medium"),
        finding("red-team-post", "Agent red-team engineering post", "high"),
    ]


def _run_judge_shapes(run_dir: Path, findings: list[dict], shape) -> tuple[list[dict], dict, str]:
    """Run Phase 2 with a fake judge that approves `shape(items)` and rejects
    nothing else; returns (fresh, judged artifact, captured stdout)."""
    def reply(system: str, user: str, model: str | None = None) -> str:
        start = user.index("## Findings to evaluate")
        items = json.loads(user[user.index("[", start):user.index("\n\nEvaluate each finding")])
        return json.dumps({"approved": shape(items), "rejected": []})

    out = io.StringIO()
    with patch("daily_news.runtime._call_llm_proxy", side_effect=reply), \
            contextlib.redirect_stdout(out):
        fresh = research.phase_2_judge_research(
            catalog.TOPICS["agentic-platform"], copy.deepcopy(findings), run_dir,
        )
    judged = json.loads((run_dir / "02-research-judged.json").read_text())
    return fresh, judged, out.getvalue()


def _judge_run_dir(root: Path, name: str, today: str) -> Path:
    run_dir = root / name / catalog.TOPICS["agentic-platform"]["category"] / today
    run_dir.mkdir(parents=True)
    return run_dir


def test_phase_two_restores_approvals_with_altered_urls() -> None:
    """Judge approvals keyed by finding_id survive a URL the judge altered and
    take title/summary/date_tag from the source finding.

    Regression for agentic-platform 2026-10-05: the judge log said 3 approved
    but Phase 2 ended with 0 fresh and no record of the 3 approvals.
    """
    with tempfile.TemporaryDirectory() as temporary:
        today = datetime.now(timezone.utc).date().isoformat()
        findings = _judge_source_findings(today)
        run_dir = _judge_run_dir(Path(temporary), "a", today)
        fresh, _, _ = _run_judge_shapes(run_dir, findings, lambda items: [
            {"finding_id": item["finding_id"], "url": f"{item['url']}?src=newsletter&aid=x1"}
            for item in items
        ])
        check([item["title"] for item in fresh] == [f["title"] for f in findings],
              f"approved findings with altered URLs were lost: {fresh!r}")
        for story, source in zip(fresh, findings):
            for field in ("url", "summary", "category", "source_domain", "event", "event_terms"):
                check(story.get(field) == source[field], f"{field} not restored: {story!r}")
            check(story.get("date_tag") == "fresh", story)
            check("finding_id" not in story, "run-local finding_id leaked into the artifact")


def test_phase_two_keeps_bare_string_id_approvals() -> None:
    """A judge that approves by bare finding_id string keeps those findings."""
    with tempfile.TemporaryDirectory() as temporary:
        today = datetime.now(timezone.utc).date().isoformat()
        findings = _judge_source_findings(today)
        run_dir = _judge_run_dir(Path(temporary), "b", today)
        fresh, _, _ = _run_judge_shapes(
            run_dir, findings, lambda items: [item["finding_id"] for item in items],
        )
        check([item["title"] for item in fresh] == [f["title"] for f in findings],
              f"bare-string id approvals were lost: {fresh!r}")
        check(all(item.get("summary") and item.get("date_tag") == "fresh" for item in fresh), fresh)


def test_phase_two_records_unmatched_judge_approval() -> None:
    """An approval with no id and a URL no source carries is recorded, never lost."""
    with tempfile.TemporaryDirectory() as temporary:
        today = datetime.now(timezone.utc).date().isoformat()
        findings = _judge_source_findings(today)
        run_dir = _judge_run_dir(Path(temporary), "c", today)
        invented = {"title": "Invented story", "url": "https://nowhere.example/invented"}
        fresh, judged, out = _run_judge_shapes(
            run_dir, findings, lambda items: [copy.deepcopy(invented)],
        )
        check(fresh == [], fresh)
        unmatched = [r for r in judged["rejected"] if r.get("reason") == "unmatched_judge_output"]
        check(len(unmatched) == 1 and unmatched[0]["finding"] == invented,
              f"unmatched approval was not recorded: {judged['rejected']!r}")
        check("[WARN] judge_research — 1 approved item(s) could not be matched" in out, out)


def test_phase_two_rejects_id_url_conflict() -> None:
    """An id naming one finding with another finding's URL is ambiguous."""
    with tempfile.TemporaryDirectory() as temporary:
        today = datetime.now(timezone.utc).date().isoformat()
        findings = _judge_source_findings(today)
        run_dir = _judge_run_dir(Path(temporary), "d", today)
        fresh, judged, _ = _run_judge_shapes(run_dir, findings, lambda items: [
            {**items[0], "url": items[1]["url"]},
        ])
        check(fresh == [], f"id/URL conflict shipped a finding: {fresh!r}")
        check([r.get("reason") for r in judged["rejected"]] == ["ambiguous_judge_output"],
              judged["rejected"])


def test_phase_two_applies_judge_significance() -> None:
    """The judge's editorial_significance adjustment is the one change kept."""
    with tempfile.TemporaryDirectory() as temporary:
        today = datetime.now(timezone.utc).date().isoformat()
        findings = _judge_source_findings(today)
        run_dir = _judge_run_dir(Path(temporary), "e", today)
        fresh, _, _ = _run_judge_shapes(run_dir, findings, lambda items: [
            {"finding_id": items[2]["finding_id"], "editorial_significance": "Low",
             "title": "Judge-rewritten title"},
            {"finding_id": items[0]["finding_id"]},
        ])
        by_url = {item["url"]: item for item in fresh}
        lowered = by_url[findings[2]["url"]]
        check(lowered["editorial_significance"] == "low", lowered)
        check(lowered["title"] == findings[2]["title"], "judge rewrote the source title")
        check(by_url[findings[0]["url"]]["editorial_significance"] == "medium", fresh)


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

        valid_chain = (
            "modelRoles:\n  web: openai-codex/gpt-5.6-luna\n"
            "retry:\n  fallbackChains:\n    web:\n"
            "      - anthropic/claude-haiku-4-5\n      - web/searxng\n"
        )
        searxng_block = "searxng:\n  endpoint: http://localhost:8080\n  categories: general,news\n"
        for name, text, expected, message in (
            ("no-claude",
             "modelRoles:\n  web: openai-codex/gpt-5.6-luna\n"
             "retry:\n  fallbackChains:\n    web:\n      - web/searxng\n" + searxng_block,
             "web search chain", "preflight accepted a chain without the Claude fallback"),
            ("legacy-order",
             valid_chain + "providers:\n  webSearchOrder:\n    - codex\n    - searxng\n" + searxng_block,
             "webSearchOrder is retired", "preflight accepted the retired webSearchOrder key"),
        ):
            wrong_config = Path(temporary) / f"{name}-digest-config.yml"
            wrong_config.write_text(text)
            with patch.object(runtime, "DIGEST_OMP_CONFIG", wrong_config):
                raised = False
                try:
                    workflow.validate_runtime_contract()
                except RuntimeError as error:
                    raised = expected in str(error)
                check(raised, message)

        localized_config = Path(temporary) / "localized-digest-config.yml"
        localized_config.write_text(valid_chain + searxng_block + "  language: en\n")
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
            scored_fresh = research.phase_2b_attention(
                catalog.TOPICS["ai-tech"], fresh, run_dir
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
                scored = research.phase_2b_attention(catalog.TOPICS["ai-tech"], fresh, run_dir)
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
            scored_fresh = research.phase_2b_attention(
                catalog.TOPICS["world"], fresh, run_dir
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
            queue = research.phase_3_rank(catalog.TOPICS["ai-tech"], fresh, run_dir)
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


def _record_fetches(urls: list[str]):
    def fake_omp(prompt: str, **kwargs: object) -> str:
        url = prompt.split("Fetch this article: ", 1)[1].splitlines()[0]
        urls.append(url)
        return json.dumps({
            "title": "Fetched", "url": url, "date_confirmed": "2026-09-27",
            "author": "", "summary": "A detailed factual summary.",
            "key_details": ["detail"], "fetch_success": True,
        })
    return fake_omp


def test_hard_paywall_story_never_reaches_fetch() -> None:
    check(contracts.hard_paywall_domain("https://amp.washingtonpost.com/x") == "washingtonpost.com",
          "subdomain of a paywalled publisher not matched")
    check(contracts.hard_paywall_domain("WWW.TheInformation.com/articles/x") == "theinformation.com",
          "scheme-less mixed-case host not matched")
    check(contracts.hard_paywall_domain("https://notwashingtonpost.com/x") is None,
          "suffix without a label boundary matched")
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        run_dir = root / catalog.TOPICS["world"]["category"] / "2026-09-27"
        run_dir.mkdir(parents=True)
        paywalled = [
            ("https://www.washingtonpost.com/weather/2026/09/26/noreaster/", 95.0,
             "Major nor'easter batters East Coast", ["nor'easter", "coastal flooding"]),
            ("https://amp.washingtonpost.com/science/2026/09/26/dogs-words/", 94.0,
             "Dogs learn words the same way babies do", ["dog word learning"]),
            ("https://www.theinformation.com/articles/chip-talks", 93.0,
             "Anthropic in talks with Samsung on custom chips", ["Samsung custom chips"]),
        ]
        fresh = [{
            "title": title, "url": url, "priority_score": score,
            "editorial_significance": "medium", "date_published": "2026-09-27",
            "event": title, "event_terms": terms,
        } for url, score, title, terms in paywalled]
        fresh.append({
            "title": "Mortgage rates break past 7%", "url": "https://wboi.org/mortgage-rates",
            "priority_score": 50.0, "editorial_significance": "medium",
            "date_published": "2026-09-27", "event": "Mortgage rates top 7%",
            "event_terms": ["mortgage rates"],
        })
        research_findings = copy.deepcopy(fresh)
        fetched: list[str] = []
        with patch.object(runtime, "DIGESTS_DIR", root), \
                patch.object(runtime, "ARTICLE_CACHE_DIR", root / "cache"), \
                patch.object(research, "FRESH_CAP", 1), \
                patch.object(runtime, "_call_omp_p", side_effect=_record_fetches(fetched)):
            queue = research.phase_3_rank(
                catalog.TOPICS["world"], fresh, run_dir, research_findings,
            )
            research.phase_4_fetch(catalog.TOPICS["world"], queue, run_dir)
        # The paywalled stories rank first, so they must be gone before the cap
        # or the one fresh slot is wasted on an unreadable page.
        check(fetched == ["https://wboi.org/mortgage-rates"], f"fetched={fetched!r}")
        artifact = json.loads((run_dir / "03-urls-ranked.json").read_text())
        check(
            sorted(item["url"] for item in artifact["paywall_dropped"])
            == sorted(url for url, *_ in paywalled),
            artifact["paywall_dropped"],
        )
        check(artifact["paywall_substituted"] == [], artifact["paywall_substituted"])


def test_hard_paywall_story_uses_alternate_source() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        run_dir = root / catalog.TOPICS["world"]["category"] / "2026-09-27"
        run_dir.mkdir(parents=True)
        wapo = "https://www.washingtonpost.com/national-security/2026/09/26/trump-rejects-iran-proposal/"
        story = {
            "title": "Trump rejects Iran's proposal to reopen Strait of Hormuz, restart peace talks",
            "url": wapo, "source_domain": "washingtonpost.com",
            "priority_score": 88.0, "editorial_significance": "high",
            "date_published": "2026-09-26",
            "event": "Trump rejected Iran's proposal to reopen the Strait of Hormuz and restart peace talks.",
            "event_terms": ["Strait of Hormuz", "Trump rejects Iran proposal"],
        }
        alternate = {
            "title": "Trump rejects Iran's proposal to reopen the Strait of Hormuz",
            "url": "https://www.aljazeera.com/news/2026/9/26/trump-rejects-iran-roadmap",
            "source_domain": "aljazeera.com", "date_published": "2026-09-26",
            "summary": "Trump rejected Iran's roadmap to reopen the strait.",
            "event": "Trump rejected Iran's proposal to reopen the Strait of Hormuz.",
            "event_terms": ["Strait of Hormuz", "Iran roadmap rejected"],
        }
        research_findings = [
            copy.deepcopy(story),
            # Same story on another paywalled host is never a substitute.
            {**alternate, "url": "https://www.theinformation.com/articles/hormuz"},
            # Shares a term but describes a different event.
            {"title": "US helps double oil volume exiting the Gulf",
             "url": "https://fortune.com/2026/09/26/gulf-oil-volume/",
             "event": "The US military is guiding tankers out of the Gulf.",
             "event_terms": ["Strait of Hormuz", "tanker escorts"]},
            alternate,
        ]
        fetched: list[str] = []
        with patch.object(runtime, "DIGESTS_DIR", root), \
                patch.object(runtime, "ARTICLE_CACHE_DIR", root / "cache"), \
                patch.object(runtime, "_call_omp_p", side_effect=_record_fetches(fetched)):
            queue = research.phase_3_rank(
                catalog.TOPICS["world"], [copy.deepcopy(story)], run_dir, research_findings,
            )
            research.phase_4_fetch(catalog.TOPICS["world"], queue, run_dir)
        check(fetched == [alternate["url"]], f"fetched={fetched!r}")
        check(len(queue) == 1, queue)
        kept = queue[0]
        check(kept["title"] == alternate["title"] and kept["source_domain"] == "aljazeera.com", kept)
        check(kept["priority_score"] == 88.0 and kept["editorial_significance"] == "high",
              f"story ranking fields lost: {kept!r}")
        check(kept["paywall_substituted_from"] == wapo, kept)
        artifact = json.loads((run_dir / "03-urls-ranked.json").read_text())
        check(artifact["paywall_dropped"] == [], artifact["paywall_dropped"])
        check(
            [(item["original_url"], item["alternate_url"]) for item in artifact["paywall_substituted"]]
            == [(wapo, alternate["url"])],
            artifact["paywall_substituted"],
        )


def test_hard_paywall_story_uses_same_event_attention_url() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        category = catalog.TOPICS["world"]["category"]
        run_dir = root / category / "2026-09-27"
        run_dir.mkdir(parents=True)
        covered = "https://www.apnews.com/article/noreaster-yesterday-coverage"
        (root / category / "2026-09-26").mkdir()
        (root / category / "2026-09-26" / "06-curated.json").write_text(json.dumps({
            "fresh": [{"url": covered}],
        }))
        wapo = "https://www.washingtonpost.com/weather/2026/09/26/major-noreaster/"
        ranked_elsewhere = "https://www.cbsnews.com/news/noreaster-east-coast-flooding/"
        chosen = "https://www.dw.com/en/powerful-noreaster-storm-batters-us/a-1234"
        story = {
            "title": "Major nor'easter batters East Coast with coastal flooding",
            "url": wapo, "source_domain": "washingtonpost.com", "priority_score": 90.0,
            "editorial_significance": "high", "date_published": "2026-09-26",
            "event": "A nor'easter brought coastal flooding and outages to the East Coast.",
            "event_terms": ["nor'easter", "coastal flooding"],
            "attention": {"status": "ok", "evidence": {"same_event_urls": [
                # Each earlier entry is unusable here: paywalled, already ranked on its
                # own, or covered by a previous day's edition.
                {"url": "https://www.theinformation.com/articles/noreaster", "domain": "theinformation.com",
                 "title": "Nor'easter", "source": "panel"},
                {"url": ranked_elsewhere, "domain": "cbsnews.com", "title": "Nor'easter floods coast",
                 "source": "gkg"},
                {"url": covered, "domain": "apnews.com", "title": "Powerful nor'easter", "source": "gkg"},
                {"url": chosen, "domain": "dw.com",
                 "title": "Powerful 'nor'easter' storm batters US", "source": "gkg"},
            ]}},
        }
        other = {
            "title": "Unrelated budget story", "url": ranked_elsewhere,
            "priority_score": 10.0, "editorial_significance": "low", "date_published": "2026-09-27",
        }
        fetched: list[str] = []
        with patch.object(runtime, "DIGESTS_DIR", root), \
                patch.object(runtime, "ARTICLE_CACHE_DIR", root / "cache"), \
                patch.object(runtime, "_call_omp_p", side_effect=_record_fetches(fetched)):
            queue = research.phase_3_rank(
                catalog.TOPICS["world"], [copy.deepcopy(story), other],
                run_dir, [copy.deepcopy(story), other],
            )
            research.phase_4_fetch(catalog.TOPICS["world"], queue, run_dir)
        check(sorted(fetched) == sorted([chosen, ranked_elsewhere]), f"fetched={fetched!r}")
        swapped = next(item for item in queue if item.get("paywall_substituted_from") == wapo)
        check(swapped["url"] == chosen and swapped["source_domain"] == "dw.com"
              and swapped["priority_score"] == 90.0, swapped)
        artifact = json.loads((run_dir / "03-urls-ranked.json").read_text())
        check(
            [(item["alternate_url"], item["alternate_origin"]) for item in artifact["paywall_substituted"]]
            == [(chosen, "attention:gkg")],
            artifact["paywall_substituted"],
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


def _fetches_by_host(urls: list[str], failing: tuple[str, ...] = (), raising: tuple[str, ...] = ()):
    """Fake fetch model: URLs on ``failing`` hosts report fetch_success=false,
    on ``raising`` hosts raise; every other URL fetches."""
    def fake_omp(prompt: str, **kwargs: object) -> str:
        url = prompt.split("Fetch this article: ", 1)[1].splitlines()[0]
        urls.append(url)
        if any(host in url for host in raising):
            raise RuntimeError(f"omp crashed on {url}")
        ok = not any(host in url for host in failing)
        return json.dumps({
            "title": f"Fetched {url}", "url": url, "date_confirmed": "2026-09-30",
            "author": "", "summary": "A detailed factual summary." if ok else "HTTP 403 Forbidden.",
            "key_details": ["detail"] if ok else [], "fetch_success": ok,
        })
    return fake_omp


FTC_STORY = {
    "title": "FTC opens investigation into OpenAI and Anthropic over consumer AI risks",
    "event": "The FTC opened an investigation into OpenAI and Anthropic over consumer AI risks.",
    "event_terms": ["FTC investigation", "OpenAI"],
    "source_verdict": "fresh",
}


def test_failed_fetch_uses_alternate_source() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        category = catalog.TOPICS["ai-tech"]["category"]
        run_dir = root / category / "2026-10-01"
        run_dir.mkdir(parents=True)
        covered = "https://www.reuters.com/technology/ftc-probe-openai-anthropic/"
        (root / category / "2026-09-30").mkdir()
        (root / category / "2026-09-30" / "06-curated.json").write_text(json.dumps({
            "fresh": [{"url": covered}],
        }))
        ap = "https://apnews.com/article/ftc-openai-anthropic"
        other_queue = "https://www.theverge.com/ai/chip-export-rules"
        research_alternate = "https://www.theguardian.com/us-news/2026/sep/30/ftc-openai-anthropic"
        attention_alternate = "https://siliconangle.com/2026/09/30/ftc-openai-anthropic/"
        story = {
            **FTC_STORY, "url": ap, "source_domain": "apnews.com", "priority_score": 95.0,
            "editorial_significance": "high", "date_published": "2026-09-30",
            "attention": {"status": "ok", "evidence": {"same_event_urls": [
                # Unusable: same outlet, covered yesterday, hard paywall, already queued.
                {"url": "https://apnews.com/article/ftc-probe-explainer", "domain": "apnews.com",
                 "title": "FTC probe explained", "source": "panel"},
                {"url": covered, "domain": "reuters.com", "title": "FTC probes AI labs", "source": "gkg"},
                {"url": "https://www.theinformation.com/articles/ftc-ai", "domain": "theinformation.com",
                 "title": "FTC AI probe", "source": "panel"},
                {"url": other_queue, "domain": "theverge.com", "title": "FTC", "source": "panel"},
                {"url": attention_alternate, "domain": "siliconangle.com",
                 "title": "FTC investigating OpenAI, Anthropic", "source": "panel"},
            ]}},
        }
        other = {
            "title": "US tightens chip export rules", "url": other_queue, "priority_score": 40.0,
            "editorial_significance": "medium", "date_published": "2026-09-30",
            "event": "The US tightened chip export rules.", "event_terms": ["chip export rules"],
        }
        guardian = {
            **FTC_STORY, "url": research_alternate, "source_domain": "theguardian.com",
            "title": "FTC opens investigation into OpenAI and Anthropic",
            "date_published": "2026-09-30", "summary": "US regulator probes AI labs.",
        }
        fetched: list[str] = []
        with patch.object(runtime, "DIGESTS_DIR", root), \
                patch.object(runtime, "ARTICLE_CACHE_DIR", root / "cache"), \
                patch.object(runtime, "_call_omp_p", side_effect=_fetches_by_host(fetched, failing=("apnews.com",))):
            queue = research.phase_3_rank(
                catalog.TOPICS["ai-tech"], [copy.deepcopy(story), copy.deepcopy(other)], run_dir,
                [copy.deepcopy(story), copy.deepcopy(other), guardian],
            )
            results = research.phase_4_fetch(catalog.TOPICS["ai-tech"], queue, run_dir)
        ranked = json.loads((run_dir / "03-urls-ranked.json").read_text())["phase_4_queue"]
        alternates = next(item for item in ranked if item["url"] == ap)["fetch_alternates"]
        check(
            [(entry["url"], entry["origin"]) for entry in alternates]
            == [(research_alternate, "research"), (attention_alternate, "attention:panel")],
            alternates,
        )
        check(sorted(fetched[:2]) == sorted([ap, other_queue]) and fetched[2:] == [research_alternate],
              f"fetched={fetched!r}")
        check([item.get("fetch_substituted_from") for item in results] == [ap, None], results)
        swapped = results[0]
        check(swapped["url"] == research_alternate and swapped["fetch_success"]
              and swapped["source_domain"] == "theguardian.com"
              and swapped["fetch_alternate_origin"] == "research", swapped)
        check(swapped["priority_score"] == 95.0 and swapped["editorial_significance"] == "high",
              f"ranking fields lost: {swapped!r}")
        check(all("fetch_alternates" not in item for item in results), results)


def test_failed_fetch_alternates_exhausted() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        alternates = [
            {"url": "https://raise.example/ftc", "title": "FTC A", "source_domain": "raise.example",
             "origin": "research", "overlap": 0.6},
            {"url": "https://blocked.example/ftc", "title": "FTC B", "source_domain": "blocked.example",
             "origin": "attention:panel", "overlap": None},
            {"url": "https://third.example/ftc", "title": "FTC C", "source_domain": "third.example",
             "origin": "attention:gkg", "overlap": None},
        ]
        queue = [{**FTC_STORY, "url": "https://apnews.com/article/ftc", "fetch_alternates": alternates}]
        fetched: list[str] = []
        with patch.object(runtime, "ARTICLE_CACHE_DIR", root / "cache"), \
                patch.object(runtime, "_call_omp_p", side_effect=_fetches_by_host(
                    fetched, failing=("apnews.com", "blocked.example"), raising=("raise.example",))):
            results = research.phase_4_fetch(catalog.TOPICS["ai-tech"], queue, root)
        alternate_calls = [url for url in fetched if "apnews.com" not in url]
        check(alternate_calls == [alternates[0]["url"], alternates[1]["url"]]
              and len(alternate_calls) <= research.FETCH_ALTERNATE_LIMIT,
              f"alternates retried or over limit: {fetched!r}")
        record = results[0]
        check(record["url"] == queue[0]["url"] and record["fetch_success"] is False, record)
        tried = record["fetch_alternates_tried"]
        check([entry["url"] for entry in tried] == [alternates[0]["url"], alternates[1]["url"]], tried)
        check("omp crashed" in tried[0]["reason"] and tried[1]["reason"] == "HTTP 403 Forbidden.", tried)


def test_failed_fetch_same_story_substitutes_once() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        cached_alternate = "https://www.theguardian.com/ftc"
        queue = [
            {**FTC_STORY, "url": "https://apnews.com/article/ftc", "priority_score": 90.0, "fetch_alternates": [
                {"url": cached_alternate, "title": "FTC probes AI labs", "source_domain": "theguardian.com",
                 "origin": "attention:panel", "overlap": None},
            ]},
            {**FTC_STORY, "url": "https://www.axios.com/ftc", "title": "FTC opens investigation into OpenAI",
             "fetch_alternates": [
                 {"url": "https://www.semafor.com/ftc", "title": "FTC probes", "source_domain": "semafor.com",
                  "origin": "attention:panel", "overlap": None},
             ]},
            {"title": "Chip rules", "url": "https://www.theverge.com/chips", "event_terms": ["chip rules"],
             "fetch_alternates": [
                 {"url": "https://www.wired.com/chips", "title": "Chip rules", "source_domain": "wired.com",
                  "origin": "research", "overlap": 0.5},
             ]},
        ]
        fetched: list[str] = []
        with patch.object(runtime, "ARTICLE_CACHE_DIR", root / "cache"), \
                patch.object(runtime, "_call_omp_p", side_effect=_fetches_by_host(
                    fetched, failing=("apnews.com", "axios.com"))):
            runtime._save_article_cache(cached_alternate, {
                "title": "FTC probes AI labs", "url": cached_alternate, "date_confirmed": "2026-09-30",
                "author": "", "summary": "Cached summary.", "key_details": [], "fetch_success": True,
            }, model=runtime.MODEL)
            results = research.phase_4_fetch(catalog.TOPICS["ai-tech"], queue, root)
        check(sorted(fetched) == sorted(item["url"] for item in queue),
              f"alternate fetched by model: {fetched!r}")
        first, second, third = results
        check(first["url"] == cached_alternate and first["cache_hit"] and first["summary"] == "Cached summary."
              and first["fetch_substituted_from"] == queue[0]["url"] and first["priority_score"] == 90.0, first)
        check(second["url"] == queue[1]["url"] and second["fetch_success"] is False
              and second["fetch_alternate_skipped"] == "same story already fetched"
              and "fetch_alternates_tried" not in second, second)
        check(third["url"] == queue[2]["url"] and "fetch_substituted_from" not in third, third)




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
        blocked_urls = contracts.load_cross_topic_urls(topic, run_dir)
        inputs = runtime.phase_inputs(
            "curate",
            topic=topic,
            upstream={
                "summaries": runtime.canonical_fingerprint(summaries),
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
            {"fresh": [cached_story]},
        )
        sidecar = run_dir / "referenced-urls.json"
        check(not sidecar.exists(), "sidecar unexpectedly preexisted")
        with patch(
            "daily_news.contracts.collect_referenced_urls",
            return_value=["example.com/source"],
        ):
            fresh = editorial.phase_6_curate(topic, summaries, run_dir)
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
            fresh = editorial.phase_6_curate(
                catalog.TOPICS["ai-tech"], [summary], run_dir
            )
        check(len(fresh) == 1, f"fresh story was not curated: {fresh}")
        check(fresh[0]["date_confirmed"] == fresh_day,
              f"date_confirmed not backfilled: {fresh[0].get('date_confirmed')!r}")
        final = json.loads((run_dir / "06c-editorial-final.json").read_text())
        check(
            any("date_confirmed" in warning for warning in final["validation_warnings"]),
            final["validation_warnings"],
        )


def editorial_fixture(issue_date: str | None = None) -> list[dict]:
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
    return candidates


def test_editorial_validation() -> None:
    candidates = editorial_fixture()
    first_id = candidates[0]["candidate_id"]
    second_id = candidates[1]["candidate_id"]
    proposal = {
        "selected_fresh": [
            {"candidate_id": first_id, "editorial_summary": "Approved summary."},
            {"candidate_id": "candidate-unknown", "editorial_summary": "Bad."},
            {"candidate_id": first_id, "editorial_summary": "Duplicate."},
            {"candidate_id": second_id, "editorial_summary": "Second story."},
        ],
    }
    validated, warnings = editorial.validate_editorial_proposal(proposal, candidates)
    check(
        [item["candidate_id"] for item in validated["selected_fresh"]] == [first_id, second_id],
        validated,
    )
    check(validated["selected_fresh"][0]["editorial_summary"] == "Approved summary.", validated)
    check(
        validated["balance_summary"]
        == "Validated selection: 2 fresh; 2 source domain(s); categories: Policy, Research.",
        validated["balance_summary"],
    )
    check(any("unknown candidate_id" in warning for warning in warnings), warnings)
    check(any("duplicate fresh selection" in warning for warning in warnings), warnings)

    empty, _ = editorial.validate_editorial_proposal({"selected_fresh": []}, candidates)
    check(
        empty["balance_summary"] == "Validated selection: no publishable fresh stories.",
        empty["balance_summary"],
    )


def test_editorial_critic_patch_contract() -> None:
    candidates = editorial_fixture()
    proposal = {
        "selected_fresh": [
            {"candidate_id": candidates[0]["candidate_id"]},
            {"candidate_id": candidates[1]["candidate_id"]},
        ],
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


def test_editorial_drops_stale_fresh_selection() -> None:
    """A stale Fresh pick never ships under Fresh."""
    candidates = editorial_fixture()
    stale_day = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%d")
    stale = copy.deepcopy(candidates[0])
    stale["date_published"] = stale_day
    stale["date_confirmed"] = stale_day
    candidates = [stale, copy.deepcopy(candidates[1])]
    proposal = {
        "selected_fresh": [
            {"candidate_id": candidate["candidate_id"]} for candidate in candidates
        ],
    }
    validated, warnings = editorial.validate_editorial_proposal(proposal, candidates)
    check(len(validated["selected_fresh"]) == 1, validated["selected_fresh"])
    check(
        validated["selected_fresh"][0]["candidate_id"] == candidates[1]["candidate_id"],
        validated["selected_fresh"],
    )
    check(any("stale fresh selection" in warning for warning in warnings), warnings)


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
        "gaps": "",
        "balance_summary": "",
    }
    validated, warnings = editorial.validate_editorial_proposal(proposal, candidates)
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
                "date_tag": "fresh",
                "source_verdict": "fresh",
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
            "gaps": "",
            "balance_summary": "",
        }
        fresh_proposal = {
            "selected_fresh": [{
                "candidate_id": fresh_c_id,
                "rank": 1,
                "editorial_summary": "Reviewed factual summary.",
                "selection_reason": "Only fresh-eligible candidate.",
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
            fresh = editorial.phase_6_curate(
                catalog.TOPICS["agentic-platform"], summaries, run_dir
            )
        check(len(fresh) == 1, f"expected 1 fresh after hint retry, got {fresh}")
        check(fresh[0]["url"] == "https://example.com/fresh-c", fresh)
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
            "date_tag": "fresh",
            "source_verdict": "fresh",
            "judge_verdict": "keep",
        }
        candidate_id = editorial.editorial_candidate_id(summary)
        proposal = {
            "selected_fresh": [{
                "candidate_id": candidate_id,
                "rank": 1,
                "editorial_summary": "Prices spiked 39%.",
                "selection_reason": "Consumer impact.",
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
            fresh = editorial.phase_6_curate(
                catalog.TOPICS["ai-hardware"], [summary], run_dir
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
        check(not responses, f"unused model responses: {responses!r}")


def test_critic_emptying_valid_fresh_still_fails_closed() -> None:
    """The 'removed every valid fresh story' guard must still fire when
    genuinely fresh candidates exist, so a broken critic cannot empty the
    digest; the validated proposal is retained."""
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        run_dir = root / "ai-tech" / "2026-08-12"
        run_dir.mkdir(parents=True)
        candidates = editorial_fixture(run_dir.name)
        summaries = [
            {key: value for key, value in candidate.items() if key != "candidate_id"}
            for candidate in candidates
        ]
        proposal = {
            "selected_fresh": [
                {"candidate_id": candidates[0]["candidate_id"], "rank": 1,
                 "editorial_summary": "Fresh story one.", "selection_reason": "Top."},
                {"candidate_id": candidates[1]["candidate_id"], "rank": 2,
                 "editorial_summary": "Fresh story two.", "selection_reason": "Second."},
            ],
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
            fresh = editorial.phase_6_curate(
                catalog.TOPICS["ai-tech"], summaries, run_dir
            )
        artifact = json.loads((run_dir / "06-curated.json").read_text())
        check(artifact["editorial"]["review_status"] == "unavailable", artifact)
        check(len(fresh) == 2, f"valid fresh stories were lost: {fresh}")


def test_phase_six_fallback_and_review_chain() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        run_dir = root / "ai-tech" / "2026-08-10"
        run_dir.mkdir(parents=True)
        candidates = editorial_fixture(run_dir.name)
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
            fresh = editorial.phase_6_curate(
                catalog.TOPICS["ai-tech"], summaries, run_dir
            )
        check(len(fresh) == 1, fresh)
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
        candidates = editorial_fixture(run_dir.name)
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
            fresh = editorial.phase_6_curate(
                catalog.TOPICS["ai-tech"], summaries, run_dir
            )
        check(len(fresh) == 1, fresh)
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
        candidates = editorial_fixture(run_dir.name)
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
            fresh = editorial.phase_6_curate(
                catalog.TOPICS["ai-tech"], summaries, run_dir
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
        candidates = editorial_fixture(run_dir.name)
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
            }],
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
            fresh = editorial.phase_6_curate(
                catalog.TOPICS["world"], summaries, run_dir
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
        candidates = editorial_fixture(run_dir.name)
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
        }
        responses = [
            json.dumps(proposal),
            json.dumps({"verdict": "reject", "changes": []}),
            json.dumps({"verdict": "reject", "changes": []}),
        ]
        with patch.object(runtime, "DIGESTS_DIR", root), patch.object(
            runtime, "_call_llm_proxy", side_effect=responses
        ):
            fresh = editorial.phase_6_curate(
                catalog.TOPICS["ai-tech"], summaries, run_dir
            )
        artifact = json.loads((run_dir / "06-curated.json").read_text())
        check(len(fresh) == 2, "critic rejection did not use source-ranked fallback")
        check(
            all(story.get("summary") != "Proposed summary." for story in fresh),
            "rejected proposal summary shipped",
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
        [{"summary": "A verified change occurred. Additional detail follows."}]
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
    )
    check(
        fallback == "Emergency crews moved residents to safer ground.",
        fallback,
    )
    initials = (
        "ElevenLabs is letting employees sell vested equity in a tender offer "
        "co-led by Wellington and T. Rowe Price. Flow Engineering raised a Series B."
    )
    check(
        copy_module.first_complete_sentence(initials)
        == initials.removesuffix(" Flow Engineering raised a Series B."),
        copy_module.first_complete_sentence(initials),
    )
    valid, reason = copy_module.validate_standfirst(
        "ElevenLabs runs a tender offer co-led by Wellington and T.", []
    )
    check(not valid and "abbreviation period" in reason, reason)
    clipped = editorial.clean_editorial_text("word " * 300, limit=80)
    check(clipped.endswith("word…") and len(clipped) <= 81, clipped)

    fresh = [{
        "title": "Safe <Title>",
        "url": "https://example.com/story?a=1&b=2",
        "category": "Research",
        "summary": "Verified & reviewed.",
    }]
    rendered = archive.render_digest_html(
        {"title": "Test Section"}, fresh, "Verified source-backed standfirst."
    )
    check("Safe &lt;Title&gt;" in rendered, "title was not escaped")
    check('href="https://example.com/story?a=1&amp;b=2"' in rendered,
          "URL was not safely rendered")
    check("{{FRESH_STORIES}}" not in rendered, "template placeholder remained")
    check("STORY BLOCK TEMPLATE" not in rendered, "template instructions leaked")


def test_phase_eight_publication_artifact() -> None:
    """Phase 8 publishes stable local data without private editorial fields."""
    with tempfile.TemporaryDirectory() as temporary:
        digest_dir = Path(temporary) / "world-digest"
        run_dir = digest_dir / f"{datetime.now():%Y-%m-%d}"
        digest_dir.mkdir(parents=True)
        run_dir.mkdir()
        (run_dir / "06-curated.json").write_text(json.dumps({"fresh": []}))
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
        second_story = {
            "title": "Second",
            "url": "https://example.com/b",
            "summary": "Second source-backed summary.",
            "editorial_significance": "high",
            "priority_score": 100.0,
            "selection_reason": "private editorial reasoning",
        }
        stories = [fresh_story, second_story]
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
                run_dir,
                digest_dir,
                fresh=stories,
            )
        check(not subprocess_run.called, "topic archive attempted to send email")
        check((digest_dir / f"{datetime.now():%Y-%m-%d}.html").exists(),
              "daily HTML archive missing")
        publication = json.loads(publication_path.read_text())
        check(publication["slug"] == "world", publication)
        check(publication["schema_version"] == 2, publication)
        check(publication["ranking_schema_version"] == catalog.RANKING_SCHEMA_VERSION, publication)
        check(publication["standfirst"] == standfirst, publication["standfirst"])
        check([story["url"] for story in publication["fresh"]]
              == [fresh_story["url"], second_story["url"]], publication)
        check("candidate_id" not in publication["fresh"][0], publication["fresh"][0])
        check("selection_reason" not in publication["fresh"][1], publication["fresh"][1])


def test_archive_index_urls_rejected() -> None:
    """Archive, pagination, and bare-date index pages are listings, not articles
    (digest-quality audit 2026-09-29: ai-hardware 09-28 published the
    TechPowerUp news archive index as a Fresh story). Every September URL the
    rule flags is one of these indexes; real article URLs stay eligible."""
    for listing in (
        "https://www.techpowerup.com/news-archive?month=0927",
        "https://github.blog/changelog/month/09-2026/",
        "https://www.climate.gov/news-features/category/news?page=3",
        "https://example.com/news/page/2/",
        "https://example.com/news/2026/09/28/",
        "https://www.theguardian.com/technology/2026/sep",
    ):
        check(contracts.is_listing_url(listing), f"index page not flagged: {listing}")
    for article in (
        "https://www.techpowerup.com/350844/nvidia-board-partners-receive-rtx-50-super-but-gddr7-pricing-holds-the-release-back",
        "https://github.blog/changelog/2026-09-22-opentelemetry-in-the-github-copilot-app/",
        "https://techcrunch.com/2026/09/28/spacexs-starship-rocket-reaches-orbit-for-the-first-time/",
        "https://www.gematsu.com/?p=1035212",
        "https://www.murata.com/en-us/news/event/other/2026/0928",
        "https://example.com/internet-archive-wins-appeal",
    ):
        check(not contracts.is_listing_url(article), f"article flagged as listing: {article}")


def test_listing_urls_rejected() -> None:
    """Section/date archive URLs (Guardian .../all) must never be selected into
    Fresh (digest-quality audit 2026-08-21: world-digest entries on 08-20 and
    08-21 were the same two Guardian .../all pages, which fetch as the section
    listing, not an article)."""
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
    proposal = {
        "selected_fresh": [
            {"candidate_id": candidates[0]["candidate_id"]},
        ],
    }
    validated, warnings = editorial.validate_editorial_proposal(
        proposal, candidates, set(),
    )
    check(validated["selected_fresh"] == [], validated["selected_fresh"])
    check(any("listing URL fresh selection" in warning for warning in warnings), warnings)


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
    into Fresh; they are not article hosts (digest-quality audit 2026-08-24:
    research invented assets.theregister.com links that 405'd)."""
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
    proposal = {
        "selected_fresh": [
            {"candidate_id": candidates[0]["candidate_id"]},
        ],
    }
    validated, warnings = editorial.validate_editorial_proposal(
        proposal, candidates, set(),
    )
    check(validated["selected_fresh"] == [], validated["selected_fresh"])
    check(any("asset-CDN fresh selection" in warning for warning in warnings), warnings)


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
        test_recent_coverage_ledger_blocks_other_section_repeats,
        test_phase_two_shared_url_findings_keep_their_own_metadata,
        test_phase_two_drops_unidentified_shared_url_finding,
        test_phase_two_restores_approvals_with_altered_urls,
        test_phase_two_keeps_bare_string_id_approvals,
        test_phase_two_records_unmatched_judge_approval,
        test_phase_two_rejects_id_url_conflict,
        test_phase_two_applies_judge_significance,
        test_runtime_preflight_fails_closed_on_missing_symbol,
        test_phase_inputs_include_actual_code_hashes,
        test_empty_phase_has_explicit_durable_outcome,
        test_attention_phase_persists_durable_observations,
        test_attention_phase_leaves_out_failed_sources_and_unadjudicated_stories,
        test_offline_attention_phase_never_reaches_the_network,
        test_phase_three_uses_product_priority,
        test_hard_paywall_story_never_reaches_fetch,
        test_hard_paywall_story_uses_alternate_source,
        test_hard_paywall_story_uses_same_event_attention_url,
        test_phase_four_concurrency_and_shared_cache,
        test_failed_fetch_uses_alternate_source,
        test_failed_fetch_alternates_exhausted,
        test_failed_fetch_same_story_substitutes_once,
        test_phase_five_backfills_date_confirmed_from_date_published,
        test_cached_curation_regenerates_referenced_url_sidecar,
        test_phase_six_backfills_missing_date_confirmed_on_curated_fresh,
        test_editorial_validation,
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
        test_phase_eight_publication_artifact,
        test_listing_urls_rejected,
        test_archive_index_urls_rejected,
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
