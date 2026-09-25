"""Daily News workflow orchestration and executable-facing preflight."""
from __future__ import annotations

import math
import os
import signal
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - preflight reports dependency
    yaml = None

from workflow_state import WorkflowState

from . import archive, attention, catalog, contracts, editorial, research, runtime
from .catalog import TOPICS

def validate_runtime_contract() -> None:
    """Fail before research when a load-bearing catalog/runtime symbol is missing."""
    errors: list[str] = []
    contract_values = {
        "CROSS_DAY_DEDUP_DAYS": getattr(catalog, "CROSS_DAY_DEDUP_DAYS", None),
        "REFERENCED_URLS_SCHEMA_VERSION": getattr(catalog, "REFERENCED_URLS_SCHEMA_VERSION", None),
        "RANKING_SCHEMA_VERSION": getattr(catalog, "RANKING_SCHEMA_VERSION", None),
        "ATTENTION_SCHEMA_VERSION": getattr(attention, "SCHEMA_VERSION", None),
        "ATTENTION_STAGE_BUDGET_SECONDS": getattr(
            attention, "ATTENTION_STAGE_BUDGET_SECONDS", None
        ),
        "MAX_ATTENTION_STAGE_BUDGET_SECONDS": getattr(
            attention, "MAX_ATTENTION_STAGE_BUDGET_SECONDS", None
        ),
    }
    for name, minimum in (
        ("CROSS_DAY_DEDUP_DAYS", 1),
        ("REFERENCED_URLS_SCHEMA_VERSION", 1),
        ("RANKING_SCHEMA_VERSION", 1),
        ("ATTENTION_SCHEMA_VERSION", 1),
    ):
        value = contract_values[name]
        if not isinstance(value, int) or value < minimum:
            errors.append(f"{name} must be an integer >= {minimum} (got {value!r})")
    budget = contract_values["ATTENTION_STAGE_BUDGET_SECONDS"]
    budget_ceiling = contract_values["MAX_ATTENTION_STAGE_BUDGET_SECONDS"]
    if (
        isinstance(budget, bool)
        or not isinstance(budget, (int, float))
        or isinstance(budget_ceiling, bool)
        or not isinstance(budget_ceiling, (int, float))
        or not math.isfinite(float(budget))
        or not math.isfinite(float(budget_ceiling))
        or budget_ceiling <= 0
        or budget < 0
        or budget > budget_ceiling
    ):
        errors.append(
            "ATTENTION_STAGE_BUDGET_SECONDS must be a number between 0 and "
            f"MAX_ATTENTION_STAGE_BUDGET_SECONDS (got {budget!r}, ceiling "
            f"{budget_ceiling!r})"
        )
    if len(TOPICS) != 5:
        errors.append(f"TOPICS must contain five sections (got {len(TOPICS)})")
    for key, config in TOPICS.items():
        missing = {
            field for field in ("category", "web_slug", "web_title", "research_angles")
            if field not in config
        }
        if missing:
            errors.append(f"{key} missing fields: {', '.join(sorted(missing))}")
    for name, owner in (
        ("load_recent_coverage_ledger", contracts),
        ("tracker_display_source", contracts),
        ("load_cross_topic_urls", contracts),
        ("phase_2_judge_research", research),
        ("phase_2b_attention", research),
    ):
        if not callable(getattr(owner, name, None)):
            errors.append(f"{name} is missing or not callable")
    for name, path in (
        ("TEMPLATE_PATH", runtime.TEMPLATE_PATH),
        ("DIGEST_OMP_SANDBOX", runtime.DIGEST_OMP_SANDBOX),
        ("DIGEST_OMP_CONFIG", runtime.DIGEST_OMP_CONFIG),
    ):
        if not path.is_file():
            errors.append(f"{name} is missing or not a file: {path}")
    if runtime.DIGEST_OMP_CONFIG.is_file():
        if yaml is None:
            errors.append("PyYAML is required to validate DIGEST_OMP_CONFIG")
        else:
            try:
                digest_config = yaml.safe_load(runtime.DIGEST_OMP_CONFIG.read_text()) or {}
                provider_order = digest_config.get("providers", {}).get("webSearchOrder", [])
                if provider_order[:2] != ["codex", "searxng"]:
                    errors.append("DIGEST_OMP_CONFIG providers.webSearchOrder must start with ['codex', 'searxng']")
                searxng = digest_config.get("searxng", {})
                if searxng.get("endpoint") != runtime.SEARXNG_URL:
                    errors.append(f"DIGEST_OMP_CONFIG searxng.endpoint must be {runtime.SEARXNG_URL}")
                categories = {item.strip() for item in str(searxng.get("categories", "")).split(",")}
                if not {"general", "news"}.issubset(categories):
                    errors.append("DIGEST_OMP_CONFIG searxng.categories must include general and news")
                if searxng.get("language") not in (None, ""):
                    errors.append("DIGEST_OMP_CONFIG searxng.language must remain unset")
            except Exception as error:
                errors.append(f"DIGEST_OMP_CONFIG is invalid YAML: {error}")
    if errors:
        raise RuntimeError("Daily News preflight failed: " + "; ".join(errors))


def _write_test_report(
    run_dir: Path,
    topic: dict[str, Any],
    category: str,
    phase_times: dict[str, float],
    total_time: float,
    n_findings: int,
    n_summaries: int,
    n_fresh: int,
    n_ongoing: int,
) -> None:
    """Write the existing test-run report artifact."""
    report_path = run_dir / "test-report.md"
    model = runtime.MODEL_OVERRIDE or runtime.MODEL
    provider_info = runtime._detect_model_provider(model)
    lines = [
        f"# Test Report: {topic['title']}",
        "",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Model:** `{model}`",
        f"**Provider:** `{provider_info['provider']}` ({provider_info['chat_url']})",
        f"**Label:** `{runtime.TEST_LABEL or 'N/A'}`",
        "",
        "## Timing",
        "",
        "| Phase | Time (s) | Time (min) |",
        "|-------|----------|------------|",
    ]
    for name, seconds in phase_times.items():
        lines.append(f"| {name} | {seconds:.0f} | {seconds / 60:.1f} |")
    lines.append(f"| **Total** | **{total_time:.0f}** | **{total_time / 60:.1f}** |")
    lines += [
        "",
        "## Throughput",
        "",
        "| Metric | Count |",
        "|--------|-------|",
        f"| Phase 1 findings | {n_findings} |",
        f"| Phase 4 summaries | {n_summaries} |",
        f"| Final fresh stories | {n_fresh} |",
        f"| Final ongoing stories | {n_ongoing} |",
        "",
        "## Artifacts",
        "",
    ]
    for artifact in sorted(run_dir.iterdir()):
        if artifact.is_file():
            lines.append(f"- `{artifact.name}` ({artifact.stat().st_size / 1024:.1f} KB)")
    runtime.atomic_write_text(report_path, "\n".join(lines) + "\n")
    print(f"  [test] Report written → {report_path}")


def run_digest(category: str, dry_run: bool = False) -> None:
    """Run all nine Daily News phases for one topic."""
    validate_runtime_contract()
    if category not in TOPICS:
        print(f"Unknown topic: {category}")
        print(f"Available: {', '.join(TOPICS)}")
        raise SystemExit(1)

    topic = TOPICS[category]
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if runtime.TEST_MODE:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        label = (runtime.TEST_LABEL or "test") + "-" + timestamp
        test_root = runtime.TEST_ROOT or runtime.DIGESTS_DIR / "test"
        digest_dir = test_root / topic["category"]
        run_dir = digest_dir / label
        prod_sif = runtime.DIGESTS_DIR / topic["category"] / "stories-in-flight.json"
        if prod_sif.exists():
            digest_dir.mkdir(parents=True, exist_ok=True)
            runtime.atomic_write_text(digest_dir / "stories-in-flight.json", prod_sif.read_text())
            print(f"  [test] Copied stories-in-flight from prod ({prod_sif})")
    else:
        digest_dir = runtime.DIGESTS_DIR / topic["category"]
        run_dir = digest_dir / today_str
    run_dir.mkdir(parents=True, exist_ok=True)

    model_note = f" [model: {runtime.MODEL_OVERRIDE}]" if runtime.MODEL_OVERRIDE else ""
    if not runtime.TEST_MODE:
        def _interrupt_handler(signum: int, _frame: Any) -> None:
            """Record an interrupted final state instead of leaving 'running'."""
            try:
                WorkflowState(
                    run_dir, runtime.WORKFLOW_NAME, run_id=run_dir.name
                ).abort_interrupted_phases(
                    error=f"interrupted by signal {signum}"
                )
            except BaseException as error:  # never mask the original signal
                print(f"  [interrupt] could not record aborted state: {error}")
            signal.signal(signum, signal.SIG_DFL)
            os.kill(os.getpid(), signum)

        for _signal in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(_signal, _interrupt_handler)
    print(f"\n{'=' * 60}")
    print(f"  {topic['title']} — {today_str}{model_note}")
    print(f"  Run dir: {run_dir}")
    if runtime.TEST_MODE:
        print("  *** TEST MODE — output isolated, no email ***")
    print(f"{'=' * 60}\n")

    overall_start = time.time()
    phase_times: dict[str, float] = {}

    def phase_start(name: str) -> float:
        started = time.time()
        print(f"\n── {name} ──")
        return started

    def phase_done(name: str, started: float) -> None:
        elapsed = time.time() - started
        phase_times[name] = elapsed
        print(f"  [{elapsed:.0f}s] {name}")

    setup_started = phase_start("Phase 0: Setup")
    # Test runs copy the production tracker; its evidence runs live there too.
    stories_in_flight = archive.load_and_prune_stories_in_flight(
        digest_dir,
        evidence_dir=(
            runtime.DIGESTS_DIR / topic["category"] if runtime.TEST_MODE else None
        ),
    )
    active_stories = [story for story in stories_in_flight.get("stories", []) if story.get("status") == "active"]
    print(f"  Stories in flight: {len(active_stories)} active")
    if not runtime.TEST_MODE:
        archive.cleanup_old_artifacts(digest_dir)
    phase_done("Phase 0: Setup", setup_started)

    retry_state_path = digest_dir / ".retry-state.json"
    retry_count = 0
    try:
        if not runtime.TEST_MODE and retry_state_path.exists():
            try:
                retry_state = json.loads(retry_state_path.read_text())
                retry_count = int(retry_state.get("retry_count", 0))
                delay = min(10 * (2 ** retry_count), 600)
                if retry_count > 0:
                    print(f"  *** Cross-process backoff: attempt #{retry_count + 1}, waiting {delay}s")
                    time.sleep(delay)
            except (json.JSONDecodeError, ValueError, OSError):
                pass

        findings: list[dict] = []
        summaries: list[dict] = []
        fresh: list[dict] = []
        ongoing: list[dict] = []
        for stub_retry in range(2):
            if stub_retry > 0:
                if runtime.MODEL_OVERRIDE:
                    print(f"  *** Both primary and fallback models already exhausted ({runtime.MODEL_OVERRIDE}).")
                    break
                runtime.MODEL_OVERRIDE = runtime.MODEL_FALLBACK
                print(f"  *** STUB RETRY: retrying with fallback: {runtime.MODEL_OVERRIDE}")
                archive.archive_stub_attempt(run_dir)

            started = phase_start("Phase 1: Research")
            runtime.check_search_health("pre-phase1")
            findings = research.phase_1_research(topic, run_dir, stories_in_flight)
            if not findings and not runtime.TEST_MODE:
                fallback = runtime.MODEL if runtime.MODEL_OVERRIDE else runtime.MODEL_FALLBACK
                retry_delay = min(10 * (2 ** (retry_count + 1)), 120)
                print(f"  *** Backoff: waiting {retry_delay}s before fallback retry")
                time.sleep(retry_delay)
                runtime.MODEL_OVERRIDE = fallback
                archive.archive_stub_attempt(run_dir)
                findings = research.phase_1_research(topic, run_dir, stories_in_flight)
                if findings:
                    print(f"  *** RETRY succeeded with fallback model: {fallback}")
                else:
                    runtime.check_search_health("post-fallback-retry")
            phase_done("Phase 1: Research", started)

            started = phase_start("Phase 2: Judge Research")
            fresh_findings, ongoing_findings = research.phase_2_judge_research(
                topic, findings, run_dir, stories_in_flight,
            )
            phase_done("Phase 2: Judge Research", started)

            started = phase_start("Phase 2b: Observe Attention")
            fresh_findings, ongoing_findings = research.phase_2b_attention(
                topic, fresh_findings, ongoing_findings, run_dir,
            )
            phase_done("Phase 2b: Observe Attention", started)

            started = phase_start("Phase 3: Rank URLs")
            phase_4_queue, sif_candidates = research.phase_3_rank(
                topic, fresh_findings, ongoing_findings, stories_in_flight, run_dir,
            )
            phase_done("Phase 3: Rank URLs", started)

            started = phase_start("Phase 4: Fetch & Summarize")
            summaries = research.phase_4_fetch(topic, phase_4_queue, run_dir)
            phase_done("Phase 4: Fetch & Summarize", started)

            started = phase_start("Phase 5: Judge Summaries")
            judged = research.phase_5_judge_summaries(topic, summaries, run_dir)
            phase_done("Phase 5: Judge Summaries", started)

            started = phase_start("Phase 6: Curate")
            fresh, stories_in_flight, ongoing = editorial.phase_6_curate(
                topic, judged, sif_candidates, stories_in_flight, run_dir,
            )
            phase_done("Phase 6: Curate", started)
            if stories_in_flight.get("stories"):
                kept, re_cooled, re_pruned = archive.prune_and_cool_stories(stories_in_flight["stories"])
                if re_cooled or re_pruned:
                    print(f"  [post-6] Re-cooled {re_cooled} stale, re-pruned {re_pruned} expired stories")
                    stories_in_flight["stories"] = kept

            if stub_retry == 0 and not fresh and not runtime.TEST_MODE:
                if not runtime.MODEL_OVERRIDE:
                    print("  *** Stub detected: 0 fresh stories after Phase 6; retrying with fallback.")
                    continue
                print(f"  *** Stub detected but already on fallback ({runtime.MODEL_OVERRIDE}).")
            break

        started = phase_start("Phase 7: Write Archive HTML")
        notice = ""
        if research._UPSTREAM_OUTAGE:
            notice = (
                "NOTE: Today’s research stage was degraded—the research API returned no fresh findings. "
                "The stories below are ongoing coverage carried over from previous days."
            )
        rendered_html = archive.phase_7_write(topic, fresh, ongoing, run_dir, notice=notice)
        phase_done("Phase 7: Write Archive HTML", started)

        started = phase_start("Phase 8: Archive & Publish Artifact")
        archive.phase_8_archive(
            topic, rendered_html, stories_in_flight, run_dir, digest_dir,
            fresh=fresh, ongoing=ongoing, notice=notice, archive_daily=not dry_run,
        )
        phase_done("Phase 8: Archive & Publish Artifact", started)

        started = phase_start("Phase 9: Summary")
        archive.phase_9_summary(topic, fresh, ongoing, run_dir, digest_dir)
        phase_done("Phase 9: Summary", started)
        archive.cleanup_stub_attempts(run_dir)
    except Exception as error:
        if not runtime.TEST_MODE:
            try:
                retry_state = json.loads(retry_state_path.read_text()) if retry_state_path.exists() else {}
                retry_state["retry_count"] = int(retry_state.get("retry_count", 0)) + 1
                retry_state["last_failure"] = datetime.now(timezone.utc).isoformat()
                runtime.atomic_write_json(retry_state_path, retry_state)
            except Exception:
                pass
        print(f"\n  FATAL: {error}")
        traceback.print_exc()
        raise

    overall_elapsed = time.time() - overall_start
    print(f"\n{'=' * 60}")
    print(f"  Digest complete in {overall_elapsed:.0f}s ({overall_elapsed / 60:.1f} min)")
    print(f"{'=' * 60}\n")
    if not runtime.TEST_MODE:
        model = runtime.MODEL_OVERRIDE or runtime.MODEL
        runs_log = digest_dir / ".runs.log"
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        runtime.atomic_write_text(
            runs_log,
            runs_log.read_text() + f"{now_utc} {category} duration={overall_elapsed:.0f}s model={model}\n"
            if runs_log.exists() else f"{now_utc} {category} duration={overall_elapsed:.0f}s model={model}\n",
        )
    if runtime.TEST_MODE:
        _write_test_report(run_dir, topic, category, phase_times, overall_elapsed,
                           len(findings), len(summaries), len(fresh), len(ongoing))
    if not runtime.TEST_MODE and retry_state_path.exists():
        try:
            retry_state_path.unlink()
            print("  [done] Cleared retry state (successful run)")
        except OSError:
            pass
