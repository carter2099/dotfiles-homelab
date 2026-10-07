"""Daily News workflow orchestration and executable-facing preflight."""
from __future__ import annotations

import math
import os
import signal
import sys
import time
import traceback
from copy import deepcopy
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
    paywall_domains = getattr(contracts, "HARD_PAYWALL_DOMAINS", None)
    if not isinstance(paywall_domains, frozenset) or not paywall_domains or not all(
        isinstance(domain, str) and domain == domain.strip().lower()
        and "." in domain and not domain.startswith("www.")
        for domain in paywall_domains
    ):
        errors.append(
            "HARD_PAYWALL_DOMAINS must be a non-empty frozenset of lowercase "
            f"bare domains (got {paywall_domains!r})"
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
                if "webSearchOrder" in (digest_config.get("providers") or {}):
                    errors.append("DIGEST_OMP_CONFIG providers.webSearchOrder is retired; use modelRoles.web")
                web_chain = [(digest_config.get("modelRoles") or {}).get("web")] + list(
                    ((digest_config.get("retry") or {}).get("fallbackChains") or {}).get("web") or []
                )
                if web_chain != list(runtime.DIGEST_WEB_SEARCH_CHAIN):
                    errors.append(
                        "DIGEST_OMP_CONFIG web search chain (modelRoles.web + retry.fallbackChains.web) "
                        f"must be {list(runtime.DIGEST_WEB_SEARCH_CHAIN)}"
                    )
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
) -> None:
    """Write the existing test-run report artifact."""
    report_path = run_dir / "test-report.md"
    model = runtime.MODEL_OVERRIDE or runtime.MODEL
    if runtime._omp_authenticated(model):
        provider = f"`{model.split('/', 1)[0]}` (omp login)"
    else:
        provider_info = runtime._detect_model_provider(model)
        provider = f"`{provider_info['provider']}` ({provider_info['chat_url']})"
    lines = [
        f"# Test Report: {topic['title']}",
        "",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"**Model:** `{model}`",
        f"**Provider:** {provider}",
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
        primary_research_model = runtime._effective_model(runtime.MODEL)
        # A --model run retries empty research on the configured primary instead.
        fallback_research_model = runtime.MODEL if runtime.MODEL_OVERRIDE else runtime.MODEL_FALLBACK
        research_model = primary_research_model
        research_fallback_reason: str | None = None

        def run_research(model: str) -> list[dict]:
            # The fallback covers only this research pass: Phases 2-9 always run
            # on the primary (or --model) again.
            with runtime.scoped_model_override(model):
                return research.phase_1_research(topic, run_dir)

        for stub_retry in range(2):
            if stub_retry > 0:
                research_model = fallback_research_model
                research_fallback_reason = "no-fresh-stories"
                print(f"  *** STUB RETRY: retrying research with fallback: {research_model}")
                archive.archive_stub_attempt(run_dir)

            started = phase_start("Phase 1: Research")
            runtime.check_search_health("pre-phase1")
            findings = run_research(research_model)
            if not findings and not runtime.TEST_MODE:
                if research_model == primary_research_model:
                    research_model = fallback_research_model
                    research_fallback_reason = "no-findings"
                else:
                    research_model = primary_research_model
                retry_delay = min(10 * (2 ** (retry_count + 1)), 120)
                print(f"  *** Backoff: waiting {retry_delay}s before research retry with {research_model}")
                time.sleep(retry_delay)
                archive.archive_stub_attempt(run_dir)
                findings = run_research(research_model)
                if findings:
                    print(f"  *** RETRY succeeded with research model: {research_model}")
                else:
                    runtime.check_search_health("post-fallback-retry")
            phase_done("Phase 1: Research", started)
            # Phase 2 edits findings in place; Phase 3 draws paywall alternates
            # from the research output as persisted in 01-research-raw.json.
            research_findings = deepcopy(findings)

            started = phase_start("Phase 2: Judge Research")
            fresh_findings = research.phase_2_judge_research(topic, findings, run_dir)
            phase_done("Phase 2: Judge Research", started)

            started = phase_start("Phase 2b: Observe Attention")
            fresh_findings = research.phase_2b_attention(topic, fresh_findings, run_dir)
            phase_done("Phase 2b: Observe Attention", started)

            started = phase_start("Phase 3: Rank URLs")
            phase_4_queue = research.phase_3_rank(
                topic, fresh_findings, run_dir, research_findings,
            )
            phase_done("Phase 3: Rank URLs", started)

            started = phase_start("Phase 4: Fetch & Summarize")
            summaries = research.phase_4_fetch(topic, phase_4_queue, run_dir)
            phase_done("Phase 4: Fetch & Summarize", started)

            started = phase_start("Phase 5: Judge Summaries")
            judged = research.phase_5_judge_summaries(topic, summaries, run_dir)
            phase_done("Phase 5: Judge Summaries", started)

            started = phase_start("Phase 6: Curate")
            fresh = editorial.phase_6_curate(topic, judged, run_dir)
            phase_done("Phase 6: Curate", started)

            if stub_retry == 0 and not fresh and not runtime.TEST_MODE:
                if runtime.MODEL_OVERRIDE:
                    print(f"  *** Stub detected; --model {runtime.MODEL_OVERRIDE} run, no fallback retry.")
                elif research_model == primary_research_model:
                    print("  *** Stub detected: 0 fresh stories after Phase 6; retrying research with fallback.")
                    continue
                else:
                    print(f"  *** Stub detected but research already ran on fallback ({research_model}).")
            break

        started = phase_start("Phase 7: Write Archive HTML")
        notice = ""
        if research._UPSTREAM_OUTAGE:
            notice = (
                "NOTE: Today’s research stage was degraded—the research API returned no fresh findings."
            )
        rendered_html = archive.phase_7_write(topic, fresh, run_dir, notice=notice)
        phase_done("Phase 7: Write Archive HTML", started)

        started = phase_start("Phase 8: Archive & Publish Artifact")
        archive.phase_8_archive(
            topic, rendered_html, run_dir, digest_dir,
            fresh=fresh, notice=notice, archive_daily=not dry_run,
        )
        phase_done("Phase 8: Archive & Publish Artifact", started)

        started = phase_start("Phase 9: Summary")
        archive.phase_9_summary(topic, fresh, run_dir, digest_dir)
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
        # run_all_digests.sh turns a trailing research_fallback= field into a
        # lifecycle WARN line; keep it last.
        record = (
            f"{now_utc} {category} duration={overall_elapsed:.0f}s model={model} "
            f"research_model={research_model}"
        )
        if research_fallback_reason:
            record += f" research_fallback={research_fallback_reason}"
        runtime.atomic_write_text(
            runs_log,
            (runs_log.read_text() if runs_log.exists() else "") + record + "\n",
        )
    if runtime.TEST_MODE:
        _write_test_report(run_dir, topic, category, phase_times, overall_elapsed,
                           len(findings), len(summaries), len(fresh))
    if not runtime.TEST_MODE and retry_state_path.exists():
        try:
            retry_state_path.unlink()
            print("  [done] Cleared retry state (successful run)")
        except OSError:
            pass
