#!/usr/bin/env python3
"""Analyze stored Daily News attention artifacts without making new requests."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any

from daily_news.attention import analyze_attention_artifact
from daily_news.catalog import TOPICS


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _duration(started_at: Any, completed_at: Any) -> float | None:
    started = _parse_timestamp(started_at)
    completed = _parse_timestamp(completed_at)
    if started is None or completed is None:
        return None
    return max(0.0, (completed - started).total_seconds())


def _state_timing(state_path: Path) -> tuple[float | None, float | None]:
    """Read authoritative attention and whole-run durations from SQLite state."""
    if not state_path.is_file():
        return None, None
    try:
        with sqlite3.connect(state_path) as connection:
            phase = connection.execute(
                """
                SELECT started_at, completed_at
                FROM phase_state
                WHERE phase = 'attention'
                ORDER BY attempt DESC, completed_at DESC
                LIMIT 1
                """
            ).fetchone()
            run = connection.execute(
                """
                SELECT created_at, completed_at
                FROM workflow_runs
                ORDER BY updated_at DESC
                LIMIT 1
                """
            ).fetchone()
    except sqlite3.Error:
        return None, None
    phase_seconds = _duration(*(phase or (None, None)))
    run_seconds = _duration(*(run or (None, None)))
    return phase_seconds, run_seconds


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _section_analysis(
    root: Path,
    category: str,
    issue_date: str,
    *,
    label: str | None = None,
) -> dict[str, Any]:
    run_dir = root / category / issue_date
    artifact_path = run_dir / "02b-attention.json"
    artifact = _read_json(artifact_path)
    display_category = label or category
    if artifact is None:
        return {
            "category": display_category,
            "status": "missing_or_invalid",
            "artifact": str(artifact_path),
        }

    phase_seconds, run_seconds = _state_timing(run_dir / "workflow-state.sqlite3")
    summary = analyze_attention_artifact(
        artifact,
        phase_elapsed_seconds=phase_seconds,
        run_elapsed_seconds=run_seconds,
    )
    return {
        "category": display_category,
        "status": "ok",
        "artifact": str(artifact_path),
        **summary,
    }


def _sum_metric(sections: list[dict[str, Any]], *path: str) -> float:
    total = 0.0
    for section in sections:
        value: Any = section
        for part in path:
            if not isinstance(value, dict):
                value = None
                break
            value = value.get(part)
        if isinstance(value, (int, float)):
            total += float(value)
    return total


def analyze(root: Path, issue_date: str) -> dict[str, Any]:
    sections = [
        _section_analysis(
            root,
            topic["category"],
            issue_date,
            label=topic_key,
        )
        for topic_key, topic in TOPICS.items()
    ]
    valid = [section for section in sections if section.get("status") == "ok"]
    candidates = _sum_metric(valid, "coverage", "candidates")
    available = _sum_metric(valid, "coverage", "available")
    unavailable = _sum_metric(valid, "coverage", "unavailable")
    matched = sum(
        int((section.get("coverage", {}).get("status_counts") or {}).get("ok", 0)) for section in valid
    )
    jev_requests = _sum_metric(valid, "coverage", "jev", "requests")
    jev_tokens = _sum_metric(valid, "coverage", "jev", "input_tokens")
    changed = _sum_metric(valid, "priority", "recorded", "score_changed")
    promoted = _sum_metric(valid, "priority", "recorded", "promoted")
    demoted = _sum_metric(valid, "priority", "recorded", "demoted")
    attention_seconds = _sum_metric(valid, "runtime", "attention_stage_seconds")
    total_run_seconds = _sum_metric(valid, "runtime", "total_run_seconds")
    other_phase_seconds = max(0.0, total_run_seconds - attention_seconds)

    aggregate = {
        "sections": len(valid),
        "candidates": int(candidates),
        "available": int(available),
        "unavailable": int(unavailable),
        "coverage_rate": round(available / candidates, 3) if candidates else 0.0,
        "matched": matched,
        "jev_requests": int(jev_requests),
        "jev_input_tokens": int(jev_tokens),
        "priority_vs_editorial": {
            "score_changed": int(changed),
            "promoted": int(promoted),
            "demoted": int(demoted),
        },
        "runtime_attribution": {
            "attention_stage_seconds": round(attention_seconds, 3),
            "other_phase_seconds": round(other_phase_seconds, 3),
            "total_run_seconds": round(total_run_seconds, 3),
            "attention_share": round(
                attention_seconds / total_run_seconds, 3
            ) if total_run_seconds > 0 else 0.0,
            "basis": "workflow-state SQLite phase timestamps",
        },
    }
    return {
        "schema_version": 3,
        "issue_date": issue_date,
        "source": "stored 02b-attention.json and workflow-state.sqlite3 artifacts",
        "sections": sections,
        "aggregate": aggregate,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare applied priorities with an editorial-only baseline"
    )
    parser.add_argument(
        "issue_date",
        nargs="?",
        default=datetime.now(timezone.utc).date().isoformat(),
        help="UTC edition date (default: today)",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.home() / "digests",
        help="Daily News artifact root (default: ~/digests)",
    )
    args = parser.parse_args(argv)
    print(json.dumps(analyze(args.root, args.issue_date), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
