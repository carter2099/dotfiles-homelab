#!/usr/bin/env python3
"""Validate manual golf-run judgments and calculate model summaries."""

from __future__ import annotations

import csv
import json
import statistics
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ANALYSIS_PATH = ROOT / "golf-analysis.json"
SCORES_PATH = ROOT / "golf-scores.json"
SCORES_CSV_PATH = ROOT / "golf-run-results.csv"
CRITERIA = ("tool_calling", "accuracy", "readability")


def main() -> None:
    analysis = json.loads(ANALYSIS_PATH.read_text())
    scores = json.loads(SCORES_PATH.read_text())
    expected = {(run["model"], run["run"]) for run in analysis["runs"]}
    analysis_by_key = {
        (run["model"], run["run"]): run for run in analysis["runs"]
    }
    reviews = scores["reviews"]
    actual = {(review["model"], review["run"]) for review in reviews}
    if len(actual) != len(reviews):
        raise SystemExit("duplicate model/run score")
    if actual != expected:
        raise SystemExit(
            f"score coverage mismatch: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )

    by_model: dict[str, list[dict]] = defaultdict(list)
    for review in reviews:
        for criterion in CRITERIA:
            value = review["scores"][criterion]
            if not isinstance(value, int) or not 0 <= value <= 5:
                raise SystemExit(
                    f"invalid {criterion} score for {review['model']} run {review['run']}: {value}"
                )
        review["overall"] = statistics.mean(
            review["scores"][criterion] for criterion in CRITERIA
        )
        run = analysis_by_key[(review["model"], review["run"])]
        review["telemetry"] = {
            "duration_seconds": run["duration_seconds"],
            "model_turn_count": run["model_turn_count"],
            "initial_ttft_seconds": run["initial_ttft_seconds"],
            "mean_turn_ttft_seconds": run["mean_ttft_seconds"],
            "mean_generation_tokens_per_second": run[
                "mean_generation_tokens_per_second"
            ],
            "tool_call_count": run["tool_call_count"],
            "tool_errors": run["tool_errors"],
            "advisor_severity_counts": run["advisor_severity_counts"],
        }
        by_model[review["model"]].append(review)

    summary = {}
    analysis_summary = analysis["summary"]
    for model, model_reviews in by_model.items():
        model_runs = [
            analysis_by_key[(review["model"], review["run"])]
            for review in model_reviews
        ]
        summary[model] = {
            "runs": len(model_reviews),
            "tool_calling_mean": statistics.mean(
                review["scores"]["tool_calling"] for review in model_reviews
            ),
            "accuracy_mean": statistics.mean(
                review["scores"]["accuracy"] for review in model_reviews
            ),
            "readability_mean": statistics.mean(
                review["scores"]["readability"] for review in model_reviews
            ),
            "overall_mean": statistics.mean(
                review["overall"] for review in model_reviews
            ),
            "per_run_overall": [review["overall"] for review in model_reviews],
            "runs_with_correct_date_window": sum(
                review["scores"]["accuracy"] > 0 for review in model_reviews
            ),
            "runs_with_accuracy_at_least_4": sum(
                review["scores"]["accuracy"] >= 4 for review in model_reviews
            ),
            "runs_at_omp_time_limit": sum(
                run["duration_seconds"] >= 600 for run in model_runs
            ),
            "empty_final_answers": sum(
                not run["final_answer"].strip() for run in model_runs
            ),
            "mean_duration_seconds": analysis_summary[model]["mean_duration_seconds"],
            "mean_initial_ttft_seconds": analysis_summary[model][
                "mean_initial_ttft_seconds"
            ],
            "mean_turn_ttft_seconds": analysis_summary[model][
                "mean_turn_ttft_seconds"
            ],
            "mean_generation_tokens_per_second": analysis_summary[model][
                "mean_generation_tokens_per_second"
            ],
            "total_tool_calls": analysis_summary[model]["total_tool_calls"],
            "runs_with_tools": analysis_summary[model]["runs_with_tools"],
            "total_tool_errors": analysis_summary[model]["total_tool_errors"],
            "advisor_severity_counts": analysis_summary[model][
                "advisor_severity_counts"
            ],
        }
    scores["summary"] = summary
    SCORES_PATH.write_text(json.dumps(scores, indent=2) + "\n")
    fieldnames = [
        "model",
        "run",
        "tool_calling_score",
        "accuracy_score",
        "readability_score",
        "overall_score",
        "duration_seconds",
        "model_turn_count",
        "initial_ttft_seconds",
        "mean_turn_ttft_seconds",
        "mean_generation_tokens_per_second",
        "tool_call_count",
        "tool_errors",
        "advisor_severity_counts",
        "notes",
    ]
    with SCORES_CSV_PATH.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for review in reviews:
            telemetry = review["telemetry"]
            writer.writerow(
                {
                    "model": review["model"],
                    "run": review["run"],
                    "tool_calling_score": review["scores"]["tool_calling"],
                    "accuracy_score": review["scores"]["accuracy"],
                    "readability_score": review["scores"]["readability"],
                    "overall_score": review["overall"],
                    "duration_seconds": telemetry["duration_seconds"],
                    "model_turn_count": telemetry["model_turn_count"],
                    "initial_ttft_seconds": telemetry["initial_ttft_seconds"],
                    "mean_turn_ttft_seconds": telemetry["mean_turn_ttft_seconds"],
                    "mean_generation_tokens_per_second": telemetry[
                        "mean_generation_tokens_per_second"
                    ],
                    "tool_call_count": telemetry["tool_call_count"],
                    "tool_errors": telemetry["tool_errors"],
                    "advisor_severity_counts": json.dumps(
                        telemetry["advisor_severity_counts"], separators=(",", ":")
                    ),
                    "notes": review["notes"],
                }
            )
    print(f"validated {len(reviews)} scores; wrote {SCORES_PATH}")


if __name__ == "__main__":
    main()
