#!/usr/bin/env python3
"""Compile the benchmark artifacts into one reviewable result document."""

from __future__ import annotations

import csv
import json
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUTPUT_PATH = ROOT / "research-summary.json"
OUTPUT_CSV_PATH = ROOT / "finalist-results.csv"


def load_json(name: str) -> dict:
    return json.loads((ROOT / name).read_text())


def mean(values: list[float | None]) -> float | None:
    present = [value for value in values if value is not None]
    return statistics.mean(present) if present else None


def main() -> None:
    with (ROOT / "quant-context-matrix.csv").open(newline="") as handle:
        matrix_rows = list(csv.DictReader(handle))
    selections = load_json("final-selections.json")
    api = load_json("api-performance.json")
    failures = load_json("observed-failures.json")
    weather = load_json("weather-source-truth.json")

    matrix_by_model: dict[str, list[dict]] = defaultdict(list)
    for row in matrix_rows:
        matrix_by_model[row["model"]].append(row)

    matrix_summary = {}
    for model, rows in matrix_by_model.items():
        matrix_summary[model] = {
            "rows": len(rows),
            "statuses": dict(Counter(row["status"] for row in rows)),
            "quants": sorted({row["quant"] for row in rows}),
            "contexts": sorted({int(row["context_tokens"]) for row in rows}),
            "kv_types": sorted({row["kv_type"] for row in rows}),
            "q4_kv_speed_rows": [
                {
                    "quant": row["quant"],
                    "context_tokens": int(row["context_tokens"]),
                    "gpu_layers": int(row["gpu_layers"]) if row["gpu_layers"].isdigit() else row["gpu_layers"],
                    "cpu_moe_layers": int(row["cpu_moe_layers"]) if row["cpu_moe_layers"].isdigit() else None,
                    "prompt_tokens_per_second": float(row["prompt_tokens_per_second"]),
                    "generation_tokens_per_second": float(row["generation_tokens_per_second"]),
                }
                for row in rows
                if row["status"] == "completed" and row["kv_type"] == "q4_0"
            ],
        }

    api_by_key = {(item.get("tag"), item["model"]): item for item in api["models"]}
    finalists = []
    for selection in selections["models"]:
        model_id = selection["model_id"]
        final = api_by_key.get(("final", model_id))
        if final is None and model_id == "qwen-3.6-35b-q8-fast":
            final = api_by_key.get(("final", "qwen-3.6-35b-q8"))
        cold = api_by_key.get(("cold-fixed", model_id))
        if cold is None and model_id == "qwen-3.6-35b-q8-fast":
            cold = api_by_key.get(("cold-fixed", "qwen-3.6-35b-q8"))
        concurrent = api_by_key.get(("np2", model_id))
        if concurrent is None and model_id == "qwen-3.6-35b-q8-fast":
            concurrent = api_by_key.get(("np2", "qwen-3.6-35b-q8"))

        record = dict(selection)
        if final:
            sequential = final["sequential"]
            draft_tokens = sum(
                (run.get("timings") or {}).get("draft_n", 0) for run in sequential
            )
            accepted_draft_tokens = sum(
                (run.get("timings") or {}).get("draft_n_accepted", 0)
                for run in sequential
            )
            record["final_api"] = {
                "runs": len(sequential),
                "mean_warm_ttft_seconds": mean([run["ttft_seconds"] for run in sequential]),
                "min_warm_ttft_seconds": min(run["ttft_seconds"] for run in sequential),
                "max_warm_ttft_seconds": max(run["ttft_seconds"] for run in sequential),
                "mean_generation_tokens_per_second": mean(
                    [run["client_tokens_per_second"] for run in sequential]
                ),
                "min_generation_tokens_per_second": min(
                    run["client_tokens_per_second"] for run in sequential
                ),
                "max_generation_tokens_per_second": max(
                    run["client_tokens_per_second"] for run in sequential
                ),
                "draft_tokens": draft_tokens,
                "accepted_draft_tokens": accepted_draft_tokens,
                "draft_acceptance_rate": (
                    accepted_draft_tokens / draft_tokens if draft_tokens else None
                ),
            }
        if cold:
            record["model_swap"] = {
                "ttft_seconds": cold["cold_request"]["ttft_seconds"],
                "elapsed_seconds": cold["cold_request"]["elapsed_seconds"],
            }
        if concurrent:
            requests = concurrent["concurrency"]["results"]
            record["two_slot_128k_concurrency"] = {
                "requests": len(requests),
                "all_http_200_without_fallback": all(
                    request["http_status"] == 200 and not request["fallback_header"]
                    for request in requests
                ),
                "per_request_ttft_seconds": [request["ttft_seconds"] for request in requests],
                "per_request_tokens_per_second": [
                    request["client_tokens_per_second"] for request in requests
                ],
                "aggregate_tokens_per_second": sum(
                    request["client_tokens_per_second"] for request in requests
                ),
                "wall_seconds": concurrent["concurrency"]["wall_seconds"],
            }
        finalists.append(record)

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hardware": selections["hardware"],
        "methodology": {
            "weight_quants": ["Q4_K_M", "Q5_K_M", "Q6_K", "Q8_0"],
            "contexts": [131072, 262144],
            "kv_types": ["q8_0", "q4_0"],
            "matrix_combinations": len(matrix_rows),
            "speed_test": "llama-bench: 512 prompt tokens and 128 generated tokens, three measured repetitions",
            "context_test": "200K-token planted-fact recall against each 256K finalist",
            "concurrency_test": "Two simultaneous streamed requests with two 128K slots",
            "quality_test": weather["evaluation_prompt"],
        },
        "matrix_totals": {
            "rows": len(matrix_rows),
            "statuses": dict(Counter(row["status"] for row in matrix_rows)),
        },
        "matrix": matrix_summary,
        "finalists": finalists,
        "failures": failures["failures"],
        "weather_source_truth": {
            "as_of": weather["as_of"],
            "latest_nws_validation": weather.get("latest_nws_validation"),
            "location": weather["location"],
            "date_interpretation": weather["date_interpretation"],
            "sources": weather["sources"],
            "days": weather["days"],
            "evaluation_rules": weather["evaluation_rules"],
        },
        "system_changes": {
            "removed": ["Qwythos 9B serving entry and GGUF"],
            "installed": ["Gemma 4 26B-A4B quants plus MTP drafter", "Gemma 4 12B quants plus MTP drafter"],
            "registered_model_ids": [
                "qwen-3.6-35b-q8",
                "qwen-3.6-35b-q8-fast",
                "qwen-3.5-4b-q8",
                "agents-a1-4b-q8",
                "ornith-1.0-35b-q8",
                "ornith-1.0-9b-q6",
                "gemma-4-12b-q5",
                "gemma-4-26b-q8",
            ],
            "open_webui_custom_ids_migrated": [
                "qwen-3.6-35b-q6 -> qwen-3.6-35b-q8",
                "qwen-3.6-35b-q6-fast -> qwen-3.6-35b-q8-fast",
            ],
            "proxy_timeout_fix": {
                "source_change": "dev/llm-proxy main.go: http.Server.WriteTimeout disabled for streaming and long-context responses",
                "regression": "The former production binary disconnected a completed 1002.62-second backend response at its absolute ten-minute write deadline.",
                "candidate_test": "A 201031-token Ornith 1.0 35B request completed through the candidate in 1001.06 seconds with 10/10 recall.",
                "release_commit": "8eae5006e11ebcb20ac63bb4240352d52b041d41",
                "deployed_test": "The released binary returned a fresh 201031-token run in 970.91 seconds, HTTP 200, with 10/10 recall and no fallback.",
                "release_status": "committed, pushed, deployed, and regression-tested",
            },
        },
    }

    context_path = ROOT / "context-recall-results.json"
    if context_path.exists():
        output["context_recall"] = load_json(context_path.name)
    golf_path = ROOT / "golf-analysis.json"
    if golf_path.exists():
        output["golf_analysis"] = load_json(golf_path.name)
    scores_path = ROOT / "golf-scores.json"
    if scores_path.exists():
        output["golf_scores"] = load_json(scores_path.name)
    memory_path = ROOT / "runtime-memory-observations.json"
    if memory_path.exists():
        output["runtime_memory_observations"] = load_json(memory_path.name)
    inventory_path = ROOT / "installed-gguf-inventory.json"
    if inventory_path.exists():
        output["installed_gguf_inventory"] = load_json(inventory_path.name)

    context_records = output.get("context_recall", {}).get("results", [])
    golf_summary = output.get("golf_scores", {}).get("summary", {})
    finalist_fields = [
        "model",
        "quant",
        "weight_size_gb",
        "context_tokens",
        "kv_type",
        "serving_cpu_moe_layers",
        "mtp_enabled",
        "warm_ttft_seconds",
        "warm_generation_tokens_per_second",
        "model_swap_ttft_seconds",
        "context_recall_score",
        "context_elapsed_seconds",
        "context_prompt_tokens_per_second",
        "context_generation_tokens_per_second",
        "concurrency_ttft_seconds",
        "concurrency_per_request_tokens_per_second",
        "concurrency_aggregate_tokens_per_second",
        "golf_tool_calling_mean",
        "golf_accuracy_mean",
        "golf_readability_mean",
        "golf_overall_mean",
        "golf_correct_date_runs_of_5",
        "golf_runs_at_omp_time_limit",
        "golf_empty_final_answers",
        "golf_mean_duration_seconds",
        "golf_mean_initial_ttft_seconds",
        "golf_mean_generation_tokens_per_second",
        "golf_total_tool_calls",
        "golf_total_tool_errors",
    ]
    with OUTPUT_CSV_PATH.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=finalist_fields)
        writer.writeheader()
        for record in finalists:
            model_id = record["model_id"]
            evaluation_model_id = (
                "qwen-3.6-35b-q8-fast"
                if model_id == "qwen-3.6-35b-q8"
                else model_id
            )
            context = next(
                (
                    item
                    for item in context_records
                    if item.get("model") == evaluation_model_id
                    and item.get("tag") == "deployed-proxy"
                    and item.get("status") == "completed"
                ),
                None,
            ) or next(
                (
                    item
                    for item in context_records
                    if item.get("model") == evaluation_model_id
                    and item.get("tag") == "patched-proxy"
                    and item.get("status") == "completed"
                ),
                {},
            )
            golf = golf_summary.get(evaluation_model_id, {})
            concurrent = record.get("two_slot_128k_concurrency", {})
            writer.writerow(
                {
                    "model": model_id,
                    "quant": record["quant"],
                    "weight_size_gb": round(record["weight_size_bytes"] / 1e9, 3),
                    "context_tokens": record["context_tokens"],
                    "kv_type": record["kv_type_k"],
                    "serving_cpu_moe_layers": record["serving_cpu_moe_layers"],
                    "mtp_enabled": record["mtp_enabled"],
                    "warm_ttft_seconds": record.get("final_api", {}).get(
                        "mean_warm_ttft_seconds"
                    ),
                    "warm_generation_tokens_per_second": record.get(
                        "final_api", {}
                    ).get("mean_generation_tokens_per_second"),
                    "model_swap_ttft_seconds": record.get("model_swap", {}).get(
                        "ttft_seconds"
                    ),
                    "context_recall_score": context.get("score"),
                    "context_elapsed_seconds": context.get("elapsed_seconds"),
                    "context_prompt_tokens_per_second": context.get(
                        "timings", {}
                    ).get("prompt_per_second"),
                    "context_generation_tokens_per_second": context.get(
                        "timings", {}
                    ).get("predicted_per_second"),
                    "concurrency_ttft_seconds": json.dumps(
                        concurrent.get("per_request_ttft_seconds")
                    ),
                    "concurrency_per_request_tokens_per_second": json.dumps(
                        concurrent.get("per_request_tokens_per_second")
                    ),
                    "concurrency_aggregate_tokens_per_second": concurrent.get(
                        "aggregate_tokens_per_second"
                    ),
                    "golf_tool_calling_mean": golf.get("tool_calling_mean"),
                    "golf_accuracy_mean": golf.get("accuracy_mean"),
                    "golf_readability_mean": golf.get("readability_mean"),
                    "golf_overall_mean": golf.get("overall_mean"),
                    "golf_correct_date_runs_of_5": golf.get(
                        "runs_with_correct_date_window"
                    ),
                    "golf_runs_at_omp_time_limit": golf.get(
                        "runs_at_omp_time_limit"
                    ),
                    "golf_empty_final_answers": golf.get("empty_final_answers"),
                    "golf_mean_duration_seconds": golf.get(
                        "mean_duration_seconds"
                    ),
                    "golf_mean_initial_ttft_seconds": golf.get(
                        "mean_initial_ttft_seconds"
                    ),
                    "golf_mean_generation_tokens_per_second": golf.get(
                        "mean_generation_tokens_per_second"
                    ),
                    "golf_total_tool_calls": golf.get("total_tool_calls"),
                    "golf_total_tool_errors": golf.get("total_tool_errors"),
                }
            )

    OUTPUT_PATH.write_text(json.dumps(output, indent=2) + "\n")
    print(f"wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
