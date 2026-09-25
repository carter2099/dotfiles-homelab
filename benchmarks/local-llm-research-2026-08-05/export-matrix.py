#!/usr/bin/env python3
"""Export the quant/context/KV fit and speed matrix as one flat CSV."""

from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FIT_PATH = ROOT / "fit-estimates.json"
SPEED_PATH = ROOT / "placement-speed-benchmarks.json"
OUTPUT_PATH = ROOT / "quant-context-matrix.csv"


def find_test(tests: list[dict], *, prompt: int = 0, generation: int = 0) -> dict:
    return next(
        (
            test
            for test in tests
            if test.get("n_prompt") == prompt and test.get("n_gen") == generation
        ),
        {},
    )


def main() -> None:
    fit = json.loads(FIT_PATH.read_text())
    speed = json.loads(SPEED_PATH.read_text())
    measured = {
        (
            row["model"],
            row["quant"],
            row["context_tokens"],
            row["kv_type"],
        ): row
        for row in speed["results"]
    }
    fields = [
        "model",
        "quant",
        "weight_size_gb",
        "context_tokens",
        "kv_type",
        "status",
        "gpu_layers",
        "cpu_moe_layers",
        "cuda_model_mib",
        "cuda_context_mib",
        "cuda_compute_mib",
        "cuda_total_mib",
        "host_model_mib",
        "host_context_mib",
        "host_compute_mib",
        "host_total_mib",
        "prompt_tokens",
        "prompt_tokens_per_second",
        "prompt_tps_stddev",
        "generated_tokens",
        "generation_tokens_per_second",
        "generation_tps_stddev",
        "estimated_warm_ttft_512_seconds",
        "failure_reason",
        "raw_file",
    ]
    rows = []
    for estimate in fit["results"]:
        key = (
            estimate["model"],
            estimate["quant"],
            estimate["context_tokens"],
            estimate["kv_type_k"],
        )
        result = measured.get(key, {})
        tests = result.get("results", [])
        prompt = find_test(tests, prompt=512)
        generation = find_test(tests, generation=128)
        prompt_tps = prompt.get("avg_ts")
        generation_tps = generation.get("avg_ts")
        warm_ttft = (
            512 / prompt_tps + 1 / generation_tps
            if prompt_tps and generation_tps
            else None
        )
        devices = estimate.get("devices", {})
        cuda = devices.get("CUDA0", {})
        host = devices.get("Host", {})
        model_size = prompt.get("model_size") or generation.get("model_size")
        rows.append(
            {
                "model": estimate["model"],
                "quant": estimate["quant"],
                "weight_size_gb": round(model_size / 1_000_000_000, 3) if model_size else None,
                "context_tokens": estimate["context_tokens"],
                "kv_type": estimate["kv_type_k"],
                "status": result.get(
                    "status",
                    "not_run" if estimate["projected_fit_with_reserve"] else "projected_failure",
                ),
                "gpu_layers": estimate.get("gpu_layers"),
                "cpu_moe_layers": estimate.get("cpu_moe_layers"),
                "cuda_model_mib": cuda.get("model_mib"),
                "cuda_context_mib": cuda.get("context_mib"),
                "cuda_compute_mib": cuda.get("compute_mib"),
                "cuda_total_mib": cuda.get("total_mib"),
                "host_model_mib": host.get("model_mib"),
                "host_context_mib": host.get("context_mib"),
                "host_compute_mib": host.get("compute_mib"),
                "host_total_mib": host.get("total_mib"),
                "prompt_tokens": prompt.get("n_prompt"),
                "prompt_tokens_per_second": prompt_tps,
                "prompt_tps_stddev": prompt.get("stddev_ts"),
                "generated_tokens": generation.get("n_gen"),
                "generation_tokens_per_second": generation_tps,
                "generation_tps_stddev": generation.get("stddev_ts"),
                "estimated_warm_ttft_512_seconds": round(warm_ttft, 6) if warm_ttft else None,
                "failure_reason": result.get("reason") or result.get("error"),
                "raw_file": result.get("raw_file"),
            }
        )

    rows.sort(key=lambda row: (row["model"], row["quant"], row["context_tokens"], row["kv_type"]))
    with OUTPUT_PATH.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {OUTPUT_PATH} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
