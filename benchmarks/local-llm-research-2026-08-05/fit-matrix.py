#!/usr/bin/env python3
"""Estimate exact llama.cpp memory use for the requested quant/context grid."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PLAN_PATH = ROOT / "matrix-plan.json"
OUTPUT_PATH = ROOT / "fit-estimates.json"
REMOTE_DIR = r"C:\llm"
FIT_EXE = rf"{REMOTE_DIR}\llama-fit-params.exe"
VRAM_MIB = 12227
RAM_MIB = 32705
VRAM_RESERVE_MIB = 1024
RAM_RESERVE_MIB = 4096
KV_TYPES = ("q8_0", "q4_0")

MEMORY_RE = re.compile(
    r"^(CUDA\d+|Host)\s+(\d+)\s+(\d+)\s+(\d+)\s*$", re.MULTILINE
)


def remote(command: str, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["ssh", "gamingrig", command],
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def estimate(
    file_name: str,
    context: int,
    kv_type: str,
    gpu_layers: int,
    cpu_moe_layers: int | None,
) -> dict:
    model_path = rf"{REMOTE_DIR}\{file_name}"
    command = (
        f'"{FIT_EXE}" -m "{model_path}" '
        f"-c {context} -ctk {kv_type} -ctv {kv_type} "
        f"-ngl {gpu_layers} -fit off -fitp on -n 1 -p test"
    )
    if cpu_moe_layers is not None:
        command += f" --n-cpu-moe {cpu_moe_layers}"

    started = datetime.now(timezone.utc)
    result = remote(command)
    combined = f"{result.stdout}\n{result.stderr}".strip()
    devices = {}
    for device, model, ctx, compute in MEMORY_RE.findall(combined):
        devices[device] = {
            "model_mib": int(model),
            "context_mib": int(ctx),
            "compute_mib": int(compute),
            "total_mib": int(model) + int(ctx) + int(compute),
        }

    cuda = devices.get("CUDA0")
    host = devices.get("Host")
    fits = bool(
        result.returncode == 0
        and cuda
        and host
        and cuda["total_mib"] <= VRAM_MIB - VRAM_RESERVE_MIB
        and host["total_mib"] <= RAM_MIB - RAM_RESERVE_MIB
    )
    return {
        "file": file_name,
        "context_tokens": context,
        "kv_type_k": kv_type,
        "kv_type_v": kv_type,
        "gpu_layers": gpu_layers,
        "cpu_moe_layers": cpu_moe_layers,
        "return_code": result.returncode,
        "duration_seconds": round(
            (datetime.now(timezone.utc) - started).total_seconds(), 3
        ),
        "devices": devices,
        "projected_fit_with_reserve": fits,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def trial_summary(record: dict) -> dict:
    return {
        "gpu_layers": record["gpu_layers"],
        "cpu_moe_layers": record["cpu_moe_layers"],
        "return_code": record["return_code"],
        "devices": record["devices"],
        "projected_fit_with_reserve": record["projected_fit_with_reserve"],
    }


def optimize_placement(
    file_name: str, context: int, kv_type: str, is_moe: bool
) -> dict:
    """Find the fastest projected placement that preserves memory reserves."""
    cache: dict[tuple[int, int | None], dict] = {}

    def run(gpu_layers: int, cpu_moe_layers: int | None) -> dict:
        key = (gpu_layers, cpu_moe_layers)
        if key not in cache:
            cache[key] = estimate(
                file_name, context, kv_type, gpu_layers, cpu_moe_layers
            )
        return cache[key]

    if is_moe:
        # Minimize CPU expert layers: more experts on GPU is the faster placement.
        low, high = 0, 99
        while low < high:
            middle = (low + high) // 2
            record = run(99, middle)
            cuda = record["devices"].get("CUDA0")
            if record["return_code"] != 0 or not cuda:
                record["placement_search"] = [
                    trial_summary(item) for item in cache.values()
                ]
                record["failure_reason"] = "memory estimator failed"
                return record
            if cuda["total_mib"] <= VRAM_MIB - VRAM_RESERVE_MIB:
                high = middle
            else:
                low = middle + 1
        selected = run(99, low)
        selected["placement"] = "partial MoE expert offload"
    else:
        # Maximize GPU layers while preserving VRAM. This also minimizes host RAM.
        low, high = 0, 99
        while low < high:
            middle = (low + high + 1) // 2
            record = run(middle, None)
            cuda = record["devices"].get("CUDA0")
            if record["return_code"] != 0 or not cuda:
                record["placement_search"] = [
                    trial_summary(item) for item in cache.values()
                ]
                record["failure_reason"] = "memory estimator failed"
                return record
            if cuda["total_mib"] <= VRAM_MIB - VRAM_RESERVE_MIB:
                low = middle
            else:
                high = middle - 1
        selected = run(low, None)
        selected["placement"] = "maximum dense layers on GPU"

    selected["placement_search"] = [
        trial_summary(item) for item in cache.values()
    ]
    if not selected["projected_fit_with_reserve"]:
        cuda = selected["devices"].get("CUDA0")
        host = selected["devices"].get("Host")
        if not cuda or not host:
            selected["failure_reason"] = "memory estimator returned no device totals"
        elif host["total_mib"] > RAM_MIB - RAM_RESERVE_MIB:
            selected["failure_reason"] = "host RAM exceeds reserve-adjusted capacity"
        else:
            selected["failure_reason"] = "VRAM exceeds reserve-adjusted capacity"
    return selected


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--models", nargs="*")
    parser.add_argument("--quants", nargs="*")
    parser.add_argument("--contexts", nargs="*", type=int)
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def wanted(value: object, requested: list | None) -> bool:
    return not requested or value in requested


def main() -> None:
    args = parse_args()
    plan = json.loads(PLAN_PATH.read_text())
    output = (
        json.loads(OUTPUT_PATH.read_text())
        if OUTPUT_PATH.exists()
        else {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "hardware": {
                "gpu": "NVIDIA GeForce RTX 5070",
                "vram_mib": VRAM_MIB,
                "ram_mib": RAM_MIB,
                "vram_reserve_mib": VRAM_RESERVE_MIB,
                "ram_reserve_mib": RAM_RESERVE_MIB,
            },
            "method": (
                "llama-fit-params build 10171 with automatic fitting disabled; "
                "binary search maximizes dense GPU layers or minimizes MoE CPU "
                "expert layers while preserving 1 GiB VRAM and 4 GiB host-RAM "
                "reserves; q8_0 and q4_0 KV evaluated"
            ),
            "results": [],
        }
    )

    completed = {
        (
            item["model"],
            item["quant"],
            item["context_tokens"],
            item["kv_type_k"],
        )
        for item in output["results"]
        if item.get("return_code") == 0
    }
    for model_id, model in plan["models"].items():
        if not wanted(model_id, args.models):
            continue
        for quant in model["quants"]:
            if not wanted(quant["label"], args.quants):
                continue
            for context in plan["contexts"]:
                if not wanted(context, args.contexts):
                    continue
                for kv_type in KV_TYPES:
                    key = (model_id, quant["label"], context, kv_type)
                    if key in completed and not args.force:
                        print(f"skip completed: {key}", flush=True)
                        continue
                    print(
                        f"{model_id} {quant['label']} {context} {kv_type}",
                        flush=True,
                    )
                    record = optimize_placement(
                        quant["file"], context, kv_type, model["cpu_moe"]
                    )
                    record.update({"model": model_id, "quant": quant["label"]})
                    output["results"] = [
                        item
                        for item in output["results"]
                        if (
                            item["model"],
                            item["quant"],
                            item["context_tokens"],
                            item["kv_type_k"],
                        )
                        != key
                    ]
                    output["results"].append(record)
                    output["updated_at"] = datetime.now(timezone.utc).isoformat()
                    OUTPUT_PATH.write_text(json.dumps(output, indent=2) + "\n")

    print(f"wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
