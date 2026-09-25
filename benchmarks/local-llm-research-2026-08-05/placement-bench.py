#!/usr/bin/env python3
"""Benchmark each quant/context using the fastest reserve-safe tensor placement."""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PLAN_PATH = ROOT / "matrix-plan.json"
FIT_PATH = ROOT / "fit-estimates.json"
OUTPUT_PATH = ROOT / "placement-speed-benchmarks.json"
RAW_DIR = ROOT / "raw" / "placement-bench"
REMOTE_DIR = r"C:\llm"
BENCH_EXE = rf"{REMOTE_DIR}\llama-bench.exe"


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--models", nargs="*")
    parser.add_argument("--quants", nargs="*")
    parser.add_argument("--contexts", nargs="*", type=int)
    parser.add_argument(
        "--kv-types", nargs="*", choices=("q8_0", "q4_0"), default=["q8_0", "q4_0"]
    )
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def selected(value: object, requested: list | None) -> bool:
    return not requested or value in requested


def remote(command: str, timeout: int = 1200) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["ssh", "gamingrig", command],
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def load_output(repetitions: int) -> dict:
    if OUTPUT_PATH.exists():
        output = json.loads(OUTPUT_PATH.read_text())
        output["method"]["repetitions"] = repetitions
        output["method"]["placement"] = (
            "fit-matrix reserve-safe placement for the named context; q8_0 "
            "and q4_0 KV are benchmarked independently"
        )
        return output
    return {
        "created_at": now(),
        "method": {
            "binary": "llama-bench build 10171",
            "prompt_tokens": 512,
            "generated_tokens": 128,
            "repetitions": repetitions,
            "threads": 8,
            "flash_attention": "on",
            "placement": (
                "fit-matrix reserve-safe placement for the named context; q8_0 "
                "and q4_0 KV are benchmarked independently"
            ),
        },
        "results": [],
    }


def save(output: dict) -> None:
    output["updated_at"] = now()
    OUTPUT_PATH.write_text(json.dumps(output, indent=2) + "\n")


def main() -> None:
    args = parse_args()
    plan = json.loads(PLAN_PATH.read_text())
    fit = json.loads(FIT_PATH.read_text())
    output = load_output(args.repetitions)
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    completed = {
        (
            item["model"],
            item["quant"],
            item["context_tokens"],
            item.get("kv_type"),
        )
        for item in output["results"]
        if item["status"] in ("completed", "projected_failure")
    }

    for model_id, model in plan["models"].items():
        if not selected(model_id, args.models):
            continue
        for quant in model["quants"]:
            label = quant["label"]
            if not selected(label, args.quants):
                continue
            for context in plan["contexts"]:
                if not selected(context, args.contexts):
                    continue
                for kv_type in args.kv_types:
                    key = (model_id, label, context, kv_type)
                    if key in completed and not args.force:
                        print(f"skip completed: {key}", flush=True)
                        continue

                    placement = next(
                        (
                            item
                            for item in fit["results"]
                            if item["model"] == model_id
                            and item["quant"] == label
                            and item["context_tokens"] == context
                            and item["kv_type_k"] == kv_type
                            and item["projected_fit_with_reserve"]
                        ),
                        None,
                    )
                    if placement is None:
                        record = {
                            "model": model_id,
                            "quant": label,
                            "context_tokens": context,
                            "kv_type": kv_type,
                            "status": "projected_failure",
                            "error": "No placement preserves memory reserves",
                        }
                    else:
                        raw_path = (
                            RAW_DIR
                            / f"{model_id}--{label}--{context}--{kv_type}.json"
                        )
                        parts = [
                            f'"{BENCH_EXE}"',
                            "-m",
                            f'"{REMOTE_DIR}\\{quant["file"]}"',
                            "-p",
                            "512",
                            "-n",
                            "128",
                            "-r",
                            str(args.repetitions),
                            "-o",
                            "json",
                            "-oe",
                            "json",
                            "-t",
                            "8",
                            "-ctk",
                            kv_type,
                            "-ctv",
                            kv_type,
                            "-ngl",
                            str(placement["gpu_layers"]),
                            "-fa",
                            "on",
                            "-mmp",
                            "0",
                            "--prio",
                            "2",
                        ]
                        if placement["cpu_moe_layers"] is not None:
                            parts.extend(
                                ["-ncmoe", str(placement["cpu_moe_layers"])]
                            )
                        command = " ".join(parts)
                        print(
                            f"run: {model_id} {label} {context} {kv_type}",
                            flush=True,
                        )
                        started = datetime.now(timezone.utc)
                        try:
                            result = remote(command)
                            duration = (
                                datetime.now(timezone.utc) - started
                            ).total_seconds()
                            raw_path.write_text(
                                json.dumps(
                                    {
                                        "command": command,
                                        "return_code": result.returncode,
                                        "stdout": result.stdout,
                                        "stderr": result.stderr,
                                    },
                                    indent=2,
                                )
                                + "\n"
                            )
                            parsed = (
                                json.loads(result.stdout)
                                if result.returncode == 0
                                else None
                            )
                            error = None
                        except (
                            subprocess.TimeoutExpired,
                            json.JSONDecodeError,
                        ) as exc:
                            duration = (
                                datetime.now(timezone.utc) - started
                            ).total_seconds()
                            result = None
                            parsed = None
                            error = f"{type(exc).__name__}: {exc}"
                        return_code = result.returncode if result else None
                        record = {
                            "model": model_id,
                            "quant": label,
                            "file": quant["file"],
                            "context_tokens": context,
                            "kv_type": kv_type,
                            "gpu_layers": placement["gpu_layers"],
                            "cpu_moe_layers": placement["cpu_moe_layers"],
                            "status": (
                                "completed" if return_code == 0 else "failed"
                            ),
                            "return_code": return_code,
                            "duration_seconds": round(duration, 3),
                            "results": parsed,
                            "error": error,
                            "raw_file": str(raw_path.relative_to(ROOT)),
                            "fit_devices": placement["devices"],
                        }

                    output["results"] = [
                        item
                        for item in output["results"]
                        if (
                            item["model"],
                            item["quant"],
                            item["context_tokens"],
                            item.get("kv_type"),
                        )
                        != key
                    ]
                    output["results"].append(record)
                    save(output)
                    print(
                        f"{record['status']}: {model_id} {label} "
                        f"{context} {kv_type}",
                        flush=True,
                    )

    save(output)
    print(f"wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
