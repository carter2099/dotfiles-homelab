#!/usr/bin/env python3
"""Run the preliminary llama-bench quant matrix on the gaming rig.

Each case is persisted immediately so interrupted runs can be resumed. Context capacity is
measured separately by fit-matrix.py because llama-bench only allocates its short test KV.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PLAN_PATH = ROOT / "matrix-plan.json"
OUTPUT_PATH = ROOT / "speed-benchmarks.json"
RAW_DIR = ROOT / "raw" / "llama-bench"
REMOTE_DIR = r"C:\llm"
BENCH_EXE = rf"{REMOTE_DIR}\llama-bench.exe"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def remote(command: str, timeout: int = 1200) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["ssh", "gamingrig", command],
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--models", nargs="*", help="Only these matrix model IDs")
    parser.add_argument("--quants", nargs="*", help="Only these quant labels")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--force", action="store_true", help="Repeat completed cases")
    return parser.parse_args()


def load_output() -> dict:
    if OUTPUT_PATH.exists():
        return json.loads(OUTPUT_PATH.read_text())
    return {
        "generated_at": utc_now(),
        "method": {
            "binary": "llama-bench build 10171",
            "prompt_tokens": 512,
            "generated_tokens": 128,
            "threads": 8,
            "batch_threads": 8,
            "flash_attention": "on",
            "kv_cache": "q8_0 K and V",
            "gpu_layers": "all non-MoE tensors; all MoE experts on CPU",
            "repetitions": 3,
        },
        "results": [],
    }


def save(output: dict) -> None:
    output["updated_at"] = utc_now()
    OUTPUT_PATH.write_text(json.dumps(output, indent=2) + "\n")


def selected(value: str, requested: list[str] | None) -> bool:
    return not requested or value in requested


def main() -> None:
    args = parse_args()
    plan = json.loads(PLAN_PATH.read_text())
    output = load_output()
    output["method"]["repetitions"] = args.repetitions
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    completed = {
        (record["model"], record["quant"])
        for record in output["results"]
        if record.get("status") == "completed"
    }

    for model_id, model in plan["models"].items():
        if not selected(model_id, args.models):
            continue
        for quant in model["quants"]:
            label = quant["label"]
            if not selected(label, args.quants):
                continue
            key = (model_id, label)
            if key in completed and not args.force:
                print(f"skip completed: {model_id} {label}", flush=True)
                continue

            file_name = quant["file"]
            raw_path = RAW_DIR / f"{model_id}--{label.replace('/', '_')}.json"
            command_parts = [
                f'"{BENCH_EXE}"',
                "-m",
                f'"{REMOTE_DIR}\\{file_name}"',
                "-p", "512",
                "-n", "128",
                "-r", str(args.repetitions),
                "-o", "json",
                "-oe", "json",
                "-t", "8",
                "-ctk", "q8_0",
                "-ctv", "q8_0",
                "-ngl", "999",
                "-fa", "on",
                "-mmp", "0",
                "--prio", "2",
            ]
            if model["cpu_moe"]:
                command_parts.extend(["-ncmoe", "999"])
            command = " ".join(command_parts)
            print(f"run: {model_id} {label}", flush=True)
            started = datetime.now(timezone.utc)
            try:
                result = remote(command)
                duration = (datetime.now(timezone.utc) - started).total_seconds()
                raw = {
                    "command": command,
                    "return_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }
                raw_path.write_text(json.dumps(raw, indent=2) + "\n")
                parsed = json.loads(result.stdout) if result.returncode == 0 else None
                status = "completed" if result.returncode == 0 else "failed"
                error = None
            except (subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
                duration = (datetime.now(timezone.utc) - started).total_seconds()
                parsed = None
                status = "failed"
                error = f"{type(exc).__name__}: {exc}"

            output["results"] = [
                record
                for record in output["results"]
                if (record["model"], record["quant"]) != key
            ]
            output["results"].append(
                {
                    "model": model_id,
                    "quant": label,
                    "file": file_name,
                    "status": status,
                    "duration_seconds": round(duration, 3),
                    "results": parsed,
                    "error": error,
                    "raw_file": str(raw_path.relative_to(ROOT)),
                }
            )
            save(output)
            print(f"{status}: {model_id} {label} ({duration:.1f}s)", flush=True)

    save(output)
    print(f"wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
