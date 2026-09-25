#!/usr/bin/env python3
"""Run independent OMP golf-weather evaluations and preserve event telemetry."""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RAW_DIR = ROOT / "raw" / "golf"
RESULTS_PATH = ROOT / "golf-runs.json"
PROMPT = (
    "I'm golfing at the Purdue golf courses this weekend. What will the weather "
    "be like the next 3 days there? From about 9am to 5pm each day"
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("models", nargs="+")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--thinking", choices=("off", "minimal", "low", "medium", "high"), default="off")
    parser.add_argument("--max-time", default="10m")
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def load_results() -> dict:
    if RESULTS_PATH.exists():
        return json.loads(RESULTS_PATH.read_text())
    return {"prompt": PROMPT, "created_at": now(), "runs": []}


def save(results: dict) -> None:
    results["updated_at"] = now()
    RESULTS_PATH.write_text(json.dumps(results, indent=2) + "\n")


def main() -> None:
    args = parse_args()
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    results = load_results()

    for model in args.models:
        for run_number in range(1, args.runs + 1):
            existing = next(
                (
                    run
                    for run in results["runs"]
                    if run["model"] == model and run["run"] == run_number
                ),
                None,
            )
            if existing and existing.get("status") == "completed" and not args.force:
                print(f"skip completed: {model} run {run_number}", flush=True)
                continue

            raw_path = RAW_DIR / f"{model}--run-{run_number}.jsonl"
            command = [
                "omp",
                "-p",
                "--mode", "json",
                "--allow-home",
                "--cwd", "/home/carter",
                "--session-dir", "/home/carter/.omp/agent/sessions-automated",
                "--no-session",
                "--provider", "local-llm",
                "--model", model,
                "--api-key", "none",
                "--thinking", args.thinking,
                "--max-time", args.max_time,
                "--auto-approve",
                PROMPT,
            ]
            print(f"run: {model} {run_number}/{args.runs}", flush=True)
            started_wall = now()
            started = time.monotonic()
            stderr_path = raw_path.with_suffix(".stderr.txt")
            with raw_path.open("w") as output_file, stderr_path.open("w") as error_file:
                process = subprocess.Popen(
                    command,
                    cwd="/home/carter",
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=error_file,
                    bufsize=1,
                )
                assert process.stdout is not None
                for line in process.stdout:
                    received = {
                        "received_monotonic_seconds": round(time.monotonic() - started, 6),
                        "event": json.loads(line),
                    }
                    output_file.write(json.dumps(received, separators=(",", ":")) + "\n")
                    output_file.flush()
                return_code = process.wait()

            duration = round(time.monotonic() - started, 3)
            record = {
                "model": model,
                "run": run_number,
                "thinking": args.thinking,
                "status": "completed" if return_code == 0 else "failed",
                "return_code": return_code,
                "started_at": started_wall,
                "duration_seconds": duration,
                "raw_file": str(raw_path.relative_to(ROOT)),
                "stderr_file": str(stderr_path.relative_to(ROOT)),
            }
            results["runs"] = [
                run
                for run in results["runs"]
                if not (run["model"] == model and run["run"] == run_number)
            ]
            results["runs"].append(record)
            save(results)
            print(f"{record['status']}: {model} run {run_number} ({duration:.1f}s)", flush=True)

    save(results)
    print(f"wrote {RESULTS_PATH}")


if __name__ == "__main__":
    main()
