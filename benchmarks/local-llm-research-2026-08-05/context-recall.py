#!/usr/bin/env python3
"""Run the existing planted-fact context benchmark against final model configs."""

from __future__ import annotations

import argparse
import http.client
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONTEXT_ROOT = ROOT.parent / "context-window"
OUTPUT_PATH = ROOT / "context-recall-results.json"
EXPECTED = [
    "portland",
    "age 7",
    "dune",
    "2019",
    "daily grind",
    "maple",
    "march 14",
    "2 years",
    "thai green curry",
    "queenstown",
]


def score_answer(answer: str) -> dict[str, bool]:
    normalized = answer.lower()
    matches = {expected: expected in normalized for expected in EXPECTED}
    matches["age 7"] = matches["age 7"] or bool(
        re.search(r"(?mi)^\s*\**2[.)][^\n]*\b(?:7|seven)\b", answer)
    )
    return matches


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("models", nargs="+")
    parser.add_argument("--target", type=int, choices=(100_000, 200_000), default=200_000)
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--tag", default="proxy")
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def load_output() -> dict:
    if OUTPUT_PATH.exists():
        return json.loads(OUTPUT_PATH.read_text())
    return {
        "created_at": now(),
        "method": "Single non-streamed planted-fact recall request; case-insensitive expected-answer matching",
        "results": [],
    }


def save(output: dict) -> None:
    output["updated_at"] = now()
    OUTPUT_PATH.write_text(json.dumps(output, indent=2) + "\n")


def request(model: str, content: str, host: str, port: int) -> dict:
    body = json.dumps(
        {
            "model": model,
            "messages": [{"role": "user", "content": content}],
            "max_tokens": 2048,
            "temperature": 0.1,
            "stream": False,
            "chat_template_kwargs": {"enable_thinking": False},
        }
    )
    connection = http.client.HTTPConnection(host, port, timeout=3600)
    started = time.monotonic()
    try:
        connection.request(
            "POST",
            "/v1/chat/completions",
            body=body,
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        fallback_header = response.getheader("X-Fallback")
        payload = response.read().decode("utf-8", errors="replace")
    finally:
        connection.close()
    elapsed = time.monotonic() - started
    data = json.loads(payload)
    return {
        "http_status": response.status,
        "fallback_header": fallback_header,
        "elapsed_seconds": round(elapsed, 6),
        "response": data,
    }


def main() -> None:
    args = parse_args()
    benchmark_path = CONTEXT_ROOT / f"context_{args.target:_}.md"
    content = benchmark_path.read_text()
    output = load_output()

    for model in args.models:
        key = (model, args.target, args.tag)
        existing = next(
            (
                item
                for item in output["results"]
                if (
                    item["model"],
                    item["target_tokens"],
                    item.get("tag", "proxy"),
                ) == key
            ),
            None,
        )
        if existing and existing.get("status") == "completed" and not args.force:
            print(f"skip completed: {model} {args.target}", flush=True)
            continue

        print(f"run: {model} {args.target}", flush=True)
        try:
            raw = request(model, content, args.host, args.port)
            message = raw["response"].get("choices", [{}])[0].get("message", {})
            answer = message.get("content") or ""
            matches = score_answer(answer)
            record = {
                "model": model,
                "target_tokens": args.target,
                "benchmark_file": str(benchmark_path),
                "tag": args.tag,
                "endpoint": f"http://{args.host}:{args.port}/v1/chat/completions",
                "status": (
                    "completed"
                    if raw["http_status"] == 200 and not raw["fallback_header"]
                    else "failed"
                ),
                "http_status": raw["http_status"],
                "fallback_header": raw["fallback_header"],
                "elapsed_seconds": raw["elapsed_seconds"],
                "score": sum(matches.values()),
                "matches": matches,
                "answer": answer,
                "finish_reason": raw["response"].get("choices", [{}])[0].get("finish_reason"),
                "usage": raw["response"].get("usage"),
                "timings": raw["response"].get("timings"),
                "error": raw["response"].get("error"),
            }
        except Exception as exc:
            record = {
                "model": model,
                "target_tokens": args.target,
                "benchmark_file": str(benchmark_path),
                "tag": args.tag,
                "endpoint": f"http://{args.host}:{args.port}/v1/chat/completions",
                "status": "failed",
                "error": f"{type(exc).__name__}: {exc}",
            }

        output["results"] = [
            item
            for item in output["results"]
            if (
                item["model"],
                item["target_tokens"],
                item.get("tag", "proxy"),
            ) != key
        ]
        output["results"].append(record)
        save(output)
        print(f"{record['status']}: {model}, score={record.get('score')}", flush=True)

    save(output)
    print(f"wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
