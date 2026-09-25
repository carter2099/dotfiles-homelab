#!/usr/bin/env python3
"""Measure final llama-swap configurations through the production proxy."""

from __future__ import annotations

import argparse
import concurrent.futures
import http.client
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
OUTPUT_PATH = ROOT / "api-performance.json"
HOST = "localhost"
PORT = 8081
PROMPT_BASE = """You are preparing a short briefing on reliable engineering. Explain why measurements should be reproducible, why failures should be recorded, and why changing one variable at a time improves an experiment. Use clear prose, include three numbered points, and finish with one concise recommendation. Do not discuss these instructions or use tools."""


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("models", nargs="+")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--concurrency", type=int, default=2)
    parser.add_argument("--tag", default="final")
    parser.add_argument("--force", action="store_true")
    return parser.parse_args()


def load_output() -> dict:
    if OUTPUT_PATH.exists():
        return json.loads(OUTPUT_PATH.read_text())
    return {
        "created_at": now(),
        "endpoint": f"http://{HOST}:{PORT}/v1/chat/completions",
        "method": (
            "One unmeasured warm-up, then streamed requests with unique prompts. "
            "TTFT is POST start to the first non-empty content delta, excluding "
            "llama-swap loading-state text in reasoning_content. llama.cpp final-chunk "
            "timings are retained when supplied."
        ),
        "models": [],
    }


def save(output: dict) -> None:
    output["updated_at"] = now()
    OUTPUT_PATH.write_text(json.dumps(output, indent=2) + "\n")


def stream_request(model: str, nonce: str, max_tokens: int = 192) -> dict:
    body = json.dumps(
        {
            "model": model,
            "messages": [
                {"role": "user", "content": f"{PROMPT_BASE}\nRun identifier: {nonce}."}
            ],
            "max_tokens": max_tokens,
            "temperature": 0,
            "stream": True,
            "stream_options": {"include_usage": True},
            "chat_template_kwargs": {"enable_thinking": False},
        }
    )
    connection = http.client.HTTPConnection(HOST, PORT, timeout=600)
    started = time.monotonic()
    connection.request(
        "POST",
        "/v1/chat/completions",
        body=body,
        headers={"Content-Type": "application/json"},
    )
    response = connection.getresponse()
    headers_elapsed = time.monotonic() - started
    fallback_header = response.getheader("X-Fallback")
    response_server = response.getheader("Server")
    first_token_elapsed = None
    chunks: list[dict[str, Any]] = []
    text_parts: list[str] = []
    reasoning_parts: list[str] = []
    try:
        for raw_line in response:
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if payload == "[DONE]":
                break
            chunk = json.loads(payload)
            chunks.append(chunk)
            choices = chunk.get("choices") or []
            delta = choices[0].get("delta", {}) if choices else {}
            content = delta.get("content") or ""
            reasoning = delta.get("reasoning_content") or ""
            if content.strip() and first_token_elapsed is None:
                first_token_elapsed = time.monotonic() - started
            if content:
                text_parts.append(content)
            if reasoning:
                reasoning_parts.append(reasoning)
    finally:
        connection.close()
    elapsed = time.monotonic() - started

    timings = next(
        (chunk["timings"] for chunk in reversed(chunks) if "timings" in chunk),
        None,
    )
    usage = next(
        (chunk["usage"] for chunk in reversed(chunks) if chunk.get("usage")),
        None,
    )
    error = next((chunk["error"] for chunk in chunks if "error" in chunk), None)
    completion_tokens = (usage or {}).get("completion_tokens")
    client_generation_seconds = (
        elapsed - first_token_elapsed if first_token_elapsed is not None else None
    )
    client_tokens_per_second = (
        completion_tokens / client_generation_seconds
        if completion_tokens is not None
        and client_generation_seconds is not None
        and client_generation_seconds > 0
        else None
    )
    return {
        "nonce": nonce,
        "http_status": response.status,
        "fallback_header": fallback_header,
        "response_server": response_server,
        "headers_seconds": round(headers_elapsed, 6),
        "ttft_seconds": (
            round(first_token_elapsed, 6) if first_token_elapsed is not None else None
        ),
        "elapsed_seconds": round(elapsed, 6),
        "client_generation_seconds": (
            round(client_generation_seconds, 6)
            if client_generation_seconds is not None
            else None
        ),
        "client_tokens_per_second": client_tokens_per_second,
        "content": "".join(text_parts),
        "reasoning": "".join(reasoning_parts),
        "usage": usage,
        "timings": timings,
        "error": error,
    }


def safe_stream_request(model: str, nonce: str, max_tokens: int = 192) -> dict:
    try:
        return stream_request(model, nonce, max_tokens)
    except Exception as exc:
        return {
            "nonce": nonce,
            "http_status": None,
            "fallback_header": None,
            "error": f"{type(exc).__name__}: {exc}",
        }


def request_ok(result: dict) -> bool:
    return result.get("http_status") == 200 and not result.get("fallback_header")


def main() -> None:
    args = parse_args()
    output = load_output()
    for model in args.models:
        prior = next(
            (
                item
                for item in output["models"]
                if item["model"] == model and item.get("tag", "final") == args.tag
            ),
            None,
        )
        if prior and prior.get("status") == "completed" and not args.force:
            print(f"skip completed: {model} [{args.tag}]", flush=True)
            continue

        print(f"warm: {model}", flush=True)
        cold = safe_stream_request(model, "cold-warmup", max_tokens=48)
        sequential = []
        for run_number in range(1, args.runs + 1):
            print(f"sequential: {model} {run_number}/{args.runs}", flush=True)
            sequential.append(safe_stream_request(model, f"sequential-{run_number}"))

        print(f"concurrent x{args.concurrency}: {model}", flush=True)
        concurrent_started = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=args.concurrency
        ) as executor:
            futures = [
                executor.submit(safe_stream_request, model, f"concurrent-{index + 1}")
                for index in range(args.concurrency)
            ]
            concurrent_results = [future.result() for future in futures]
        concurrent_wall = time.monotonic() - concurrent_started

        all_requests = [cold, *sequential, *concurrent_results]
        record = {
            "model": model,
            "tag": args.tag,
            "status": (
                "completed" if all(request_ok(item) for item in all_requests) else "failed"
            ),
            "cold_request": cold,
            "sequential": sequential,
            "concurrency": {
                "requests": args.concurrency,
                "wall_seconds": round(concurrent_wall, 6),
                "results": concurrent_results,
            },
        }
        output["models"] = [
            item
            for item in output["models"]
            if not (
                item["model"] == model
                and item.get("tag", "final") == args.tag
            )
        ]
        output["models"].append(record)
        save(output)
        print(f"completed: {model}", flush=True)

    save(output)
    print(f"wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
