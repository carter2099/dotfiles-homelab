#!/usr/bin/env python3
"""Standalone fixtures for steward NDJSON / JSON extract plumbing.

Run: python3 ~/scripts/test_steward_extract.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from steward.runtime import (  # noqa: E402
    _extract_json,
    _ndjson_looks_like_event_stream,
    extract_from_ndjson,
)


def _ok(name: str) -> None:
    print(f"OK  {name}")


def _fail(name: str, msg: str) -> None:
    print(f"FAIL {name}: {msg}", file=sys.stderr)
    raise SystemExit(1)


def test_legacy_deltas() -> None:
    ndjson = "\n".join([
        json.dumps({"type": "session", "id": "x"}),
        json.dumps({
            "type": "message_update",
            "assistantMessageEvent": {"type": "text_delta", "delta": "HEL"},
        }),
        json.dumps({
            "type": "message_update",
            "assistantMessageEvent": {"type": "text_delta", "delta": "LO"},
        }),
        json.dumps({
            "type": "message_end",
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": "HELLO"}],
                "usage": {"input": 1, "output": 2, "cost": {"total": 0.01}},
            },
        }),
    ])
    text, stats = extract_from_ndjson(ndjson)
    if text != "HELLO":
        _fail("legacy_deltas", f"text={text!r}")
    if stats.get("format") not in ("legacy-delta", "mixed"):
        _fail("legacy_deltas", f"format={stats.get('format')}")
    # deltas present → must not double-append message_end text
    if text == "HELLOHELLO":
        _fail("legacy_deltas", "duplicated end text")
    _ok("legacy_deltas")


def test_modern_message_end() -> None:
    body = '```json\n{"summaries":{"demo":"ok one two three"}}\n```'
    ndjson = "\n".join([
        json.dumps({"type": "agent_start"}),
        json.dumps({
            "type": "message_end",
            "message": {
                "role": "user",
                "content": [{"type": "text", "text": "hi"}],
            },
        }),
        json.dumps({
            "type": "message_end",
            "message": {
                "role": "assistant",
                "content": [
                    {"type": "thinking", "thinking": "ignore me"},
                    {"type": "text", "text": body},
                    {"type": "toolCall", "name": "bash", "arguments": {}},
                ],
                "usage": {"input": 10, "output": 20, "cost": {"total": 0.02}},
                "stopReason": "stop",
            },
        }),
    ])
    text, stats = extract_from_ndjson(ndjson)
    if text != body:
        _fail("modern_message_end", f"text={text!r}")
    if stats.get("format") != "message-end":
        _fail("modern_message_end", f"format={stats.get('format')}")
    if stats.get("input_tokens") != 10 or stats.get("output_tokens") != 20:
        _fail("modern_message_end", f"usage={stats}")
    if "ignore me" in text:
        _fail("modern_message_end", "thinking leaked")
    pkt = _extract_json(text, "modern")
    if pkt != {"summaries": {"demo": "ok one two three"}}:
        _fail("modern_message_end", f"packet={pkt}")
    _ok("modern_message_end")


def test_api_error_empty() -> None:
    ndjson = "\n".join([
        json.dumps({"type": "turn_start"}),
        json.dumps({
            "type": "message_end",
            "message": {
                "role": "assistant",
                "content": [],
                "stopReason": "error",
                "errorStatus": 403,
                "errorMessage": "403 RegionError: China only\nmore detail",
                "usage": {"input": 0, "output": 0, "cost": {"total": 0}},
            },
        }),
        json.dumps({
            "type": "agent_end",
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "x"}]},
                {
                    "role": "assistant",
                    "content": [],
                    "stopReason": "error",
                    "errorStatus": 403,
                    "errorMessage": "403 RegionError: China only\nmore detail",
                },
            ],
        }),
    ])
    text, stats = extract_from_ndjson(ndjson)
    if text.strip():
        _fail("api_error_empty", f"expected empty text, got {text!r}")
    if not stats.get("errors"):
        _fail("api_error_empty", "expected errors")
    if "403" not in stats["errors"][0]:
        _fail("api_error_empty", f"errors={stats['errors']}")
    _ok("api_error_empty")


def test_mixed_no_dup() -> None:
    ndjson = "\n".join([
        json.dumps({
            "type": "message_update",
            "assistantMessageEvent": {"type": "text_delta", "delta": "AB"},
        }),
        json.dumps({
            "type": "message_update",
            "assistantMessageEvent": {"type": "text_delta", "delta": "CD"},
        }),
        json.dumps({
            "type": "message_end",
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": "ABCD"}],
            },
        }),
    ])
    text, stats = extract_from_ndjson(ndjson)
    if text != "ABCD":
        _fail("mixed_no_dup", f"text={text!r}")
    if stats.get("format") != "mixed":
        _fail("mixed_no_dup", f"format={stats.get('format')}")
    _ok("mixed_no_dup")


def test_extract_fenced() -> None:
    raw = 'Here you go:\n```json\n{"a": 1, "b": [2, 3]}\n```\nthanks'
    pkt = _extract_json(raw, "fenced")
    if pkt != {"a": 1, "b": [2, 3]}:
        _fail("extract_fenced", f"pkt={pkt}")
    _ok("extract_fenced")


def test_extract_rejects_ndjson_bleed() -> None:
    stream = "\n".join([
        json.dumps({"type": "session", "version": 3, "id": "abc"}),
        json.dumps({"type": "agent_start"}),
        json.dumps({
            "type": "message_start",
            "message": {"role": "user", "content": [{"type": "text", "text": "hi"}]},
        }),
    ])
    if not _ndjson_looks_like_event_stream(stream):
        _fail("ndjson_detect", "should detect event stream")
    try:
        _extract_json(stream, "bleed")
    except ValueError as e:
        if "NDJSON" not in str(e) and "ndjson" not in str(e).lower():
            _fail("extract_rejects_ndjson_bleed", f"wrong error: {e}")
    else:
        _fail("extract_rejects_ndjson_bleed", "expected ValueError")
    _ok("extract_rejects_ndjson_bleed")


def test_extract_brace_balanced() -> None:
    # Prose + nested arrays/objects; greedy regex would over-eat.
    packet = {"ok": True, "items": [1, 2, {"n": "x"}]}
    prose = (
        "Result follows.\n"
        + json.dumps(packet)
        + "\nTrailing notes with {not json} braces."
    )
    pkt = _extract_json(prose, "balanced")
    if pkt != packet:
        _fail("extract_brace_balanced", f"pkt={pkt}")
    _ok("extract_brace_balanced")


def test_multi_turn_join() -> None:
    ndjson = "\n".join([
        json.dumps({
            "type": "message_end",
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": "FIRST\n"}],
            },
        }),
        json.dumps({
            "type": "message_end",
            "message": {
                "role": "assistant",
                "content": [{"type": "text", "text": "```json\n{\"v\":2}\n```"}],
            },
        }),
    ])
    text, stats = extract_from_ndjson(ndjson)
    if "FIRST" not in text or '{"v":2}' not in text.replace(" ", ""):
        # extract from joined text should get last fence
        pass
    pkt = _extract_json(text, "multi")
    if pkt != {"v": 2}:
        _fail("multi_turn_join", f"text={text!r} pkt={pkt}")
    _ok("multi_turn_join")


def main() -> None:
    test_legacy_deltas()
    test_modern_message_end()
    test_api_error_empty()
    test_mixed_no_dup()
    test_extract_fenced()
    test_extract_rejects_ndjson_bleed()
    test_extract_brace_balanced()
    test_multi_turn_join()
    print("ALL PASSED")


if __name__ == "__main__":
    main()
