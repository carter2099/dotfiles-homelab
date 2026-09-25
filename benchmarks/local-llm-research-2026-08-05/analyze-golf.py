#!/usr/bin/env python3
"""Extract timing, tool, and final-response evidence from OMP golf runs."""

from __future__ import annotations

from collections import defaultdict
import json
import re
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RUNS_PATH = ROOT / "golf-runs.json"
OUTPUT_PATH = ROOT / "golf-analysis.json"


def content_text(message: dict) -> str:
    return "".join(
        item.get("text", "")
        for item in message.get("content", [])
        if item.get("type") == "text"
    )


def load_events(path: Path) -> list[tuple[float, dict]]:
    events = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            wrapper = json.loads(line)
            received = wrapper["received_monotonic_seconds"]
            event = wrapper["event"]
        except json.JSONDecodeError:
            timestamp, payload = line.split(" ", 1)
            hours, minutes, seconds = timestamp.split(":")
            received = int(hours) * 3600 + int(minutes) * 60 + float(seconds)
            event = json.loads(payload)
        events.append((received, event))
    return events


def analyze_run(run: dict) -> dict:
    events = load_events(ROOT / run["raw_file"])
    pending_turn_start = None
    active_inference = None
    model_turns = []
    tool_starts: dict[str, tuple[float, dict]] = {}
    tools = []
    final_answer = ""
    advisor_messages = []
    agent_end_seconds = None

    for received, event in events:
        event_type = event.get("type")
        if event_type == "turn_start":
            pending_turn_start = received
        elif event_type == "message_start":
            message = event.get("message", {})
            if message.get("role") == "assistant":
                initial_content = "".join(
                    item.get("thinking", "") + item.get("text", "")
                    for item in message.get("content", [])
                )
                loading_prefix = (
                    "llama-swap loading model:" in initial_content
                    or "━" in initial_content
                )
                active_inference = {
                    "request_start_seconds": pending_turn_start,
                    "message_start_seconds": received,
                    "first_token_seconds": None,
                    "ttft_seconds": None,
                    "loading_state": loading_prefix and "Done!" not in initial_content,
                    "loading_finished": loading_prefix and "Done!" in initial_content,
                    "loading_text": initial_content if loading_prefix else "",
                }
            elif message.get("role") == "custom" and message.get("customType") == "advisor":
                advisor_messages.append(message.get("content", ""))
        elif event_type == "message_update" and active_inference is not None:
            update = event.get("assistantMessageEvent", {})
            delta = update.get("delta") or ""
            if (
                "llama-swap loading model:" in delta
                or (
                    "━" in delta
                    and active_inference["first_token_seconds"] is None
                    and not active_inference["loading_finished"]
                )
            ):
                active_inference["loading_state"] = True
            if active_inference["loading_state"]:
                active_inference["loading_text"] += delta
                if "Done!" in active_inference["loading_text"]:
                    active_inference["loading_state"] = False
                    active_inference["loading_finished"] = True
                continue
            if active_inference["loading_finished"]:
                if not delta.strip() or set(delta.strip()) <= {"━"}:
                    continue
                active_inference["loading_finished"] = False
            if (
                update.get("type") in {"thinking_delta", "text_delta", "toolcall_delta"}
                and delta.strip()
                and active_inference["first_token_seconds"] is None
            ):
                active_inference["first_token_seconds"] = received
                if active_inference["request_start_seconds"] is not None:
                    active_inference["ttft_seconds"] = (
                        received - active_inference["request_start_seconds"]
                    )
        elif event_type == "message_end":
            message = event.get("message", {})
            if message.get("role") == "assistant" and active_inference is not None:
                first_token_seconds = (
                    active_inference["first_token_seconds"]
                    or active_inference["message_start_seconds"]
                )
                active_inference["first_token_seconds"] = first_token_seconds
                if (
                    active_inference["ttft_seconds"] is None
                    and active_inference["request_start_seconds"] is not None
                ):
                    active_inference["ttft_seconds"] = (
                        first_token_seconds - active_inference["request_start_seconds"]
                    )
                usage = message.get("usage") or {}
                output_tokens = usage.get("output")
                generation_seconds = received - first_token_seconds
                active_inference.update(
                    {
                        "end_seconds": received,
                        "generation_seconds": generation_seconds,
                        "output_tokens": output_tokens,
                        "generation_tokens_per_second": (
                            output_tokens / generation_seconds
                            if output_tokens is not None and generation_seconds > 0
                            else None
                        ),
                        "stop_reason": message.get("stopReason"),
                        "response_id": message.get("responseId"),
                        "has_tool_call": any(
                            item.get("type") == "toolCall"
                            for item in message.get("content", [])
                        ),
                    }
                )
                text = content_text(message)
                if text:
                    final_answer = text
                model_turns.append(active_inference)
                active_inference = None
        elif event_type == "tool_execution_start":
            tool_starts[event["toolCallId"]] = (received, event)
        elif event_type == "tool_execution_end":
            start = tool_starts.pop(event["toolCallId"], None)
            tools.append(
                {
                    "tool_call_id": event["toolCallId"],
                    "name": event.get("toolName"),
                    "args": start[1].get("args") if start else None,
                    "intent": start[1].get("intent") if start else None,
                    "started_seconds": start[0] if start else None,
                    "duration_seconds": received - start[0] if start else None,
                    "result_excerpt": content_text(event.get("result", {}))[:2000],
                    "is_error": bool(event.get("isError")),
                }
            )
        elif event_type == "agent_end":
            agent_end_seconds = received
            if not final_answer:
                for message in reversed(event.get("messages", [])):
                    if message.get("role") == "assistant":
                        text = content_text(message)
                        if text:
                            final_answer = text
                            break

    severity_counts: dict[str, int] = {}
    for message in advisor_messages:
        severities = re.findall(r'<advisory severity="([^"]+)"', message)
        if not severities:
            severities = ["unknown"]
        for severity in severities:
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

    valid_ttft = [
        turn["ttft_seconds"]
        for turn in model_turns
        if turn["ttft_seconds"] is not None
    ]
    valid_tps = [
        turn["generation_tokens_per_second"]
        for turn in model_turns
        if turn["generation_tokens_per_second"] is not None
    ]
    return {
        **run,
        "agent_end_seconds": agent_end_seconds,
        "model_turn_count": len(model_turns),
        "model_turns": model_turns,
        "initial_ttft_seconds": model_turns[0]["ttft_seconds"] if model_turns else None,
        "total_output_tokens": sum(
            turn["output_tokens"]
            for turn in model_turns
            if turn["output_tokens"] is not None
        ),
        "mean_ttft_seconds": sum(valid_ttft) / len(valid_ttft) if valid_ttft else None,
        "mean_generation_tokens_per_second": (
            sum(valid_tps) / len(valid_tps) if valid_tps else None
        ),
        "tool_call_count": len(tools),
        "tools": tools,
        "tool_errors": sum(tool["is_error"] for tool in tools),
        "advisor_messages": advisor_messages,
        "advisor_severity_counts": severity_counts,
        "final_answer": final_answer,
    }


def mean_present(values: list[float | None]) -> float | None:
    present = [value for value in values if value is not None]
    return statistics.mean(present) if present else None


def main() -> None:
    runs = json.loads(RUNS_PATH.read_text())
    analyzed = [analyze_run(run) for run in runs["runs"]]
    by_model: dict[str, list[dict]] = defaultdict(list)
    for run in analyzed:
        by_model[run["model"]].append(run)

    summary = {}
    for model, model_runs in by_model.items():
        severity_counts: dict[str, int] = {}
        for run in model_runs:
            for severity, count in run["advisor_severity_counts"].items():
                severity_counts[severity] = severity_counts.get(severity, 0) + count
        summary[model] = {
            "runs": len(model_runs),
            "completed_runs": sum(run["status"] == "completed" for run in model_runs),
            "mean_duration_seconds": statistics.mean(
                run["duration_seconds"] for run in model_runs
            ),
            "mean_initial_ttft_seconds": mean_present(
                [run["initial_ttft_seconds"] for run in model_runs]
            ),
            "mean_turn_ttft_seconds": mean_present(
                [run["mean_ttft_seconds"] for run in model_runs]
            ),
            "mean_generation_tokens_per_second": mean_present(
                [run["mean_generation_tokens_per_second"] for run in model_runs]
            ),
            "total_model_turns": sum(run["model_turn_count"] for run in model_runs),
            "total_tool_calls": sum(run["tool_call_count"] for run in model_runs),
            "runs_with_tools": sum(run["tool_call_count"] > 0 for run in model_runs),
            "total_tool_errors": sum(run["tool_errors"] for run in model_runs),
            "advisor_severity_counts": severity_counts,
        }

    output = {
        "prompt": runs["prompt"],
        "summary": summary,
        "runs": analyzed,
    }
    OUTPUT_PATH.write_text(json.dumps(output, indent=2) + "\n")
    print(f"wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
