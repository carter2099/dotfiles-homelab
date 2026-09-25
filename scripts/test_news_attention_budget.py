#!/usr/bin/env python3
"""Behavioral contracts for bounded snapshot collection, reuse, and Jev calls."""

from __future__ import annotations

import tempfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from daily_news import attention_sources
from daily_news.attention_sources import SourceSkipped, collect_snapshot, load_or_build_snapshot
from jev import JevClient, JevUnavailable, gate, noul_certainty

WINDOW_END = datetime(2026, 9, 24, 6, 0, tzinfo=timezone.utc)


def check(condition: bool, message: object) -> None:
    if not condition:
        raise AssertionError(message)


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.value += seconds


def _ok(rows: list[dict], *, incomplete: str = ""):
    def collector(ctx):
        check(ctx.window_end == WINDOW_END and ctx.window_start == WINDOW_END - timedelta(hours=30), ctx)
        return rows, {"note": "fixture", **({"incomplete": incomplete} if incomplete else {})}
    return collector


def _raise(error: Exception):
    def collector(ctx):
        raise error
    return collector


def test_failed_and_skipped_sources_stay_explicit() -> None:
    snapshot = collect_snapshot(
        WINDOW_END,
        sources=("gkg", "hn", "jetstream", "mastodon"),
        now=WINDOW_END,
        collectors={
            "gkg": _ok([{"src": "gkg", "title": "A"}]),
            "mastodon": _ok([{"src": "mastodon", "title": "M"}], incomplete="1 of 6 Mastodon instances failed"),
            "hn": _raise(TimeoutError("attention snapshot budget exhausted")),
            "jetstream": _raise(SourceSkipped("window is older than Jetstream replay retention")),
        },
    )
    sources = snapshot["sources"]
    check(sources["gkg"]["status"] == "ok" and sources["gkg"]["rows"] == 1, sources)
    check(sources["hn"]["status"] == "unavailable" and "budget exhausted" in sources["hn"]["error"], sources)
    check(sources["jetstream"]["status"] == "skipped", sources)
    check(sources["mastodon"]["status"] == "partial" and sources["mastodon"]["rows"] == 1, sources)
    check(sorted(row["title"] for row in snapshot["rows"]) == ["A", "M"], snapshot["rows"])
    check(len(snapshot["id"]) == 16, snapshot["id"])


def test_live_only_sources_cannot_observe_a_past_window() -> None:
    called: list[str] = []

    def record(name: str):
        def collector(ctx):
            called.append(name)
            return [], {}
        return collector

    snapshot = collect_snapshot(
        WINDOW_END,
        sources=("gkg", "techmeme", "mastodon"),
        now=WINDOW_END + timedelta(hours=12),
        collectors={name: record(name) for name in ("gkg", "techmeme", "mastodon")},
    )
    check(called == ["gkg"], called)
    check(snapshot["sources"]["techmeme"]["status"] == "skipped", snapshot["sources"])
    check(snapshot["sources"]["gkg"]["status"] == "ok", snapshot["sources"])


def test_snapshot_is_shared_and_incomplete_sources_retry_a_bounded_number_of_times() -> None:
    calls: list[tuple[str, ...]] = []

    def collect(window_end, *, sources=("gkg", "hn"), now=None, budget_seconds=0.0):
        calls.append(tuple(sources))
        attempt = len(calls)
        gkg = {
            1: _ok([{"src": "gkg", "title": "A"}], incomplete="1 of 2 GKG files unavailable"),
            2: _raise(RuntimeError("HTTP 503")),
        }.get(attempt, _ok([{"src": "gkg", "title": "A"}, {"src": "gkg", "title": "A2"}]))
        return collect_snapshot(window_end, sources=sources, now=now,
                                collectors={"gkg": gkg, "hn": _raise(RuntimeError("HTTP 503"))})

    edition = date(2026, 9, 24)
    start = WINDOW_END + timedelta(minutes=30)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        first = load_or_build_snapshot(root, edition, now=start, collect=collect)
        check(calls == [("gkg", "hn"), ("gkg", "hn")] and not first["reused"], calls)
        # A worse retry never discards the partial inventory it was meant to improve.
        check(first["sources"]["gkg"]["status"] == "partial", first["sources"])
        check([row["title"] for row in first["rows"]] == ["A"], first["rows"])
        second = load_or_build_snapshot(root, edition, now=start + timedelta(hours=1), collect=collect)
        check(calls[-1] == ("gkg", "hn") and second["reused"], calls)
        check(second["sources"]["gkg"]["status"] == "ok", second["sources"])
        check(sorted(row["title"] for row in second["rows"]) == ["A", "A2"], second["rows"])
        check(second["sources"]["hn"]["status"] == "unavailable" and second["sources"]["hn"]["attempts"] == 3,
              second["sources"])
        check(second["id"] != first["id"], (first["id"], second["id"]))
        third = load_or_build_snapshot(root, edition, now=start + timedelta(hours=2), collect=collect)
        check(len(calls) == 3 and third["id"] == second["id"], calls)
        for day in range(1, 5):
            (root / f"2026-09-0{day}").mkdir()
        attention_sources.prune_snapshots(root, keep=3)
        check(sorted(child.name for child in root.iterdir()) == ["2026-09-03", "2026-09-04", "2026-09-24"],
              sorted(child.name for child in root.iterdir()))


def test_window_ends_on_a_published_quarter_hour_and_never_after_noon() -> None:
    edition = date(2026, 9, 24)
    run = datetime(2026, 9, 24, 6, 20, 14, tzinfo=timezone.utc)
    check(attention_sources.default_window_end(edition, run) == datetime(2026, 9, 24, 5, 45, tzinfo=timezone.utc),
          attention_sources.default_window_end(edition, run))
    late = datetime(2026, 9, 24, 15, 0, tzinfo=timezone.utc)
    check(attention_sources.default_window_end(edition, late) == datetime(2026, 9, 24, 12, tzinfo=timezone.utc),
          attention_sources.default_window_end(edition, late))


class FakeResponse:
    def __init__(self, status: int, body: dict | None = None, headers: dict | None = None) -> None:
        self.status_code = status
        self._body = body or {}
        self.headers = headers or {}

    def json(self) -> dict:
        return self._body


QUESTIONS = {"same": {"type": "noul", "instructions": "Same event?"}}


def test_jev_retries_rate_limits_within_its_deadline() -> None:
    clock = FakeClock()
    responses = [
        FakeResponse(429, headers={"retry-after": "3"}),
        FakeResponse(200, {"answers": {"same": {"type": "noul", "noul": 0.9}}, "usage": {"input_tokens": 120}}),
    ]
    client = JevClient("key", deadline=60.0, clock=clock, sleep=clock.sleep,
                       post=lambda *args, **kwargs: responses.pop(0))
    answers = client.ask("test", {"story": "x"}, QUESTIONS)
    check(answers["same"]["noul"] == 0.9, answers)
    check(clock.sleeps == [3.0], clock.sleeps)
    check(client.usage()["input_tokens"] == 120 and client.usage()["failures"] == 0, client.usage())
    check(client.usage()["attempts"] == 2 and client.usage()["requests"] == 1, client.usage())


def test_jev_never_sleeps_past_its_deadline_or_accepts_partial_answers() -> None:
    clock = FakeClock()
    client = JevClient("key", deadline=5.0, clock=clock, sleep=clock.sleep,
                       post=lambda *args, **kwargs: FakeResponse(429, headers={"retry-after": "20"}))
    try:
        client.ask("test", {"story": "x"}, QUESTIONS)
    except JevUnavailable as error:
        check(error.reason == "deadline", error)
    else:
        raise AssertionError("a retry that crosses the deadline must fail fast")
    check(clock.sleeps == [], clock.sleeps)

    partial = JevClient("key", clock=clock, sleep=clock.sleep,
                        post=lambda *args, **kwargs: FakeResponse(200, {"answers": {}}))
    try:
        partial.ask("test", {"story": "x"}, QUESTIONS)
    except JevUnavailable as error:
        check(error.reason == "incomplete", error)
    else:
        raise AssertionError("an answer missing a question must not be accepted")

    rejected = JevClient("key", clock=clock, sleep=clock.sleep,
                         post=lambda *args, **kwargs: FakeResponse(401))
    try:
        rejected.ask("test", {"story": "x"}, QUESTIONS)
    except JevUnavailable as error:
        check(error.reason == "http" and "401" in str(error), error)
    else:
        raise AssertionError("authentication failures are not retried")
    check(rejected.usage()["failures"] == 1, rejected.usage())


def test_jev_breaker_opens_after_three_failed_asks_and_a_success_resets_it() -> None:
    clock = FakeClock()
    posts: list[int] = []
    status = [503]

    def post(*args, **kwargs):
        posts.append(status[0])
        if status[0] == 200:
            return FakeResponse(200, {"answers": {"same": {"type": "noul", "noul": 0.2}}})
        return FakeResponse(status[0])

    client = JevClient("key", clock=clock, sleep=clock.sleep, post=post)
    for _ in range(3):
        try:
            client.ask("test", {"story": "x"}, QUESTIONS)
        except JevUnavailable as error:
            check(error.reason == "server", error)
        else:
            raise AssertionError("a 503 outage must fail")
    sent = len(posts)
    check(sent == 9, posts)  # three asks x three attempts
    for _ in range(5):
        try:
            client.ask("test", {"story": "x"}, QUESTIONS)
        except JevUnavailable as error:
            check(error.reason == "breaker_open", error)
        else:
            raise AssertionError("an open breaker must not send")
    check(len(posts) == sent, "an open breaker sent requests")
    usage = client.usage()
    check(usage["failures"] == 3 and usage["failure_reasons"] == {"server": 3, "breaker_open": 5}, usage)
    check(usage["attempts"] == 9 and usage["purposes"]["test"] == {"asks": 8, "failures": 8}, usage)

    status[0] = 200
    healthy = JevClient("key", clock=clock, sleep=clock.sleep, post=post)
    for code in (503, 200, 503, 503):
        status[0] = code
        try:
            healthy.ask("test", {"story": "x"}, QUESTIONS)
        except JevUnavailable:
            pass
    status[0] = 200
    check(healthy.ask("test", {"story": "x"}, QUESTIONS)["same"]["noul"] == 0.2, "a success resets the breaker")


def test_jev_rejects_non_numeric_or_out_of_range_answers_and_foreign_models() -> None:
    clock = FakeClock()
    score_q = {"level": {"type": "score", "instructions": "How big?", "criteria": ["small", "medium", "large"]}}
    bad_scores = ["2", True, None, float("nan"), -0.1, 2.5]
    for bad in bad_scores:
        client = JevClient("key", clock=clock, sleep=clock.sleep,
                           post=lambda *a, bad=bad, **k: FakeResponse(
                               200, {"answers": {"level": {"type": "score", "score": bad, "confidence": 0.9}}}))
        try:
            client.ask("test", {"story": "x"}, score_q)
        except JevUnavailable as error:
            check(error.reason == "incomplete", error)
        else:
            raise AssertionError(f"score {bad!r} must be rejected")
    for bad in (True, "0.9", 1.5):
        client = JevClient("key", clock=clock, sleep=clock.sleep,
                           post=lambda *a, bad=bad, **k: FakeResponse(
                               200, {"answers": {"same": {"type": "noul", "noul": bad}}}))
        try:
            client.ask("test", {"story": "x"}, QUESTIONS)
        except JevUnavailable as error:
            check(error.reason == "incomplete", error)
        else:
            raise AssertionError(f"noul {bad!r} must be rejected")
    good = JevClient("key", clock=clock, sleep=clock.sleep,
                     post=lambda *a, **k: FakeResponse(
                         200, {"model": "jev-1.13.0",
                               "answers": {"level": {"type": "score", "score": 2, "confidence": 0.9}}}))
    check(good.ask("test", {"story": "x"}, score_q)["level"]["score"] == 2, "an in-range integer score is valid")
    foreign = JevClient("key", clock=clock, sleep=clock.sleep,
                        post=lambda *a, **k: FakeResponse(
                            200, {"model": "jev-2.0.0", "answers": {"same": {"type": "noul", "noul": 0.5}}}))
    try:
        foreign.ask("test", {"story": "x"}, QUESTIONS)
    except JevUnavailable as error:
        check(error.reason == "model_mismatch", error)
    else:
        raise AssertionError("an answer from another model must be rejected")
    check(gate(0.95) == "ACT" and gate(0.7) == "REVIEW" and gate(0.5) == "UNKNOWN", "gate levels")
    check(gate(True) == "UNKNOWN" and gate(float("nan")) == "UNKNOWN", "gate rejects non-numbers")
    check(noul_certainty(0.5) == 0.0 and noul_certainty(0.0) == 1.0, "noul certainty")


def main() -> None:
    tests = [
        test_failed_and_skipped_sources_stay_explicit,
        test_live_only_sources_cannot_observe_a_past_window,
        test_snapshot_is_shared_and_incomplete_sources_retry_a_bounded_number_of_times,
        test_window_ends_on_a_published_quarter_hour_and_never_after_noon,
        test_jev_retries_rate_limits_within_its_deadline,
        test_jev_never_sleeps_past_its_deadline_or_accepts_partial_answers,
        test_jev_breaker_opens_after_three_failed_asks_and_a_success_resets_it,
        test_jev_rejects_non_numeric_or_out_of_range_answers_and_foreign_models,
    ]
    for test in tests:
        test()
        print(f"OK  {test.__name__}")
    print("ALL PASSED")


if __name__ == "__main__":
    main()
