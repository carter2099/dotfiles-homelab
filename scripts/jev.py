"""Shared bounded client for TypeSafe's Jev System One model.

Jev answers typed questions (Score, Choice, Noul) about a supplied state with
calibrated probabilities. Every homelab caller (Daily News, the steward) uses
this one module: one pinned model, one key path, one retry/deadline policy and
one consecutive-failure breaker. A failure is always ``JevUnavailable``; the
caller treats it as "unknown", never as a default answer.
"""

from __future__ import annotations

import math
import threading
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Callable

import requests

API_URL = "https://api.typesafe.ai/v1/systemone"
# Pinned: News adjudication and importance thresholds were benchmarked on this version.
MODEL = "jev-1.13.0"
KEY_PATH = Path.home() / ".local/state/typesafe/api-key"
REQUEST_TIMEOUT_SECONDS = 30.0
MAX_ATTEMPTS = 3
MAX_RETRY_DELAY_SECONDS = 20.0
BREAKER_FAILURES = 3

REASONS = frozenset({
    "no_key", "deadline", "breaker_open", "http", "rate", "server",
    "network", "malformed", "incomplete", "model_mismatch",
})


class JevUnavailable(RuntimeError):
    """Jev could not answer inside the caller's bounds; ``reason`` is one of ``REASONS``."""

    def __init__(self, reason: str, detail: str = "") -> None:
        if reason not in REASONS:
            raise ValueError(f"unknown JevUnavailable reason {reason!r}")
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


def gate(confidence: float, act: float = 0.9, review: float = 0.6) -> str:
    """Map a confidence to ``ACT``, ``REVIEW`` or ``UNKNOWN``; there is no default label."""
    if not _number(confidence, 0.0, 1.0) or not 0.0 <= review <= act <= 1.0:
        return "UNKNOWN"
    if confidence >= act:
        return "ACT"
    if confidence >= review:
        return "REVIEW"
    return "UNKNOWN"


def noul_certainty(p: float) -> float:
    """Noul answers carry no confidence field; ``|2p - 1|`` is how far p is from a coin flip."""
    return abs(2.0 * float(p) - 1.0)


def _number(value: Any, low: float, high: float) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and low <= value <= high
    )


def _retry_delay(response: Any, attempt: int) -> float:
    delay = float(2 ** attempt)
    value = (getattr(response, "headers", None) or {}).get("retry-after")
    if value:
        try:
            delay = float(value)
        except ValueError:
            try:
                delay = (parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()
            except (TypeError, ValueError):
                pass
    return min(max(delay, 0.5), MAX_RETRY_DELAY_SECONDS)


def _valid_answer(question: dict[str, Any], answer: Any) -> bool:
    if not isinstance(answer, dict) or answer.get("type") != question.get("type"):
        return False
    if question["type"] == "noul":
        return _number(answer.get("noul"), 0.0, 1.0)
    if not _number(answer.get("confidence"), 0.0, 1.0):
        return False
    if question["type"] == "score":
        criteria = question.get("criteria")
        top = len(criteria) - 1 if isinstance(criteria, (list, dict)) and criteria else math.inf
        return _number(answer.get("score"), 0.0, top)
    value = answer.get("choice")
    return isinstance(value, str) and bool(value)


class JevClient:
    """Thread-safe Jev caller: retries never cross the shared deadline, and after
    ``breaker`` consecutive failed asks every ask fails fast without a request."""

    def __init__(
        self,
        api_key: str,
        *,
        model: str = MODEL,
        deadline: float | None = None,
        breaker: int = BREAKER_FAILURES,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        post: Callable[..., Any] | None = None,
    ) -> None:
        self.model = model
        self.deadline = deadline
        self.breaker = breaker
        self._key = api_key
        self._clock = clock
        self._sleep = sleep
        self._post = post
        self._local = threading.local()
        self._lock = threading.Lock()
        self._consecutive_failures = 0
        self.attempts = 0
        self.requests = 0
        self.input_tokens = 0
        self.failures = 0
        self.failure_reasons: dict[str, int] = {}
        self.purposes: dict[str, dict[str, int]] = {}

    def _remaining(self) -> float | None:
        return None if self.deadline is None else self.deadline - self._clock()

    def _send(self, payload: dict[str, Any], timeout: float) -> Any:
        if self._post is not None:
            return self._post(API_URL, json=payload, timeout=timeout)
        session = getattr(self._local, "session", None)
        if session is None:
            session = requests.Session()
            session.headers.update({"Authorization": f"Bearer {self._key}",
                                    "Content-Type": "application/json"})
            self._local.session = session
        return session.post(API_URL, json=payload, timeout=timeout)

    def _record(self, purpose: str, reason: str | None) -> None:
        with self._lock:
            stats = self.purposes.setdefault(purpose, {"asks": 0, "failures": 0})
            stats["asks"] += 1
            if reason is None:
                self._consecutive_failures = 0
                return
            stats["failures"] += 1
            self.failure_reasons[reason] = self.failure_reasons.get(reason, 0) + 1
            if reason != "breaker_open":
                self.failures += 1
                self._consecutive_failures += 1

    def ask(
        self, purpose: str, state: Any, questions: dict[str, dict[str, Any]]
    ) -> dict[str, dict[str, Any]]:
        """Return validated answers keyed like ``questions`` or raise ``JevUnavailable``.

        ``purpose`` is a short tag (e.g. ``news.relation``) used in ``usage()``.
        """
        with self._lock:
            open_breaker = self._consecutive_failures >= self.breaker
        if open_breaker:
            self._record(purpose, "breaker_open")
            raise JevUnavailable("breaker_open", f"{self.breaker} consecutive Jev failures")
        try:
            answers = self._ask(state, questions)
        except JevUnavailable as error:
            self._record(purpose, error.reason)
            raise
        self._record(purpose, None)
        return answers

    def _ask(self, state: Any, questions: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
        payload = {"model": self.model, "state": state, "questions": questions}
        reason, detail = "deadline", "no attempt made"
        for attempt in range(MAX_ATTEMPTS):
            remaining = self._remaining()
            if remaining is not None and remaining <= 1.0:
                raise JevUnavailable("deadline", "Jev deadline reached")
            timeout = REQUEST_TIMEOUT_SECONDS if remaining is None else min(REQUEST_TIMEOUT_SECONDS, remaining)
            with self._lock:
                self.attempts += 1
            try:
                response = self._send(payload, timeout)
            except requests.RequestException as error:
                reason, detail = "network", " ".join(str(error).split())[:200]
                response = None
            else:
                if response.status_code == 200:
                    try:
                        body = response.json()
                        answers = body["answers"]
                        tokens = int((body.get("usage") or {}).get("input_tokens") or 0)
                    except (ValueError, KeyError, TypeError, AttributeError):
                        reason, detail = "malformed", "malformed Jev response"
                    else:
                        with self._lock:
                            self.input_tokens += tokens
                        answered = body.get("model")
                        if answered is not None and answered != self.model:
                            raise JevUnavailable("model_mismatch", f"answered by {answered}, pinned {self.model}")
                        if isinstance(answers, dict) and all(
                            _valid_answer(question, answers.get(key)) for key, question in questions.items()
                        ):
                            with self._lock:
                                self.requests += 1
                            return answers
                        reason, detail = "incomplete", "Jev response did not answer every question"
                elif response.status_code == 429:
                    reason, detail = "rate", "HTTP 429"
                elif response.status_code >= 500:
                    reason, detail = "server", f"HTTP {response.status_code}"
                else:
                    raise JevUnavailable("http", f"HTTP {response.status_code}")
            if attempt + 1 < MAX_ATTEMPTS:
                delay = _retry_delay(response, attempt)
                remaining = self._remaining()
                if remaining is not None and delay >= remaining - 1.0:
                    raise JevUnavailable("deadline", f"{detail}; retry would cross the Jev deadline")
                self._sleep(delay)
        raise JevUnavailable(reason, detail)

    def usage(self) -> dict[str, Any]:
        """Counters for artifacts and health logs; ``attempts`` counts every POST sent (billed or not)."""
        with self._lock:
            return {
                "model": self.model,
                "attempts": self.attempts,
                "requests": self.requests,
                "input_tokens": self.input_tokens,
                "failures": self.failures,
                "failure_reasons": dict(self.failure_reasons),
                "purposes": {name: dict(stats) for name, stats in self.purposes.items()},
            }


def load_client(**kwargs: Any) -> JevClient | None:
    """Build a client from ``KEY_PATH``, or ``None`` when no key is provisioned."""
    try:
        key = KEY_PATH.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return JevClient(key, **kwargs) if key else None
