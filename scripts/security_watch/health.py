"""The one health check: what a deploy's health gate and the hourly self-check both run.

A component's ``health`` URLs are loopback origins; ``health_host`` names the Host header
an origin routes by (herdr-web-client answers 404 to a bare ``127.0.0.1`` request, which
held the breaker open 2026-11-24..26 when repo-pr had its own probe without it).  A URL
is healthy once it answers below 400 (a redirect is not followed: it is itself healthy).
"""

from __future__ import annotations

import contextlib
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable

from security_watch import config

HEALTH_BUDGET_SECONDS = 60.0
HEALTH_POLL_SECONDS = 2.0

Probe = Callable[[str, str], int]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # a 3xx answer is itself healthy
        return None


def http_status(url: str, host: str = "", timeout: float = 10.0) -> int:
    """HTTP status of a loopback GET (0 when unreachable or not loopback)."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "http" or parts.hostname != "127.0.0.1":
        return 0
    headers = {"User-Agent": config.USER_AGENT}
    if host:
        headers["Host"] = host
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
    try:
        with opener.open(urllib.request.Request(url, headers=headers), timeout=timeout) as resp:
            return int(resp.status)
    except urllib.error.HTTPError as exc:
        with contextlib.suppress(Exception):
            exc.close()
        return int(exc.code)
    except Exception:
        return 0


def host_of(spec: config.ComponentSpec) -> str:
    return str(spec.get("health_host", "") or "")


def probe_url(url: str, host: str, *, probe: Probe = http_status,
              sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic,
              deadline: float) -> tuple[bool, str]:
    """Poll one URL until it answers below 400 or ``deadline`` (a ``clock`` value) passes."""
    while True:
        status = probe(url, host)
        if 0 < status < 400:
            return True, f"{url} {status}"
        if clock() >= deadline:
            return False, f"{url} answered {status or 'nothing'}"
        sleep(HEALTH_POLL_SECONDS)


def check_health(spec: config.ComponentSpec, *, probe: Probe = http_status,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic,
                 budget: float = HEALTH_BUDGET_SECONDS) -> tuple[bool, str]:
    """GET every spec.health URL until status < 400, retrying within ``budget`` seconds."""
    deadline = clock() + budget
    seen: list[str] = []
    for url in spec.health:
        ok, detail = probe_url(url, host_of(spec), probe=probe, sleep=sleep, clock=clock, deadline=deadline)
        if not ok:
            return False, f"{detail} within {int(budget)}s"
        seen.append(detail)
    return True, "; ".join(seen) or "no health URLs"
