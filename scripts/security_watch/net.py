"""Allowlisted HTTP client for security-watch (urllib only).

Every network request of the watcher goes through :func:`fetch`, which refuses hosts
outside ``config.ALLOWED_HOSTS``, non-http(s) schemes and oversized bodies.
"""

from __future__ import annotations

import http.client
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

from security_watch import config


class FetchError(Exception):
    def __init__(self, url: str, status: int | None, reason: str):
        super().__init__(f"{url}: {status if status is not None else 'error'}: {reason}")
        self.url = url
        self.status = status
        self.reason = reason


@dataclass
class Response:
    status: int
    headers: dict[str, str]   # lower-case keys
    body: bytes
    url: str

    def json(self) -> Any:
        return json.loads(self.body)

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


Fetch = Callable[..., Response]


def _check_url(url: str) -> None:
    try:
        parts = urllib.parse.urlsplit(url)
        host = (parts.hostname or "").lower()
        parts.port  # raises ValueError on a malformed port
    except ValueError as exc:
        raise FetchError(url, None, f"invalid url: {exc}") from None
    if parts.scheme not in ("http", "https"):
        raise FetchError(url, None, "scheme not allowed")
    if parts.username is not None or parts.password is not None:
        raise FetchError(url, None, "credentials in url not allowed")
    if host not in config.ALLOWED_HOSTS:
        raise FetchError(url, None, "host not allowed")


def _headers(raw: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    if raw is None:
        return out
    for name, value in raw.items():
        key = str(name).lower()
        out[key] = f"{out[key]}, {value}" if key in out else str(value)
    return out


def _read_limited(stream: Any, url: str, status: int | None, max_bytes: int) -> bytes:
    body = stream.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise FetchError(url, status, f"body larger than {max_bytes} bytes")
    return body


def fetch(url: str, *, method: str = "GET", body: bytes | None = None, headers: dict | None = None,
          timeout: float = 20, max_bytes: int = 16_000_000, etag: str | None = None,
          last_modified: str | None = None) -> Response:
    _check_url(url)
    request_headers = {str(k): str(v) for k, v in (headers or {}).items()
                       if str(k).lower() != "user-agent"}
    request_headers["User-Agent"] = config.USER_AGENT
    if etag:
        request_headers["If-None-Match"] = etag
    if last_modified:
        request_headers["If-Modified-Since"] = last_modified
    request = urllib.request.Request(url, data=body, headers=request_headers, method=method.upper())
    try:
        resp = urllib.request.urlopen(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        try:
            if exc.code == 304:
                return Response(status=304, headers=_headers(exc.headers), body=b"", url=url)
            reason = str(exc.reason or "") or f"HTTP {exc.code}"
            raise FetchError(url, exc.code, reason) from None
        finally:
            exc.close()
    except (urllib.error.URLError, http.client.HTTPException, socket.timeout, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", None) or exc
        raise FetchError(url, None, str(reason) or type(exc).__name__) from None
    try:
        status = int(getattr(resp, "status", None) or resp.getcode() or 0)
        final_url = resp.geturl() if hasattr(resp, "geturl") else url
        if final_url and final_url != url:
            # urlopen follows redirects itself; never accept content served by another host.
            try:
                _check_url(final_url)
            except FetchError as exc:
                raise FetchError(url, status, f"redirected to {final_url}: {exc.reason}") from None
        response_headers = _headers(getattr(resp, "headers", None))
        if status == 304:
            return Response(status=304, headers=response_headers, body=b"", url=final_url or url)
        if status >= 400:
            raise FetchError(url, status, f"HTTP {status}")
        length = response_headers.get("content-length", "")
        if length.isdigit() and int(length) > max_bytes:
            raise FetchError(url, status, f"body larger than {max_bytes} bytes")
        try:
            data = _read_limited(resp, url, status, max_bytes)
        except (http.client.HTTPException, socket.timeout, OSError) as exc:
            raise FetchError(url, status, f"read failed: {exc}") from None
        return Response(status=status, headers=response_headers, body=data, url=final_url or url)
    finally:
        close = getattr(resp, "close", None)
        if close:
            close()


def _decode(resp: Response, url: str) -> Any:
    try:
        return resp.json()
    except ValueError as exc:
        raise FetchError(url, resp.status, f"invalid JSON: {exc}") from None


def get_json(url: str, *, fetch: Fetch = fetch, timeout: float = 20) -> Any:
    resp = fetch(url, headers={"Accept": "application/json"}, timeout=timeout)
    return _decode(resp, url)


def post_json(url: str, payload: Any, *, fetch: Fetch = fetch, timeout: float = 30) -> Any:
    resp = fetch(url, method="POST", body=json.dumps(payload).encode("utf-8"),
                 headers={"Content-Type": "application/json", "Accept": "application/json"},
                 timeout=timeout)
    return _decode(resp, url)
