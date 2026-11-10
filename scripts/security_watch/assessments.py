"""Verified not-affected assessments (``assessments.toml``).

An entry states that a component is not affected by some CVEs and carries the
deterministic checks that prove it.  Every scan re-runs the checks; a failing check
fails closed (the finding keeps its urgency and gains the failure as a reason).
"""

from __future__ import annotations

import re
import shlex
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from security_watch import config

ASSESSMENTS_PATH: Path = config.PACKAGE_DIR / "assessments.toml"
CHECK_TIMEOUT = 30
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CLIP = 200


@dataclass(frozen=True)
class Check:
    """Passes when the command exits 0 and ``expect`` (re.search) matches stdout."""
    argv: tuple[str, ...]
    expect: str
    container: str = ""  # non-empty -> run as ["docker", "exec", container, *argv]


@dataclass(frozen=True)
class NotAffected:
    id: str
    component: str
    cves: tuple[str, ...]
    reason: str
    verified: str  # ISO date a human/agent verified it
    checks: tuple[Check, ...]


@dataclass
class Verdict:
    id: str
    ok: bool
    detail: str  # which check failed and why ("" when ok)


def _text(raw: dict, key: str, where: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{where}: {key!r} must be a non-empty string")
    return value


def _check(raw, where: str) -> Check:
    if not isinstance(raw, dict):
        raise ValueError(f"{where}: must be a table")
    argv = raw.get("argv")
    if (not isinstance(argv, list) or not argv
            or not all(isinstance(a, str) and a for a in argv)):
        raise ValueError(f"{where}: 'argv' must be a non-empty list of non-empty strings")
    expect = _text(raw, "expect", where)
    try:
        re.compile(expect)
    except re.error as exc:
        raise ValueError(f"{where}: 'expect' is not a valid regex: {exc}") from None
    container = raw.get("container", "")
    if not isinstance(container, str):
        raise ValueError(f"{where}: 'container' must be a string")
    return Check(argv=tuple(argv), expect=expect, container=container)


def _entry(raw, index: int) -> NotAffected:
    where = f"assessments.toml not_affected[{index}]"
    if not isinstance(raw, dict):
        raise ValueError(f"{where}: must be a table")
    entry_id = _text(raw, "id", where)
    where = f"assessments.toml not_affected {entry_id!r}"
    component = _text(raw, "component", where)
    reason = _text(raw, "reason", where)
    verified = _text(raw, "verified", where)
    if not _DATE_RE.match(verified):
        raise ValueError(f"{where}: 'verified' must be an ISO date (YYYY-MM-DD), got {verified!r}")
    cves = raw.get("cves")
    if not isinstance(cves, list) or not cves:
        raise ValueError(f"{where}: 'cves' must be a non-empty list")
    for cve in cves:
        if not isinstance(cve, str) or not _CVE_RE.match(cve):
            raise ValueError(f"{where}: invalid CVE id {cve!r} (expected CVE-YYYY-NNNN)")
    checks = raw.get("checks")
    if not isinstance(checks, list) or not checks:
        raise ValueError(f"{where}: 'checks' must be a non-empty list")
    return NotAffected(id=entry_id, component=component, cves=tuple(cves), reason=reason,
                       verified=verified,
                       checks=tuple(_check(c, f"{where} check {n + 1}") for n, c in enumerate(checks)))


def load(path: Path = ASSESSMENTS_PATH) -> list[NotAffected]:
    """Parse and validate the ledger; missing file -> [].  Invalid file -> ValueError."""
    if not path.exists():
        return []
    try:
        data = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"assessments.toml: invalid TOML: {exc}") from None
    raws = data.get("not_affected", [])
    if not isinstance(raws, list):
        raise ValueError("assessments.toml: 'not_affected' must be an array of tables")
    entries: list[NotAffected] = []
    seen: set[str] = set()
    for index, raw in enumerate(raws):
        entry = _entry(raw, index)
        if entry.id in seen:
            raise ValueError(f"assessments.toml: duplicate not_affected id {entry.id!r}")
        seen.add(entry.id)
        entries.append(entry)
    return entries


def _clip(text: str) -> str:
    return " ".join((text or "").split())[:_CLIP]


def _run_check(check: Check, run) -> str:
    """'' when the check passes, else why it failed."""
    argv = ["docker", "exec", check.container, *check.argv] if check.container else list(check.argv)
    shown = shlex.join(argv)
    proc = run(argv, timeout=CHECK_TIMEOUT)
    if proc.returncode == 124:
        return f"{shown}: timeout after {CHECK_TIMEOUT}s"
    if proc.returncode != 0:
        err = _clip(proc.stderr or proc.stdout or "")
        return f"{shown}: rc {proc.returncode}" + (f": {err}" if err else "")
    if re.search(check.expect, proc.stdout or "") is None:
        return f"{shown}: expected /{check.expect}/ not found in stdout: {_clip(proc.stdout)!r}"
    return ""


def verify(entries: Sequence[NotAffected], *, run) -> dict[str, Verdict]:
    """Run every entry's checks (``run`` = inventory.default_run signature); never raises.

    An entry is ok only when all its checks pass; the first failure is the detail.
    """
    verdicts: dict[str, Verdict] = {}
    for entry in entries:
        detail = ""
        for n, check in enumerate(entry.checks, 1):
            try:
                why = _run_check(check, run)
            except Exception as exc:  # noqa: BLE001 -- fail closed, never raise
                why = f"{shlex.join(check.argv)}: {type(exc).__name__}: {_clip(str(exc))}"
            if why:
                detail = f"check {n}: {why}"
                break
        verdicts[entry.id] = Verdict(id=entry.id, ok=not detail, detail=detail)
    return verdicts
