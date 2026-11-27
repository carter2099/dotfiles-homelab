"""RubyGems advisories from ruby-advisory-db, read through bundler-audit.

OSV and GitHub's global advisory database miss many gem advisories that only
ruby-advisory-db carries (net-ssh's 2026 GHSAs and httpx's CVE-2026-129784 were in
neither), and ruby-advisory-db is what the repos' ``bundler-audit`` CI gate reads.
``audit`` writes the inventoried gems as a lockfile and runs ``bundle-audit check
--format json`` against it, so findings match that gate exactly.

The database (``~/.local/share/ruby-advisory-db``, shared with the steward's nightly
bundle-audit) is updated at most every ``UPDATE_INTERVAL``; a failed update with an
existing database keeps the previous copy.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from security_watch import config, resolve
from security_watch.model import Package

UPDATE_INTERVAL = 6 * 3600
AUDIT_TIMEOUT = 120
# The bundler-audit release whose `check --format json` output audit() parses; selfcheck
# reports any other installed version (installed in the global rbenv Ruby; the steward's
# toolchain updater carries gems to each new Ruby patch).
BUNDLE_AUDIT_VERSION = "0.9.3"
_CONSTRAINT = re.compile(r"^\s*(~>|>=|<=|!=|=|>|<)?\s*([0-9][0-9A-Za-z.]*)\s*$")


def _log(message: str) -> None:
    print(f"security-watch: rubysec: {message}", file=sys.stderr)


def db_dir() -> Path:
    return config.home() / ".local/share/ruby-advisory-db"


def tool_env() -> dict[str, str]:
    """rbenv shims first, the global Ruby (a repo's .ruby-version must not pick the tool)."""
    env = {k: v for k, v in os.environ.items() if k != "RBENV_VERSION" and not k.startswith("BUNDLE_")}
    rbenv = config.home() / ".rbenv"
    env["PATH"] = f"{rbenv / 'shims'}:{rbenv / 'bin'}:{env.get('PATH', '')}"
    return env


def lockfile(packages: list[Package]) -> str:
    """A minimal Gemfile.lock listing ``packages``: bundler-audit only reads the GEM specs."""
    specs = sorted({(p.name, p.version) for p in packages if p.ecosystem == "RubyGems"})
    lines = ["GEM", "  remote: https://rubygems.org/", "  specs:"]
    lines += [f"    {name} ({version})" for name, version in specs]
    lines += ["", "PLATFORMS", "  ruby", "", "DEPENDENCIES", ""]
    return "\n".join(lines)


def _update_db(run: Callable[..., Any], now: float) -> str:
    """Refresh the database when older than UPDATE_INTERVAL; '' or a note (never raises)."""
    head = db_dir() / ".git" / "FETCH_HEAD"
    if head.exists() and now - head.stat().st_mtime < UPDATE_INTERVAL:
        return ""
    if not head.exists() and (db_dir() / "gems").is_dir():
        # A fresh clone has no FETCH_HEAD yet; its age is the gems directory's.
        if now - (db_dir() / "gems").stat().st_mtime < UPDATE_INTERVAL:
            return ""
    proc = run(["bundle-audit", "update", "--quiet"], timeout=AUDIT_TIMEOUT, env=tool_env())
    if proc.returncode == 0:
        return ""
    note = f"bundle-audit update failed ({(proc.stderr or proc.stdout or '').strip()[:200]})"
    _log(note)
    return note


def audit(packages: list[Package], *, run: Callable[..., Any], clock: Callable[[], float] = time.time) -> list[dict]:
    """bundler-audit ``unpatched_gem`` results for ``packages``; RuntimeError when it cannot run."""
    if not any(p.ecosystem == "RubyGems" for p in packages):
        return []
    note = _update_db(run, clock())
    if note and not (db_dir() / "gems").is_dir():
        raise RuntimeError(note)
    with tempfile.TemporaryDirectory(prefix="security-watch-rubysec-") as tmp:
        Path(tmp, "Gemfile.lock").write_text(lockfile(packages))
        proc = run(["bundle-audit", "check", "--format", "json", "--gemfile-lock", "Gemfile.lock", tmp],
                   timeout=AUDIT_TIMEOUT, env=tool_env(), cwd=tmp)
    # bundle-audit exits 1 when it found vulnerabilities; anything else is a failure.
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"bundle-audit check exited {proc.returncode}: "
                           f"{(proc.stderr or proc.stdout or '').strip()[:200]}")
    try:
        data = json.loads(proc.stdout or "")
    except ValueError:
        raise RuntimeError(f"bundle-audit check printed no JSON: {(proc.stdout or '')[:200]}") from None
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        raise RuntimeError("bundle-audit JSON has no results list")
    return [r for r in results if isinstance(r, dict) and r.get("type") == "unpatched_gem"]


def fixed_versions(patched: list[str]) -> list[str]:
    """The lowest version each patched requirement admits: '~> 7.3, >= 7.3.5' -> '7.3.5',
    '~> 7.3.9' -> '7.3.9', '>= 8.1.1' -> '8.1.1'.  Entries without a lower bound are dropped."""
    out: list[str] = []
    for entry in patched or ():
        lower = ""
        for part in str(entry).split(","):
            match = _CONSTRAINT.match(part)
            if not match or (match.group(1) or "=") not in ("~>", ">=", "=", ">"):
                continue
            if not lower or resolve.version_lt(lower, match.group(2)):
                lower = match.group(2)
        if lower and lower not in out:
            out.append(lower)
    return out


def finding_fields(result: dict) -> dict[str, Any]:
    """Collector.add keyword fields (plus ``group``) for one bundler-audit result."""
    adv = result.get("advisory") or {}
    cve = f"CVE-{adv['cve']}" if adv.get("cve") else ""
    ghsa = f"GHSA-{adv['ghsa']}" if adv.get("ghsa") else ""
    ident = str(adv.get("id") or ghsa or cve)
    return {
        "group": cve or ghsa or ident,
        "advisory_ids": [i for i in dict.fromkeys([ghsa or ident, ident]) if i],
        "cves": [cve] if cve else [],
        "fixed": fixed_versions(list(adv.get("patched_versions") or [])),
        "severity": str(adv.get("criticality") or "").lower(),
        "summary": str(adv.get("title") or ""),
    }
