"""Hourly self-checks of the remediation machinery, written to report.json for the
steward's nightly email (contract with ``steward/report.py``):

``health_probes``  every component health URL, probed by ``health.probe_url`` exactly as a
                   deploy's health gate does (health_host, no redirects): a probe that cannot
                   pass now would fail the next deploy (action #65, 2026-11-24).
``unexercised``    (component, playbook) fix paths that never completed successfully: the
                   first real run of a path is where its untested code runs (also #65).
``coverage_gaps``  interpreters a container ships outside any OS package with no advisory
                   source and no ``runtime_waivers`` entry (Ruby2Shell went unflagged on the
                   blog for a week because its source-built Ruby was not inventoried).
``tooling``        the external tools scans depend on, against their declared versions.

Results are cached in kv ``selfcheck`` and refreshed at most every ``INTERVAL``.
"""

from __future__ import annotations

import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from security_watch import config, health, model, reach, rubysec, scan

INTERVAL = timedelta(hours=1)
PROBE_BUDGET_SECONDS = 6.0
KV_KEY = "selfcheck"
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_SUCCESS = ("verified", "done")
# Interpreter command -> runtime name used in components.toml `runtimes`.
_RUNTIME_OF = {"ruby": "ruby", "python3": "python", "node": "node", "php": "php"}
# The edits repo-pr may take over from release-rebuild (act.selection).
_REPO_PR_EDITS = {"go-toolchain", "go-module", "pip-pin"}


def _log(message: str) -> None:
    print(f"security-watch: selfcheck: {message}", file=sys.stderr)


def _name(spec) -> str:
    return str(spec.get("name") or spec.id)


def health_probes(specs: dict, *, probe: health.Probe = health.http_status,
                  sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic,
                  now: datetime) -> list[dict]:
    rows = []
    for spec in specs.values():
        host = health.host_of(spec)
        for url in spec.health:
            ok, detail = health.probe_url(url, host, probe=probe, sleep=sleep, clock=clock,
                                          deadline=clock() + PROBE_BUDGET_SECONDS)
            rows.append({"component": spec.id, "name": _name(spec), "url": url, "host": host, "ok": ok,
                         "detail": detail if ok else f"{detail} within {int(PROBE_BUDGET_SECONDS)}s",
                         "checked_at": model.iso(now)})
    return rows


def fix_paths(spec) -> list[str]:
    """Playbooks that may act on ``spec`` (mirrors act.selection's owner routing)."""
    if spec.owner == "alert":
        return []
    paths = [spec.owner]
    if spec.owner == "release-rebuild" and spec.repo and _REPO_PR_EDITS & set(spec.get("edits") or ()):
        paths.append("repo-pr")
    return paths


def unexercised(store, specs: dict) -> list[dict]:
    done = {(a.get("playbook"), a.get("component_id")) for a in store.actions_since(_EPOCH)
            if a.get("status") in _SUCCESS}
    return [{"component": spec.id, "name": _name(spec), "playbook": playbook}
            for spec in specs.values() for playbook in fix_paths(spec)
            if (playbook, spec.id) not in done]


def coverage_gaps(store, specs: dict) -> list[dict]:
    rows = []
    for inv in store.inventories():
        spec = specs.get(inv.component_id)
        if spec is None:
            continue
        error = (inv.meta or {}).get("interpreters_error")
        if error:
            rows.append({"component": spec.id, "name": _name(spec), "runtime": "", "path": "",
                         "detail": f"interpreter scan failed: {error}"})
            continue
        declared = set((spec.get("runtimes") or {}).keys()) | set((spec.get("repo_runtimes") or {}).keys())
        waivers = spec.get("runtime_waivers") or {}
        for item in (inv.meta or {}).get("interpreters") or ():
            if item.get("owner"):
                continue   # an OS package: OSV matches it with the distro's records
            runtime = _RUNTIME_OF.get(item.get("name", ""), item.get("name", ""))
            if runtime in waivers:
                continue
            path = item.get("resolved") or item.get("path") or ""
            if runtime not in declared:
                detail = (f"{path} belongs to no OS package and is not inventoried: add it to "
                          f"`runtimes` with an advisory source, or to `runtime_waivers` with a reason")
            elif not scan.has_runtime_feed(spec, runtime):
                detail = f"{path} is inventoried but has no advisory source (no `advisory_repo` or release feed)"
            else:
                continue
            rows.append({"component": spec.id, "name": _name(spec), "runtime": runtime, "path": path,
                         "detail": detail})
    return rows


def _bundle_audit(run) -> dict:
    want = rubysec.BUNDLE_AUDIT_VERSION
    proc = run(["bundle-audit", "version"], timeout=60, env=rubysec.tool_env())
    match = re.search(r"bundler-audit (\S+)", proc.stdout or "") if proc.returncode == 0 else None
    have = match.group(1) if match else None
    if have is None:
        return {"tool": "bundle-audit", "want": want, "have": None, "ok": False,
                "detail": f"bundle-audit is missing from the global rbenv Ruby: gem scans for the blog and "
                          f"delta_neutral cannot complete; install with `gem install bundler-audit -v {want}`"}
    if have != want:
        return {"tool": "bundle-audit", "want": want, "have": have, "ok": False,
                "detail": f"bundle-audit {have} is installed but {want} is declared (rubysec.BUNDLE_AUDIT_VERSION); "
                          "check its JSON output still parses, then update the declaration"}
    return {"tool": "bundle-audit", "want": want, "have": have, "ok": True, "detail": "ok"}


def _govulncheck(run) -> dict:
    want = reach.GOVULNCHECK.rsplit("@", 1)[-1]
    go = str(config.expand(reach.GO_BIN))
    proc = run([go, "env", "GOMODCACHE"], timeout=60)
    if proc.returncode != 0:
        return {"tool": "govulncheck", "want": want, "have": None, "ok": False,
                "detail": f"{reach.GO_BIN} does not run, so Go reachability checks cannot: {(proc.stderr or '').strip()[:150]}"}
    cache = Path((proc.stdout or "").strip()) / "golang.org" / "x" / f"vuln@{want}"
    have = want if cache.is_dir() else "not cached (fetched on first use)"
    return {"tool": "govulncheck", "want": want, "have": have, "ok": True,
            "detail": f"run as `go run {reach.GOVULNCHECK}`"}


def tooling(run) -> list[dict]:
    return [_bundle_audit(run), _govulncheck(run)]


def run_checks(store, specs: dict, *, run, now: datetime, probe: health.Probe = health.http_status,
               sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic,
               force: bool = False) -> dict:
    """Refresh the cached results when older than INTERVAL (or ``force``); returns them."""
    cached = store.get_kv(KV_KEY) or {}
    checked = model.parse_iso(cached.get("checked_at")) if isinstance(cached, dict) else None
    if not force and checked is not None and now - checked < INTERVAL:
        return cached
    result: dict[str, Any] = {"checked_at": model.iso(now), "health_probes": [], "unexercised": [],
                              "coverage_gaps": [], "tooling": []}
    failures: list[dict] = []
    for key, fn in (("health_probes", lambda: health_probes(specs, probe=probe, sleep=sleep, clock=clock, now=now)),
                    ("unexercised", lambda: unexercised(store, specs)),
                    ("coverage_gaps", lambda: coverage_gaps(store, specs)),
                    ("tooling", lambda: tooling(run))):
        try:
            result[key] = fn()
        except Exception as exc:  # noqa: BLE001 - one broken check must not hide the others
            _log(f"{key} failed: {type(exc).__name__}: {exc}")
            failures.append({"tool": f"selfcheck {key}", "want": "", "have": None, "ok": False,
                             "detail": f"the {key} self-check crashed: {type(exc).__name__}: {exc}"[:300]})
    result["tooling"] = list(result["tooling"]) + failures
    store.set_kv(KV_KEY, result)
    return result


def report_fields(store) -> dict:
    """The four report.json keys from the last self-check (absent before the first run)."""
    cached = store.get_kv(KV_KEY) or {}
    if not isinstance(cached, dict):
        return {}
    return {key: list(cached.get(key) or []) for key in ("health_probes", "unexercised", "coverage_gaps", "tooling")
            if key in cached}
