"""security-watch CLI and the 15-minute tick.

Subcommands: tick (default), scan, status, report, breaker-reset, replay, fix.
Every tick phase is guarded: a failing phase logs, marks the run degraded and the
tick continues.  Only a bug outside the phase guards exits 1 (so systemd's
OnFailure=notify-failure fires).
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import fcntl
import json
import os
import subprocess
import sys
import tempfile
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterator

from security_watch import config, model, net

ACTIVE_STATES = {"active", "activating", "reloading", "deactivating"}
UNKNOWN_RETRY = timedelta(minutes=15)


def _log(message: str) -> None:
    print(f"security-watch: runner: {message}", file=sys.stderr)


# --- single instance ---------------------------------------------------------

@contextlib.contextmanager
def tick_lock(state_dir: Path | None = None) -> Iterator[bool]:
    """Non-blocking flock on <state_dir>/tick.lock; yields False when another tick holds it."""
    directory = state_dir or config.state_dir()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(directory / "tick.lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


# --- steward ------------------------------------------------------------------

def steward_active(run: Callable[..., subprocess.CompletedProcess] | None = None) -> bool:
    """True when any steward unit is running (or its state cannot be read: fail closed)."""
    for unit in config.STEWARD_UNITS:
        argv = ["systemctl", "--user", "show", "-p", "ActiveState", "--value", unit]
        try:
            if run is not None:
                proc = run(argv, timeout=10)
            else:
                proc = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                      timeout=10, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            _log(f"steward state unreadable ({exc}); treating as active")
            return True
        if proc.returncode != 0:
            _log(f"systemctl show {unit} exited {proc.returncode}; treating steward as active")
            return True
        if (proc.stdout or "").strip() in ACTIVE_STATES:
            return True
    return False


# --- tick ---------------------------------------------------------------------

@dataclass
class Deps:
    """Everything a tick touches outside the store (replaced wholesale by replay/tests)."""
    fetch: Callable[..., Any]
    run: Callable[..., Any]
    collect: Callable[[config.ComponentSpec, datetime], model.Inventory]
    fingerprint: Callable[[config.ComponentSpec], str]
    steward_active: Callable[[], bool]
    send: Callable[..., Any] | None
    lock: Callable[..., Any]
    host_lock: Callable[..., Any]
    clock: Callable[[], datetime] = model.utcnow
    monotonic: Callable[[], float] = time.monotonic
    reach_kwargs: dict[str, Any] = field(default_factory=dict)


def default_deps() -> Deps:
    import deploy_lock
    from security_watch import inventory

    def collect(spec, now):
        return inventory.collect(spec, run=inventory.default_run, fetch=net.fetch, now=now)

    def fingerprint(spec):
        return inventory.fingerprint(spec, run=inventory.default_run)

    return Deps(fetch=net.fetch, run=inventory.default_run, collect=collect, fingerprint=fingerprint,
                steward_active=steward_active, send=None, lock=deploy_lock.surface_lock,
                host_lock=deploy_lock.host_lock)


class _Phases:
    def __init__(self) -> None:
        self.status: dict[str, str] = {}

    def run(self, name: str, fn: Callable[[], Any], default: Any = None) -> Any:
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001 - phase guard: log, mark degraded, continue
            reason = " ".join(f"{type(exc).__name__}: {exc}".split())[:300]
            self.status[name] = f"failed: {reason}"
            _log(f"{name} phase failed: {reason}")
            traceback.print_exc(file=sys.stderr)
            return default
        self.status[name] = "ok"
        return result

    def skip(self, name: str, why: str) -> None:
        self.status[name] = f"skipped: {why}"

    @property
    def degraded(self) -> bool:
        return any(v.startswith("failed") for v in self.status.values())


def _same_inventory(a: model.Inventory | None, b: model.Inventory) -> bool:
    return a is not None and (a.status, a.fingerprint, a.packages) == (b.status, b.fingerprint, b.packages)


def _merge_previous(store, f: model.Finding) -> None:
    """Carry reach/urgency from the stored finding so an unchanged finding compares "same"."""
    old = store.get_finding(f.key)
    if old is None or old.status == "fixed":
        return
    if f.reach is None:
        f.reach = old.reach
    f.urgency = old.urgency
    f.reasons = list(old.reasons)


def _store_scan(store, result, *, now, only: set[str] | None = None) -> list[str]:
    """Upsert findings, close vanished ones on completely scanned components; returns changed keys."""
    changed = []
    for f in result.findings:
        if only is not None and f.component_id not in only:
            continue
        _merge_previous(store, f)
        if store.upsert_finding(f, now) in ("new", "updated"):
            changed.append(f.key)
    for component in sorted(result.complete):
        if only is not None and component not in only:
            continue
        keys = {f.key for f in result.findings if f.component_id == component}
        for key in store.close_missing_findings(component, keys, now):
            _log(f"resolved {key}")
    return changed


def _flagging(signals: list[model.Signal]) -> list[model.Signal]:
    return [s for s in signals if s.tier in (model.TIER_ISSUER, model.TIER_CURATED) and s.cves]


def act_ctx(store, policy: config.Policy, specs: dict[str, config.ComponentSpec], deps: Deps, now: datetime):
    """The remediation context shared by ticks and ``fix``: every open finding, and a rescan
    that re-inventories + scans one component and returns (its open affected findings,
    whether the scan of that component was complete)."""
    from security_watch import act as act_mod
    from security_watch import scan

    def rescan(component_id: str) -> tuple[list[model.Finding], bool]:
        spec = specs[component_id]
        at = deps.clock()
        inv = deps.collect(spec, at)
        store.put_inventory(inv)
        result = scan.scan([inv], specs, store=store, fetch=deps.fetch, now=at)
        _store_scan(store, result, now=at, only={component_id})
        complete = set(store.get_kv("last_complete", []) or [])
        is_complete = component_id in result.complete
        if is_complete:
            complete.add(component_id)
        else:
            complete.discard(component_id)
        store.set_kv("last_complete", sorted(complete))
        found = [f for f in store.open_findings() if f.component_id == component_id and f.status == "affected"]
        return found, is_complete

    return act_mod.ActCtx(
        store=store, policy=policy, specs=specs, now=now, run=deps.run, fetch=deps.fetch,
        lock=deps.lock, host_lock=deps.host_lock, steward_active=deps.steward_active, rescan=rescan,
        findings={f.key: f for f in store.open_findings()},
    )



def run_tick(store, policy: config.Policy, specs: dict[str, config.ComponentSpec], deps: Deps, *,
             force_inventory: bool = False, force_scan: bool = False, act_enabled: bool = True) -> dict:
    """One pass over every phase; returns the run summary (also recorded in the store)."""
    from security_watch import act as act_mod
    from security_watch import feeds, notify, reach, report, scan

    started = deps.clock()
    now = started
    deadline = deps.monotonic() + policy.tick_budget_seconds
    phases = _Phases()
    summary: dict[str, Any] = {"mode": policy.mode}

    def over_budget() -> bool:
        return deps.monotonic() >= deadline

    # feeds
    poll = phases.run("feeds", lambda: feeds.poll_due(store, policy, now=now, fetch=deps.fetch))
    new_signals: list[model.Signal] = list(poll.new) + list(poll.updated) if poll else []
    if poll:
        summary["sources"] = {
            "ok": sum(1 for v in poll.health.values() if v == "ok"),
            "failed": sorted(k for k, v in poll.health.items() if v.startswith("failed")),
        }
        summary["signals"] = {"new": len(poll.new), "updated": len(poll.updated)}
    flagged = _flagging(list(poll.new) if poll else [])

    # inventory
    def inventory_phase() -> list[str]:
        refresh = timedelta(hours=policy.inventory_refresh_hours)
        changed: list[str] = []
        for spec in specs.values():
            if over_budget():
                _log("tick budget exhausted during inventory; remaining components wait")
                break
            prev = store.get_inventory(spec.id)
            why = ""
            if force_inventory:
                why = "forced"
            elif flagged:
                why = f"signal {flagged[0].source}:{flagged[0].key}"
            elif prev is None:
                why = "never collected"
            elif now - prev.collected_at >= refresh:
                why = "stale"
            elif prev.status != "ok" and now - prev.collected_at >= UNKNOWN_RETRY:
                why = f"previous inventory {prev.status}"
            else:
                try:
                    fp = deps.fingerprint(spec)
                except Exception as exc:  # noqa: BLE001 - unreadable fingerprint: collect to be safe
                    fp = ""
                    why = f"fingerprint failed: {type(exc).__name__}"
                if fp and fp != prev.fingerprint:
                    why = "fingerprint changed"
            if not why:
                continue
            try:
                inv = deps.collect(spec, now)
            except Exception as exc:  # noqa: BLE001 - unknown, never clean
                inv = model.Inventory(component_id=spec.id, collected_at=now, status="unknown", fingerprint="",
                                      reason=f"inventory error: {type(exc).__name__}: {exc}"[:300])
            store.put_inventory(inv)
            if not _same_inventory(prev, inv):
                changed.append(spec.id)
        return changed

    changed_inventory = phases.run("inventory", inventory_phase, default=[]) or []
    summary["inventory_changed"] = changed_inventory

    # scan
    scan_result = None
    last_scan = model.parse_iso(store.get_kv("last_scan"))
    rescan_due = last_scan is None or now - last_scan >= timedelta(minutes=policy.osv_rescan_minutes)
    changed_findings: list[str] = []
    if force_scan or changed_inventory or new_signals or rescan_due:
        def scan_phase():
            inventories = [inv for inv in store.inventories() if inv.component_id in specs]
            result = scan.scan(inventories, specs, store=store, fetch=deps.fetch, now=now, deadline=deadline)
            changed_findings.extend(_store_scan(store, result, now=now))
            # A scan cut short by the tick deadline continues on the next tick instead of
            # waiting for the hourly rescan.
            pending = result.stats.get("osv_pending") or any(
                str(u.get("reason", "")).startswith(("OSV records pending", "OSV scan pending"))
                for u in result.unknown)
            if not pending:
                store.set_kv("last_scan", model.iso(now))
            store.set_kv("last_unknown", list(result.unknown))
            store.set_kv("last_complete", sorted(result.complete))
            return result
        scan_result = phases.run("scan", scan_phase)
        if scan_result is not None:
            summary["scan"] = dict(scan_result.stats)
    else:
        phases.skip("scan", "nothing changed")

    # reachability: changed findings plus open findings whose reachability is still unknown,
    # so deferred work and expired unknowns are retried (reach.assess applies its own cache,
    # backoff and per-tick/per-day caps).
    retry_keys = [f.key for f in store.open_findings()
                  if f.status == "affected" and (f.reach is None or f.reach.verdict == "unknown")]
    reach_keys = list(dict.fromkeys([*changed_findings, *retry_keys]))
    if reach_keys and not over_budget():
        def reach_phase():
            targets = [f for f in (store.get_finding(k) for k in reach_keys)
                       if f is not None and f.status == "affected"]
            if not targets:
                return 0
            inventories = {inv.component_id: inv for inv in store.inventories()}
            reach.assess(targets, inventories, specs, store=store, policy=policy, now=now, run=deps.run,
                         deadline=deadline, **deps.reach_kwargs)
            for f in targets:
                store.upsert_finding(f, now)
            return len(targets)
        summary["reach_assessed"] = phases.run("reach", reach_phase, default=0)
    elif reach_keys:
        phases.skip("reach", "tick budget exhausted")

    # prioritize (a stopgap load failure leaves findings un-downgraded: fail closed)
    stopgaps = phases.run("stopgaps", config.load_stopgaps, default=[]) or []

    # Verified not-affected assessments; a load/verify failure degrades the run and downgrades
    # nothing (fail closed).
    def assessments_phase():
        from security_watch import assessments
        entries = assessments.load()
        verdicts = assessments.verify(entries, run=deps.run)
        return [(e, verdicts[e.id]) for e in entries]
    not_affected = phases.run("assessments", assessments_phase, default=[]) or []

    def prioritize_phase():
        open_findings = store.open_findings()
        scan.prioritize(open_findings, specs, policy, store=store, now=now, stopgaps=stopgaps,
                        not_affected=not_affected)
        for f in open_findings:
            store.upsert_finding(f, now)
        return open_findings
    open_findings = phases.run("prioritize", prioritize_phase, default=None)
    if open_findings is None:
        open_findings = store.open_findings()

    # act
    act_result = None
    if not act_enabled:
        phases.skip("act", "disabled for this command")
    elif over_budget():
        phases.skip("act", "tick budget exhausted")
    else:
        def act_phase():
            ctx = act_ctx(store, policy, specs, deps, now)
            return act_mod.act([f for f in ctx.findings.values() if f.status == "affected"], ctx)
        act_result = phases.run("act", act_phase)
        if act_result is not None:
            summary["act"] = {"proposed": len(act_result.proposed), "executed": len(act_result.executed),
                              "advanced": len(act_result.advanced), "refused": len(act_result.refused)}

    # notify
    def notify_phase():
        items = notify.urgent_items(store.open_findings(), new_signals, store, policy, specs, now,
                                    stopgaps=stopgaps, act_result=act_result)
        return notify.send_urgent(items, store=store, policy=policy, now=now, send=deps.send)
    summary["urgent_email"] = bool(phases.run("notify", notify_phase, default=False))

    # report
    finished = deps.clock()
    outcome = "degraded" if phases.degraded else "ok"
    tick = {"started": started, "finished": finished, "outcome": outcome}

    def report_phase():
        data = report.build_report(store, policy, specs, scan_result, act_result, tick, finished,
                                   stopgaps=stopgaps, not_affected=not_affected)
        report.write_report(data)
        return data
    report_data = phases.run("report", report_phase)
    outcome = "degraded" if phases.degraded else "ok"

    summary["phases"] = dict(phases.status)
    summary["outcome"] = outcome
    store.record_run(started=started, finished=deps.clock(), outcome=outcome, summary=summary)
    summary["report"] = report_data
    _log(f"tick {outcome}: " + ", ".join(f"{k}={v}" for k, v in phases.status.items()))
    return summary


def _load() -> tuple[config.Policy, dict[str, config.ComponentSpec]]:
    policy = config.load_policy()
    specs = {spec.id: spec for spec in config.load_components()}
    return policy, specs


def cmd_tick(*, force: bool = False) -> int:
    from security_watch.store import Store
    with tick_lock() as acquired:
        if not acquired:
            print("security-watch: another tick is running; skipping")
            return 0
        policy, specs = _load()
        with Store() as store:
            run_tick(store, policy, specs, default_deps(), force_inventory=force, force_scan=force,
                     act_enabled=not force)
    return 0


# --- status / report / breaker -------------------------------------------------

def cmd_status() -> int:
    from security_watch.store import Store
    policy, _specs = _load()
    now = model.utcnow()
    with Store() as store:
        breaker = store.breaker() or {}
        runs = store.runs_since(now - timedelta(days=1))
        findings = store.open_findings()
        unknown = store.get_kv("last_unknown", []) or []
        from security_watch import feeds
        failing = [name for name in feeds.SOURCES
                   if int((store.source_state(name) or {}).get("consecutive_failures") or 0) > 0]
    counts = {u: sum(1 for f in findings if f.urgency == u)
              for u in (model.URGENCY_URGENT, model.URGENCY_NORMAL, model.URGENCY_LOW)}
    print(f"mode: {policy.mode}")
    print("breaker: " + (f"OPEN since {breaker.get('since')}: {breaker.get('reason')}" if breaker.get("open")
                         else "closed"))
    if runs:
        last = runs[-1]
        print(f"last tick: {last['finished']} ({last['outcome']}); ticks in 24h: {len(runs)}")
    else:
        print("last tick: none in 24h")
    print(f"open findings: {len(findings)} (urgent {counts['urgent']}, normal {counts['normal']}, "
          f"low {counts['low']})")
    for f in sorted(findings, key=lambda f: (f.urgency != model.URGENCY_URGENT, f.key))[:10]:
        fixed = ", ".join(f.fixed_versions) or "no fix"
        print(f"  [{f.urgency}] {f.key} {f.package.ecosystem}/{f.package.name} {f.package.version} -> {fixed}")
    print(f"unknown components: {len(unknown)}")
    for u in unknown[:10]:
        print(f"  {u.get('component')}: {u.get('reason')}")
    print("failing sources: " + (", ".join(failing) if failing else "none"))
    return 0


def cmd_report() -> int:
    path = config.report_path()
    try:
        text = path.read_text()
    except FileNotFoundError:
        print(f"security-watch: no report at {path} yet", file=sys.stderr)
        return 1
    sys.stdout.write(text)
    return 0


def cmd_breaker_reset() -> int:
    from security_watch.store import Store
    with Store() as store:
        before = store.breaker() or {}
        store.reset_breaker(model.utcnow())
    print("breaker reset" + (f" (was open: {before.get('reason')})" if before.get("open") else " (was closed)"))
    return 0


# --- fix (supervised remediation) ---------------------------------------------------

FIX_POLL_SECONDS = 60        # --wait: one advance() step per minute
FIX_LOCK_WAIT_SECONDS = 900  # a plain tick ends within policy.tick_budget_seconds; one running a long
                             # apply may hold tick.lock up to the unit's TimeoutStartSec=2h (retry later)
FIX_LOCK_POLL_SECONDS = 5
FIX_EXIT = {"done": 0, "verified": 0, "planned": 0, "pending": 3, "running": 3, "refused": 2}


def _fix_log(message: str) -> None:
    print(f"security-watch: fix: {message}", file=sys.stderr)


def _fix_progress(row: dict) -> None:
    who = f"#{row['id']} " if row.get("id") is not None else ""
    target = f" -> {row['target']}" if row.get("target") else ""
    detail = f": {row['detail']}" if row.get("detail") else ""
    _fix_log(f"{who}{row.get('playbook') or '-'} on {row.get('component') or '-'}{target}: "
             f"{row.get('status')}{detail}")


@contextlib.contextmanager
def _fix_step(deps: Deps, sleep: Callable[[float], Any], wait_seconds: float) -> Iterator[bool]:
    """Hold tick.lock around one apply/advance step so a concurrent tick neither declares the
    running apply interrupted nor advances the same action twice; never held while ``--wait``
    sleeps.  Yields False when a tick kept the lock for ``wait_seconds``."""
    deadline = deps.monotonic() + wait_seconds
    announced = False
    while True:
        with tick_lock() as acquired:
            if acquired:
                yield True
                return
        if deps.monotonic() >= deadline:
            yield False
            return
        if not announced:
            _fix_log("a tick is running; waiting for it to finish")
            announced = True
        sleep(FIX_LOCK_POLL_SECONDS)


def _fix_list(store, policy, specs, deps, registry, out) -> int:
    from security_watch import act as act_mod
    rows = act_mod.list_manual(act_ctx(store, policy, specs, deps, deps.clock()), registry)
    if not rows:
        print("no open affected finding with a fix available", file=out)
    for row in rows:
        head = f"{row['component']}  {row['playbook'] or '-'}  ({', '.join(row['finding_keys'])})"
        if row["refusal"]:
            print(f"{head}\n    refused: {row['refusal']}", file=out)
            continue
        print(f"{head}\n    target: {row['target']}", file=out)
        if row["age_gate"]:
            print(f"    age gate: {row['age_gate']} (fix --skip-age-gate overrides)", file=out)
        for step in row["plan_steps"]:
            print(f"    - {step}", file=out)
    return 0


def run_fix(args: argparse.Namespace, store, policy: config.Policy, specs: dict[str, config.ComponentSpec],
            deps: Deps, *, registry=None, sleep: Callable[[float], Any] = time.sleep, out=None) -> int:
    """``fix``: list, start (``run_manual``) or resume (``advance_manual``) a supervised fix.

    Prints one progress line per step to stderr and the final row as JSON to ``out``.  Exit 0 on
    done/verified (and dry runs), 3 when still pending, 2 on refusal, 1 on failed/rolled_back/unverified.
    """
    from security_watch import act as act_mod
    out = out or sys.stdout
    if args.list:
        return _fix_list(store, policy, specs, deps, registry, out)

    with _fix_step(deps, sleep, FIX_LOCK_WAIT_SECONDS) as locked:
        ctx = act_ctx(store, policy, specs, deps, deps.clock())
        if not locked:
            row = {"id": args.resume, "playbook": args.playbook or "", "component": args.component or "",
                   "status": "refused", "target": "", "undo": "", "plan_steps": [],
                   "detail": f"a tick held tick.lock for {FIX_LOCK_WAIT_SECONDS}s; retry later"}
        elif args.resume is not None:
            row = act_mod.advance_manual(args.resume, ctx, registry=registry)
        else:
            row = act_mod.run_manual(args.component, ctx, registry=registry, playbook=args.playbook,
                                     finding_keys=args.findings, skip_age_gate=args.skip_age_gate,
                                     dry_run=args.dry_run)
    _fix_progress(row)

    deadline = deps.monotonic() + max(0, args.wait)
    while row.get("status") in ("pending", "running") and row.get("id") is not None:
        remaining = deadline - deps.monotonic()
        if remaining <= 0:
            break
        sleep(min(FIX_POLL_SECONDS, remaining))
        with _fix_step(deps, sleep, 0) as locked:
            if locked:
                row = act_mod.advance_manual(row["id"], act_ctx(store, policy, specs, deps, deps.clock()),
                                             registry=registry)
            else:
                row = act_mod.action_row(store.get_action(row["id"]))
                row["detail"] = f"a tick is running (it advances the action too); {row['detail']}"
        _fix_progress(row)

    print(json.dumps(row, sort_keys=True, default=str), file=out)
    return FIX_EXIT.get(row.get("status"), 1)


def _fix_usage_error(args: argparse.Namespace) -> str:
    modes = [name for name, on in (("<component>", args.component), ("--list", args.list),
                                   ("--resume", args.resume is not None)) if on]
    if len(modes) != 1:
        return "fix needs exactly one of <component>, --list or --resume ACTION_ID"
    start_only = [name for name, on in (("--playbook", args.playbook), ("--finding", args.findings),
                                        ("--dry-run", args.dry_run), ("--skip-age-gate", args.skip_age_gate)) if on]
    if start_only and modes[0] != "<component>":
        return f"{', '.join(start_only)} only apply to fix <component>"
    if args.list and args.wait:
        return "--wait does not apply to fix --list"
    if args.wait < 0:
        return "--wait must be >= 0"
    return ""


def cmd_fix(args: argparse.Namespace) -> int:
    from security_watch.store import Store
    policy, specs = _load()
    with Store() as store:
        return run_fix(args, store, policy, specs, default_deps())



# --- replay ---------------------------------------------------------------------

class ReplayFetch:
    """Serves <fixture>/http/ per manifest.json; anything unlisted answers 404 (never the network)."""

    def __init__(self, fixture_dir: Path):
        self.root = Path(fixture_dir)
        manifest = json.loads((self.root / "manifest.json").read_text())
        self.routes: dict[str, str] = dict(manifest.get("routes") or {})
        self.querybatch: dict = dict(manifest.get("osv_querybatch") or {})
        self.requests: list[tuple[str, str]] = []

    def __call__(self, url: str, *, method: str = "GET", body: bytes | None = None, headers: dict | None = None,
                 timeout: float = 20, max_bytes: int = 16_000_000, etag: str | None = None,
                 last_modified: str | None = None) -> net.Response:
        self.requests.append((method, url))
        if method == "POST" and self.querybatch and url == self.querybatch.get("url"):
            return self._querybatch(url, body or b"{}")
        rel = self.routes.get(url) or self.routes.get(url.split("?", 1)[0])
        if rel is None or method != "GET":
            raise net.FetchError(url, 404, "replay: no fixture for this request")
        return net.Response(status=200, headers={}, body=(self.root / rel).read_bytes(), url=url)

    def _querybatch(self, url: str, body: bytes) -> net.Response:
        table = json.loads((self.root / self.querybatch["file"]).read_text())
        results = []
        for query in json.loads(body).get("queries") or []:
            pkg = query.get("package") or {}
            key = f"{pkg.get('ecosystem')}/{pkg.get('name')}@{query.get('version')}"
            vulns = [] if query.get("page_token") else (table.get(key) or [])
            results.append({"vulns": vulns} if vulns else {})
        return net.Response(status=200, headers={"content-type": "application/json"},
                            body=json.dumps({"results": results}).encode(), url=url)


def _replay_run(argv, **_kwargs) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(list(argv), 127, "", "replay: subprocesses are disabled")


def _replay_omp(_prompt: str) -> str:
    raise RuntimeError("replay: agent disabled")


@contextlib.contextmanager
def _env(**values: str) -> Iterator[None]:
    saved = {k: os.environ.get(k) for k in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def replay(fixture_dir: Path) -> dict:
    """Run one shadow tick against a recorded fixture; returns {"report", "outbox", "summary"}."""
    import deploy_lock
    from security_watch.store import Store, inventory_from_dict

    fixture_dir = Path(fixture_dir).resolve()
    manifest = json.loads((fixture_dir / "manifest.json").read_text())
    fixed_now = model.parse_iso(manifest.get("now")) or model.utcnow()
    inventories = {inv.component_id: inv for inv in
                   (inventory_from_dict(d) for d in json.loads((fixture_dir / "inventory.json").read_text()))}
    policy = dataclasses.replace(config.load_policy(), mode="shadow", reach_max_agent_calls_per_tick=0)
    specs = {spec.id: spec for spec in config.load_components() if spec.id in inventories}

    with tempfile.TemporaryDirectory(prefix="security-watch-replay-") as tmp:
        tmp_path = Path(tmp)
        outbox = tmp_path / "outbox"
        outbox.mkdir()
        sent: list[str] = []

        def send(subject: str, html_body: str, recipients: list[str]) -> None:
            sent.append(subject)
            (outbox / f"{len(sent):03d}.json").write_text(
                json.dumps({"subject": subject, "recipients": recipients, "html": html_body}))

        def collect(spec, now):
            inv = inventories[spec.id]
            return dataclasses.replace(inv, collected_at=now)

        deps = Deps(
            fetch=ReplayFetch(fixture_dir), run=_replay_run, collect=collect,
            fingerprint=lambda spec: inventories[spec.id].fingerprint,
            steward_active=lambda: False, send=send, lock=deploy_lock.surface_lock,
            host_lock=deploy_lock.host_lock, clock=lambda: fixed_now,
            reach_kwargs={"load_jev": False, "jev_client": None, "omp_call": _replay_omp},
        )
        with _env(SECURITY_WATCH_STATE_DIR=str(tmp_path / "state"), DEPLOY_LOCK_DIR=str(tmp_path / "locks")):
            with Store() as store:
                summary = run_tick(store, policy, specs, deps)
        report_data = summary.pop("report", None)
        return {"report": report_data, "outbox": sent, "summary": summary}


# --- CLI --------------------------------------------------------------------------

def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="security_watch_runner.py", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("tick", help="one timer pass (default)")
    sub.add_parser("scan", help="force inventory + scan now (no remediation)")
    sub.add_parser("status", help="short text summary")
    sub.add_parser("report", help="print report.json")
    sub.add_parser("breaker-reset", help="close the remediation breaker")
    rp = sub.add_parser("replay", help="shadow tick over a recorded fixture (offline)")
    rp.add_argument("fixture_dir", type=Path)
    rp.add_argument("--json", action="store_true", help="compact single-line JSON")
    fp = sub.add_parser("fix", help="supervised fix of one component (Carter-approved: ignores shadow mode, "
                                    "the daily cap and the cooldown)")
    fp.add_argument("component", nargs="?", help="component id from components.toml")
    fp.add_argument("--list", action="store_true",
                    help="plan (never apply) every component with open affected findings that have a fix")
    fp.add_argument("--resume", type=int, metavar="ACTION_ID", help="advance a pending manual action")
    fp.add_argument("--playbook", metavar="ID", help="required when the findings need more than one playbook")
    fp.add_argument("--finding", action="append", dest="findings", metavar="KEY",
                    help="restrict to this finding key (repeatable)")
    fp.add_argument("--dry-run", action="store_true", help="plan and gate only; apply nothing")
    fp.add_argument("--skip-age-gate", action="store_true",
                    help="allow a fix release younger than release_min_age_hours with one issuer source")
    fp.add_argument("--wait", type=int, default=0, metavar="SECONDS",
                    help=f"advance a pending action every {FIX_POLL_SECONDS}s until done or SECONDS pass")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    command = args.command or "tick"
    if command == "fix":
        error = _fix_usage_error(args)
        if error:
            parser.error(error)
    try:
        if command == "tick":
            return cmd_tick()
        if command == "scan":
            return cmd_tick(force=True)
        if command == "status":
            return cmd_status()
        if command == "report":
            return cmd_report()
        if command == "breaker-reset":
            return cmd_breaker_reset()
        if command == "replay":
            result = replay(args.fixture_dir)
            print(json.dumps(result, indent=None if args.json else 2, sort_keys=True, default=str))
            return 0
        if command == "fix":
            return cmd_fix(args)
    except Exception:  # noqa: BLE001 - escaped the phase guards: a bug; exit 1 for OnFailure
        traceback.print_exc(file=sys.stderr)
        return 1
    raise AssertionError(f"unhandled command {command}")
