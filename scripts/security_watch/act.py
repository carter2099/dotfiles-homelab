"""Remediation gatekeeper for security-watch.

``act()`` decides which open findings may be remediated this tick and runs the
selected playbook through the gates documented in the build contract:

    breaker open -> refuse all (alert)
    steward unit active -> defer (no alert)
    shadow mode -> plan only, record a proposal (dedupe 24 h per component+target)
    >= max_actions_per_day executed in 24 h -> refuse (alert)
    component action within component_cooldown_hours -> defer
    an active action on the component -> skip
    plan() -> Refusal recorded
    release younger than release_min_age_hours -> require two independent issuer sources
    at most ONE new active execution per tick
    apply -> journal -> verify by rescan (findings must clear) -> breaker on failure

Playbooks own the mutation (and take the deploy lock themselves); this module owns
the journal, the breaker and every policy decision.  Multi-tick actions started on
earlier ticks are advanced first.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Callable, ContextManager, Mapping, Protocol

from security_watch import config, model, resolve
from security_watch.model import Finding, Outcome, Plan, Refusal

if TYPE_CHECKING:  # pragma: no cover - typing only
    from security_watch.store import Store

# Ecosystem -> deterministic repo edit that can fix a non-stdlib package of a
# release-rebuild component (via the repo-pr playbook).
_EDIT_FOR_ECOSYSTEM = {"Go": "go-module", "PyPI": "pip-pin"}

_URGENCY_RANK = {model.URGENCY_URGENT: 0, model.URGENCY_NORMAL: 1, model.URGENCY_LOW: 2}
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}
_OUTCOME_STATUSES = {"done", "pending", "failed", "rolled_back", "refused"}


def _log(message: str) -> None:
    print(f"security-watch: act: {message}", file=sys.stderr)


@dataclass
class ActCtx:
    store: "Store"
    policy: config.Policy
    specs: dict[str, config.ComponentSpec]
    now: datetime
    run: Callable[..., Any]
    fetch: Callable[..., Any]
    lock: Callable[..., ContextManager]          # deploy_lock.surface_lock(key, *, timeout, holder)
    host_lock: Callable[..., ContextManager]     # deploy_lock.host_lock(*, timeout, holder)
    steward_active: Callable[[], bool]
    rescan: Callable[[str], list[Finding]]       # re-inventory + scan one component; its open findings
    findings: dict[str, Finding] = field(default_factory=dict)   # all open findings (read-only)


class Playbook(Protocol):
    id: str
    multi_tick: bool

    def plan(self, findings: list[Finding], spec: config.ComponentSpec, ctx: ActCtx) -> Plan | Refusal: ...

    def apply(self, plan: Plan, ctx: ActCtx) -> Outcome: ...

    def advance(self, action: dict, ctx: ActCtx) -> Outcome: ...


@dataclass
class ActResult:
    proposed: list[dict] = field(default_factory=list)
    executed: list[dict] = field(default_factory=list)
    advanced: list[dict] = field(default_factory=list)
    refused: list[Refusal] = field(default_factory=list)


def playbooks() -> dict[str, Playbook]:
    """The production registry (imported lazily: playbooks import this module)."""
    from security_watch import playbooks_ops, playbooks_repo
    return {**playbooks_ops.PLAYBOOKS, **playbooks_repo.PLAYBOOKS}


# --- playbook selection ------------------------------------------------------

def _selection(finding: Finding, spec: config.ComponentSpec) -> tuple[str | None, str, bool]:
    """(playbook id or None, reason when None, whether that reason is surfaced to Carter).

    Alert-only owners and pin_owner ecosystems are permanent "no automated fix" facts
    (alert=True, recorded); the running kernel and rebuild-without-edit are not.
    """
    pkg = finding.package
    if spec.owner == "alert":
        note = spec.get("note") or ""
        return None, "alert-only component (no automated fix)" + (f": {note}" if note else ""), True
    pin_owner = spec.get("pin_owner") or {}
    for eco in (pkg.ecosystem, pkg.ecosystem.split(":", 1)[0]):
        if eco in pin_owner:
            return None, str(pin_owner[eco]), True
    if spec.owner == "release-rebuild":
        if pkg.ecosystem == "Go" and pkg.name == "stdlib":
            return "release-rebuild", "", False
        edit = _EDIT_FOR_ECOSYSTEM.get(pkg.ecosystem)
        if edit and edit in (spec.get("edits") or ()) and spec.repo:
            return "repo-pr", "", False
        return None, (f"no deterministic fix for {pkg.ecosystem} package {pkg.name} "
                      "(rebuild only fixes Go stdlib)"), False
    if spec.owner == "apt-security":
        if pkg.binary == "running-kernel":
            return None, "running kernel: the steward reboots after unattended-upgrades installs the fixed kernel", False
        return "apt-security", "", False
    return spec.owner, "", False


def select_playbook(finding: Finding, spec: config.ComponentSpec) -> str | None:
    return _selection(finding, spec)[0]


# --- helpers -----------------------------------------------------------------

def _row(action_id: Any, playbook: str, component: str, status: str, target: str,
         detail: str, undo: str, **extra: Any) -> dict:
    row = {"id": action_id, "playbook": playbook, "component": component, "status": status,
           "target": target, "detail": detail, "undo": undo}
    row.update(extra)
    return row


def _refuse(ctx: ActCtx, result: ActResult, refusal: Refusal) -> None:
    result.refused.append(refusal)
    if refusal.alert:
        ctx.store.record_refusal(refusal, ctx.now)
    _log(f"{'refused' if refusal.alert else 'deferred'} {refusal.playbook} on "
         f"{refusal.component_id}: {refusal.reason}")


def _breaker_open(ctx: ActCtx) -> tuple[bool, str]:
    state = ctx.store.breaker() or {}
    return bool(state.get("open")), str(state.get("reason") or "")


def _touched(outcome: Outcome) -> bool:
    """Production touched?  Missing/unknown counts as touched (fail closed)."""
    value = (outcome.state or {}).get("production_touched")
    return True if value is None else bool(value)


def _normalize(outcome: Any) -> Outcome:
    if not isinstance(outcome, Outcome) or outcome.status not in _OUTCOME_STATUSES:
        return Outcome(status="failed", detail=f"playbook returned an invalid outcome: {outcome!r}"[:500],
                       state={"production_touched": True, "production_touched_unknown": True})
    return outcome


def _crashed(stage: str, exc: BaseException) -> Outcome:
    return Outcome(status="failed", detail=f"{stage} raised {type(exc).__name__}: {exc}"[:500],
                   state={"production_touched": True, "production_touched_unknown": True})


def _settle(ctx: ActCtx, action_id: int, playbook: str, component: str, target: str,
            finding_keys: list[str], outcome: Outcome, fallback_undo: str) -> dict:
    """Journal an apply/advance outcome, verify done actions, trip the breaker on failure."""
    undo = outcome.undo or fallback_undo
    state = dict(outcome.state or {})
    detail = outcome.detail
    status = outcome.status
    trip = ""
    finished = True
    if status == "pending":
        finished = False
    elif status == "done":
        if outcome.verify:
            try:
                remaining = ctx.rescan(component)
            except Exception as exc:  # an unknown scan is never clean
                remaining = None
                detail = f"{detail}; verify rescan failed: {type(exc).__name__}: {exc}"
            if remaining is None:
                status, trip = "unverified", "verify rescan failed"
            else:
                open_keys = {f.key for f in remaining if f.status != "fixed"}
                still = [k for k in finding_keys if k in open_keys]
                if still:
                    status = "unverified"
                    trip = f"findings still open after fix: {', '.join(still)}"
                    detail = f"{detail}; {trip}"
                else:
                    status = "verified"
    elif status in ("failed", "rolled_back"):
        if _touched(outcome):
            trip = f"{status} with production touched"
    ctx.store.update_action(action_id, status=status, detail=detail, now=ctx.now, undo=undo,
                            state=state, finished=finished)
    if trip:
        ctx.store.trip_breaker(f"action #{action_id} {playbook} on {component}: {trip}: {outcome.detail}"[:500],
                               ctx.now)
        _log(f"breaker tripped by action #{action_id} ({playbook} on {component}): {trip}")
    _log(f"action #{action_id} {playbook} on {component} -> {status}")
    return _row(action_id, playbook, component, status, target, detail, undo)


def _two_source_gate(plan: Plan, findings: list[Finding], ctx: ActCtx) -> str:
    """'' when the plan may proceed, else the deferral reason."""
    if not plan.release_published:
        return ""
    min_age = timedelta(hours=ctx.policy.release_min_age_hours)
    try:
        published = model.parse_iso(plan.release_published)
    except (TypeError, ValueError):
        published = None
    if published is not None and ctx.now - published >= min_age:
        return ""
    covered = [f for f in findings if f.key in set(plan.finding_keys)] or findings
    counts: list[int] = []
    for finding in covered:
        records: list[dict] = []
        for vuln_id in finding.advisory_ids:
            cached = ctx.store.osv_get(vuln_id)
            if cached:
                records.append(cached[0])
        counts.append(resolve.independent_sources_naming(
            records, finding.package.ecosystem, finding.package.name, plan.fixed_version))
    count = min(counts) if counts else 0
    if count >= 2:
        return ""
    age = "unknown age" if published is None else f"{(ctx.now - published).total_seconds() / 3600:.0f}h old"
    return (f"fix release {plan.fixed_version or '?'} is {age} (< {ctx.policy.release_min_age_hours}h) and "
            f"{count} independent issuer source(s) name it; 2 required")


def _activity_time(action: dict) -> datetime | None:
    times = [model.parse_iso(action.get(k)) for k in ("started_at", "updated_at", "finished_at")]
    times = [t for t in times if t is not None]
    return max(times) if times else None


# --- advance -----------------------------------------------------------------

def _advance(registry: Mapping[str, Playbook], ctx: ActCtx, result: ActResult,
             steward: bool) -> None:
    open_, reason = _breaker_open(ctx)
    for action in ctx.store.active_actions():
        action_id = action["id"]
        pb_id = action.get("playbook") or ""
        component = action.get("component_id") or ""
        target = action.get("target") or ""
        keys = list(action.get("finding_keys") or [])
        undo = action.get("undo") or ""
        if action.get("status") == "running":
            # apply() is synchronous: a "running" row from an earlier tick was interrupted.
            seen = _activity_time(action)
            if seen is not None and ctx.now - seen < timedelta(seconds=ctx.policy.tick_budget_seconds):
                continue
            outcome = Outcome(status="failed", detail="apply was interrupted (no outcome journaled)",
                              state={"production_touched": True, "production_touched_unknown": True})
            result.advanced.append(_settle(ctx, action_id, pb_id, component, target, keys, outcome, undo))
            continue
        playbook = registry.get(pb_id)
        if playbook is None or not getattr(playbook, "multi_tick", False):
            outcome = Outcome(status="failed", detail=f"pending action has no multi-tick playbook {pb_id!r}",
                              state={"production_touched": True, "production_touched_unknown": True})
            result.advanced.append(_settle(ctx, action_id, pb_id, component, target, keys, outcome, undo))
            continue
        if not ctx.policy.active or open_ or steward:
            why = ("shadow mode" if not ctx.policy.active
                   else f"breaker open: {reason}" if open_ else "steward run active")
            _refuse(ctx, result, Refusal(pb_id, component, f"action #{action_id} not advanced: {why}", alert=False))
            continue
        spec = ctx.specs.get(component)
        if spec is not None and spec.get("steward_stops") and ctx.steward_active():
            _refuse(ctx, result, Refusal(pb_id, component, f"action #{action_id} not advanced: steward run active",
                                         alert=False))
            continue
        try:
            outcome = _normalize(playbook.advance(action, ctx))
        except Exception as exc:
            outcome = _crashed("advance", exc)
        if outcome.status == "refused":
            # Transient (e.g. lock busy): keep the action pending for the next tick.
            _refuse(ctx, result, Refusal(pb_id, component, f"action #{action_id}: {outcome.detail}", alert=False))
            continue
        result.advanced.append(_settle(ctx, action_id, pb_id, component, target, keys, outcome, undo))
        open_, reason = _breaker_open(ctx)


# --- act ---------------------------------------------------------------------

def _group_rank(findings: list[Finding]) -> tuple:
    return (min(_URGENCY_RANK.get(f.urgency, 3) for f in findings),
            0 if any(f.kev for f in findings) else 1,
            min(_SEVERITY_RANK.get(f.severity, 4) for f in findings))


def act(findings: list[Finding], ctx: ActCtx, registry: Mapping[str, Playbook] | None = None) -> ActResult:
    registry = playbooks() if registry is None else registry
    result = ActResult()
    policy = ctx.policy
    steward = bool(ctx.steward_active())

    _advance(registry, ctx, result, steward)

    groups: dict[tuple[str, str], list[Finding]] = {}
    no_fix: dict[tuple[str, str, str], list[str]] = {}   # (component, owner, reason) -> finding keys
    for finding in findings:
        if finding.status != "affected":
            continue
        spec = ctx.specs.get(finding.component_id)
        if spec is None:
            continue
        pb_id, why, alert = _selection(finding, spec)
        if pb_id is None:
            if alert:  # alert-only owner / pin_owner: explain why there is no automated fix
                no_fix.setdefault((spec.id, spec.owner, why), []).append(finding.key)
            elif finding.fix_available:
                result.refused.append(Refusal(spec.owner, spec.id, f"{finding.key}: {why}", alert=False))
            continue
        if finding.fix_available:
            groups.setdefault((spec.id, pb_id), []).append(finding)
    for (component, owner, why), keys in sorted(no_fix.items()):
        _refuse(ctx, result, Refusal(owner, component, f"no automated fix: {why} ({', '.join(sorted(keys))})",
                                     alert=True))

    since_day = ctx.now - timedelta(hours=24)
    executed_today = ctx.store.executed_actions_since(since_day) if policy.active and groups else 0
    executed_now = 0

    for (component, pb_id), group in sorted(groups.items(), key=lambda kv: (_group_rank(kv[1]), kv[0])):
        spec = ctx.specs[component]
        open_, reason = _breaker_open(ctx)
        if open_:
            _refuse(ctx, result, Refusal(pb_id, component, f"breaker open: {reason}", alert=True))
            continue
        if steward:
            _refuse(ctx, result, Refusal(pb_id, component, "steward run active; retry next tick", alert=False))
            continue
        playbook = registry.get(pb_id)
        if playbook is None:
            _refuse(ctx, result, Refusal(pb_id, component, f"playbook {pb_id!r} is not registered", alert=True))
            continue

        if not policy.active:
            plan = _plan(playbook, group, spec, ctx, result)
            if plan is None:
                continue
            if ctx.store.proposal_exists(component, plan.target, since_day):
                continue
            action_id = ctx.store.start_action(plan, mode="shadow", status="proposed", now=ctx.now)
            note = _two_source_gate(plan, group, ctx)
            detail = f"would wait: {note}" if note else "proposal (shadow mode)"
            ctx.store.update_action(action_id, status="proposed", detail=detail, now=ctx.now, undo=plan.undo)
            result.proposed.append(_row(action_id, pb_id, component, "proposed", plan.target, detail, plan.undo,
                                        steps=list(plan.steps)))
            _log(f"proposed #{action_id} {pb_id} on {component}: {plan.target}")
            continue

        if executed_today + executed_now >= policy.max_actions_per_day:
            _refuse(ctx, result, Refusal(pb_id, component,
                                         f"daily action cap reached ({policy.max_actions_per_day} in 24h)",
                                         alert=True))
            continue
        cooldown = timedelta(hours=policy.component_cooldown_hours)
        recent = [a for a in ctx.store.actions_since(ctx.now - cooldown)
                  if a.get("component_id") == component and a.get("mode") == "active"
                  and a.get("status") not in ("proposed", "refused")
                  and (_activity_time(a) or ctx.now) > ctx.now - cooldown]
        if recent:
            _refuse(ctx, result, Refusal(pb_id, component,
                                         f"component cooldown: action #{recent[-1]['id']} within "
                                         f"{policy.component_cooldown_hours}h", alert=False))
            continue
        running = [a for a in ctx.store.active_actions() if a.get("component_id") == component]
        if running:
            _refuse(ctx, result, Refusal(pb_id, component, f"action #{running[0]['id']} in progress", alert=False))
            continue
        plan = _plan(playbook, group, spec, ctx, result)
        if plan is None:
            continue
        wait = _two_source_gate(plan, group, ctx)
        if wait:
            _refuse(ctx, result, Refusal(pb_id, component, wait, alert=False))
            continue
        if executed_now >= 1:
            _refuse(ctx, result, Refusal(pb_id, component, "one execution per tick; deferred to next tick",
                                         alert=False))
            continue
        if spec.get("steward_stops") and ctx.steward_active():
            _refuse(ctx, result, Refusal(pb_id, component, "steward run active; retry next tick", alert=False))
            continue

        keys = list(plan.finding_keys) or [f.key for f in group]
        action_id = ctx.store.start_action(plan, mode="active", status="running", now=ctx.now)
        _log(f"executing #{action_id} {pb_id} on {component}: {plan.target}")
        try:
            outcome = _normalize(playbook.apply(plan, ctx))
        except Exception as exc:
            outcome = _crashed("apply", exc)
        if outcome.status == "refused":
            ctx.store.update_action(action_id, status="refused", detail=outcome.detail, now=ctx.now,
                                    undo=outcome.undo or plan.undo, state=dict(outcome.state or {}),
                                    finished=True)
            _refuse(ctx, result, Refusal(pb_id, component, outcome.detail, alert=False))
            continue
        executed_now += 1
        result.executed.append(_settle(ctx, action_id, pb_id, component, plan.target, keys, outcome, plan.undo))
    return result


def _plan(playbook: Playbook, group: list[Finding], spec: config.ComponentSpec, ctx: ActCtx,
          result: ActResult) -> Plan | None:
    try:
        planned = playbook.plan(list(group), spec, ctx)
    except Exception as exc:
        planned = Refusal(playbook.id, spec.id, f"plan failed: {type(exc).__name__}: {exc}"[:500], alert=True)
    if isinstance(planned, Refusal):
        _refuse(ctx, result, planned)
        return None
    if not isinstance(planned, Plan):
        _refuse(ctx, result, Refusal(playbook.id, spec.id, f"plan returned {type(planned).__name__}", alert=True))
        return None
    return planned
