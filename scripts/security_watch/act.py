"""Remediation gatekeeper for security-watch.

``act()`` decides which open findings may be remediated this tick and runs the
selected playbook through the gates documented in the build contract:

    all findings of a group low urgency -> skip (manual ``fix`` may still run it)
    breaker open -> defer (no alert: the breaker itself is reported)
    steward unit active -> defer (no alert)
    shadow mode -> plan only, record a proposal (dedupe 24 h per component+target)
    an active action on the component -> refuse (alert: "action #N in progress: <detail>")
    >= max_actions_per_day executed in 24 h -> refuse (alert); urgent groups (any finding
        urgent) skip this gate, but every autonomous execution still counts toward the cap
    an unsuccessful autonomous action on the component (refused/failed/rolled_back/unverified,
        refused applies included) within component_cooldown_hours -> defer the whole
        component (urgent groups included)
    a finding in a verified/done autonomous action on its component within
        component_cooldown_hours -> excluded before grouping (cleared or leftover alike), so a
        success never delays other findings; a group left empty -> refuse (no alert)
    plan() -> Refusal recorded
    the same target failed twice in a row without touching production (7 days) -> refuse (alert)
    release younger than release_min_age_hours -> require two independent issuer sources
    at most ONE new active execution per tick
    apply -> journal -> verify by rescan -> breaker on failure

Verification rescans the component and checks the keys the playbook verified it fixes
(``Outcome.state["verified_keys"]``, else every planned key).  An incomplete rescan keeps
the action ``pending`` in stage ``verify`` and later ticks re-verify it for up to
``VERIFY_RETRY``.  A complete rescan is ``verified`` when every key cleared, or when some
cleared and no key of the highest urgency among them is still open (detail lists the
leftovers); otherwise ``unverified`` and the breaker opens.

Playbooks own the mutation (and take the deploy lock themselves); this module owns
the journal, the breaker and every policy decision.  Multi-tick actions started on
earlier ticks are advanced first.

Supervised fixes (``run_manual``/``advance_manual``, the runner's ``fix`` command) are
journaled with mode ``manual``: Carter approved them, so shadow mode, the daily cap and
the cooldown do not apply, while the breaker, steward, in-flight action, plan and
two-source gates (the last skippable) and the same verify/undo/breaker settle path do.
Pending manual actions advance on every tick, shadow mode included.
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
DEPLOY_STUCK = timedelta(hours=2)        # a "deploying" row older than this was interrupted
VERIFY_RETRY = timedelta(hours=6)        # incomplete verification rescans retried this long
UNTOUCHED_FAILURE_LIMIT = 2              # consecutive untouched failures of one target ...
UNTOUCHED_FAILURE_WINDOW = timedelta(days=7)   # ... within this window refuse the target


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
    rescan: Callable[[str], tuple[list[Finding], bool]]   # re-inventory + scan one component:
                                                          # (its open findings, scan complete?)
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


def _key_rank(ctx: ActCtx, key: str, remaining: list[Finding]) -> int:
    """Urgency rank of a finding key (fresh rescan row, else the stored finding); unknown -> urgent."""
    finding = next((f for f in remaining if f.key == key), None) or ctx.store.get_finding(key)
    return _URGENCY_RANK.get(finding.urgency, 0) if finding is not None else 0


def _verify(ctx: ActCtx, component: str, keys: list[str], since: datetime) -> tuple[str, str, str]:
    """Rescan ``component`` and judge ``keys``: (status, breaker reason or "", note for the detail).

    ``pending`` while the rescan is incomplete (or raised) and ``since`` is younger than
    ``VERIFY_RETRY``; ``verified`` when every key cleared, or some cleared and none of the
    highest-urgency keys is still open; else ``unverified`` (trips the breaker)."""
    error = ""
    try:
        remaining, complete = ctx.rescan(component)
    except Exception as exc:  # an unknown scan is never clean: retried like an incomplete one
        remaining, complete = [], False
        error = f" ({type(exc).__name__}: {exc})"[:300]
    if not complete:
        if ctx.now - since >= VERIFY_RETRY:
            reason = f"verification rescan incomplete for {VERIFY_RETRY.total_seconds() / 3600:g}h{error}"
            return "unverified", reason, reason
        return "pending", "", (f"verification pending: rescan incomplete{error}; retried until "
                               f"{model.iso(since + VERIFY_RETRY)}")
    open_keys = {f.key for f in remaining if f.status != "fixed"}
    still = [k for k in keys if k in open_keys]
    if not still:
        return "verified", "", ""
    cleared = len(keys) - len(still)
    ranks = {k: _key_rank(ctx, k, remaining) for k in keys}
    top = min(ranks.values())
    top_open = [k for k in still if ranks[k] == top]
    if cleared and not top_open:
        return "verified", "", f"{cleared} of {len(keys)} cleared; still open: {', '.join(still)}"
    reason = f"findings still open after fix: {', '.join(still)}"
    if cleared:
        reason += f" ({cleared} of {len(keys)} cleared; most urgent still open: {', '.join(top_open)})"
    return "unverified", reason, reason


def _journal(ctx: ActCtx, action_id: int, playbook: str, component: str, target: str, *, status: str,
             detail: str, undo: str, state: dict, finished: bool, trip: str, cause: str) -> dict:
    ctx.store.update_action(action_id, status=status, detail=detail, now=ctx.now, undo=undo,
                            state=state, finished=finished)
    if trip:
        ctx.store.trip_breaker(f"action #{action_id} {playbook} on {component}: {trip}: {cause}"[:500], ctx.now)
        _log(f"breaker tripped by action #{action_id} ({playbook} on {component}): {trip}")
    _log(f"action #{action_id} {playbook} on {component} -> {status}")
    return _row(action_id, playbook, component, status, target, detail, undo)


def _settle(ctx: ActCtx, action_id: int, playbook: str, component: str, target: str,
            finding_keys: list[str], outcome: Outcome, fallback_undo: str) -> dict:
    """Journal an apply/advance outcome, verify done actions, trip the breaker on failure.

    A done outcome verifies ``state["verified_keys"]`` when the playbook narrowed the fix to
    them, else every planned key; an incomplete rescan leaves the action pending in stage
    ``verify`` (``_advance_pending`` re-verifies it on later ticks)."""
    undo = outcome.undo or fallback_undo
    state = dict(outcome.state or {})
    detail = outcome.detail
    status = outcome.status
    trip = ""
    finished = status != "pending"
    if status == "done" and outcome.verify:
        keys = [str(k) for k in state.get("verified_keys") or ()] or list(finding_keys)
        status, trip, note = _verify(ctx, component, keys, ctx.now)
        if status == "pending":
            finished = False
            state.update(stage="verify", verify_keys=keys, verify_since=model.iso(ctx.now), verify_detail=detail)
        if note:
            detail = f"{detail}; {note}"
    elif status in ("failed", "rolled_back") and _touched(outcome):
        trip = f"{status} with production touched"
    return _journal(ctx, action_id, playbook, component, target, status=status, detail=detail, undo=undo,
                    state=state, finished=finished, trip=trip, cause=outcome.detail)


def _reverify(ctx: ActCtx, action: dict) -> dict | Refusal:
    """A later tick's verification of an action pending in stage ``verify``."""
    action_id = action["id"]
    pb_id = action.get("playbook") or ""
    component = action.get("component_id") or ""
    state = dict(action.get("state") or {})
    keys = [str(k) for k in state.get("verify_keys") or ()] or list(action.get("finding_keys") or [])
    since = model.parse_iso(state.get("verify_since")) or _activity_time(action) or ctx.now
    status, trip, note = _verify(ctx, component, keys, since)
    if status == "pending":
        return Refusal(pb_id, component, f"action #{action_id}: {note}", alert=False)
    state.pop("stage", None)
    base = str(state.get("verify_detail") or action.get("detail") or "")
    detail = f"{base}; {note}" if note else base
    return _journal(ctx, action_id, pb_id, component, action.get("target") or "", status=status, detail=detail,
                    undo=action.get("undo") or "", state=state, finished=True, trip=trip, cause=base)


def _two_source_gate(plan: Plan, findings: list[Finding], ctx: ActCtx) -> str:
    """'' when the plan may proceed, else the deferral reason.

    Sources are counted for the covered findings whose fixed versions include
    ``plan.fixed_version`` (the release the plan installs); when none lists it, for the
    plan's first covered finding."""
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
    counted = [f for f in covered if plan.fixed_version and plan.fixed_version in f.fixed_versions] or covered[:1]
    counts: list[int] = []
    for finding in counted:
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


def _untouched_failures(ctx: ActCtx, component: str, target: str) -> list[dict]:
    """Newest-first streak of executed actions on (component, target) within
    ``UNTOUCHED_FAILURE_WINDOW`` that ended ``failed`` with production explicitly untouched;
    any other executed outcome of that target ends the streak (refusals are neutral)."""
    rows = [a for a in ctx.store.actions_since(ctx.now - UNTOUCHED_FAILURE_WINDOW)
            if a.get("component_id") == component and a.get("target") == target
            and a.get("mode") in ("active", "manual") and a.get("status") not in ("proposed", "refused")]
    streak: list[dict] = []
    for action in reversed(rows):
        if action.get("status") != "failed" or (action.get("state") or {}).get("production_touched") is not False:
            break
        streak.append(action)
    return streak


def _activity_time(action: dict) -> datetime | None:
    times = [model.parse_iso(action.get(k)) for k in ("started_at", "updated_at", "finished_at")]
    times = [t for t in times if t is not None]
    return max(times) if times else None


# --- advance -----------------------------------------------------------------

def _advance_pending(registry: Mapping[str, Playbook], ctx: ActCtx, action: dict, steward: bool) -> dict | Refusal:
    """One step of a pending action: its settled row, or a Refusal when it stays pending.

    Stage ``verify`` only re-verifies (read-only rescan, in every mode).  Stage ``deploying``
    (journaled by a playbook right before a deploy script) is never re-advanced: older than
    ``DEPLOY_STUCK`` the deploy was interrupted -> failed, production touched.  Otherwise
    manual actions advance in every mode (Carter approved them); autonomous ones only in
    active mode.  An open breaker or an active steward run blocks both.
    """
    action_id = action["id"]
    pb_id = action.get("playbook") or ""
    component = action.get("component_id") or ""
    target = action.get("target") or ""
    keys = list(action.get("finding_keys") or [])
    undo = action.get("undo") or ""
    state = dict(action.get("state") or {})
    stage = state.get("stage")
    if stage == "verify":
        return _reverify(ctx, action)
    if stage == "deploying":
        seen = _activity_time(action) or ctx.now
        if ctx.now - seen <= DEPLOY_STUCK:
            return Refusal(pb_id, component, f"action #{action_id} deploying since {model.iso(seen)}", alert=False)
        outcome = Outcome(status="failed", detail=(f"deploy interrupted: stage 'deploying' since {model.iso(seen)} "
                                                   f"with no outcome journaled ({action.get('detail') or ''})")[:500],
                          state={**state, "production_touched": True})
        return _settle(ctx, action_id, pb_id, component, target, keys, outcome, undo)
    playbook = registry.get(pb_id)
    if playbook is None or not getattr(playbook, "multi_tick", False):
        outcome = Outcome(status="failed", detail=f"pending action has no multi-tick playbook {pb_id!r}",
                          state={"production_touched": True, "production_touched_unknown": True})
        return _settle(ctx, action_id, pb_id, component, target, keys, outcome, undo)
    open_, reason = _breaker_open(ctx)
    why = ""
    if action.get("mode") != "manual" and not ctx.policy.active:
        why = "shadow mode"
    elif open_:
        why = f"breaker open: {reason}"
    elif steward:
        why = "steward run active"
    else:
        spec = ctx.specs.get(component)
        if spec is not None and spec.get("steward_stops") and ctx.steward_active():
            why = "steward run active"
    if why:
        return Refusal(pb_id, component, f"action #{action_id} not advanced: {why}", alert=False)
    try:
        outcome = _normalize(playbook.advance(action, ctx))
    except Exception as exc:
        outcome = _crashed("advance", exc)
    if outcome.status == "refused":
        # Kept pending for the next step (e.g. lock busy, PR on hold); the reason is journaled
        # as the detail so a blocked action stays visible, and surfaced when the playbook asks.
        ctx.store.update_action(action_id, status="pending", detail=outcome.detail, now=ctx.now)
        return Refusal(pb_id, component, f"action #{action_id}: {outcome.detail}",
                       alert=bool((outcome.state or {}).get("alert")))
    return _settle(ctx, action_id, pb_id, component, target, keys, outcome, undo)


def _advance(registry: Mapping[str, Playbook], ctx: ActCtx, result: ActResult,
             steward: bool) -> None:
    for action in ctx.store.active_actions():
        if action.get("status") == "running":
            # apply() is synchronous: a "running" row from an earlier tick was interrupted.
            seen = _activity_time(action)
            if seen is not None and ctx.now - seen < timedelta(seconds=ctx.policy.tick_budget_seconds):
                continue
            outcome = Outcome(status="failed", detail="apply was interrupted (no outcome journaled)",
                              state={"production_touched": True, "production_touched_unknown": True})
            result.advanced.append(_settle(ctx, action["id"], action.get("playbook") or "",
                                           action.get("component_id") or "", action.get("target") or "",
                                           list(action.get("finding_keys") or []), outcome,
                                           action.get("undo") or ""))
            continue
        step = _advance_pending(registry, ctx, action, steward)
        if isinstance(step, Refusal):
            _refuse(ctx, result, step)
        else:
            result.advanced.append(step)


# --- act ---------------------------------------------------------------------

def _group_rank(findings: list[Finding]) -> tuple:
    return (min(_URGENCY_RANK.get(f.urgency, 3) for f in findings),
            0 if any(f.kev for f in findings) else 1,
            min(_SEVERITY_RANK.get(f.severity, 4) for f in findings))


# Autonomous outcomes that start the component cooldown (unsuccessful attempts only).
_COOLDOWN_STATUSES = frozenset({"refused", "failed", "rolled_back", "unverified"})
# Autonomous outcomes that put only their own finding keys on cooldown.
_SUCCESS_STATUSES = frozenset({"verified", "done"})


def _recently_attempted(ctx: ActCtx) -> dict[tuple[str, str], dict]:
    """(component, finding key) -> newest verified/done autonomous action that covered the key
    within ``component_cooldown_hours``.  Such findings sit out autonomous grouping so a
    leftover the plan could not clear is not re-attempted with the same plan every tick."""
    cooldown = timedelta(hours=ctx.policy.component_cooldown_hours)
    attempted: dict[tuple[str, str], dict] = {}
    for action in ctx.store.actions_since(ctx.now - cooldown):
        if (action.get("mode") != "active" or action.get("status") not in _SUCCESS_STATUSES
                or (_activity_time(action) or ctx.now) <= ctx.now - cooldown):
            continue
        for key in action.get("finding_keys") or []:
            attempted[(action.get("component_id") or "", key)] = action   # ORDER BY id: newest wins
    return attempted


def act(findings: list[Finding], ctx: ActCtx, registry: Mapping[str, Playbook] | None = None) -> ActResult:
    registry = playbooks() if registry is None else registry
    result = ActResult()
    policy = ctx.policy
    steward = bool(ctx.steward_active())

    _advance(registry, ctx, result, steward)

    # Per-finding cooldown after success, computed after _advance so an action that verified this
    # tick already counts; applied before grouping so a group's urgency reflects eligible findings.
    attempted = _recently_attempted(ctx) if policy.active else {}
    held: dict[tuple[str, str], list[tuple[Finding, dict]]] = {}

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
            prior = attempted.get((spec.id, finding.key))
            if prior is not None:
                held.setdefault((spec.id, pb_id), []).append((finding, prior))
                continue
            groups.setdefault((spec.id, pb_id), []).append(finding)
    for (component, pb_id), entries in sorted(held.items()):
        if (component, pb_id) in groups:
            continue   # other findings of the group proceed; the held ones simply sit out
        priors = {a["id"]: a for _, a in entries}
        by = ", ".join(f"action #{i} ({a.get('status')})" for i, a in sorted(priors.items()))
        keys = ", ".join(sorted({f.key for f, _ in entries}))
        _refuse(ctx, result, Refusal(pb_id, component,
                                     f"already attempted by {by} within {policy.component_cooldown_hours}h; "
                                     f"still open: {keys}", alert=False))
    for (component, owner, why), keys in sorted(no_fix.items()):
        _refuse(ctx, result, Refusal(owner, component, f"no automated fix: {why} ({', '.join(sorted(keys))})",
                                     alert=True))

    since_day = ctx.now - timedelta(hours=24)
    executed_today = ctx.store.executed_actions_since(since_day) if policy.active and groups else 0
    executed_now = 0

    for (component, pb_id), group in sorted(groups.items(), key=lambda kv: (_group_rank(kv[1]), kv[0])):
        spec = ctx.specs[component]
        if all(f.urgency == model.URGENCY_LOW for f in group):
            result.refused.append(Refusal(pb_id, component, "every finding is low urgency; fix manually if wanted",
                                          alert=False))
            continue
        open_, reason = _breaker_open(ctx)
        if open_:
            # Not recorded per group: the open breaker is reported (and emailed) on its own.
            result.refused.append(Refusal(pb_id, component, f"breaker open: {reason}", alert=False))
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

        running = [a for a in ctx.store.active_actions() if a.get("component_id") == component]
        if running:
            blocker = running[0]
            _refuse(ctx, result, Refusal(pb_id, component,
                                         f"action #{blocker['id']} in progress: {blocker.get('detail') or blocker.get('status')}",
                                         alert=True))
            continue
        # Urgent groups bypass the cap; their executions still count, so they can use up the
        # day's budget for normal groups.
        urgent = any(f.urgency == model.URGENCY_URGENT for f in group)
        if not urgent and executed_today + executed_now >= policy.max_actions_per_day:
            _refuse(ctx, result, Refusal(pb_id, component,
                                         f"daily action cap reached ({policy.max_actions_per_day} in 24h)",
                                         alert=True))
            continue
        cooldown = timedelta(hours=policy.component_cooldown_hours)
        # Only unsuccessful autonomous attempts start the cooldown (refused applies included, so a
        # refusing playbook backs off instead of retrying every tick); verified/done ones only hold
        # their own finding keys (see _recently_attempted).
        recent = [a for a in ctx.store.actions_since(ctx.now - cooldown)
                  if a.get("component_id") == component and a.get("mode") == "active"
                  and a.get("status") in _COOLDOWN_STATUSES
                  and (_activity_time(a) or ctx.now) > ctx.now - cooldown]
        if recent:
            _refuse(ctx, result, Refusal(pb_id, component,
                                         f"component cooldown: action #{recent[-1]['id']} ended "
                                         f"{recent[-1]['status']} within {policy.component_cooldown_hours}h",
                                         alert=False))
            continue
        plan = _plan(playbook, group, spec, ctx, result)
        if plan is None:
            continue
        streak = _untouched_failures(ctx, component, plan.target)
        if len(streak) >= UNTOUCHED_FAILURE_LIMIT:
            _refuse(ctx, result, Refusal(pb_id, component,
                                         f"failed twice without touching production: {streak[0].get('detail') or ''}; "
                                         "fix manually or change the plan", alert=True))
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
            state = dict(outcome.state or {})
            ctx.store.update_action(action_id, status="refused", detail=outcome.detail, now=ctx.now,
                                    undo=outcome.undo or plan.undo, state=state, finished=True)
            _refuse(ctx, result, Refusal(pb_id, component, outcome.detail, alert=bool(state.get("alert"))))
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


# --- supervised (manual) fixes --------------------------------------------------

def action_row(action: dict) -> dict:
    """A journaled action as a ``fix`` row ``{id, playbook, component, status, target, detail, undo, plan_steps}``."""
    plan = action.get("plan") or {}
    return _row(action.get("id"), action.get("playbook") or "", action.get("component_id") or "",
                action.get("status") or "", action.get("target") or "", action.get("detail") or "",
                action.get("undo") or "", plan_steps=list(plan.get("steps") or []))


def _fix_groups(ctx: ActCtx, spec: config.ComponentSpec, finding_keys: list[str] | None = None
                ) -> tuple[dict[str, list[Finding]], dict[str, list[str]], list[str]]:
    """Open affected+fix_available findings of one component (optionally restricted to
    ``finding_keys``): (playbook id -> findings, no-fix reason -> keys, requested keys not eligible)."""
    wanted = set(finding_keys or ())
    groups: dict[str, list[Finding]] = {}
    no_fix: dict[str, list[str]] = {}
    seen: set[str] = set()
    for finding in sorted(ctx.findings.values(), key=lambda f: f.key):
        if finding.component_id != spec.id or finding.status != "affected" or not finding.fix_available:
            continue
        if wanted and finding.key not in wanted:
            continue
        seen.add(finding.key)
        pb_id, why, _alert = _selection(finding, spec)
        if pb_id is None:
            no_fix.setdefault(why, []).append(finding.key)
        else:
            groups.setdefault(pb_id, []).append(finding)
    return groups, no_fix, sorted(wanted - seen)


def _choices(groups: Mapping[str, list[Finding]]) -> str:
    return "; ".join(f"{pb_id} ({', '.join(f.key for f in group)})" for pb_id, group in sorted(groups.items()))


def run_manual(component_id: str, ctx: ActCtx, *, registry: Mapping[str, Playbook] | None = None,
               playbook: str | None = None, finding_keys: list[str] | None = None,
               skip_age_gate: bool = False, dry_run: bool = False) -> dict:
    """Carter-approved fix of one component, outside the autonomous gates (shadow mode, the
    daily cap and the cooldown do not apply).  The breaker, an active steward run, an action
    already in flight on the component, plan refusals and (unless ``skip_age_gate``) the
    two-source rule still refuse.  Returns the ``fix`` row; status ``refused`` for any refusal,
    ``planned`` for a dry run, else the settled outcome (``pending`` continues via
    ``advance_manual`` or the next tick)."""
    registry = playbooks() if registry is None else registry
    result = ActResult()

    def refused(pb_id: str | None, reason: str, *, alert: bool = False, target: str = "",
                steps: list[str] | None = None) -> dict:
        _refuse(ctx, result, Refusal(pb_id or "", component_id, reason, alert=alert))
        return _row(None, pb_id or "", component_id, "refused", target, reason, "", plan_steps=list(steps or []))

    spec = ctx.specs.get(component_id)
    if spec is None:
        return refused(playbook, f"unknown component {component_id!r}")
    groups, no_fix, missing = _fix_groups(ctx, spec, finding_keys)
    if missing:
        return refused(playbook, f"not an open affected finding with a fix on {component_id}: {', '.join(missing)}")
    if not groups:
        why = "; ".join(f"{reason} ({', '.join(keys)})" for reason, keys in sorted(no_fix.items()))
        return refused(playbook, "no open affected finding with an automated fix" + (f": {why}" if why else ""))
    if playbook is None:
        if len(groups) > 1:
            return refused(None, f"findings need {len(groups)} playbooks; choose one with --playbook: "
                                 f"{_choices(groups)}")
        pb_id = next(iter(groups))
    elif playbook not in groups:
        return refused(playbook, f"playbook {playbook!r} fixes none of the selected findings; "
                                 f"choices: {_choices(groups)}")
    else:
        pb_id = playbook
    group = groups[pb_id]

    open_, reason = _breaker_open(ctx)
    if open_:
        return refused(pb_id, f"breaker open: {reason}")
    if ctx.steward_active():
        return refused(pb_id, "steward run active; retry when it finishes")
    running = [a for a in ctx.store.active_actions() if a.get("component_id") == component_id]
    if running:
        return refused(pb_id, f"action #{running[0]['id']} ({running[0].get('mode')}, {running[0].get('status')}) "
                              f"in progress on {component_id}; resume it with fix --resume {running[0]['id']}")
    pb = registry.get(pb_id)
    if pb is None:
        return refused(pb_id, f"playbook {pb_id!r} is not registered", alert=True)

    plan = _plan(pb, group, spec, ctx, result)
    if plan is None:
        return _row(None, pb_id, component_id, "refused", "", result.refused[-1].reason, "", plan_steps=[])
    steps = list(plan.steps)
    if not skip_age_gate:
        wait = _two_source_gate(plan, group, ctx)
        if wait:
            return refused(pb_id, f"{wait} (--skip-age-gate overrides)", target=plan.target, steps=steps)
    if dry_run:
        return _row(None, pb_id, component_id, "planned", plan.target, "dry run: nothing applied", plan.undo,
                    plan_steps=steps)

    keys = list(plan.finding_keys) or [f.key for f in group]
    action_id = ctx.store.start_action(plan, mode="manual", status="running", now=ctx.now)
    _log(f"manual #{action_id} {pb_id} on {component_id}: {plan.target}")
    try:
        outcome = _normalize(pb.apply(plan, ctx))
    except Exception as exc:
        outcome = _crashed("apply", exc)
    if outcome.status == "refused":
        undo = outcome.undo or plan.undo
        ctx.store.update_action(action_id, status="refused", detail=outcome.detail, now=ctx.now, undo=undo,
                                state=dict(outcome.state or {}), finished=True)
        _refuse(ctx, result, Refusal(pb_id, component_id, outcome.detail,
                                     alert=bool((outcome.state or {}).get("alert"))))
        return _row(action_id, pb_id, component_id, "refused", plan.target, outcome.detail, undo, plan_steps=steps)
    row = _settle(ctx, action_id, pb_id, component_id, plan.target, keys, outcome, plan.undo)
    row["plan_steps"] = steps
    return row


def advance_manual(action_id: int, ctx: ActCtx, *, registry: Mapping[str, Playbook] | None = None) -> dict:
    """One ``advance()`` step of a pending manual action through the shared settle path.

    A terminal or ``running`` action is returned as journaled; a blocked step (breaker, steward,
    transient playbook refusal, incomplete verification rescan) leaves it ``pending`` with the
    reason as ``detail``."""
    registry = playbooks() if registry is None else registry
    try:
        action = ctx.store.get_action(action_id)
    except KeyError:
        return _row(action_id, "", "", "refused", "", f"no action #{action_id}", "", plan_steps=[])
    if action.get("mode") != "manual":
        row = action_row(action)
        row.update(status="refused", detail=f"action #{action_id} is a {action.get('mode')} action; "
                                            "only manual actions can be resumed")
        return row
    if action.get("status") != "pending":
        return action_row(action)
    step = _advance_pending(registry, ctx, action, bool(ctx.steward_active()))
    if isinstance(step, Refusal):
        _refuse(ctx, ActResult(), step)
        row = action_row(ctx.store.get_action(action_id))
        row["detail"] = step.reason
        return row
    step["plan_steps"] = action_row(action)["plan_steps"]
    return step


def list_manual(ctx: ActCtx, registry: Mapping[str, Playbook] | None = None) -> list[dict]:
    """Plan (never apply, never journal) every component's open affected+fix_available findings:
    one row ``{component, playbook, finding_keys, target, refusal, age_gate, plan_steps}`` per
    selected playbook, plus rows with an empty playbook for findings without an automated fix."""
    registry = playbooks() if registry is None else registry
    rows: list[dict] = []
    components = sorted({f.component_id for f in ctx.findings.values()
                         if f.status == "affected" and f.fix_available})
    for component in components:
        spec = ctx.specs.get(component)
        if spec is None:
            keys = sorted(f.key for f in ctx.findings.values() if f.component_id == component)
            rows.append({"component": component, "playbook": "", "finding_keys": keys, "target": "",
                         "refusal": "component not in components.toml", "age_gate": "", "plan_steps": []})
            continue
        groups, no_fix, _missing = _fix_groups(ctx, spec)
        for pb_id, group in sorted(groups.items()):
            row = {"component": component, "playbook": pb_id, "finding_keys": [f.key for f in group],
                   "target": "", "refusal": "", "age_gate": "", "plan_steps": []}
            pb = registry.get(pb_id)
            if pb is None:
                row["refusal"] = f"playbook {pb_id!r} is not registered"
            else:
                try:
                    planned = pb.plan(list(group), spec, ctx)
                except Exception as exc:
                    planned = Refusal(pb_id, component, f"plan failed: {type(exc).__name__}: {exc}"[:500])
                if isinstance(planned, Plan):
                    row.update(target=planned.target, plan_steps=list(planned.steps),
                               age_gate=_two_source_gate(planned, group, ctx))
                elif isinstance(planned, Refusal):
                    row["refusal"] = planned.reason
                else:
                    row["refusal"] = f"plan returned {type(planned).__name__}"
            rows.append(row)
        for why, keys in sorted(no_fix.items()):
            rows.append({"component": component, "playbook": "", "finding_keys": keys, "target": "",
                         "refusal": f"no automated fix: {why}", "age_gate": "", "plan_steps": []})
    return rows
