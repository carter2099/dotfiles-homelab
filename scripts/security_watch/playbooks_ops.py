"""Operational remediation playbooks for security-watch.

Each playbook fixes one kind of component through its existing owner:

    apt-security        host/runtime apt packages (host lock)
    steward-freshrss    steward P1 FreshRSS image pin bump, else a Debian refresh of the derived image
    steward-openwebui   steward P1 guarded Open WebUI update
    steward-searxng     steward P1 SearXNG image pin bump (maturity override)
    steward-omp         steward P1 omp self-update
    steward-herdr       steward P1 herdr self-update
    steward-toolchain   steward P1 same-line toolchain update
    release-rebuild     repo release script for host Go binaries (Go stdlib fixes)
    compose-digest      news compose image tag@digest bump (no other owner)

``plan()`` never mutates production (metadata fetches and read-only git/dpkg/docker
probes; apt-security may refresh the apt lists under the host lock when they are stale).
``apply()`` takes the deploy lock itself, verifies image candidates against OSV before
switching, and always reports ``Outcome.state["production_touched"]``.  Image playbooks
apply a candidate that clears at least one planned finding and report the cleared subset
as ``Outcome.state["verified_keys"]`` (the only keys verification then checks); a
refusal that needs Carter carries ``Outcome.state["alert"]``.  Release, deploy and apt
subprocesses run in their own process group, killed as a whole on timeout.  The steward
P1 functions do not lock internally; they run inside the lock held here.
"""

from __future__ import annotations

import contextlib
import functools
import hashlib
import os
import re
import shlex
import shutil
import sys
import time
import urllib.error
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

import deploy_lock
from security_watch import config, model
from security_watch.model import Finding, Outcome, Package, Plan, Refusal

HEALTH_BUDGET_SECONDS = 60.0
HEALTH_POLL_SECONDS = 2.0
PULL_TIMEOUT = 600
RELEASE_TIMEOUT = 1800        # security-watch.service allows 2 h (TimeoutStartSec) for this path
TOOLCHAIN_BUDGET_SECONDS = 1800
APT_INSTALL_TIMEOUT = 900
APT_UPDATE_TIMEOUT = 600
APT_LISTS_MAX_AGE = 3600      # seconds; older lists are refreshed before a plan gives up on a candidate
# apt-get update touches the stamp (15update-stamp hook) and replaces changed list files.
APT_FRESHNESS_PATHS = (Path("/var/lib/apt/lists"), Path("/var/lib/apt/periodic/update-success-stamp"))
# The units that run apt/unattended-upgrade.  unattended-upgrades.service is NOT checked: on
# Ubuntu it is the always-active shutdown helper; the lock files catch any other apt run.
APT_BUSY_UNITS = ("apt-daily.service", "apt-daily-upgrade.service")
APT_LOCK_FILES = ("/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock", "/var/lib/apt/lists/lock")
_APT_LOCK_TEXT = ("Could not get lock", "Unable to acquire the dpkg frontend lock",
                  "Unable to lock directory", "Unable to lock the administration directory")
_BUSY_STATES = frozenset({"active", "activating", "deactivating", "reloading", "refreshing"})
SEARXNG_MAX_CANDIDATES = 5
GO_BUILD_LOCK = "toolchain-go-user"   # the steward swaps ~/.local/go under this key (exclusive)
# Components whose release must not overlap their own scheduled job: user units that use the
# deployed tree, and daily UTC start times (hour, minute).  A release is refused from
# QUIET_LEAD_SECONDS before a start (the longest release plus a margin, so one started just
# outside the window cannot still be running at the start) until QUIET_WINDOW_MINUTES after it.
QUIET_WINDOWS: dict[str, tuple[tuple[str, ...], tuple[tuple[int, int], ...]]] = {
    "homelab-backup": (("homelab-backup.service", "homelab-backup-restore-drill.service"), ((3, 0),)),
}
QUIET_WINDOW_MINUTES = 15
QUIET_LEAD_SECONDS = RELEASE_TIMEOUT + 5 * 60
_OWUI_STOPPED_MARK = "old container restarted"   # steward skip reason after it stopped open-webui
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_URGENCY_RANK = {model.URGENCY_URGENT: 0, model.URGENCY_NORMAL: 1, model.URGENCY_LOW: 2}
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

_DOCKER_APT = frozenset({
    "docker-ce", "docker-ce-cli", "containerd.io", "docker-ce-rootless-extras",
    "docker-buildx-plugin", "docker-compose-plugin",
})
_TOOLCHAIN_STEPS = {  # components.toml `toolchain` -> (p1_toolchain step, line width)
    "node": ("toolchain_node", 1),
    "go_user": ("toolchain_go_user", 2),
    "go_root": ("toolchain_go_root", 2),
}
_PY_LIST = (
    "import importlib.metadata as m\n"
    "for d in m.distributions():\n"
    "    n = d.metadata['Name']\n"
    "    if n:\n"
    "        print(n + '\\t' + str(d.version))\n"
)
_IMAGE_LINE = re.compile(
    r"^(?P<indent>[ \t]*)image:[ \t]*(?P<ref>(?P<repo>[A-Za-z0-9._/-]+):(?P<tag>[A-Za-z0-9._-]+)"
    r"@(?P<digest>sha256:[0-9a-f]{64}))[ \t]*$",
    re.M,
)


def _log(message: str) -> None:
    print(f"security-watch: playbooks: {message}", file=sys.stderr)


def _updates():
    from steward import updates
    return updates


def _toolchains():
    from steward import toolchains
    return toolchains


def _querybatch(packages, *, fetch):
    from security_watch import resolve
    return resolve.querybatch(packages, fetch=fetch)


def _version_lt(a: str, b: str) -> bool:
    from security_watch import resolve
    return resolve.version_lt(a, b)


# --- small helpers -------------------------------------------------------------

def _outcome(status: str, detail: str, *, touched: bool, undo: str = "",
             state: dict | None = None) -> Outcome:
    data = dict(state or {})
    data["production_touched"] = bool(touched)
    return Outcome(status=status, detail=str(detail)[:1500], undo=undo,
                   verify=status == "done", state=data)


def _run(ctx, argv, *, timeout: float = 120, env: dict | None = None, cwd: str | None = None):
    return ctx.run([str(a) for a in argv], timeout=timeout, env=env, cwd=cwd)


def _run_group(ctx, argv, *, timeout: float, env: dict | None = None, cwd: str | None = None):
    """A release/deploy/apt subprocess in its own session, whose whole process group is killed
    on timeout (``inventory.run_group``).  Only the production runner is swapped; any other
    ``ctx.run`` (tests, replay) is called as is."""
    from security_watch import inventory
    if ctx.run is inventory.default_run:
        return inventory.run_group([str(a) for a in argv], timeout=timeout, env=env, cwd=cwd)
    return _run(ctx, argv, timeout=timeout, env=env, cwd=cwd)


def _sha256(path: str | Path) -> str:
    try:
        with open(path, "rb") as fh:
            return hashlib.file_digest(fh, "sha256").hexdigest()
    except OSError:
        return ""


def _most_urgent(findings: list[Finding]) -> Finding:
    """The finding the two-source rule is evaluated for (first among equals)."""
    return min(findings, key=lambda f: (_URGENCY_RANK.get(f.urgency, 1), not f.kev,
                                        _SEVERITY_RANK.get(f.severity, 4)))


def _tail(proc, limit: int = 400) -> str:
    return f"{proc.stdout or ''}\n{proc.stderr or ''}".strip()[-limit:]


def _expand_argv(argv) -> list[str]:
    return [str(config.expand(a)) if str(a).startswith("~/") else str(a) for a in argv]


def _iso(value: Any) -> str | None:
    try:
        return model.iso(model.parse_iso(str(value))) if value else None
    except (TypeError, ValueError):
        return None


def _pkgs_text(findings: list[Finding]) -> str:
    seen: list[str] = []
    for f in findings:
        text = f"{f.package.name} {f.package.version}"
        if text not in seen:
            seen.append(text)
    return ", ".join(seen)


def _strip_v(version: str) -> str:
    version = str(version or "").strip()
    for prefix in ("go", "v"):
        if version.startswith(prefix) and version[len(prefix):][:1].isdigit():
            return version[len(prefix):]
    return version


def _vkey():
    return functools.cmp_to_key(
        lambda a, b: -1 if _version_lt(a, b) else (1 if _version_lt(b, a) else 0))


def _line(version: str, width: int) -> tuple[int, ...] | None:
    match = re.match(r"v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", _strip_v(version))
    if not match:
        return None
    parts = tuple(int(p) for p in match.groups() if p is not None)
    return parts[:width] if len(parts) >= width else None


def _min_newer(installed: str, fixed: list[str]) -> str | None:
    """Smallest fixed version newer than ``installed``."""
    newer = [_strip_v(v) for v in fixed if v and _version_lt(_strip_v(installed), _strip_v(v))]
    return min(newer, key=_vkey()) if newer else None


def _fix_hint(finding: Finding) -> str:
    """Exact fixed version for the two-source rule: smallest one above the installed version."""
    fixed = [v for v in finding.fixed_versions if v]
    if len(fixed) <= 1:
        return fixed[0] if fixed else ""
    newer = [v for v in fixed if _version_lt(finding.package.version, v)]
    return min(newer or fixed, key=_vkey())


def _semver(text: str) -> str:
    match = re.search(r"(\d+\.\d+\.\d+)", text or "")
    return match.group(1) if match else ""


class _Quiet(contextlib.redirect_stdout):
    """Steward P1 functions print progress; keep stdout for the CLI."""

    def __init__(self):
        super().__init__(sys.stderr)


class _Track:
    def __init__(self):
        self.touched = False
        self.undo = ""


# --- health ----------------------------------------------------------------------

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


def check_health(spec: config.ComponentSpec, *, probe: Callable[[str, str], int] = http_status,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic,
                 budget: float = HEALTH_BUDGET_SECONDS) -> tuple[bool, str]:
    """GET every spec.health URL until status < 400, retrying within ``budget`` seconds."""
    host = str(spec.get("health_host", "") or "")
    deadline = clock() + budget
    seen: list[str] = []
    for url in spec.health:
        while True:
            status = probe(url, host)
            if 0 < status < 400:
                seen.append(f"{url} {status}")
                break
            if clock() >= deadline:
                return False, f"{url} answered {status or 'nothing'} within {int(budget)}s"
            sleep(HEALTH_POLL_SECONDS)
    return True, "; ".join(seen) or "no health URLs"


# --- candidate image verification -----------------------------------------------

def _norm_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _listing_kind(ecosystem: str) -> str:
    if ecosystem.startswith(("Debian", "Ubuntu")):
        return "dpkg"
    if ecosystem.startswith("Alpine"):
        return "apk"
    return "pypi" if ecosystem == "PyPI" else ""


def candidate_listing(ctx, image: str, kind: str, spec: config.ComponentSpec,
                      cache: dict | None = None) -> dict[str, list[str]] | None:
    """``{package: [versions]}`` of one package manager inside ``image`` (dpkg/apk keyed by
    source/origin package, PyPI by normalized name), or None when it cannot be listed.
    ``cache`` keeps one listing per (image, kind), so a candidate costs one `docker run`
    per ecosystem however many findings it is checked for."""
    if cache is not None and (image, kind) in cache:
        return cache[(image, kind)]
    base = ["docker", "run", "--rm", "--network", "none", "--entrypoint"]
    if kind == "dpkg":
        argv = [*base, "dpkg-query", image, "-W", "-f", r"${source:Package}\t${source:Version}\n"]
    elif kind == "apk":
        argv = [*base, "apk", image, "list", "--installed"]
    elif kind == "pypi":
        python = spec.get("python") or ["python3"]
        python = [python] if isinstance(python, str) else list(python)
        argv = [*base, python[0], image, *python[1:], "-c", _PY_LIST]
    else:
        return None
    proc = _run(ctx, argv, timeout=180)
    listing: dict[str, list[str]] | None = None
    if proc.returncode == 0:
        found: dict[str, set[str]] = {}
        for line in (proc.stdout or "").splitlines():
            if kind == "apk":
                match = re.match(r"(\S+)\s+\S+\s+\{([^}]*)\}", line)
                pieces = match.group(1).rsplit("-", 2) if match else []
                if len(pieces) == 3:
                    found.setdefault(match.group(2), set()).add(f"{pieces[1]}-{pieces[2]}")
                continue
            name, _, version = line.partition("\t")
            name, version = name.strip(), version.strip()
            if name and version:
                found.setdefault(_norm_py(name) if kind == "pypi" else name, set()).add(version)
        listing = {name: sorted(versions) for name, versions in found.items()}
    if cache is not None:
        cache[(image, kind)] = listing
    return listing


def candidate_versions(ctx, image: str, pkg: Package, spec: config.ComponentSpec,
                       cache: dict | None = None) -> list[str] | None:
    """Versions of ``pkg`` inside ``image`` ([] = absent), or None when it cannot be listed."""
    kind = _listing_kind(pkg.ecosystem)
    listing = candidate_listing(ctx, image, kind, spec, cache) if kind else None
    if listing is None:
        return None
    return list(listing.get(_norm_py(pkg.name) if kind == "pypi" else pkg.name, []))


@dataclass
class CandidateCheck:
    """Which findings a candidate image clears.  ``error`` = nothing could be verified
    (pull or OSV failure, transient); otherwise ``still`` explains each uncleared finding."""
    image: str
    cleared: list[Finding] = field(default_factory=list)
    still: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def keys(self) -> list[str]:
        return [f.key for f in self.cleared]

    def refused(self) -> Outcome | None:
        """The refusal when nothing can be applied; alert only when the candidate clears nothing."""
        if self.error:
            return _outcome("refused", self.error, touched=False)
        if not self.cleared:
            return _outcome("refused", f"candidate {self.image} clears none of the {len(self.still)} "
                                       f"finding(s): {'; '.join(self.still)}",
                            touched=False, state={"alert": True})
        return None

    def stamp(self, out: Outcome) -> Outcome:
        """Record the verified subset on an apply outcome (and name what stays open)."""
        out.state["verified_keys"] = self.keys
        if self.still:
            total = len(self.cleared) + len(self.still)
            note = (f"candidate verified to clear {len(self.cleared)} of {total} finding(s); "
                    f"still shipped: {'; '.join(self.still)}")
            out.detail = f"{out.detail}; {note}"[:1500]
        return out


def verify_candidate(ctx, image: str, findings: list[Finding], spec: config.ComponentSpec,
                     querybatch=_querybatch, cache: dict | None = None) -> CandidateCheck:
    """Per finding: cleared when OSV no longer reports its advisories for the candidate's
    versions of its package (or the package is gone).  One listing per ecosystem, one OSV
    batch for every queried version."""
    cache = {} if cache is None else cache
    check = CandidateCheck(image)
    pending: list[tuple[Finding, list[str], list[Package]]] = []
    queried: dict[Package, None] = {}
    for finding in findings:
        pkg = finding.package
        versions = candidate_versions(ctx, image, pkg, spec, cache)
        if versions is None:
            check.still.append(f"could not list {pkg.ecosystem} package {pkg.name} inside {image}")
        elif not versions:
            check.cleared.append(finding)
        else:
            packages = [Package(pkg.ecosystem, pkg.name, v) for v in versions]
            pending.append((finding, versions, packages))
            queried.update(dict.fromkeys(packages))
    if not pending:
        return check
    try:
        hits = querybatch(list(queried), fetch=ctx.fetch)
    except Exception as exc:
        return CandidateCheck(image, error=f"OSV query for candidate {image} failed: "
                                           f"{type(exc).__name__}: {exc}")
    for finding, versions, packages in pending:
        wanted = set(finding.advisory_ids)
        still = sorted({vid for p in packages for vid, _ in (hits.get(p) or []) if vid in wanted})
        if still:
            check.still.append(f"{image} still ships {finding.package.name} {', '.join(versions)} "
                               f"affected by {', '.join(still)}")
        else:
            check.cleared.append(finding)
    return check


# --- base --------------------------------------------------------------------------

class _Base:
    id = ""
    multi_tick = False

    def __init__(self, *, probe: Callable[[str, str], int] | None = None,
                 sleep: Callable[[float], None] | None = None,
                 clock: Callable[[], float] | None = None, querybatch=None,
                 updates=None, toolchains=None, releases=None):
        self.probe = probe or http_status
        self.sleep = sleep or time.sleep
        self.clock = clock or time.monotonic
        self.querybatch = querybatch or _querybatch
        self._updates_mod = updates
        self._toolchains_mod = toolchains
        self._releases = releases

    def updates(self):
        return self._updates_mod or _updates()

    def toolchains(self):
        return self._toolchains_mod or _toolchains()

    @property
    def holder(self) -> str:
        return f"security-watch:{self.id}"

    def refusal(self, spec_id: str, reason: str, alert: bool = True) -> Refusal:
        return Refusal(playbook=self.id, component_id=spec_id, reason=reason, alert=alert)

    def health(self, spec) -> tuple[bool, str]:
        return check_health(spec, probe=self.probe, sleep=self.sleep, clock=self.clock)

    def lock(self, spec, ctx):
        return ctx.lock(spec.lock, timeout=ctx.policy.lock_timeout_seconds, holder=self.holder)

    def advance(self, action: dict, ctx) -> Outcome:
        return _outcome("failed", f"{self.id} is single-tick; nothing to advance", touched=False)

    def apply(self, plan: Plan, ctx) -> Outcome:
        spec = ctx.specs.get(plan.component_id)
        if spec is None:
            return _outcome("refused", f"unknown component {plan.component_id}", touched=False)
        track = _Track()
        try:
            with self.lock(spec, ctx):
                return self._apply(plan, spec, ctx, track)
        except deploy_lock.LockTimeout as exc:
            if track.touched:
                return _outcome("failed", f"{exc} after the change started", touched=True,
                                undo=track.undo or plan.undo)
            return _outcome("refused", f"{exc}; retrying next tick", touched=False)
        except Exception as exc:
            _log(f"{self.id} on {plan.component_id} raised {type(exc).__name__}: {exc}")
            return _outcome("failed", f"{self.id} apply raised {type(exc).__name__}: {exc}",
                            touched=track.touched, undo=track.undo or plan.undo)

    def _apply(self, plan: Plan, spec, ctx, track: _Track) -> Outcome:  # pragma: no cover
        raise NotImplementedError

    # shared by image playbooks
    def pull_and_verify(self, ctx, image: str, plan: Plan, spec, cache: dict | None = None) -> CandidateCheck:
        proc = _run(ctx, ["docker", "pull", image], timeout=PULL_TIMEOUT)
        if proc.returncode != 0:
            return CandidateCheck(image, error=f"docker pull {image} failed (exit {proc.returncode}): "
                                               f"{_tail(proc, 300)}")
        findings = [ctx.findings[k] for k in plan.finding_keys if k in ctx.findings]
        if not findings:
            return CandidateCheck(image, error="the plan's findings are no longer open")
        return verify_candidate(ctx, image, findings, spec, querybatch=self.querybatch, cache=cache)


def _map_packet(packet: dict, *, undo: str, ok: tuple[str, ...] = ("ok",),
                touched_on_failure: bool = True) -> Outcome:
    """Map a steward P1 packet onto an Outcome."""
    status = str(packet.get("status") or "")
    fields = [f"{k}={packet[k]}" for k in ("pre_version", "current_tag", "post_version", "latest_tag",
                                          "target_version", "reason", "error", "rollback_error")
              if packet.get(k)]
    detail = f"steward {packet.get('step', 'p1')}: {status}" + (f" ({'; '.join(fields)})" if fields else "")
    revert = str(packet.get("revert") or "")
    if status in ok:
        return _outcome("done", detail, touched=True, undo=revert or undo, state={"packet_status": status})
    if status in ("reverted", "rolled_back"):
        return _outcome("rolled_back", detail, touched=True, undo=revert or undo,
                        state={"packet_status": status})
    if status == "failed":
        return _outcome("failed", detail, touched=touched_on_failure, undo=revert or undo,
                        state={"packet_status": status})
    # skipped / current / warning / error: nothing changed in production
    return _outcome("refused", detail, touched=False, state={"packet_status": status})


# --- steward image playbooks ----------------------------------------------------

def _verify_step(findings, image: str) -> str:
    return (f"verify with OSV which of {_pkgs_text(findings)} {image} fixes; refuse (alert) if none, "
            "else apply and verify only the cleared findings")


def _image_plan(pb: _Base, spec, findings, *, target: str, image: str, current: str,
                published: Any, undo: str, owner_step: str, state: dict) -> Plan:
    return Plan(
        playbook=pb.id, component_id=spec.id, finding_keys=[f.key for f in findings],
        target=target, lock_keys=[spec.lock],
        steps=[f"docker pull {image}", _verify_step(findings, image),
               f"{owner_step} (pin, up, health, roll back on failure) under deploy lock {spec.lock}",
               "rescan the component"],
        undo=undo, release_published=_iso(published), fixed_version=_fix_hint(_most_urgent(findings)),
        state={"image": image, "current": current, **state},
    )


_COMPOSE_IMAGE = re.compile(r"^[ \t]*image:[ \t]*(?P<ref>[A-Za-z0-9._/-]+:[A-Za-z0-9._-]+)[ \t]*$", re.M)
BUILD_TIMEOUT = 1800


class StewardFreshRSS(_Base):
    """Upstream tag bump through the steward; without a newer tag, a Debian refresh.

    ~/freshrss deploys a local derived build (Dockerfile: the pinned upstream
    image as FRESHRSS_BASE plus an apt upgrade layer keyed by SECURITY_REFRESH).
    When upstream has not rebuilt, a new SECURITY_REFRESH picks up Debian
    security updates without changing the pin.
    """
    id = "steward-freshrss"

    def plan(self, findings, spec, ctx):
        up = self.updates()
        compose = Path(up.FRESHRSS_COMPOSE)
        try:
            text = compose.read_text()
        except OSError as exc:
            return self.refusal(spec.id, f"cannot read {compose}: {exc}")
        match = up._FRESHRSS_PIN_RE.search(text)
        if not match:
            return self.refusal(spec.id, f"could not parse the freshrss/freshrss tag@digest pin in {compose}")
        current = match.group(1)
        try:
            tags = ctx.fetch(up.FRESHRSS_TAGS_API, timeout=20).json().get("results", [])
        except Exception as exc:
            return self.refusal(spec.id, f"Docker Hub FreshRSS tag list unavailable: {exc}", alert=False)
        target = up._select_freshrss_tag(tags, current)
        if not target:
            return self._refresh_plan(findings, spec, ctx, up, compose, text, current)
        item = {"name": target["name"], "digest": target["digest"],
                "last_updated": target.get("last_updated", "")}
        image = f"freshrss/freshrss:{item['name']}@{item['digest']}"
        undo = (f"sed -i {shlex.quote('s|' + image + '|' + match.group(0) + '|')} {shlex.quote(str(compose))}"
                f" && {shlex.quote(str(up.FRESHRSS_UP))}")
        return _image_plan(self, spec, findings, target=f"freshrss {item['name']}", image=image,
                           current=current, published=item["last_updated"], undo=undo,
                           owner_step="steward _p1_freshrss_update", state={"item": item})

    def _refresh_plan(self, findings, spec, ctx, up, compose: Path, text: str, current: str):
        still = (f"no newer upstream FreshRSS release; current image {current} "
                 f"still ships {_pkgs_text(findings)}")
        if not all(f.package.ecosystem.startswith("Debian") for f in findings):
            return self.refusal(spec.id, still)
        images = [m.group("ref") for m in _COMPOSE_IMAGE.finditer(text)]
        if "FRESHRSS_BASE:" not in text or len(images) != 1:
            return self.refusal(spec.id, f"{still}; {compose} is not the derived build "
                                         "(build arg FRESHRSS_BASE + one local `image:` tag)")
        local = images[0]
        repo = local.rsplit(":", 1)[0]
        stamp = ctx.now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        workdir = compose.parent
        rollback = f"{repo}:rollback-{stamp}"
        candidate = f"{repo}:candidate-{stamp}"
        recreate = "docker compose up -d --no-build --force-recreate"
        undo = (f"docker tag {rollback} {local} && cd {shlex.quote(str(workdir))} && {recreate}")
        pkgs = ", ".join(dict.fromkeys(f.package.name for f in findings))
        container = str(spec.get("container", "") or spec.id)
        return Plan(
            playbook=self.id, component_id=spec.id, finding_keys=[f.key for f in findings],
            target=f"freshrss derived image refresh (Debian security updates for {pkgs})",
            lock_keys=[spec.lock],
            steps=[f"docker build {candidate} from the pinned base with SECURITY_REFRESH={stamp}",
                   _verify_step(findings, candidate),
                   f"tag the running image as {rollback}",
                   f"SECURITY_REFRESH={stamp} {up.FRESHRSS_UP} under deploy lock {spec.lock}",
                   "health check " + (", ".join(spec.health) or "(none)"),
                   f"on failure retag {rollback} as {local} and {recreate}",
                   "rescan the component"],
            # Debian security updates from the distro archive (like repo-pr base-refresh): not a newly
            # released upstream artifact, so exempt from the 72 h / two-source rule.
            undo=undo, release_published=None, fixed_version=_fix_hint(_most_urgent(findings)),
            state={"refresh": stamp, "current": current, "local": local, "candidate": candidate,
                   "rollback": rollback, "compose": str(compose), "up": str(up.FRESHRSS_UP),
                   "container": container},
        )

    def _apply(self, plan, spec, ctx, track):
        if plan.state.get("refresh"):
            return self._apply_refresh(plan, spec, ctx, track)
        check = self.pull_and_verify(ctx, plan.state["image"], plan, spec)
        refused = check.refused()
        if refused:
            return refused
        track.touched, track.undo = True, plan.undo
        with _Quiet():
            packet = self.updates()._p1_freshrss_update(tags=[plan.state["item"]])
        return check.stamp(_map_packet(
            packet, undo=plan.undo, ok=("ok", "updated", "bumped"),
            touched_on_failure=bool(packet.get("reverted_to") or packet.get("rollback_error"))))

    def _apply_refresh(self, plan, spec, ctx, track):
        st = plan.state
        compose = Path(st["compose"])
        workdir = str(compose.parent)
        findings = [ctx.findings[k] for k in plan.finding_keys if k in ctx.findings]
        if not findings:
            return _outcome("refused", "the plan's findings are no longer open", touched=False)
        match = self.updates()._FRESHRSS_PIN_RE.search(compose.read_text())
        if not match:
            return _outcome("refused", f"could not parse the freshrss/freshrss pin in {compose}", touched=False)
        stamp, candidate = st["refresh"], st["candidate"]
        proc = _run_group(ctx, ["docker", "build", "--build-arg", f"FRESHRSS_BASE={match.group(0)}",
                                "--build-arg", f"SECURITY_REFRESH={stamp}", "-t", candidate, workdir],
                          timeout=BUILD_TIMEOUT)
        if proc.returncode != 0:
            return _outcome("refused", f"candidate build failed (exit {proc.returncode}): {_tail(proc, 300)}",
                            touched=False)
        try:
            check = verify_candidate(ctx, candidate, findings, spec, querybatch=self.querybatch)
            refused = check.refused()
            if refused:
                return refused
            proc = _run(ctx, ["docker", "inspect", "--format", "{{.Image}}", st["container"]], timeout=60)
            running = (proc.stdout or "").strip()
            if proc.returncode != 0 or not running:
                return _outcome("refused", f"cannot find the running image of {st['container']}: {_tail(proc, 200)}",
                                touched=False)
            proc = _run(ctx, ["docker", "tag", running, st["rollback"]], timeout=60)
            if proc.returncode != 0:
                return _outcome("refused", f"cannot tag the rollback image {st['rollback']}: {_tail(proc, 200)}",
                                touched=False)
            track.touched, track.undo = True, plan.undo
            proc = _run_group(ctx, [st["up"]], timeout=BUILD_TIMEOUT, cwd=workdir,
                              env={**os.environ, "SECURITY_REFRESH": stamp})
            if proc.returncode == 0:
                healthy, health = self.health(spec)
                if healthy:
                    return check.stamp(_outcome(
                        "done", f"rebuilt {st['local']} with SECURITY_REFRESH={stamp} on "
                                f"{match.group(0)}; healthy ({health})", touched=True, undo=plan.undo))
                reason = f"health failed: {health}"
            else:
                reason = f"{st['up']} exited {proc.returncode}: {_tail(proc, 300)}"
            tagged = _run(ctx, ["docker", "tag", st["rollback"], st["local"]], timeout=60)
            again = _run_group(ctx, ["docker", "compose", "-f", str(compose), "up", "-d", "--no-build",
                                     "--force-recreate"], timeout=600, cwd=workdir)
            if tagged.returncode != 0 or again.returncode != 0:
                healthy, health = False, (f"rollback retag exited {tagged.returncode}, "
                                          f"up exited {again.returncode}: {_tail(again, 200)}")
            else:
                healthy, health = self.health(spec)
            if healthy:
                return check.stamp(_outcome("rolled_back", f"{reason}; restored {st['rollback']}; "
                                                           f"healthy ({health})", touched=True, undo=plan.undo))
            return check.stamp(_outcome("failed", f"{reason}; restored {st['rollback']} but still unhealthy: "
                                                  f"{health}", touched=True, undo=plan.undo))
        finally:
            _run(ctx, ["docker", "image", "rm", candidate], timeout=120)


class StewardOpenWebUI(_Base):
    id = "steward-openwebui"

    def plan(self, findings, spec, ctx):
        up = self.updates()
        compose = Path(up.OPENWEBUI_COMPOSE)
        try:
            text = compose.read_text()
        except OSError as exc:
            return self.refusal(spec.id, f"cannot read {compose}: {exc}")
        match = re.search(re.escape(up.OPENWEBUI_IMAGE) + r":([^\s\"'@]+)", text)
        current = match.group(1) if match else ""
        if not up._semver(current):
            return self.refusal(spec.id, f"could not parse an exact Open WebUI semver pin: {current!r}")
        try:
            release = ctx.fetch(up.GH_API, headers={"Accept": "application/vnd.github+json"},
                                timeout=20).json()
        except Exception as exc:
            return self.refusal(spec.id, f"Open WebUI release lookup failed: {exc}", alert=False)
        latest = str(release.get("tag_name") or "").lstrip("v")
        stable = not release.get("draft") and not release.get("prerelease") and up._semver(latest)
        if not stable or up._semver(latest) <= up._semver(current):
            return self.refusal(spec.id, f"no newer stable Open WebUI release; current image {current} "
                                         f"still ships {_pkgs_text(findings)}")
        release = {k: release.get(k) for k in ("tag_name", "html_url", "published_at", "draft", "prerelease")}
        image = f"{up.OPENWEBUI_IMAGE}:{latest}"
        undo = (f"steward rollback: restore {up.OPENWEBUI_IMAGE}:{current} in {compose} and the "
                f"pre-update data copy under {up.OPENWEBUI_RECOVERY_ROOT}")
        return _image_plan(self, spec, findings, target=f"open-webui {latest}", image=image,
                           current=current, published=release.get("published_at"), undo=undo,
                           owner_step="steward _p1_openwebui", state={"release": release})

    def _apply(self, plan, spec, ctx, track):
        check = self.pull_and_verify(ctx, plan.state["image"], plan, spec)
        refused = check.refused()
        if refused:
            return refused
        track.touched, track.undo = True, plan.undo
        with _Quiet():
            packet = self.updates()._p1_openwebui(False, release=plan.state["release"])
        status = str(packet.get("status") or "")
        reason = str(packet.get("reason") or packet.get("error") or "")
        if status in ("skipped", "error") and _OWUI_STOPPED_MARK in reason:
            # The steward stopped open-webui for its snapshot gate, then gave up: a downtime
            # cycle, not a no-op, so it must count as a failure (cooldown, cap, email).
            return check.stamp(_outcome(
                "failed", f"steward openwebui_update stopped open-webui, then {status}: {reason}",
                touched=True, undo=plan.undo, state={"packet_status": status}))
        error = str(packet.get("error") or "")
        untouched = error.startswith(("image pull failed", "image identity mismatch", "GitHub release lookup"))
        return check.stamp(_map_packet(packet, undo=plan.undo, ok=("ok",),
                                       touched_on_failure=bool(packet.get("local_mutation")) or not untouched))


def _searxng_undo(image: str, pin: str, compose: Path) -> str:
    return (f"sed -i {shlex.quote('s|' + image + '|' + pin + '|')} {shlex.quote(str(compose))}"
            f" && docker compose -f {shlex.quote(str(compose))} up -d")


def _tag_age(item: dict, now: datetime):
    try:
        published = model.parse_iso(str(item.get("last_updated") or ""))
    except ValueError:
        return None
    return now - published if published else None


class StewardSearXNG(_Base):
    id = "steward-searxng"

    def plan(self, findings, spec, ctx):
        up = self.updates()
        compose = Path(up.HOME) / "searxng" / "docker-compose.yml"
        try:
            text = compose.read_text()
        except OSError as exc:
            return self.refusal(spec.id, f"cannot read {compose}: {exc}")
        pin = re.search(r"docker\.io/searxng/searxng@sha256:[0-9a-f]{64}", text)
        if not pin:
            return self.refusal(spec.id, f"could not parse the immutable SearXNG image pin in {compose}")
        proc = _run(ctx, ["docker", "inspect", "searxng", "--format",
                          '{{index .Config.Labels "org.opencontainers.image.version"}}'], timeout=30)
        current = (proc.stdout or "").strip() if proc.returncode == 0 else ""
        if not up._searxng_tag_date(current):
            return self.refusal(spec.id, f"could not read the running SearXNG version label: {current!r}",
                                alert=False)
        try:
            tags = ctx.fetch(up.SEARXNG_TAGS_API, timeout=20).json().get("results", [])
        except Exception as exc:
            return self.refusal(spec.id, f"Docker Hub SearXNG tag list unavailable: {exc}", alert=False)
        current_item = next((t for t in tags if t.get("name") == current), None)
        anchor = [current_item] if current_item else []
        # Every tag newer than the running one, newest first (the steward's own ordering).
        pool = list(tags)
        newer: list[dict] = []
        pinned = None
        while len(newer) < SEARXNG_MAX_CANDIDATES:
            pick = up._select_mature_searxng_tag(pool, current, now=ctx.now, min_age_days=0)
            if not pick:
                break
            pool = [t for t in pool if t is not pick]
            item = {"name": pick["name"], "digest": pick["digest"], "last_updated": pick.get("last_updated", "")}
            image = f"docker.io/searxng/searxng@{item['digest']}"
            if image == pin.group(0):
                pinned = item
                continue
            mature = up._select_mature_searxng_tag([pick, *anchor], current, now=ctx.now) is not None
            newer.append({"item": item, "image": image, "mature": mature})
        if not newer:
            if pinned:
                return self.refusal(spec.id, f"SearXNG {pinned['name']} is already pinned and still ships "
                                             f"{_pkgs_text(findings)}")
            return self.refusal(spec.id, f"no newer upstream SearXNG release; current image {current} "
                                         f"still ships {_pkgs_text(findings)}")
        # Target = the newest tag already past act's age gate (else the newest: the two-source rule
        # decides).  Older tags than the target pass the same gate, so apply may fall back to them
        # newest-first when the target does not carry the fix.
        min_age = timedelta(hours=ctx.policy.release_min_age_hours)
        start = next((i for i, c in enumerate(newer)
                      if (age := _tag_age(c["item"], ctx.now)) is not None and age >= min_age), 0)
        candidates = newer[start:]
        target = candidates[0]
        state: dict[str, Any] = {"item": target["item"], "candidates": candidates, "current_item": current_item,
                                 "pin": pin.group(0), "compose": str(compose)}
        if not target["mature"]:
            # Younger than the steward soak: act's two-source rule gates it via release_published.
            state["min_age_days"] = 0
        plan = _image_plan(self, spec, findings, target=f"searxng {target['item']['name']}",
                           image=target["image"], current=current, published=target["item"]["last_updated"],
                           undo=_searxng_undo(target["image"], pin.group(0), compose),
                           owner_step="steward _p1_searxng_update", state=state)
        if len(candidates) > 1:
            plan.steps[1] += ("; if it clears none, try " + ", ".join(c["item"]["name"] for c in candidates[1:])
                              + " in that order")
        return plan

    def _apply(self, plan, spec, ctx, track):
        st = plan.state
        candidates = st.get("candidates") or [
            {"item": st["item"], "image": st["image"], "mature": "min_age_days" not in st}]
        cache: dict = {}
        failed: list[CandidateCheck] = []
        chosen, check = None, None
        for cand in candidates:
            check = self.pull_and_verify(ctx, cand["image"], plan, spec, cache)
            if check.refused() is None:
                chosen = cand
                break
            failed.append(check)
        if chosen is None:
            detail = " | ".join(c.refused().detail for c in failed)
            # Alert only when every candidate was verified and none clears anything.
            return _outcome("refused", detail, touched=False,
                            state={"alert": not any(c.error for c in failed)})
        undo = plan.undo
        if chosen["image"] != st["image"] and st.get("pin") and st.get("compose"):
            undo = _searxng_undo(chosen["image"], st["pin"], Path(st["compose"]))
        track.touched, track.undo = True, undo
        kwargs = {} if chosen["mature"] else {"min_age_days": 0}
        # The running tag rides along so the steward compares by publish time, not tag date.
        tags = [chosen["item"], *([st["current_item"]] if st.get("current_item") else [])]
        with _Quiet():
            packet = self.updates()._p1_searxng_update(tags=tags, now=ctx.now, **kwargs)
        out = _map_packet(packet, undo=undo, ok=("ok",),
                          touched_on_failure=bool(packet.get("reverted_to") or packet.get("rollback_error")))
        if failed:
            out.detail = (f"chose searxng {chosen['item']['name']} after "
                          f"{'; '.join(c.refused().detail for c in failed)}; {out.detail}")[:1500]
        return check.stamp(out)


# --- steward self-updating runtimes ------------------------------------------------

class _StewardRuntime(_Base):
    label = ""

    def plan(self, findings, spec, ctx):
        covered: list[Finding] = []
        fixes: list[str] = []
        for finding in findings:
            fix = _min_newer(finding.package.version, finding.fixed_versions)
            if fix:
                covered.append(finding)
                fixes.append(fix)
        if not covered:
            return self.refusal(spec.id, f"installed {_pkgs_text(findings)} is not older than any fixed "
                                         f"version ({', '.join(findings[0].fixed_versions) or 'none'})")
        fixed = max(fixes, key=_vkey())
        installed = covered[0].package.version
        return Plan(
            playbook=self.id, component_id=spec.id, finding_keys=[f.key for f in covered],
            target=f"{self.label} >= {fixed}", lock_keys=[spec.lock],
            steps=[f"steward {self.step_name} under deploy lock {spec.lock}",
                   f"require the installed version >= {fixed}", "rescan the component"],
            undo=self.undo_text(installed), fixed_version=fixed,
            state={"installed": installed, "fixed": fixed},
        )

    step_name = ""

    def undo_text(self, installed: str) -> str:  # pragma: no cover
        raise NotImplementedError

    def call(self):  # pragma: no cover
        raise NotImplementedError

    def _apply(self, plan, spec, ctx, track):
        track.touched, track.undo = True, plan.undo
        with _Quiet():
            packet = self.call()
        pre = _semver(str(packet.get("pre_version") or ""))
        post = _semver(str(packet.get("post_version") or ""))
        status = packet.get("status")
        if status == "ok" and post and _version_lt(post, plan.state["fixed"]):
            return _outcome("failed", f"{self.label} updated to {post}, still below the fixed "
                                      f"{plan.state['fixed']}", touched=True,
                            undo=str(packet.get("revert") or plan.undo))
        if status == "skipped":
            return _outcome("refused", f"{self.label}: {packet.get('reason') or 'skipped'} "
                                       f"(no release >= {plan.state['fixed']} installed)", touched=False)
        changed = bool(packet.get("reverted_to")) or (bool(pre) and pre != post)
        return _map_packet(packet, undo=plan.undo, ok=("ok",), touched_on_failure=changed)


class StewardOmp(_StewardRuntime):
    id = "steward-omp"
    label = "omp"
    step_name = "_p1_omp_update (snapshot, omp update, smoke, restore on breakage)"

    def undo_text(self, installed):
        return (f"install -m 755 ~/.local/state/omp-rollback/omp-{installed} ~/.bun/bin/omp "
                f"(snapshot the steward takes before updating)")

    def call(self):
        return self.updates()._p1_omp_update()


class StewardHerdr(_StewardRuntime):
    id = "steward-herdr"
    label = "herdr"
    step_name = "_p1_herdr_update (herdr update)"

    def undo_text(self, installed):
        return f"reinstall herdr {installed} from its GitHub release (`herdr update` keeps no rollback copy)"

    def call(self):
        return self.updates()._p1_herdr_update()


# --- steward toolchains -----------------------------------------------------------

def _default_releases(name: str, store) -> list[dict]:
    from security_watch import feeds
    if name == "node":
        return [{"version": _strip_v(r.get("version", "")), "date": r.get("date")}
                for r in feeds.node_index(store)]
    return [{"version": _strip_v(v)} for v in feeds.go_stable(store)]


def _go_release_date(store, version: str) -> str | None:
    """When Go ``version`` was released: the go_releases signal's own date, else when this
    watcher first saw it (never earlier than the release, so the age gate errs on the safe side)."""
    key = f"go{_strip_v(version)}"
    sig = store.signal("go_releases", key)
    if sig is None:
        return None
    if sig.published:
        return _iso(sig.published)
    for seen, first_seen, _ in store.signals_since(_EPOCH, sources=["go_releases"]):
        if seen.key == key:
            return _iso(first_seen)
    return None


class StewardToolchain(_Base):
    id = "steward-toolchain"

    def plan(self, findings, spec, ctx):
        name = str(spec.get("toolchain", ""))
        if name not in _TOOLCHAIN_STEPS:
            return self.refusal(spec.id, f"toolchain {name!r} has no steward P1 step")
        step, width = _TOOLCHAIN_STEPS[name]
        installed = _strip_v(findings[0].package.version)
        cur_line = _line(installed, width)
        fixes: list[str] = []
        for finding in findings:
            fixed = [_strip_v(v) for v in finding.fixed_versions if v]
            same = [v for v in fixed if _line(v, width) == cur_line and _version_lt(installed, v)]
            if not same:
                return self.refusal(spec.id, (
                    f"fixed version(s) {', '.join(fixed) or 'none'} for {finding.package.name} are on another "
                    f"line than installed {installed}; the steward P1 updates within "
                    f"{'.'.join(map(str, cur_line or ()))}.x only"))
            fixes.append(min(same, key=_vkey()))
        fixed = max(fixes, key=_vkey())
        try:
            releases = (self._releases or _default_releases)(name, ctx.store)
        except Exception as exc:
            return self.refusal(spec.id, f"release list unavailable: {exc}", alert=False)
        newest = self.toolchains().select_same_line(installed, releases, width)
        if not newest or _version_lt(newest["version"], fixed):
            have = newest["version"] if newest else installed
            return self.refusal(spec.id, f"newest same-line {name} release {have} is not >= fixed {fixed}")
        version = newest["version"]
        # The steward installs the newest same-line release, not necessarily the fixed one: the
        # age gate must see that release's own date.  Unknown date -> retry, never skip the gate.
        published = _iso(newest.get("date"))
        if not published and name != "node":
            published = _go_release_date(ctx.store, version)
        if not published:
            return self.refusal(spec.id, f"release date of {name} {version} is unknown; the 72 h / two-source "
                                         f"gate cannot be applied (retrying)", alert=False)
        return Plan(
            playbook=self.id, component_id=spec.id, finding_keys=[f.key for f in findings],
            target=f"{name} {version}", lock_keys=[spec.lock],
            steps=[f"steward toolchains.p1_toolchain({step!r}) under deploy lock {spec.lock}",
                   f"require {name} >= {fixed}", "rescan the component"],
            undo=f"steward toolchain rollback: switch {name} back to {installed}",
            release_published=published, fixed_version=fixed,
            state={"step": step, "fixed": fixed, "installed": installed, "target": version},
        )

    def _active_version(self, step: str) -> str:
        """The toolchain's active version per the steward driver ('' when unreadable)."""
        try:
            tc = self.toolchains()
            return _strip_v(str(tc.drivers(tc.Ctx(dry_run=True))[step].current() or ""))
        except Exception as exc:
            _log(f"cannot read the active {step} version: {type(exc).__name__}: {exc}")
            return ""

    def _apply(self, plan, spec, ctx, track):
        track.touched, track.undo = True, plan.undo
        with _Quiet():
            packet = self.toolchains().p1_toolchain(
                plan.state["step"], dry_run=False, deadline=time.monotonic() + TOOLCHAIN_BUDGET_SECONDS)
        status = packet.get("status")
        post = _strip_v(str(packet.get("post_version") or ""))
        if status == "ok" and (not post or _version_lt(post, plan.state["fixed"])):
            return _outcome("failed", f"toolchain now {post or 'unknown'}, below fixed {plan.state['fixed']}",
                            touched=True, undo=str(packet.get("revert") or plan.undo))
        if status == "warning":
            # ToolchainError or an unexpected exception: production is untouched only when the
            # active version is provably still the planned-from one.
            active = self._active_version(plan.state["step"])
            unchanged = bool(active) and active == plan.state["installed"]
            return _outcome("failed", f"steward {plan.state['step']}: {packet.get('error', 'warning')} "
                                      f"(active version {active or 'unreadable'})",
                            touched=not unchanged, undo="" if unchanged else plan.undo)
        return _map_packet(packet, undo=plan.undo, ok=("ok",), touched_on_failure=True)


# --- apt-security -----------------------------------------------------------------

def _dpkg_ge(ctx, a: str, b: str) -> bool:
    return _run(ctx, ["dpkg", "--compare-versions", a, "ge", b], timeout=30).returncode == 0


def _upstream(version: str) -> str:
    version = re.sub(r"^\d+:", "", version or "")
    return version.rsplit("-", 1)[0] if "-" in version else version


def _apt_policy(ctx, packages: list[str]) -> dict[str, tuple[str, str]]:
    """``{package: (installed, candidate)}`` keyed exactly as requested.

    ``apt-cache policy libfoo:amd64`` prints its header as ``libfoo:``, so headers are
    matched on the name without the architecture qualifier.
    """
    proc = _run(ctx, ["apt-cache", "policy", *packages], timeout=60)
    requested = {p.split(":", 1)[0]: p for p in packages}
    result: dict[str, tuple[str, str]] = {}
    current = ""
    installed = ""
    for line in (proc.stdout or "").splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            header = line.rstrip()[:-1]
            current, installed = requested.get(header.split(":", 1)[0], header), ""
        elif current and line.strip().startswith("Installed:"):
            installed = line.split(":", 1)[1].strip()
        elif current and line.strip().startswith("Candidate:"):
            candidate = line.split(":", 1)[1].strip()
            result[current] = (installed, candidate)
    return result


def _dpkg_installed(ctx) -> list[tuple[str, str, str]]:
    """(source package, binary package, version) of every installed package."""
    proc = _run(ctx, ["dpkg-query", "-W", "-f",
                      r"${db:Status-Abbrev}\t${source:Package}\t${binary:Package}\t${Version}\n"], timeout=60)
    rows = []
    for line in (proc.stdout or "").splitlines():
        parts = line.split("\t")
        if len(parts) == 4 and parts[0].startswith("ii"):
            rows.append((parts[1], parts[2], parts[3]))
    return rows


def _apt_lock_error(proc) -> bool:
    text = f"{proc.stdout or ''}\n{proc.stderr or ''}"
    return any(marker in text for marker in _APT_LOCK_TEXT)


def _unit_states(ctx, units, *, user: bool) -> list[str] | None:
    """``systemctl is-active`` state per unit (None when unreadable)."""
    proc = _run(ctx, ["systemctl", *(["--user"] if user else []), "is-active", *units], timeout=30)
    states = (proc.stdout or "").split()
    return states if len(states) == len(units) else None


def _apt_busy(ctx) -> str:
    """Why apt/dpkg is busy right now ('' when idle; an unreadable state counts as busy)."""
    states = _unit_states(ctx, APT_BUSY_UNITS, user=False)
    if states is None:
        return f"cannot read the state of {', '.join(APT_BUSY_UNITS)}"
    running = [u for u, s in zip(APT_BUSY_UNITS, states) if s in _BUSY_STATES]
    if running:
        return f"{', '.join(running)} running"
    proc = _run(ctx, ["sudo", "-n", "fuser", *APT_LOCK_FILES], timeout=30)
    if proc.returncode == 0:
        return f"apt/dpkg lock files in use (pids {' '.join((proc.stdout or '').split()) or '?'})"
    if proc.returncode != 1 or (proc.stderr or "").strip():
        return f"cannot check the apt/dpkg locks: {_tail(proc, 200)}"
    return ""


def _apt_update(ctx) -> tuple[str, bool]:
    """Refresh the apt lists (caller holds the host lock): ('', False) on success, else
    (reason, alert).  Busy/lock contention retries silently; any other failure is an alert
    (a broken source needs Carter) but never a failed action: nothing was installed."""
    busy = _apt_busy(ctx)
    if busy:
        return f"apt busy: {busy}; retrying later", False
    proc = _run_group(ctx, ["sudo", "-n", "apt-get", "update", "-qq"], timeout=APT_UPDATE_TIMEOUT)
    if proc.returncode == 0:
        return "", False
    if _apt_lock_error(proc):
        return f"apt-get update could not take the apt lock: {_tail(proc, 200)}; retrying later", False
    return f"apt-get update failed (exit {proc.returncode}): {_tail(proc, 300)}", True


def _apt_lists_age(now: datetime) -> float:
    """Seconds since the apt lists were last refreshed (inf when unknown)."""
    mtimes = []
    for path in APT_FRESHNESS_PATHS:
        with contextlib.suppress(OSError):
            mtimes.append(path.stat().st_mtime)
    return now.timestamp() - max(mtimes) if mtimes else float("inf")


class AptSecurity(_Base):
    id = "apt-security"

    def lock(self, spec, ctx):
        # Host-wide apt work: the exclusive host lock already excludes every surface lock.
        return ctx.host_lock(timeout=ctx.policy.lock_timeout_seconds, holder=self.holder)

    def plan(self, findings, spec, ctx):
        runtime_pkgs = list(spec.get("apt_packages") or [])
        scan = self._candidates(findings, spec, ctx, runtime_pkgs)
        if isinstance(scan, Refusal):
            return scan
        if scan["missing"] and _apt_lists_age(ctx.now) > APT_LISTS_MAX_AGE:
            # The lists may predate the fix: refresh once, then decide on fresh candidates.
            try:
                with ctx.host_lock(timeout=ctx.policy.lock_timeout_seconds, holder=self.holder):
                    reason, alert = _apt_update(ctx)
            except deploy_lock.LockTimeout as exc:
                reason, alert = f"{exc}; stale apt lists not refreshed, retrying next tick", False
            if reason:
                return self.refusal(spec.id, reason, alert=alert)
            scan = self._candidates(findings, spec, ctx, runtime_pkgs)
            if isinstance(scan, Refusal):
                return scan
        covered, chosen, targets = scan["covered"], scan["chosen"], scan["targets"]
        installed, policy = scan["installed"], scan["policy"]
        if not covered:
            return self.refusal(spec.id, "; ".join(scan["problems"])[:1000])
        install = sorted({p for f in covered for p in targets[f.key]})
        old = {p: installed.get(p, "") for p in install}
        undo = "sudo apt-get install --allow-downgrades " + " ".join(
            shlex.quote(f"{p}={v}") for p, v in old.items() if v)
        units = list(spec.get("system_units") or [])
        steps = [f"require {', '.join(APT_BUSY_UNITS)} idle and no process holding the apt/dpkg locks",
                 "sudo -n apt-get update -qq (host lock)",
                 f"apt-get -s install --only-upgrade {' '.join(install)}: refuse if it would remove a package",
                 f"sudo -n apt-get install --only-upgrade --no-remove -y {' '.join(install)} (host lock)"]
        if any(p in _DOCKER_APT or p.startswith(("docker", "containerd")) for p in install):
            steps.append("wait for the docker stack and assert the daemon root")
        if "cloudflared" in install:
            steps.append("sudo -n systemctl restart cloudflared; require active")
        gate = ([f"systemctl is-active {' '.join(units)}"] if units else []) + list(spec.health)
        steps.append("health gate: " + (", ".join(gate) or "(none)")
                     + "; on failure no automatic downgrade (as with unattended-upgrades): failed, "
                       "breaker, email with the undo")
        steps.append("rescan the component")
        return Plan(
            playbook=self.id, component_id=spec.id, finding_keys=[f.key for f in covered],
            target=", ".join(f"{p} {policy[p][1]}" for p in install if p in policy),
            # Distro/vendor apt archives: exempt from the 72 h / two-source rule (no release_published).
            lock_keys=["host"], steps=steps, undo=undo,
            fixed_version=chosen[_most_urgent(covered).key],
            state={"packages": install, "old": old, "fixed": chosen, "runtime": bool(runtime_pkgs),
                   "targets": {f.key: targets[f.key] for f in covered}},
        )

    def _candidates(self, findings, spec, ctx, runtime_pkgs: list[str]) -> dict | Refusal:
        """Per finding, the smallest fixed version the apt candidates reach (from the current lists)."""
        rows = _dpkg_installed(ctx)
        installed = {binary: version for _, binary, version in rows}
        targets: dict[str, list[str]] = {}
        if runtime_pkgs:
            present = [p for p in runtime_pkgs if p in installed]
            if not present:
                return self.refusal(spec.id, f"none of {', '.join(runtime_pkgs)} is installed")
            for finding in findings:
                targets[finding.key] = present
        else:
            by_source: dict[str, list[str]] = {}
            for source, binary, _ in rows:
                by_source.setdefault(source, []).append(binary)
            for finding in findings:
                targets[finding.key] = by_source.get(finding.package.name, [])
        packages = sorted({p for pkgs in targets.values() for p in pkgs})
        policy = _apt_policy(ctx, packages) if packages else {}

        covered: list[Finding] = []
        chosen: dict[str, str] = {}
        problems: list[str] = []
        missing = False
        for finding in findings:
            pkgs = targets.get(finding.key) or []
            if not pkgs:
                problems.append(f"{finding.package.name}: no installed binary package")
                continue
            fixed_all = [_strip_v(v) if runtime_pkgs else v for v in finding.fixed_versions if v]
            fixed_all = sorted(fixed_all, key=functools.cmp_to_key(
                lambda a, b: 0 if a == b else (1 if _dpkg_ge(ctx, a, b) else -1)))
            pick = ""
            for fixed in fixed_all:
                if runtime_pkgs:
                    primary = pkgs[0]
                    cand = policy.get(primary, ("", ""))[1]
                    if (cand and cand != "(none)" and _dpkg_ge(ctx, _upstream(cand), fixed)
                            and not _dpkg_ge(ctx, _upstream(installed.get(primary, "")), fixed)):
                        pick = fixed
                        break
                else:
                    cands = [policy.get(p, ("", ""))[1] for p in pkgs]
                    if (all(c and c != "(none)" and _dpkg_ge(ctx, c, fixed) for c in cands)
                            and any(not _dpkg_ge(ctx, installed.get(p, ""), fixed) for p in pkgs)):
                        pick = fixed
                        break
            if pick:
                covered.append(finding)
                chosen[finding.key] = pick
            else:
                missing = True
                shown = ", ".join(f"{p} {installed.get(p, '?')} -> {policy.get(p, ('', '(none)'))[1] or '(none)'}"
                                  for p in pkgs)
                problems.append(f"{finding.package.name}: no apt candidate >= fixed "
                                f"{', '.join(fixed_all) or '(none)'} ({shown})")
        return {"installed": installed, "targets": targets, "policy": policy, "covered": covered,
                "chosen": chosen, "problems": problems, "missing": missing}

    def _apply(self, plan, spec, ctx, track):
        packages = list(plan.state["packages"])
        reason, alert = _apt_update(ctx)
        if reason:
            return _outcome("refused", reason, touched=False, state={"alert": alert})
        sim = _run(ctx, ["apt-get", "-s", "install", "--only-upgrade", *packages], timeout=300)
        if sim.returncode != 0:
            if _apt_lock_error(sim):
                return _outcome("refused", f"apt simulation could not take the apt lock: {_tail(sim, 200)}; "
                                           "retrying later", touched=False)
            return _outcome("refused", f"apt-get -s install failed (exit {sim.returncode}): {_tail(sim, 300)}",
                            touched=False, state={"alert": True})
        removed = [line.split()[1] for line in (sim.stdout or "").splitlines()
                   if line.startswith("Remv ") and len(line.split()) > 1]
        if removed:
            return _outcome("refused", f"upgrading {' '.join(packages)} would remove {', '.join(removed)}; "
                                       "not installing (resolve by hand)", touched=False, state={"alert": True})
        planned = {p.split(":", 1)[0] for p in packages}
        extra = sorted({line.split()[1].split(":", 1)[0] for line in (sim.stdout or "").splitlines()
                        if line.startswith("Inst ") and len(line.split()) > 1} - planned)
        track.touched, track.undo = True, plan.undo
        proc = _run_group(ctx, ["sudo", "-n", "apt-get", "install", "--only-upgrade", "--no-remove", "-y",
                                "-o", "DPkg::Lock::Timeout=120",
                                "-o", "Dpkg::Options::=--force-confdef",
                                "-o", "Dpkg::Options::=--force-confold", *packages],
                          timeout=APT_INSTALL_TIMEOUT)
        if proc.returncode != 0:
            if _apt_lock_error(proc):  # apt never got the lock: nothing was unpacked
                return _outcome("refused", f"apt-get install could not take the apt lock: {_tail(proc, 200)}; "
                                           "retrying later", touched=False)
            return _outcome("failed", f"apt-get install failed (exit {proc.returncode}): {_tail(proc)}",
                            touched=True, undo=plan.undo)
        now_installed = {binary: version for _, binary, version in _dpkg_installed(ctx)}
        problems = []
        for key, fixed in plan.state["fixed"].items():
            pkgs = plan.state["targets"][key][:1] if plan.state["runtime"] else plan.state["targets"][key]
            for pkg in pkgs:
                version = now_installed.get(pkg, "")
                have = _upstream(version) if plan.state["runtime"] else version
                if not version or not _dpkg_ge(ctx, have, fixed):
                    problems.append(f"{pkg} is {version or 'missing'}, below fixed {fixed}")
        notes = [", ".join(f"{p} {plan.state['old'].get(p, '?')} -> {now_installed.get(p, '?')}" for p in packages)]
        if extra:
            notes.append(f"also installed/upgraded as dependencies: {', '.join(extra)}")
        if any(p in _DOCKER_APT or p.startswith(("docker", "containerd")) for p in packages):
            up = self.updates()
            with _Quiet():
                ready = up._wait_docker_stack_ready(120)
                asserted = up._p1_docker_assert()
            if ready.get("status") != "ok":
                problems.append(f"docker stack not ready: {ready}")
            if asserted.get("status") != "ok":
                problems.append(f"docker daemon assert failed: {asserted.get('error')}")
        if "cloudflared" in packages:
            restart = _run(ctx, ["sudo", "-n", "systemctl", "restart", "cloudflared"], timeout=120)
            active = _run(ctx, ["systemctl", "is-active", "cloudflared"], timeout=30)
            if restart.returncode != 0 or (active.stdout or "").strip() != "active":
                problems.append(f"cloudflared not active after restart: {(active.stdout or '').strip()} "
                                f"{_tail(restart, 200)}")
            else:
                notes.append("cloudflared restarted")
        # Health gate: system units of the spec (system scope) plus its loopback origins.  There is
        # no automatic downgrade (older versions usually leave the indexes; unattended-upgrades does
        # not roll back either): a failure is `failed`, touched -> breaker + email with the undo.
        units = list(spec.get("system_units") or [])
        if units:
            states = _unit_states(ctx, units, user=False)
            down = [f"{u} {s}" for u, s in zip(units, states or ["unreadable"] * len(units)) if s != "active"]
            if down:
                problems.append(f"system units not active: {', '.join(down)}")
        healthy, health = self.health(spec)
        if not healthy:
            problems.append(f"health: {health}")
        if problems:
            return _outcome("failed", "; ".join(notes + problems), touched=True, undo=plan.undo)
        return _outcome("done", "; ".join(notes + ([f"healthy ({health})"] if units or spec.health else [])),
                        touched=True, undo=plan.undo)


# --- release-rebuild -----------------------------------------------------------------

def _git(ctx, repo: Path, *args, timeout: float = 60):
    return _run(ctx, ["git", "-C", str(repo), *args], timeout=timeout)


def _host_go_version() -> str:
    try:
        first = (config.home() / ".local/go/VERSION").read_text().splitlines()[0]
    except (OSError, IndexError):
        return ""
    return _strip_v(first.strip())


def _go_affected(version: str, fixed: list[str]) -> bool:
    fixed = [_strip_v(v) for v in fixed if v]
    if not fixed:
        return True
    same = [v for v in fixed if _line(v, 2) == _line(version, 2)]
    if same:
        return _version_lt(version, min(same, key=_vkey()))
    return _version_lt(version, min(fixed, key=_vkey()))


def _same_revision(a: str, b: str) -> bool:
    a, b = (a or "").strip().lower(), (b or "").strip().lower()
    if not a or not b:
        return False
    return a == b or (min(len(a), len(b)) >= 12 and (a.startswith(b) or b.startswith(a)))


def _quiet_reason(ctx, spec) -> str:
    """Why ``spec``'s release must wait for its own scheduled job ('' when clear)."""
    units, starts = QUIET_WINDOWS.get(spec.id, ((), ()))
    now = ctx.now.astimezone(timezone.utc)
    second = now.hour * 3600 + now.minute * 60 + now.second
    for hour, start in starts:
        # Signed offset from the start, wrapped to (-12 h, +12 h].
        offset = (second - (hour * 3600 + start * 60) + 43200) % 86400 - 43200
        if -QUIET_LEAD_SECONDS <= offset <= QUIET_WINDOW_MINUTES * 60:
            return (f"within the {hour:02d}:{start:02d} UTC {spec.id} run window "
                    f"({QUIET_LEAD_SECONDS // 60} min before to {QUIET_WINDOW_MINUTES} min after); "
                    "retrying after it")
    if units:
        states = _unit_states(ctx, units, user=True)
        if states is None:
            return f"cannot read the state of {', '.join(units)}"
        running = [u for u, s in zip(units, states) if s in _BUSY_STATES]
        if running:
            return f"{', '.join(running)} is running; retrying after it"
    return ""


class ReleaseRebuild(_Base):
    id = "release-rebuild"

    def plan(self, findings, spec, ctx):
        stdlib = [f for f in findings if f.package.ecosystem == "Go" and f.package.name == "stdlib"]
        if not stdlib:
            return self.refusal(spec.id, "release-rebuild only fixes Go stdlib findings")
        host_go = _host_go_version()
        if not host_go:
            return self.refusal(spec.id, "cannot read the host Go toolchain version (~/.local/go/VERSION)")
        # Only the findings the host Go already fixes; the rest wait for the go-user toolchain.
        stdlib = [f for f in stdlib if not _go_affected(host_go, f.fixed_versions)]
        if not stdlib:
            return self.refusal(spec.id, f"host Go {host_go} is affected; the go-user toolchain fix comes first",
                                alert=False)
        quiet = _quiet_reason(ctx, spec)
        if quiet:
            return self.refusal(spec.id, quiet, alert=False)
        if not spec.repo or not spec.get("release"):
            return self.refusal(spec.id, "component has no repo or release command")
        repo = config.home() / "dev" / spec.repo
        if not (repo / ".git").exists():
            return self.refusal(spec.id, f"{repo} is not a git checkout")
        status = _git(ctx, repo, "status", "--porcelain")
        if status.returncode != 0:
            return self.refusal(spec.id, f"git status failed in {repo}: {_tail(status, 200)}", alert=False)
        if (status.stdout or "").strip():
            return self.refusal(spec.id, f"{repo} has uncommitted changes; a rebuild would ship them")
        branch = (_git(ctx, repo, "branch", "--show-current").stdout or "").strip()
        if branch != "main":
            return self.refusal(spec.id, f"{repo} is on branch {branch or '(detached)'}, not main; "
                                         f"a rebuild would ship that code")
        fetched = _git(ctx, repo, "fetch", "--quiet", "origin", timeout=120)
        if fetched.returncode != 0:
            return self.refusal(spec.id, f"git fetch origin failed in {repo}: {_tail(fetched, 200)}", alert=False)
        head = (_git(ctx, repo, "rev-parse", "HEAD").stdout or "").strip()
        origin = (_git(ctx, repo, "rev-parse", "origin/main").stdout or "").strip()
        if not head or head != origin:
            return self.refusal(spec.id, f"{repo} HEAD {head[:12] or '?'} != origin/main {origin[:12] or '?'}; "
                                         f"a rebuild would ship code that differs from origin/main")
        inv = ctx.store.get_inventory(spec.id)
        entries = {}
        for entry in (inv.meta.get("binaries", []) if inv else []):
            if entry.get("path"):
                entries[str(config.expand(str(entry["path"])))] = entry
        binaries = [config.expand(b) for b in spec.get("binaries", [])]
        if not binaries:
            return self.refusal(spec.id, "component lists no binaries to snapshot")
        for path in binaries:
            entry = entries.get(str(path)) or {}
            revision = str(entry.get("vcs_revision") or "")
            if not _same_revision(revision, head):
                return self.refusal(spec.id, (
                    f"{path} was built from {revision[:12] or 'an unknown revision'} but {repo} HEAD is "
                    f"{head[:12]}; a rebuild would ship new code, not only the Go fix"))
            if entry.get("vcs_modified"):
                return self.refusal(spec.id, (
                    f"{path} was built from a modified tree (vcs.modified=true) on {revision[:12]}; "
                    "a rebuild from the clean checkout would drop those changes"))
        fixes = [v for v in (_min_newer(f.package.version, f.fixed_versions) for f in stdlib) if v]
        fixed = max(fixes, key=_vkey()) if fixes else ""
        units = list(spec.get("units", []))
        snapshot_root = config.state_dir() / "rollback" / spec.id
        undo = (f"install -m 755 the binaries snapshotted under {snapshot_root}/<timestamp>/ back to "
                f"{', '.join(map(str, binaries))}"
                + (f" && systemctl --user restart {' '.join(units)}" if units else ""))
        return Plan(
            playbook=self.id, component_id=spec.id, finding_keys=[f.key for f in stdlib],
            target=f"{spec.repo} {head[:12]} rebuild with go{host_go}", lock_keys=[spec.lock],
            steps=[f"snapshot {', '.join(map(str, binaries))} to {snapshot_root}/<timestamp>/",
                   f"under the lock: require a clean {repo} at HEAD {head[:12]}"
                   + (f" and {spec.id}'s own job idle" if spec.id in QUIET_WINDOWS else ""),
                   f"hold deploy lock {GO_BUILD_LOCK} (shared) and require no steward run, then run "
                   f"{' '.join(spec.get('release'))} in {repo} with ~/.local/go/bin first on PATH "
                   f"(process group, {RELEASE_TIMEOUT}s)",
                   "health check " + (", ".join(spec.health) or "(none)"),
                   "release failed with every binary unchanged and healthy: failed, untouched (no restart)",
                   "otherwise on failure restore the snapshots" + (f" and restart {' '.join(units)}" if units else ""),
                   "rescan the component"],
            undo=undo, fixed_version=fixed,
            state={"head": head, "host_go": host_go, "binaries": [str(b) for b in binaries]},
        )

    def _restore(self, ctx, spec, pairs: list[list[str]], reason: str, undo: str) -> Outcome:
        errors = []
        for src, snap in pairs:
            target = Path(src)
            tmp = target.with_name(f".{target.name}.security-watch-restore")
            try:
                shutil.copyfile(snap, tmp)
                os.chmod(tmp, 0o755)
                os.replace(tmp, target)
            except OSError as exc:
                errors.append(f"restore {target}: {exc}")
        units = list(spec.get("units", []))
        if units:
            proc = _run(ctx, ["systemctl", "--user", "restart", *units], timeout=180)
            if proc.returncode != 0:
                errors.append(f"restart {' '.join(units)} failed: {_tail(proc, 200)}")
        healthy, health = self.health(spec)
        detail = f"{reason}; restored snapshots" + (f"; restarted {' '.join(units)}" if units else "")
        if errors or not healthy:
            return _outcome("failed", f"{detail}; {'; '.join(errors + ([] if healthy else [health]))}",
                            touched=True, undo=undo)
        return _outcome("rolled_back", f"{detail}; healthy again ({health})", touched=True, undo=undo)

    def _apply(self, plan, spec, ctx, track):
        binaries = [Path(b) for b in plan.state["binaries"]]
        missing = [str(b) for b in binaries if not b.is_file()]
        if missing:
            return _outcome("refused", f"binaries missing, nothing to snapshot: {', '.join(missing)}",
                            touched=False)
        home = config.home()
        repo = home / "dev" / spec.repo
        # Re-check under the deploy lock: the plan's checks ran before the lock wait.
        quiet = _quiet_reason(ctx, spec)
        if quiet:
            return _outcome("refused", quiet, touched=False)
        status = _git(ctx, repo, "status", "--porcelain")
        if status.returncode != 0:
            return _outcome("refused", f"git status failed in {repo}: {_tail(status, 200)}", touched=False)
        if (status.stdout or "").strip():
            return _outcome("refused", f"{repo} has uncommitted changes since the plan; a rebuild would ship them",
                            touched=False, state={"alert": True})
        head = (_git(ctx, repo, "rev-parse", "HEAD").stdout or "").strip()
        if head != plan.state["head"]:
            return _outcome("refused", f"{repo} HEAD moved to {head[:12] or '?'} since the plan "
                                       f"({plan.state['head'][:12]}); replanning next tick", touched=False)
        stamp = ctx.now.strftime("%Y%m%dT%H%M%SZ")
        snap_dir = config.state_dir() / "rollback" / spec.id / stamp
        snap_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(snap_dir, 0o700)
        pairs: list[list[str]] = []
        used: set[str] = set()
        for index, binary in enumerate(binaries):
            name = binary.name if binary.name not in used else f"{index}-{binary.name}"
            used.add(name)
            dest = snap_dir / name
            shutil.copyfile(binary, dest)
            os.chmod(dest, 0o755)
            pairs.append([str(binary), str(dest)])
        units = list(spec.get("units", []))
        undo = " && ".join(f"install -m 755 {shlex.quote(snap)} {shlex.quote(src)}" for src, snap in pairs)
        if units:
            undo += f" && systemctl --user restart {' '.join(units)}"
        env = dict(os.environ)
        env["PATH"] = f"{home}/.local/go/bin:{home}/.local/bin:{os.environ.get('PATH', '')}"
        argv = _expand_argv(spec.get("release"))
        # The steward swaps ~/.local/go under this key (exclusive): no swap mid-build.
        with deploy_lock.service_lock(GO_BUILD_LOCK, shared=True, timeout=ctx.policy.lock_timeout_seconds,
                                      holder=self.holder):
            if ctx.steward_active():
                return _outcome("refused", "steward run started; retrying next tick", touched=False)
            track.touched, track.undo = True, undo
            proc = _run_group(ctx, argv, timeout=RELEASE_TIMEOUT, env=env, cwd=str(repo))
        state = {"snapshot": str(snap_dir), "release_exit": proc.returncode}
        if proc.returncode != 0:
            reason = f"release {' '.join(argv)} exited {proc.returncode}: {_tail(proc, 300)}"
            changed = [src for src, snap in pairs if _sha256(src) != _sha256(snap)]
            if not changed:
                healthy, health = self.health(spec)
                if healthy:
                    # Died before replacing anything (tests, vet, build): production untouched.
                    return _outcome("failed", f"{reason}; every binary unchanged and healthy ({health}); "
                                              "nothing restarted", touched=False, state=state)
                reason = f"{reason}; binaries unchanged but unhealthy: {health}"
            else:
                reason = f"{reason}; changed: {', '.join(changed)}"
            out = self._restore(ctx, spec, pairs, reason, undo)
            out.state.update(state)
            return out
        healthy, health = self.health(spec)
        if healthy:
            return _outcome("done", f"rebuilt {spec.repo} at {plan.state['head'][:12]} with "
                                    f"go{plan.state['host_go']}; healthy ({health})",
                            touched=True, undo=undo, state=state)
        out = self._restore(ctx, spec, pairs, f"health failed after release: {health}", undo)
        out.state.update(state)
        return out


# --- compose-digest ---------------------------------------------------------------

def _hub_repo(repo: str) -> str | None:
    repo = repo.removeprefix("docker.io/")
    if "/" in repo and "." in repo.split("/", 1)[0]:
        return None  # another registry
    return repo if "/" in repo else f"library/{repo}"


def _write_text_atomic(path: Path, text: str) -> None:
    tmp = path.with_name(f".{path.name}.security-watch.tmp")
    tmp.write_text(text)
    with contextlib.suppress(OSError):
        os.chmod(tmp, path.stat().st_mode & 0o7777)
    os.replace(tmp, path)


class ComposeDigest(_Base):
    id = "compose-digest"

    def plan(self, findings, spec, ctx):
        compose = config.expand(str(spec.get("compose", "")))
        try:
            text = compose.read_text()
        except OSError as exc:
            return self.refusal(spec.id, f"cannot read {compose}: {exc}")
        matches = list(_IMAGE_LINE.finditer(text))
        if len(matches) != 1:
            return self.refusal(spec.id, f"expected exactly one `image: <repo>:<tag>@sha256:<digest>` line in "
                                         f"{compose}, found {len(matches)}")
        match = matches[0]
        repo, tag, digest = match.group("repo"), match.group("tag"), match.group("digest")
        hub = _hub_repo(repo)
        if not hub:
            return self.refusal(spec.id, f"{repo} is not a Docker Hub image")
        base = f"https://hub.docker.com/v2/repositories/{hub}/tags"
        try:
            info = ctx.fetch(f"{base}/{tag}", timeout=20).json()
        except Exception as exc:
            return self.refusal(spec.id, f"Docker Hub tag lookup failed: {exc}", alert=False)
        new_tag, new_digest, published = "", "", None
        if info.get("digest") and info["digest"] != digest:
            new_tag, new_digest, published = tag, info["digest"], info.get("last_updated")
        else:
            version = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(.*)", tag)
            if not version:
                return self.refusal(spec.id, f"{repo}:{tag} is unchanged and not a <major>.<minor>.<patch> tag")
            major, minor, patch, suffix = version.groups()
            pattern = re.compile(rf"{major}\.{minor}\.(\d+){re.escape(suffix)}")
            best: tuple[int, dict] | None = None
            url: str | None = f"{base}?name={major}.{minor}.&page_size=100"
            pages = 0
            try:
                while url and pages < 5:
                    page = ctx.fetch(url, timeout=20).json()
                    pages += 1
                    for item in page.get("results", []):
                        hit = pattern.fullmatch(str(item.get("name", "")))
                        if hit and item.get("digest") and int(hit.group(1)) > int(patch):
                            if best is None or int(hit.group(1)) > best[0]:
                                best = (int(hit.group(1)), item)
                    url = page.get("next")
            except Exception as exc:
                return self.refusal(spec.id, f"Docker Hub tag list failed: {exc}", alert=False)
            if best is None:
                return self.refusal(spec.id, (
                    f"no newer {repo} {major}.{minor}.x{suffix} image than {tag} (digest unchanged); "
                    f"it still ships {_pkgs_text(findings)}"))
            new_tag, new_digest, published = best[1]["name"], best[1]["digest"], best[1].get("last_updated")
        image = f"{repo}:{new_tag}@{new_digest}"
        old_line = match.group(0)
        new_line = f"{match.group('indent')}image: {image}"
        up = " ".join(_expand_argv(spec.get("up", [])))
        undo = (f"sed -i {shlex.quote('s|' + image + '|' + match.group('ref') + '|')} "
                f"{shlex.quote(str(compose))} && {up}")
        return Plan(
            playbook=self.id, component_id=spec.id, finding_keys=[f.key for f in findings],
            target=f"{repo}:{new_tag}@{new_digest[:19]}", lock_keys=[spec.lock],
            steps=[f"docker pull {image}", _verify_step(findings, "it"),
                   f"rewrite the image line in {compose}", f"run {up}",
                   "health check " + (", ".join(spec.health) or "(none)"),
                   "on failure restore the compose file and rerun", "rescan the component"],
            undo=undo, release_published=_iso(published), fixed_version=_fix_hint(_most_urgent(findings)),
            state={"image": image, "compose": str(compose), "old_line": old_line, "new_line": new_line},
        )

    def _apply(self, plan, spec, ctx, track):
        check = self.pull_and_verify(ctx, plan.state["image"], plan, spec)
        refused = check.refused()
        if refused:
            return refused
        compose = Path(plan.state["compose"])
        original = compose.read_text()
        lines = original.splitlines(keepends=True)
        index = next((i for i, line in enumerate(lines) if line.rstrip("\r\n") == plan.state["old_line"]), None)
        if index is None:
            return _outcome("refused", f"{compose} changed since the plan; image line not found", touched=False)
        ending = lines[index][len(lines[index].rstrip("\r\n")):]
        lines[index] = plan.state["new_line"] + ending
        argv = _expand_argv(spec.get("up", []))
        track.touched, track.undo = True, plan.undo
        _write_text_atomic(compose, "".join(lines))
        proc = _run_group(ctx, argv, timeout=600, cwd=str(compose.parent))
        if proc.returncode == 0:
            healthy, health = self.health(spec)
            if healthy:
                return check.stamp(_outcome("done", f"pinned {plan.state['image']}; healthy ({health})",
                                            touched=True, undo=plan.undo))
            reason = f"health failed: {health}"
        else:
            reason = f"{' '.join(argv)} exited {proc.returncode}: {_tail(proc, 300)}"
        _write_text_atomic(compose, original)
        again = _run_group(ctx, argv, timeout=600, cwd=str(compose.parent))
        healthy, health = self.health(spec) if again.returncode == 0 else (False, f"rerun exited {again.returncode}")
        if healthy:
            return check.stamp(_outcome("rolled_back", f"{reason}; restored the original image line; "
                                                       f"healthy ({health})", touched=True, undo=plan.undo))
        return check.stamp(_outcome("failed", f"{reason}; restored the original image line but still "
                                              f"unhealthy: {health}", touched=True, undo=plan.undo))


PLAYBOOKS: dict[str, _Base] = {pb.id: pb for pb in (
    AptSecurity(),
    StewardFreshRSS(),
    StewardOpenWebUI(),
    StewardSearXNG(),
    StewardOmp(),
    StewardHerdr(),
    StewardToolchain(),
    ReleaseRebuild(),
    ComposeDigest(),
)}
