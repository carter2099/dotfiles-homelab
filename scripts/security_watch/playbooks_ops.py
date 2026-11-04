"""Operational remediation playbooks for security-watch.

Each playbook fixes one kind of component through its existing owner:

    apt-security        host/runtime apt packages (host lock)
    steward-freshrss    steward P1 FreshRSS image pin bump
    steward-openwebui   steward P1 guarded Open WebUI update
    steward-searxng     steward P1 SearXNG image pin bump (maturity override)
    steward-omp         steward P1 omp self-update
    steward-herdr       steward P1 herdr self-update
    steward-toolchain   steward P1 same-line toolchain update
    release-rebuild     repo release script for host Go binaries (Go stdlib fixes)
    compose-digest      news compose image tag@digest bump (no other owner)

``plan()`` never mutates (metadata fetches and read-only git/dpkg/docker probes
only).  ``apply()`` takes the deploy lock itself, verifies image candidates
against OSV before switching, and always reports
``Outcome.state["production_touched"]``.  The steward P1 functions do not lock
internally; they run inside the lock held here.
"""

from __future__ import annotations

import contextlib
import functools
import os
import re
import shlex
import shutil
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

import deploy_lock
from security_watch import config, model
from security_watch.model import Finding, Outcome, Package, Plan, Refusal

HEALTH_BUDGET_SECONDS = 60.0
HEALTH_POLL_SECONDS = 2.0
PULL_TIMEOUT = 600
RELEASE_TIMEOUT = 1800
TOOLCHAIN_BUDGET_SECONDS = 1800
APT_INSTALL_TIMEOUT = 1800

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


def candidate_versions(ctx, image: str, pkg: Package, spec: config.ComponentSpec) -> list[str] | None:
    """Versions of ``pkg`` inside ``image`` ([] = absent), or None when it cannot be listed."""
    base = ["docker", "run", "--rm", "--network", "none", "--entrypoint"]
    eco = pkg.ecosystem
    if eco.startswith(("Debian", "Ubuntu")):
        argv = [*base, "dpkg-query", image, "-W", "-f", r"${source:Package}\t${source:Version}\n"]
    elif eco.startswith("Alpine"):
        argv = [*base, "apk", image, "list", "--installed"]
    elif eco == "PyPI":
        python = spec.get("python") or ["python3"]
        python = [python] if isinstance(python, str) else list(python)
        argv = [*base, python[0], image, *python[1:], "-c", _PY_LIST]
    else:
        return None
    proc = _run(ctx, argv, timeout=180)
    if proc.returncode != 0:
        return None
    versions: set[str] = set()
    for line in (proc.stdout or "").splitlines():
        if eco.startswith("Alpine"):
            match = re.match(r"(\S+)\s+\S+\s+\{([^}]*)\}", line)
            if not match or match.group(2) != pkg.name:
                continue
            pieces = match.group(1).rsplit("-", 2)
            if len(pieces) == 3:
                versions.add(f"{pieces[1]}-{pieces[2]}")
            continue
        name, _, version = line.partition("\t")
        if not version.strip():
            continue
        same = _norm_py(name) == _norm_py(pkg.name) if eco == "PyPI" else name.strip() == pkg.name
        if same:
            versions.add(version.strip())
    return sorted(versions)


def verify_candidate(ctx, image: str, findings: list[Finding], spec: config.ComponentSpec,
                     querybatch=_querybatch) -> str:
    """'' when OSV no longer reports any finding's advisories for the candidate's package."""
    for finding in findings:
        pkg = finding.package
        versions = candidate_versions(ctx, image, pkg, spec)
        if versions is None:
            return f"could not list {pkg.ecosystem} package {pkg.name} inside candidate {image}"
        if not versions:
            continue
        queried = [Package(pkg.ecosystem, pkg.name, v) for v in versions]
        try:
            hits = querybatch(queried, fetch=ctx.fetch)
        except Exception as exc:
            return f"OSV query for the candidate failed: {type(exc).__name__}: {exc}"
        wanted = set(finding.advisory_ids)
        still = sorted({vid for p in queried for vid, _ in (hits.get(p) or []) if vid in wanted})
        if still:
            return (f"candidate {image} still ships {pkg.name} {', '.join(versions)} "
                    f"affected by {', '.join(still)}")
    return ""


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
    def pull_and_verify(self, ctx, image: str, plan: Plan, spec) -> str:
        proc = _run(ctx, ["docker", "pull", image], timeout=PULL_TIMEOUT)
        if proc.returncode != 0:
            return f"docker pull {image} failed (exit {proc.returncode}): {_tail(proc, 300)}"
        findings = [ctx.findings[k] for k in plan.finding_keys if k in ctx.findings]
        if not findings:
            return "the plan's findings are no longer open"
        return verify_candidate(ctx, image, findings, spec, querybatch=self.querybatch)


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

def _image_plan(pb: _Base, spec, findings, *, target: str, image: str, current: str,
                published: Any, undo: str, owner_step: str, state: dict) -> Plan:
    return Plan(
        playbook=pb.id, component_id=spec.id, finding_keys=[f.key for f in findings],
        target=target, lock_keys=[spec.lock],
        steps=[f"docker pull {image}",
               f"verify with OSV that {_pkgs_text(findings)} is fixed inside {image}",
               f"{owner_step} (pin, up, health, roll back on failure) under deploy lock {spec.lock}",
               "rescan the component"],
        undo=undo, release_published=_iso(published), fixed_version=_fix_hint(findings[0]),
        state={"image": image, "current": current, **state},
    )


class StewardFreshRSS(_Base):
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
            return self.refusal(spec.id, f"no newer upstream FreshRSS release; current image {current} "
                                         f"still ships {_pkgs_text(findings)}")
        item = {"name": target["name"], "digest": target["digest"],
                "last_updated": target.get("last_updated", "")}
        image = f"freshrss/freshrss:{item['name']}@{item['digest']}"
        undo = (f"sed -i {shlex.quote('s|' + image + '|' + match.group(0) + '|')} {shlex.quote(str(compose))}"
                f" && {shlex.quote(str(up.FRESHRSS_UP))}")
        return _image_plan(self, spec, findings, target=f"freshrss {item['name']}", image=image,
                           current=current, published=item["last_updated"], undo=undo,
                           owner_step="steward _p1_freshrss_update", state={"item": item})

    def _apply(self, plan, spec, ctx, track):
        reason = self.pull_and_verify(ctx, plan.state["image"], plan, spec)
        if reason:
            return _outcome("refused", reason, touched=False)
        track.touched, track.undo = True, plan.undo
        with _Quiet():
            packet = self.updates()._p1_freshrss_update(tags=[plan.state["item"]])
        return _map_packet(packet, undo=plan.undo, ok=("ok", "updated", "bumped"),
                           touched_on_failure=bool(packet.get("reverted_to") or packet.get("rollback_error")))


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
        reason = self.pull_and_verify(ctx, plan.state["image"], plan, spec)
        if reason:
            return _outcome("refused", reason, touched=False)
        track.touched, track.undo = True, plan.undo
        with _Quiet():
            packet = self.updates()._p1_openwebui(False, release=plan.state["release"])
        error = str(packet.get("error") or "")
        untouched = error.startswith(("image pull failed", "image identity mismatch", "GitHub release lookup"))
        return _map_packet(packet, undo=plan.undo, ok=("ok",),
                           touched_on_failure=bool(packet.get("local_mutation")) or not untouched)


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
        state: dict[str, Any] = {}
        target = up._select_mature_searxng_tag(tags, current, now=ctx.now)
        if not target:
            target = up._select_mature_searxng_tag(tags, current, now=ctx.now, min_age_days=0)
            if target:
                # Younger than the steward soak: act's two-source rule gates it via release_published.
                state["min_age_days"] = 0
        if not target:
            return self.refusal(spec.id, f"no newer upstream SearXNG release; current image {current} "
                                         f"still ships {_pkgs_text(findings)}")
        item = {"name": target["name"], "digest": target["digest"],
                "last_updated": target.get("last_updated", "")}
        image = f"docker.io/searxng/searxng@{item['digest']}"
        if image == pin.group(0):
            return self.refusal(spec.id, f"SearXNG {item['name']} is already pinned and still ships "
                                         f"{_pkgs_text(findings)}")
        undo = (f"sed -i {shlex.quote('s|' + image + '|' + pin.group(0) + '|')} {shlex.quote(str(compose))}"
                f" && docker compose -f {shlex.quote(str(compose))} up -d")
        return _image_plan(self, spec, findings, target=f"searxng {item['name']}", image=image,
                           current=current, published=item["last_updated"], undo=undo,
                           owner_step="steward _p1_searxng_update", state={"item": item, **state})

    def _apply(self, plan, spec, ctx, track):
        reason = self.pull_and_verify(ctx, plan.state["image"], plan, spec)
        if reason:
            return _outcome("refused", reason, touched=False)
        track.touched, track.undo = True, plan.undo
        kwargs = {"min_age_days": plan.state["min_age_days"]} if "min_age_days" in plan.state else {}
        with _Quiet():
            packet = self.updates()._p1_searxng_update(tags=[plan.state["item"]], now=ctx.now, **kwargs)
        return _map_packet(packet, undo=plan.undo, ok=("ok",),
                           touched_on_failure=bool(packet.get("reverted_to") or packet.get("rollback_error")))


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
        return Plan(
            playbook=self.id, component_id=spec.id, finding_keys=[f.key for f in findings],
            target=f"{name} {newest['version']}", lock_keys=[spec.lock],
            steps=[f"steward toolchains.p1_toolchain({step!r}) under deploy lock {spec.lock}",
                   f"require {name} >= {fixed}", "rescan the component"],
            undo=f"steward toolchain rollback: switch {name} back to {installed}",
            release_published=_iso(newest.get("date")), fixed_version=fixed,
            state={"step": step, "fixed": fixed, "installed": installed, "target": newest["version"]},
        )

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
        if status == "warning":  # ToolchainError: the switch never happened or rolled itself back
            return _outcome("failed", f"steward {plan.state['step']}: {packet.get('error', 'warning')}",
                            touched=False)
        return _map_packet(packet, undo=plan.undo, ok=("ok",), touched_on_failure=True)


# --- apt-security -----------------------------------------------------------------

def _dpkg_ge(ctx, a: str, b: str) -> bool:
    return _run(ctx, ["dpkg", "--compare-versions", a, "ge", b], timeout=30).returncode == 0


def _upstream(version: str) -> str:
    version = re.sub(r"^\d+:", "", version or "")
    return version.rsplit("-", 1)[0] if "-" in version else version


def _apt_policy(ctx, packages: list[str]) -> dict[str, tuple[str, str]]:
    proc = _run(ctx, ["apt-cache", "policy", *packages], timeout=60)
    result: dict[str, tuple[str, str]] = {}
    current = ""
    installed = ""
    for line in (proc.stdout or "").splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            current, installed = line.rstrip()[:-1], ""
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


class AptSecurity(_Base):
    id = "apt-security"

    def lock(self, spec, ctx):
        # Host-wide apt work: the exclusive host lock already excludes every surface lock.
        return ctx.host_lock(timeout=ctx.policy.lock_timeout_seconds, holder=self.holder)

    def plan(self, findings, spec, ctx):
        runtime_pkgs = list(spec.get("apt_packages") or [])
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
                shown = ", ".join(f"{p} {installed.get(p, '?')} -> {policy.get(p, ('', '(none)'))[1] or '(none)'}"
                                  for p in pkgs)
                problems.append(f"{finding.package.name}: no apt candidate >= fixed "
                                f"{', '.join(fixed_all) or '(none)'} ({shown})")
        if not covered:
            return self.refusal(spec.id, "; ".join(problems)[:1000])
        install = sorted({p for f in covered for p in targets[f.key]})
        old = {p: installed.get(p, "") for p in install}
        undo = "sudo apt-get install --allow-downgrades " + " ".join(
            shlex.quote(f"{p}={v}") for p, v in old.items() if v)
        steps = ["sudo -n apt-get update -qq",
                 f"sudo -n apt-get install --only-upgrade -y {' '.join(install)} (host lock)"]
        if any(p in _DOCKER_APT or p.startswith(("docker", "containerd")) for p in install):
            steps.append("wait for the docker stack and assert the daemon root")
        if "cloudflared" in install:
            steps.append("sudo -n systemctl restart cloudflared; require active")
        steps.append("rescan the component")
        return Plan(
            playbook=self.id, component_id=spec.id, finding_keys=[f.key for f in covered],
            target=", ".join(f"{p} {policy[p][1]}" for p in install if p in policy),
            lock_keys=["host"], steps=steps, undo=undo,
            fixed_version=chosen[covered[0].key],
            state={"packages": install, "old": old, "fixed": chosen, "runtime": bool(runtime_pkgs),
                   "targets": {f.key: targets[f.key] for f in covered}},
        )

    def _apply(self, plan, spec, ctx, track):
        packages = list(plan.state["packages"])
        proc = _run(ctx, ["sudo", "-n", "apt-get", "update", "-qq"], timeout=600)
        if proc.returncode != 0:
            return _outcome("failed", f"apt-get update failed (exit {proc.returncode}): {_tail(proc)}",
                            touched=False)
        track.touched, track.undo = True, plan.undo
        proc = _run(ctx, ["sudo", "-n", "apt-get", "install", "--only-upgrade", "-y",
                          "-o", "DPkg::Lock::Timeout=120",
                          "-o", "Dpkg::Options::=--force-confdef",
                          "-o", "Dpkg::Options::=--force-confold", *packages],
                    timeout=APT_INSTALL_TIMEOUT)
        if proc.returncode != 0:
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
        healthy, health = self.health(spec)
        if not healthy:
            problems.append(f"health: {health}")
        if problems:
            return _outcome("failed", "; ".join(notes + problems), touched=True, undo=plan.undo)
        return _outcome("done", "; ".join(notes), touched=True, undo=plan.undo)


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


class ReleaseRebuild(_Base):
    id = "release-rebuild"

    def plan(self, findings, spec, ctx):
        stdlib = [f for f in findings if f.package.ecosystem == "Go" and f.package.name == "stdlib"]
        if not stdlib:
            return self.refusal(spec.id, "release-rebuild only fixes Go stdlib findings")
        host_go = _host_go_version()
        if not host_go:
            return self.refusal(spec.id, "cannot read the host Go toolchain version (~/.local/go/VERSION)")
        for finding in stdlib:
            if _go_affected(host_go, finding.fixed_versions):
                return self.refusal(spec.id, f"host Go {host_go} is affected; the go-user toolchain fix comes first",
                                    alert=False)
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
            revision = str((entries.get(str(path)) or {}).get("vcs_revision") or "")
            if not _same_revision(revision, head):
                return self.refusal(spec.id, (
                    f"{path} was built from {revision[:12] or 'an unknown revision'} but {repo} HEAD is "
                    f"{head[:12]}; a rebuild would ship new code, not only the Go fix"))
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
                   f"run {' '.join(spec.get('release'))} in {repo} with ~/.local/go/bin first on PATH",
                   "health check " + (", ".join(spec.health) or "(none)"),
                   "on failure restore the snapshots" + (f" and restart {' '.join(units)}" if units else ""),
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
        home = config.home()
        env = dict(os.environ)
        env["PATH"] = f"{home}/.local/go/bin:{home}/.local/bin:{os.environ.get('PATH', '')}"
        repo = home / "dev" / spec.repo
        argv = _expand_argv(spec.get("release"))
        track.touched, track.undo = True, undo
        proc = _run(ctx, argv, timeout=RELEASE_TIMEOUT, env=env, cwd=str(repo))
        state = {"snapshot": str(snap_dir), "release_exit": proc.returncode}
        if proc.returncode != 0:
            reason = f"release {' '.join(argv)} exited {proc.returncode}: {_tail(proc, 300)}"
            if spec.get("transactional"):
                healthy, health = self.health(spec)
                if healthy:
                    return _outcome("rolled_back", f"{reason}; the release script rolled back; healthy ({health})",
                                    touched=True, undo=undo, state=state)
                reason = f"{reason}; unhealthy after the script's rollback: {health}"
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
            steps=[f"docker pull {image}",
                   f"verify with OSV that {_pkgs_text(findings)} is fixed inside it",
                   f"rewrite the image line in {compose}", f"run {up}",
                   "health check " + (", ".join(spec.health) or "(none)"),
                   "on failure restore the compose file and rerun", "rescan the component"],
            undo=undo, release_published=_iso(published), fixed_version=_fix_hint(findings[0]),
            state={"image": image, "compose": str(compose), "old_line": old_line, "new_line": new_line},
        )

    def _apply(self, plan, spec, ctx, track):
        reason = self.pull_and_verify(ctx, plan.state["image"], plan, spec)
        if reason:
            return _outcome("refused", reason, touched=False)
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
        proc = _run(ctx, argv, timeout=600, cwd=str(compose.parent))
        if proc.returncode == 0:
            healthy, health = self.health(spec)
            if healthy:
                return _outcome("done", f"pinned {plan.state['image']}; healthy ({health})",
                                touched=True, undo=plan.undo)
            reason = f"health failed: {health}"
        else:
            reason = f"{' '.join(argv)} exited {proc.returncode}: {_tail(proc, 300)}"
        _write_text_atomic(compose, original)
        again = _run(ctx, argv, timeout=600, cwd=str(compose.parent))
        healthy, health = self.health(spec) if again.returncode == 0 else (False, f"rerun exited {again.returncode}")
        if healthy:
            return _outcome("rolled_back", f"{reason}; restored the original image line; healthy ({health})",
                            touched=True, undo=plan.undo)
        return _outcome("failed", f"{reason}; restored the original image line but still unhealthy: {health}",
                        touched=True, undo=plan.undo)


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
