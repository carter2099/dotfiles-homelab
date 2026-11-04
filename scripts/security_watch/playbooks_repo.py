"""repo-pr playbook: deterministic repo edit -> PR -> CI -> merge -> owner deploy.

The only playbook that edits a repo (contract principle 5).  Each action is one
edit kind, chosen from issuer-record fields only (ecosystem, package, fixed
version):

  base-refresh   Dockerfile ``ARG SECURITY_REFRESH=<stamp>`` before the stage's
                 package-upgrade RUN, so the next build re-runs the distro upgrade
  go-builder     Dockerfile ``FROM golang:<X.Y.Z>-<variant>[@sha256:...]`` bump
  go-toolchain   go.mod ``toolchain go<X.Y.Z>`` bump
  go-module      ``go get <module>@v<fixed>`` + ``go mod tidy``
  pip-pin        requirements.txt ``name==<fixed>`` bump

apply() opens the PR from a throw-away worktree of origin/main; advance() walks
``ci -> merging -> deploy`` across ticks.  Carter stops an action by labelling the
PR ``hold`` (or closing it).  The deploy runs under ``ctx.lock(spec.lock)`` through
the component's existing owner: steward P1 app_deploy or the repo's release script.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import tempfile
import time
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable

from deploy_lock import LockTimeout

from security_watch import config, model, net
from security_watch.config import ComponentSpec
from security_watch.model import Finding, Outcome, Plan, Refusal

PLAYBOOK_ID = "repo-pr"
GITHUB_OWNER = "carter2099"
PR_LABEL = "security-watch"
HOLD_LABEL = "hold"
WAIT_LIMIT = timedelta(hours=24)        # CI, merge and deploy each give up after this
RELEASE_TIMEOUT = 1800
HEALTH_ATTEMPTS = 6
HEALTH_RETRY_SECONDS = 5
HUB_TAG_URL = "https://hub.docker.com/v2/repositories/library/golang/tags/{tag}"
PR_VIEW_FIELDS = "state,mergeable,mergeStateStatus,headRefOid,labels,statusCheckRollup,mergeCommit"

OS_ECOSYSTEM_PREFIXES = ("Debian:", "Ubuntu:", "Alpine:")
_CI_OK_CONCLUSIONS = frozenset({"success", "neutral", "skipped"})
_URGENCY_RANK = {model.URGENCY_URGENT: 0, model.URGENCY_NORMAL: 1, model.URGENCY_LOW: 2}


def _log(message: str) -> None:
    print(f"security-watch: repo-pr: {message}", file=sys.stderr)


# --- versions ----------------------------------------------------------------

def _strip_prefix(version: str) -> str:
    value = str(version).strip()
    if value.startswith("go"):
        return value[2:]
    if value[:1] in ("v", "V"):
        return value[1:]
    return value


def _vkey(version: str) -> tuple:
    """Sort key for Go/semver/PEP 440-ish versions (numeric release, pre < final < post)."""
    value = _strip_prefix(version)
    match = re.match(r"(\d+(?:\.\d+)*)(.*)", value)
    if not match:
        return ((), 0, value)
    nums = [int(part) for part in match[1].split(".")]
    while nums and nums[-1] == 0:
        nums.pop()
    rest = match[2]
    if not rest or rest.startswith("+"):
        rank = 1
    elif re.match(r"[.-]?post", rest, re.I):
        rank = 2
    else:
        rank = 0
    return (tuple(nums), rank, rest)


def _vlt(a: str, b: str) -> bool:
    return _vkey(a) < _vkey(b)


def _minor_line(version: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", _strip_prefix(version))[:2]
    return tuple(int(p) for p in parts)


def _same_line_fixed(fixed: list[str], current: str) -> str | None:
    """Smallest fixed version on ``current``'s major.minor line."""
    line = _minor_line(current)
    same = [_strip_prefix(v) for v in fixed if _minor_line(v) == line]
    return min(same, key=_vkey) if same else None


def _smallest_fixed_above(fixed: list[str], installed: str) -> str | None:
    above = [_strip_prefix(v) for v in fixed if _vlt(installed, v)]
    return min(above, key=_vkey) if above else None


def _max_version(a: str | None, b: str) -> str:
    return b if a is None or _vlt(a, b) else a


# --- Go module versions (semver; pseudo-versions are never pinned) ------------

GO_PROXY_LIST_URL = "https://proxy.golang.org/{module}/@v/list"
_GO_PSEUDO = re.compile(
    r"^v?\d+\.\d+\.\d+-"
    r"(?:\d{14}|(?:[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*\.)?0\.\d{14})"
    r"-[0-9a-f]{12}(?:\+incompatible)?$")
_SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def is_go_pseudo_version(version: str) -> bool:
    """vX.0.0-ts-hash, vX.Y.Z-0.ts-hash and vX.Y.Z-pre.0.ts-hash forms."""
    return bool(_GO_PSEUDO.match(str(version).strip()))


def _semver_key(version: str) -> tuple:
    """Semver 2.0 precedence: releases above their pre-releases; numeric ids below alphanumeric."""
    match = _SEMVER.match(str(version).strip())
    if not match:
        return ((), 0, ())
    core = tuple(int(match[i]) for i in (1, 2, 3))
    if match[4] is None:
        return (core, 1, ())
    ids = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in match[4].split("."))
    return (core, 0, ids)


def _semver_lt(a: str, b: str) -> bool:
    return _semver_key(a) < _semver_key(b)


def escape_module_path(module: str) -> str:
    """Go module proxy case escaping: each upper-case letter becomes '!' + lower-case."""
    return "".join(f"!{c.lower()}" if "A" <= c <= "Z" else c for c in module)


def resolve_go_tag(module: str, version: str, fetch) -> str | None:
    """Smallest tagged release (no pre-release) >= ``version`` from proxy.golang.org, without "v".

    None when no such tag exists (or the proxy does not know the module); other
    proxy failures raise RuntimeError (transient).
    """
    url = GO_PROXY_LIST_URL.format(module=escape_module_path(module))
    try:
        body = fetch(url, timeout=20).text()
    except net.FetchError as exc:
        if exc.status in (404, 410):
            return None
        raise RuntimeError(f"Go module proxy list for {module} failed: {exc.reason}") from None
    floor = "v" + _strip_prefix(version)
    tags = []
    for line in body.splitlines():
        tag = line.strip()
        match = _SEMVER.match(tag)
        if not match or match[4] is not None or is_go_pseudo_version(tag):
            continue
        if not _semver_lt(tag, floor):
            tags.append(tag)
    return _strip_prefix(min(tags, key=_semver_key)) if tags else None


# --- pure edit functions -------------------------------------------------------

_APT_UPGRADE = re.compile(r"\bapt-get\b[^&|;]*?\b(?:dist-)?upgrade\b")
_APT_UPDATE = re.compile(r"\bapt-get\b[^&|;]*?\bupdate\b")
_APK_UPGRADE = re.compile(r"\bapk\b[^&|;]*?\bupgrade\b")
_APK_ADD = re.compile(r"\bapk\b[^&|;]*?\badd\b")
_REFRESH_ARG = re.compile(r"^(?P<lead>\s*ARG\s+SECURITY_REFRESH)(?:=\S*)?(?P<trail>\s*)$", re.I)


def _instructions(lines: list[str]) -> list[tuple[int, str, str]]:
    """(first physical line index, KEYWORD, joined text) per Dockerfile instruction."""
    out: list[tuple[int, str, str]] = []
    i, n = 0, len(lines)
    while i < n:
        stripped = lines[i].strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        start, parts = i, [lines[i].rstrip("\r\n")]
        while parts[-1].rstrip().endswith("\\") and i + 1 < n:
            i += 1
            parts.append(lines[i].rstrip("\r\n"))
        out.append((start, stripped.split(None, 1)[0].upper(), " ".join(parts)))
        i += 1
    return out


def refresh_arg(dockerfile_text: str, stamp: str) -> str | None:
    """Insert or update ``ARG SECURITY_REFRESH=<stamp>`` before the package-upgrade RUN.

    The stage is the LAST stage with a RUN containing ``apt-get upgrade`` or
    ``apk upgrade``; only when no stage upgrades does the last stage with
    ``apt-get update`` / ``apk add`` qualify (a build stage that merely installs
    tooling must not win over the runtime base stage that upgrades).  The ARG goes
    immediately before that stage's first RUN naming any of the four commands; an
    existing ``ARG SECURITY_REFRESH`` in that stage is updated in place.  A changed
    ARG value invalidates the build cache for every following RUN of the stage.
    None when no stage has such a RUN.
    """
    lines = dockerfile_text.splitlines(keepends=True)
    stage = -1
    stage_of: dict[int, int] = {}
    hits: list[tuple[int, int, bool]] = []      # (stage, line index, is upgrade)
    for start, keyword, text in _instructions(lines):
        if keyword == "FROM":
            stage += 1
        stage_of[start] = stage
        if keyword != "RUN" or stage < 0:
            continue
        upgrade = bool(_APT_UPGRADE.search(text) or _APK_UPGRADE.search(text))
        if upgrade or _APT_UPDATE.search(text) or _APK_ADD.search(text):
            hits.append((stage, start, upgrade))
    if not hits:
        return None
    upgrades = [h for h in hits if h[2]]
    chosen = max(h[0] for h in (upgrades or hits))
    position = min(h[1] for h in hits if h[0] == chosen)
    for index, owner in stage_of.items():
        if owner != chosen:
            continue
        line = lines[index]
        body = line.rstrip("\r\n")
        match = _REFRESH_ARG.match(body)
        if match:
            lines[index] = f"{match['lead']}={stamp}{match['trail']}{line[len(body):]}"
            return "".join(lines)
    newline = "\r\n" if lines[position].endswith("\r\n") else "\n"
    lines[position:position] = [
        f"# security-watch: bump to re-run the package upgrade below on the next build{newline}",
        f"ARG SECURITY_REFRESH={stamp}{newline}",
    ]
    return "".join(lines)


_GOLANG_FROM = re.compile(
    r"^(?P<lead>\s*FROM\s+(?:--platform=\S+\s+)?)"
    r"(?P<image>(?:docker\.io/)?(?:library/)?golang)"
    r":(?P<version>\d+\.\d+(?:\.\d+)?)"
    r"(?P<variant>-[A-Za-z0-9][A-Za-z0-9._-]*)?"
    r"(?P<digest>@sha256:[0-9a-f]{64})?"
    r"(?P<rest>(?:\s+AS\s+\S+)?\s*)$",
    re.I,
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def _golang_froms(dockerfile_text: str) -> list[dict[str, str]]:
    out = []
    for line in dockerfile_text.splitlines():
        match = _GOLANG_FROM.match(line)
        if match:
            out.append({"version": match["version"], "variant": (match["variant"] or "")[1:],
                        "digest": (match["digest"] or "")[1:]})
    return out


def bump_golang_from(dockerfile_text: str, new_version: str, digest: str | None) -> str | None:
    """Rewrite every ``FROM [docker.io/library/]golang:<X.Y.Z>[-<variant>][@sha256:..]`` line.

    Keeps the image prefix, variant and ``AS <stage>``; the digest is replaced only
    on lines that pinned one (``digest`` = ``sha256:<64 hex>``).  None when there is
    no such line, nothing changes, a pinned line has no valid replacement digest, or
    pinned lines use different variants (one digest cannot serve both).
    """
    version = _strip_prefix(new_version)
    if digest is not None:
        digest = digest[1:] if digest.startswith("@") else digest
        if not _DIGEST.fullmatch(digest):
            return None
    lines = dockerfile_text.splitlines(keepends=True)
    found = changed = False
    pinned_variants: set[str] = set()
    for index, line in enumerate(lines):
        body = line.rstrip("\r\n")
        match = _GOLANG_FROM.match(body)
        if not match:
            continue
        found = True
        pin = ""
        if match["digest"]:
            if not digest:
                return None
            pinned_variants.add(match["variant"] or "")
            pin = f"@{digest}"
        new = f"{match['lead']}{match['image']}:{version}{match['variant'] or ''}{pin}{match['rest']}"
        if new != body:
            changed = True
            lines[index] = new + line[len(body):]
    if not found or not changed or len(pinned_variants) > 1:
        return None
    return "".join(lines)


_TOOLCHAIN = re.compile(r"^toolchain[ \t]+go(?P<version>\S+)", re.M)


def _go_mod_toolchain(go_mod_text: str) -> str | None:
    match = _TOOLCHAIN.search(go_mod_text)
    return match["version"] if match else None


def bump_go_toolchain(go_mod_text: str, new_version: str) -> str | None:
    """``toolchain go<old>`` -> ``toolchain go<new>``; None without a toolchain line or when not older."""
    version = _strip_prefix(new_version)
    match = _TOOLCHAIN.search(go_mod_text)
    if not match or not _vlt(match["version"], version):
        return None
    return go_mod_text[:match.start("version")] + version + go_mod_text[match.end("version"):]


def _go_mod_required(go_mod_text: str, module: str) -> str | None:
    """Version go.mod requires for ``module`` (single-line or block form), without "v"."""
    pattern = re.compile(r"^\s*(?:require\s+)?" + re.escape(module) + r"\s+(v\S+)", re.M)
    match = pattern.search(go_mod_text)
    return _strip_prefix(match[1]) if match else None


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


_REQ_PIN = re.compile(
    r"^(?P<lead>\s*)(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"(?P<extras>\s*\[[^\]]*\])?(?P<op>\s*==(?!=)\s*)(?P<version>[^\s;#,=]+)(?P<tail>(?:[\s;#].*)?)$"
)


def _pip_pin(requirements_text: str, name: str) -> str | None:
    want = _pep503(name)
    for line in requirements_text.splitlines():
        match = _REQ_PIN.match(line)
        if match and _pep503(match["name"]) == want:
            return match["version"]
    return None


def bump_pip_pin(requirements_text: str, name: str, new_version: str) -> str | None:
    """Rewrite ``name==<old>`` (PEP 503 name match, ``==`` pins only) to ``==<new>``.

    Extras, environment markers and comments are kept.  None when no ``==`` pin of
    that name exists or nothing changes.
    """
    want = _pep503(name)
    lines = requirements_text.splitlines(keepends=True)
    changed = False
    for index, line in enumerate(lines):
        body = line.rstrip("\r\n")
        match = _REQ_PIN.match(body)
        if not match or _pep503(match["name"]) != want:
            continue
        if match["version"] != new_version:
            lines[index] = (body[:match.start("version")] + new_version + body[match.end("version"):]
                            + line[len(body):])
            changed = True
    return "".join(lines) if changed else None


# --- helpers -----------------------------------------------------------------

def _repo_dir(spec: ComponentSpec) -> Path:
    return config.expand(f"~/dev/{spec.repo}")


def _github(spec: ComponentSpec) -> str:
    return spec.get("github") or f"{GITHUB_OWNER}/{spec.repo}"


def _tilde(path: Path) -> str:
    text, home = str(path), str(config.home())
    return "~" + text[len(home):] if text.startswith(home + "/") else text


def _go_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PATH"] = f"{config.home() / '.local/go/bin'}:{env.get('PATH', '')}"
    return env


def _tail(result: Any, limit: int = 300) -> str:
    text = f"{getattr(result, 'stdout', '') or ''}\n{getattr(result, 'stderr', '') or ''}".strip()
    return text[-limit:]


def _json(result: Any) -> Any:
    try:
        return json.loads(result.stdout or "")
    except (TypeError, ValueError):
        return None


def _is_os_ecosystem(ecosystem: str) -> bool:
    return ecosystem.startswith(OS_ECOSYSTEM_PREFIXES)


def _is_go_stdlib(pkg: model.Package) -> bool:
    return pkg.ecosystem == "Go" and pkg.name == "stdlib"


def _edit_kind(finding: Finding, spec: ComponentSpec) -> tuple[str | None, str]:
    """(edit, "") or (None, why no repo edit exists for this finding)."""
    pkg = finding.package
    if _is_os_ecosystem(pkg.ecosystem):
        if spec.kind == "container":
            return "base-refresh", ""
        return None, f"{pkg.ecosystem} packages on a {spec.kind} are not built from {spec.repo}"
    if _is_go_stdlib(pkg):
        if spec.kind == "container" or (spec.kind == "host-binary" and spec.get("dockerfile")):
            return "go-builder", ""
        if spec.kind == "host-binary":
            return "go-toolchain", ""
        return None, f"Go stdlib on a {spec.kind} has no repo edit"
    if pkg.ecosystem == "Go":
        return "go-module", ""
    if pkg.ecosystem == "PyPI":
        return "pip-pin", ""
    return None, f"no repo edit for ecosystem {pkg.ecosystem}"


def _group_slug(group: str) -> str:
    slug = re.sub(r"[^a-z0-9.]+", "-", group.lower()).strip("-.")
    return slug[:60] or "finding"


# --- playbook ----------------------------------------------------------------

class RepoPrPlaybook:
    id = PLAYBOOK_ID
    multi_tick = True

    def __init__(self, *, app_deploy: Callable[..., dict] | None = None,
                 deploy_registry: dict | None = None, auto_merge_repos: set[str] | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self._app_deploy = app_deploy
        self._deploy_registry = deploy_registry
        self._auto_merge_repos = auto_merge_repos
        self._sleep = sleep

    # steward integration (imported lazily: the steward package is heavy)
    def _steward_app_deploy(self) -> Callable[..., dict]:
        if self._app_deploy is None:
            from steward import updates
            self._app_deploy = updates._p1_app_deploy
        return self._app_deploy

    def _registry(self) -> dict:
        if self._deploy_registry is None:
            from steward import config as steward_config
            self._deploy_registry = steward_config.DEPLOY_REGISTRY
        return self._deploy_registry

    def _auto_merge(self) -> set[str]:
        if self._auto_merge_repos is None:
            from steward import config as steward_config
            self._auto_merge_repos = set(steward_config.AUTO_MERGE_CANDIDATES)
        return self._auto_merge_repos

    # --- plan ------------------------------------------------------------

    def plan(self, findings: list[Finding], spec: ComponentSpec, ctx) -> Plan | Refusal:
        pid = self.id

        def refuse(reason: str, alert: bool = True) -> Refusal:
            return Refusal(pid, spec.id, reason, alert=alert)

        if not spec.repo:
            return refuse(f"{spec.id} has no repo for a PR")
        if not findings:
            return refuse("no findings to fix", alert=False)
        allowed = list(spec.get("edits") or [])
        pin_owner = spec.get("pin_owner") or {}
        ordered = sorted(findings, key=lambda f: _URGENCY_RANK.get(f.urgency, 3))
        candidates: list[tuple[str, Finding]] = []
        refusals: list[Refusal] = []
        for finding in ordered:
            pkg = finding.package
            if pkg.ecosystem in pin_owner:
                refusals.append(refuse(f"{pkg.ecosystem} {pkg.name}: {pin_owner[pkg.ecosystem]}"))
                continue
            edit, why = _edit_kind(finding, spec)
            if edit is None:
                refusals.append(refuse(f"{pkg.ident()}: {why}"))
                continue
            if edit not in allowed:
                refusals.append(refuse(
                    f"{pkg.ident()} needs edit {edit}, not allowed for {spec.id} "
                    f"(edits: {', '.join(allowed) or 'none'})"))
                continue
            if not finding.fix_available or not finding.fixed_versions:
                refusals.append(refuse(f"{pkg.ident()}: no fixed version published yet", alert=False))
                continue
            candidates.append((edit, finding))
        if not candidates:
            return refusals[0]
        edit = candidates[0][0]
        group = [f for e, f in candidates if e == edit]

        repo = _repo_dir(spec)
        fetched: list[bool] = []

        def read(path: str) -> str | None:
            if not fetched:
                result = ctx.run(["git", "-C", str(repo), "fetch", "--quiet", "origin"], timeout=120)
                if result.returncode != 0:
                    raise RuntimeError(f"git fetch failed in {_tilde(repo)}: {_tail(result)}")
                fetched.append(True)
            result = ctx.run(["git", "-C", str(repo), "show", f"origin/main:{path}"], timeout=60)
            return result.stdout if result.returncode == 0 else None

        try:
            built = getattr(self, "_plan_" + edit.replace("-", "_"))(group, spec, ctx, read)
        except RuntimeError as exc:
            return refuse(str(exc)[:500], alert=False)
        if isinstance(built, Refusal):
            return built
        target, path, params, fixed_version, edit_step = built
        gh = _github(spec)
        cves = sorted({c for f in group for c in f.cves})
        first_group = group[0].group
        deploy = spec.get("deploy", "")
        kind, _, arg = deploy.partition(":")
        if kind == "steward-app":
            deploy_step = f"under lock {spec.lock}: steward P1 app_deploy {arg} (CI-green origin/main)"
        else:
            deploy_step = (f"under lock {spec.lock}: git pull --ff-only origin main in {_tilde(repo)}, "
                           f"bash {arg}, health check")
        return Plan(
            playbook=pid,
            component_id=spec.id,
            finding_keys=[f.key for f in group],
            target=target,
            lock_keys=[spec.lock],
            steps=[
                f"git fetch; detached worktree of origin/main from {_tilde(repo)}",
                edit_step,
                f"commit on secwatch/{spec.id}-{_group_slug(first_group)}-<YYYYmmddHHMM>, push, "
                f"open PR on {gh} labelled {PR_LABEL}",
                f"wait for CI green + mergeable (label '{HOLD_LABEL}' stops it); merge with the repo's allowed method",
                deploy_step,
                f"rescan {spec.id}; the findings must clear",
            ],
            undo=(f"before merge: gh pr close <n> --repo {gh} --delete-branch; after merge: "
                  f"git -C {_tilde(repo)} revert --no-edit <merge sha> && git -C {_tilde(repo)} push origin main, "
                  f"then redeploy ({deploy})"),
            release_published=None,
            fixed_version=fixed_version,
            state={"edit": edit, "path": path, "params": params, "repo": spec.repo, "github": gh,
                   "cves": cves, "group": first_group,
                   "packages": sorted({f.package.name for f in group})},
        )

    def _plan_base_refresh(self, group, spec, ctx, read):
        path = spec.get("dockerfile") or "Dockerfile"
        text = read(path)
        if text is None:
            return Refusal(self.id, spec.id, f"cannot read origin/main:{path} in {spec.repo}")
        stamp = ctx.now.strftime("%Y%m%d%H%M")
        if refresh_arg(text, stamp) is None:
            return Refusal(self.id, spec.id,
                           f"{spec.repo}/{path} has no apt-get/apk upgrade step for a refresh")
        distros = sorted({f.package.ecosystem.split(":", 1)[0] for f in group})
        names = sorted({f.package.name for f in group})
        target = (f"{spec.id}: {path} ARG SECURITY_REFRESH "
                  f"({'/'.join(distros)} security updates for {', '.join(names)})")
        step = f"set ARG SECURITY_REFRESH={stamp} in {path} before the package-upgrade RUN"
        return target, path, {"stamp": stamp}, group[0].fixed_versions[0], step

    def _plan_go_builder(self, group, spec, ctx, read):
        path = spec.get("dockerfile") or "Dockerfile"
        text = read(path)
        if text is None:
            return Refusal(self.id, spec.id, f"cannot read origin/main:{path} in {spec.repo}")
        froms = _golang_froms(text)
        if not froms:
            return Refusal(self.id, spec.id, f"{spec.repo}/{path} has no FROM golang:<X.Y.Z> line")
        current, variant = froms[0]["version"], froms[0]["variant"]
        need = None
        for finding in group:
            fixed = _same_line_fixed(finding.fixed_versions, current)
            if fixed is None:
                line = ".".join(map(str, _minor_line(current)))
                return Refusal(self.id, spec.id,
                               f"{finding.group}: no fixed Go release on the {line} line "
                               f"(fixed: {', '.join(finding.fixed_versions)})")
            need = _max_version(need, fixed)
        if not _vlt(current, need):
            return Refusal(self.id, spec.id,
                           f"{spec.repo}/{path} already builds with golang {current} (fix {need}); "
                           "the deployed artifact is stale and needs a redeploy")
        tag = f"{need}-{variant}" if variant else need
        try:
            meta = net.get_json(HUB_TAG_URL.format(tag=tag), fetch=ctx.fetch)
        except net.FetchError as exc:
            if exc.status == 404:
                return Refusal(self.id, spec.id, f"golang:{tag} is not on Docker Hub yet", alert=False)
            return Refusal(self.id, spec.id, f"Docker Hub lookup of golang:{tag} failed: {exc.reason}",
                           alert=False)
        digest = meta.get("digest") if isinstance(meta, dict) else None
        pinned = any(f["digest"] for f in froms)
        if pinned and not (isinstance(digest, str) and _DIGEST.fullmatch(digest)):
            return Refusal(self.id, spec.id, f"Docker Hub returned no digest for golang:{tag}", alert=False)
        if bump_golang_from(text, need, digest if pinned else None) is None:
            return Refusal(self.id, spec.id, f"cannot rewrite the golang FROM lines of {spec.repo}/{path}")
        params = {"version": need, "digest": digest if pinned else None}
        target = f"{spec.id}: {path} golang {current} -> {need}"
        step = f"FROM golang:{tag}{'@' + digest if pinned else ''} in {path} (stage names kept)"
        return target, path, params, need, step

    def _plan_go_toolchain(self, group, spec, ctx, read):
        text = read("go.mod")
        if text is None:
            return Refusal(self.id, spec.id, f"cannot read origin/main:go.mod in {spec.repo}")
        current = _go_mod_toolchain(text)
        if current is None:
            return Refusal(self.id, spec.id, f"{spec.repo}/go.mod has no toolchain line")
        need = None
        for finding in group:
            fixed = _same_line_fixed(finding.fixed_versions, current)
            if fixed is None:
                line = ".".join(map(str, _minor_line(current)))
                return Refusal(self.id, spec.id,
                               f"{finding.group}: no fixed Go release on the {line} line "
                               f"(fixed: {', '.join(finding.fixed_versions)})")
            need = _max_version(need, fixed)
        if bump_go_toolchain(text, need) is None:
            return Refusal(self.id, spec.id,
                           f"{spec.repo}/go.mod already uses toolchain go{current} (fix {need}); "
                           "the deployed binary is stale and needs a rebuild")
        target = f"{spec.id}: go.mod toolchain go{current} -> go{need}"
        return target, "go.mod", {"version": need}, need, f"set toolchain go{need} in go.mod"

    def _plan_go_module(self, group, spec, ctx, read):
        text = read("go.mod")
        if text is None:
            return Refusal(self.id, spec.id, f"cannot read origin/main:go.mod in {spec.repo}")
        modules: dict[str, str] = {}
        required: dict[str, str] = {}
        for finding in group:
            name = finding.package.name
            have = _go_mod_required(text, name)
            if have is None:
                return Refusal(self.id, spec.id, f"{name} is not required in {spec.repo}/go.mod")
            above = [_strip_prefix(v) for v in finding.fixed_versions
                     if _semver_lt(finding.package.version, v)]
            fixed = min(above, key=_semver_key) if above else None
            if fixed is None:
                return Refusal(self.id, spec.id,
                               f"{name}: no fixed version above {finding.package.version} "
                               f"(fixed: {', '.join(finding.fixed_versions)})")
            if is_go_pseudo_version(fixed):
                pseudo = fixed
                fixed = resolve_go_tag(name, pseudo, ctx.fetch)
                if fixed is None:
                    return Refusal(self.id, spec.id,
                                   f"fix for {name} exists only at an untagged commit (v{pseudo}); "
                                   "waiting for a tagged release")
            if not _semver_lt(have, fixed):
                return Refusal(self.id, spec.id,
                               f"{spec.repo}/go.mod already requires {name} v{have} (fix {fixed}); "
                               "the deployed binary is stale and needs a rebuild")
            current = modules.get(name)
            modules[name] = fixed if current is None or _semver_lt(current, fixed) else current
            required[name] = have
        pairs = sorted(modules.items())
        target = f"{spec.id}: go.mod " + ", ".join(f"{m} v{required[m]} -> v{v}" for m, v in pairs)
        step = "go get " + " ".join(f"{m}@v{v}" for m, v in pairs) + " && go mod tidy"
        return target, "go.mod", {"modules": [list(p) for p in pairs]}, pairs[0][1], step

    def _plan_pip_pin(self, group, spec, ctx, read):
        text = read("requirements.txt")
        if text is None:
            return Refusal(self.id, spec.id, f"cannot read origin/main:requirements.txt in {spec.repo}")
        pins: dict[str, str] = {}
        current: dict[str, str] = {}
        for finding in group:
            name = finding.package.name
            have = _pip_pin(text, name)
            if have is None:
                return Refusal(self.id, spec.id, f"{name} is not pinned with == in {spec.repo}/requirements.txt")
            fixed = _smallest_fixed_above(finding.fixed_versions, finding.package.version)
            if fixed is None:
                return Refusal(self.id, spec.id,
                               f"{name}: no fixed version above {finding.package.version} "
                               f"(fixed: {', '.join(finding.fixed_versions)})")
            if not _vlt(have, fixed):
                return Refusal(self.id, spec.id,
                               f"{spec.repo}/requirements.txt already pins {name}=={have} (fix {fixed}); "
                               "the deployed venv is stale and needs a release")
            pins[name] = _max_version(pins.get(name), fixed)
            current[name] = have
        pairs = sorted(pins.items())
        target = f"{spec.id}: requirements.txt " + ", ".join(f"{n} {current[n]} -> {v}" for n, v in pairs)
        step = "pin " + ", ".join(f"{n}=={v}" for n, v in pairs) + " in requirements.txt"
        return target, "requirements.txt", {"pins": [list(p) for p in pairs]}, pairs[0][1], step

    # --- apply -----------------------------------------------------------

    def apply(self, plan: Plan, ctx) -> Outcome:
        st = plan.state
        spec = ctx.specs[plan.component_id]
        repo = _repo_dir(spec)
        gh = st.get("github") or _github(spec)
        edit = st["edit"]
        untouched = {"production_touched": False}

        def fail(detail: str) -> Outcome:
            _log(f"{spec.id}: {detail}")
            return Outcome("failed", detail[:500], verify=False, state=dict(untouched))

        result = ctx.run(["git", "-C", str(repo), "fetch", "origin"], timeout=120)
        if result.returncode != 0:
            return fail(f"git fetch origin failed in {_tilde(repo)}: {_tail(result)}")
        tmp = Path(tempfile.mkdtemp(prefix=f"secwatch-{spec.id}-"))
        try:
            result = ctx.run(["git", "-C", str(repo), "worktree", "add", "--detach", str(tmp), "origin/main"],
                             timeout=120)
            if result.returncode != 0:
                return fail(f"git worktree add failed: {_tail(result)}")
            files, error = self._apply_edit(st, tmp, ctx)
            if error:
                return fail(f"{edit} edit failed: {error}")
            status = ctx.run(["git", "-C", str(tmp), "status", "--porcelain"], timeout=60)
            if status.returncode != 0 or not (status.stdout or "").strip():
                return fail(f"{edit} edit produced no change on origin/main")
            cves = list(st.get("cves") or [])
            title = f"security: {edit} for {', '.join(cves) or st.get('group') or plan.target}"
            branch = f"secwatch/{spec.id}-{_group_slug(st.get('group') or 'finding')}-{ctx.now.strftime('%Y%m%d%H%M')}"
            for argv in (["git", "-C", str(tmp), "add", "--", *files],
                         ["git", "-C", str(tmp), "commit", "-m", title, "-m", plan.target]):
                result = ctx.run(argv, timeout=120)
                if result.returncode != 0:
                    return fail(f"{argv[3]} failed: {_tail(result)}")
            head = (ctx.run(["git", "-C", str(tmp), "rev-parse", "HEAD"], timeout=30).stdout or "").strip()
            workflows = tmp / ".github" / "workflows"
            has_ci = workflows.is_dir() and any(workflows.glob("*.y*ml"))
            result = ctx.run(["git", "-C", str(tmp), "push", "origin", f"HEAD:refs/heads/{branch}"], timeout=180)
            if result.returncode != 0:
                return fail(f"git push origin {branch} failed: {_tail(result)}")
            body = self._pr_body(plan, ctx, spec)
            ctx.run(["gh", "label", "create", PR_LABEL, "--repo", gh, "--color", "B60205", "--force"], timeout=60)
            create = ["gh", "pr", "create", "--repo", gh, "--base", "main", "--head", branch,
                      "--title", title, "--body", body]
            result = ctx.run([*create, "--label", PR_LABEL], timeout=120)
            if result.returncode != 0:
                result = ctx.run(create, timeout=120)
            match = re.search(r"https://\S+/pull/(\d+)", result.stdout or "")
            if result.returncode != 0 or not match:
                ctx.run(["git", "-C", str(repo), "push", "origin", "--delete", branch], timeout=120)
                return fail(f"gh pr create failed: {_tail(result)}")
            number, url = int(match[1]), match[0]
        finally:
            ctx.run(["git", "-C", str(repo), "worktree", "remove", "--force", str(tmp)], timeout=60)
            shutil.rmtree(tmp, ignore_errors=True)
            ctx.run(["git", "-C", str(repo), "worktree", "prune"], timeout=60)
        _log(f"{spec.id}: opened {url} ({plan.target})")
        return Outcome(
            "pending", f"opened PR #{number} {url}; waiting for CI",
            undo=f"gh pr close {number} --repo {gh} --delete-branch",
            verify=False,
            state={"stage": "ci", "repo": spec.repo, "github": gh, "branch": branch, "pr": number,
                   "url": url, "edit": edit, "head": head, "has_ci": has_ci, "title": title,
                   "created_at": model.iso(ctx.now), "production_touched": False},
        )

    def _apply_edit(self, st: dict, tmp: Path, ctx) -> tuple[list[str], str]:
        """Apply the planned edit inside the worktree: (changed files, error)."""
        edit, params = st["edit"], st.get("params") or {}
        if edit == "go-module":
            pseudo = [f"{m}@v{v}" for m, v in params.get("modules", []) if is_go_pseudo_version(v)]
            if pseudo:
                return [], f"refusing to pin pseudo-version(s) {', '.join(pseudo)}"
            argv = ["go", "get", *(f"{m}@v{v}" for m, v in params.get("modules", []))]
            for command in (argv, ["go", "mod", "tidy"]):
                result = ctx.run(command, timeout=600, cwd=str(tmp), env=_go_env())
                if result.returncode != 0:
                    return [], f"{' '.join(command[:2])} failed: {_tail(result)}"
            files = ["go.mod"] + (["go.sum"] if (tmp / "go.sum").exists() else [])
            return files, ""
        path = st["path"]
        target = tmp / path
        try:
            text = target.read_text()
        except OSError as exc:
            return [], f"cannot read {path}: {exc}"
        if edit == "base-refresh":
            new = refresh_arg(text, params["stamp"])
        elif edit == "go-builder":
            new = bump_golang_from(text, params["version"], params.get("digest"))
        elif edit == "go-toolchain":
            new = bump_go_toolchain(text, params["version"])
        elif edit == "pip-pin":
            new = text
            for name, version in params.get("pins", []):
                new = bump_pip_pin(new, name, version) if new is not None else None
        else:
            return [], f"unknown edit {edit!r}"
        if new is None:
            return [], f"{edit} does not apply to origin/main:{path}"
        target.write_text(new)
        return [path], ""

    def _pr_body(self, plan: Plan, ctx, spec: ComponentSpec) -> str:
        lines = [f"Opened by security-watch for `{spec.id}`.", "", f"**Target:** {plan.target}", "",
                 "**Findings (issuer records):**"]
        for key in plan.finding_keys:
            finding = (ctx.findings or {}).get(key)
            if finding is None:
                lines.append(f"- {key}")
                continue
            ids = ", ".join(finding.cves or finding.advisory_ids)
            lines.append(f"- {ids}: {finding.package.ident()} fixed in {', '.join(finding.fixed_versions)}"
                         f" ({finding.severity or 'unrated'}, {finding.urgency})")
        lines += ["", "**Steps:**", *[f"{i}. {s}" for i, s in enumerate(plan.steps, 1)], "",
                  f"security-watch merges this PR once CI is green, then deploys it. Add the `{HOLD_LABEL}` "
                  "label to stop it; closing the PR cancels the action."]
        return "\n".join(lines)

    # --- advance ---------------------------------------------------------

    def advance(self, action: dict, ctx) -> Outcome:
        state = dict(action.get("state") or {})
        state.setdefault("production_touched", False)
        spec = ctx.specs.get(action.get("component_id"))
        if spec is None:
            return Outcome("failed", f"component {action.get('component_id')!r} is no longer registered",
                           verify=False, state=state)
        stage = state.get("stage")
        if stage == "ci":
            return self._advance_ci(state, spec, ctx)
        if stage == "merging":
            return self._advance_merging(state, spec, ctx)
        if stage == "deploy":
            return self._advance_deploy(state, spec, ctx)
        return Outcome("failed", f"unknown repo-pr stage {stage!r}", verify=False, state=state)

    def _undo(self, state: dict, spec: ComponentSpec) -> str:
        repo = _tilde(_repo_dir(spec))
        if state.get("merge_sha") or state.get("stage") == "deploy":
            sha = state.get("merge_sha") or "<merge sha>"
            return (f"git -C {repo} revert --no-edit {sha} && git -C {repo} push origin main, "
                    f"then redeploy ({spec.get('deploy', '')})")
        return f"gh pr close {state.get('pr')} --repo {state.get('github')} --delete-branch"

    def _wait(self, state: dict, since_key: str, detail: str, spec: ComponentSpec, ctx) -> Outcome:
        since = model.parse_iso(state.get(since_key)) or model.parse_iso(state.get("created_at"))
        if since is not None and ctx.now - since >= WAIT_LIMIT:
            return Outcome("failed", f"{detail}; gave up after {int(WAIT_LIMIT.total_seconds() // 3600)} h",
                           undo=self._undo(state, spec), verify=False, state=state)
        return Outcome("pending", detail, undo=self._undo(state, spec), verify=False, state=state)

    def _pr_view(self, state: dict, ctx) -> tuple[dict | None, str]:
        result = ctx.run(["gh", "pr", "view", str(state.get("pr")), "--repo", str(state.get("github")),
                          "--json", PR_VIEW_FIELDS], timeout=60)
        data = _json(result) if result.returncode == 0 else None
        if not isinstance(data, dict):
            return None, f"gh pr view #{state.get('pr')} failed: {_tail(result, 200)}"
        return data, ""

    @staticmethod
    def _held(data: dict) -> bool:
        return any(isinstance(l, dict) and str(l.get("name", "")).lower() == HOLD_LABEL
                   for l in data.get("labels") or [])

    def _merged(self, state: dict, data: dict, ctx) -> None:
        commit = data.get("mergeCommit") or {}
        state.update(stage="deploy", merge_sha=commit.get("oid") if isinstance(commit, dict) else "",
                     merged_at=model.iso(ctx.now))

    def _advance_ci(self, state: dict, spec: ComponentSpec, ctx) -> Outcome:
        data, err = self._pr_view(state, ctx)
        if data is None:
            return self._wait(state, "created_at", err, spec, ctx)
        if self._held(data):
            return Outcome("refused", f"PR #{state['pr']} held by Carter (label '{HOLD_LABEL}')",
                           undo=self._undo(state, spec), verify=False, state=state)
        pr_state = data.get("state")
        if pr_state == "MERGED":
            self._merged(state, data, ctx)
            return Outcome("pending", f"PR #{state['pr']} was merged; deploy next tick",
                           undo=self._undo(state, spec), verify=False, state=state)
        if pr_state == "CLOSED":
            return Outcome("failed", f"PR #{state['pr']} was closed without merge",
                           undo="", verify=False, state=state)
        head = state.get("head")
        if head and data.get("headRefOid") and data["headRefOid"] != head:
            return Outcome("failed", f"PR #{state['pr']} head changed since security-watch opened it "
                                     f"({head[:7]} -> {data['headRefOid'][:7]}); not merging",
                           undo=self._undo(state, spec), verify=False, state=state)
        verdict, detail = _checks(data.get("statusCheckRollup"), bool(state.get("has_ci", True)))
        if verdict == "failed":
            return Outcome("failed", f"PR #{state['pr']} checks failed: {detail}",
                           undo=self._undo(state, spec), verify=False, state=state)
        if verdict == "pending":
            return self._wait(state, "created_at", f"PR #{state['pr']} checks pending: {detail}", spec, ctx)
        mergeable = data.get("mergeable")
        if mergeable == "CONFLICTING":
            return Outcome("failed", f"PR #{state['pr']} conflicts with main",
                           undo=self._undo(state, spec), verify=False, state=state)
        if mergeable != "MERGEABLE":
            return self._wait(state, "created_at", f"PR #{state['pr']} mergeable={mergeable}", spec, ctx)
        method, err = self._merge_method(state, ctx)
        if method is None:
            return self._wait(state, "created_at", err, spec, ctx)
        argv = ["gh", "pr", "merge", str(state["pr"]), "--repo", state["github"], f"--{method}"]
        if head:
            argv += ["--match-head-commit", head]
        if spec.repo in self._auto_merge():
            argv.append("--auto")
        result = ctx.run(argv, timeout=120)
        if result.returncode != 0:
            return self._wait(state, "created_at", f"gh pr merge failed: {_tail(result, 200)}", spec, ctx)
        state.update(stage="merging", merge_method=method, merge_requested_at=model.iso(ctx.now))
        _log(f"{spec.id}: merging PR #{state['pr']} ({method}; {detail})")
        return Outcome("pending", f"PR #{state['pr']} green ({detail}); merge requested ({method})",
                       undo=self._undo(state, spec), verify=False, state=state)

    def _merge_method(self, state: dict, ctx) -> tuple[str | None, str]:
        result = ctx.run(["gh", "repo", "view", str(state.get("github")), "--json",
                          "rebaseMergeAllowed,squashMergeAllowed,mergeCommitAllowed"], timeout=60)
        data = _json(result) if result.returncode == 0 else None
        if not isinstance(data, dict):
            return None, f"gh repo view failed: {_tail(result, 200)}"
        for key, method in (("rebaseMergeAllowed", "rebase"), ("squashMergeAllowed", "squash"),
                            ("mergeCommitAllowed", "merge")):
            if data.get(key):
                return method, ""
        return None, f"{state.get('github')} allows no merge method"

    def _advance_merging(self, state: dict, spec: ComponentSpec, ctx) -> Outcome:
        data, err = self._pr_view(state, ctx)
        if data is None:
            return self._wait(state, "merge_requested_at", err, spec, ctx)
        pr_state = data.get("state")
        if pr_state == "MERGED":
            self._merged(state, data, ctx)
            return Outcome("pending", f"PR #{state['pr']} merged; deploy next tick",
                           undo=self._undo(state, spec), verify=False, state=state)
        if pr_state == "CLOSED":
            return Outcome("failed", f"PR #{state['pr']} was closed without merge",
                           undo="", verify=False, state=state)
        if self._held(data):
            return Outcome("refused", f"PR #{state['pr']} held by Carter (label '{HOLD_LABEL}')",
                           undo=self._undo(state, spec), verify=False, state=state)
        return self._wait(state, "merge_requested_at", f"PR #{state['pr']} not merged yet", spec, ctx)

    def _advance_deploy(self, state: dict, spec: ComponentSpec, ctx) -> Outcome:
        holder = f"security-watch:repo-pr:{spec.id}"
        try:
            with ctx.lock(spec.lock, timeout=ctx.policy.lock_timeout_seconds, holder=holder):
                return self._deploy(state, spec, ctx)
        except LockTimeout as exc:
            return self._wait(state, "merged_at", f"deploy lock {spec.lock} busy: {exc}", spec, ctx)

    def _deploy(self, state: dict, spec: ComponentSpec, ctx) -> Outcome:
        kind, _, arg = str(spec.get("deploy", "")).partition(":")
        if kind == "steward-app" and arg:
            return self._deploy_app(arg, state, spec, ctx)
        if kind == "release" and arg:
            return self._deploy_release(arg, state, spec, ctx)
        return Outcome("failed", f"unsupported deploy {spec.get('deploy')!r} for {spec.id}",
                       undo=self._undo(state, spec), verify=False, state=state)

    def _deploy_app(self, service: str, state: dict, spec: ComponentSpec, ctx) -> Outcome:
        registry_spec = self._registry().get(service)
        if registry_spec is None:
            return Outcome("failed", f"{service} is not in steward DEPLOY_REGISTRY",
                           undo=self._undo(state, spec), verify=False, state=state)
        row = self._steward_app_deploy()(service, registry_spec, dry_run=False, sleep=self._sleep) or {}
        status = row.get("status")
        reason = str(row.get("reason") or row.get("error") or "")
        if status == "skipped":
            if reason == "current":
                return Outcome("done", f"{service} production already at origin/main (contains PR #{state.get('pr')})",
                               undo=self._undo(state, spec), verify=True, state=state)
            return self._wait(state, "merged_at", f"steward app_deploy {service} skipped: {reason}", spec, ctx)
        state["production_touched"] = True
        undo = row.get("revert") or self._undo(state, spec)
        if status == "ok":
            healthy, detail = self._health(spec, ctx)
            if healthy:
                return Outcome("done", f"deployed {service} via steward app_deploy ({reason}); {detail}",
                               undo=undo, verify=True, state=state)
            return Outcome("failed", f"steward app_deploy {service} ok but health failed: {detail}",
                           undo=undo, verify=False, state=state)
        if status == "rolled_back":
            return Outcome("rolled_back", f"steward app_deploy {service} rolled back: {reason}",
                           undo=undo, verify=False, state=state)
        return Outcome("failed", f"steward app_deploy {service} {status or 'returned no status'}: {reason}"[:500],
                       undo=undo, verify=False, state=state)

    def _deploy_release(self, script: str, state: dict, spec: ComponentSpec, ctx) -> Outcome:
        repo = _repo_dir(spec)
        git = ["git", "-C", str(repo)]
        branch = ctx.run([*git, "symbolic-ref", "--short", "HEAD"], timeout=30)
        if branch.returncode != 0 or (branch.stdout or "").strip() != "main":
            return self._wait(state, "merged_at", f"{_tilde(repo)} is not on main", spec, ctx)
        dirty = ctx.run([*git, "status", "--porcelain"], timeout=60)
        if dirty.returncode != 0 or (dirty.stdout or "").strip():
            return self._wait(state, "merged_at", f"{_tilde(repo)} has uncommitted changes", spec, ctx)
        pull = ctx.run([*git, "pull", "--ff-only", "origin", "main"], timeout=180)
        if pull.returncode != 0:
            return self._wait(state, "merged_at", f"git pull --ff-only failed: {_tail(pull, 200)}", spec, ctx)
        sha = state.get("merge_sha")
        if sha and ctx.run([*git, "merge-base", "--is-ancestor", sha, "HEAD"], timeout=30).returncode != 0:
            return self._wait(state, "merged_at", f"{_tilde(repo)} main does not contain {sha[:7]} yet", spec, ctx)
        state["production_touched"] = True
        _log(f"{spec.id}: running bash {script} in {_tilde(repo)}")
        result = ctx.run(["bash", script], timeout=RELEASE_TIMEOUT, cwd=str(repo), env=_go_env())
        healthy, detail = self._health(spec, ctx)
        undo = self._undo(state, spec)
        if result.returncode == 0 and healthy:
            return Outcome("done", f"bash {script} ok; {detail}", undo=undo, verify=True, state=state)
        if result.returncode == 0:
            return Outcome("failed", f"bash {script} ok but health failed: {detail}",
                           undo=undo, verify=False, state=state)
        if healthy and spec.health:
            return Outcome("rolled_back", f"bash {script} exited {result.returncode} (service healthy: "
                                          f"previous release kept): {_tail(result, 200)}",
                           undo=undo, verify=False, state=state)
        return Outcome("failed", f"bash {script} exited {result.returncode}; {detail}: {_tail(result, 200)}",
                       undo=undo, verify=False, state=state)

    def _health(self, spec: ComponentSpec, ctx) -> tuple[bool, str]:
        if not spec.health:
            return True, "no health URL"
        problems = []
        for url in spec.health:
            last = ""
            for attempt in range(HEALTH_ATTEMPTS):
                try:
                    response = ctx.fetch(url, timeout=10)
                    if response.status < 400:
                        last = ""
                        break
                    last = f"HTTP {response.status}"
                except net.FetchError as exc:
                    last = f"HTTP {exc.status}" if exc.status else exc.reason
                except OSError as exc:
                    last = str(exc)
                if attempt + 1 < HEALTH_ATTEMPTS:
                    self._sleep(HEALTH_RETRY_SECONDS)
            if last:
                problems.append(f"{url}: {last}")
        return (False, "; ".join(problems)) if problems else (True, "health OK")


def _checks(rollup: Any, has_ci: bool) -> tuple[str, str]:
    """("green" | "pending" | "failed", detail) for a PR statusCheckRollup."""
    if not rollup:
        return ("pending", "no checks reported yet") if has_ci else ("green", "repo has no CI workflows")
    failed, pending = [], []
    for check in rollup:
        if not isinstance(check, dict):
            failed.append("unreadable check")
        elif check.get("__typename") == "StatusContext" or "state" in check:
            state = str(check.get("state") or "").upper()
            label = f"{check.get('context')}: {state or '?'}"
            if state == "SUCCESS":
                continue
            (pending if state in ("PENDING", "EXPECTED", "") else failed).append(label)
        else:
            status = str(check.get("status") or "").upper()
            conclusion = str(check.get("conclusion") or "").lower()
            label = f"{check.get('name')}: {status}/{conclusion or '-'}"
            if status != "COMPLETED":
                pending.append(label)
            elif conclusion not in _CI_OK_CONCLUSIONS:
                failed.append(label)
    if failed:
        return "failed", "; ".join(failed[:4])
    if pending:
        return "pending", "; ".join(pending[:4])
    return "green", f"{len(rollup)} check(s) green"


PLAYBOOKS = {PLAYBOOK_ID: RepoPrPlaybook()}
