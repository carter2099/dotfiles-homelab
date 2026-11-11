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

Ecosystems in a component's ``pin_owner`` (e.g. the blog's RubyGems, owned by the
dependabot-webhook) are never edited: once origin/main's lockfile resolves a fixed version
the plan is deploy-only, until then it refuses with the owner's reason.

apply() opens the PR from a throw-away worktree of origin/main (repos without CI run
their own checks there first; refused while another security-watch PR is open);
advance() walks ``ci -> merging -> deploy`` across ticks.  Carter stops an action by
labelling the PR ``hold`` or closing it; any other pre-merge failure closes the PR and
deletes its branch.  When origin/main already carries the fix the plan is deploy-only
and starts at ``deploy``.  The deploy runs under ``ctx.lock(spec.lock)`` through the
component's existing owner: steward P1 app_deploy, or the repo's release script once
CI on main's HEAD is green (stage ``deploying`` is journaled right before it starts).
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

from security_watch import config, inventory, model, net
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
GO_PROXY_INFO_URL = "https://proxy.golang.org/{module}/@v/v{version}.info"
GO_TOOLCHAIN_INFO_URL = "https://proxy.golang.org/golang.org/toolchain/@v/v0.0.1-go{version}.linux-amd64.info"
TITLE_MAX = 100                        # GitHub rejects titles over 256; keep them readable
PR_BODY_MAX = 60000                    # GitHub's PR body limit is 65536 characters
CHECK_TIMEOUT = 1200                   # pre-push checks of a repo without CI, per command

# Output proving a release script got past its preconditions: printed when its production
# transaction starts, or by the rollback its EXIT trap always runs once it has.  A non-zero
# exit without the marker (and with the artifact fingerprint unchanged) died before changing
# anything.  Scripts not listed -- e.g. prompt-guard deploy.sh, whose rollback is silent --
# always count as production touched.
_TRANSACTION_MARKERS = {
    ("homelab-dashboard", "release.sh"): r"^==> promoting ",
    ("beatz", "release.sh"): r"Beats (?:deployment rolled back|rollback failed)",
    ("llm-proxy", "release.sh"): r"Deployment rolled back and restored health|LLM Proxy rollback failed",
}

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


# pin_owner ecosystem -> (repo-relative lockfile on origin/main, parser of its packages)
_PIN_LOCKFILES = {"RubyGems": ("Gemfile.lock", inventory.parse_gemfile_lock)}


def _pin_owner(pkg: model.Package, spec: ComponentSpec) -> str:
    """The component's pin_owner reason for ``pkg``'s ecosystem, or ''."""
    owners = spec.get("pin_owner") or {}
    for eco in (pkg.ecosystem, pkg.ecosystem.split(":", 1)[0]):
        if eco in owners:
            return str(owners[eco])
    return ""


def _owner_landed(finding: Finding, owner: str, read: Callable[[str], str | None],
                  lockfiles: dict[str, dict[str, str] | None]) -> tuple[str | None, str]:
    """(version origin/main resolves, note) when the pin owner already merged a fixed version,
    else (None, why there is nothing to deploy yet).  ``lockfiles`` caches parsed lockfiles."""
    pkg = finding.package
    head = f"{pkg.ecosystem} {pkg.name}: {owner}"
    need = _smallest_fixed_above(finding.fixed_versions, pkg.version)
    if need is None:
        return None, f"{head}; no fixed version above {pkg.version} published yet"
    entry = _PIN_LOCKFILES.get(pkg.ecosystem)
    if entry is None:
        return None, head
    path, parse = entry
    if path not in lockfiles:
        text = read(path)
        lockfiles[path] = None if text is None else {p.name: p.version for p in parse(text)}
    resolved = lockfiles[path]
    have = resolved.get(pkg.name) if resolved is not None else None
    if have is None:
        return None, f"{head}; origin/main:{path} does not resolve {pkg.name}"
    if _vlt(have, need):
        return None, f"{head}; origin/main still resolves {pkg.name} {have} (fixed in {need})"
    return have, f"{path} resolves {pkg.name} {have}"


def _group_slug(group: str) -> str:
    slug = re.sub(r"[^a-z0-9.]+", "-", group.lower()).strip("-.")
    return slug[:60] or "finding"


def proxy_release_time(url: str, fetch) -> str:
    """ISO publish time from a proxy.golang.org ``.info`` document (its ``Time``).

    RuntimeError when the date is unknown: the plan is refused (transient, retried)
    instead of skipping the age rule.
    """
    try:
        data = net.get_json(url, fetch=fetch)
    except net.FetchError as exc:
        raise RuntimeError(f"release date lookup {url} failed: {exc.reason}") from None
    raw = data.get("Time") if isinstance(data, dict) else None
    try:
        when = model.parse_iso(raw) if isinstance(raw, str) else None
    except ValueError:
        when = None
    if when is None:
        raise RuntimeError(f"{url} names no release Time")
    return model.iso(when)


def pr_title(edit: str, count: int, lead: str) -> str:
    """Fixed-length summary; the full finding list goes into the commit and PR bodies."""
    title = (f"security: {edit} for {lead}" if count <= 1
             else f"security: {edit} ({count} findings incl. {lead})")
    return title if len(title) <= TITLE_MAX else title[:TITLE_MAX - 3] + "..."


def _commit_findings(plan: Plan, st: dict) -> str:
    ids = list(st.get("cves") or []) or list(plan.finding_keys)
    text = f"Fixes ({len(plan.finding_keys)} findings): " + ", ".join(ids)
    not_addressed = list(st.get("not_addressed") or [])
    if not_addressed:
        text += "\n\nNot addressed:\n" + "\n".join(f"- {note}" for note in not_addressed)
    return text


def _deploy_step(spec: ComponentSpec, repo: Path) -> str:
    kind, _, arg = str(spec.get("deploy", "")).partition(":")
    if kind == "steward-app":
        return f"under lock {spec.lock}: steward P1 app_deploy {arg} (CI-green origin/main)"
    return (f"under lock {spec.lock}: git pull --ff-only origin main in {_tilde(repo)}, wait for CI green "
            f"on that commit (repos with CI), journal 'deploying', bash {arg}, health check")


def commit_ci_verdict(runs_payload: dict, status_payload: dict) -> tuple[bool | None, str]:
    """steward ``updates._ci_green(allow_pending=True)`` on the two REST payloads of one commit
    (``/check-runs`` and ``/status``): True green, None not finished (nothing reported yet,
    still running, or cancelled by a newer push), False red."""
    runs = [r for r in runs_payload.get("check_runs") or [] if isinstance(r, dict)]
    statuses = [s for s in status_payload.get("statuses") or [] if isinstance(s, dict)]
    try:
        total = int(runs_payload.get("total_count", len(runs)))
    except (TypeError, ValueError):
        total = len(runs)
    if total > len(runs):
        return False, f"{total} check runs exceed one page; cannot verify all"
    incomplete = ([f"{r.get('name')}: {r.get('status')}/{r.get('conclusion')}"
                   for r in runs if r.get("status") != "completed"]
                  + [f"{s.get('context')}: {s.get('state')}" for s in statuses if s.get("state") == "pending"])
    problems = ([f"{r.get('name')}: {r.get('status')}/{r.get('conclusion')}"
                 for r in runs if r.get("status") == "completed" and r.get("conclusion") not in _CI_OK_CONCLUSIONS]
                + [f"{s.get('context')}: {s.get('state')}" for s in statuses
                   if s.get("state") not in ("success", "pending")])
    cancelled = [p for p in problems if p.endswith("/cancelled")]
    if problems and len(cancelled) != len(problems):
        return False, "; ".join(problems[:6])
    if cancelled:
        return None, "; ".join((cancelled + incomplete)[:6])
    if not runs and not statuses:
        return None, "no CI checks reported"
    if incomplete:
        return None, "; ".join(incomplete[:6])
    return True, f"{len(runs)} check run(s), {len(statuses)} status(es) green"


# --- playbook ----------------------------------------------------------------

class RepoPrPlaybook:
    id = PLAYBOOK_ID
    multi_tick = True

    def __init__(self, *, app_deploy: Callable[..., dict] | None = None,
                 deploy_registry: dict | None = None, auto_merge_repos: set[str] | None = None,
                 sleep: Callable[[float], None] = time.sleep,
                 script_run: Callable[..., Any] | None = None):
        self._app_deploy = app_deploy
        self._deploy_registry = deploy_registry
        self._auto_merge_repos = auto_merge_repos
        self._sleep = sleep
        # Release/deploy scripts and pre-push checks: own process group, killed whole on timeout.
        self._script_run = script_run if script_run is not None else inventory.run_group

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

        def refuse(reason: str, alert: bool = True, finding: Finding | None = None) -> Refusal:
            return Refusal(pid, spec.id, reason, alert=alert, finding_keys=[finding.key] if finding else [])

        if not spec.repo:
            return refuse(f"{spec.id} has no repo for a PR")
        if not findings:
            return refuse("no findings to fix", alert=False)
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

        allowed = list(spec.get("edits") or [])
        ordered = sorted(findings, key=lambda f: _URGENCY_RANK.get(f.urgency, 3))
        candidates: list[tuple[str, Finding]] = []
        refusals: list[Refusal] = []
        owner_fixed: dict[str, tuple[str, str]] = {}   # finding key -> (version on origin/main, note)
        lockfiles: dict[str, dict[str, str] | None] = {}
        for finding in ordered:
            pkg = finding.package
            owner = _pin_owner(pkg, spec)
            if owner:
                try:
                    landed, note = _owner_landed(finding, owner, read, lockfiles)
                except RuntimeError as exc:
                    refusals.append(refuse(str(exc)[:500], alert=False, finding=finding))
                    continue
                if landed is None:
                    refusals.append(refuse(note, finding=finding))
                    continue
                owner_fixed[finding.key] = (landed, note)
                candidates.append(("pin-owner", finding))
                continue
            edit, why = _edit_kind(finding, spec)
            if edit is None:
                refusals.append(refuse(f"{pkg.ident()}: {why}", finding=finding))
                continue
            if edit not in allowed:
                refusals.append(refuse(
                    f"{pkg.ident()} needs edit {edit}, not allowed for {spec.id} "
                    f"(edits: {', '.join(allowed) or 'none'})", finding=finding))
                continue
            if not finding.fix_available or not finding.fixed_versions:
                refusals.append(refuse(f"{pkg.ident()}: no fixed version published yet", alert=False,
                                       finding=finding))
                continue
            candidates.append((edit, finding))
        if not candidates:
            return refusals[0]
        edit = candidates[0][0]
        group = [f for e, f in candidates if e == edit]

        try:
            if edit == "pin-owner":
                # The owner already merged the fix: never a PR, only a deploy of origin/main.
                part = {"deploy_only": True, "findings": group, "fixed_version": owner_fixed[group[0].key][0],
                        "stale": "; ".join(sorted({owner_fixed[f.key][1] for f in group}))}
            else:
                part = getattr(self, "_plan_" + edit.replace("-", "_"))(group, spec, ctx, read)
            if isinstance(part, Refusal):
                return part
            main_sha, has_ci = self._origin_main(repo, ctx) if part.get("deploy_only") else ("", True)
        except RuntimeError as exc:
            return refuse(str(exc)[:500], alert=False)
        covered = list(part.get("findings") or group)
        gh = _github(spec)
        lead = covered[0]
        state = {"edit": edit, "repo": spec.repo, "github": gh,
                 "cves": sorted({c for f in covered for c in f.cves}), "group": lead.group,
                 "lead": lead.cves[0] if lead.cves else lead.group,
                 "packages": sorted({f.package.name for f in covered}),
                 "not_addressed": list(part.get("skipped") or [])}
        keys = [f.key for f in covered]
        deploy = spec.get("deploy", "")
        deploy_step = _deploy_step(spec, repo)
        if part.get("deploy_only"):
            state.update(deploy_only=True, main_sha=main_sha, has_ci=has_ci)
            return Plan(
                playbook=pid,
                component_id=spec.id,
                finding_keys=keys,
                target=f"{spec.id}: redeploy origin/main {main_sha[:7]} ({part['stale']})",
                lock_keys=[spec.lock],
                steps=[f"no PR: origin/main of {spec.repo} already contains the fix ({part['stale']}); "
                       "the deployed artifact is stale",
                       deploy_step,
                       f"rescan {spec.id}; the findings must clear"],
                undo=(f"redeploy the previously deployed release of {spec.id} ({deploy}); "
                      "origin/main is unchanged"),
                # The fix is already merged (by Carter or Dependabot), so there is no new
                # release for the age rule to hold back.
                release_published=None,
                fixed_version=part["fixed_version"],
                state=state,
            )
        state.update(path=part["path"], params=part["params"])
        return Plan(
            playbook=pid,
            component_id=spec.id,
            finding_keys=keys,
            target=part["target"],
            lock_keys=[spec.lock],
            steps=[
                f"git fetch; detached worktree of origin/main from {_tilde(repo)}",
                part["step"],
                "repo without CI workflows: run its verify.sh (else go build/vet/test) in the worktree "
                "before pushing; failure stops here",
                f"commit on secwatch/{spec.id}-{_group_slug(lead.group)}-<YYYYmmddHHMM>, push, "
                f"open PR on {gh} labelled {PR_LABEL} (refused while another {PR_LABEL} PR is open)",
                f"wait for CI green + mergeable (label '{HOLD_LABEL}' stops it); merge with the repo's "
                "allowed method, deleting the branch; any pre-merge failure closes the PR",
                deploy_step,
                f"rescan {spec.id}; the findings must clear",
            ],
            undo=(f"before merge: gh pr close <n> --repo {gh} --delete-branch; after merge: "
                  f"git -C {_tilde(repo)} revert --no-edit <merge sha> && git -C {_tilde(repo)} push origin main, "
                  f"then redeploy ({deploy})"),
            release_published=part.get("published"),
            fixed_version=part["fixed_version"],
            state=state,
        )

    @staticmethod
    def _origin_main(repo: Path, ctx) -> tuple[str, bool]:
        """(origin/main sha, whether origin/main has CI workflows); RuntimeError when unreadable."""
        result = ctx.run(["git", "-C", str(repo), "rev-parse", "--verify", "origin/main^{commit}"], timeout=30)
        sha = (result.stdout or "").strip()
        if result.returncode != 0 or not sha:
            raise RuntimeError(f"cannot resolve origin/main in {_tilde(repo)}: {_tail(result, 200)}")
        tree = ctx.run(["git", "-C", str(repo), "ls-tree", "--name-only", "origin/main", ".github/workflows/"],
                       timeout=30)
        names = (tree.stdout or "").split() if tree.returncode == 0 else []
        return sha, any(n.endswith((".yml", ".yaml")) for n in names)

    # Each _plan_<edit> returns a Refusal or a dict: target, path, params, step, fixed_version,
    # published (release ISO time for the age rule), findings (the covered subset; default the
    # whole group), skipped (findings left out, listed in the PR body as not addressed) -- or
    # {"deploy_only": True, "stale": why, "fixed_version", "findings"?} when origin/main
    # already carries the fix and only the deployed artifact is stale.

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
        # No release date: the fix is whatever the distro archive ships at build time (Debian/
        # Alpine security updates), not one newly published artifact -- exempt from the age rule.
        return {"target": target, "path": path, "params": {"stamp": stamp}, "step": step,
                "fixed_version": group[0].fixed_versions[0]}

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
            return {"deploy_only": True, "fixed_version": need,
                    "stale": f"{path} already builds with golang {current}, fix {need}"}
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
        published = proxy_release_time(GO_TOOLCHAIN_INFO_URL.format(version=need), ctx.fetch)
        return {"target": f"{spec.id}: {path} golang {current} -> {need}", "path": path,
                "params": {"version": need, "digest": digest if pinned else None},
                "step": f"FROM golang:{tag}{'@' + digest if pinned else ''} in {path} (stage names kept)",
                "fixed_version": need, "published": published}

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
            return {"deploy_only": True, "fixed_version": need,
                    "stale": f"go.mod already uses toolchain go{current}, fix {need}"}
        published = proxy_release_time(GO_TOOLCHAIN_INFO_URL.format(version=need), ctx.fetch)
        return {"target": f"{spec.id}: go.mod toolchain go{current} -> go{need}", "path": "go.mod",
                "params": {"version": need}, "step": f"set toolchain go{need} in go.mod",
                "fixed_version": need, "published": published}

    def _plan_go_module(self, group, spec, ctx, read):
        text = read("go.mod")
        if text is None:
            return Refusal(self.id, spec.id, f"cannot read origin/main:go.mod in {spec.repo}")
        modules: dict[str, str] = {}
        required: dict[str, str] = {}
        bumped: list[Finding] = []
        stale: list[tuple[Finding, str, str]] = []
        skipped: list[str] = []
        for finding in group:
            name = finding.package.name
            have = _go_mod_required(text, name)
            if have is None:
                skipped.append(f"{name} is not required in {spec.repo}/go.mod")
                continue
            above = [_strip_prefix(v) for v in finding.fixed_versions
                     if _semver_lt(finding.package.version, v)]
            fixed = min(above, key=_semver_key) if above else None
            if fixed is None:
                skipped.append(f"{name}: no fixed version above {finding.package.version} "
                               f"(fixed: {', '.join(finding.fixed_versions)})")
                continue
            if is_go_pseudo_version(fixed):
                pseudo = fixed
                fixed = resolve_go_tag(name, pseudo, ctx.fetch)
                if fixed is None:
                    skipped.append(f"fix for {name} exists only at an untagged commit (v{pseudo}); "
                                   "waiting for a tagged release")
                    continue
            if not _semver_lt(have, fixed):
                stale.append((finding, f"{name} v{have}", fixed))
                continue
            current = modules.get(name)
            modules[name] = fixed if current is None or _semver_lt(current, fixed) else current
            required[name] = have
            bumped.append(finding)
        if not bumped and not stale:
            return Refusal(self.id, spec.id, skipped[0])
        covered = {id(f) for f in bumped} | {id(f) for f, _, _ in stale}
        findings = [f for f in group if id(f) in covered]
        if not bumped:
            return {"deploy_only": True, "findings": findings, "skipped": skipped,
                    "fixed_version": stale[0][2],
                    "stale": "go.mod already requires " + ", ".join(d for _, d, _ in stale)}
        pairs = sorted(modules.items())
        published = max((proxy_release_time(
            GO_PROXY_INFO_URL.format(module=escape_module_path(m), version=v), ctx.fetch) for m, v in pairs),
            key=model.parse_iso)
        return {"target": f"{spec.id}: go.mod " + ", ".join(f"{m} v{required[m]} -> v{v}" for m, v in pairs),
                "path": "go.mod", "params": {"modules": [list(p) for p in pairs]},
                "step": "go get " + " ".join(f"{m}@v{v}" for m, v in pairs) + " && go mod tidy",
                "fixed_version": modules[bumped[0].package.name], "published": published,
                "findings": findings, "skipped": skipped}

    def _plan_pip_pin(self, group, spec, ctx, read):
        text = read("requirements.txt")
        if text is None:
            return Refusal(self.id, spec.id, f"cannot read origin/main:requirements.txt in {spec.repo}")
        pins: dict[str, str] = {}
        current: dict[str, str] = {}
        bumped: list[Finding] = []
        stale: list[tuple[Finding, str, str]] = []
        skipped: list[str] = []
        for finding in group:
            name = finding.package.name
            have = _pip_pin(text, name)
            if have is None:
                skipped.append(f"{name} is not pinned with == in {spec.repo}/requirements.txt")
                continue
            fixed = _smallest_fixed_above(finding.fixed_versions, finding.package.version)
            if fixed is None:
                skipped.append(f"{name}: no fixed version above {finding.package.version} "
                               f"(fixed: {', '.join(finding.fixed_versions)})")
                continue
            if not _vlt(have, fixed):
                stale.append((finding, f"{name}=={have}", fixed))
                continue
            pins[name] = _max_version(pins.get(name), fixed)
            current[name] = have
            bumped.append(finding)
        if not bumped and not stale:
            return Refusal(self.id, spec.id, skipped[0])
        covered = {id(f) for f in bumped} | {id(f) for f, _, _ in stale}
        findings = [f for f in group if id(f) in covered]
        if not bumped:
            return {"deploy_only": True, "findings": findings, "skipped": skipped,
                    "fixed_version": stale[0][2],
                    "stale": "requirements.txt already pins " + ", ".join(d for _, d, _ in stale)}
        pairs = sorted(pins.items())
        # No release date: PyPI fixes are exempt from the age rule (pip-pin is gated by CI
        # or the repo's own checks plus the release script's verify).
        return {"target": f"{spec.id}: requirements.txt " + ", ".join(f"{n} {current[n]} -> {v}" for n, v in pairs),
                "path": "requirements.txt", "params": {"pins": [list(p) for p in pairs]},
                "step": "pin " + ", ".join(f"{n}=={v}" for n, v in pairs) + " in requirements.txt",
                "fixed_version": pins[bumped[0].package.name], "findings": findings, "skipped": skipped}

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

        if st.get("deploy_only"):
            return self._start_deploy_only(st, spec, gh, ctx)
        existing, err = self._open_watch_pr(gh, ctx)
        if err:
            return Outcome("refused", err[:500], verify=False, state=dict(untouched))
        if existing:
            return Outcome("refused", f"open security-watch PR #{existing.get('number')} {existing.get('url')} "
                                      f"already exists on {gh}; merge or close it first",
                           verify=False, state={**untouched, "alert": True})
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
            workflows = tmp / ".github" / "workflows"
            has_ci = workflows.is_dir() and any(workflows.glob("*.y*ml"))
            if not has_ci:
                error = self._pre_push_checks(tmp, ctx)
                if error:
                    return fail(f"{spec.repo} has no CI and its checks fail on the edited tree "
                                f"(nothing pushed): {error}")
            title = pr_title(edit, len(plan.finding_keys), st.get("lead") or st.get("group") or plan.target)
            branch = f"secwatch/{spec.id}-{_group_slug(st.get('group') or 'finding')}-{ctx.now.strftime('%Y%m%d%H%M')}"
            for argv in (["git", "-C", str(tmp), "add", "--", *files],
                         ["git", "-C", str(tmp), "commit", "-m", title, "-m", plan.target,
                          "-m", _commit_findings(plan, st)]):
                result = ctx.run(argv, timeout=120)
                if result.returncode != 0:
                    return fail(f"{argv[3]} failed: {_tail(result)}")
            head = (ctx.run(["git", "-C", str(tmp), "rev-parse", "HEAD"], timeout=30).stdout or "").strip()
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

    def _start_deploy_only(self, st: dict, spec: ComponentSpec, gh: str, ctx) -> Outcome:
        """origin/main already fixes the findings: no PR, the action starts at the deploy stage."""
        sha = str(st.get("main_sha") or "")
        state = {"stage": "deploy", "deploy_only": True, "repo": spec.repo, "github": gh,
                 "edit": st.get("edit"), "merge_sha": sha, "has_ci": bool(st.get("has_ci", True)),
                 "created_at": model.iso(ctx.now), "merged_at": model.iso(ctx.now),
                 "production_touched": False}
        _log(f"{spec.id}: origin/main {sha[:7]} already contains the fix; deploy-only action")
        return Outcome("pending", f"origin/main {sha[:7]} already contains the fix; deploying it next tick",
                       undo=self._undo(state, spec), verify=False, state=state)

    @staticmethod
    def _open_watch_pr(gh: str, ctx) -> tuple[dict | None, str]:
        """(an open security-watch PR on ``gh`` or None, error when the list failed)."""
        result = ctx.run(["gh", "pr", "list", "--repo", gh, "--state", "open", "--limit", "100",
                          "--json", "number,url,headRefName,labels"], timeout=60)
        data = _json(result) if result.returncode == 0 else None
        if not isinstance(data, list):
            return None, f"cannot list open PRs on {gh}: {_tail(result, 200)}"
        for pr in data:
            if not isinstance(pr, dict):
                continue
            labels = {str(l.get("name", "")).lower() for l in pr.get("labels") or [] if isinstance(l, dict)}
            if PR_LABEL in labels or str(pr.get("headRefName") or "").startswith("secwatch/"):
                return pr, ""
        return None, ""

    def _pre_push_checks(self, tmp: Path, ctx) -> str:
        """The repo's own checks on the edited worktree (repos without CI); '' when they pass."""
        if (tmp / "verify.sh").is_file():
            commands = [["bash", "verify.sh"]]
        elif (tmp / "go.mod").is_file():
            commands = [["go", "build", "./..."], ["go", "vet", "./..."], ["go", "test", "./..."]]
        else:
            return ""
        for argv in commands:
            result = self._script_run(argv, timeout=CHECK_TIMEOUT, cwd=str(tmp), env=_go_env())
            if result.returncode != 0:
                return f"{' '.join(argv)} exited {result.returncode}: {_tail(result, 200)}"
        return ""

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
                 f"**Findings (issuer records, {len(plan.finding_keys)}):**"]
        for key in plan.finding_keys:
            finding = (ctx.findings or {}).get(key)
            if finding is None:
                lines.append(f"- {key}")
                continue
            ids = ", ".join(finding.cves or finding.advisory_ids)
            lines.append(f"- {ids}: {finding.package.ident()} fixed in {', '.join(finding.fixed_versions)}"
                         f" ({finding.severity or 'unrated'}, {finding.urgency})")
        not_addressed = list(plan.state.get("not_addressed") or [])
        if not_addressed:
            lines += ["", "**Not addressed by this PR (no deterministic fix yet):**",
                      *[f"- {note}" for note in not_addressed]]
        lines += ["", "**Steps:**", *[f"{i}. {s}" for i, s in enumerate(plan.steps, 1)], "",
                  f"security-watch merges this PR once CI is green, then deploys it. Add the `{HOLD_LABEL}` "
                  "label to stop it; closing the PR cancels the action."]
        body = "\n".join(lines)
        return body if len(body) <= PR_BODY_MAX else body[:PR_BODY_MAX - 40] + "\n\n(list truncated)"

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
            return self._advance_deploy(action, state, spec, ctx)
        if stage == "deploying":
            # Journaled right before a release/deploy script whose outcome never landed: the
            # tick died (unit timeout, OOM) or another process is still running it.  Never
            # re-run it blindly; act fails the row with the breaker once it is stale.
            return Outcome("refused", f"deploy started {state.get('deploying_at') or '?'} journaled no outcome "
                                      "(interrupted or still running); not re-running it",
                           undo=self._undo(state, spec), verify=False, state=state)
        return Outcome("failed", f"unknown repo-pr stage {stage!r}", verify=False, state=state)

    def _undo(self, state: dict, spec: ComponentSpec) -> str:
        repo = _tilde(_repo_dir(spec))
        if state.get("deploy_only"):
            return (f"redeploy the previously deployed release of {spec.id} ({spec.get('deploy', '')}); "
                    "origin/main was not changed")
        if state.get("merge_sha") or state.get("stage") in ("deploy", "deploying"):
            sha = state.get("merge_sha") or "<merge sha>"
            return (f"git -C {repo} revert --no-edit {sha} && git -C {repo} push origin main, "
                    f"then redeploy ({spec.get('deploy', '')})")
        return f"gh pr close {state.get('pr')} --repo {state.get('github')} --delete-branch"

    def _wait(self, state: dict, since_key: str, detail: str, spec: ComponentSpec, ctx) -> Outcome:
        since = model.parse_iso(state.get(since_key)) or model.parse_iso(state.get("created_at"))
        if since is not None and ctx.now - since >= WAIT_LIMIT:
            detail = f"{detail}; gave up after {int(WAIT_LIMIT.total_seconds() // 3600)} h"
            if state.get("stage") in ("ci", "merging"):
                detail += self._close_pr(state, ctx, detail)
                return Outcome("failed", detail[:500], undo="", verify=False, state=state)
            return Outcome("failed", detail[:500], undo=self._undo(state, spec), verify=False, state=state)
        return Outcome("pending", detail, undo=self._undo(state, spec), verify=False, state=state)

    @staticmethod
    def _close_pr(state: dict, ctx, reason: str, *, delete_branch: bool = True) -> str:
        """Close a PR the action gives up on (pre-merge); returns a detail suffix."""
        argv = ["gh", "pr", "close", str(state.get("pr")), "--repo", str(state.get("github")),
                "--comment", f"security-watch stopped: {reason}"[:1000]]
        if delete_branch:
            argv.append("--delete-branch")
        result = ctx.run(argv, timeout=60)
        if result.returncode != 0:
            return f"; closing PR #{state.get('pr')} failed: {_tail(result, 150)}"
        return f"; closed PR #{state.get('pr')}" + (" and deleted its branch" if delete_branch else "")

    @staticmethod
    def _delete_branch(state: dict, ctx) -> str:
        """Delete the secwatch branch of a PR someone else closed; returns a detail suffix."""
        branch = str(state.get("branch") or "")
        if not branch.startswith("secwatch/"):
            return ""
        result = ctx.run(["gh", "api", "-X", "DELETE", f"repos/{state.get('github')}/git/refs/heads/{branch}"],
                         timeout=60)
        return f"; deleted branch {branch}" if result.returncode == 0 else ""

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

    def _held_outcome(self, state: dict, spec: ComponentSpec) -> Outcome:
        return Outcome("refused", f"held by Carter: {state.get('url') or 'PR #' + str(state.get('pr'))}",
                       undo=self._undo(state, spec), verify=False, state={**state, "alert": True})

    def _closed(self, state: dict, ctx) -> Outcome:
        detail = f"PR #{state['pr']} was closed without merge (action cancelled)" + self._delete_branch(state, ctx)
        return Outcome("failed", detail, undo="", verify=False, state=state)

    def _merged(self, state: dict, data: dict, ctx) -> None:
        commit = data.get("mergeCommit") or {}
        state.update(stage="deploy", merge_sha=commit.get("oid") if isinstance(commit, dict) else "",
                     merged_at=model.iso(ctx.now))

    def _advance_ci(self, state: dict, spec: ComponentSpec, ctx) -> Outcome:
        data, err = self._pr_view(state, ctx)
        if data is None:
            return self._wait(state, "created_at", err, spec, ctx)
        pr_state = data.get("state")
        if pr_state == "MERGED":
            self._merged(state, data, ctx)
            return Outcome("pending", f"PR #{state['pr']} was merged; deploy next tick",
                           undo=self._undo(state, spec), verify=False, state=state)
        if pr_state == "CLOSED":
            return self._closed(state, ctx)
        if self._held(data):
            return self._held_outcome(state, spec)
        head = state.get("head")
        if head and data.get("headRefOid") and data["headRefOid"] != head:
            detail = (f"PR #{state['pr']} head changed since security-watch opened it "
                      f"({head[:7]} -> {data['headRefOid'][:7]}); not merging")
            # Someone pushed to the branch: close the PR but keep their commits on it.
            detail += self._close_pr(state, ctx, detail, delete_branch=False)
            return Outcome("failed", detail, undo="", verify=False, state=state)
        verdict, detail = _checks(data.get("statusCheckRollup"), bool(state.get("has_ci", True)))
        if verdict == "failed":
            detail = f"PR #{state['pr']} checks failed: {detail}"
            detail += self._close_pr(state, ctx, detail)
            return Outcome("failed", detail[:500], undo="", verify=False, state=state)
        if verdict == "pending":
            return self._wait(state, "created_at", f"PR #{state['pr']} checks pending: {detail}", spec, ctx)
        mergeable = data.get("mergeable")
        if mergeable == "CONFLICTING":
            detail = f"PR #{state['pr']} conflicts with main"
            detail += self._close_pr(state, ctx, detail)
            return Outcome("failed", detail, undo="", verify=False, state=state)
        if mergeable != "MERGEABLE":
            return self._wait(state, "created_at", f"PR #{state['pr']} mergeable={mergeable}", spec, ctx)
        method, err = self._merge_method(state, ctx)
        if method is None:
            return self._wait(state, "created_at", err, spec, ctx)
        argv = ["gh", "pr", "merge", str(state["pr"]), "--repo", state["github"], f"--{method}",
                "--delete-branch"]
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
            return self._closed(state, ctx)
        if self._held(data):
            return self._held_outcome(state, spec)
        return self._wait(state, "merge_requested_at", f"PR #{state['pr']} not merged yet", spec, ctx)

    def _advance_deploy(self, action: dict, state: dict, spec: ComponentSpec, ctx) -> Outcome:
        holder = f"security-watch:repo-pr:{spec.id}"
        try:
            with ctx.lock(spec.lock, timeout=ctx.policy.lock_timeout_seconds, holder=holder):
                return self._deploy(action, state, spec, ctx)
        except LockTimeout as exc:
            return self._wait(state, "merged_at", f"deploy lock {spec.lock} busy: {exc}", spec, ctx)

    def _deploy(self, action: dict, state: dict, spec: ComponentSpec, ctx) -> Outcome:
        kind, _, arg = str(spec.get("deploy", "")).partition(":")
        if kind == "steward-app" and arg:
            return self._deploy_app(action, arg, state, spec, ctx)
        if kind == "release" and arg:
            return self._deploy_release(action, arg, state, spec, ctx)
        return Outcome("failed", f"unsupported deploy {spec.get('deploy')!r} for {spec.id}",
                       undo=self._undo(state, spec), verify=False, state=state)

    @staticmethod
    def _journal_deploying(action: dict, state: dict, detail: str, ctx) -> None:
        """Contract 8: production counts as touched from here until an outcome is journaled."""
        ctx.store.update_action(action["id"], status="pending", detail=detail[:500], now=ctx.now,
                                state={**state, "stage": "deploying", "deploying_at": model.iso(ctx.now),
                                       "production_touched": True})

    def _deploy_app(self, action: dict, service: str, state: dict, spec: ComponentSpec, ctx) -> Outcome:
        registry_spec = self._registry().get(service)
        if registry_spec is None:
            return Outcome("failed", f"{service} is not in steward DEPLOY_REGISTRY",
                           undo=self._undo(state, spec), verify=False, state=state)
        self._journal_deploying(action, state, f"deploying {service} via steward app_deploy", ctx)
        row = self._steward_app_deploy()(service, registry_spec, dry_run=False, sleep=self._sleep) or {}
        status = row.get("status")
        reason = str(row.get("reason") or row.get("error") or "")
        if status == "skipped":
            if reason == "current":
                if state.get("deploy_only"):
                    return Outcome("failed", f"{service} production is already at origin/main yet the findings "
                                             "are open; a redeploy cannot clear them (rebuild it manually)",
                                   undo="", verify=False, state=state)
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

    def _commit_ci(self, github: str, sha: str, ctx) -> tuple[bool | None, str]:
        """steward ``_ci_green(allow_pending=True)`` for one commit: True green, None not
        finished / not readable yet, False red."""
        payloads = []
        for kind in ("check-runs", "status"):
            result = ctx.run(["gh", "api", f"repos/{github}/commits/{sha}/{kind}?per_page=100"], timeout=60)
            data = _json(result) if result.returncode == 0 else None
            if not isinstance(data, dict):
                return None, f"{kind} lookup failed: {_tail(result, 150)}"
            payloads.append(data)
        return commit_ci_verdict(*payloads)

    def _deploy_release(self, action: dict, script: str, state: dict, spec: ComponentSpec, ctx) -> Outcome:
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
        rev = ctx.run([*git, "rev-parse", "HEAD"], timeout=30)
        head = (rev.stdout or "").strip()
        if rev.returncode != 0 or not head:
            return self._wait(state, "merged_at", f"cannot read HEAD in {_tilde(repo)}: {_tail(rev, 200)}",
                              spec, ctx)
        if state.get("has_ci", True):
            # A rebase/squash merge is a new commit: release scripts gate on its own CI run
            # (homelab-dashboard's ci_gate dies while it runs), so wait for main's CI first.
            green, ci = self._commit_ci(state.get("github") or _github(spec), head, ctx)
            if green is None:
                return self._wait(state, "merged_at", f"waiting for CI on {head[:7]} before bash {script}: {ci}",
                                  spec, ctx)
            if not green:
                return self._wait(state, "merged_at", f"CI on {head[:7]} is red; not running bash {script}: {ci}",
                                  spec, ctx)
        # The component's own scheduled job (homelab-backup's 03:00 UTC run) must not overlap a
        # release: same window as release-rebuild.  Stays pending (no 24 h give-up), untouched.
        from security_watch.playbooks_ops import _quiet_reason
        quiet = _quiet_reason(ctx, spec)
        if quiet:
            return Outcome("pending", f"not running bash {script}: {quiet}",
                           undo=self._undo(state, spec), verify=False, state=state)
        marker = _TRANSACTION_MARKERS.get((spec.repo, script))
        before = inventory.fingerprint(spec, run=ctx.run) if marker else ""
        state["deployed_head"] = head
        self._journal_deploying(action, state, f"deploying {head[:7]}: bash {script} in {_tilde(repo)}", ctx)
        _log(f"{spec.id}: running bash {script} in {_tilde(repo)} at {head[:7]}")
        result = self._script_run(["bash", script], timeout=RELEASE_TIMEOUT, cwd=str(repo), env=_go_env())
        undo = self._undo(state, spec)
        if (result.returncode not in (0, 124) and marker and before
                and not re.search(marker, f"{result.stdout or ''}\n{result.stderr or ''}", re.M)
                and inventory.fingerprint(spec, run=ctx.run) == before):
            state["production_touched"] = False
            return Outcome("failed", f"bash {script} exited {result.returncode} in its preconditions, before "
                                     f"changing production: {_tail(result, 200)}",
                           undo=undo, verify=False, state=state)
        state["production_touched"] = True
        healthy, detail = self._health(spec, ctx)
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
