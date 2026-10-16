"""P7b repair worker and trusted patch publisher.

:func:`run_fix` stages each target repository's verified base commit into a
disposable snapshot with ``git archive`` (never the live checkout), lets one
headless omp agent edit only that snapshot, runs the deterministic validation
plan on a separate copy, and asks a second omp call to judge the exact diff.
Like the other homelab agents, omp runs as Carter with its stored login;
``--no-new-privs`` blocks sudo.  Only a judge-pass result can reach
:func:`publish_validated_result`, which stores an exact, path-bounded commit
under refs/steward-review without changing HEAD, the index, or the checkout.
"""
from __future__ import annotations

import ast
import builtins
import copy
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .config import HOME, SESSION_DIR, STEWARD_MODEL, STEWARD_PATH

PROTOCOL_VERSION = "steward-worker-v1"
OMP_BIN = HOME / ".bun" / "bin" / "omp"
HEADLESS_CONFIG = HOME / ".omp" / "agent" / "headless-override.yml"
DEV_ROOT = Path(os.environ.get("STEWARD_DEV_ROOT", "/home/carter/dev"))
MAX_FINDINGS = 32
MAX_PATHS_PER_REPOSITORY = 64
# Existing test files that import a repaired module may receive an
# additive-only regression test (see _check_additive_test_change).
MAX_COMPANION_TESTS = 3
_TEST_FILE_RE = re.compile(r"^(?:test_.*|.*_test)\.py$")
MAX_DIFF_BYTES = 768 * 1024
MAX_COMMAND_OUTPUT = 4000
MAX_VALIDATION_SECONDS = 900
MAX_REPAIR_SECONDS = 2700

# Source repositories are intentionally narrower than the rest of Carter's
# home.  App code lives in ~/dev; ~/scripts is repaired only through a
# disposable clone of the private dotfiles repository under STEWARD_CODE_ROOT
# (never the live checkout), and system-config is never model-published.
_ALLOWED_REPO_ROOT = DEV_ROOT.resolve()
_PROTECTED_COMPONENTS = {
    ".git",
    ".github",
    ".ssh",
    ".omp",
    ".config",
    "cloudflare",
    "r2",
    "secrets",
    "credentials",
    "auth",
}
_PROTECTED_FILE_NAMES = {".gitignore", ".gitattributes", ".gitmodules"}
_INFRA_COMPONENTS = {
    "deploy", "deployment", "infra", "infrastructure", "terraform", "k8s",
    "kubernetes", "k3s", "systemd", "system-config", "backup", "backups",
    "steward", "orchestrator", "security",
}
_INFRA_FILE_RE = re.compile(
    r"(?i)^(?:dockerfile(?:[.-].*)?|(?:docker-)?compose(?:[.-].*)?\.ya?ml|"
    r"(?:release|deploy|up)\.sh|procfile(?:\..*)?|wrangler(?:\..*)?|"
    r".*\.(?:service|timer|socket|mount|path|tf|tfvars))$"
)
_INFRA_REPOSITORIES = {
    "homelab-backup", "prompt-guard", "opencode-go-proxy",
    "dependabot-webhook", "llm-proxy",
}
_SECRET_NAME_RE = re.compile(
    r"(?i)(?:^|[/.])(?:\.env(?:\..*)?|.*(?:api[-_]?token|credentials?|master\.key|"
    r"auth\.json|(?:id[_-]?(?:rsa|ed25519))|.*\.pem|.*\.ovpn|.*\.htpasswd))$"
)
_SECRET_VALUE_RE = re.compile(
    r"(?is)(\b(?:authorization|bearer|api[-_]?key|access[-_]?token|refresh[-_]?token|"
    r"password|passwd|secret(?:[-_]?access)?[-_]?key)\b\s*[:=]\s*)([^\s,;]+)"
)
_LONG_TOKEN_RE = re.compile(r"(?i)\b(?:sk-[a-z0-9_-]{20,}|gh[pousr]_[a-z0-9_]{20,})\b")
_PATH_RE = re.compile(
    r"(?P<path>(?:~/|/home/carter/)?dev/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.@+:-]+)*)"
)

# Steward/dotfiles code repairs (routing's steward-code route) use a
# disposable clone of the private dotfiles repository, created by the parent
# directly under this root.  Only such a clone may name ``scripts/**`` paths
# (including the otherwise-infrastructure ``steward`` component).
STEWARD_CODE_ROOT = DEV_ROOT / ".steward-code"
REPO_KIND_APP = "app"
REPO_KIND_STEWARD_CODE = "steward-code"
# Never model-repaired: routing/allowlist and autonomy-gate code (router,
# worker policy, steward-code PR/merge/pickup, the P7c resolver and its
# approve CLI, the workflow's fingerprint/abort boundary, the runtime's model
# tool allowlist and no-new-privs wrapper), publication and secret-scanning
# policy, Jev thresholds, the verification gates, and the tests that pin them.
# These stay needs-Carter (no self-widening of autonomy).  The one list is
# used by routing, the worker, the root helper, the publisher and the pre-PR gate.
STEWARD_CODE_PROTECTED = frozenset({
    "scripts/jev.py",
    "scripts/dotfiles_commit.py",
    "scripts/steward_runner.py",
    "scripts/steward_approve.py",
    ".local/bin/steward-approve",
    "scripts/steward/config.py",
    "scripts/steward/routing.py",
    "scripts/steward/worker.py",
    "scripts/steward/runtime.py",
    "scripts/steward/workflow.py",
    "scripts/steward/resolver.py",
    "scripts/steward/code_prs.py",
    "scripts/steward/code_pickup.py",
    "scripts/steward/dotfiles.py",
    "scripts/steward/public_dotfiles.py",
    "scripts/test_steward_routing.py",
    "scripts/test_steward_worker.py",
    "scripts/test_steward_workflow.py",
    "scripts/test_steward_resolver.py",
    "scripts/test_steward_code_prs.py",
    "scripts/test_steward_dotfiles.py",
    "scripts/test_steward_public_dotfiles.py",
})
_STEWARD_CODE_PROTECTED_RE = re.compile(r"^scripts/verify-[^/]*\.sh$")
# verify-<name>.sh full runs for a steward-code patch: ``steward`` always, the
# others when a changed path is in their area (prefix match).
STEWARD_CODE_VERIFIERS = (
    ("steward", ("",)),
    ("daily-news", (
        "scripts/daily_news/", "scripts/digest_runner.py", "scripts/news_",
        "scripts/send_digest.py", "scripts/run_all_digests.sh", "scripts/test_digest_",
        "scripts/test_news_", "scripts/digest-omp-sandbox.ts",
        "scripts/analyze_daily_news_attention.py", "scripts/workflow_state.py",
        "scripts/requirements-daily-news.txt",
    )),
    ("dependabot-intake", (
        "scripts/hyperliquid_dependabot_intake.py",
        "scripts/test_hyperliquid_dependabot_intake.py",
    )),
    ("hyperliquid-guard", (
        "scripts/run_hyperliquid_sdk.sh", "scripts/cleanup-rig-requests.sh",
        "scripts/smoke-test-llm.sh", "scripts/update_llama_cpp_remote.sh",
        "scripts/test_hyperliquid_dependabot_guard.ts", "scripts/send_digest.py",
        "scripts/hyperliquid_dependabot_intake.py",
    )),
)

# Tracked files outside ~/scripts that those verifiers read from the checkout
# (verify-daily-news.sh preflights with HOME=<checkout>; the Hyperliquid guard
# verifier bundles the shipped guard and checks its unit).  They sit under
# components a snapshot otherwise leaves out, so a steward-code snapshot stages
# exactly these, read-only: they are never repair paths, and _snapshot_diff
# rejects any worker change to them.
STEWARD_CODE_VERIFIER_SUPPORT = frozenset({
    ".omp/agent/daily-news-headless.yml",
    ".config/hyperliquid-agent/omp-dependabot-guard.ts",
    ".config/systemd/user/hyperliquid-sdk.service",
})


def repo_kind(root: Path | str) -> str:
    """Lexical: a direct child of STEWARD_CODE_ROOT is a steward-code clone."""
    path = Path(os.path.normpath(str(root)))
    return REPO_KIND_STEWARD_CODE if path.parent == Path(os.path.normpath(str(STEWARD_CODE_ROOT))) else REPO_KIND_APP


def steward_code_verifiers(paths: Iterable[str]) -> list[str]:
    """verify-<name>.sh names that must pass for a change to ``paths``."""
    paths = list(paths)
    return [
        name for name, prefixes in STEWARD_CODE_VERIFIERS
        if name == "steward" or any(p.startswith(prefix) for p in paths for prefix in prefixes)
    ]


def steward_code_validation_commands(paths: Iterable[str]) -> list[list[str]]:
    return [["bash", f"scripts/verify-{name}.sh", "full"] for name in steward_code_verifiers(paths)]


def steward_code_path_reason(path: str) -> str | None:
    """Why a repository-relative path may not be model-repaired; None if it may."""
    p = Path(path)
    if path in STEWARD_CODE_PROTECTED or _STEWARD_CODE_PROTECTED_RE.fullmatch(path):
        return f"{path} is routing/allowlist, secret-scanning, publication, or gate code"
    if not path.startswith("scripts/") or len(p.parts) < 2:
        return f"only ~/scripts/** is auto-repairable: {path}"
    lowered = [part.lower() for part in p.parts]
    if any(part in _PROTECTED_COMPONENTS for part in lowered) or any(
        part in _PROTECTED_FILE_NAMES for part in lowered
    ):
        return f"{path} is Git metadata or a credential location"
    if any(part in _INFRA_COMPONENTS - {"steward"} for part in lowered) or _INFRA_FILE_RE.fullmatch(p.name):
        return f"{path} is deployment/systemd/security/backup infrastructure"
    if _SECRET_NAME_RE.search(path) or _SECRET_NAME_RE.search(p.name):
        return f"{path} looks like a secret"
    return None

# Commands are argv vectors, never shell strings.  The parent may only pass
# these fixed validation families; the worker does not execute a model-
# supplied command.  Extra project-specific checks can be added by the human
# provisioning policy, not by an audit finding.
_VALIDATION_PROGRAMS = {
    "python3",
    "python",
    "pytest",
    "go",
    "npm",
    "bun",
    "cargo",
    "ruby",
    "bundle",
}


class WorkerPolicyError(ValueError):
    """A request or result violated the bounded-worker policy."""


class WorkerExecutionError(RuntimeError):
    """The isolated service could not complete a request."""


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _redact(value: Any) -> Any:
    """Remove obvious secret values before audit text enters the worker."""
    if isinstance(value, Mapping):
        return {str(k): _redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    if isinstance(value, tuple):
        return [_redact(v) for v in value]
    if not isinstance(value, str):
        return value
    value = _SECRET_VALUE_RE.sub(r"\1[REDACTED]", value)
    return _LONG_TOKEN_RE.sub("[REDACTED]", value)


def _safe_relpath(path: str, *, source_listing: bool = False, kind: str = REPO_KIND_APP) -> str:
    if not isinstance(path, str):
        raise WorkerPolicyError("relative path is not text")
    raw = path
    p = Path(raw)
    if (
        not raw or raw != raw.strip() or raw != p.as_posix()
        or raw == "." or p.is_absolute() or ".." in p.parts
        or "\\" in raw or any(ord(char) < 32 or ord(char) == 127 for char in raw)
    ):
        raise WorkerPolicyError(f"unsafe relative path: {path!r}")
    if kind == REPO_KIND_STEWARD_CODE:
        if source_listing and raw in STEWARD_CODE_VERIFIER_SUPPORT:
            return p.as_posix()
        if not source_listing:
            reason = steward_code_path_reason(raw)
            if reason:
                raise WorkerPolicyError(f"steward-code path is not repairable: {reason}")
            return p.as_posix()
    protected_components = _PROTECTED_COMPONENTS
    protected_files = _PROTECTED_FILE_NAMES
    if source_listing:
        # Existing repository metadata/workflows may be present in a snapshot,
        # but they can never be selected as an allowed repair path.
        protected_components = protected_components - {".github"}
        protected_files = frozenset()
    if any(part.lower() in protected_components for part in p.parts):
        raise WorkerPolicyError(f"protected path is not repairable: {path!r}")
    if any(part.lower() in protected_files for part in p.parts):
        raise WorkerPolicyError(f"Git metadata/workflow path is not repairable: {path!r}")
    if not source_listing and (
        any(part.lower() in _INFRA_COMPONENTS for part in p.parts)
        or _INFRA_FILE_RE.fullmatch(p.name)
    ):
        raise WorkerPolicyError(f"infrastructure path is not repairable: {path!r}")
    if _SECRET_NAME_RE.search("/".join(p.parts)) or _SECRET_NAME_RE.search(p.name):
        raise WorkerPolicyError(f"secret-looking path is not repairable: {path!r}")
    return p.as_posix()


def _under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def _run(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout: float = 120,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one deterministic argv command without a shell."""
    return subprocess.run(
        [str(arg) for arg in argv],
        cwd=str(cwd) if cwd is not None else None,
        env=dict(env) if env is not None else _minimal_env(),
        input=input_text,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _git_args(root: Path, *args: str) -> list[str]:
    """Use only built-in Git behavior; local executable filters are rejected."""
    return [
        "/usr/bin/git",
        "-C",
        str(root),
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "diff.external=",
        "-c",
        "core.quotePath=false",
        "-c",
        "core.pager=cat",
        *args,
    ]


def _minimal_env(*, home: str = "/var/empty") -> dict[str, str]:
    return {
        "HOME": home,
        "PATH": STEWARD_PATH,
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_LITERAL_PATHSPECS": "1",
        "NO_COLOR": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    }


def _check_repo_config(root: Path, execute=None) -> None:
    """Inspect configuration names without running worktree/filter machinery."""
    git_dir = root / ".git"
    config = git_dir / "config"
    if git_dir.is_symlink() or not git_dir.is_dir() or config.is_symlink() or not config.is_file():
        raise WorkerPolicyError("repair requires a conventional non-symlink Git repository")
    argv = [
        "/usr/bin/git", "config", "--file", str(config), "--no-includes",
        "--null", "--name-only", "--list",
    ]
    cp = _run(argv, timeout=20) if execute is None else execute(argv)
    if cp.returncode != 0:
        raise WorkerPolicyError("cannot inspect repository configuration")
    for key in cp.stdout.lower().split("\0"):
        if (
            key.startswith(("filter.", "include.", "includeif."))
            or key in {"extensions.worktreeconfig", "extensions.partialclone"}
            or (key.startswith("remote.") and key.endswith(".promisor"))
            or (key.startswith("tar.") and key.endswith(".command"))
        ):
            raise WorkerPolicyError(f"executable or indirect Git configuration is not permitted: {key}")


def _repo_root(path: Path) -> Path:
    candidate = path.expanduser()
    if not candidate.is_absolute():
        raise WorkerPolicyError(f"repository path must be absolute: {path}")
    # Resolve the existing parent, but do not resolve a missing target file.
    probe = candidate if candidate.is_dir() else candidate.parent
    if not probe.exists():
        raise WorkerPolicyError(f"repository path does not exist: {path}")
    cp = _run(
        _git_args(probe, "rev-parse", "--show-toplevel"),
        timeout=20,
    )
    if cp.returncode != 0:
        raise WorkerPolicyError(f"not a Git worktree: {path}")
    root = Path(cp.stdout.strip()).resolve()
    if not _under(root, _ALLOWED_REPO_ROOT):
        raise WorkerPolicyError(f"repository is outside ~/dev: {root}")
    relative = root.relative_to(_ALLOWED_REPO_ROOT).parts
    if not relative or relative[0].lower() in _INFRA_REPOSITORIES:
        raise WorkerPolicyError(f"infrastructure repository is not repairable: {root}")
    _check_repo_config(root)
    return root


def _git_status(root: Path) -> str:
    _check_repo_config(root)
    cp = _run(
        _git_args(root, "status", "--porcelain=v1", "-z"),
        timeout=20,
    )
    if cp.returncode != 0:
        raise WorkerPolicyError(f"could not inspect repository status: {root}")
    return cp.stdout


def _tracked_paths(root: Path) -> list[str]:
    cp = _run(_git_args(root, "ls-files", "-z"), timeout=30)
    if cp.returncode != 0:
        raise WorkerPolicyError(f"could not enumerate repository: {root}")
    paths = []
    for path in cp.stdout.split("\0"):
        if not path:
            continue
        try:
            _safe_relpath(path, source_listing=True, kind=repo_kind(root))
        except WorkerPolicyError:
            continue
        paths.append(path)
    # A tracked symlink could point back into Carter's hidden home after a
    # snapshot. Refuse it rather than attempting to dereference selectively.
    # A steward-code clone (the dotfiles repo tracks systemd wants/ links)
    # never stages symlinks, so they are left out instead.
    tree = _run(_git_args(root, "ls-files", "-s", "-z"), timeout=30)
    if tree.returncode != 0:
        raise WorkerPolicyError(f"could not inspect repository modes: {root}")
    linked = set()
    for row in tree.stdout.split("\0"):
        if not row:
            continue
        mode = row.split(" ", 1)[0]
        if mode in {"120000", "160000"}:
            if repo_kind(root) != REPO_KIND_STEWARD_CODE or mode == "160000":
                raise WorkerPolicyError(f"symlinked or submodule source is not repairable: {root}")
            linked.add(row.partition("\t")[2])
    return [path for path in paths if path not in linked]


def _base_sha(root: Path) -> str:
    cp = _run(
        _git_args(root, "rev-parse", "--verify", "HEAD^{commit}"),
        timeout=20,
    )
    if cp.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", cp.stdout.strip()):
        raise WorkerPolicyError(f"could not determine repository base: {root}")
    return cp.stdout.strip()


def _normalise_target(repo: Path, path: str | None) -> str:
    """Convert a finding path to a safe path relative to its repository."""
    if path is None or not str(path).strip():
        raise WorkerPolicyError("a code repair must name an affected file")
    raw = str(path).strip()
    prefix = str(repo) + "/"
    if raw == str(repo):
        raise WorkerPolicyError("repository root is not a file path")
    if raw.startswith(prefix):
        raw = raw[len(prefix):]
    elif raw.startswith("~/"):
        home_path = Path("/home/carter") / raw[2:]
        if _under(home_path, repo):
            raw = str(home_path.resolve().relative_to(repo))
    elif raw.startswith("/home/carter/"):
        absolute = Path(raw)
        if _under(absolute, repo):
            raw = str(absolute.resolve().relative_to(repo))
    return _safe_relpath(raw, kind=repo_kind(repo))


def _find_repo_for_path(value: str, repos: Sequence[Path]) -> tuple[Path, str] | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    candidates: list[Path] = []
    if raw.startswith("~/"):
        candidates.append(Path("/home/carter") / raw[2:])
    elif raw.startswith("/home/carter/"):
        candidates.append(Path(raw))
    elif raw.startswith("dev/"):
        candidates.append(DEV_ROOT / raw[4:])
    for repo in repos:
        for candidate in candidates:
            if _under(candidate, repo):
                return repo, str(candidate.resolve().relative_to(repo))
    return None


def _explicit_repo_values(finding: Mapping[str, Any]) -> list[str]:
    values = []
    for key in ("repo", "repository", "repo_path", "worktree", "project"):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            values.append(value.strip())
    return values


def _explicit_paths(finding: Mapping[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("path", "file", "target", "source", "affected_path"):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            values.append(value.strip())
    for key in ("paths", "files", "affected_paths", "target_paths"):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            values.append(value.strip())
        elif isinstance(value, (list, tuple)):
            values.extend(str(item).strip() for item in value if str(item).strip())
    return values


def _target_plans(findings: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    """Build one or more clean app-repository plans from finding metadata.

    A finding without a concrete ``~/dev`` path is deliberately not guessed at:
    infrastructure, credential, deployment, and steward-source findings become
    reviewable/deferred rows instead of giving a model a broad filesystem.
    """
    if len(findings) > MAX_FINDINGS:
        return [], [f"too many findings (max {MAX_FINDINGS})"]
    explicit_roots: dict[str, Path] = {}
    errors: list[str] = []
    for finding in findings:
        if not isinstance(finding, Mapping):
            errors.append("finding is not an object")
            continue
        for value in _explicit_repo_values(finding):
            candidate = value
            if not candidate.startswith(("/", "~/")):
                candidate = str(DEV_ROOT / candidate)
            try:
                root = _repo_root(Path(candidate))
            except WorkerPolicyError as exc:
                errors.append(str(exc))
                continue
            explicit_roots[str(root)] = root

    all_repos = list(explicit_roots.values())
    if not all_repos:
        # Absolute paths in claim/evidence/fix are accepted only when they are
        # visibly inside ~/dev.  Never infer from a bare filename.
        for finding in findings:
            explicit_values = _explicit_paths(finding)
            text = " ".join(
                str(finding.get(key) or "")
                for key in ("claim", "evidence", "fix", "action")
            )
            values = explicit_values + [
                match.group("path") for match in _PATH_RE.finditer(text)
            ]
            for value in values:
                if not str(value).startswith(("/", "~/", "dev/")):
                    continue
                if str(value).startswith("~/"):
                    candidate = Path("/home/carter") / str(value)[2:]
                elif str(value).startswith("dev/"):
                    candidate = DEV_ROOT / str(value)[4:]
                else:
                    candidate = Path(str(value))
                try:
                    root = _repo_root(candidate)
                except WorkerPolicyError:
                    continue
                if root not in all_repos:
                    all_repos.append(root)

    if not all_repos:
        return [], errors or ["finding does not identify an allowed ~/dev repository/file"]

    by_repo: dict[str, dict[str, Any]] = {
        str(root): {
            "source": str(root), "base_sha": _base_sha(root), "allowed_paths": [],
            "companion_test_paths": [], "findings": [],
        }
        for root in all_repos
    }
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        paths = _explicit_paths(finding)
        if not paths:
            # Findings produced by older audit packets may carry only a path in
            # prose.  Infer it only when the complete ~/dev path is present;
            # bare filenames still remain non-actionable.
            text = " ".join(
                str(finding.get(key) or "")
                for key in ("claim", "evidence", "fix", "action")
            )
            paths.extend(
                match.group("path")
                for match in _PATH_RE.finditer(text)
                if _find_repo_for_path(match.group("path"), all_repos) is not None
            )
        matched = False
        matched_roots: set[Path] = set()
        for value in paths:
            hit = _find_repo_for_path(value, all_repos)
            if hit is None:
                # A path relative to an explicitly supplied repository is valid
                # when exactly one repository was named.
                if len(all_repos) == 1 and not value.startswith(("/", "~/", "dev/")):
                    root = all_repos[0]
                    try:
                        rel = _normalise_target(root, value)
                    except WorkerPolicyError as exc:
                        errors.append(str(exc))
                        continue
                    bucket = by_repo[str(root)]
                    if rel not in bucket["allowed_paths"]:
                        bucket["allowed_paths"].append(rel)
                    matched_roots.add(root)
                    matched = True
                else:
                    errors.append(f"path is outside the selected repository: {value}")
                continue
            root, raw_rel = hit
            try:
                rel = _normalise_target(root, raw_rel)
            except WorkerPolicyError as exc:
                errors.append(str(exc))
                continue
            bucket = by_repo[str(root)]
            if rel not in bucket["allowed_paths"]:
                bucket["allowed_paths"].append(rel)
            matched_roots.add(root)
            matched = True
        if not paths:
            # A repo-only finding is not enough: the worker must have exact file
            # boundaries, even if the model could otherwise inspect the repo.
            errors.append("finding names a repository but no affected file path")
        if matched:
            for root in matched_roots:
                by_repo[str(root)]["findings"].append(dict(_redact(finding)))

    for bucket in by_repo.values():
        if not bucket["allowed_paths"]:
            errors.append(f"no allowed files for repository {bucket['source']}")
            continue
        if len(bucket["allowed_paths"]) > MAX_PATHS_PER_REPOSITORY:
            errors.append(f"too many repair paths for repository {bucket['source']}")
        tracked = set(_tracked_paths(Path(bucket["source"])))
        missing = [path for path in bucket["allowed_paths"] if path not in tracked]
        # A new source file can be intentionally added only when the finding
        # names it and the parent checkout is clean; allow it, but reject a
        # path hidden by a directory traversal or symlink.
        for path in missing:
            candidate = Path(bucket["source"]) / path
            if candidate.exists() and candidate.is_symlink():
                errors.append(f"symlink repair path is forbidden: {candidate}")
    if errors:
        return [], sorted(set(errors))

    plans = []
    for bucket in by_repo.values():
        root = Path(bucket["source"])
        try:
            if _git_status(root):
                return [], [f"repository has pre-existing changes; refusing to publish: {root}"]
            # Read from the clean checkout, so the files equal the base commit.
            bucket["companion_test_paths"] = _companion_tests(root, bucket["allowed_paths"])
            _validation_plan(root, bucket["allowed_paths"], bucket["companion_test_paths"])
        except WorkerPolicyError as exc:
            return [], [str(exc)]
        plans.append(bucket)
    return plans, []


def _validation_plan(
    root: Path, allowed_paths: Sequence[str], companion_test_paths: Sequence[str] = (),
) -> list[list[str]]:
    """Select trusted argv checks from project files, never from audit prose."""
    checked = [*allowed_paths, *companion_test_paths]
    commands = [["git", "diff", "--no-ext-diff", "--no-textconv", "--check", "HEAD", "--", *checked]]
    if repo_kind(root) == REPO_KIND_STEWARD_CODE:
        # The full offline gate for every touched area, run inside the
        # isolated snapshot of the dotfiles clone (fix and judge copies).
        # Keyed on the source paths: _companion_tests only admits a companion
        # whose area adds no verifier, so the set equals the one the pre-PR
        # gate derives from whichever of those paths the patch changes.
        return commands + steward_code_validation_commands(allowed_paths)
    suffixes = {Path(path).suffix.lower() for path in allowed_paths}
    if ".py" in suffixes:
        commands.append(["python3", "-m", "compileall", "-q", *[p for p in checked if p.endswith(".py")]])
        if any(root.glob("test*.py")) or (root / "tests").is_dir():
            commands.append(["python3", "-m", "unittest", "discover"])
    if ".go" in suffixes and (root / "go.mod").exists():
        commands.append(["go", "test", "./..."])
    if suffixes & {".js", ".jsx", ".ts", ".tsx"} and (root / "package.json").exists():
        commands.append(["bun", "run", "test"] if any((root / name).exists() for name in ("bun.lock", "bun.lockb")) else ["npm", "test"])
    if ".rs" in suffixes and (root / "Cargo.toml").exists():
        commands.append(["cargo", "test"])
    if ".rb" in suffixes:
        commands.append(["ruby", "-e", "ARGV.each { |path| RubyVM::InstructionSequence.compile_file(path) }", *[p for p in allowed_paths if p.endswith(".rb")]])
        if (root / "Gemfile").exists() and (root / "spec").is_dir():
            commands.append(["bundle", "exec", "rspec"])
    if len(commands) == 1:
        raise WorkerPolicyError("no executable validation family for the selected paths")
    return commands


# --------------------- companion regression-test files ---------------------


def _module_names(source: str, test_path: str) -> tuple[set[str], set[str]]:
    """Dotted (module, package) names by which ``test_path`` may import ``source``.

    Import roots are the repository root, the test file's directory, and its
    parent: e.g. scripts/test_digest_pipeline.py imports
    scripts/daily_news/contracts.py as ``daily_news.contracts``.
    """
    parts = Path(source).with_suffix("").parts
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    test_dir = Path(test_path).parent.parts
    modules: set[str] = set()
    packages: set[str] = set()
    for prefix in {(), test_dir, test_dir[:-1]}:
        if len(prefix) >= len(parts) or parts[:len(prefix)] != prefix:
            continue
        rest = parts[len(prefix):]
        modules.add(".".join(rest))
        if len(rest) > 1:
            packages.add(".".join(rest[:-1]))
    return modules, packages


def _imported_names(tree: ast.AST) -> set[str]:
    """Absolute dotted names imported anywhere in ``tree`` (``from a import b`` -> a, a.b)."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module)
            names.update(f"{node.module}.{alias.name}" for alias in node.names if alias.name != "*")
    return names


def _companion_tests(root: Path, allowed_paths: Sequence[str]) -> list[str]:
    """Existing test files that import a repaired Python module, best first.

    A companion must be tracked, named test_*.py/*_test.py, repairable under
    the same path policy as a target (so protected steward tests never
    qualify), and, in a steward-code clone, must not add a verifier.  Rank:
    imports the module itself before only its package; then same directory
    or a top-level tests/ directory; then path.
    """
    sources = [path for path in allowed_paths if path.endswith(".py")]
    room = min(MAX_COMPANION_TESTS, MAX_PATHS_PER_REPOSITORY - len(allowed_paths))
    if not sources or room <= 0:
        return []
    kind = repo_kind(root)
    verifiers = steward_code_verifiers(allowed_paths) if kind == REPO_KIND_STEWARD_CODE else None
    ranked: list[tuple[tuple[int, int], str]] = []
    for path in sorted(_tracked_paths(root)):
        if path in allowed_paths or not _TEST_FILE_RE.fullmatch(Path(path).name):
            continue
        try:
            _safe_relpath(path, kind=kind)
        except WorkerPolicyError:
            continue
        if verifiers is not None and steward_code_verifiers([*allowed_paths, path]) != verifiers:
            continue
        candidate = root / path
        try:
            if candidate.is_symlink() or not candidate.is_file() or candidate.stat().st_size > MAX_DIFF_BYTES:
                continue
            imported = _imported_names(ast.parse(candidate.read_text(encoding="utf-8"), filename=path))
        except (OSError, SyntaxError, ValueError):
            continue
        keys = []
        for source in sources:
            modules, packages = _module_names(source, path)
            if any(name == m or name.startswith(m + ".") for name in imported for m in modules):
                reference = 0
            elif any(name == p or name.startswith(p + ".") for name in imported for p in packages):
                reference = 1
            else:
                continue
            near = Path(path).parent == Path(source).parent or Path(path).parts[0] in {"tests", "test"}
            keys.append((reference, 0 if near else 1))
        if keys:
            ranked.append((min(keys), path))
    return [path for _, path in sorted(ranked)[:room]]


def _companion_paths(values: Any, allowed: Sequence[str], kind: str) -> list[str]:
    """Validate a request's companion test paths; sorted."""
    if values is None:
        return []
    if not isinstance(values, (list, tuple)):
        raise WorkerPolicyError("companion test paths are not a list")
    paths = sorted(_safe_relpath(path, kind=kind) for path in values)
    if (
        len(paths) > MAX_COMPANION_TESTS or len(set(paths)) != len(paths)
        or set(paths) & set(allowed)
        or not all(_TEST_FILE_RE.fullmatch(Path(path).name) for path in paths)
    ):
        raise WorkerPolicyError("invalid companion test paths")
    return paths


# Additive-only policy for a changed companion.  Definition-time code in an
# added def/class (decorators, defaults, annotations, class bodies) runs at
# import, before any existing test; added bodies run between existing tests.
# Neither may alter what existing tests see, so both are kept inert.
_TEST_DECORATOR_ROOTS = frozenset({"unittest", "mock", "patch", "pytest"})
_STATE_CALLS = frozenset({"setattr", "delattr", "exec", "eval", "globals", "__import__"})
_DEFS = (ast.FunctionDef, ast.AsyncFunctionDef)


def _dotted(node: ast.AST) -> list[str] | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    return [node.id, *reversed(parts)] if isinstance(node, ast.Name) else None


def _is_literal(node: ast.AST) -> bool:
    try:
        ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return False
    return True


def _inert_decorator(node: ast.AST) -> bool:
    call = node if isinstance(node, ast.Call) else None
    name = _dotted(call.func if call else node)
    if not name or name[0] not in _TEST_DECORATOR_ROOTS:
        return False
    return call is None or all(
        isinstance(arg, ast.Lambda) or _dotted(arg) is not None or _is_literal(arg)
        for arg in [*call.args, *(keyword.value for keyword in call.keywords)]
    )


def _signature_reason(node: ast.AST) -> str | None:
    """Why a def's definition-time expressions could run code; None if inert."""
    if not all(_inert_decorator(item) for item in node.decorator_list):
        return "decorators may only be unittest/mock/pytest helpers with literal, name or lambda arguments"
    if not isinstance(node, _DEFS):
        return None
    args = node.args
    if not all(_is_literal(item) or _dotted(item) is not None
               for item in [*args.defaults, *(d for d in args.kw_defaults if d is not None)]):
        return "default arguments must be literals or names"
    annotations = [
        item.annotation for item in (*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg)
        if item is not None and item.annotation is not None
    ] + ([node.returns] if node.returns is not None else [])
    if not all(isinstance(item, ast.Constant) or _dotted(item) is not None for item in annotations):
        return "annotations must be names or strings"
    return None


def _added_definition_reason(node: ast.AST, module_names: set[str]) -> str | None:
    """Why an added def/class could change existing behaviour; None if it cannot."""
    reason = _signature_reason(node)
    if reason:
        return reason
    if isinstance(node, ast.ClassDef):
        if not all(_dotted(item) is not None for item in [*node.bases, *(k.value for k in node.keywords)]):
            return "class bases must be names"
        for item in node.body:
            if isinstance(item, _DEFS):
                reason = _signature_reason(item)
                if reason:
                    return f"method {item.name}: {reason}"
            elif not (
                isinstance(item, ast.Pass)
                or (isinstance(item, ast.Expr) and isinstance(item.value, ast.Constant))
                or (isinstance(item, ast.Assign) and _is_literal(item.value)
                    and all(isinstance(target, ast.Name) for target in item.targets))
            ):
                return "class body may hold only methods, literal attributes and a docstring"
    for sub in ast.walk(node):
        if isinstance(sub, (ast.Global, ast.Nonlocal)):
            return "declares global/nonlocal"
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) and sub.func.id in _STATE_CALLS:
            return f"calls {sub.func.id}()"
        if isinstance(sub, (ast.Attribute, ast.Subscript)) and isinstance(sub.ctx, (ast.Store, ast.Del)):
            base = sub
            while isinstance(base, (ast.Attribute, ast.Subscript)):
                base = base.value
            if isinstance(base, ast.Name) and base.id in module_names:
                return f"assigns into module-level object {base.id!r} (use unittest.mock.patch)"
    return None


def _bound_names(stmt: ast.AST) -> set[str]:
    """Module-level names a top-level statement binds."""
    if isinstance(stmt, (*_DEFS, ast.ClassDef)):
        return {stmt.name}
    if isinstance(stmt, (ast.Import, ast.ImportFrom)):
        return {alias.asname or alias.name.split(".")[0] for alias in stmt.names if alias.name != "*"}
    names: set[str] = set()
    stack: list[ast.AST] = [stmt]
    while stack:
        node = stack.pop()
        if isinstance(node, (*_DEFS, ast.ClassDef, ast.Import, ast.ImportFrom)):
            names |= _bound_names(node)
            continue
        if isinstance(node, (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            names.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            names.add(node.rest)
        stack.extend(ast.iter_child_nodes(node))
    return names


def _check_additive_test_change(path: str, before: str, after: str) -> None:
    """Accept a companion test change only if it purely adds tests.

    Every base top-level statement must survive in order and AST-identical,
    except that an existing def/class may gain new nested functions (classes:
    new ``test_*`` methods) and its list/tuple literals may gain bare names of
    newly added top-level test functions (runner registration).  New
    top-level statements may only be fresh defs/classes, imports, or literal
    assignments to fresh names; nothing may rebind a pre-existing name; and at
    least one new ``test_*`` function or method must be added.
    """
    def reject(reason: str) -> None:
        raise WorkerPolicyError(f"companion test {path} is not an additive-only change: {reason}")

    try:
        base = ast.parse(before, filename=path)
        new = ast.parse(after, filename=path)
    except (SyntaxError, ValueError) as exc:
        reject(f"base or new file does not parse ({exc.__class__.__name__})")
    reserved = set(dir(builtins))
    for stmt in base.body:
        reserved |= _bound_names(stmt)
    # Any identifier the base uses (it may resolve to a module global).
    reserved |= {node.id for node in ast.walk(base) if isinstance(node, ast.Name)}
    module_names: set[str] = set()
    for stmt in new.body:
        module_names |= _bound_names(stmt)
    fresh_tests = {
        stmt.name for stmt in new.body
        if isinstance(stmt, _DEFS) and stmt.name.startswith("test_") and stmt.name not in reserved
    }
    added_tests = 0

    def counterpart(old: ast.AST, cand: ast.AST) -> bool:
        """True if ``cand`` is ``old`` plus permitted additions; raise if it is a modified ``old``."""
        nonlocal added_tests
        if ast.dump(old) == ast.dump(cand):
            return True
        if not (isinstance(old, (*_DEFS, ast.ClassDef)) and type(old) is type(cand) and old.name == cand.name):
            return False
        known = {
            node.name if isinstance(node, (*_DEFS, ast.ClassDef))
            else node.id if isinstance(node, ast.Name) else node.arg
            for node in ast.walk(old) if isinstance(node, (*_DEFS, ast.ClassDef, ast.Name, ast.arg))
        }
        stripped = copy.deepcopy(cand)
        kept = []
        for item in stripped.body:
            if isinstance(item, _DEFS) and item.name not in known:
                if isinstance(old, ast.ClassDef) and not item.name.startswith("test_"):
                    reject(f"new method {old.name}.{item.name} is not a test_* method")
                reason = _added_definition_reason(item, module_names)
                if reason:
                    reject(f"{old.name}.{item.name}: {reason}")
                if isinstance(old, ast.ClassDef):
                    added_tests += 1
                continue
            kept.append(item)
        stripped.body = kept
        for node in ast.walk(stripped):
            if isinstance(node, (ast.List, ast.Tuple)):
                node.elts = [
                    elt for elt in node.elts
                    if not (isinstance(elt, ast.Name) and isinstance(elt.ctx, ast.Load) and elt.id in fresh_tests)
                ]
        if ast.dump(old) != ast.dump(stripped):
            reject(f"existing {old.name} (line {old.lineno}) was modified beyond adding tests")
        return True

    additions: list[ast.stmt] = []
    position = 0
    for old in base.body:
        while position < len(new.body):
            cand = new.body[position]
            position += 1
            if counterpart(old, cand):
                break
            additions.append(cand)
        else:
            reject(f"existing top-level {type(old).__name__} at line {old.lineno} was modified, moved or removed")
    additions.extend(new.body[position:])

    bound_by_additions: set[str] = set()
    for stmt in additions:
        where = f"new top-level {type(stmt).__name__} at line {stmt.lineno}"
        if isinstance(stmt, (*_DEFS, ast.ClassDef)):
            reason = _added_definition_reason(stmt, module_names)
            if reason:
                reject(f"{stmt.name}: {reason}")
            if isinstance(stmt, ast.ClassDef):
                added_tests += sum(isinstance(item, _DEFS) and item.name.startswith("test_") for item in stmt.body)
            elif stmt.name.startswith("test_"):
                added_tests += 1
        elif isinstance(stmt, (ast.Import, ast.ImportFrom)):
            if any(alias.name == "*" for alias in stmt.names):
                reject(f"{where} is a star import")
        elif isinstance(stmt, ast.Assign):
            if not all(isinstance(target, ast.Name) for target in stmt.targets) or not _is_literal(stmt.value):
                reject(f"{where} must assign a literal to plain names")
        else:
            reject(f"{where} is not a def, class, import or literal assignment")
        names = _bound_names(stmt)
        clash = names & (reserved | bound_by_additions)
        if clash:
            reject(f"{where} rebinds existing name(s) {sorted(clash)}")
        bound_by_additions |= names
    if not added_tests:
        reject("no new test_* function or method was added")


def _safe_request_findings(findings: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        row = {
            key: _redact(finding.get(key))
            for key in (
                "id",
                "claim",
                "evidence",
                "fix",
                "finding",
                "path",
                "file",
                "repo",
                "repository",
                "repo_path",
                "paths",
                "files",
                "affected_paths",
                "target_paths",
                "prior_judge_note",
                "prior_fix_action",
                "prior_fix_status",
            )
            if finding.get(key) is not None
        }
        out.append(row)
    return out[:MAX_FINDINGS]


def _policy_proposals(
    findings: Sequence[Mapping[str, Any]],
    reason: str,
) -> list[dict[str, Any]]:
    """Turn out-of-scope findings into reviewable, non-mutating proposals."""
    rows: list[dict[str, Any]] = []
    for finding in findings:
        identity = str(
            finding.get("id")
            or finding.get("finding")
            or finding.get("claim")
            or "unidentified finding"
        )[:240]
        rows.append(
            {
                "finding": identity,
                "id": identity,
                "status": "deferred",
                "proposal": True,
                "action": (
                    "Reviewable proposal only; no production or source mutation was "
                    f"permitted by the worker policy ({reason[:240]})."
                ),
                "runtime_effect": "not_deployed",
            }
        )
    return rows


def run_fix(
    section_name: str,
    findings: Sequence[Mapping[str, Any]],
    *,
    iteration: int = 1,
    timeout: int = MAX_REPAIR_SECONDS,
) -> dict[str, Any]:
    """Run the P7b fixer and judge on disposable snapshots of the target repos.

    Stable entry point used by ``fixes.py``.  The result is an untrusted
    proposal until ``publish_validated_result`` accepts its exact diff.
    """
    findings = [dict(item) for item in findings if isinstance(item, Mapping)]
    plans, errors = _target_plans(findings)
    if errors:
        reason = "; ".join(errors[:8])
        return {
            "protocol_version": PROTOCOL_VERSION,
            "status": "policy-rejected",
            "error": reason,
            "fix_packet": {
                "fixes_applied": _policy_proposals(findings, reason),
                "summary": "No permitted app source was identified; proposal deferred for review.",
            },
            "judge_packet": {"verdict": "fail", "reviewed": [], "summary": "worker policy rejected request"},
            "repositories": [],
        }
    section = str(section_name)[:120]
    iteration = max(1, int(iteration))
    timeout = min(MAX_REPAIR_SECONDS, max(60, int(timeout)))
    repositories = [
        {
            "source": plan["source"],
            "base_sha": plan["base_sha"],
            "allowed_paths": sorted(plan["allowed_paths"]),
            "companion_test_paths": sorted(plan.get("companion_test_paths") or []),
            "validation_commands": _validation_plan(
                Path(plan["source"]), plan["allowed_paths"], plan.get("companion_test_paths") or [],
            ),
            "findings": _safe_request_findings(plan.get("findings", [])),
        }
        for plan in plans
    ]
    try:
        with tempfile.TemporaryDirectory(prefix="steward-p7b-") as temporary:
            run_root = Path(temporary)
            home = run_root / "home"
            home.mkdir(mode=0o700)
            outputs = []
            for index, repository in enumerate(repositories):
                workspace = run_root / f"repo-{index}"
                _stage_snapshot(Path(repository["source"]), repository["base_sha"], workspace)
                outputs.append(_worker_repository(
                    section, iteration, {**repository, "workspace": str(workspace)}, home, timeout,
                ))
    except (OSError, subprocess.TimeoutExpired, ValueError, WorkerExecutionError) as exc:
        return {
            "protocol_version": PROTOCOL_VERSION,
            "status": "worker-failed",
            "error": str(exc)[:1000],
            "fix_packet": {"fixes_applied": [], "summary": "Repair worker failed."},
            "judge_packet": {"verdict": "fail", "reviewed": [], "summary": str(exc)[:400]},
            "repositories": [],
        }
    verdicts = [str(output["judge_packet"].get("verdict") or "") for output in outputs]
    # Any partial/fail keeps the iteration in scope and blocks publication.
    all_pass = all(verdict == "pass" for verdict in verdicts)
    all_fixes: list[dict[str, Any]] = []
    all_reviews: list[dict[str, Any]] = []
    for output in outputs:
        all_fixes.extend(output["fix_packet"].get("fixes_applied") or [])
        all_reviews.extend(output["judge_packet"].get("reviewed") or [])
    return {
        "protocol_version": PROTOCOL_VERSION,
        "status": "ok",
        "section": section,
        "iteration": iteration,
        "fix_packet": {
            "fixes_applied": all_fixes[:MAX_FINDINGS],
            "summary": " ".join(
                str(output["fix_packet"].get("summary") or "").strip()
                for output in outputs
                if output["fix_packet"].get("summary")
            )[:1000],
        },
        "judge_packet": {
            "verdict": "pass" if all_pass else ("partial" if any(v == "partial" for v in verdicts) else "fail"),
            "reviewed": all_reviews[:MAX_FINDINGS],
            "summary": " ".join(
                str(output["judge_packet"].get("summary") or "").strip()
                for output in outputs
                if output["judge_packet"].get("summary")
            )[:1000],
        },
        "repositories": outputs,
        "_trusted_repositories": [
            {
                key: repository[key]
                for key in ("source", "base_sha", "allowed_paths", "companion_test_paths", "validation_commands")
            }
            for repository in repositories
        ],
    }


def _stage_snapshot(source: Path, base: str, workspace: Path) -> None:
    """Extract the permitted files of the verified base commit into ``workspace``.

    ``git archive`` reads the immutable commit, never HEAD, the index, or the
    checkout, so the agent edits a copy and Carter's repository is untouched.
    """
    head = _run(_git_args(source, "rev-parse", "--verify", "HEAD^{commit}"), timeout=20)
    if head.returncode != 0 or head.stdout.strip() != base:
        raise WorkerPolicyError(f"source base changed before staging: {source}")
    files = _tracked_paths(source)
    if not files:
        raise WorkerPolicyError(f"source snapshot has no permitted files: {source}")
    workspace.mkdir(mode=0o700)
    archive = subprocess.Popen(
        _git_args(source, "archive", "--format=tar", base, "--", *files),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_minimal_env(),
    )
    try:
        tar = subprocess.run(
            ["/bin/tar", "-xf", "-", "-C", str(workspace), "--no-same-owner"],
            stdin=archive.stdout,
            capture_output=True,
            timeout=120,
            check=False,
        )
    finally:
        if archive.stdout is not None:
            archive.stdout.close()
    if archive.wait(timeout=30) != 0 or tar.returncode != 0:
        detail = (tar.stderr or b"").decode(errors="replace")[:500]
        raise WorkerExecutionError(f"source archive failed for {source}: {detail}")


def _validate_result_paths(
    repository: Mapping[str, Any],
    trusted: Mapping[str, Mapping[str, Any]],
) -> tuple[Path, list[str], list[str], list[str]]:
    """Returns (root, changed, accepted paths, companion test paths)."""
    source_text = str(repository.get("source") or "")
    expected = trusted.get(source_text)
    if not expected:
        raise WorkerPolicyError("worker result source is not in the trusted request")
    if str(expected.get("base_sha") or "") != str(repository.get("base_sha") or ""):
        raise WorkerPolicyError("worker result base SHA differs from the trusted request")
    source = Path(source_text)
    root = _repo_root(source)
    if root != source.resolve() or str(root) != source_text:
        raise WorkerPolicyError(f"result repository root changed: {source}")
    kind = repo_kind(root)
    allowed = [_safe_relpath(path, kind=kind) for path in repository.get("allowed_paths") or []]
    expected_allowed = sorted(str(path) for path in expected.get("allowed_paths") or [])
    if sorted(allowed) != expected_allowed:
        raise WorkerPolicyError("worker result allowed paths differ from the trusted request")
    companions = _companion_paths(repository.get("companion_test_paths"), allowed, kind)
    if companions != sorted(str(path) for path in expected.get("companion_test_paths") or []):
        raise WorkerPolicyError("worker result companion test paths differ from the trusted request")
    accepted = sorted({*allowed, *companions})
    changed = [_safe_relpath(path, kind=kind) for path in repository.get("changed_paths") or []]
    if len(set(changed)) != len(changed):
        raise WorkerPolicyError("worker result contains duplicate changed paths")
    if not set(changed).issubset(accepted):
        extra = sorted(set(changed) - set(accepted))
        raise WorkerPolicyError(f"worker changed disallowed paths: {extra}")
    return root, changed, accepted, companions


def _commit_env() -> dict[str, str]:
    env = _minimal_env()
    env["GIT_CONFIG_GLOBAL"] = "/dev/null"
    env["GIT_CONFIG_SYSTEM"] = "/dev/null"
    env["GIT_DIFF_OPTS"] = ""
    return env


_PUBLISH_LOCK = threading.RLock()
_PUBLISH_LOCK_PATH = Path("/tmp/steward-worker-publish.lock")



def _actual_diff_paths(root: Path, diff: str) -> list[str]:
    """Read actual patch paths from Git before touching the parent checkout."""
    summary = _run(
        _git_args(root, "apply", "--numstat", "--summary"),
        cwd=root,
        env=_commit_env(),
        timeout=60,
        input_text=diff,
    )
    if summary.returncode != 0:
        raise WorkerPolicyError(f"could not parse worker diff: {(summary.stderr or summary.stdout)[:400]}")
    paths: set[str] = set()
    for line in summary.stdout.splitlines():
        fields = line.split("\t", 2)
        if len(fields) != 3:
            continue
        if fields[0] == "-" or fields[1] == "-":
            raise WorkerPolicyError("binary worker diff is not permitted")
        path = fields[2]
        if " => " in path:
            raise WorkerPolicyError("worker rename/copy diffs are not permitted")
        paths.add(_safe_relpath(path, kind=repo_kind(root)))
    for line in diff.splitlines():
        if line.startswith(("rename from ", "rename to ", "copy from ", "copy to ", "similarity index ")):
            raise WorkerPolicyError("worker rename/copy metadata is not permitted")
        marker, _, mode = line.partition(" mode ")
        if marker in {"new file", "deleted file", "old", "new"}:
            if mode not in {"100644", "100755"}:
                raise WorkerPolicyError(f"worker patch has forbidden file mode: {mode}")
    if not paths:
        raise WorkerPolicyError("worker diff has no inspectable paths")
    return sorted(paths)


def _check_companion_diff(root: Path, base: str, diff: str, paths: Sequence[str]) -> None:
    """Apply ``diff`` to ``base`` in a private index and check each changed companion."""
    if not paths:
        return
    with tempfile.TemporaryDirectory(prefix="steward-companion-") as temporary:
        env = _commit_env()
        env["GIT_INDEX_FILE"] = str(Path(temporary) / "index")

        def git(*args: str, input_text: str | None = None) -> str:
            cp = _run(_git_args(root, *args), env=env, timeout=90, input_text=input_text)
            if cp.returncode != 0:
                raise WorkerPolicyError(f"companion test Git operation failed: {(cp.stderr or cp.stdout)[:500]}")
            return cp.stdout

        git("read-tree", base)
        git("apply", "--cached", input_text=diff)
        for path in paths:
            _check_additive_test_change(path, git("cat-file", "blob", f"{base}:{path}"), git("cat-file", "blob", f":{path}"))


def _review_commit(root: Path, base: str, diff: str, section: str, *, dry_run: bool) -> dict[str, Any]:
    """Build from the bound commit in a private index; never touch user state."""
    with tempfile.TemporaryDirectory(prefix="steward-review-") as temporary:
        env = _commit_env()
        env["GIT_INDEX_FILE"] = str(Path(temporary) / "index")

        def git(*args: str, input_text: str | None = None) -> str:
            cp = _run(_git_args(root, *args), env=env, timeout=90, input_text=input_text)
            if cp.returncode != 0:
                raise WorkerPolicyError(f"review Git operation failed: {(cp.stderr or cp.stdout)[:500]}")
            return cp.stdout.strip()

        git("read-tree", base)
        git("apply", "--cached", "--whitespace=error", input_text=diff)
        git("diff", "--cached", "--no-ext-diff", "--no-textconv", "--check", base)
        tree = git("write-tree")
        if not re.fullmatch(r"[0-9a-f]{40}", tree):
            raise WorkerPolicyError("review tree is not a valid object")
        if dry_run:
            return {"status": "dry-run", "tree": tree}
        # Content-addressed refs make repeated identical nightly proposals
        # idempotent. Only this private namespace is ever advanced.
        ref = f"refs/steward-review/{base}-{tree}"
        existing = _run(_git_args(root, "rev-parse", "--verify", ref), env=env, timeout=20)
        if existing.returncode == 0:
            commit = existing.stdout.strip()
            if git("rev-parse", f"{commit}^{{tree}}") != tree or git("rev-list", "--parents", "-n", "1", commit) != f"{commit} {base}":
                raise WorkerPolicyError("existing review reference has different provenance")
        else:
            commit = git(
                "-c", "user.name=Homelab Steward", "-c", "user.email=steward@localhost",
                "commit-tree", tree, "-p", base, "--no-gpg-sign",
                "-m", f"chore: steward review {str(section).strip()[:80]}",
            )
            if not re.fullmatch(r"[0-9a-f]{40}", commit):
                raise WorkerPolicyError("review commit is not a valid object")
            try:
                git("update-ref", ref, commit, "0" * 40)
            except (WorkerPolicyError, subprocess.TimeoutExpired):
                # A lost acknowledgement must not obscure an already-created
                # reference. No checkout/index rollback is ever necessary.
                if git("rev-parse", "--verify", ref) != commit:
                    raise
        return {
            "status": "published-review", "commit": commit, "ref": ref,
            "publication_policy": "local-review-ref",
        }


def _publish_validated_result_unlocked(
    result: Mapping[str, Any],
    section_name: str,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Store judge-approved review commits without executing repository code."""
    commits: list[dict[str, Any]] = []
    try:
        if result.get("protocol_version") != PROTOCOL_VERSION or result.get("status") != "ok":
            raise WorkerPolicyError("worker protocol or execution did not succeed")
        judge = result.get("judge_packet")
        if not isinstance(judge, Mapping) or judge.get("verdict") != "pass":
            raise WorkerPolicyError("existing judge did not return pass")
        trusted_raw = result.get("_trusted_repositories")
        repositories = result.get("repositories")
        if not isinstance(trusted_raw, list) or not trusted_raw or not isinstance(repositories, list):
            raise WorkerPolicyError("worker result lacks trusted repository bindings")
        trusted: dict[str, dict[str, Any]] = {}
        for raw in trusted_raw:
            if not isinstance(raw, Mapping):
                raise WorkerPolicyError("trusted repository binding is not an object")
            source = str(raw.get("source") or "")
            base = str(raw.get("base_sha") or "")
            kind = repo_kind(source)
            allowed = sorted(_safe_relpath(path, kind=kind) for path in raw.get("allowed_paths") or [])
            if not source.startswith("/") or not re.fullmatch(r"[0-9a-f]{40}", base) or not allowed or source in trusted:
                raise WorkerPolicyError("invalid or duplicate trusted repository binding")
            trusted[source] = {
                "base_sha": base, "allowed_paths": allowed,
                "companion_test_paths": _companion_paths(raw.get("companion_test_paths"), allowed, kind),
                "validation_commands": raw.get("validation_commands"),
            }
        sources = [item.get("source") for item in repositories if isinstance(item, Mapping)]
        if len(sources) != len(repositories) or len(set(sources)) != len(sources) or set(sources) != set(trusted):
            raise WorkerPolicyError("worker repositories differ from the trusted request")
        candidates = []
        for item in repositories:
            root, changed, accepted, companions = _validate_result_paths(item, trusted)
            base = str(item["base_sha"])
            if _base_sha(root) != base:
                raise WorkerPolicyError(f"repository advanced while worker ran: {root}")
            diff = item.get("diff")
            if not isinstance(diff, str) or len(diff.encode()) > MAX_DIFF_BYTES:
                raise WorkerPolicyError("worker diff is not bounded text")
            if not diff.strip():
                if changed:
                    raise WorkerPolicyError("worker supplied changed paths without a diff")
                continue
            if "\x00" in diff or "GIT binary patch" in diff or _sha256_text(diff) != item.get("diff_sha256"):
                raise WorkerPolicyError("binary or hash-mismatched worker diff")
            actual = _actual_diff_paths(root, diff)
            if set(actual) != set(changed) or not set(actual).issubset(accepted):
                raise WorkerPolicyError("actual diff paths differ from the trusted allowed paths")
            # Existing tests may only gain tests; never be weakened.
            _check_companion_diff(root, base, diff, sorted(set(actual) & set(companions)))
            if not isinstance(item.get("validation"), list) or not item["validation"] or any(
                not isinstance(record, Mapping) or type(record.get("returncode")) is not int or record["returncode"] != 0
                for record in item["validation"]
            ):
                raise WorkerPolicyError("worker validation is missing or failed")
            if [record.get("argv") for record in item["validation"]] != trusted[str(root)]["validation_commands"]:
                raise WorkerPolicyError("worker validation differs from the trusted plan")
            candidates.append((root, base, diff, changed))
        fix_packet = result.get("fix_packet", {})
        if not isinstance(fix_packet, Mapping) or not isinstance(fix_packet.get("fixes_applied", []), list):
            raise WorkerPolicyError("worker fix packet is malformed")
        if not candidates and any(
            isinstance(row, Mapping) and row.get("status") == "fixed"
            for row in fix_packet.get("fixes_applied", [])
        ):
            raise WorkerPolicyError("worker claimed a repair without a source diff")
        for root, base, diff, changed in candidates:
            commit = _review_commit(root, base, diff, section_name, dry_run=dry_run)
            commits.append({"repository": str(root), "changed_paths": changed, **commit})
        return {"status": "dry-run" if dry_run else "published", "commits": commits}
    except (OSError, TypeError, ValueError, subprocess.TimeoutExpired, WorkerPolicyError) as exc:
        return {"status": "publish-rejected", "error": str(exc)[:1000], "commits": commits}


def publish_validated_result(
    result: Mapping[str, Any],
    section_name: str,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Serialize trusted publication across concurrent P7b sections."""
    with _PUBLISH_LOCK:
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        lock_fd = os.open(_PUBLISH_LOCK_PATH, flags, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            return _publish_validated_result_unlocked(
                result,
                section_name,
                dry_run=dry_run,
            )
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)


# ----------------------------- worker side -----------------------------


def _extract_json(text: str) -> Any:
    if not isinstance(text, str):
        raise WorkerPolicyError("model output is not text")
    fences = re.findall(r"```(?:json)?\s*\n?(.*?)```", text, flags=re.DOTALL | re.IGNORECASE)
    for candidate in reversed(fences):
        try:
            return json.loads(candidate.strip())
        except json.JSONDecodeError:
            pass
    stripped = text.strip()
    for candidate in (stripped,):
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass
    for start, char in enumerate(text):
        if char not in "[{":
            continue
        closer = "]" if char == "[" else "}"
        depth = 0
        in_string = False
        escaped = False
        for end in range(start, len(text)):
            ch = text[end]
            if in_string:
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_string = False
                continue
            if ch == '"':
                in_string = True
            elif ch == char:
                depth += 1
            elif ch == closer:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start : end + 1])
                    except json.JSONDecodeError:
                        break
    raise WorkerPolicyError("model output did not contain a JSON packet")


def _assistant_text_from_message(msg: Mapping[str, Any]) -> str:
    content = msg.get("content")
    if not isinstance(content, list):
        return ""
    return "".join(
        str(part.get("text") or "")
        for part in content
        if isinstance(part, Mapping) and part.get("type") == "text"
    )


def _ndjson_text(stdout: str) -> str:
    deltas: list[str] = []
    ends: list[str] = []
    for line in (stdout or "").splitlines():
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, Mapping):
            continue
        typ = obj.get("type")
        if typ == "message_update":
            event = obj.get("assistantMessageEvent")
            if isinstance(event, Mapping) and event.get("type") == "text_delta":
                deltas.append(str(event.get("delta") or ""))
        elif typ in ("message_end", "turn_end"):
            msg = obj.get("message")
            if isinstance(msg, Mapping) and msg.get("role") == "assistant":
                text = _assistant_text_from_message(msg)
                if text:
                    ends.append(text)
        elif typ == "agent_end":
            for msg in obj.get("messages") or []:
                if isinstance(msg, Mapping) and msg.get("role") == "assistant":
                    text = _assistant_text_from_message(msg)
                    if text:
                        ends.append(text)
    return "".join(deltas) if deltas else "\n".join(ends)


def _omp_call(prompt: str, cwd: Path, timeout: int) -> str:
    timeout = max(60, min(MAX_REPAIR_SECONDS, timeout))
    cp = _run(
        [
            "/usr/bin/setpriv", "--no-new-privs",
            str(OMP_BIN),
            "-p",
            "--model", STEWARD_MODEL,
            "--no-extensions", "--no-skills", "--no-rules",
            "--no-lsp", "--no-pty", "--no-title",
            "--tools", "read,bash,edit,write,grep,glob,todo",
            "--max-time", str(timeout),
            "--mode",
            "json",
            "--cwd",
            str(cwd),
            "--session-dir",
            str(SESSION_DIR),
            "--config",
            str(HEADLESS_CONFIG),
            "--add-dir",
            str(cwd),
            prompt,
        ],
        cwd=cwd,
        timeout=timeout,
        # Carter's environment plus the deterministic Git/Python settings, so
        # the agent's own test runs leave no bytecode in the snapshot.
        env={**os.environ, **_minimal_env(home=str(HOME))},
        input_text="",
    )
    text = _ndjson_text(cp.stdout or "")
    if cp.returncode != 0 and not text.strip():
        raise WorkerExecutionError(f"worker OMP failed (rc={cp.returncode}): {(cp.stderr or '')[:500]}")
    if not text.strip():
        raise WorkerExecutionError("worker OMP returned no assistant text")
    return text


def _initialise_snapshot(root: Path) -> None:
    env = _minimal_env()
    for argv in (
        ["/usr/bin/git", "init", "--initial-branch=main"],
        ["/usr/bin/git", "-c", "user.name=Steward Snapshot", "-c", "user.email=snapshot@localhost", "-c", "core.hooksPath=/dev/null", "add", "--all"],
        ["/usr/bin/git", "-c", "user.name=Steward Snapshot", "-c", "user.email=snapshot@localhost", "-c", "core.hooksPath=/dev/null", "commit", "--no-verify", "-m", "steward source snapshot"],
    ):
        cp = _run(argv, cwd=root, env=env, timeout=90)
        if cp.returncode != 0:
            raise WorkerExecutionError(f"snapshot git operation failed: {(cp.stderr or cp.stdout)[:500]}")


def _status_paths(root: Path) -> tuple[list[str], list[str]]:
    status = _git_status(root)
    changed: list[str] = []
    untracked: list[str] = []
    for row in status.split("\0"):
        if not row:
            continue
        if row.startswith("?? "):
            untracked.append(row[3:])
        elif len(row) >= 4:
            value = row[3:]
            # Rename entries can carry a second NUL-delimited destination; a
            # rename itself is disallowed by the publisher unless both paths
            # are explicitly allowed, so represent the visible destination.
            changed.append(value)
    return changed, untracked


def _snapshot_diff(
    root: Path, allowed_paths: Sequence[str], companion_test_paths: Sequence[str] = (),
) -> tuple[str, list[str]]:
    # Companions are existing files, so they can never be created untracked.
    accepted = [*allowed_paths, *companion_test_paths]
    changed, untracked = _status_paths(root)
    for path in changed:
        if (root / path).is_symlink():
            raise WorkerPolicyError(f"worker created a symlink: {path}")
    for path in untracked:
        if path not in allowed_paths:
            raise WorkerPolicyError(f"worker created disallowed untracked file: {path}")
        candidate = root / path
        if candidate.is_symlink():
            raise WorkerPolicyError(f"worker created a symlink: {path}")
        add_intent = _run(
            ["/usr/bin/git", "add", "--intent-to-add", "--", path],
            cwd=root,
            env=_minimal_env(),
            timeout=30,
        )
        if add_intent.returncode != 0:
            raise WorkerExecutionError(f"could not register new worker path: {path}")
        changed.append(path)
    changed = sorted(set(changed))
    if not set(changed).issubset(set(accepted)):
        raise WorkerPolicyError(f"worker changed disallowed paths: {sorted(set(changed) - set(accepted))}")
    for path in sorted(set(changed) & set(companion_test_paths)):
        before = _run(
            ["/usr/bin/git", "cat-file", "blob", f"HEAD:{path}"], cwd=root, env=_minimal_env(), timeout=30,
        )
        if before.returncode != 0:
            raise WorkerExecutionError(f"could not read base companion test: {path}")
        try:
            after = (root / path).read_text(encoding="utf-8")
        except FileNotFoundError:
            raise WorkerPolicyError(f"worker deleted companion test: {path}")
        _check_additive_test_change(path, before.stdout, after)
    cp = _run(
        [
            "/usr/bin/git",
            "-c",
            "core.fsmonitor=false",
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--binary",
            "--full-index",
            "HEAD",
            "--",
            *accepted,
        ],
        cwd=root,
        env=_minimal_env(),
        timeout=60,
    )
    if cp.returncode != 0:
        raise WorkerExecutionError(f"could not collect worker diff: {(cp.stderr or cp.stdout)[:500]}")
    diff = cp.stdout
    if len(diff.encode()) > MAX_DIFF_BYTES:
        raise WorkerPolicyError("worker diff exceeds bounded size")
    check = _run(
        [
            "/usr/bin/git",
            "-c",
            "core.fsmonitor=false",
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--check",
            "HEAD",
            "--",
            *accepted,
        ],
        cwd=root,
        env=_minimal_env(),
        timeout=30,
    )
    if check.returncode != 0:
        raise WorkerPolicyError(f"worker diff check failed: {(check.stderr or check.stdout)[:400]}")
    return diff, changed


def _run_validations(root: Path, commands: Sequence[Sequence[str]], home: Path) -> list[dict[str, Any]]:
    records = []
    env = _minimal_env(home=str(home))
    env["PYTHONPYCACHEPREFIX"] = str(home / "pycache")
    env["RBENV_ROOT"] = str(HOME / ".rbenv")
    env["GOTOOLCHAIN"] = "local"
    env["GOPROXY"] = "off"
    env["CARGO_NET_OFFLINE"] = "true"
    for raw in commands:
        if not isinstance(raw, (list, tuple)) or not raw:
            raise WorkerPolicyError("validation plan contains an invalid command")
        argv = [str(item) for item in raw]
        verifier = argv[0] == "bash" and argv in [
            ["bash", f"scripts/verify-{name}.sh", "full"] for name, _ in STEWARD_CODE_VERIFIERS
        ]
        if argv[0] not in _VALIDATION_PROGRAMS and argv[0] != "git" and not verifier:
            raise WorkerPolicyError(f"validation program is not allowed: {argv[0]}")
        if any("\x00" in item or item.startswith("/") for item in argv):
            raise WorkerPolicyError("validation command contains an absolute/unsafe argument")
        started = time.monotonic()
        cp = _run(["/usr/bin/setpriv", "--no-new-privs", *argv], cwd=root, env=env, timeout=MAX_VALIDATION_SECONDS)
        records.append(
            {
                "argv": argv,
                "returncode": cp.returncode,
                "duration_seconds": round(time.monotonic() - started, 3),
                "stdout": (cp.stdout or "")[-MAX_COMMAND_OUTPUT:],
                "stderr": (cp.stderr or "")[-MAX_COMMAND_OUTPUT:],
            }
        )
        if cp.returncode != 0:
            diagnostic = (cp.stderr or cp.stdout or "no command output").strip()[-1600:]
            raise WorkerExecutionError(
                f"validation failed (exit {cp.returncode}): {' '.join(argv)}\n{diagnostic}"
            )
    return records


def _fix_prompt(
    section: str, findings: Sequence[Mapping[str, Any]], allowed: Sequence[str], iteration: int,
    companions: Sequence[str] = (),
) -> str:
    companion_text = (
        "Companion test files (existing tests that import the affected code; additions only):\n"
        f"{json.dumps(list(companions))}\n"
        "You MAY add a regression test to one of these files that fails without your fix and passes with it. "
        "Only additions are allowed: new test functions (def test_...) or new test_* methods, registering a new "
        "test function in an existing runner list (e.g. tests = [...] in main()), new imports, and new literal "
        "constants. Existing tests must not be modified: do not change, reorder, remove or rename any existing "
        "test, assertion, helper, statement or list element, and do not rebind an existing name. New tests must "
        "not mutate module-level state (no global/nonlocal, setattr/delattr, or assignment into imported modules; "
        "use unittest.mock.patch/patch.object instead) and may only use unittest/mock/pytest decorators. "
        "Any other change to these files is rejected automatically.\n"
        if companions else ""
    )
    return (
        f"You are the bounded P7b code-repair worker for audit section {section!r}.\n\n"
        f"This is retry iteration {iteration}. Work ONLY in the supplied disposable Git worktree.\n"
        f"Allowed files (exact relative paths; no other file may change"
        f"{' except the companion test files below' if companions else ''}): {json.dumps(list(allowed))}\n"
        f"{companion_text}"
        f"Findings:\n{json.dumps(list(findings), indent=2, default=str)[:24000]}\n\n"
        "Rules:\n"
        "- Repair only a concrete application-code finding whose affected path is listed above.\n"
        "- Do not inspect or access /home/carter, credentials, SSH, Cloudflare, R2, Docker, LXD, Kubernetes, sudo, or unrelated repositories.\n"
        "- Do not change deployment, infrastructure, security, backup, orchestrator, or policy files.\n"
        "- Do not commit, push, deploy, send mail, or create users/resources. The trusted parent handles publication.\n"
        "- Run the focused validation commands available in this worktree; never hide a failure.\n"
        "- Return ONLY a fenced JSON object with fixes_applied and summary.\n"
        '{"fixes_applied":[{"finding":"exact finding text or id","action":"what changed and validation run","status":"fixed|deferred|failed"}],"summary":"one sentence"}'
    )


def _judge_prompt(section: str, findings: Sequence[Mapping[str, Any]], fix_packet: Mapping[str, Any], diff: str, validations: Sequence[Mapping[str, Any]]) -> str:
    return (
        f"You are the existing skeptical P7b repair judge for audit section {section!r}.\n\n"
        "Review the proposed code repair in the disposable candidate worktree. Inspect the actual files and diff, and independently assess the validation records.\n"
        f"Findings:\n{json.dumps(list(findings), indent=2, default=str)[:18000]}\n\n"
        f"FIX PACKET:\n{json.dumps(dict(fix_packet), indent=2, default=str)[:10000]}\n\n"
        f"VALIDATION:\n{json.dumps(list(validations), indent=2, default=str)[:10000]}\n\n"
        f"DIFF:\n{diff[:30000]}\n\n"
        "Reject unrelated paths, incomplete fixes, failed/missing validation, guessed behavior, or any infrastructure/security/credential change.\n"
        "If the diff adds tests, fail the fix if any added test does not exercise the fixed behaviour, or could pass without the fix (i.e. would also pass on the unpatched base).\n"
        "Return ONLY this fenced JSON shape, using the exact finding claim text or id so the parent can match rows:\n"
        '{"verdict":"pass|partial|fail","reviewed":[{"finding":"...","ok":true,"note":"independent evidence"}],"summary":"one sentence"}'
    )


def _validate_fix_packet(packet: Any) -> dict[str, Any]:
    if not isinstance(packet, Mapping):
        raise WorkerPolicyError("fix packet is not an object")
    rows = packet.get("fixes_applied")
    if not isinstance(rows, list):
        raise WorkerPolicyError("fix packet fixes_applied is not a list")
    out = []
    for row in rows:
        if not isinstance(row, Mapping):
            raise WorkerPolicyError("fix packet row is not an object")
        status = str(row.get("status") or "").lower()
        if status not in {"fixed", "deferred", "failed"}:
            raise WorkerPolicyError("fix packet has invalid status")
        finding = str(row.get("finding") or row.get("id") or "").strip()
        action = str(row.get("action") or "").strip()
        if not finding or not action:
            raise WorkerPolicyError("fix packet row lacks finding/action")
        out.append({"finding": finding[:500], "action": action[:1200], "status": status})
    return {"fixes_applied": out[:MAX_FINDINGS], "summary": str(packet.get("summary") or "")[:1000]}

def _validate_judge_packet(packet: Any) -> dict[str, Any]:
    if not isinstance(packet, Mapping):
        raise WorkerPolicyError("judge packet is not an object")
    verdict = str(packet.get("verdict") or "").lower()
    if verdict not in {"pass", "partial", "fail"}:
        raise WorkerPolicyError("judge packet has invalid verdict")
    rows = packet.get("reviewed")
    if not isinstance(rows, list):
        raise WorkerPolicyError("judge packet reviewed is not a list")
    out = []
    for row in rows:
        if not isinstance(row, Mapping):
            raise WorkerPolicyError("judge row is not an object")
        finding = str(row.get("finding") or row.get("id") or "").strip()
        note = str(row.get("note") or "").strip()
        if not finding or not note or not isinstance(row.get("ok"), bool):
            raise WorkerPolicyError("judge row lacks finding/boolean ok/note")
        out.append({"finding": finding[:500], "ok": row["ok"], "note": note[:1200]})
    return {"verdict": verdict, "reviewed": out[:MAX_FINDINGS], "summary": str(packet.get("summary") or "")[:1000]}


def _worker_repository(
    section: str, iteration: int, repository: Mapping[str, Any], home: Path, timeout: int,
) -> dict[str, Any]:
    workspace = Path(str(repository.get("workspace") or ""))
    kind = repo_kind(str(repository.get("source") or ""))
    allowed = [_safe_relpath(path, kind=kind) for path in repository.get("allowed_paths") or []]
    if not allowed:
        raise WorkerPolicyError("worker repository has no allowed paths")
    companions = _companion_paths(repository.get("companion_test_paths"), allowed, kind)
    if not workspace.is_absolute() or not workspace.is_dir():
        raise WorkerPolicyError(f"worker workspace missing: {workspace}")
    _initialise_snapshot(workspace)
    findings = [finding for finding in repository.get("findings") or [] if isinstance(finding, Mapping)]
    validation_commands = repository.get("validation_commands") or []
    git_config = workspace / ".git" / "config"
    try:
        config_before = git_config.read_bytes()
    except OSError as exc:
        raise WorkerExecutionError(f"worker snapshot has no Git config: {exc}")
    base_before = _run(
        ["/usr/bin/git", "-C", str(workspace), "rev-parse", "HEAD"],
        env=_minimal_env(),
        timeout=20,
    ).stdout.strip()
    if not base_before:
        raise WorkerExecutionError("worker snapshot has no base commit")
    fix_text = _omp_call(_fix_prompt(section, findings, allowed, iteration, companions), workspace, timeout)
    fix_packet = _validate_fix_packet(_extract_json(fix_text))
    try:
        if git_config.read_bytes() != config_before:
            raise WorkerPolicyError("worker modified Git configuration")
    except OSError as exc:
        raise WorkerPolicyError(f"worker removed Git configuration: {exc}")
    head_after = _run(
        ["/usr/bin/git", "-C", str(workspace), "rev-parse", "HEAD"],
        env=_minimal_env(),
        timeout=20,
    ).stdout.strip()
    if head_after != base_before:
        raise WorkerPolicyError("worker created or rewrote a Git commit")
    hooks = workspace / ".git" / "hooks"
    if hooks.exists() and any(
        path.is_file() and not path.name.endswith(".sample")
        for path in hooks.iterdir()
    ):
        raise WorkerPolicyError("worker created a Git hook")
    diff, changed = _snapshot_diff(workspace, allowed, companions)
    # The judge gets a separate candidate copy so its read-only role cannot
    # alter the patch that will be handed to the parent.  The candidate itself
    # is still disposable and no changes from this second call are published.
    judge_workspace = workspace.parent / (workspace.name + "-judge")
    if judge_workspace.exists():
        shutil.rmtree(judge_workspace)
    clone = _run(["/usr/bin/git", "clone", "--no-hardlinks", str(workspace), str(judge_workspace)], env=_minimal_env(), timeout=120)
    if clone.returncode != 0:
        raise WorkerExecutionError(f"could not create judge worktree: {(clone.stderr or clone.stdout)[:500]}")
    if diff:
        applied = _run(
            _git_args(judge_workspace, "apply", "--index", "--whitespace=error"),
            env=_minimal_env(), timeout=60, input_text=diff,
        )
        if applied.returncode != 0:
            raise WorkerExecutionError(f"could not apply exact candidate for judge: {(applied.stderr or applied.stdout)[:500]}")
    try:
        validations = _run_validations(judge_workspace, validation_commands, home)
        candidate = _run(
            _git_args(judge_workspace, "diff", "--no-ext-diff", "--no-textconv", "--binary", "--full-index", "HEAD"),
            env=_minimal_env(), timeout=60,
        )
        if candidate.returncode != 0 or candidate.stdout != diff:
            raise WorkerPolicyError("validation changed the captured candidate")
        judge_text = _omp_call(
            _judge_prompt(section, findings, fix_packet, diff, validations), judge_workspace, timeout,
        )
        judge_packet = _validate_judge_packet(_extract_json(judge_text))
        if judge_packet["verdict"] == "pass":
            for finding in findings:
                names = {str(finding.get(key) or "").strip()[:500] for key in ("id", "claim")}
                names.discard("")
                matching = [row for row in judge_packet["reviewed"] if row["finding"] in names]
                if len(matching) != 1 or matching[0]["ok"] is not True:
                    raise WorkerPolicyError("judge pass lacks an affirmative review for every finding")
    finally:
        shutil.rmtree(judge_workspace, ignore_errors=True)
    return {
        "source": str(repository.get("source") or ""),
        "base_sha": str(repository.get("base_sha") or ""),
        "allowed_paths": allowed,
        "companion_test_paths": companions,
        "changed_paths": changed,
        "diff": diff,
        "diff_sha256": _sha256_text(diff),
        "validation": validations,
        "fix_packet": fix_packet,
        "judge_packet": judge_packet,
    }
