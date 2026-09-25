"""P7b bounded repair worker and trusted patch publisher.

The normal steward process is Carter's user service.  It never gives that
process's checkout or credentials to a model.  Instead :func:`run_isolated_fix`
serializes a small request for the root-owned ``steward-worker-run`` helper.
The helper creates source snapshots under ``/var/lib/steward-worker`` and
starts the unprivileged worker service.  The worker edits only those snapshots,
runs the deterministic validation plan, and asks the existing judge role to
review the resulting diff.  Only a judge-pass result can reach
:func:`publish_validated_result`, which stores an exact, path-bounded commit
under refs/steward-review without changing HEAD, the index, or the checkout.

This module is intentionally standard-library-only so the installed worker
copy can run with Carter's home masked by systemd.  Keep the parent-side and
worker-side protocol versioned together with the provisioning helper.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import selectors
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

PROTOCOL_VERSION = "steward-worker-v1"
WORKER_USER = "steward-worker"
WORKER_HOME = Path("/var/lib/steward-worker")
WORKER_PRIVATE_HOME = Path(os.environ.get("HOME", "/var/empty"))
WORKER_RUN_ROOT = WORKER_HOME / "runs"
WORKER_REQUEST_ROOT = WORKER_HOME / "requests"
WORKER_OMP = Path("/usr/local/libexec/steward-worker/omp")
WORKER_OMP_CONFIG = Path("/etc/steward-worker/omp-config.yml")
WORKER_HELPER = Path(
    os.environ.get("STEWARD_WORKER_HELPER", "/usr/local/libexec/steward-worker-run")
)
DEV_ROOT = Path(os.environ.get("STEWARD_DEV_ROOT", "/home/carter/dev"))
MAX_FINDINGS = 32
MAX_PATHS_PER_REPOSITORY = 64
MAX_DIFF_BYTES = 768 * 1024
MAX_PACKET_BYTES = 2 * 1024 * 1024
MAX_COMMAND_OUTPUT = 4000
MAX_VALIDATION_SECONDS = 900
MAX_REPAIR_SECONDS = 2700

# Source repositories are intentionally narrower than the rest of Carter's
# home.  App code lives in ~/dev; scripts/system-config are maintained by a
# human-reviewed source handoff and are never model-published by P7b.
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


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


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


def _safe_relpath(path: str, *, source_listing: bool = False) -> str:
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
        "PATH": "/usr/local/libexec/steward-worker/bin:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin",
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
            _safe_relpath(path, source_listing=True)
        except WorkerPolicyError:
            continue
        paths.append(path)
    # A tracked symlink could point back into Carter's hidden home after a
    # snapshot. Refuse it rather than attempting to dereference selectively.
    tree = _run(_git_args(root, "ls-files", "-s", "-z"), timeout=30)
    if tree.returncode != 0:
        raise WorkerPolicyError(f"could not inspect repository modes: {root}")
    for row in tree.stdout.split("\0"):
        if not row:
            continue
        mode = row.split(" ", 1)[0]
        if mode in {"120000", "160000"}:
            raise WorkerPolicyError(f"symlinked or submodule source is not repairable: {root}")
    return paths


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
    return _safe_relpath(raw)


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
        str(root): {"source": str(root), "base_sha": _base_sha(root), "allowed_paths": [], "findings": []}
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
            status = _git_status(root)
            _validation_plan(root, bucket["allowed_paths"])
        except WorkerPolicyError as exc:
            return [], [str(exc)]
        if status:
            return [], [f"repository has pre-existing changes; refusing to publish: {root}"]
        plans.append(bucket)
    return plans, []


def _validation_plan(root: Path, allowed_paths: Sequence[str]) -> list[list[str]]:
    """Select trusted argv checks from project files, never from audit prose."""
    commands = [["git", "diff", "--no-ext-diff", "--no-textconv", "--check", "HEAD", "--", *allowed_paths]]
    suffixes = {Path(path).suffix.lower() for path in allowed_paths}
    if ".py" in suffixes:
        commands.append(["python3", "-m", "compileall", "-q", *[p for p in allowed_paths if p.endswith(".py")]])
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


def _write_private_json(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        payload = _json_bytes(data)
        if len(payload) > MAX_PACKET_BYTES:
            raise WorkerPolicyError("worker request is too large")
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        fd = -1
    finally:
        if fd >= 0:
            os.close(fd)


def _read_json(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > MAX_PACKET_BYTES:
        raise WorkerPolicyError(f"worker packet is too large: {path}")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise WorkerPolicyError(f"worker packet must be an object: {path}")
    return data


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


def run_isolated_fix(
    section_name: str,
    findings: Sequence[Mapping[str, Any]],
    *,
    run_dir: Path | None = None,
    iteration: int = 1,
    timeout: int = MAX_REPAIR_SECONDS,
) -> dict[str, Any]:
    """Run the P7b fixer and existing judge inside the worker service.

    Stable signature used by ``fixes.py``.  The helper's result is an untrusted
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
    root = Path(run_dir or WORKER_RUN_ROOT)
    if not root.is_absolute() or not root.exists():
        return {
            "protocol_version": PROTOCOL_VERSION,
            "status": "isolation-unavailable",
            "error": f"P7b run directory is unavailable: {root}",
            "fix_packet": {"fixes_applied": [], "summary": "Isolation is not provisioned."},
            "judge_packet": {"verdict": "fail", "reviewed": [], "summary": "worker helper unavailable"},
            "repositories": [],
        }
    request_id = uuid.uuid4().hex
    request_path = root / f".steward-worker-request-{request_id}.json"
    result_path = root / f".steward-worker-result-{request_id}.json"
    request = {
        "protocol_version": PROTOCOL_VERSION,
        "request_id": request_id,
        "section": str(section_name)[:120],
        "iteration": max(1, int(iteration)),
        "findings": _safe_request_findings(findings),
        "repositories": [
            {
                "source": plan["source"],
                "base_sha": plan["base_sha"],
                "allowed_paths": sorted(plan["allowed_paths"]),
                "validation_commands": _validation_plan(
                    Path(plan["source"]), plan["allowed_paths"]
                ),
                "findings": _safe_request_findings(plan.get("findings", [])),
            }
            for plan in plans
        ],
    }
    try:
        _write_private_json(request_path, request)
        command = [
            str(WORKER_HELPER),
            "--request",
            str(request_path),
            "--result",
            str(result_path),
            "--timeout",
            str(min(MAX_REPAIR_SECONDS, max(60, int(timeout)))),
        ]
        if os.geteuid() != 0:
            command = ["/usr/bin/sudo", "-n", *command]
        cp = _run(command, env=_minimal_env(), timeout=max(120, int(timeout) + 30))
        if cp.returncode != 0:
            detail = (cp.stderr or cp.stdout or "worker helper failed").strip()
            return {
                "protocol_version": PROTOCOL_VERSION,
                "status": "worker-failed",
                "error": detail[:1000],
                "fix_packet": {"fixes_applied": [], "summary": "Isolated worker failed."},
                "judge_packet": {"verdict": "fail", "reviewed": [], "summary": detail[:400]},
                "repositories": [],
            }
        if not result_path.exists():
            raise WorkerExecutionError("worker helper returned success without a result packet")
        result = _read_json(result_path)
        if result.get("protocol_version") != PROTOCOL_VERSION:
            raise WorkerExecutionError("worker protocol version mismatch")
        result["_trusted_repositories"] = [
            {key: repository[key] for key in ("source", "base_sha", "allowed_paths", "validation_commands")}
            for repository in request["repositories"]
        ]
        return result
    except (OSError, subprocess.TimeoutExpired, ValueError, WorkerPolicyError, WorkerExecutionError) as exc:
        return {
            "protocol_version": PROTOCOL_VERSION,
            "status": "worker-failed",
            "error": str(exc)[:1000],
            "fix_packet": {"fixes_applied": [], "summary": "Isolated worker failed."},
            "judge_packet": {"verdict": "fail", "reviewed": [], "summary": str(exc)[:400]},
            "repositories": [],
        }
    finally:
        for path in (request_path, result_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                # The helper may have left a diagnostic owned by root; its
                # bounded retention policy removes it on the next invocation.
                pass

def _validate_result_paths(
    repository: Mapping[str, Any],
    trusted: Mapping[str, Mapping[str, Any]],
) -> tuple[Path, list[str], list[str]]:
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
    allowed = [_safe_relpath(path) for path in repository.get("allowed_paths") or []]
    expected_allowed = sorted(str(path) for path in expected.get("allowed_paths") or [])
    if sorted(allowed) != expected_allowed:
        raise WorkerPolicyError("worker result allowed paths differ from the trusted request")
    changed = [_safe_relpath(path) for path in repository.get("changed_paths") or []]
    if len(set(changed)) != len(changed):
        raise WorkerPolicyError("worker result contains duplicate changed paths")
    if not set(changed).issubset(set(allowed)):
        extra = sorted(set(changed) - set(allowed))
        raise WorkerPolicyError(f"worker changed disallowed paths: {extra}")
    return root, changed, allowed


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
        paths.add(_safe_relpath(path))
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
            allowed = sorted(_safe_relpath(path) for path in raw.get("allowed_paths") or [])
            if not source.startswith("/") or not re.fullmatch(r"[0-9a-f]{40}", base) or not allowed or source in trusted:
                raise WorkerPolicyError("invalid or duplicate trusted repository binding")
            trusted[source] = {
                "base_sha": base, "allowed_paths": allowed,
                "validation_commands": raw.get("validation_commands"),
            }
        sources = [item.get("source") for item in repositories if isinstance(item, Mapping)]
        if len(sources) != len(repositories) or len(set(sources)) != len(sources) or set(sources) != set(trusted):
            raise WorkerPolicyError("worker repositories differ from the trusted request")
        candidates = []
        for item in repositories:
            root, changed, allowed = _validate_result_paths(item, trusted)
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
            if set(actual) != set(changed) or not set(actual).issubset(allowed):
                raise WorkerPolicyError("actual diff paths differ from the trusted allowed paths")
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


WORKER_PROXY_SOCKET = Path("/run/steward-worker/proxy.sock")
WORKER_PROXY_IDLE_SECONDS = 300
WORKER_PROXY_PORT = 18082


class _LocalProxyBridge:
    """Expose only the mounted fixed Unix relay on an isolated loopback port."""

    def __init__(self) -> None:
        self.listener: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self.stop = threading.Event()

    def start(self) -> None:
        if self.listener is not None:
            return
        if not WORKER_PROXY_SOCKET.exists():
            raise WorkerExecutionError("fixed steward-worker proxy socket is not mounted")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind(("127.0.0.1", WORKER_PROXY_PORT))
            listener.listen(8)
            listener.settimeout(1)
        except OSError:
            listener.close()
            raise WorkerExecutionError(
                f"worker loopback bridge port {WORKER_PROXY_PORT} is unavailable"
            )
        self.listener = listener
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    @staticmethod
    def _close(sock: socket.socket | None) -> None:
        if sock is None:
            return
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def _connection(self, client: socket.socket) -> None:
        upstream: socket.socket | None = None
        selector: selectors.BaseSelector | None = None
        try:
            upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            upstream.settimeout(15)
            # The path is a compile-time constant mounted by systemd.  It is
            # never taken from the request, model prompt, or HTTP payload.
            upstream.connect(str(WORKER_PROXY_SOCKET))
            client.setblocking(False)
            upstream.setblocking(False)
            selector = selectors.DefaultSelector()
            states = {
                client: {
                    "peer": upstream,
                    "buffer": bytearray(),
                    "reading": True,
                    "eof": False,
                    "write_closed": False,
                },
                upstream: {
                    "peer": client,
                    "buffer": bytearray(),
                    "reading": True,
                    "eof": False,
                    "write_closed": False,
                },
            }

            def refresh(sock: socket.socket) -> None:
                state = states[sock]
                peer_state = states[state["peer"]]
                events = 0
                if state["reading"] and len(peer_state["buffer"]) < MAX_DIFF_BYTES:
                    events |= selectors.EVENT_READ
                if state["buffer"]:
                    events |= selectors.EVENT_WRITE
                try:
                    if events:
                        selector.modify(sock, events, state["peer"])
                    else:
                        selector.unregister(sock)
                except KeyError:
                    if events:
                        selector.register(sock, events, state["peer"])

            selector.register(client, selectors.EVENT_READ, upstream)
            selector.register(upstream, selectors.EVENT_READ, client)
            last_activity = time.monotonic()
            while not self.stop.is_set():
                remaining = WORKER_PROXY_IDLE_SECONDS - (time.monotonic() - last_activity)
                if remaining <= 0:
                    return
                events = selector.select(timeout=min(1.0, remaining))
                if not events:
                    continue
                for key, mask in events:
                    source = key.fileobj
                    destination = key.data
                    source_state = states[source]
                    destination_state = states[destination]
                    if mask & selectors.EVENT_READ and source_state["reading"]:
                        room = MAX_DIFF_BYTES - len(destination_state["buffer"])
                        if room > 0:
                            try:
                                payload = source.recv(min(65536, room))
                            except (BlockingIOError, InterruptedError):
                                payload = None
                            except OSError:
                                return
                            if payload:
                                destination_state["buffer"].extend(payload)
                                last_activity = time.monotonic()
                            elif payload == b"":
                                source_state["reading"] = False
                                source_state["eof"] = True
                                if (
                                    not destination_state["buffer"]
                                    and not destination_state["write_closed"]
                                ):
                                    try:
                                        destination.shutdown(socket.SHUT_WR)
                                    except OSError:
                                        pass
                                    destination_state["write_closed"] = True
                    if mask & selectors.EVENT_WRITE:
                        pending = source_state["buffer"]
                        if pending:
                            try:
                                sent = source.send(pending)
                            except (BlockingIOError, InterruptedError):
                                sent = 0
                                time.sleep(0.001)
                            except OSError:
                                return
                            if sent:
                                del pending[:sent]
                                last_activity = time.monotonic()
                        if (
                            not pending
                            and destination_state["eof"]
                            and not source_state["write_closed"]
                        ):
                            try:
                                source.shutdown(socket.SHUT_WR)
                            except OSError:
                                pass
                            source_state["write_closed"] = True
                    if all(
                        state["eof"] and not state["buffer"]
                        for state in states.values()
                    ):
                        return
                    for sock in states:
                        refresh(sock)
        except OSError:
            return
        finally:
            if selector is not None:
                selector.close()
            self._close(upstream)
            self._close(client)

    def _serve(self) -> None:
        listener = self.listener
        if listener is None:
            return
        while not self.stop.is_set():
            try:
                client, _address = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self.stop.is_set():
                    return
                continue
            threading.Thread(target=self._connection, args=(client,), daemon=True).start()

    def close(self) -> None:
        self.stop.set()
        self._close(self.listener)
        self.listener = None
        if self.thread is not None:
            self.thread.join(timeout=2)
            self.thread = None


def _omp_call(prompt: str, cwd: Path, session_dir: Path, timeout: int) -> str:
    if not WORKER_OMP.exists() or not WORKER_OMP_CONFIG.exists():
        raise WorkerExecutionError("worker OMP binary/config is not provisioned")
    session_dir.mkdir(parents=True, exist_ok=True)
    env = _minimal_env(home=str(WORKER_PRIVATE_HOME))
    env["PI_CODING_AGENT_DIR"] = str(WORKER_PRIVATE_HOME / ".omp" / "agent")
    cp = _run(
        [
            str(WORKER_OMP),
            "-p",
            "--model",
            "opencode-go/deepseek-v4.1-flash",
            "--api-key", "proxy",
            "--no-extensions", "--no-skills", "--no-rules",
            "--no-lsp", "--no-pty", "--no-title",
            "--tools", "read,bash,edit,write,grep,glob,todo",
            "--max-time", str(max(60, min(MAX_REPAIR_SECONDS, timeout))),
            "--mode",
            "json",
            "--cwd",
            str(cwd),
            "--session-dir",
            str(session_dir),
            "--config",
            str(WORKER_OMP_CONFIG),
            "--add-dir",
            str(cwd),
            prompt,
        ],
        cwd=cwd,
        timeout=max(60, min(MAX_REPAIR_SECONDS, timeout)),
        env=env,
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


def _snapshot_diff(root: Path, allowed_paths: Sequence[str]) -> tuple[str, list[str]]:
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
    if not set(changed).issubset(set(allowed_paths)):
        raise WorkerPolicyError(f"worker changed disallowed paths: {sorted(set(changed) - set(allowed_paths))}")
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
            *allowed_paths,
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
            *allowed_paths,
        ],
        cwd=root,
        env=_minimal_env(),
        timeout=30,
    )
    if check.returncode != 0:
        raise WorkerPolicyError(f"worker diff check failed: {(check.stderr or check.stdout)[:400]}")
    return diff, changed


def _run_validations(root: Path, commands: Sequence[Sequence[str]]) -> list[dict[str, Any]]:
    records = []
    env = _minimal_env(home=str(WORKER_PRIVATE_HOME))
    env["PYTHONPYCACHEPREFIX"] = str(WORKER_PRIVATE_HOME / "pycache")
    env["GOTOOLCHAIN"] = "local"
    env["GOPROXY"] = "off"
    env["CARGO_NET_OFFLINE"] = "true"
    for raw in commands:
        if not isinstance(raw, (list, tuple)) or not raw:
            raise WorkerPolicyError("validation plan contains an invalid command")
        argv = [str(item) for item in raw]
        if argv[0] not in _VALIDATION_PROGRAMS and argv[0] != "git":
            raise WorkerPolicyError(f"validation program is not allowed: {argv[0]}")
        if any("\x00" in item or item.startswith("/") for item in argv):
            raise WorkerPolicyError("validation command contains an absolute/unsafe argument")
        started = time.monotonic()
        cp = _run(argv, cwd=root, env=env, timeout=MAX_VALIDATION_SECONDS)
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


def _fix_prompt(section: str, findings: Sequence[Mapping[str, Any]], allowed: Sequence[str], iteration: int) -> str:
    return (
        f"You are the bounded P7b code-repair worker for audit section {section!r}.\n\n"
        f"This is retry iteration {iteration}. Work ONLY in the supplied disposable Git worktree.\n"
        f"Allowed files (exact relative paths; no other file may change): {json.dumps(list(allowed))}\n"
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


def _worker_repository(request: Mapping[str, Any], repository: Mapping[str, Any], session_root: Path) -> dict[str, Any]:
    workspace = Path(str(repository.get("workspace") or ""))
    if not workspace.is_absolute() or not _under(workspace, WORKER_RUN_ROOT):
        raise WorkerPolicyError(f"workspace outside worker run root: {workspace}")
    allowed = [_safe_relpath(path) for path in repository.get("allowed_paths") or []]
    if not allowed:
        raise WorkerPolicyError("worker repository has no allowed paths")
    if not workspace.exists():
        raise WorkerPolicyError(f"worker workspace missing: {workspace}")
    _initialise_snapshot(workspace)
    findings = [
        finding
        for finding in repository.get("findings", request.get("findings")) or []
        if isinstance(finding, Mapping)
    ]
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
    fix_text = _omp_call(
        _fix_prompt(str(request.get("section") or "unknown"), findings, allowed, int(request.get("iteration") or 1)),
        workspace,
        session_root / "fix",
        int(request.get("timeout") or MAX_REPAIR_SECONDS),
    )
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
    diff, changed = _snapshot_diff(workspace, allowed)
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
        validations = _run_validations(judge_workspace, validation_commands)
        candidate = _run(
            _git_args(judge_workspace, "diff", "--no-ext-diff", "--no-textconv", "--binary", "--full-index", "HEAD"),
            env=_minimal_env(), timeout=60,
        )
        if candidate.returncode != 0 or candidate.stdout != diff:
            raise WorkerPolicyError("validation changed the captured candidate")
        judge_text = _omp_call(
            _judge_prompt(str(request.get("section") or "unknown"), findings, fix_packet, diff, validations),
            judge_workspace,
            session_root / "judge",
            int(request.get("timeout") or MAX_REPAIR_SECONDS),
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
        "changed_paths": changed,
        "diff": diff,
        "diff_sha256": _sha256_text(diff),
        "validation": validations,
        "fix_packet": fix_packet,
        "judge_packet": judge_packet,
    }


def run_worker_request(request_path: Path, result_path: Path) -> dict[str, Any]:
    """Worker-service entrypoint; only the installed unit should call this."""
    request = _read_json(request_path)
    if request.get("protocol_version") != PROTOCOL_VERSION:
        raise WorkerPolicyError("worker request protocol mismatch")
    request_id = str(request.get("request_id") or "")
    if not re.fullmatch(r"[a-f0-9]{32}", request_id):
        raise WorkerPolicyError("invalid worker request id")
    expected_home = WORKER_RUN_ROOT / request_id / "home"
    if WORKER_PRIVATE_HOME != expected_home or not expected_home.is_dir():
        raise WorkerPolicyError("worker HOME is not owned by this request")
    if request_path != WORKER_REQUEST_ROOT / f"{request_id}.json" or result_path != WORKER_RUN_ROOT / request_id / "result.json":
        raise WorkerPolicyError("worker request/result identity differs from this request")
    repositories = request.get("repositories")
    if not isinstance(repositories, list) or not repositories:
        raise WorkerPolicyError("worker request has no repositories")
    session_root = WORKER_RUN_ROOT / request_id / "sessions"
    bridge = _LocalProxyBridge()
    bridge.start()
    outputs = []
    try:
        for index, repository in enumerate(repositories):
            if not isinstance(repository, Mapping):
                raise WorkerPolicyError("worker repository request is not an object")
            outputs.append(_worker_repository(request, repository, session_root / str(index)))
    finally:
        bridge.close()
    verdicts = [str(output["judge_packet"].get("verdict") or "") for output in outputs]
    # Existing judge semantics are retained: any partial/fail keeps the
    # iteration in scope and blocks parent publication.
    all_pass = all(verdict == "pass" for verdict in verdicts)
    all_fixes: list[dict[str, Any]] = []
    all_reviews: list[dict[str, Any]] = []
    for output in outputs:
        all_fixes.extend(output["fix_packet"].get("fixes_applied") or [])
        all_reviews.extend(output["judge_packet"].get("reviewed") or [])
    result = {
        "protocol_version": PROTOCOL_VERSION,
        "request_id": request_id,
        "status": "ok",
        "section": request.get("section"),
        "iteration": request.get("iteration"),
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
        "security": {
            "identity": WORKER_USER,
            "home": str(WORKER_PRIVATE_HOME),
            "network": "provider-proxy-only",
            "credentials": "none",
            "publication": "parent-local-review-ref",
        },
    }
    _write_result_json(result_path, result)
    return result


def _write_result_json(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _json_bytes(data)
    if len(payload) > MAX_PACKET_BYTES:
        raise WorkerPolicyError("worker result is too large")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _cli() -> int:
    parser = argparse.ArgumentParser(description="bounded steward repair worker")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    try:
        if not args.worker:
            parser.error("worker module is only executable with --worker")
        run_worker_request(args.request, args.result)
        return 0
    except Exception as exc:
        try:
            _write_result_json(
                args.result,
                {
                    "protocol_version": PROTOCOL_VERSION,
                    "status": "worker-failed",
                    "error": str(exc)[:1000],
                    "fix_packet": {"fixes_applied": [], "summary": "Isolated worker failed."},
                    "judge_packet": {"verdict": "fail", "reviewed": [], "summary": str(exc)[:400]},
                    "repositories": [],
                },
            )
        except Exception:
            pass
        print(f"steward-worker: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(_cli())
