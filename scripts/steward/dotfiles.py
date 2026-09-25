"""Fail-safe P9b dotfiles hygiene.

Code owns every safety decision: scope, sensitive names, secret scans, size
and text checks, exact-diff hashes, staging, commit, push and remote
verification.  Jev answers only one narrow question per candidate path: is
this finished change unrelated to active interactive work?  Anything Jev
cannot answer confidently is held for Carter.
"""
from __future__ import annotations
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

import jev

from .config import DOTFILES_REPO, HOME, SECRET_PATTERNS
from .runtime import atomic_write_json, run, run_capture_ok

DOTFILES_GIT = HOME / ".dotfiles-homelab"
SESSION_ROOT = HOME / ".omp" / "agent" / "sessions"
ACTIVE_SESSION_MINUTES = 12 * 60
MAX_TITLE_CHARS = 160
MAX_CWD_CHARS = 512
MAX_CONTEXT_CHARS = 2400
MAX_DIFF_CHARS = 200_000
# Jev sees every candidate diff in full; a larger diff is held, never truncated.
JEV_MAX_DIFF_CHARS = 12_000
JEV_PHASE_SECONDS = 120
JEV_UNRELATED_CONFIDENCE = 0.9
JEV_FINISHED_MIN = 0.6
JEV_ACTIVE_CONFIDENCE = 0.6
JEV_PURPOSE = "steward P9b: may this dotfiles change be auto-committed?"
JEV_QUESTIONS = {
    "overlap": {
        "type": "choice",
        "instructions": (
            "Which best describes the change in `diff` to the file at `path` "
            "relative to the interactive work described in `sessions`?"
        ),
        "criteria": {
            "part_of_session": (
                "The change is part of, or directly supports, the work in one of "
                "`sessions`: the same file, feature, program or config area."
            ),
            "unrelated": (
                "The change is unrelated to every session in `sessions` "
                "(this includes an empty `sessions` list)."
            ),
            "cannot_tell": "The information given is too thin to decide.",
        },
    },
    "finished": {
        "type": "noul",
        "instructions": (
            "Is `diff` a complete, self-consistent change rather than half-finished "
            "work (for example unbalanced edits, TODO placeholders, commented-out "
            "experiments or debug prints)?"
        ),
    },
}
# P9b commits modifications/deletions of already-tracked files, plus new text
# files under NEW_FILE_ROOTS that pass every gate below.
COMMITTABLE_STATUS = frozenset({" M", " D"})
UNTRACKED_STATUS = "??"
NEW_FILE_ROOTS = (
    "scripts",
    "system-config",
    ".config/systemd/user",
    ".omp/agent/prompts",
    "news",
    "searxng",
    "open-webui",
    "freshrss",
)
MAX_NEW_FILE_BYTES = 256 * 1024
TEXT_SNIFF_BYTES = 8192

# Deterministic pre-push secret scan of the staged diff. Findings name the
# path, line, and rule only — never the matched value.
_SECRET_FILE_NAMES = frozenset({"env", ".env", "token"})
_SECRET_LINE_RULES = (
    ("private-key block", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY")),
    ("github token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("github fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}")),
    ("sk- API key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
)
_TOKEN_ASSIGNMENT = re.compile(
    r"""\b(?P<name>[A-Z0-9_]*_TOKEN|HF_TOKEN|WEBHOOK_SECRET_[A-Z0-9_]*)\b["']?\s*[:=]\s*(?P<value>\S.*)$"""
)
_GENERIC_ASSIGNMENT = re.compile(
    r"""[\w.-]+["']?\s*[:=]\s*["']?(?P<value>[A-Za-z0-9+/_=.-]{24,})"""
)
_REFERENCE_MARKERS = ("${", "$(", "os.environ", "getenv(", "secret_ref")


def _shannon_entropy(value: str) -> float:
    counts = {ch: value.count(ch) for ch in set(value)}
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def _is_reference(value: str) -> bool:
    stripped = value.strip().strip("\"'")
    return (
        not stripped
        or stripped.startswith("$")
        or stripped.startswith(_REFERENCE_MARKERS)
    )


def _secret_file_name(path: str) -> bool:
    name = Path(path).name.lower()
    return (
        name in _SECRET_FILE_NAMES
        or name.startswith(".env")
        or name.endswith(("token", ".key"))
        or "credentials" in name
    )


def scan_diff_for_secrets(diff: str) -> list[dict[str, Any]]:
    """Scan a unified git diff (added lines only) for credential material."""
    findings: list[dict[str, Any]] = []
    path = ""
    deleted_file = False
    line_no = 0
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            path, deleted_file = line.split(" b/", 1)[-1], False
            continue
        if line.startswith("deleted file mode"):
            deleted_file = True
            continue
        if line.startswith("+++ "):
            if not deleted_file and _secret_file_name(path):
                findings.append({"path": path, "line": 0, "rule": "secret-like file name"})
            continue
        if line.startswith("@@"):
            match = re.search(r"\+(\d+)", line)
            line_no = int(match.group(1)) - 1 if match else 0
            continue
        if not line.startswith("+"):
            if line.startswith(" "):
                line_no += 1
            continue
        line_no += 1
        text = line[1:]
        rule = next((name for name, pattern in _SECRET_LINE_RULES if pattern.search(text)), None)
        if rule is None:
            token = _TOKEN_ASSIGNMENT.search(text)
            if token and not _is_reference(token.group("value")):
                rule = f"{token.group('name')} assignment"
        if rule is None:
            for generic in _GENERIC_ASSIGNMENT.finditer(text):
                value = generic.group("value")
                if not _is_reference(value) and _shannon_entropy(value) >= 4.2:
                    rule = "high-entropy assignment"
                    break
        if rule:
            findings.append({"path": path, "line": line_no, "rule": rule})
    return findings


def _origin_matches(git_dir: Path, home: Path) -> str | None:
    """None when origin fetch+push URLs point at the private dotfiles repo."""
    expected = re.compile(
        rf"^(git@github\.com:|ssh://git@github\.com/|https://github\.com/)"
        rf"{re.escape(DOTFILES_REPO)}(\.git)?/?$"
    )
    for extra in ((), ("--push",)):
        stdout, _, code = run_capture_ok(
            _git_command(git_dir, home, "remote", "get-url", *extra, "origin")
        )
        if code != 0 or not expected.match(stdout.strip()):
            return f"origin does not point at {DOTFILES_REPO}"
    return None


_SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)
    (?:api[_-]?key|secret(?:[_-]?access)?[_-]?key|password|passwd|auth[_-]?token|
       access[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key)
    [\"']?\s*[:=]\s*(?P<value>.+)$
    """
)

# These are the only work-tree roots P9b may ever consider.  The path check is
# component-aware; a prefix such as ``~/.config.evil`` is not accepted.
def allowed_prefixes(home: Path | None = None) -> tuple[Path, ...]:
    root = Path(home if home is not None else HOME)
    return tuple(
        root / part
        for part in (
            ".config",
            ".local/bin",
            ".zshrc",
            ".omp",
            "scripts",
            "open-webui",
            "searxng",
            "freshrss",
            ".config/systemd/user",
        )
    )

def _bounded(value: object, limit: int) -> str:
    text = str(value or "").replace("\x00", " ").strip()
    return text[:limit]


def _status_map(status: str | bytes) -> dict[str, str]:
    """Return exact paths and status codes from Git's NUL-delimited porcelain."""
    items = iter(os.fsdecode(status).split("\x00"))
    result: dict[str, str] = {}
    for record in items:
        if not record:
            continue
        code, path = record[:2], record[3:]
        result[path] = code
        if "R" in code or "C" in code:
            result[next(items)] = code
    return result


def _safe_home_path(path: str, home: Path | None = None) -> Path | None:
    """Resolve a relative work-tree path without permitting traversal."""
    candidate = Path(path)
    if candidate.is_absolute() or "\x00" in path:
        return None
    root = Path(home if home is not None else HOME).resolve()
    try:
        resolved = (root / candidate).resolve(strict=False)
        resolved.relative_to(root)
    except (OSError, ValueError):
        return None
    return resolved

def _path_in_allowed_scope(path: str, home: Path | None = None) -> bool:
    resolved = _safe_home_path(path, home)
    if resolved is None:
        return False
    for prefix in allowed_prefixes(home):
        try:
            resolved.relative_to(prefix.resolve())
            return True
        except (OSError, ValueError):
            continue
    return False


def _path_in_new_file_roots(path: str, home: Path | None = None) -> bool:
    resolved = _safe_home_path(path, home)
    if resolved is None:
        return False
    root = Path(home if home is not None else HOME)
    for part in NEW_FILE_ROOTS:
        try:
            resolved.relative_to((root / part).resolve())
            return True
        except (OSError, ValueError):
            continue
    return False


def _new_file_reason(path: str, home: Path) -> str | None:
    """Why a new file may not be auto-committed; None when it is a small text file."""
    target = home / path
    try:
        info = target.lstat()
        if not stat.S_ISREG(info.st_mode):
            return "new path is not a regular file"
        if info.st_size > MAX_NEW_FILE_BYTES:
            return f"new file exceeds {MAX_NEW_FILE_BYTES} bytes"
        with target.open("rb") as handle:
            if b"\x00" in handle.read(TEXT_SNIFF_BYTES):
                return "new file is binary"
    except OSError as exc:
        return f"new file unreadable: {exc.strerror or exc}"
    return None
def _is_sensitive(path: str) -> bool:
    candidate = Path(path)
    values = (path, candidate.name, *candidate.parts)
    return any(
        pattern.match(value.lower())
        for pattern in SECRET_PATTERNS
        for value in values
    )


def _message_text(message: Mapping[str, Any]) -> str:
    content = message.get("content")
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    chunks: list[str] = []
    for part in content:
        if not isinstance(part, Mapping):
            continue
        if part.get("type") == "text" and isinstance(part.get("text"), str):
            chunks.append(part["text"])
    return "".join(chunks)


def _session_evidence(path: Path, now: datetime, active_window: timedelta) -> dict[str, Any] | None:
    try:
        mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    except OSError:
        return None
    if now - mtime > active_window:
        return None

    malformed = False
    closed = False
    title = ""
    cwd = ""
    messages: list[str] = []
    session_id = path.stem
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except (TypeError, ValueError):
                    malformed = True
                    continue
                if not isinstance(item, Mapping):
                    malformed = True
                    continue
                if item.get("customType") == "session_exit":
                    closed = True
                if item.get("type") == "session":
                    session_id = _bounded(item.get("id") or session_id, 160)
                    title = _bounded(item.get("title") or title, MAX_TITLE_CHARS)
                    cwd = _bounded(item.get("cwd") or cwd, MAX_CWD_CHARS)
                elif item.get("type") == "title":
                    title = _bounded(item.get("title") or title, MAX_TITLE_CHARS)
                message = item.get("message")
                if isinstance(message, Mapping):
                    role = message.get("role")
                    if role in {"user", "assistant"}:
                        text = _message_text(message).strip()
                        if text:
                            messages.append(f"{role}: {text}")
                    cwd = _bounded(message.get("cwd") or cwd, MAX_CWD_CHARS)
                cwd = _bounded(item.get("cwd") or cwd, MAX_CWD_CHARS)
    except OSError:
        malformed = True

    if closed:
        return None
    context = "\n".join(messages[-8:])
    return {
        "path": str(path),
        "session_id": session_id,
        "title": _bounded(title or path.stem, MAX_TITLE_CHARS),
        "cwd": _bounded(cwd, MAX_CWD_CHARS),
        "recent_context": _bounded(context, MAX_CONTEXT_CHARS),
        "mtime": mtime.isoformat(),
        "malformed": malformed,
        "closed": False,
    }


def collect_active_session_evidence(
    session_root: Path | None = None,
    *,
    now: datetime | None = None,
    active_window_minutes: int = ACTIVE_SESSION_MINUTES,
) -> list[dict[str, Any]]:
    """Collect recursively discovered, recent, unclosed interactive sessions.

    A malformed recent transcript is retained as evidence rather than ignored:
    the caller must fail closed and classify affected paths as ambiguous.
    """
    root = Path(session_root if session_root is not None else HOME / ".omp" / "agent" / "sessions")
    if not root.is_dir():
        return []
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    window = timedelta(minutes=max(0, int(active_window_minutes)))
    evidence: list[dict[str, Any]] = []
    try:
        paths = sorted(root.rglob("*.jsonl"))
    except OSError:
        return [{
            "path": str(root), "session_id": "", "title": "", "cwd": "",
            "recent_context": "", "mtime": "", "malformed": True, "closed": False,
        }]
    for path in paths:
        if not path.is_file():
            continue
        item = _session_evidence(path, current, window)
        if item is not None:
            evidence.append(item)
    return evidence


def _session_mentions_path(session: Mapping[str, Any], path: str, home: Path) -> bool:
    relative = Path(path)
    absolute = _safe_home_path(path, home)
    home_root = home.resolve()
    cwd_value = str(session.get("cwd") or "")
    if cwd_value:
        try:
            cwd = Path(cwd_value).expanduser().resolve(strict=False)
            # A session launched at $HOME is not evidence that every file in
            # the homedir is active. Specific project/subdirectory CWDs are.
            if cwd != home_root and absolute is not None and (absolute == cwd or cwd in absolute.parents):
                return True
        except (OSError, RuntimeError):
            return True
    context = str(session.get("recent_context") or "")
    normalized = str(relative).replace("\\", "/")
    if normalized and normalized in context.replace("\\", "/"):
        return True
    if absolute is not None and str(absolute) in context:
        return True
    return False


def exact_path_diff(path: str, *, git_dir: Path = DOTFILES_GIT, home: Path = HOME) -> str:
    """Return the complete staged-form diff for exactly one work-tree path."""
    if _safe_home_path(path, home) is None:
        raise ValueError(f"unsafe dotfiles path: {path}")
    fd, index_path = tempfile.mkstemp(prefix="steward-dotfiles-index-")
    os.close(fd)
    os.unlink(index_path)
    env = {**os.environ, "GIT_INDEX_FILE": index_path}
    try:
        _, stderr, code = run_capture_ok(
            _git_command(git_dir, home, "read-tree", "HEAD"),
            env=env,
        )
        if code != 0:
            raise RuntimeError(stderr or "could not initialize temporary index")
        _, stderr, code = run_capture_ok(
            _git_command(git_dir, home, "add", "-A", "--", path),
            env=env,
        )
        if code != 0:
            raise RuntimeError(stderr or f"could not stage {path} in temporary index")
        stdout, stderr, code = run_capture_ok(
            _git_command(
                git_dir,
                home,
                "diff",
                "--cached",
                "--no-renames",
                "--full-index",
                "--binary",
                "--no-ext-diff",
                "--no-color",
                "HEAD",
                "--",
                path,
            ),
            env=env,
        )
        if code != 0:
            raise RuntimeError(stderr or f"could not diff {path}")
        return stdout
    finally:
        try:
            os.remove(index_path)
        except FileNotFoundError:
            pass


def _cached_path_diff(path: str, *, git_dir: Path, home: Path) -> str:
    stdout, stderr, code = run_capture_ok(
        _git_command(
            git_dir,
            home,
            "diff",
            "--cached",
            "--no-renames",
            "--full-index",
            "--binary",
            "--no-ext-diff",
            "--no-color",
            "HEAD",
            "--",
            path,
        )
    )
    if code != 0:
        raise RuntimeError(stderr or f"could not read staged diff for {path}")
    return stdout


def _diff_hash(diff: str) -> str:
    return hashlib.sha256(diff.encode("utf-8", "surrogatepass")).hexdigest()


def _sensitive_diff_reason(diff: str) -> str | None:
    if "GIT binary patch" in diff or "\nBinary files " in diff:
        return "binary changes require manual review"
    if len(diff) > MAX_DIFF_CHARS:
        return f"diff exceeds {MAX_DIFF_CHARS} characters"
    for line in diff.splitlines():
        if not line or line[0] not in {"+", "-"} or line.startswith(("+++", "---")):
            continue
        text = line[1:].strip()
        if "BEGIN " in text and "PRIVATE KEY" in text:
            return "diff contains private-key material"
        match = _SECRET_ASSIGNMENT.search(text)
        if not match:
            continue
        value = match.group("value").strip().rstrip(",").strip("\"'")
        # Placeholders must be the whole value; a substring such as "none"
        # inside a real password is not a reason to skip it.
        if (
            len(value) >= 8
            and not _is_reference(value)
            and value.lower() not in _PLACEHOLDER_VALUES
        ):
            return "diff contains a credential-like assignment"
    if scan_diff_for_secrets(diff):
        return "diff contains credential-like material"
    return None


_PLACEHOLDER_VALUES = frozenset({
    "<redacted>", "changeme", "placeholder", "none", "null", "example",
    "your-token-here", "xxxxxxxx",
})


def classify_dotfile_paths(
    changed_paths: Iterable[str],
    *,
    home: Path = HOME,
    active_sessions: Iterable[Mapping[str, Any]] = (),
    untracked: Iterable[str] = (),
) -> dict[str, dict[str, str]]:
    """Apply deterministic safety classifications before Jev is consulted."""
    sessions = list(active_sessions)
    new_files = set(untracked)
    result: dict[str, dict[str, str]] = {}
    malformed = any(bool(session.get("malformed")) for session in sessions)
    for path in dict.fromkeys(str(item) for item in changed_paths):
        is_new = path in new_files
        new_root = is_new and _path_in_new_file_roots(path, home)
        new_reason = _new_file_reason(path, home) if new_root else None
        if not new_root and not _path_in_allowed_scope(path, home):
            result[path] = {"classification": "out_of_scope", "reason": "path is outside the allowlist"}
        elif is_new and not new_root:
            result[path] = {
                "classification": "untracked",
                "reason": "new file outside the auto-commit roots; add manually if wanted",
            }
        elif _is_sensitive(path) or (is_new and _secret_file_name(path)):
            result[path] = {"classification": "sensitive", "reason": "path matches the secret denylist"}
        elif new_reason:
            result[path] = {"classification": "untracked", "reason": new_reason}
        elif malformed:
            result[path] = {"classification": "ambiguous", "reason": "recent session evidence is malformed"}
        elif any(_session_mentions_path(session, path, home) for session in sessions):
            result[path] = {"classification": "active", "reason": "path is in active session context"}
    return result


def _redact_lines(text: str) -> str:
    redacted: list[str] = []
    for line in text.splitlines():
        match = _SECRET_ASSIGNMENT.search(line)
        if match:
            line = line[:match.start("value")] + "[REDACTED]"
        token = _TOKEN_ASSIGNMENT.search(line)
        if token:
            line = line[:token.start("value")] + "[REDACTED]"
        for _, pattern in _SECRET_LINE_RULES:
            line = pattern.sub("[REDACTED]", line)
        if "BEGIN " in line and "PRIVATE KEY" in line:
            line = "[REDACTED PRIVATE KEY MATERIAL]"
        redacted.append(line)
    return "\n".join(redacted)


def _redact_context(value: object) -> str:
    return _redact_lines(_bounded(value, MAX_CONTEXT_CHARS))


def jev_state(path: str, diff: str, sessions: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """The exact state Jev sees for one candidate path (redacted, never truncated)."""
    return {
        "path": path,
        "diff": _redact_lines(diff),
        "sessions": [
            {
                "title": _redact_lines(_bounded(session.get("title"), MAX_TITLE_CHARS)),
                "cwd": _bounded(session.get("cwd"), MAX_CWD_CHARS),
                "recent_context": _redact_context(session.get("recent_context")),
            }
            for session in sessions
        ],
    }


def jev_classify_path(
    client: Any,
    path: str,
    diff: str,
    sessions: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Commit-gate one path: unrelated only on a confident, finished Jev answer."""
    if len(diff) > JEV_MAX_DIFF_CHARS:
        return {
            "classification": "ambiguous",
            "reason": f"diff exceeds the {JEV_MAX_DIFF_CHARS}-character Jev budget",
        }
    if client is None:
        return {"classification": "ambiguous", "reason": "Jev unavailable (no_key)"}
    try:
        answers = client.ask(JEV_PURPOSE, jev_state(path, diff, sessions), JEV_QUESTIONS)
    except jev.JevUnavailable as exc:
        return {
            "classification": "ambiguous",
            "reason": f"Jev unavailable ({exc.reason})",
        }
    overlap = answers["overlap"]
    choice = overlap.get("choice")
    confidence = float(overlap["confidence"])
    finished = float(answers["finished"]["noul"])
    logged: dict[str, Any] = {
        "overlap": choice,
        "overlap_confidence": round(confidence, 4),
        "finished": round(finished, 4),
    }
    if isinstance(overlap.get("probabilities"), Mapping):
        logged["overlap_probabilities"] = dict(overlap["probabilities"])
    if (
        choice == "unrelated"
        and confidence >= JEV_UNRELATED_CONFIDENCE
        and finished >= JEV_FINISHED_MIN
    ):
        classification, reason = "unrelated", "Jev: finished change unrelated to active sessions"
    elif choice == "part_of_session" and confidence >= JEV_ACTIVE_CONFIDENCE:
        classification, reason = "active", "Jev: change belongs to an active session"
    else:
        classification = "ambiguous"
        reason = (
            f"Jev below the commit gate (overlap={choice} @ {confidence:.2f}, "
            f"finished={finished:.2f})"
        )
    return {"classification": classification, "reason": reason, "jev": logged}


def _git_command(git_dir: Path, home: Path, *args: str) -> list[str]:
    return ["/usr/bin/git", "--git-dir", str(git_dir), "--work-tree", str(home), *args]


def _snapshot(git_dir: Path, home: Path) -> tuple[dict[str, str], str | None]:
    stdout, stderr, code = run_capture_ok(
        _git_command(
            git_dir,
            home,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        ),
        text=False,
    )
    if code != 0:
        return {}, os.fsdecode(stderr or stdout) or "git status failed"
    return _status_map(stdout), None


def _staged_paths(git_dir: Path, home: Path) -> tuple[set[str], str | None]:
    stdout, stderr, code = run_capture_ok(
        _git_command(
            git_dir,
            home,
            "diff",
            "--cached",
            "--no-renames",
            "--name-only",
            "-z",
        ),
        text=False,
    )
    if code != 0:
        return set(), os.fsdecode(stderr or stdout) or "git staged diff failed"
    return {path for path in os.fsdecode(stdout).split("\x00") if path}, None


def untracked_in_scope(
    *, git_dir: Path = DOTFILES_GIT, home: Path = HOME
) -> list[str]:
    """Untracked ('??') paths in P9b scope that are still uncommitted (listed for Carter)."""
    statuses, error = _snapshot(git_dir, home)
    if error:
        raise RuntimeError(error)
    return sorted(
        path for path, code in statuses.items()
        if code == "??" and (
            _path_in_allowed_scope(path, home) or _path_in_new_file_roots(path, home)
        )
    )


def _current_branch(git_dir: Path, home: Path) -> str | None:
    stdout, _, code = run_capture_ok(
        _git_command(git_dir, home, "symbolic-ref", "--short", "HEAD")
    )
    branch = stdout.strip()
    return branch if code == 0 and branch else None


def _head_oid(git_dir: Path, home: Path) -> str | None:
    stdout, _, code = run_capture_ok(
        _git_command(git_dir, home, "rev-parse", "HEAD")
    )
    value = stdout.strip()
    return value if code == 0 and re.fullmatch(r"[0-9a-f]{40}", value) else None


def _remote_oid(git_dir: Path, home: Path, branch: str) -> str | None:
    stdout, _, code = run_capture_ok(
        _git_command(git_dir, home, "ls-remote", "origin", f"refs/heads/{branch}")
    )
    if code != 0:
        return None
    fields = stdout.split()
    return fields[0] if fields and re.fullmatch(r"[0-9a-f]{40}", fields[0]) else None


def _pre_push_block(
    git_dir: Path,
    home: Path,
    diff_command: list[str],
    *,
    check_origin: bool = True,
    check_scan: bool = True,
) -> dict[str, Any] | None:
    """Deterministic gate before any push: origin identity + secret scan."""
    origin_error = _origin_matches(git_dir, home) if check_origin else None
    if origin_error:
        return {
            "status": "push_blocked",
            "phase_status": "failed",
            "phase_failed": True,
            "reason": origin_error,
        }
    if not check_scan:
        return None
    diff, stderr, code = run_capture_ok(diff_command)
    if code != 0:
        return {
            "status": "push_blocked",
            "phase_status": "failed",
            "phase_failed": True,
            "reason": f"could not read diff for secret scan: {(stderr or '')[:300]}",
        }
    findings = scan_diff_for_secrets(diff)
    if findings:
        return {
            "status": "secret_blocked",
            "phase_status": "failed",
            "phase_failed": True,
            "secret_findings": findings[:50],
            "reason": (
                f"secret scan blocked the push: {len(findings)} hit(s) in "
                + ", ".join(sorted({f['path'] for f in findings}))[:500]
            ),
        }
    return None


def _pending_push_record(branch: str, commit: str) -> dict[str, str]:
    """Return the exact immutable identity that may be retried later."""
    return {"branch": branch, "commit": commit}


def _retry_pending_push(
    pending: Mapping[str, Any],
    *,
    git_dir: Path,
    home: Path,
    paths: Iterable[str] = (),
) -> dict[str, Any]:
    """Push only the exact committed branch/OID recorded by a prior attempt."""
    branch = pending.get("branch")
    commit = pending.get("commit")
    base = {
        "paths": list(paths),
        "commit": commit,
        "branch": branch,
        "pending_push": dict(pending),
    }
    if (
        not isinstance(branch, str)
        or not branch
        or branch.startswith("-")
        or any(char.isspace() or char == "\x00" for char in branch)
        or not isinstance(commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", commit) is None
    ):
        return {
            **base,
            "status": "pending_diverged",
            "phase_status": "failed",
            "phase_failed": True,
            "reason": "pending push record is malformed",
        }

    current_branch = _current_branch(git_dir, home)
    current_head = _head_oid(git_dir, home)
    if current_branch != branch:
        return {
            **base,
            "status": "pending_diverged",
            "phase_status": "failed",
            "phase_failed": True,
            "reason": (
                f"pending push branch diverged: expected {branch!r}, "
                f"found {current_branch!r}"
            ),
        }
    if current_head != commit:
        return {
            **base,
            "status": "pending_diverged",
            "phase_status": "failed",
            "phase_failed": True,
            "reason": (
                f"pending push HEAD diverged: expected {commit}, "
                f"found {current_head or 'missing'}"
            ),
        }

    statuses, status_error = _snapshot(git_dir, home)
    staged, staged_error = _staged_paths(git_dir, home)
    tracked_changes = {
        path for path, code in statuses.items() if code != UNTRACKED_STATUS
    }
    if status_error or staged_error or tracked_changes or staged:
        return {
            **base,
            "status": "pending_diverged",
            "phase_status": "failed",
            "phase_failed": True,
            "reason": (
                status_error
                or staged_error
                or "working tree changed since pending commit"
            ),
        }

    # The original push may have reached the remote before reporting failure.
    remote = _remote_oid(git_dir, home, branch)
    if remote == commit:
        return {
            **base,
            "status": "committed",
            "push": "verified",
            "remote_commit": remote,
        } | {"pending_push": None}

    blocked = _pre_push_block(
        git_dir, home,
        _git_command(git_dir, home, "show", "--format=", "-p", "--no-renames",
                     "--no-ext-diff", "--no-color", commit),
    )
    if blocked:
        return {**base, **blocked}

    try:
        run(
            _git_command(
                git_dir,
                home,
                "push",
                "origin",
                f"{commit}:refs/heads/{branch}",
            ),
            capture_output=True,
            text=True,
        )
    except Exception as exc:
        return {
            **base,
            "status": "push_failed",
            "phase_status": "failed",
            "phase_failed": True,
            "reason": str(exc),
        }
    verified = _remote_oid(git_dir, home, branch)
    if verified != commit:
        return {
            **base,
            "status": "remote_unverified",
            "phase_status": "failed",
            "phase_failed": True,
            "reason": "remote did not verify the exact pending commit",
            "remote_commit": verified,
        }
    return {
        **base,
        "status": "committed",
        "push": "verified",
        "remote_commit": verified,
        "pending_push": None,
    }

def _commit_exact_paths(
    paths: list[str],
    *,
    git_dir: Path,
    home: Path,
    expected_dirty_paths: Iterable[str] | None = None,
    expected_diff_hashes: Mapping[str, str] | None = None,
    push: bool = True,
    pre_push_check: Callable[[], bool] | None = None,
    new_paths: Iterable[str] = (),
) -> dict[str, Any]:
    """Commit only staged bytes identical to the diffs reviewed by the gate.

    ``new_paths`` names the untracked files that passed the new-file gate; any
    other untracked path is refused.
    """
    approved = set(paths)
    new_files = set(new_paths) & approved
    expected = set(expected_dirty_paths or paths)
    reviewed_hashes = dict(expected_diff_hashes or {})
    untouched = expected - approved
    if not approved:
        return {"status": "nothing_to_commit", "paths": []}

    def unstage_owned_paths() -> None:
        try:
            run(
                _git_command(git_dir, home, "reset", "--quiet", "HEAD", "--", *paths),
                capture_output=True,
                text=True,
            )
        except (subprocess.CalledProcessError, OSError):
            pass

    before, error = _snapshot(git_dir, home)
    if error:
        return {"status": "ambiguous", "reason": error}
    if set(before) != expected:
        return {"status": "ambiguous", "reason": "dirty paths changed before staging"}
    if any(code[0] not in {" ", "?"} for code in before.values()):
        return {
            "status": "ambiguous",
            "reason": "pre-staged index state is not owned by P9b",
        }
    untracked_or_unsupported = sorted(
        path for path in paths
        if before.get(path) not in COMMITTABLE_STATUS
        and not (path in new_files and before.get(path) == UNTRACKED_STATUS)
    )
    if untracked_or_unsupported:
        return {
            "status": "ambiguous",
            "reason": (
                "only tracked modifications/deletions and gated new files may be committed: "
                + ", ".join(untracked_or_unsupported)[:500]
            ),
        }
    tracked = [path for path in paths if path not in new_files]
    added = sorted(new_files)
    if any(_new_file_reason(path, home) for path in added):
        return {"status": "ambiguous", "reason": "new file changed type or size before staging"}
    try:
        if tracked:
            run(
                # -u never adds untracked files, even if a path race created one.
                _git_command(git_dir, home, "add", "-u", "--", *tracked),
                capture_output=True,
                text=True,
            )
        if added:
            run(
                _git_command(git_dir, home, "add", "--", *added),
                capture_output=True,
                text=True,
            )
    except (subprocess.CalledProcessError, OSError) as exc:
        unstage_owned_paths()
        return {"status": "ambiguous", "reason": f"exact-path staging failed: {exc}"}

    staged, error = _staged_paths(git_dir, home)
    if error or staged != approved:
        unstage_owned_paths()
        return {
            "status": "ambiguous",
            "reason": error or "staged paths differ from approved paths",
        }
    if reviewed_hashes:
        try:
            staged_hashes = {
                path: _diff_hash(
                    _cached_path_diff(path, git_dir=git_dir, home=home)
                )
                for path in paths
            }
        except RuntimeError as exc:
            unstage_owned_paths()
            return {"status": "ambiguous", "reason": str(exc)}
        expected_hashes = {path: reviewed_hashes.get(path, "") for path in paths}
        if staged_hashes != expected_hashes:
            unstage_owned_paths()
            return {
                "status": "ambiguous",
                "reason": "staged content differs from reviewed diff",
            }

    after_stage, error = _snapshot(git_dir, home)
    if error or set(after_stage) != expected:
        unstage_owned_paths()
        return {
            "status": "ambiguous",
            "reason": error or "dirty paths changed during staging",
        }
    blocked = _pre_push_block(
        git_dir, home,
        _git_command(git_dir, home, "diff", "--cached", "--no-renames",
                     "--no-ext-diff", "--no-color", "HEAD"),
        check_origin=False,
    )
    if blocked:
        unstage_owned_paths()
        return {**blocked, "paths": paths, "untouched_paths": sorted(untouched)}
    try:
        run(
            _git_command(
                git_dir,
                home,
                "commit",
                "-m",
                "chore: steward dotfiles hygiene",
            ),
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, OSError) as exc:
        unstage_owned_paths()
        return {"status": "ambiguous", "reason": f"commit failed: {exc}"}

    local_oid = _head_oid(git_dir, home)
    branch = _current_branch(git_dir, home)
    if not local_oid or not branch:
        return {
            "status": "ambiguous",
            "reason": "could not identify committed branch",
        }
    result: dict[str, Any] = {
        "status": "committed",
        "paths": paths,
        "untouched_paths": sorted(untouched),
        "commit": local_oid,
        "branch": branch,
    }
    if not push:
        result["push"] = "not_requested"
        return result

    before_push, error = _snapshot(git_dir, home)
    staged_after, staged_error = _staged_paths(git_dir, home)
    if error or set(before_push) != untouched or staged_error or staged_after:
        return {
            "status": "push_pending",
            "commit": local_oid,
            "branch": branch,
            "pending_push": _pending_push_record(branch, local_oid),
            "reason": error or staged_error or "race detected before push",
        }
    if pre_push_check is not None and not pre_push_check():
        return {
            "status": "push_pending",
            "commit": local_oid,
            "branch": branch,
            "pending_push": _pending_push_record(branch, local_oid),
            "reason": "race detected before push",
        }
    origin_block = _pre_push_block(git_dir, home, [], check_scan=False)
    if origin_block:
        return {
            **origin_block,
            "commit": local_oid,
            "branch": branch,
            "pending_push": _pending_push_record(branch, local_oid),
        }
    try:
        run(
            _git_command(
                git_dir,
                home,
                "push",
                "origin",
                f"{local_oid}:refs/heads/{branch}",
            ),
            capture_output=True,
            text=True,
        )
    except Exception as exc:
        return {
            "status": "push_failed",
            "commit": local_oid,
            "branch": branch,
            "pending_push": _pending_push_record(branch, local_oid),
            "reason": str(exc),
        }
    verified = _remote_oid(git_dir, home, branch)
    if verified != local_oid:
        return {
            "status": "remote_unverified",
            "commit": local_oid,
            "branch": branch,
            "pending_push": _pending_push_record(branch, local_oid),
            "remote_commit": verified,
        }
    result.update({"push": "verified", "remote_commit": verified})
    return result


def phase_9b_dotfiles(
    run_dir: Path,
    dry_run: bool = False,
    *,
    git_dir: Path | None = None,
    home: Path | None = None,
    session_root: Path | None = None,
    push: bool = True,
    jev_client: Any | None = None,
) -> dict[str, Any]:
    """Classify and, only when proven safe, commit exact dotfiles paths.

    ``jev_client`` (tests inject a fake) defaults to ``jev.load_client`` with a
    phase deadline; no key means every candidate is held as ambiguous.
    """
    print("[P9b] dotfiles hygiene")
    artifact = Path(run_dir) / "09b-dotfiles.json"
    root_home = Path(home if home is not None else HOME)
    root_git = Path(git_dir if git_dir is not None else root_home / ".dotfiles-homelab")
    root_sessions = Path(
        session_root
        if session_root is not None
        else root_home / ".omp" / "agent" / "sessions"
    )
    prior_artifact: dict[str, Any] = {}
    if artifact.is_file():
        try:
            loaded = json.loads(artifact.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                prior_artifact = loaded
        except (OSError, UnicodeError, json.JSONDecodeError):
            prior_artifact = {}
    pending = prior_artifact.get("pending_push")
    if (
        pending is None
        and prior_artifact.get("status") in {
            "push_pending", "push_failed", "remote_unverified"
        }
        and prior_artifact.get("branch") is not None
        and prior_artifact.get("commit") is not None
    ):
        # Migrate the pre-pending-push artifact shape without ever inventing
        # a new commit: only the recorded branch/OID may be retried.
        pending = {
            "branch": prior_artifact.get("branch"),
            "commit": prior_artifact.get("commit"),
        }
    if pending is not None:
        prior_paths = prior_artifact.get("paths", [])
        if not isinstance(prior_paths, list):
            prior_paths = []
        if isinstance(pending, Mapping):
            result = _retry_pending_push(
                pending,
                git_dir=root_git,
                home=root_home,
                paths=(str(path) for path in prior_paths),
            )
        else:
            result = {
                "status": "pending_diverged",
                "phase_status": "failed",
                "phase_failed": True,
                "reason": "pending push record is malformed",
                "pending_push": pending,
                "paths": prior_paths,
            }
        if result.get("pending_push") is None:
            result.pop("pending_push", None)
        atomic_write_json(artifact, result)
        print(f"[P9b] {result.get('status')} -> {artifact}")
        return result
    statuses, status_error = _snapshot(root_git, root_home)
    if status_error:
        result = {"status": "ambiguous", "reason": status_error, "changed_paths": []}
        atomic_write_json(artifact, result)
        return result
    changed = sorted(statuses)
    if not changed:
        result = {"status": "clean", "changed_paths": [], "classifications": {}}
        atomic_write_json(artifact, result)
        return result

    sessions = collect_active_session_evidence(root_sessions)
    session_fingerprint = _diff_hash(
        json.dumps(sessions, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    )
    untracked = sorted(p for p, c in statuses.items() if c == UNTRACKED_STATUS)
    deterministic = classify_dotfile_paths(
        changed, home=root_home, active_sessions=sessions, untracked=untracked
    )
    for path, code in statuses.items():
        if path in deterministic:
            continue
        if code not in COMMITTABLE_STATUS and code != UNTRACKED_STATUS:
            deterministic[path] = {
                "classification": "ambiguous",
                "reason": f"git status {code!r} is not a plain tracked modification/deletion",
            }
    records: list[dict[str, Any]] = []
    reviewed_diff_hashes: dict[str, str] = {}
    reviewed_diff_sizes: dict[str, int] = {}
    for path in changed:
        if path in deterministic:
            continue
        try:
            diff = exact_path_diff(path, git_dir=root_git, home=root_home)
        except (OSError, RuntimeError, ValueError) as exc:
            deterministic[path] = {
                "classification": "ambiguous",
                "reason": f"exact diff unavailable: {str(exc)[:300]}",
            }
            continue
        if not diff:
            deterministic[path] = {
                "classification": "ambiguous",
                "reason": "exact diff is empty",
            }
            continue
        risk = _sensitive_diff_reason(diff)
        if risk:
            classification = (
                "sensitive"
                if "credential" in risk or "private-key" in risk
                else "ambiguous"
            )
            deterministic[path] = {
                "classification": classification,
                "reason": risk,
            }
            continue
        reviewed_diff_hashes[path] = _diff_hash(diff)
        reviewed_diff_sizes[path] = len(diff)
        records.append({"path": path, "diff": diff})

    classifications: dict[str, dict[str, Any]] = dict(deterministic)
    if records:
        client = (
            jev_client
            if jev_client is not None
            else jev.load_client(deadline=time.monotonic() + JEV_PHASE_SECONDS)
        )
        for row in records:
            classifications[row["path"]] = jev_classify_path(
                client, row["path"], row["diff"], sessions
            )

    eligible = sorted(
        path
        for path, row in classifications.items()
        if row.get("classification") == "unrelated"
        and (
            statuses.get(path) in COMMITTABLE_STATUS
            or statuses.get(path) == UNTRACKED_STATUS
        )
    )
    session_artifacts = [
        {
            "session_id": session.get("session_id", ""),
            "title": _bounded(session.get("title"), MAX_TITLE_CHARS),
            "cwd": _bounded(session.get("cwd"), MAX_CWD_CHARS),
            "mtime": session.get("mtime", ""),
            "malformed": bool(session.get("malformed")),
        }
        for session in sessions
    ]
    base = {
        "changed_paths": changed,
        "untracked_paths": untracked,
        "active_sessions": session_artifacts,
        "active_sessions_sha256": session_fingerprint,
        "classifications": classifications,
        "reviewed_diffs": {
            path: {
                "sha256": reviewed_diff_hashes[path],
                "characters": reviewed_diff_sizes[path],
            }
            for path in sorted(reviewed_diff_hashes)
        },
    }
    if dry_run:
        result = {"status": "dry_run", "would_commit": eligible, **base}
        atomic_write_json(artifact, result)
        return result
    if not eligible:
        result = {
            "status": "skipped",
            "reason": "no unambiguously unrelated paths",
            **base,
        }
        atomic_write_json(artifact, result)
        return result

    latest_statuses, status_error = _snapshot(root_git, root_home)
    latest_sessions = collect_active_session_evidence(root_sessions)
    latest_session_fingerprint = _diff_hash(
        json.dumps(
            latest_sessions,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
    )
    if (
        status_error
        or set(latest_statuses) != set(changed)
        or latest_session_fingerprint != session_fingerprint
    ):
        result = {
            "status": "ambiguous",
            "reason": status_error or "path or active-session race before staging",
            **base,
        }
        atomic_write_json(artifact, result)
        return result
    latest_deterministic = classify_dotfile_paths(
        changed, home=root_home, active_sessions=latest_sessions, untracked=untracked
    )
    if any(path in latest_deterministic for path in eligible):
        result = {
            "status": "ambiguous",
            "reason": "active-session race before staging",
            **base,
        }
        atomic_write_json(artifact, result)
        return result
    try:
        latest_hashes = {
            path: _diff_hash(
                exact_path_diff(path, git_dir=root_git, home=root_home)
            )
            for path in eligible
        }
    except (OSError, RuntimeError, ValueError) as exc:
        result = {
            "status": "ambiguous",
            "reason": f"exact diff race check failed: {str(exc)[:300]}",
            **base,
        }
        atomic_write_json(artifact, result)
        return result
    if latest_hashes != {path: reviewed_diff_hashes[path] for path in eligible}:
        result = {
            "status": "ambiguous",
            "reason": "reviewed diff changed before staging",
            **base,
        }
        atomic_write_json(artifact, result)
        return result

    def _before_push() -> bool:
        current_status, current_error = _snapshot(root_git, root_home)
        current_staged, staged_error = _staged_paths(root_git, root_home)
        if (
            current_error
            or set(current_status) != (set(changed) - set(eligible))
            or staged_error
            or current_staged
        ):
            return False
        current_sessions = collect_active_session_evidence(root_sessions)
        current_fingerprint = _diff_hash(
            json.dumps(
                current_sessions,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
        )
        if current_fingerprint != session_fingerprint:
            return False
        current_deterministic = classify_dotfile_paths(
            changed, home=root_home, active_sessions=current_sessions, untracked=untracked
        )
        return not any(path in current_deterministic for path in eligible)

    commit_result = _commit_exact_paths(
        eligible,
        git_dir=root_git,
        home=root_home,
        expected_dirty_paths=changed,
        expected_diff_hashes=reviewed_diff_hashes,
        push=push,
        pre_push_check=_before_push,
        new_paths=[path for path in eligible if statuses.get(path) == UNTRACKED_STATUS],
    )
    result = {**base, **commit_result}
    if result.get("status") in {"push_pending", "push_failed", "remote_unverified"}:
        if (
            not isinstance(result.get("pending_push"), Mapping)
            and isinstance(result.get("branch"), str)
            and isinstance(result.get("commit"), str)
        ):
            result["pending_push"] = _pending_push_record(
                result["branch"], result["commit"]
            )
        result.update({
            "phase_status": "failed",
            "phase_failed": True,
            "reason": str(
                result.get("reason")
                or "dotfiles commit was not pushed and requires exact retry"
            )[:2048],
        })
    atomic_write_json(artifact, result)
    print(f"[P9b] {result.get('status')} -> {artifact}")
    return result


__all__ = [name for name in globals() if not name.startswith("__")]
