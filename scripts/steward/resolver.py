"""P7c resolve: try to settle every item that would otherwise land in "Needs You".

Inputs are the P7b routes left ``needs_carter`` (joined to their judge-confirmed
audit findings) plus tracked dotfiles edits that P9b can never stage (paths
outside its allowlist, e.g. ``system-config/``).

Per item, code builds a bounded, deterministic evidence pack (git history of
the paths, the interactive OMP sessions whose tool calls touched them, their
memoirs, deployed rig state where checkable, doc lines, and the exact diff).
Every transcript/memoir/file excerpt passes the deterministic secret scanners
first; an excerpt with a hit is dropped (never redacted-and-sent) and the drop
is recorded.  A ``--no-tools`` model call with the evidence inlined picks one
action from the item class's fixed menu and must cite evidence; atomic Jev Noul
questions then gate it:

* every answer certain >= 0.9 on the "yes" side -> act (commit/revert/doc_fix
  only, within the hard limits below);
* >= 0.6 -> Needs You with the recommendation and one ``steward-approve``
  command;
* lower, a "no" answer, or any Jev/model failure -> unknown (Needs You as
  before, with the evidence summary).

Hard limits live in code: secret scans, private publish globs, paths owned by
an active interactive session, fingerprinted steward source/policy, network/
sudo/systemd paths, deletions, ``patch`` (never autonomous), and at most
``MAX_AUTONOMOUS_ACTIONS`` per night.  A modified canonical rig file under
``system-config/gamingrig-linux/`` that is byte-identical to its deployed copy
(read-only check over the pinned ``gamingrig-linux`` alias, only when P1 saw
the rig on Linux tonight) is committed without any model or Jev judgment.

P7c never fails the run: any error yields a degraded artifact.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import stat
import contextlib
import difflib
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

import jev

from . import dotfiles, public_dotfiles, routing, runtime
from .config import HOME, P7B_REPORT_ONLY_SECTIONS, STEWARD_MODEL
from .runtime import atomic_write_json, run_capture_ok

ARTIFACT = "07c-resolve.json"
APPROVALS = "07c-approvals.jsonl"
SAVED_DIR = "07c-saved"
ACTIONS_JOURNAL = "07c-actions.jsonl"
APPROVE_CLI = "steward-approve"

MAX_ITEMS = 12
MAX_AUTONOMOUS_ACTIONS = 5
ACT_CERTAINTY = 0.9
REVIEW_CERTAINTY = 0.6
PHASE_SECONDS = 1500
MODEL_TIMEOUT = 420
JEV_SECONDS = 180

SESSION_LOOKBACK_DAYS = 30
MAX_SESSIONS_PER_PATH = 4
MAX_CALLS_PER_SESSION = 5
CALL_EXCERPT_CHARS = 700
USER_EXCERPT_CHARS = 500
MEMOIR_EXCERPT_CHARS = 2000
DIFF_BUDGET_CHARS = dotfiles.JEV_MAX_DIFF_CHARS
# Current text of the files an item targets or names, so the model can write an
# exact OLD -> NEW: whole file up to this size, else numbered regions.
FILE_WHOLE_CHARS = 12_000
FILE_SLICE_CHARS = 6_000
MAX_FILES_PER_ITEM = 4
FILE_TOTAL_CHARS = 24_000
DOC_EXCERPT_CHARS = 6000
FINDING_CHARS = 2500
MAX_EVIDENCE_CHARS = 48_000
MAX_JEV_STATE_CHARS = 40_000

RIG_CANONICAL_ROOT = "system-config/gamingrig-linux/"
# Under system-config/ only these user-level rig configs may change autonomously;
# everything else there (root-run helpers, worker policy, units, scripts) is
# recommend-only with an approval command.
RIG_AUTONOMOUS_ROOT = "system-config/gamingrig-linux/config/"
# Canonical -> deployed map for the user-owned rig files (environment.md
# "Canonical inventory and deployment map").  Root-owned netplan/sshd/ufw files
# are deliberately absent: they are never checked or acted on autonomously.
RIG_DEPLOY_MAP = {
    "AGENTS.md": "/home/carte/AGENTS.md",
    ".zshrc": "/home/carte/.zshrc",
    ".zprofile": "/home/carte/.zprofile",
    ".tmux.conf": "/home/carte/.tmux.conf",
    "ssh/config": "/home/carte/.ssh/config",
    "ssh/known_hosts": "/home/carte/.ssh/known_hosts",
    "config/herdr/config.toml": "/home/carte/.config/herdr/config.toml",
    "config/omp/config.yml": "/home/carte/.omp/agent/config.yml",
    "config/omp/models.yml": "/home/carte/.omp/agent/models.yml",
}
RIG_DEPLOY_PREFIXES = {"config/nvim/": "/home/carte/.config/nvim/"}

# Network exposure, sudo, SSH daemon and systemd paths: content is never changed
# autonomously (revert) and they get no rig shortcut.
_INFRA_PATH = re.compile(
    r"(^|/)(ufw[^/]*|netplan|sshd_config\.d|sudoers(\.d)?|systemd|polkit[^/]*)(/|$)"
    r"|\.(service|timer|socket|path|mount)$|ufw-expected-rules",
    re.IGNORECASE,
)
_STEWARD_SOURCE = re.compile(
    r"^scripts/(steward(/|_runner\.py$)|workflow_state\.py$|test_steward|jev\.py$)"
    r"|^system-config/dotfiles-publish"
)

MENUS = {
    "uncommitted": ("commit", "revert", "hold"),
    "drift": ("doc_fix", "patch", "hold"),
    "code": ("patch", "hold"),
    "fyi": ("hold",),
}
AUTONOMOUS_ACTIONS = frozenset({"commit", "revert", "doc_fix"})
ACTION_MEANING = {
    "commit": "commit the exact modified tracked path(s) to the private dotfiles repo as they are now",
    "revert": "restore the tracked path(s) to the committed version, discarding the uncommitted edit",
    "doc_fix": "replace one exact passage in a doc under ~/notes/docs with corrected text",
    "patch": "edit a config/code file (exact OLD -> NEW); only ever applied by Carter's approval command",
    "hold": "do nothing; leave the item for Carter",
}
JEV_PURPOSE = "steward P7c: may the resolver's proposed action proceed?"
JEV_QUESTIONS: dict[str, dict[str, dict[str, str]]] = {
    "commit": {
        "intended": {
            "type": "noul",
            "instructions": (
                "Does the evidence show that the author intended the change in `proposal` "
                "to persist (it is deliberate, deployed, or relied on, not an experiment)?"
            ),
        },
        "complete": {
            "type": "noul",
            "instructions": (
                "Is the change in `proposal` complete and self-consistent rather than a "
                "half-finished edit (no placeholders, unbalanced edits, or debug leftovers)?"
            ),
        },
    },
    "revert": {
        "unwanted": {
            "type": "noul",
            "instructions": (
                "Does the evidence show the change in `proposal` was accidental, an abandoned "
                "experiment, or superseded, so the file should return to its committed version?"
            ),
        },
        "no_loss": {
            "type": "noul",
            "instructions": (
                "Would restoring the committed version lose nothing the author still wants "
                "according to the evidence?"
            ),
        },
    },
    "doc_fix": {
        "supported": {
            "type": "noul",
            "instructions": "Is every fact in the proposed new documentation text supported by the evidence?",
        },
        "doc_is_wrong": {
            "type": "noul",
            "instructions": (
                "Does the evidence show the documentation, not the live system or config, "
                "is what is wrong?"
            ),
        },
        "minimal": {
            "type": "noul",
            "instructions": "Does the proposed edit change only what the finding requires?",
        },
    },
    "patch": {
        "supported": {
            "type": "noul",
            "instructions": "Is the proposed file edit supported by the evidence and the finding?",
        },
        "correct": {
            "type": "noul",
            "instructions": (
                "Is the proposed edit complete and correct for the finding, without "
                "unrelated changes?"
            ),
        },
    },
}


class Unknown(Exception):
    """The resolver cannot decide; the message is a plain reason."""


class SecretHold(Unknown):
    """A secret-scanner hit in what would be sent; the item is held, nothing is sent."""


class PartialAction(Exception):
    """An action mutated state but did not finish (e.g. committed, push failed)."""

    def __init__(self, reason: str, outcome: dict[str, Any]) -> None:
        super().__init__(reason)
        self.outcome = outcome


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _clip(text: Any, limit: int) -> str:
    value = str(text if text is not None else "").replace("\x00", " ")
    return value if len(value) <= limit else value[:limit] + "…"


def secret_reason(text: Any) -> str | None:
    """Deterministic secret scan of arbitrary text, one raw line at a time.

    Uses the strongest shared line scanner (P9b's rules plus P9c's extra rules:
    bearer tokens, JWTs, URL credentials, 32-hex keys, secret URL parameters,
    webhook URLs).  Lines are scanned verbatim, so a line that itself starts
    with ``+`` is never mistaken for a diff header.
    """
    if not text:
        return None
    try:
        for line in str(text).splitlines():
            rule = public_dotfiles._line_finding(line, entropy=True, mac=False)
            if rule:
                return rule
    except Exception as exc:  # a scanner failure is never a pass
        return f"secret scan failed: {type(exc).__name__}"
    return None


def secret_reason_obj(value: Any) -> str | None:
    """Scan every string (keys included) in a JSON-like object before sending it."""
    if isinstance(value, Mapping):
        for key, item in value.items():
            hit = secret_reason(key) or secret_reason_obj(item)
            if hit:
                return hit
        return None
    if isinstance(value, (list, tuple)):
        for item in value:
            hit = secret_reason_obj(item)
            if hit:
                return hit
        return None
    return secret_reason(value) if isinstance(value, str) else None


@contextlib.contextmanager
def _literal_pathspecs():
    """Every git call below (ours, P9b's, P7b's doc route) treats paths literally."""
    previous = os.environ.get("GIT_LITERAL_PATHSPECS")
    os.environ["GIT_LITERAL_PATHSPECS"] = "1"
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("GIT_LITERAL_PATHSPECS", None)
        else:
            os.environ["GIT_LITERAL_PATHSPECS"] = previous


def _home_rel(raw: Any, home: Path, repo: str = "") -> str | None:
    """Home-relative POSIX path for a finding target, or None when outside home."""
    value = str(raw or "").strip().strip("`")
    if not value:
        return None
    value = re.sub(r":\d+(-\d+)?$", "", value)  # drop file:line suffixes
    if value.startswith("~/"):
        path = home / value[2:]
    elif value.startswith("/"):
        path = Path(value)
    else:
        base = Path(repo).expanduser() if repo else home
        if str(base).startswith("~/"):
            base = home / str(base)[2:]
        path = base / value
    try:
        rel = Path(os.path.normpath(path)).relative_to(home)
    except ValueError:
        return None
    text = rel.as_posix()
    if text in ("", ".") or text.startswith("..") or text.split("/")[0] == ".dotfiles-homelab":
        return None
    return text


# ── context ──────────────────────────────────────────────────────────


@dataclass
class ResolveContext:
    run_dir: Path
    dry_run: bool = False
    home: Path = HOME
    git_dir: Path | None = None
    session_root: Path | None = None
    memoir_root: Path | None = None
    doc_roots: tuple[Path, ...] | None = None
    policy_path: Path | None = None
    protected_paths: frozenset[str] = frozenset()
    omp_call: Callable[..., str] | None = None
    jev_client: Any = None
    load_jev: bool = True
    rig_sha256: Callable[[str], str | None] | None = None
    active_sessions: list[dict[str, Any]] | None = None
    push: bool = True
    max_actions: int = MAX_AUTONOMOUS_ACTIONS
    deadline: float | None = None
    now: datetime = field(default_factory=_now)
    output: Path | None = None
    journal_errors: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.run_dir = Path(self.run_dir)
        self.home = Path(self.home)
        self.git_dir = Path(self.git_dir or self.home / ".dotfiles-homelab")
        self.session_root = Path(self.session_root or self.home / ".omp" / "agent" / "sessions")
        self.memoir_root = Path(self.memoir_root or self.home / "notes" / "logs" / "sessions")
        self.doc_roots = tuple(Path(p) for p in (self.doc_roots or (self.home / "notes" / "docs",)))
        self.policy_path = Path(self.policy_path or self.home / public_dotfiles.POLICY_REL)
        if self.deadline is None:
            self.deadline = time.monotonic() + PHASE_SECONDS

    @property
    def run_date(self) -> str:
        return self.run_dir.name

    def call_model(self, prompt: str) -> str:
        call = self.omp_call or runtime._call_omp_p
        remaining = max(30, int((self.deadline or 0) - time.monotonic()))
        return call(
            prompt, model=STEWARD_MODEL, mode="json", tools=runtime.NO_TOOLS,
            timeout=min(MODEL_TIMEOUT, remaining),
        )

    def jev(self) -> Any:
        if self.jev_client is None and self.load_jev:
            self.load_jev = False
            self.jev_client = jev.load_client(deadline=time.monotonic() + JEV_SECONDS)
        return self.jev_client

    def git(self, *args: str, text: bool = True) -> tuple[Any, str, int]:
        return run_capture_ok(
            dotfiles._git_command(self.git_dir, self.home, "--literal-pathspecs", *args), text=text
        )


def _approve_command(run_date: str, item_id: str) -> str:
    return f"{APPROVE_CLI} {run_date} {item_id}"


def _dotfiles_display() -> str:
    return "git --git-dir=$HOME/.dotfiles-homelab --work-tree=$HOME"


# ── items ────────────────────────────────────────────────────────────


@dataclass
class Item:
    id: str
    source: str  # "route" | "dotfiles"
    section: str
    finding_id: str
    klass: str
    paths: list[str]
    claim: str = ""
    finding: dict[str, Any] = field(default_factory=dict)
    statuses: dict[str, str] = field(default_factory=dict)
    resolved_by: str = ""

    def record(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "section": self.section,
            "finding_id": self.finding_id,
            "class": self.klass,
            "paths": list(self.paths),
            "claim": self.claim,
        }


def _item_id(*parts: str) -> str:
    text = "-".join(p for p in parts if p)
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60]
    return slug or "item"


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None


def _audit_findings(audit: Mapping[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for section in (audit or {}).get("sections") or []:
        if not isinstance(section, Mapping):
            continue
        name = str(section.get("name") or "")
        for index, raw in enumerate(routing._confirmed_findings(section), start=1):
            finding = routing.normalize_finding(name, raw, index)
            out[(name, finding["id"])] = finding
    return out


_STATUS_LINE = re.compile(r"^\s*([MADRCU?!]{1,2})\s+(\S.*)$")


def _audit_dirty_paths(run_dir: Path) -> set[str]:
    """Paths the P7 collectors saw modified in the dotfiles repo tonight."""
    seen: set[str] = set()
    for evidence in sorted(run_dir.glob("07-audit-*.json.evidence.json")):
        data = _read_json(evidence)
        status = data.get("dotfiles_status") if isinstance(data, Mapping) else None
        if not isinstance(status, str):
            continue
        for line in status.splitlines():
            match = _STATUS_LINE.match(line)
            if match and "?" not in match.group(1):
                seen.add(match.group(2).strip())
    return seen


def _target_paths(finding: Mapping[str, Any], home: Path) -> list[str]:
    target = finding.get("target") if isinstance(finding.get("target"), Mapping) else {}
    raw: list[Any] = []
    for key in ("paths", "path", "doc", "file"):
        value = target.get(key)
        if isinstance(value, str):
            raw.append(value)
        elif isinstance(value, list):
            raw.extend(value)
    repo = str(target.get("repo") or "")
    out: list[str] = []
    for value in raw:
        rel = _home_rel(value, home, repo)
        if rel and rel not in out:
            out.append(rel)
    return out


def _entries(rel: str, statuses: Mapping[str, str]) -> dict[str, str]:
    """Status-map entries for a path: the path itself or anything below it."""
    prefix = rel.rstrip("/") + "/"
    return {p: c for p, c in statuses.items() if p == rel or p.startswith(prefix)}


def _classify(section: str, paths: list[str], statuses: Mapping[str, str],
              audit_dirty: set[str]) -> tuple[str, list[str], bool]:
    """Class, paths, and whether the item is already resolved.

    Tracked states (modified, deleted, staged, conflicted) of a path or of files
    below a directory path make the item ``uncommitted`` (on those exact files).
    Untracked entries are never clean: such an item is not resolved and keeps
    its drift/code class (a fix is usually an ignore rule or a doc edit).  Only
    a path with no status entry at all counts as resolved.
    """
    tracked = [p for rel in paths for p, c in _entries(rel, statuses).items() if c != "??"]
    if tracked:
        return "uncommitted", list(dict.fromkeys(tracked)), False
    untracked = {rel for rel in paths if _entries(rel, statuses)}
    if section in P7B_REPORT_ONLY_SECTIONS:
        return "fyi", paths, False
    seen_dirty = [p for p in paths if p in audit_dirty and p not in untracked]
    if seen_dirty and not untracked:
        return "uncommitted", seen_dirty, True
    if any(p.startswith(("scripts/", "system-config/", ".local/bin/", ".config/")) for p in paths):
        return "code", paths, False
    return "drift", paths, False


def collect_items(ctx: ResolveContext, statuses: Mapping[str, str]) -> list[Item]:
    run_dir = ctx.run_dir
    fixes = _read_json(run_dir / "07b-fixes.json") or {}
    audit = _read_json(run_dir / "07-audit.json") or {}
    findings = _audit_findings(audit)
    audit_dirty = _audit_dirty_paths(run_dir)
    items: list[Item] = []
    covered: set[str] = set()
    for row in fixes.get("routes") or []:
        if not isinstance(row, Mapping) or row.get("status") != "needs_carter":
            continue
        section = str(row.get("section") or "")
        finding_id = str(row.get("finding_id") or "")
        finding = dict(findings.get((section, finding_id)) or {})
        finding.setdefault("claim", str(row.get("claim") or ""))
        finding.setdefault("decision", str(row.get("decision") or ""))
        finding["route_detail"] = str(row.get("detail") or "")
        paths = _target_paths(finding, ctx.home)
        klass, paths, resolved = _classify(section, paths, statuses, audit_dirty)
        item = Item(
            id=_item_id(section, finding_id), source="route", section=section,
            finding_id=finding_id, klass=klass, paths=paths,
            claim=str(row.get("claim") or finding.get("claim") or ""), finding=finding,
            statuses={p: statuses.get(p, "") for p in paths} if klass == "uncommitted" else {
                p: ", ".join(f"{c.strip() or c} {q}" for q, c in _entries(p, statuses).items())
                for p in paths if _entries(p, statuses)
            },
        )
        if resolved:
            item.resolved_by = "clean"
        covered.update(paths)
        items.append(item)
    # P9b never stages tracked edits outside its allowlist; they would wait forever.
    for path, code in sorted(statuses.items()):
        if code not in dotfiles.COMMITTABLE_STATUS or path in covered:
            continue
        if dotfiles._path_in_allowed_scope(path, ctx.home):
            continue
        items.append(Item(
            id=_item_id("dotfiles", path), source="dotfiles", section="dotfiles",
            finding_id=path, klass="uncommitted", paths=[path],
            claim=f"Tracked edit to {path} is outside P9b's auto-commit allowlist and stays uncommitted.",
            statuses={path: code},
        ))
    seen: set[str] = set()
    unique = []
    for item in items:
        base, n = item.id, 2
        while item.id in seen:
            item.id = f"{base}-{n}"
            n += 1
        seen.add(item.id)
        unique.append(item)
    return unique


# ── evidence ─────────────────────────────────────────────────────────


@dataclass
class Evidence:
    entries: list[dict[str, str]] = field(default_factory=list)
    dropped: list[dict[str, str]] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    size: int = 0

    def add(self, kind: str, source: str, text: str, limit: int) -> str | None:
        text = str(text or "").strip()
        if not text:
            return None
        reason = secret_reason(source) or secret_reason(text)
        if reason:
            shown = "[source withheld: secret scan hit]" if secret_reason(source) else source
            self.dropped.append({"kind": kind, "source": shown, "reason": reason})
            return None
        text = _clip(text, limit)
        if self.size + len(text) > MAX_EVIDENCE_CHARS:
            self.dropped.append({"kind": kind, "source": source, "reason": "evidence budget exhausted"})
            return None
        label = f"E{len(self.entries) + 1}"
        self.entries.append({"label": label, "kind": kind, "source": source, "text": text})
        self.size += len(text)
        return label

    def labels(self) -> set[str]:
        return {entry["label"] for entry in self.entries}

    def summary(self) -> list[dict[str, str]]:
        return [{"label": e["label"], "kind": e["kind"], "source": e["source"]} for e in self.entries]


def _git_log(ctx: ResolveContext, rel: str, limit: int = 6) -> str:
    fmt = ["log", f"-n{limit}", f"--until={ctx.now.isoformat()}", "--date=iso-strict",
           "--format=%h %ad %s", "--"]
    if rel.startswith("notes/"):
        notes = ctx.home / "notes"
        stdout, _, code = run_capture_ok(["git", "--literal-pathspecs", "-C", str(notes), *fmt,
                                          rel[len("notes/"):]])
    else:
        stdout, _, code = ctx.git(*fmt, rel)
    return stdout.strip() if code == 0 else ""


def _last_commit_epoch(ctx: ResolveContext, rel: str) -> float | None:
    stdout, _, code = ctx.git("log", "-n1", "--format=%ct", "--", rel)
    try:
        return float(stdout.strip()) if code == 0 and stdout.strip() else None
    except ValueError:
        return None


def _session_id_for(path: Path, root: Path) -> str:
    for part in [path.stem, *[p.name for p in path.parents]]:
        match = re.search(r"_([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$", part)
        if match:
            return match.group(1)
        if Path(part) == root:
            break
    return path.stem


def _message_text(message: Mapping[str, Any]) -> str:
    return dotfiles._message_text(message)


def scan_sessions(ctx: ResolveContext, paths: Iterable[str]) -> dict[str, list[dict[str, Any]]]:
    """Tool calls in interactive transcripts that name each path, newest first.

    Only lines containing a path string are parsed (the transcripts are large);
    each hit keeps the tool name, intent, bounded arguments, and the latest user
    text before it in the same transcript.
    """
    home = ctx.home
    needles: dict[str, str] = {}
    since: dict[str, float] = {}
    horizon = ctx.now.timestamp() - SESSION_LOOKBACK_DAYS * 86400
    for rel in paths:
        needles[rel] = rel
        needles[str(home / rel)] = rel
        committed = _last_commit_epoch(ctx, rel)
        since[rel] = max(horizon, (committed or horizon) - 86400)
    hits: dict[str, list[dict[str, Any]]] = {rel: [] for rel in since}
    if not needles or not ctx.session_root.is_dir():
        return hits
    floor = min(since.values())
    try:
        files = [p for p in ctx.session_root.rglob("*.jsonl") if p.is_file()]
    except OSError:
        return hits
    for path in files:
        try:
            if path.stat().st_mtime < floor:
                continue
        except OSError:
            continue
        session_id = _session_id_for(path, ctx.session_root)
        title = ""
        last_user = ""
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    compact = line[:400].replace('": "', '":"')
                    if not title and '"type":"session"' in compact[:200]:
                        try:
                            title = str(json.loads(line).get("title") or "")
                        except ValueError:
                            pass
                    if '"role":"user"' in compact:
                        try:
                            msg = json.loads(line).get("message") or {}
                        except (ValueError, AttributeError):
                            msg = {}
                        if isinstance(msg, Mapping) and msg.get("role") == "user":
                            text = _message_text(msg).strip()
                            if text:
                                last_user = text
                            continue
                    matched = [rel for needle, rel in needles.items() if needle in line]
                    if not matched or '"toolCall"' not in line:
                        continue
                    try:
                        item = json.loads(line)
                    except ValueError:
                        continue
                    msg = item.get("message") if isinstance(item, Mapping) else None
                    content = msg.get("content") if isinstance(msg, Mapping) else None
                    if not isinstance(content, list):
                        continue
                    stamp = str(item.get("timestamp") or "")
                    try:
                        epoch = datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
                    except ValueError:
                        epoch = path.stat().st_mtime
                    for part in content:
                        if not isinstance(part, Mapping) or part.get("type") != "toolCall":
                            continue
                        args = part.get("arguments")
                        rendered = json.dumps(args, ensure_ascii=False)
                        for rel in dict.fromkeys(matched):
                            if rel not in rendered and str(home / rel) not in rendered:
                                continue
                            if epoch < since[rel] or epoch > ctx.now.timestamp():
                                continue
                            intent = args.get("i") if isinstance(args, Mapping) else ""
                            hits[rel].append({
                                "session_file": str(path),
                                "session_id": session_id,
                                "title": _clip(title, 160),
                                "timestamp": stamp,
                                "epoch": epoch,
                                "tool": str(part.get("name") or ""),
                                "intent": _clip(intent, 200),
                                "arguments": _clip(rendered, CALL_EXCERPT_CHARS),
                                "user": _clip(last_user, USER_EXCERPT_CHARS),
                            })
        except OSError:
            continue
    for rel, rows in hits.items():
        rows.sort(key=lambda r: r["epoch"], reverse=True)
    return hits


_MUTATING_TOOLS = ("edit", "write", "ast_edit", "bash", "eval")


def _memoir_index(root: Path) -> dict[str, Path]:
    index: dict[str, Path] = {}
    if not root.is_dir():
        return index
    for memoir in sorted(root.glob("*/*.md")):
        try:
            with memoir.open("r", encoding="utf-8", errors="replace") as handle:
                head = handle.read(1200)
        except OSError:
            continue
        match = re.search(r"^session_id:\s*(\S+)", head, re.MULTILINE)
        if match:
            index[match.group(1)] = memoir
    return index


_PATH_MENTION = re.compile(
    r"(?<![\w/.-])((?:~/|/home/[a-z]+/)?(?:\.?[\w-]+/)*\.?[\w.-]*\.[A-Za-z][\w]*|~/\.[\w.-]+)(?::(\d+)(?:-(\d+))?)?"
)


def _mentioned_files(ctx: ResolveContext, item: Item) -> dict[str, list[int]]:
    """Home-relative existing files the item targets or names, with cited line numbers."""
    finding = item.finding
    target = finding.get("target") if isinstance(finding.get("target"), Mapping) else {}
    repo = str(target.get("repo") or "")
    out: dict[str, list[int]] = {}
    for rel in item.paths:
        out.setdefault(rel, [])
    text = " ".join(str(finding.get(k) or "") for k in ("claim", "fix", "decision", "evidence"))
    text += " " + item.claim
    for match in _PATH_MENTION.finditer(text):
        raw, start, end = match.group(1), match.group(2), match.group(3)
        for base in (repo, ""):
            rel = _home_rel(raw, ctx.home, base)
            if rel and (ctx.home / rel).is_file():
                lines = out.setdefault(rel, [])
                if start:
                    lines.extend(range(int(start), int(end or start) + 1)[:40])
                break
    return {rel: lines for rel, lines in out.items() if (ctx.home / rel).is_file()}


def _file_slice(path: Path, finding: Mapping[str, Any], lines_cited: Iterable[int]) -> str:
    """Current text with line numbers: whole file if small, else regions around cited
    lines and the finding's key terms (bounded)."""
    try:
        if path.is_symlink() or path.stat().st_size > 4 * 1024 * 1024:
            return ""
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return ""
    lines = text.splitlines()
    number = lambda idx: f"{idx + 1}: {lines[idx]}"  # noqa: E731
    if len(text) <= FILE_WHOLE_CHARS:
        return "\n".join(number(i) for i in range(len(lines)))
    haystack = " ".join(str(finding.get(k) or "") for k in ("claim", "fix", "evidence", "decision"))
    terms = re.findall(r"`([^`\n]{3,60})`", haystack)
    terms += re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*_[A-Za-z0-9_]+|[a-z]+[A-Z]\w+)\b", haystack)
    wanted: set[int] = {n - 1 for n in lines_cited if 0 < n <= len(lines)}
    for term in dict.fromkeys(t.strip() for t in terms):
        key = term.split(".")[-1].split("(")[0]
        if len(key) < 4:
            continue
        hits = [i for i, line in enumerate(lines) if key in line][:3]
        wanted.update(hits)
    if not wanted:
        wanted = {0}
    keep: set[int] = set()
    for index in sorted(wanted):
        keep.update(range(max(0, index - 8), min(len(lines), index + 25)))
    out, previous = [], None
    for index in sorted(keep):
        if previous is not None and index != previous + 1:
            out.append("…")
        out.append(number(index))
        previous = index
    return _clip("\n".join(out), FILE_SLICE_CHARS)


def _path_state(ctx: ResolveContext, rel: str) -> str:
    """Git state of a path (or below it) incl. untracked and ignored entries, labelled."""
    stdout, stderr, code = ctx.git("status", "--porcelain=v1", "--ignored", "--untracked-files=all",
                                   "--", rel)
    if code != 0:
        return f"unknown (git status failed: {_clip(stderr, 120)})"
    labels = {"??": "untracked", "!!": "ignored"}
    rows = [line for line in stdout.splitlines() if line.strip()]
    if not rows:
        exists = (ctx.home / rel).exists()
        return "clean (tracked, unmodified)" if exists else "absent"
    shown = [f"{labels.get(r[:2], 'status ' + repr(r[:2]))}: {r[3:]}" for r in rows[:12]]
    if len(rows) > 12:
        shown.append(f"... {len(rows) - 12} more")
    return "; ".join(shown)


def _doc_lines(ctx: ResolveContext, paths: list[str], finding: Mapping[str, Any]) -> list[tuple[str, str]]:
    """(source, text) doc excerpts: the finding's target doc/old text, else docs naming the paths."""
    out: list[tuple[str, str]] = []
    target = finding.get("target") if isinstance(finding.get("target"), Mapping) else {}
    doc = _home_rel(target.get("doc"), ctx.home) if target else None
    if doc:
        try:
            text = (ctx.home / doc).read_text(encoding="utf-8")
            old = str(target.get("old_text") or "")
            at = text.find(old) if old else -1
            if at >= 0:
                text = text[max(0, at - 1500): at + len(old) + 1500]
            out.append((doc, _clip(text, DOC_EXCERPT_CHARS)))
        except (OSError, UnicodeError):
            pass
    tails = []
    for rel in paths:
        parts = rel.split("/")
        tails.append("/".join(parts[-2:]) if len(parts) > 1 else rel)
    if not tails:
        return out
    for root in ctx.doc_roots:
        if not root.is_dir():
            continue
        for md in sorted(root.rglob("*.md")):
            try:
                lines = md.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeError):
                continue
            hits = [f"{n + 1}: {line}" for n, line in enumerate(lines) if any(t in line for t in tails)]
            if hits:
                out.append((str(md.relative_to(ctx.home)) if md.is_relative_to(ctx.home) else str(md),
                            "\n".join(hits[:8])))
            if len(out) >= 6:
                return out
    return out


def build_evidence(ctx: ResolveContext, item: Item, sessions: Mapping[str, list[dict[str, Any]]],
                   memoirs: Mapping[str, Path], diffs: Mapping[str, str],
                   deployed: Mapping[str, str]) -> Evidence:
    ev = Evidence()
    finding = item.finding
    if finding:
        text = "\n".join(
            f"{key}: {finding.get(key)}" for key in ("claim", "evidence", "fix", "decision")
            if finding.get(key)
        )
        ev.add("finding", f"{item.section} {item.finding_id} (P7 audit, run {ctx.run_date})", text, FINDING_CHARS)
    ev.facts["run_date"] = ctx.run_date
    for rel in item.paths:
        ev.facts.setdefault("status", {})[rel] = _path_state(ctx, rel)
    if item.klass in ("code", "drift"):
        total = 0
        for rel, cited in list(_mentioned_files(ctx, item).items())[:MAX_FILES_PER_ITEM]:
            excerpt = _file_slice(ctx.home / rel, finding, cited)
            if not excerpt or total + len(excerpt) > FILE_TOTAL_CHARS:
                continue
            if ev.add("file", f"current ~/{rel} (line-numbered)", excerpt, FILE_WHOLE_CHARS):
                total += len(excerpt)
    for rel in item.paths:
        log = _git_log(ctx, rel)
        if log:
            ev.add("git_log", f"git log {rel}", log, 1200)
        if rel in diffs:
            ev.add("diff", f"uncommitted diff of {rel} vs HEAD", diffs[rel], DIFF_BUDGET_CHARS)
        if rel in deployed:
            ev.add("deployed", f"deployed rig copy of {rel}", deployed[rel], 400)
        calls = sessions.get(rel) or []
        calls = sorted(calls, key=lambda c: (c["tool"] not in _MUTATING_TOOLS, -c["epoch"]))
        by_session: dict[str, list[dict[str, Any]]] = {}
        for call in calls:
            by_session.setdefault(call["session_id"], []).append(call)
        for session_id in list(by_session)[:MAX_SESSIONS_PER_PATH]:
            rows = by_session[session_id][:MAX_CALLS_PER_SESSION]
            source = f"session {session_id} ({rows[0]['title'] or Path(rows[0]['session_file']).name})"
            for call in rows:
                ev.add("session_user", f"{source} user text before {call['timestamp']}", call["user"],
                       USER_EXCERPT_CHARS)
                ev.add("session_call", f"{source} {call['tool']} at {call['timestamp']}",
                       f"intent: {call['intent']}\narguments: {call['arguments']}", CALL_EXCERPT_CHARS + 250)
            memoir = memoirs.get(session_id)
            if memoir is not None:
                try:
                    body = memoir.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    body = ""
                ev.add("memoir", f"memoir {memoir.relative_to(ctx.memoir_root) if memoir.is_relative_to(ctx.memoir_root) else memoir}",
                       body, MEMOIR_EXCERPT_CHARS)
        ev.facts.setdefault("sessions", {})[rel] = len(by_session)
    for source, text in _doc_lines(ctx, item.paths, finding):
        ev.add("doc", source, text, DOC_EXCERPT_CHARS)
    return ev


# ── hard limits ──────────────────────────────────────────────────────


def _load_private_policy(ctx: ResolveContext) -> Callable[[str], bool]:
    try:
        policy = public_dotfiles.load_policy(ctx.policy_path)
    except Exception:
        return lambda _path: True  # unreadable policy: everything is private (fail closed)
    return policy.is_private


def _active_owner(ctx: ResolveContext, rel: str, sessions: list[dict[str, Any]]) -> str | None:
    for session in sessions:
        if session.get("malformed"):
            return "recent session evidence is malformed"
        if dotfiles._session_mentions_path(session, rel, ctx.home):
            return f"active interactive session {session.get('session_id') or '?'} touches {rel}"
    return None


def _protected(ctx: ResolveContext, rel: str) -> bool:
    absolute = str((ctx.home / rel).resolve())
    return bool(_STEWARD_SOURCE.search(rel)) or absolute in ctx.protected_paths or str(ctx.home / rel) in ctx.protected_paths


def _autonomy_block(ctx: ResolveContext, rel: str) -> str | None:
    """Why an autonomous commit/revert of ``rel`` is not allowed (None = allowed)."""
    if _protected(ctx, rel):
        return f"{rel} is fingerprinted steward source or policy; approval only"
    if _INFRA_PATH.search(rel):
        return f"{rel} is a network, sudo, SSH-daemon or systemd path; approval only"
    if rel.startswith("system-config/") and not rel.startswith(RIG_AUTONOMOUS_ROOT):
        return (f"{rel}: under system-config/ only gamingrig-linux/config/** changes "
                "autonomously; approval only")
    return None


def _rig_deploy_target(rel: str) -> str | None:
    if not rel.startswith(RIG_CANONICAL_ROOT):
        return None
    tail = rel[len(RIG_CANONICAL_ROOT):]
    if tail in RIG_DEPLOY_MAP:
        return RIG_DEPLOY_MAP[tail]
    for prefix, dest in RIG_DEPLOY_PREFIXES.items():
        if tail.startswith(prefix) and ".." not in tail.split("/"):
            return dest + tail[len(prefix):]
    return None


def _rig_linux_tonight(run_dir: Path) -> bool:
    applied = _read_json(run_dir / "01-applied.json") or {}
    for step in applied.get("steps") or []:
        if isinstance(step, Mapping) and step.get("step") == "gamingrig_maintenance":
            probes = [s for s in step.get("substeps") or [] if isinstance(s, Mapping)
                      and s.get("step") == "platform_probe"]
            return step.get("os") == "Linux" and any(p.get("status") == "ok" for p in probes)
    return False


def _rig_sha256_over_ssh(dest: str) -> str | None:
    """Read-only sha256 of one deployed file via the pinned alias (fails closed)."""
    from . import updates  # local import: updates is large and only needed here

    stdout, _, code = updates._rig_ssh(["sha256sum", "--", dest], timeout=30)
    match = re.match(r"^([0-9a-f]{64})\s", stdout or "")
    return match.group(1) if code == 0 and match else None


# ── decision ─────────────────────────────────────────────────────────


def _decision_prompt(item: Item, ev: Evidence, menu: tuple[str, ...]) -> str:
    evidence = "\n\n".join(
        f"[{e['label']}] ({e['kind']}; {e['source']})\n{e['text']}" for e in ev.entries
    )
    options = "\n".join(f"- {name}: {ACTION_MEANING[name]}" for name in menu)
    extra = ""
    if "doc_fix" in menu:
        extra += (
            '\nFor doc_fix also return "doc_edit": {"doc": "<path under ~/notes/docs>", '
            '"old_text": "<exact current text, occurring once>", "new_text": "<replacement>"}.'
        )
    if "patch" in menu:
        extra += (
            '\nFor patch also return "patch": {"path": "<~/ path of the file>", '
            '"old_text": "<exact current text, occurring once>", "new_text": "<replacement>"}.'
        )
    return (
        "You are the homelab steward's resolver. This item sits in Carter's 'Needs You' list "
        "only because no automatic route exists for it. Pick exactly ONE action from the fixed "
        "menu: the one the evidence shows Carter would approve. Use ONLY the evidence given (you "
        "have no tools). Code, not you, enforces safety and executes, Carter can undo every "
        "action, and Jev independently checks your choice. Choose hold when the evidence does "
        "not support another action, or when it shows the problem is already fixed.\n\n"
        f"Run date: {ev.facts.get('run_date')}\nItem class: {item.klass}\n"
        f"Claim: {item.claim}\nPaths: {', '.join(item.paths) or '(none)'}\n"
        f"Path status now: {json.dumps(ev.facts.get('status', {}))}\n\n"
        f"Menu:\n{options}\n\nEvidence:\n{evidence or '(none)'}\n\n"
        "Return ONLY this JSON:\n```json\n"
        '{"action": "<menu item>", "rationale": "<two sentences>", '
        '"citations": ["E1", "..."], "already_fixed": false}\n```'
        f"{extra}\nCitations must name evidence labels that support the choice. File excerpts "
        "prefix each line with 'N: ' (its line number); that prefix is not part of the file, so "
        "never include it in old_text/new_text. Path status 'untracked' or 'ignored' entries are "
        "real files on disk, not a clean path."
    )


def _exact_edit(raw: Any, ctx: ResolveContext, *, doc: bool, is_private: Callable[[str], bool]) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise Unknown("the proposal gives no edit")
    rel = _home_rel(raw.get("doc") if doc else raw.get("path"), ctx.home)
    if not rel:
        raise Unknown("the proposed edit names no file under home")
    path = ctx.home / rel
    if doc and not any(path.resolve().is_relative_to(r.resolve()) for r in ctx.doc_roots):
        raise Unknown(f"{rel} is outside the doc roots")
    if is_private(rel) or dotfiles._is_sensitive(rel):
        raise Unknown(f"{rel} is private or credential-like")
    old, new = raw.get("old_text"), raw.get("new_text")
    if not isinstance(old, str) or not old or not isinstance(new, str) or new == old:
        raise Unknown("the proposed edit needs exact, different old and new text")
    try:
        if path.is_symlink() or not path.is_file():
            raise Unknown(f"{rel} is not a regular file")
        data = path.read_bytes()
        content = data.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise Unknown(f"{rel} is unreadable: {exc}") from None
    if content.count(old) != 1:
        raise Unknown(f"the old text occurs {content.count(old)} times in {rel}; it must occur once")
    hit = secret_reason(new)
    if hit:
        raise Unknown(f"the proposed text failed the secret scan ({hit})")
    return {"path": rel, "old_text": old, "new_text": new, "file_sha256": _sha256(data)}


def decide(ctx: ResolveContext, item: Item, ev: Evidence, menu: tuple[str, ...],
           is_private: Callable[[str], bool]) -> dict[str, Any]:
    prompt = _decision_prompt(item, ev, menu)
    hit = secret_reason(prompt)
    if hit:
        raise SecretHold(f"the assembled model prompt failed the secret scan ({hit}); nothing was sent")
    try:
        packet = runtime._extract_json(ctx.call_model(prompt), label="resolver decision")
    except Exception as exc:
        raise Unknown(f"resolver model failed: {_clip(exc, 200)}") from None
    if not isinstance(packet, Mapping):
        raise Unknown("resolver model returned no JSON object")
    action = str(packet.get("action") or "").strip().lower()
    if action not in menu:
        raise Unknown(f"resolver model chose {action!r}, which is not on the {item.klass} menu")
    citations = [str(c).strip() for c in packet.get("citations") or [] if str(c).strip()]
    known = ev.labels()
    if action != "hold" and (not citations or any(c not in known for c in citations)):
        raise Unknown("resolver model did not cite existing evidence")
    decision: dict[str, Any] = {
        "action": action,
        "rationale": _clip(packet.get("rationale"), 600),
        "citations": citations,
        "already_fixed": packet.get("already_fixed") is True,
    }
    if action == "doc_fix":
        decision["edit"] = _exact_edit(packet.get("doc_edit"), ctx, doc=True, is_private=is_private)
    elif action == "patch":
        decision["edit"] = _exact_edit(packet.get("patch"), ctx, doc=False, is_private=is_private)
    return decision


def _jev_state(item: Item, ev: Evidence, decision: Mapping[str, Any], diffs: Mapping[str, str]) -> dict[str, Any]:
    action = decision["action"]
    if action in ("commit", "revert"):
        proposal: Any = {rel: diffs.get(rel, "") for rel in item.paths}
    else:
        edit = decision.get("edit") or {}
        proposal = {"file": edit.get("path"), "old_text": edit.get("old_text"), "new_text": edit.get("new_text")}
    return {
        "item_class": item.klass,
        "claim": item.claim,
        "proposed_action": action,
        "action_meaning": ACTION_MEANING[action],
        "proposal": proposal,
        "resolver_rationale": decision.get("rationale", ""),
        "evidence": [f"[{e['label']}] ({e['kind']}; {e['source']}) {e['text']}" for e in ev.entries
                     if not decision.get("citations") or e["label"] in decision["citations"]],
    }


def jev_gate(ctx: ResolveContext, state: Mapping[str, Any], action: str) -> dict[str, Any]:
    """Ask the action's atomic questions; return tier + per-question p (never raises)."""
    questions = JEV_QUESTIONS[action]
    hit = secret_reason_obj(state)
    if hit:
        return {"tier": "unknown", "certainty": 0.0, "secret_hold": True,
                "reason": f"the Jev state failed the secret scan ({hit}); nothing was sent"}
    rendered = json.dumps(state, ensure_ascii=False, sort_keys=True)
    if len(rendered) > MAX_JEV_STATE_CHARS:
        return {"tier": "unknown", "certainty": 0.0, "reason": "evidence exceeds the Jev budget"}
    client = ctx.jev()
    if client is None:
        return {"tier": "unknown", "certainty": 0.0, "reason": "Jev unavailable (no_key)"}
    try:
        answers = client.ask(JEV_PURPOSE, dict(state), questions)
    except jev.JevUnavailable as exc:
        return {"tier": "unknown", "certainty": 0.0, "reason": f"Jev unavailable ({exc.reason})"}
    except Exception as exc:
        return {"tier": "unknown", "certainty": 0.0, "reason": f"Jev failed ({type(exc).__name__})"}
    probabilities: dict[str, float] = {}
    certainty = 1.0
    for key in questions:
        try:
            p = float(answers[key]["noul"])
        except (KeyError, TypeError, ValueError):
            return {"tier": "unknown", "certainty": 0.0, "reason": f"Jev answer {key} missing"}
        probabilities[key] = round(p, 4)
        certainty = min(certainty, jev.noul_certainty(p) if p > 0.5 else 0.0)
    tier = "act" if certainty >= ACT_CERTAINTY else "recommend" if certainty >= REVIEW_CERTAINTY else "unknown"
    reason = "" if tier != "unknown" else (
        "Jev answered no to " + ", ".join(k for k, p in probabilities.items() if p <= 0.5)
        if any(p <= 0.5 for p in probabilities.values()) else f"Jev certainty {certainty:.2f} is below {REVIEW_CERTAINTY}"
    )
    return {"tier": tier, "certainty": round(certainty, 4), "answers": probabilities, "reason": reason}


# ── execution ────────────────────────────────────────────────────────


def _snapshot(ctx: ResolveContext) -> dict[str, str]:
    statuses, error = dotfiles._snapshot(ctx.git_dir, ctx.home)
    if error:
        raise RuntimeError(f"dotfiles status failed: {_clip(error, 300)}")
    return statuses


def _path_hashes(ctx: ResolveContext, paths: Iterable[str]) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for rel in paths:
        diff = dotfiles.exact_path_diff(rel, git_dir=ctx.git_dir, home=ctx.home)
        try:
            content = _sha256((ctx.home / rel).read_bytes())
        except OSError:
            content = "missing"
        out[rel] = {"diff_sha256": dotfiles._diff_hash(diff), "content_sha256": content}
    return out


def _check_hashes(ctx: ResolveContext, recorded: Mapping[str, Mapping[str, str]]) -> None:
    current = _path_hashes(ctx, recorded)
    for rel, want in recorded.items():
        if current.get(rel) != dict(want):
            raise Unknown(f"{rel} changed since it was judged")


def execute_commit(ctx: ResolveContext, item_id: str, hashes: Mapping[str, Mapping[str, str]],
                   message: str) -> dict[str, Any]:
    paths = sorted(hashes)
    statuses = _snapshot(ctx)
    if any(statuses.get(p) != " M" for p in paths):
        raise Unknown("the paths are no longer plain tracked modifications")
    _check_hashes(ctx, hashes)
    for rel in paths:
        diff = dotfiles.exact_path_diff(rel, git_dir=ctx.git_dir, home=ctx.home)
        hit = dotfiles._sensitive_diff_reason(diff) or secret_reason(diff)
        if hit:
            raise Unknown(f"{rel}: {hit}")
    result = dotfiles._commit_exact_paths(
        paths, git_dir=ctx.git_dir, home=ctx.home,
        expected_dirty_paths=set(statuses),
        expected_diff_hashes={p: hashes[p]["diff_sha256"] for p in paths},
        push=ctx.push, message=message,
    )
    status = result.get("status")
    sha = str(result.get("commit") or "")
    if status != "committed" and sha:
        # Committed locally but not (verifiably) pushed: report the partial state.
        raise PartialAction(
            f"commit {sha[:8]} was made locally but not pushed ({status}: "
            f"{_clip(result.get('reason'), 200)})",
            {"commit": sha, "undo": f"{_dotfiles_display()} revert --no-edit {sha}"},
        )
    if status != "committed":
        raise RuntimeError(f"commit {status}: {_clip(result.get('reason') or result.get('findings'), 300)}")
    sha = str(result.get("commit") or "")
    return {
        "commit": sha,
        "push": result.get("push", ""),
        "undo": f"{_dotfiles_display()} revert --no-edit {sha} && {_dotfiles_display()} push origin HEAD",
        "summary": f"Committed {', '.join(paths)} to the private dotfiles repo ({sha[:8]}).",
    }


def execute_revert(ctx: ResolveContext, item_id: str, hashes: Mapping[str, Mapping[str, str]]) -> dict[str, Any]:
    paths = sorted(hashes)
    statuses = _snapshot(ctx)
    if any(statuses.get(p) != " M" for p in paths):
        raise Unknown("the paths are no longer plain tracked modifications")
    _check_hashes(ctx, hashes)
    saved_root = ctx.run_dir / SAVED_DIR / item_id
    undo = []
    for rel in paths:
        source = ctx.home / rel
        data = source.read_bytes()
        mode = stat.S_IMODE(source.stat().st_mode)
        target = saved_root / rel
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        undo.append(f"install -m {mode:o} {shlex.quote(str(target))} {shlex.quote(str(source))}")
    reverted: list[str] = []
    try:
        for rel in paths:
            _, stderr, code = ctx.git("checkout", "HEAD", "--", rel)
            if code != 0:
                raise RuntimeError(f"git checkout {rel} failed: {_clip(stderr, 300)}")
            reverted.append(rel)
        after = _snapshot(ctx)
        if any(p in after for p in paths):
            raise RuntimeError("revert left the paths modified")
    except Exception as exc:
        # Backups of every path exist; restoring an unreverted path from its
        # backup is a no-op, so the full undo is always safe to run.
        raise PartialAction(
            f"revert stopped after {len(reverted)} of {len(paths)} path(s) "
            f"({', '.join(reverted) or 'none'} reverted): {_clip(exc, 300)}",
            {"undo": " && ".join(undo), "saved": str(saved_root), "reverted_paths": reverted},
        ) from None
    return {
        "undo": " && ".join(undo),
        "saved": str(saved_root),
        "summary": f"Reverted {', '.join(paths)} to the committed version; the discarded edit is saved in {saved_root}.",
    }


def execute_doc_fix(ctx: ResolveContext, item: Item, edit: Mapping[str, Any]) -> dict[str, Any]:
    doc = ctx.home / edit["path"]
    try:
        data = doc.read_bytes()
    except OSError as exc:
        raise Unknown(f"cannot read {edit['path']}: {exc}") from None
    if _sha256(data) != edit["file_sha256"]:
        raise Unknown(f"{edit['path']} changed since it was judged")
    # routing.execute_doc_fix sends the finding text and a unified diff of the
    # doc (default 3 context lines) to the re-check model: scan exactly that.
    try:
        doc_text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Unknown(f"{edit['path']} is not UTF-8 text") from None
    recheck_diff = "".join(difflib.unified_diff(
        doc_text.splitlines(keepends=True),
        doc_text.replace(edit["old_text"], edit["new_text"], 1).splitlines(keepends=True),
    ))
    outgoing = {
        "section": item.section, "id": item.finding_id or item.id, "claim": item.claim,
        "evidence": item.finding.get("evidence", ""), "fix": item.finding.get("fix", ""),
        "doc": str(doc), "diff": recheck_diff,
    }
    hit = secret_reason_obj(outgoing)
    if hit:
        raise SecretHold(f"the doc-fix re-check input failed the secret scan ({hit}); nothing was sent")
    finding = routing.normalize_finding(item.section, {
        "id": item.finding_id or item.id,
        "claim": item.claim,
        "evidence": item.finding.get("evidence", ""),
        "fix": item.finding.get("fix", ""),
        "action": "doc_fix",
        "severity": item.finding.get("severity", ""),
        "target": {"doc": str(doc), "old_text": edit["old_text"], "new_text": edit["new_text"]},
    })
    route_ctx = routing.RouteContext(
        dry_run=False, run_dir=ctx.run_dir, home=ctx.home,
        doc_roots=tuple(ctx.doc_roots), doc_files=(), omp_call=ctx.omp_call,
    )
    row = routing.execute_doc_fix(item.section, finding, route_ctx)
    if row.get("status") != "done":
        detail = _clip(row.get("detail") or row.get("summary") or "doc fix not kept", 400)
        if row.get("commit"):
            raise PartialAction(f"doc fix committed but not pushed: {detail}",
                                {"commit": row.get("commit", ""), "undo": row.get("revert", "")})
        raise RuntimeError(detail)
    return {"commit": row.get("commit", ""), "undo": row.get("revert", ""), "summary": row.get("summary", "")}


# ── phase ────────────────────────────────────────────────────────────


def _journal(ctx: ResolveContext, record: dict[str, Any]) -> None:
    """Durably record one executed action; a journal failure keeps the record and degrades."""
    try:
        _journal_write(ctx, record)
    except Exception as exc:
        record["journal_error"] = f"{type(exc).__name__}: {_clip(exc, 200)}"
        ctx.journal_errors.append(str(record.get("id")))


def _journal_write(ctx: ResolveContext, record: Mapping[str, Any]) -> None:
    """Durably record one executed action before anything else happens."""
    path = ctx.run_dir / ACTIONS_JOURNAL
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(dict(record), sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def _prior_done(ctx: ResolveContext) -> list[dict[str, Any]]:
    """Actions an earlier attempt of tonight's P7c already executed.

    Read from the append-only action journal (written right after each
    action, so a crash before the artifact is written loses nothing) and the
    previous artifact.  They count against the nightly cap and are carried
    forward verbatim, keeping their undo commands, instead of being re-judged.
    """
    carried: dict[str, dict[str, Any]] = {}
    prior = _read_json(ctx.run_dir / ARTIFACT)
    if isinstance(prior, Mapping):
        for r in prior.get("items") or []:
            if isinstance(r, Mapping) and r.get("executed"):
                carried[str(r.get("id"))] = dict(r)
    try:
        lines = (ctx.run_dir / ACTIONS_JOURNAL).read_text(encoding="utf-8").splitlines()
    except OSError:
        lines = []
    for line in lines:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict) and row.get("id"):
            carried[str(row["id"])] = row
    return list(carried.values())


def _hold(record: dict[str, Any], status: str, reason: str) -> dict[str, Any]:
    record.update(status=status, reason=_clip(reason, 400))
    return record


def resolve_item(ctx: ResolveContext, item: Item, *, statuses: Mapping[str, str],
                 sessions: Mapping[str, list[dict[str, Any]]], memoirs: Mapping[str, Path],
                 active: list[dict[str, Any]], is_private: Callable[[str], bool],
                 budget: dict[str, int]) -> dict[str, Any]:
    record = item.record()
    record.update(status="unknown", action="", tier="", reason="", approve_command="", undo="",
                  dropped_excerpts=[], evidence=[])
    if item.resolved_by:
        logs = {rel: _git_log(ctx, rel, 1) for rel in item.paths}
        return _hold(record, "resolved", "no longer modified; latest commit: " + "; ".join(
            f"{rel}: {log or '?'}" for rel, log in logs.items()))
    if item.klass == "fyi":
        return _hold(record, "held", "report-only finding; the menu is hold only")
    blocked = {}
    for rel in item.paths:
        if is_private(rel) or dotfiles._is_sensitive(rel):
            return _hold(record, "held", f"{rel} is private/credential-like; never touched")
        owner = _active_owner(ctx, rel, active)
        if owner:
            blocked[rel] = owner
    odd = {p: item.statuses.get(p) for p in item.paths
           if item.klass == "uncommitted"
           and item.statuses.get(p) and item.statuses.get(p) not in dotfiles.COMMITTABLE_STATUS}
    if odd:
        return _hold(record, "held", "path has a git state the resolver never acts on (staged, "
                     "untracked or conflicted): " + ", ".join(f"{p} {c!r}" for p, c in odd.items()))
    diffs: dict[str, str] = {}
    hashes: dict[str, dict[str, str]] = {}
    if item.klass == "uncommitted":
        for rel in item.paths:
            try:
                diff = dotfiles.exact_path_diff(rel, git_dir=ctx.git_dir, home=ctx.home)
            except (OSError, RuntimeError, ValueError) as exc:
                return _hold(record, "unknown", f"exact diff unavailable for {rel}: {_clip(exc, 200)}")
            risk = dotfiles._sensitive_diff_reason(diff) or secret_reason(diff)
            if risk:
                return _hold(record, "held", f"{rel}: {risk}; never sent to a model")
            if len(diff) > DIFF_BUDGET_CHARS:
                return _hold(record, "unknown", f"{rel}: diff exceeds {DIFF_BUDGET_CHARS} characters (held, never truncated)")
            diffs[rel] = diff
        hashes = _path_hashes(ctx, item.paths)
    record["hashes"] = hashes
    deployed: dict[str, str] = {}
    # Deterministic rig shortcut: canonical == deployed, byte for byte.
    if (
        item.klass == "uncommitted"
        and item.paths
        and all(item.statuses.get(p) == " M" and _rig_deploy_target(p)
                and p.startswith(RIG_AUTONOMOUS_ROOT) and not _autonomy_block(ctx, p)
                for p in item.paths)
        and ctx.rig_sha256 is not None
    ):
        identical = True
        for rel in item.paths:
            remote = ctx.rig_sha256(_rig_deploy_target(rel))
            local = hashes[rel]["content_sha256"]
            deployed[rel] = (
                "deployed copy not checked tonight (the rig was not reachable on Linux)" if remote is None
                else f"sha256 {remote} {'==' if remote == local else '!='} canonical {local}"
            )
            identical = identical and remote == local
        record["deployed"] = deployed
        if identical and not blocked:
            record.update(action="commit", tier="shortcut", decided_by="deployed-identical",
                          proposal={"hashes": hashes},
                          approve_command=_approve_command(ctx.run_date, item.id))
            return _act(ctx, item, record, {"action": "commit"}, hashes, budget)
    ev = build_evidence(ctx, item, sessions, memoirs, diffs, deployed)
    record["evidence"] = ev.summary()
    record["dropped_excerpts"] = ev.dropped
    menu = MENUS[item.klass]
    try:
        decision = decide(ctx, item, ev, menu, is_private)
    except SecretHold as exc:
        return _hold(record, "held", str(exc))
    except Unknown as exc:
        return _hold(record, "unknown", str(exc))
    record.update(action=decision["action"], rationale=decision["rationale"],
                  citations=decision["citations"], already_fixed=decision["already_fixed"])
    if decision["action"] == "hold":
        return _hold(record, "held", "resolver chose hold" + (" (evidence shows it is already fixed)"
                                                             if decision["already_fixed"] else ""))
    edit = decision.get("edit")
    if edit:
        record["proposal"] = {"edit": edit}
        owner = _active_owner(ctx, edit["path"], active)
        if owner:
            blocked[edit["path"]] = owner
    else:
        record["proposal"] = {"hashes": hashes}
    gate = jev_gate(ctx, _jev_state(item, ev, decision, diffs), decision["action"])
    record["jev"] = gate
    record["tier"] = gate["tier"]
    record["certainty"] = gate.get("certainty", 0.0)
    if gate["tier"] == "unknown":
        return _hold(record, "held" if gate.get("secret_hold") else "unknown",
                     gate.get("reason") or "Jev was not confident")
    record["approve_command"] = _approve_command(ctx.run_date, item.id)
    action = decision["action"]
    limit = None
    if action not in AUTONOMOUS_ACTIONS:
        limit = "patch is never applied autonomously"
    elif gate["tier"] != "act":
        limit = f"Jev certainty {gate.get('certainty', 0):.2f} is below {ACT_CERTAINTY}"
    elif blocked:
        limit = next(iter(blocked.values()))
    elif action in ("commit", "revert") and any(_autonomy_block(ctx, p) for p in item.paths):
        limit = next(_autonomy_block(ctx, p) for p in item.paths if _autonomy_block(ctx, p))
    elif action in ("commit", "revert") and any(item.statuses.get(p) != " M" for p in item.paths):
        limit = "deletions are never committed or restored autonomously"
    elif action == "doc_fix" and _protected(ctx, edit["path"]):
        limit = "the doc is fingerprinted steward policy"
    if limit:
        return _hold(record, "recommended", limit)
    return _act(ctx, item, record, decision, hashes, budget)


def _act(ctx: ResolveContext, item: Item, record: dict[str, Any], decision: Mapping[str, Any],
         hashes: Mapping[str, Mapping[str, str]], budget: dict[str, int]) -> dict[str, Any]:
    action = decision["action"]
    record["approve_command"] = record.get("approve_command") or _approve_command(ctx.run_date, item.id)
    if budget["used"] >= ctx.max_actions:
        return _hold(record, "recommended", f"nightly cap of {ctx.max_actions} autonomous actions reached")
    if ctx.dry_run:
        return _hold(record, "dry_run", f"dry run: would {action} autonomously")
    budget["used"] += 1
    record["executed"] = True
    try:
        if action == "commit":
            outcome = execute_commit(ctx, item.id, hashes,
                                     f"steward P7c: commit {', '.join(item.paths)}"[:200])
        elif action == "revert":
            outcome = execute_revert(ctx, item.id, hashes)
        else:
            outcome = execute_doc_fix(ctx, item, decision["edit"])
    except SecretHold as exc:
        budget["used"] -= 1
        record.pop("executed", None)
        return _hold(record, "held", str(exc))
    except Unknown as exc:
        budget["used"] -= 1
        record.pop("executed", None)
        return _hold(record, "recommended", str(exc))
    except PartialAction as exc:
        record.update(exc.outcome)
        _hold(record, "failed", f"{action} partly done: {exc}")
    except Exception as exc:
        _hold(record, "failed", f"{action} failed: {_clip(exc, 300)}")
    else:
        record.update(status="done", reason="", **outcome)
    _journal(ctx, record)
    return record


def _resolve_all(ctx: ResolveContext, result: dict[str, Any]) -> None:
    statuses = _snapshot(ctx)
    items = collect_items(ctx, statuses)
    result["skipped_items"] = [i.id for i in items[MAX_ITEMS:]]
    items = items[:MAX_ITEMS]
    active = (ctx.active_sessions if ctx.active_sessions is not None
              else dotfiles.collect_active_session_evidence(ctx.session_root))
    is_private = _load_private_policy(ctx)
    needs_sessions = [p for i in items if i.klass != "fyi" and not i.resolved_by for p in i.paths]
    sessions = scan_sessions(ctx, needs_sessions)
    memoirs = _memoir_index(ctx.memoir_root)
    carried = _prior_done(ctx)
    result["items"].extend(carried)
    carried_ids = {str(r.get("id")) for r in carried}
    budget = {"used": len(carried)}
    for item in items:
        if item.id in carried_ids:
            continue
        if time.monotonic() > (ctx.deadline or 0):
            result["items"].append(_hold(item.record(), "unknown", "P7c deadline reached"))
            continue
        try:
            record = resolve_item(ctx, item, statuses=statuses, sessions=sessions, memoirs=memoirs,
                                  active=active, is_private=is_private, budget=budget)
        except Exception as exc:  # one item never blocks the rest
            record = _hold(item.record(), "unknown", f"resolver error: {type(exc).__name__}: {_clip(exc, 300)}")
        result["items"].append(record)
    result["autonomous_actions"] = budget["used"]
    failed = [r["id"] for r in result["items"] if r.get("status") == "failed"]
    reasons = []
    if failed:
        reasons.append("P7c action(s) failed: " + ", ".join(failed))
    if ctx.journal_errors:
        reasons.append("P7c action journal write failed for: " + ", ".join(ctx.journal_errors)
                       + " (records kept in this artifact)")
    if reasons:
        result.update(phase_status="degraded", reason="; ".join(reasons))


def phase_7c_resolve(run_dir: Path, dry_run: bool = False, **overrides: Any) -> dict[str, Any]:
    """Resolve Needs You items; never raises (a failure is a degraded artifact)."""
    print("[P7c] resolve")
    ctx = ResolveContext(run_dir=Path(run_dir), dry_run=dry_run, **overrides)
    if ctx.rig_sha256 is None and _rig_linux_tonight(ctx.run_dir):
        ctx.rig_sha256 = _rig_sha256_over_ssh
    output = ctx.output or ctx.run_dir / ARTIFACT
    result: dict[str, Any] = {
        "run_date": ctx.run_date,
        "dry_run": dry_run,
        "max_autonomous_actions": ctx.max_actions,
        "items": [],
    }
    try:
        # Git pathspecs are work-tree relative (the unit's cwd is $HOME already).
        with contextlib.chdir(ctx.home), _literal_pathspecs():
            _resolve_all(ctx, result)
    except Exception as exc:
        result.update(phase_status="degraded", reason=f"P7c failed: {type(exc).__name__}: {_clip(exc, 400)}")
    client = ctx.jev_client
    if client is not None and hasattr(client, "usage"):
        try:
            result["jev_usage"] = client.usage()
        except Exception:
            pass
    counts: dict[str, int] = {}
    for record in result["items"]:
        counts[record.get("status", "?")] = counts.get(record.get("status", "?"), 0) + 1
    result["counts"] = counts
    atomic_write_json(output, result)
    print(f"[P7c] {counts or 'no items'} -> {output}")
    return result


# ── approval ─────────────────────────────────────────────────────────


class ApprovalRefused(Exception):
    pass


def load_resolution(run_dir: Path) -> dict[str, Any]:
    data = _read_json(Path(run_dir) / ARTIFACT)
    if not isinstance(data, Mapping):
        raise ApprovalRefused(f"no readable {ARTIFACT} in {run_dir}")
    return dict(data)


def _approved_ids(run_dir: Path) -> set[str]:
    done: set[str] = set()
    try:
        for line in (Path(run_dir) / APPROVALS).read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if row.get("status") == "done":
                done.add(str(row.get("id")))
    except OSError:
        pass
    return done


STEWARD_UNITS = ("homelab-steward.service", "homelab-steward-resume.service")
_STOPPED_STATES = frozenset({"inactive", "failed"})


def _steward_running(run: Callable[..., tuple[str, str, int]] = run_capture_ok) -> bool:
    """True unless every steward unit is positively stopped (fails closed)."""
    stdout, _, code = run(["systemctl", "--user", "is-active", *STEWARD_UNITS])
    states = (stdout or "").split()
    if len(states) != len(STEWARD_UNITS) or code not in (0, 3):
        return True
    return any(state not in _STOPPED_STATES for state in states)


def _apply_edit(ctx: ResolveContext, item_id: str, edit: Mapping[str, Any], *, commit_doc: bool) -> dict[str, Any]:
    path = ctx.home / edit["path"]
    data = path.read_bytes()
    if _sha256(data) != edit["file_sha256"]:
        raise ApprovalRefused(f"{edit['path']} changed since it was judged")
    content = data.decode("utf-8")
    if content.count(edit["old_text"]) != 1:
        raise ApprovalRefused("the old text no longer occurs exactly once")
    hit = secret_reason(edit["new_text"])
    if hit:
        raise ApprovalRefused(f"the new text failed the secret scan ({hit})")
    top = None
    tracked_dotfile = False
    if commit_doc:
        stdout, _, code = run_capture_ok(["git", "-C", str(path.parent), "rev-parse", "--show-toplevel"])
        if code != 0:
            raise ApprovalRefused(f"{edit['path']} is not in a git repository")
        top = Path(stdout.strip())
        rel = str(path.resolve().relative_to(top.resolve()))
        dirty, _, _ = run_capture_ok(["git", "-C", str(top), "status", "--porcelain", "--", rel])
        if dirty.strip():
            raise ApprovalRefused(f"{edit['path']} has uncommitted changes")
    else:
        # An approved patch to a tracked private-dotfiles path is committed like any
        # approved commit (exact path, reviewed diff hash, secret scan, push); left
        # uncommitted it would only reappear as drift that P9b can never stage.
        _, _, code = run_capture_ok(["git", f"--git-dir={ctx.git_dir}", f"--work-tree={ctx.home}",
                                     "ls-files", "--error-unmatch", "--", edit["path"]])
        tracked_dotfile = code == 0
        if tracked_dotfile and edit["path"] in _snapshot(ctx):
            raise ApprovalRefused(f"{edit['path']} has uncommitted changes")
    saved = ctx.run_dir / SAVED_DIR / item_id / edit["path"]
    saved.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(saved, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    mode = stat.S_IMODE(path.stat().st_mode)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.")
    with os.fdopen(fd, "wb") as handle:
        handle.write(content.replace(edit["old_text"], edit["new_text"], 1).encode("utf-8"))
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    undo = f"install -m {mode:o} {shlex.quote(str(saved))} {shlex.quote(str(path))}"
    if tracked_dotfile:
        try:
            committed = execute_commit(ctx, item_id, _path_hashes(ctx, [edit["path"]]),
                                       f"steward P7c (approved): patch {edit['path']}"[:200])
        except (Unknown, RuntimeError) as exc:
            path.write_bytes(data)
            raise ApprovalRefused(f"commit failed: {_clip(exc, 300)}; the original text was restored") from None
        return {**committed, "summary": f"Patched {edit['path']} and {committed['summary'][0].lower()}"
                                        f"{committed['summary'][1:]}"}
    if top is None:
        return {"undo": undo, "summary": f"Patched {edit['path']} (not committed)."}
    msg = f"docs(steward P7c): approved fix in {rel}"
    _, err, code = run_capture_ok(["git", "-C", str(top), "commit", "--only", "-m", msg, "--", rel])
    if code != 0:
        path.write_bytes(data)
        raise ApprovalRefused(f"commit failed: {_clip(err, 300)}; the original text was restored")
    sha, _, _ = run_capture_ok(["git", "-C", str(top), "rev-parse", "HEAD"])
    branch, _, _ = run_capture_ok(["git", "-C", str(top), "symbolic-ref", "--quiet", "--short", "HEAD"])
    _, perr, pcode = run_capture_ok(["git", "-C", str(top), "push", "origin",
                                     f"{sha.strip()}:refs/heads/{branch.strip()}"], timeout=180)
    return {
        "commit": sha.strip(),
        "push": "verified" if pcode == 0 else f"failed: {_clip(perr, 200)}",
        "undo": f"git -C {shlex.quote(str(top))} revert --no-edit {sha.strip()}",
        "summary": f"Edited {edit['path']} and committed {sha.strip()[:8]}.",
    }


def approve(run_dir: Path, item_id: str, *, dry_run: bool = False,
            steward_running: Callable[[], bool] = _steward_running, **overrides: Any) -> dict[str, Any]:
    """Execute exactly the recorded proposal for one item after re-validation."""
    run_dir = Path(run_dir)
    data = load_resolution(run_dir)
    record = next((r for r in data.get("items") or [] if isinstance(r, Mapping) and r.get("id") == item_id), None)
    if record is None:
        raise ApprovalRefused(f"no item {item_id!r} in {run_dir / ARTIFACT}")
    if record.get("status") not in {"recommended", "dry_run"} or not record.get("approve_command"):
        raise ApprovalRefused(f"item {item_id} is {record.get('status')}; nothing to approve")
    if item_id in _approved_ids(run_dir):
        raise ApprovalRefused(f"item {item_id} was already approved")
    if steward_running():
        raise ApprovalRefused("the nightly steward (or its resume unit) is running, or its state "
                              "could not be read; approve after it finishes")
    ctx = ResolveContext(run_dir=run_dir, **overrides)
    is_private = _load_private_policy(ctx)
    action = record.get("action")
    proposal = record.get("proposal") or {}
    paths = list(record.get("paths") or [])
    touched = [e["path"] for e in [proposal.get("edit")] if isinstance(e, Mapping) and e.get("path")] or paths
    for rel in touched:
        if is_private(rel) or dotfiles._is_sensitive(rel):
            raise ApprovalRefused(f"{rel} is private/credential-like")
    try:
        with contextlib.chdir(ctx.home), _literal_pathspecs():
            outcome = _execute_approval(ctx, item_id, action, proposal, paths, dry_run)
    except Unknown as exc:
        raise ApprovalRefused(str(exc)) from None
    except PartialAction as exc:
        with (run_dir / APPROVALS).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"id": item_id, "action": action, "status": "failed",
                                     "at": _now().isoformat(), "reason": str(exc), **exc.outcome},
                                    sort_keys=True) + "\n")
        raise ApprovalRefused(f"{action} partly done: {exc}; undo: {exc.outcome.get('undo')}") from None
    except (RuntimeError, OSError, ValueError) as exc:
        raise ApprovalRefused(f"{action} failed: {_clip(exc, 400)}") from None
    row = {"id": item_id, "action": action, "status": "dry_run" if dry_run else "done",
           "at": _now().isoformat(), **outcome}
    if not dry_run:
        with (run_dir / APPROVALS).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    return row


def _execute_approval(ctx: ResolveContext, item_id: str, action: Any, proposal: Mapping[str, Any],
                      paths: list[str], dry_run: bool) -> dict[str, Any]:
    if action in ("commit", "revert"):
        hashes = proposal.get("hashes") or {}
        if sorted(hashes) != sorted(paths) or not hashes:
            raise ApprovalRefused("the recorded proposal has no content hashes")
        if not dry_run:
            if action == "commit":
                return execute_commit(ctx, item_id, hashes,
                                      f"steward P7c (approved): commit {', '.join(paths)}"[:200])
            return execute_revert(ctx, item_id, hashes)
        _check_hashes(ctx, hashes)
        for rel in hashes:
            diff = dotfiles.exact_path_diff(rel, git_dir=ctx.git_dir, home=ctx.home)
            if dotfiles._sensitive_diff_reason(diff) or secret_reason(diff):
                raise ApprovalRefused(f"{rel} failed the secret scan")
        return {"summary": f"dry run: would {action} {', '.join(paths)}"}
    if action in ("doc_fix", "patch"):
        edit = proposal.get("edit")
        if not isinstance(edit, Mapping):
            raise ApprovalRefused("the recorded proposal has no edit")
        if not dry_run:
            return _apply_edit(ctx, item_id, edit, commit_doc=action == "doc_fix")
        if _sha256((ctx.home / edit["path"]).read_bytes()) != edit.get("file_sha256"):
            raise ApprovalRefused(f"{edit['path']} changed since it was judged")
        return {"summary": f"dry run: would apply the {action} to {edit['path']}"}
    raise ApprovalRefused(f"item {item_id} has no executable action ({action!r})")


def _cli(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="P7c resolver dry-run against a run directory")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--out", required=True, help="write the artifact here, not into the run dir")
    parser.add_argument("--git-dir", help="alternate dotfiles git dir")
    parser.add_argument("--home", help="alternate dotfiles work tree (sessions, memoirs, docs stay real)")
    parser.add_argument("--as-of", help="ISO time: ignore session calls and commits after it (replay)")
    parser.add_argument("--no-active-sessions", action="store_true",
                        help="replay: treat no session as active (use the run's 09b record)")
    parser.add_argument("--no-rig", action="store_true", help="skip the read-only deployed-rig check")
    args = parser.parse_args(argv)
    overrides: dict[str, Any] = {"output": Path(args.out)}
    if args.git_dir:
        overrides["git_dir"] = Path(args.git_dir)
    if args.home:
        overrides.update(
            home=Path(args.home),
            session_root=HOME / ".omp" / "agent" / "sessions",
            memoir_root=HOME / "notes" / "logs" / "sessions",
            doc_roots=(HOME / "notes" / "docs",),
            policy_path=HOME / public_dotfiles.POLICY_REL,
        )
    if args.as_of:
        overrides["now"] = datetime.fromisoformat(args.as_of.replace("Z", "+00:00"))
    if args.no_active_sessions:
        overrides["active_sessions"] = []
    if args.no_rig:
        overrides["rig_sha256"] = lambda _dest: None
    result = phase_7c_resolve(Path(args.run_dir), dry_run=True, **overrides)
    print(json.dumps(result.get("counts"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
