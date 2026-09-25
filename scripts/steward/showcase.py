"""P9c public showcase: publish policy and nightly snapshot publisher.

The private dotfiles repo (carter2099/dotfiles-homelab-private) is the source
of truth.  Every night the publisher builds a squashed snapshot of the tracked
paths whose publish scope is ``public`` and pushes it to the public showcase
repo (carter2099/dotfiles-homelab).  No private history ever leaves the host:
the public repo only receives snapshot commits built in a local bare mirror.

Scope of one path, in order (``decide``):
1. ``private`` glob in system-config/dotfiles-publish.toml -> private.
2. Deterministic secret scan (file name, credential lines, private keys, bare
   tokens, MAC addresses) -> held.  Held content is never sent to Jev.
3. ``public`` glob -> public.
4. Recorded decision in system-config/dotfiles-publish-decisions.json -> it.
5. Otherwise Jev decides; only a confident safe answer publishes.  Anything
   else, including JevUnavailable, holds the path (listed in the email).

A file that is already public and changed must also pass a Jev
credential/personal veto on its changed hunks; otherwise the previously
published version stays.
"""
from __future__ import annotations

import difflib
import json
import os
import re
import subprocess
import tempfile
import time
import tomllib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from . import dotfiles
from .config import HOME
from .runtime import atomic_write_json

POLICY_PATH = HOME / "system-config" / "dotfiles-publish.toml"
DECISIONS_PATH = HOME / "system-config" / "dotfiles-publish-decisions.json"
STATE_DIR = HOME / ".local" / "state" / "dotfiles-showcase"
PUBLIC_REPO = "carter2099/dotfiles-homelab"
PUBLIC_URL = f"https://github.com/{PUBLIC_REPO}.git"
PUBLIC_REF = "refs/heads/main"
ARTIFACT = "09c-showcase.json"

JEV_BUDGET_SECONDS = 120.0
MAX_JEV_CHARS = 60_000
HUNK_CONTEXT = 20

# Scope of an ambiguous path (J032 thresholds; publishing is irreversible).
SCOPE_PUBLISH = {"credential": 0.05, "personal": 0.15}
SCOPE_HOMELAB_PUBLISH = 0.85
SCOPE_PRIVATE = 0.5
SCOPE_HOMELAB_PRIVATE = 0.15
# Veto on changed hunks of an already-public file.
VETO_PUBLISH = {"credential": 0.05, "personal": 0.15}
VETO_BLOCK = 0.5

_CREDENTIAL_Q = (
    "Does `{field}` contain the actual value of a password, API key, access token, "
    "private key, session cookie, or other secret (not a placeholder, an "
    "environment-variable reference, or the name of a file that holds one)?"
)
_PERSONAL_Q = (
    "Does `{field}` contain private personal information about the author or anyone "
    "else, such as phone numbers, a home street address, financial or trading account "
    "numbers or balances, health details, or private conversations? The author's name, "
    "a git commit email, internal IP addresses, hostnames and firewall rules do not count."
)
SCOPE_QUESTIONS: dict[str, dict[str, Any]] = {
    "credential": {"type": "noul", "instructions": _CREDENTIAL_Q.format(field="content")},
    "personal": {"type": "noul", "instructions": _PERSONAL_Q.format(field="content")},
    "homelab": {
        "type": "noul",
        "instructions": (
            "Is `content` configuration, code, documentation, or agent instructions for a "
            "personal computer setup or homelab (dotfiles, services, scripts, tools), as "
            "opposed to runtime state, logs, caches, databases, exported personal data, or "
            "private notes?"
        ),
    },
}
VETO_QUESTIONS: dict[str, dict[str, Any]] = {
    "credential": {"type": "noul", "instructions": _CREDENTIAL_Q.format(field="changes")},
    "personal": {"type": "noul", "instructions": _PERSONAL_Q.format(field="changes")},
}

_MAC = re.compile(r"(?<![0-9A-Fa-f:-])[0-9A-Fa-f]{2}(?:([:-])[0-9A-Fa-f]{2})(?:\1[0-9A-Fa-f]{2}){4}(?![0-9A-Fa-f:-])")


@dataclass
class Policy:
    private: list[str]
    public: list[str]
    entropy_exempt: list[str] = field(default_factory=list)
    _private_re: list[re.Pattern[str]] = field(default_factory=list, repr=False)
    _public_re: list[re.Pattern[str]] = field(default_factory=list, repr=False)
    _entropy_re: list[re.Pattern[str]] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        self._private_re = [_glob_re(g, re.IGNORECASE) for g in self.private]
        self._public_re = [_glob_re(g) for g in self.public]
        self._entropy_re = [_glob_re(g) for g in self.entropy_exempt]

    def is_private(self, path: str) -> bool:
        """Case-insensitive; a private directory (any path prefix) makes everything below it private."""
        parts = path.split("/")
        prefixes = ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]
        return any(p.fullmatch(prefix) for p in self._private_re for prefix in prefixes)

    def is_public(self, path: str) -> bool:
        return any(p.fullmatch(path) for p in self._public_re)

    def entropy_checked(self, path: str) -> bool:
        return not any(p.fullmatch(path) for p in self._entropy_re)


@dataclass
class Decision:
    scope: str  # "public" | "private" | "held"
    by: str  # "rule" | "scan" | "decision" | "jev"
    reason: str
    record: dict[str, Any] | None = None  # new decision to persist


def _glob_re(glob: str, flags: int = 0) -> re.Pattern[str]:
    """Path glob: ``**/`` any directories (incl. none), ``**`` anything, ``*``/``?`` within one component."""
    out, i = [], 0
    while i < len(glob):
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif glob[i] == "*":
            out.append("[^/]*")
            i += 1
        elif glob[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(glob[i]))
            i += 1
    return re.compile("".join(out), flags)


def load_policy(path: Path = POLICY_PATH) -> Policy:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    private, public = data.get("private"), data.get("public")
    exempt = data.get("entropy_exempt", [])
    if not (isinstance(private, list) and isinstance(public, list) and isinstance(exempt, list)
            and all(isinstance(g, str) and g for g in private + public + exempt)):
        raise ValueError(
            f"{path}: 'private', 'public' and 'entropy_exempt' must be lists of non-empty globs"
        )
    return Policy(private=private, public=public, entropy_exempt=exempt)


def load_decisions(path: Path = DECISIONS_PATH) -> dict[str, dict[str, Any]]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: decisions must be a JSON object")
    return {
        k: v for k, v in data.items()
        if isinstance(v, dict) and v.get("scope") in {"public", "private"}
    }


def save_decisions(path: Path, decisions: dict[str, dict[str, Any]]) -> None:
    atomic_write_json(Path(path), dict(sorted(decisions.items())))


_URL_OR_NAME = re.compile(
    r"//\S*"  # URL remainder after "https:"
    r"|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+[,;)]*"  # dotted identifier (module.CONST)
    r"|[\w.@-]*(?:/[\w.@~-]+)+/?[\"',;)]*"  # path or owner/repo
    r"|[A-Z][A-Z0-9_]*=\S*"  # ENV=value (the value is checked on its own)
)
_PLACEHOLDER = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+|<[^>]*>|x{8,}|\*{4,}", re.IGNORECASE)


def _line_finding(text: str, entropy: bool = True, mac: bool = True) -> str | None:
    """One credential rule for a line, reusing the P9b detectors."""
    rule = next((name for name, pattern in dotfiles._SECRET_LINE_RULES if pattern.search(text)), None)
    if rule:
        return rule
    token = dotfiles._TOKEN_ASSIGNMENT.search(text)
    if token and not dotfiles._is_reference(token.group("value")):
        value = token.group("value").strip().strip("\"',")
        if not _PLACEHOLDER.fullmatch(value) and value.lower() not in dotfiles._PLACEHOLDER_VALUES:
            return f"{token.group('name')} assignment"
    match = dotfiles._SECRET_ASSIGNMENT.search(text.strip())
    if match:
        value = match.group("value").strip().rstrip(",;").strip("\"'")
        if (
            len(value) >= 8
            and not dotfiles._is_reference(value)
            and not value.startswith(("=", "/", "(", "[", "{"))  # comparison, path, call
            and not _PLACEHOLDER.fullmatch(value)
            and value.lower() not in dotfiles._PLACEHOLDER_VALUES
        ):
            return "credential-like assignment"
    for generic in dotfiles._GENERIC_ASSIGNMENT.finditer(text) if entropy else ():
        value = generic.group("value")
        if (
            not dotfiles._is_reference(value)
            and not _URL_OR_NAME.fullmatch(value)
            and dotfiles._shannon_entropy(value) >= 4.2
        ):
            return "high-entropy assignment"
    if mac and _MAC.search(text):
        return "MAC address"
    return None


def scan_diff(diff: str, policy: Policy | None = None, *, mac: bool = True) -> list[dict[str, Any]]:
    """Scan added lines of a unified git diff; findings name path, line and rule only."""
    findings: list[dict[str, Any]] = []
    path, deleted, line_no = "", False, 0
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            path, deleted = line.split(" b/", 1)[-1], False
            continue
        if line.startswith("deleted file mode"):
            deleted = True
            continue
        if line.startswith("+++ "):
            if not deleted and (dotfiles._secret_file_name(path) or dotfiles._is_sensitive(path)):
                findings.append({"path": path, "line": 0, "rule": "secret-looking file name"})
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
        entropy = policy.entropy_checked(path) if policy else True
        rule = _line_finding(line[1:], entropy, mac)
        if rule:
            findings.append({"path": path, "line": line_no, "rule": rule})
    return findings


def scan(path: str, content: bytes, *, entropy: bool = True) -> str | None:
    """Deterministic secret scan; the reason names the rule and line, never the value."""
    if dotfiles._secret_file_name(path) or dotfiles._is_sensitive(path):
        return "secret-looking file name"
    if b"\0" in content:
        return "binary file requires manual review"
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return "non-UTF-8 file requires manual review"
    for number, line in enumerate(text.splitlines(), 1):
        rule = _line_finding(line, entropy)
        if rule:
            return f"{rule} (line {number})"
    return None


def _ask(client: Any, purpose: str, state: dict[str, Any],
         questions: dict[str, dict[str, Any]]) -> tuple[dict[str, float] | None, str]:
    """Noul probabilities, or (None, reason) when Jev cannot answer."""
    if client is None:
        return None, "Jev unavailable (no client)"
    import jev

    try:
        answers = client.ask(purpose, state, questions)
    except jev.JevUnavailable as error:
        return None, f"Jev unavailable ({getattr(error, 'reason', 'error')})"
    try:
        return {q: float(answers[q]["noul"]) for q in questions}, ""
    except (KeyError, TypeError, ValueError):
        return None, "Jev answer incomplete"


def _jev_scope(path: str, text: str, client: Any, today: str) -> Decision:
    if len(text) > MAX_JEV_CHARS:
        return Decision("held", "jev", f"too large for Jev ({len(text)} chars); decide manually")
    probs, why = _ask(client, "dotfiles-showcase-scope", {"path": path, "content": text},
                      SCOPE_QUESTIONS)
    if probs is None:
        return Decision("held", "jev", why)
    import jev

    record = {
        "scope": "",
        "by": "jev",
        "model": jev.MODEL,
        "probabilities": {k: round(v, 4) for k, v in probs.items()},
        "confidence": round(min(jev.noul_certainty(v) for v in probs.values()), 4),
        "date": today,
    }
    shown = ", ".join(f"{k}={v:.2f}" for k, v in probs.items())
    if (all(probs[k] < limit for k, limit in SCOPE_PUBLISH.items())
            and probs["homelab"] >= SCOPE_HOMELAB_PUBLISH):
        record["scope"] = "public"
        return Decision("public", "jev", f"Jev: safe homelab content ({shown})", record)
    if (probs["credential"] >= SCOPE_PRIVATE or probs["personal"] >= SCOPE_PRIVATE
            or probs["homelab"] <= SCOPE_HOMELAB_PRIVATE):
        record["scope"] = "private"
        return Decision("private", "jev", f"Jev: keep private ({shown})", record)
    return Decision("held", "jev", f"Jev not confident ({shown})")


def decide(path: str, content: bytes, *, policy: Policy,
           decisions: dict[str, dict[str, Any]],
           client: Any | Callable[[], Any] = None, today: str | None = None) -> Decision:
    """Publish scope of one path.  ``client`` may be a Jev client or a zero-arg factory."""
    if policy.is_private(path):
        return Decision("private", "rule", "private rule")
    hit = scan(path, content, entropy=policy.entropy_checked(path))
    if hit:
        return Decision("held", "scan", hit)
    if policy.is_public(path):
        return Decision("public", "rule", "public rule")
    recorded = decisions.get(path)
    if recorded:
        return Decision(recorded["scope"], "decision",
                        f"recorded decision by {recorded.get('by', '?')}")
    jev_client = client() if callable(client) and not hasattr(client, "ask") else client
    return _jev_scope(path, content.decode("utf-8"), jev_client,
                      today or datetime.now(timezone.utc).strftime("%Y-%m-%d"))


def veto(path: str, old: bytes, new: bytes, client: Any) -> tuple[str, str]:
    """Jev credential/personal veto on the changed hunks: ('publish'|'held'|'blocked', reason)."""
    try:
        old_text, new_text = old.decode("utf-8"), new.decode("utf-8")
    except UnicodeDecodeError:
        return "held", "non-UTF-8 change requires manual review"
    changes = "".join(difflib.unified_diff(
        old_text.splitlines(keepends=True), new_text.splitlines(keepends=True),
        f"a/{path}", f"b/{path}", n=HUNK_CONTEXT,
    ))
    if not changes:
        return "publish", "no textual change"
    if len(changes) > MAX_JEV_CHARS:
        return "held", f"change too large for Jev ({len(changes)} chars); previous version kept"
    probs, why = _ask(client, "dotfiles-showcase-change-veto",
                      {"path": path, "changes": changes}, VETO_QUESTIONS)
    if probs is None:
        return "held", f"{why}; previous version kept"
    shown = ", ".join(f"{k}={v:.2f}" for k, v in probs.items())
    if any(v >= VETO_BLOCK for v in probs.values()):
        return "blocked", f"Jev veto ({shown}); previous version kept"
    if all(probs[k] < limit for k, limit in VETO_PUBLISH.items()):
        return "publish", f"Jev: change safe ({shown})"
    return "held", f"Jev not confident ({shown}); previous version kept"


def _load_jev_client() -> Any:
    try:
        import jev
    except ImportError:
        return None
    return jev.load_client(deadline=time.monotonic() + JEV_BUDGET_SECONDS)


def _git(git_dir: Path, *args: str, input: bytes | None = None,
         env: dict[str, str] | None = None, check: bool = True) -> bytes:
    cp = subprocess.run(
        ["git", f"--git-dir={git_dir}", *args], input=input, capture_output=True,
        timeout=120, env={**os.environ, **(env or {})},
    )
    if check and cp.returncode != 0:
        raise RuntimeError(f"git {args[0]} failed: {cp.stderr.decode(errors='replace').strip()[:400]}")
    return cp.stdout


def _tracked(git_dir: Path, ref: str) -> list[tuple[str, str, str, str]]:
    out = _git(git_dir, "ls-tree", "-r", "-z", "--full-tree", ref)
    rows = []
    for item in out.decode("utf-8", "surrogateescape").split("\0"):
        if item:
            meta, path = item.split("\t", 1)
            mode, kind, oid = meta.split()
            rows.append((mode, kind, oid, path))
    return rows


def _load_state(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"published": {}}
    if not isinstance(data, dict) or not isinstance(data.get("published"), dict):
        raise ValueError(f"{path}: malformed showcase state")
    return data


def _ensure_mirror(mirror: Path) -> None:
    if not (mirror / "HEAD").exists():
        mirror.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "--quiet", "--bare", "--initial-branch=main", str(mirror)],
                       check=True, capture_output=True, timeout=60)


def _build_commit(git_dir: Path, mirror: Path, final: dict[str, dict[str, str]],
                  message: str) -> tuple[str, str | None]:
    """Copy blobs into the mirror, write the snapshot tree, commit it. Returns (commit, parent)."""
    for entry in final.values():
        oid = entry["blob"]
        if subprocess.run(["git", f"--git-dir={mirror}", "cat-file", "-e", oid],
                          capture_output=True, timeout=60).returncode != 0:
            body = _git(git_dir, "cat-file", "blob", oid)
            written = _git(mirror, "hash-object", "-w", "--stdin", input=body).decode().strip()
            if written != oid:
                raise RuntimeError(f"blob copy mismatch for {oid}")
    with tempfile.TemporaryDirectory() as tmp:
        index_env = {"GIT_INDEX_FILE": str(Path(tmp) / "index")}
        info = "".join(f"{e['mode']} {e['blob']}\t{p}\n" for p, e in sorted(final.items()))
        _git(mirror, "update-index", "--add", "--index-info",
             input=info.encode("utf-8", "surrogateescape"), env=index_env)
        tree = _git(mirror, "write-tree", env=index_env).decode().strip()
    parent = _git(mirror, "rev-parse", "--verify", "--quiet", PUBLIC_REF, check=False).decode().strip() or None
    if parent and _git(mirror, "rev-parse", f"{parent}^{{tree}}").decode().strip() == tree:
        return parent, parent
    args = ["commit-tree", tree, "-m", message] + (["-p", parent] if parent else [])
    commit = _git(mirror, *args).decode().strip()
    return commit, parent


def _outgoing_findings(mirror: Path, commit: str, parent: str | None,
                       policy: Policy) -> list[dict[str, Any]]:
    args = ["diff-tree", "-r", "-p", "--no-color"]
    args += [parent, commit] if parent else ["--root", commit]
    diff = _git(mirror, *args).decode("utf-8", "replace")
    return scan_diff(diff, policy)


def publish(*, dry_run: bool = False, push: bool = True, client: Any = _load_jev_client,
            git_dir: Path = dotfiles.DOTFILES_GIT, ref: str = "HEAD",
            policy_path: Path = POLICY_PATH, decisions_path: Path = DECISIONS_PATH,
            state_dir: Path = STATE_DIR, remote_url: str = PUBLIC_URL,
            today: str | None = None) -> dict[str, Any]:
    """Build (and unless dry_run, push) the public snapshot of the private repo."""
    today = today or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    policy = load_policy(policy_path)
    decisions = load_decisions(decisions_path)
    state_path = Path(state_dir) / "state.json"
    state = _load_state(state_path)
    previous: dict[str, dict[str, str]] = state["published"]
    source = _git(git_dir, "rev-parse", ref).decode().strip()

    jev_client: list[Any] = []

    def get_client() -> Any:
        if not jev_client:
            jev_client.append(client() if callable(client) and not hasattr(client, "ask") else client)
        return jev_client[0]

    final: dict[str, dict[str, str]] = {}
    added, updated, removed, held, blocked, private, recorded = [], [], [], [], [], [], {}
    for mode, kind, oid, path in _tracked(git_dir, ref):
        prev = previous.get(path)
        if kind != "blob":
            private.append({"path": path, "reason": f"{kind} entries are never published"})
            continue
        if prev and prev == {"mode": mode, "blob": oid} and not policy.is_private(path):
            final[path] = prev
            continue
        content = _git(git_dir, "cat-file", "blob", oid)
        d = decide(path, content, policy=policy, decisions={**decisions, **recorded},
                   client=get_client, today=today)
        if d.record:
            recorded[path] = d.record
        if d.scope == "private":
            private.append({"path": path, "reason": d.reason})
            if prev:
                removed.append({"path": path, "reason": d.reason})
            continue
        if d.scope == "held":
            if prev:
                final[path] = prev
                held.append({"path": path, "reason": f"{d.reason}; previous version kept"})
            else:
                held.append({"path": path, "reason": d.reason})
            continue
        entry = {"mode": mode, "blob": oid}
        if not prev:
            final[path] = entry
            added.append({"path": path, "reason": d.reason})
            continue
        old = _git(git_dir, "cat-file", "blob", prev["blob"])
        verdict, why = veto(path, old, content, get_client())
        if verdict == "publish":
            final[path] = entry
            updated.append({"path": path, "reason": why})
        else:
            final[path] = prev
            (blocked if verdict == "blocked" else held).append({"path": path, "reason": why})
    removed += [
        {"path": p, "reason": "no longer tracked"}
        for p in previous if p not in final and not any(r["path"] == p for r in removed)
        and not any(h["path"] == p for h in held)
    ]
    changed = final != previous or not state.get("commit")
    result: dict[str, Any] = {
        "status": "",
        "dry_run": dry_run,
        "repo": PUBLIC_REPO,
        "source_head": source,
        "published_count": len(final),
        "private_count": len(private),
        "added": added,
        "updated": updated,
        "removed": removed,
        "held": held,
        "blocked": blocked,
        "private": sorted(p["path"] for p in private),
        "decisions_recorded": sorted(recorded),
        "published_paths": sorted(final),
    }
    if recorded and not dry_run:
        save_decisions(decisions_path, {**load_decisions(decisions_path), **recorded})
    if not changed:
        result["status"] = "unchanged"
        result["commit"] = state.get("commit")
        return result
    if dry_run:
        result["status"] = "dry_run"
        return result
    mirror = Path(state_dir) / "mirror.git"
    _ensure_mirror(mirror)
    commit, parent = _build_commit(git_dir, mirror, final, f"Publish homelab snapshot {today}")
    result["commit"] = commit
    findings = _outgoing_findings(mirror, commit, parent, policy) if commit != parent else []
    if findings:
        result["status"] = "secret_blocked"
        result["secret_findings"] = findings[:20]
        return result
    if push:
        # Push the snapshot itself; the mirror ref only advances once the remote has it,
        # so an unpushed snapshot never becomes history of a later one.
        cp = subprocess.run(["git", f"--git-dir={mirror}", "push", "--quiet", remote_url,
                             f"{commit}:{PUBLIC_REF}"], capture_output=True, text=True, timeout=180)
        if cp.returncode != 0:
            result["status"] = "push_failed"
            result["reason"] = cp.stderr.strip()[:400]
            return result
    if commit != parent:
        _git(mirror, "update-ref", PUBLIC_REF, commit, *([parent] if parent else []))
    atomic_write_json(state_path, {
        "published": final, "commit": commit, "source_head": source,
        "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    })
    result["status"] = "published" if push else "committed"
    return result


def phase_9c_showcase(run_dir: Path, dry_run: bool = False) -> dict[str, Any]:
    """Nightly P9c: publish the public subset of the dotfiles repo."""
    print("[P9c] public showcase")
    result = publish(dry_run=dry_run)
    atomic_write_json(Path(run_dir) / ARTIFACT, result)
    print(f"  showcase {result['status']}: {result['published_count']} published, "
          f"{len(result['held'])} held, {len(result['blocked'])} blocked")
    return result
