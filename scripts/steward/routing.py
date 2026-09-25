"""P7b finding router: one deterministic route per confirmed audit finding.

The audit model proposes an ``action`` (finding schema v2); this module
validates it against a fixed policy table and runs the matching executor.
Anything that fails validation becomes ``needs_carter`` with a plain reason.

Executors and their boundaries:

- ``doc_fix``: exact single replacement in an allowlisted doc, an independent
  read-only model re-check, then one commit for that file and a push.
- ``cleanup``: ignore rule + untrack paths matching ``CLEANUP_PATTERNS`` in the
  dotfiles bare repository only.
- ``deploy`` / ``version_update``: recorded only; the P1 steps own execution.
- ``code_fix``: the existing isolated worker fix/judge loop (injected by
  ``fixes.phase_7b_fix``), then a PR for a published review commit, with
  auto-merge only when live repository checks allow it (never ``--admin``).
"""
from __future__ import annotations

import difflib
import json
import re
import shlex
import subprocess
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .config import (
    AUTO_MERGE_CANDIDATES,
    AUTO_MERGE_EXCLUDED,
    CLEANUP_PATTERNS,
    DEPLOY_REGISTRY,
    DOC_FIX_FILES,
    DOC_FIX_ROOTS,
    FINDING_ACTIONS,
    FINDING_SEVERITIES,
    HOME,
    LOW_DEFAULT_SEVERITY_SECTIONS,
    MAX_WORKERS,
    P7B_REPORT_ONLY_SECTIONS,
    STEWARD_MODEL,
    VERSION_REGISTRY,
)
from . import runtime
from .worker import _INFRA_REPOSITORIES

ROUTE_KEYS = (
    "section", "finding_id", "claim", "severity", "action", "status",
    "summary", "detail", "decision", "revert", "pr_url", "commit", "iteration",
)
ROUTE_STATUSES = (
    "done", "pr_opened", "pr_auto_merge", "needs_carter", "report_only",
    "failed", "handled_by_p1",
)
# P1 step rows (01-applied.json) that execute version_update routes.
VERSION_STEPS = {
    "searxng": "searxng",
    "llama.cpp": "llama_cpp",
    "open-webui": "openwebui_update",
}
AUTO_MERGE_RECENT_RUNS = 5
# gh flag per repository setting, in order of preference.  Never --admin.
_MERGE_METHODS = (("allow_rebase_merge", "--rebase"), ("allow_squash_merge", "--squash"),
                  ("allow_merge_commit", "--merge"))
_ROUTED_VERDICTS = {"DRIFT", "ATTENTION"}
_TEXT_LIMIT = 1000


class RouteRejected(Exception):
    """Validation failure; the message is a human-readable needs_carter reason."""


def _run_cmd(argv, *, cwd=None, input_text=None, timeout=120):
    """Run argv; never raise. Returns a CompletedProcess."""
    try:
        return subprocess.run(
            [str(a) for a in argv],
            cwd=str(cwd) if cwd is not None else None,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=None if input_text is not None else subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(list(map(str, argv)), 127, "", str(exc))


def _gh_cmd(args, cwd=None):
    return _run_cmd(["gh", *args], cwd=cwd, timeout=120)


@dataclass
class RouteContext:
    """Injectable boundaries so tests never touch production state."""

    dry_run: bool = False
    run_dir: Path | None = None
    today: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    home: Path = HOME
    dev_root: Path = HOME / "dev"
    doc_roots: Sequence[Path] = DOC_FIX_ROOTS
    doc_files: Sequence[Path] = DOC_FIX_FILES
    dotfiles_git_dir: Path = HOME / ".dotfiles-homelab"
    cleanup_patterns: Sequence[str] = CLEANUP_PATTERNS
    omp_call: Callable[..., str] | None = None
    extract_json: Callable[[str], Any] | None = None
    run: Callable[..., subprocess.CompletedProcess] = _run_cmd
    gh: Callable[..., subprocess.CompletedProcess] = _gh_cmd
    fix_section: Callable[..., Mapping[str, Any]] | None = None
    max_workers: int = MAX_WORKERS

    def call_model(self, prompt):
        call = self.omp_call or runtime._call_omp_p
        return call(prompt, model=STEWARD_MODEL, mode="json", tools=runtime.NO_TOOLS)

    def parse_json(self, text):
        return (self.extract_json or runtime._extract_json)(text)


# ── normalization ────────────────────────────────────────────────────


def _text(value, limit=_TEXT_LIMIT):
    return str(value if value is not None else "").strip()[:limit]


def _confirmed_findings(section):
    """Confirmed findings, each overlaid on its worker finding (judge wins)."""
    workers = {
        f.get("id"): f
        for f in section.get("worker_findings") or []
        if isinstance(f, dict) and f.get("id")
    }
    out = []
    for item in section.get("judge_confirmed") or []:
        if not isinstance(item, dict):
            continue
        merged = dict(workers.get(item.get("id")) or {})
        merged.update({k: v for k, v in item.items() if v is not None})
        out.append(merged)
    return out


def normalize_finding(section_name, finding, index=1):
    """Return a v2-shaped finding; v1 findings route to needs_carter."""
    severity = str(finding.get("severity") or "").strip().lower()
    if severity not in FINDING_SEVERITIES:
        severity = "low" if section_name in LOW_DEFAULT_SEVERITY_SECTIONS else "medium"
    action = str(finding.get("action") or "").strip().lower()
    note = _text(finding.get("routing_note"))
    if not action:
        action, note = "needs_carter", note or "no route proposed"
    elif action not in FINDING_ACTIONS:
        note = f"unknown route {action!r} proposed"
        action = "needs_carter"
    target = finding.get("target")
    target = dict(target) if isinstance(target, Mapping) else {}
    return {
        "id": _text(finding.get("id"), 120) or f"finding-{index}",
        "claim": _text(finding.get("claim") or finding.get("finding"), 400),
        "evidence": _text(finding.get("evidence"), 4000),
        "fix": _text(finding.get("fix"), 2000),
        "severity": severity,
        "action": action,
        "target": target,
        "decision": _text(finding.get("decision"), 400),
        "routing_note": note,
    }


def _row(section, finding, status, summary, detail="", **extra):
    row = {
        "section": section,
        "finding_id": finding["id"],
        "claim": finding["claim"],
        "severity": finding["severity"],
        "action": finding["action"],
        "status": status,
        "summary": _text(summary),
        "detail": _text(detail),
        "decision": "",
        "revert": "",
        "pr_url": "",
        "commit": "",
        "iteration": None,
    }
    for key, value in extra.items():
        if key not in row:
            raise KeyError(f"route row key outside contract: {key}")
        row[key] = _text(value) if isinstance(value, str) else value
    return row


def _needs_carter(section, finding, reason, summary=None):
    decision = finding.get("decision") or (
        f"Decide how to handle: {finding['fix']}" if finding.get("fix") else
        "Decide how to handle this finding."
    )
    return _row(
        section, finding, "needs_carter",
        summary or "No automatic route; Carter decides.",
        reason, decision=_text(decision, 400),
    )


def _home_display(path, home, assign=False):
    """Render a path with ~ (standalone word) or $HOME (after '=')."""
    path, home = str(path), str(home)
    if path == home or path.startswith(home + "/"):
        return ("$HOME" if assign else "~") + path[len(home):]
    return shlex.quote(path)


def _under(path, root):
    try:
        Path(path).relative_to(Path(root))
        return True
    except ValueError:
        return False


# ── git helpers ──────────────────────────────────────────────────────


@dataclass
class _Repo:
    """A git repository addressed either normally or as a bare+work-tree pair."""

    base: list
    cwd: Path
    display: str

    def git(self, ctx, *args, timeout=120):
        return ctx.run([*self.base, *args], cwd=self.cwd, timeout=timeout)

    def out(self, ctx, *args):
        cp = self.git(ctx, *args)
        if cp.returncode != 0:
            raise RouteRejected(
                f"git {' '.join(args[:2])} failed: {_text(cp.stderr or cp.stdout, 300)}"
            )
        return cp.stdout


def _dotfiles_repo(ctx):
    git_dir, home = Path(ctx.dotfiles_git_dir), Path(ctx.home)
    return _Repo(
        ["git", f"--git-dir={git_dir}", f"--work-tree={home}"], home,
        f"git --git-dir={_home_display(git_dir, home, True)} "
        f"--work-tree={_home_display(home, home, True)}",
    )


def _plain_repo(ctx, top):
    return _Repo(["git", "-C", str(top)], top, f"git -C {_home_display(top, ctx.home)}")


def _current_branch(repo, ctx):
    branch = repo.out(ctx, "symbolic-ref", "--quiet", "--short", "HEAD").strip()
    if not branch:
        raise RouteRejected("repository is not on a branch")
    return branch


def _push(repo, ctx, sha, branch):
    cp = repo.git(ctx, "push", "origin", f"{sha}:refs/heads/{branch}", timeout=180)
    return cp.returncode == 0, _text(cp.stderr or cp.stdout, 500)


# ── doc_fix ──────────────────────────────────────────────────────────


def _doc_repo(ctx, doc):
    """Resolve the doc allowlist; returns (repo, relpath) or raises."""
    resolved_files = {Path(p).expanduser().resolve() for p in ctx.doc_files}
    if doc in resolved_files:
        return _dotfiles_repo(ctx), str(doc.relative_to(Path(ctx.home).resolve()))
    for root in ctx.doc_roots:
        root = Path(root).expanduser().resolve()
        if _under(doc, root) and doc != root:
            cp = ctx.run(["git", "-C", str(doc.parent), "rev-parse", "--show-toplevel"])
            if cp.returncode != 0 or not cp.stdout.strip():
                raise RouteRejected(f"{doc} is not inside a git repository")
            top = Path(cp.stdout.strip()).resolve()
            return _plain_repo(ctx, top), str(doc.relative_to(top))
    raise RouteRejected(
        f"doc {doc} is outside the doc-fix allowlist (~/notes/docs/ or ~/AGENTS.md)"
    )


def _doc_path(ctx, raw):
    raw = str(raw or "").strip()
    if not raw:
        raise RouteRejected("no automatic route: the doc fix names no document")
    if raw.startswith("~/"):
        path = Path(ctx.home) / raw[2:]
    else:
        path = Path(raw)
    if not path.is_absolute():
        raise RouteRejected(f"doc path is not absolute: {raw}")
    doc = path.resolve()
    if not doc.is_file():
        raise RouteRejected(f"doc does not exist: {raw}")
    return doc


def _recheck_prompt(section, finding, doc, diff):
    return (
        "You are an independent, read-only reviewer for an automated documentation edit. "
        "Do NOT edit files, run git, or change anything; only answer.\n\n"
        f"Audit section: {section}\nFinding id: {finding['id']}\n"
        f"Finding claim: {finding['claim']}\n"
        f"Finding evidence: {finding['evidence']}\n"
        f"Proposed fix: {finding['fix']}\n\n"
        f"Document: {doc}\nUnified diff of the edit:\n```diff\n{diff}\n```\n\n"
        "Questions:\n"
        "1. Is every factual statement in the new text supported by the finding's evidence?\n"
        "2. Does the edit change nothing beyond what the finding requires?\n"
        "3. Could the old text describe the intended state, with the live system being what "
        "is broken or misconfigured (so the system, not the document, should change)? Answer "
        "true when the evidence shows a failure, an error, or an unreachable/removed resource "
        "behind the mismatch.\n"
        "Answer pass only if 1 and 2 are clearly yes and 3 is clearly no. Return ONLY this JSON:\n"
        '```json\n{"verdict": "pass" | "fail", "supported_by_evidence": true | false, '
        '"changes_only_target": true | false, "system_should_change": true | false, '
        '"reason": "one sentence"}\n```'
    )


def _clear_pass(packet):
    return (
        isinstance(packet, Mapping)
        and str(packet.get("verdict") or "").strip().lower() == "pass"
        and packet.get("supported_by_evidence") is True
        and packet.get("changes_only_target") is True
        and packet.get("system_should_change") is False
    )


def execute_doc_fix(section, finding, ctx):
    target = finding["target"]
    try:
        doc = _doc_path(ctx, target.get("doc"))
        old_text, new_text = target.get("old_text"), target.get("new_text")
        if not isinstance(old_text, str) or not old_text:
            raise RouteRejected("no automatic route: the doc fix gives no exact current text")
        if not isinstance(new_text, str) or new_text == old_text:
            raise RouteRejected("no automatic route: the doc fix gives no different replacement text")
        repo, rel = _doc_repo(ctx, doc)
        original = doc.read_bytes()
        try:
            content = original.decode("utf-8")
        except UnicodeDecodeError:
            raise RouteRejected(f"{doc} is not UTF-8 text") from None
        count = content.count(old_text)
        if count != 1:
            raise RouteRejected(
                f"the text to replace occurs {count} times in {doc.name}; it must occur exactly once"
            )
        if repo.git(ctx, "ls-files", "--error-unmatch", "--", rel).returncode != 0:
            raise RouteRejected(f"{doc.name} is not tracked by git, so the edit could not be reverted")
        if repo.out(ctx, "status", "--porcelain", "--", rel).strip():
            raise RouteRejected(
                f"{doc.name} has uncommitted changes; the steward will not mix its edit with them"
            )
        branch = _current_branch(repo, ctx)
    except RouteRejected as exc:
        return _needs_carter(section, finding, str(exc))
    except OSError as exc:
        return _needs_carter(section, finding, f"could not read the document: {exc}")

    if ctx.dry_run:
        return _row(section, finding, "report_only",
                    f"Dry run: would replace one passage in {doc.name} and commit it.",
                    "validation passed; nothing changed")

    updated = content.replace(old_text, new_text, 1).encode("utf-8")
    diff = "".join(difflib.unified_diff(
        content.splitlines(keepends=True),
        updated.decode("utf-8").splitlines(keepends=True),
        fromfile=f"a/{rel}", tofile=f"b/{rel}",
    ))

    def restore():
        doc.write_bytes(original)

    doc.write_bytes(updated)
    try:
        packet = ctx.parse_json(ctx.call_model(_recheck_prompt(section, finding, doc, diff)))
    except Exception as exc:  # model/transport failure: never keep an unchecked edit
        restore()
        return _row(section, finding, "failed",
                    f"Doc fix for {doc.name} was not kept: the independent re-check could not run.",
                    f"re-check error: {exc}")
    if not _clear_pass(packet):
        restore()
        reason = _text(packet.get("reason") if isinstance(packet, Mapping) else packet, 400)
        return _needs_carter(
            section, finding,
            f"the independent re-check did not confirm the edit ({reason or 'no clear pass'}); "
            "the original text was restored",
            summary=f"Proposed edit to {doc.name} was rejected by the re-check and undone.",
        )
    if doc.read_bytes() != updated:
        return _needs_carter(section, finding,
                             f"{doc.name} changed while the edit was being checked; nothing was committed")

    message = f"docs(steward): {section} {finding['id']}: {finding['claim'][:72]}"
    cp = repo.git(ctx, "commit", "--only", "-m", message, "--", rel)
    if cp.returncode != 0:
        restore()
        return _row(section, finding, "failed",
                    f"Doc fix for {doc.name} could not be committed; the original text was restored.",
                    _text(cp.stderr or cp.stdout))
    sha = repo.out(ctx, "rev-parse", "HEAD").strip()
    revert = f"{repo.display} revert {sha}"
    pushed, push_error = _push(repo, ctx, sha, branch)
    if not pushed:
        return _row(section, finding, "failed",
                    f"Doc fix for {doc.name} was committed locally but the push failed.",
                    push_error, revert=revert, commit=sha)
    return _row(section, finding, "done",
                f"Corrected {doc.name} ({section}) and pushed the commit.",
                "independent re-check passed", revert=revert, commit=sha)


# ── cleanup ──────────────────────────────────────────────────────────


def _cleanup_patterns_for(ctx, paths):
    home = str(Path(ctx.home))
    matched = []
    for raw in paths:
        value = str(raw or "").strip()
        if value.startswith("~/"):
            value = value[2:]
        elif value.startswith(home + "/"):
            value = value[len(home) + 1:]
        if not value or value.startswith("/") or ".." in Path(value).parts:
            raise RouteRejected(f"cleanup path {raw!r} is not a home-relative path")
        for pattern in ctx.cleanup_patterns:
            if value == pattern.rstrip("/") or value.startswith(pattern):
                if pattern not in matched:
                    matched.append(pattern)
                break
        else:
            raise RouteRejected(
                f"cleanup path {raw!r} does not match an allowed cleanup pattern "
                f"({', '.join(ctx.cleanup_patterns)})"
            )
    return matched


def execute_cleanup(section, finding, ctx):
    paths = finding["target"].get("paths")
    if isinstance(paths, str):
        paths = [paths]
    try:
        if not isinstance(paths, list) or not paths:
            raise RouteRejected("no automatic route: the cleanup names no paths")
        patterns = _cleanup_patterns_for(ctx, paths)
        repo = _dotfiles_repo(ctx)
        ignore = Path(ctx.home) / ".gitignore"
        if repo.git(ctx, "ls-files", "--error-unmatch", "--", ".gitignore").returncode != 0:
            raise RouteRejected("~/.gitignore is not tracked in the dotfiles repo")
        if repo.out(ctx, "status", "--porcelain", "--", ".gitignore").strip():
            raise RouteRejected("~/.gitignore has uncommitted changes")
        if repo.out(ctx, "diff", "--cached", "--name-only").strip():
            raise RouteRejected("the dotfiles index already has staged changes")
        branch = _current_branch(repo, ctx)
        original = ignore.read_bytes()
    except RouteRejected as exc:
        return _needs_carter(section, finding, str(exc))
    except OSError as exc:
        return _needs_carter(section, finding, f"could not read ~/.gitignore: {exc}")

    lines = {line.strip() for line in original.decode("utf-8", "replace").splitlines()}
    missing_rules = [
        "/" + p for p in patterns if "/" + p not in lines and p not in lines
    ]
    untrack = []
    for pattern in patterns:
        listed = repo.git(ctx, "ls-files", "-z", "--", pattern.rstrip("/"))
        if listed.returncode == 0 and listed.stdout.strip("\0"):
            untrack.append(pattern.rstrip("/"))
    if not missing_rules and not untrack:
        return _row(section, finding, "done",
                    "Already ignored and untracked; nothing needed changing.")
    plan = ", ".join(
        [f"ignore {r}" for r in missing_rules] + [f"untrack {p}/" for p in untrack]
    )
    if ctx.dry_run:
        return _row(section, finding, "report_only", f"Dry run: would {plan} in dotfiles.",
                    "validation passed; nothing changed")

    def rollback():
        repo.git(ctx, "reset", "-q", "--", ".gitignore", *untrack)
        ignore.write_bytes(original)

    try:
        if missing_rules:
            text = original.decode("utf-8", "replace")
            if text and not text.endswith("\n"):
                text += "\n"
            ignore.write_text(text + "".join(r + "\n" for r in missing_rules))
            repo.out(ctx, "add", "--", ".gitignore")
        if untrack:
            repo.out(ctx, "rm", "-r", "--cached", "--quiet", "--", *untrack)
        staged = [
            p for p in repo.out(ctx, "diff", "--cached", "--name-only", "-z").split("\0") if p
        ]
        allowed = [".gitignore", *untrack]
        stray = [p for p in staged if not any(p == a or p.startswith(a + "/") for a in allowed)]
        if stray:
            raise RouteRejected(f"unexpected staged paths: {', '.join(stray[:5])}")
        message = f"chore(steward): {section} {finding['id']}: {plan}"[:200]
        repo.out(ctx, "commit", "-q", "-m", message)
    except RouteRejected as exc:
        rollback()
        return _row(section, finding, "failed", "Dotfiles cleanup could not be committed; nothing changed.",
                    str(exc))
    sha = repo.out(ctx, "rev-parse", "HEAD").strip()
    revert = f"{repo.display} revert {sha}"
    pushed, push_error = _push(repo, ctx, sha, branch)
    if not pushed:
        return _row(section, finding, "failed",
                    "Dotfiles cleanup was committed locally but the push failed.",
                    push_error, revert=revert, commit=sha)
    return _row(section, finding, "done", f"Dotfiles cleanup: {plan}.",
                revert=revert, commit=sha)


# ── deploy / version_update ──────────────────────────────────────────


def _p1_step(applied, step, service=None):
    for row in (applied or {}).get("steps") or []:
        if not isinstance(row, Mapping) or row.get("step") != step:
            continue
        if service is None or row.get("service") == service:
            return row
    return None


def execute_p1_route(section, finding, ctx, applied):
    action = finding["action"]
    service = str(finding["target"].get("service") or "").strip()
    if action == "deploy":
        if service not in DEPLOY_REGISTRY:
            return _needs_carter(section, finding,
                                 f"no automatic deploy route for service {service or '(none named)'!r}")
        step = _p1_step(applied, "app_deploy", service)
    else:
        if service not in VERSION_REGISTRY:
            return _needs_carter(section, finding,
                                 f"no automatic version-update route for {service or '(none named)'!r}")
        step = _p1_step(applied, VERSION_STEPS[service])
    what = "deploy" if action == "deploy" else "version update"
    if step is None:
        return _row(section, finding, "handled_by_p1",
                    f"The P1 {service} {what} step owns this; it did not run tonight.",
                    "no P1 step row in 01-applied.json")
    status = str(step.get("status") or "")
    reason = _text(step.get("error") or step.get("detail") or step.get("reason"))
    versions = ""
    if step.get("pre_version") or step.get("post_version"):
        versions = f" ({step.get('pre_version') or '?'} -> {step.get('post_version') or '?'})"
    if status in ("failed", "rolled_back"):
        return _row(section, finding, "failed",
                    f"Tonight's P1 {service} {what} {status.replace('_', ' ')}{versions}.",
                    reason or status, revert=_text(step.get("revert")))
    return _row(section, finding, "handled_by_p1",
                f"Tonight's P1 {service} {what} step: {status or 'unknown'}{versions}.",
                reason, revert=_text(step.get("revert")))


# ── code_fix ─────────────────────────────────────────────────────────


def _code_fix_target(ctx, finding):
    """Validate and flatten a code_fix finding to the worker's keys."""
    target = finding["target"]
    raw_repo = str(target.get("repo") or "").strip()
    if not raw_repo:
        raise RouteRejected("no automatic route: the finding names no repairable repository")
    home = Path(ctx.home)
    if raw_repo.startswith("~/"):
        repo = home / raw_repo[2:]
    elif raw_repo.startswith("/"):
        repo = Path(raw_repo)
    else:
        repo = Path(ctx.dev_root) / raw_repo
    repo = repo.resolve()
    dev_root = Path(ctx.dev_root).resolve()
    if not _under(repo, dev_root) or repo == dev_root:
        raise RouteRejected(f"repository {raw_repo} is not an app repository under ~/dev")
    for protected in (Path(ctx.dotfiles_git_dir), home / "scripts", home / "system-config"):
        if _under(repo, protected.resolve()):
            raise RouteRejected(f"repository {raw_repo} is steward/dotfiles infrastructure")
    if repo.name in _INFRA_REPOSITORIES:
        raise RouteRejected(f"{repo.name} is an infrastructure repository; code repairs need Carter")
    if repo.name in AUTO_MERGE_EXCLUDED:
        raise RouteRejected(f"{repo.name} is excluded from automatic code repair")
    if not (repo / ".git").exists():
        raise RouteRejected(f"{raw_repo} is not a git repository")
    paths = target.get("paths")
    if isinstance(paths, str):
        paths = [paths]
    if not isinstance(paths, list) or not paths:
        raise RouteRejected("no automatic route: the finding names no repairable file")
    rels = []
    for raw in paths:
        value = str(raw or "").strip()
        if value.startswith("~/"):
            value = str(home / value[2:])
        if value.startswith("/"):
            if not _under(Path(value), repo):
                raise RouteRejected(f"path {raw} is outside {repo.name}")
            value = str(Path(value).relative_to(repo))
        if not value or ".." in Path(value).parts:
            raise RouteRejected(f"path {raw!r} is not a safe repository-relative path")
        candidate = repo / value
        if candidate.is_symlink() or not candidate.exists():
            raise RouteRejected(f"path {value} does not exist in {repo.name}")
        if value not in rels:
            rels.append(value)
    return {
        "id": finding["id"],
        "claim": finding["claim"],
        "evidence": finding["evidence"],
        "fix": finding["fix"],
        "repo": str(repo),
        "paths": rels,
    }


def _gh_json(ctx, args, cwd):
    cp = ctx.gh(args, cwd)
    if cp.returncode != 0:
        return None
    try:
        return json.loads(cp.stdout or "null")
    except json.JSONDecodeError:
        return None


def auto_merge_eligibility(ctx, repo_name, nwo, branch, cwd=None):
    """Live checks; returns (eligible, reason). Every check must pass."""
    for name in (repo_name, str(nwo or "").rsplit("/", 1)[-1]):
        if name in AUTO_MERGE_EXCLUDED:
            return False, f"{name} is excluded from auto-merge"
    if repo_name not in AUTO_MERGE_CANDIDATES:
        return False, f"{repo_name} is not an auto-merge candidate"
    info = _gh_json(ctx, ["api", f"repos/{nwo}"], cwd)
    if not isinstance(info, Mapping):
        return False, "could not read repository settings"
    if info.get("allow_auto_merge") is not True:
        return False, "auto-merge is disabled in the repository settings"
    quoted = urllib.parse.quote(branch, safe="")
    required = False
    protection = _gh_json(ctx, ["api", f"repos/{nwo}/branches/{quoted}/protection"], cwd)
    if isinstance(protection, Mapping):
        checks = protection.get("required_status_checks")
        if isinstance(checks, Mapping) and (checks.get("contexts") or checks.get("checks")):
            required = True
    if not required:
        rules = _gh_json(ctx, ["api", f"repos/{nwo}/rules/branches/{quoted}"], cwd)
        for rule in rules if isinstance(rules, list) else []:
            if not isinstance(rule, Mapping) or rule.get("type") != "required_status_checks":
                continue
            params = rule.get("parameters")
            if isinstance(params, Mapping) and params.get("required_status_checks"):
                required = True
                break
    if not required:
        return False, f"{branch} does not require a status check"
    # Only push runs on the default branch are CI evidence; Dependabot "dynamic"
    # and scheduled runs would otherwise stand in for the test suite.
    runs = _gh_json(ctx, [
        "api",
        f"repos/{nwo}/actions/runs?branch={quoted}&event=push&status=completed"
        f"&per_page={AUTO_MERGE_RECENT_RUNS}",
    ], cwd)
    rows = runs.get("workflow_runs") if isinstance(runs, Mapping) else None
    if not isinstance(rows, list):
        return False, "could not read recent workflow runs"
    rows = rows[:AUTO_MERGE_RECENT_RUNS]
    if len(rows) < AUTO_MERGE_RECENT_RUNS:
        return False, f"fewer than {AUTO_MERGE_RECENT_RUNS} completed push runs on {branch}"
    bad = [r for r in rows if not isinstance(r, Mapping) or r.get("conclusion") != "success"]
    if bad:
        return False, f"{len(bad)} of the last {AUTO_MERGE_RECENT_RUNS} {branch} push runs did not succeed"
    return True, "required checks, auto-merge setting, and recent CI all pass"


def repo_merge_method(ctx, nwo, cwd=None):
    """(gh flag, "") for the first merge method the repository allows, or (None, reason)."""
    info = _gh_json(ctx, ["api", f"repos/{nwo}"], cwd)
    if not isinstance(info, Mapping):
        return None, "could not read the repository merge settings"
    for setting, flag in _MERGE_METHODS:
        if info.get(setting) is True:
            return flag, ""
    return None, "no merge method is enabled in the repository settings"


def _pr_body(section, findings, section_result):
    lines = [f"Automated repair from the Homelab Steward audit section `{section}`.", "", "## Findings"]
    for f in findings:
        lines += [f"- **{f['id']}** ({f['severity']}): {f['claim']}",
                  f"  - Evidence: {f['evidence'][:1500]}"]
    iterations = section_result.get("iterations") or []
    last = iterations[-1] if iterations else {}
    lines += ["", "## Validation"]
    for repo in last.get("validation") or []:
        for record in repo.get("records") or []:
            if isinstance(record, Mapping):
                argv = " ".join(str(a) for a in record.get("argv") or [])
                lines.append(f"- `{argv}` -> exit {record.get('returncode')}")
    lines += [
        "", "## Judge",
        f"Verdict: {section_result.get('judge_verdict', 'unknown')} "
        f"after {section_result.get('iteration_count', len(iterations))} iteration(s).",
        _text(section_result.get("judge_summary"), 2000),
    ]
    return "\n".join(lines)[:20000]


def open_pull_request(ctx, section, repo, commit, findings, section_result):
    """Push a validated review commit and open (maybe auto-merge) a PR."""
    repo = Path(repo)
    view = _gh_json(ctx, ["repo", "view", "--json", "nameWithOwner,defaultBranchRef"], repo)
    nwo = view.get("nameWithOwner") if isinstance(view, Mapping) else None
    default = ((view or {}).get("defaultBranchRef") or {}).get("name") if isinstance(view, Mapping) else None
    if not nwo or not default:
        return {"status": "failed", "summary": "Could not identify the GitHub repository for the PR.",
                "detail": "gh repo view failed", "commit": commit}
    branch = f"steward/{ctx.today}-{section}-{commit[:8]}"
    git_repo = _plain_repo(ctx, repo)
    pushed, error = _push(git_repo, ctx, commit, branch)
    if not pushed:
        return {"status": "failed", "summary": "The reviewed repair commit could not be pushed.",
                "detail": error, "commit": commit}
    title = f"steward: {section} repair ({commit[:8]})"
    cp = ctx.gh([
        "pr", "create", "--repo", nwo, "--head", branch, "--base", default,
        "--title", title, "--body", _pr_body(section, findings, section_result),
    ], repo)
    url = (cp.stdout or "").strip().splitlines()[-1:] if cp.returncode == 0 else []
    if not url:
        return {"status": "failed", "summary": "Pushed the repair branch but could not open a PR.",
                "detail": _text(cp.stderr or cp.stdout),
                "revert": f"git -C {_home_display(repo, ctx.home)} push origin --delete {branch}",
                "commit": commit}
    url = url[0].strip()
    close = f"gh pr close {url} --delete-branch"
    eligible, reason = auto_merge_eligibility(ctx, repo.name, nwo, default, repo)
    flag = None
    if eligible:
        flag, why = repo_merge_method(ctx, nwo, repo)
        if flag is None:
            reason = why
    if flag:
        merge = ctx.gh(["pr", "merge", url, "--auto", flag, "--delete-branch"], repo)
        if merge.returncode == 0:
            return {
                "status": "pr_auto_merge",
                "summary": f"Opened a PR for {repo.name}; it will merge once required checks pass.",
                "detail": reason, "pr_url": url, "commit": commit,
                "revert": f"{close} (before merge) or git -C {_home_display(repo, ctx.home)} "
                          f"revert <merged commit> on {default}",
            }
        reason = f"auto-merge request failed: {_text(merge.stderr or merge.stdout, 300)}"
    return {
        "status": "pr_opened",
        "summary": f"Opened a PR for {repo.name}; it waits for Carter's review.",
        "detail": reason, "pr_url": url, "commit": commit, "revert": close,
    }


def _matching_fix_row(section_result, flat):
    key = re.sub(r"\s+", " ", flat["claim"].lower())[:200]
    for row in reversed(section_result.get("fixes_applied") or []):
        if not isinstance(row, Mapping):
            continue
        if row.get("id") == flat["id"]:
            return row
        text = re.sub(r"\s+", " ", str(row.get("finding") or "").strip().lower())[:200]
        if key and text == key:
            return row
    return {}


def _code_fix_rows(ctx, section, items, section_result):
    """items: list of (normalized finding, flattened worker finding)."""
    rows = []
    status = str(section_result.get("status") or "")
    iterations = section_result.get("iteration_count") or None
    if status == "dry-run":
        return [
            _row(section, f, "report_only",
                 f"Dry run: would send {Path(flat['repo']).name} to the isolated repair worker.",
                 "validation passed; nothing changed")
            for f, flat in items
        ]
    commits = {
        str(c.get("repository")): c for c in section_result.get("source_repair_commits") or []
        if isinstance(c, Mapping) and c.get("commit")
    }
    pr_results = {}
    for repo_path, commit in commits.items():
        repo_findings = [f for f, flat in items if flat["repo"] == repo_path]
        pr_results[repo_path] = open_pull_request(
            ctx, section, repo_path, str(commit["commit"]), repo_findings, section_result)
    judge = _text(section_result.get("judge_summary") or section_result.get("error"), 500)
    stop = str(section_result.get("stop_reason") or "")
    for finding, flat in items:
        fix_row = _matching_fix_row(section_result, flat)
        iteration = fix_row.get("iteration") or iterations
        pr = pr_results.get(flat["repo"])
        if pr is not None:
            rows.append(_row(
                section, finding, pr["status"], pr["summary"], pr.get("detail", ""),
                pr_url=pr.get("pr_url", ""), commit=pr.get("commit", ""),
                revert=pr.get("revert", ""), iteration=iteration,
            ))
        elif status == "fix-failed" or stop == "worker-unavailable":
            rows.append(_row(section, finding, "failed",
                             "The isolated repair worker could not run for this finding.",
                             judge or "worker unavailable", iteration=iteration))
        else:
            reason = (
                f"the repair worker's policy refused it: {judge}" if stop == "policy-rejected"
                else f"automatic repair did not pass review ({stop or 'no change'}): {judge}"
            )
            row = _needs_carter(section, finding, reason,
                                summary="Automatic code repair was attempted but not accepted.")
            row["iteration"] = iteration
            rows.append(row)
    return rows


# ── router ───────────────────────────────────────────────────────────


def route_findings(sections, applied=None, ctx: RouteContext | None = None):
    """Route every confirmed finding. Returns {"routes", "sections"}.

    ``sections`` holds the code_fix section results from ``ctx.fix_section``
    (the legacy 07b ``sections`` shape); non-code routes never reach it.
    """
    ctx = ctx or RouteContext()
    routes: list[tuple[int, dict]] = []
    code_fix: dict[str, list] = {}
    order = 0
    slots: dict[str, list[int]] = {}
    for section in sections or []:
        if not isinstance(section, Mapping):
            continue
        name = str(section.get("name") or "")
        verdict = str(section.get("verdict") or "").removeprefix("cached-")
        if verdict not in _ROUTED_VERDICTS:
            continue
        for index, raw in enumerate(_confirmed_findings(section), start=1):
            finding = normalize_finding(name, raw, index)
            order += 1
            if name in P7B_REPORT_ONLY_SECTIONS:
                # Report-only means "never mutate automatically", not "unimportant":
                # a finding that asks for Carter's decision stays a decision.
                proposed = finding["action"]
                if proposed == "needs_carter":
                    routes.append((order, _needs_carter(
                        name, finding,
                        finding["routing_note"] or "this section is report-only by policy")))
                    continue
                finding["action"] = "report_only"
                routes.append((order, _row(
                    name, finding, "report_only", "Reported only; this section is never auto-fixed.",
                    f"section is report-only by policy (proposed route: {proposed})")))
                continue
            action = finding["action"]
            try:
                if action == "needs_carter":
                    row = _needs_carter(name, finding, finding["routing_note"] or "the audit asks for Carter's decision")
                elif action == "report_only":
                    row = _row(name, finding, "report_only", "Reported only.", finding["routing_note"])
                elif action == "doc_fix":
                    row = execute_doc_fix(name, finding, ctx)
                elif action == "cleanup":
                    row = execute_cleanup(name, finding, ctx)
                elif action in ("deploy", "version_update"):
                    row = execute_p1_route(name, finding, ctx, applied)
                else:  # code_fix
                    flat = _code_fix_target(ctx, finding)
                    code_fix.setdefault(name, []).append((finding, flat))
                    slots.setdefault(name, []).append(order)
                    continue
            except RouteRejected as exc:
                row = _needs_carter(name, finding, str(exc))
            except Exception as exc:  # one bad finding never blocks the rest
                row = _row(name, finding, "failed", f"The {action} route failed unexpectedly.",
                           f"{type(exc).__name__}: {exc}")
            routes.append((order, row))

    section_results = _run_code_fix_sections(ctx, code_fix)
    for name, items in code_fix.items():
        result = section_results.get(name) or {"status": "fix-failed", "error": "no result"}
        try:
            rows = _code_fix_rows(ctx, name, items, result)
        except Exception as exc:
            rows = [
                _row(name, f, "failed", "The code-fix route failed unexpectedly.",
                     f"{type(exc).__name__}: {exc}")
                for f, _ in items
            ]
        routes.extend(zip(slots[name], rows))
    routes.sort(key=lambda pair: pair[0])
    return {
        "routes": [row for _, row in routes],
        "sections": list(section_results.values()),
    }


def _run_code_fix_sections(ctx, code_fix):
    if not code_fix:
        return {}
    if ctx.fix_section is None:
        raise RuntimeError("route_findings needs ctx.fix_section for code_fix findings")
    results = {}
    if ctx.dry_run:
        for name, items in code_fix.items():
            results[name] = ctx.fix_section(name, [flat for _, flat in items], True, ctx.run_dir)
        return results
    with ThreadPoolExecutor(max_workers=max(1, ctx.max_workers)) as pool:
        futures = {
            pool.submit(ctx.fix_section, name, [flat for _, flat in items], False, ctx.run_dir): name
            for name, items in code_fix.items()
        }
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                results[name] = fut.result()
            except Exception as exc:
                results[name] = {"section": name, "status": "fix-failed", "error": str(exc)}
    return results
