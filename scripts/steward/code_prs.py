"""P7b steward-code route: repair ~/scripts through a PR on the private dotfiles repo.

The router (``routing._steward_code_target``) accepts a confirmed ``code_fix``
finding on ``~/scripts/**`` unless ``worker.steward_code_path_reason`` names a
protected path.  This module then

1. clones origin/main of the private dotfiles repository into a disposable
   directory under ``worker.STEWARD_CODE_ROOT`` (the live tree must match
   origin/main on the finding's paths), which the unchanged repair worker
   repairs in a disposable snapshot, validates (``verify-*.sh full`` for every
   touched area), and has judged;
2. gates the published review commit deterministically: single commit on
   the base, only allowed paths, bounded diff, deterministic secret scan, no
   added sudo/firewall/systemd-enablement/network-exposure lines, and every
   required verifier recorded as passed;
3. pushes ``steward/fix-<date>-<id>`` from the steward process and opens a PR
   labelled ``steward-auto``.  ``code_pickup`` merges it after 24 h.
"""
from __future__ import annotations

import json
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

from .code_pickup import BRANCH_PREFIX, HOLD_LABEL, LABEL, OBJECTION_WINDOW, PR_MARKER
from .config import DOTFILES_REPO
from .dotfiles import scan_diff_for_secrets
from .worker import steward_code_path_reason, steward_code_validation_commands

MAX_PRS_PER_NIGHT = 1
MAX_FILES = 8
MAX_CHANGED_LINES = 400
# Lines that would change host privileges or exposure are Carter's call,
# whether the patch adds them or removes them.
_RISKY_LINES = (
    ("sudo", re.compile(r"(?<![A-Za-z0-9])sudo|NOPASSWD", re.IGNORECASE)),
    ("firewall", re.compile(r"\b(?:ufw|iptables|ip6tables|nft)\b")),
    ("systemd enablement", re.compile(
        r"\bsystemctl\b.*\b(?:enable|unmask|link|mask)\b|\.wants/|\bWantedBy=")),
    ("network exposure", re.compile(r"0\.0\.0\.0|\[::\]|\bINADDR_ANY\b|--publish\b|\bingress:")),
    ("privilege", re.compile(r"\bsetcap\b|\bchmod\s+[ugoa]*\+s\b|\bchown\s+root\b")),
)
# Removing a line that mentions one of these deletes a guard; never automatic.
GUARD_TOKENS = ("setpriv", "no-new-privs", "_SECRET", "scan", "protected", "PROTECTED",
                "--admin", "hold")


class StewardCodeRejected(Exception):
    """A deterministic gate refused the change; the message is for Carter."""


def _text(value, limit=600):
    return str(value if value is not None else "").strip()[:limit]


def _git(ctx, repo, *args, timeout=120, input_text=None):
    return ctx.run(["git", "-c", "core.hooksPath=/dev/null", "-C", str(repo), *args],
                   cwd=repo, timeout=timeout, input_text=input_text)


def _must(cp, what):
    if cp.returncode != 0:
        raise StewardCodeRejected(f"{what} failed: {_text(cp.stderr or cp.stdout, 300)}")
    return cp.stdout


def _content_lines(diff):
    """(sign, path, text) for every added/removed line inside a hunk.

    Tracks hunk state, so content starting with '++'/'--' (which renders as
    '+++'/'---') is still content, not a file header."""
    path, in_hunk = "", False
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            path, in_hunk = line.split(" b/", 1)[-1], False
        elif line.startswith("@@"):
            in_hunk = True
        elif in_hunk and line[:1] in ("+", "-"):
            yield line[0], path, line[1:]


def _line_risk(sign, text):
    for label, pattern in _RISKY_LINES:
        if pattern.search(text):
            verb = "adds" if sign == "+" else "removes"
            return f"patch {verb} a {label} line; host-exposure changes need Carter"
    if sign == "-":
        token = next((t for t in GUARD_TOKENS if t in text), None)
        if token:
            return f"patch removes a guard line (mentions {token!r}); needs Carter"
    if sign == "+":
        rule = _line_secret(text)
        if rule:
            return f"secret scan flagged an added line ({rule})"
    return None


def _line_secret(text):
    from .public_dotfiles import _line_finding  # the P9c superset of the P9b rules
    return _line_finding(text)


def remote_url(ctx):
    """The private repository fetch URL (ctx override first, else origin)."""
    if getattr(ctx, "dotfiles_remote", None):
        return str(ctx.dotfiles_remote)
    cp = ctx.run(["git", "--git-dir", str(ctx.dotfiles_git_dir), "config", "--get",
                  "remote.origin.url"], cwd=None, timeout=20)
    url = (cp.stdout or "").strip()
    if not re.fullmatch(rf"(?:git@github\.com:|ssh://git@github\.com/|https://github\.com/)"
                        rf"{re.escape(DOTFILES_REPO)}(?:\.git)?", url):
        raise StewardCodeRejected("dotfiles origin is not the private dotfiles repository")
    return url


def blocking_pr(ctx, paths: Sequence[str]):
    """(url, reason) of a steward-code PR that blocks a new one, else None.

    One per night: any steward-auto PR (any state) on today's branch prefix.
    No duplicates: any OPEN steward-auto PR touching one of ``paths``."""
    cp = ctx.gh(["pr", "list", "--repo", DOTFILES_REPO, "--state", "all", "--label", LABEL,
                 "--limit", "50", "--json", "headRefName,url,state,files"], None)
    try:
        rows = json.loads(cp.stdout or "null") if cp.returncode == 0 else None
    except ValueError:
        rows = None
    if not isinstance(rows, list):
        raise StewardCodeRejected(f"could not list steward-code PRs: {_text(cp.stderr, 200)}")
    prefix = f"{BRANCH_PREFIX}{ctx.today}-"
    wanted = set(paths)
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        url = str(row.get("url") or "")
        if str(row.get("headRefName") or "").startswith(prefix):
            return url, "a steward-code PR was already opened tonight"
        touched = {str((f or {}).get("path") or "") for f in row.get("files") or []}
        overlap = sorted(wanted & touched)
        if row.get("state") == "OPEN" and overlap:
            return url, "an open steward-code PR already changes " + ", ".join(overlap[:5])
    return None


def prepare_scratch(ctx, paths: Sequence[str]):
    """Clone origin/main into a fresh scratch repository; returns (path, base)."""
    url = remote_url(ctx)
    root = Path(ctx.steward_code_root)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix=f"{ctx.today}-", dir=root))
    try:
        _must(ctx.run(["git", "init", "-q", "--initial-branch=main", str(scratch)], cwd=None,
                      timeout=30), "git init")
        _must(_git(ctx, scratch, "fetch", "-q", "--no-tags", "--depth", "1", url, "refs/heads/main",
                   timeout=300), "fetch origin/main")
        base = _must(_git(ctx, scratch, "rev-parse", "FETCH_HEAD"), "rev-parse").strip()
        _must(_git(ctx, scratch, "-c", "advice.detachedHead=false", "checkout", "-q", "--detach", base),
              "checkout")
        home = Path(ctx.home)
        for rel in paths:
            live, copy = home / rel, scratch / rel
            if copy.is_symlink() or not copy.is_file():
                raise StewardCodeRejected(f"~/{rel} is not a regular file on origin/main")
            if not live.is_file() or live.read_bytes() != copy.read_bytes():
                raise StewardCodeRejected(
                    f"live ~/{rel} differs from origin/main; commit/push or pick it up first")
        return scratch, base
    except BaseException:
        shutil.rmtree(scratch, ignore_errors=True)
        raise


def _verification_records(section_result, repo):
    iterations = section_result.get("iterations") or []
    last = iterations[-1] if iterations else {}
    for entry in last.get("validation") or []:
        if isinstance(entry, Mapping) and str(entry.get("repository")) == str(repo):
            return [r for r in entry.get("records") or [] if isinstance(r, Mapping)]
    return []


def gate(ctx, repo, base, commit, section_result):
    """Deterministic pre-PR gate; returns the facts for the PR body or raises."""
    parents = _must(_git(ctx, repo, "rev-list", "--parents", "-n", "1", commit), "rev-list").split()
    if parents != [commit, base]:
        raise StewardCodeRejected("review commit is not a single commit on origin/main")
    names = _must(_git(ctx, repo, "diff", "--name-only", "-z", "--no-renames", base, commit), "diff")
    paths = [p for p in names.split("\0") if p]
    if not paths:
        raise StewardCodeRejected("review commit changes nothing")
    if len(paths) > MAX_FILES:
        raise StewardCodeRejected(f"patch touches {len(paths)} files (cap {MAX_FILES})")
    for path in paths:
        reason = steward_code_path_reason(path)
        if reason:
            raise StewardCodeRejected(f"steward-code protected: {reason}")
    numstat = _must(_git(ctx, repo, "diff", "--numstat", "--no-renames", base, commit), "numstat")
    changed = 0
    for line in numstat.splitlines():
        added, removed, _ = (line.split("\t", 2) + ["", ""])[:3]
        if not added.isdigit() or not removed.isdigit():
            raise StewardCodeRejected("binary changes are not auto-repairable")
        changed += int(added) + int(removed)
    if changed > MAX_CHANGED_LINES:
        raise StewardCodeRejected(f"patch changes {changed} lines (cap {MAX_CHANGED_LINES})")
    diff = _must(_git(ctx, repo, "diff", "--no-ext-diff", "--no-textconv", "--no-renames",
                      base, commit), "diff")
    secrets = scan_diff_for_secrets(diff)
    if secrets:
        where = ", ".join(f"{s.get('path')}:{s.get('line')} ({s.get('rule')})" for s in secrets[:5])
        raise StewardCodeRejected(f"secret scan flagged {where}")
    for sign, path, text in _content_lines(diff):
        risk = _line_risk(sign, text)
        if risk:
            raise StewardCodeRejected(f"{path}: {risk}")
    records = _verification_records(section_result, repo)
    required = steward_code_validation_commands(paths)
    by_argv = {tuple(str(a) for a in r.get("argv") or []): r for r in records}
    missing = [" ".join(argv) for argv in required if tuple(argv) not in by_argv]
    failed = [" ".join(str(a) for a in r.get("argv") or []) for r in records
              if type(r.get("returncode")) is not int or r.get("returncode") != 0]
    if missing or failed or not records:
        raise StewardCodeRejected(
            "verification did not pass: " + "; ".join(
                [f"missing {m}" for m in missing] + [f"failed {f}" for f in failed]
                or ["no verification records"]))
    return {"paths": paths, "changed_lines": changed, "records": records}


def _body(section, findings, facts, section_result):
    lines = [PR_MARKER, f"Automated steward-code repair from audit section `{section}`.", "",
             "## Finding"]
    for f in findings:
        lines += [f"- **{f['id']}** ({f['severity']}): {f['claim']}",
                  f"  - Evidence: {_text(f.get('evidence'), 1500)}",
                  f"  - Fix asked for: {_text(f.get('fix'), 800)}"]
    lines += ["", f"## Change ({facts['changed_lines']} changed lines)"]
    lines += [f"- `~/{p}`" for p in facts["paths"]]
    lines += ["", "## Verification (repair worker, patched snapshot of this base)"]
    for record in facts["records"]:
        output = f"{record.get('stdout') or ''}\n{record.get('stderr') or ''}".strip()
        tail = [line for line in output.splitlines() if line.strip()][-3:]
        argv = " ".join(str(a) for a in record.get("argv") or [])
        lines.append(f"- `{argv[:200]}` -> exit {record.get('returncode')}"
                     + (f": `{' / '.join(t.strip() for t in tail)[:300]}`" if tail else ""))
    lines += [
        "", "## Judge",
        f"Verdict: {section_result.get('judge_verdict', 'unknown')}. "
        + _text(section_result.get("judge_summary"), 1500),
        "", "## Objection window",
        f"The steward merges this PR at its first nightly startup at least "
        f"{int(OBJECTION_WINDOW.total_seconds() // 3600)} h after it was opened, once the branch "
        "is up to date with main, `scripts-ci` is green on the head commit, and the head tree "
        "passes the verifiers again on the host. **To object: close this PR or add the "
        f"label `{HOLD_LABEL}`.** After a merge, undo with `git revert <merge commit>` on main; "
        "the next steward startup picks the revert up.",
    ]
    return "\n".join(lines)[:20000]


def _slug(value, limit=40):
    return re.sub(r"[^a-z0-9]+", "-", str(value).lower()).strip("-")[:limit] or "finding"


def _ensure_labels(ctx):
    for name, color, description in (
        (LABEL, "0e8a16", "Opened by the homelab steward; auto-merges after 24 h"),
        (HOLD_LABEL, "d93f0b", "Stops the steward from auto-merging this PR"),
    ):
        # Fails harmlessly when the label already exists.
        ctx.gh(["label", "create", name, "--repo", DOTFILES_REPO, "--color", color,
                "--description", description], None)


def open_steward_code_pr(ctx, section, repo, base, commit, findings, section_result):
    """Gate, push, and open the PR.  Returns route-row fields; never raises."""
    repo = Path(repo)
    try:
        facts = gate(ctx, repo, base, commit, section_result)
    except StewardCodeRejected as exc:
        return {"status": "needs_carter", "commit": commit,
                "summary": "The steward-code repair was not proposed: a deterministic gate refused it.",
                "detail": str(exc)}
    fid = findings[0]["id"] if findings else "finding"
    branch = f"{BRANCH_PREFIX}{ctx.today}-{_slug(section, 24)}-{_slug(fid, 24)}-{commit[:8]}"
    try:
        url = remote_url(ctx)
    except StewardCodeRejected as exc:
        return {"status": "failed", "summary": "Could not identify the private dotfiles remote.",
                "detail": str(exc), "commit": commit}
    push = _git(ctx, repo, "push", "-q", url, f"{commit}:refs/heads/{branch}", timeout=180)
    if push.returncode != 0:
        return {"status": "failed", "summary": "The reviewed steward-code commit could not be pushed.",
                "detail": _text(push.stderr or push.stdout), "commit": commit}
    _ensure_labels(ctx)
    title = f"steward: fix {section}/{fid} in {', '.join(facts['paths'])}"[:120]
    cp = ctx.gh(["pr", "create", "--repo", DOTFILES_REPO, "--head", branch, "--base", "main",
                 "--title", title, "--label", LABEL,
                 "--body", _body(section, findings, facts, section_result)], None)
    pr_url = (cp.stdout or "").strip().splitlines()[-1:] if cp.returncode == 0 else []
    if not pr_url:
        return {"status": "failed", "summary": "Pushed the steward-code branch but could not open a PR.",
                "detail": _text(cp.stderr or cp.stdout), "commit": commit,
                "revert": f"git push {url} --delete {branch}"}
    pr_url = pr_url[0].strip()
    return {
        "status": "pr_auto_merge", "pr_url": pr_url, "commit": commit,
        "summary": (f"Opened a steward-code PR on {DOTFILES_REPO}; it merges after the 24 h "
                    f"objection window unless closed or labelled '{HOLD_LABEL}'."),
        "detail": f"{', '.join('~/' + p for p in facts['paths'])}; verification passed: "
                  + ", ".join(" ".join(map(str, r.get("argv") or [])) for r in facts["records"]
                              if (r.get("argv") or [""])[0] == "bash"),
        "revert": f"gh pr close {pr_url} --delete-branch (before merge) or git revert <merge commit> "
                  f"on {DOTFILES_REPO} main",
    }
