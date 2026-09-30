"""Steward startup: merge due steward-code PRs, then fast-forward the live tree.

``steward_runner.py`` parses the command line first, then (fresh runs only,
never ``--resume``) calls :func:`startup` before the workflow's source/policy
fingerprint is taken.  When the pickup changed the live tree the runner
re-execs, so the whole run uses one consistent source version; a pickup that
moved HEAD without ending verified aborts the run (:func:`abort_if_unsafe`).

Merge (``steward_code_merge``): open PRs on the private dotfiles repository
that the steward opened (label ``steward-auto``, ``steward/fix-`` branch,
steward's own GitHub login, body marker) merge only when they are at least
24 h old, not labelled ``hold``, not draft, open, ``MERGEABLE``; origin/main
equals the live HEAD and the PR's files have no local changes; the PR branch
is up to date with origin/main (otherwise the branch is updated through the
REST API and the steward waits, bounded, for CI on the new head); every check
on the head commit is green (including ``scripts-ci``'s ``verify``); and the
head tree, checked out in a throwaway clone, passes the ``verify-*.sh full``
of every area it touches.  At most one merge per night (steward-auto merges
from the last 20 h count, so reruns do not add one), squash (else merge
commit), ``--match-head-commit``, never ``--admin``.  A PR pending more than
72 h past its window is escalated to Needs You.

Pickup (``dotfiles_pickup``): fast-forward ``$HOME`` (bare repo
``~/.dotfiles-homelab``) to origin/main only when HEAD is ``main``, the update
is a strict fast-forward, and no changed path is locally modified or an
untracked collision (git's own refusal is also a skip).  Afterwards every
applicable ``verify-*.sh full`` must pass against the live tree; otherwise
exactly the changed paths are restored to the previous commit and the branch
ref is reset with a compare-and-swap.  Never ``reset --hard`` over ``$HOME``.

If a PR was merged at this startup but the live tree did not take it, the
steward pushes a revert commit (non-force) on top of the merge and
fast-forwards the live tree to it, so origin and live stay one line of
history and P9b/P7c pushes keep fast-forwarding.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from .config import DOTFILES_REPO, HOME, RUN_DIR_BASE
from .worker import steward_code_verifiers

LABEL = "steward-auto"
HOLD_LABEL = "hold"
BRANCH_PREFIX = "steward/fix-"
PR_MARKER = "<!-- steward-code-pr -->"
OBJECTION_WINDOW = timedelta(hours=24)
ESCALATE_AFTER = timedelta(hours=72)
MAX_MERGES_PER_NIGHT = 1
MERGED_LOOKBACK = timedelta(hours=20)
REQUIRED_CHECK = "verify"  # scripts-ci job
GREEN_CONCLUSIONS = {"success", "neutral", "skipped"}
VERIFY_TIMEOUT = 900
CI_WAIT_SECONDS = 600
POLL_SECONDS = 15
PACKET_ENV = "STEWARD_CODE_STARTUP"
DONE_ENV = "STEWARD_CODE_STARTUP_DONE"
_PR_FIELDS = (
    "number,title,url,state,isDraft,author,labels,headRefName,headRefOid,"
    "baseRefName,createdAt,mergeable,isCrossRepository,body,files"
)
_STEWARD_IDENTITY = {
    "GIT_AUTHOR_NAME": "Homelab Steward", "GIT_AUTHOR_EMAIL": "steward@localhost",
    "GIT_COMMITTER_NAME": "Homelab Steward", "GIT_COMMITTER_EMAIL": "steward@localhost",
}
_TEXT = 600


def _run(argv, *, cwd=None, timeout=120, env=None, input_text=None):
    """Run argv; never raise.  Returns a CompletedProcess."""
    try:
        return subprocess.run(
            [str(a) for a in argv], cwd=str(cwd) if cwd else None, env=env,
            input=input_text, capture_output=True, text=True, timeout=timeout,
            stdin=None if input_text is not None else subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess([str(a) for a in argv], 127, "", str(exc))


def _gh(args):
    return _run(["gh", *args], timeout=120)


@dataclass
class StartupContext:
    """Injectable boundaries so tests never touch GitHub or the real $HOME."""

    dry_run: bool = False
    home: Path = HOME
    git_dir: Path = HOME / ".dotfiles-homelab"
    nwo: str = DOTFILES_REPO
    branch: str = "main"
    remote: str | None = None  # fetch/push URL; default: the live origin URL
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    run: Callable[..., subprocess.CompletedProcess] = _run
    gh: Callable[..., subprocess.CompletedProcess] = _gh
    sleep: Callable[[float], None] = time.sleep
    monotonic: Callable[[], float] = time.monotonic
    verify_timeout: int = VERIFY_TIMEOUT
    ci_wait_seconds: int = CI_WAIT_SECONDS
    poll_seconds: int = POLL_SECONDS
    record_dir: Path = RUN_DIR_BASE

    def git_env(self, *, read_only=True, identity=False):
        env = dict(os.environ)
        env.update({"GIT_LITERAL_PATHSPECS": "1", "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"})
        if read_only:
            env["GIT_OPTIONAL_LOCKS"] = "0"  # a status/diff never rewrites the index
        if identity:
            env.update(_STEWARD_IDENTITY)
        return env

    def git(self, *args, git_dir=None, read_only=True, timeout=120, input_text=None):
        argv = ["git", "-c", "core.hooksPath=/dev/null", "--git-dir", str(git_dir or self.git_dir),
                "--work-tree", str(self.home), *args]
        return self.run(argv, cwd=self.home, timeout=timeout,
                        env=self.git_env(read_only=read_only), input_text=input_text)

    def bare(self, git_dir, *args, timeout=180, identity=False):
        """git in a throwaway repository (never the live one)."""
        return self.run(["git", "-c", "core.hooksPath=/dev/null", "--git-dir", str(git_dir), *args],
                        cwd=None, timeout=timeout, env=self.git_env(identity=identity))


def _text(value, limit=_TEXT):
    return str(value if value is not None else "").strip()[:limit]


def _out(cp):
    return _text(cp.stderr or cp.stdout, 400)


def _gh_json(ctx, args):
    cp = ctx.gh(args)
    if cp.returncode != 0:
        return None
    try:
        return json.loads(cp.stdout or "null")
    except ValueError:
        return None


def _parse_time(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _origin_url(ctx):
    if ctx.remote:
        return ctx.remote
    cp = ctx.git("config", "--get", "remote.origin.url")
    return cp.stdout.strip() if cp.returncode == 0 else ""


def _live_head(ctx):
    cp = ctx.git("rev-parse", "HEAD")
    return cp.stdout.strip() if cp.returncode == 0 else ""


def _scratch_clone(ctx, temp, *, bare=True):
    """A throwaway clone borrowing the live objects read-only; returns its git dir."""
    target = Path(temp) / ("repo.git" if bare else "tree")
    argv = ["git", "clone", "-q", "--shared", "--no-tags",
            "--bare" if bare else "--no-checkout", str(ctx.git_dir), str(target)]
    cp = ctx.run(argv, timeout=120, env=ctx.git_env())
    if cp.returncode != 0:
        raise RuntimeError(f"temp clone failed: {_out(cp)}")
    return target if bare else target / ".git"


# ── merge ────────────────────────────────────────────────────────────


def _steward_authored(pr, login):
    return (
        isinstance(pr, Mapping)
        and str(pr.get("headRefName") or "").startswith(BRANCH_PREFIX)
        and not pr.get("isCrossRepository")
        and ((pr.get("author") or {}).get("login") == login)
        and PR_MARKER in str(pr.get("body") or "")
        and LABEL in _labels(pr)
    )


def _labels(pr):
    return {str((label or {}).get("name") or "") for label in pr.get("labels") or []}


def _ci_state(ctx, sha):
    """(done, green, reason) from the check runs on the exact head commit."""
    data = _gh_json(ctx, ["api", f"repos/{ctx.nwo}/commits/{sha}/check-runs?per_page=100"])
    runs = data.get("check_runs") if isinstance(data, Mapping) else None
    if not isinstance(runs, list):
        return True, False, "could not read check runs"
    if not any(isinstance(r, Mapping) and r.get("name") == REQUIRED_CHECK for r in runs):
        return False, False, f"no '{REQUIRED_CHECK}' check on {sha[:8]} yet"
    for r in runs:
        if not isinstance(r, Mapping):
            return True, False, "malformed check run"
        if r.get("status") != "completed":
            return False, False, f"check '{r.get('name')}' is {r.get('status')}"
    for r in runs:
        if r.get("conclusion") not in GREEN_CONCLUSIONS:
            return True, False, f"check '{r.get('name')}' concluded {r.get('conclusion')}"
    return True, True, f"{len(runs)} check(s) green on {sha[:8]}"


def _wait(ctx, probe):
    """Poll ``probe() -> (done, value)`` until done or the CI wait bound passes."""
    deadline = ctx.monotonic() + (0 if ctx.dry_run else ctx.ci_wait_seconds)
    while True:
        done, value = probe()
        if done or ctx.monotonic() >= deadline:
            return done, value
        ctx.sleep(ctx.poll_seconds)


def _wait_ci(ctx, sha):
    def probe():
        done, green, why = _ci_state(ctx, sha)
        return done, (green, why)

    done, (green, why) = _wait(ctx, probe)
    return green, (why if done else f"{why} (waited {ctx.ci_wait_seconds}s)")


def _base_tip(ctx, base):
    ref = _gh_json(ctx, ["api", f"repos/{ctx.nwo}/git/ref/heads/{base}"])
    return ((ref or {}).get("object") or {}).get("sha") if isinstance(ref, Mapping) else None


def _behind_by(ctx, head, base):
    """Commits on ``base`` the PR head does not contain (None if unreadable)."""
    cmp = _gh_json(ctx, ["api", f"repos/{ctx.nwo}/compare/{head}...{base}"])
    if not isinstance(cmp, Mapping) or not isinstance(cmp.get("ahead_by"), int):
        return None
    return cmp["ahead_by"]


def _update_branch(ctx, number, head):
    """Merge origin/main into the PR branch (REST; gh 2.45 has no update-branch).

    Returns (new head | None, reason)."""
    cp = ctx.gh(["api", "-X", "PUT", f"repos/{ctx.nwo}/pulls/{number}/update-branch",
                 "-f", f"expected_head_sha={head}"])
    if cp.returncode != 0:
        return None, f"branch update failed: {_out(cp)}"

    def probe():
        pull = _gh_json(ctx, ["api", f"repos/{ctx.nwo}/pulls/{number}"])
        sha = ((pull or {}).get("head") or {}).get("sha") if isinstance(pull, Mapping) else None
        mergeable = pull.get("mergeable") if isinstance(pull, Mapping) else None
        return bool(sha and sha != head and mergeable is not None), (sha, mergeable)

    done, (sha, mergeable) = _wait(ctx, probe)
    if not done:
        return None, "branch update requested; GitHub has not produced the new head yet"
    if mergeable is not True:
        return None, "the updated branch conflicts with origin/main"
    return sha, f"branch updated to {sha[:8]}"


def _live_tree_blocker(ctx, tip, paths):
    """Why the live tree could not fast-forward over ``paths``; None when it can."""
    head = _live_head(ctx)
    if not head:
        return "cannot read the live HEAD"
    if head != tip:
        return (f"live HEAD {head[:8]} is not origin/{ctx.branch} "
                f"{str(tip)[:8]} (unpicked or unpushed commits)")
    dirty = _dirty_paths(ctx, paths)
    if dirty:
        return "live tree has local changes to " + ", ".join(dirty[:8])
    return None


def _dirty_paths(ctx, paths):
    """Tracked paths modified vs HEAD (index or work tree) plus untracked collisions."""
    paths = sorted(set(paths))
    if not paths:
        return []  # an empty pathspec would mean "everything"
    cp = ctx.git("diff", "--name-only", "-z", "HEAD", "--", *paths)
    dirty = set(filter(None, (cp.stdout or "").split("\0"))) if cp.returncode == 0 else set(paths)
    tracked = ctx.git("ls-files", "-z", "--", *paths)
    known = set(filter(None, (tracked.stdout or "").split("\0")))
    for path in paths:
        if path not in known and os.path.lexists(Path(ctx.home) / path):
            dirty.add(path)
    return sorted(dirty)


def _run_verifiers(ctx, paths, root=None, label="~"):
    """verify-<area>.sh full for every area ``paths`` touch, run in ``root``."""
    root = Path(root or ctx.home)
    records = []
    for name in steward_code_verifiers(paths):
        started = ctx.monotonic()
        cp = ctx.run(["bash", str(root / "scripts" / f"verify-{name}.sh"), "full"], cwd=root,
                     timeout=ctx.verify_timeout, env=dict(os.environ))
        records.append({
            "argv": ["bash", f"{label}/scripts/verify-{name}.sh", "full"],
            "returncode": cp.returncode,
            "duration_seconds": round(ctx.monotonic() - started, 1),
            "output_tail": ((cp.stdout or "") + (cp.stderr or "")).strip()[-1500:],
        })
        if cp.returncode != 0:
            break
    return records


def _verify_pr_tree(ctx, number, head, paths):
    """Check out the PR head in a throwaway clone and run its area verifiers."""
    temp = tempfile.mkdtemp(prefix="steward-premerge-")
    try:
        git_dir = _scratch_clone(ctx, temp, bare=False)
        tree = git_dir.parent
        fetch = ctx.bare(git_dir, "fetch", "-q", "--no-tags", _origin_url(ctx),
                         f"refs/pull/{number}/head")
        fetched = ctx.bare(git_dir, "rev-parse", "FETCH_HEAD").stdout.strip()
        if fetch.returncode != 0 or fetched != head:
            return [{"argv": ["git", "fetch", f"refs/pull/{number}/head"], "returncode": 1,
                     "output_tail": _out(fetch) or f"fetched {fetched[:8]}, expected {head[:8]}"}]
        checkout = ctx.run(["git", "-c", "core.hooksPath=/dev/null", "-C", str(tree), "checkout",
                            "-q", "--detach", head], timeout=120, env=ctx.git_env(read_only=False))
        if checkout.returncode != 0:
            return [{"argv": ["git", "checkout", head], "returncode": 1, "output_tail": _out(checkout)}]
        return _run_verifiers(ctx, paths, root=tree, label=f"<PR #{number} head {head[:8]}>")
    finally:
        shutil.rmtree(temp, ignore_errors=True)


def _merge_flag(ctx):
    info = _gh_json(ctx, ["api", f"repos/{ctx.nwo}"])
    if not isinstance(info, Mapping):
        return None, "could not read the repository merge settings"
    # Squash first: one revertable commit even after update-branch merges.
    if info.get("allow_squash_merge") is True:
        return "--squash", ""
    if info.get("allow_merge_commit") is True:
        return "--merge", ""
    return None, "neither squash nor merge commits are enabled"


def _merged_recently(ctx):
    """steward-auto PRs merged in the last MERGED_LOOKBACK (None if unreadable)."""
    rows = _gh_json(ctx, ["pr", "list", "--repo", ctx.nwo, "--state", "merged", "--label", LABEL,
                          "--limit", "20", "--json", "number,mergedAt,headRefName"])
    if not isinstance(rows, list):
        return None
    since = ctx.now - MERGED_LOOKBACK
    return sum(
        1 for row in rows
        if isinstance(row, Mapping) and str(row.get("headRefName") or "").startswith(BRANCH_PREFIX)
        and (_parse_time(row.get("mergedAt")) or datetime.min.replace(tzinfo=timezone.utc)) >= since
    )


def undo_command(nwo, sha, flag):
    mainline = "-m 1 " if flag == "--merge" else ""
    return (f"git revert {mainline}{sha} on {nwo} main (clone it, revert, push); "
            f"the next steward startup picks the revert up")


def merge_due_prs(ctx: StartupContext) -> dict[str, Any]:
    """Merge at most one due steward-code PR; list the rest as pending/held."""
    packet: dict[str, Any] = {
        "step": "steward_code_merge", "repo": ctx.nwo, "dry_run": ctx.dry_run,
        "merged": [], "pending": [], "held": [], "errors": [],
    }
    user = _gh_json(ctx, ["api", "user"])
    login = user.get("login") if isinstance(user, Mapping) else None
    prs = _gh_json(ctx, ["pr", "list", "--repo", ctx.nwo, "--state", "open", "--label", LABEL,
                         "--limit", "50", "--json", _PR_FIELDS])
    recent = _merged_recently(ctx)
    if not login or not isinstance(prs, list) or recent is None:
        packet["errors"].append("could not list steward-code PRs (gh user/pr list failed)")
        packet["status"], packet["reason"] = "warning", packet["errors"][0]
        return packet
    prs = sorted((p for p in prs if _steward_authored(p, login)),
                 key=lambda p: str(p.get("createdAt") or ""))
    flag = None
    for pr in prs:
        number = pr.get("number")
        item = {"number": number, "url": pr.get("url", ""),
                "title": _text(pr.get("title"), 200), "created_at": pr.get("createdAt")}
        escalate = False

        def pending(reason, needs=False, **extra):
            row = {**item, "reason": _text(reason), **extra}
            if needs or escalate:
                row["needs_carter"] = True
            packet["pending"].append(row)

        if str(pr.get("state") or "OPEN") != "OPEN":
            continue
        if HOLD_LABEL in _labels(pr):
            packet["held"].append({**item, "reason": f"labelled '{HOLD_LABEL}'"})
            continue
        created = _parse_time(pr.get("createdAt"))
        if created is None:
            pending("unreadable creation time")
            continue
        due = created + OBJECTION_WINDOW
        if ctx.now < due:
            pending("objection window open", due=due.isoformat(timespec="minutes"))
            continue
        escalate = ctx.now >= due + ESCALATE_AFTER
        if pr.get("isDraft"):
            pending("draft")
            continue
        if recent + len(packet["merged"]) >= MAX_MERGES_PER_NIGHT:
            pending(f"nightly merge limit ({MAX_MERGES_PER_NIGHT}) reached")
            continue
        if pr.get("mergeable") != "MERGEABLE":
            pending(f"not mergeable ({pr.get('mergeable') or 'unknown'})")
            continue
        head = str(pr.get("headRefOid") or "")
        base = str(pr.get("baseRefName") or ctx.branch)
        files = [str(f.get("path") or "") for f in pr.get("files") or [] if isinstance(f, Mapping)]
        tip = _base_tip(ctx, base)
        if not tip:
            pending(f"could not read origin/{base}")
            continue
        blocker = _live_tree_blocker(ctx, tip, files)
        if blocker:
            pending(f"merge deferred: {blocker}")
            continue
        behind = _behind_by(ctx, head, base)
        if behind is None:
            pending(f"could not compare the PR with origin/{base}")
            continue
        if behind:
            if ctx.dry_run:
                pending(f"{behind} commit(s) behind origin/{base}; dry run: would update the "
                        "branch, wait for CI, verify, and merge")
                continue
            head, why = _update_branch(ctx, number, head)
            if not head:
                pending(why)
                continue
            if _base_tip(ctx, base) != tip or _behind_by(ctx, head, base) != 0:
                pending(f"origin/{base} moved while the branch was updated; retried next night")
                continue
        green, why = _wait_ci(ctx, head)
        if not green:
            pending(f"CI not green: {why}")
            continue
        records = _verify_pr_tree(ctx, number, head, files)
        failed = [r for r in records if r.get("returncode") != 0]
        if failed or not records:
            last = failed[-1] if failed else {"argv": ["verify"], "returncode": None, "output_tail": ""}
            pending(f"pre-merge verification of the PR tree failed: {' '.join(last['argv'])} exit "
                    f"{last['returncode']}: {_text(last.get('output_tail'), 1500)[-300:]}", needs=True)
            continue
        if flag is None:
            flag, why = _merge_flag(ctx)
            if flag is None:
                packet["errors"].append(why)
                break
        if ctx.dry_run:
            pending(f"dry run: would merge ({flag}, head {head[:8]}; pre-merge verification passed)")
            continue
        # Re-check right before merging: the CI wait and verification take
        # minutes, and a local commit or edit landing meanwhile would make
        # the merge unpickable (the wedge).
        if _base_tip(ctx, base) != tip:
            pending(f"origin/{base} moved during the pre-merge checks; retried next night")
            continue
        blocker = _live_tree_blocker(ctx, tip, files)
        if blocker:
            pending(f"merge deferred: {blocker}")
            continue
        cp = ctx.gh(["pr", "merge", str(number), "--repo", ctx.nwo, flag,
                     "--match-head-commit", head, "--delete-branch"])
        if cp.returncode != 0:
            packet["errors"].append(f"#{number}: merge failed: {_out(cp)}")
            continue
        view = _gh_json(ctx, ["pr", "view", str(number), "--repo", ctx.nwo,
                              "--json", "mergeCommit,state"])
        sha = str(((view or {}).get("mergeCommit") or {}).get("oid") or "") if isinstance(view, Mapping) else ""
        packet["merged"].append({**item, "merge_commit": sha, "base": tip, "head": head,
                                 "paths": files[:50], "verify": records,
                                 "undo": undo_command(ctx.nwo, sha or "<merge commit>", flag)})
    packet["status"] = "warning" if packet["errors"] else ("ok" if packet["merged"] else "skipped")
    packet["reason"] = (f"{len(packet['merged'])} merged, {len(packet['pending'])} pending, "
                        f"{len(packet['held'])} held" + (f"; {packet['errors'][0]}" if packet["errors"] else ""))
    return packet


# ── pickup ───────────────────────────────────────────────────────────


def _changes(ctx, old, new, git_dir=None):
    """[(status, path)] between two commits, renames split into D + A."""
    cp = ctx.git("diff", "--name-status", "-z", "--no-renames", old, new, git_dir=git_dir)
    if cp.returncode != 0:
        raise RuntimeError(f"git diff failed: {_out(cp)}")
    fields = (cp.stdout or "").split("\0")
    return [(fields[i][:1], fields[i + 1]) for i in range(0, len(fields) - 1, 2) if fields[i]]


def _commits(ctx, old, new, git_dir=None):
    cp = ctx.git("log", "--format=%H%x09%s", f"{old}..{new}", git_dir=git_dir)
    rows = [line.split("\t", 1) for line in (cp.stdout or "").splitlines() if "\t" in line]
    return [{"sha": sha, "subject": _text(subject, 200)} for sha, subject in rows[:50]]


def _restore(ctx, old, new, changes):
    """Put exactly ``changes`` back to ``old`` and CAS the branch ref back."""
    existing = [p for s, p in changes if s != "A"]
    added = [p for s, p in changes if s == "A"]
    problems = []
    if existing:
        cp = ctx.git("checkout", old, "--pathspec-from-file=-", "--pathspec-file-nul",
                     read_only=False, input_text="\0".join(existing) + "\0")
        if cp.returncode != 0:
            problems.append(f"checkout failed: {_out(cp)}")
    for path in added:
        cp = ctx.git("rm", "-q", "--cached", "--ignore-unmatch", "--", path, read_only=False)
        if cp.returncode != 0:
            problems.append(f"unstage {path} failed: {_out(cp)}")
        target = Path(ctx.home) / path
        if target.is_symlink() or target.is_file():
            target.unlink()
    cp = ctx.git("update-ref", f"refs/heads/{ctx.branch}", old, new, read_only=False)
    if cp.returncode != 0:
        problems.append(f"update-ref failed: {_out(cp)}")
    head = _live_head(ctx)
    if head != old:
        problems.append(f"HEAD is {head[:8]}, expected {old[:8]}")
    dirty = _dirty_paths(ctx, [p for _, p in changes])
    if dirty:
        problems.append("paths still differ from the previous commit: " + ", ".join(dirty[:8]))
    return problems


def pickup(ctx: StartupContext) -> dict[str, Any]:
    """Fast-forward the live tree to origin/<branch> behind the verification gate."""
    packet: dict[str, Any] = {"step": "dotfiles_pickup", "dry_run": ctx.dry_run, "changed": False,
                              "commits": [], "paths": []}
    branch = ctx.git("symbolic-ref", "-q", "HEAD")
    if branch.stdout.strip() != f"refs/heads/{ctx.branch}":
        return {**packet, "status": "skipped",
                "reason": f"live HEAD is not on {ctx.branch} ({branch.stdout.strip() or 'detached'})"}
    old = _live_head(ctx)
    packet["old"] = old
    temp = None
    fetch_dir = None
    try:
        if ctx.dry_run:
            # Never write into the live repository: fetch into a throwaway
            # bare clone that borrows the live objects read-only.
            temp = tempfile.mkdtemp(prefix="steward-pickup-")
            try:
                fetch_dir = _scratch_clone(ctx, temp)
            except RuntimeError as exc:
                return {**packet, "status": "failed", "reason": str(exc)}
            fetch = ctx.bare(fetch_dir, "fetch", "-q", "--no-tags", _origin_url(ctx),
                             f"refs/heads/{ctx.branch}")
        else:
            fetch = ctx.git("fetch", "-q", "--no-tags", "origin", f"refs/heads/{ctx.branch}",
                            read_only=False, timeout=180)
        if fetch.returncode != 0:
            return {**packet, "status": "failed", "reason": f"fetch failed: {_out(fetch)}"}
        new = ctx.git("rev-parse", "FETCH_HEAD", git_dir=fetch_dir).stdout.strip()
        packet["new"] = new
        if not new:
            return {**packet, "status": "failed", "reason": "fetch produced no FETCH_HEAD"}
        if new == old:
            return {**packet, "status": "up_to_date", "reason": f"already at origin/{ctx.branch}"}
        ancestor = ctx.git("merge-base", "--is-ancestor", old, new, git_dir=fetch_dir)
        if ancestor.returncode != 0:
            return {**packet, "status": "skipped",
                    "reason": f"not a fast-forward: live HEAD {old[:8]} is not an ancestor of "
                              f"origin/{ctx.branch} {new[:8]} (local commits not pushed)"}
        changes = _changes(ctx, old, new, git_dir=fetch_dir)
        packet["commits"] = _commits(ctx, old, new, git_dir=fetch_dir)
        packet["paths"] = [p for _, p in changes][:200]
        dirty = _dirty_paths(ctx, [p for _, p in changes])
        if dirty:
            return {**packet, "status": "skipped", "local_changes": dirty[:50],
                    "reason": "local changes to paths the fast-forward would change: "
                              + ", ".join(dirty[:8])}
        if ctx.dry_run:
            return {**packet, "status": "would_fast_forward",
                    "verifiers": steward_code_verifiers(packet["paths"]),
                    "reason": f"dry run: would fast-forward {len(packet['commits'])} commit(s)"}
        merge = ctx.git("merge", "--ff-only", "-q", new, read_only=False, timeout=180)
        if merge.returncode != 0:
            if _live_head(ctx) == old:
                return {**packet, "status": "skipped",
                        "reason": f"git refused the fast-forward: {_out(merge)}"}
            return {**packet, "status": "failed", "head_moved": True,
                    "reason": f"git fast-forward errored after moving HEAD: {_out(merge)}",
                    "manual_recovery": f"inspect `git --git-dir=$HOME/.dotfiles-homelab "
                                       f"--work-tree=$HOME status`; previous commit {old}"}
        packet["verify"] = _run_verifiers(ctx, [p for _, p in changes])
        if all(r["returncode"] == 0 for r in packet["verify"]):
            return {**packet, "status": "fast_forwarded", "changed": True,
                    "reason": f"fast-forwarded {len(packet['commits'])} commit(s); verification passed"}
        problems = _restore(ctx, old, new, changes)
        if problems:
            return {**packet, "status": "failed", "changed": True,
                    "reason": "verification failed and the restore is incomplete: "
                              + "; ".join(problems),
                    "manual_recovery": f"git --git-dir=$HOME/.dotfiles-homelab --work-tree=$HOME "
                                       f"checkout {old} -- <paths above>; then update-ref "
                                       f"refs/heads/{ctx.branch} {old}"}
        return {**packet, "status": "rolled_back",
                "reason": "verification failed after the fast-forward; the changed paths and "
                          f"{ctx.branch} were restored to {old[:8]}"}
    finally:
        if temp:
            shutil.rmtree(temp, ignore_errors=True)


# ── keep origin and live on one line after a failed pickup ───────────


def revert_unpicked_merge(ctx: StartupContext, merged: Mapping[str, Any], why: str) -> dict[str, Any]:
    """Push a revert of ``merged`` on origin and fast-forward live onto it.

    Only when origin/main is still exactly the merge commit and live is still
    at the merge's parent: the revert's tree then equals live's tree, so the
    live fast-forward changes no file and the next pickup is clean."""
    merge_sha, base = str(merged.get("merge_commit") or ""), str(merged.get("base") or "")
    manual = (f"origin/{ctx.branch} is ahead of the live tree: revert {merge_sha[:12]} on "
              f"{ctx.nwo} {ctx.branch} (git revert, push), then run the steward")
    if not merge_sha or not base:
        return {"status": "failed", "reason": "merge commit unknown", "manual_recovery": manual}
    if _live_head(ctx) != base:
        return {"status": "failed", "reason": "live HEAD is not the pre-merge commit",
                "manual_recovery": manual}
    temp = tempfile.mkdtemp(prefix="steward-revert-")
    url = _origin_url(ctx)
    try:
        repo = _scratch_clone(ctx, temp)
        fetch = ctx.bare(repo, "fetch", "-q", "--no-tags", url, f"refs/heads/{ctx.branch}")
        tip = ctx.bare(repo, "rev-parse", "FETCH_HEAD").stdout.strip()
        if fetch.returncode != 0 or tip != merge_sha:
            return {"status": "failed", "manual_recovery": manual,
                    "reason": f"origin/{ctx.branch} is {tip[:8] or 'unreadable'}, not the merge "
                              f"{merge_sha[:8]}: {_out(fetch)}"}
        parent = ctx.bare(repo, "rev-parse", f"{merge_sha}^1").stdout.strip()
        if parent != base:
            return {"status": "failed", "manual_recovery": manual,
                    "reason": f"merge parent {parent[:8]} is not the live commit {base[:8]}"}
        tree = ctx.bare(repo, "rev-parse", f"{base}^{{tree}}").stdout.strip()
        message = (f"Revert steward-code PR #{merged.get('number')} ({merge_sha[:8]})\n\n"
                   f"The live tree did not take the merge: {_text(why, 300)}")
        revert = ctx.bare(repo, "commit-tree", tree, "-p", merge_sha, "-m", message, identity=True)
        revert_sha = revert.stdout.strip()
        if revert.returncode != 0 or not revert_sha:
            return {"status": "failed", "reason": f"commit-tree failed: {_out(revert)}",
                    "manual_recovery": manual}
        push = ctx.bare(repo, "push", "-q", url, f"{revert_sha}:refs/heads/{ctx.branch}")
        if push.returncode != 0:
            return {"status": "failed", "reason": f"revert push failed: {_out(push)}",
                    "manual_recovery": manual}
    except RuntimeError as exc:
        return {"status": "failed", "reason": str(exc), "manual_recovery": manual}
    finally:
        shutil.rmtree(temp, ignore_errors=True)
    result = {"status": "reverted", "revert_commit": revert_sha}
    fetch = ctx.git("fetch", "-q", "--no-tags", "origin", f"refs/heads/{ctx.branch}",
                    read_only=False, timeout=180)
    if fetch.returncode != 0 or ctx.git("rev-parse", "FETCH_HEAD").stdout.strip() != revert_sha:
        return {**result, "live": "behind", "reason": f"revert pushed; live fetch failed: {_out(fetch)} "
                                                      "(the next pickup fast-forwards it)"}
    ff = ctx.git("merge", "--ff-only", "-q", revert_sha, read_only=False)
    if ff.returncode != 0 or _live_head(ctx) != revert_sha:
        return {**result, "live": "behind",
                "reason": f"revert pushed; live fast-forward refused: {_out(ff)} (the next pickup retries)"}
    return {**result, "live": "at_revert", "reason": f"revert {revert_sha[:8]} pushed; live fast-forwarded to it"}


def _reconcile(ctx, packet):
    """After a merge the live tree did not take, bring origin back in line."""
    merge, pick = packet.get("merge") or {}, packet.get("pickup") or {}
    if pick.get("status") == "fast_forwarded":
        return
    live = _live_head(ctx)
    for item in merge.get("merged") or []:
        if not item.get("merge_commit") or live == item["merge_commit"]:
            continue
        why = f"live pickup {pick.get('status')}: {_text(pick.get('reason'), 200)}"
        result = revert_unpicked_merge(ctx, item, why)
        item["revert"] = result
        item["revert_reason"] = why
        if result.get("revert_commit"):
            item["reverted_by"] = result["revert_commit"]
            merge.setdefault("errors", []).append(
                f"#{item.get('number')} merged ({item['merge_commit'][:8]}) then reverted "
                f"({result['revert_commit'][:8]}) because the {why}; {result.get('reason')}")
        else:
            merge.setdefault("errors", []).append(
                f"#{item.get('number')} merged but the live tree did not take it ({why}) and the "
                f"automatic revert failed: {result.get('reason')}. {result.get('manual_recovery')}")
        merge["status"] = "warning"


# ── startup entry ────────────────────────────────────────────────────


def startup(args, *, ctx: StartupContext | None = None,
            environ: dict[str, str] | None = None) -> dict[str, Any] | None:
    """Run merge + pickup once per fresh run (``args`` from the workflow parser)."""
    environ = os.environ if environ is None else environ
    if args.resume or getattr(args, "continue_after_fixes", False) or environ.get(DONE_ENV):
        return None
    ctx = ctx or StartupContext(dry_run=bool(args.dry_run))
    packet: dict[str, Any] = {"dry_run": ctx.dry_run}
    for key, operation in (("merge", merge_due_prs), ("pickup", pickup)):
        before = _live_head(ctx) if key == "pickup" else ""
        try:
            packet[key] = operation(ctx)
        except Exception as exc:  # reported, never a crash before the run records it
            packet[key] = {"step": f"steward_code_{key}", "status": "failed",
                           "reason": f"{type(exc).__name__}: {_text(exc)}"}
            if key == "pickup" and _live_head(ctx) != before:
                packet[key]["head_moved"] = True  # unverified tree: abort_if_unsafe stops the run
        print(f"[startup] {key}: {packet[key].get('status')} "
              f"{_text(packet[key].get('reason'), 200)}".rstrip(), flush=True)
    if not ctx.dry_run:
        try:
            _reconcile(ctx, packet)
        except Exception as exc:
            packet["merge"].setdefault("errors", []).append(f"reconcile failed: {type(exc).__name__}: {exc}")
            packet["merge"]["status"] = "warning"
    environ[PACKET_ENV] = json.dumps(packet, default=str)  # every list above is bounded
    environ[DONE_ENV] = "1"
    return packet


def startup_packet(environ: Mapping[str, str] | None = None) -> dict[str, Any] | None:
    """The packet published by :func:`startup` for this process tree, if any."""
    raw = (os.environ if environ is None else environ).get(PACKET_ENV)
    try:
        value = json.loads(raw) if raw else None
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def unsafe_reason(packet):
    """Why the run must not continue on this tree (None when it may)."""
    pick = (packet or {}).get("pickup") or {}
    if pick.get("status") == "failed" and (pick.get("changed") or pick.get("head_moved")):
        return f"live-tree pickup left an unverified tree: {pick.get('reason')}"
    return None


def abort_if_unsafe(packet, ctx: StartupContext | None = None):
    """Fail closed: record the packet and exit non-zero (OnFailure notifies)."""
    reason = unsafe_reason(packet)
    if not reason:
        return
    ctx = ctx or StartupContext()
    record = Path(ctx.record_dir) / ctx.now.strftime("%Y-%m-%d") / "00-startup-abort.json"
    try:
        record.parent.mkdir(parents=True, exist_ok=True)
        record.write_text(json.dumps({"reason": reason, "packet": packet}, indent=1, default=str))
    except OSError:
        pass
    print(f"[startup] ABORT: {reason} (recorded in {record})", file=sys.stderr, flush=True)
    raise SystemExit(1)


def reexec_if_changed(packet, argv0=None):
    """Re-exec the entrypoint so a changed live tree is loaded from scratch.

    Only a verified fast-forward changes the source on disk: a rollback
    restores it, and a revert fast-forward keeps the same tree."""
    pick = (packet or {}).get("pickup") or {}
    if pick.get("status") != "fast_forwarded" or not pick.get("changed"):
        return
    entry = str(Path(argv0 or sys.argv[0]).resolve())
    sys.stdout.flush()
    sys.stderr.flush()
    os.execv(sys.executable, [sys.executable, entry, *sys.argv[1:]])
