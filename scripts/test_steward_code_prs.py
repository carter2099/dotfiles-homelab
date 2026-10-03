#!/usr/bin/env python3
"""Behavioral tests for steward-code PRs: routing, pre-PR gate, merge, pickup."""
from __future__ import annotations

import io
import json
import os
import runpy
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from steward import code_pickup, code_prs, routing, worker  # noqa: E402

GIT_ENV = {**os.environ, "GIT_AUTHOR_NAME": "T", "GIT_AUTHOR_EMAIL": "t@example.com",
           "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@example.com",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
NWO = "carter2099/dotfiles-homelab-private"


def git(*args, cwd=None, input_text=None, env=None):
    cp = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True,
                        input=input_text, env=env or GIT_ENV)
    if cp.returncode != 0:
        raise AssertionError(f"git {args} failed: {cp.stderr}")
    return cp.stdout.strip()


def done(rc=0, out="", err=""):
    return subprocess.CompletedProcess(["fake"], rc, out, err)


VERIFY_SCRIPT = """#!/usr/bin/env bash
# Fails when any tracked script contains the BROKEN marker, or (environment-
# dependent failure) when the checkout has an untracked FAIL_LIVE marker.
cd "$(dirname "$0")/.."
if grep -rq --exclude='verify-*.sh' BROKEN scripts; then echo "verification FAILED"; exit 1; fi
if [ -e FAIL_LIVE ]; then echo "live environment FAILED"; exit 1; fi
echo "Ran 3 tests"; echo OK
"""


class DotfilesSandbox:
    """Temp $HOME tracked by a bare repo, plus a bare 'GitHub' origin."""

    def __init__(self, tmp):
        self.root = Path(tmp)
        self.home = self.root / "home"
        (self.home / "scripts" / "steward").mkdir(parents=True)
        (self.home / "notes").mkdir()
        self.origin = self.root / "origin.git"
        git("init", "-q", "--bare", "--initial-branch=main", str(self.origin))
        self.git_dir = self.home / ".dotfiles-homelab"
        git("init", "-q", "--bare", "--initial-branch=main", str(self.git_dir))
        self.dot = ["--git-dir", str(self.git_dir), "--work-tree", str(self.home)]
        git(*self.dot, "config", "status.showUntrackedFiles", "no")
        git(*self.dot, "remote", "add", "origin", str(self.origin))
        files = {
            "scripts/verify-steward.sh": VERIFY_SCRIPT,
            "scripts/steward/health.py": "LIMIT = 1\n",
            "scripts/steward/audit.py": "def scan():\n    return 1\n",
            "scripts/steward/queue.py": "DAYS = 3  # threshold\n",
            "scripts/steward/sudo_user.py": "run(['sudo', 'true'])\n",
            "scripts/steward/routing.py": "ROUTES = 1\n",
            "scripts/steward/public_dotfiles.py": "RULES = 1\n",
            "scripts/steward/dotfiles.py": "SCAN = 1\n",
            "scripts/steward/config.py": "ALLOW = 1\n",
            "scripts/jev.py": "THRESHOLD = 0.9\n",
            "scripts/daily_news/workflow.py": "X = 1\n",
            "scripts/deploy.sh": "echo deploy\n",
            "system-config/dotfiles-publish-policy.json": "{}\n",
            "notes/readme.md": "hello\n",
            "AGENTS.md": "rules\n",
        }
        for rel, text in files.items():
            self.write(rel, text)
        (self.home / "scripts/verify-steward.sh").chmod(0o755)
        git(*self.dot, "add", *files)
        git(*self.dot, "commit", "-q", "-m", "seed")
        git(*self.dot, "push", "-q", "origin", "main")
        # A second clone plays "GitHub web merges" into origin.
        self.upstream = self.root / "upstream"
        git("clone", "-q", str(self.origin), str(self.upstream))

    def write(self, rel, text):
        path = self.home / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def head(self):
        return git(*self.dot, "rev-parse", "HEAD")

    def _write_upstream(self, changes):
        for rel, text in changes.items():
            path = self.upstream / rel
            if text is None:
                git("-C", str(self.upstream), "rm", "-q", rel)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
                git("-C", str(self.upstream), "add", rel)

    def _sync_upstream(self):
        git("-C", str(self.upstream), "fetch", "-q", "origin")
        git("-C", str(self.upstream), "checkout", "-q", "-B", "main", "origin/main")

    def upstream_commit(self, changes, message="upstream change"):
        """changes: {rel: text or None (delete)}; pushes to origin main, returns sha."""
        self._sync_upstream()
        self._write_upstream(changes)
        git("-C", str(self.upstream), "commit", "-q", "-m", message)
        git("-C", str(self.upstream), "push", "-q", "origin", "HEAD:main")
        return git("-C", str(self.upstream), "rev-parse", "HEAD")

    def make_pr(self, number, changes):
        """A PR head commit on origin main, at refs/pull/<n>/head; returns its sha."""
        self._sync_upstream()
        self._write_upstream(changes)
        git("-C", str(self.upstream), "commit", "-q", "-m", f"steward fix #{number}")
        git("-C", str(self.upstream), "push", "-q", "-f", "origin", f"HEAD:refs/pull/{number}/head")
        sha = git("-C", str(self.upstream), "rev-parse", "HEAD")
        self._sync_upstream()
        return sha

    def pull_live(self):
        """What an earlier successful pickup would have done."""
        git(*self.dot, "fetch", "-q", "origin", "main")
        git(*self.dot, "merge", "-q", "--ff-only", "FETCH_HEAD")


# ── worker policy ────────────────────────────────────────────────────


class StewardCodePolicyTests(unittest.TestCase):
    def test_scripts_allowed_but_protected_paths_are_not(self):
        for ok in ("scripts/steward/health.py", "scripts/steward/audit.py",
                   "scripts/daily_news/workflow.py", "scripts/steward_resume_helper.py",
                   "scripts/test_steward_health.py"):
            self.assertIsNone(worker.steward_code_path_reason(ok), ok)
        for bad in ("scripts/steward/routing.py", "scripts/steward/config.py",
                    "scripts/steward/worker.py", "scripts/steward/public_dotfiles.py",
                    "scripts/steward/dotfiles.py", "scripts/jev.py", "scripts/verify-steward.sh",
                    "scripts/steward/code_prs.py", "scripts/steward/code_pickup.py",
                    "scripts/steward/resolver.py", "scripts/steward/runtime.py",
                    "scripts/steward/workflow.py", "scripts/steward_approve.py",
                    ".local/bin/steward-approve", "scripts/test_steward_resolver.py",
                    "scripts/test_steward_routing.py", "scripts/test_steward_code_prs.py",
                    "scripts/test_steward_worker.py", "scripts/test_steward_workflow.py",
                    "system-config/dotfiles-publish-policy.json", ".config/systemd/user/x.service",
                    "scripts/homelab.service", "scripts/deploy.sh", "scripts/.env",
                    "scripts/backup/run.py", "notes/readme.md", "AGENTS.md"):
            self.assertIsNotNone(worker.steward_code_path_reason(bad), bad)

    def test_kind_scopes_the_policy(self):
        with self.assertRaises(worker.WorkerPolicyError):
            worker._safe_relpath("scripts/steward/health.py")  # app repos: infra component
        self.assertEqual(
            worker._safe_relpath("scripts/steward/health.py", kind=worker.REPO_KIND_STEWARD_CODE),
            "scripts/steward/health.py")
        with self.assertRaises(worker.WorkerPolicyError):
            worker._safe_relpath("scripts/steward/routing.py", kind=worker.REPO_KIND_STEWARD_CODE)
        self.assertEqual(worker.repo_kind(worker.STEWARD_CODE_ROOT / "2026-09-29-abc"),
                         worker.REPO_KIND_STEWARD_CODE)
        self.assertEqual(worker.repo_kind(worker.DEV_ROOT / "blog"), worker.REPO_KIND_APP)
        self.assertEqual(worker.repo_kind(worker.STEWARD_CODE_ROOT / "a" / "b"), worker.REPO_KIND_APP)

    def test_validation_plan_runs_every_touched_verifier(self):
        root = worker.STEWARD_CODE_ROOT / "x"
        plan = worker._validation_plan(root, ["scripts/steward/health.py"])
        self.assertEqual(plan[1:], [["bash", "scripts/verify-steward.sh", "full"]])
        plan = worker._validation_plan(root, ["scripts/daily_news/workflow.py"])
        self.assertEqual(plan[1:], [["bash", "scripts/verify-steward.sh", "full"],
                                    ["bash", "scripts/verify-daily-news.sh", "full"]])

    def test_risk_rules_catch_embedded_sudo_names_but_not_pseudo(self):
        for sign, text in (("+", "_owui_sudo(['true'])"), ("-", "def owui_sudo(argv):"),
                           ("+", "SUDO_BIN = '/usr/bin/sudo'"), ("-", "run(['sudo', 'apt'])"),
                           ("+", "open('/etc/sudoers.d/x')")):
            self.assertIn("sudo line", code_prs._line_risk(sign, text) or "", (sign, text))
        self.assertIsNone(code_prs._line_risk("+", "pseudocode = 1"))
        self.assertIsNone(code_prs._line_risk("-", "LIMIT = 1"))

    def test_only_exact_verifier_commands_may_use_bash(self):
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(worker, "WORKER_PRIVATE_HOME", Path(tmp)):
            with self.assertRaises(worker.WorkerPolicyError):
                worker._run_validations(Path(tmp), [["bash", "-c", "true"]])
            with self.assertRaises(worker.WorkerPolicyError):
                worker._run_validations(Path(tmp), [["bash", "scripts/verify-evil.sh", "full"]])
            (Path(tmp) / "scripts").mkdir()
            (Path(tmp) / "scripts/verify-steward.sh").write_text("exit 0\n")
            records = worker._run_validations(Path(tmp), [["bash", "scripts/verify-steward.sh", "full"]])
            self.assertEqual(records[0]["returncode"], 0)


class StewardCodeCloneTests(unittest.TestCase):
    """The worker planner/publisher accept a steward-code clone within its policy."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dev = Path(tmp.name) / "dev"
        self.clone = self.dev / ".steward-code" / "2026-09-29-abc"
        self.clone.mkdir(parents=True)
        for name, value in (("_ALLOWED_REPO_ROOT", self.dev),
                            ("STEWARD_CODE_ROOT", self.dev / ".steward-code")):
            p = patch.object(worker, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.run_git("init", "-q", "--initial-branch=main")
        (self.clone / "scripts/steward").mkdir(parents=True)
        (self.clone / "scripts/steward/health.py").write_text("LIMIT = 1\n")
        (self.clone / "scripts/steward/routing.py").write_text("ROUTES = 1\n")
        wants = self.clone / ".config/systemd/user/timers.target.wants"
        wants.mkdir(parents=True)
        os.symlink("/etc/x.timer", wants / "x.timer")
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "seed")
        self.base = self.run_git("rev-parse", "HEAD")

    def run_git(self, *args):
        return git("-C", str(self.clone), *args)

    def packet(self, path, text):
        original = (self.clone / path).read_text()
        (self.clone / path).write_text(text)
        diff = subprocess.run(["git", "-C", str(self.clone), "diff", "--no-ext-diff", "--full-index", "HEAD"],
                              capture_output=True, text=True, check=True).stdout
        (self.clone / path).write_text(original)
        commands = worker._validation_plan(self.clone, [path])
        return {
            "protocol_version": worker.PROTOCOL_VERSION, "status": "ok",
            "judge_packet": {"verdict": "pass"},
            "_trusted_repositories": [{"source": str(self.clone), "base_sha": self.base,
                                       "allowed_paths": [path], "validation_commands": commands}],
            "repositories": [{"source": str(self.clone), "base_sha": self.base, "allowed_paths": [path],
                              "changed_paths": [path], "diff": diff, "diff_sha256": worker._sha256_text(diff),
                              "validation": [{"argv": c, "returncode": 0} for c in commands]}],
        }

    def test_plan_skips_symlinks_and_runs_the_verifier(self):
        plans, errors = worker._target_plans([{"id": "f1", "claim": "limit", "repo": str(self.clone),
                                               "paths": ["scripts/steward/health.py"]}])
        self.assertEqual(errors, [])
        self.assertEqual(plans[0]["allowed_paths"], ["scripts/steward/health.py"])
        self.assertNotIn(".config/systemd/user/timers.target.wants/x.timer",
                         worker._tracked_paths(self.clone))
        self.assertIn(["bash", "scripts/verify-steward.sh", "full"],
                      worker._validation_plan(self.clone, plans[0]["allowed_paths"]))
        plans, errors = worker._target_plans([{"id": "f1", "claim": "x", "repo": str(self.clone),
                                               "paths": ["scripts/steward/routing.py"]}])
        self.assertEqual(plans, [])
        self.assertTrue(any("steward-code path is not repairable" in e for e in errors), errors)

    def test_snapshot_stages_verifier_support_files_read_only(self):
        # verify-daily-news.sh preflights the checkout's .omp config; without
        # it every Daily News repair failed validation inside the worker.
        for rel in (*worker.STEWARD_CODE_VERIFIER_SUPPORT, ".omp/agent/config.yml", ".config/other/app.conf"):
            (self.clone / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.clone / rel).write_text("x\n")
        self.run_git("add", "-A")
        self.run_git("commit", "-q", "-m", "support")
        listed = worker._tracked_paths(self.clone)
        for rel in worker.STEWARD_CODE_VERIFIER_SUPPORT:
            self.assertIn(rel, listed)
            with self.assertRaises(worker.WorkerPolicyError):
                worker._safe_relpath(rel, kind=worker.REPO_KIND_STEWARD_CODE)
        self.assertNotIn(".omp/agent/config.yml", listed)
        self.assertNotIn(".config/other/app.conf", listed)
        app = self.dev / "app"
        for rel in worker.STEWARD_CODE_VERIFIER_SUPPORT:
            (app / rel).parent.mkdir(parents=True, exist_ok=True)
            (app / rel).write_text("x\n")
        (app / "main.py").write_text("x = 1\n")
        git("init", "-q", "--initial-branch=main", cwd=app)
        git("add", "-A", cwd=app)
        git("commit", "-q", "-m", "seed", cwd=app)
        self.assertEqual(worker._tracked_paths(app), ["main.py"])

    def test_publisher_accepts_allowed_and_rejects_protected_paths(self):
        result = worker.publish_validated_result(self.packet("scripts/steward/health.py", "LIMIT = 2\n"), "s")
        self.assertEqual(result["status"], "published", result)
        result = worker.publish_validated_result(self.packet("scripts/steward/routing.py", "ROUTES = 2\n"), "s")
        self.assertEqual(result["status"], "publish-rejected")


# ── routing + pre-PR gate ────────────────────────────────────────────


def finding(fid="finding-1", paths=("scripts/steward/health.py",), repo="~/scripts", **kw):
    base = {"id": fid, "claim": f"claim {fid}", "evidence": "observed", "fix": "raise the limit",
            "action": "code_fix", "target": {"repo": repo, "paths": list(paths)}}
    base.update(kw)
    return base


def section(name, findings):
    return {"name": name, "verdict": "DRIFT",
            "worker_findings": [dict(f) for f in findings], "judge_confirmed": [dict(f) for f in findings]}


class Gh:
    """Fake gh for the PR route."""

    def __init__(self, listed=None):
        self.calls = []
        self.listed = listed or []

    def __call__(self, args, cwd=None):
        self.calls.append(list(args))
        if args[:2] == ["pr", "list"]:
            return done(0, json.dumps(self.listed))
        if args[:2] == ["label", "create"]:
            return done(1, "", "already exists")
        if args[:2] == ["pr", "create"]:
            return done(0, f"https://github.com/{NWO}/pull/9\n")
        return done(1, "", f"unexpected {args}")


def records(*argvs, rc=0):
    return [{"argv": list(a), "returncode": rc, "stdout": "Ran 3 tests\nOK\n"} for a in argvs]


VERIFY = ("bash", "scripts/verify-steward.sh", "full")
DIFF_CHECK = ("git", "diff", "--check")


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.sb = DotfilesSandbox(self._tmp.name)
        self.scratch_root = self.sb.root / "dev" / ".steward-code"
        self.worker_calls = []

    def tearDown(self):
        self._tmp.cleanup()

    def ctx(self, fix=None, gh=None, dry_run=False):
        return routing.RouteContext(
            today="2026-09-29", home=self.sb.home, dev_root=self.sb.root / "dev",
            dotfiles_git_dir=self.sb.git_dir, dotfiles_remote=str(self.sb.origin),
            steward_code_root=self.scratch_root, gh=gh or Gh(), dry_run=dry_run,
            fix_section=fix or (lambda *a: (_ for _ in ()).throw(AssertionError("worker must not run"))),
        )

    def fake_fix(self, changes, validation):
        """A worker that turns the scratch into a review commit with ``changes``."""

        def fix(name, findings, dry_run, run_dir):
            self.worker_calls.append(findings)
            repo = Path(findings[0]["repo"])
            base = git("-C", str(repo), "rev-parse", "HEAD")
            env = {**GIT_ENV, "GIT_INDEX_FILE": str(self.sb.root / "review-index")}
            git("-C", str(repo), "read-tree", base, env=env)
            for rel, text in changes.items():
                blob = git("-C", str(repo), "hash-object", "-w", "--stdin", input_text=text)
                git("-C", str(repo), "update-index", "--add", "--cacheinfo", f"100644,{blob},{rel}", env=env)
            tree = git("-C", str(repo), "write-tree", env=env)
            commit = git("-C", str(repo), "commit-tree", tree, "-p", base, "-m", "chore: steward review")
            return {"section": name, "status": "review-required", "judge_verdict": "pass",
                    "judge_summary": "fix verified", "iteration_count": 1, "stop_reason": "pass",
                    "fixes_applied": [{"id": "finding-1", "status": "deferred", "iteration": 1}],
                    "iterations": [{"validation": [{"repository": str(repo), "records": validation}]}],
                    "source_repair_commits": [{"repository": str(repo), "commit": commit}]}
        return fix

    def route(self, findings, **kw):
        return routing.route_findings([section("steward-code", findings)], {}, self.ctx(**kw))["routes"]

    def remote_branches(self):
        return git("--git-dir", str(self.sb.origin), "branch", "--list", "steward/*")

    def test_steward_code_finding_reaches_the_worker_in_a_scratch_clone(self):
        fix = self.fake_fix({"scripts/steward/health.py": "LIMIT = 2\n"}, records(DIFF_CHECK, VERIFY))
        gh = Gh()
        rows = self.route([finding()], fix=fix, gh=gh)
        self.assertEqual(rows[0]["status"], "pr_auto_merge", rows[0])
        sent = self.worker_calls[0][0]
        self.assertEqual(sent["paths"], ["scripts/steward/health.py"])
        self.assertEqual(Path(sent["repo"]).parent, self.scratch_root.resolve())
        self.assertFalse(Path(sent["repo"]).exists(), "scratch clone is removed")
        branch = self.remote_branches()
        self.assertTrue(branch.startswith("steward/fix-2026-09-29-steward-code-finding-1-"), branch)
        create = next(c for c in gh.calls if c[:2] == ["pr", "create"])
        self.assertEqual(create[create.index("--repo") + 1], NWO)
        self.assertEqual(create[create.index("--label") + 1], "steward-auto")
        body = create[create.index("--body") + 1]
        for text in (code_pickup.PR_MARKER, "claim finding-1", "bash scripts/verify-steward.sh full",
                     "exit 0", "label `hold`", "git revert"):
            self.assertIn(text, body)
        self.assertEqual(rows[0]["pr_url"], f"https://github.com/{NWO}/pull/9")
        self.assertIn("gh pr close", rows[0]["revert"])
        # The live tree is untouched; only origin gained a branch.
        self.assertEqual((self.sb.home / "scripts/steward/health.py").read_text(), "LIMIT = 1\n")

    def test_protected_targets_stay_needs_carter_without_a_worker(self):
        for paths, repo in (
            (["scripts/steward/routing.py"], "~/scripts"),
            (["steward/public_dotfiles.py"], "~/scripts"),
            (["scripts/steward/dotfiles.py"], "~"),
            (["scripts/jev.py"], "~/.dotfiles-homelab"),
            (["scripts/steward/config.py"], "dotfiles-homelab-private"),
            (["scripts/verify-steward.sh"], "~"),
            (["dotfiles-publish-policy.json"], "~/system-config"),
            (["scripts/deploy.sh"], "~"),
            (["notes/readme.md"], "~"),
            (["~/scripts/../AGENTS.md"], "~"),
        ):
            rows = self.route([finding(paths=paths, repo=repo)])
            self.assertEqual(rows[0]["status"], "needs_carter", (paths, rows[0]))
            self.assertTrue(rows[0]["detail"])
        self.assertEqual(self.worker_calls, [])
        self.assertEqual(self.remote_branches(), "")

    def test_untracked_or_locally_diverged_paths_are_refused(self):
        self.sb.write("scripts/steward/new.py", "x = 1\n")
        rows = self.route([finding(paths=["scripts/steward/new.py"])])
        self.assertEqual(rows[0]["status"], "needs_carter")
        self.assertIn("not tracked", rows[0]["detail"])
        self.sb.write("scripts/steward/health.py", "LIMIT = 5  # local edit\n")
        rows = self.route([finding()], fix=self.fake_fix({}, []), gh=Gh())
        self.assertEqual(rows[0]["status"], "needs_carter")
        self.assertIn("differs from origin/main", rows[0]["detail"])
        self.assertEqual(self.worker_calls, [])
        self.assertEqual(list(self.scratch_root.iterdir()), [])

    def test_pr_only_after_verification_passes(self):
        cases = {
            "failed verifier": ({"scripts/steward/health.py": "LIMIT = 2\n"},
                                records(DIFF_CHECK) + records(VERIFY, rc=1)),
            "missing verifier": ({"scripts/steward/health.py": "LIMIT = 2\n"}, records(DIFF_CHECK)),
            "missing area verifier": ({"scripts/daily_news/workflow.py": "X = 2\n"},
                                      records(DIFF_CHECK, VERIFY)),
            "protected path in commit": ({"scripts/steward/routing.py": "ROUTES = 2\n"},
                                         records(DIFF_CHECK, VERIFY)),
            "secret": ({"scripts/steward/health.py": "GH = 'ghp_" + "a1B2" * 10 + "'\n"},
                       records(DIFF_CHECK, VERIFY)),
            "sudo": ({"scripts/steward/health.py": "run(['sudo', 'ufw', 'allow', '22'])\n"},
                     records(DIFF_CHECK, VERIFY)),
            "size cap": ({"scripts/steward/health.py": "x = 1\n" * 500}, records(DIFF_CHECK, VERIFY)),
        }
        for label, (changes, validation) in cases.items():
            with self.subTest(label):
                gh = Gh()
                paths = ["scripts/daily_news/workflow.py"] if "area" in label else None
                f = finding(paths=paths) if paths else finding()
                rows = self.route([f], fix=self.fake_fix(changes, validation), gh=gh)
                self.assertEqual(rows[0]["status"], "needs_carter", (label, rows[0]))
                self.assertFalse(any(c[:2] == ["pr", "create"] for c in gh.calls), label)
                self.assertEqual(self.remote_branches(), "", label)

    def test_risky_or_guard_removing_lines_are_refused(self):
        ok = records(DIFF_CHECK, VERIFY)
        cases = {
            "removed sudo line": ({"scripts/steward/sudo_user.py": "X = 1\n"}, "removes a sudo line"),
            "removed guard": ({"scripts/steward/audit.py": "X = 1\n"}, "removes a guard line"),
            "removed threshold": ({"scripts/steward/queue.py": "X = 1\n"}, "mentions 'hold'"),
            "'++' content secret": ({"scripts/steward/health.py": "LIMIT = 1\n++ ghp_" + "a1B2" * 10 + "\n"},
                                    "secret scan flagged"),
            "bearer token": ({"scripts/steward/health.py": "H = 'Authorization: Bearer " + "x9Y8" * 10 + "'\n"},
                             "secret scan flagged"),
        }
        for label, (changes, expected) in cases.items():
            with self.subTest(label):
                gh = Gh()
                rows = self.route([finding()], fix=self.fake_fix(changes, ok), gh=gh)
                self.assertEqual(rows[0]["status"], "needs_carter", (label, rows[0]))
                self.assertIn(expected, rows[0]["detail"], label)
                self.assertFalse(any(c[:2] == ["pr", "create"] for c in gh.calls), label)
                self.assertEqual(self.remote_branches(), "", label)

    def test_one_steward_code_pr_per_night(self):
        fix = self.fake_fix({"scripts/steward/health.py": "LIMIT = 2\n"}, records(DIFF_CHECK, VERIFY))
        rows = self.route([finding(), finding("finding-2")], fix=fix, gh=Gh())
        self.assertEqual([r["status"] for r in rows], ["pr_auto_merge", "report_only"])
        self.assertEqual(len(self.worker_calls), 1)
        # A resumed P7b on the same night does not open a second PR.
        gh = Gh(listed=[{"headRefName": "steward/fix-2026-09-29-x-y-1234abcd", "url": "u",
                         "state": "CLOSED", "files": []}])
        rows = self.route([finding()], fix=fix, gh=gh)
        self.assertEqual(rows[0]["status"], "report_only")
        self.assertEqual(len(self.worker_calls), 1)

    def test_no_duplicate_pr_for_paths_an_open_pr_already_changes(self):
        fix = self.fake_fix({"scripts/steward/health.py": "LIMIT = 2\n"}, records(DIFF_CHECK, VERIFY))
        older = {"headRefName": "steward/fix-2026-09-28-s-f-1234abcd", "url": "u28",
                 "files": [{"path": "scripts/steward/health.py"}]}
        rows = self.route([finding()], fix=fix, gh=Gh(listed=[{**older, "state": "OPEN"}]))
        self.assertEqual(rows[0]["status"], "report_only")
        self.assertIn("already changes scripts/steward/health.py", rows[0]["summary"])
        self.assertEqual(self.worker_calls, [])
        # A closed (objected) PR does not block a new attempt.
        rows = self.route([finding()], fix=fix, gh=Gh(listed=[{**older, "state": "CLOSED"}]))
        self.assertEqual(rows[0]["status"], "pr_auto_merge")

    def test_dry_run_does_not_clone_or_call_the_worker(self):
        rows = self.route([finding()], dry_run=True)
        self.assertEqual(rows[0]["status"], "report_only")
        self.assertFalse(self.scratch_root.exists())


# ── startup merge ────────────────────────────────────────────────────


NOW = datetime(2026, 9, 29, 4, 0, tzinfo=timezone.utc)
GREEN = [{"name": "verify", "status": "completed", "conclusion": "success"}]


def iso(hours_ago):
    return (NOW - timedelta(hours=hours_ago)).isoformat().replace("+00:00", "Z")


def pr(number, *, age_hours=30, labels=("steward-auto",), branch=None, mergeable="MERGEABLE",
       state="OPEN", author="carter2099", head=None, files=("scripts/steward/health.py",), draft=False):
    return {
        "number": number, "title": f"steward: fix {number}", "url": f"https://github.com/{NWO}/pull/{number}",
        "state": state, "isDraft": draft, "author": {"login": author},
        "labels": [{"name": n} for n in labels],
        "headRefName": branch or f"steward/fix-2026-09-27-s-f{number}-abcdef12",
        "headRefOid": head or f"{number:040d}", "baseRefName": "main",
        "createdAt": iso(age_hours), "mergeable": mergeable, "isCrossRepository": False,
        "body": f"{code_pickup.PR_MARKER}\nbody", "files": [{"path": p} for p in files],
    }


class FakeGitHub:
    """gh backed by the sandbox's bare origin: PR heads live at refs/pull/<n>/head."""

    def __init__(self, sb, prs, *, checks=None, merged=(), update_head_green=True, on_checks=None):
        self.sb, self.calls = sb, []
        self.prs = {p["number"]: p for p in prs}
        self.checks = dict(checks or {})
        self.merged = list(merged)
        self.merge_commits = {}
        self.update_head_green = update_head_green
        self.on_checks = on_checks  # side effect while the steward waits on CI

    def og(self, *args, env=None):
        return git("--git-dir", str(self.sb.origin), *args, env=env)

    def main(self):
        return self.og("rev-parse", "refs/heads/main")

    def __call__(self, args):
        self.calls.append(list(args))
        if args[:2] == ["api", "user"]:
            return done(0, json.dumps({"login": "carter2099"}))
        if args[:2] == ["pr", "list"]:
            if "merged" in args:
                return done(0, json.dumps(self.merged))
            return done(0, json.dumps(list(self.prs.values())))
        if args[:2] == ["pr", "merge"]:
            return self.merge(int(args[2]), args)
        if args[:2] == ["pr", "view"]:
            return done(0, json.dumps({"state": "MERGED",
                                       "mergeCommit": {"oid": self.merge_commits.get(int(args[2]), "")}}))
        if args[:3] == ["api", "-X", "PUT"]:
            return self.update_branch(int(args[3].split("/pulls/")[1].split("/")[0]), args)
        if args[0] == "api":
            path = args[1]
            if "/check-runs" in path:
                sha = path.split("/commits/")[1].split("/")[0]
                if self.on_checks:
                    self.on_checks()
                return done(0, json.dumps({"check_runs": self.checks.get(sha, GREEN)}))
            if "/git/ref/heads/" in path:
                return done(0, json.dumps({"object": {"sha": self.main()}}))
            if "/compare/" in path:
                head = path.split("/compare/")[1].split("...")[0]
                behind = self.og("rev-list", "--count", f"{head}..refs/heads/main")
                return done(0, json.dumps({"ahead_by": int(behind)}))
            if "/pulls/" in path:
                n = int(path.split("/pulls/")[1])
                return done(0, json.dumps({"head": {"sha": self.prs[n]["headRefOid"]}, "mergeable": True}))
            if path == f"repos/{NWO}":
                return done(0, json.dumps({"allow_squash_merge": True, "allow_merge_commit": True}))
        return done(1, "", f"unexpected {args}")

    def merge(self, n, args):
        head = args[args.index("--match-head-commit") + 1]
        if head != self.prs[n]["headRefOid"]:
            return done(1, "", "head moved")
        tip = self.main()
        tree = self.og("rev-parse", f"{head}^{{tree}}")
        sha = self.og("commit-tree", tree, "-p", tip, "-m", f"squash #{n}", env=GIT_ENV)
        self.og("update-ref", "refs/heads/main", sha, tip)
        self.merge_commits[n] = sha
        return done(0)

    def update_branch(self, n, args):
        expected = next(a for a in args if a.startswith("expected_head_sha=")).split("=", 1)[1]
        head = self.prs[n]["headRefOid"]
        if expected != head:
            return done(1, "", "expected_head_sha mismatch")
        tree = self.og("merge-tree", "--write-tree", head, "refs/heads/main").splitlines()[0]
        new = self.og("commit-tree", tree, "-p", head, "-p", "refs/heads/main", "-m", "merge main",
                      env=GIT_ENV)
        self.og("update-ref", f"refs/pull/{n}/head", new)
        self.prs[n]["headRefOid"] = new
        if not self.update_head_green:
            self.checks[new] = [{"name": "verify", "status": "queued", "conclusion": None}]
        return done(0, '{"message": "Updating pull request branch."}')


class MergeTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.sb = DotfilesSandbox(self._tmp.name)
        self.clock = [0.0]
        env = patch.dict(os.environ, {k: v for k, v in GIT_ENV.items() if k.startswith("GIT_CONFIG")})
        env.start()
        self.addCleanup(env.stop)

    def tearDown(self):
        self._tmp.cleanup()

    def ctx(self, gh, dry_run=False):
        return code_pickup.StartupContext(
            dry_run=dry_run, home=self.sb.home, git_dir=self.sb.git_dir, nwo=NWO, now=NOW, gh=gh,
            remote=str(self.sb.origin), verify_timeout=60, ci_wait_seconds=300, poll_seconds=30,
            sleep=lambda s: self.clock.__setitem__(0, self.clock[0] + s),
            monotonic=lambda: self.clock[0], record_dir=self.sb.root / "runs")

    def merge(self, prs, dry_run=False, **kw):
        gh = FakeGitHub(self.sb, prs, **kw)
        return code_pickup.merge_due_prs(self.ctx(gh, dry_run)), gh

    def good_pr(self, n=5, changes=None, **kw):
        return pr(n, head=self.sb.make_pr(n, changes or {"scripts/steward/health.py": "LIMIT = 2\n"}), **kw)

    def merges(self, gh):
        return [c for c in gh.calls if c[:2] == ["pr", "merge"]]

    def test_merges_one_due_green_verified_pr_without_admin(self):
        old = self.sb.head()
        p = self.good_pr()
        packet, gh = self.merge([p])
        self.assertEqual([m["number"] for m in packet["merged"]], [5], packet)
        (call,) = self.merges(gh)
        self.assertEqual(call[2:], ["5", "--repo", NWO, "--squash", "--match-head-commit", p["headRefOid"],
                                    "--delete-branch"])
        self.assertNotIn("--admin", sum(gh.calls, []))
        merged = packet["merged"][0]
        self.assertEqual(merged["base"], old)
        self.assertEqual(merged["verify"][0]["returncode"], 0)
        self.assertIn(f"git revert {merged['merge_commit']}", merged["undo"])
        self.assertEqual(git("--git-dir", str(self.sb.origin), "show", "main:scripts/steward/health.py"),
                         "LIMIT = 2")

    def test_objection_window_hold_draft_closed_and_foreign_prs_are_not_merged(self):
        prs = [pr(1, age_hours=23.5), pr(2, labels=("steward-auto", "hold")), pr(3, draft=True),
               pr(4, state="CLOSED"), pr(6, author="someone-else"), pr(7, branch="feature/x"),
               pr(8, labels=())]
        packet, gh = self.merge(prs)
        self.assertEqual(self.merges(gh), [])
        self.assertEqual([p["number"] for p in packet["held"]], [2])
        pending = {p["number"]: p["reason"] for p in packet["pending"]}
        self.assertIn("objection window", pending[1])
        self.assertEqual(pending[3], "draft")
        self.assertNotIn(4, pending)
        for foreign in (6, 7, 8):
            self.assertNotIn(foreign, pending)

    def test_ci_must_be_green_on_the_head_commit(self):
        p = self.good_pr()
        for runs in ([], [{"name": "verify", "status": "in_progress", "conclusion": None}],
                     [{"name": "verify", "status": "completed", "conclusion": "failure"}],
                     [{"name": "verify", "status": "completed", "conclusion": "success"},
                      {"name": "other", "status": "completed", "conclusion": "cancelled"}]):
            packet, gh = self.merge([dict(p)], checks={p["headRefOid"]: runs})
            self.assertEqual(self.merges(gh), [], runs)
            self.assertIn("CI not green", packet["pending"][0]["reason"])

    def test_not_mergeable_is_pending_and_escalates_after_72h(self):
        packet, gh = self.merge([pr(5, mergeable="CONFLICTING")])
        self.assertEqual(self.merges(gh), [])
        self.assertIn("CONFLICTING", packet["pending"][0]["reason"])
        self.assertNotIn("needs_carter", packet["pending"][0])
        packet, _ = self.merge([pr(5, mergeable="UNKNOWN", age_hours=24 + 72 + 1)])
        self.assertTrue(packet["pending"][0]["needs_carter"])

    def test_at_most_one_merge_per_night_including_earlier_runs(self):
        a, b = self.good_pr(5, age_hours=40), pr(6, age_hours=30)
        packet, gh = self.merge([a, b])
        self.assertEqual(len(self.merges(gh)), 1)
        self.assertEqual(packet["merged"][0]["number"], 5)
        self.assertIn("nightly merge limit", packet["pending"][0]["reason"])
        # A second fresh run the same night: the earlier merge counts.
        earlier = [{"number": 4, "mergedAt": iso(2), "headRefName": "steward/fix-2026-09-27-a-b-12345678"}]
        self.sb.pull_live()  # the first run's pickup
        packet, gh = self.merge([self.good_pr(7, {"scripts/steward/health.py": "LIMIT = 7\n"})],
                                merged=earlier)
        self.assertEqual(self.merges(gh), [])
        self.assertIn("nightly merge limit", packet["pending"][0]["reason"])
        yesterday = [{**earlier[0], "mergedAt": iso(25)}]
        packet, gh = self.merge([self.good_pr(8, {"scripts/steward/health.py": "LIMIT = 8\n"})],
                                merged=yesterday)
        self.assertEqual(len(self.merges(gh)), 1)

    def test_branch_behind_origin_is_updated_through_the_rest_api_then_merged(self):
        p = self.good_pr()
        old_head = p["headRefOid"]
        self.sb.upstream_commit({"scripts/steward/audit.py": "def scan():\n    return 2\n"})
        self.sb.pull_live()
        packet, gh = self.merge([p])
        put = next(c for c in gh.calls if c[:3] == ["api", "-X", "PUT"])
        self.assertEqual(put[3:], [f"repos/{NWO}/pulls/5/update-branch", "-f",
                                   f"expected_head_sha={old_head}"])
        self.assertFalse(any(c[:2] == ["pr", "update-branch"] for c in gh.calls))
        (call,) = self.merges(gh)
        new_head = gh.prs[5]["headRefOid"]
        self.assertNotEqual(new_head, old_head)
        self.assertEqual(call[call.index("--match-head-commit") + 1], new_head)
        self.assertEqual(packet["merged"][0]["number"], 5)
        main = git("--git-dir", str(self.sb.origin), "show", "main:scripts/steward/audit.py")
        self.assertEqual(main, "def scan():\n    return 2")

    def test_updated_branch_without_ci_in_time_stays_pending(self):
        p = self.good_pr()
        self.sb.upstream_commit({"scripts/steward/audit.py": "def scan():\n    return 2\n"})
        self.sb.pull_live()
        packet, gh = self.merge([p], update_head_green=False)
        self.assertEqual(self.merges(gh), [])
        self.assertIn("waited 300s", packet["pending"][0]["reason"])
        self.assertGreaterEqual(self.clock[0], 300)

    def test_pre_merge_verification_of_the_pr_tree_blocks_the_merge(self):
        p = self.good_pr(changes={"scripts/steward/health.py": "LIMIT = 2  # BROKEN\n"})
        before = git("--git-dir", str(self.sb.origin), "rev-parse", "main")
        packet, gh = self.merge([p])
        self.assertEqual(self.merges(gh), [])
        self.assertIn("pre-merge verification of the PR tree failed", packet["pending"][0]["reason"])
        self.assertTrue(packet["pending"][0]["needs_carter"])
        self.assertEqual(git("--git-dir", str(self.sb.origin), "rev-parse", "main"), before)

    def test_live_tree_must_be_able_to_pick_the_merge_up(self):
        p = self.good_pr()
        self.sb.upstream_commit({"notes/readme.md": "moved on\n"})  # live not picked up yet
        packet, gh = self.merge([dict(p)])
        self.assertEqual(self.merges(gh), [])
        self.assertIn("not origin/main", packet["pending"][0]["reason"])
        self.sb.pull_live()
        self.sb.write("scripts/steward/health.py", "LIMIT = 9  # local\n")
        packet, gh = self.merge([dict(p)])
        self.assertEqual(self.merges(gh), [])
        self.assertIn("local changes to scripts/steward/health.py", packet["pending"][0]["reason"])

    def test_live_change_during_the_pre_merge_checks_blocks_the_merge(self):
        p = self.good_pr()

        def carter_commits_locally():  # lands while the steward waits on CI
            self.sb.write("AGENTS.md", "rules edited during the wait\n")
            git(*self.sb.dot, "commit", "-q", "-m", "local", "--", "AGENTS.md")

        before = git("--git-dir", str(self.sb.origin), "rev-parse", "main")
        packet, gh = self.merge([p], on_checks=carter_commits_locally)
        self.assertEqual(self.merges(gh), [])
        self.assertIn("is not origin/main", packet["pending"][0]["reason"])
        self.assertEqual(git("--git-dir", str(self.sb.origin), "rev-parse", "main"), before)

        def carter_edits_the_pr_file():
            self.sb.write("scripts/steward/health.py", "LIMIT = 9  # mid-wait edit\n")

        git(*self.sb.dot, "push", "-q", "origin", "main")  # origin == live again
        p = self.good_pr(6)
        packet, gh = self.merge([p], on_checks=carter_edits_the_pr_file)
        self.assertEqual(self.merges(gh), [])
        self.assertIn("local changes to scripts/steward/health.py", packet["pending"][0]["reason"])

    def test_dry_run_never_mutates(self):
        packet, gh = self.merge([self.good_pr()], dry_run=True)
        self.assertEqual(self.merges(gh), [])
        self.assertFalse(any(c[:3] == ["api", "-X", "PUT"] for c in gh.calls))
        self.assertIn("dry run: would merge (--squash", packet["pending"][0]["reason"])

    # ── the wedge: merged on origin, live did not take it ──

    def startup(self, gh):
        args = SimpleNamespace(resume=False, continue_after_fixes=False, dry_run=False)
        return code_pickup.startup(args, ctx=self.ctx(gh), environ={})

    def assert_one_line_of_history_and_p9b_push_works(self):
        live = self.sb.head()
        self.assertEqual(git("--git-dir", str(self.sb.origin), "rev-parse", "main"), live)
        self.sb.write("AGENTS.md", "rules v2\n")
        git(*self.sb.dot, "commit", "-q", "-m", "chore: steward dotfiles hygiene", "--", "AGENTS.md")
        git(*self.sb.dot, "push", "-q", "origin", "main")  # non-force, like P9b
        self.assertEqual(git("--git-dir", str(self.sb.origin), "rev-parse", "main"), self.sb.head())

    def test_failed_live_verification_after_merge_reverts_on_origin(self):
        old = self.sb.head()
        p = self.good_pr()
        (self.sb.home / "FAIL_LIVE").write_text("x\n")  # passes in the clean PR tree, fails live
        packet = self.startup(FakeGitHub(self.sb, [p]))
        self.assertEqual(packet["pickup"]["status"], "rolled_back", packet["pickup"])
        merged = packet["merge"]["merged"][0]
        revert = merged["reverted_by"]
        self.assertEqual(packet["merge"]["status"], "warning")
        self.assertIn("then reverted", packet["merge"]["errors"][0])
        self.assertEqual(git("--git-dir", str(self.sb.origin), "rev-parse", "main"), revert)
        self.assertEqual(git("--git-dir", str(self.sb.origin), "rev-parse", f"{revert}^"),
                         merged["merge_commit"])
        self.assertEqual(git("--git-dir", str(self.sb.origin), "rev-parse", f"{revert}^{{tree}}"),
                         git(*self.sb.dot, "rev-parse", f"{old}^{{tree}}"))
        self.assertEqual(self.sb.head(), revert)
        self.assertEqual((self.sb.home / "scripts/steward/health.py").read_text(), "LIMIT = 1\n")
        self.assertIsNone(code_pickup.unsafe_reason(packet))
        self.assert_one_line_of_history_and_p9b_push_works()

    def test_failed_live_fetch_after_merge_reverts_and_next_pickup_is_clean(self):
        p = self.good_pr()
        good_url = git(*self.sb.dot, "config", "remote.origin.url")
        git(*self.sb.dot, "config", "remote.origin.url", str(self.sb.root / "missing.git"))
        packet = self.startup(FakeGitHub(self.sb, [p]))
        self.assertEqual(packet["pickup"]["status"], "failed")
        merged = packet["merge"]["merged"][0]
        self.assertEqual(merged["revert"]["live"], "behind")
        self.assertEqual(git("--git-dir", str(self.sb.origin), "rev-parse", "main"), merged["reverted_by"])
        git(*self.sb.dot, "config", "remote.origin.url", good_url)
        nxt = code_pickup.pickup(self.ctx(FakeGitHub(self.sb, [])))
        self.assertEqual(nxt["status"], "fast_forwarded", nxt)
        self.assertEqual(nxt["paths"], [])  # the revert restores the live tree's content
        self.assert_one_line_of_history_and_p9b_push_works()


# ── startup pickup ───────────────────────────────────────────────────


class PickupTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.sb = DotfilesSandbox(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def ctx(self, dry_run=False, run=None):
        return code_pickup.StartupContext(dry_run=dry_run, home=self.sb.home, git_dir=self.sb.git_dir,
                                          nwo=NWO, now=NOW, verify_timeout=60,
                                          run=run or code_pickup._run, record_dir=self.sb.root / "runs")

    def pick(self, dry_run=False, run=None):
        with patch.dict(os.environ, {k: v for k, v in GIT_ENV.items() if k.startswith("GIT_CONFIG")}):
            return code_pickup.pickup(self.ctx(dry_run, run))

    def test_up_to_date(self):
        self.assertEqual(self.pick()["status"], "up_to_date")

    def test_fast_forward_then_verification_passes(self):
        old = self.sb.head()
        new = self.sb.upstream_commit({"scripts/steward/health.py": "LIMIT = 2\n",
                                       "scripts/steward/added.py": "A = 1\n"})
        packet = self.pick()
        self.assertEqual(packet["status"], "fast_forwarded", packet)
        self.assertTrue(packet["changed"])
        self.assertEqual(self.sb.head(), new)
        self.assertEqual((self.sb.home / "scripts/steward/health.py").read_text(), "LIMIT = 2\n")
        self.assertEqual(sorted(packet["paths"]), ["scripts/steward/added.py", "scripts/steward/health.py"])
        self.assertEqual([c["sha"] for c in packet["commits"]], [new])
        self.assertEqual(packet["verify"][0]["returncode"], 0)
        self.assertNotEqual(old, new)

    def test_pathless_fast_forward_ignores_unrelated_local_changes(self):
        self.sb.write("AGENTS.md", "uncommitted local rules\n")
        self.assertEqual(code_pickup._dirty_paths(self.ctx(), []), [])
        git("-C", str(self.sb.upstream), "commit", "-q", "--allow-empty", "-m", "empty")
        git("-C", str(self.sb.upstream), "push", "-q", "origin", "HEAD:main")
        packet = self.pick()
        self.assertEqual(packet["status"], "fast_forwarded", packet)
        self.assertEqual((self.sb.home / "AGENTS.md").read_text(), "uncommitted local rules\n")

    def test_refuses_non_fast_forward(self):
        self.sb.write("AGENTS.md", "local rules\n")
        git(*self.sb.dot, "commit", "-q", "-am", "local unpushed")
        local = self.sb.head()
        self.sb.upstream_commit({"scripts/steward/health.py": "LIMIT = 2\n"})
        packet = self.pick()
        self.assertEqual(packet["status"], "skipped")
        self.assertIn("not a fast-forward", packet["reason"])
        self.assertEqual(self.sb.head(), local)
        self.assertEqual((self.sb.home / "scripts/steward/health.py").read_text(), "LIMIT = 1\n")

    def test_refuses_locally_modified_and_untracked_colliding_paths(self):
        old = self.sb.head()
        self.sb.upstream_commit({"scripts/steward/health.py": "LIMIT = 2\n"})
        self.sb.write("scripts/steward/health.py", "LIMIT = 7  # Carter's edit\n")
        packet = self.pick()
        self.assertEqual(packet["status"], "skipped")
        self.assertEqual(packet["local_changes"], ["scripts/steward/health.py"])
        self.assertEqual(self.sb.head(), old)
        self.assertEqual((self.sb.home / "scripts/steward/health.py").read_text(),
                         "LIMIT = 7  # Carter's edit\n")

        self.sb.write("scripts/steward/health.py", "LIMIT = 1\n")
        self.sb.upstream_commit({"scripts/steward/brand_new.py": "B = 1\n"})
        self.sb.write("scripts/steward/brand_new.py", "untracked local file\n")
        packet = self.pick()
        self.assertEqual(packet["status"], "skipped")
        self.assertIn("scripts/steward/brand_new.py", packet["local_changes"])
        self.assertEqual((self.sb.home / "scripts/steward/brand_new.py").read_text(),
                         "untracked local file\n")

    def test_failed_verification_restores_exactly_the_changed_paths(self):
        old = self.sb.head()
        self.sb.upstream_commit({
            "scripts/steward/health.py": "LIMIT = 2  # BROKEN\n",
            "scripts/steward/added.py": "A = 1\n",
            "notes/readme.md": None,
        })
        # Unrelated local work elsewhere in $HOME must survive the rollback.
        self.sb.write("AGENTS.md", "uncommitted local rules\n")
        self.sb.write("scripts/untracked_scratch.txt", "mine\n")
        packet = self.pick()
        self.assertEqual(packet["status"], "rolled_back", packet)
        self.assertEqual(packet["verify"][-1]["returncode"], 1)
        self.assertEqual(self.sb.head(), old)
        self.assertEqual((self.sb.home / "scripts/steward/health.py").read_text(), "LIMIT = 1\n")
        self.assertFalse((self.sb.home / "scripts/steward/added.py").exists())
        self.assertEqual((self.sb.home / "notes/readme.md").read_text(), "hello\n")
        self.assertEqual((self.sb.home / "AGENTS.md").read_text(), "uncommitted local rules\n")
        self.assertEqual((self.sb.home / "scripts/untracked_scratch.txt").read_text(), "mine\n")
        status = git(*self.sb.dot, "status", "--porcelain")
        self.assertEqual(status, "M AGENTS.md")
        self.assertIsNone(code_pickup.unsafe_reason({"pickup": packet}))

    def failing(self, needle):
        """A runner that executes every command but reports failure for ``needle``."""
        def run(argv, **kw):
            cp = code_pickup._run(argv, **kw)
            if needle in argv:
                return done(1, "", f"{needle} exploded")
            return cp
        return run

    def test_unverified_tree_aborts_the_run(self):
        self.sb.upstream_commit({"scripts/steward/health.py": "LIMIT = 2\n"})
        packet = self.pick(run=self.failing("--ff-only"))  # HEAD moved, then "error"
        self.assertEqual((packet["status"], packet["head_moved"]), ("failed", True))
        with self.assertRaises(SystemExit) as raised:
            code_pickup.abort_if_unsafe({"pickup": packet}, self.ctx())
        self.assertEqual(raised.exception.code, 1)
        record = self.sb.root / "runs" / "2026-09-29" / "00-startup-abort.json"
        self.assertIn("unverified tree", json.loads(record.read_text())["reason"])

    def test_incomplete_restore_aborts_the_run(self):
        self.sb.upstream_commit({"scripts/steward/health.py": "LIMIT = 2  # BROKEN\n"})
        packet = self.pick(run=self.failing("update-ref"))
        self.assertEqual(packet["status"], "failed")
        self.assertTrue(packet["changed"])
        self.assertIn("restore is incomplete", packet["reason"])
        with self.assertRaises(SystemExit):
            code_pickup.abort_if_unsafe({"pickup": packet}, self.ctx())

    def test_dry_run_leaves_the_live_repository_untouched(self):
        new = self.sb.upstream_commit({"scripts/steward/health.py": "LIMIT = 2\n"})
        refs_before = git(*self.sb.dot, "for-each-ref")
        objects_before = git("--git-dir", str(self.sb.git_dir), "count-objects", "-v")
        packet = self.pick(dry_run=True)
        self.assertEqual(packet["status"], "would_fast_forward", packet)
        self.assertEqual(packet["new"], new)
        self.assertEqual(packet["paths"], ["scripts/steward/health.py"])
        self.assertEqual(git(*self.sb.dot, "for-each-ref"), refs_before)
        self.assertEqual(git("--git-dir", str(self.sb.git_dir), "count-objects", "-v"), objects_before)
        self.assertFalse((self.sb.git_dir / "FETCH_HEAD").exists())
        self.assertEqual((self.sb.home / "scripts/steward/health.py").read_text(), "LIMIT = 1\n")


class StartupTests(unittest.TestCase):
    @staticmethod
    def args(**kw):
        return SimpleNamespace(**{"resume": False, "continue_after_fixes": False, "dry_run": False, **kw})

    def test_runs_once_per_fresh_run_and_publishes_the_packet(self):
        calls = []

        def fake(name):
            def op(ctx):
                calls.append((name, ctx.dry_run))
                return {"step": name, "status": "ok", "reason": name}
            return op

        env = {}
        with patch.object(code_pickup, "merge_due_prs", fake("merge")), \
                patch.object(code_pickup, "pickup", fake("pickup")):
            self.assertIsNone(code_pickup.startup(self.args(resume=True), environ=env))
            self.assertIsNone(code_pickup.startup(self.args(resume=True, continue_after_fixes=True),
                                                  environ=env))
            packet = code_pickup.startup(self.args(dry_run=True), environ=env)
            self.assertIsNone(code_pickup.startup(self.args(), environ=env))  # re-exec'd child
        self.assertEqual(calls, [("merge", True), ("pickup", True)])
        self.assertEqual(code_pickup.startup_packet(env), packet)

    def test_a_failing_step_is_reported_not_raised(self):
        def boom(ctx):
            raise RuntimeError("gh exploded")

        with patch.object(code_pickup, "merge_due_prs", boom), \
                patch.object(code_pickup, "pickup", lambda ctx: {"status": "up_to_date"}):
            packet = code_pickup.startup(self.args(dry_run=True), environ={})
        self.assertEqual(packet["merge"]["status"], "failed")
        self.assertIn("gh exploded", packet["merge"]["reason"])

    def test_exception_after_pickup_moved_head_aborts_the_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = DotfilesSandbox(tmp)
            sb.upstream_commit({"scripts/steward/health.py": "LIMIT = 2  # BROKEN\n"})
            ctx = code_pickup.StartupContext(home=sb.home, git_dir=sb.git_dir, nwo=NWO, now=NOW,
                                             verify_timeout=60, record_dir=sb.root / "runs")
            skipped = {"step": "steward_code_merge", "status": "skipped", "reason": "none", "merged": []}

            def boom(*a, **kw):
                raise OSError("disk vanished mid-restore")

            with patch.object(code_pickup, "merge_due_prs", lambda c: skipped), \
                    patch.object(code_pickup, "_restore", boom), \
                    patch.dict(os.environ, {k: v for k, v in GIT_ENV.items() if k.startswith("GIT_CONFIG")}):
                packet = code_pickup.startup(self.args(), ctx=ctx, environ={})
            self.assertEqual(packet["pickup"]["status"], "failed")
            self.assertTrue(packet["pickup"]["head_moved"])
            self.assertIn("disk vanished", packet["pickup"]["reason"])
            with self.assertRaises(SystemExit):
                code_pickup.abort_if_unsafe(packet, ctx)

    def run_runner(self, *argv):
        """Execute steward_runner.py's __main__ with startup and the workflow stubbed."""
        seen = []
        from steward import workflow
        runner = Path(__file__).resolve().parent / "steward_runner.py"
        with patch.object(code_pickup, "startup", lambda args: seen.append(args)), \
                patch.object(workflow, "main", lambda: 0), \
                patch.object(sys, "argv", [str(runner), *argv]), \
                patch("sys.stdout", new_callable=io.StringIO), patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as raised:
                runpy.run_path(str(runner), run_name="__main__")
        return raised.exception.code, seen

    def test_runner_parses_arguments_before_any_startup_mutation(self):
        code, seen = self.run_runner("--help")
        self.assertEqual((code, seen), (0, []))
        code, seen = self.run_runner("--run-dir", "/tmp/x")  # invalid without --resume
        self.assertEqual((code, seen), (2, []))
        code, seen = self.run_runner("--dry")  # argparse abbreviation of --dry-run
        self.assertEqual(code, 0)
        self.assertTrue(seen[0].dry_run)
        code, seen = self.run_runner()
        self.assertEqual((code, seen[0].dry_run, seen[0].resume), (0, False, False))


if __name__ == "__main__":
    unittest.main()
