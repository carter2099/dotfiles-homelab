#!/usr/bin/env python3
"""Behavioral tests for the P7b finding router (steward.routing)."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from steward import fixes, routing  # noqa: E402

CONTRACT_KEYS = {
    "section", "finding_id", "claim", "severity", "action", "status", "summary",
    "detail", "decision", "revert", "pr_url", "commit", "iteration",
}


def git(*args, cwd=None):
    cp = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if cp.returncode != 0:
        raise AssertionError(f"git {args} failed: {cp.stderr}")
    return cp.stdout.strip()


def cp(rc=0, out="", err=""):
    return subprocess.CompletedProcess(["fake"], rc, out, err)


def section(name, findings, verdict="DRIFT"):
    return {
        "name": name,
        "verdict": verdict,
        "worker_findings": [dict(f) for f in findings if f.get("id")],
        "judge_confirmed": [dict(f) for f in findings],
    }


def finding(fid="finding-1", **kw):
    base = {"id": fid, "claim": f"claim {fid}", "evidence": "observed evidence", "fix": "do the fix"}
    base.update(kw)
    return base


PASS_JSON = '```json\n{"verdict": "pass", "supported_by_evidence": true, "changes_only_target": true, "system_should_change": false, "reason": "ok"}\n```'
FAIL_JSON = '{"verdict": "fail", "supported_by_evidence": false, "changes_only_target": true, "system_should_change": false, "reason": "unsupported claim"}'
# The documented state is right and the host is broken: the doc must not be "corrected".
SYSTEM_BROKEN_JSON = '{"verdict": "pass", "supported_by_evidence": true, "changes_only_target": true, "system_should_change": true, "reason": "endpoint unreachable"}'


class Sandbox:
    """Temp home with a notes repo, a dotfiles bare repo, and a ~/dev app repo."""

    def __init__(self, tmp):
        self.root = Path(tmp)
        self.home = self.root / "home"
        self.home.mkdir()
        self.remotes = self.root / "remotes"
        self.remotes.mkdir()
        # notes repo
        self.notes = self.home / "notes"
        self.notes_origin = self._bare("notes.git")
        self._init(self.notes, self.notes_origin)
        docs = self.notes / "docs" / "homelab"
        docs.mkdir(parents=True)
        self.doc = docs / "backup.md"
        self.doc.write_text("# Backup\n\nThe backup runs at 02:00 UTC.\nRetention is 7 days.\n")
        (docs / "dirty.md").write_text("Old fact here.\n")
        self._commit(self.notes, "seed")
        # dotfiles bare repo tracking ~/AGENTS.md and ~/.gitignore
        self.dot_git = self.home / ".dotfiles-homelab"
        self.dot_origin = self._bare("dotfiles.git")
        git("init", "-q", "--bare", "--initial-branch=main", str(self.dot_git))
        self.dot = ["--git-dir", str(self.dot_git), "--work-tree", str(self.home)]
        git(*self.dot, "config", "user.name", "Test")
        git(*self.dot, "config", "user.email", "t@example.com")
        git(*self.dot, "config", "commit.gpgsign", "false")
        git(*self.dot, "config", "status.showUntrackedFiles", "no")
        git(*self.dot, "remote", "add", "origin", str(self.dot_origin))
        (self.home / "AGENTS.md").write_text("Agents use model X.\n")
        (self.home / ".gitignore").write_text("/other/\n")
        (self.home / "nltk_data" / "corpora").mkdir(parents=True)
        (self.home / "nltk_data" / "corpora" / "a.txt").write_text("data\n")
        (self.home / "secret.txt").write_text("keep\n")
        git(*self.dot, "add", "AGENTS.md", ".gitignore", "nltk_data", "secret.txt")
        git(*self.dot, "commit", "-q", "-m", "seed")
        git(*self.dot, "push", "-q", "origin", "main")
        # ~/dev app repo
        self.dev = self.home / "dev"
        self.dev.mkdir()
        self.app = self.dev / "blog"
        self.app_origin = self._bare("blog.git")
        self._init(self.app, self.app_origin)
        (self.app / "app.py").write_text("print('hi')\n")
        self._commit(self.app, "seed")
        for name in ("llm-proxy", "prompt-guard"):
            repo = self.dev / name
            repo.mkdir()
            git("init", "-q", str(repo))
            (repo / "main.py").write_text("x = 1\n")
        self.model_calls = []
        self.model_reply = PASS_JSON

    def _bare(self, name):
        path = self.remotes / name
        git("init", "-q", "--bare", "--initial-branch=main", str(path))
        return path

    def _init(self, repo, origin):
        repo.mkdir(parents=True, exist_ok=True)
        git("init", "-q", "--initial-branch=main", str(repo))
        for key, value in (("user.name", "Test"), ("user.email", "t@example.com"),
                           ("commit.gpgsign", "false")):
            git("-C", str(repo), "config", key, value)
        git("-C", str(repo), "remote", "add", "origin", str(origin))

    def _commit(self, repo, msg):
        git("-C", str(repo), "add", "-A")
        git("-C", str(repo), "commit", "-q", "-m", msg)
        git("-C", str(repo), "push", "-q", "origin", "main")

    def fake_model(self, prompt, model=None, mode=None, *, tools):
        # The doc-fix re-check reviews an inlined diff; it must never get tools.
        assert tools == (), tools
        self.model_calls.append({"prompt": prompt, "model": model, "mode": mode})
        return self.model_reply

    def ctx(self, **kw):
        base = dict(
            today="2026-09-24",
            home=self.home,
            dev_root=self.dev,
            doc_roots=(self.notes / "docs",),
            doc_files=(self.home / "AGENTS.md",),
            dotfiles_git_dir=self.dot_git,
            omp_call=self.fake_model,
            gh=lambda args, cwd=None: cp(1, "", "gh disabled in test"),
            fix_section=lambda *a: (_ for _ in ()).throw(AssertionError("worker must not run")),
        )
        base.update(kw)
        return routing.RouteContext(**base)


class SandboxTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.sb = Sandbox(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def route(self, sections, applied=None, **ctx):
        return routing.route_findings(sections, applied, self.sb.ctx(**ctx))

    def one(self, name, f, applied=None, **ctx):
        result = self.route([section(name, [f])], applied, **ctx)
        self.assertEqual(len(result["routes"]), 1)
        row = result["routes"][0]
        self.assertEqual(set(row), CONTRACT_KEYS)
        self.assertIn(row["status"], routing.ROUTE_STATUSES)
        return row

    def doc_fix(self, doc=None, old="The backup runs at 02:00 UTC.", new="The backup runs at 03:00 UTC.", fid="finding-1"):
        return finding(fid, action="doc_fix", target={
            "doc": str(doc or self.sb.doc), "old_text": old, "new_text": new})


class RouteTableTests(SandboxTest):
    def test_needs_carter_keeps_decision(self):
        row = self.one("notes-resources", finding(action="needs_carter", decision="Repair agent.db?", severity="high"))
        self.assertEqual((row["status"], row["decision"], row["severity"]), ("needs_carter", "Repair agent.db?", "high"))

    def test_report_only_action(self):
        row = self.one("agent-fleet-review", finding(action="report_only"))
        self.assertEqual(row["status"], "report_only")

    def test_unknown_action_becomes_needs_carter(self):
        row = self.one("agent-fleet-review", finding(action="reboot_everything"))
        self.assertEqual((row["action"], row["status"]), ("needs_carter", "needs_carter"))
        self.assertIn("reboot_everything", row["detail"])

    def test_v1_finding_defaults(self):
        row = self.one("digest-quality", finding())  # no severity/action/target
        self.assertEqual((row["action"], row["status"], row["severity"]), ("needs_carter", "needs_carter", "medium"))
        self.assertEqual(row["detail"], "no route proposed")
        self.assertIn("do the fix", row["decision"])
        low = self.one("docs-accuracy", finding())
        self.assertEqual(low["severity"], "low")

    def test_v1_guard_item_without_id(self):
        f = {"claim": "historical credential unresolved", "evidence": "x"}
        result = self.route([{"name": "digest-quality", "verdict": "ATTENTION",
                              "worker_findings": [], "judge_confirmed": [f]}])
        self.assertEqual(result["routes"][0]["finding_id"], "finding-1")

    def test_judge_values_override_worker(self):
        s = section("digest-quality", [finding(action="needs_carter", severity="low")])
        s["judge_confirmed"][0]["severity"] = "high"
        row = self.route([s])["routes"][0]
        self.assertEqual(row["severity"], "high")

    def test_report_only_sections_are_forced(self):
        before = self.sb.doc.read_bytes()
        for name in ("version-currency", "security-posture"):
            row = self.one(name, self.doc_fix())
            self.assertEqual((row["action"], row["status"]), ("report_only", "report_only"))
            self.assertIn("doc_fix", row["detail"])
        self.assertEqual(self.sb.doc.read_bytes(), before)
        self.assertEqual(self.sb.model_calls, [])

    def test_report_only_sections_keep_carter_decisions(self):
        row = self.one("security-posture", finding(
            action="needs_carter", decision="Remove the LAN-wide 33099 allow?"))
        self.assertEqual(row["status"], "needs_carter")
        self.assertEqual(row["decision"], "Remove the LAN-wide 33099 allow?")

    def test_pass_and_cached_verdicts(self):
        result = self.route([
            section("digest-quality", [finding(action="needs_carter")], verdict="PASS"),
            section("config-doc-drift", [finding(action="needs_carter")], verdict="cached-DRIFT"),
        ])
        self.assertEqual([r["section"] for r in result["routes"]], ["config-doc-drift"])

    def test_deploy_routes(self):
        applied = {"steps": [
            {"step": "app_deploy", "service": "blog", "status": "ok", "pre_version": "aaa", "post_version": "bbb",
             "revert": "deploy aaa"},
        ]}
        ok = self.one("config-doc-drift", finding(action="deploy", target={"service": "blog"}), applied)
        self.assertEqual(ok["status"], "handled_by_p1")
        self.assertIn("aaa -> bbb", ok["summary"])
        self.assertEqual(ok["revert"], "deploy aaa")
        failed = self.one("config-doc-drift", finding(action="deploy", target={"service": "blog"}), {"steps": [
            {"step": "app_deploy", "service": "blog", "status": "failed", "error": "health check failed; rolled back"}]})
        self.assertEqual((failed["status"], failed["detail"]), ("failed", "health check failed; rolled back"))
        missing = self.one("config-doc-drift", finding(action="deploy", target={"service": "blog"}), {})
        self.assertEqual(missing["status"], "handled_by_p1")
        bad = self.one("config-doc-drift", finding(action="deploy", target={"service": "open-webui"}), applied)
        self.assertEqual(bad["status"], "needs_carter")

    def test_version_update_routes(self):
        applied = {"steps": [
            {"step": "searxng", "status": "ok", "pre_version": "1", "post_version": "2"},
            {"step": "openwebui_update", "status": "rolled_back", "reason": "health failed"},
            {"step": "llama_cpp", "status": "skipped", "reason": "no newer release is 7 days old"},
        ]}
        rows = {s: self.one("config-doc-drift", finding(action="version_update", target={"service": s}), applied)
                for s in ("searxng", "open-webui", "llama.cpp", "traefik")}
        self.assertEqual(rows["searxng"]["status"], "handled_by_p1")
        self.assertEqual((rows["open-webui"]["status"], rows["open-webui"]["detail"]), ("failed", "health failed"))
        self.assertEqual(rows["llama.cpp"]["status"], "handled_by_p1")
        self.assertIn("7 days", rows["llama.cpp"]["detail"])
        self.assertEqual(rows["traefik"]["status"], "needs_carter")

    def test_one_bad_finding_does_not_block_section(self):
        result = self.route([section("docs-accuracy", [
            finding("finding-1", action="doc_fix", target={"doc": "/etc/passwd", "old_text": "a", "new_text": "b"}),
            finding("finding-2", action="report_only"),
        ])])
        self.assertEqual([r["status"] for r in result["routes"]], ["needs_carter", "report_only"])


class DocFixTests(SandboxTest):
    def test_valid_doc_fix_commits_pushes_and_records_revert(self):
        row = self.one("docs-accuracy", self.doc_fix())
        self.assertEqual(row["status"], "done", row)
        self.assertIn("03:00 UTC", self.sb.doc.read_text())
        sha = git("-C", str(self.sb.notes), "rev-parse", "HEAD")
        self.assertEqual(row["commit"], sha)
        self.assertEqual(row["revert"], f"git -C ~/notes revert {sha}")
        self.assertEqual(git("--git-dir", str(self.sb.notes_origin), "rev-parse", "main"), sha)
        changed = git("-C", str(self.sb.notes), "show", "--name-only", "--format=%s", sha).splitlines()
        self.assertIn("docs-accuracy finding-1", changed[0])
        self.assertEqual([c for c in changed[1:] if c], ["docs/homelab/backup.md"])
        call = self.sb.model_calls[0]
        self.assertEqual(call["mode"], "json")
        self.assertIn("observed evidence", call["prompt"])
        self.assertIn("+The backup runs at 03:00 UTC.", call["prompt"])

    def test_commit_only_touches_the_doc(self):
        other = self.sb.notes / "docs" / "homelab" / "dirty.md"
        other.write_text("Carter is editing this.\n")
        git("-C", str(self.sb.notes), "add", str(other))
        row = self.one("docs-accuracy", self.doc_fix())
        self.assertEqual(row["status"], "done")
        files = git("-C", str(self.sb.notes), "show", "--name-only", "--format=", "HEAD").splitlines()
        self.assertEqual(files, ["docs/homelab/backup.md"])
        self.assertIn("docs/homelab/dirty.md", git("-C", str(self.sb.notes), "diff", "--cached", "--name-only"))

    def test_old_text_must_occur_exactly_once(self):
        missing = self.one("docs-accuracy", self.doc_fix(old="not in the doc"))
        self.assertEqual(missing["status"], "needs_carter")
        self.assertIn("0 times", missing["detail"])
        self.sb.doc.write_text(self.sb.doc.read_text() + "Retention is 7 days.\n")
        git("-C", str(self.sb.notes), "commit", "-qam", "dup")
        twice = self.one("docs-accuracy", self.doc_fix(old="Retention is 7 days.", new="Retention is 30 days."))
        self.assertIn("2 times", twice["detail"])
        self.assertEqual(self.sb.model_calls, [])
        self.assertEqual(git("-C", str(self.sb.notes), "log", "-1", "--format=%s"), "dup")

    def test_dirty_file_is_refused(self):
        dirty = self.sb.notes / "docs" / "homelab" / "dirty.md"
        dirty.write_text("Old fact here.\nCarter's uncommitted line.\n")
        row = self.one("docs-accuracy", self.doc_fix(doc=dirty, old="Old fact here.", new="New fact here."))
        self.assertEqual(row["status"], "needs_carter")
        self.assertIn("uncommitted changes", row["detail"])
        self.assertIn("Carter's uncommitted line", dirty.read_text())
        self.assertIn("Old fact here.", dirty.read_text())

    def test_judge_fail_restores_original_bytes(self):
        before = self.sb.doc.read_bytes()
        head = git("-C", str(self.sb.notes), "rev-parse", "HEAD")
        self.sb.model_reply = FAIL_JSON
        row = self.one("docs-accuracy", self.doc_fix())
        self.assertEqual(row["status"], "needs_carter")
        self.assertIn("unsupported claim", row["detail"])
        self.assertEqual(self.sb.doc.read_bytes(), before)
        self.assertEqual(git("-C", str(self.sb.notes), "rev-parse", "HEAD"), head)

    def test_partial_pass_and_model_error_restore(self):
        before = self.sb.doc.read_bytes()
        self.sb.model_reply = '{"verdict": "pass", "supported_by_evidence": true, "changes_only_target": false, "system_should_change": false}'
        self.assertEqual(self.one("docs-accuracy", self.doc_fix())["status"], "needs_carter")
        self.assertEqual(self.sb.doc.read_bytes(), before)

        def boom(*a, **k):
            raise RuntimeError("omp down")
        row = self.one("docs-accuracy", self.doc_fix(), omp_call=boom)
        self.assertEqual(row["status"], "failed")
        self.assertEqual(self.sb.doc.read_bytes(), before)

    def test_doc_fix_refuses_to_document_a_broken_system(self):
        before = self.sb.doc.read_bytes()
        self.sb.model_reply = SYSTEM_BROKEN_JSON
        self.assertEqual(self.one("docs-accuracy", self.doc_fix())["status"], "needs_carter")
        self.assertEqual(self.sb.doc.read_bytes(), before)

    def test_outside_allowlist_and_symlink_escape(self):
        outside = self.sb.notes / "README.md"
        outside.write_text("The backup runs at 02:00 UTC.\n")
        self.assertEqual(self.one("docs-accuracy", self.doc_fix(doc=outside))["status"], "needs_carter")
        link = self.sb.notes / "docs" / "escape.md"
        link.symlink_to(outside)
        row = self.one("docs-accuracy", self.doc_fix(doc=link))
        self.assertEqual(row["status"], "needs_carter")
        self.assertIn("allowlist", row["detail"])
        same = self.one("docs-accuracy", self.doc_fix(new="The backup runs at 02:00 UTC."))
        self.assertEqual(same["status"], "needs_carter")

    def test_agents_md_uses_dotfiles_repo(self):
        row = self.one("agents-md-truth", self.doc_fix(
            doc=self.sb.home / "AGENTS.md", old="model X", new="model Y"))
        self.assertEqual(row["status"], "done", row)
        sha = git(*self.sb.dot, "rev-parse", "HEAD")
        self.assertEqual(row["revert"],
                         f"git --git-dir=$HOME/.dotfiles-homelab --work-tree=$HOME revert {sha}")
        self.assertEqual(git("--git-dir", str(self.sb.dot_origin), "rev-parse", "main"), sha)
        self.assertEqual(git(*self.sb.dot, "show", "--name-only", "--format=", sha), "AGENTS.md")


class CleanupTests(SandboxTest):
    def cleanup(self, *paths):
        return finding(action="cleanup", target={"paths": list(paths)})

    def test_pattern_enforcement(self):
        head = git(*self.sb.dot, "rev-parse", "HEAD")
        for paths in (("secret.txt",), ("nltk_data/", "secret.txt"), ("../etc/nltk_data/",), ("/nltk_data/",), ()):
            row = self.one("notes-resources", self.cleanup(*paths))
            self.assertEqual(row["status"], "needs_carter", paths)
        self.assertEqual(git(*self.sb.dot, "rev-parse", "HEAD"), head)
        self.assertIn("secret.txt", git(*self.sb.dot, "ls-files"))

    def test_untracks_and_ignores_only_matching_paths(self):
        row = self.one("notes-resources", self.cleanup("~/nltk_data/corpora/a.txt"))
        self.assertEqual(row["status"], "done", row)
        tracked = git(*self.sb.dot, "ls-files").splitlines()
        self.assertEqual(sorted(tracked), [".gitignore", "AGENTS.md", "secret.txt"])
        self.assertTrue((self.sb.home / "nltk_data" / "corpora" / "a.txt").exists())
        self.assertIn("/nltk_data/", (self.sb.home / ".gitignore").read_text())
        sha = git(*self.sb.dot, "rev-parse", "HEAD")
        self.assertEqual(row["revert"], f"git --git-dir=$HOME/.dotfiles-homelab --work-tree=$HOME revert {sha}")
        files = sorted(git(*self.sb.dot, "show", "--name-only", "--format=", sha).splitlines())
        self.assertEqual(files, [".gitignore", "nltk_data/corpora/a.txt"])
        self.assertEqual(git("--git-dir", str(self.sb.dot_origin), "rev-parse", "main"), sha)
        again = self.one("notes-resources", self.cleanup("nltk_data/"))
        self.assertEqual((again["status"], again["commit"]), ("done", ""))

    def test_refuses_when_index_has_staged_changes(self):
        (self.sb.home / "secret.txt").write_text("changed\n")
        git(*self.sb.dot, "add", "secret.txt")
        row = self.one("notes-resources", self.cleanup("nltk_data/"))
        self.assertEqual(row["status"], "needs_carter")
        self.assertIn("staged", row["detail"])


class FakeGh:
    def __init__(self, *, allow=True, protection=None, rules=None, runs=None, merge_rc=0,
                 methods=None):
        self.calls = []
        self.allow = allow
        self.protection = protection
        self.rules = rules if rules is not None else []
        self.runs = runs if runs is not None else ["success"] * 5
        self.merge_rc = merge_rc
        self.methods = {"allow_rebase_merge": True} if methods is None else methods

    def __call__(self, args, cwd=None):
        self.calls.append(list(args))
        if args[:2] == ["repo", "view"]:
            return cp(0, json.dumps({"nameWithOwner": "carter2099/blog", "defaultBranchRef": {"name": "main"}}))
        if args[:2] == ["pr", "create"]:
            return cp(0, "https://github.com/carter2099/blog/pull/7\n")
        if args[:2] == ["pr", "merge"]:
            return cp(self.merge_rc, "", "merge refused" if self.merge_rc else "")
        if args[0] == "api":
            path = args[1]
            if path.endswith("/protection"):
                return cp(0, json.dumps(self.protection)) if self.protection else cp(1, "", "Branch not protected")
            if "/rules/branches/" in path:
                return cp(0, json.dumps(self.rules))
            if "/actions/runs" in path:
                return cp(0, json.dumps({"workflow_runs": [{"conclusion": c} for c in self.runs]}))
            return cp(0, json.dumps({"allow_auto_merge": self.allow, "default_branch": "main",
                                     **self.methods}))
        return cp(1, "", f"unexpected gh call {args}")


CLASSIC = {"required_status_checks": {"contexts": ["ci"], "checks": [{"context": "ci"}]}}


class AutoMergeTests(unittest.TestCase):
    def check(self, gh, name="blog"):
        ctx = routing.RouteContext(gh=gh)
        return routing.auto_merge_eligibility(ctx, name, "carter2099/" + name, "main")

    def test_all_satisfied(self):
        self.assertEqual(self.check(FakeGh(protection=CLASSIC))[0], True)

    def test_active_ruleset_satisfies_required_check(self):
        rules = [{"type": "required_status_checks",
                  "parameters": {"required_status_checks": [{"context": "ci"}]}}]
        self.assertTrue(self.check(FakeGh(rules=rules))[0])

    def test_missing_required_check(self):
        ok, reason = self.check(FakeGh(rules=[{"type": "deletion"}]))
        self.assertFalse(ok)
        self.assertIn("status check", reason)
        ok, _ = self.check(FakeGh(protection={"required_status_checks": None}))
        self.assertFalse(ok)

    def test_auto_merge_disabled(self):
        ok, reason = self.check(FakeGh(allow=False, protection=CLASSIC))
        self.assertFalse(ok)
        self.assertIn("disabled", reason)

    def test_red_or_too_few_recent_runs(self):
        self.assertFalse(self.check(FakeGh(protection=CLASSIC, runs=["success"] * 4 + ["failure"]))[0])
        self.assertFalse(self.check(FakeGh(protection=CLASSIC, runs=["success"] * 3))[0])

    def test_excluded_and_non_candidate_repos(self):
        for name in ("llm-proxy", "homelab-backup", "random-app"):
            gh = FakeGh(protection=CLASSIC)
            self.assertFalse(self.check(gh, name)[0])
            self.assertEqual(gh.calls, [])


class CodeFixTests(SandboxTest):
    def code_fix(self, repo=None, paths=("app.py",), fid="finding-1"):
        return finding(fid, action="code_fix", target={"repo": str(repo or self.sb.app), "paths": list(paths)})

    def test_flattening_and_section_grouping(self):
        seen = []

        def fake_fix(name, findings, dry_run, run_dir):
            seen.append((name, findings, dry_run))
            return {"section": name, "status": "completed", "stop_reason": "no_progress",
                    "judge_summary": "tests still fail", "iteration_count": 2, "fixes_applied": []}

        result = self.route([
            section("digest-quality", [self.code_fix(), finding("finding-2", action="needs_carter")]),
            section("config-doc-drift", [finding(action="report_only")]),
        ], fix_section=fake_fix)
        self.assertEqual(len(seen), 1)
        name, findings, dry = seen[0]
        self.assertEqual((name, dry), ("digest-quality", False))
        self.assertEqual(findings, [{
            "id": "finding-1", "claim": "claim finding-1", "evidence": "observed evidence",
            "fix": "do the fix", "repo": str(self.sb.app.resolve()), "paths": ["app.py"],
        }])
        from steward import worker
        self.assertEqual(worker._explicit_repo_values(findings[0]), [str(self.sb.app.resolve())])
        self.assertEqual(worker._explicit_paths(findings[0]), ["app.py"])
        rows = result["routes"]
        self.assertEqual([r["finding_id"] for r in rows], ["finding-1", "finding-2", "finding-1"])
        self.assertEqual((rows[0]["status"], rows[0]["iteration"]), ("needs_carter", 2))
        self.assertIn("tests still fail", rows[0]["detail"])
        self.assertEqual(len(result["sections"]), 1)

    def test_invalid_targets_never_reach_worker(self):
        cases = [
            self.code_fix(repo=self.sb.dev / "llm-proxy", paths=("main.py",)),
            self.code_fix(repo=self.sb.dev / "prompt-guard", paths=("main.py",)),
            self.code_fix(repo=self.sb.home / ".dotfiles-homelab"),
            self.code_fix(repo=self.sb.notes, paths=("docs",)),
            self.code_fix(paths=("missing.py",)),
            self.code_fix(paths=("../notes/x",)),
            self.code_fix(paths=()),
            finding(action="code_fix", target={}),
        ]
        for f in cases:
            row = self.one("digest-quality", f)
            self.assertEqual(row["status"], "needs_carter", f)
            self.assertTrue(row["detail"])

    def test_worker_unavailable_is_failed(self):
        row = self.one("digest-quality", self.code_fix(), fix_section=lambda *a: {
            "status": "fix-failed", "stop_reason": "worker-unavailable", "judge_summary": "helper missing"})
        self.assertEqual(row["status"], "failed")

    def published(self):
        base = git("-C", str(self.sb.app), "rev-parse", "HEAD")
        tree = git("-C", str(self.sb.app), "rev-parse", "HEAD^{tree}")
        commit = git("-C", str(self.sb.app), "commit-tree", tree, "-p", base, "-m", "chore: steward review")
        repo = str(self.sb.app.resolve())

        def fake_fix(name, findings, dry_run, run_dir):
            return {
                "section": name, "status": "review-required", "judge_verdict": "pass",
                "judge_summary": "fix verified", "iteration_count": 1, "stop_reason": "pass",
                "fixes_applied": [{"id": "finding-1", "finding": "claim finding-1", "status": "deferred", "iteration": 1}],
                "iterations": [{"validation": [{"repository": repo, "records": [{"argv": ["python3", "-m", "unittest"], "returncode": 0}]}]}],
                "source_repair_commits": [{"repository": repo, "commit": commit}],
            }
        return commit, fake_fix

    def test_pr_route_auto_merge(self):
        commit, fake_fix = self.published()
        gh = FakeGh(protection=CLASSIC)
        row = self.one("digest-quality", self.code_fix(), fix_section=fake_fix, gh=gh)
        self.assertEqual(row["status"], "pr_auto_merge", row)
        self.assertEqual(row["pr_url"], "https://github.com/carter2099/blog/pull/7")
        self.assertEqual(row["commit"], commit)
        self.assertEqual(row["iteration"], 1)
        branch = f"steward/2026-09-24-digest-quality-{commit[:8]}"
        self.assertEqual(git("--git-dir", str(self.sb.app_origin), "rev-parse", branch), commit)
        create = next(c for c in gh.calls if c[:2] == ["pr", "create"])
        body = create[create.index("--body") + 1]
        for text in ("claim finding-1", "observed evidence", "python3 -m unittest", "fix verified"):
            self.assertIn(text, body)
        self.assertEqual(create[create.index("--head") + 1], branch)
        merge = next(c for c in gh.calls if c[:2] == ["pr", "merge"])
        self.assertEqual(merge[3:], ["--auto", "--rebase", "--delete-branch"])
        self.assertFalse(any("--admin" in c for c in gh.calls))

    def test_pr_route_uses_the_merge_method_the_repository_allows(self):
        _, fake_fix = self.published()
        gh = FakeGh(protection=CLASSIC, methods={"allow_rebase_merge": False,
                                                 "allow_squash_merge": True})
        row = self.one("digest-quality", self.code_fix(), fix_section=fake_fix, gh=gh)
        self.assertEqual(row["status"], "pr_auto_merge", row)
        merge = next(c for c in gh.calls if c[:2] == ["pr", "merge"])
        self.assertEqual(merge[3:], ["--auto", "--squash", "--delete-branch"])
        self.assertFalse(any("--admin" in c for c in gh.calls))

        _, fake_fix = self.published()
        gh = FakeGh(protection=CLASSIC, methods={})
        row = self.one("digest-quality", self.code_fix(), fix_section=fake_fix, gh=gh)
        self.assertEqual(row["status"], "pr_opened")
        self.assertIn("no merge method", row["detail"])
        self.assertFalse(any(c[:2] == ["pr", "merge"] for c in gh.calls))

    def test_pr_route_stays_open_when_ineligible(self):
        _, fake_fix = self.published()
        gh = FakeGh(allow=False, protection=CLASSIC)
        row = self.one("digest-quality", self.code_fix(), fix_section=fake_fix, gh=gh)
        self.assertEqual(row["status"], "pr_opened")
        self.assertIn("disabled", row["detail"])
        self.assertEqual(row["revert"], "gh pr close https://github.com/carter2099/blog/pull/7 --delete-branch")
        self.assertFalse(any(c[:2] == ["pr", "merge"] for c in gh.calls))


class DryRunAndPhaseTests(SandboxTest):
    def audit(self):
        return {"sections": [
            section("docs-accuracy", [
                finding("finding-1", action="doc_fix", target={
                    "doc": str(self.sb.doc), "old_text": "Retention is 7 days.", "new_text": "Retention is 30 days."}),
                finding("finding-2", action="cleanup", target={"paths": ["nltk_data/"]}),
            ]),
            section("version-currency", [finding(action="version_update", target={"service": "searxng"})]),
            section("digest-quality", [finding(action="needs_carter", decision="Pick one", severity="high")]),
        ]}

    def run_phase(self, audit, dry_run, **ctx):
        run_dir = self.sb.root / "run"
        run_dir.mkdir(exist_ok=True)
        (run_dir / "07-audit.json").write_text(json.dumps(audit))
        with patch.object(fixes, "run_isolated_fix", side_effect=AssertionError("worker must not run")):
            ctx.setdefault("fix_section", None)
            result = fixes.phase_7b_fix(run_dir, dry_run=dry_run, route_context=self.sb.ctx(**ctx))
        written = json.loads((run_dir / "07b-fixes.json").read_text())
        self.assertEqual(written, result)
        return written

    def test_phase_writes_contract_routes_and_skips_worker(self):
        doc_before = self.sb.doc.read_bytes()
        out = self.run_phase(self.audit(), dry_run=False)
        self.assertEqual(set(out), {"sections", "report_only", "routes", "status"})
        self.assertEqual(out["sections"], [])
        self.assertEqual(out["report_only"], [{"section": "version-currency", "status": "report-only", "findings_count": 1}])
        for row in out["routes"]:
            self.assertEqual(set(row), CONTRACT_KEYS)
        self.assertEqual([r["status"] for r in out["routes"]], ["done", "done", "report_only", "needs_carter"])
        self.assertNotEqual(self.sb.doc.read_bytes(), doc_before)

    def test_dry_run_mutates_nothing(self):
        notes_head = git("-C", str(self.sb.notes), "rev-parse", "HEAD")
        dot_head = git(*self.sb.dot, "rev-parse", "HEAD")
        doc_before = self.sb.doc.read_bytes()
        ignore_before = (self.sb.home / ".gitignore").read_bytes()
        audit = self.audit()
        audit["sections"].append(section("config-doc-drift", [finding(
            action="code_fix", target={"repo": str(self.sb.app), "paths": ["app.py"]})]))
        gh = FakeGh(protection=CLASSIC)
        out = self.run_phase(audit, dry_run=True, gh=gh)
        statuses = {(r["section"], r["finding_id"]): r["status"] for r in out["routes"]}
        self.assertEqual(statuses[("docs-accuracy", "finding-1")], "report_only")
        self.assertEqual(statuses[("docs-accuracy", "finding-2")], "report_only")
        self.assertEqual(statuses[("config-doc-drift", "finding-1")], "report_only")
        self.assertTrue(all(r["summary"].startswith("Dry run") for r in out["routes"]
                            if r["action"] in ("doc_fix", "cleanup", "code_fix")))
        self.assertEqual(out["sections"][0]["status"], "dry-run")
        self.assertEqual(git("-C", str(self.sb.notes), "rev-parse", "HEAD"), notes_head)
        self.assertEqual(git(*self.sb.dot, "rev-parse", "HEAD"), dot_head)
        self.assertEqual(self.sb.doc.read_bytes(), doc_before)
        self.assertEqual((self.sb.home / ".gitignore").read_bytes(), ignore_before)
        self.assertIn("nltk_data/corpora/a.txt", git(*self.sb.dot, "ls-files"))
        self.assertEqual(self.sb.model_calls, [])
        self.assertEqual(gh.calls, [])

    def test_legacy_v1_audit_renders_routes(self):
        out = self.run_phase({"sections": [section("config-doc-drift", [finding()], verdict="ATTENTION")]}, dry_run=False)
        self.assertEqual(out["routes"][0]["status"], "needs_carter")
        self.assertEqual(out["sections"], [])

    def test_no_audit(self):
        run_dir = self.sb.root / "empty"
        run_dir.mkdir()
        out = fixes.phase_7b_fix(run_dir, route_context=self.sb.ctx())
        self.assertEqual(out, {"sections": [], "routes": [], "status": "no_audit"})


if __name__ == "__main__":
    unittest.main()
