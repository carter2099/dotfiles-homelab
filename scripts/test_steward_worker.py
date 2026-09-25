#!/usr/bin/env python3
"""Repair proposals cannot mutate user state or execute Git filters."""
from __future__ import annotations

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from steward import worker


class WorkerBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / "app"
        self.repo.mkdir()
        boundary = patch.object(worker, "_ALLOWED_REPO_ROOT", self.root)
        boundary.start()
        self.addCleanup(boundary.stop)
        self.git("init", "--initial-branch=main")
        self.git("config", "user.name", "Worker Test")
        self.git("config", "user.email", "worker-test@localhost")
        (self.repo / "main.py").write_text("def answer():\n    return 1\n")
        (self.repo / ".gitignore").write_text("__pycache__/\n")
        self.git("add", "main.py", ".gitignore")
        self.git("commit", "-m", "original application")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.commands = worker._validation_plan(self.repo, ["main.py"])

    def git(self, *args):
        return subprocess.run(
            ["/usr/bin/git", "-C", str(self.repo), *args],
            env=worker._minimal_env(), text=True, capture_output=True, check=True,
        ).stdout

    @staticmethod
    def answer(source):
        namespace = {}
        exec(source, namespace)
        return namespace["answer"]()

    def packet(self):
        original = (self.repo / "main.py").read_text()
        (self.repo / "main.py").write_text("def answer():\n    return 2\n")
        diff = self.git("diff", "--no-ext-diff", "--no-textconv", "--full-index", "HEAD")
        (self.repo / "main.py").write_text(original)
        binding = {
            "source": str(self.repo), "base_sha": self.base,
            "allowed_paths": ["main.py"], "validation_commands": self.commands,
        }
        return {
            "protocol_version": worker.PROTOCOL_VERSION, "status": "ok",
            "judge_packet": {"verdict": "pass"},
            "_trusted_repositories": [binding],
            "repositories": [{
                "source": str(self.repo), "base_sha": self.base,
                "allowed_paths": ["main.py"], "changed_paths": ["main.py"],
                "diff": diff, "diff_sha256": worker._sha256_text(diff),
                "validation": [{"argv": command, "returncode": 0} for command in self.commands],
            }],
        }

    def test_review_preserves_staged_and_unstaged_user_edits(self):
        packet = self.packet()
        (self.repo / "main.py").write_text("def answer():\n    return 41\n")
        (self.repo / "user.txt").write_text("unrelated staged work\n")
        self.git("add", "main.py", "user.txt")
        (self.repo / "main.py").write_text("def answer():\n    return 42\n")
        before = self.git("status", "--porcelain=v1", "-z")
        result = worker.publish_validated_result(packet, "application-behavior")
        self.assertEqual(result["status"], "published", result)
        review = result["commits"][0]
        self.assertEqual(self.git("rev-parse", "HEAD").strip(), self.base)
        self.assertEqual(self.git("status", "--porcelain=v1", "-z"), before)
        self.assertEqual(self.answer(self.git("show", ":main.py")), 41)
        self.assertEqual(self.answer((self.repo / "main.py").read_text()), 42)
        self.assertEqual(self.git("show", ":user.txt"), "unrelated staged work\n")
        self.assertEqual(self.answer(self.git("show", f"{review['ref']}:main.py")), 2)
        repeated = worker.publish_validated_result(packet, "application-behavior")
        self.assertEqual(repeated["commits"][0]["commit"], review["commit"])

    def test_active_filter_is_rejected_before_reading_worktree(self):
        (self.repo / ".gitattributes").write_text("*.py filter=trap\n")
        self.git("add", ".gitattributes")
        self.git("commit", "-m", "attribute fixture")
        marker = self.root / "filter-executed"
        self.git("config", "filter.trap.clean", f"touch {marker}; cat")
        (self.repo / "main.py").write_text("def answer():\n    return 12345\n")
        plans, errors = worker._target_plans([
            {"repository": str(self.repo), "paths": ["main.py"], "claim": "wrong answer"},
        ])
        self.assertEqual(plans, [])
        self.assertTrue(errors)
        self.assertFalse(marker.exists(), "a Git filter executed as the parent user")

    def test_deployment_file_cannot_be_selected_for_repair(self):
        with self.assertRaises(worker.WorkerPolicyError):
            worker._safe_relpath("Dockerfile")
        packet = self.packet()
        packet["_trusted_repositories"][0]["allowed_paths"] = ["deploy/routing.yml"]
        result = worker.publish_validated_result(packet, "application-behavior")
        self.assertEqual(result["status"], "publish-rejected")
        self.assertEqual(self.git("for-each-ref", "refs/steward-review"), "")

    def test_changed_validation_plan_cannot_publish(self):
        packet = self.packet()
        packet["repositories"][0]["validation"] = [{"argv": ["python3", "--version"], "returncode": 0}]
        result = worker.publish_validated_result(packet, "application-behavior")
        self.assertEqual(result["status"], "publish-rejected")
        self.assertEqual(self.git("for-each-ref", "refs/steward-review"), "")

    def test_failed_validation_retains_the_real_command_error(self):
        (self.repo / "test_broken.py").write_text(
            "import unittest\n"
            "class BrokenTest(unittest.TestCase):\n"
            "    def test_content(self):\n"
            "        raise RuntimeError('attachment content is missing')\n"
        )
        home = self.root / "validation-home"
        home.mkdir()
        with patch.object(worker, "WORKER_PRIVATE_HOME", home):
            with self.assertRaises(worker.WorkerExecutionError) as failure:
                worker._run_validations(self.repo, [["python3", "-m", "unittest", "discover"]])
        self.assertIn("RuntimeError: attachment content is missing", str(failure.exception))

    def test_judge_and_validation_observe_the_exact_repaired_candidate(self):
        (self.repo / "test_answer.py").write_text(
            "import unittest\nfrom main import answer\n"
            "class AnswerTest(unittest.TestCase):\n"
            "    def test_answer(self):\n        self.assertEqual(answer(), 2)\n"
        )
        self.git("add", "test_answer.py")
        self.git("commit", "-m", "consumer regression fixture")
        run_root = self.root / "runs"
        snapshot = run_root / "request" / "repo-0"
        shutil.copytree(self.repo, snapshot, ignore=shutil.ignore_patterns(".git"))
        home = self.root / "home"
        home.mkdir()
        finding = {"claim": "answer returns the wrong result"}
        calls = []

        def model(_prompt, cwd, _sessions, _timeout):
            if not calls:
                (cwd / "main.py").write_text("def answer():\n    return 2\n")
                calls.append("fix")
                return json.dumps({"fixes_applied": [{"finding": finding["claim"], "action": "correct answer", "status": "fixed"}], "summary": "repaired"})
            self.assertEqual(self.answer((cwd / "main.py").read_text()), 2)
            calls.append("judge")
            return json.dumps({"verdict": "pass", "reviewed": [{"finding": finding["claim"], "ok": True, "note": "consumer returns 2"}], "summary": "verified"})

        repository = {
            "workspace": str(snapshot), "source": str(self.repo),
            "base_sha": self.git("rev-parse", "HEAD").strip(), "allowed_paths": ["main.py"],
            "validation_commands": worker._validation_plan(self.repo, ["main.py"]),
            "findings": [finding],
        }
        with patch.object(worker, "WORKER_RUN_ROOT", run_root), patch.object(worker, "WORKER_PRIVATE_HOME", home), patch.object(worker, "_omp_call", side_effect=model):
            result = worker._worker_repository({"section": "application-behavior"}, repository, self.root / "sessions")
        packet = {
            "protocol_version": worker.PROTOCOL_VERSION, "status": "ok",
            "judge_packet": result["judge_packet"], "repositories": [result],
            "_trusted_repositories": [copy.deepcopy(repository)],
        }
        published = worker.publish_validated_result(packet, "application-behavior")
        self.assertEqual(published["status"], "published", published)
        self.assertEqual(self.answer(self.git("show", f"{published['commits'][0]['ref']}:main.py")), 2)
        self.assertEqual(self.answer((self.repo / "main.py").read_text()), 1)


if __name__ == "__main__":
    unittest.main()
