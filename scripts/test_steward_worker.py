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

# A runner-style companion test file, shaped like scripts/test_digest_pipeline.py.
DIGEST_BASE = '''"""Digest fixtures."""
from daily_news import contracts


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def test_parse():
    check(contracts.parse("a") == "a", "parse keeps text")


def test_render():
    value = contracts.parse("b")
    check(value == "b", "parse keeps other text")


def main():
    tests = [test_parse, test_render]
    for test in tests:
        test()


if __name__ == "__main__":
    main()
'''
REGISTERED = "tests = [test_parse, test_render, test_parse_strips]"


def with_regression(source=DIGEST_BASE):
    """Append a new test function and register it in main()'s runner list."""
    new_test = '\n\ndef test_parse_strips():\n    check(contracts.parse(" a ") == "a", "parse strips")\n'
    return source.replace("\n\ndef main():", new_test + "\n\ndef main():").replace(
        "tests = [test_parse, test_render]", REGISTERED)


APP_TEST = (
    "import unittest\n\nfrom main import answer\n\n\n"
    "class AnswerTest(unittest.TestCase):\n"
    "    def test_answer_is_int(self):\n        self.assertIsInstance(answer(), int)\n"
)


def review_packet(repo, git, allowed, edits, companions):
    """A judge-pass worker result for ``edits`` against HEAD of ``repo``."""
    base = git("rev-parse", "HEAD").strip()
    originals = {path: (repo / path).read_text() for path in edits}
    for path, text in edits.items():
        (repo / path).write_text(text)
    diff = git("diff", "--no-ext-diff", "--no-textconv", "--full-index", "HEAD")
    for path, text in originals.items():
        (repo / path).write_text(text)
    commands = worker._validation_plan(repo, allowed, companions)
    binding = {
        "source": str(repo), "base_sha": base, "allowed_paths": list(allowed),
        "companion_test_paths": list(companions), "validation_commands": commands,
    }
    return {
        "protocol_version": worker.PROTOCOL_VERSION, "status": "ok",
        "judge_packet": {"verdict": "pass"},
        "_trusted_repositories": [binding],
        "repositories": [{
            **binding, "changed_paths": sorted(edits),
            "diff": diff, "diff_sha256": worker._sha256_text(diff),
            "validation": [{"argv": command, "returncode": 0} for command in commands],
        }],
    }


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
        with self.assertRaises(worker.WorkerExecutionError) as failure:
            worker._run_validations(self.repo, [["python3", "-m", "unittest", "discover"]], home)
        self.assertIn("RuntimeError: attachment content is missing", str(failure.exception))

    def test_judge_and_validation_observe_the_exact_repaired_candidate(self):
        (self.repo / "test_answer.py").write_text(
            "import unittest\nfrom main import answer\n"
            "class AnswerTest(unittest.TestCase):\n"
            "    def test_answer(self):\n        self.assertEqual(answer(), 2)\n"
        )
        self.git("add", "test_answer.py")
        self.git("commit", "-m", "consumer regression fixture")
        snapshot = self.root / "runs" / "repo-0"
        shutil.copytree(self.repo, snapshot, ignore=shutil.ignore_patterns(".git"))
        home = self.root / "home"
        home.mkdir()
        finding = {"claim": "answer returns the wrong result"}
        calls = []

        def model(_prompt, cwd, _timeout):
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
        with patch.object(worker, "_omp_call", side_effect=model):
            result = worker._worker_repository("application-behavior", 1, repository, home, 600)
        packet = {
            "protocol_version": worker.PROTOCOL_VERSION, "status": "ok",
            "judge_packet": result["judge_packet"], "repositories": [result],
            "_trusted_repositories": [copy.deepcopy(repository)],
        }
        published = worker.publish_validated_result(packet, "application-behavior")
        self.assertEqual(published["status"], "published", published)
        self.assertEqual(self.answer(self.git("show", f"{published['commits'][0]['ref']}:main.py")), 2)
        self.assertEqual(self.answer((self.repo / "main.py").read_text()), 1)

    def test_run_fix_edits_a_base_snapshot_without_secrets_or_the_checkout(self):
        (self.repo / ".env").write_text("TOKEN=do-not-show-the-model\n")
        self.git("add", ".env")
        self.git("commit", "-m", "tracked env file")
        finding = {"id": "f1", "claim": "answer returns the wrong result",
                   "repo": str(self.repo), "paths": ["main.py"]}
        seen = []

        def model(_prompt, cwd, _timeout):
            seen.append(sorted(p.name for p in cwd.iterdir() if p.name != ".git"))
            if len(seen) == 1:
                (cwd / "main.py").write_text("def answer():\n    return 2\n")
                return json.dumps({"fixes_applied": [{"finding": "f1", "action": "fix", "status": "fixed"}], "summary": "repaired"})
            return json.dumps({"verdict": "pass", "reviewed": [{"finding": "f1", "ok": True, "note": "ok"}], "summary": "verified"})

        with patch.object(worker, "_omp_call", side_effect=model):
            result = worker.run_fix("application-behavior", [finding])
        self.assertEqual(result["status"], "ok", result)
        self.assertNotIn(".env", seen[0], "a credential-looking tracked file reached the model")
        self.assertIn("main.py", seen[0])
        published = worker.publish_validated_result(result, "application-behavior")
        self.assertEqual(published["status"], "published", published)
        self.assertEqual(self.answer(self.git("show", f"{published['commits'][0]['ref']}:main.py")), 2)
        self.assertEqual(self.answer((self.repo / "main.py").read_text()), 1)

    def add_tests(self):
        (self.repo / "test_main.py").write_text(APP_TEST)
        (self.repo / "test_other.py").write_text(
            "import unittest\n\n\nclass OtherTest(unittest.TestCase):\n"
            "    def test_truth(self):\n        self.assertTrue(True)\n"
        )
        self.git("add", "test_main.py", "test_other.py")
        self.git("commit", "-m", "test fixtures")

    def test_non_companion_test_file_is_still_a_disallowed_path(self):
        self.add_tests()
        plans, errors = worker._target_plans([
            {"repository": str(self.repo), "paths": ["main.py"], "claim": "wrong answer"},
        ])
        self.assertEqual(errors, [])
        self.assertEqual(plans[0]["companion_test_paths"], ["test_main.py"])
        added = "\n    def test_more(self):\n        self.assertTrue(1)\n"
        other = (self.repo / "test_other.py").read_text() + added
        packet = review_packet(self.repo, self.git, ["main.py"], {"test_other.py": other}, ["test_main.py"])
        result = worker.publish_validated_result(packet, "application-behavior")
        self.assertEqual(result["status"], "publish-rejected")
        self.assertIn("disallowed", result["error"])
        (self.repo / "test_other.py").write_text(other)
        with self.assertRaisesRegex(worker.WorkerPolicyError, "disallowed"):
            worker._snapshot_diff(self.repo, ["main.py"], ["test_main.py"])
        self.git("checkout", "--", "test_other.py")
        # A weakened companion is rejected on the worker side as well.
        (self.repo / "test_main.py").write_text(APP_TEST.replace("int)", "object)") + added)
        with self.assertRaisesRegex(worker.WorkerPolicyError, "additive-only"):
            worker._snapshot_diff(self.repo, ["main.py"], ["test_main.py"])
        self.assertEqual(self.git("for-each-ref", "refs/steward-review"), "")

    def test_run_fix_may_add_a_regression_test_to_a_companion(self):
        self.add_tests()
        finding = {"id": "f1", "claim": "answer returns the wrong result",
                   "repo": str(self.repo), "paths": ["main.py"]}
        prompts = []

        def model(prompt, cwd, _timeout):
            prompts.append(prompt)
            if len(prompts) == 1:
                (cwd / "main.py").write_text("def answer():\n    return 2\n")
                (cwd / "test_main.py").write_text(
                    APP_TEST + "\n    def test_answer_is_two(self):\n        self.assertEqual(answer(), 2)\n"
                )
                return json.dumps({"fixes_applied": [{"finding": "f1", "action": "fix + regression test", "status": "fixed"}], "summary": "repaired"})
            return json.dumps({"verdict": "pass", "reviewed": [{"finding": "f1", "ok": True, "note": "ok"}], "summary": "verified"})

        with patch.object(worker, "_omp_call", side_effect=model):
            result = worker.run_fix("application-behavior", [finding])
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual(result["judge_packet"]["verdict"], "pass", result)
        self.assertIn("Companion test files", prompts[0])
        self.assertIn('["test_main.py"]', prompts[0])
        self.assertIn("could pass without the fix", prompts[1])
        self.assertEqual(result["_trusted_repositories"][0]["companion_test_paths"], ["test_main.py"])
        self.assertEqual(result["repositories"][0]["changed_paths"], ["main.py", "test_main.py"])
        self.assertIn(["python3", "-m", "compileall", "-q", "main.py", "test_main.py"],
                      result["_trusted_repositories"][0]["validation_commands"])
        published = worker.publish_validated_result(result, "application-behavior")
        self.assertEqual(published["status"], "published", published)
        ref = published["commits"][0]["ref"]
        self.assertIn("test_answer_is_two", self.git("show", f"{ref}:test_main.py"))
        self.assertEqual(self.answer(self.git("show", f"{ref}:main.py")), 2)


class AdditiveCompanionCheckTests(unittest.TestCase):
    PATH = "scripts/test_digest_pipeline.py"

    def assertRejected(self, after):
        with self.assertRaises(worker.WorkerPolicyError):
            worker._check_additive_test_change(self.PATH, DIGEST_BASE, after)

    def test_new_test_registered_in_existing_runner_list_is_accepted(self):
        worker._check_additive_test_change(self.PATH, DIGEST_BASE, with_regression())

    def test_inserted_return_is_rejected(self):
        self.assertRejected(with_regression().replace(
            "def test_parse():\n", "def test_parse():\n    return\n"))

    def test_deleted_or_reordered_runner_element_is_rejected(self):
        self.assertRejected(with_regression().replace(REGISTERED, "tests = [test_parse, test_parse_strips]"))
        self.assertRejected(with_regression().replace(
            REGISTERED, "tests = [test_render, test_parse, test_parse_strips]"))

    def test_modified_assertion_is_rejected(self):
        self.assertRejected(with_regression().replace(
            'contracts.parse("a") == "a"', 'contracts.parse("a") == contracts.parse("a")'))

    def test_redefined_existing_test_is_rejected(self):
        self.assertRejected(with_regression() + "\n\ndef test_render():\n    pass\n")

    def test_new_module_level_statements_are_rejected(self):
        self.assertRejected(with_regression() + "\ncheck = lambda *a: None\n")
        self.assertRejected(with_regression() + "\nsetattr(contracts, 'parse', str)\n")
        self.assertRejected(with_regression() + "\nfixture = lambda: None\n")

    def test_import_alias_rebinding_an_existing_name_is_rejected(self):
        self.assertRejected(with_regression().replace(
            "from daily_news import contracts\n", "from daily_news import contracts\nfrom os import path as check\n"))

    def test_new_test_may_not_mutate_module_state(self):
        self.assertRejected(with_regression().replace(
            "def test_parse_strips():\n", "def test_parse_strips():\n    contracts.parse = str\n"))

    def test_change_without_a_new_test_or_unparsable_file_is_rejected(self):
        self.assertRejected(DIGEST_BASE + "# note\n")
        self.assertRejected(with_regression() + "def broken(:\n")


class StewardCodeCompanionTests(unittest.TestCase):
    CONTRACTS = "scripts/daily_news/contracts.py"
    DIGEST = "scripts/test_digest_pipeline.py"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name, value in (("_ALLOWED_REPO_ROOT", self.root),
                            ("STEWARD_CODE_ROOT", self.root / ".steward-code")):
            boundary = patch.object(worker, name, value)
            boundary.start()
            self.addCleanup(boundary.stop)
        self.clone = self.root / ".steward-code" / "clone"
        files = {
            "scripts/daily_news/__init__.py": "",
            self.CONTRACTS: "def parse(text):\n    return text\n",
            "scripts/daily_news/archive.py": "ARCHIVE = 1\n",
            self.DIGEST: DIGEST_BASE,
            "scripts/test_archive_only.py": "from daily_news import archive\n\n\ndef test_archive():\n    assert archive.ARCHIVE\n",
            # Protected: the steward's own policy tests stay needs-Carter.
            "scripts/test_steward_worker.py": "from daily_news import contracts\n",
            # Would add the dependabot-intake verifier to a daily-news fix.
            "scripts/test_hyperliquid_dependabot_intake.py": "from daily_news import contracts\n",
            "scripts/test_unrelated.py": "import json\n",
        }
        for rel, text in files.items():
            path = self.clone / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        self.git("init", "--initial-branch=main")
        self.git("config", "user.name", "Worker Test")
        self.git("config", "user.email", "worker-test@localhost")
        self.git("add", "-A")
        self.git("commit", "-m", "dotfiles fixture")

    def git(self, *args):
        return subprocess.run(
            ["/usr/bin/git", "-C", str(self.clone), *args],
            env=worker._minimal_env(), text=True, capture_output=True, check=True,
        ).stdout

    def test_daily_news_target_selects_its_digest_test_as_companion(self):
        plans, errors = worker._target_plans([
            {"id": "f1", "claim": "contracts keeps padding", "repo": str(self.clone), "paths": [self.CONTRACTS]},
        ])
        self.assertEqual(errors, [])
        self.assertEqual(plans[0]["allowed_paths"], [self.CONTRACTS])
        # Direct module import ranks before a package-only import; protected
        # steward tests and verifier-widening tests are never companions.
        self.assertEqual(plans[0]["companion_test_paths"], [self.DIGEST, "scripts/test_archive_only.py"])
        plan = worker._validation_plan(self.clone, plans[0]["allowed_paths"], plans[0]["companion_test_paths"])
        self.assertEqual(plan[1:], [["bash", "scripts/verify-steward.sh", "full"],
                                    ["bash", "scripts/verify-daily-news.sh", "full"]])
        self.assertEqual(plan[0][-3:], [self.CONTRACTS, self.DIGEST, "scripts/test_archive_only.py"])
        with self.assertRaises(worker.WorkerPolicyError):
            worker._companion_paths(["scripts/test_steward_worker.py"], [self.CONTRACTS],
                                    worker.REPO_KIND_STEWARD_CODE)

    def test_companion_change_round_trips_through_the_trusted_request(self):
        fixed = "def parse(text):\n    return text.strip()\n"
        packet = review_packet(self.clone, self.git, [self.CONTRACTS],
                               {self.CONTRACTS: fixed, self.DIGEST: with_regression()}, [self.DIGEST])
        mismatched = copy.deepcopy(packet)
        mismatched["repositories"][0]["companion_test_paths"] = []
        result = worker.publish_validated_result(mismatched, "s")
        self.assertEqual(result["status"], "publish-rejected")
        self.assertIn("companion test paths differ", result["error"])
        weakened = review_packet(
            self.clone, self.git, [self.CONTRACTS],
            {self.CONTRACTS: fixed, self.DIGEST: with_regression().replace(REGISTERED, "tests = [test_parse_strips]")},
            [self.DIGEST],
        )
        result = worker.publish_validated_result(weakened, "s")
        self.assertEqual(result["status"], "publish-rejected")
        self.assertIn("additive-only", result["error"])
        self.assertEqual(self.git("for-each-ref", "refs/steward-review"), "")
        result = worker.publish_validated_result(packet, "s")
        self.assertEqual(result["status"], "published", result)
        self.assertEqual(result["commits"][0]["changed_paths"], [self.CONTRACTS, self.DIGEST])
        self.assertIn("test_parse_strips", self.git("show", f"{result['commits'][0]['ref']}:{self.DIGEST}"))

    def test_publisher_returns_pre_pr_gate_objections_to_the_fix_loop(self):
        # 2026-10-17: only code_prs.gate saw this after the loop ended, so the
        # worker never got to revise it. The objection now rejects publication.
        leaked = "def parse(text):\n    return text  # ghp_" + "a1B2" * 10 + "\n"
        packet = review_packet(self.clone, self.git, [self.CONTRACTS], {self.CONTRACTS: leaked}, [])
        result = worker.publish_validated_result(packet, "s")
        self.assertEqual(result["status"], "publish-rejected")
        self.assertIn("pre-PR gate would refuse this patch", result["error"])
        self.assertIn("secret scan flagged", result["error"])
        self.assertEqual(self.git("for-each-ref", "refs/steward-review"), "")


if __name__ == "__main__":
    unittest.main()
