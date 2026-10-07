#!/usr/bin/env python3
"""Behavioral checks for P7c resolve and the steward-approve path."""
from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import jev
from steward import report, resolver

RIG = "system-config/gamingrig-linux/config/omp/config.yml"
RIG_ID = "dotfiles-system-config-gamingrig-linux-config-omp-config-yml"
RUN_DATE = "2026-09-29"
# Built at runtime so this source file never carries a token-shaped literal.
SECRET = "gh" + "p_" + "Q7xR2mK9" * 5
RIG2 = "system-config/gamingrig-linux/config/nvim/init.lua"
SESSION_ID = "01a0aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee"
# Session tool calls count only within 24 h before the path's last commit (the
# fixture commits at test time), so fixture calls must be recent, never a fixed date.
_CALL_TIME = datetime.now(timezone.utc) - timedelta(hours=1)
CALL_AT = _CALL_TIME.strftime("%Y-%m-%dT%H:%M:%SZ")
CALL_AT2 = (_CALL_TIME + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
# The review's five shapes; the last one starts with "+" like a diff line.
SECRET_SHAPES = {
    "bearer": "Authorization: Bearer " + "Zx9Qw" * 8,
    "jwt": "tok " + "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0" + ".SflKxwRJSMeKKF2QT4fw",
    "url_credentials": "https://" + "carter:" + "Sw0rdfish99" + "@git.example.net/repo",
    "hex32": "key " + "9f86d081" + "884c7d65" + "9a2feaa0" + "c55ad015",
    "plus_line": "++" + "gh" + "p_" + "Lm4Nb7Vc" * 5,
}


def model_reply(action: str, **extra: object) -> str:
    packet = {"action": action, "rationale": "evidence shows it", "citations": ["E1"], **extra}
    return "```json\n" + json.dumps(packet) + "\n```"


class FakeModel:
    def __init__(self, *replies: str) -> None:
        self.replies = list(replies)
        self.prompts: list[str] = []

    def __call__(self, prompt: str, **_kwargs: object) -> str:
        self.prompts.append(prompt)
        return self.replies.pop(0) if self.replies else model_reply("hold")


class FakeJev:
    def __init__(self, p: float | None = 0.99) -> None:
        self.p = p
        self.states: list[dict] = []

    def ask(self, _purpose, state, questions):
        self.states.append(state)
        if self.p is None:
            raise jev.JevUnavailable("network", "offline")
        return {key: {"type": "noul", "noul": self.p} for key in questions}


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.home = root / "home"
        self.git_dir = root / "git"
        self.run_dir = root / "digests" / RUN_DATE
        self.sessions = root / "sessions"
        for path in (self.home, self.run_dir, self.sessions / "-", root / "memoirs"):
            path.mkdir(parents=True)
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(self.git_dir)], check=True)
        for key, value in (("user.name", "t"), ("user.email", "t@example.invalid")):
            self.git("config", key, value)
        self.write("system-config/dotfiles-publish.toml",
                   'private = ["secret/**"]\npublic = ["system-config/**"]\n')
        self.write(RIG, "default: model-a\n")
        self.write("system-config/b.conf", "b = 1\n")
        self.write(RIG2, "set number\n")
        self.write("scripts/tool.conf", "limit = 10\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "base")
        (self.run_dir / "07b-fixes.json").write_text('{"routes": []}', encoding="utf-8")

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", f"--git-dir={self.git_dir}", f"--work-tree={self.home}", *args],
            check=True, capture_output=True, text=True, cwd=self.home,
        ).stdout

    def write(self, rel: str, text: str) -> None:
        path = self.home / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def head(self) -> str:
        return self.git("rev-parse", "HEAD").strip()

    def transcript(self, *lines: dict) -> None:
        path = self.sessions / "-" / "2026-09-28T10-00-00-000Z_01a0aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee.jsonl"
        path.write_text("".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8")

    def resolve(self, **overrides):
        options = dict(
            home=self.home, git_dir=self.git_dir, session_root=self.sessions,
            memoir_root=self.root / "memoirs", active_sessions=[], push=False,
            rig_sha256=lambda _dest: None, load_jev=False,
        )
        options.update(overrides)
        result = resolver.phase_7c_resolve(self.run_dir, **options)
        return result, {item["id"]: item for item in result["items"]}

    def approve(self, item_id: str, **kwargs):
        return resolver.approve(
            self.run_dir, item_id, steward_running=lambda: False,
            home=self.home, git_dir=self.git_dir, push=False, **kwargs,
        )


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class ResolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.fx = Fixture(Path(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_rig_shortcut_commits_only_byte_identical_deployed_copy(self) -> None:
        self.fx.write(RIG, "default: model-b\n")
        base = self.fx.head()
        model, judge = FakeModel(), FakeJev()
        _, items = self.fx.resolve(
            rig_sha256=lambda dest: sha("default: model-a\n"), omp_call=model, jev_client=judge,
        )
        self.assertEqual(items[RIG_ID]["status"], "held")
        self.assertEqual(self.fx.head(), base)
        self.assertEqual(len(model.prompts), 1, "a differing deployed copy falls through to judgment")

        model, judge = FakeModel(), FakeJev()
        seen: list[str] = []
        _, items = self.fx.resolve(
            rig_sha256=lambda dest: seen.append(dest) or sha("default: model-b\n"),
            omp_call=model, jev_client=judge,
        )
        record = items[RIG_ID]
        self.assertEqual((record["status"], record["action"], record["tier"]), ("done", "commit", "shortcut"))
        self.assertEqual(seen, ["/home/carte/.omp/agent/config.yml"])
        self.assertEqual((model.prompts, judge.states), ([], []))
        self.assertNotEqual(self.fx.head(), base)
        self.assertEqual(self.fx.git("status", "--porcelain", "--", RIG), "")
        self.assertIn(f"revert --no-edit {record['commit']}", record["undo"])

    def test_secret_bearing_transcript_excerpts_never_reach_model_or_jev(self) -> None:
        self.fx.write(RIG, "default: model-b\n")
        self.fx.transcript(
            {"type": "session", "id": "01a0aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee", "title": "rig tuning"},
            {"type": "message", "timestamp": CALL_AT,
             "message": {"role": "user", "content": f"use token {SECRET} and switch the rig model"}},
            {"type": "message", "timestamp": CALL_AT2,
             "message": {"role": "assistant", "content": [{"type": "toolCall", "name": "edit",
                         "arguments": {"i": "Switching rig default model", "input": f"[{RIG}#AB12]"}}]}},
        )
        model, judge = FakeModel(model_reply("commit")), FakeJev(0.99)
        _, items = self.fx.resolve(omp_call=model, jev_client=judge)
        record = items[RIG_ID]
        self.assertEqual(record["status"], "done")
        seen = "\n".join(model.prompts) + json.dumps(judge.states)
        self.assertNotIn(SECRET, seen)
        self.assertIn("Switching rig default model", model.prompts[0])
        self.assertIn("session_user", [d["kind"] for d in record["dropped_excerpts"]])

    def test_jev_certainty_tiers(self) -> None:
        cases = (
            (0.99, "done"),        # certainty 0.98 >= 0.9: act
            (0.9, "recommended"),  # certainty 0.8: Needs You with approval command
            (0.02, "unknown"),     # a confident "no"
            (None, "unknown"),     # Jev failure
        )
        for p, expected in cases:
            with self.subTest(p=p):
                self.fx.git("reset", "-q", "--hard", "HEAD")
                self.fx.write(RIG, f"default: model-{p}\n")
                (self.fx.run_dir / resolver.ARTIFACT).unlink(missing_ok=True)
                (self.fx.run_dir / resolver.ACTIONS_JOURNAL).unlink(missing_ok=True)
                base = self.fx.head()
                _, items = self.fx.resolve(omp_call=FakeModel(model_reply("commit")), jev_client=FakeJev(p))
                record = items[RIG_ID]
                self.assertEqual(record["status"], expected)
                if expected == "recommended":
                    self.assertEqual(record["approve_command"], f"steward-approve {RUN_DATE} {RIG_ID}")
                if expected != "done":
                    self.assertEqual(self.fx.head(), base)
                    self.assertIn(RIG, self.fx.git("status", "--porcelain"))
                if expected == "unknown":
                    self.assertEqual(record["approve_command"], "")

    def test_patch_is_never_applied_autonomously_only_by_approval(self) -> None:
        (self.fx.run_dir / "07b-fixes.json").write_text(json.dumps({"routes": [{
            "section": "agent-fleet-review", "finding_id": "finding-1", "status": "needs_carter",
            "claim": "limit is too low", "severity": "low", "action": "needs_carter",
        }]}), encoding="utf-8")
        (self.fx.run_dir / "07-audit.json").write_text(json.dumps({"sections": [{
            "name": "agent-fleet-review", "verdict": "DRIFT",
            "judge_confirmed": [{"id": "finding-1", "claim": "limit is too low", "action": "needs_carter",
                                 "evidence": "limit = 10 truncates", "target": {"paths": ["scripts/tool.conf"]}}],
        }]}), encoding="utf-8")
        patch = {"path": "~/scripts/tool.conf", "old_text": "limit = 10", "new_text": "limit = 50"}
        _, items = self.fx.resolve(omp_call=FakeModel(model_reply("patch", patch=patch)), jev_client=FakeJev(0.999))
        record = items["agent-fleet-review-finding-1"]
        self.assertEqual((record["status"], record["action"]), ("recommended", "patch"))
        self.assertEqual((self.fx.home / "scripts/tool.conf").read_text(), "limit = 10\n")

        base = self.fx.head()
        row = self.fx.approve("agent-fleet-review-finding-1")
        self.assertEqual((self.fx.home / "scripts/tool.conf").read_text(), "limit = 50\n")
        # A tracked dotfiles path is committed by the approval, not left as drift.
        self.assertNotEqual(self.fx.head(), base)
        self.assertEqual(self.fx.git("status", "--porcelain", "--", "scripts/tool.conf"), "")
        self.assertIn(f"revert --no-edit {row['commit']}", row["undo"])
        with self.assertRaises(resolver.ApprovalRefused):
            self.fx.approve("agent-fleet-review-finding-1")

    def test_approval_refuses_changed_content_and_a_running_steward(self) -> None:
        self.fx.write(RIG, "default: model-b\n")
        _, items = self.fx.resolve(omp_call=FakeModel(model_reply("commit")), jev_client=FakeJev(0.9))
        self.assertEqual(items[RIG_ID]["status"], "recommended")
        base = self.fx.head()
        with self.assertRaisesRegex(resolver.ApprovalRefused, "is running"):
            resolver.approve(self.fx.run_dir, RIG_ID, steward_running=lambda: True,
                             home=self.fx.home, git_dir=self.fx.git_dir)
        self.fx.write(RIG, "default: model-c\n")
        with self.assertRaisesRegex(resolver.ApprovalRefused, "changed since it was judged"):
            self.fx.approve(RIG_ID)
        self.assertEqual(self.fx.head(), base)

        self.fx.write(RIG, "default: model-b\n")
        row = self.fx.approve(RIG_ID)
        self.assertNotEqual(self.fx.head(), base)
        self.assertIn("revert --no-edit", row["undo"])

    def test_active_session_paths_are_never_touched(self) -> None:
        self.fx.write(RIG, "default: model-b\n")
        base = self.fx.head()
        active = [{"session_id": "live", "cwd": "", "recent_context": f"editing {RIG}", "malformed": False}]
        _, items = self.fx.resolve(
            active_sessions=active, rig_sha256=lambda _dest: sha("default: model-b\n"),
            omp_call=FakeModel(model_reply("commit")), jev_client=FakeJev(0.999),
        )
        record = items[RIG_ID]
        self.assertEqual(record["status"], "recommended")
        self.assertIn("active interactive session live", record["reason"])
        self.assertEqual(self.fx.head(), base)

    def test_nightly_cap_limits_autonomous_actions(self) -> None:
        self.fx.write(RIG, "default: model-b\n")
        self.fx.write(RIG2, "set nonumber\n")
        result, items = self.fx.resolve(
            max_actions=1, omp_call=FakeModel(model_reply("commit"), model_reply("commit")),
            jev_client=FakeJev(0.999),
        )
        statuses = sorted(item["status"] for item in items.values())
        self.assertEqual(statuses, ["done", "recommended"])
        capped = next(item for item in items.values() if item["status"] == "recommended")
        self.assertIn("nightly cap", capped["reason"])
        self.assertEqual(result["autonomous_actions"], 1)

        # A resumed attempt carries the executed action forward and stays capped.
        _, again = self.fx.resolve(max_actions=1, omp_call=FakeModel(model_reply("commit")),
                                   jev_client=FakeJev(0.999))
        self.assertEqual(sorted(item["status"] for item in again.values()), ["done", "recommended"])

    def test_failure_is_degraded_not_raised(self) -> None:
        result, _ = self.fx.resolve(git_dir=self.fx.root / "missing")
        self.assertEqual(result["phase_status"], "degraded")
        self.assertTrue(json.loads((self.fx.run_dir / resolver.ARTIFACT).read_text())["reason"])

    def test_every_secret_shape_in_every_placement_is_withheld(self) -> None:
        for shape, token in SECRET_SHAPES.items():
            for placement in ("transcript", "title", "memoir", "doc", "claim"):
                with self.subTest(shape=shape, placement=placement):
                    with tempfile.TemporaryDirectory() as tmp:
                        fx = Fixture(Path(tmp))
                        fx.write(RIG, "default: model-b\n")
                        title = f"rig tuning {token}" if placement == "title" else "rig tuning"
                        user = f"switch the rig model\n{token}" if placement == "transcript" else "switch it"
                        fx.transcript(
                            {"type": "session", "id": SESSION_ID, "title": title},
                            {"type": "message", "timestamp": CALL_AT,
                             "message": {"role": "user", "content": user}},
                            {"type": "message", "timestamp": CALL_AT2,
                             "message": {"role": "assistant", "content": [{"type": "toolCall", "name": "edit",
                                         "arguments": {"i": "Switching rig model", "input": f"[{RIG}#AB12]"}}]}},
                        )
                        memoirs = fx.root / "memoirs" / "2026-09-28"
                        memoirs.mkdir()
                        body = token if placement == "memoir" else "switched the rig model"
                        (memoirs / "1000-rig.md").write_text(
                            f"---\nsession_id: {SESSION_ID}\n---\n# Rig\n\n{body}\n", encoding="utf-8")
                        docs = fx.home / "notes" / "docs"
                        docs.mkdir(parents=True)
                        extra = f" {token}" if placement == "doc" else ""
                        (docs / "rig.md").write_text(f"The rig reads omp/config.yml.{extra}\n", encoding="utf-8")
                        if placement == "claim":
                            claim = f"rig config uncommitted {token}"
                            (fx.run_dir / "07b-fixes.json").write_text(json.dumps({"routes": [{
                                "section": "config-doc-drift", "finding_id": "finding-1",
                                "status": "needs_carter", "claim": claim}]}), encoding="utf-8")
                            (fx.run_dir / "07-audit.json").write_text(json.dumps({"sections": [{
                                "name": "config-doc-drift", "verdict": "DRIFT", "judge_confirmed": [{
                                    "id": "finding-1", "claim": claim, "action": "needs_carter",
                                    "target": {"paths": [RIG]}}]}]}), encoding="utf-8")
                        model, judge = FakeModel(model_reply("commit")), FakeJev(0.9)
                        _, items = fx.resolve(omp_call=model, jev_client=judge, doc_roots=(docs,))
                        sent = "\n".join(model.prompts) + json.dumps(judge.states)
                        self.assertNotIn(token.lstrip("+"), sent)
                        (record,) = items.values()
                        if placement == "claim":
                            self.assertEqual(record["status"], "held")
                            self.assertEqual((model.prompts, judge.states), ([], []))
                        else:
                            self.assertEqual(len(model.prompts), 1)
                            self.assertTrue(record["dropped_excerpts"])
                            artifact = (fx.run_dir / resolver.ARTIFACT).read_text()
                            self.assertNotIn(token.lstrip("+"), artifact)

    def test_staged_or_other_git_states_are_dirty_not_resolved(self) -> None:
        (self.fx.run_dir / "07b-fixes.json").write_text(json.dumps({"routes": [{
            "section": "config-doc-drift", "finding_id": "finding-1", "status": "needs_carter",
            "claim": "rig edit uncommitted"}]}), encoding="utf-8")
        (self.fx.run_dir / "07-audit.json").write_text(json.dumps({"sections": [{
            "name": "config-doc-drift", "verdict": "DRIFT", "judge_confirmed": [{
                "id": "finding-1", "claim": "rig edit uncommitted", "action": "needs_carter",
                "target": {"paths": [RIG]}}]}]}), encoding="utf-8")
        (self.fx.run_dir / "07-audit-5-config.json.evidence.json").write_text(
            json.dumps({"dotfiles_status": f" M {RIG}"}), encoding="utf-8")
        for state in ("M ", "MM"):
            with self.subTest(state=state):
                self.fx.git("reset", "-q", "--hard", "HEAD")
                self.fx.write(RIG, "default: staged\n")
                self.fx.git("add", "--", RIG)
                if state == "MM":
                    self.fx.write(RIG, "default: staged and edited\n")
                model = FakeModel(model_reply("commit"))
                _, items = self.fx.resolve(omp_call=model, jev_client=FakeJev(0.999))
                record = items["config-doc-drift-finding-1"]
                self.assertEqual(record["status"], "held")
                self.assertIn(repr(state), record["reason"])
                self.assertEqual(model.prompts, [])
        self.fx.git("reset", "-q", "--hard", "HEAD")
        _, items = self.fx.resolve(omp_call=FakeModel(), jev_client=FakeJev())
        self.assertEqual(items["config-doc-drift-finding-1"]["status"], "resolved")

    def test_privileged_system_config_paths_are_approval_only(self) -> None:
        for rel, action in (("system-config/ufw-rebuild.sh", "revert"),
                            ("system-config/docker-user-rules.sh", "commit"),
                            ("system-config/gamingrig-linux/.zshrc", "commit")):
            with self.subTest(path=rel):
                self.fx.write(rel, "original\n")
                self.fx.git("add", "--", rel)
                self.fx.git("commit", "-q", "-m", f"add {rel}")
                (self.fx.run_dir / resolver.ACTIONS_JOURNAL).unlink(missing_ok=True)
                self.fx.write(rel, "edited\n")
                base = self.fx.head()
                model = FakeModel(model_reply(action))
                _, items = self.fx.resolve(
                    omp_call=model, jev_client=FakeJev(0.999),
                    rig_sha256=lambda _dest: sha("edited\n"),  # identical deployed copy
                )
                (record,) = [r for r in items.values() if r["paths"] == [rel]]
                self.assertEqual(record["status"], "recommended")
                self.assertIn("approval only", record["reason"])
                self.assertEqual(len(model.prompts), 1, "no deterministic shortcut outside config/**")
                self.assertEqual(self.fx.head(), base)
                self.assertEqual((self.fx.home / rel).read_text(), "edited\n")
                self.fx.git("checkout", "--", rel)

    def test_revert_uses_literal_pathspecs(self) -> None:
        glob_path = "system-config/gamingrig-linux/config/[ab].conf"
        plain = "system-config/gamingrig-linux/config/a.conf"
        for rel in (glob_path, plain):
            self.fx.write(rel, "committed\n")
        self.fx.git("add", "-A")
        self.fx.git("commit", "-q", "-m", "glob files")
        for rel in (glob_path, plain):
            self.fx.write(rel, "edited\n")
        _, items = self.fx.resolve(
            omp_call=FakeModel(model_reply("revert"), model_reply("hold")), jev_client=FakeJev(0.999))
        statuses = sorted(r["status"] for r in items.values())
        self.assertEqual(statuses, ["done", "held"])
        self.assertEqual((self.fx.home / glob_path).read_text(), "committed\n")
        self.assertEqual((self.fx.home / plain).read_text(), "edited\n")

    def test_partial_action_is_failed_with_commit_and_undo_in_needs_you(self) -> None:
        self.fx.write(RIG, "default: model-b\n")
        result, items = self.fx.resolve(push=True, rig_sha256=lambda _dest: sha("default: model-b\n"))
        record = items[RIG_ID]
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["commit"], self.fx.head())
        self.assertIn("not pushed", record["reason"])
        self.assertEqual(result["phase_status"], "degraded")
        fixes = report._load_fixes_with_resolutions(self.fx.run_dir)
        page = report._html_actions({"sections": []}, fixes, {"steps": []})
        self.assertIn("Needs You", page)
        self.assertIn(record["commit"][:12], page)
        self.assertIn(f"undo: {record['undo']}", report.html.unescape(page))

    def test_executed_actions_survive_a_crash_before_the_artifact(self) -> None:
        self.fx.write(RIG, "default: model-b\n")
        self.fx.write(RIG2, "set nonumber\n")
        with mock.patch.object(resolver, "atomic_write_json", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.fx.resolve(max_actions=1, omp_call=FakeModel(model_reply("commit"), model_reply("commit")),
                                jev_client=FakeJev(0.999))
        self.assertFalse((self.fx.run_dir / resolver.ARTIFACT).exists())
        head = self.fx.head()
        _, items = self.fx.resolve(max_actions=1, omp_call=FakeModel(model_reply("commit")),
                                   jev_client=FakeJev(0.999))
        done = [r for r in items.values() if r["status"] == "done"]
        self.assertEqual(len(done), 1)
        self.assertIn("revert --no-edit", done[0]["undo"])
        self.assertEqual(sorted(r["status"] for r in items.values()), ["done", "recommended"])
        self.assertEqual(self.fx.head(), head, "the cap still holds after the crash")

    def _route(self, section: str, claim: str, paths: list[str], **finding) -> None:
        (self.fx.run_dir / "07b-fixes.json").write_text(json.dumps({"routes": [{
            "section": section, "finding_id": "finding-1", "status": "needs_carter", "claim": claim}]}),
            encoding="utf-8")
        (self.fx.run_dir / "07-audit.json").write_text(json.dumps({"sections": [{
            "name": section, "verdict": "DRIFT", "judge_confirmed": [{
                "id": "finding-1", "claim": claim, "action": "needs_carter",
                "target": {"paths": paths}, **finding}]}]}), encoding="utf-8")

    def test_untracked_and_ignored_entries_are_never_reported_clean(self) -> None:
        predict = ".omp/agent/predict"
        self.fx.write(".gitignore", "*.log\n")
        self.fx.git("add", ".gitignore")
        self.fx.git("commit", "-q", "-m", "ignore logs")
        self.fx.write(f"{predict}/ngram/cursor.json", "{}\n")
        self.fx.write(f"{predict}/ngram/debug.log", "noise\n")
        self._route("config-doc-drift", "OMP predict files are untracked", [predict])
        # The audit collector saw the path dirty; untracked files must not make it "resolved".
        (self.fx.run_dir / "07-audit-5-config.json.evidence.json").write_text(
            json.dumps({"dotfiles_status": f"?? {predict}/ngram/cursor.json"}), encoding="utf-8")
        patch = {"path": "~/.gitignore", "old_text": "*.log\n", "new_text": "*.log\n/.omp/agent/predict/\n"}
        model = FakeModel(model_reply("patch", patch=patch))
        _, items = self.fx.resolve(omp_call=model, jev_client=FakeJev(0.999))
        record = items["config-doc-drift-finding-1"]
        self.assertEqual((record["class"], record["status"], record["action"]), ("drift", "recommended", "patch"))
        prompt = model.prompts[0]
        self.assertIn(f"untracked: {predict}/ngram/cursor.json", prompt)
        self.assertIn(f"ignored: {predict}/ngram/debug.log", prompt)
        self.assertNotIn('"clean', prompt.split("Path status now:")[1].splitlines()[0])
        self.assertNotIn(predict, (self.fx.home / ".gitignore").read_text())

    def test_target_and_named_files_are_sent_as_numbered_slices(self) -> None:
        small = "scripts/tool.conf"
        big = "scripts/big.py"
        body = [f"value_{n} = {n}" for n in range(1, 2001)]
        body[1499] = "LISTING_LIMIT = 10  # the line the finding cites"
        self.fx.write(big, "\n".join(body) + "\n")
        self._route("digest-quality", "limits are too low", [small],
                    fix=f"raise LISTING_LIMIT in ~/{big}:1500 and the limit in {small}")
        model = FakeModel(model_reply("hold"))
        self.fx.resolve(omp_call=model, jev_client=FakeJev())
        prompt = model.prompts[0]
        self.assertIn(f"current ~/{small} (line-numbered)", prompt)
        self.assertIn("1: limit = 10", prompt)
        self.assertIn(f"current ~/{big} (line-numbered)", prompt)
        self.assertIn("1500: LISTING_LIMIT = 10", prompt)
        self.assertNotIn("value_1900 = 1900", prompt, "a large file is sliced, not sent whole")

    def test_file_slice_with_a_secret_is_dropped(self) -> None:
        self.fx.write("scripts/tool.conf", f"limit = 10\n{SECRET_SHAPES['bearer']}\n")
        self.fx.git("commit", "-q", "-am", "committed file carrying a token")  # clean, so the file is sliced
        self._route("digest-quality", "limit too low", ["scripts/tool.conf"])
        model = FakeModel(model_reply("hold"))
        _, items = self.fx.resolve(omp_call=model, jev_client=FakeJev())
        self.assertNotIn(SECRET_SHAPES["bearer"], model.prompts[0])
        self.assertIn("file", [d["kind"] for d in items["digest-quality-finding-1"]["dropped_excerpts"]])

    def _doc_fix_setup(self, *, evidence: str, doc: str) -> tuple[Path, Path]:
        notes = self.fx.home / "notes"
        (notes / "docs").mkdir(parents=True)
        origin = self.fx.root / "notes-origin.git"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True)
        for args in (("init", "-q", "-b", "main"), ("config", "user.name", "t"),
                     ("config", "user.email", "t@example.invalid")):
            subprocess.run(["git", "-C", str(notes), *args], check=True)
        (notes / "docs" / "blog.md").write_text(doc, encoding="utf-8")
        for args in (("add", "-A"), ("commit", "-q", "-m", "doc"), ("remote", "add", "origin", str(origin)),
                     ("push", "-q", "origin", "main")):
            subprocess.run(["git", "-C", str(notes), *args], check=True)
        (self.fx.run_dir / "07b-fixes.json").write_text(json.dumps({"routes": [{
            "section": "docs-accuracy", "finding_id": "finding-1", "status": "needs_carter",
            "claim": "blog.md pin is stale"}]}), encoding="utf-8")
        (self.fx.run_dir / "07-audit.json").write_text(json.dumps({"sections": [{
            "name": "docs-accuracy", "verdict": "DRIFT", "judge_confirmed": [{
                "id": "finding-1", "claim": "blog.md pin is stale", "evidence": evidence,
                "target": {"doc": "~/notes/docs/blog.md"}}]}]}), encoding="utf-8")
        return notes, origin

    def test_doc_fix_recheck_never_receives_unscanned_finding_or_doc_text(self) -> None:
        edit = {"doc": "~/notes/docs/blog.md", "old_text": "714c218", "new_text": "d254cfb"}
        recheck = ('```json\n{"verdict":"pass","supported_by_evidence":true,"changes_only_target":true,'
                   '"system_should_change":false,"reason":"ok"}\n```')
        cases = {
            "clean": ("production HEAD d254cfb", "Deployed commit: 714c218.\n", "done"),
            "secret in finding evidence": (f"HEAD d254cfb; {SECRET}", "Deployed commit: 714c218.\n", "held"),
            "secret in diff context": ("production HEAD d254cfb",
                                       f"{SECRET_SHAPES['bearer']}\nDeployed commit: 714c218.\n", "held"),
        }
        for name, (evidence, doc, expected) in cases.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                self.fx = Fixture(Path(tmp))
                notes, _ = self._doc_fix_setup(evidence=evidence, doc=doc)
                model = FakeModel(model_reply("doc_fix", doc_edit=edit), recheck)
                _, items = self.fx.resolve(omp_call=model, jev_client=FakeJev(0.999),
                                           doc_roots=(notes / "docs",))
                record = items["docs-accuracy-finding-1"]
                self.assertEqual(record["status"], expected, record["reason"])
                sent = "\n".join(model.prompts)
                self.assertNotIn(SECRET, sent)
                self.assertNotIn(SECRET_SHAPES["bearer"], sent)
                if expected == "held":
                    self.assertEqual(len(model.prompts), 1, "the re-check model is never called")
                    self.assertIn("re-check input failed the secret scan", record["reason"])
                    self.assertIn("714c218", (notes / "docs" / "blog.md").read_text())
                    self.assertNotIn("executed", record)
                else:
                    self.assertEqual(len(model.prompts), 2)

    def test_revert_failing_midway_is_partial_with_full_undo(self) -> None:
        (self.fx.run_dir / "07b-fixes.json").write_text(json.dumps({"routes": [{
            "section": "config-doc-drift", "finding_id": "finding-1", "status": "needs_carter",
            "claim": "rig experiments"}]}), encoding="utf-8")
        (self.fx.run_dir / "07-audit.json").write_text(json.dumps({"sections": [{
            "name": "config-doc-drift", "verdict": "DRIFT", "judge_confirmed": [{
                "id": "finding-1", "claim": "rig experiments", "action": "needs_carter",
                "target": {"paths": [RIG, RIG2]}}]}]}), encoding="utf-8")
        self.fx.write(RIG, "default: experiment\n")
        self.fx.write(RIG2, "set experiment\n")
        real_git = resolver.ResolveContext.git

        def flaky_git(ctx, *args, **kwargs):
            if args[:1] == ("checkout",) and RIG in args:
                return "", "fatal: simulated failure", 128
            return real_git(ctx, *args, **kwargs)

        with mock.patch.object(resolver.ResolveContext, "git", flaky_git):
            result, items = self.fx.resolve(omp_call=FakeModel(model_reply("revert")),
                                            jev_client=FakeJev(0.999))
        record = items["config-doc-drift-finding-1"]
        self.assertEqual(record["status"], "failed")
        self.assertIn("partly done", record["reason"])
        self.assertEqual(record["reverted_paths"], [RIG2])
        self.assertEqual(result["phase_status"], "degraded")
        self.assertEqual((self.fx.home / RIG2).read_text(), "set number\n")
        subprocess.run(record["undo"], shell=True, check=True)
        self.assertEqual((self.fx.home / RIG).read_text(), "default: experiment\n")
        self.assertEqual((self.fx.home / RIG2).read_text(), "set experiment\n")

    def test_journal_failure_keeps_the_executed_record_and_degrades(self) -> None:
        self.fx.write(RIG, "default: model-b\n")
        base = self.fx.head()
        with mock.patch.object(resolver, "_journal_write", side_effect=OSError("disk full")):
            result, items = self.fx.resolve(rig_sha256=lambda _dest: sha("default: model-b\n"))
        record = items[RIG_ID]
        self.assertEqual(record["status"], "done")
        self.assertNotEqual(self.fx.head(), base)
        self.assertIn("revert --no-edit", record["undo"])
        self.assertIn("disk full", record["journal_error"])
        self.assertEqual(result["phase_status"], "degraded")
        saved = json.loads((self.fx.run_dir / resolver.ARTIFACT).read_text())
        (kept,) = [r for r in saved["items"] if r["id"] == RIG_ID]
        self.assertEqual((kept["status"], kept["undo"]), ("done", record["undo"]))

    def test_steward_running_check_fails_closed(self) -> None:
        cases = (
            (("inactive\ninactive\n", "", 3), False),
            (("inactive\nfailed\n", "", 3), False),
            (("inactive\nactivating\n", "", 0), True),
            (("active\ninactive\n", "", 0), True),
            (("", "Failed to connect to bus", 1), True),
            (("inactive\n", "", 3), True),
        )
        for output, running in cases:
            with self.subTest(output=output):
                seen = []
                result = resolver._steward_running(lambda argv, **_k: seen.append(argv) or output)
                self.assertEqual(result, running)
                self.assertEqual(seen[0][-2:], ["homelab-steward.service", "homelab-steward-resume.service"])


class ReportResolutionTests(unittest.TestCase):
    ROUTE = {"section": "config-doc-drift", "finding_id": "finding-1", "claim": "rig edits uncommitted",
             "severity": "low", "action": "needs_carter", "status": "needs_carter", "decision": "commit or revert"}

    def render(self, resolution: dict, steward_code=None) -> str:
        fixes = report._apply_resolutions({"routes": [dict(self.ROUTE)]}, {"items": [resolution]})
        return report._html_actions({"sections": []}, fixes, {"steps": []}, steward_code)

    def test_needs_you_row_carries_recommendation_and_approve_command(self) -> None:
        page = self.render({"source": "route", "section": "config-doc-drift", "finding_id": "finding-1",
                            "status": "recommended", "action": "commit", "certainty": 0.7,
                            "approve_command": "steward-approve 2026-09-29 config-doc-drift-finding-1"})
        self.assertIn("Needs You", page)
        self.assertIn("resolver recommends commit (Jev certainty 0.70)", page)
        self.assertIn("approve with: steward-approve 2026-09-29 config-doc-drift-finding-1", page)

    def test_autonomous_action_moves_to_done_with_undo(self) -> None:
        page = self.render({"source": "route", "section": "config-doc-drift", "finding_id": "finding-1",
                            "status": "done", "action": "commit", "summary": "Committed the rig edits.",
                            "undo": "git revert abc"})
        self.assertNotIn("Needs You", page)
        self.assertIn("Committed the rig edits.", page)
        self.assertIn("Undo: git revert abc", page)

    def test_failed_live_tree_pickup_needs_carter(self) -> None:
        code = {"pickup": {"step": "dotfiles_pickup", "status": "failed", "reason": "verify failed",
                           "manual_recovery": "git reset --hard OLD"}}
        page = report._html_actions({"sections": []}, {"routes": []}, {"steps": []}, code)
        self.assertIn("live tree pickup FAILED: verify failed — git reset --hard OLD", page)
        facts = report._build_tldr_facts({"steps": []}, {"sections": []}, {}, {"routes": []}, {},
                                         steward_code=code)
        self.assertTrue(any("live tree pickup FAILED" in item for item in facts["carter_items"]))

    def test_degraded_resolver_is_reported(self) -> None:
        fixes = report._apply_resolutions({"routes": [dict(self.ROUTE)]},
                                          {"phase_status": "degraded", "reason": "P7c failed: boom", "items": []})
        page = report._html_actions({"sections": []}, fixes, {"steps": []})
        self.assertIn("The Needs You resolver (P7c) did not finish: P7c failed: boom", page)


if __name__ == "__main__":
    unittest.main()
