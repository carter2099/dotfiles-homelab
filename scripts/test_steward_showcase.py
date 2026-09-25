#!/usr/bin/env python3
"""P9c public showcase: leaks never publish, rules beat Jev, Jev failures hold."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import jev
from steward import showcase

# Synthetic leak fixtures, assembled at runtime so this file itself stays clean.
FAKE = "Q7vX2mK9pL4s" + "T8wZ1nB5cR3dF6gH0jY"
LEAKS = {
    "github token": "token = '" + "gh" + "p_" + FAKE + "abcde'\n",
    "fine-grained token": "t = " + "github" + "_pat_" + FAKE + "\n",
    "sk key": "client(key='" + "s" + "k-" + FAKE + "')\n",
    "aws key": "AWS = '" + "AK" + "IA" + "ABCDEFGHIJKLMNOP'\n",
    "private key": "-----BEGIN " + "OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n",
    "mac": "WAKE = '00:" + "1a:2b:3c:4d:5e'\n",
    "pw assignment": "db_pass" + "word = 'hunter2hunter2'\n",
}
POLICY = """
private = [".ssh/**", "k3s/**", "**/env", "**/*token*", "**/*secret*", "**/*api_key*",
           "**/*.kdbx", ".local/bin/rigwake"]
public = ["scripts/**", "AGENTS.md", ".local/bin/**"]
entropy_exempt = ["benchmarks/**"]
"""


class FakeJev:
    def __init__(self, answers=None, error=None):
        self.answers = answers or {}
        self.error = error
        self.calls = []

    def ask(self, purpose, state, questions):
        self.calls.append((purpose, state))
        if self.error:
            raise self.error
        return {q: {"type": "noul", "noul": self.answers.get(q, 0.0)} for q in questions}


SAFE_SCOPE = {"credential": 0.01, "personal": 0.02, "homelab": 0.97}


class ShowcaseTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.src = self.root / "src"
        self.src.mkdir()
        self.remote = self.root / "public.git"
        self.git("init", "--quiet", "--initial-branch=main", str(self.src), cwd=self.root)
        self.git("init", "--quiet", "--bare", "--initial-branch=main", str(self.remote), cwd=self.root)
        env = {
            "GIT_AUTHOR_NAME": "Showcase test", "GIT_AUTHOR_EMAIL": "t@example.invalid",
            "GIT_COMMITTER_NAME": "Showcase test", "GIT_COMMITTER_EMAIL": "t@example.invalid",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        }
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.policy_path = self.root / "policy.toml"
        self.policy_path.write_text(POLICY)
        self.decisions_path = self.root / "decisions.json"
        self.state_dir = self.root / "state"
        self.policy = showcase.load_policy(self.policy_path)

    def git(self, *args, cwd=None):
        return subprocess.run(["git", *args], cwd=cwd or self.src, check=True,
                              capture_output=True, text=True, timeout=30).stdout

    def commit(self, files, message="change"):
        for rel, text in files.items():
            path = self.src / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        self.git("add", "--all")
        self.git("commit", "--quiet", "-m", message)

    def publish(self, client, remote_url_override=None, **kw):
        return showcase.publish(
            client=client, git_dir=self.src / ".git", policy_path=self.policy_path,
            decisions_path=self.decisions_path, state_dir=self.state_dir,
            remote_url=remote_url_override or str(self.remote), today="2026-09-25", **kw,
        )

    def public_files(self):
        return set(self.git("ls-tree", "-r", "--name-only", "main", cwd=self.remote).split())

    def test_leaks_in_public_paths_are_held_and_never_sent_to_jev(self):
        jev_client = FakeJev(SAFE_SCOPE)
        for rule, text in LEAKS.items():
            for path in ("scripts/leak.py", "notes/leak.txt"):
                d = showcase.decide(path, ("ok = 1\n" + text).encode(), policy=self.policy,
                                    decisions={path: {"scope": "public", "by": "carter"}},
                                    client=jev_client)
                self.assertEqual((d.scope, d.by), ("held", "scan"), (rule, path, d))
        self.assertEqual(jev_client.calls, [])

    def test_publish_excludes_leaks_private_paths_and_private_history(self):
        files = {f"scripts/leak_{i}.py": "x = 1\n" + text for i, text in enumerate(LEAKS.values())}
        files.update({
            "scripts/good.py": "print('hello homelab')\n",
            "AGENTS.md": "# Agents\nThinkPad 192.168.4.20 runs the steward.\n",
            ".ssh/config": "Host rig\n  HostName 192.168.4.103\n",
            "k3s/freshrss.yaml": "kind: Deployment\n",
            ".config/app/env": "HOME_URL=https://example.invalid\n",
            ".local/bin/rigwake": "echo wake\n",
        })
        self.commit(files, "private history message")
        result = self.publish(FakeJev(SAFE_SCOPE))
        self.assertEqual(result["status"], "published", result)
        self.assertEqual(self.public_files(), {"AGENTS.md", "scripts/good.py"})
        log = self.git("log", "--format=%P %s", "main", cwd=self.remote).splitlines()
        self.assertEqual(log, [" Publish homelab snapshot 2026-09-25"])
        self.assertEqual(
            {h["path"] for h in result["held"]}, {f"scripts/leak_{i}.py" for i in range(len(LEAKS))}
        )
        self.assertEqual(self.publish(FakeJev(SAFE_SCOPE))["status"], "unchanged")

    def test_private_rule_beats_recorded_decision_and_jev(self):
        jev_client = FakeJev(SAFE_SCOPE)
        d = showcase.decide(".ssh/config", b"Host rig\n", policy=self.policy,
                            decisions={".ssh/config": {"scope": "public", "by": "jev"}},
                            client=jev_client)
        self.assertEqual((d.scope, d.by), ("private", "rule"))
        self.assertEqual(jev_client.calls, [])

    def test_ambiguous_confident_jev_publishes_and_records(self):
        self.commit({"news/nginx.conf": "server { listen 8080; }\n"})
        jev_client = FakeJev(SAFE_SCOPE)
        result = self.publish(jev_client)
        self.assertIn("news/nginx.conf", self.public_files())
        recorded = json.loads(self.decisions_path.read_text())["news/nginx.conf"]
        self.assertEqual((recorded["scope"], recorded["by"]), ("public", "jev"))
        self.assertEqual(result["decisions_recorded"], ["news/nginx.conf"])
        # A recorded decision is reused without asking again.
        self.commit({"news/nginx.conf": "server { listen 8081; }\n"})
        showcase.decide("news/nginx.conf", b"x\n", policy=self.policy,
                        decisions=showcase.load_decisions(self.decisions_path),
                        client=(later := FakeJev(error=AssertionError("asked"))))
        self.assertEqual(later.calls, [])

    def test_unconfident_or_unavailable_jev_holds_without_recording(self):
        self.commit({"news/a.conf": "a = 1\n", "news/b.conf": "b = 2\n"})
        for client in (FakeJev(error=jev.JevUnavailable("server", "HTTP 503")),
                       FakeJev({"credential": 0.01, "personal": 0.3, "homelab": 0.9}),
                       None):
            result = self.publish(client, dry_run=True)
            self.assertEqual({h["path"] for h in result["held"]}, {"news/a.conf", "news/b.conf"})
            self.assertEqual(result["decisions_recorded"], [])
        self.assertFalse(self.decisions_path.exists())

    def test_changed_public_file_needs_jev_veto_else_previous_version_stays(self):
        self.commit({"scripts/tool.py": "v = 1\n"})
        self.assertEqual(self.publish(FakeJev())["status"], "published")
        self.commit({"scripts/tool.py": "v = 2\nowner_phone = '555 0100'\n"})
        blocked = self.publish(FakeJev({"personal": 0.8}))
        self.assertEqual([b["path"] for b in blocked["blocked"]], ["scripts/tool.py"])
        held = self.publish(FakeJev(error=jev.JevUnavailable("deadline")))
        self.assertEqual([h["path"] for h in held["held"]], ["scripts/tool.py"])
        self.assertEqual(self.git("show", "main:scripts/tool.py", cwd=self.remote), "v = 1\n")
        ok = self.publish(FakeJev({"credential": 0.01, "personal": 0.05}))
        self.assertEqual([u["path"] for u in ok["updated"]], ["scripts/tool.py"])
        self.assertIn("v = 2", self.git("show", "main:scripts/tool.py", cwd=self.remote))

    def test_private_rules_are_case_insensitive_and_cover_directories(self):
        for path in ("scripts/API_KEY.txt", "scripts/Secret.txt", "scripts/vault.KDBX",
                     "scripts/secrets/cf", "K3S/x.yaml", ".ssh/keys/deploy"):
            self.assertTrue(self.policy.is_private(path), path)
        self.assertFalse(self.policy.is_private("scripts/good.py"))

    def test_failed_push_never_becomes_public_history(self):
        self.commit({"scripts/a.py": "a = 1\n", "scripts/notes.py": "n = 1\n"})
        missing = self.root / "missing.git"
        first = self.publish(FakeJev(), remote_url_override=str(missing))
        self.assertEqual(first["status"], "push_failed")
        self.policy_path.write_text(POLICY.replace('"k3s/**"', '"k3s/**", "scripts/notes.py"'))
        self.assertEqual(self.publish(FakeJev())["status"], "published")
        history = self.git("log", "--format=", "--name-only", "--all", cwd=self.remote)
        self.assertNotIn("scripts/notes.py", history)
        self.assertEqual(self.public_files(), {"scripts/a.py"})

    def test_file_that_becomes_private_is_removed(self):
        self.commit({"scripts/a.py": "a = 1\n", "scripts/b.py": "b = 1\n"})
        self.publish(FakeJev())
        self.policy_path.write_text(POLICY.replace('"k3s/**"', '"k3s/**", "scripts/b.py"'))
        result = self.publish(FakeJev())
        self.assertEqual([r["path"] for r in result["removed"]], ["scripts/b.py"])
        self.assertEqual(self.public_files(), {"scripts/a.py"})


if __name__ == "__main__":
    unittest.main()
