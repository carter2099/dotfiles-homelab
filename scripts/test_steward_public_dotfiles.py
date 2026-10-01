#!/usr/bin/env python3
"""P9c public dotfiles: leaks never publish, rules beat Jev, Jev failures hold."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import jev
from steward import public_dotfiles

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
           "**/*.kdbx", ".local/bin/rigwake", "system-config/**"]
public = ["scripts/**", "AGENTS.md", ".local/bin/**"]
entropy_exempt = ["benchmarks/**"]
"""


class FakeJev:
    """``answers`` for every ask, or ``sequence[i]`` for the i-th ask; ``budget`` asks
    succeed before the shared deadline runs out (JevUnavailable('deadline'))."""

    def __init__(self, answers=None, error=None, sequence=None, budget=None):
        self.answers = answers or {}
        self.error = error
        self.sequence = sequence
        self.budget = budget
        self.calls = []

    def ask(self, purpose, state, questions):
        self.calls.append((purpose, state))
        if self.error:
            raise self.error
        if self.budget is not None and len(self.calls) > self.budget:
            raise jev.JevUnavailable("deadline", "Jev deadline reached")
        answers = self.sequence[len(self.calls) - 1] if self.sequence else self.answers
        return {q: {"type": "noul", "noul": answers.get(q, 0.0)} for q in questions}


def numbered(count, tag="line"):
    return "".join(f"{tag}_{i} = 'homelab setting number {i}'\n" for i in range(count))


SAFE_SCOPE = {"credential": 0.01, "personal": 0.02, "homelab": 0.97}


class PublicDotfilesTests(unittest.TestCase):
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
            "GIT_AUTHOR_NAME": "Public dotfiles test", "GIT_AUTHOR_EMAIL": "t@example.invalid",
            "GIT_COMMITTER_NAME": "Public dotfiles test", "GIT_COMMITTER_EMAIL": "t@example.invalid",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        }
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.policy_path = self.src / public_dotfiles.POLICY_REL
        self.policy_path.parent.mkdir(parents=True)
        self.policy_path.write_text(POLICY)
        self.decisions_path = self.root / "decisions.json"
        self.state_dir = self.root / "state"
        self.policy = public_dotfiles.load_policy(self.policy_path)

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
        return public_dotfiles.publish(
            client=client, git_dir=self.src / ".git",
            decisions_path=self.decisions_path, state_dir=self.state_dir,
            remote_url=remote_url_override or str(self.remote), today="2026-09-25", **kw,
        )

    def public_files(self):
        return set(self.git("ls-tree", "-r", "--name-only", "main", cwd=self.remote).split())

    def test_leaks_in_public_paths_are_held_and_never_sent_to_jev(self):
        jev_client = FakeJev(SAFE_SCOPE)
        for rule, text in LEAKS.items():
            for path in ("scripts/leak.py", "notes/leak.txt"):
                d = public_dotfiles.decide(
                    path, ("ok = 1\n" + text).encode(), policy=self.policy,
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
        d = public_dotfiles.decide(".ssh/config", b"Host rig\n", policy=self.policy,
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
        public_dotfiles.decide("news/nginx.conf", b"x\n", policy=self.policy,
                               decisions=public_dotfiles.load_decisions(self.decisions_path),
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
        self.commit({public_dotfiles.POLICY_REL: POLICY.replace('"k3s/**"', '"k3s/**", "scripts/notes.py"')})
        self.assertEqual(self.publish(FakeJev())["status"], "published")
        history = self.git("log", "--format=", "--name-only", "--all", cwd=self.remote)
        self.assertNotIn("scripts/notes.py", history)
        self.assertEqual(self.public_files(), {"scripts/a.py"})

    def test_recorded_decisions_are_committed_alone(self):
        home = self.root / "home"
        home.mkdir()
        self.git("init", "--quiet", "--initial-branch=main", str(home), cwd=self.root)
        decisions = home / "system-config" / "dotfiles-publish-decisions.json"
        decisions.parent.mkdir()
        decisions.write_text("{}\n")
        (home / "other.conf").write_text("a\n")
        self.git("add", "--all", cwd=home)
        self.git("commit", "--quiet", "-m", "base", cwd=home)
        kw = dict(decisions_path=decisions, git_dir=home / ".git", home=home, push=False)
        self.assertEqual(public_dotfiles.commit_decisions(**kw)["status"], "unchanged")
        public_dotfiles.save_decisions(decisions, {"news/a.conf": {"scope": "public", "by": "jev"}})
        (home / "other.conf").write_text("carter's uncommitted edit\n")
        result = public_dotfiles.commit_decisions(**kw)
        self.assertEqual(result["status"], "committed", result)
        self.assertEqual(self.git("show", "--name-only", "--format=", "HEAD", cwd=home).split(),
                         ["system-config/dotfiles-publish-decisions.json"])
        self.assertEqual(self.git("status", "--porcelain", cwd=home).strip(), "M other.conf")

    def test_new_public_rule_path_needs_jev_clearance(self):
        self.commit({"scripts/new.py": "print('clean by regex')\n"})
        held = self.publish(FakeJev(error=jev.JevUnavailable("network")))
        self.assertEqual([h["path"] for h in held["held"]], ["scripts/new.py"])
        blocked = self.publish(FakeJev({"credential": 0.9}))
        self.assertEqual([b["path"] for b in blocked["blocked"]], ["scripts/new.py"])
        self.assertNotIn("scripts/new.py", self.public_files() if blocked["status"] == "published" else set())
        client = FakeJev()
        ok = self.publish(client)
        self.assertEqual([a["path"] for a in ok["added"]], ["scripts/new.py"])
        self.assertEqual(client.calls[0][0], "dotfiles-public-change-veto")
        self.assertIn("clean by regex", client.calls[0][1]["changes"])

    def test_carter_decision_replaces_the_veto_for_that_exact_content_only(self):
        fixture = "fixture = 1  # stands in for content Jev would veto\n"
        self.commit({"scripts/test_fixture.py": fixture})
        blob = self.git("rev-parse", "HEAD:scripts/test_fixture.py").strip()
        self.decisions_path.write_text(json.dumps({"scripts/test_fixture.py": {
            "scope": "public", "by": "carter", "blob": blob, "date": "2026-09-30"}}))
        # Jev would block it; Carter's exact-blob decision publishes without asking.
        vetoing = FakeJev({"credential": 0.9})
        first = self.publish(vetoing)
        self.assertEqual([a["path"] for a in first["added"]], ["scripts/test_fixture.py"], first)
        self.assertEqual(vetoing.calls, [])
        # Any later edit is new content: the normal veto on the diff applies again.
        self.commit({"scripts/test_fixture.py": fixture + "fixture = 2\n"})
        blocked = self.publish(FakeJev({"personal": 0.9}))
        self.assertEqual([b["path"] for b in blocked["blocked"]], ["scripts/test_fixture.py"])
        self.assertEqual(self.git("show", "main:scripts/test_fixture.py", cwd=self.remote), fixture)
        # The deterministic scan is never overruled by a decision.
        leak = next(iter(LEAKS.values()))
        d = public_dotfiles.decide("scripts/leak.py", leak.encode(), policy=self.policy, decisions={
            "scripts/leak.py": {"scope": "public", "by": "carter",
                                "blob": public_dotfiles.blob_oid(leak.encode())}}, client=FakeJev())
        self.assertEqual((d.scope, d.by), ("held", "scan"))

    def test_scanner_catches_bearer_jwt_webhooks_url_credentials_and_hex_keys(self):
        seg = "abcdefghij" + "KLMNOPQRST"
        hexkey = "0123456789" + "abcdef0123456789abcdef"
        fixtures = [
            "headers = {'Authorization': 'Bear" + "er " + seg + seg + "'}",
            "tok = '" + "ey" + "J" + seg + ".ey" + "J" + seg + "." + seg + "'",
            "url = 'https://hooks." + "slack.com/services/T000/B000/" + seg + "'",
            "url = 'https://discord" + ".com/api/webhooks/123456/" + seg + "'",
            "db = 'postgres://carter:" + seg + "@db.lan/app'",
            "u = 'https://api.example.com/v1?access_" + "token=" + seg + "'",
            "API = '" + hexkey + "'",
        ]
        for line in fixtures:
            self.assertIsNotNone(public_dotfiles.scan("scripts/x.py", (line + "\n").encode()), line)
        self.assertIsNone(public_dotfiles.scan(
            "scripts/x.py", b"url = 'https://github.com/carter2099/dotfiles-homelab/blob/main/README.md'\n"))

    def test_decisions_are_tied_to_blob_and_saved_only_after_push(self):
        self.commit({"news/a.conf": "a = 1\n"})
        failed = self.publish(FakeJev(SAFE_SCOPE), remote_url_override=str(self.root / "missing.git"))
        self.assertEqual(failed["status"], "push_failed")
        self.assertFalse(self.decisions_path.exists())
        self.assertEqual(self.publish(FakeJev(SAFE_SCOPE))["status"], "published")
        blob = self.git("rev-parse", "HEAD:news/a.conf").strip()
        self.assertEqual(public_dotfiles.load_decisions(self.decisions_path)["news/a.conf"]["blob"], blob)
        # A recorded public decision for different content is not trusted for a first publication.
        public_dotfiles.save_decisions(self.decisions_path, {
            "news/b.conf": {"scope": "public", "by": "jev", "blob": blob}})
        self.commit({"news/b.conf": "b = 2\n"})
        result = self.publish(FakeJev(error=jev.JevUnavailable("deadline")))
        self.assertEqual([h["path"] for h in result["held"]], ["news/b.conf"])
        self.assertNotIn("news/b.conf", self.public_files())

    def test_policy_is_read_from_the_source_commit(self):
        self.commit({"scripts/a.py": "a = 1\n"})
        self.policy_path.write_text(POLICY.replace('"k3s/**"', '"k3s/**", "scripts/**"'))
        self.publish(FakeJev())
        self.assertEqual(self.public_files(), {"scripts/a.py"})

    def test_file_that_becomes_private_is_removed(self):
        self.commit({"scripts/a.py": "a = 1\n", "scripts/b.py": "b = 1\n"})
        self.publish(FakeJev())
        self.commit({public_dotfiles.POLICY_REL: POLICY.replace('"k3s/**"', '"k3s/**", "scripts/b.py"')})
        result = self.publish(FakeJev())
        self.assertEqual([r["path"] for r in result["removed"]], ["scripts/b.py"])
        self.assertEqual(self.public_files(), {"scripts/a.py"})

    def test_veto_thresholds(self):
        for probs, verdict in (({"credential": 0.49, "personal": 0.49}, "publish"),
                               ({"credential": 0.01, "personal": 0.5}, "held"),
                               ({"credential": 0.79, "personal": 0.1}, "held"),
                               ({"credential": 0.8, "personal": 0.1}, "blocked")):
            got, why = public_dotfiles.veto("scripts/t.py", b"a = 1\n", b"a = 2\n", FakeJev(probs))
            self.assertEqual(got, verdict, (probs, why))

    def test_large_change_is_chunked_and_the_worst_chunk_decides(self):
        self.commit({"scripts/big.py": "v = 1\n"})
        self.publish(FakeJev())
        self.commit({"scripts/big.py": numbered(3000)})  # ~130k chars of diff
        low = {"credential": 0.02, "personal": 0.2}
        client = FakeJev(sequence=[low, {"credential": 0.02, "personal": 0.9}, low, low])
        result = self.publish(client)
        self.assertEqual([b["path"] for b in result["blocked"]], ["scripts/big.py"], result)
        self.assertEqual(self.git("show", "main:scripts/big.py", cwd=self.remote), "v = 1\n")
        sent = [state["changes"] for _, state in client.calls]
        self.assertGreaterEqual(len(sent), 2)
        self.assertTrue(all(len(c) <= public_dotfiles.MAX_JEV_CHARS for c in sent))
        client = FakeJev(low)
        result = self.publish(client)
        self.assertEqual([u["path"] for u in result["updated"]], ["scripts/big.py"], result)
        # Together the chunks cover every added line.
        sent = "".join(state["changes"] for _, state in client.calls)
        self.assertTrue(all(f"+line_{i} =" in sent for i in (0, 1500, 2999)))
        self.assertIn("personal=0.20", result["updated"][0]["reason"])

    def test_change_beyond_the_chunk_cap_is_held(self):
        self.commit({"scripts/big.py": "v = 1\n"})
        self.publish(FakeJev())
        self.commit({"scripts/big.py": numbered(400)})
        client = FakeJev()
        with mock.patch.object(public_dotfiles, "MAX_JEV_CHARS", 2000):
            result = self.publish(client)
        self.assertEqual([h["path"] for h in result["held"]], ["scripts/big.py"])
        self.assertIn("too large", result["held"][0]["reason"])
        self.assertEqual(client.calls, [])

    def test_renamed_file_is_vetoed_on_its_rename_diff(self):
        body = numbered(200)
        self.commit({"scripts/old_name.py": body})
        self.publish(FakeJev())
        self.git("mv", "scripts/old_name.py", "scripts/new_name.py")
        self.commit({"scripts/new_name.py": body.replace("line_100 =", "line_100b ="),
                     "scripts/fresh.py": "print('brand new')\n"})
        client = FakeJev({"credential": 0.38, "personal": 0.1})
        result = self.publish(client)
        self.assertEqual(self.public_files(), {"scripts/new_name.py", "scripts/fresh.py"})
        added = {a["path"]: a["reason"] for a in result["added"]}
        self.assertIn("renamed from scripts/old_name.py", added["scripts/new_name.py"])
        self.assertNotIn("renamed", added["scripts/fresh.py"])
        sent = {state["path"]: state["changes"] for _, state in client.calls}
        rename_diff = sent["scripts/new_name.py"]
        self.assertIn("--- a/scripts/old_name.py", rename_diff)
        self.assertIn("+line_100b =", rename_diff)
        self.assertNotIn("line_10 =", rename_diff)  # outside the hunk: not the whole content
        # A genuinely new file is still judged on its whole content.
        self.assertIn("+print('brand new')", sent["scripts/fresh.py"])
        self.assertEqual([r["path"] for r in result["removed"]], ["scripts/old_name.py"])

    def test_exhausted_jev_budget_holds_the_remaining_paths(self):
        self.commit({"scripts/a.py": "a = 1\n", "scripts/big.py": "v = 1\n", "scripts/c.py": "c = 1\n"})
        self.publish(FakeJev())
        self.commit({"scripts/a.py": "a = 2\n", "scripts/big.py": numbered(3000),
                     "scripts/c.py": "c = 2\n"})
        result = self.publish(FakeJev(budget=2))  # a.py, then big.py's first chunk
        self.assertEqual([u["path"] for u in result["updated"]], ["scripts/a.py"])
        held = {h["path"]: h["reason"] for h in result["held"]}
        self.assertEqual(set(held), {"scripts/big.py", "scripts/c.py"})
        self.assertIn("deadline", held["scripts/big.py"])
        self.assertIn("chunk 2/", held["scripts/big.py"])
        self.assertEqual(self.git("show", "main:scripts/c.py", cwd=self.remote), "c = 1\n")


class DotfilesCommitPathspecTests(unittest.TestCase):
    def test_glob_characters_in_paths_are_literal(self):
        import dotfiles_commit as dc

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            git_dir = home / ".dotfiles-homelab"
            env = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_AUTHOR_NAME": "t",
                   "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t",
                   "GIT_COMMITTER_EMAIL": "t@example.invalid"}
            subprocess.run(["git", "init", "--quiet", "--bare", str(git_dir)], check=True)
            (home / "s*").write_text("star\n")
            (home / "sa").write_text("other\n")
            (home / "policy.toml").write_text('private = []\npublic = ["**"]\n')
            with mock.patch.dict(os.environ, env), \
                    mock.patch.object(dc, "HOME", home), mock.patch.object(dc, "GIT_DIR", git_dir), \
                    mock.patch.object(dc.public_dotfiles, "POLICY_PATH", home / "policy.toml"), \
                    mock.patch.object(dc.public_dotfiles, "DECISIONS_PATH", home / "decisions.json"):
                self.assertEqual(dc.main(["-m", "star", "--no-push", str(home / "s*")]), 0)
            files = subprocess.run(["git", f"--git-dir={git_dir}", "ls-tree", "-r", "--name-only", "HEAD"],
                                   capture_output=True, text=True, check=True).stdout.split("\n")
            self.assertEqual([f for f in files if f], ["s*"])


if __name__ == "__main__":
    unittest.main()
