import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from security_watch import assessments, config, report  # noqa: E402
from security_watch.assessments import Check, NotAffected, Verdict  # noqa: E402
from security_watch.store import Store  # noqa: E402

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)

VALID = """
[[not_affected]]
id = "sshole"
component = "host"
cves = ["CVE-2026-123158"]
reason = "glibc and no password auth"
verified = "2026-11-09"

[[not_affected.checks]]
argv = ["ldd", "/usr/sbin/sshd"]
expect = 'libc\\.so\\.6'

[[not_affected.checks]]
argv = ["sshd", "-T"]
expect = '(?m)^passwordauthentication no$'
container = "box"
"""


class FakeRun:
    """Replies by argv tuple; records calls."""

    def __init__(self, replies):
        self.replies = replies
        self.calls = []

    def __call__(self, argv, *, timeout, env=None, cwd=None):
        self.calls.append((list(argv), timeout, env))
        rc, out, err = self.replies[tuple(argv)]
        return subprocess.CompletedProcess(list(argv), rc, out, err)


def entry(*checks, entry_id="sshole"):
    return NotAffected(id=entry_id, component="host", cves=("CVE-2026-123158",), reason="r",
                       verified="2026-11-09", checks=tuple(checks))


class LoadTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "assessments.toml"

    def load(self, text):
        self.path.write_text(text)
        return assessments.load(self.path)

    def test_missing_file_is_empty(self):
        self.assertEqual(assessments.load(self.path), [])

    def test_valid_file(self):
        (e,) = self.load(VALID)
        self.assertEqual((e.id, e.component, e.cves, e.verified), ("sshole", "host", ("CVE-2026-123158",),
                                                                   "2026-11-09"))
        self.assertEqual(e.checks, (Check(argv=("ldd", "/usr/sbin/sshd"), expect=r"libc\.so\.6"),
                                    Check(argv=("sshd", "-T"), expect="(?m)^passwordauthentication no$",
                                          container="box")))

    def test_bad_cve_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid CVE id 'CVE-26-1'"):
            self.load(VALID.replace("CVE-2026-123158", "CVE-26-1"))

    def test_duplicate_id_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate not_affected id 'sshole'"):
            self.load(VALID + VALID)

    def test_missing_checks_is_rejected(self):
        text = VALID.split("[[not_affected.checks]]")[0]
        with self.assertRaisesRegex(ValueError, "'checks' must be a non-empty list"):
            self.load(text)

    def test_empty_fields_are_rejected(self):
        for old, new, msg in (('reason = "glibc and no password auth"', 'reason = ""', "'reason'"),
                              ('verified = "2026-11-09"', 'verified = ""', "'verified'"),
                              ('component = "host"', 'component = " "', "'component'"),
                              ('cves = ["CVE-2026-123158"]', "cves = []", "'cves'"),
                              ('argv = ["ldd", "/usr/sbin/sshd"]', "argv = []", "'argv'"),
                              ("expect = 'libc\\.so\\.6'", "expect = '('", "not a valid regex")):
            with self.subTest(msg=msg), self.assertRaisesRegex(ValueError, msg):
                self.load(VALID.replace(old, new))

    def test_invalid_toml_is_value_error(self):
        with self.assertRaisesRegex(ValueError, "invalid TOML"):
            self.load("[[not_affected]\n")

    def test_shipped_ledger_is_valid(self):
        entries = assessments.load()
        self.assertIn("CVE-2026-123158", [cve for e in entries for cve in e.cves])
        self.assertEqual(assessments.ASSESSMENTS_PATH, config.PACKAGE_DIR / "assessments.toml")


class VerifyTests(unittest.TestCase):
    LDD = Check(argv=("ldd", "/usr/sbin/sshd"), expect=r"libc\.so\.6")
    SSHD = Check(argv=("sshd", "-T"), expect="(?m)^passwordauthentication no$")

    def test_all_checks_pass(self):
        run = FakeRun({("ldd", "/usr/sbin/sshd"): (0, "libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6\n", ""),
                       ("sshd", "-T"): (0, "port 22\npasswordauthentication no\n", "")})
        verdicts = assessments.verify([entry(self.LDD, self.SSHD)], run=run)
        self.assertEqual(verdicts, {"sshole": Verdict(id="sshole", ok=True, detail="")})
        self.assertEqual([c[1] for c in run.calls], [30, 30])
        self.assertTrue(all(c[2] is None for c in run.calls))

    def test_nonzero_exit_fails(self):
        run = FakeRun({("ldd", "/usr/sbin/sshd"): (1, "", "not a dynamic executable")})
        v = assessments.verify([entry(self.LDD, self.SSHD)], run=run)["sshole"]
        self.assertFalse(v.ok)
        self.assertEqual(v.detail, "check 1: ldd /usr/sbin/sshd: rc 1: not a dynamic executable")
        self.assertEqual(len(run.calls), 1)

    def test_regex_miss_fails_and_clips_stdout(self):
        out = "passwordauthentication yes\n" + "x" * 500
        run = FakeRun({("ldd", "/usr/sbin/sshd"): (0, "libc.so.6\n", ""), ("sshd", "-T"): (0, out, "")})
        v = assessments.verify([entry(self.LDD, self.SSHD)], run=run)["sshole"]
        self.assertFalse(v.ok)
        self.assertTrue(v.detail.startswith("check 2: sshd -T: expected /(?m)^passwordauthentication no$/ "
                                            "not found in stdout: 'passwordauthentication yes xxx"), v.detail)
        self.assertNotIn("x" * 201, v.detail)

    def test_timeout_fails(self):
        run = FakeRun({("ldd", "/usr/sbin/sshd"): (124, "", "timeout after 30s")})
        v = assessments.verify([entry(self.LDD)], run=run)["sshole"]
        self.assertEqual((v.ok, v.detail), (False, "check 1: ldd /usr/sbin/sshd: timeout after 30s"))

    def test_container_check_is_prefixed_with_docker_exec(self):
        check = Check(argv=("sshd", "-T"), expect="passwordauthentication no", container="box")
        run = FakeRun({("docker", "exec", "box", "sshd", "-T"): (0, "passwordauthentication no\n", "")})
        v = assessments.verify([entry(check)], run=run)["sshole"]
        self.assertTrue(v.ok, v.detail)
        self.assertEqual(run.calls[0][0], ["docker", "exec", "box", "sshd", "-T"])

    def test_run_exception_fails_closed_and_other_entries_still_run(self):
        def run(argv, *, timeout, env=None, cwd=None):
            if argv[0] == "boom":
                raise OSError("no such file")
            return subprocess.CompletedProcess(argv, 0, "ok", "")
        verdicts = assessments.verify([entry(Check(argv=("boom",), expect="ok"), entry_id="a"),
                                       entry(Check(argv=("fine",), expect="ok"), entry_id="b")], run=run)
        self.assertFalse(verdicts["a"].ok)
        self.assertIn("OSError: no such file", verdicts["a"].detail)
        self.assertTrue(verdicts["b"].ok)


class ReportTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        env = mock.patch.dict(os.environ, {"SECURITY_WATCH_STATE_DIR": str(root / "state"),
                                           "DEPLOY_LOCK_DIR": str(root / "locks"),
                                           "HOME": str(root / "home")})
        env.start()
        self.addCleanup(env.stop)
        self.store = Store(root / "state" / "state.sqlite3")
        self.addCleanup(self.store.close)

    def build(self, **kw):
        tick = {"started": NOW, "finished": NOW, "outcome": "ok"}
        return report.build_report(self.store, config.load_policy(), {}, None, None, tick, NOW,
                                   stopgaps=[], **kw)

    def test_report_lists_assessments_with_verdicts(self):
        ok = entry(Check(argv=("true",), expect=""))
        bad = NotAffected(id="other", component="news", cves=("CVE-2026-1111",), reason="x",
                          verified="2026-11-01", checks=ok.checks)
        data = self.build(not_affected=[(ok, Verdict("sshole", True, "")),
                                        (bad, Verdict("other", False, "check 1: true: rc 1"))])
        self.assertEqual(data["schema"], 1)
        self.assertEqual(data["not_affected"], [
            {"id": "sshole", "component": "host", "cves": ["CVE-2026-123158"], "reason": "r",
             "verified": "2026-11-09", "ok": True, "detail": ""},
            {"id": "other", "component": "news", "cves": ["CVE-2026-1111"], "reason": "x",
             "verified": "2026-11-01", "ok": False, "detail": "check 1: true: rc 1"}])

    def test_report_without_assessments_has_empty_list(self):
        self.assertEqual(self.build()["not_affected"], [])


if __name__ == "__main__":
    unittest.main()
