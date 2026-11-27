import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import subprocess  # noqa: E402
import unittest  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402

from security_watch import config, inventory, model, selfcheck  # noqa: E402
from security_watch.model import Inventory  # noqa: E402

NOW = datetime(2026, 11, 26, 18, 0, tzinfo=timezone.utc)
SPECS = {spec.id: spec for spec in config.load_components()}


class FakeStore:
    def __init__(self, actions=(), inventories=()):
        self.kv = {}
        self._actions = list(actions)
        self._inventories = list(inventories)

    def get_kv(self, key, default=None):
        return self.kv.get(key, default)

    def set_kv(self, key, value):
        self.kv[key] = value

    def actions_since(self, since):
        return list(self._actions)

    def inventories(self):
        return list(self._inventories)


def completed(argv, rc=0, out="", err=""):
    return subprocess.CompletedProcess(argv, rc, out, err)


def inv(component, interpreters=None, error=""):
    meta = {"interpreters": interpreters or []} if not error else {"interpreters_error": error}
    return Inventory(component_id=component, collected_at=NOW, status="ok", fingerprint="fp", packages=[], meta=meta)


class HealthProbeTests(unittest.TestCase):
    def test_probes_use_the_components_health_host_and_budget(self):
        seen, clock = [], [0.0]

        def probe(url, host):
            seen.append((url, host))
            return 200 if host == "remote.carter2099.com" else 404

        def sleep(seconds):
            clock[0] += seconds
        rows = selfcheck.health_probes({"h": SPECS["herdr-web-client"], "b": SPECS["blog"]}, probe=probe,
                                       sleep=sleep, clock=lambda: clock[0], now=NOW)
        herdr = [r for r in rows if r["component"] == "herdr-web-client"]
        blog = [r for r in rows if r["component"] == "blog"]
        self.assertEqual([r["ok"] for r in herdr], [True])
        self.assertEqual(herdr[0]["host"], "remote.carter2099.com")
        self.assertFalse(blog[0]["ok"])
        self.assertEqual(blog[0]["detail"], "http://127.0.0.1:33099/up answered 404 within 6s")
        self.assertIn(("http://127.0.0.1:30145/", "remote.carter2099.com"), seen)


class UnexercisedTests(unittest.TestCase):
    def test_lists_fix_paths_without_a_successful_action(self):
        store = FakeStore(actions=[
            {"playbook": "release-rebuild", "component_id": "herdr-web-client", "status": "verified"},
            {"playbook": "repo-pr", "component_id": "herdr-web-client", "status": "failed"},
            {"playbook": "repo-pr", "component_id": "blog", "status": "verified"},
        ])
        specs = {k: SPECS[k] for k in ("herdr-web-client", "blog", "delta-neutral", "bun")}
        pairs = {(r["component"], r["playbook"]) for r in selfcheck.unexercised(store, specs)}
        # herdr's repo-pr path (taken over from release-rebuild for go-toolchain/go-module) only
        # ever failed: action #65 was its first run.  bun is alert-only: nothing to exercise.
        self.assertEqual(pairs, {("herdr-web-client", "repo-pr"), ("delta-neutral", "repo-pr")})


class CoverageGapTests(unittest.TestCase):
    def gaps(self, inventories, specs=None):
        return selfcheck.coverage_gaps(FakeStore(inventories=inventories), specs or SPECS)

    def test_source_built_interpreter_without_advisory_source_is_a_gap(self):
        python = {"name": "python3", "path": "/usr/local/bin/python3", "resolved": "/usr/local/bin/python3.12",
                  "owner": ""}
        [gap] = self.gaps([inv("open-webui", [python])])
        self.assertEqual((gap["component"], gap["runtime"], gap["path"]),
                         ("open-webui", "python", "/usr/local/bin/python3.12"))
        self.assertIn("runtime_waivers", gap["detail"])

    def test_os_packaged_covered_and_waived_interpreters_are_not_gaps(self):
        ruby = {"name": "ruby", "path": "/usr/local/bin/ruby", "resolved": "/usr/local/bin/ruby", "owner": ""}
        php = {"name": "php", "path": "/usr/bin/php", "resolved": "/usr/bin/php8.4", "owner": "php8.4-cli"}
        python = {"name": "python3", "path": "/usr/local/bin/python3", "resolved": "/usr/local/bin/python3", "owner": ""}
        waived = SPECS["open-webui"].__class__(**{**SPECS["open-webui"].__dict__, "extra": {
            **SPECS["open-webui"].extra, "runtime_waivers": {"python": "upstream image owns CPython"}}})
        specs = {**SPECS, "open-webui": waived}
        self.assertEqual(self.gaps([inv("blog", [ruby]), inv("freshrss", [php]), inv("open-webui", [python])], specs), [])

    def test_declared_runtime_without_feed_and_scan_errors_are_reported(self):
        no_feed = SPECS["blog"].__class__(**{**SPECS["blog"].__dict__, "extra": {
            k: v for k, v in SPECS["blog"].extra.items() if k != "advisory_repo"}})
        ruby = {"name": "ruby", "path": "/usr/local/bin/ruby", "resolved": "/usr/local/bin/ruby", "owner": ""}
        rows = self.gaps([inv("blog", [ruby]), inv("searxng", error="rc 1: boom")], {**SPECS, "blog": no_feed})
        self.assertEqual({r["component"] for r in rows}, {"blog", "searxng"})
        self.assertIn("no advisory source", next(r for r in rows if r["component"] == "blog")["detail"])

    def test_container_scan_parses_interpreter_rows(self):
        out = "ruby\t/usr/local/bin/ruby\t/usr/local/bin/ruby\t\nphp\t/usr/bin/php\t/usr/bin/php8.4\tphp8.4-cli\nx\ty\n"
        rows, err = inventory._container_interpreters("blog-web-1", lambda argv, **kw: completed(argv, 0, out))
        self.assertEqual(err, "")
        self.assertEqual([(r["name"], r["owner"]) for r in rows], [("ruby", ""), ("php", "php8.4-cli")])
        _, err = inventory._container_interpreters("x", lambda argv, **kw: completed(argv, 1, "", "no sh"))
        self.assertIn("interpreter scan failed", err)


class ToolingTests(unittest.TestCase):
    def run_with(self, bundle_out, rc=0):
        def run(argv, **kw):
            if argv[0] == "bundle-audit":
                return completed(argv, rc, bundle_out)
            return completed(argv, 0, "/nonexistent/modcache\n")
        return {t["tool"]: t for t in selfcheck.tooling(run)}

    def test_declared_bundle_audit_is_ok_and_drift_or_absence_is_not(self):
        self.assertTrue(self.run_with("bundler-audit 0.9.3\n")["bundle-audit"]["ok"])
        drift = self.run_with("bundler-audit 0.9.4\n")["bundle-audit"]
        self.assertFalse(drift["ok"])
        self.assertEqual(drift["have"], "0.9.4")
        missing = self.run_with("", rc=127)["bundle-audit"]
        self.assertFalse(missing["ok"])
        self.assertIn("gem install bundler-audit -v 0.9.3", missing["detail"])
        self.assertTrue(self.run_with("bundler-audit 0.9.3\n")["govulncheck"]["ok"])


class RunChecksTests(unittest.TestCase):
    def test_results_are_cached_for_an_hour_and_a_crash_is_reported(self):
        store = FakeStore()
        calls = []

        def probe(url, host):
            calls.append(url)
            return 200
        run = lambda argv, **kw: completed(argv, 0, "bundler-audit 0.9.3\n")  # noqa: E731
        first = selfcheck.run_checks(store, {"blog": SPECS["blog"]}, run=run, now=NOW, probe=probe)
        self.assertEqual(len(calls), 1)
        selfcheck.run_checks(store, {"blog": SPECS["blog"]}, run=run, now=NOW + timedelta(minutes=30), probe=probe)
        self.assertEqual(len(calls), 1)
        self.assertEqual(selfcheck.report_fields(store)["health_probes"], first["health_probes"])

        broken = FakeStore()
        broken.inventories = lambda: (_ for _ in ()).throw(RuntimeError("db locked"))
        result = selfcheck.run_checks(broken, {"blog": SPECS["blog"]}, run=run, now=NOW, probe=probe)
        self.assertEqual(result["coverage_gaps"], [])
        crash = [t for t in result["tooling"] if t["tool"] == "selfcheck coverage_gaps"]
        self.assertEqual(len(crash), 1)
        self.assertFalse(crash[0]["ok"])


if __name__ == "__main__":
    unittest.main()
