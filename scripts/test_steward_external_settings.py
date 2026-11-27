#!/usr/bin/env python3
"""P3a expected-unit and external-settings drift: detection and email rendering (offline)."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from steward import external_settings as ext  # noqa: E402
from steward import health, report  # noqa: E402

ENABLED = (
    "comfy-web.service enabled enabled\n"
    "gpg-agent.socket enabled enabled\n"
    "session-migration.service enabled enabled\n"
    "launchpadlib-cache-clean.timer enabled enabled\n"
    "notify-failure@x.service enabled enabled\n"
    "homelab-steward.timer enabled enabled\n"
    "stray.timer enabled enabled\n"
)


class ExpectedUnitDriftTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "expected-user-units.txt"
        self.commands = []

    def tearDown(self):
        self.tmp.cleanup()

    def drift(self, states, listing=ENABLED, list_rc=0):
        def fake(cmd, **_kwargs):
            self.commands.append(list(cmd))
            if "is-enabled" in cmd:
                state = states.get(cmd[-1], "enabled")
                if state is None:
                    return "", "Failed to connect to bus", 1
                return f"{state}\n", "", 0 if state == "enabled" else 1
            if "list-unit-files" in cmd:
                return listing, "boom", list_rc
            raise AssertionError(cmd)
        with patch.object(health, "run_capture_ok", side_effect=fake):
            return health.expected_unit_drift(self.path)

    def test_parse_skips_comments_and_blanks(self):
        self.path.write_text("# header\n\ncomfy-web.service\n  # indented\nhomelab-steward.timer\n")
        self.assertEqual(health._read_expected_units(self.path),
                         ["comfy-web.service", "homelab-steward.timer"])

    def test_all_enabled_and_listed_is_ok(self):
        self.path.write_text("comfy-web.service\nhomelab-steward.timer\nstray.timer\n")
        result = self.drift({})
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual(result["extra"], [])
        for cmd in self.commands:  # read-only systemctl only
            self.assertEqual(cmd[:2], ["systemctl", "--user"])
            self.assertIn(cmd[2], ("is-enabled", "list-unit-files"))

    def test_disabled_and_not_found_units_are_drift_with_state(self):
        self.path.write_text("comfy-web.service\nhomelab-steward.timer\ngone.service\nstray.timer\n")
        result = self.drift({"comfy-web.service": "disabled", "gone.service": "not-found"})
        self.assertEqual(result["status"], "drift")
        self.assertEqual(result["not_enabled"], [
            {"unit": "comfy-web.service", "state": "disabled"},
            {"unit": "gone.service", "state": "not-found"}])

    def test_enabled_homelab_unit_missing_from_list_is_extra_os_defaults_ignored(self):
        self.path.write_text("comfy-web.service\nhomelab-steward.timer\n")
        result = self.drift({})
        self.assertEqual(result["status"], "drift")
        self.assertEqual(result["extra"], ["stray.timer"])

    def test_missing_file_bad_line_and_systemctl_failure_are_not_clean(self):
        self.assertEqual(self.drift({})["status"], "attention_needed")
        self.path.write_text("comfy-web.service\nrm -rf /\n")
        self.assertEqual(self.drift({})["status"], "error")
        self.path.write_text("comfy-web.service\n")
        result = self.drift({"comfy-web.service": None})
        self.assertEqual(result["status"], "error")
        self.assertIn("Failed to connect to bus", result["reason"])
        self.assertEqual(self.drift({}, list_rc=1)["status"], "error")


def gh_result(table):
    """Fake ext._gh from {path: (status, data, message)}; unknown paths are API failures."""
    def fake(path, deadline, paginate=False):
        if path not in table:
            raise ext.CollectError(f"gh api {path}: HTTP 502")
        return table[path]
    return fake


REPO = "carter2099/blog"
GH_TABLE = {
    f"repos/{REPO}": (200, {
        "visibility": "public", "default_branch": "main", "archived": False,
        "allow_auto_merge": True, "allow_merge_commit": True, "allow_squash_merge": True,
        "allow_rebase_merge": True, "allow_update_branch": False,
        "delete_branch_on_merge": False, "node_id": "R_x", "updated_at": "2026-01-01T00:00:00Z",
        "security_and_analysis": {"secret_scanning": {"status": "enabled"}},
    }, ""),
    f"repos/{REPO}/rulesets": (200, [{"id": 7, "name": "gate"}], ""),
    f"repos/{REPO}/rulesets/7": (200, {
        "id": 7, "name": "gate", "target": "branch", "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "rules": [{"type": "required_status_checks"}], "bypass_actors": [],
        "node_id": "RRS", "created_at": "x", "_links": {}, "current_user_can_bypass": "always",
    }, ""),
    f"repos/{REPO}/branches/main/protection": (404, None, "Branch not protected"),
    f"repos/{REPO}/automated-security-fixes": (200, {"enabled": True, "paused": False}, ""),
    f"repos/{REPO}/vulnerability-alerts": (404, None, "Vulnerability alerts are disabled."),
    f"repos/{REPO}/hooks": (200, [{
        "id": 1, "name": "web", "active": True, "events": ["push", "pull_request"],
        "config": {"url": "https://hooks.example/webhook", "content_type": "json",
                   "insecure_ssl": "0", "secret": "********"},
        "last_response": {"code": 200}, "updated_at": "x"}], ""),
    f"repos/{REPO}/labels?per_page=100": (200, [{"name": "z"}, {"name": "a", "id": 3}], ""),
}


class GithubSnapshotTests(unittest.TestCase):
    def snapshot(self, table):
        with patch.object(ext, "_gh", side_effect=gh_result(table)):
            return ext.github_snapshot(REPO, time.monotonic() + 30)

    def test_normalizes_and_drops_volatile_fields_and_secrets(self):
        snap = self.snapshot(GH_TABLE)
        self.assertEqual(snap["settings"]["security_and_analysis"], {"secret_scanning": "enabled"})
        self.assertNotIn("node_id", snap["settings"])
        self.assertEqual(snap["rulesets"], [{
            "name": "gate", "target": "branch", "enforcement": "active",
            "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
            "rules": [{"type": "required_status_checks"}], "bypass_actors": []}])
        self.assertIsNone(snap["branch_protection"])
        self.assertEqual(snap["vulnerability_alerts"], {"enabled": False})
        self.assertEqual(snap["webhooks"], [{
            "name": "web", "active": True, "events": ["pull_request", "push"],
            "config": {"url": "https://hooks.example/webhook", "content_type": "json",
                       "insecure_ssl": "0"}}])
        self.assertNotIn("********", json.dumps(snap))
        self.assertEqual(snap["labels"], ["a", "z"])

    def test_permission_refusals_are_recorded_unreadable(self):
        table = dict(GH_TABLE)
        upgrade = "Upgrade to GitHub Pro or make this repository public to enable this feature."
        table[f"repos/{REPO}/rulesets"] = (403, None, upgrade)
        table[f"repos/{REPO}/branches/main/protection"] = (403, None, upgrade)
        table[f"repos/{REPO}/hooks"] = (404, None, "Not Found")
        snap = self.snapshot(table)
        self.assertEqual(snap["rulesets"], {"unreadable": f"HTTP 403: {upgrade}"})
        self.assertEqual(snap["branch_protection"], {"unreadable": f"HTTP 403: {upgrade}"})
        self.assertEqual(snap["webhooks"], {"unreadable": "HTTP 404: Not Found"})

    def test_other_failures_raise(self):
        table = dict(GH_TABLE)
        del table[f"repos/{REPO}/hooks"]
        with self.assertRaises(ext.CollectError):
            self.snapshot(table)

    def test_gh_status_parsing(self):
        def run(stdout, stderr, rc):
            cp = subprocess.CompletedProcess([], rc, stdout, stderr)
            with patch.object(ext.subprocess, "run", return_value=cp):
                return ext._gh("repos/x/y/hooks", time.monotonic() + 30)
        self.assertEqual(run("", "", 0), (204, None, ""))
        self.assertEqual(run('[{"a":1}]', "", 0), (200, [{"a": 1}], ""))
        self.assertEqual(run('{"message":"Must have admin rights"}',
                             "gh: Must have admin rights (HTTP 403)", 1),
                         (403, None, "Must have admin rights"))
        with self.assertRaises(ext.CollectError):
            run('{"message":"Server Error"}', "gh: Server Error (HTTP 500)", 1)
        with self.assertRaises(ext.CollectError):
            run("", "error connecting to api.github.com", 1)


class CompareTests(unittest.TestCase):
    def test_diff_paths_use_names_for_lists(self):
        old = {"rulesets": [{"name": "gate", "enforcement": "active"}], "labels": ["a"]}
        new = {"rulesets": [{"name": "gate", "enforcement": "disabled"}], "labels": ["a", "b"],
               "webhooks": []}
        self.assertEqual(ext.diff_paths(old, new), [
            {"path": "labels", "change": "changed"},
            {"path": "rulesets.gate.enforcement", "change": "changed"},
            {"path": "webhooks", "change": "added"}])

    def test_compare_reports_changed_new_stale_and_unreadable_transitions(self):
        tracked = {"github/a.json": {"rulesets": [{"name": "g"}]},
                   "github/old.json": {}, "cloudflare/dns.json": {"records": []}}
        live = {"github/a.json": {"rulesets": {"unreadable": "HTTP 403: x"}},
                "github/new.json": {}, "cloudflare/dns.json": {"records": []}}
        result = ext.compare(live, tracked)
        self.assertEqual(result["status"], "drift")
        by_path = {f["path"]: f for f in result["files"]}
        self.assertEqual(by_path["github/a.json"]["changes"],
                         [{"path": "rulesets", "change": "changed"}])
        self.assertEqual(by_path["github/new.json"]["status"], "new")
        self.assertEqual(by_path["github/old.json"]["status"], "stale")
        self.assertNotIn("cloudflare/dns.json", by_path)
        self.assertEqual(ext.compare(tracked, tracked)["status"], "ok")

    def test_errors_are_never_clean_and_do_not_mark_files_stale(self):
        tracked = {"github/carter2099__blog.json": {}, "cloudflare/dns.json": {}}
        result = ext.compare({}, tracked, ["carter2099/blog: gh api x: timed out",
                                           "Cloudflare DNS records: timed out"])
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["files"], [])

    def test_check_with_tracked_dir_and_collection_errors(self):
        with tempfile.TemporaryDirectory() as tmp, \
                patch.dict("os.environ", {"STEWARD_OFFLINE": "0"}):
            root = Path(tmp)
            (root / "github").mkdir()
            (root / "github" / "x.json").write_text(ext.render({"a": 1}))
            with patch.object(ext, "collect", return_value=({"github/x.json": {"a": 1}}, [])):
                self.assertEqual(ext.check(root)["status"], "ok")
            with patch.object(ext, "collect", return_value=({"github/x.json": {"a": 2}}, [])):
                result = ext.check(root)
                self.assertEqual(result["status"], "drift")
                self.assertEqual(result["files"][0]["changes"], [{"path": "a", "change": "changed"}])
            with patch.object(ext, "collect", side_effect=RuntimeError("boom")):
                self.assertEqual(ext.check(root)["status"], "error")
        with patch.dict("os.environ", {"STEWARD_OFFLINE": "1"}):
            self.assertEqual(ext.check(Path("/nonexistent"))["status"], "error")

    def test_write_aborts_on_secret_or_api_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            leak = {"github/x.json": {"hook": "Authorization: Bearer " + "A1b2C3d4" * 5}}
            with patch.object(ext, "collect", return_value=(leak, [])):
                result = ext.write(root)
            self.assertEqual(result["status"], "aborted")
            self.assertIn("github/x.json", result["errors"][0])
            with patch.object(ext, "collect", return_value=({"github/x.json": {}}, ["boom"])):
                self.assertEqual(ext.write(root)["status"], "aborted")
            self.assertEqual(list(root.iterdir()), [])
            with patch.object(ext, "collect", return_value=({"github/x.json": {"a": 1}}, [])):
                self.assertEqual(ext.write(root)["written"], ["github/x.json"])
            self.assertEqual(json.loads((root / "github" / "x.json").read_text()), {"a": 1})

    def test_cloudflare_ids_are_redacted_and_aud_fingerprinted(self):
        ids = {"acct0123": "<account-id>", "tun-1": "<homelab-tunnel-id>"}
        data = ext._redact({"content": "tun-1.cfargotunnel.com",
                            "include": [{"account_id": "acct0123"}]}, ids)
        self.assertEqual(data, {"content": "<homelab-tunnel-id>.cfargotunnel.com",
                                "include": [{"account_id": "<account-id>"}]})
        aud = ext._fingerprint_aud({"originRequest": {"access": {"audTag": ["abc"]}}, "aud": "abc"})
        self.assertEqual(aud["aud"], aud["originRequest"]["access"]["audTag"][0])
        self.assertTrue(aud["aud"].startswith("sha256:"))


class DriftRenderingTests(unittest.TestCase):
    def watching(self, remediation):
        triaged = report._triage({"steps": []}, {"sections": []}, {"routes": []},
                                 remediation=remediation)
        self.assertEqual(triaged["needs"], [])
        return [(w["text"], w["command"]) for w in triaged["watching"]]

    def test_clean_results_render_nothing(self):
        self.assertEqual(self.watching({"unit_drift": {"status": "ok"},
                                        "external_settings": {"status": "ok", "files": []}}), [])
        self.assertEqual(self.watching({}), [])

    def test_unit_drift_lines(self):
        rows = self.watching({"unit_drift": {
            "status": "drift", "extra": ["stray.timer"],
            "not_enabled": [{"unit": "comfy-web.service", "state": "disabled"},
                            {"unit": "gone.service", "state": "not-found"}]}})
        self.assertIn(("User unit comfy-web.service is disabled, expected enabled",
                       "systemctl --user enable --now comfy-web.service"), rows)
        self.assertIn(("User unit gone.service is not-found, expected enabled",
                       "systemctl --user status gone.service"), rows)
        self.assertIn(("1 enabled user unit not in the expected unit list "
                       "(~/system-config/expected-user-units.txt): add if intended",
                       "stray.timer"), rows)
        rows = self.watching({"unit_drift": {"status": "error", "reason": "bus down"}})
        self.assertEqual(rows, [("User unit drift check did not run: bus down", "")])

    def test_external_settings_drift_and_error_lines(self):
        rows = self.watching({"external_settings": {
            "status": "error", "refresh": ext.REFRESH_COMMAND,
            "errors": ["Cloudflare DNS records: timed out"],
            "files": [{"path": "github/carter2099__blog.json", "status": "changed",
                       "changes": [{"path": "rulesets.gate.enforcement", "change": "changed"},
                                   {"path": "labels", "change": "changed"}]}]}})
        self.assertIn(("GitHub carter2099/blog settings differ from the tracked snapshot: "
                       "rulesets.gate.enforcement changed, labels changed; refresh if intended",
                       ext.REFRESH_COMMAND), rows)
        self.assertIn(("External settings check did not finish: Cloudflare DNS records: timed out",
                       ext.CHECK_COMMAND), rows)


if __name__ == "__main__":
    unittest.main()
