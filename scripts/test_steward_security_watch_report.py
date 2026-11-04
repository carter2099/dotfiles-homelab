#!/usr/bin/env python3
"""The nightly email maps security-watch's report.json into its triage and card."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from steward import report  # noqa: E402

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)


def iso(delta=timedelta()):
    return (NOW - delta).isoformat()


def sample(**overrides):
    data = {
        "schema": 1, "generated_at": iso(timedelta(minutes=10)), "mode": "shadow",
        "breaker": {"open": False, "reason": "", "since": None},
        "sources": [
            {"name": "zero_wire", "tier": "curated", "last_success": iso(timedelta(minutes=20)),
             "last_error": "", "consecutive_failures": 0, "ok_rate_7d": 1.0},
            {"name": "ubuntu_usn", "tier": "issuer", "last_success": iso(timedelta(days=2)),
             "last_error": "HTTP 503", "consecutive_failures": 190, "ok_rate_7d": 0.6},
        ],
        "findings": [{
            "key": "freshrss|CVE-2026-111497", "component": "freshrss", "exposure": "public",
            "package": "Debian:13/brotli", "version": "1.1.0-2", "fixed": ["1.1.0-2+deb13u1"],
            "fix_available": True, "cves": ["CVE-2026-111497"],
            "advisories": ["DEBIAN-CVE-2026-111497"], "kev": True, "zero_wire": ["node2shell"],
            "severity": "critical", "summary": "brotli decoder overflow",
            "reach": {"verdict": "reachable", "p": 0.93, "method": "agent+jev", "summary": "s"},
            "urgency": "urgent", "reasons": ["public surface", "CISA KEV"],
            "first_seen": iso(timedelta(hours=2)), "status": "affected",
        }],
        "unknown": [{"component": "searxng", "reason": "os void has no OSV ecosystem"}],
        "actions_24h": [], "proposed": [], "refused": [], "leads_24h": [], "resolved_24h": [],
        "shadow": {"since": iso(timedelta(days=3)), "days": 3.0, "source_ok_rate": 0.97,
                   "urgent_sent_7d": 1, "eligible": False,
                   "criteria": ["14 days in shadow (3.0)"]},
        "last_tick": {"started": iso(timedelta(minutes=11)),
                      "finished": iso(timedelta(minutes=10)), "outcome": "ok"},
    }
    data.update(overrides)
    return data


def triage(data):
    return report._triage({"steps": []}, {"sections": []}, {"routes": []},
                          security_watch=data, now=NOW)


class SecurityWatchReportTests(unittest.TestCase):
    def test_fresh_report_maps_open_finding_and_failing_source_to_watching(self):
        triaged = triage(sample())
        self.assertEqual(triaged["needs"], [])
        texts = [w["text"] for w in triaged["watching"]]
        self.assertTrue(any("freshrss: Debian:13/brotli 1.1.0-2 — CVE-2026-111497" in t
                            and "fix 1.1.0-2+deb13u1" in t and "reachable 0.93" in t
                            for t in texts), texts)
        self.assertTrue(any(t.startswith("Security feed ubuntu_usn failing since") for t in texts))
        self.assertFalse(any("zero_wire" in t for t in texts))
        self.assertFalse(any("stale" in t for t in texts))

    def test_stale_report_is_a_watching_item(self):
        generated = iso(timedelta(hours=3))
        triaged = triage(sample(generated_at=generated))
        self.assertIn(f"security-watch report is stale (last {generated})",
                      [w["text"] for w in triaged["watching"]])
        self.assertEqual(triaged["needs"], [])

    def test_open_breaker_needs_carter(self):
        data = sample(breaker={"open": True, "reason": "freshrss findings did not clear",
                               "since": iso(timedelta(hours=5))})
        triaged = triage(data)
        (needs,) = triaged["needs"]
        self.assertIn("circuit breaker is open", needs["text"])
        self.assertIn("freshrss findings did not clear", needs["why"])
        self.assertEqual(needs["command"], report.SECURITY_WATCH_BREAKER_RESET)
        self.assertEqual(triaged["verdict"][0], "problem")

    def test_failed_action_and_overdue_urgent_finding_need_carter(self):
        data = sample(actions_24h=[{
            "id": 7, "playbook": "steward-freshrss", "component": "freshrss", "mode": "active",
            "status": "rolled_back", "target": "freshrss 1.28.1", "detail": "health check failed",
            "undo": "restore the previous image pin", "started_at": iso(timedelta(hours=3)),
            "finished_at": iso(timedelta(hours=3))}])
        data["findings"][0]["first_seen"] = iso(timedelta(hours=30))
        texts = [n["text"] for n in triage(data)["needs"]]
        self.assertIn("Security fix for freshrss (steward-freshrss) was rolled back", texts)
        self.assertTrue(any(t.startswith("Unpatched urgent vulnerability — freshrss") for t in texts))

    def test_verified_action_is_a_change_with_undo(self):
        data = sample(mode="active", actions_24h=[{
            "id": 8, "playbook": "apt-security", "component": "host", "mode": "active",
            "status": "verified", "target": "libbrotli1 1.1.0-2ubuntu0.2",
            "detail": "installed", "undo": "sudo apt install libbrotli1=1.1.0-2ubuntu0.1",
            "started_at": iso(timedelta(hours=1)), "finished_at": iso(timedelta(hours=1))}])
        triaged = triage(data)
        (change,) = triaged["changes"]
        self.assertEqual(change["kind"], "change")
        self.assertEqual(change["group"], "Updates")
        self.assertEqual(change["text"], "Security fix: host — libbrotli1 1.1.0-2ubuntu0.2")
        self.assertEqual(change["undo"], ["sudo apt install libbrotli1=1.1.0-2ubuntu0.1"])
        self.assertEqual(triaged["undo"], [change])

    def test_shadow_proposal_and_alert_refusal_are_watching(self):
        data = sample(
            proposed=[{"component": "freshrss", "playbook": "steward-freshrss",
                       "target": "freshrss 1.28.1", "steps": ["bump"], "undo": "u",
                       "since": iso()}],
            refused=[{"component": "carter-news", "playbook": "compose-digest",
                      "reason": "no newer image", "alert": True, "since": iso()},
                     {"component": "blog", "playbook": "repo-pr", "reason": "quiet",
                      "alert": False, "since": iso()}])
        texts = [w["text"] for w in triage(data)["watching"]]
        self.assertIn("Security watch proposes steward-freshrss for freshrss: freshrss 1.28.1 "
                      "(shadow mode, not applied)", texts)
        self.assertIn("Security watch cannot fix carter-news (compose-digest): no newer image",
                      texts)
        self.assertFalse(any("quiet" in t for t in texts))

    def test_missing_or_invalid_report_adds_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            with patch.dict(os.environ, {"SECURITY_WATCH_STATE_DIR": str(state)}):
                self.assertEqual(report._load_security_watch_report(), {})
                (state / "report.json").write_text("{not json")
                self.assertEqual(report._load_security_watch_report(), {})
                (state / "report.json").write_text(json.dumps({"schema": 99}))
                self.assertEqual(report._load_security_watch_report(), {})
                (state / "report.json").write_text(json.dumps(sample()))
                self.assertEqual(report._load_security_watch_report()["mode"], "shadow")
        empty = triage({})
        self.assertEqual((empty["needs"], empty["watching"], empty["changes"]), ([], [], []))
        self.assertEqual(report._html_security_watch({}), "")

    def test_section_renders_mode_breaker_shadow_findings_and_blind_spots(self):
        html = report._html_security_watch(sample(), now=NOW)
        for expected in ("shadow", "closed", "not yet", "14 days in shadow (3.0)",
                         "Debian:13/brotli 1.1.0-2", "1.1.0-2+deb13u1", "urgent",
                         "reachable 0.93", "ubuntu_usn", "1 component"):
            self.assertIn(expected, html)
        card = report._section("Security watch", report.COLOR["audit"], html)
        self.assertIn("Security watch", card)
        hostile = sample()
        hostile["findings"][0]["package"] = "<script>x</script>"
        self.assertNotIn("<script>", report._html_security_watch(hostile, now=NOW))

    def test_stopgaps_render_active_and_flag_removable(self):
        remove = "sudo rm /etc/nginx/conf.d/block-brotli.conf && sudo systemctl reload nginx"
        data = sample(stopgaps=[
            {"id": "sg-brotli-news", "component": "carter-news", "cves": ["CVE-2026-111497"],
             "description": "disable brotli", "since": iso(timedelta(days=1)),
             "remove": "undo it", "doc": "notes/x.md", "status": "active"},
            {"id": "sg-old", "component": "blog", "cves": [], "description": "d",
             "since": iso(timedelta(days=9)), "remove": remove, "doc": "", "status": "removable"},
            {"id": "sg-maybe", "component": "freshrss", "cves": [], "description": "d",
             "since": iso(), "remove": "r", "doc": "", "status": "unverified"},
        ])
        watching = triage(data)["watching"]
        (item,) = [w for w in watching if w["text"].startswith("Stopgap")]
        self.assertEqual(item["text"], f"Stopgap sg-old can be removed: {remove}")
        self.assertEqual((item["todo"], item["command"]), (remove, remove))
        html = report._html_security_watch(data, now=NOW)
        self.assertIn("sg-brotli-news", html)
        self.assertIn("carter-news", html)
        self.assertIn("since 2026-11-02 12:00 UTC", html)
        self.assertNotIn("sg-old", html)
        self.assertNotIn("sg-maybe", html)

    def test_missing_stopgaps_field_adds_nothing(self):
        data = sample()
        self.assertNotIn("stopgaps", data)
        self.assertFalse(any(w["text"].startswith("Stopgap") for w in triage(data)["watching"]))
        self.assertNotIn("stopgaps", report._html_security_watch(data, now=NOW).lower())


if __name__ == "__main__":
    unittest.main()
