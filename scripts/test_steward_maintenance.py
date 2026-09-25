#!/usr/bin/env python3
"""Guard the distinction between a maintenance pause and a real outage."""
from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from steward import audit


class DependabotMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.run_dir = Path("/tmp/steward-maintenance-regression")
        self.setup = {
            "run_dir": str(self.run_dir), "phase_status": "succeeded", "dry_run": False,
            "dependabot": {"was_active": True, "stopped": True, "error": None},
        }
        self.stopped = (
            "LoadState=loaded\nActiveState=inactive\nSubState=dead\nResult=success\n"
        )

    def assess(self, state=None, exit_code=0):
        with patch.object(audit, "run_capture_ok", return_value=(
            self.stopped if state is None else state, "", exit_code,
        )):
            return audit._dependabot_maintenance_evidence(
                self.run_dir, self.setup,
            )["assessment"]

    def test_owned_pause_ends_when_service_is_running_again(self):
        self.assertEqual(self.assess(), "maintenance-stopped")
        self.assertEqual(self.assess(
            "LoadState=loaded\nActiveState=active\nSubState=running\nResult=success\n"
        ), "running")

    def test_preexisting_outage_is_not_maintenance(self):
        self.setup["dependabot"].update(was_active=False, stopped=False)
        self.assertEqual(self.assess(), "unexpected")

    def test_another_runs_stop_cannot_authorize_current_outage(self):
        self.setup["run_dir"] += "-previous"
        self.assertEqual(self.assess(), "unexpected")

    def test_failed_stop_and_failed_service_are_not_exempt(self):
        self.setup["dependabot"]["error"] = "stop command failed"
        self.assertEqual(self.assess(), "unexpected")
        self.setup["dependabot"]["error"] = None
        self.assertEqual(self.assess(
            "LoadState=loaded\nActiveState=failed\nSubState=failed\nResult=exit-code\n"
        ), "unexpected")

    def test_missing_service_evidence_cannot_be_reported_as_expected(self):
        self.assertEqual(self.assess("", exit_code=1), "unverifiable")


if __name__ == "__main__":
    unittest.main()
