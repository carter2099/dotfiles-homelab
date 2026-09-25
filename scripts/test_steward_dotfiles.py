#!/usr/bin/env python3
"""Exercise hygiene against real Git status and staging boundaries."""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from steward import dotfiles


class DotfilesPathTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.git_dir = self.home / ".git"
        self.git("init", "--quiet")
        self.git("config", "user.name", "Hygiene regression")
        self.git("config", "user.email", "hygiene@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        (self.home / ".config").mkdir()

    def git(self, *args):
        return subprocess.run(
            ["git", "-C", str(self.home), *args],
            check=True, capture_output=True, text=True, timeout=15,
        )

    def tracked(self, path):
        (self.home / path).write_text("original\n")
        self.git("add", "--", path)
        self.git("commit", "--quiet", "-m", "baseline")

    def test_first_unstaged_path_survives_command_capture(self):
        path = ".config/agent.conf"
        self.tracked(path)
        (self.home / path).write_text("changed\n")
        status, error = dotfiles._snapshot(self.git_dir, self.home)
        self.assertIsNone(error)
        self.assertEqual(status, {path: " M"})

    def test_rename_and_literal_filename_survive_status_and_staging(self):
        old = ".config/old -> café 'name'\r\n "
        new = ".config/ new -> café \"name\"\r\n "
        self.tracked(old)
        self.git("mv", "--", old, new)
        status, error = dotfiles._snapshot(self.git_dir, self.home)
        self.assertIsNone(error)
        self.assertEqual(status, {new: "R ", old: "R "})
        staged, error = dotfiles._staged_paths(self.git_dir, self.home)
        self.assertIsNone(error)
        self.assertEqual(staged, {old, new})


if __name__ == "__main__":
    unittest.main()
