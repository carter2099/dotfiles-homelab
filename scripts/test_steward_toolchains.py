#!/usr/bin/env python3
"""Behavioral tests for P1 same-line toolchain updates (fakes only, no network)."""
from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from unittest.mock import patch

from steward import audit, report, toolchains

NOW = datetime(2026, 10, 23, 5, 0, tzinfo=timezone.utc)


def _script(text):
    return "#!/bin/sh\n" + text + "\n"


def _write_tree(root, version, go_script=None):
    (root / "bin").mkdir(parents=True)
    (root / "VERSION").write_text(f"go{version}\ntime 2026-10-01\n")
    go = root / "bin" / "go"
    go.write_text(go_script or _script(f"printf go{version}"))
    go.chmod(0o755)


def _tarball(version, go_script=None):
    """A go<version>.linux-amd64.tar.gz whose bin/go is a tiny shell script."""
    with tempfile.TemporaryDirectory() as tmp:
        _write_tree(Path(tmp) / "go", version, go_script)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            tar.add(Path(tmp) / "go", arcname="go")
        return buffer.getvalue()


def _go_index(sha_by_version):
    return json.dumps([
        {"version": f"go{v}", "stable": True, "files": [
            {"os": "linux", "arch": "amd64", "kind": "archive",
             "filename": f"go{v}.linux-amd64.tar.gz", "sha256": sha}]}
        for v, sha in sha_by_version.items()
    ] + [{"version": "go1.28rc1", "stable": False, "files": []}]).encode()


class GoUserFixture:
    """A temp HOME with ~/.local/go at 1.27.3 and a fake upstream."""

    def __init__(self, test, *, new_script=None, published_sha=None):
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        self.target = self.home / ".local" / "go"
        _write_tree(self.target, "1.27.3")
        self.target.chmod(0o700)
        self.archive = _tarball("1.27.4", new_script)
        real_sha = hashlib.sha256(self.archive).hexdigest()
        self.index = _go_index({
            "1.28.1": "0" * 64,          # newer line: never applied
            "1.27.4": published_sha or real_sha,
            "1.27.3": "1" * 64,
            "1.26.11": "2" * 64,
        })
        self.downloads = []

    def fetch(self, url):
        assert url == toolchains.GO_INDEX, url
        return self.index

    def download(self, url, dest, timeout):
        self.downloads.append(url)
        Path(dest).write_bytes(self.archive)

    def ctx(self, **kwargs):
        return toolchains.Ctx(home=self.home, fetch=self.fetch, download=self.download,
                              now=lambda: NOW, env={"PATH": os.environ["PATH"]}, **kwargs)

    def run(self, **kwargs):
        return toolchains.p1_toolchain("toolchain_go_user", ctx=self.ctx(**kwargs))

    def version(self):
        return (self.target / "VERSION").read_text().splitlines()[0]

    def state(self):
        path = self.home / ".local/state/toolchain-rollback/state.json"
        return json.loads(path.read_text()) if path.exists() else None

    def leftovers(self):
        root = self.home / ".local/state/toolchain-rollback"
        staging = root / "staging"
        return sorted(p.name for p in staging.iterdir()) if staging.exists() else []


class SameLineSelectionTests(unittest.TestCase):
    RELEASES = [{"version": v} for v in (
        "26.12.0", "26.12.1", "26.9.3", "27.0.0", "27.1.0", "25.99.9", "26.13.0-rc.1")]

    def test_node_major_line_never_crosses_major(self):
        picked = toolchains.select_same_line("26.12.0", self.RELEASES, 1)
        self.assertEqual(picked["version"], "26.12.1")
        self.assertEqual(toolchains.newest_other_line("26.12.0", self.RELEASES, 1), "27.1.0")

    def test_minor_line_never_crosses_minor(self):
        releases = [{"version": v} for v in ("1.26.10", "1.26.11", "1.27.0", "1.27.4", "2.0.0")]
        self.assertEqual(toolchains.select_same_line("1.26.10", releases, 2)["version"], "1.26.11")
        self.assertIsNone(toolchains.select_same_line("1.27.4", releases, 2))
        self.assertIsNone(toolchains.select_same_line("1.26.11", releases[:2], 2))
        self.assertEqual(toolchains.newest_other_line("1.26.10", releases, 2), "2.0.0")

    def test_never_downgrades_or_takes_prereleases(self):
        releases = [{"version": v} for v in ("4.0.6", "4.0.7", "4.0.8-preview1", "4.1.0")]
        self.assertIsNone(toolchains.select_same_line("4.0.7", releases, 2))


class GoTreeUpdateTests(unittest.TestCase):
    def test_same_line_update_swaps_tree_and_keeps_rollback_outside_work_tree(self):
        fx = GoUserFixture(self)
        packet = fx.run()
        self.assertEqual(packet["status"], "ok", packet)
        self.assertEqual((packet["pre_version"], packet["post_version"]), ("1.27.3", "1.27.4"))
        self.assertEqual(packet["newer_line"], "1.28.1")
        self.assertEqual(fx.version(), "go1.27.4")
        self.assertEqual(fx.target.stat().st_mode & 0o777, 0o700)
        record, = fx.state()["replaced"]
        old = Path(record["path"])
        self.assertEqual(old.parent, fx.home / ".local/state/toolchain-rollback")
        self.assertEqual((old / "VERSION").read_text().splitlines()[0], "go1.27.3")
        self.assertEqual(record["state"], "replaced")
        self.assertEqual(fx.leftovers(), [])
        # The undo command really restores the previous tree.
        subprocess.run(packet["revert"], shell=True, check=True)
        self.assertEqual(fx.version(), "go1.27.3")
        items = report._p1_events({"steps": [packet]})
        self.assertEqual([(i["kind"], i["text"]) for i in items],
                         [("change", "Go (~/.local/go) 1.27.3 → 1.27.4")])
        self.assertEqual(items[0]["undo"], [packet["revert"]])

    def test_current_tree_is_skipped_without_download(self):
        fx = GoUserFixture(self)
        fx.index = _go_index({"1.27.3": "1" * 64, "1.28.0": "0" * 64})
        packet = fx.run()
        self.assertEqual(packet["status"], "skipped")
        self.assertEqual(packet["newer_line"], "1.28.0")
        self.assertEqual(fx.downloads, [])
        self.assertEqual(report._p1_events({"steps": [packet]}), [])

    def test_checksum_mismatch_changes_nothing(self):
        fx = GoUserFixture(self, published_sha="f" * 64)
        packet = fx.run()
        self.assertEqual(packet["status"], "warning")
        self.assertIn("checksum mismatch", packet["error"])
        self.assertEqual(fx.version(), "go1.27.3")
        self.assertEqual(fx.state()["replaced"], [])
        self.assertEqual(fx.leftovers(), [])
        item, = report._p1_events({"steps": [packet]})
        self.assertEqual(item["kind"], "watch")

    def test_failed_smoke_after_switch_rolls_back_and_reports(self):
        # The new go only breaks once it runs from the live path.
        broken = _script('case "$0" in */.local/go/bin/go) exit 3;; esac\nprintf go1.27.4')
        fx = GoUserFixture(self, new_script=broken)
        packet = fx.run()
        self.assertEqual(packet["status"], "reverted", packet)
        self.assertEqual(packet["reverted_to"], "1.27.3")
        self.assertEqual(fx.version(), "go1.27.3")
        self.assertEqual(fx.state()["replaced"], [])
        root = fx.home / ".local/state/toolchain-rollback"
        self.assertEqual(sorted(p.name for p in root.glob("go-user-*")), [])
        self.assertEqual(fx.leftovers(), [])
        item, = report._p1_events({"steps": [packet]})
        self.assertEqual(item["kind"], "watch")
        self.assertIn("rolled back to 1.27.3", item["text"])

    def test_new_install_failing_smoke_is_never_switched(self):
        fx = GoUserFixture(self, new_script=_script("exit 1"))
        packet = fx.run()
        self.assertEqual(packet["status"], "warning")
        self.assertIn("nothing changed", packet["error"])
        self.assertEqual(fx.version(), "go1.27.3")
        self.assertEqual(fx.leftovers(), [])

    def test_dry_run_mutates_nothing(self):
        fx = GoUserFixture(self)
        packet = fx.run(dry_run=True)
        self.assertEqual(packet["status"], "available")
        self.assertEqual(packet["target"], "1.27.4")
        self.assertEqual(fx.downloads, [])
        self.assertEqual(fx.version(), "go1.27.3")
        self.assertFalse((fx.home / ".local/state").exists())

    def test_no_time_left_skips_with_warning(self):
        fx = GoUserFixture(self)
        packet = fx.run(deadline=0.0, monotonic=lambda: 100.0)
        self.assertEqual(packet["status"], "warning")
        self.assertIn("budget", packet["error"])
        self.assertEqual(fx.downloads, [])


class FakeDriver(toolchains.Driver):
    """Engine-level fake: an in-memory 'active version' with injectable faults."""
    key, label = "go-user", "Go (~/.local/go)"

    def __init__(self, ctx, *, active="1.27.3", fail_unswitch=False, broken_active=False):
        super().__init__(ctx)
        self.active_version = active
        self.fail_unswitch, self.broken_active = fail_unswitch, broken_active

    def current(self):
        return self.active_version

    def active(self):
        return "active"

    def releases(self):
        return [{"version": "1.27.4"}]

    def stage(self, rel):
        return {"path": "staged", "version": rel["version"]}

    def smoke(self, where):
        if where == "active" and self.broken_active:
            raise toolchains.ToolchainError("go smoke test failed")
        return self.active_version if where == "active" else "1.27.4"

    def switch(self, staged, cur, record):
        self.active_version = record["installed"]

    def unswitch(self, staged, cur, record):
        if self.fail_unswitch:
            raise toolchains.ToolchainError("exchange failed: Device or resource busy")
        self.active_version = cur

    def discard(self, staged):
        pass

    def undo(self, cur, record):
        return f"restore {cur}"


class EngineTests(unittest.TestCase):
    def _ctx(self, tmp):
        return toolchains.Ctx(home=Path(tmp), now=lambda: NOW, env={"PATH": os.environ["PATH"]})

    def test_unverified_rollback_is_needs_you_and_never_pruned(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = self._ctx(tmp)
            driver = FakeDriver(ctx, broken_active=True, fail_unswitch=True)
            state = toolchains.load_state(ctx)
            packet = {"step": "toolchain_go_user", **toolchains._update(driver, state)}
            self.assertEqual(packet["status"], "failed")
            self.assertIn("rollback NOT verified", packet["error"])
            self.assertEqual(state["replaced"][0]["state"], "rollback_unverified")
            items = report._p1_events({"steps": [packet]})
            self.assertIn("needs", [i["kind"] for i in items])
            self.assertIn("restore 1.27.3", next(i for i in items if i["kind"] == "needs")["todo"])
            ctx.now = lambda: NOW + timedelta(days=30)
            self.assertEqual(toolchains._prune(driver, state), ([], []))


class RetentionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        root = self.home / ".rbenv"
        for version in ("3.3.12", "3.4.11", "4.0.6", "4.0.7", "4.0.8"):
            (root / "versions" / version / "bin").mkdir(parents=True)
        (root / "version").write_text("4.0.8\n")
        shims = root / "shims"
        shims.mkdir()
        for name, body in (("ruby", "printf 4.0.8"), ("gem", "echo 4.0.20")):
            (shims / name).write_text(_script(body))
            (shims / name).chmod(0o755)
        fakebin = self.home / "fakebin"
        fakebin.mkdir()
        (fakebin / "rbenv").write_text(_script(
            'case "$1" in\n'
            '  global) cat "$RBENV_ROOT/version";;\n'
            '  uninstall) rm -rf "$RBENV_ROOT/versions/$3";;\n'
            '  *) exit 2;;\nesac'))
        (fakebin / "rbenv").chmod(0o755)
        (self.home / "dev" / "app").mkdir(parents=True)
        (self.home / "dev" / "app" / ".ruby-version").write_text("3.4.11\n")
        (self.home / "scripts").mkdir()
        (self.home / "scripts" / "run.sh").write_text("RBENV_VERSION=4.0.6 bundle exec rake\n")
        self.ctx = toolchains.Ctx(
            home=self.home, now=lambda: NOW,
            env={"PATH": f"{fakebin}:{os.environ['PATH']}"})
        self.driver = toolchains.drivers(self.ctx)["toolchain_ruby"]

    def _record(self, version, installed, days):
        return {"key": "ruby", "version": version, "installed": installed,
                "replaced_at": (NOW - timedelta(days=days)).isoformat(), "state": "replaced"}

    def test_prunes_only_old_unpinned_versions_it_replaced(self):
        state = {"replaced": [
            self._record("4.0.7", "4.0.8", 8),    # unpinned, old: removed
            self._record("4.0.6", "4.0.7", 20),   # pinned by RBENV_VERSION in ~/scripts
            self._record("3.4.11", "4.0.6", 30),  # pinned by ~/dev/app/.ruby-version
        ], "last": {}}
        removed, notes = toolchains._prune(self.driver, state)
        self.assertEqual(removed, ["4.0.7"])
        versions = sorted(p.name for p in (self.home / ".rbenv/versions").iterdir())
        # 3.3.12 was never replaced by P1, so it is never touched.
        self.assertEqual(versions, ["3.3.12", "3.4.11", "4.0.6", "4.0.8"])
        self.assertEqual(sorted(r["version"] for r in state["replaced"]), ["3.4.11", "4.0.6"])
        self.assertEqual(notes, ["kept 4.0.6: pinned", "kept 3.4.11: pinned"])

    def test_keeps_young_replacements_and_when_current_smoke_fails(self):
        state = {"replaced": [self._record("4.0.7", "4.0.8", 6)], "last": {}}
        self.assertEqual(toolchains._prune(self.driver, state), ([], []))
        state["replaced"][0]["replaced_at"] = (NOW - timedelta(days=9)).isoformat()
        (self.home / ".rbenv/shims/ruby").write_text(_script("exit 1"))
        removed, notes = toolchains._prune(self.driver, state)
        self.assertEqual(removed, [])
        self.assertIn("failed its smoke test", notes[0])
        self.assertTrue((self.home / ".rbenv/versions/4.0.7").exists())

    def test_tree_prune_never_removes_paths_outside_its_rollback_dir(self):
        fx = GoUserFixture(self)
        ctx = fx.ctx()
        driver = toolchains.drivers(ctx)["toolchain_go_user"]
        outside = fx.home / ".local" / "go-1.27.2.bak"
        _write_tree(outside, "1.27.2")
        state = {"replaced": [{"key": "go-user", "version": "1.27.2", "installed": "1.27.3",
                               "replaced_at": (NOW - timedelta(days=9)).isoformat(),
                               "state": "replaced", "path": str(outside)}], "last": {}}
        removed, notes = toolchains._prune(driver, state)
        self.assertEqual(removed, [])
        self.assertTrue(outside.exists())
        self.assertIn("not a rollback tree", notes[0])


class AuditEvidenceTests(unittest.TestCase):
    def test_large_untracked_directory_is_one_status_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            git_dir = home / ".dotfiles-homelab"
            subprocess.run(["git", "init", "-q", "--bare", str(git_dir)], check=True)
            subprocess.run(["git", "--git-dir", str(git_dir), "config",
                            "status.showUntrackedFiles", "all"], check=True)
            (git_dir / "info").mkdir(exist_ok=True)
            (git_dir / "info" / "exclude").write_text("/.dotfiles-homelab/\n")
            bak = home / ".local" / "go1.27.2.bak"
            for index in range(200):
                (bak / f"pkg{index}").mkdir(parents=True)
                (bak / f"pkg{index}" / "file.go").write_text("package x\n")
            with patch.object(audit, "HOME", home):
                evidence = audit._audit_collector_5_config_drift()
        self.assertEqual(evidence["dotfiles_status"].splitlines(), ["?? .local/"])


if __name__ == "__main__":
    unittest.main()
