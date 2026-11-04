#!/usr/bin/env python3
"""deploy_lock: cross-process exclusion, shared coexistence, re-entrancy, order."""
from __future__ import annotations

import fcntl
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import deploy_lock  # noqa: E402

# Child process: take one lock, report "ready", hold it until stdin gets a line.
CHILD = r"""
import sys
sys.path.insert(0, sys.argv[1])
import deploy_lock
key, mode, holder = sys.argv[2], sys.argv[3], sys.argv[4]
if mode == "host":
    lock = deploy_lock.host_lock(holder=holder)
else:
    lock = deploy_lock.service_lock(key, shared=(mode == "shared"), holder=holder)
with lock:
    print("ready", flush=True)
    sys.stdin.readline()
"""


class DeployLockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name) / "locks"
        env = patch.dict(os.environ, {"DEPLOY_LOCK_DIR": str(self.dir)})
        env.start()
        self.addCleanup(env.stop)
        self.assertEqual(deploy_lock._HELD, {})

    def tearDown(self):
        self.assertEqual(deploy_lock._HELD, {}, "a test leaked a held lock")

    def hold(self, key, mode="exclusive", holder="child:test"):
        """Start a child process holding ``key``; returns it once the lock is held."""
        proc = subprocess.Popen(
            [sys.executable, "-c", CHILD, str(SCRIPTS), key, mode, holder],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
            env={**os.environ, "DEPLOY_LOCK_DIR": str(self.dir)},
        )

        def stop():
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=10)
            for stream in (proc.stdin, proc.stdout):
                stream.close()

        self.addCleanup(stop)
        self.assertEqual(proc.stdout.readline().strip(), "ready")
        return proc

    def release(self, proc):
        proc.stdin.write("\n")
        proc.stdin.flush()
        self.assertEqual(proc.wait(timeout=10), 0)

    def locked_elsewhere(self, key):
        """True when another open file description holds ``key`` (any mode)."""
        path = self.dir / f"{key}.lock"
        if not path.exists():
            return False
        fd = os.open(path, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        finally:
            os.close(fd)
        return False

    def test_exclusive_lock_blocks_a_second_process(self):
        child = self.hold("freshrss", holder="security-watch:steward-freshrss")
        with self.assertRaises(deploy_lock.LockTimeout) as caught:
            with deploy_lock.service_lock("freshrss", timeout=0):
                self.fail("acquired a lock another process holds")
        error = caught.exception
        self.assertEqual(error.key, "freshrss")
        self.assertIn("security-watch:steward-freshrss", error.holder)
        self.assertEqual(error.info["pid"], child.pid)
        self.assertEqual(error.info["mode"], "exclusive")
        self.assertIn("deploy lock freshrss held by", str(error))
        self.release(child)
        with deploy_lock.service_lock("freshrss", timeout=0, holder="steward:freshrss"):
            self.assertIn("freshrss", deploy_lock._HELD)

    def test_positive_timeout_polls_until_it_expires(self):
        self.hold("omp")
        started = time.monotonic()
        with self.assertRaises(deploy_lock.LockTimeout):
            with deploy_lock.service_lock("omp", timeout=0.6):
                self.fail("acquired a held lock")
        self.assertGreaterEqual(time.monotonic() - started, 0.5)

    def test_shared_locks_coexist_across_processes_and_exclude_exclusive(self):
        child = self.hold("host", mode="shared")
        with deploy_lock.service_lock("host", shared=True, timeout=0):
            self.assertEqual(deploy_lock._HELD["host"][1], "shared")
        with self.assertRaises(deploy_lock.LockTimeout):
            with deploy_lock.host_lock(timeout=0):
                self.fail("host exclusive while a surface holds host shared")
        self.release(child)
        with deploy_lock.host_lock(timeout=0):
            pass

    def test_same_mode_is_reentrant_and_released_at_the_last_exit(self):
        with deploy_lock.service_lock("searxng", holder="outer"):
            with deploy_lock.service_lock("searxng", timeout=0, holder="inner"):
                self.assertEqual(deploy_lock._HELD["searxng"][0], 2)
            self.assertEqual(deploy_lock._HELD["searxng"][0], 1)
            self.assertTrue(self.locked_elsewhere("searxng"))
        self.assertNotIn("searxng", deploy_lock._HELD)
        self.assertFalse(self.locked_elsewhere("searxng"))

    def test_mode_mismatch_in_one_process_raises(self):
        with deploy_lock.service_lock("news"):
            with self.assertRaises(RuntimeError):
                with deploy_lock.service_lock("news", shared=True):
                    self.fail("converted exclusive to shared")
            self.assertEqual(deploy_lock._HELD["news"][0], 1)
        with deploy_lock.host_lock():
            with self.assertRaises(RuntimeError):
                with deploy_lock.surface_lock("freshrss"):
                    self.fail("took host shared under host exclusive")
            self.assertNotIn("freshrss", deploy_lock._HELD)

    def test_surface_lock_takes_host_shared_before_the_key(self):
        with deploy_lock.surface_lock("app-blog", holder="steward:app_deploy"):
            self.assertEqual(deploy_lock._HELD["host"][1], "shared")
            self.assertEqual(deploy_lock._HELD["app-blog"][1], "exclusive")
        child = self.hold("host", mode="host")
        with self.assertRaises(deploy_lock.LockTimeout) as caught:
            with deploy_lock.surface_lock("app-blog", timeout=0):
                self.fail("surface lock under a host-exclusive holder")
        self.assertEqual(caught.exception.key, "host")
        self.assertFalse(self.locked_elsewhere("app-blog"))
        self.release(child)

    def test_surface_lock_waits_for_a_busy_key_without_blocking_other_surfaces(self):
        child = self.hold("open-webui")
        with self.assertRaises(deploy_lock.LockTimeout) as caught:
            with deploy_lock.surface_lock("open-webui", timeout=0):
                self.fail("acquired a held surface")
        self.assertEqual(caught.exception.key, "open-webui")
        self.assertNotIn("host", deploy_lock._HELD)
        with deploy_lock.surface_lock("freshrss", timeout=0):
            pass
        self.release(child)

    def test_holders_reports_live_holders_only(self):
        child = self.hold("toolchain-node", holder="steward:toolchain_node")
        with deploy_lock.service_lock("llama-cpp", holder="steward:llama_cpp"):
            held = deploy_lock.holders()
        self.assertEqual(held["toolchain-node"]["holder"], "steward:toolchain_node")
        self.assertEqual(held["toolchain-node"]["pid"], child.pid)
        self.assertEqual(held["toolchain-node"]["mode"], "exclusive")
        self.assertEqual(held["llama-cpp"]["pid"], os.getpid())
        self.assertTrue(held["llama-cpp"]["since"])
        self.release(child)
        self.assertEqual(deploy_lock.holders(), {})

    def test_lock_files_are_private_and_keys_are_validated(self):
        with deploy_lock.service_lock("herdr"):
            pass
        self.assertEqual(stat.S_IMODE(self.dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.dir / "herdr.lock").stat().st_mode) & 0o077, 0)
        for bad in ("", "Host", "-x", "a/b", "../x", "x" * 65):
            with self.subTest(key=bad), self.assertRaises(ValueError):
                with deploy_lock.service_lock(bad):
                    pass

    def test_symlinked_lock_file_is_refused(self):
        self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        target = Path(self.tmp.name) / "elsewhere"
        target.write_text("")
        (self.dir / "freshrss.lock").symlink_to(target)
        with self.assertRaises(OSError):
            with deploy_lock.service_lock("freshrss", timeout=0):
                self.fail("followed a symlinked lock file")


if __name__ == "__main__":
    unittest.main()
