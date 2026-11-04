import os
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from security_watch import config, store  # noqa: E402
from security_watch.model import (  # noqa: E402
    AdvisoryPackage,
    Finding,
    Inventory,
    Package,
    Plan,
    Reach,
    Refusal,
    Signal,
    iso,
)

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
HOUR = timedelta(hours=1)


def make_finding(key="freshrss|CVE-2026-111497", component="freshrss", **kw):
    fields = dict(
        key=key,
        component_id=component,
        group=key.split("|", 1)[1],
        package=Package("Debian:13", "brotli", "1.1.0-2", binary="libbrotli1"),
        advisory_ids=["DEBIAN-CVE-2026-111497"],
        cves=["CVE-2026-111497"],
        fixed_versions=["1.1.0-2+deb13u1"],
        fix_available=True,
        severity="critical",
    )
    fields.update(kw)
    return Finding(**fields)


def make_plan(component="freshrss", target="freshrss 1.30.5"):
    return Plan(playbook="steward-freshrss", component_id=component,
                finding_keys=[f"{component}|CVE-2026-111497"], target=target,
                lock_keys=["freshrss"], steps=["pull", "up"], undo="undo-cmd",
                fixed_version="1.1.0-2+deb13u1", state={"tag": "1.30.5"})


class StoreTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = mock.patch.dict(os.environ, {"SECURITY_WATCH_STATE_DIR": str(Path(self.tmp.name) / "state"),
                                           "HOME": self.tmp.name})
        env.start()
        self.addCleanup(env.stop)
        self.store = store.Store()
        self.addCleanup(self.store.close)


class OpenTests(StoreTestCase):
    def test_default_path_uses_private_state_dir_and_file(self):
        path = config.db_path()
        self.assertEqual(self.store.path, path)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_reopen_is_idempotent_and_keeps_data(self):
        self.store.set_kv("go_stable", ["1.27.3"])
        version = self.store.schema_version
        self.store.close()
        with store.Store() as again:
            self.assertEqual(again.schema_version, version)
            self.assertEqual(again.get_kv("go_stable"), ["1.27.3"])
            mode = again._conn.execute("PRAGMA journal_mode").fetchone()[0]
            self.assertEqual(mode.lower(), "wal")

    def test_kv_default_and_round_trip(self):
        self.assertEqual(self.store.get_kv("missing", {"a": 1}), {"a": 1})
        self.store.set_kv("php_active", {"8.4": {"version": "8.4.27"}})
        self.assertEqual(self.store.get_kv("php_active"), {"8.4": {"version": "8.4.27"}})


class SourceTests(StoreTestCase):
    def test_unknown_source_has_empty_state(self):
        state = self.store.source_state("kev")
        self.assertEqual(state["consecutive_failures"], 0)
        self.assertIsNone(state["last_attempt"])
        self.assertEqual(state["state"], {})

    def test_none_keeps_previous_values_and_failures_count(self):
        self.store.record_source("kev", ok=True, now=NOW, cursor="v1", etag='"e1"',
                                 last_modified="Tue, 03 Nov 2026 10:00:00 GMT", state={"seen": 3})
        self.store.record_source("kev", ok=False, now=NOW + HOUR, error="timeout")
        self.store.record_source("kev", ok=False, now=NOW + 2 * HOUR, error="HTTP 503")
        state = self.store.source_state("kev")
        self.assertEqual(state["cursor"], "v1")
        self.assertEqual(state["etag"], '"e1"')
        self.assertEqual(state["last_modified"], "Tue, 03 Nov 2026 10:00:00 GMT")
        self.assertEqual(state["state"], {"seen": 3})
        self.assertEqual(state["consecutive_failures"], 2)
        self.assertEqual(state["last_error"], "HTTP 503")
        self.assertEqual(state["last_success"], iso(NOW))
        self.assertEqual(state["last_attempt"], iso(NOW + 2 * HOUR))

        self.store.record_source("kev", ok=True, now=NOW + 3 * HOUR, cursor={"v": 2})
        state = self.store.source_state("kev")
        self.assertEqual(state["consecutive_failures"], 0)
        self.assertEqual(state["last_error"], "")
        self.assertEqual(state["cursor"], {"v": 2})
        self.assertEqual(state["etag"], '"e1"')

    def test_ok_rate_counts_attempts_since(self):
        self.assertIsNone(self.store.source_ok_rate("osv", NOW))
        self.store.record_source("osv", ok=False, now=NOW - 10 * HOUR, error="old")
        for i, ok in enumerate([True, True, False, True]):
            self.store.record_source("osv", ok=ok, now=NOW + i * HOUR, error=None if ok else "x")
        self.store.record_source("other", ok=False, now=NOW, error="x")
        self.assertAlmostEqual(self.store.source_ok_rate("osv", NOW), 0.75)
        self.assertAlmostEqual(self.store.source_ok_rate("osv", NOW - 11 * HOUR), 0.6)
        self.assertEqual(self.store.source_ok_rate("other", NOW), 0.0)

    def test_record_run_prunes_old_attempts_and_runs(self):
        old = NOW - timedelta(days=31)
        self.store.record_source("osv", ok=False, now=old, error="x")
        self.store.record_run(started=old, finished=old, outcome="ok", summary={})
        self.store.record_source("osv", ok=True, now=NOW)
        self.store.record_run(started=NOW, finished=NOW + HOUR / 4, outcome="degraded", summary={"n": 1})
        self.assertEqual(self.store.source_ok_rate("osv", old - HOUR), 1.0)
        runs = self.store.runs_since(old - HOUR)
        self.assertEqual([r["outcome"] for r in runs], ["degraded"])
        self.assertEqual(runs[0]["summary"], {"n": 1})
        self.assertEqual(self.store.first_run_at(), old)


class SignalTests(StoreTestCase):
    def sig(self, version="g1", **kw):
        fields = dict(source="github_advisories", key="oven-sh/bun#GHSA-x", version=version,
                      title="Bun advisory", url="https://github.com/oven-sh/bun", tier="issuer",
                      cves=("CVE-2026-1",),
                      packages=(AdvisoryPackage("npm", "bun", ">= 1.0.21, < 1.4.4", ("1.4.4",)),))
        fields.update(kw)
        return Signal(**fields)

    def test_new_updated_same(self):
        self.assertEqual(self.store.upsert_signal(self.sig(), NOW), "new")
        self.assertEqual(self.store.upsert_signal(self.sig(), NOW + HOUR), "same")
        self.assertEqual(self.store.upsert_signal(self.sig("g2", title="t2"), NOW + 2 * HOUR), "updated")
        got = self.store.signal("github_advisories", "oven-sh/bun#GHSA-x")
        self.assertEqual(got, self.sig("g2", title="t2"))
        self.assertIsInstance(got.packages[0], AdvisoryPackage)
        self.assertEqual(got.packages[0].fixed, ("1.4.4",))
        self.assertIsNone(self.store.signal("github_advisories", "nope"))

    def test_signals_since_and_source_filter(self):
        self.store.upsert_signal(self.sig(), NOW - 5 * HOUR)
        self.store.upsert_signal(self.sig(key="other"), NOW)
        self.store.upsert_signal(Signal(source="kev", key="CVE-2026-2", version="1", title="k",
                                        url="", tier="curated"), NOW)
        recent = self.store.signals_since(NOW - HOUR)
        self.assertEqual(sorted(s.key for s, _, _ in recent), ["CVE-2026-2", "other"])
        only = self.store.signals_since(NOW - 10 * HOUR, sources={"github_advisories"})
        self.assertEqual([s.key for s, _, _ in only], ["oven-sh/bun#GHSA-x", "other"])
        self.assertEqual(only[0][1], iso(NOW - 5 * HOUR))
        self.assertEqual(self.store.signals_since(NOW - HOUR, sources=[]), [])
        self.assertEqual(len(self.store.all_signals("github_advisories")), 2)


class OsvCacheTests(StoreTestCase):
    def test_round_trip_with_fetched_at(self):
        self.assertIsNone(self.store.osv_get("GO-2026-1"))
        self.store.osv_put("GO-2026-1", {"id": "GO-2026-1", "aliases": ["CVE-2026-3"]}, NOW)
        record, fetched = self.store.osv_get("GO-2026-1")
        self.assertEqual(record["aliases"], ["CVE-2026-3"])
        self.assertEqual(fetched, NOW)


class FindingTests(StoreTestCase):
    def test_first_seen_is_preserved_and_changes_are_detected(self):
        f = make_finding()
        self.assertEqual(self.store.upsert_finding(f, NOW), "new")
        self.assertEqual(f.first_seen, iso(NOW))
        again = make_finding()
        self.assertEqual(self.store.upsert_finding(again, NOW + HOUR), "same")
        self.assertEqual(again.first_seen, iso(NOW))
        changed = make_finding(kev=True, reach=Reach("reachable", "agent+jev", p=0.9))
        self.assertEqual(self.store.upsert_finding(changed, NOW + 2 * HOUR), "updated")
        self.assertEqual(changed.first_seen, iso(NOW))
        stored = self.store.get_finding(f.key)
        self.assertTrue(stored.kev)
        self.assertEqual(stored.first_seen, iso(NOW))
        self.assertIsInstance(stored.package, Package)
        self.assertEqual(stored.reach, Reach("reachable", "agent+jev", p=0.9))

    def test_close_missing_only_touches_that_component(self):
        keep = make_finding("freshrss|CVE-2026-1")
        gone = make_finding("freshrss|CVE-2026-2")
        other = make_finding("blog|CVE-2026-2", component="blog")
        for f in (keep, gone, other):
            self.store.upsert_finding(f, NOW)
        closed = self.store.close_missing_findings("freshrss", {keep.key}, NOW + HOUR)
        self.assertEqual(closed, [gone.key])
        self.assertEqual(self.store.get_finding(gone.key).status, "fixed")
        self.assertEqual(sorted(f.key for f in self.store.open_findings()), sorted([keep.key, other.key]))
        self.assertEqual([f.key for f in self.store.findings_resolved_since(NOW)], [gone.key])
        self.assertEqual(self.store.close_missing_findings("freshrss", {keep.key}, NOW + 2 * HOUR), [])
        self.assertEqual([f.key for f in self.store.findings_resolved_since(NOW + 90 * timedelta(minutes=1))], [])

    def test_reopened_finding_keeps_first_seen_and_clears_resolution(self):
        f = make_finding()
        self.store.upsert_finding(f, NOW)
        self.store.close_missing_findings("freshrss", set(), NOW + HOUR)
        back = make_finding()
        self.assertEqual(self.store.upsert_finding(back, NOW + 2 * HOUR), "updated")
        self.assertEqual(back.first_seen, iso(NOW))
        self.assertEqual([x.key for x in self.store.open_findings()], [f.key])
        self.assertEqual(self.store.findings_resolved_since(NOW), [])


class ReachAndInventoryTests(StoreTestCase):
    def test_reach_round_trip(self):
        reach = Reach("not_reachable", "govulncheck", p=None, summary="symbol not called",
                      evidence=[{"file": "main.go", "line": 3, "note": "n"}],
                      assessed_at=iso(NOW), cache_key="k1")
        self.assertIsNone(self.store.get_reach("k1"))
        self.store.put_reach("k1", reach, NOW)
        self.assertEqual(self.store.get_reach("k1"), reach)

    def test_inventory_round_trip_latest_per_component(self):
        inv = Inventory("blog", NOW - HOUR, "ok", "sha256:aa",
                        packages=[Package("Debian:12", "brotli", "1.0.9-2", "libbrotli1", "/var/lib/dpkg")],
                        meta={"os": "debian 12", "binaries": [{"path": "/usr/local/bin/thrust"}]})
        newer = Inventory("blog", NOW, "partial", "sha256:bb", reason="gems unreadable")
        self.store.put_inventory(inv)
        self.assertEqual(self.store.get_inventory("blog"), inv)
        self.store.put_inventory(newer)
        got = self.store.get_inventory("blog")
        self.assertEqual(got, newer)
        self.assertEqual(got.collected_at, NOW)
        self.assertEqual([i.component_id for i in self.store.inventories()], ["blog"])
        self.assertIsNone(self.store.get_inventory("missing"))


class ActionJournalTests(StoreTestCase):
    def test_counts_active_last_action_and_proposals(self):
        shadow = self.store.start_action(make_plan(), mode="shadow", status="proposed", now=NOW - 2 * HOUR)
        a1 = self.store.start_action(make_plan(), mode="active", status="running", now=NOW - HOUR)
        a2 = self.store.start_action(make_plan("blog", "blog rebuild"), mode="active", status="running", now=NOW)
        refused = self.store.start_action(make_plan("news"), mode="active", status="refused", now=NOW)
        self.store.update_action(a1, status="verified", detail="ok", now=NOW, undo="u2",
                                 state={"production_touched": True}, finished=True)
        self.store.update_action(a2, status="pending", detail="waiting", now=NOW)

        self.assertEqual(self.store.executed_actions_since(NOW - 3 * HOUR), 2)
        self.assertEqual(self.store.executed_actions_since(NOW - HOUR / 2), 1)
        self.assertEqual([a["id"] for a in self.store.active_actions()], [a2])
        last = self.store.last_action("freshrss")
        self.assertEqual(last["id"], a1)
        self.assertEqual(last["status"], "verified")
        self.assertEqual(last["undo"], "u2")
        self.assertEqual(last["state"], {"production_touched": True})
        self.assertEqual(last["finished_at"], iso(NOW))
        self.assertEqual(store.plan_from_dict(last["plan"]), make_plan())
        self.assertEqual(self.store.last_action("freshrss", mode="shadow")["id"], shadow)
        self.assertIsNone(self.store.last_action("missing"))

        self.assertTrue(self.store.proposal_exists("freshrss", "freshrss 1.30.5", NOW - 3 * HOUR))
        self.assertFalse(self.store.proposal_exists("freshrss", "freshrss 1.30.5", NOW - HOUR))
        self.assertFalse(self.store.proposal_exists("freshrss", "other target", NOW - 3 * HOUR))
        self.assertFalse(self.store.proposal_exists("blog", "blog rebuild", NOW - 3 * HOUR))

        recent = self.store.actions_since(NOW - HOUR / 2)
        self.assertEqual([a["id"] for a in recent], [a1, a2, refused])
        got = self.store.get_action(shadow)
        self.assertEqual(got["finding_keys"], ["freshrss|CVE-2026-111497"])
        self.assertEqual(got["mode"], "shadow")
        self.assertIsNone(got["finished_at"])
        with self.assertRaises(KeyError):
            self.store.get_action(9999)


class NotificationBreakerRefusalTests(StoreTestCase):
    def test_notifications(self):
        self.assertIsNone(self.store.notified_at("k"))
        self.store.record_notification("k", "subject", NOW - HOUR)
        self.store.record_notification("k", "subject", NOW)
        self.store.record_notification("j", "subject", NOW - 5 * HOUR)
        self.assertEqual(self.store.notified_at("k"), NOW)
        self.assertEqual(self.store.notifications_since(NOW - 2 * HOUR), 2)

    def test_breaker_trip_and_reset(self):
        self.assertEqual(self.store.breaker(), {"open": False, "reason": "", "since": None})
        self.store.trip_breaker("rollback on freshrss", NOW)
        self.store.trip_breaker("second failure", NOW + HOUR)
        self.assertEqual(self.store.breaker(), {"open": True, "reason": "rollback on freshrss", "since": iso(NOW)})
        self.store.reset_breaker(NOW + 2 * HOUR)
        self.assertEqual(self.store.breaker(), {"open": False, "reason": "", "since": None})
        self.store.trip_breaker("again", NOW + 3 * HOUR)
        self.assertEqual(self.store.breaker()["since"], iso(NOW + 3 * HOUR))

    def test_refusals_keep_latest_per_component_playbook(self):
        r = Refusal("steward-freshrss", "freshrss", "no newer image", alert=True)
        self.store.record_refusal(r, NOW - 2 * HOUR)
        self.store.record_refusal(r, NOW)
        rows = self.store.refusals_since(NOW - HOUR)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["since"], iso(NOW - 2 * HOUR))
        self.assertEqual(rows[0]["component"], "freshrss")
        self.store.record_refusal(Refusal("steward-freshrss", "freshrss", "lock busy", alert=False), NOW + HOUR)
        rows = self.store.refusals_since(NOW - HOUR)
        self.assertEqual((rows[0]["reason"], rows[0]["alert"], rows[0]["since"]), ("lock busy", False, iso(NOW + HOUR)))
        self.assertEqual(self.store.refusals_since(NOW + 2 * HOUR), [])


if __name__ == "__main__":
    unittest.main()
