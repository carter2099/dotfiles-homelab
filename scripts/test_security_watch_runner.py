#!/usr/bin/env python3
"""Offline tests for security-watch notify/report/runner (incl. the node2shell replay)."""

import contextlib
import dataclasses
import io
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from security_watch import config, feeds, model, notify, report, runner  # noqa: E402
from security_watch.model import Finding, Inventory, Package, Signal  # noqa: E402
from security_watch.store import Store  # noqa: E402

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
FIXTURE = Path(__file__).resolve().parent / "security_watch" / "fixtures" / "node2shell"


def _specs():
    return {spec.id: spec for spec in config.load_components()}


def _finding(component="freshrss", group="CVE-2026-111497", urgency=model.URGENCY_URGENT, severity="critical",
             name="brotli", version="1.1.0-2"):
    return Finding(
        key=f"{component}|{group}", component_id=component, group=group,
        package=Package("Debian:13", name, version, binary="libbrotli1"),
        advisory_ids=[f"DEBIAN-{group}"], cves=[group], fixed_versions=["1.1.0-2+deb13u1"], fix_available=True,
        severity=severity, kev=True, zero_wire=["node2shell"], urgency=urgency, reasons=["CISA KEV"],
    )


class _StoreCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        env = mock.patch.dict(os.environ, {"SECURITY_WATCH_STATE_DIR": str(self.tmp / "state"),
                                           "DEPLOY_LOCK_DIR": str(self.tmp / "locks"),
                                           "HOME": str(self.tmp / "home")})
        env.start()
        self.addCleanup(env.stop)
        self.store = Store(self.tmp / "state" / "state.sqlite3")
        self.addCleanup(self.store.close)
        self.addCleanup(self._tmp.cleanup)
        self.policy = config.load_policy()
        self.specs = _specs()


class NotifyTests(_StoreCase):
    def _signals(self):
        return [
            Signal(source="php_announce", key="php-1", version="1", title="Upcoming Critical PHP Security Release",
                   url="https://news-web.php.net/php.announce/1", tier=model.TIER_LEAD,
                   urgency_hint="pre-announcement"),
            Signal(source="ransomware_live", key="victim-1", version="1", title="Cloudflare listed by a group",
                   url="https://example.invalid/v", tier=model.TIER_LEAD, urgency_hint="vendor-breach"),
            Signal(source="zero_wire", key="mystery", version="1", title="Mystery <b>bug</b>",
                   url="https://radar.cloudflare.com/security/zero-wire/mystery", tier=model.TIER_CURATED,
                   urgency_hint="needs-attention"),
            Signal(source="zero_wire", key="node2shell", version="1", title="node2shell",
                   url="https://radar.cloudflare.com/security/zero-wire/node2shell", tier=model.TIER_CURATED,
                   urgency_hint="needs-attention", cves=("CVE-2026-111497",)),
            Signal(source="go_releases", key="go1.27.4", version="1.27.4", title="Go 1.27.4 released",
                   url="https://go.dev/doc/devel/release", tier=model.TIER_ISSUER),
        ]

    def test_urgent_items_selects_each_urgent_kind(self):
        self.store.put_inventory(Inventory("freshrss", NOW, "ok", "fp",
                                           packages=[Package(model.RUNTIME_ECOSYSTEM, "php", "8.4.27")]))
        self.store.trip_breaker("verify failed on freshrss", NOW)
        act_result = SimpleNamespace(
            executed=[{"id": 7, "playbook": "steward-freshrss", "component": "freshrss", "status": "rolled_back",
                       "target": "freshrss 1.30.5", "detail": "health failed", "undo": "x"},
                      {"id": 8, "playbook": "apt-security", "component": "host", "status": "verified",
                       "target": "apt", "detail": "", "undo": ""}],
            advanced=[{"id": 9, "playbook": "release-rebuild", "component": "llm-proxy", "status": "unverified",
                       "target": "go1.27.4 rebuild", "detail": "finding still open", "undo": ""}])
        findings = [_finding(), _finding(component="news", urgency=model.URGENCY_NORMAL)]
        items = notify.urgent_items(findings, self._signals(), act_result, self.store, self.policy, self.specs, NOW)
        dedupes = [i["dedupe"] for i in items]
        self.assertEqual(dedupes, [
            "finding:freshrss|CVE-2026-111497",
            "signal:php_announce:php-1",
            "signal:ransomware_live:victim-1",
            "signal:zero_wire:mystery",
            "action:7:rolled_back",
            "action:9:unverified",
            f"breaker:{self.store.breaker()['since']}",
        ])
        self.assertEqual({i["kind"] for i in items},
                         {"finding", "pre-announcement", "vendor-breach", "manual-check", "action", "breaker"})

    def test_php_pre_announcement_needs_a_php_runtime(self):
        self.store.put_inventory(Inventory("news", NOW, "ok", "fp", packages=[Package("Alpine:v3.24", "brotli", "1")]))
        items = notify.urgent_items([], self._signals()[:1], None, self.store, self.policy, self.specs, NOW)
        self.assertEqual(items, [])

    def test_send_urgent_dedupes_and_escapes(self):
        sent = []
        items = notify.urgent_items([_finding()], self._signals()[2:3], None, self.store, self.policy,
                                    self.specs, NOW)
        self.assertTrue(notify.send_urgent(items, store=self.store, policy=self.policy, now=NOW,
                                           send=lambda *a: sent.append(a)))
        self.assertEqual(len(sent), 1)
        subject, body, recipients = sent[0]
        self.assertTrue(subject.startswith("Security watch: 2 urgent — CVE-2026-111497 in freshrss"))
        self.assertEqual(recipients, [self.policy.recipient])
        self.assertIn("Mystery &lt;b&gt;bug&lt;/b&gt;", body)
        self.assertNotIn("<b>bug</b>", body)
        self.assertNotIn("src=", body)
        self.assertFalse(notify.send_urgent(items, store=self.store, policy=self.policy, now=NOW + timedelta(minutes=15),
                                            send=lambda *a: sent.append(a)))
        self.assertEqual(len(sent), 1)

    def _item(self, name, rank=(notify.RANK_FINDING, 4)):
        return {"dedupe": f"finding:{name}|CVE-1", "title": name, "lines": [], "kind": "finding", "rank": rank}

    def test_daily_cap_counts_emails_not_items(self):
        policy = dataclasses.replace(self.policy, urgent_max_per_day=2)
        sent = []

        def send(*args):
            sent.append(args)
        first = [self._item(f"a{n}") for n in range(8)]
        self.assertTrue(notify.send_urgent(first, store=self.store, policy=policy, now=NOW, send=send))
        self.assertTrue(sent[0][0].startswith("Security watch: 8 urgent — a0"))
        self.assertTrue(all(self.store.notified_at(i["dedupe"]) for i in first))
        self.assertTrue(notify.send_urgent(first + [self._item("b")], store=self.store, policy=policy,
                                           now=NOW + timedelta(minutes=15), send=send))
        self.assertTrue(sent[1][0].startswith("Security watch: 1 urgent — b"))
        self.assertFalse(notify.send_urgent([self._item("c")], store=self.store, policy=policy,
                                            now=NOW + timedelta(hours=1), send=send))
        self.assertEqual(len(sent), 2)
        self.assertIsNone(self.store.notified_at("finding:c|CVE-1"))
        self.assertEqual(notify.emails_since(self.store, NOW - timedelta(days=1)), 2)
        self.assertTrue(notify.send_urgent([self._item("c")], store=self.store, policy=policy,
                                           now=NOW + timedelta(hours=25), send=send))
        self.assertEqual(len(sent), 3)

    def test_large_batches_render_most_severe_and_defer_the_rest(self):
        sent = []
        plain = [self._item(f"p{n:02d}") for n in range(28)]
        curated = [self._item("kev-high", (notify.RANK_CURATED_FINDING, 1)),
                   self._item("kev-critical", (notify.RANK_CURATED_FINDING, 0))]
        breaker = {"dedupe": "breaker:x", "title": "Remediation breaker opened", "lines": [], "kind": "breaker",
                   "rank": (notify.RANK_OPERATIONAL, 0)}
        items = plain + curated + [breaker]
        self.assertTrue(notify.send_urgent(items, store=self.store, policy=self.policy, now=NOW,
                                           send=lambda *a: sent.append(a)))
        subject, body, _ = sent[0]
        self.assertEqual(subject, "Security watch: 31 urgent — Remediation breaker opened")
        self.assertIn("+6 more in tonight's steward report", body)
        self.assertLess(body.index("kev-critical"), body.index("kev-high"))
        self.assertLess(body.index("kev-high"), body.index("p00"))
        self.assertIn("p21", body)
        self.assertNotIn("p22", body)
        rendered = {i["dedupe"] for i in [breaker] + curated + plain[:22]}
        for item in items:
            self.assertEqual(self.store.notified_at(item["dedupe"]) is not None, item["dedupe"] in rendered,
                             item["dedupe"])
        self.assertTrue(notify.send_urgent(items, store=self.store, policy=self.policy,
                                           now=NOW + timedelta(minutes=15), send=lambda *a: sent.append(a)))
        self.assertTrue(sent[1][0].startswith("Security watch: 6 urgent — p22"))
        self.assertNotIn("more in tonight", sent[1][1])


REPORT_KEYS = {"schema", "generated_at", "mode", "breaker", "sources", "findings", "unknown", "actions_24h",
               "proposed", "refused", "leads_24h", "resolved_24h", "shadow", "stopgaps", "last_tick"}
STOPGAP_KEYS = {"id", "component", "cves", "description", "since", "remove", "doc", "status"}
FINDING_KEYS = {"key", "component", "exposure", "package", "version", "fixed", "fix_available", "cves",
                "advisories", "kev", "zero_wire", "severity", "summary", "reach", "urgency", "reasons",
                "first_seen", "status"}


class ReportTests(_StoreCase):
    def _all_sources_ok(self, when):
        for name in feeds.SOURCES:
            self.store.record_source(name, ok=True, now=when)

    def _tick(self):
        return {"started": NOW, "finished": NOW, "outcome": "ok"}

    def test_build_report_matches_schema(self):
        self.store.upsert_finding(_finding(component="news", urgency=model.URGENCY_NORMAL), NOW)
        self.store.upsert_finding(_finding(severity="high"), NOW)
        self.store.upsert_finding(_finding(component="blog", severity="critical"), NOW)
        self.store.set_kv("last_unknown", [{"component": "searxng", "reason": "void"}])
        data = report.build_report(self.store, self.policy, self.specs, None, None, self._tick(), NOW)
        self.assertEqual(set(data), REPORT_KEYS)
        self.assertEqual(data["schema"], 1)
        self.assertEqual(data["mode"], self.policy.mode)
        self.assertEqual(set(data["breaker"]), {"open", "reason", "since"})
        self.assertEqual([s["name"] for s in data["sources"]], list(feeds.SOURCES))
        self.assertEqual(set(data["sources"][0]),
                         {"name", "tier", "last_success", "last_error", "consecutive_failures", "ok_rate_7d"})
        self.assertEqual([f["key"] for f in data["findings"]],
                         ["blog|CVE-2026-111497", "freshrss|CVE-2026-111497", "news|CVE-2026-111497"])
        first = data["findings"][1]
        self.assertEqual(set(first), FINDING_KEYS)
        self.assertEqual((first["exposure"], first["package"], first["version"]),
                         ("public", "Debian:13/brotli", "1.1.0-2"))
        self.assertEqual(data["unknown"], [{"component": "searxng", "reason": "void"}])
        self.assertEqual(set(data["shadow"]),
                         {"since", "days", "source_ok_rate", "urgent_sent_7d", "eligible", "criteria"})
        self.assertEqual(data["last_tick"], {"started": model.iso(NOW), "finished": model.iso(NOW), "outcome": "ok"})
        report.write_report(data)
        self.assertTrue(config.report_path().is_file())

    def test_shadow_eligible_after_min_days_with_healthy_sources(self):
        start = NOW - timedelta(days=self.policy.shadow_min_days + 1)
        self.store.record_run(started=start, finished=start, outcome="ok", summary={})
        self._all_sources_ok(NOW - timedelta(hours=1))
        items = [{"dedupe": f"finding:x{n}", "title": f"x{n}", "lines": [], "kind": "finding"} for n in range(2)]
        self.assertTrue(notify.send_urgent(items, store=self.store, policy=self.policy,
                                           now=NOW - timedelta(days=2), send=lambda *a: None))
        shadow = report.build_report(self.store, self.policy, self.specs, None, None, self._tick(), NOW)["shadow"]
        self.assertTrue(shadow["eligible"], shadow)
        self.assertEqual(shadow["criteria"], [])
        self.assertEqual(shadow["days"], float(self.policy.shadow_min_days + 1))
        self.assertEqual(shadow["source_ok_rate"], 1.0)
        self.assertEqual(shadow["urgent_sent_7d"], 1)
        self.assertEqual(shadow["since"], model.iso(start))

    def test_shadow_not_eligible_lists_unmet_criteria(self):
        start = NOW - timedelta(days=3)
        self.store.record_run(started=start, finished=start, outcome="ok", summary={})
        self._all_sources_ok(NOW - timedelta(hours=2))
        self.store.record_source("onecrl", ok=False, now=NOW - timedelta(hours=1), error="boom")
        self.store.trip_breaker("rolled back", NOW)
        shadow = report.build_report(self.store, self.policy, self.specs, None, None, self._tick(), NOW)["shadow"]
        self.assertFalse(shadow["eligible"])
        self.assertEqual(shadow["days"], 3.0)
        self.assertEqual(shadow["source_ok_rate"], 0.5)
        self.assertEqual(len(shadow["criteria"]), 3, shadow["criteria"])
        self.assertIn("onecrl", shadow["criteria"][1])
        self.assertIn("breaker open", shadow["criteria"][2])

    def test_shadow_never_run_is_not_eligible(self):
        shadow = report.build_report(self.store, self.policy, self.specs, None, None, self._tick(), NOW)["shadow"]
        self.assertIsNone(shadow["since"])
        self.assertEqual(shadow["days"], 0.0)
        self.assertEqual(shadow["source_ok_rate"], 0.0)
        self.assertFalse(shadow["eligible"])


class StopgapTests(_StoreCase):
    SG = config.Stopgap(id="sg-brotli", component="freshrss", cves=("CVE-2026-111497",),
                        description="WAF rule blocks brotli request bodies", since="2026-10-25",
                        remove="cloudflare: disable rule sg-brotli", doc="docs/homelab/security-mitigations.md")

    def _status(self):
        rows = report.build_report(self.store, self.policy, self.specs, None, None,
                                   {"started": NOW, "finished": NOW, "outcome": "ok"}, NOW,
                                   stopgaps=[self.SG])["stopgaps"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(set(rows[0]), STOPGAP_KEYS)
        return rows[0]["status"]

    def _items(self):
        return notify.urgent_items([], [], None, self.store, self.policy, self.specs, NOW, stopgaps=[self.SG])

    def test_unverified_when_no_covered_finding_was_seen(self):
        self.store.upsert_finding(_finding(component="news"), NOW)          # other component
        self.store.upsert_finding(_finding(group="CVE-2026-1"), NOW)        # other CVE
        self.store.set_kv("last_complete", ["freshrss", "news"])
        self.assertEqual(self._status(), "unverified")
        self.assertEqual(self._items(), [])

    def test_active_while_a_covered_finding_is_open(self):
        self.store.upsert_finding(_finding(), NOW)
        self.store.set_kv("last_complete", ["freshrss"])
        self.assertEqual(self._status(), "active")
        self.assertEqual(self._items(), [])

    def test_fixed_but_not_completely_scanned_is_not_removable(self):
        self.store.upsert_finding(_finding(), NOW - timedelta(hours=2))
        self.store.close_missing_findings("freshrss", set(), NOW - timedelta(hours=1))
        self.store.set_kv("last_complete", ["news"])
        self.assertEqual(self._status(), "unverified")

    def test_removable_once_fixed_and_scanned_completely_alerts_once(self):
        self.store.upsert_finding(_finding(), NOW - timedelta(hours=2))
        self.store.close_missing_findings("freshrss", set(), NOW - timedelta(hours=1))
        self.store.set_kv("last_complete", ["freshrss"])
        self.assertEqual(self._status(), "removable")
        items = self._items()
        self.assertEqual([i["dedupe"] for i in items], ["stopgap-removable:sg-brotli"])
        self.assertIn("Remove with: cloudflare: disable rule sg-brotli", items[0]["lines"])
        sent = []
        self.assertTrue(notify.send_urgent(items, store=self.store, policy=self.policy, now=NOW,
                                           send=lambda *a: sent.append(a)))
        self.assertFalse(notify.send_urgent(self._items(), store=self.store, policy=self.policy,
                                            now=NOW + timedelta(minutes=15), send=lambda *a: sent.append(a)))
        self.assertEqual(len(sent), 1)
        self.assertIn("Stopgap removable: sg-brotli", sent[0][0])


class TickLockTests(unittest.TestCase):
    def test_second_tick_skips_while_lock_is_held(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state"
            with mock.patch.dict(os.environ, {"SECURITY_WATCH_STATE_DIR": str(state), "HOME": tmp}):
                with runner.tick_lock() as first:
                    self.assertTrue(first)
                    with runner.tick_lock() as second:
                        self.assertFalse(second)
                    out = io.StringIO()
                    with mock.patch.object(runner, "run_tick", side_effect=AssertionError("must not run")), \
                            contextlib.redirect_stdout(out):
                        self.assertEqual(runner.main(["tick"]), 0)
                    self.assertIn("skipping", out.getvalue())
                with runner.tick_lock() as again:
                    self.assertTrue(again)

    def test_steward_active_reads_systemctl(self):
        calls = []

        def run(argv, **_kw):
            calls.append(argv)
            state = "activating" if argv[-1] == config.STEWARD_UNITS[-1] else "inactive"
            return SimpleNamespace(returncode=0, stdout=f"{state}\n")
        self.assertTrue(runner.steward_active(run=run))
        self.assertEqual(calls[0][:6], ["systemctl", "--user", "show", "-p", "ActiveState", "--value"])
        self.assertFalse(runner.steward_active(run=lambda argv, **kw: SimpleNamespace(returncode=0, stdout="inactive")))
        self.assertTrue(runner.steward_active(run=lambda argv, **kw: SimpleNamespace(returncode=1, stdout="")))


class ReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        tmp = Path(cls._tmp.name)
        env = {"HOME": str(tmp / "home"), "SECURITY_WATCH_STATE_DIR": str(tmp / "unused-state"),
               "DEPLOY_LOCK_DIR": str(tmp / "unused-locks")}
        with mock.patch.dict(os.environ, env), contextlib.redirect_stderr(io.StringIO()), \
                mock.patch("security_watch.net.fetch", side_effect=AssertionError("network in replay")):
            cls.result = runner.replay(FIXTURE)
        cls.unused_state = tmp / "unused-state"

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def setUp(self):
        self.report = self.result["report"]
        self.findings = {f["key"]: f for f in self.report["findings"]}

    def test_freshrss_finding_is_urgent_kev_and_zero_wire(self):
        fresh = self.findings["freshrss|CVE-2026-111497"]
        self.assertEqual(fresh["urgency"], "urgent")
        self.assertTrue(fresh["kev"])
        self.assertEqual(fresh["zero_wire"], ["node2shell"])
        self.assertEqual(fresh["fixed"], ["1.1.0-2+deb13u1"])
        self.assertEqual(fresh["exposure"], "public")

    def test_news_affected_and_host_clean(self):
        self.assertIn("news|CVE-2026-111497", self.findings)
        self.assertEqual([k for k, f in self.findings.items()
                          if f["component"] == "host" and f["package"].endswith("/brotli")], [])

    def test_bun_repo_advisory_names_fix(self):
        bun = [f for f in self.findings.values() if f["component"] == "bun"]
        self.assertTrue(bun)
        self.assertTrue(all(f["fixed"] == ["1.4.4"] for f in bun), bun)

    def test_shadow_mode_executes_nothing_and_sends_one_email(self):
        self.assertEqual(self.report["mode"], "shadow")
        self.assertEqual(self.report["actions_24h"], [])
        self.assertEqual(len(self.result["outbox"]), 1)
        self.assertIn("urgent", self.result["outbox"][0])

    def test_replay_never_touches_the_configured_state_dir(self):
        self.assertFalse(self.unused_state.exists())


if __name__ == "__main__":
    unittest.main()
