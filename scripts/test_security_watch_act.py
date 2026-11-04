import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import contextlib
import dataclasses
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from security_watch import act, config, model
from security_watch.model import Finding, Outcome, Package, Plan, Refusal
from security_watch.store import Store

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)


def make_policy(mode="active", **overrides):
    policy = dataclasses.replace(
        config.load_policy(), mode=mode, max_actions_per_day=3, component_cooldown_hours=12,
        release_min_age_hours=72, tick_budget_seconds=600)
    return dataclasses.replace(policy, **overrides)


def make_spec(cid, owner, **extra):
    repo = extra.pop("repo", "")
    return config.ComponentSpec(id=cid, kind="container", collector="container", exposure="public",
                                owner=owner, lock=cid, repo=repo, extra=extra)


def make_finding(cid="freshrss", cve="CVE-2026-1001", eco="Debian:13", name="brotli",
                 version="1.1.0-2", binary="", fixed="1.1.0-2+deb13u1", urgency=model.URGENCY_NORMAL):
    return Finding(key=f"{cid}|{cve}", component_id=cid, group=cve,
                   package=Package(eco, name, version, binary=binary),
                   advisory_ids=[f"DEBIAN-{cve}"], cves=[cve], fixed_versions=[fixed],
                   fix_available=True, urgency=urgency)


class FakePlaybook:
    def __init__(self, pid, *, multi_tick=False, outcome=None, advance_outcome=None,
                 refusal=None, release_published=None, apply_error=None):
        self.id = pid
        self.multi_tick = multi_tick
        self.outcome = outcome or Outcome("done", "installed", undo="undo-cmd",
                                          state={"production_touched": True})
        self.advance_outcome = advance_outcome
        self.refusal = refusal
        self.release_published = release_published
        self.apply_error = apply_error
        self.plans = []
        self.applied = []
        self.advanced = []

    def plan(self, findings, spec, ctx):
        self.plans.append([f.key for f in findings])
        if self.refusal:
            return Refusal(self.id, spec.id, self.refusal, alert=True)
        return Plan(playbook=self.id, component_id=spec.id, finding_keys=[f.key for f in findings],
                    target=f"{spec.id} fixed", lock_keys=[spec.lock], steps=["update"], undo="undo-cmd",
                    release_published=self.release_published, fixed_version="1.1.0-2+deb13u1")

    def apply(self, plan, ctx):
        self.applied.append(plan)
        if self.apply_error:
            raise self.apply_error
        return self.outcome

    def advance(self, action, ctx):
        self.advanced.append(action)
        return self.advance_outcome


class ActTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"SECURITY_WATCH_STATE_DIR": self.tmp.name, "HOME": self.tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.store = Store(Path(self.tmp.name) / "state.sqlite3")
        self.addCleanup(self.store.close)
        self.rescans = []
        self.remaining = {}
        self.steward = False

    def ctx(self, *, mode="active", now=NOW, specs=None, **policy):
        specs = specs or {"freshrss": make_spec("freshrss", "steward-freshrss")}

        def rescan(cid):
            self.rescans.append(cid)
            return list(self.remaining.get(cid, []))

        return act.ActCtx(store=self.store, policy=make_policy(mode, **policy), specs=specs, now=now,
                          run=lambda *a, **k: None, fetch=lambda *a, **k: None,
                          lock=lambda *a, **k: contextlib.nullcontext(),
                          host_lock=lambda *a, **k: contextlib.nullcontext(),
                          steward_active=lambda: self.steward, rescan=rescan, findings={})

    def record_executed(self, cid, *, at, status="verified"):
        plan = Plan(playbook="steward-freshrss", component_id=cid, finding_keys=[f"{cid}|CVE-2026-9"],
                    target=f"{cid} old", lock_keys=[cid], steps=[], undo="")
        action_id = self.store.start_action(plan, mode="active", status="running", now=at)
        self.store.update_action(action_id, status=status, detail="done", now=at, finished=True)
        return action_id


class ShadowTests(ActTestBase):
    def test_shadow_records_one_proposal_without_applying_and_dedupes(self):
        pb = FakePlaybook("steward-freshrss")
        registry = {pb.id: pb}
        result = act.act([make_finding()], self.ctx(mode="shadow"), registry=registry)
        self.assertEqual(len(result.proposed), 1)
        self.assertEqual(result.proposed[0]["status"], "proposed")
        self.assertEqual(pb.applied, [])
        again = act.act([make_finding()], self.ctx(mode="shadow", now=NOW + timedelta(minutes=15)),
                        registry=registry)
        self.assertEqual(again.proposed, [])
        self.assertEqual(pb.applied, [])
        actions = self.store.actions_since(NOW - timedelta(days=1))
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["mode"], "shadow")
        self.assertEqual(self.store.executed_actions_since(NOW - timedelta(days=1)), 0)


class GateTests(ActTestBase):
    def test_breaker_open_refuses_all_with_alert(self):
        self.store.trip_breaker("earlier failure", NOW - timedelta(hours=1))
        pb = FakePlaybook("steward-freshrss")
        result = act.act([make_finding()], self.ctx(), registry={pb.id: pb})
        self.assertEqual(pb.plans, [])
        self.assertEqual(len(result.refused), 1)
        self.assertTrue(result.refused[0].alert)
        self.assertIn("breaker", result.refused[0].reason)
        self.assertEqual(len(self.store.refusals_since(NOW - timedelta(hours=1))), 1)

    def test_steward_active_defers_without_alert(self):
        self.steward = True
        pb = FakePlaybook("steward-freshrss")
        result = act.act([make_finding()], self.ctx(), registry={pb.id: pb})
        self.assertEqual(pb.plans, [])
        self.assertEqual(pb.applied, [])
        self.assertEqual(len(result.refused), 1)
        self.assertFalse(result.refused[0].alert)
        self.assertEqual(self.store.refusals_since(NOW - timedelta(hours=1)), [])

    def test_daily_cap_refuses_with_alert(self):
        for i, cid in enumerate(("a", "b", "c")):
            self.record_executed(cid, at=NOW - timedelta(hours=2 + i))
        pb = FakePlaybook("steward-freshrss")
        result = act.act([make_finding()], self.ctx(), registry={pb.id: pb})
        self.assertEqual(pb.applied, [])
        self.assertTrue(result.refused[0].alert)
        self.assertIn("cap", result.refused[0].reason)
        self.assertEqual(len(self.store.refusals_since(NOW - timedelta(hours=1))), 1)

    def test_component_cooldown_defers(self):
        self.record_executed("freshrss", at=NOW - timedelta(hours=2))
        pb = FakePlaybook("steward-freshrss")
        result = act.act([make_finding()], self.ctx(), registry={pb.id: pb})
        self.assertEqual(pb.applied, [])
        self.assertFalse(result.refused[0].alert)
        self.assertIn("cooldown", result.refused[0].reason)

    def test_cooldown_expired_allows_execution(self):
        self.record_executed("freshrss", at=NOW - timedelta(hours=13))
        pb = FakePlaybook("steward-freshrss")
        result = act.act([make_finding()], self.ctx(), registry={pb.id: pb})
        self.assertEqual(len(pb.applied), 1)
        self.assertEqual(result.executed[0]["status"], "verified")

    def test_plan_refusal_is_recorded(self):
        pb = FakePlaybook("steward-freshrss", refusal="no newer upstream image contains the fix")
        result = act.act([make_finding()], self.ctx(), registry={pb.id: pb})
        self.assertEqual(pb.applied, [])
        self.assertEqual(result.refused[0].reason, "no newer upstream image contains the fix")
        self.assertEqual(len(self.store.refusals_since(NOW - timedelta(hours=1))), 1)

    def test_only_one_execution_per_tick(self):
        specs = {"freshrss": make_spec("freshrss", "steward-freshrss"),
                 "open-webui": make_spec("open-webui", "steward-openwebui")}
        a = FakePlaybook("steward-freshrss")
        b = FakePlaybook("steward-openwebui")
        findings = [make_finding("freshrss", urgency=model.URGENCY_URGENT), make_finding("open-webui")]
        result = act.act(findings, self.ctx(specs=specs), registry={a.id: a, b.id: b})
        self.assertEqual(len(a.applied), 1)
        self.assertEqual(b.applied, [])
        self.assertEqual(len(result.executed), 1)
        deferred = [r for r in result.refused if r.component_id == "open-webui"]
        self.assertEqual(len(deferred), 1)
        self.assertFalse(deferred[0].alert)


class TwoSourceTests(ActTestBase):
    def setUp(self):
        super().setUp()
        self.store.osv_put("DEBIAN-CVE-2026-1001", {"id": "DEBIAN-CVE-2026-1001"}, NOW)
        self.seen = []

    def run_with_sources(self, count):
        def naming(records, ecosystem, name, version):
            self.seen.append(([r.get("id") for r in records], ecosystem, name, version))
            return count

        pb = FakePlaybook("steward-freshrss", release_published=model.iso(NOW - timedelta(hours=5)))
        with mock.patch.object(act.resolve, "independent_sources_naming", naming):
            result = act.act([make_finding()], self.ctx(), registry={pb.id: pb})
        return pb, result

    def test_young_release_with_one_source_defers(self):
        pb, result = self.run_with_sources(1)
        self.assertEqual(pb.applied, [])
        self.assertFalse(result.refused[0].alert)
        self.assertIn("1 independent", result.refused[0].reason)
        self.assertEqual(self.seen, [(["DEBIAN-CVE-2026-1001"], "Debian:13", "brotli", "1.1.0-2+deb13u1")])

    def test_young_release_with_two_sources_proceeds(self):
        pb, result = self.run_with_sources(2)
        self.assertEqual(len(pb.applied), 1)
        self.assertEqual(result.executed[0]["status"], "verified")

    def test_mature_release_needs_no_second_source(self):
        pb = FakePlaybook("steward-freshrss", release_published=model.iso(NOW - timedelta(hours=100)))
        with mock.patch.object(act.resolve, "independent_sources_naming", side_effect=AssertionError):
            act.act([make_finding()], self.ctx(), registry={pb.id: pb})
        self.assertEqual(len(pb.applied), 1)


class OutcomeTests(ActTestBase):
    def test_failed_apply_with_production_touched_trips_breaker(self):
        pb = FakePlaybook("steward-freshrss",
                          outcome=Outcome("failed", "health check failed", state={"production_touched": True}))
        result = act.act([make_finding()], self.ctx(), registry={pb.id: pb})
        self.assertEqual(result.executed[0]["status"], "failed")
        self.assertTrue(self.store.breaker()["open"])

    def test_rolled_back_without_production_touched_keeps_breaker_closed(self):
        pb = FakePlaybook("steward-freshrss",
                          outcome=Outcome("rolled_back", "build failed", state={"production_touched": False}))
        act.act([make_finding()], self.ctx(), registry={pb.id: pb})
        self.assertFalse(self.store.breaker()["open"])

    def test_apply_exception_fails_conservatively(self):
        pb = FakePlaybook("steward-freshrss", apply_error=RuntimeError("boom"))
        result = act.act([make_finding()], self.ctx(), registry={pb.id: pb})
        self.assertEqual(result.executed[0]["status"], "failed")
        self.assertTrue(self.store.breaker()["open"])

    def test_done_with_findings_still_open_is_unverified_and_trips(self):
        finding = make_finding()
        self.remaining["freshrss"] = [finding]
        pb = FakePlaybook("steward-freshrss")
        result = act.act([finding], self.ctx(), registry={pb.id: pb})
        self.assertEqual(self.rescans, ["freshrss"])
        self.assertEqual(result.executed[0]["status"], "unverified")
        self.assertEqual(self.store.get_action(result.executed[0]["id"])["status"], "unverified")
        self.assertTrue(self.store.breaker()["open"])

    def test_done_and_cleared_is_verified_with_undo(self):
        pb = FakePlaybook("steward-freshrss")
        result = act.act([make_finding()], self.ctx(), registry={pb.id: pb})
        row = result.executed[0]
        self.assertEqual(row["status"], "verified")
        self.assertEqual(row["undo"], "undo-cmd")
        self.assertEqual(set(row), {"id", "playbook", "component", "status", "target", "detail", "undo"})
        self.assertFalse(self.store.breaker()["open"])

    def test_pending_action_is_advanced_on_next_tick(self):
        pb = FakePlaybook("steward-freshrss", multi_tick=True,
                          outcome=Outcome("pending", "pr opened", state={"production_touched": False, "pr": 7}),
                          advance_outcome=Outcome("done", "merged and deployed", undo="revert",
                                                  state={"production_touched": True}))
        first = act.act([make_finding()], self.ctx(), registry={pb.id: pb})
        action_id = first.executed[0]["id"]
        self.assertEqual(self.store.get_action(action_id)["status"], "pending")
        self.assertEqual(self.store.get_action(action_id)["state"].get("pr"), 7)

        second = act.act([make_finding()], self.ctx(now=NOW + timedelta(minutes=15)), registry={pb.id: pb})
        self.assertEqual(len(pb.advanced), 1)
        self.assertEqual(pb.advanced[0]["id"], action_id)
        self.assertEqual(len(pb.applied), 1)
        self.assertEqual(second.advanced[0]["status"], "verified")
        self.assertEqual(self.store.get_action(action_id)["status"], "verified")
        self.assertEqual(self.store.active_actions(), [])


class NoFixRefusalTests(ActTestBase):
    def specs(self):
        return {
            "bun": make_spec("bun", "alert", note="herdr-web-client's build requires Bun 1.3.14 exactly"),
            "blog": make_spec("blog", "repo-pr", repo="blog", pin_owner={"RubyGems": "dependabot owns bundler"}),
            "host": make_spec("host", "apt-security"),
            "llm-proxy": make_spec("llm-proxy", "release-rebuild", repo="llm-proxy", edits=["go-toolchain"]),
        }

    def findings(self):
        no_fix = make_finding("bun", eco="runtime", name="bun")
        no_fix.fix_available = False
        unknown = make_finding("bun", cve="CVE-2026-1002", eco="runtime", name="bun")
        unknown.status = "unknown"
        return [no_fix, unknown,
                make_finding("blog", eco="RubyGems", name="rack"),
                make_finding("host", eco="Ubuntu:24.04:LTS", name="linux", binary="running-kernel"),
                make_finding("llm-proxy", eco="Go", name="golang.org/x/net")]

    def check(self, mode):
        result = act.act(self.findings(), self.ctx(mode=mode, specs=self.specs()), registry={})
        alerts = {r.component_id: r for r in result.refused if r.alert}
        self.assertEqual(set(alerts), {"bun", "blog"})
        self.assertIn("requires Bun 1.3.14 exactly", alerts["bun"].reason)
        self.assertIn("bun|CVE-2026-1001", alerts["bun"].reason)
        self.assertNotIn("CVE-2026-1002", alerts["bun"].reason)
        self.assertIn("dependabot owns bundler", alerts["blog"].reason)
        quiet = {r.component_id for r in result.refused if not r.alert}
        self.assertEqual(quiet, {"host", "llm-proxy"})
        self.assertEqual(len(self.store.refusals_since(NOW - timedelta(hours=1))), 2)

    def test_alert_owner_and_pin_owner_are_recorded_in_shadow_mode(self):
        self.check("shadow")

    def test_alert_owner_and_pin_owner_are_recorded_in_active_mode(self):
        self.check("active")


class SelectPlaybookTests(unittest.TestCase):
    def test_alert_owner_selects_nothing(self):
        self.assertIsNone(act.select_playbook(make_finding("bun"), make_spec("bun", "alert")))

    def test_pin_owner_ecosystem_selects_nothing(self):
        spec = make_spec("blog", "repo-pr", repo="blog", pin_owner={"RubyGems": "dependabot owns bundler"})
        gem = make_finding("blog", eco="RubyGems", name="rack")
        self.assertIsNone(act.select_playbook(gem, spec))
        self.assertEqual(act.select_playbook(make_finding("blog"), spec), "repo-pr")

    def test_release_rebuild_stdlib_vs_module(self):
        spec = make_spec("llm-proxy", "release-rebuild", repo="llm-proxy", edits=["go-module"])
        stdlib = make_finding("llm-proxy", eco="Go", name="stdlib", version="1.27.2")
        module = make_finding("llm-proxy", eco="Go", name="golang.org/x/net", version="0.40.0")
        self.assertEqual(act.select_playbook(stdlib, spec), "release-rebuild")
        self.assertEqual(act.select_playbook(module, spec), "repo-pr")
        no_edit = make_spec("x", "release-rebuild", repo="x", edits=["go-toolchain"])
        self.assertIsNone(act.select_playbook(module, no_edit))
        no_repo = make_spec("x", "release-rebuild", edits=["go-module"])
        self.assertIsNone(act.select_playbook(module, no_repo))
        self.assertIsNone(act.select_playbook(make_finding("llm-proxy", eco="npm", name="x"), spec))

    def test_kernel_selects_nothing_other_apt_packages_apt_security(self):
        spec = make_spec("host", "apt-security")
        kernel = make_finding("host", eco="Ubuntu:24.04:LTS", name="linux", binary="running-kernel")
        self.assertIsNone(act.select_playbook(kernel, spec))
        self.assertEqual(act.select_playbook(make_finding("host", eco="Ubuntu:24.04:LTS"), spec), "apt-security")

    def test_other_owner_is_returned_verbatim(self):
        self.assertEqual(act.select_playbook(make_finding(), make_spec("freshrss", "steward-freshrss")),
                         "steward-freshrss")


if __name__ == "__main__":
    unittest.main()
