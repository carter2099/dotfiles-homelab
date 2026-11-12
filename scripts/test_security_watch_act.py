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
        self.incomplete = set()
        self.steward = False

    def ctx(self, *, mode="active", now=NOW, specs=None, **policy):
        specs = specs or {"freshrss": make_spec("freshrss", "steward-freshrss")}

        def rescan(cid):
            self.rescans.append(cid)
            return list(self.remaining.get(cid, [])), cid not in self.incomplete

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
    def test_breaker_open_defers_all_without_per_group_refusal_rows(self):
        self.store.trip_breaker("earlier failure", NOW - timedelta(hours=1))
        specs = {"freshrss": make_spec("freshrss", "steward-freshrss"),
                 "open-webui": make_spec("open-webui", "steward-openwebui")}
        a, b = FakePlaybook("steward-freshrss"), FakePlaybook("steward-openwebui")
        result = act.act([make_finding(), make_finding("open-webui")], self.ctx(specs=specs),
                         registry={a.id: a, b.id: b})
        self.assertEqual(a.plans + b.plans, [])
        self.assertEqual(len(result.refused), 2)
        self.assertFalse(any(r.alert for r in result.refused))
        self.assertTrue(all("breaker" in r.reason for r in result.refused))
        self.assertEqual(self.store.refusals_since(NOW - timedelta(hours=1)), [])

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

    def test_daily_cap_skipped_for_urgent_group_and_still_counted(self):
        for i, cid in enumerate(("a", "b", "c")):
            self.record_executed(cid, at=NOW - timedelta(hours=2 + i))
        specs = {"freshrss": make_spec("freshrss", "steward-freshrss"),
                 "open-webui": make_spec("open-webui", "steward-openwebui")}
        a, b = FakePlaybook("steward-freshrss"), FakePlaybook("steward-openwebui")
        findings = [make_finding("freshrss", urgency=model.URGENCY_URGENT), make_finding("open-webui")]
        result = act.act(findings, self.ctx(specs=specs), registry={a.id: a, b.id: b})
        self.assertEqual(len(a.applied), 1)
        self.assertEqual(b.applied, [])
        self.assertEqual([r["component"] for r in result.executed], ["freshrss"])
        normal = [r for r in result.refused if r.component_id == "open-webui"]
        self.assertEqual(len(normal), 1)
        self.assertTrue(normal[0].alert)
        self.assertIn("daily action cap reached", normal[0].reason)
        self.assertFalse(any("cap" in r.reason for r in result.refused if r.component_id == "freshrss"))
        self.assertEqual(self.store.executed_actions_since(NOW - timedelta(hours=24)), 4)

    def test_two_urgent_groups_still_one_execution_per_tick(self):
        for i, cid in enumerate(("a", "b", "c")):
            self.record_executed(cid, at=NOW - timedelta(hours=2 + i))
        specs = {"freshrss": make_spec("freshrss", "steward-freshrss"),
                 "open-webui": make_spec("open-webui", "steward-openwebui")}
        a, b = FakePlaybook("steward-freshrss"), FakePlaybook("steward-openwebui")
        findings = [make_finding("freshrss", urgency=model.URGENCY_URGENT),
                    make_finding("open-webui", urgency=model.URGENCY_URGENT)]
        result = act.act(findings, self.ctx(specs=specs), registry={a.id: a, b.id: b})
        self.assertEqual(len(a.applied) + len(b.applied), 1)
        self.assertEqual(len(result.executed), 1)
        deferred = [r for r in result.refused if r.component_id != result.executed[0]["component"]]
        self.assertEqual(len(deferred), 1)
        self.assertIn("one execution per tick", deferred[0].reason)

    def test_component_cooldown_defers(self):
        action_id = self.record_executed("freshrss", at=NOW - timedelta(hours=2), status="failed")
        pb = FakePlaybook("steward-freshrss")
        result = act.act([make_finding()], self.ctx(), registry={pb.id: pb})
        self.assertEqual(pb.applied, [])
        self.assertFalse(result.refused[0].alert)
        self.assertIn("cooldown", result.refused[0].reason)
        self.assertIn(f"action #{action_id} ended failed", result.refused[0].reason)

    def test_cooldown_expired_allows_execution(self):
        self.record_executed("freshrss", at=NOW - timedelta(hours=13), status="failed")
        pb = FakePlaybook("steward-freshrss")
        result = act.act([make_finding()], self.ctx(), registry={pb.id: pb})
        self.assertEqual(len(pb.applied), 1)
        self.assertEqual(result.executed[0]["status"], "verified")

    def test_successful_action_starts_no_cooldown(self):
        for status, cve in (("verified", "CVE-2026-1001"), ("done", "CVE-2026-1002")):
            with self.subTest(status=status):
                self.record_executed("freshrss", at=NOW - timedelta(hours=2), status=status)
                pb = FakePlaybook("steward-freshrss")
                result = act.act([make_finding(cve=cve)], self.ctx(max_actions_per_day=10),
                                 registry={pb.id: pb})
                self.assertEqual(len(pb.applied), 1)
                self.assertFalse(any("cooldown" in r.reason for r in result.refused))

    def test_verified_action_holds_its_leftover_key_but_not_new_findings(self):
        action_id = self.record_executed("freshrss", at=NOW - timedelta(hours=2))   # covers freshrss|CVE-2026-9
        leftover, new = make_finding(cve="CVE-2026-9"), make_finding()
        pb = FakePlaybook("steward-freshrss")
        held = act.act([leftover], self.ctx(), registry={pb.id: pb})
        self.assertEqual(pb.plans, [])
        self.assertEqual(len(held.refused), 1)
        self.assertFalse(held.refused[0].alert)
        self.assertIn(f"already attempted by action #{action_id} (verified) within 12h", held.refused[0].reason)
        self.assertIn("still open: freshrss|CVE-2026-9", held.refused[0].reason)

        result = act.act([leftover, new], self.ctx(now=NOW + timedelta(minutes=15)), registry={pb.id: pb})
        self.assertEqual(pb.plans, [["freshrss|CVE-2026-1001"]])
        self.assertEqual(len(pb.applied), 1)
        self.assertEqual(result.executed[0]["status"], "verified")

    def test_verified_leftover_is_eligible_again_after_cooldown(self):
        self.record_executed("freshrss", at=NOW - timedelta(hours=13))
        pb = FakePlaybook("steward-freshrss")
        act.act([make_finding(cve="CVE-2026-9")], self.ctx(), registry={pb.id: pb})
        self.assertEqual(pb.plans, [["freshrss|CVE-2026-9"]])
        self.assertEqual(len(pb.applied), 1)

    def test_failed_action_still_blocks_whole_component(self):
        action_id = self.record_executed("freshrss", at=NOW - timedelta(hours=2), status="failed")
        pb = FakePlaybook("steward-freshrss")
        result = act.act([make_finding(cve="CVE-2026-9"), make_finding()], self.ctx(), registry={pb.id: pb})
        self.assertEqual(pb.plans, [])
        self.assertEqual(len(result.refused), 1)
        self.assertIn(f"component cooldown: action #{action_id} ended failed", result.refused[0].reason)

    def test_cooldown_applies_to_urgent_group(self):
        self.record_executed("freshrss", at=NOW - timedelta(hours=2), status="unverified")
        pb = FakePlaybook("steward-freshrss")
        result = act.act([make_finding(urgency=model.URGENCY_URGENT)], self.ctx(), registry={pb.id: pb})
        self.assertEqual(pb.applied, [])
        self.assertIn("ended unverified", result.refused[0].reason)

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
            "freshrss": make_spec("freshrss", "steward-freshrss", pin_owner={"PHP": "upstream image owns php"}),
            "host": make_spec("host", "apt-security"),
            "llm-proxy": make_spec("llm-proxy", "release-rebuild", repo="llm-proxy", edits=["go-toolchain"]),
        }

    def findings(self):
        no_fix = make_finding("bun", eco="runtime", name="bun")
        no_fix.fix_available = False
        unknown = make_finding("bun", cve="CVE-2026-1002", eco="runtime", name="bun")
        unknown.status = "unknown"
        return [no_fix, unknown,
                make_finding("freshrss", eco="PHP", name="php"),
                make_finding("host", eco="Ubuntu:24.04:LTS", name="linux", binary="running-kernel"),
                make_finding("llm-proxy", eco="Go", name="golang.org/x/net")]

    def check(self, mode):
        result = act.act(self.findings(), self.ctx(mode=mode, specs=self.specs()), registry={})
        alerts = {r.component_id: r for r in result.refused if r.alert}
        self.assertEqual(set(alerts), {"bun", "freshrss"})
        self.assertIn("requires Bun 1.3.14 exactly", alerts["bun"].reason)
        self.assertIn("bun|CVE-2026-1001", alerts["bun"].reason)
        self.assertNotIn("CVE-2026-1002", alerts["bun"].reason)
        self.assertIn("upstream image owns php", alerts["freshrss"].reason)
        self.assertEqual(alerts["freshrss"].finding_keys, ["freshrss|CVE-2026-1001"])
        quiet = {r.component_id for r in result.refused if not r.alert}
        self.assertEqual(quiet, {"host", "llm-proxy"})
        self.assertEqual(len(self.store.refusals_since(NOW - timedelta(hours=1))), 2)

    def test_alert_owner_and_pin_owner_are_recorded_in_shadow_mode(self):
        self.check("shadow")

    def test_alert_owner_and_pin_owner_are_recorded_in_active_mode(self):
        self.check("active")


class ManualTests(ActTestBase):
    def mctx(self, findings, **kw):
        ctx = self.ctx(**kw)
        ctx.findings = {f.key: f for f in findings}
        return ctx

    def multi_tick_pb(self):
        return FakePlaybook("steward-freshrss", multi_tick=True,
                            outcome=Outcome("pending", "pr opened", state={"production_touched": False, "pr": 7}),
                            advance_outcome=Outcome("done", "merged and deployed", undo="revert",
                                                    state={"production_touched": True}))

    def test_ignores_shadow_mode_daily_cap_and_cooldown(self):
        for i, cid in enumerate(("freshrss", "b", "c")):
            self.record_executed(cid, at=NOW - timedelta(hours=1 + i))
        pb = FakePlaybook("steward-freshrss")
        row = act.run_manual("freshrss", self.mctx([make_finding()], mode="shadow"), registry={pb.id: pb})
        self.assertEqual(len(pb.applied), 1)
        self.assertEqual(row["status"], "verified")
        self.assertEqual(set(row), {"id", "playbook", "component", "status", "target", "detail", "undo",
                                    "plan_steps"})
        self.assertEqual(row["plan_steps"], ["update"])
        self.assertEqual(row["undo"], "undo-cmd")
        self.assertEqual(self.store.get_action(row["id"])["mode"], "manual")
        self.assertEqual(self.rescans, ["freshrss"])
        self.assertFalse(self.store.breaker()["open"])
        self.assertEqual(self.store.executed_actions_since(NOW - timedelta(days=1)), 3)

    def test_breaker_open_refuses(self):
        self.store.trip_breaker("earlier failure", NOW - timedelta(hours=1))
        pb = FakePlaybook("steward-freshrss")
        row = act.run_manual("freshrss", self.mctx([make_finding()]), registry={pb.id: pb})
        self.assertEqual(row["status"], "refused")
        self.assertIn("breaker open", row["detail"])
        self.assertEqual((pb.plans, pb.applied), ([], []))

    def test_steward_active_refuses(self):
        self.steward = True
        pb = FakePlaybook("steward-freshrss")
        row = act.run_manual("freshrss", self.mctx([make_finding()]), registry={pb.id: pb})
        self.assertEqual(row["status"], "refused")
        self.assertIn("steward", row["detail"])
        self.assertEqual((pb.plans, pb.applied), ([], []))

    def test_several_playbooks_need_a_choice(self):
        specs = {"llm-proxy": make_spec("llm-proxy", "release-rebuild", repo="llm-proxy", edits=["go-module"])}
        stdlib = make_finding("llm-proxy", cve="CVE-2026-2001", eco="Go", name="stdlib", version="1.27.2")
        module = make_finding("llm-proxy", cve="CVE-2026-2002", eco="Go", name="golang.org/x/net", version="0.40.0")
        rebuild, pr = FakePlaybook("release-rebuild"), FakePlaybook("repo-pr")
        registry = {rebuild.id: rebuild, pr.id: pr}
        row = act.run_manual("llm-proxy", self.mctx([stdlib, module], specs=specs), registry=registry)
        self.assertEqual(row["status"], "refused")
        self.assertIn("--playbook", row["detail"])
        self.assertIn("release-rebuild (llm-proxy|CVE-2026-2001)", row["detail"])
        self.assertIn("repo-pr (llm-proxy|CVE-2026-2002)", row["detail"])
        self.assertEqual(rebuild.plans + pr.plans, [])

        row = act.run_manual("llm-proxy", self.mctx([stdlib, module], specs=specs), registry=registry,
                             playbook="repo-pr")
        self.assertEqual(row["status"], "verified")
        self.assertEqual(pr.plans, [["llm-proxy|CVE-2026-2002"]])
        self.assertEqual(rebuild.applied, [])

    def test_finding_restriction(self):
        specs = {"llm-proxy": make_spec("llm-proxy", "release-rebuild", repo="llm-proxy", edits=["go-module"])}
        stdlib = make_finding("llm-proxy", cve="CVE-2026-2001", eco="Go", name="stdlib", version="1.27.2")
        module = make_finding("llm-proxy", cve="CVE-2026-2002", eco="Go", name="golang.org/x/net", version="0.40.0")
        rebuild = FakePlaybook("release-rebuild")
        row = act.run_manual("llm-proxy", self.mctx([stdlib, module], specs=specs), registry={rebuild.id: rebuild},
                             finding_keys=["llm-proxy|CVE-2026-2001"])
        self.assertEqual(row["status"], "verified")
        self.assertEqual(rebuild.plans, [["llm-proxy|CVE-2026-2001"]])
        row = act.run_manual("llm-proxy", self.mctx([stdlib], specs=specs), registry={rebuild.id: rebuild},
                             finding_keys=["llm-proxy|CVE-2026-9999"])
        self.assertEqual(row["status"], "refused")
        self.assertIn("llm-proxy|CVE-2026-9999", row["detail"])

    def test_plan_refusal_is_returned_and_recorded(self):
        pb = FakePlaybook("steward-freshrss", refusal="no newer upstream image contains the fix")
        row = act.run_manual("freshrss", self.mctx([make_finding()]), registry={pb.id: pb})
        self.assertEqual(row["status"], "refused")
        self.assertIsNone(row["id"])
        self.assertEqual(row["detail"], "no newer upstream image contains the fix")
        self.assertEqual(pb.applied, [])
        self.assertEqual([r["reason"] for r in self.store.refusals_since(NOW - timedelta(hours=1))],
                         ["no newer upstream image contains the fix"])
        self.assertEqual(self.store.actions_since(NOW - timedelta(days=1)), [])

    def test_unverified_trips_breaker(self):
        finding = make_finding()
        self.remaining["freshrss"] = [finding]
        pb = FakePlaybook("steward-freshrss")
        row = act.run_manual("freshrss", self.mctx([finding]), registry={pb.id: pb})
        self.assertEqual(row["status"], "unverified")
        self.assertEqual(self.store.get_action(row["id"])["status"], "unverified")
        self.assertTrue(self.store.breaker()["open"])

    def test_failed_with_production_touched_trips_breaker(self):
        pb = FakePlaybook("steward-freshrss",
                          outcome=Outcome("failed", "health check failed", state={"production_touched": True}))
        row = act.run_manual("freshrss", self.mctx([make_finding()]), registry={pb.id: pb})
        self.assertEqual(row["status"], "failed")
        self.assertTrue(self.store.breaker()["open"])

    def test_two_source_gate_unless_skipped_and_dry_run_applies_nothing(self):
        self.store.osv_put("DEBIAN-CVE-2026-1001", {"id": "DEBIAN-CVE-2026-1001"}, NOW)
        pb = FakePlaybook("steward-freshrss", release_published=model.iso(NOW - timedelta(hours=5)))
        with mock.patch.object(act.resolve, "independent_sources_naming", return_value=1):
            row = act.run_manual("freshrss", self.mctx([make_finding()]), registry={pb.id: pb})
            self.assertEqual(row["status"], "refused")
            self.assertIn("1 independent", row["detail"])
            self.assertEqual(row["target"], "freshrss fixed")
            dry = act.run_manual("freshrss", self.mctx([make_finding()]), registry={pb.id: pb},
                                 skip_age_gate=True, dry_run=True)
            self.assertEqual((dry["status"], dry["id"], dry["target"]), ("planned", None, "freshrss fixed"))
            self.assertEqual(pb.applied, [])
            self.assertEqual(self.store.actions_since(NOW - timedelta(days=1)), [])
            row = act.run_manual("freshrss", self.mctx([make_finding()]), registry={pb.id: pb}, skip_age_gate=True)
        self.assertEqual(row["status"], "verified")
        self.assertEqual(len(pb.applied), 1)

    def test_shadow_tick_advances_a_pending_manual_action(self):
        pb = self.multi_tick_pb()
        row = act.run_manual("freshrss", self.mctx([make_finding()], mode="shadow"), registry={pb.id: pb})
        self.assertEqual(row["status"], "pending")
        self.assertEqual(self.store.executed_actions_since(NOW - timedelta(days=1)), 0)

        tick = act.act([make_finding()], self.ctx(mode="shadow", now=NOW + timedelta(minutes=15)),
                       registry={pb.id: pb})
        self.assertEqual(len(pb.advanced), 1)
        self.assertEqual(tick.advanced[0]["status"], "verified")
        self.assertEqual(self.store.get_action(row["id"])["status"], "verified")

    def test_shadow_tick_still_skips_pending_autonomous_actions(self):
        pb = self.multi_tick_pb()
        act.act([make_finding()], self.ctx(), registry={pb.id: pb})
        act.act([make_finding()], self.ctx(mode="shadow", now=NOW + timedelta(minutes=15)), registry={pb.id: pb})
        self.assertEqual(pb.advanced, [])

    def test_active_gate_sees_manual_action_and_breaker_blocks_advance(self):
        pb = self.multi_tick_pb()
        row = act.run_manual("freshrss", self.mctx([make_finding()]), registry={pb.id: pb})
        self.store.trip_breaker("other failure", NOW)
        later = self.ctx(now=NOW + timedelta(minutes=15))
        result = act.act([make_finding()], later, registry={pb.id: pb})
        self.assertEqual((pb.advanced, len(pb.applied)), ([], 1))
        self.assertTrue(any(f"action #{row['id']} not advanced: breaker open" in r.reason for r in result.refused))
        self.store.reset_breaker(NOW)
        pb.advance_outcome = Outcome("pending", "waiting for CI", state={"production_touched": False})
        result = act.act([make_finding()], self.ctx(now=NOW + timedelta(minutes=30)), registry={pb.id: pb})
        self.assertEqual(len(pb.advanced), 1)
        self.assertEqual(len(pb.applied), 1)   # no autonomous apply while the manual action is in flight
        self.assertTrue(any(f"action #{row['id']} in progress" in r.reason for r in result.refused))
        again = act.run_manual("freshrss", self.mctx([make_finding()]), registry={pb.id: pb})
        self.assertEqual(again["status"], "refused")
        self.assertIn(f"fix --resume {row['id']}", again["detail"])

    def test_advance_manual(self):
        pb = self.multi_tick_pb()
        row = act.run_manual("freshrss", self.mctx([make_finding()], mode="shadow"), registry={pb.id: pb})
        self.steward = True
        blocked = act.advance_manual(row["id"], self.ctx(mode="shadow"), registry={pb.id: pb})
        self.assertEqual(blocked["status"], "pending")
        self.assertIn("steward", blocked["detail"])
        self.steward = False
        done = act.advance_manual(row["id"], self.ctx(mode="shadow"), registry={pb.id: pb})
        self.assertEqual(done["status"], "verified")
        self.assertEqual(done["plan_steps"], ["update"])
        self.assertEqual(act.advance_manual(row["id"], self.ctx(), registry={pb.id: pb})["status"], "verified")
        self.assertEqual(len(pb.advanced), 1)
        self.assertEqual(act.advance_manual(9999, self.ctx(), registry={pb.id: pb})["status"], "refused")
        auto = self.record_executed("freshrss", at=NOW, status="pending")
        self.assertEqual(act.advance_manual(auto, self.ctx(), registry={pb.id: pb})["status"], "refused")

    def test_list_manual_plans_without_applying(self):
        specs = {"freshrss": make_spec("freshrss", "steward-freshrss"),
                 "bun": make_spec("bun", "alert", note="pinned")}
        pb = FakePlaybook("steward-freshrss")
        rows = act.list_manual(self.mctx([make_finding(), make_finding("bun", eco="runtime", name="bun")],
                                         specs=specs), registry={pb.id: pb})
        self.assertEqual([(r["component"], r["playbook"]) for r in rows], [("bun", ""), ("freshrss", "steward-freshrss")])
        self.assertIn("alert-only", rows[0]["refusal"])
        self.assertEqual((rows[1]["target"], rows[1]["plan_steps"], rows[1]["refusal"]),
                         ("freshrss fixed", ["update"], ""))
        self.assertEqual(pb.applied, [])
        self.assertEqual(self.store.actions_since(NOW - timedelta(days=1)), [])

    def test_manual_incomplete_verify_stays_pending_and_resume_verifies(self):
        pb = FakePlaybook("steward-freshrss")       # single-tick: the verify stage needs no advance()
        self.incomplete.add("freshrss")
        row = act.run_manual("freshrss", self.mctx([make_finding()], mode="shadow"), registry={pb.id: pb})
        self.assertEqual(row["status"], "pending")
        self.assertEqual(row["plan_steps"], ["update"])
        blocked = act.advance_manual(row["id"], self.ctx(mode="shadow"), registry={pb.id: pb})
        self.assertEqual(blocked["status"], "pending")
        self.assertIn("verification pending", blocked["detail"])
        self.incomplete.clear()
        done = act.advance_manual(row["id"], self.ctx(mode="shadow"), registry={pb.id: pb})
        self.assertEqual(done["status"], "verified")
        self.assertEqual(done["plan_steps"], ["update"])
        self.assertEqual(len(pb.applied), 1)

    def test_manual_partial_verify_is_verified(self):
        urgent = make_finding(urgency=model.URGENCY_URGENT)
        leftover = make_finding(cve="CVE-2026-1002")
        self.remaining["freshrss"] = [leftover]
        pb = FakePlaybook("steward-freshrss")
        row = act.run_manual("freshrss", self.mctx([urgent, leftover]), registry={pb.id: pb})
        self.assertEqual(row["status"], "verified")
        self.assertIn("1 of 2 cleared", row["detail"])
        self.assertFalse(self.store.breaker()["open"])

    def test_manual_refusal_with_alert_is_recorded(self):
        pb = FakePlaybook("steward-freshrss", outcome=Outcome("refused", "candidate still ships it",
                                                               state={"production_touched": False, "alert": True}))
        row = act.run_manual("freshrss", self.mctx([make_finding()]), registry={pb.id: pb})
        self.assertEqual(row["status"], "refused")
        self.assertEqual([r["reason"] for r in self.store.refusals_since(NOW - timedelta(hours=1))],
                         ["candidate still ships it"])


class VerifyTests(ActTestBase):
    """Settle semantics: partial verification, verified_keys, incomplete rescans."""

    def stored(self, *findings):
        for finding in findings:
            self.store.upsert_finding(dataclasses.replace(finding), NOW - timedelta(hours=1))
        return list(findings)

    def test_partial_verify_with_most_urgent_cleared_is_verified_without_breaker(self):
        urgent = make_finding(urgency=model.URGENCY_URGENT)
        leftover = make_finding(cve="CVE-2026-1002")
        self.stored(urgent, leftover)
        self.remaining["freshrss"] = [leftover]
        pb = FakePlaybook("steward-freshrss")
        result = act.act([urgent, leftover], self.ctx(), registry={pb.id: pb})
        row = result.executed[0]
        self.assertEqual(row["status"], "verified")
        self.assertIn("1 of 2 cleared; still open: freshrss|CVE-2026-1002", row["detail"])
        self.assertEqual(self.store.get_action(row["id"])["status"], "verified")
        self.assertFalse(self.store.breaker()["open"])

    def test_most_urgent_key_still_open_is_unverified_and_trips(self):
        urgent = make_finding(urgency=model.URGENCY_URGENT)
        cleared = make_finding(cve="CVE-2026-1002")
        self.stored(urgent, cleared)
        self.remaining["freshrss"] = [urgent]
        pb = FakePlaybook("steward-freshrss")
        result = act.act([urgent, cleared], self.ctx(), registry={pb.id: pb})
        self.assertEqual(result.executed[0]["status"], "unverified")
        self.assertIn("freshrss|CVE-2026-1001", self.store.breaker()["reason"])
        self.assertTrue(self.store.breaker()["open"])

    def test_nothing_cleared_is_unverified_and_trips(self):
        a, b = make_finding(), make_finding(cve="CVE-2026-1002", urgency=model.URGENCY_URGENT)
        self.stored(a, b)
        self.remaining["freshrss"] = [a, b]
        pb = FakePlaybook("steward-freshrss")
        result = act.act([a, b], self.ctx(), registry={pb.id: pb})
        self.assertEqual(result.executed[0]["status"], "unverified")
        self.assertTrue(self.store.breaker()["open"])

    def test_verified_keys_narrow_what_is_verified(self):
        a, b = make_finding(), make_finding(cve="CVE-2026-1002")
        self.stored(a, b)
        self.remaining["freshrss"] = [b]     # same urgency: verifying both keys would trip
        pb = FakePlaybook("steward-freshrss", outcome=Outcome(
            "done", "installed", undo="undo-cmd", state={"production_touched": True, "verified_keys": [a.key]}))
        result = act.act([a, b], self.ctx(), registry={pb.id: pb})
        self.assertEqual(pb.applied[0].finding_keys, [a.key, b.key])
        self.assertEqual(result.executed[0]["status"], "verified")
        self.assertNotIn("still open", result.executed[0]["detail"])
        self.assertFalse(self.store.breaker()["open"])

    def test_incomplete_rescan_stays_pending_and_is_reverified_next_tick(self):
        finding = make_finding()
        self.incomplete.add("freshrss")
        pb = FakePlaybook("steward-freshrss")
        first = act.act([finding], self.ctx(), registry={pb.id: pb})
        action_id = first.executed[0]["id"]
        self.assertEqual(first.executed[0]["status"], "pending")
        action = self.store.get_action(action_id)
        self.assertEqual((action["status"], action["state"]["stage"]), ("pending", "verify"))
        self.assertFalse(self.store.breaker()["open"])

        second = act.act([finding], self.ctx(now=NOW + timedelta(minutes=15)), registry={pb.id: pb})
        self.assertEqual(second.advanced, [])
        self.assertTrue(any(f"action #{action_id}: verification pending" in r.reason for r in second.refused))
        self.assertEqual(self.store.get_action(action_id)["status"], "pending")

        self.incomplete.clear()
        third = act.act([finding], self.ctx(now=NOW + timedelta(minutes=30)), registry={pb.id: pb})
        self.assertEqual(third.advanced[0]["status"], "verified")
        self.assertEqual(self.store.get_action(action_id)["status"], "verified")
        self.assertEqual((len(pb.applied), pb.advanced), (1, []))
        self.assertEqual(self.rescans, ["freshrss"] * 3)
        self.assertFalse(self.store.breaker()["open"])

    def test_incomplete_rescan_for_six_hours_is_unverified_and_trips(self):
        finding = make_finding()
        self.incomplete.add("freshrss")
        pb = FakePlaybook("steward-freshrss")
        action_id = act.act([finding], self.ctx(), registry={pb.id: pb}).executed[0]["id"]
        act.act([finding], self.ctx(now=NOW + timedelta(hours=5)), registry={pb.id: pb})
        self.assertEqual(self.store.get_action(action_id)["status"], "pending")
        later = act.act([finding], self.ctx(now=NOW + timedelta(hours=6)), registry={pb.id: pb})
        self.assertEqual(later.advanced[0]["status"], "unverified")
        self.assertTrue(self.store.breaker()["open"])
        self.assertIn("incomplete", self.store.breaker()["reason"])

    def test_rescan_error_is_retried_like_an_incomplete_scan(self):
        ctx = self.ctx()
        ctx.rescan = mock.Mock(side_effect=RuntimeError("osv down"))
        pb = FakePlaybook("steward-freshrss")
        row = act.act([make_finding()], ctx, registry={pb.id: pb}).executed[0]
        self.assertEqual(row["status"], "pending")
        self.assertIn("osv down", row["detail"])
        self.assertFalse(self.store.breaker()["open"])


class HardeningGateTests(ActTestBase):
    def record_failed(self, target, *, at, touched=False):
        plan = Plan(playbook="steward-freshrss", component_id="freshrss", finding_keys=["freshrss|CVE-2026-1001"],
                    target=target, lock_keys=["freshrss"], steps=[], undo="")
        action_id = self.store.start_action(plan, mode="active", status="running", now=at)
        self.store.update_action(action_id, status="failed", detail="gh pr create failed", now=at,
                                 state={"production_touched": touched}, finished=True)
        return action_id

    def test_refused_apply_starts_cooldown_not_cap_and_records_alert(self):
        pb = FakePlaybook("steward-freshrss", outcome=Outcome(
            "refused", "candidate still ships CVE-2026-1001", state={"production_touched": False, "alert": True}))
        result = act.act([make_finding()], self.ctx(), registry={pb.id: pb})
        self.assertEqual(result.executed, [])
        self.assertTrue(result.refused[-1].alert)
        self.assertEqual([r["reason"] for r in self.store.refusals_since(NOW - timedelta(hours=1))],
                         ["candidate still ships CVE-2026-1001"])
        self.assertEqual(self.store.executed_actions_since(NOW - timedelta(days=1)), 0)

        again = act.act([make_finding()], self.ctx(now=NOW + timedelta(hours=1)), registry={pb.id: pb})
        self.assertEqual(len(pb.applied), 1)
        self.assertIn("cooldown", again.refused[-1].reason)
        act.act([make_finding()], self.ctx(now=NOW + timedelta(hours=13)), registry={pb.id: pb})
        self.assertEqual(len(pb.applied), 2)

    def test_refused_apply_without_alert_is_not_recorded(self):
        pb = FakePlaybook("steward-freshrss", outcome=Outcome("refused", "lock busy",
                                                               state={"production_touched": False}))
        result = act.act([make_finding()], self.ctx(), registry={pb.id: pb})
        self.assertFalse(result.refused[-1].alert)
        self.assertEqual(self.store.refusals_since(NOW - timedelta(hours=1)), [])

    def test_two_untouched_failures_of_a_target_refuse_with_alert(self):
        self.record_failed("freshrss fixed", at=NOW - timedelta(hours=40))
        self.record_failed("freshrss fixed", at=NOW - timedelta(hours=20))
        pb = FakePlaybook("steward-freshrss")
        result = act.act([make_finding()], self.ctx(), registry={pb.id: pb})
        self.assertEqual(pb.applied, [])
        refusal = result.refused[-1]
        self.assertTrue(refusal.alert)
        self.assertIn("failed twice without touching production: gh pr create failed", refusal.reason)
        self.assertIn("fix manually or change the plan", refusal.reason)
        self.assertEqual(len(self.store.refusals_since(NOW - timedelta(hours=1))), 1)

    def test_untouched_failure_of_another_target_does_not_count(self):
        self.record_failed("freshrss older target", at=NOW - timedelta(hours=40))
        self.record_failed("freshrss fixed", at=NOW - timedelta(hours=20))
        pb = FakePlaybook("steward-freshrss")
        act.act([make_finding()], self.ctx(), registry={pb.id: pb})
        self.assertEqual(len(pb.applied), 1)

    def test_untouched_failure_older_than_seven_days_does_not_count(self):
        self.record_failed("freshrss fixed", at=NOW - timedelta(days=8))
        self.record_failed("freshrss fixed", at=NOW - timedelta(hours=20))
        pb = FakePlaybook("steward-freshrss")
        act.act([make_finding()], self.ctx(), registry={pb.id: pb})
        self.assertEqual(len(pb.applied), 1)

    def test_touched_failure_does_not_count(self):
        self.record_failed("freshrss fixed", at=NOW - timedelta(hours=40))
        self.record_failed("freshrss fixed", at=NOW - timedelta(hours=20), touched=True)
        pb = FakePlaybook("steward-freshrss")
        act.act([make_finding()], self.ctx(), registry={pb.id: pb})
        self.assertEqual(len(pb.applied), 1)

    def test_all_low_group_is_skipped_autonomously_but_runs_manually(self):
        low = make_finding(urgency=model.URGENCY_LOW)
        pb = FakePlaybook("steward-freshrss")
        for mode in ("active", "shadow"):
            result = act.act([low], self.ctx(mode=mode), registry={pb.id: pb})
            self.assertEqual(pb.plans, [])
            self.assertFalse(result.refused[-1].alert)
            self.assertIn("low urgency", result.refused[-1].reason)
        ctx = self.ctx()
        ctx.findings = {low.key: low}
        row = act.run_manual("freshrss", ctx, registry={pb.id: pb})
        self.assertEqual(row["status"], "verified")
        self.assertEqual(len(pb.applied), 1)

    def test_low_finding_rides_along_with_a_normal_one(self):
        pb = FakePlaybook("steward-freshrss")
        act.act([make_finding(urgency=model.URGENCY_LOW), make_finding(cve="CVE-2026-1002")], self.ctx(),
                registry={pb.id: pb})
        self.assertEqual(pb.plans, [["freshrss|CVE-2026-1001", "freshrss|CVE-2026-1002"]])

    def test_two_source_gate_counts_only_findings_naming_the_planned_version(self):
        for cve in ("CVE-2026-1001", "CVE-2026-1002"):
            self.store.osv_put(f"DEBIAN-{cve}", {"id": f"DEBIAN-{cve}"}, NOW)
        named = make_finding()
        other = make_finding(cve="CVE-2026-1002", fixed="1.1.0-3")
        seen = []

        def naming(records, ecosystem, name, version):
            ids = [r["id"] for r in records]
            seen.append(ids)
            return 2 if ids == ["DEBIAN-CVE-2026-1001"] else 0

        pb = FakePlaybook("steward-freshrss", release_published=model.iso(NOW - timedelta(hours=5)))
        with mock.patch.object(act.resolve, "independent_sources_naming", naming):
            act.act([named, other], self.ctx(), registry={pb.id: pb})
        self.assertEqual(seen, [["DEBIAN-CVE-2026-1001"]])
        self.assertEqual(len(pb.applied), 1)

    def test_two_source_gate_falls_back_to_first_finding(self):
        self.store.osv_put("DEBIAN-CVE-2026-1001", {"id": "DEBIAN-CVE-2026-1001"}, NOW)
        a = make_finding(fixed="9.9")
        b = make_finding(cve="CVE-2026-1002", fixed="9.8")
        seen = []

        def naming(records, ecosystem, name, version):
            seen.append([r["id"] for r in records])
            return 1

        pb = FakePlaybook("steward-freshrss", release_published=model.iso(NOW - timedelta(hours=5)))
        with mock.patch.object(act.resolve, "independent_sources_naming", naming):
            result = act.act([a, b], self.ctx(), registry={pb.id: pb})
        self.assertEqual(seen, [["DEBIAN-CVE-2026-1001"]])
        self.assertEqual(pb.applied, [])
        self.assertIn("1 independent", result.refused[-1].reason)

    def deploying_action(self, *, at):
        plan = Plan(playbook="repo-pr", component_id="freshrss", finding_keys=["freshrss|CVE-2026-1001"],
                    target="freshrss fixed", lock_keys=["freshrss"], steps=[], undo="revert")
        action_id = self.store.start_action(plan, mode="active", status="running", now=at)
        self.store.update_action(action_id, status="pending", detail="deploying release.sh", now=at,
                                 state={"stage": "deploying", "production_touched": True, "pr": 4})
        return action_id

    def test_stuck_deploying_row_fails_and_trips_after_two_hours(self):
        pb = FakePlaybook("repo-pr", multi_tick=True)
        recent = self.deploying_action(at=NOW - timedelta(minutes=90))
        result = act.act([], self.ctx(), registry={pb.id: pb})
        self.assertEqual((pb.advanced, result.advanced), ([], []))
        self.assertEqual(self.store.get_action(recent)["status"], "pending")
        self.assertFalse(self.store.breaker()["open"])

        result = act.act([], self.ctx(now=NOW + timedelta(minutes=31)), registry={pb.id: pb})
        self.assertEqual(pb.advanced, [])
        self.assertEqual(result.advanced[0]["status"], "failed")
        self.assertIn("deploy interrupted", result.advanced[0]["detail"])
        self.assertEqual(self.store.get_action(recent)["status"], "failed")
        self.assertTrue(self.store.breaker()["open"])

    def test_pending_action_blocking_a_component_is_an_alert_refusal(self):
        pb = FakePlaybook("steward-freshrss", multi_tick=True,
                          outcome=Outcome("pending", "PR #4 opened", state={"production_touched": False}),
                          advance_outcome=Outcome("refused", "PR #4 labelled hold",
                                                  state={"production_touched": False}))
        action_id = act.act([make_finding()], self.ctx(), registry={pb.id: pb}).executed[0]["id"]
        result = act.act([make_finding()], self.ctx(now=NOW + timedelta(minutes=15)), registry={pb.id: pb})
        self.assertEqual(self.store.get_action(action_id)["detail"], "PR #4 labelled hold")
        blocked = [r for r in result.refused if r.alert]
        self.assertEqual([r.reason for r in blocked], [f"action #{action_id} in progress: PR #4 labelled hold"])
        self.assertEqual([r["reason"] for r in self.store.refusals_since(NOW)],
                         [f"action #{action_id} in progress: PR #4 labelled hold"])


class SelectPlaybookTests(unittest.TestCase):
    def test_alert_owner_selects_nothing(self):
        self.assertIsNone(act.select_playbook(make_finding("bun"), make_spec("bun", "alert")))

    def test_pin_owner_ecosystem_goes_to_repo_pr_only_on_repo_pr_components(self):
        spec = make_spec("blog", "repo-pr", repo="blog", pin_owner={"RubyGems": "dependabot owns bundler"})
        gem = make_finding("blog", eco="RubyGems", name="rack")
        self.assertEqual(act.select_playbook(gem, spec), "repo-pr")
        other = make_spec("blog", "steward-freshrss", pin_owner={"RubyGems": "dependabot owns bundler"})
        self.assertIsNone(act.select_playbook(gem, other))

    def test_release_rebuild_stdlib_vs_module(self):
        spec = make_spec("llm-proxy", "release-rebuild", repo="llm-proxy", edits=["go-module"])
        stdlib = make_finding("llm-proxy", eco="Go", name="stdlib", version="1.27.2")
        module = make_finding("llm-proxy", eco="Go", name="golang.org/x/net", version="0.40.0")
        self.assertEqual(act.select_playbook(stdlib, spec), "release-rebuild")
        self.assertEqual(act.select_playbook(module, spec), "repo-pr")
        no_edit = make_spec("x", "release-rebuild", repo="x", edits=["go-toolchain"])
        self.assertIsNone(act.select_playbook(module, no_edit))
        self.assertEqual(act.select_playbook(stdlib, no_edit), "repo-pr")   # go.mod toolchain fixed at the source
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
