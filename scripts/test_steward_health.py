#!/usr/bin/env python3
"""P3a is report-only: drift is detected and reported, never repaired."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from steward import health

ADDED = (
    "Added user rules (see 'ufw status' for running firewall):\n"
    "ufw allow in on cni0\n"
    "ufw allow from 192.168.4.0/24 to any port 22 proto tcp\n"
)
SS = (
    "LISTEN 0 4096 0.0.0.0:33099 0.0.0.0:* users:((\"docker-proxy\",pid=4242,fd=4))\n"
)


class P3aReportOnlyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.expected = self.root / "ufw-expected-rules.txt"
        self.commands = []

    def tearDown(self):
        self.tmp.cleanup()

    def _record(self, result):
        def fake(cmd, **_kwargs):
            self.commands.append(list(cmd))
            return result(cmd)
        return fake

    def run_phase(self, publisher=""):
        def capture(cmd):
            if "ss" in cmd:
                return SS
            if cmd[:3] == ["docker", "ps", "--filter"]:
                return publisher
            return ""

        with patch.object(health, "UFW_EXPECTED_RULES", self.expected), \
                patch.object(health, "run_capture", side_effect=self._record(capture)), \
                patch.object(health, "run_capture_ok", side_effect=self._record(
                    lambda cmd: (ADDED, "", 0) if "ufw" in cmd else ("", "", 7))), \
                patch.object(health, "run_ok", side_effect=self._record(lambda cmd: False)), \
                patch.object(health, "run", side_effect=AssertionError("P3a must not mutate")):
            return health.phase_3a_remediation(self.root, dry_run=False)

    def assert_no_mutation(self):
        for cmd in self.commands:
            joined = " ".join(cmd)
            self.assertNotIn("kill", cmd, joined)
            self.assertFalse(cmd[:2] == ["docker", "rm"], joined)
            if "ufw" in cmd:
                self.assertEqual(cmd[cmd.index("ufw") + 1:], ["show", "added"], joined)

    def test_drift_reports_missing_and_extra_without_mutating(self):
        self.expected.write_text(
            "ufw allow in on cni0\nufw allow in on flannel.1\n", encoding="utf-8"
        )
        data = self.run_phase()
        drift = data["ufw_drift"]
        self.assertEqual(drift["status"], "drift")
        self.assertEqual(drift["missing"], ["ufw allow in on flannel.1"])
        self.assertEqual(
            drift["extra"], ["ufw allow from 192.168.4.0/24 to any port 22 proto tcp"]
        )
        self.assertEqual(data["bridge_probe"]["status"], "unreachable")
        orphan = next(r for r in data["docker_proxy"] if r["port"] == 33099)
        self.assertEqual(orphan["action"], "attention_needed")
        self.assert_no_mutation()

    def test_matching_rules_are_ok(self):
        self.expected.write_text(ADDED.split("\n", 1)[1], encoding="utf-8")
        data = self.run_phase(publisher="blog-web-1 Up 3 hours")
        self.assertEqual(data["ufw_drift"]["status"], "ok")
        self.assertEqual(data["docker_proxy"][0]["action"], "ok")
        self.assert_no_mutation()

    def test_missing_expected_list_is_reported_not_repaired(self):
        data = self.run_phase()
        self.assertEqual(data["ufw_drift"]["reason"], "expected rule list missing")
        self.assert_no_mutation()


class ModelToolPolicyTests(unittest.TestCase):
    def capture_cmd(self, **kwargs):
        from steward import runtime
        seen = {}

        def fake_run(cmd, **_):
            seen["cmd"] = cmd
            return runtime.subprocess.CompletedProcess(cmd, 0, "answer", "")

        with patch.object(runtime.subprocess, "run", side_effect=fake_run):
            runtime._call_omp_p("prompt", **kwargs)
        return seen["cmd"]

    def test_call_without_tools_is_rejected(self):
        from steward import runtime
        with self.assertRaises(TypeError):
            runtime._call_omp_p("prompt")
        for bad in (None, "read", ("read", "bash"), ("edit",)):
            with self.subTest(tools=bad), self.assertRaises(ValueError):
                self.capture_cmd(tools=bad)

    def test_tool_flags(self):
        from steward import runtime
        cmd = self.capture_cmd(tools=runtime.NO_TOOLS)
        self.assertIn("--no-tools", cmd)
        self.assertNotIn("--tools", cmd)
        cmd = self.capture_cmd(tools=runtime.READ_ONLY_TOOLS)
        self.assertEqual(cmd[cmd.index("--tools") + 1], "read,grep,glob")

    def test_p3_troubleshooter_is_read_only_and_diagnose_only(self):
        from steward import runtime
        calls = []

        def fake_call(prompt, **kwargs):
            calls.append((prompt, kwargs))
            return '{"status": "diagnosed", "diagnosis": "x", "next_steps": ["y"], "evidence": []}'

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            health.write_json(run_dir / "01-applied.json", {"steps": [{"step": "apt_upgrade"}]})
            health.write_json(run_dir / "02-validation.json",
                              {"checks": [{"name": "endpoint_blog", "status": "fail"}]})
            prev = {"checks": [{"name": "endpoint_blog", "status": "ok"}]}
            with patch.object(health, "_p1_deploy_step_ok", return_value=True), \
                    patch.object(health, "read_json", side_effect=lambda p: (
                        prev if "02-validation" in str(p) and tmp not in str(p)
                        else runtime.read_json(p))), \
                    patch.object(health.Path, "exists", return_value=True), \
                    patch.object(health, "run_capture", return_value=""), \
                    patch.object(health, "_call_omp_p", side_effect=fake_call), \
                    patch.object(health, "phase_2_validate", return_value={"checks": []}), \
                    patch.object(health, "_p3_jev_client", return_value=None), \
                    patch.object(health, "run_capture_ok",
                                 side_effect=AssertionError("no Jev, no action")):
                data = health.phase_3_troubleshoot(run_dir)
        prompt, kwargs = calls[0]
        self.assertEqual(kwargs["tools"], runtime.READ_ONLY_TOOLS)
        self.assertIn("DIAGNOSE-ONLY", prompt)
        self.assertNotIn("do it", prompt)
        self.assertEqual(data["next_steps"], ["y"])
        self.assertFalse(data["fix_actions"][0]["executed"])


class FakeJev:
    """Test double for jev.JevClient: answers per endpoint, or raises."""

    def __init__(self, answers=None, exc=None):
        self.answers, self.exc, self.calls = answers or {}, exc, []

    def ask(self, purpose, state, questions):
        self.calls.append((purpose, state, questions))
        if self.exc is not None:
            raise self.exc
        choice, confidence = self.answers[state["endpoint"]]
        return {"action": {"type": "choice", "choice": choice, "confidence": confidence}}


class P3FixMenuTests(unittest.TestCase):
    PACKET = {"status": "diagnosed", "diagnosis": "container exited after image bump",
              "next_steps": [], "evidence": ["blog-web-1 Exited (1) 3 minutes ago"]}

    def apply(self, endpoints, client):
        ran = []

        def fake_run(argv, **_):
            ran.append(list(argv))
            return "", "", 0

        with patch.object(health, "run_capture_ok", side_effect=fake_run):
            rows = health._p3_apply_fix_menu(endpoints, [], self.PACKET, client)
        return rows, ran

    def test_menu_is_per_endpoint_and_excludes_forbidden_targets(self):
        client = FakeJev({"llm-proxy": ("none", 0.99)})
        self.apply(["llm-proxy"], client)
        criteria = client.calls[0][2]["action"]["criteria"]
        self.assertEqual(set(criteria), {"restart_unit", "none"})
        for endpoint in health.P3_ENDPOINT_SERVICES:
            for action in health._p3_fix_menu(endpoint).values():
                joined = " ".join(action["argv"] or [])
                for banned in ("herdr", "llama", "k3s", "ssh", "sh -c"):
                    self.assertNotIn(banned, joined)

    def test_jev_state_includes_the_endpoints_own_p1_step(self):
        steps = [{"step": "freshrss", "status": "bumped"}, {"step": "searxng", "status": "ok"}]
        state = health._p3_jev_state("freshrss", steps, self.PACKET)
        self.assertEqual([s["step"] for s in state["p1_steps_tonight"]], ["freshrss"])

    def test_off_menu_or_wrong_target_choice_never_executes(self):
        for choice in ("restart_container", "restart_cloudflared", "rm -rf /", None):
            with self.subTest(choice=choice):
                rows, ran = self.apply(["llm-proxy"], FakeJev({"llm-proxy": (choice, 0.99)}))
                self.assertEqual(ran, [])
                self.assertFalse(rows[0]["executed"])

    def test_none_or_low_confidence_takes_no_action(self):
        for answer in (("none", 0.99), ("restart_container", 0.79),
                       ("restart_container", None)):
            with self.subTest(answer=answer):
                rows, ran = self.apply(["blog"], FakeJev({"blog": answer}))
                self.assertEqual(ran, [])
                self.assertFalse(rows[0]["executed"])

    def test_jev_unavailable_takes_no_action(self):
        rows, ran = self.apply(["blog"], FakeJev(exc=health.jev.JevUnavailable("breaker_open")))
        self.assertEqual(ran, [])
        self.assertIn("breaker_open", rows[0]["reason"])
        rows, ran = self.apply(["blog"], None)
        self.assertEqual(ran, [])

    def test_at_most_three_actions_per_night(self):
        endpoints = ["blog", "news", "open-webui", "searxng"]
        rows, ran = self.apply(
            endpoints, FakeJev({e: ("restart_container", 0.95) for e in endpoints}))
        self.assertEqual(len(ran), 3)
        self.assertFalse(rows[3]["executed"])

    def test_happy_path_runs_menu_argv_then_revalidates(self):
        from steward import runtime
        events = []
        client = FakeJev({"blog": ("restart_container", 0.9)})

        def fake_run(argv, **_):
            events.append(("run", list(argv)))
            return "blog-web-1", "", 0

        def fake_validate(_run_dir):
            events.append(("validate",))
            return {"checks": [{"name": "endpoint_blog", "status": "ok"}]}

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            health.write_json(run_dir / "01-applied.json", {"steps": [{"step": "apt_upgrade"}]})
            health.write_json(run_dir / "02-validation.json",
                              {"checks": [{"name": "endpoint_blog", "status": "fail"}]})
            prev = {"checks": [{"name": "endpoint_blog", "status": "ok"}]}
            with patch.object(health, "_p1_deploy_step_ok", return_value=True), \
                    patch.object(health, "read_json", side_effect=lambda p: (
                        prev if "02-validation" in str(p) and tmp not in str(p)
                        else runtime.read_json(p))), \
                    patch.object(health.Path, "exists", return_value=True), \
                    patch.object(health, "run_capture", return_value=""), \
                    patch.object(health, "_call_omp_p", return_value=json.dumps(self.PACKET)), \
                    patch.object(health, "phase_2_validate", side_effect=fake_validate), \
                    patch.object(health, "_p3_jev_client", return_value=client), \
                    patch.object(health, "run_capture_ok", side_effect=fake_run):
                data = health.phase_3_troubleshoot(run_dir)
                saved = runtime.read_json(run_dir / "03-troubleshoot.json")
        self.assertEqual(events, [("run", ["docker", "restart", "--time", "30", "blog-web-1"]),
                                  ("validate",)])
        row = data["fix_actions"][0]
        self.assertEqual((row["choice"], row["confidence"], row["executed"]),
                         ("restart_container", 0.9, True))
        self.assertEqual(row["outcome"], "healthy after re-validation")
        self.assertTrue(data["re_validation_healthy"])
        self.assertEqual(saved["fix_actions"], data["fix_actions"])

    def test_resume_keeps_tonights_ledger_and_rows(self):
        from steward import runtime
        prior = [{"endpoint": e, "choice": "restart_container", "confidence": 0.9,
                  "executed": True, "argv": ["docker", "restart", "--time", "30", c],
                  "exit_code": 0, "outcome": "still failing"}
                 for e, c in (("blog", "blog-web-1"), ("news", "carter-news"),
                              ("open-webui", "open-webui"))]
        client = FakeJev({"searxng": ("restart_container", 0.95)})
        failing = [{"name": f"endpoint_{e}", "status": "fail"} for e in ("blog", "searxng")]
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            health.write_json(run_dir / "01-applied.json", {"steps": [{"step": "apt_upgrade"}]})
            health.write_json(run_dir / "02-validation.json", {"checks": failing})
            health.write_json(run_dir / "03-troubleshoot.json",
                              {"triggered": True, "fix_actions": prior})
            prev = {"checks": [{"name": c["name"], "status": "ok"} for c in failing]}
            with patch.object(health, "_p1_deploy_step_ok", return_value=True), \
                    patch.object(health, "read_json", side_effect=lambda p: (
                        prev if "02-validation" in str(p) and tmp not in str(p)
                        else runtime.read_json(p))), \
                    patch.object(health.Path, "exists", return_value=True), \
                    patch.object(health, "run_capture", return_value=""), \
                    patch.object(health, "_call_omp_p", return_value=json.dumps(self.PACKET)), \
                    patch.object(health, "phase_2_validate", return_value={"checks": failing}), \
                    patch.object(health, "_p3_jev_client", return_value=client), \
                    patch.object(health, "run_capture_ok",
                                 side_effect=AssertionError("cap already used tonight")):
                data = health.phase_3_troubleshoot(run_dir)
                saved = runtime.read_json(run_dir / "03-troubleshoot.json")
        self.assertEqual([c[1]["endpoint"] for c in client.calls], ["searxng"])
        rows = {r["endpoint"]: r for r in saved["fix_actions"]}
        self.assertEqual(set(rows), {"blog", "news", "open-webui", "searxng"})
        self.assertTrue(rows["news"]["executed"])
        self.assertFalse(rows["searxng"]["executed"])
        self.assertIn("nightly limit", rows["searxng"]["reason"])
        self.assertEqual(saved["fix_actions"], data["fix_actions"])


if __name__ == "__main__":
    unittest.main()
