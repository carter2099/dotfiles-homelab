#!/usr/bin/env python3
"""Behavioral tests for audit finding schema v2, docs firewall evidence, and P7 pool size."""
from __future__ import annotations

import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

from steward import audit

DOC = "/home/carter/notes/docs/homelab/searxng.md"


def _finding(**extra):
    item = {"claim": "doc says port 8080", "evidence": "ss shows 8081", "fix": "update doc"}
    item.update(extra)
    return item


def _worker(*findings, section=None, verdict="DRIFT"):
    return audit._prepare_audit_worker_packet(
        {"verdict": verdict, "findings": list(findings)}, section
    )


def _confirm(worker, section=None, **judge_fields):
    item = {"id": "finding-1", "evidence": "re-ran ss"}
    item.update(judge_fields)
    return audit._validate_audit_judge_packet(
        {"verdict": "DRIFT", "confirmed": [item], "rejected": []}, worker, section
    )["confirmed"][0]


class FindingSchemaV2Tests(unittest.TestCase):
    def test_v2_fields_survive_judge_validation(self):
        target = {"doc": DOC, "old_text": "port 8080\n", "new_text": "port 8081\n"}
        worker = _worker(_finding(severity="low", action="doc_fix", target=target),
                         section="docs-accuracy")
        confirmed = _confirm(worker, "docs-accuracy",
                             target={"doc": "/etc/passwd"}, claim="rewritten")
        self.assertEqual(confirmed["claim"], "doc says port 8080")
        self.assertEqual(confirmed["fix"], "update doc")
        self.assertEqual(confirmed["severity"], "low")
        self.assertEqual(confirmed["action"], "doc_fix")
        # Judge-supplied targets are ignored; old_text keeps its exact bytes.
        self.assertEqual(confirmed["target"], target)
        self.assertNotIn("decision", confirmed)

    def test_invalid_routing_fields_normalize_without_invalidating_packet(self):
        worker = _worker(
            _finding(severity="catastrophic", action="rewrite_everything", target="searxng.md"),
            _finding(severity=3, target={"repo": 7, "paths": ["", "a.py", None],
                                         "service": "blog"}),
            section="config-doc-drift",
        )
        first, second = worker["findings"]
        self.assertEqual([first["id"], second["id"]], ["finding-1", "finding-2"])
        for item in (first, second):
            self.assertEqual(item["severity"], "medium")
            self.assertEqual(item["action"], "needs_carter")
            self.assertEqual(item["routing_note"], "no route proposed")
            self.assertEqual(item["decision"], "")
        self.assertEqual(first["target"], {})
        self.assertEqual(second["target"], {"paths": ["a.py"], "service": "blog"})

    def test_missing_severity_defaults_low_for_low_sections(self):
        for section, expected in (("version-currency", "low"), ("docs-accuracy", "low"),
                                  ("security-posture", "medium"), (None, "medium")):
            with self.subTest(section=section):
                item = _worker(_finding(action="report_only"), section=section)["findings"][0]
                self.assertEqual(item["severity"], expected)
                self.assertNotIn("routing_note", item)

    def test_decision_only_kept_for_needs_carter(self):
        worker = _worker(
            _finding(action="needs_carter", decision=" Rotate the token? "),
            _finding(action="report_only", decision="stray"),
        )
        self.assertEqual(worker["findings"][0]["decision"], "Rotate the token?")
        self.assertNotIn("decision", worker["findings"][1])

    def test_judge_overrides_severity_and_invalid_judge_severity_falls_back(self):
        worker = _worker(_finding(severity="low", action="report_only"))
        self.assertEqual(_confirm(worker, severity="HIGH")["severity"], "high")
        self.assertEqual(_confirm(worker, severity="urgent")["severity"], "low")

    def test_judge_may_only_downgrade_action(self):
        worker = _worker(_finding(severity="medium", action="code_fix",
                                  target={"repo": "/home/carter/dev/blog", "paths": ["a.rb"]}))
        downgraded = _confirm(worker, action="needs_carter", routing_note="repo is infra",
                              decision="Should the steward edit this repo?")
        self.assertEqual(downgraded["action"], "needs_carter")
        self.assertEqual(downgraded["routing_note"], "repo is infra")
        self.assertEqual(downgraded["decision"], "Should the steward edit this repo?")
        self.assertEqual(downgraded["judge_downgraded_from"], "code_fix")
        self.assertEqual(downgraded["target"]["repo"], "/home/carter/dev/blog")

        report_only = _confirm(worker, action="report_only")
        self.assertEqual(report_only["action"], "report_only")
        self.assertIn("code_fix", report_only["routing_note"])

        # An upgrade/sidegrade from the judge is ignored.
        sideways = _confirm(worker, action="deploy", routing_note="ignored")
        self.assertEqual(sideways["action"], "code_fix")
        self.assertNotIn("routing_note", sideways)
        self.assertNotIn("judge_downgraded_from", sideways)

    def test_legacy_packets_without_v2_fields_still_validate(self):
        worker = {"verdict": "DRIFT", "findings": [
            {"id": "finding-1", "claim": "c", "evidence": "e", "fix": "f"},
            {"id": "finding-2", "claim": "c2", "evidence": "e2", "fix": "f2"},
        ]}
        judge = {"verdict": "DRIFT",
                 "confirmed": [{"id": "finding-1", "evidence": "verified"}],
                 "rejected": [{"id": "finding-2", "reason": "not reproduced"}]}
        normalized = audit._validate_audit_judge_packet(judge, worker)
        confirmed = normalized["confirmed"][0]
        self.assertEqual((confirmed["claim"], confirmed["fix"]), ("c", "f"))
        self.assertEqual(confirmed["severity"], "medium")
        self.assertEqual(confirmed["action"], "needs_carter")
        self.assertEqual(normalized["rejected"][0]["claim"], "c2")
        self.assertNotIn("severity", normalized["rejected"][0])
        # Legacy PASS artifacts stay cacheable.
        self.assertTrue(audit._audit_artifact_cacheable({
            "name": "docs-accuracy", "verdict": "PASS", "worker_verdict": "PASS",
            "judge_verdict": "PASS", "worker_findings": [],
            "judge_confirmed": [], "judge_rejected": [],
        }))

    def test_existing_judge_invariants_hold(self):
        worker = _worker(_finding(action="doc_fix"))
        with self.assertRaises(ValueError):
            audit._validate_audit_judge_packet(
                {"verdict": "PASS", "confirmed": [{"id": "finding-1", "evidence": "x",
                                                   "severity": "high"}], "rejected": []},
                worker)
        with self.assertRaises(ValueError):
            audit._validate_audit_judge_packet(
                {"verdict": "DRIFT", "confirmed": [], "rejected": []}, worker)
        with self.assertRaises(ValueError):
            audit._prepare_audit_worker_packet(
                {"verdict": "DRIFT", "findings": [_finding(fix="", action="doc_fix")]})

    def test_guard_items_carry_v2_fields(self):
        evidence = {"known_credential_incident": {"status": "unresolved", "source": "doc"}}
        verdict, confirmed = audit._apply_deterministic_audit_guards(
            "security-posture", evidence, "PASS", [])
        self.assertEqual(verdict, "ATTENTION")
        guard = confirmed[0]
        self.assertEqual(guard["severity"], "high")
        self.assertEqual(guard["action"], "needs_carter")
        self.assertEqual(guard["target"], {})
        self.assertTrue(guard["decision"].strip())


class DocsFirewallEvidenceTests(unittest.TestCase):
    def test_docs_accuracy_evidence_contains_ufw_rules_first(self):
        rules = "Status: active\n\nTo Action From\n8082/tcp ALLOW 192.168.4.103"
        commands = []

        def fake_run_capture(cmd, **kwargs):
            commands.append(cmd)
            return rules if cmd == ["sudo", "ufw", "status"] else "other"

        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(audit, "HOME", Path(tmp)), \
                patch.object(audit, "run_capture", side_effect=fake_run_capture), \
                patch.object(audit, "user_env", return_value={}):
            evidence = audit._audit_collector_8_docs_accuracy()
        self.assertIn(["sudo", "ufw", "status"], commands)
        self.assertEqual(next(iter(evidence)), "firewall")
        self.assertEqual(evidence["firewall"]["ufw_status"], rules)
        self.assertFalse(evidence["firewall"]["truncated"])

    def test_docs_firewall_evidence_is_bounded(self):
        huge = "x" * (audit._DOCS_UFW_STATUS_MAX + 50)
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(audit, "HOME", Path(tmp)), \
                patch.object(audit, "run_capture", return_value=huge), \
                patch.object(audit, "user_env", return_value={}):
            evidence = audit._audit_collector_8_docs_accuracy()
        self.assertEqual(len(evidence["firewall"]["ufw_status"]), audit._DOCS_UFW_STATUS_MAX)
        self.assertTrue(evidence["firewall"]["truncated"])


class AuditPoolTests(unittest.TestCase):
    def test_audit_pool_uses_audit_max_workers(self):
        sizes = []

        def recording_pool(max_workers):
            sizes.append(max_workers)
            return ThreadPoolExecutor(max_workers=max_workers)

        section = {"name": "fake", "collector": lambda: {"k": 1},
                   "artifact": "07-audit-fake.json", "timeout": 1, "guidance": "g"}
        result = {"name": "fake", "verdict": "PASS", "judge_confirmed": [],
                  "judge_rejected": []}
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(audit, "AUDIT_SECTIONS", [section]), \
                patch.object(audit, "AUDIT_MAX_WORKERS", 7), \
                patch.object(audit, "MAX_WORKERS", 3), \
                patch.object(audit, "ThreadPoolExecutor", side_effect=recording_pool), \
                patch.object(audit, "_load_prev_artifact", return_value=None), \
                patch.object(audit, "_session_memory_context", return_value=""), \
                patch.object(audit, "_run_audit_agent_pair", return_value=result):
            master = audit.phase_7_audit(Path(tmp), {"prev_date": ""})
        self.assertEqual(sizes, [7])
        self.assertEqual(master["sections"][0]["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
