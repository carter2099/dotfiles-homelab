#!/usr/bin/env python3
"""Behavioral tests for steward delayed-update selection and rollback."""
from __future__ import annotations

import contextlib
import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from unittest.mock import MagicMock, Mock, patch
import jev
from steward import dotfiles

from steward import audit, config, fixes, report, routing, updates


class DelayedUpdateTests(unittest.TestCase):
    NOW = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)

    def test_release_maturity_boundary_is_seven_days(self):
        self.assertTrue(updates._release_is_mature(
            "2026-08-18T12:00:00Z", now=self.NOW))
        self.assertFalse(updates._release_is_mature(
            "2026-08-18T12:00:01Z", now=self.NOW))

    def test_searxng_selects_newest_mature_tag(self):
        tags = [
            {"name": "2026.8.17-aaaa1111", "last_updated": "2026-08-17T12:00:00Z",
             "digest": "sha256:" + "1" * 64},
            {"name": "2026.8.18-bbbb2222", "last_updated": "2026-08-18T12:00:00Z",
             "digest": "sha256:" + "2" * 64},
            {"name": "2026.8.19-cccc3333", "last_updated": "2026-08-19T12:00:00Z",
             "digest": "sha256:" + "3" * 64},
        ]
        target = updates._select_mature_searxng_tag(
            tags, "2026.8.17-aaaa1111", now=self.NOW)
        self.assertEqual(target["name"], "2026.8.18-bbbb2222")

    def test_llama_selects_newest_mature_release(self):
        releases = [
            {"tag_name": "b10453", "published_at": "2026-08-17T12:00:00Z"},
            {"tag_name": "b10488", "published_at": "2026-08-18T12:00:00Z"},
            {"tag_name": "b10500", "published_at": "2026-08-19T12:00:00Z"},
        ]
        target = updates._select_mature_llama_release(
            releases, "b10453", now=self.NOW)
        self.assertEqual(target["tag_name"], "b10488")

    def test_searxng_failed_health_check_restores_pin(self):
        old_digest = "sha256:" + "1" * 64
        new_digest = "sha256:" + "2" * 64
        tags = [
            {"name": "2026.8.17-aaaa1111", "last_updated": "2026-08-17T12:00:00Z",
             "digest": old_digest},
            {"name": "2026.8.18-bbbb2222", "last_updated": "2026-08-18T12:00:00Z",
             "digest": new_digest},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            compose = home / "searxng" / "docker-compose.yml"
            compose.parent.mkdir()
            original = (
                "services:\n  core:\n"
                f"    image: docker.io/searxng/searxng@{old_digest}\n"
            )
            compose.write_text(original)
            with (
                patch.object(updates, "HOME", home),
                patch.object(updates, "run_capture", return_value="2026.8.17-aaaa1111"),
                patch.object(updates, "run"),
                patch.object(updates, "_wait_searxng_healthy",
                             side_effect=[False, True]),
            ):
                result = updates._p1_searxng_update(tags=tags, now=self.NOW)
            self.assertEqual(result["status"], "reverted")
            self.assertEqual(compose.read_text(), original)

    def test_searxng_success_keeps_new_immutable_pin(self):
        old_digest = "sha256:" + "1" * 64
        new_digest = "sha256:" + "2" * 64
        tags = [
            {"name": "2026.8.17-aaaa1111", "last_updated": "2026-08-17T12:00:00Z",
             "digest": old_digest},
            {"name": "2026.8.18-bbbb2222", "last_updated": "2026-08-18T12:00:00Z",
             "digest": new_digest},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            compose = home / "searxng" / "docker-compose.yml"
            compose.parent.mkdir()
            compose.write_text(
                "services:\n  core:\n"
                f"    image: docker.io/searxng/searxng@{old_digest}\n"
            )
            with (
                patch.object(updates, "HOME", home),
                patch.object(updates, "run_capture", return_value="2026.8.17-aaaa1111"),
                patch.object(updates, "run"),
                patch.object(updates, "_wait_searxng_healthy", return_value=True),
            ):
                result = updates._p1_searxng_update(tags=tags, now=self.NOW)
            self.assertEqual(result["status"], "ok")
            self.assertIn(new_digest, compose.read_text())

    def _freshrss_update(self, home, tags, **patches):
        compose = home / "freshrss" / "docker-compose.yml"
        patches.update(FRESHRSS_DIR=compose.parent, FRESHRSS_COMPOSE=compose,
                       FRESHRSS_UP=compose.parent / "up.sh")
        with contextlib.ExitStack() as stack:
            for name, value in patches.items():
                stack.enter_context(patch.object(updates, name, value))
            return updates._p1_freshrss_update(tags=tags)

    FRESHRSS_OLD = "freshrss/freshrss:1.30.0@sha256:" + "1" * 64
    FRESHRSS_TAGS = [
        {"name": "latest", "digest": "sha256:" + "9" * 64},
        {"name": "1.29.9", "digest": "sha256:" + "8" * 64},
        {"name": "1.30.1", "digest": "sha256:" + "2" * 64},
        {"name": "1.31.0", "digest": None},
    ]

    def _freshrss_home(self, tmp):
        compose = Path(tmp) / "freshrss" / "docker-compose.yml"
        compose.parent.mkdir()
        original = f"services:\n  freshrss:\n    image: {self.FRESHRSS_OLD}\n"
        compose.write_text(original)
        return compose, original

    def test_freshrss_bumps_compose_pin_to_newest_digest_tag_and_runs_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            compose, _ = self._freshrss_home(tmp)
            run = Mock()
            result = self._freshrss_update(
                Path(tmp), self.FRESHRSS_TAGS, run=run,
                _wait_freshrss_healthy=Mock(return_value=True))
            self.assertEqual(result["status"], "bumped")
            self.assertEqual(result["latest_tag"], "1.30.1")
            self.assertIn("freshrss/freshrss:1.30.1@sha256:" + "2" * 64, compose.read_text())
            self.assertEqual(run.call_args_list[-1].args[0], [str(compose.parent / "up.sh")])
            self.assertTrue(updates._p1_deploy_step_ok(result))

    def test_freshrss_failed_health_check_restores_pin_and_reruns_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            compose, original = self._freshrss_home(tmp)
            run = Mock()
            result = self._freshrss_update(
                Path(tmp), self.FRESHRSS_TAGS, run=run,
                _wait_freshrss_healthy=Mock(side_effect=[False, True]))
            self.assertEqual(result["status"], "reverted")
            self.assertEqual(compose.read_text(), original)
            up_calls = [c for c in run.call_args_list
                        if c.args[0] == [str(compose.parent / "up.sh")]]
            self.assertEqual(len(up_calls), 2)
            self.assertFalse(updates._p1_deploy_step_ok(result))

    def test_freshrss_pull_failure_leaves_production_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            compose, original = self._freshrss_home(tmp)
            run = Mock(side_effect=subprocess.CalledProcessError(1, ["docker", "pull"]))
            wait = Mock(return_value=True)
            result = self._freshrss_update(
                Path(tmp), self.FRESHRSS_TAGS, run=run, _wait_freshrss_healthy=wait)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["reason"], "pull failed")
            self.assertEqual(compose.read_text(), original)
            self.assertEqual(run.call_count, 1)
            wait.assert_not_called()

    def test_freshrss_never_downgrades(self):
        with tempfile.TemporaryDirectory() as tmp:
            compose, original = self._freshrss_home(tmp)
            run = Mock()
            result = self._freshrss_update(Path(tmp), self.FRESHRSS_TAGS[:2], run=run)
            self.assertEqual(result["status"], "current")
            self.assertEqual(compose.read_text(), original)
            run.assert_not_called()

    def test_openwebui_fresh_release_goes_straight_to_the_guarded_transaction(self):
        # Published hours ago: there is no soak, the latest stable release installs.
        release = {
            "tag_name": "v0.11.3",
            "draft": False,
            "prerelease": False,
            "html_url": "https://github.com/open-webui/open-webui/releases/tag/v0.11.3",
            "published_at": "2026-08-25T09:00:00Z",
            "body": "### Fixed\n- a bug",
        }
        response = MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(release).encode()
        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "docker-compose.yml"
            original = (
                "services:\n  open-webui:\n"
                "    image: ghcr.io/open-webui/open-webui:0.11.1\n"
            )
            compose.write_text(original)
            with (
                patch.object(updates, "OPENWEBUI_COMPOSE", compose),
                patch.object(updates.urllib.request, "urlopen", return_value=response),
                patch.object(updates, "_owui_transaction",
                             return_value={"status": "ok"}) as transaction,
            ):
                result = updates._p1_openwebui()
        self.assertEqual(result, {"status": "ok"})
        transaction.assert_called_once()
        current, target, compose_text, common = transaction.call_args.args
        self.assertEqual((current, target, compose_text), ("0.11.1", "0.11.3", original))
        self.assertEqual(common["reason"], "latest stable release")
        self.assertNotIn("soak_until", common)
    def test_openwebui_never_reports_a_downgrade(self):
        release = {
            "tag_name": "v0.11.3",
            "draft": False,
            "prerelease": False,
            "published_at": "2026-08-01T00:00:00Z",
        }
        response = MagicMock()
        response.__enter__.return_value.read.return_value = json.dumps(release).encode()
        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "docker-compose.yml"
            compose.write_text(
                "services:\n  open-webui:\n"
                "    image: ghcr.io/open-webui/open-webui:0.11.4\n"
            )
            with (
                patch.object(updates, "OPENWEBUI_COMPOSE", compose),
                patch.object(updates.urllib.request, "urlopen", return_value=response),
                patch.object(updates, "_owui_transaction") as transaction,
            ):
                result = updates._p1_openwebui()

        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["reason"], "current")
        self.assertEqual(result["post_version"], "0.11.4")
        self.assertFalse(result["local_mutation"])
        transaction.assert_not_called()
        self.assertEqual(report._tldr_collect_updates({"steps": [result]})[0], [])

    def test_llama_reports_verified_remote_rollback(self):
        releases = [
            {"tag_name": "b10488", "published_at": "2026-08-18T12:00:00Z"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            helper = Path(tmp) / "update.sh"
            helper.write_text("exit 1\n")
            with (
                patch.object(updates, "LLAMA_CPP_UPDATE_SCRIPT", helper),
                patch.object(updates, "run_capture",
                             return_value="/opt/llama.cpp/b10453/bin/llama-server"),
                patch.object(updates, "run_capture_ok",
                             return_value=("", "ROLLBACK_OK b10453", 1)),
            ):
                result = updates._p1_llama_cpp_update(
                    releases=releases, now=self.NOW)
            self.assertEqual(result["status"], "reverted")
            self.assertEqual(result["reverted_to"], "b10453")

    def test_judge_verdict_overrides_worker_pass(self):
        packet = {
            "verdict": "ATTENTION",
            "confirmed": [{"claim": "manual action remains"}],
        }
        self.assertEqual(audit._final_audit_verdict("PASS", packet), "ATTENTION")
        self.assertEqual(audit._final_audit_verdict("DRIFT", {}), "UNVERIFIABLE")
        self.assertEqual(
            audit._final_audit_verdict(
                "PASS", {"confirmed": [{"claim": "missing judge verdict"}]}
            ),
            "UNVERIFIABLE",
        )
        self.assertEqual(
            audit._final_audit_verdict(
                "DRIFT", {"judge_error": "timeout", "confirmed": []}
            ),
            "judge-failed",
        )

    def test_audit_judge_packet_schema_fails_closed(self):
        worker = audit._prepare_audit_worker_packet({
            "verdict": "DRIFT",
            "findings": [{
                "claim": "tracked config differs",
                "evidence": "diff output",
                "fix": "sync the tracked copy",
            }],
        })
        invalid = [
            [],
            {"verdict": "PASS", "confirmed": {}, "rejected": []},
            {"verdict": "PASS", "confirmed": [{"id": "", "evidence": "x"}], "rejected": []},
            {"verdict": "UNKNOWN", "confirmed": [], "rejected": []},
            {"verdict": "PASS", "confirmed": [], "rejected": []},
            {
                "verdict": "PASS",
                "confirmed": [{
                    "id": "finding-1",
                    "evidence": "reproduced diff",
                }],
                "rejected": [],
            },
        ]
        for packet in invalid:
            with self.assertRaises(ValueError):
                audit._validate_audit_judge_packet(packet, worker)

        canonical = audit._validate_audit_judge_packet({
            "verdict": "ATTENTION",
            "confirmed": [{
                "id": "finding-1",
                "claim": "judge paraphrase is ignored",
                "evidence": "reproduced diff",
                "fix": "judge rewrite is ignored",
            }],
            "rejected": [],
        }, worker)
        self.assertEqual(canonical["confirmed"][0]["claim"], "tracked config differs")
        self.assertEqual(canonical["confirmed"][0]["fix"], "sync the tracked copy")

        rejected = audit._validate_audit_judge_packet({
            "verdict": "PASS",
            "confirmed": [],
            "rejected": [{
                "id": "finding-1",
                "reason": "not reproduced",
            }],
        }, worker)
        self.assertEqual(rejected["rejected"][0]["claim"], "tracked config differs")

        normalized_rejection = audit._validate_audit_judge_packet({
            "verdict": "DRIFT",
            "confirmed": [],
            "rejected": [{
                "id": "finding-1",
                "reason": "not an unresolved problem",
            }],
        }, worker)
        self.assertEqual(normalized_rejection["verdict"], "PASS")
        self.assertEqual(normalized_rejection["verdict_normalized_from"], "DRIFT")

        clean_worker = audit._prepare_audit_worker_packet({
            "verdict": "PASS",
            "findings": [],
        })
        normalized = audit._validate_audit_judge_packet({
            "verdict": "DRIFT",
            "confirmed": [],
            "rejected": [],
        }, clean_worker)
        self.assertEqual(normalized["verdict"], "PASS")
        self.assertEqual(normalized["verdict_normalized_from"], "DRIFT")

        with self.assertRaises(ValueError):
            audit._prepare_audit_worker_packet({
                "verdict": "ATTENTION",
                "findings": [{"claim": "", "evidence": "x", "fix": "y"}],
            })

    def test_worker_packet_retry_on_prose_only_output(self):
        section = {"name": "agent-fleet-review", "guidance": "inspect", "timeout": 600}
        prose_cut_short = (
            "Timers firing correctly so far. Now digging into dependabot outcomes... "
            "Need to veri"
        )
        retry_packet = (
            '```json\n{"verdict": "UNVERIFIABLE", "findings": ['
            '{"claim": "fleet checks incomplete", "evidence": "run cut short", '
            '"fix": "re-run section manually"}]}\n```'
        )
        judge_packet = (
            '```json\n{"verdict": "UNVERIFIABLE", "confirmed": [], "rejected": ['
            '{"id": "finding-1", "claim": "fleet checks incomplete", '
            '"reason": "not independently verified"}]}\n```'
        )
        with patch.object(
            audit, "_call_omp_p",
            side_effect=[prose_cut_short, retry_packet, judge_packet],
        ) as mock_call:
            result = audit._run_audit_agent_pair(section, {}, "hash1")
        self.assertEqual(result["verdict"], "UNVERIFIABLE")
        self.assertNotEqual(result["verdict"], "worker-failed")
        self.assertEqual(mock_call.call_count, 3)
        self.assertIn("Emit ONLY the fenced", mock_call.call_args_list[1].args[0])

    def test_worker_failed_persists_only_after_retry_missing_packet(self):
        section = {"name": "agent-fleet-review", "guidance": "inspect", "timeout": 600}
        prose = "investigating fleet state without ever emitting a packet"
        with patch.object(
            audit, "_call_omp_p",
            side_effect=[prose, prose],
        ) as mock_call:
            result = audit._run_audit_agent_pair(section, {}, "hash1")
        self.assertEqual(result["verdict"], "worker-failed")
        self.assertEqual(mock_call.call_count, 2)

    def test_judge_packet_retries_once_after_invalid_output(self):
        section = {"name": "digest-quality", "guidance": "inspect", "timeout": 600}
        worker_packet = '```json\n{"verdict": "PASS", "findings": []}\n```'
        invalid_judge = (
            '```json\n{"verdict": "UNKNOWN", "confirmed": [], "rejected": []}\n```'
        )
        valid_judge = (
            '```json\n{"verdict": "PASS", "confirmed": [], "rejected": []}\n```'
        )
        with patch.object(
            audit, "_call_omp_p",
            side_effect=[worker_packet, invalid_judge, valid_judge],
        ) as mock_call:
            result = audit._run_audit_agent_pair(section, {}, "hash1")

        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["judge_attempts"], 2)
        self.assertEqual(len(result["judge_retry_errors"]), 1)
        self.assertEqual(mock_call.call_count, 3)

    def test_judge_failure_persists_only_after_retry(self):
        section = {"name": "digest-quality", "guidance": "inspect", "timeout": 600}
        worker_packet = '```json\n{"verdict": "PASS", "findings": []}\n```'
        invalid_judge = "judge prose without a JSON packet"
        with patch.object(
            audit, "_call_omp_p",
            side_effect=[worker_packet, invalid_judge, invalid_judge],
        ) as mock_call:
            result = audit._run_audit_agent_pair(section, {}, "hash1")

        self.assertEqual(result["verdict"], "judge-failed")
        self.assertEqual(result["judge_attempts"], 2)
        self.assertEqual(len(result["judge_retry_errors"]), 2)
        self.assertEqual(mock_call.call_count, 3)

    def test_audit_cache_requires_clean_judge_provenance(self):
        worker = audit._prepare_audit_worker_packet({
            "verdict": "PASS",
            "findings": [],
        })
        artifact = {
            "verdict": "PASS",
            "worker_verdict": "PASS",
            "judge_verdict": "PASS",
            "worker_findings": worker["findings"],
            "judge_confirmed": [],
            "judge_rejected": [],
            "judge_error": "",
        }
        self.assertTrue(audit._audit_artifact_cacheable(artifact))

        artifact["verdict"] = "ATTENTION"
        artifact["judge_verdict"] = "ATTENTION"
        self.assertFalse(audit._audit_artifact_cacheable(artifact))

        artifact["verdict"] = "PASS"
        artifact["judge_verdict"] = "PASS"
        artifact["judge_error"] = "timeout"
        self.assertFalse(audit._audit_artifact_cacheable(artifact))

    def test_report_only_open_item_uses_concrete_claim(self):
        audit_data = {"sections": [{
            "name": "security-posture",
            "verdict": "DRIFT",
            "judge_confirmed": [{
                "claim": "gaming rig 8082 firewall allowance is undocumented",
            }],
        }]}
        fixes_data = {
            "sections": [],
            "report_only": [{"section": "security-posture"}],
        }
        facts = report._build_tldr_facts(
            {"steps": []},
            audit_data,
            {"plans": {}, "ideas": {}},
            fixes_data,
            {},
        )
        self.assertTrue(facts["audit_open"][0]["manual"])
        self.assertIn("gaming rig 8082", facts["needs_carter"][0])

    def test_judge_failure_is_automation_not_carter_action(self):
        audit_data = {"sections": [{
            "name": "digest-quality",
            "verdict": "judge-failed",
            "judge_error": (
                "invalid audit judge verdict; retry also failed: missing finding id"
            ),
        }]}
        facts = report._build_tldr_facts(
            {"steps": []},
            audit_data,
            {"plans": {}, "ideas": {}},
            {"sections": []},
            {},
        )
        self.assertEqual(facts["needs_carter"], [])
        self.assertEqual(facts["n_sections_open"], 0)
        self.assertEqual(facts["n_sections_incomplete"], 1)

    def test_version_currency_is_report_only(self):
        sections = [
            {
                "name": "version-currency",
                "verdict": "DRIFT",
                "judge_confirmed": [{"id": "finding-1", "claim": "Traefik newer"}],
                "worker_findings": [{"id": "finding-1", "claim": "Traefik newer"}],
            },
            {
                "name": "config-doc-drift",
                "verdict": "ATTENTION",
                "judge_confirmed": [{"id": "finding-1", "claim": "tracked config differs"}],
                "worker_findings": [{"id": "finding-1", "claim": "tracked config differs"}],
            },
            {
                "name": "digest-quality",
                "verdict": "PASS",
                "judge_confirmed": [],
                "worker_findings": [],
            },
        ]
        to_fix, report_only = fixes._p7b_fix_candidates(sections)
        self.assertEqual(to_fix, [(
            "config-doc-drift",
            [{"id": "finding-1", "claim": "tracked config differs"}],
        )])
        self.assertEqual(report_only, [{
            "section": "version-currency",
            "status": "report-only",
            "findings_count": 1,
        }])

        invented = [{
            "name": "security-posture",
            "verdict": "ATTENTION",
            "worker_findings": [],
            "judge_confirmed": [{"claim": "historical credential unresolved"}],
        }]
        to_fix, report_only = fixes._p7b_fix_candidates(invented)
        self.assertEqual(to_fix, [])
        self.assertEqual(report_only[0]["section"], "security-posture")

    def test_security_collector_retains_unresolved_incident(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            doc = home / "notes" / "docs" / "homelab" / "opencode-go-proxy.md"
            doc.parent.mkdir(parents=True)

            def collect():
                with (
                    patch.object(audit, "HOME", home),
                    patch.object(audit.urllib.request, "urlopen",
                                 side_effect=OSError("offline")),
                    patch.object(audit, "run_capture", return_value=""),
                    patch.object(audit, "_gather_repo_secrets",
                                 return_value={"findings_summary": "clean"}),
                ):
                    return audit._audit_collector_4_security()

            doc.write_text("Known credential incident: unresolved.\n")
            unresolved = collect()
            self.assertEqual(
                unresolved["known_credential_incident"]["status"], "unresolved"
            )
            verdict, confirmed = audit._apply_deterministic_audit_guards(
                "security-posture", unresolved, "PASS", []
            )
            self.assertEqual(verdict, "ATTENTION")
            self.assertEqual(len(confirmed), 1)

            doc.unlink()
            missing = collect()
            self.assertEqual(
                missing["known_credential_incident"]["status"], "unverifiable"
            )
            verdict, _ = audit._apply_deterministic_audit_guards(
                "security-posture", missing, "PASS", []
            )
            self.assertEqual(verdict, "ATTENTION")

            doc.write_text("Known credential incident: resolved.\n")
            resolved = collect()
            verdict, confirmed = audit._apply_deterministic_audit_guards(
                "security-posture", resolved, "PASS", []
            )
            self.assertEqual((verdict, confirmed), ("PASS", []))
    def test_local_apt_timeout_is_explicit_and_bounded(self):
        timeout = subprocess.TimeoutExpired(
            ["sudo", "apt", "upgrade", "-y"], updates.P1_APT_TIMEOUT
        )
        with patch.object(
            updates,
            "run",
            side_effect=[Mock(), timeout],
        ) as run_mock:
            result = updates._p1_apt_upgrade()

        self.assertEqual(result["status"], "timeout")
        self.assertEqual(result["stage"], "apt upgrade")
        self.assertIn("timed out", result["error"])
        self.assertEqual(
            run_mock.call_args_list[-1].kwargs["timeout"],
            updates.P1_APT_TIMEOUT,
        )
        # Modified conffiles (logind.conf, UPower.conf) must survive upgrades.
        self.assertIn("Dpkg::Options::=--force-confold", run_mock.call_args_list[-1].args[0])


class GamingRigMaintenanceTests(unittest.TestCase):
    def _linux_probe(self):
        return (
            {
                "step": "platform_probe",
                "status": "ok",
                "os": "Linux",
                "host": updates.RIG_SSH_ALIAS,
            },
            True,
        )

    def _healthy(self, step="health"):
        return {
            "step": step,
            "status": "ok",
            "checks": [
                {"step": "disk", "status": "ok"},
                {"step": "failed_units", "status": "ok"},
                {"step": "nvidia_smi", "status": "ok"},
                {"step": "llama_swap", "status": "ok"},
                {"step": "model_endpoint", "status": "ok"},
            ],
        }

    @staticmethod
    def _json_response(payload):
        response = MagicMock()
        response.__enter__.return_value = response
        response.__exit__.return_value = None
        response.read.return_value = json.dumps(payload).encode()
        return response

    def test_ssh_argv_is_pinned_bounded_and_quoted(self):
        argv = updates._rig_ssh_command(
            ["bun", "add", "-g", "pkg@1.2.3;touch /tmp/should-not-run"]
        )
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("ConnectTimeout=10", argv)
        self.assertIn("gamingrig-linux", argv)
        self.assertNotIn("StrictHostKeyChecking=no", argv)
        self.assertIn(
            "'pkg@1.2.3;touch /tmp/should-not-run'",
            argv,
        )
        self.assertIn("env", argv)
        self.assertIn(f"PATH={updates.RIG_REMOTE_PATH}", argv)
        self.assertEqual(
            updates.RIG_MODEL_ENDPOINT,
            "http://192.168.4.103:8080/v1/models",
        )

    def test_offline_rig_is_skipped_without_follow_up_commands(self):
        with patch.object(
            updates, "_rig_ssh",
            return_value=("", "Connection timed out", 255),
        ) as ssh:
            result = updates._p1_gamingrig_maintenance()
        self.assertEqual(result["status"], "skipped")
        self.assertIn("offline or sleeping", result["reason"])
        ssh.assert_called_once()

    def test_refusal_and_no_route_are_the_other_offline_signatures(self):
        for message in ("Connection refused", "No route to host"):
            with self.subTest(message=message), patch.object(
                updates, "_rig_ssh", return_value=("", message, 255)
            ):
                result = updates._p1_gamingrig_maintenance()
            self.assertEqual(result["status"], "skipped")
            self.assertIn("offline or sleeping", result["reason"])


    def test_windows_rig_is_skipped_only_with_trusted_proxy_corroboration(self):
        with (
            patch.object(
                updates, "_rig_ssh",
                return_value=("MINGW64_NT-10.0", "", 0),
            ) as ssh,
            patch.object(
                updates.urllib.request,
                "urlopen",
                return_value=self._json_response({"rig_os": "windows"}),
            ) as urlopen,
        ):
            result = updates._p1_gamingrig_maintenance()
        self.assertEqual(result["status"], "skipped")
        self.assertIn("trusted llm-proxy", result["reason"])
        self.assertEqual(urlopen.call_count, 1)
        ssh.assert_called_once()

    def test_uncorroborated_windows_probe_is_failure(self):
        with (
            patch.object(
                updates, "_rig_ssh",
                return_value=("MINGW64_NT-10.0", "", 0),
            ) as ssh,
            patch.object(
                updates.urllib.request,
                "urlopen",
                return_value=self._json_response({"rig_os": "linux"}),
            ),
        ):
            result = updates._p1_gamingrig_maintenance()
        self.assertEqual(result["status"], "failed")
        self.assertIn("not corroborated", result["error"])
        ssh.assert_called_once()

    def test_auth_failure_is_not_classified_as_offline(self):
        with patch.object(
            updates, "_rig_ssh",
            return_value=("", "Permission denied (publickey)", 255),
        ) as ssh:
            result = updates._p1_gamingrig_maintenance()
        self.assertEqual(result["status"], "failed")
        self.assertNotIn("offline or sleeping", result.get("reason", ""))
        ssh.assert_called_once()

    def test_host_key_mismatch_is_failure_without_windows_corroboration(self):
        with (
            patch.object(
                updates, "_rig_ssh",
                return_value=("", "Host key verification failed", 255),
            ) as ssh,
            patch.object(
                updates, "_rig_windows_health_corroboration",
                return_value={"status": "failed", "error": "rig_os=linux"},
            ),
        ):
            result = updates._p1_gamingrig_maintenance()
        self.assertEqual(result["status"], "failed")
        self.assertIn("host key mismatch", result["reason"])
        self.assertIn("did not corroborate Windows", result["error"])
        ssh.assert_called_once()

    def test_linux_host_key_mismatch_is_skipped_when_windows_is_corroborated(self):
        with (
            patch.object(
                updates, "_rig_ssh",
                return_value=("", "Host key verification failed", 255),
            ) as ssh,
            patch.object(
                updates, "_rig_windows_health_corroboration",
                return_value={"status": "ok", "rig_os": "windows"},
            ),
        ):
            result = updates._p1_gamingrig_maintenance()
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["substeps"][0]["os"], "Windows")
        self.assertIn("trusted llm-proxy", result["reason"])
        ssh.assert_called_once()


    def test_linux_noop_maintenance_is_success(self):
        with (
            patch.object(updates, "_rig_platform_probe",
                         return_value=self._linux_probe()),
            patch.object(updates, "_rig_apt_upgrade",
                         return_value={"step": "apt_upgrade", "status": "ok",
                                       "upgraded_count": 0}),
            patch.object(updates, "_rig_herdr_update",
                         return_value={"step": "herdr_update", "status": "skipped",
                                       "reason": "already current"}),

            patch.object(updates, "_rig_omp_update",
                         return_value={"step": "omp_update", "status": "skipped",
                                       "reason": "already current"}),
            patch.object(updates, "_rig_health_checks",
                         return_value=self._healthy()),
            patch.object(updates, "_rig_reboot_required",
                         return_value={"step": "reboot_required", "status": "skipped",
                                       "required": False}),
        ):
            result = updates._p1_gamingrig_maintenance()
        self.assertEqual(result["status"], "ok")
        self.assertFalse(result.get("rebooted"))
        self.assertEqual(len(result["substeps"]), 6)

    def test_apt_upgrade_reports_planned_and_actual_change_counts(self):
        responses = [
            {"step": "apt_update", "status": "ok", "stdout_tail": "ok"},
            {
                "step": "apt_upgrade_plan",
                "status": "ok",
                "stdout_tail": "3 upgraded, 0 newly installed, 0 to remove.",
            },
            {
                "step": "apt_upgrade_apply",
                "status": "ok",
                "stdout_tail": "1 upgraded, 0 newly installed, 0 to remove.",
            },
        ]
        with patch.object(
            updates, "_rig_command_result", side_effect=responses
        ) as command:
            result = updates._rig_apt_upgrade()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["planned_count"], 3)
        self.assertEqual(result["upgraded_count"], 1)
        self.assertEqual(command.call_count, 3)

    def test_apt_upgrade_parses_long_plan_and_apply_output(self):
        plan_output = "5 upgraded, 0 newly installed, 0 to remove.\n" + (
            "Inst example [1.0] (1.1 Ubuntu:24.04/noble-updates [amd64])\n"
            "Conf example (1.1 Ubuntu:24.04/noble-updates [amd64])\n"
        ) * 100
        apply_output = "2 upgraded, 0 newly installed, 0 to remove.\n" + (
            "Setting up example (1.1) ...\n"
        ) * 100
        with patch.object(
            updates, "_rig_ssh",
            side_effect=[
                ("Reading package lists...\n", "", 0),
                (plan_output, "", 0),
                (apply_output, "", 0),
            ],
        ):
            result = updates._rig_apt_upgrade()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["planned_count"], 5)
        self.assertEqual(result["upgraded_count"], 2)
        self.assertLess(len(json.dumps(result)), 5000)

    def test_apt_upgrade_takes_upgrades_that_need_new_packages(self):
        # A new kernel's NVIDIA module and the split linux-firmware arrive as new
        # packages; plain `upgrade` kept them back and booted the rig GPU-less.
        with patch.object(
            updates, "_rig_ssh",
            side_effect=[
                ("Reading package lists...\n", "", 0),
                ("9 upgraded, 2 newly installed, 0 to remove and 0 not upgraded.\n", "", 0),
                ("9 upgraded, 2 newly installed, 0 to remove and 0 not upgraded.\n", "", 0),
            ],
        ) as ssh:
            result = updates._rig_apt_upgrade()
        self.assertEqual(result["status"], "ok")
        self.assertEqual((result["upgraded_count"], result["installed_count"]), (9, 2))
        plan_argv, apply_argv = (call.args[0] for call in ssh.call_args_list[1:])
        for argv in (plan_argv, apply_argv):
            self.assertEqual(argv[-2:], ["--with-new-pkgs", "upgrade"])
        self.assertNotIn("dist-upgrade", apply_argv)
        rendered = report._html_gamingrig_update({
            "step": "gamingrig_maintenance", "host": "gamingrig-linux",
            "status": "ok", "substeps": [result],
        })
        self.assertIn("9 packages upgraded, 2 newly installed", rendered)

    def test_apt_upgrade_does_not_apply_an_invalid_or_failed_plan(self):
        for output, code in (
            ("Reading package lists...\n", 0),
            ("5 upgraded, 0 newly installed, 0 to remove.\n", 100),
        ):
            with self.subTest(output=output, code=code), patch.object(
                updates, "_rig_ssh",
                side_effect=[
                    ("Reading package lists...\n", "", 0),
                    (output, "apt plan failed" if code else "", code),
                ],
            ):
                result = updates._rig_apt_upgrade()
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["upgraded_count"], 0)

    def test_model_endpoint_requires_exact_retained_ids(self):
        expected = list(updates.RIG_REQUIRED_MODEL_IDS)
        payload = {
            "object": "list",
            "data": [{"id": model_id} for model_id in expected],
        }
        response = json.dumps(payload)
        responses = [
            {"step": "disk", "status": "ok", "stdout_tail": "/dev/root 50%"},
            {"step": "failed_units", "status": "ok", "exit_code": 0},
            {"step": "nvidia_smi", "status": "ok", "stdout_tail": "RTX 5070"},
            {"step": "llama_swap", "status": "ok", "exit_code": 0},
            {
                "step": "model_endpoint",
                "status": "ok",
                "stdout_tail": response[-700:],
                "_full_stdout": response,
                "_full_stderr": "",
            },
        ]
        with patch.object(updates, "_rig_command_result", side_effect=responses):
            result = updates._rig_health_checks()
        model_check = result["checks"][-1]
        self.assertEqual(result["status"], "ok")
        self.assertEqual(model_check["model_ids"], expected)
        self.assertNotIn("_full_stdout", model_check)

    def test_model_endpoint_malformed_empty_and_missing_ids_fail_health(self):
        expected = list(updates.RIG_REQUIRED_MODEL_IDS)
        invalid_payloads = [
            "",
            json.dumps({"object": "list", "data": []}),
            json.dumps({
                "object": "list",
                "data": [{"id": model_id} for model_id in expected[:-1]],
            }),
            json.dumps({
                "object": "list",
                "data": [{"id": model_id} for model_id in expected]
                + [{"id": "unexpected-model"}],
            }),
            json.dumps({
                "object": "list",
                "data": [{"name": expected[0]}]
                + [{"id": model_id} for model_id in expected[1:]],
            }),
            json.dumps({
                "object": "list",
                "data": [{"id": model_id} for model_id in expected[:-1]]
                + [{"id": expected[0]}],
            }),
            "{not-json",
        ]
        for response in invalid_payloads:
            with self.subTest(response=response[:30]):
                responses = [
                    {"step": "disk", "status": "ok", "stdout_tail": "/dev/root 50%"},
                    {"step": "failed_units", "status": "ok", "exit_code": 0},
                    {"step": "nvidia_smi", "status": "ok", "stdout_tail": "RTX 5070"},
                    {"step": "llama_swap", "status": "ok", "exit_code": 0},
                    {
                        "step": "model_endpoint",
                        "status": "ok",
                        "stdout_tail": response[-700:],
                        "_full_stdout": response,
                        "_full_stderr": "",
                    },
                ]
                with patch.object(
                    updates, "_rig_command_result", side_effect=responses
                ):
                    result = updates._rig_health_checks()
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["checks"][-1]["status"], "failed")

    def test_omp_update_rolls_back_with_bun_after_broken_smoke(self):
        responses = [
            ("omp/1.0.0", "", 0),       # pre-version
            ("", "update failed", 1),   # update
            ("omp/1.1.0", "", 0),       # post-version
            ("", "broken binary", 1),   # post-update smoke
            ("", "", 0),                # bun rollback
            ("omp/1.0.0", "", 0),       # reverted version
            ("", "", 0),                # reverted smoke
        ]
        with patch.object(updates, "_rig_ssh", side_effect=responses) as ssh:
            result = updates._rig_omp_update()
        self.assertEqual(result["status"], "reverted")
        self.assertEqual(result["reverted_to"], "omp/1.0.0")
        rollback_call = ssh.call_args_list[4].args[0]
        self.assertEqual(rollback_call[-1],
                         "@oh-my-pi/pi-coding-agent@1.0.0")
        self.assertNotIn(";", " ".join(rollback_call))


    def test_wait_for_linux_requires_a_changed_boot_id(self):
        old_boot = "11111111-1111-1111-1111-111111111111"
        new_boot = "22222222-2222-2222-2222-222222222222"
        with (
            patch.object(
                updates,
                "_rig_ssh",
                side_effect=[
                    (old_boot, "", 0),
                    (new_boot, "", 0),
                ],
            ),
            patch.object(updates.time, "monotonic", side_effect=[0, 1]),
            patch.object(updates.time, "sleep"),

        ):
            result = updates._rig_wait_for_linux(old_boot, timeout_s=2)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["boot_id"], new_boot)
        self.assertEqual(result["attempts"], 2)
    def test_post_reboot_health_polls_until_every_check_is_healthy(self):
        failed = self._healthy()
        failed["status"] = "failed"
        failed["error"] = "model_endpoint: HTTP 503"
        with (
            patch.object(
                updates, "_rig_health_checks",
                side_effect=[failed, self._healthy()],
            ) as health,
            patch.object(updates.time, "monotonic", side_effect=[0, 0]),
            patch.object(updates.time, "sleep") as sleep,
        ):
            result = updates._rig_wait_for_health(timeout_s=2)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["step"], "post_reboot_health")
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(health.call_count, 2)
        sleep.assert_called_once()

    def test_reboot_accepts_established_disconnect_but_not_timeout(self):
        with patch.object(
            updates, "_rig_ssh",
            return_value=("", "Connection timed out", 255),
        ):
            timed_out = updates._rig_reboot()
        self.assertEqual(timed_out["status"], "failed")
        self.assertFalse(timed_out["requested"])

        with patch.object(
            updates, "_rig_ssh",
            return_value=("", "Connection to gamingrig-linux closed", 255),
        ):
            closed = updates._rig_reboot()
        self.assertEqual(closed["status"], "ok")
        self.assertTrue(closed["requested"])

    def test_reboot_rearms_bootnext_waits_for_linux_and_rechecks_health(self):
        with (
            patch.object(updates, "_rig_platform_probe",
                         return_value=self._linux_probe()),
            patch.object(updates, "_rig_apt_upgrade",
                         return_value={"step": "apt_upgrade", "status": "ok",
                                       "upgraded_count": 1}),
            patch.object(updates, "_rig_herdr_update",
                         return_value={"step": "herdr_update", "status": "skipped"}),
            patch.object(updates, "_rig_omp_update",
                         return_value={"step": "omp_update", "status": "skipped"}),
            patch.object(updates, "_rig_health_checks",
                         side_effect=[self._healthy("post_reboot_health")]) as health,
            patch.object(updates, "_rig_reboot_required",
                         return_value={"step": "reboot_required", "status": "ok",
                                       "required": True}),
            patch.object(updates, "_rig_boot_gpu_ready",
                         return_value={"step": "boot_gpu_ready", "status": "ok"}),
            patch.object(updates, "_rig_arm_bootnext",
                         return_value={"step": "bootnext", "status": "ok",
                                       "entry": "0001"}),
            patch.object(updates, "_rig_boot_id",
                         return_value={"step": "pre_reboot_boot_id", "status": "ok",
                                       "boot_id": "11111111-1111-1111-1111-111111111111"}),
            patch.object(updates, "_rig_reboot",
                         return_value={"step": "reboot", "status": "ok"}),
            patch.object(updates, "_rig_wait_for_linux",
                         return_value={"step": "ssh_return", "status": "ok",
                                       "os": "Linux"}) as wait,
        ):
            result = updates._p1_gamingrig_maintenance()
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["reboot_requested"])
        self.assertTrue(result["new_boot_observed"])
        self.assertTrue(result["rebooted"])

        self.assertTrue(result["post_reboot_health_passed"])
        self.assertEqual(health.call_count, 1)
        self.assertEqual(result["post_reboot_health"]["status"], "ok")
        wait.assert_called_once_with(
            "11111111-1111-1111-1111-111111111111")
    def test_failed_ssh_return_does_not_claim_rebooted_or_rechecked(self):
        with (
            patch.object(updates, "_rig_platform_probe",
                         return_value=self._linux_probe()),
            patch.object(updates, "_rig_apt_upgrade",
                         return_value={"step": "apt_upgrade", "status": "ok",
                                       "upgraded_count": 0}),
            patch.object(updates, "_rig_herdr_update",
                         return_value={"step": "herdr_update", "status": "skipped"}),
            patch.object(updates, "_rig_omp_update",
                         return_value={"step": "omp_update", "status": "skipped"}),
            patch.object(updates, "_rig_health_checks",
                         return_value=self._healthy()),
            patch.object(updates, "_rig_reboot_required",
                         return_value={"step": "reboot_required", "status": "ok",
                                       "required": True}),
            patch.object(updates, "_rig_boot_gpu_ready",
                         return_value={"step": "boot_gpu_ready", "status": "ok"}),
            patch.object(updates, "_rig_arm_bootnext",
                         return_value={"step": "bootnext", "status": "ok"}),
            patch.object(updates, "_rig_boot_id",
                         return_value={"step": "pre_reboot_boot_id", "status": "ok",
                                       "boot_id": "11111111-1111-1111-1111-111111111111"}),
            patch.object(updates, "_rig_reboot",
                         return_value={"step": "reboot", "status": "ok",
                                       "requested": True}),
            patch.object(updates, "_rig_wait_for_linux",
                         return_value={"step": "ssh_return", "status": "failed",
                                       "error": "new boot not observed"}),
        ):
            result = updates._p1_gamingrig_maintenance()
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["reboot_requested"])
        self.assertFalse(result["new_boot_observed"])
        self.assertFalse(result["rebooted"])
        self.assertFalse(result["post_reboot_health_passed"])
        rendered = report._html_gamingrig_update(result)
        self.assertIn("ssh_return", rendered)
        self.assertNotIn("rebooted;", rendered)



    def test_reboot_waits_while_boot_kernel_lacks_the_nvidia_module(self):
        deferred = {
            "step": "boot_gpu_ready", "status": "warning",
            "kernel": "6.8.0-142-generic",
            "reason": "reboot deferred: kernel 6.8.0-142-generic has no NVIDIA "
                      "module (driver 595.71.05)",
        }
        with (
            patch.object(updates, "_rig_platform_probe",
                         return_value=self._linux_probe()),
            patch.object(updates, "_rig_apt_upgrade",
                         return_value={"step": "apt_upgrade", "status": "ok",
                                       "upgraded_count": 0}),
            patch.object(updates, "_rig_herdr_update",
                         return_value={"step": "herdr_update", "status": "skipped"}),
            patch.object(updates, "_rig_omp_update",
                         return_value={"step": "omp_update", "status": "skipped"}),
            patch.object(updates, "_rig_health_checks",
                         return_value=self._healthy()) as health,
            patch.object(updates, "_rig_reboot_required",
                         return_value={"step": "reboot_required", "status": "ok",
                                       "required": True}),
            patch.object(updates, "_rig_boot_gpu_ready", return_value=deferred),
            patch.object(updates, "_rig_reboot") as reboot,
        ):
            result = updates._p1_gamingrig_maintenance()
        reboot.assert_not_called()
        health.assert_called_once()
        self.assertEqual(result["status"], "ok")
        self.assertFalse(result["reboot_requested"])
        self.assertIn("no NVIDIA module", report._html_gamingrig_update(result))
        lines, failures = report._tldr_collect_gamingrig_updates(result)
        self.assertEqual(failures, 0)
        self.assertTrue(any("reboot deferred" in line for line in lines))

    def test_boot_gpu_gate_requires_module_matching_the_driver(self):
        def run(module):
            responses = [
                {"step": "boot_kernel", "status": "ok",
                 "stdout_tail": "/boot/vmlinuz-6.8.0-142-generic\n"},
                {"step": "nvidia_driver", "status": "ok",
                 "stdout_tail": "/usr/lib/x86_64-linux-gnu/libnvidia-ml.so.595.91.07\n"},
                module,
            ]
            with patch.object(updates, "_rig_command_result", side_effect=responses):
                return updates._rig_boot_gpu_ready()

        ready = run({"step": "nvidia_module", "status": "ok", "stdout_tail": "595.91.07\n"})
        self.assertEqual(ready["status"], "ok")

        missing = run({"step": "nvidia_module", "status": "failed", "exit_code": 1,
                       "stderr_tail": "modinfo: ERROR: Module nvidia not found."})
        self.assertEqual(missing["status"], "warning")
        self.assertIn("6.8.0-142-generic has no NVIDIA module", missing["reason"])

        stale = run({"step": "nvidia_module", "status": "ok", "stdout_tail": "595.71.05\n"})
        self.assertEqual(stale["status"], "warning")
        self.assertIn("595.71.05 does not match driver 595.91.07", stale["reason"])
        self.assertFalse(updates._rig_has_failure(stale))

    def test_post_update_health_failure_is_result_data(self):
        failed = self._healthy()
        failed["status"] = "failed"
        failed["checks"][-1] = {
            "step": "model_endpoint",
            "status": "failed",
            "error": "HTTP 503",
        }
        failed["error"] = "model_endpoint: HTTP 503"
        with (
            patch.object(updates, "_rig_platform_probe",
                         return_value=self._linux_probe()),
            patch.object(updates, "_rig_apt_upgrade",
                         return_value={"step": "apt_upgrade", "status": "ok",
                                       "upgraded_count": 0}),
            patch.object(updates, "_rig_herdr_update",
                         return_value={"step": "herdr_update", "status": "skipped"}),
            patch.object(updates, "_rig_omp_update",
                         return_value={"step": "omp_update", "status": "skipped"}),
            patch.object(updates, "_rig_health_checks", return_value=failed),
            patch.object(updates, "_rig_reboot_required",
                         return_value={"step": "reboot_required", "status": "skipped",
                                       "required": False}),
        ):
            result = updates._p1_gamingrig_maintenance()
        self.assertEqual(result["status"], "failed")
        self.assertIn("model_endpoint", result["error"])

    def test_gamingrig_updates_are_signal_only_and_reach_tldr(self):
        applied = {
            "steps": [{
                "step": "gamingrig_maintenance",
                "host": "gamingrig-linux",
                "status": "failed",
                "substeps": [
                    {"step": "apt_upgrade", "status": "ok", "upgraded_count": 0},
                    {"step": "omp_update", "status": "reverted",
                     "reverted_to": "omp/1.0.0"},
                    {"step": "health", "status": "failed", "checks": [{
                        "step": "model_endpoint", "status": "failed",
                        "error": "HTTP 503",
                    }]},
                ],
            }],
        }
        html = report._html_updates(applied)
        updates, failures = report._tldr_collect_updates(applied)

        self.assertIn("rolled back", html)
        self.assertIn("model_endpoint", html)
        self.assertEqual(failures, 2)
        self.assertTrue(any("rolled back" in item for item in updates))
        self.assertTrue(any("HTTP 503" in item for item in updates))
    def test_all_failed_reboot_gates_are_rendered(self):
        names = (
            "reboot_required", "pre_reboot_boot_id", "bootnext",
            "reboot", "ssh_return", "post_reboot_health",
        )
        substeps = [
            {"step": name, "status": "failed", "error": f"{name} failed"}
            for name in names
        ]
        rendered = report._html_gamingrig_update({
            "step": "gamingrig_maintenance",
            "host": "gamingrig-linux",
            "status": "failed",
            "substeps": substeps,
        })
        for name in names:
            self.assertIn(name, rendered)

    def test_rig_apply_failures_lead_tldr_health_and_needs_carter(self):
        applied = {
            "steps": [
                {
                    "step": "other_update",
                    "status": "ok",
                },
                {
                    "step": "gamingrig_maintenance",
                    "host": "gamingrig-linux",
                    "status": "failed",
                    "substeps": [{
                        "step": "apt_upgrade",
                        "status": "failed",
                        "error": "apt unavailable",
                    }],
                },
            ],
        }
        facts = report._build_tldr_facts(
            applied,
            {"sections": []},
            {"plans": {}, "ideas": {}},
            {"sections": []},
            {},
        )
        self.assertFalse(facts["health_ok"])

        self.assertIn("apt unavailable", facts["health_issues"][0])
        self.assertIn("gaming-rig apply failure", facts["needs_carter"][0])
        deterministic = report._tldr_deterministic(facts)
        self.assertTrue(deterministic.startswith("Health issues:"))
        self.assertIn("apt unavailable", deterministic)
    def test_phase_failure_without_steps_is_visible_to_reports(self):
        applied = {
            "phase": "apply",
            "phase_status": "failed",
            "phase_failed": True,
            "error": "apt upgrade timed out after 900s",
        }
        rendered = report._html_updates(applied)
        updates, failures = report._tldr_collect_updates(applied)
        facts = report._build_tldr_facts(
            applied,
            {"sections": []},
            {"plans": {}, "ideas": {}},
            {"sections": []},
            {},
        )

        self.assertIn("Maintenance: FAILED", rendered)
        self.assertEqual(failures, 1)
        self.assertIn("P1 maintenance failed", updates[0])
        self.assertIn("apt upgrade timed out", facts["health_issues"][0])
        self.assertTrue(any("maintenance" in item for item in facts["needs_carter"]))
    def test_gamingrig_runs_before_local_apt_failure(self):
        calls = []
        remote = {
            "step": "gamingrig_maintenance",
            "host": updates.RIG_SSH_ALIAS,
            "status": "ok",
            "local_mutation": False,
            "substeps": [],
        }
        local_failure = {
            "step": "apt_upgrade",
            "status": "failed",
            "error": "apt failed",
        }
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)

            def run_remote(*, dry_run=False):
                calls.append("rig")
                return remote

            def run_apt():
                calls.append("apt")
                return local_failure

            with (
                patch.object(updates, "_p1_gamingrig_maintenance", run_remote),
                patch.object(updates, "_p1_apt_upgrade", run_apt),
                patch.object(updates, "_p1_omp_db_repair",
                             return_value={"step": "omp_db_repair", "status": "skipped"}),
            ):
                result = updates.phase_1_apply(run_dir)
        self.assertEqual(calls, ["rig", "apt"])
        self.assertEqual(result["steps"][0]["step"], "gamingrig_maintenance")
    def test_phase_one_timeout_preserves_prior_remote_packet(self):
        remote = {
            "step": "gamingrig_maintenance",
            "host": updates.RIG_SSH_ALIAS,
            "status": "ok",
            "local_mutation": False,
            "substeps": [],
        }
        timeout = subprocess.TimeoutExpired(
            ["sudo", "apt", "upgrade", "-y"], updates.P1_APT_TIMEOUT
        )
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            with (
                patch.object(
                    updates,
                    "_p1_gamingrig_maintenance",
                    return_value=remote,
                ),
                patch.object(
                    updates,
                    "_p1_apt_upgrade",
                    side_effect=timeout,
                ),
                patch.object(
                    updates,
                    "_p1_omp_db_repair",
                    return_value={"step": "omp_db_repair", "status": "skipped"},
                ),
            ):
                result = updates.phase_1_apply(run_dir)
            artifact = json.loads((run_dir / "01-applied.json").read_text())

        self.assertEqual(result["phase_status"], "failed")
        self.assertEqual(artifact["steps"][0], remote)
        self.assertEqual(artifact["steps"][2]["status"], "timeout")
        self.assertIn("timed out", artifact["steps"][2]["error"])

class _FakeJev:
    """Records every ask; answers with one fixed overlap choice and finished noul."""

    def __init__(self, choice="unrelated", confidence=0.97, finished=0.9, error=None, on_ask=None):
        self.choice, self.confidence, self.finished = choice, confidence, finished
        self.error, self.on_ask = error, on_ask
        self.calls = []

    def ask(self, purpose, state, questions):
        self.calls.append({"purpose": purpose, "state": state, "questions": questions})
        if self.on_ask is not None:
            self.on_ask()
        if self.error is not None:
            raise self.error
        return {
            "overlap": {"type": "choice", "choice": self.choice, "confidence": self.confidence},
            "finished": {"type": "noul", "noul": self.finished},
        }


class DotfilesP9bTests(unittest.TestCase):
    def _git(self, *args, cwd=None):
        return subprocess.run(
            ["/usr/bin/git", *args],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
        )

    def _fixture_repo(self, tmp):
        bare = tmp / "dotfiles.git"
        work = tmp / "home"
        self._git("init", "--bare", str(bare))
        self._git("clone", str(bare), str(work))
        self._git("config", "user.name", "P9b Test", cwd=work)
        self._git("config", "user.email", "p9b@example.test", cwd=work)
        config = work / ".config" / "demo"
        config.parent.mkdir(parents=True)
        config.write_text("initial\n")
        self._git("add", "--", ".config/demo", cwd=work)
        self._git("commit", "-m", "initial", cwd=work)
        self._git("push", "origin", "HEAD:main", cwd=work)
        self._git("--git-dir", str(bare), "symbolic-ref", "HEAD", "refs/heads/main")
        self._git("--git-dir", str(bare), "config", "core.bare", "false")
        self._git("--git-dir", str(bare), "config", "core.worktree", str(work))
        self._git("--git-dir", str(bare), "config", "user.name", "P9b Test")
        self._git("--git-dir", str(bare), "config", "user.email", "p9b@example.test")
        # A real dotfiles checkout has an index; without one every tracked file
        # would look deleted+untracked.
        self._git("--git-dir", str(bare), "--work-tree", str(work), "reset", "-q")
        return bare, work, config

    def test_recursive_session_evidence_and_exit_marker(self):
        with tempfile.TemporaryDirectory() as tmp_name:
            root = Path(tmp_name) / "sessions"
            nested = root / "project" / "deeper"
            nested.mkdir(parents=True)
            active = nested / "active.jsonl"
            active.write_text(json.dumps({
                "type": "session",
                "id": "active-1",
                "title": "Bounded title",
                "cwd": "/tmp/project",
            }) + "\n" + json.dumps({
                "type": "message",
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": "edited .config/demo"}],
                },
            }) + "\n")
            evidence = dotfiles.collect_active_session_evidence(
                root,
                now=datetime.now(timezone.utc),
            )
            self.assertEqual(len(evidence), 1)
            self.assertEqual(evidence[0]["session_id"], "active-1")
            active.write_text(active.read_text() + json.dumps({
                "type": "custom",
                "customType": "session_exit",
            }) + "\n")
            self.assertEqual(
                dotfiles.collect_active_session_evidence(
                    root,
                    now=datetime.now(timezone.utc),
                ),
                [],
            )

    def _new_file_run(self, tmp, rel, content, client, **kwargs):
        bare, home, _ = self._fixture_repo(Path(tmp))
        target = home / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content)
        run_dir = home / "run"
        run_dir.mkdir()
        result = dotfiles.phase_9b_dotfiles(
            run_dir, home=home, git_dir=bare, session_root=home / "sessions",
            push=False, jev_client=client, **kwargs,
        )
        head_files = self._git(
            "--git-dir", str(bare), "show", "--name-only", "--format=", "HEAD"
        ).stdout.split()
        return result, head_files, json.loads((run_dir / "09b-dotfiles.json").read_text())

    def test_new_text_file_in_root_is_committed_on_clean_jev_answer(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = _FakeJev()
            result, head_files, artifact = self._new_file_run(
                tmp, "scripts/tool.py", "print('hi')\n", client
            )
            self.assertEqual(result["status"], "committed")
            self.assertEqual(head_files, ["scripts/tool.py"])
            self.assertEqual([c["state"]["path"] for c in client.calls], ["scripts/tool.py"])
            self.assertIn("print('hi')", client.calls[0]["state"]["diff"])
            self.assertEqual(
                artifact["classifications"]["scripts/tool.py"]["jev"],
                {"overlap": "unrelated", "overlap_confidence": 0.97, "finished": 0.9},
            )

    def test_new_file_outside_roots_is_listed_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = _FakeJev()
            result, head_files, _ = self._new_file_run(
                tmp, ".config/other/new.conf", "x = 1\n", client
            )
            self.assertEqual(result["status"], "skipped")
            self.assertEqual(client.calls, [])
            self.assertEqual(head_files, [".config/demo"])
            self.assertEqual(
                result["classifications"][".config/other/new.conf"]["classification"],
                "untracked",
            )

    def test_secret_in_new_file_is_blocked_before_jev(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = _FakeJev()
            token = "ghp_" + "a1B2" * 9
            result, head_files, artifact = self._new_file_run(
                tmp, "scripts/deploy.sh", f"curl -H 'Authorization: {token}'\n", client
            )
            self.assertEqual(client.calls, [])
            self.assertEqual(head_files, [".config/demo"])
            self.assertEqual(
                result["classifications"]["scripts/deploy.sh"]["classification"], "sensitive"
            )
            self.assertNotIn(token, json.dumps(artifact))

    def test_binary_or_oversized_new_file_is_listed_not_sent(self):
        cases = {
            "binary": ("scripts/blob.dat", b"abc\x00def\n"),
            "oversized": ("scripts/big.txt", "x" * (dotfiles.MAX_NEW_FILE_BYTES + 1)),
        }
        for name, (rel, content) in cases.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                client = _FakeJev()
                result, head_files, _ = self._new_file_run(tmp, rel, content, client)
                self.assertEqual(client.calls, [])
                self.assertEqual(head_files, [".config/demo"])
                self.assertEqual(result["classifications"][rel]["classification"], "untracked")
                self.assertIn(rel, result["untracked_paths"])

    def test_jev_unavailable_or_low_confidence_holds_new_file(self):
        clients = {
            "unavailable": _FakeJev(error=jev.JevUnavailable("server", "HTTP 503")),
            "low_confidence": _FakeJev(confidence=0.85),
            "unfinished": _FakeJev(finished=0.4),
        }
        for name, client in clients.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                result, head_files, _ = self._new_file_run(
                    tmp, "scripts/tool.py", "print('hi')\n", client
                )
                self.assertEqual(result["status"], "skipped")
                self.assertEqual(head_files, [".config/demo"])
                self.assertEqual(
                    result["classifications"]["scripts/tool.py"]["classification"],
                    "ambiguous",
                )

    def test_missing_jev_key_holds_candidates(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            dotfiles.jev, "load_client", return_value=None
        ):
            result, head_files, _ = self._new_file_run(
                tmp, "scripts/tool.py", "print('hi')\n", None
            )
            self.assertEqual(head_files, [".config/demo"])
            self.assertEqual(
                result["classifications"]["scripts/tool.py"]["classification"], "ambiguous"
            )

    def test_diff_over_jev_budget_is_held_without_truncation(self):
        with tempfile.TemporaryDirectory() as tmp:
            client = _FakeJev()
            body = "".join(f"line {i}\n" for i in range(dotfiles.JEV_MAX_DIFF_CHARS // 6))
            result, head_files, _ = self._new_file_run(tmp, "scripts/long.txt", body, client)
            self.assertEqual(client.calls, [])
            self.assertEqual(head_files, [".config/demo"])
            row = result["classifications"]["scripts/long.txt"]
            self.assertEqual(row["classification"], "ambiguous")
            self.assertIn("Jev budget", row["reason"])

    def test_parent_commits_exact_unrelated_path_without_push(self):
        with tempfile.TemporaryDirectory() as tmp_name:
            bare, home, config = self._fixture_repo(Path(tmp_name))
            config.write_text("changed by test\n")
            run_dir = home / "run"
            run_dir.mkdir()
            client = _FakeJev()
            result = dotfiles.phase_9b_dotfiles(
                run_dir,
                home=home,
                git_dir=bare,
                session_root=home / "sessions",
                push=False,
                jev_client=client,
            )
            self.assertEqual(result["status"], "committed")
            self.assertEqual(result["push"], "not_requested")
            self.assertEqual(result["paths"], [".config/demo"])
            self.assertEqual(
                self._git(
                    "--git-dir", str(bare), "show", "--format=", "HEAD:.config/demo"
                ).stdout,
                "changed by test\n",
            )

    def test_jev_state_is_redacted_and_artifact_omits_raw_context_and_diffs(self):
        with tempfile.TemporaryDirectory() as tmp_name:
            bare, home, config = self._fixture_repo(Path(tmp_name))
            config.write_text("changed by test\n")
            session_root = home / "sessions"
            session_root.mkdir()
            token = "ghp_" + "a1B2" * 9
            hf = "hf_" + "Q7x" * 12
            (session_root / "active.jsonl").write_text(json.dumps({
                "type": "session",
                "id": "active-root",
                "title": f"Root session {token}",
                "cwd": str(home),
            }) + "\n" + json.dumps({
                "type": "message",
                "message": {
                    "role": "user",
                    "content": [{
                        "type": "text",
                        "text": f"unrelated active work {token}\nHF_TOKEN={hf}",
                    }],
                },
            }) + "\n")
            client = _FakeJev()
            run_dir = home / "run"
            run_dir.mkdir()
            result = dotfiles.phase_9b_dotfiles(
                run_dir,
                dry_run=True,
                home=home,
                git_dir=bare,
                session_root=session_root,
                push=False,
                jev_client=client,
            )
            self.assertEqual(result["status"], "dry_run")
            self.assertEqual(result["would_commit"], [".config/demo"])
            [call] = client.calls
            self.assertEqual(call["questions"], dotfiles.JEV_QUESTIONS)
            self.assertEqual(set(call["state"]), {"path", "diff", "sessions"})
            self.assertEqual(
                call["state"]["sessions"][0]["recent_context"],
                "user: unrelated active work [REDACTED]\nHF_TOKEN=[REDACTED]",
            )
            self.assertEqual(call["state"]["sessions"][0]["title"], "Root session [REDACTED]")
            self.assertNotIn(token, json.dumps(call["state"]))
            self.assertNotIn(hf, json.dumps(call["state"]))
            artifact = json.loads((run_dir / "09b-dotfiles.json").read_text())
            self.assertNotIn("diffs", artifact)
            self.assertNotIn("recent_context", json.dumps(artifact))
            self.assertNotIn("changed by test", json.dumps(artifact))

    def test_symlink_under_new_file_root_is_never_committed(self):
        with tempfile.TemporaryDirectory() as tmp:
            bare, home, _ = self._fixture_repo(Path(tmp))
            (home / "scripts").mkdir()
            (home / "scripts" / "link.sh").symlink_to(home / ".config" / "demo")
            run_dir = home / "run"
            run_dir.mkdir()
            client = _FakeJev()
            result = dotfiles.phase_9b_dotfiles(
                run_dir, home=home, git_dir=bare, session_root=home / "sessions",
                push=False, jev_client=client,
            )
            self.assertEqual(client.calls, [])
            self.assertEqual(
                result["classifications"]["scripts/link.sh"]["classification"], "untracked"
            )
            self.assertEqual(
                self._git("--git-dir", str(bare), "show", "--name-only", "--format=", "HEAD")
                .stdout.split(),
                [".config/demo"],
            )

    def test_reviewed_diff_race_is_rejected_before_staging(self):
        with tempfile.TemporaryDirectory() as tmp_name:
            bare, home, config = self._fixture_repo(Path(tmp_name))
            config.write_text("first version\n")

            client = _FakeJev(on_ask=lambda: config.write_text("second version\n"))

            run_dir = home / "run"
            run_dir.mkdir()
            result = dotfiles.phase_9b_dotfiles(
                run_dir,
                home=home,
                git_dir=bare,
                session_root=home / "sessions",
                push=False,
                jev_client=client,
            )
            self.assertEqual(result["status"], "ambiguous")
            self.assertIn("diff changed", result["reason"])
            self.assertEqual(
                self._git(
                    "--git-dir", str(bare), "show", "--format=", "HEAD:.config/demo"
                ).stdout,
                "initial\n",
            )

    def test_credential_like_diff_is_never_sent_to_classifier(self):
        with tempfile.TemporaryDirectory() as tmp_name:
            bare, home, config = self._fixture_repo(Path(tmp_name))
            fake = "-".join(("not", "a", "real", "but", "secret", "shaped", "value"))
            config.write_text(f'api_key = "{fake}"\n')
            run_dir = home / "run"
            run_dir.mkdir()
            response = _FakeJev(error=AssertionError("sensitive diff reached Jev"))
            result = dotfiles.phase_9b_dotfiles(
                run_dir,
                home=home,
                git_dir=bare,
                session_root=home / "sessions",
                push=False,
                jev_client=response,
            )
            self.assertEqual(result["status"], "skipped")
            self.assertEqual(
                result["classifications"][".config/demo"]["classification"],
                "sensitive",
            )
            self.assertEqual(response.calls, [])

    def test_malformed_recent_session_skips_all_paths(self):
        with tempfile.TemporaryDirectory() as tmp_name:
            bare, home, config = self._fixture_repo(Path(tmp_name))
            config.write_text("changed by test\n")
            session_root = home / "sessions" / "nested"
            session_root.mkdir(parents=True)
            (session_root / "broken.jsonl").write_text("{not-json\n")
            run_dir = home / "run"
            run_dir.mkdir()
            response = _FakeJev(error=AssertionError("Jev must not classify ambiguity"))
            result = dotfiles.phase_9b_dotfiles(
                run_dir,
                home=home,
                git_dir=bare,
                session_root=home / "sessions",
                push=False,
                jev_client=response,
            )
            self.assertEqual(result["status"], "skipped")
            self.assertEqual(
                result["classifications"][".config/demo"]["classification"],
                "ambiguous",
            )
            self.assertEqual(response.calls, [])

    def test_untracked_paths_are_listed_never_staged(self):
        with tempfile.TemporaryDirectory() as tmp_name:
            bare, home, config = self._fixture_repo(Path(tmp_name))
            config.write_text("changed by test\n")
            new = home / ".config" / "new-unit.conf"
            new.write_text("brand new\n")
            run_dir = home / "run"
            run_dir.mkdir()

            client = _FakeJev()

            result = dotfiles.phase_9b_dotfiles(
                run_dir, home=home, git_dir=bare,
                session_root=home / "sessions", push=False, jev_client=client,
            )
            self.assertEqual(result["status"], "committed")
            self.assertEqual(result["paths"], [".config/demo"])
            self.assertIn(".config/new-unit.conf", result["untracked_paths"])
            self.assertEqual(
                result["classifications"][".config/new-unit.conf"]["classification"],
                "untracked",
            )
            self.assertEqual([c["state"]["path"] for c in client.calls], [".config/demo"])
            committed = self._git(
                "--git-dir", str(bare), "show", "--name-only", "--format=", "HEAD"
            ).stdout.split()
            self.assertEqual(committed, [".config/demo"])
            self.assertEqual(
                dotfiles.untracked_in_scope(git_dir=bare, home=home),
                [".config/new-unit.conf"],
            )

    def test_commit_refuses_untracked_path_even_if_approved(self):
        with tempfile.TemporaryDirectory() as tmp_name:
            bare, home, _ = self._fixture_repo(Path(tmp_name))
            (home / ".config" / "new.conf").write_text("x\n")
            statuses, _ = dotfiles._snapshot(bare, home)
            result = dotfiles._commit_exact_paths(
                [".config/new.conf"], git_dir=bare, home=home,
                expected_dirty_paths=list(statuses), push=False,
            )
            self.assertEqual(result["status"], "ambiguous")
            self.assertEqual(
                self._git("--git-dir", str(bare), "diff", "--cached", "--name-only").stdout,
                "",
            )

    def test_secret_scan_blocks_commit_and_push(self):
        with tempfile.TemporaryDirectory() as tmp_name:
            bare, home, config = self._fixture_repo(Path(tmp_name))
            head = self._git("--git-dir", str(bare), "rev-parse", "HEAD").stdout
            fake = "hf_" + "Q7x" * 12
            name = "HF_" + "TOKEN"
            config.write_text(f"{name}={fake}\n")
            run_dir = home / "run"
            run_dir.mkdir()
            # The pre-classifier gate keeps it away from the model...
            result = dotfiles.phase_9b_dotfiles(
                run_dir, home=home, git_dir=bare, session_root=home / "sessions",
                push=True, jev_client=_FakeJev(error=AssertionError("reached Jev")),
            )
            self.assertEqual(
                result["classifications"][".config/demo"]["classification"], "sensitive"
            )
            # ...and the staged-diff scan blocks commit+push even if approved.
            statuses, _ = dotfiles._snapshot(bare, home)
            result = dotfiles._commit_exact_paths(
                [".config/demo"], git_dir=bare, home=home,
                expected_dirty_paths=list(statuses), push=True,
            )
            self.assertEqual(result["status"], "secret_blocked")
            self.assertTrue(result["phase_failed"])
            self.assertEqual(result["secret_findings"][0]["path"], ".config/demo")
            self.assertNotIn(fake, json.dumps(result))
            self.assertEqual(self._git("--git-dir", str(bare), "rev-parse", "HEAD").stdout, head)
            self.assertEqual(
                self._git("--git-dir", str(bare), "diff", "--cached", "--name-only").stdout,
                "",
            )

    def test_bare_tokens_and_placeholder_substrings_are_not_skipped(self):
        bare_token = "ghp_" + "a1B2" * 9
        diff = (
            "diff --git a/.config/x b/.config/x\n--- a/.config/x\n+++ b/.config/x\n"
            "@@ -1,0 +1,2 @@\n"
            f"+git remote set-url origin https://{bare_token}@github.com/c/r.git\n"
            "+sk-" + "Zq9" * 10 + "\n"
        )
        self.assertEqual(
            [h["line"] for h in dotfiles.scan_diff_for_secrets(diff)], [1, 2]
        )
        self.assertIsNotNone(dotfiles._sensitive_diff_reason(diff))
        nonesque = (
            "diff --git a/.config/x b/.config/x\n--- a/.config/x\n+++ b/.config/x\n"
            "@@ -1,0 +1 @@\n+pass" + "word = Xnone-Real-Pass-42\n"
        )
        self.assertIsNotNone(dotfiles._sensitive_diff_reason(nonesque))

    def test_secret_scan_rules(self):
        def diff(path, *added):
            body = "".join(f"+{line}\n" for line in added)
            return (f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
                    f"@@ -1,0 +1,{len(added)} @@\n{body}")

        hits = dotfiles.scan_diff_for_secrets(diff(
            ".config/app.conf",
            "token = " + "ghp_" + "a1B2" * 9,
            "WEBHOOK_SECRET" + "_GITHUB=" + "s3cr3tV4lue" * 2,
            "key: " + "AKIA" + "ABCDEFGHIJKLMNOP",
            "-----BEGIN OPENSSH " + "PRIVATE KEY-----",
            "blob = '" + "Zx9Qr2Lm8Tv4Wp6Ks1Nb3Hc5Jd7Fg0Ya'",
        ))
        self.assertEqual([h["line"] for h in hits], [1, 2, 3, 4, 5])
        self.assertEqual(dotfiles.scan_diff_for_secrets(diff(
            ".config/app.conf",
            "HF_TOKEN=${HF_TOKEN}",
            "sha = " + "0123456789abcdef" * 4,
            "Environment=PATH=/usr/local/bin:/usr/bin",
        )), [])
        self.assertEqual(
            dotfiles.scan_diff_for_secrets(diff(".config/cloudflare/api-token", "x"))[0]["rule"],
            "secret-like file name",
        )
        self.assertEqual(
            dotfiles.scan_diff_for_secrets(diff("secrets/prod.key", "x"))[0]["rule"],
            "secret-like file name",
        )


class OpenWebUIUpdateTests(unittest.TestCase):
    NOW = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)
    OLD = "services:\n  open-webui:\n    image: ghcr.io/open-webui/open-webui:0.11.1\n"
    STATE = {"integrity": "ok", "missing_tables": [],
             "counts": {"user": 1, "chat": 10, "model": 3}}

    def _release(self, published="2026-08-01T00:00:00Z", body=""):
        return {"tag_name": "v0.11.3", "draft": False, "prerelease": False,
                "published_at": published, "body": body}

    def _run(self, tmp, *, verify=(("", {}),), db_state=None, dry_run=False,
             release=None):
        """Run the full guarded transaction against fakes; return (result, calls)."""
        compose = Path(tmp) / "docker-compose.yml"
        compose.write_text(self.OLD)
        calls = {"compose": [], "sudo": [], "verify": []}

        def fake_compose(*args, timeout=300):
            calls["compose"].append(args)
            return "", "", 0

        def fake_sudo(*args, timeout=None):
            calls["sudo"].append(args)
            if args[:2] == ("tar", "-tzf"):
                return "./\n./webui.db\n./uploads/\n", "", 0
            return "", "", 0

        verify_results = list(verify)

        def fake_verify(expected, baseline, recovery, label):
            calls["verify"].append((expected, label, compose.read_text()))
            return verify_results.pop(0)

        with (
            patch.object(updates, "OPENWEBUI_COMPOSE", compose),
            patch.object(updates, "OPENWEBUI_RECOVERY_ROOT", Path(tmp) / "recovery"),
            patch.object(updates, "_owui_container_state",
                         return_value={"status": "running", "health": "healthy"}),
            patch.object(updates, "_owui_api_version", return_value="0.11.1"),
            patch.object(updates, "_owui_free_space_problem", return_value=""),
            patch.object(updates, "run_capture_ok", return_value=("", "", 0)),
            patch.object(updates, "_owui_image_identity",
                         return_value=("0.11.3", "ghcr.io/open-webui/open-webui@sha256:ab", "id")),
            patch.object(updates, "_owui_sqlite", return_value=("", "", 0)),
            patch.object(updates, "_owui_db_state", return_value=db_state or self.STATE),
            patch.object(updates, "_owui_compose", side_effect=fake_compose),
            patch.object(updates, "_owui_sudo", side_effect=fake_sudo),
            patch.object(updates, "_owui_verify", side_effect=fake_verify),
        ):
            result = updates._p1_openwebui(dry_run, release=release or self._release())
        return result, calls, compose.read_text()

    def test_success_pins_target_and_records_revert(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, calls, compose = self._run(tmp)
            recorded = json.loads(
                (Path(result["recovery_dir"]) / "steward-update.json").read_text())
        self.assertEqual(result["status"], "ok")
        self.assertEqual((result["pre_version"], result["post_version"]), ("0.11.1", "0.11.3"))
        self.assertEqual(result["reason"], "latest stable release")
        self.assertTrue(result["local_mutation"])
        self.assertIn("open-webui:0.11.3", compose)
        self.assertIn("open-webui:0.11.1", result["revert"])
        self.assertEqual(calls["verify"][0][:2], ("0.11.3", "post"))
        self.assertTrue(updates._p1_deploy_step_ok(result))
        self.assertEqual(recorded["status"], "ok")
        archive = next(args for args in calls["sudo"] if "-czpf" in args)
        self.assertIn("--exclude=./cache", archive)

    def test_failed_gate_restores_image_pin_and_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, calls, compose = self._run(tmp, verify=[
                ("migration/startup errors in logs: alembic failed", {}),
                ("", {"api_version": "0.11.1"}),
            ])
        self.assertEqual(result["status"], "rolled_back")
        self.assertEqual(result["post_version"], "0.11.1")
        self.assertIn("alembic failed", result["error"])
        self.assertEqual(compose, self.OLD)
        # The rollback verify ran against the restored pin.
        self.assertEqual(calls["verify"][1][:2], ("0.11.1", "rollback"))
        self.assertEqual(calls["verify"][1][2], self.OLD)
        restore = next(args for args in calls["sudo"] if args[:2] == ("bash", "-c"))
        self.assertEqual(restore[2], updates._OWUI_RESTORE_SCRIPT)
        self.assertTrue(restore[-1].endswith("data-critical.tar.gz"))
        # quiesce, start target, then the rollback's stop and restart.
        self.assertEqual(calls["compose"], [("stop", "open-webui"), ("up", "-d"),
                                            ("stop", "open-webui"), ("up", "-d")])
        self.assertEqual(result["step"], "openwebui_update")

    def test_failed_rollback_is_failed_with_manual_revert(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, _, _ = self._run(tmp, verify=[
                ("container not healthy", {}), ("HTTP 502", {"api_version": ""})])
        self.assertEqual(result["status"], "failed")
        self.assertIn("ROLLBACK FAILED", result["error"])
        self.assertIn("data-critical.tar.gz", result["revert"])

    def test_unusable_baseline_skips_before_any_downtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, calls, compose = self._run(
                tmp, db_state={"integrity": "*** corrupt", "counts": {}, "missing_tables": []})
        self.assertEqual(result["status"], "skipped")
        self.assertTrue(result["reason"].startswith("baseline:"))
        self.assertEqual(compose, self.OLD)
        self.assertEqual(calls["compose"], [])
        self.assertEqual(calls["verify"], [])

    def test_dry_run_and_current_mutate_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, calls, compose = self._run(tmp, dry_run=True)
        self.assertEqual(result["status"], "skipped")
        self.assertTrue(result["reason"].startswith("dry run: would update 0.11.1 -> 0.11.3"))
        self.assertEqual(compose, self.OLD)
        self.assertEqual(calls, {"compose": [], "sudo": [], "verify": []})
        with tempfile.TemporaryDirectory() as tmp:
            release = {**self._release(), "tag_name": "v0.11.1"}
            result, calls, compose = self._run(tmp, release=release)
        self.assertEqual((result["status"], result["reason"]), ("skipped", "current"))
        self.assertEqual(compose, self.OLD)
        self.assertEqual(calls, {"compose": [], "sudo": [], "verify": []})

    def test_previous_image_removed_only_after_health_pass(self):
        images = {"ghcr.io/open-webui/open-webui:0.11.1": "sha256:old"}
        with tempfile.TemporaryDirectory() as tmp:
            passed, _, _ = self._run(tmp)
        with tempfile.TemporaryDirectory() as tmp:
            rolled_back, _, _ = self._run(tmp, verify=[
                ("container not healthy", {}), ("", {"api_version": "0.11.1"})])
        self.assertEqual(rolled_back["status"], "rolled_back")
        _, removed = _run_docker_cleanup([passed], images=images)
        self.assertEqual(removed, ["sha256:old"])
        # Rollback: 0.11.1 is running again and must stay.
        result, removed = _run_docker_cleanup([rolled_back], images=images)
        self.assertEqual(removed, [])
        self.assertEqual(result["superseded_images"], [])


def _cache_record(record_id, parent="", days=10, in_use=False, now=None):
    used = (now or DockerCleanupTests.NOW) - timedelta(days=days)
    return {"ID": record_id + ("*" if in_use else ""), "Parent": parent,
            "InUse": "true" if in_use else "false", "Size": "1.5MB",
            "LastUsedAt": "" if in_use else used.strftime("%Y-%m-%d %H:%M:%S.123456789 +0000 UTC")}


def _run_docker_cleanup(steps, *, images=(), containers=(), dangling=(), cache=(),
                        rm_error="", now=None):
    """Run _p1_docker_cleanup against a fake docker CLI; return (result, removed IDs)."""
    images = dict(images)
    calls = []

    def fake(cmd, **kwargs):
        calls.append(cmd)
        args = cmd[1:]
        if args[:2] == ["ps", "-aq"]:
            return "".join(f"container{i}\n" for i in range(len(containers))), "", 0
        if args[:1] == ["inspect"]:
            return "".join(f"{image_id}\n" for image_id in containers), "", 0
        if args[:2] == ["image", "inspect"]:
            ref = args[-1]
            if ref in images or ref in dangling:
                return f"{images.get(ref, ref)}\n", "", 0
            return "", f"Error: No such image: {ref}", 1
        if args[:2] == ["image", "rm"]:
            if rm_error:
                return "", rm_error, 1
            return f"Deleted: {args[2]}\n", "", 0
        if args[:1] == ["images"]:
            return "".join(f"{image_id}\n" for image_id in dangling), "", 0
        if args[:2] == ["system", "df"]:
            return json.dumps(list(cache)), "", 0
        if args[:2] == ["builder", "prune"]:
            record_id = args[-1].split("=", 1)[1]
            return f"ID\tRECLAIMABLE\tSIZE\n{record_id}\ttrue\t1.5MB\nTotal:\t1.5MB\n", "", 0
        raise AssertionError(f"unexpected command {cmd}")

    with patch.object(updates, "run_capture_ok", side_effect=fake):
        result = updates._p1_docker_cleanup(steps, now=now or DockerCleanupTests.NOW)
    removed = [cmd[3] for cmd in calls if cmd[1:3] == ["image", "rm"]]
    result["_prune_ids"] = [cmd[-1].split("=", 1)[1] for cmd in calls
                            if cmd[1:3] == ["builder", "prune"]]
    return result, removed


class DockerCleanupTests(unittest.TestCase):
    NOW = datetime(2026, 9, 29, 4, 0, tzinfo=timezone.utc)
    FRESHRSS_OLD = "freshrss/freshrss:1.30.0@sha256:" + "1" * 64
    SEARXNG_OLD = "docker.io/searxng/searxng@sha256:" + "2" * 64

    def test_only_successful_image_updates_supersede_their_previous_image(self):
        images = {self.FRESHRSS_OLD: "sha256:fresh", self.SEARXNG_OLD: "sha256:searx"}
        steps = [
            {"step": "freshrss", "status": "bumped", "pre_image": self.FRESHRSS_OLD,
             "post_image": "freshrss/freshrss:1.30.1@sha256:" + "3" * 64},
            {"step": "searxng", "status": "reverted", "reverted_to": self.SEARXNG_OLD},
        ]
        result, removed = _run_docker_cleanup(steps, images=images)
        self.assertEqual(removed, ["sha256:fresh"])
        self.assertEqual(result["status"], "ok")

    def test_image_used_by_any_container_is_never_removed(self):
        steps = [{"step": "searxng", "status": "ok", "pre_image": self.SEARXNG_OLD,
                  "post_image": "docker.io/searxng/searxng@sha256:" + "4" * 64}]
        # A stopped container still holds the superseded image and a dangling one.
        result, removed = _run_docker_cleanup(
            steps, images={self.SEARXNG_OLD: "sha256:searx"},
            containers=["sha256:searx", "sha256:pinned"],
            dangling=["sha256:pinned", "sha256:orphan"])
        self.assertEqual(removed, ["sha256:orphan"])
        self.assertEqual(result["kept_in_use"], [self.SEARXNG_OLD, "sha256:pinned"])

    def test_removal_failure_is_reported_not_raised(self):
        steps = [{"step": "openwebui_update", "status": "ok",
                  "pre_image": "ghcr.io/open-webui/open-webui:0.11.3",
                  "post_image": "ghcr.io/open-webui/open-webui:0.11.4"}]
        result, _ = _run_docker_cleanup(
            steps, images={"ghcr.io/open-webui/open-webui:0.11.3": "sha256:old"},
            rm_error="Error response from daemon: conflict: unable to delete")
        self.assertEqual(result["status"], "warning")
        self.assertIn("unable to delete", result["reason"])
        # A cleanup problem degrades P1; it never fails or retries it.
        data = updates._finish_p1(Path("/nonexistent"), {"steps": [result]},
                                  progress=lambda payload: None)
        self.assertEqual(data["phase_status"], "degraded")

    def test_docker_unavailable_is_reported_not_raised(self):
        with patch.object(updates, "run_capture_ok",
                          return_value=("", "Cannot connect to the Docker daemon", 1)):
            result = updates._p1_docker_cleanup([], now=self.NOW)
        self.assertEqual(result["status"], "warning")
        self.assertIn("Cannot connect", result["reason"])

    def test_build_cache_prunes_only_whole_stale_chains_leaves_first(self):
        cache = [
            # stale chain: base <- mid <- leaf, all unused for 8+ days
            _cache_record("base", days=40), _cache_record("mid", "base", days=30),
            _cache_record("leaf", "mid", days=8),
            # warm chain: an old parent stays while a child was used this week
            _cache_record("old", days=40), _cache_record("warm", "old", days=6),
            # the stale sibling of the warm record still goes
            _cache_record("sibling", "old", days=20),
            # an in-use record keeps its whole ancestry
            _cache_record("held", days=40), _cache_record("busy", "held", in_use=True),
        ]
        result, _ = _run_docker_cleanup([], cache=cache)
        pruned = result["_prune_ids"]
        self.assertEqual(sorted(pruned), ["base", "leaf", "mid", "sibling"])
        self.assertLess(pruned.index("leaf"), pruned.index("mid"))
        self.assertLess(pruned.index("mid"), pruned.index("base"))
        self.assertEqual(result["build_cache"]["reclaimed"], "6MB")
        self.assertEqual(result["status"], "ok")

    def test_build_cache_keeps_anything_used_within_seven_days(self):
        cache = [
            _cache_record("used_7d_minus_1s", days=7, now=self.NOW + timedelta(seconds=1)),
            _cache_record("used_7d_plus_1s", days=7, now=self.NOW - timedelta(seconds=1)),
        ]
        result, _ = _run_docker_cleanup([], cache=cache)
        self.assertEqual(result["_prune_ids"], ["used_7d_plus_1s"])


class OmpUpdateTests(unittest.TestCase):
    def _home(self, tmp, local="symlink"):
        home = Path(tmp)
        canonical = home / ".bun" / "bin" / "omp"
        canonical.parent.mkdir(parents=True)
        canonical.write_text("#!/bin/sh\n")
        canonical.chmod(0o755)
        local_bin = home / ".local" / "bin"
        local_bin.mkdir(parents=True)
        if local == "symlink":
            (local_bin / "omp").symlink_to(canonical)
        elif local == "stray":
            (local_bin / "omp").write_text("#!/bin/sh\n")
            (local_bin / "omp").chmod(0o755)
        (home / "proc").mkdir()
        return home, canonical, local_bin

    def _run(self, home, local_bin, versions):
        """versions: realpath -> [version before update, version after]."""
        state = {"updated": False}
        commands = []

        def fake_capture(cmd, **kwargs):
            commands.append(cmd)
            before, after = versions[os.path.realpath(cmd[0])]
            return after if state["updated"] else before

        def fake_capture_ok(cmd, **kwargs):
            commands.append(cmd)
            if cmd[1:] == ["update"]:
                state["updated"] = True
            return "", "", 0

        env = {"PATH": f"{local_bin}:{home / '.bun' / 'bin'}"}
        with (
            patch.object(updates, "HOME", home),
            patch.object(updates, "user_env", return_value=env),
            patch.object(updates, "run_capture", side_effect=fake_capture),
            patch.object(updates, "run_capture_ok", side_effect=fake_capture_ok),
        ):
            result = updates._p1_omp_update(proc_root=home / "proc")
        return result, commands

    def test_update_uses_only_the_canonical_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            home, canonical, local_bin = self._home(tmp)
            result, commands = self._run(
                home, local_bin, {str(canonical): ["omp/1.0.0", "omp/1.1.0"]})
        self.assertEqual(result["status"], "ok")
        self.assertEqual((result["pre_version"], result["post_version"]),
                         ("omp/1.0.0", "omp/1.1.0"))
        mutations = [cmd for cmd in commands if cmd[1:] in (["update"], ["-p"])]
        self.assertTrue(mutations)
        self.assertTrue(all(cmd[0] == str(canonical) for cmd in mutations))
        self.assertFalse(any(cmd[0] == "omp" for cmd in commands))
        snapshot = home / ".local" / "state" / "omp-rollback" / "omp-1.0.0"
        self.assertEqual(result["snapshot"], str(snapshot))
        self.assertEqual(result["revert"], f"install -m 755 {snapshot} {canonical}")
        self.assertEqual({entry["realpath"] for entry in result["entry_points"]},
                         {str(canonical)})
        self.assertEqual(result["stale_processes"], {"count": 0, "pids": []})

    def test_rollback_restores_the_binary_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            home, canonical, local_bin = self._home(tmp)
            canonical.write_text("#!/bin/sh\necho good 1.0.0\n")
            smoke = iter([1, 0])

            def fake_capture_ok(cmd, **kwargs):
                if cmd[1:] == ["-p"]:
                    return "", "", next(smoke)
                if cmd[1:] == ["update"]:
                    canonical.write_text("#!/bin/sh\nbroken 1.1.0\n")
                return "", "", 0

            with (
                patch.object(updates, "HOME", home),
                patch.object(updates, "user_env", return_value={"PATH": str(local_bin)}),
                patch.object(updates, "run_capture",
                             side_effect=["omp/1.0.0", "omp/1.1.0", "omp/1.0.0",
                                          "omp/1.0.0"]),
                patch.object(updates, "run_capture_ok", side_effect=fake_capture_ok) as ok,
            ):
                result = updates._p1_omp_update(proc_root=home / "proc")
            self.assertEqual(result["status"], "reverted")
            self.assertEqual(canonical.read_text(), "#!/bin/sh\necho good 1.0.0\n")
            self.assertTrue(os.access(canonical, os.X_OK))
            # No package-manager reinstall (would create a second install).
            self.assertFalse(any("bun" in os.path.basename(str(call.args[0][0]))
                                 for call in ok.call_args_list))

    def test_snapshots_keep_only_the_last_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            home, canonical, _ = self._home(tmp)
            rollback = home / "rb"
            for i, tag in enumerate(("1.0.0", "1.1.0", "1.2.0")):
                snap = updates._omp_snapshot(canonical, tag, rollback)
                os.utime(snap, (1000 + i, 1000 + i))
            self.assertEqual(sorted(p.name for p in rollback.iterdir()),
                             ["omp-1.1.0", "omp-1.2.0"])

    def test_entry_point_mismatch_fails_the_step(self):
        with tempfile.TemporaryDirectory() as tmp:
            home, canonical, local_bin = self._home(tmp, local="stray")
            stray = str(local_bin / "omp")
            result, _ = self._run(home, local_bin, {
                str(canonical): ["omp/1.0.0", "omp/1.1.0"],
                stray: ["omp/1.0.0", "omp/1.0.0"],
            })
        self.assertEqual(result["status"], "failed")
        self.assertIn("resolve to different files", result["error"])
        self.assertIn("report different versions", result["error"])
        self.assertIn(f"local_bin={stray}", result["error"])
        # A failed omp_update never triggers the worker refresh.
        self.assertEqual(updates._p1_worker_omp_refresh(result)["status"], "skipped")

    def test_stale_processes_are_counted_never_killed(self):
        with tempfile.TemporaryDirectory() as tmp:
            home, canonical, _ = self._home(tmp)
            proc = home / "proc"
            links = {
                "101": f"{canonical} (deleted)",        # replaced by the update
                "102": str(canonical),                  # current: fine
                "103": "/opt/old/omp",                  # a different install
                "104": "/usr/bin/python3",              # not omp
                "105": str(updates.WORKER_OMP),         # sandbox copy by design
            }
            for pid, target in links.items():
                (proc / pid).mkdir()
                os.symlink(target, proc / pid / "exe")
            (proc / "self").mkdir()
            with patch.object(updates.os, "kill") as kill:
                stale = updates._omp_stale_processes(canonical, proc)
            kill.assert_not_called()
        self.assertEqual(stale, {"count": 2, "pids": [101, 103]})


class WorkerOmpRefreshTests(unittest.TestCase):
    OK = {"step": "omp_update", "status": "ok",
          "pre_version": "omp/1.0.0", "post_version": "omp/1.1.0"}

    def test_refresh_runs_only_after_a_version_change(self):
        for omp_result in (
            {**self.OK, "status": "skipped", "post_version": "omp/1.0.0"},
            {**self.OK, "post_version": "omp/1.0.0"},
            {**self.OK, "status": "reverted"},
            {**self.OK, "status": "failed"},
        ):
            with (
                self.subTest(omp_result=omp_result),
                patch.object(updates, "run_capture_ok") as ok,
                patch.object(updates, "run_capture") as capture,
            ):
                result = updates._p1_worker_omp_refresh(omp_result)
                self.assertEqual(result["status"], "skipped")
                ok.assert_not_called()
                capture.assert_not_called()

    def test_refresh_runs_omp_only_provisioning_and_verifies_version(self):
        with tempfile.TemporaryDirectory() as tmp, (
            patch.object(updates, "HOME", Path(tmp))
        ), patch.object(updates, "run_capture",
                        side_effect=["omp/1.0.0", "omp/1.1.0"]), patch.object(
            updates, "run_capture_ok", return_value=("refreshed", "", 0)
        ) as ok:
            result = updates._p1_worker_omp_refresh(self.OK)
        self.assertEqual(result["status"], "ok")
        self.assertEqual((result["pre_version"], result["post_version"]),
                         ("omp/1.0.0", "omp/1.1.0"))
        self.assertEqual(ok.call_args.args[0], [
            "sudo", "-n", "bash", f"{tmp}/system-config/steward-worker-provision.sh",
            "--omp-only"])

    def test_worker_version_mismatch_fails(self):
        with patch.object(updates, "run_capture",
                          side_effect=["omp/1.0.0", "omp/1.0.0"]), patch.object(
            updates, "run_capture_ok", return_value=("", "", 0)
        ):
            result = updates._p1_worker_omp_refresh(self.OK)
        self.assertEqual(result["status"], "failed")
        self.assertIn("worker omp reports omp/1.0.0, local is omp/1.1.0", result["error"])


class AppDeployTests(unittest.TestCase):
    PRE, NEW, LOCAL = "a" * 40, "b" * 40, "c" * 40

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        home = Path(tmp.name)
        self.spec = {
            "repo": home / "dev" / "blog",
            "github": "carter2099/blog",
            "production": home / "blog" / "blog",
            "deploy": ["bash", str(home / "dev" / "blog" / "deploy" / "deploy.sh")],
            "timeout": 1800,
        }
        self.state = {
            "prod": self.PRE, "origin": self.NEW, "local": self.PRE, "branch": "main",
            "dirty": "", "not_ancestors": set(),
            "runs": [{"name": "test", "status": "completed", "conclusion": "success"},
                     {"name": "scan", "status": "completed", "conclusion": "skipped"}],
            "statuses": [], "deploy_code": 0, "deploy_moves_to": self.NEW,
        }
        self.commands = []
        self.deploy_kwargs = None

    def _fake(self, cmd, **kwargs):
        state = self.state
        self.commands.append(cmd)
        if cmd[0] == "git":
            path, args = cmd[2], cmd[3:]
            if args == ["rev-parse", "HEAD"]:
                return (state["prod"] if path == str(self.spec.get("production"))
                        else state["local"]) + "\n", "", 0
            if args[:2] == ["rev-parse", "--verify"]:
                return state["origin"] + "\n", "", 0
            if args[:2] == ["symbolic-ref", "--short"]:
                return state["branch"] + "\n", "", 0
            if args[0] == "status":
                return state["dirty"], "", 0
            if args[:2] == ["merge-base", "--is-ancestor"]:
                return "", "", 1 if args[2] in state["not_ancestors"] else 0
            if args[:2] == ["merge", "--ff-only"]:
                state["local"] = state["origin"]
            return "", "", 0
        if cmd[0] == "gh":
            if cmd[2].endswith("check-runs?per_page=100"):
                runs = state["runs"]
                return json.dumps({"total_count": len(runs), "check_runs": runs}), "", 0
            return json.dumps({"state": "pending", "statuses": state["statuses"]}), "", 0
        if cmd[0] == "timeout":
            self.deploy_kwargs = kwargs
            state["prod"] = state["deploy_moves_to"]
            return "deploy output", "", state["deploy_code"]
        if cmd == self.spec.get("version_cmd"):
            return state["prod"] + "\n", "", 0
        raise AssertionError(f"unexpected command {cmd}")

    def _deploy(self):
        with patch.object(updates, "run_capture_ok", side_effect=self._fake):
            return updates._p1_app_deploy("blog", self.spec)

    def _deployed(self):
        return any(cmd[0] == "timeout" for cmd in self.commands)

    def test_each_gate_skips_without_deploying(self):
        cases = {
            "current": ({"origin": self.PRE}, "current"),
            "dirty": ({"dirty": " M app.rb\n"}, "uncommitted changes"),
            "off-main": ({"branch": "feature"}, "is on feature, not main"),
            "non-ff": ({"local": self.LOCAL, "not_ancestors": {self.LOCAL}},
                       "cannot fast-forward"),
            "ci-red": ({"runs": [{"name": "test", "status": "completed",
                                  "conclusion": "failure"}]}, "not CI-green: test"),
            "ci-pending": ({"runs": [{"name": "test", "status": "in_progress",
                                      "conclusion": None}]}, "not CI-green"),
            "ci-status-red": ({"statuses": [{"context": "ext", "state": "failure"}]},
                              "ext: failure"),
            "no-checks": ({"runs": []}, "no CI checks reported"),
        }
        base = dict(self.state)
        for name, (overrides, expected) in cases.items():
            with self.subTest(name):
                self.state = {**base, **overrides}
                self.commands = []
                result = self._deploy()
                self.assertEqual(result["status"], "skipped")
                self.assertIn(expected, result["reason"])
                self.assertEqual(result["service"], "blog")
                self.assertIsNone(result["revert"])
                self.assertFalse(self._deployed())
                self.assertFalse(any(cmd[3:5] == ["merge", "--ff-only"]
                                     for cmd in self.commands if cmd[0] == "git"))

    def test_herdr_web_client_is_deployed_by_its_transactional_release_script(self):
        spec = config.DEPLOY_REGISTRY["herdr-web-client"]
        self.assertEqual(spec["deploy"][-1],
                         str(config.HOME / "dev" / "herdr-web-client" / "deploy" / "release.sh"))
        self.assertEqual(spec["version_cmd"][1:], ["--version"])

    def test_artifact_service_verifies_the_version_its_binary_reports(self):
        # release.sh builds the canonical checkout; the binary's --version is production.
        del self.spec["production"]
        self.spec["version_cmd"] = ["/opt/bin/app", "--version"]
        result = self._deploy()
        self.assertEqual(result["status"], "ok")
        self.assertEqual((result["pre_version"], result["post_version"]), (self.PRE, self.NEW))
        # A failed release that restored the previous binary is a verified rollback,
        # even though the canonical checkout already fast-forwarded.
        self.state.update({"prod": self.PRE, "local": self.PRE,
                           "deploy_code": 1, "deploy_moves_to": self.PRE})
        self.assertEqual(self._deploy()["status"], "rolled_back")
        self.state.update({"prod": "dev"})
        self.commands = []
        result = self._deploy()
        self.assertEqual(result["status"], "skipped")
        self.assertIn("not a commit SHA", result["reason"])
        self.assertFalse(self._deployed())

    def test_success_fast_forwards_deploys_and_records_revert(self):
        result = self._deploy()
        self.assertEqual(result["status"], "ok")
        self.assertEqual((result["pre_version"], result["post_version"]), (self.PRE, self.NEW))
        self.assertTrue(result["local_mutation"])
        self.assertIn(f"read-tree -u --reset {self.PRE}", result["revert"])
        self.assertIn("push origin main", result["revert"])
        self.assertIn("deploy.sh", result["revert"])
        order = [cmd[3] if cmd[0] == "git" else cmd[0] for cmd in self.commands]
        self.assertLess(order.index("merge"), order.index("timeout"))
        self.assertTrue(updates._p1_deploy_step_ok(result))

    def test_timeout_sends_term_with_grace_before_any_kill(self):
        self.state.update({"deploy_code": 124, "deploy_moves_to": self.PRE})
        result = self._deploy()
        deploy = next(cmd for cmd in self.commands if cmd[0] == "timeout")
        self.assertEqual(deploy[:4], ["timeout", "--signal=TERM", "--kill-after=120", "1800"])
        self.assertEqual(deploy[4:], self.spec["deploy"])
        self.assertNotIn("--signal=KILL", deploy)
        # The outer Python timeout (which SIGKILLs) never pre-empts `timeout`.
        self.assertGreater(self.deploy_kwargs["timeout"], 1800 + 120)
        self.assertEqual(result["status"], "rolled_back")
        self.assertIn("timed out after 1800s (sent TERM)", result["error"])

    def test_failure_verifies_rollback_to_previous_sha(self):
        self.state.update({"deploy_code": 1, "deploy_moves_to": self.PRE})
        result = self._deploy()
        self.assertEqual(result["status"], "rolled_back")
        self.assertEqual(result["post_version"], self.PRE)
        self.assertIn(f"verified back at {self.PRE[:7]}", result["error"])
        self.assertIsNone(result["revert"])

    def test_failure_with_unverified_rollback_is_failed(self):
        self.state.update({"deploy_code": 1, "deploy_moves_to": self.NEW})
        result = self._deploy()
        self.assertEqual(result["status"], "failed")
        self.assertIn("rollback NOT verified", result["error"])

    def test_success_exit_with_wrong_production_head_is_failed(self):
        self.state.update({"deploy_moves_to": self.LOCAL})
        result = self._deploy()
        self.assertEqual(result["status"], "failed")
        self.assertIn("expected origin/main", result["error"])


class PhaseOneOrderTests(unittest.TestCase):
    def test_step_order_and_worker_refresh_input(self):
        calls = []

        def step(name, **extra):
            def run(*args, **kwargs):
                calls.append(name)
                return {"step": name, "status": "skipped", **extra}
            return run

        omp_row = {"step": "omp_update", "status": "ok",
                   "pre_version": "omp/1", "post_version": "omp/2"}
        seen = {}

        def refresh(result):
            calls.append("worker_omp_refresh")
            seen["omp"] = result
            return {"step": "worker_omp_refresh", "status": "ok"}

        def deploy(service, spec, dry_run=False):
            calls.append(f"app_deploy:{service}")
            return {"status": "skipped", "reason": "current"}

        def cleanup(steps):
            calls.append("docker_cleanup")
            seen["cleanup_saw"] = [row["step"] for row in steps]
            return {"step": "docker_cleanup", "status": "skipped"}

        with tempfile.TemporaryDirectory() as tmp, (
            patch.object(updates, "_p1_gamingrig_maintenance", step("gamingrig_maintenance"))
        ), patch.object(updates, "_p1_apt_upgrade", step("apt_upgrade")), patch.object(
            updates, "_p1_auto_pkgs", return_value=[]
        ), patch.object(updates, "_p1_freshrss_update", step("freshrss")), patch.object(
            updates, "_p1_openwebui", step("openwebui_update")
        ), patch.object(updates, "_p1_herdr_update", step("herdr_update")), patch.object(
            updates, "_p1_searxng_update", step("searxng")
        ), patch.object(updates, "_p1_llama_cpp_update", step("llama_cpp")), patch.object(
            updates, "_p1_omp_update", lambda: calls.append("omp_update") or dict(omp_row)
        ), patch.object(updates, "_p1_worker_omp_refresh", refresh), patch.object(
            updates, "_p1_app_deploy", deploy
        ), patch.object(updates, "_p1_dependabot_merge", step("dependabot_merge")), patch.object(
            updates, "DEPLOY_REGISTRY", {"blog": {}}
        ), patch.object(updates, "_p1_docker_cleanup", cleanup), patch.object(
            updates, "_p1_omp_db_repair", step("omp_db_repair")
        ):
            result = updates.phase_1_apply(Path(tmp))
        self.assertEqual(calls, [
            "gamingrig_maintenance", "omp_db_repair", "apt_upgrade", "freshrss", "openwebui_update",
            "herdr_update", "searxng", "llama_cpp", "omp_update",
            "worker_omp_refresh", "dependabot_merge", "app_deploy:blog", "docker_cleanup",
        ])
        self.assertEqual(seen["omp"]["post_version"], "omp/2")
        # Cleanup sees every earlier row (to find superseded images).
        self.assertIn("openwebui_update", seen["cleanup_saw"])
        self.assertEqual(result["steps"][-2],
                         {"step": "app_deploy", "service": "blog",
                          "status": "skipped", "reason": "current"})


def _make_omp_db(path, *, corrupt_index=False):
    """Real WAL SQLite DB shaped like agent.db; optionally with a broken index.

    The index corruption rewrites the index's schema SQL to another column, so
    integrity_check reports rows missing from the index while every table row
    stays intact — exactly what REINDEX repairs.
    """
    import sqlite3
    conn = sqlite3.connect(path, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE cache(key TEXT PRIMARY KEY, a INT, b INT)")
    conn.execute("CREATE INDEX cache_a ON cache(a)")
    conn.execute("CREATE TABLE auth_credentials(id INTEGER PRIMARY KEY, secret TEXT)")
    conn.executemany("INSERT INTO cache VALUES (?, ?, ?)",
                     [(f"k{i}", i, 1000 - i) for i in range(300)])
    conn.executemany("INSERT INTO auth_credentials(secret) VALUES (?)", [("s1",), ("s2",)])
    if corrupt_index:
        conn.execute("PRAGMA writable_schema=ON")
        conn.execute("UPDATE sqlite_master SET sql='CREATE INDEX cache_a ON cache(b)' "
                     "WHERE name='cache_a'")
    conn.close()


def _file_digest(path):
    import hashlib
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class OmpDbRepairTests(unittest.TestCase):
    NOW = datetime(2026, 10, 1, 4, 5, tzinfo=timezone.utc)
    TONIGHT = int(datetime(2026, 10, 1, 3, 0, tzinfo=timezone.utc).timestamp())

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db_dir = Path(tmp.name) / "agent"
        self.db_dir.mkdir()
        self.state = Path(tmp.name) / "state"
        self.calls = []

    def _dbs(self, corrupt=()):
        for name in updates.OMP_DB_BACKUP_TARGETS:
            _make_omp_db(self.db_dir / name, corrupt_index=name in corrupt)

    def _backup_journal(self, *failed):
        return "\n".join(
            [f'time=x level=ERROR msg="target failed" target={t} error="{cause}: detail"'
             for t, cause in failed]
            + ['time=x level=ERROR msg="backup failed" error="partial backup rejected"'])

    def _run(self, *, result="exit-code", journal="", start_ok=True, dry_run=False):
        def fake(cmd, **kwargs):
            self.calls.append(cmd)
            if cmd[:3] == ["systemctl", "--user", "show"]:
                return (f"Result={result}\nExecMainStatus=1\nActiveState=failed\n"
                        f"ExecMainStartTimestamp=@{self.TONIGHT}\n", "", 0)
            if cmd[0] == "journalctl":
                return journal, "", 0
            if cmd[:3] == ["systemctl", "--user", "start"]:
                return ("", "", 0) if start_ok else ("", "Job failed", 1)
            raise AssertionError(f"unexpected command {cmd}")

        with patch.object(updates, "run_capture_ok", fake), \
                contextlib.redirect_stdout(None):
            return updates._p1_omp_db_repair(
                dry_run=dry_run, db_dir=self.db_dir, state_dir=self.state, now=self.NOW)

    def _started_backup(self):
        return [c for c in self.calls if c[:3] == ["systemctl", "--user", "start"]]

    def test_healthy_dbs_are_left_alone(self):
        self._dbs()
        before = {p.name: _file_digest(p) for p in self.db_dir.glob("*.db")}
        result = self._run()
        self.assertEqual(result["status"], "skipped")
        # Read-only handles may create empty WAL side files; DB images must not change.
        self.assertEqual({p.name: _file_digest(p) for p in self.db_dir.glob("*.db")}, before)
        self.assertFalse(self.state.exists())
        self.assertEqual(self.calls, [])

    def test_corrupt_index_is_repaired_losslessly_and_backup_rerun(self):
        self._dbs(corrupt={"agent.db"})
        live = self.db_dir / "agent.db"
        self.assertNotEqual(updates._ompdb_integrity(live), ["ok"])
        counts, hashes = updates._ompdb_snapshot(live)
        result = self._run(journal=self._backup_journal(("omp-agent-db", "integrity check")))

        self.assertEqual(result["status"], "ok")
        self.assertNotIn("needs_carter", result)
        self.assertEqual(updates._ompdb_integrity(live), ["ok"])
        self.assertEqual(updates._ompdb_snapshot(live), (counts, hashes))
        entry = next(d for d in result["dbs"] if d["db"] == "agent.db")
        self.assertEqual(entry["action"], "repaired")
        evidence = Path(entry["evidence"])
        self.assertEqual(evidence.stat().st_mode & 0o777, 0o600)
        self.assertNotEqual(updates._ompdb_integrity(evidence), ["ok"])  # pre-repair image
        self.assertEqual(sorted(p.name for p in self.state.iterdir()), [evidence.name])
        self.assertIn(str(evidence), result["reason"])
        self.assertIn("NOT a safe undo", result["undo"])
        self.assertEqual(len(self._started_backup()), 1)
        self.assertEqual(result["backup_rerun"]["status"], "passed")

    def test_failed_backup_rerun_needs_carter(self):
        self._dbs(corrupt={"agent.db"})
        result = self._run(journal=self._backup_journal(("omp-agent-db", "integrity check")),
                           start_ok=False)
        self.assertEqual(result["status"], "warning")
        self.assertTrue(result["needs_carter"])
        self.assertEqual(result["backup_rerun"]["status"], "failed")

    def test_lossy_repair_leaves_live_db_untouched(self):
        self._dbs(corrupt={"agent.db"})
        live = self.db_dir / "agent.db"
        digest = _file_digest(live)
        real_rebuild = updates._ompdb_rebuild

        def lossy_rebuild(path):
            # Stand-in for a VACUUM that drops rows from a damaged table b-tree.
            real_rebuild(path)
            import sqlite3
            with contextlib.closing(sqlite3.connect(path, isolation_level=None)) as conn:
                conn.execute("DELETE FROM cache WHERE key='k7'")

        with patch.object(updates, "_ompdb_rebuild", lossy_rebuild):
            result = self._run(
                journal=self._backup_journal(("omp-agent-db", "integrity check")))
        self.assertEqual(result["status"], "warning")
        self.assertTrue(result["needs_carter"])
        entry = next(d for d in result["dbs"] if d["db"] == "agent.db")
        self.assertEqual(entry["action"], "blocked")
        self.assertFalse(entry["gates"]["row_counts_equal"])
        self.assertIn("cache", entry["reason"])
        self.assertEqual(_file_digest(live), digest)
        self.assertEqual(self._started_backup(), [])
        self.assertTrue(Path(entry["evidence"]).exists())

    def test_changed_auth_content_blocks_repair(self):
        self._dbs(corrupt={"agent.db"})
        live = self.db_dir / "agent.db"
        digest = _file_digest(live)
        real_rebuild = updates._ompdb_rebuild

        def auth_mutating_rebuild(path):
            real_rebuild(path)
            import sqlite3
            with contextlib.closing(sqlite3.connect(path, isolation_level=None)) as conn:
                conn.execute("UPDATE auth_credentials SET secret='x' WHERE id=1")

        with patch.object(updates, "_ompdb_rebuild", auth_mutating_rebuild):
            result = self._run()
        entry = next(d for d in result["dbs"] if d["db"] == "agent.db")
        self.assertEqual(entry["gates"],
                         {"copy_integrity_ok": True, "row_counts_equal": True,
                          "auth_hashes_equal": False})
        self.assertEqual(_file_digest(live), digest)
        self.assertNotIn("s1", json.dumps(result))

    def test_backup_not_rerun_for_other_failure_causes(self):
        cases = {
            "other target also failed": self._backup_journal(
                ("omp-agent-db", "integrity check"), ("webui-db", "integrity check")),
            "unrepaired omp db named": self._backup_journal(
                ("omp-history-db", "integrity check")),
            "non-integrity cause": self._backup_journal(("omp-agent-db", "upload to r2")),
            "no target named": 'msg="backup failed" error="r2 unreachable"',
        }
        for label, journal in cases.items():
            with self.subTest(label):
                self.calls.clear()
                for leftover in self.db_dir.iterdir():
                    leftover.unlink()
                self._dbs(corrupt={"agent.db"})
                result = self._run(journal=journal)
                self.assertEqual(self._started_backup(), [])
                self.assertEqual(result["backup_rerun"]["status"], "not_run")
                self.assertTrue(result["needs_carter"])
                self.assertEqual(updates._ompdb_integrity(self.db_dir / "agent.db"), ["ok"])

    def test_successful_backup_is_not_rerun(self):
        self._dbs(corrupt={"agent.db"})
        result = self._run(result="success")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(self._started_backup(), [])

    def test_dry_run_only_reports_corruption(self):
        self._dbs(corrupt={"agent.db"})
        live = self.db_dir / "agent.db"
        digest = _file_digest(live)
        result = self._run(dry_run=True)
        self.assertEqual(result["status"], "warning")
        self.assertEqual(_file_digest(live), digest)
        self.assertFalse(self.state.exists())
        self.assertEqual(self.calls, [])

    def test_prune_keeps_newest_three_pre_repair_copies(self):
        self.state.mkdir()
        for age in range(5):
            old = self.state / f"agent-corrupt-2026090{age}T000000Z.db"
            old.write_bytes(b"x")
            os.utime(old, (1000 + age, 1000 + age))
        self._dbs(corrupt={"agent.db"})
        result = self._run(result="success")
        evidence = Path(next(d for d in result["dbs"] if d["db"] == "agent.db")["evidence"])
        self.assertEqual(sorted(p.name for p in self.state.iterdir()), sorted([
            evidence.name, "agent-corrupt-20260904T000000Z.db",
            "agent-corrupt-20260903T000000Z.db"]))

    def test_needs_carter_row_is_visible_in_report(self):
        row = {"step": "omp_db_repair", "status": "warning", "needs_carter": True,
               "reason": "agent.db blocked: lossless gates failed"}
        self.assertIn("needs Carter", report._html_updates({"steps": [row]}))
        facts = report._build_tldr_facts({"steps": [row]}, {}, {}, {}, {})
        self.assertTrue(any("agent.db blocked" in item for item in facts["needs_carter"]))


class DependabotMergeTests(unittest.TestCase):
    GREEN = [{"__typename": "CheckRun", "name": "test", "status": "COMPLETED",
              "conclusion": "SUCCESS"},
             {"__typename": "StatusContext", "context": "ext", "state": "SUCCESS"}]

    def _pr(self, number, title, branch="dependabot/npm_and_yarn/x", checks=None,
            mergeable="MERGEABLE"):
        return {"number": number, "title": title, "url": f"https://pr/{number}",
                "headRefName": branch, "baseRefName": "main", "isDraft": False,
                "mergeable": mergeable,
                "statusCheckRollup": self.GREEN if checks is None else checks}

    REBASE = {"allow_rebase_merge": True, "allow_squash_merge": True}

    def _run(self, prs, eligible=(True, "ok"), dry_run=False, settings=None):
        calls = []

        def gh(args, cwd=None):
            calls.append(list(args))
            if args[:2] == ["pr", "list"]:
                repo = args[args.index("--repo") + 1].split("/")[1]
                return subprocess.CompletedProcess(args, 0, json.dumps(prs.get(repo, [])), "")
            if args[0] == "api":
                return subprocess.CompletedProcess(
                    args, 0, json.dumps(settings or self.REBASE), "")
            return subprocess.CompletedProcess(args, 0, "", "")

        ctx = routing.RouteContext(gh=gh)
        with patch.object(routing, "auto_merge_eligibility", return_value=eligible):
            result = updates._p1_dependabot_merge(dry_run, ctx=ctx)
        return result, calls

    def test_merges_only_green_minor_prs_outside_owned_branches(self):
        prs = {
            "herdr-web-client": [
                self._pr(10, "Bump @biomejs/biome from 2.5.11 to 2.5.14"),
                self._pr(5, "Bump golang.org/x/term from 0.45.0 to 0.46.0"),
                self._pr(11, "Bump vite from 6.3.0 to 7.0.0"),
                self._pr(12, "Bump knip from 6.33.0 to 6.36.0", checks=[
                    {"__typename": "CheckRun", "name": "test", "status": "COMPLETED",
                     "conclusion": "FAILURE"}]),
                self._pr(13, "Bump knip from 6.33.0 to 6.37.0", checks=[]),
                self._pr(14, "Bump playwright from 1.62.1 to 1.63.0", mergeable="CONFLICTING"),
                self._pr(15, "Bump the npm group with 3 updates"),
            ],
            "blog": [self._pr(116, "Bump mail from 2.9.0 to 2.9.1",
                              branch="dependabot/bundler/mail-2.9.1"),
                     self._pr(117, "Bump actions/checkout from 6.0.3 to 6.0.4",
                              branch="dependabot/github_actions/actions/checkout-6.0.4")],
            "hyperliquid": [self._pr(1, "Bump a from 1.0.0 to 1.0.1")],
        }
        result, calls = self._run(prs)
        merges = [c for c in calls if c[:2] == ["pr", "merge"]]
        self.assertEqual(sorted(c[2] for c in merges), ["10", "117", "5"])
        for merge in merges:
            self.assertIn("--auto", merge)
            self.assertIn("--rebase", merge)
            self.assertNotIn("--admin", merge)
        listed = [c[c.index("--repo") + 1] for c in calls if c[:2] == ["pr", "list"]]
        self.assertNotIn("carter2099/hyperliquid", listed)
        self.assertEqual(result["status"], "ok")
        self.assertEqual([(i["repo"], i["number"]) for i in result["needs_carter"]],
                         [("herdr-web-client", 11)])
        reasons = {(i["repo"], i.get("number")): i["reason"] for i in result["skipped"]}
        self.assertIn("dependabot-webhook", reasons[("blog", 116)])
        self.assertIn("checks not green", reasons[("herdr-web-client", 12)])
        self.assertIn("no checks", reasons[("herdr-web-client", 13)])
        self.assertIn("not mergeable", reasons[("herdr-web-client", 14)])
        self.assertIn("Bump X from A to B", reasons[("herdr-web-client", 15)])
        self.assertIn("own agent", reasons[("hyperliquid", None)])
        html = report._html_updates({"steps": [result]})
        self.assertIn("herdr-web-client#10 auto-merge queued", html)
        self.assertIn("herdr-web-client#11 needs Carter", html)

    def test_unknown_mergeable_state_is_rechecked_before_skipping(self):
        prs = {"herdr-web-client": [self._pr(11, "Bump knip from 6.36.0 to 6.38.0", mergeable="UNKNOWN"),
                                    self._pr(12, "Bump vite-x from 1.0.0 to 1.0.1", mergeable="UNKNOWN")]}
        views = {11: ["UNKNOWN", "MERGEABLE"], 12: ["UNKNOWN"] * 10}
        calls = []

        def gh(args, cwd=None):
            calls.append(list(args))
            if args[:2] == ["pr", "list"]:
                repo = args[args.index("--repo") + 1].split("/")[1]
                return subprocess.CompletedProcess(args, 0, json.dumps(prs.get(repo, [])), "")
            if args[:2] == ["pr", "view"]:
                state = views[int(args[2])].pop(0)
                return subprocess.CompletedProcess(args, 0, json.dumps({"mergeable": state}), "")
            if args[0] == "api":
                return subprocess.CompletedProcess(args, 0, json.dumps(self.REBASE), "")
            return subprocess.CompletedProcess(args, 0, "", "")

        with patch.object(routing, "auto_merge_eligibility", return_value=(True, "ok")), \
                patch.object(updates, "MERGEABLE_RECHECK_SECONDS", 0):
            result = updates._p1_dependabot_merge(False, ctx=routing.RouteContext(gh=gh))
        self.assertEqual([c[2] for c in calls if c[:2] == ["pr", "merge"]], ["11"])
        reasons = {i.get("number"): i["reason"] for i in result["skipped"]}
        self.assertEqual(reasons[12], "not mergeable (UNKNOWN)")
        self.assertEqual(sum(1 for c in calls if c[:3] == ["pr", "view", "12"]),
                         updates.MERGEABLE_RECHECKS)

    def test_merge_method_follows_repository_settings(self):
        prs = {"herdr-web-client": [self._pr(10, "Bump a from 1.0.0 to 1.0.1")]}
        squash_only = {"allow_rebase_merge": False, "allow_squash_merge": True,
                       "allow_merge_commit": False}
        result, calls = self._run(prs, settings=squash_only)
        merges = [c for c in calls if c[:2] == ["pr", "merge"]]
        self.assertEqual(len(merges), 1)
        self.assertIn("--squash", merges[0])
        self.assertNotIn("--rebase", merges[0])
        self.assertNotIn("--admin", merges[0])
        self.assertEqual(result["status"], "ok")
        result, calls = self._run(prs, settings={"allow_rebase_merge": False})
        self.assertFalse([c for c in calls if c[:2] == ["pr", "merge"]])
        self.assertEqual(result["status"], "skipped")
        self.assertIn("no merge method",
                      next(i["reason"] for i in result["skipped"] if i.get("number") == 10))

    def test_commit_sha_bumps_are_not_versions(self):
        self.assertIsNone(updates._dependabot_bump("Bump foo from `8e5e7e5` to `8ade135`"))
        self.assertIsNone(updates._dependabot_bump("Bump foo from 8e5e7e5 to 8ade135"))
        self.assertTrue(updates._dependabot_bump("Bump x from 1.9.0 to 2.0.0")[3])
        self.assertFalse(updates._dependabot_bump("Bump x from v6.0.3 to v6.1.0")[3])

    def test_ineligible_repo_and_dry_run_merge_nothing(self):
        prs = {"herdr-web-client": [self._pr(10, "Bump a from 1.0.0 to 1.0.1")]}
        for kwargs, expected in (({"eligible": (False, "auto-merge is disabled")},
                                  "auto-merge is disabled"),
                                 ({"dry_run": True}, "dry run")):
            with self.subTest(expected):
                result, calls = self._run(prs, **kwargs)
                self.assertFalse([c for c in calls if c[:2] == ["pr", "merge"]])
                self.assertEqual(result["status"], "skipped")
                self.assertIn(expected, next(i["reason"] for i in result["skipped"] if i.get("number") == 10))

    def test_each_queued_merge_gets_its_own_done_row_with_real_undo_url(self):
        prs = {"herdr-web-client": [self._pr(10, "Bump a from 1.0.0 to 1.0.1"),
                                    self._pr(12, "Bump b from 2.0.0 to 2.1.0")]}
        result, _ = self._run(prs)
        self.assertIsNone(result["revert"])
        self.assertEqual([i["revert"] for i in result["merged"]], [
            "before GitHub merges: gh pr merge --disable-auto https://pr/10; after: "
            "revert the merge commit on the default branch",
            "before GitHub merges: gh pr merge --disable-auto https://pr/12; after: "
            "revert the merge commit on the default branch",
        ])
        page = report.html.unescape(
            report._html_actions({"sections": []}, {"routes": []}, {"steps": [result]}))
        self.assertIn("herdr-web-client#10 Bump a from 1.0.0 to 1.0.1 — auto-merge queued "
                      "(1.0.0 -> 1.0.1;", page)
        self.assertIn("Undo: before GitHub merges: gh pr merge --disable-auto https://pr/12", page)
        self.assertNotIn("<url>", page)
        self.assertNotIn("?", page)

    def test_recorded_step_with_placeholder_undo_renders_real_pr_url(self):
        # Shape of the 2026-10-01 01-applied.json row (written before per-PR undo existed).
        step = {"step": "dependabot_merge", "status": "ok", "local_mutation": False,
                "merged": [{"number": 11, "reason": "6.36.0 -> 6.38.0; 6 check(s) green",
                            "repo": "herdr-web-client", "title": "Bump knip from 6.36.0 to 6.38.0",
                            "url": "https://github.com/carter2099/herdr-web-client/pull/11"}],
                "needs_carter": [], "skipped": [],
                "revert": "before GitHub merges: gh pr merge --disable-auto <url>; after: "
                          "revert the merged commit on the default branch"}
        page = report.html.unescape(
            report._html_actions({"sections": []}, {"routes": []}, {"steps": [step]}))
        self.assertIn("herdr-web-client#11 Bump knip from 6.36.0 to 6.38.0 — auto-merge queued "
                      "(6.36.0 -> 6.38.0; 6 check(s) green)", page)
        self.assertIn("gh pr merge --disable-auto "
                      "https://github.com/carter2099/herdr-web-client/pull/11", page)
        self.assertNotIn("<url>", page)
        self.assertNotIn("updated ?", page)

    def test_done_step_without_versions_renders_reason_not_question_marks(self):
        step = {"step": "some_step", "status": "ok", "reason": "rotated the token",
                "revert": "restore the old token"}
        page = report._html_actions({"sections": []}, {"routes": []}, {"steps": [step]})
        self.assertIn("rotated the token", page)
        self.assertNotIn("?", page)
        versioned = {**step, "pre_version": "1.0.0", "post_version": "1.1.0"}
        page = report._html_actions({"sections": []}, {"routes": []}, {"steps": [versioned]})
        self.assertIn("updated 1.0.0 -&gt; 1.1.0", page)


class HostRebootReportTests(unittest.TestCase):
    RECORD = {"requested_at": "2026-10-01T04:02:50Z", "phase": "P3",
              "kernel_before": "6.8.0-142-generic", "boot_id_before": "boot-before",
              "packages": ["linux-image-6.8.0-146-generic"]}

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.run_dir = self.root / "2026-10-01"
        self.run_dir.mkdir()
        (self.run_dir / "reboot.json").write_text(json.dumps(self.RECORD))

    def _host(self, boot_id):
        """Patches for the current boot id and `uname -r` after the reboot."""
        return (
            patch.object(report, "_current_boot_id", return_value=boot_id),
            patch.object(report, "run_capture", side_effect=lambda cmd, **kw: (
                "6.8.0-146-generic" if cmd == ["uname", "-r"] else "")),
        )

    def _status(self, boot_id):
        boot, uname = self._host(boot_id)
        with boot, uname:
            return report._host_reboot_status(self.run_dir)

    def test_changed_boot_id_renders_reboot_line_status_row_and_tldr_fact(self):
        status = self._status("boot-after")
        line = ("ThinkPad rebooted for kernel update: 6.8.0-142-generic -> 6.8.0-146-generic "
                "(04:02 UTC, after P3); run resumed")
        self.assertEqual(status["text"], line)
        applied = {"steps": [], "host_reboot": status}
        self.assertIn(report.html.escape(line), report._html_updates(applied))
        health = report._html_health({"checks": []}, {"reboot": {"needed": False}}, applied)
        self.assertIn("Rebooted 04:02 UTC — kernel 6.8.0-146-generic", health)
        self.assertNotIn("Not needed", health)
        again = report._html_health(
            {"checks": []}, {"reboot": {"needed": True, "kernel": "6.8.0-147-generic"}}, applied)
        self.assertIn("Needed — kernel 6.8.0-147-generic", again)
        facts = report._build_tldr_facts(applied, {}, {}, {}, {})
        self.assertEqual(facts["updates"][0], line)
        self.assertEqual(report._tldr_payload(facts, "2026-10-01")[0]["updates"][0], line)

    def test_unchanged_boot_id_warns_that_host_did_not_restart(self):
        status = self._status("boot-before")
        self.assertFalse(status["rebooted"])
        self.assertEqual(status["text"], "ThinkPad reboot requested at 04:02 UTC (after P3) "
                                         "but the host did not restart")
        applied = {"steps": [], "host_reboot": status}
        self.assertIn("did not restart", report._html_updates(applied))
        health = report._html_health({"checks": []}, {}, applied)
        self.assertIn("Requested 04:02 UTC — host did not restart", health)

    def test_no_record_means_no_reboot_line(self):
        (self.run_dir / "reboot.json").unlink()
        self.assertIsNone(self._status("boot-after"))
        self.assertIn("Not needed", report._html_health({"checks": []}, {}, {"steps": []}))

    def test_summary_md_update_status_lists_the_reboot(self):
        sessions = self.root / "sessions"
        sessions.mkdir()
        boot, uname = self._host("boot-after")
        with boot, uname, patch.object(report, "RUNS_LOG", self.root / "runs.jsonl"), \
                patch.object(report, "RUN_DIR_BASE", self.root), \
                patch.object(report, "SESSION_DIR", sessions):
            report.phase_9_archive(self.run_dir, {"date": "2026-10-01"}, 1.0)
        summary = (self.run_dir / "summary.md").read_text()
        update_status = summary.split("## Update Status\n", 1)[1].split("\n\n", 1)[0]
        self.assertIn("- ThinkPad rebooted for kernel update: 6.8.0-142-generic -> "
                      "6.8.0-146-generic (04:02 UTC, after P3); run resumed", update_status)


if __name__ == "__main__":
    unittest.main(verbosity=2)
