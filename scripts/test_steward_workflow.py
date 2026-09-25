#!/usr/bin/env python3
"""Behavioral checks for steward run identity and reboot resume arguments."""
from __future__ import annotations

import argparse
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from steward import dotfiles, report, showcase, workflow
from workflow_state import WorkflowState


class StewardWorkflowArgumentTests(unittest.TestCase):
    def test_resume_accepts_exact_prior_run_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            run_dir = base / "2026-08-31"
            with mock.patch.object(workflow, "RUN_DIR_BASE", base):
                args = workflow._setup_args(["--resume", "--run-dir", str(run_dir)])
            self.assertTrue(args.resume)
            self.assertEqual(args.run_dir, str(run_dir))

    def test_post_fix_continuation_arguments_preserve_run_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            run_dir = base / "2026-08-31"
            with mock.patch.object(workflow, "RUN_DIR_BASE", base):
                args = workflow._setup_args([
                    "--resume",
                    "--run-dir",
                    str(run_dir),
                    "--continue-after-fixes",
                    "--started-at",
                    "1234.5",
                ])
            self.assertTrue(args.continue_after_fixes)
            self.assertEqual(args.run_dir, str(run_dir))
            self.assertEqual(args.started_at, 1234.5)

    def test_run_directory_requires_resume(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            with mock.patch.object(workflow, "RUN_DIR_BASE", base), self.assertRaises(SystemExit):
                workflow._setup_args(["--run-dir", str(base / "2026-08-31")])

    def test_resume_rejects_traversal_and_nested_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            invalid = [
                base.parent / "2026-08-31",
                base / "nested" / "2026-08-31",
                base / "not-a-date",
            ]
            for candidate in invalid:
                with self.subTest(candidate=candidate):
                    with mock.patch.object(workflow, "RUN_DIR_BASE", base), self.assertRaises(SystemExit):
                        workflow._setup_args(["--resume", "--run-dir", str(candidate)])


    def test_phase_preserves_artifact_written_by_legacy_operation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            artifact = run_dir / "phase.json"
            state = WorkflowState(run_dir, workflow.WORKFLOW_NAME, run_id="test")

            def operation():
                workflow.atomic_write_json(artifact, {"details": ["preserved"]})
                return None

            data, resumed = workflow._run_phase(
                state,
                phase="legacy-operation",
                artifact=artifact,
                inputs={"code_hash": "stable"},
                args=argparse.Namespace(resume=False),
                operation=operation,
            )
            self.assertFalse(resumed)
            self.assertEqual(data["details"], ["preserved"])
            self.assertEqual(data["phase_status"], "succeeded")
            self.assertEqual(
                workflow.json.loads(artifact.read_text())["details"],
                ["preserved"],
            )
            self.assertEqual(
                state.phase_record("legacy-operation")["completion_outcome"],
                "succeeded",
            )

    def test_phase_without_payload_records_explicit_skip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            artifact = run_dir / "phase.json"
            state = WorkflowState(run_dir, workflow.WORKFLOW_NAME, run_id="test")
            data, _ = workflow._run_phase(
                state,
                phase="no-output",
                artifact=artifact,
                inputs={"code_hash": "stable"},
                args=argparse.Namespace(resume=False),
                operation=lambda: None,
            )
            self.assertEqual(data["phase_status"], "skipped")
            record = state.phase_record("no-output")
            self.assertEqual(record["completion_outcome"], "skipped")
            self.assertEqual(
                record["completion_reason"],
                "phase returned no data and wrote no artifact",
            )

    def test_none_return_cannot_complete_stale_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            artifact = run_dir / "phase.json"
            artifact.write_text('{"stale": true}\n', encoding="utf-8")
            state = WorkflowState(run_dir, workflow.WORKFLOW_NAME, run_id="test")

            data, resumed = workflow._run_phase(
                state,
                phase="legacy-operation",
                artifact=artifact,
                inputs={"code_hash": "stable"},
                args=argparse.Namespace(resume=False),
                operation=lambda: None,
            )

            self.assertFalse(resumed)
            self.assertEqual(data["phase_status"], "skipped")
            self.assertNotIn("stale", workflow.json.loads(artifact.read_text()))
            self.assertEqual(
                state.phase_record("legacy-operation")["completion_outcome"],
                "skipped",
            )

    def test_p1_failure_packet_marks_phase_non_resumable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            artifact = run_dir / "01-applied.json"
            state = WorkflowState(run_dir, workflow.WORKFLOW_NAME, run_id="test")
            data, resumed = workflow._run_phase(
                state,
                phase="apply",
                artifact=artifact,
                inputs={"code_hash": "stable"},
                args=argparse.Namespace(resume=False),
                operation=lambda: {
                    "steps": [{
                        "step": "apt_upgrade",
                        "status": "failed",
                        "error": "apt unavailable",
                    }],
                },
            )

            self.assertFalse(resumed)
            self.assertEqual(data["phase_status"], "failed")
            self.assertTrue(data["phase_failed"])
            self.assertEqual(data["steps"][0]["error"], "apt unavailable")
            record = state.phase_record("apply")
            self.assertEqual(record["status"], "failed")
            self.assertEqual(record["completion_outcome"], "failed")
            self.assertFalse(record["resume_valid"])

    def test_phase_exception_preserves_prior_progress_packet(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            artifact = run_dir / "01-applied.json"
            state = WorkflowState(run_dir, workflow.WORKFLOW_NAME, run_id="test")

            def operation():
                workflow.atomic_write_json(
                    artifact,
                    {
                        "steps": [{
                            "step": "gamingrig_maintenance",
                            "status": "ok",
                        }],
                    },
                )
                raise RuntimeError("apt upgrade timed out after 900s")

            data, resumed = workflow._run_phase(
                state,
                phase="apply",
                artifact=artifact,
                inputs={"code_hash": "stable"},
                args=argparse.Namespace(resume=False),
                operation=operation,
            )

            self.assertFalse(resumed)
            self.assertEqual(data["phase_status"], "failed")
            self.assertTrue(data["phase_failed"])
            self.assertEqual(
                data["steps"][0]["step"],
                "gamingrig_maintenance",
            )
            self.assertIn("apt upgrade timed out", data["error"])
            self.assertEqual(state.phase_record("apply")["status"], "failed")

    def test_phase_exception_without_progress_still_writes_terminal_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            artifact = run_dir / "01-applied.json"
            state = WorkflowState(run_dir, workflow.WORKFLOW_NAME, run_id="test")

            data, resumed = workflow._run_phase(
                state,
                phase="apply",
                artifact=artifact,
                inputs={"code_hash": "stable"},
                args=argparse.Namespace(resume=False),
                operation=lambda: (_ for _ in ()).throw(
                    RuntimeError("apt unavailable before any step")
                ),
            )

            self.assertFalse(resumed)
            self.assertEqual(data["phase_status"], "failed")
            self.assertTrue(data["phase_failed"])
            self.assertNotIn("steps", data)
            self.assertIn("apt unavailable before any step", data["error"])
            self.assertEqual(state.phase_record("apply")["status"], "failed")

    def test_startup_fingerprint_mutation_aborts_and_records_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            artifact = run_dir / "phase.json"
            state = WorkflowState(run_dir, workflow.WORKFLOW_NAME, run_id="test")
            args = argparse.Namespace(
                resume=False,
                _startup_code_fingerprint={"/policy": "before"},
            )
            operation = mock.Mock(return_value={"result": "ok"})
            with mock.patch.object(
                workflow,
                "_code_fingerprint",
                side_effect=[{"/policy": "before"}, {"/policy": "after"}],
            ):
                with self.assertRaises(workflow.StartupFingerprintChanged):
                    workflow._run_phase(
                        state,
                        phase="phase",
                        artifact=artifact,
                        inputs={"code_hash": "stable"},
                        args=args,
                        operation=operation,
                    )

            operation.assert_called_once()
            self.assertEqual(state.phase_record("phase")["status"], "failed")
            packet = workflow.json.loads(artifact.read_text())
            self.assertTrue(packet["phase_failed"])
            self.assertIn("fingerprint changed", packet["error"])

    def test_code_fingerprint_includes_external_update_helper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            helper = Path(tmp) / "update-helper.sh"
            helper.write_text("#!/bin/sh\necho update\n", encoding="utf-8")
            with mock.patch.object(workflow, "LLAMA_CPP_UPDATE_SCRIPT", helper):
                fingerprint = workflow._code_fingerprint()
            self.assertEqual(
                fingerprint[str(helper)],
                workflow.file_sha256(helper),
            )

    def test_p7b_source_change_completes_before_clean_process_reload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            artifact = run_dir / "07b-fixes.json"
            state = WorkflowState(run_dir, workflow.WORKFLOW_NAME, run_id="test")
            source = str(
                Path(workflow.__file__).resolve().parent.parent
                / "workflow_state.py"
            )
            args = argparse.Namespace(
                resume=False,
                _startup_code_fingerprint={source: "before"},
            )
            with mock.patch.object(
                workflow,
                "_code_fingerprint",
                side_effect=[{source: "before"}, {source: "after"}],
            ):
                data, resumed = workflow._run_phase(
                    state,
                    phase="fixes",
                    artifact=artifact,
                    inputs={"code_hash": "before"},
                    args=args,
                    operation=lambda: {"sections": []},
                    source_reload_boundary=True,
                )

            self.assertFalse(resumed)
            self.assertEqual(data["phase_status"], "succeeded")
            self.assertEqual(state.phase_record("fixes")["status"], "succeeded")
            self.assertEqual(args._post_fix_source_changes, (source,))
            packet = workflow.json.loads(artifact.read_text())
            self.assertNotIn("phase_failed", packet)

    def test_p7b_policy_change_still_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            artifact = run_dir / "07b-fixes.json"
            state = WorkflowState(run_dir, workflow.WORKFLOW_NAME, run_id="test")
            policy = str(run_dir / "policy.yml")
            args = argparse.Namespace(
                resume=False,
                _startup_code_fingerprint={policy: "before"},
            )
            with mock.patch.object(
                workflow,
                "_code_fingerprint",
                side_effect=[{policy: "before"}, {policy: "after"}],
            ):
                with self.assertRaises(workflow.StartupFingerprintChanged):
                    workflow._run_phase(
                        state,
                        phase="fixes",
                        artifact=artifact,
                        inputs={"code_hash": "before"},
                        args=args,
                        operation=lambda: {"sections": []},
                        source_reload_boundary=True,
                    )

            self.assertEqual(state.phase_record("fixes")["status"], "failed")
            self.assertTrue(workflow.json.loads(artifact.read_text())["phase_failed"])

    def test_post_fix_handoff_requires_exact_completed_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            artifact = run_dir / "00-setup.json"
            state = WorkflowState(run_dir, workflow.WORKFLOW_NAME, run_id="test")
            state.begin_phase(
                "setup",
                inputs={"code_hash": "old"},
                artifact_path=artifact,
                schema_version=workflow.SCHEMA_VERSION,
            )
            state.complete_json("setup", {"run_dir": str(run_dir)})

            self.assertEqual(
                workflow._load_completed_json_phase(state, "setup", artifact),
                {"run_dir": str(run_dir)},
            )
            artifact.write_text('{"run_dir": "tampered"}', encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "changed setup state"):
                workflow._load_completed_json_phase(state, "setup", artifact)

    def test_post_fix_reload_reexecs_same_run_at_reporting_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            args = argparse.Namespace(
                dry_run=False,
                _post_fix_source_changes=("/home/carter/scripts/workflow_state.py",),
            )
            with mock.patch.object(workflow.os, "execv") as execv:
                with self.assertRaisesRegex(RuntimeError, "returned unexpectedly"):
                    workflow._restart_after_fixes(args, run_dir, 1234.5)

            command = execv.call_args.args[1]
            self.assertEqual(command[0], workflow.sys.executable)
            self.assertIn("--resume", command)
            self.assertEqual(command[command.index("--run-dir") + 1], str(run_dir))
            self.assertIn("--continue-after-fixes", command)
            self.assertEqual(command[command.index("--started-at") + 1], "1234.5")

    def test_pending_push_retries_exact_oid_and_rejects_divergence(self) -> None:
        commit = "a" * 40
        pending = {"branch": "main", "commit": commit}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_mock = mock.Mock()
            with (
                mock.patch.object(dotfiles, "_current_branch", return_value="main"),
                mock.patch.object(dotfiles, "_head_oid", return_value=commit),
                mock.patch.object(dotfiles, "_snapshot", return_value=({}, None)),
                mock.patch.object(dotfiles, "_staged_paths", return_value=(set(), None)),
                mock.patch.object(
                    dotfiles, "_remote_oid", side_effect=[None, commit]
                ),
                mock.patch.object(dotfiles, "run", run_mock),
                mock.patch.object(
                    dotfiles,
                    "run_capture_ok",
                    side_effect=lambda cmd, **_: (
                        ("git@github.com:carter2099/dotfiles-homelab-private.git\n", "", 0)
                        if "get-url" in cmd else ("", "", 0)
                    ),
                ),
            ):
                result = dotfiles._retry_pending_push(
                    pending, git_dir=root / "git", home=root / "home"
                )
            self.assertEqual(result["status"], "committed")
            self.assertEqual(result["remote_commit"], commit)
            self.assertEqual(
                run_mock.call_args.args[0][-3:],
                ["push", "origin", f"{commit}:refs/heads/main"],
            )

            run_mock.reset_mock()
            with (
                mock.patch.object(dotfiles, "_current_branch", return_value="other"),
                mock.patch.object(dotfiles, "_head_oid", return_value=commit),
                mock.patch.object(dotfiles, "run", run_mock),
            ):
                diverged = dotfiles._retry_pending_push(
                    pending, git_dir=root / "git", home=root / "home"
                )
            self.assertEqual(diverged["status"], "pending_diverged")
            run_mock.assert_not_called()

    def test_email_failure_propagates_to_failed_phase(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            template = run_dir / "template.html"
            template.write_text("{{DATE}} {{TLDR}}", encoding="utf-8")
            artifact = run_dir / "08-email.html"
            state = WorkflowState(run_dir, workflow.WORKFLOW_NAME, run_id="test")
            args = argparse.Namespace(resume=False)
            with (
                mock.patch.object(report, "TEMPLATE_PATH", template),
                mock.patch.object(report, "_build_tldr", return_value="summary"),
                mock.patch.object(
                    report,
                    "run",
                    side_effect=RuntimeError("SMTP unavailable"),
                ),
            ):
                data, resumed = workflow._run_phase(
                    state,
                    phase="render",
                    artifact=artifact,
                    inputs={"code_hash": "stable"},
                    args=args,
                    operation=lambda: report.phase_8_render_send(
                        run_dir, {"date": "2026-09-01"}
                    ),
                    json_artifact=False,
                )

            self.assertFalse(resumed)
            self.assertEqual(data["phase_status"], "failed")
            self.assertEqual(state.phase_record("render")["status"], "failed")
            self.assertEqual(
                state.phase_record("render")["completion_outcome"], "failed"
            )
            self.assertIn("email send failed", artifact.read_text())

    def test_failed_maintenance_returns_nonzero_after_successful_reporting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            state = WorkflowState(run_dir, workflow.WORKFLOW_NAME, run_id="test")
            args = argparse.Namespace(resume=False, dry_run=True)
            workflow._run_phase(
                state,
                phase="apply",
                artifact=run_dir / "01-applied.json",
                inputs={"code_hash": "stable"},
                args=args,
                operation=lambda: {"steps": [{"step": "apt_upgrade", "status": "failed", "error": "apt timed out"}]},
            )

            def render(*_args, **_kwargs):
                (run_dir / "08-email.html").write_text("<p>Maintenance failed</p>", encoding="utf-8")

            def archive(*_args, **_kwargs):
                (run_dir / "summary.md").write_text("Maintenance failed\n", encoding="utf-8")

            with (
                mock.patch.object(workflow, "_phase_inputs", return_value={"code_hash": "stable"}),
                mock.patch.object(report, "phase_8_render_send", side_effect=render),
                mock.patch.object(report, "phase_9_archive", side_effect=archive),
                mock.patch.object(dotfiles, "phase_9b_dotfiles", return_value={"status": "skipped", "reason": "dry run"}),
                mock.patch.object(showcase, "phase_9c_showcase", return_value={"status": "dry_run"}),
            ):
                exit_code = workflow._finish_after_fixes(
                    state, args, run_dir, {}, workflow.time.time()
                )

            self.assertEqual(exit_code, 1)
            self.assertEqual(state.phase_record("apply")["status"], "failed")
            for phase in ("render", "archive", "dotfiles", "showcase"):
                self.assertEqual(state.phase_record(phase)["status"], "succeeded")

if __name__ == "__main__":
    unittest.main()
