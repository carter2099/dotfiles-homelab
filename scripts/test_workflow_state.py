#!/usr/bin/env python3
"""Behavioral tests for the durable workflow state contract."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from workflow_state import (  # noqa: E402
    MAX_ERROR_LENGTH,
    WorkflowState,
    atomic_write_json,
    atomic_write_text,
    canonical_fingerprint,
    file_sha256,
)


class WorkflowStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)
        self.run_dir = self.root / "run"
        self.artifact = self.run_dir / "result.json"
        self.inputs = {"query": "stable", "limits": [1, 2, 3]}

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def make_state(self, *, run_id: str = "run-1") -> WorkflowState:
        return WorkflowState(self.run_dir, "example", run_id=run_id)

    def begin(self, state: WorkflowState, *, schema_version: int = 1) -> None:
        state.begin_phase(
            "fetch",
            inputs=self.inputs,
            artifact_path=self.artifact,
            schema_version=schema_version,
        )

    def complete(self, state: WorkflowState, value: Any = None) -> None:
        payload = {"ok": True, "value": value if value is not None else "done"}
        state.complete_json("fetch", payload)

    def run_record(self, state: WorkflowState) -> dict[str, Any]:
        connection = state._connect()
        try:
            row = connection.execute(
                """
                SELECT * FROM workflow_runs
                WHERE workflow = ? AND run_id = ?
                """,
                (state.workflow, state.run_id),
            ).fetchone()
        finally:
            connection.close()
        self.assertIsNotNone(row)
        return dict(row)

    def test_roundtrip_records_and_loads_valid_json(self) -> None:
        state = self.make_state()
        self.begin(state, schema_version=3)
        self.complete(state, {"count": 2})

        record = state.phase_record("fetch")
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record["status"], "succeeded")
        self.assertEqual(record["attempt"], 1)
        self.assertEqual(record["schema_version"], 3)
        self.assertEqual(record["artifact_path"], str(self.artifact))
        self.assertEqual(record["artifact_hash"], file_sha256(self.artifact))
        self.assertEqual(record["completion_outcome"], "succeeded")
        self.assertIsNone(record["completion_reason"])
        self.assertTrue(
            state.resume_valid(
                "fetch",
                inputs=self.inputs,
                artifact_path=self.artifact,
                schema_version=3,
            )
        )
        self.assertEqual(
            state.load_json(
                "fetch",
                inputs=self.inputs,
                artifact_path=self.artifact,
                schema_version=3,
            ),
            {"ok": True, "value": {"count": 2}},
        )

    def test_legacy_artifact_without_row_is_rejected(self) -> None:
        self.run_dir.mkdir(parents=True)
        atomic_write_json(self.artifact, {"ok": True})
        state = self.make_state()
        self.assertFalse(
            state.resume_valid(
                "fetch", inputs=self.inputs, artifact_path=self.artifact
            )
        )
        self.assertIsNone(state.phase_record("fetch"))

    def test_input_schema_and_path_mismatches_invalidate(self) -> None:
        state = self.make_state()
        self.begin(state, schema_version=2)
        self.complete(state)
        self.assertFalse(
            state.resume_valid(
                "fetch",
                inputs={"query": "changed"},
                artifact_path=self.artifact,
                schema_version=2,
            )
        )
        self.assertEqual(state.phase_record("fetch")["invalid_reason"], "input fingerprint mismatch")  # type: ignore[index]

        for kwargs, expected in (
            ({"inputs": self.inputs, "schema_version": 1}, "schema version mismatch"),
            (
                {
                    "inputs": self.inputs,
                    "artifact_path": self.run_dir / "different.json",
                    "schema_version": 2,
                },
                "artifact path mismatch",
            ),
        ):
            state.begin_phase(
                "fetch",
                inputs=self.inputs,
                artifact_path=self.artifact,
                schema_version=2,
            )
            self.complete(state)
            self.assertFalse(state.resume_valid("fetch", **kwargs))
            record = state.phase_record("fetch")
            self.assertIsNotNone(record)
            self.assertEqual(record["invalid_reason"], expected)  # type: ignore[index]

    def test_missing_and_tampered_artifacts_invalidate(self) -> None:
        state = self.make_state()
        self.begin(state)
        self.complete(state)
        self.artifact.unlink()
        self.assertFalse(
            state.resume_valid("fetch", inputs=self.inputs, artifact_path=self.artifact)
        )
        self.assertEqual(state.phase_record("fetch")["status"], "invalid")  # type: ignore[index]

        self.begin(state)
        self.complete(state)
        atomic_write_text(self.artifact, "tampered")
        self.assertFalse(
            state.resume_valid("fetch", inputs=self.inputs, artifact_path=self.artifact)
        )
        record = state.phase_record("fetch")
        self.assertIsNotNone(record)
        self.assertEqual(record["invalid_reason"], "artifact hash mismatch")  # type: ignore[index]

    def test_malformed_json_and_validator_rejection_invalidate(self) -> None:
        state = self.make_state()
        self.begin(state)
        atomic_write_text(self.artifact, "{not-json")
        state.complete_file("fetch")
        self.assertFalse(
            state.resume_valid(
                "fetch",
                inputs=self.inputs,
                artifact_path=self.artifact,
                validator=lambda _: True,
            )
        )
        self.assertIsNone(
            state.load_json("fetch", inputs=self.inputs, artifact_path=self.artifact)
        )
        self.assertEqual(state.phase_record("fetch")["status"], "invalid")  # type: ignore[index]

        self.begin(state)
        self.complete(state, "bad")
        self.assertFalse(
            state.resume_valid(
                "fetch",
                inputs=self.inputs,
                artifact_path=self.artifact,
                validator=lambda value: value["value"] == "good",
            )
        )
        record = state.phase_record("fetch")
        self.assertIsNotNone(record)
        self.assertIn("validator rejected", record["invalid_reason"])  # type: ignore[operator,index]

        self.begin(state)
        self.complete(state, "good")
        self.assertEqual(
            state.load_json(
                "fetch",
                inputs=self.inputs,
                artifact_path=self.artifact,
                validator=lambda value: value["value"] == "good",
            )["value"],
            "good",
        )

    def test_failed_phase_is_not_resumable_and_error_is_bounded(self) -> None:
        state = self.make_state()
        self.begin(state)
        state.fail_phase("fetch", "x" * (MAX_ERROR_LENGTH + 500))
        record = state.phase_record("fetch")
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record["status"], "failed")
        self.assertEqual(len(record["error"]), MAX_ERROR_LENGTH)
        self.assertFalse(
            state.resume_valid("fetch", inputs=self.inputs, artifact_path=self.artifact)
        )


    def test_interrupted_phases_become_terminal_and_nonresumable(self) -> None:
        state = self.make_state()
        research_path = self.run_dir / "01-research.json"
        publication_path = self.run_dir / "publication.json"
        state.begin_phase(
            "research",
            inputs={"stage": "research"},
            artifact_path=research_path,
        )
        state.begin_phase(
            "archive",
            inputs={"stage": "archive"},
            artifact_path=publication_path,
        )
        state.complete_json("archive", {"published": True})

        state.abort_interrupted_phases("interrupted by signal 15")

        research = state.phase_record("research")
        archive = state.phase_record("archive")
        run = self.run_record(state)
        self.assertEqual(research["status"], "aborted")
        self.assertEqual(research["completion_outcome"], "aborted")
        self.assertEqual(research["resume_valid"], 0)
        self.assertIsNotNone(research["completed_at"])
        self.assertEqual(archive["status"], "succeeded")
        self.assertEqual(run["status"], "aborted")
        self.assertEqual(run["error"], "interrupted by signal 15")
        self.assertIsNotNone(run["completed_at"])

    def test_published_run_finalization_is_idempotent_and_preserves_failures(
        self,
    ) -> None:
        state = self.make_state()
        state.begin_phase(
            "research",
            inputs={"stage": "research"},
            artifact_path=self.run_dir / "01-research.json",
        )
        state.begin_phase(
            "archive",
            inputs={"stage": "archive"},
            artifact_path=self.run_dir / "publication.json",
        )
        state.complete_json("archive", {"published": True})

        self.assertTrue(state.finalize_published())
        self.assertFalse(state.finalize_published())
        self.assertEqual(state.phase_record("research")["status"], "aborted")
        run = self.run_record(state)
        self.assertEqual(run["status"], "succeeded")
        self.assertIsNone(run["error"])
        self.assertIsNotNone(run["completed_at"])

        failed = self.make_state(run_id="failed-run")
        failed.begin_phase(
            "research",
            inputs={"stage": "research"},
            artifact_path=self.run_dir / "failed-research.json",
        )
        failed.fail_phase("research", "source validation failed")
        self.assertFalse(failed.finalize_published())
        self.assertEqual(self.run_record(failed)["status"], "failed")


    def test_empty_and_skipped_outcomes_require_and_record_reasons(self) -> None:
        state = self.make_state()
        self.begin(state)
        state.complete_json(
            "fetch",
            {"items": [], "reason": "no input"},
            outcome="empty",
            reason="no input",
        )
        record = state.phase_record("fetch")
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record["status"], "succeeded")
        self.assertEqual(record["completion_outcome"], "empty")
        self.assertEqual(record["completion_reason"], "no input")
        self.assertTrue(
            state.resume_valid("fetch", inputs=self.inputs, artifact_path=self.artifact)
        )

        self.begin(state)
        with self.assertRaises(ValueError):
            state.complete_json("fetch", {"skipped": True}, outcome="skipped")

    def test_atomic_replacement_and_private_mode(self) -> None:
        text_path = self.run_dir / "nested" / "artifact.txt"
        atomic_write_text(text_path, "first")
        os.chmod(text_path, 0o644)
        atomic_write_text(text_path, "second")
        self.assertEqual(text_path.read_text(encoding="utf-8"), "second")
        self.assertEqual(text_path.stat().st_mode & 0o777, 0o600)

        json_path = self.run_dir / "nested" / "artifact.json"
        atomic_write_json(json_path, {"b": 2, "a": 1})
        self.assertEqual(json.loads(json_path.read_text(encoding="utf-8")), {"a": 1, "b": 2})
        self.assertEqual(json_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(file_sha256(json_path), hashlib.sha256(json_path.read_bytes()).hexdigest())

    def test_text_loader_returns_hash_checked_snapshot(self) -> None:
        state = self.make_state()
        text_path = self.run_dir / "result.txt"
        state.begin_phase("text", inputs=self.inputs, artifact_path=text_path)
        atomic_write_text(text_path, "stable\n")
        state.complete_file("text")

        self.assertEqual(
            state.load_text("text", inputs=self.inputs, artifact_path=text_path),
            "stable\n",
        )
        atomic_write_text(text_path, "changed\n")
        self.assertIsNone(
            state.load_text("text", inputs=self.inputs, artifact_path=text_path)
        )
        self.assertEqual(state.phase_record("text")["status"], "invalid")  # type: ignore[index]

    def test_stale_attempt_cannot_write_or_complete_newer_attempt(self) -> None:
        first = self.make_state()
        second = self.make_state()
        first_token = first.begin_phase(
            "fetch", inputs={"attempt": 1}, artifact_path=self.artifact
        )
        second_token = second.begin_phase(
            "fetch", inputs={"attempt": 2}, artifact_path=self.artifact
        )

        with self.assertRaisesRegex(RuntimeError, "attempt changed"):
            first.complete_json(
                "fetch",
                {"owner": "stale"},
                attempt=first_token,
            )
        self.assertFalse(self.artifact.exists())

        second.complete_json(
            "fetch",
            {"owner": "current"},
            attempt=second_token,
        )
        self.assertEqual(json.loads(self.artifact.read_text()), {"owner": "current"})

    def test_attempts_increment_for_retries(self) -> None:
        state = self.make_state()
        self.begin(state)
        self.begin(state)
        record = state.phase_record("fetch")
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record["status"], "running")
        self.assertEqual(record["attempt"], 2)

        self.complete(state)
        self.begin(state)
        record = state.phase_record("fetch")
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record["attempt"], 3)

    def test_two_instances_contend_without_sleeping(self) -> None:
        first = self.make_state()
        second = self.make_state()
        barrier = threading.Barrier(2)
        errors: list[BaseException] = []

        def begin_from(state: WorkflowState) -> None:
            try:
                barrier.wait()
                self.begin(state)
            except BaseException as exc:  # pragma: no cover - assertion below
                errors.append(exc)

        threads = [
            threading.Thread(target=begin_from, args=(first,)),
            threading.Thread(target=begin_from, args=(second,)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        record = first.phase_record("fetch")
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record["attempt"], 2)

    def test_database_is_private_and_configured(self) -> None:
        state = self.make_state()
        self.assertEqual(state.db_path, self.run_dir / "workflow-state.sqlite3")
        self.assertEqual(state.db_path.stat().st_mode & 0o777, 0o600)
        connection = state._connect()
        try:
            self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            self.assertEqual(connection.execute("PRAGMA synchronous").fetchone()[0], 2)
            self.assertEqual(
                {row[1] for row in connection.execute("PRAGMA table_info(phase_state)")},
                {
                    "workflow",
                    "run_id",
                    "phase",
                    "status",
                    "input_fingerprint",
                    "artifact_path",
                    "artifact_hash",
                    "schema_version",
                    "attempt",
                    "created_at",
                    "started_at",
                    "completed_at",
                    "updated_at",
                    "error",
                    "resume_valid",
                    "invalid_reason",
                    "completion_outcome",
                    "completion_reason",
                },
            )
        finally:
            connection.close()

    def test_existing_database_schema_is_migrated(self) -> None:
        self.run_dir.mkdir(parents=True)
        db_path = self.run_dir / "workflow-state.sqlite3"
        connection = sqlite3.connect(db_path)
        try:
            connection.execute(
                """
                CREATE TABLE workflow_runs (
                    workflow TEXT NOT NULL, run_id TEXT NOT NULL, status TEXT NOT NULL,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL, completed_at TEXT,
                    error TEXT, invalid_reason TEXT, PRIMARY KEY (workflow, run_id)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE phase_state (
                    workflow TEXT NOT NULL, run_id TEXT NOT NULL, phase TEXT NOT NULL,
                    status TEXT NOT NULL, input_fingerprint TEXT NOT NULL,
                    artifact_path TEXT, artifact_hash TEXT, schema_version INTEGER NOT NULL,
                    attempt INTEGER NOT NULL, created_at TEXT NOT NULL,
                    started_at TEXT NOT NULL, completed_at TEXT, updated_at TEXT NOT NULL,
                    error TEXT, resume_valid INTEGER NOT NULL DEFAULT 0,
                    invalid_reason TEXT
                )
                """
            )
            connection.commit()
        finally:
            connection.close()

        state = self.make_state()
        migrated = state._connect()
        try:
            columns = {
                row[1] for row in migrated.execute("PRAGMA table_info(phase_state)")
            }
        finally:
            migrated.close()
        self.assertIn("completion_outcome", columns)
        self.assertIn("completion_reason", columns)

    def test_canonical_fingerprint_is_order_independent(self) -> None:
        self.assertEqual(
            canonical_fingerprint({"a": 1, "b": [True, None]}),
            canonical_fingerprint({"b": [True, None], "a": 1}),
        )


if __name__ == "__main__":
    unittest.main()
