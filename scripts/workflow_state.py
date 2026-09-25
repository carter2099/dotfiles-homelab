#!/usr/bin/env python3
"""Durable, validated state for file-producing workflow phases.

The module deliberately keeps no process-wide connection or state.  Every
operation opens its own SQLite connection, which lets separate workflow
workers safely contend for the same run database.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Final, Iterator, Mapping, TypeAlias


DEFAULT_RUN_ID: Final[str] = "default"
MAX_ERROR_LENGTH: Final[int] = 2048
SQLITE_BUSY_TIMEOUT_MS: Final[int] = 30_000
SQLITE_TIMEOUT_SECONDS: Final[float] = SQLITE_BUSY_TIMEOUT_MS / 1000
_FILE_CHUNK_SIZE: Final[int] = 1024 * 1024
_JSON_SEPARATORS: Final[tuple[str, str]] = (",", ":")

Validator: TypeAlias = Callable[[Any], bool]
PathLike: TypeAlias = Path | str

@dataclass(frozen=True)
class PhaseAttempt:
    """Immutable ownership token for one running phase attempt."""

    workflow: str
    run_id: str
    phase: str
    attempt: int
    updated_at: str
    status: str
    artifact_path: str | None

_CONTEXT_ATTEMPTS: ContextVar[
    dict[tuple[str, str, str, str], PhaseAttempt]
] = ContextVar("workflow_phase_attempts", default={})

_SCHEMA_WORKFLOW_RUNS: Final[str] = """
CREATE TABLE IF NOT EXISTS workflow_runs (
    workflow TEXT NOT NULL,
    run_id TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    error TEXT,
    invalid_reason TEXT,
    PRIMARY KEY (workflow, run_id)
)
"""

_SCHEMA_PHASE_STATE: Final[str] = """
CREATE TABLE IF NOT EXISTS phase_state (
    workflow TEXT NOT NULL,
    run_id TEXT NOT NULL,
    phase TEXT NOT NULL,
    status TEXT NOT NULL,
    input_fingerprint TEXT NOT NULL,
    artifact_path TEXT,
    artifact_hash TEXT,
    schema_version INTEGER NOT NULL,
    attempt INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    updated_at TEXT NOT NULL,
    error TEXT,
    resume_valid INTEGER NOT NULL DEFAULT 0,
    invalid_reason TEXT,
    completion_outcome TEXT,
    completion_reason TEXT,
    FOREIGN KEY (workflow, run_id)
        REFERENCES workflow_runs (workflow, run_id)
        ON DELETE CASCADE
)
"""


def _utc_now() -> str:
    """Return a lexicographically sortable UTC timestamp."""

    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _bounded_text(value: object, *, limit: int = MAX_ERROR_LENGTH) -> str:
    """Convert diagnostic text to a bounded, single stored value."""

    text = str(value)
    if len(text) <= limit:
        return text
    return text[:limit]


def _path_text(path: PathLike | None) -> str | None:
    """Return the lexical path representation used for exact identity checks."""

    if path is None:
        return None
    return str(Path(path))


def _fsync_directory(directory: Path) -> None:
    """Persist a directory entry after an atomic replacement."""

    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    fd = os.open(directory, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _json_default(value: object) -> str:
    """Encode path-like values without silently stringifying other objects."""

    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")



def canonical_fingerprint(value: Any) -> str:
    """Hash a deterministic JSON representation of ``value``.

    Inputs to workflow phases are expected to be JSON-compatible.  Sorting
    object keys and using compact separators makes equivalent mappings produce
    the same fingerprint regardless of insertion order.  NaN and infinity
    are rejected because they do not have a portable canonical JSON form.
    """

    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=_JSON_SEPARATORS,
        default=_json_default,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def file_sha256(path: PathLike) -> str:
    """Return the SHA-256 digest of a file, streaming it in bounded chunks."""

    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(_FILE_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_replace(path: PathLike, payload: bytes) -> Path:
    """Write bytes durably through a same-directory temporary file."""

    destination = Path(path)
    parent = destination.parent
    parent.mkdir(parents=True, exist_ok=True)

    temporary_fd: int | None = None
    temporary_path: Path | None = None
    try:
        temporary_fd, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            dir=parent,
        )
        temporary_path = Path(temporary_name)
        os.fchmod(temporary_fd, 0o600)
        with os.fdopen(temporary_fd, "wb") as handle:
            temporary_fd = None
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, destination)
        temporary_path = None
        _fsync_directory(parent)
        return destination
    finally:
        if temporary_fd is not None:
            os.close(temporary_fd)
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass


def atomic_write_text(path: PathLike, text: str) -> Path:
    """Atomically and durably replace a UTF-8 text artifact with mode 0600."""

    if not isinstance(text, str):
        raise TypeError("text must be a str")
    return _atomic_replace(path, text.encode("utf-8"))


def atomic_write_json(path: PathLike, data: Any) -> Path:
    """Atomically and durably replace a JSON artifact with mode 0600."""

    serialized = json.dumps(
        data,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        indent=2,
        default=_json_default,
    )
    return atomic_write_text(path, f"{serialized}\n")


class WorkflowState:
    """SQLite-backed state for one workflow run."""

    run_dir: Path
    workflow: str
    run_id: str
    db_path: Path

    def __init__(
        self,
        run_dir: Path,
        workflow: str,
        run_id: str | None = None,
        db_path: Path | None = None,
    ) -> None:
        if not isinstance(run_dir, Path):
            run_dir = Path(run_dir)
        if not isinstance(workflow, str) or not workflow:
            raise ValueError("workflow must be a non-empty string")
        effective_run_id = DEFAULT_RUN_ID if run_id is None else run_id
        if not isinstance(effective_run_id, str) or not effective_run_id:
            raise ValueError("run_id must be a non-empty string")

        self.run_dir = run_dir
        self.workflow = workflow
        self.run_id = effective_run_id
        environment_db = os.environ.get("WORKFLOW_STATE_DB")
        self.db_path = (
            Path(db_path)
            if db_path is not None
            else Path(environment_db)
            if environment_db
            else run_dir / "workflow-state.sqlite3"
        )
        self._active_attempts: dict[str, PhaseAttempt] = {}
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_database()

    def _attempt_context_key(self, phase: str) -> tuple[str, str, str, str]:
        return (
            str(self.db_path.resolve(strict=False)),
            self.workflow,
            self.run_id,
            phase,
        )

    def _remember_attempt(self, token: PhaseAttempt) -> None:
        self._active_attempts[token.phase] = token
        attempts = dict(_CONTEXT_ATTEMPTS.get())
        attempts[self._attempt_context_key(token.phase)] = token
        _CONTEXT_ATTEMPTS.set(attempts)

    def _forget_attempt(self, token: PhaseAttempt) -> None:
        if self._active_attempts.get(token.phase) == token:
            self._active_attempts.pop(token.phase, None)
        attempts = dict(_CONTEXT_ATTEMPTS.get())
        key = self._attempt_context_key(token.phase)
        if attempts.get(key) == token:
            attempts.pop(key, None)
            _CONTEXT_ATTEMPTS.set(attempts)

    def _connect(self) -> sqlite3.Connection:
        """Open a configured per-operation SQLite connection."""

        connection = sqlite3.connect(
            self.db_path,
            timeout=SQLITE_TIMEOUT_SECONDS,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _initialize_database(self) -> None:
        """Create the schema while serializing concurrent first openers."""

        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(_SCHEMA_WORKFLOW_RUNS)
            connection.execute(_SCHEMA_PHASE_STATE)
            phase_columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(phase_state)").fetchall()
            }
            if "completion_outcome" not in phase_columns:
                connection.execute(
                    "ALTER TABLE phase_state ADD COLUMN completion_outcome TEXT"
                )
            if "completion_reason" not in phase_columns:
                connection.execute(
                    "ALTER TABLE phase_state ADD COLUMN completion_reason TEXT"
                )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        os.chmod(self.db_path, 0o600)

    @contextmanager
    def _transition(self) -> Iterator[sqlite3.Connection]:
        """Run one short serialized state transition."""

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _phase_row(self, phase: str) -> sqlite3.Row | None:
        connection = self._connect()
        try:
            return connection.execute(
                """
                SELECT * FROM phase_state
                WHERE workflow = ? AND run_id = ? AND phase = ?
                """,
                (self.workflow, self.run_id, phase),
            ).fetchone()
        finally:
            connection.close()

    def _phase_dict(self, phase: str) -> dict[str, Any] | None:
        row = self._phase_row(phase)
        return None if row is None else dict(row)

    @staticmethod
    def _same_attempt(left: Mapping[str, Any], right: sqlite3.Row) -> bool:
        """Check that a transition still owns the phase attempt it read."""

        return (
            int(left["attempt"]) == int(right["attempt"])
            and str(left["updated_at"]) == str(right["updated_at"])
            and str(left["status"]) == str(right["status"])
        )

    def _refresh_run_status(
        self,
        connection: sqlite3.Connection,
        *,
        now: str,
        error: str | None = None,
        invalid_reason: str | None = None,
    ) -> None:
        """Keep the run summary consistent with its phase rows."""

        rows = connection.execute(
            """
            SELECT status FROM phase_state
            WHERE workflow = ? AND run_id = ?
            """,
            (self.workflow, self.run_id),
        ).fetchall()
        statuses = [str(row["status"]) for row in rows]
        if "running" in statuses:
            status = "running"
            completed_at: str | None = None
        elif "failed" in statuses:
            status = "failed"
            completed_at = now
        elif "invalid" in statuses:
            status = "invalid"
            completed_at = now
        elif statuses and all(item == "succeeded" for item in statuses):
            status = "succeeded"
            completed_at = now
        elif statuses and all(item in ("succeeded", "aborted") for item in statuses):
            # Interrupted (aborted) phases with no still-running work make the
            # run itself interrupted, not perpetually 'running' (digest-quality
            # audit 2026-09-03: ai-tech 2026-09-02 stayed 'running' after a
            # SIGTERM mid-run even though the edition was later published).
            status = "aborted"
            completed_at = now
        else:
            status = "running"
            completed_at = None

        existing = connection.execute(
            """
            SELECT error, invalid_reason FROM workflow_runs
            WHERE workflow = ? AND run_id = ?
            """,
            (self.workflow, self.run_id),
        ).fetchone()
        stored_error = None if existing is None else existing["error"]
        stored_invalid_reason = None if existing is None else existing["invalid_reason"]
        run_error = (
            error
            if status in ("failed", "aborted") and error is not None
            else stored_error if status in ("failed", "aborted") else None
        )
        run_invalid_reason = (
            invalid_reason
            if status == "invalid" and invalid_reason is not None
            else stored_invalid_reason
            if status == "invalid"
            else None
        )
        connection.execute(
            """
            UPDATE workflow_runs
            SET status = ?, updated_at = ?, completed_at = ?,
                error = ?, invalid_reason = ?
            WHERE workflow = ? AND run_id = ?
            """,
            (
                status,
                now,
                completed_at,
                run_error,
                run_invalid_reason,
                self.workflow,
                self.run_id,
            ),
        )

    def _invalidate_snapshot(
        self,
        snapshot: Mapping[str, Any],
        reason: str,
    ) -> None:
        """Invalidate a succeeded row unless another attempt replaced it."""

        bounded_reason = _bounded_text(reason)
        now = _utc_now()
        with self._transition() as connection:
            current = connection.execute(
                """
                SELECT * FROM phase_state
                WHERE workflow = ? AND run_id = ? AND phase = ?
                """,
                (self.workflow, self.run_id, str(snapshot["phase"])),
            ).fetchone()
            if current is None or not self._same_attempt(snapshot, current):
                return
            if str(current["status"]) != "succeeded":
                return
            connection.execute(
                """
                UPDATE phase_state
                SET status = 'invalid', updated_at = ?, completed_at = NULL,
                    error = NULL, resume_valid = 0, invalid_reason = ?
                WHERE workflow = ? AND run_id = ? AND phase = ?
                """,
                (
                    now,
                    bounded_reason,
                    self.workflow,
                    self.run_id,
                    str(snapshot["phase"]),
                ),
            )
            self._refresh_run_status(
                connection,
                now=now,
                invalid_reason=bounded_reason,
            )

    def begin_phase(
        self,
        phase: str,
        inputs: Any = None,
        artifact_path: Path | str | None = None,
        schema_version: int = 1,
    ) -> PhaseAttempt:
        """Start or retry a phase and return its immutable ownership token."""

        if not isinstance(phase, str) or not phase:
            raise ValueError("phase must be a non-empty string")
        fingerprint = canonical_fingerprint(inputs)
        requested_path = _path_text(artifact_path)
        schema = int(schema_version)
        now = _utc_now()

        with self._transition() as connection:
            connection.execute(
                """
                INSERT INTO workflow_runs
                    (workflow, run_id, status, created_at, updated_at,
                     completed_at, error, invalid_reason)
                VALUES (?, ?, 'running', ?, ?, NULL, NULL, NULL)
                ON CONFLICT(workflow, run_id) DO UPDATE SET
                    status = 'running', updated_at = ?, completed_at = NULL,
                    error = NULL, invalid_reason = NULL
                """,
                (
                    self.workflow,
                    self.run_id,
                    now,
                    now,
                    now,
                ),
            )
            previous = connection.execute(
                """
                SELECT * FROM phase_state
                WHERE workflow = ? AND run_id = ? AND phase = ?
                """,
                (self.workflow, self.run_id, phase),
            ).fetchone()
            effective_path = requested_path
            if effective_path is None and previous is not None:
                effective_path = previous["artifact_path"]
            if previous is None:
                connection.execute(
                    """
                    INSERT INTO phase_state
                        (workflow, run_id, phase, status, input_fingerprint,
                         artifact_path, artifact_hash, schema_version, attempt,
                         created_at, started_at, completed_at, updated_at,
                         error, resume_valid, invalid_reason)
                    VALUES (?, ?, ?, 'running', ?, ?, NULL, ?, 1, ?, ?, NULL, ?, NULL, 0, NULL)
                    """,
                    (
                        self.workflow,
                        self.run_id,
                        phase,
                        fingerprint,
                        effective_path,
                        schema,
                        now,
                        now,
                        now,
                    ),
                )
            else:
                connection.execute(
                    """
                    UPDATE phase_state
                    SET status = 'running', input_fingerprint = ?,
                        artifact_path = ?, artifact_hash = NULL,
                        schema_version = ?, attempt = attempt + 1,
                        started_at = ?, completed_at = NULL, updated_at = ?,
                        error = NULL, resume_valid = 0, invalid_reason = NULL,
                        completion_outcome = NULL, completion_reason = NULL
                    WHERE workflow = ? AND run_id = ? AND phase = ?
                    """,
                    (
                        fingerprint,
                        effective_path,
                        schema,
                        now,
                        now,
                        self.workflow,
                        self.run_id,
                        phase,
                    ),
                )
            current = connection.execute(
                """
                SELECT * FROM phase_state
                WHERE workflow = ? AND run_id = ? AND phase = ?
                """,
                (self.workflow, self.run_id, phase),
            ).fetchone()
            if current is None:
                raise RuntimeError("phase attempt was not persisted")
            token = PhaseAttempt(
                workflow=self.workflow,
                run_id=self.run_id,
                phase=phase,
                attempt=int(current["attempt"]),
                updated_at=str(current["updated_at"]),
                status=str(current["status"]),
                artifact_path=(
                    None
                    if current["artifact_path"] is None
                    else str(current["artifact_path"])
                ),
            )
        self._remember_attempt(token)
        return token

    def _validator_result(
        self,
        path: Path,
        validator: Validator,
    ) -> tuple[bool, str | None]:
        """Run a validator against parsed JSON, with path compatibility."""

        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            return False, f"validator input unreadable: {exc}"

        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            # A generic file validator may intentionally inspect the path.  A
            # JSON loader will still reject this artifact in load_json below.
            try:
                result = validator(path)
                accepted = result is None or bool(result)
            except Exception as validator_error:
                return False, f"validator failed: {validator_error}"
            if accepted:
                return True, None
            return False, f"validator rejected artifact: {exc}"

        try:
            result = validator(parsed)
            accepted = result is None or bool(result)
        except (AttributeError, TypeError):
            # Supporting a path validator costs nothing and keeps resume_valid
            # useful for complete_file artifacts without weakening false/raises.
            try:
                result = validator(path)
                accepted = result is None or bool(result)
            except Exception as validator_error:
                return False, f"validator failed: {validator_error}"
        except Exception as exc:
            return False, f"validator failed: {exc}"
        return (True, None) if accepted else (False, "validator rejected artifact")

    def _validated_artifact(
        self,
        phase: str,
        inputs: Any,
        artifact_path: Path | str | None,
        schema_version: int,
        validator: Validator | None,
    ) -> tuple[dict[str, Any], Path, bytes] | None:
        """Return one hash-checked row/path/payload snapshot."""

        if not isinstance(phase, str) or not phase:
            raise ValueError("phase must be a non-empty string")
        expected_fingerprint = canonical_fingerprint(inputs)
        expected_path = _path_text(artifact_path)
        expected_schema = int(schema_version)
        row = self._phase_row(phase)
        if row is None or str(row["status"]) != "succeeded":
            return None
        snapshot = dict(row)

        reason: str | None = None
        if str(row["input_fingerprint"]) != expected_fingerprint:
            reason = "input fingerprint mismatch"
        elif expected_path is not None and str(row["artifact_path"]) != expected_path:
            reason = "artifact path mismatch"
        elif row["artifact_path"] is None:
            reason = "artifact path is missing"
        elif int(row["schema_version"]) != expected_schema:
            reason = "schema version mismatch"

        path = Path(expected_path or str(row["artifact_path"] or ""))
        payload = b""
        if reason is None:
            try:
                payload = path.read_bytes()
            except OSError as exc:
                reason = f"artifact cannot be read: {exc}"
            else:
                actual_hash = hashlib.sha256(payload).hexdigest()
                if str(row["artifact_hash"] or "") != actual_hash:
                    reason = "artifact hash mismatch"

        if reason is None and path.suffix.casefold() == ".json":
            try:
                json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                reason = f"malformed JSON artifact: {exc}"

        if reason is None and validator is not None:
            accepted, validator_reason = self._validator_result(path, validator)
            if not accepted:
                reason = validator_reason or "validator rejected artifact"
            else:
                try:
                    current_hash = file_sha256(path)
                except OSError as exc:
                    reason = f"artifact changed during validation: {exc}"
                else:
                    if current_hash != str(row["artifact_hash"] or ""):
                        reason = "artifact changed during validation"

        if reason is not None:
            self._invalidate_snapshot(snapshot, reason)
            return None
        return snapshot, path, payload

    def resume_valid(
        self,
        phase: str,
        inputs: Any = None,
        artifact_path: Path | str | None = None,
        schema_version: int = 1,
        validator: Validator | None = None,
    ) -> bool:
        """Return whether a succeeded artifact exactly matches phase state."""

        return self._validated_artifact(
            phase,
            inputs,
            artifact_path,
            schema_version,
            validator,
        ) is not None

    def load_json(
        self,
        phase: str,
        inputs: Any = None,
        artifact_path: Path | str | None = None,
        schema_version: int = 1,
        validator: Validator | None = None,
    ) -> Any | None:
        """Load JSON bytes from the same validated state snapshot."""

        validated = self._validated_artifact(
            phase,
            inputs,
            artifact_path,
            schema_version,
            validator,
        )
        if validated is None:
            return None
        snapshot, _, payload = validated
        try:
            return json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._invalidate_snapshot(snapshot, f"malformed JSON artifact: {exc}")
            return None

    def load_text(
        self,
        phase: str,
        inputs: Any = None,
        artifact_path: Path | str | None = None,
        schema_version: int = 1,
        validator: Validator | None = None,
    ) -> str | None:
        """Load UTF-8 text bytes from the same validated state snapshot."""

        validated = self._validated_artifact(
            phase,
            inputs,
            artifact_path,
            schema_version,
            validator,
        )
        if validated is None:
            return None
        snapshot, _, payload = validated
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            self._invalidate_snapshot(snapshot, f"malformed text artifact: {exc}")
            return None

    def _attempt_snapshot(
        self,
        phase: str,
        attempt: PhaseAttempt | None,
    ) -> tuple[PhaseAttempt, dict[str, Any]]:
        """Resolve this caller's immutable phase-attempt ownership."""

        token = (
            attempt
            or self._active_attempts.get(phase)
            or _CONTEXT_ATTEMPTS.get().get(self._attempt_context_key(phase))
        )
        if token is None:
            raise ValueError(f"phase has not begun in this workflow state: {phase}")
        if (
            token.workflow != self.workflow
            or token.run_id != self.run_id
            or token.phase != phase
        ):
            raise ValueError("phase attempt token belongs to another phase")
        return token, {
            "phase": token.phase,
            "attempt": token.attempt,
            "updated_at": token.updated_at,
            "status": token.status,
            "artifact_path": token.artifact_path,
        }

    def _completion_path(
        self,
        phase: str,
        artifact_path: Path | str | None,
        attempt: PhaseAttempt | None,
    ) -> tuple[PhaseAttempt, dict[str, Any], Path]:
        """Resolve the artifact path owned by this caller's phase attempt."""

        token, snapshot = self._attempt_snapshot(phase, attempt)
        if snapshot["status"] != "running":
            raise ValueError(f"phase attempt is not completable: {phase}")
        requested = _path_text(artifact_path)
        stored = snapshot["artifact_path"]
        if (
            requested is not None
            and stored is not None
            and str(stored) != requested
        ):
            raise ValueError("artifact path does not match begin_phase")
        if stored is None and requested is None:
            raise ValueError("artifact path is required")
        return token, snapshot, Path(requested or str(stored))

    def _complete_owned_file(
        self,
        phase: str,
        token: PhaseAttempt,
        snapshot: Mapping[str, Any],
        path: Path,
        *,
        outcome: str,
        reason: str | None,
        writer: Callable[[], None] | None = None,
    ) -> None:
        """Write if needed and commit one owned attempt under the DB lock."""

        if outcome not in {"succeeded", "skipped", "empty", "degraded"}:
            raise ValueError(f"unsupported completion outcome: {outcome}")
        if outcome != "succeeded" and not str(reason or "").strip():
            raise ValueError(f"{outcome} completion requires a reason")
        bounded_reason = None if reason is None else _bounded_text(reason)

        with self._transition() as connection:
            current = connection.execute(
                """
                SELECT * FROM phase_state
                WHERE workflow = ? AND run_id = ? AND phase = ?
                """,
                (self.workflow, self.run_id, phase),
            ).fetchone()
            if current is None or not self._same_attempt(snapshot, current):
                raise RuntimeError("phase attempt changed before completion")
            if writer is not None:
                writer()
            if not path.is_file():
                raise FileNotFoundError(path)
            os.chmod(path, 0o600)
            artifact_hash = file_sha256(path)
            now = _utc_now()
            connection.execute(
                """
                UPDATE phase_state
                SET artifact_path = COALESCE(artifact_path, ?),
                    status = 'succeeded', artifact_hash = ?, completed_at = ?,
                    updated_at = ?, error = NULL, resume_valid = 1,
                    invalid_reason = NULL, completion_outcome = ?,
                    completion_reason = ?
                WHERE workflow = ? AND run_id = ? AND phase = ?
                """,
                (
                    _path_text(path),
                    artifact_hash,
                    now,
                    now,
                    outcome,
                    bounded_reason,
                    self.workflow,
                    self.run_id,
                    phase,
                ),
            )
            self._refresh_run_status(connection, now=now)
        self._forget_attempt(token)

    def complete_file(
        self,
        phase: str,
        artifact_path: Path | str | None = None,
        *,
        outcome: str = "succeeded",
        reason: str | None = None,
        attempt: PhaseAttempt | None = None,
    ) -> None:
        """Record an existing artifact owned by this phase attempt."""

        token, snapshot, path = self._completion_path(phase, artifact_path, attempt)
        self._complete_owned_file(
            phase,
            token,
            snapshot,
            path,
            outcome=outcome,
            reason=reason,
        )

    def complete_json(
        self,
        phase: str,
        data: Any,
        artifact_path: Path | str | None = None,
        *,
        outcome: str = "succeeded",
        reason: str | None = None,
        attempt: PhaseAttempt | None = None,
    ) -> Path:
        """Atomically write and record JSON for an owned phase attempt."""

        # Accept the equally natural ``(phase, path, data)`` spelling while
        # retaining the documented ``(phase, data, artifact_path=...)`` form.
        if (
            isinstance(data, (Path, str))
            and artifact_path is not None
            and not isinstance(artifact_path, (Path, str))
        ):
            data, artifact_path = artifact_path, data
        token, snapshot, path = self._completion_path(phase, artifact_path, attempt)
        self._complete_owned_file(
            phase,
            token,
            snapshot,
            path,
            outcome=outcome,
            reason=reason,
            writer=lambda: atomic_write_json(path, data),
        )
        return path

    def complete_text(
        self,
        phase: str,
        text: str,
        artifact_path: Path | str | None = None,
        *,
        outcome: str = "succeeded",
        reason: str | None = None,
        attempt: PhaseAttempt | None = None,
    ) -> Path:
        """Atomically write and record UTF-8 text for an owned attempt."""

        token, snapshot, path = self._completion_path(phase, artifact_path, attempt)
        self._complete_owned_file(
            phase,
            token,
            snapshot,
            path,
            outcome=outcome,
            reason=reason,
            writer=lambda: atomic_write_text(path, text),
        )
        return path

    def fail_phase(
        self,
        phase: str,
        error: str | BaseException,
        *,
        attempt: PhaseAttempt | None = None,
    ) -> None:
        """Mark this caller's phase attempt failed with bounded diagnostics."""

        token, snapshot = self._attempt_snapshot(phase, attempt)
        now = _utc_now()
        bounded_error = _bounded_text(error)
        with self._transition() as connection:
            current = connection.execute(
                """
                SELECT * FROM phase_state
                WHERE workflow = ? AND run_id = ? AND phase = ?
                """,
                (self.workflow, self.run_id, phase),
            ).fetchone()
            if current is None or not self._same_attempt(snapshot, current):
                raise RuntimeError("phase attempt changed before failure update")
            connection.execute(
                """
                UPDATE phase_state
                SET status = 'failed', completed_at = ?, updated_at = ?,
                    error = ?, resume_valid = 0, invalid_reason = NULL,
                    completion_outcome = 'failed', completion_reason = ?
                WHERE workflow = ? AND run_id = ? AND phase = ?
                """,
                (
                    now,
                    now,
                    bounded_error,
                    bounded_error,
                    self.workflow,
                    self.run_id,
                    phase,
                ),
            )
            self._refresh_run_status(connection, now=now, error=bounded_error)
        self._forget_attempt(token)

    def phase_record(self, phase: str) -> dict[str, Any] | None:
        """Return the persisted phase row, or ``None`` when absent."""

        if not isinstance(phase, str) or not phase:
            raise ValueError("phase must be a non-empty string")
        return self._phase_dict(phase)

    def abort_interrupted_phases(
        self,
        error: str | BaseException | None = None,
    ) -> None:
        """Terminally record interrupted 'running' phases and finalize the run.

        Used when a run is stopped mid-phase (SIGTERM, crash, operator stop):
        those phases will never complete, so they are recorded as 'aborted'
        and the run row leaves 'running' with a completed_at instead of being
        stuck forever (digest-quality audit 2026-09-03).
        """

        bounded_error = None if error is None else _bounded_text(error)
        now = _utc_now()
        with self._transition() as connection:
            connection.execute(
                """
                UPDATE phase_state
                SET status = 'aborted', completed_at = ?, updated_at = ?,
                    error = ?, resume_valid = 0, invalid_reason = NULL,
                    completion_outcome = 'aborted', completion_reason = ?
                WHERE workflow = ? AND run_id = ? AND status = 'running'
                """,
                (
                    now,
                    now,
                    bounded_error,
                    bounded_error,
                    self.workflow,
                    self.run_id,
                ),
            )
            self._refresh_run_status(connection, now=now, error=bounded_error)

    def finalize_published(self) -> bool:
        """Finalize an interrupted run once its artifacts were published.

        The publish/recovery path calls this after the edition built from this
        run's validated artifacts goes live: 'running' phase rows that never
        finished (e.g. research killed by SIGTERM) are recorded as 'aborted'
        and the run row is finalized to 'succeeded' with completed_at.
        Returns whether the run row was transitioned.
        """

        now = _utc_now()
        with self._transition() as connection:
            connection.execute(
                """
                UPDATE phase_state
                SET status = 'aborted', completed_at = ?, updated_at = ?,
                    error = ?, resume_valid = 0, invalid_reason = NULL,
                    completion_outcome = 'aborted', completion_reason = ?
                WHERE workflow = ? AND run_id = ? AND status = 'running'
                """,
                (
                    now,
                    now,
                    "phase interrupted; run artifacts validated and published",
                    "phase interrupted; run artifacts validated and published",
                    self.workflow,
                    self.run_id,
                ),
            )
            cursor = connection.execute(
                """
                UPDATE workflow_runs
                SET status = 'succeeded', updated_at = ?, completed_at = ?,
                    error = NULL, invalid_reason = NULL
                WHERE workflow = ? AND run_id = ?
                  AND status IN ('running', 'aborted')
                """,
                (now, now, self.workflow, self.run_id),
            )
            return int(cursor.rowcount) > 0


__all__: Final[tuple[str, ...]] = (
    "PhaseAttempt",
    "MAX_ERROR_LENGTH",
    "WorkflowState",
    "atomic_write_json",
    "atomic_write_text",
    "canonical_fingerprint",
    "file_sha256",
)
