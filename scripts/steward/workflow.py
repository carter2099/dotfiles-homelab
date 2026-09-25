"""Ordered steward workflow and durable resume orchestration."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
try:
    from workflow_state import (
        WorkflowState,
        atomic_write_json,
        atomic_write_text,
        canonical_fingerprint,
        file_sha256,
    )
except ModuleNotFoundError as error:
    if error.name != "workflow_state":
        raise
    from ..workflow_state import (
        WorkflowState,
        atomic_write_json,
        atomic_write_text,
        canonical_fingerprint,
        file_sha256,
    )

from . import audit, dotfiles, fixes, health, queue, report, setup, showcase, updates
from .config import (
    DEPENDABOT_UNIT,
    DIGEST_SCRIPT,
    HOME,
    LLAMA_CPP_UPDATE_SCRIPT,
    RUN_DIR_BASE,
    STEWARD_MODEL,
    WORKFLOW_POLICY_VERSION,
    WORKFLOW_SCHEMA_VERSION,
)
from .runtime import MemorySampler, _reboot_if_needed, run, user_env

WORKFLOW_NAME = "homelab-steward"
POLICY_VERSION = WORKFLOW_POLICY_VERSION
SCHEMA_VERSION = WORKFLOW_SCHEMA_VERSION

HEADLESS_AGENT_CONFIG = HOME / ".omp" / "agent" / "headless-override.yml"
CLOUDFLARE_CONFIG_PATHS = (
    HOME / ".config" / "cloudflare" / "api-token",
    HOME / ".config" / "cloudflare" / "account-id",
    HOME / ".config" / "cloudflare" / "homelab-tunnel-id",
)

def _external_fingerprint_paths() -> tuple[Path, ...]:
    """Return immutable helper/config paths used by resumable phases."""
    digest_paths = [Path(DIGEST_SCRIPT)]
    paths = [
        Path(DIGEST_SCRIPT),
        Path(LLAMA_CPP_UPDATE_SCRIPT),
        HEADLESS_AGENT_CONFIG,
        *CLOUDFLARE_CONFIG_PATHS,
    ]
    # Keep tests and deployment overrides honest when a phase module's
    # imported constant is replaced: hash the path the caller actually uses.
    for module, name in ((report, "DIGEST_SCRIPT"), (updates, "LLAMA_CPP_UPDATE_SCRIPT")):
        value = getattr(module, name, None)
        if value is not None:
            path = Path(value)
            paths.append(path)
            if name == "DIGEST_SCRIPT":
                digest_paths.append(path)
    paths.extend(
        path.with_name(".smtp_config")
        for path in dict.fromkeys(digest_paths)
    )
    return tuple(dict.fromkeys(paths))


class StartupFingerprintChanged(RuntimeError):
    """Raised when a loaded source or policy changes during one process."""


def _code_fingerprint() -> dict[str, str]:
    script_dir = Path(__file__).resolve().parent.parent
    files = {
        script_dir / "steward_runner.py",
        script_dir / "workflow_state.py",
        *Path(__file__).resolve().parent.glob("*.py"),
        *map(Path, _external_fingerprint_paths()),
    }
    result: dict[str, str] = {}
    for path in sorted(files, key=str):
        try:
            result[str(path)] = file_sha256(path)
        except OSError:
            result[str(path)] = "missing"
    return result


def _fingerprint_changes(
    expected: dict[str, str],
    current: dict[str, str],
) -> list[str]:
    """Return fingerprint members whose path or content changed."""
    return sorted(
        path
        for path in set(expected) | set(current)
        if expected.get(path) != current.get(path)
    )


def _fingerprint_change_error(
    expected: dict[str, str],
    current: dict[str, str],
    changed: list[str],
) -> StartupFingerprintChanged:
    detail = ", ".join(
        f"{path}: {expected.get(path, 'missing')} -> {current.get(path, 'missing')}"
        for path in changed[:12]
    )
    if len(changed) > 12:
        detail += f", ... ({len(changed)} paths changed)"
    return StartupFingerprintChanged(
        f"startup source/policy fingerprint changed during run: {detail}"
    )


def _assert_startup_fingerprint(expected: dict[str, str]) -> None:
    """Abort rather than mixing source/policy versions within one process."""
    current = _code_fingerprint()
    changed = _fingerprint_changes(expected, current)
    if changed:
        raise _fingerprint_change_error(expected, current, changed)




def _phase_code_fingerprint(args: argparse.Namespace) -> dict[str, str]:
    """Return the immutable process-start snapshot attached by ``main``."""
    snapshot = getattr(args, "_startup_code_fingerprint", None)
    if snapshot is None:
        snapshot = _code_fingerprint()
        args._startup_code_fingerprint = dict(snapshot)
    return dict(snapshot)


def _code_fingerprint_changed(args: argparse.Namespace) -> None:
    snapshot = getattr(args, "_startup_code_fingerprint", None)
    if snapshot is not None:
        _assert_startup_fingerprint(snapshot)


def _is_restartable_fix_source(path: str) -> bool:
    """Whether P7b may hand this changed source to a fresh process."""
    script_dir = Path(__file__).resolve().parent.parent
    steward_dir = Path(__file__).resolve().parent
    candidate = Path(path).expanduser().resolve()
    explicit_sources = {
        script_dir / "steward_runner.py",
        script_dir / "workflow_state.py",
    }
    for value in (
        DIGEST_SCRIPT,
        LLAMA_CPP_UPDATE_SCRIPT,
        getattr(report, "DIGEST_SCRIPT", None),
        getattr(updates, "LLAMA_CPP_UPDATE_SCRIPT", None),
    ):
        if value is not None:
            explicit_sources.add(Path(value).expanduser().resolve())
    return candidate in explicit_sources or (
        candidate.parent == steward_dir and candidate.suffix == ".py"
    )


def _record_restartable_fix_changes(args: argparse.Namespace) -> tuple[str, ...]:
    """Record P7b source changes that require a clean-process continuation."""
    expected = getattr(args, "_startup_code_fingerprint", None)
    if expected is None:
        return ()
    current = _code_fingerprint()
    changed = _fingerprint_changes(expected, current)
    if not changed:
        return ()
    if any(not _is_restartable_fix_source(path) for path in changed):
        raise _fingerprint_change_error(expected, current, changed)
    recorded = tuple(changed)
    args._post_fix_source_changes = recorded
    return recorded

_PHASE_ARTIFACTS = {
    "setup": "00-setup.json",
    "session-memory": "00b-session-memory.json",
    "apply": "01-applied.json",
    "validation": "02-validation.json",
    "troubleshoot": "03-troubleshoot.json",
    "remediation": "03a-remediation.json",
    "heartbeat": "04-heartbeat.json",
    "queue": "05-queue.json",
    "audit": "07-audit.json",
    "fixes": "07b-fixes.json",
    "render": "08-email.html",
    "archive": "summary.md",
    "dotfiles": "09b-dotfiles.json",
    "showcase": showcase.ARTIFACT,
}



def _phase_inputs(
    phase: str,
    args: argparse.Namespace,
    run_dir: Path,
    upstream: list[str] = (),
) -> dict[str, Any]:
    _code_fingerprint_changed(args)
    upstream_hashes: dict[str, str] = {}
    for name in upstream:
        path = run_dir / name
        try:
            upstream_hashes[name] = file_sha256(path)
        except OSError:
            upstream_hashes[name] = "missing"
    if phase == "dotfiles":
        dot_status, dot_error = dotfiles._snapshot(dotfiles.DOTFILES_GIT, dotfiles.HOME)
        upstream_hashes["dotfiles-status"] = canonical_fingerprint(
            {"status": dot_status, "error": dot_error}
        )
        upstream_hashes["active-sessions"] = canonical_fingerprint(
            dotfiles.collect_active_session_evidence()
        )
    code_hashes = _phase_code_fingerprint(args)
    return {
        "phase": phase,
        "code_hashes": code_hashes,
        "code_hash": canonical_fingerprint(code_hashes),
        "policy_version": POLICY_VERSION,
        "model": STEWARD_MODEL,
        "upstream_hashes": upstream_hashes,
        "flags": {
            "dry_run": bool(getattr(args, "dry_run", False)),
        },
    }


def _failure_payload(phase: str, error: BaseException) -> dict[str, Any]:
    detail = str(error)[:2048]
    return {
        "phase": phase,
        "phase_status": "failed",
        "phase_failed": True,
        "error": detail,
        "reason": detail,
    }


def _artifact_snapshot(path: Path) -> tuple[bool, str | None]:
    """Capture existence and bytes before invoking a legacy operation."""
    if not path.is_file():
        return False, None
    try:
        return True, file_sha256(path)
    except OSError:
        # A pre-existing unreadable artifact can never be proven to have
        # changed, so a None-returning operation must not adopt it.
        return True, None


def _artifact_created_or_changed(
    path: Path,
    *,
    existed: bool,
    before_hash: str | None,
) -> bool:
    if not path.is_file():
        return False
    if not existed or before_hash is None:
        return not existed
    try:
        return file_sha256(path) != before_hash
    except OSError:
        return False
def _infer_apply_outcome(data: dict[str, Any]) -> None:
    """Derive P1's durable outcome even for legacy result packets."""
    retryable: list[str] = []
    degraded: list[str] = []

    def visit(value: Any, path: str = "") -> None:
        if isinstance(value, dict):
            status = str(value.get("status") or "").strip().lower()
            if status in {"failed", "error", "timeout", "started", "reverted", "warning", "degraded"}:
                detail = value.get("error") or value.get("reason") or value.get("step") or status
                item = f"{path}: {str(detail)[:400]}" if path else str(detail)[:400]
                (retryable if status in {"failed", "error", "timeout", "started"} else degraded).append(item)
            for key in ("steps", "substeps", "checks"):
                children = value.get(key)
                if isinstance(children, list):
                    for index, child in enumerate(children):
                        visit(child, f"{path}.{key}[{index}]" if path else f"{key}[{index}]")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]" if path else f"[{index}]")

    visit(data.get("steps", []))
    if retryable:
        data.update({
            "phase_status": "failed",
            "phase_failed": True,
            "reason": "retryable P1 step failure: " + "; ".join(retryable[:8]),
        })
    elif degraded:
        data.update({
            "phase_status": "degraded",
            "reason": "P1 completed with degraded step(s): " + "; ".join(degraded[:8]),
        })


def _with_canonical_status(phase: str, data: Any) -> Any:
    """Add a canonical outcome without inventing emptiness from artifact shape."""
    if not isinstance(data, dict):
        return data
    if phase == "apply" and "phase_status" not in data:
        _infer_apply_outcome(data)
    data.setdefault("phase_status", "succeeded")
    status = data["phase_status"]
    if status not in {"succeeded", "skipped", "empty", "degraded", "failed"}:
        raise ValueError(f"{phase} returned unsupported phase_status {status!r}")
    if status != "succeeded" and not str(data.get("reason") or "").strip():
        if status == "failed" and str(data.get("error") or "").strip():
            data["reason"] = str(data["error"])[:2048]
        else:
            raise ValueError(f"{phase} returned {status} without a reason")
    return data


def _failed_result_reason(phase: str, data: Any) -> str | None:
    if not isinstance(data, dict) or data.get("phase_status") != "failed":
        return None
    return str(
        data.get("reason")
        or data.get("error")
        or f"{phase} returned a retryable failure"
    )[:2048]


def _write_failure_artifact(
    phase: str,
    artifact: Path,
    error: BaseException | str,
    *,
    json_artifact: bool,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    failure = payload if payload is not None else _failure_payload(phase, error)
    if json_artifact:
        atomic_write_json(artifact, failure)
    else:
        atomic_write_text(artifact, f"<p>{phase} failed: {error}</p>\n")
    return failure

def _owned_phase_progress(
    state: WorkflowState,
    phase: str,
    artifact: Path,
    attempt: Any,
) -> Callable[[dict[str, Any]], None]:
    """Return an atomic progress writer owned by one WorkflowState attempt."""

    def persist(payload: dict[str, Any]) -> None:
        if not isinstance(payload, dict):
            raise TypeError("phase progress payload must be an object")
        record = state.phase_record(phase)
        if (
            not record
            or record.get("status") != "running"
            or int(record.get("attempt") or 0) != int(attempt.attempt)
            or str(record.get("updated_at") or "") != str(attempt.updated_at)
        ):
            raise RuntimeError(f"phase attempt no longer owns progress: {phase}")
        owned = dict(payload)
        owned["_phase_attempt"] = {
            "workflow": attempt.workflow,
            "run_id": attempt.run_id,
            "phase": attempt.phase,
            "attempt": attempt.attempt,
            "started_at": attempt.updated_at,
        }
        atomic_write_json(artifact, owned)

    return persist


def _failure_payload_from_partial(
    phase: str,
    error: BaseException,
    artifact: Path,
    *,
    artifact_existed: bool,
    artifact_hash: str | None,
    attempt: Any,
    json_artifact: bool,
) -> dict[str, Any]:
    """Merge an owned current-attempt artifact into a terminal failure packet."""

    failure = _failure_payload(phase, error)
    if not json_artifact:
        return failure
    if not _artifact_created_or_changed(
        artifact,
        existed=artifact_existed,
        before_hash=artifact_hash,
    ):
        return failure
    try:
        partial = json.loads(artifact.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return failure
    if not isinstance(partial, dict):
        return failure
    marker = partial.get("_phase_attempt")
    if marker is not None:
        if not isinstance(marker, dict):
            return failure
        try:
            marker_attempt = int(marker.get("attempt") or 0)
            expected_attempt = int(getattr(attempt, "attempt", 0))
        except (TypeError, ValueError):
            return failure
        if (
            marker.get("workflow") != getattr(attempt, "workflow", None)
            or marker.get("run_id") != getattr(attempt, "run_id", None)
            or marker.get("phase") != getattr(attempt, "phase", None)
            or marker_attempt != expected_attempt
            or marker.get("started_at") != getattr(attempt, "updated_at", None)
        ):
            return failure
    partial.update(failure)
    return partial


def _run_phase(
    state: WorkflowState,
    *,
    phase: str,
    artifact: Path,
    inputs: dict[str, Any],
    args: argparse.Namespace,
    operation: Callable[[], Any],
    json_artifact: bool = True,
    source_reload_boundary: bool = False,
    progress_operation: Callable[[Callable[[dict[str, Any]], None]], Any] | None = None,
) -> tuple[Any, bool]:
    """Resume only a matching succeeded state row; otherwise run atomically."""
    _code_fingerprint_changed(args)
    if args.resume:
        if json_artifact:
            cached = state.load_json(
                phase,
                inputs=inputs,
                artifact_path=artifact,
                schema_version=SCHEMA_VERSION,
            )
            if cached is not None:
                print(f"[{phase}] skipped (validated resume)")
                return cached, True
        elif state.resume_valid(
            phase,
            inputs=inputs,
            artifact_path=artifact,
            schema_version=SCHEMA_VERSION,
        ):
            print(f"[{phase}] skipped (validated resume)")
            return None, True
    artifact_existed, artifact_hash = _artifact_snapshot(artifact)
    attempt = state.begin_phase(
        phase,
        inputs=inputs,
        artifact_path=artifact,
        schema_version=SCHEMA_VERSION,
    )
    progress_writer = (
        _owned_phase_progress(state, phase, artifact, attempt)
        if progress_operation is not None
        else None
    )
    try:
        data = (
            progress_operation(progress_writer)
            if progress_operation is not None
            else operation()
        )
        if source_reload_boundary:
            _record_restartable_fix_changes(args)
        else:
            _code_fingerprint_changed(args)
        artifact_changed = _artifact_created_or_changed(
            artifact,
            existed=artifact_existed,
            before_hash=artifact_hash,
        )
        if json_artifact and data is None and artifact_changed:
            try:
                data = json.loads(artifact.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                raise RuntimeError(
                    f"{phase} wrote an unreadable JSON artifact: {error}"
                ) from error
        if data is None and not artifact_changed:
            # A legacy None-returning operation may explicitly skip.  Replace
            # a stale pre-existing artifact with a fresh status packet instead
            # of completing that stale payload.
            data = {
                "phase_status": "skipped",
                "reason": (
                    "phase returned no data and wrote no new artifact"
                    if artifact_existed
                    else "phase returned no data and wrote no artifact"
                ),
            }
        data = _with_canonical_status(phase, data)
        if json_artifact:
            atomic_write_json(artifact, data)
        elif data is not None and artifact_existed and not artifact_changed:
            atomic_write_text(artifact, "")
        elif not artifact.is_file():
            atomic_write_text(artifact, "")
        failure_reason = _failed_result_reason(phase, data)
        if failure_reason is not None:
            if isinstance(data, dict):
                data["phase_failed"] = True
            if json_artifact:
                atomic_write_json(artifact, data)
            state.fail_phase(phase, failure_reason)
            print(f"[{phase}] FAILED: {failure_reason}")
            return data, False
        if isinstance(data, dict):
            outcome = str(data.get("phase_status") or "succeeded")
            reason = data.get("reason") if outcome != "succeeded" else None
        else:
            outcome = "succeeded"
            reason = None
        state.complete_file(
            phase,
            artifact,
            outcome=outcome,
            reason=None if reason is None else str(reason),
        )
        return data, False
    except StartupFingerprintChanged as error:
        failure = _failure_payload_from_partial(
            phase,
            error,
            artifact,
            artifact_existed=artifact_existed,
            artifact_hash=artifact_hash,
            attempt=attempt,
            json_artifact=json_artifact,
        )
        _write_failure_artifact(
            phase,
            artifact,
            error,
            json_artifact=json_artifact,
            payload=failure,
        )
        state.fail_phase(phase, error)
        print(f"[{phase}] FAILED: {error}")
        raise
    except Exception as error:
        failure = _failure_payload_from_partial(
            phase,
            error,
            artifact,
            artifact_existed=artifact_existed,
            artifact_hash=artifact_hash,
            attempt=attempt,
            json_artifact=json_artifact,
        )
        _write_failure_artifact(
            phase,
            artifact,
            error,
            json_artifact=json_artifact,
            payload=failure,
        )
        # Keep visible artifact names and diagnostics, but deliberately do not
        # complete the state row: failed rows are never resumable.
        state.fail_phase(phase, error)
        print(f"[{phase}] FAILED: {error}")
        return failure, False




def _load_completed_json_phase(
    state: WorkflowState,
    phase: str,
    artifact: Path,
) -> dict[str, Any]:
    """Load an exact completed artifact for the post-P7b process handoff."""
    record = state.phase_record(phase)
    expected_path = artifact.expanduser().resolve()
    try:
        recorded_path = Path(str(record["artifact_path"])).expanduser().resolve()
    except (KeyError, TypeError):
        recorded_path = None
    try:
        artifact_hash = file_sha256(expected_path)
    except OSError:
        artifact_hash = None
    if (
        not record
        or record.get("status") != "succeeded"
        or not record.get("resume_valid")
        or int(record.get("schema_version") or 0) != SCHEMA_VERSION
        or recorded_path != expected_path
        or record.get("artifact_hash") != artifact_hash
    ):
        raise RuntimeError(
            f"post-fix continuation rejected incomplete or changed {phase} state"
        )
    try:
        data = json.loads(expected_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(
            f"post-fix continuation could not read {phase} artifact: {error}"
        ) from error
    if not isinstance(data, dict):
        raise RuntimeError(
            f"post-fix continuation requires an object artifact for {phase}"
        )
    return data


def _restart_after_fixes(
    args: argparse.Namespace,
    run_dir: Path,
    started: float,
) -> None:
    """Re-exec after an authorized P7b source change, then resume at P8."""
    changed = tuple(getattr(args, "_post_fix_source_changes", ()))
    if not changed:
        return
    entrypoint = Path(__file__).resolve().parent.parent / "steward_runner.py"
    command = [
        sys.executable,
        str(entrypoint),
        "--resume",
        "--run-dir",
        str(run_dir),
        "--continue-after-fixes",
        "--started-at",
        repr(started),
    ]
    if args.dry_run:
        command.insert(2, "--dry-run")
    names = ", ".join(Path(path).name for path in changed)
    _flush_memory(args)
    print(f"[P7b] reloading changed source before reporting: {names}", flush=True)
    sys.stderr.flush()
    os.execv(command[0], command)
    raise RuntimeError("post-fix source reload returned unexpectedly")


def _finish_after_fixes(
    state: WorkflowState,
    args: argparse.Namespace,
    run_dir: Path,
    setup_data: dict[str, Any],
    started: float,
) -> int:
    """Render, archive, commit, and clean up after P7b is stable."""
    _run_phase(
        state,
        phase="render",
        artifact=run_dir / _PHASE_ARTIFACTS["render"],
        inputs=_phase_inputs(
            "render",
            args,
            run_dir,
            [
                "01-applied.json",
                "02-validation.json",
                "05-queue.json",
                "07-audit.json",
                "07b-fixes.json",
            ],
        ),
        args=args,
        operation=lambda: report.phase_8_render_send(
            run_dir, setup_data, dry_run=args.dry_run
        ),
        json_artifact=False,
    )
    elapsed = time.time() - started
    _flush_memory(args)
    _run_phase(
        state,
        phase="archive",
        artifact=run_dir / _PHASE_ARTIFACTS["archive"],
        inputs=_phase_inputs(
            "archive",
            args,
            run_dir,
            [
                "01-applied.json",
                "02-validation.json",
                "05-queue.json",
                "07-audit.json",
                "07b-fixes.json",
            ],
        ),
        args=args,
        operation=lambda: report.phase_9_archive(run_dir, setup_data, elapsed),
        json_artifact=False,
    )
    _run_phase(
        state,
        phase="dotfiles",
        artifact=run_dir / _PHASE_ARTIFACTS["dotfiles"],
        inputs=_phase_inputs("dotfiles", args, run_dir, ["summary.md"]),
        args=args,
        operation=lambda: dotfiles.phase_9b_dotfiles(
            run_dir, dry_run=args.dry_run
        ),
    )
    _run_phase(
        state,
        phase="showcase",
        artifact=run_dir / _PHASE_ARTIFACTS["showcase"],
        inputs=_phase_inputs("showcase", args, run_dir, ["09b-dotfiles.json"]),
        args=args,
        operation=lambda: showcase.phase_9c_showcase(
            run_dir, dry_run=args.dry_run
        ),
    )

    dep = setup_data.get("dependabot", {})
    if dep.get("stopped") and not args.dry_run:
        try:
            run(["systemctl", "--user", "start", DEPENDABOT_UNIT], env=user_env())
            print("[cleanup] dependabot-webhook restarted")
        except Exception as error:
            print(f"[cleanup] dependabot restart failed: {error}")
    outcomes = []
    failed = False
    for phase in _PHASE_ARTIFACTS:
        record = state.phase_record(phase)
        if not record:
            continue
        status = record.get("status")
        outcome = record.get("completion_outcome")
        if status != "failed" and outcome != "degraded":
            continue
        label = "failed" if status == "failed" else "degraded"
        failed = failed or status == "failed"
        outcomes.append(
            f"{phase} {label}: "
            f"{str(record.get('error') or record.get('completion_reason') or 'incomplete')[:240]}"
        )
    if outcomes:
        print("[maintenance] final outcome: " + "; ".join(outcomes))
    print(f"\nMaintenance {'failed' if failed else 'finished'} in {elapsed:.0f}s")
    return 1 if failed else 0


def _setup_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Homelab Steward — nightly deterministic Python orchestrator"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Skip mutations, executor, agent fan-out, and email send",
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="Resume only phases with matching durable WorkflowState rows",
    )
    parser.add_argument(
        "--run-dir",
        help="Exact prior run directory to resume; valid only with --resume",
    )
    parser.add_argument(
        "--continue-after-fixes",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--started-at", type=float, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.run_dir:
        if not args.resume:
            parser.error("--run-dir requires --resume")
        base = RUN_DIR_BASE.expanduser().resolve()
        requested = Path(args.run_dir).expanduser().resolve()
        if requested.parent != base or re.fullmatch(r"\d{4}-\d{2}-\d{2}", requested.name) is None:
            parser.error(f"--run-dir must be an immediate YYYY-MM-DD child of {base}")
        args.run_dir = str(requested)
    if args.continue_after_fixes:
        if not args.resume or not args.run_dir or args.started_at is None:
            parser.error(
                "--continue-after-fixes requires --resume, --run-dir, and --started-at"
            )
    elif args.started_at is not None:
        parser.error("--started-at requires --continue-after-fixes")
    return args


def _flush_memory(args: argparse.Namespace) -> None:
    """Persist cgroup memory maxima before a phase boundary or process handoff."""
    sampler = getattr(args, "_memory_sampler", None)
    if sampler is not None:
        sampler.flush()


def main(argv: list[str] | None = None) -> int:
    args = _setup_args(argv)
    # Every phase in this process must observe the same loaded source and
    # policy files.  Each phase boundary compares this fixed startup snapshot.
    args._startup_code_fingerprint = _code_fingerprint()
    started = args.started_at if args.started_at is not None else time.time()
    # A reboot resume must retain the original run identity across midnight.
    # The boot handoff passes --run-dir; manual same-day resumes use today's run.
    if args.run_dir:
        run_dir = Path(args.run_dir)
    else:
        run_dir = RUN_DIR_BASE / datetime.now().strftime("%Y-%m-%d")
    date_str = run_dir.name
    state = WorkflowState(run_dir, WORKFLOW_NAME, run_id=date_str)
    args._memory_sampler = MemorySampler(run_dir / "memory.json").start()

    if args.continue_after_fixes:
        setup_data = _load_completed_json_phase(
            state,
            "setup",
            run_dir / _PHASE_ARTIFACTS["setup"],
        )
        _load_completed_json_phase(
            state,
            "fixes",
            run_dir / _PHASE_ARTIFACTS["fixes"],
        )
        if bool(setup_data.get("dry_run")) != bool(args.dry_run):
            raise RuntimeError("post-fix continuation changed dry-run mode")
        print("[resume] source reloaded; continuing at reporting boundary")
        return _finish_after_fixes(state, args, run_dir, setup_data, started)

    setup_data, _ = _run_phase(
        state,
        phase="setup",
        artifact=run_dir / _PHASE_ARTIFACTS["setup"],
        inputs=_phase_inputs("setup", args, run_dir),
        args=args,
        operation=lambda: setup.phase_0_setup(args, run_dir=run_dir),
    )
    if not isinstance(setup_data, dict):
        setup_data = {}
    run_dir = Path(setup_data.get("run_dir", run_dir))

    _run_phase(
        state,
        phase="session-memory",
        artifact=run_dir / _PHASE_ARTIFACTS["session-memory"],
        inputs=_phase_inputs("session-memory", args, run_dir, ["00-setup.json"]),
        args=args,
        operation=lambda: setup.phase_0b_session_memory(
            run_dir, dry_run=args.dry_run, setup=setup_data
        ),
    )
    _run_phase(
        state,
        phase="apply",
        artifact=run_dir / _PHASE_ARTIFACTS["apply"],
        inputs=_phase_inputs("apply", args, run_dir, ["00-setup.json"]),
        args=args,
        operation=lambda: updates.phase_1_apply(run_dir, dry_run=args.dry_run),
        progress_operation=lambda persist: updates.phase_1_apply(
            run_dir,
            dry_run=args.dry_run,
            progress=persist,
        ),
    )
    _run_phase(
        state,
        phase="validation",
        artifact=run_dir / _PHASE_ARTIFACTS["validation"],
        inputs=_phase_inputs("validation", args, run_dir, ["01-applied.json"]),
        args=args,
        operation=lambda: health.phase_2_validate(run_dir),
    )
    _run_phase(
        state,
        phase="troubleshoot",
        artifact=run_dir / _PHASE_ARTIFACTS["troubleshoot"],
        inputs=_phase_inputs("troubleshoot", args, run_dir, ["01-applied.json", "02-validation.json"]),
        args=args,
        operation=lambda: health.phase_3_troubleshoot(run_dir, dry_run=args.dry_run),
    )
    _run_phase(
        state,
        phase="remediation",
        artifact=run_dir / _PHASE_ARTIFACTS["remediation"],
        inputs=_phase_inputs("remediation", args, run_dir, ["02-validation.json", "03-troubleshoot.json"]),
        args=args,
        operation=lambda: health.phase_3a_remediation(run_dir, dry_run=args.dry_run),
    )

    if _reboot_if_needed(run_dir, "P3", dry_run=args.dry_run):
        _flush_memory(args)
        print("[reboot] system is going down for reboot — will resume on boot")
        return 0

    _run_phase(
        state,
        phase="heartbeat",
        artifact=run_dir / _PHASE_ARTIFACTS["heartbeat"],
        inputs=_phase_inputs("heartbeat", args, run_dir, ["02-validation.json", "03a-remediation.json"]),
        args=args,
        operation=lambda: health.phase_4_heartbeat(run_dir),
    )
    _run_phase(
        state,
        phase="queue",
        artifact=run_dir / _PHASE_ARTIFACTS["queue"],
        inputs=_phase_inputs("queue", args, run_dir, ["04-heartbeat.json"]),
        args=args,
        operation=lambda: queue.phase_5_work_queue(run_dir, dry_run=args.dry_run),
    )
    _run_phase(
        state,
        phase="audit",
        artifact=run_dir / _PHASE_ARTIFACTS["audit"],
        inputs=_phase_inputs("audit", args, run_dir, ["05-queue.json", "04-heartbeat.json"]),
        args=args,
        operation=lambda: audit.phase_7_audit(run_dir, setup_data, dry_run=args.dry_run),
    )
    _run_phase(
        state,
        phase="fixes",
        artifact=run_dir / _PHASE_ARTIFACTS["fixes"],
        inputs=_phase_inputs("fixes", args, run_dir, ["07-audit.json"]),
        args=args,
        operation=lambda: fixes.phase_7b_fix(run_dir, dry_run=args.dry_run),
        source_reload_boundary=True,
    )
    _restart_after_fixes(args, run_dir, started)
    return _finish_after_fixes(state, args, run_dir, setup_data, started)


__all__ = ["main"]
