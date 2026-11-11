#!/usr/bin/env python3
"""steward-rig-maintenance: run the steward's gaming-rig maintenance now.

    steward-rig-maintenance

Use it while the rig is temporarily booted into Linux.  It runs exactly the
nightly P1 rig maintenance (apt, herdr, omp, gated reboot, health checks) and,
when the rig answered as Linux, the llama.cpp mature-release update, then
appends one record to ~/digests/steward/rig-maintenance.jsonl.  The nightly
report counts an ok record as the rig's last maintenance.  Refuses while any
steward unit is running or another manual run holds the rig lock.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import deploy_lock  # noqa: E402
from steward import resolver, updates  # noqa: E402
from steward.config import RUN_DIR_BASE  # noqa: E402

RECORD_PATH = RUN_DIR_BASE / "rig-maintenance.jsonl"
HOLDER = "steward-rig-maintenance"
RIG_LOCK_WAIT = 0   # another manual run in progress: refuse at once


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _append_record(record: dict) -> None:
    RECORD_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(RECORD_PATH, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def _maintain() -> list[dict]:
    steps: list[dict] = []
    rig = updates._p1_run_step(steps, "gamingrig_maintenance",
                               updates._p1_gamingrig_maintenance, lambda: None)
    if rig.get("os") == "Linux":
        updates._p1_run_step(steps, "llama_cpp", lambda: updates._p1_locked(
            "llama_cpp",
            deploy_lock.service_lock("llama-cpp", timeout=updates.P1_LOCK_WAIT,
                                     holder=f"{HOLDER}:llama_cpp"),
            updates._p1_llama_cpp_update), lambda: None)
    return steps


def _overall_status(steps: list[dict]) -> str:
    status = str(steps[0].get("status") or "failed")
    if any(s.get("step") == "llama_cpp" and s.get("status") in updates._P1_FAILURE_STATUSES
           for s in steps[1:]):
        return "failed"
    return status


def _print_summary(record: dict) -> None:
    rig = record["steps"][0]
    line = f"gaming rig: {rig.get('status')}"
    if rig.get("reason"):
        line += f" ({rig['reason']})"
    print(line)
    print("  reboot: " + ", ".join(
        f"{key}={rig.get(key)}" for key in
        ("reboot_requested", "new_boot_observed", "rebooted", "post_reboot_health_passed")))
    for sub in rig.get("substeps") or []:
        if isinstance(sub, dict):
            print(f"  {sub.get('step') or '?'}: {sub.get('status')}")
    for step in record["steps"][1:]:
        detail = f" ({step['reason']})" if step.get("reason") else ""
        print(f"llama.cpp: {step.get('status')}{detail}")
    print(f"recorded: {record['status']} in {RECORD_PATH}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="steward-rig-maintenance",
                                     description=__doc__.split("\n\n")[0])
    parser.parse_args(argv)
    if resolver._steward_running():
        print("steward-rig-maintenance: refused: a steward unit is running "
              "(or its state is unknown); try again once it has finished",
              file=sys.stderr)
        return 2
    try:
        with deploy_lock.service_lock("rig", timeout=RIG_LOCK_WAIT, holder=HOLDER):
            started_at = _utc_now()
            date = datetime.now().strftime("%Y-%m-%d")
            steps = _maintain()
            record = {
                "schema": 1,
                "date": date,
                "started_at": started_at,
                "finished_at": _utc_now(),
                "status": _overall_status(steps),
                "steps": steps,
            }
            _append_record(record)
    except deploy_lock.LockTimeout as exc:
        print(f"steward-rig-maintenance: refused: {exc}", file=sys.stderr)
        return 2
    _print_summary(record)
    return 0 if record["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
