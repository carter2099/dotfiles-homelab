#!/usr/bin/env python3
"""steward-approve: execute one P7c resolver recommendation exactly as recorded.

    steward-approve --list [RUN-DATE]        list tonight's (or RUN-DATE's) items
    steward-approve RUN-DATE ITEM-ID         execute the recorded commit/revert/doc_fix/patch
    steward-approve --dry-run RUN-DATE ITEM-ID   re-validate only

Before acting it re-checks that every path still has the exact content that was
judged (hashes in 07c-resolve.json), re-runs the secret scan and the private
publish globs, and refuses while the nightly steward is running.  Results and
undo commands are appended to 07c-approvals.jsonl in the run directory.
"""
from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from steward import resolver  # noqa: E402
from steward.config import RUN_DIR_BASE  # noqa: E402


def run_dir_for(date: str) -> Path:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        raise SystemExit(f"steward-approve: run date must be YYYY-MM-DD, got {date!r}")
    path = RUN_DIR_BASE / date
    if not path.is_dir():
        raise SystemExit(f"steward-approve: no run directory {path}")
    return path


def list_items(run_dir: Path) -> int:
    try:
        data = resolver.load_resolution(run_dir)
    except resolver.ApprovalRefused as exc:
        print(f"steward-approve: {exc}", file=sys.stderr)
        return 1
    approved = resolver._approved_ids(run_dir)
    for item in data.get("items") or []:
        status = "approved" if item.get("id") in approved else item.get("status")
        print(f"{item.get('id')}\t{status}\t{item.get('action') or '-'}\t{', '.join(item.get('paths') or [])}")
        if item.get("reason"):
            print(f"    {item['reason']}")
        if item.get("approve_command") and status in ("recommended", "dry_run"):
            print(f"    approve: {item['approve_command']}")
        if item.get("undo"):
            print(f"    undo: {item['undo']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="steward-approve", description=__doc__.split("\n\n")[0])
    parser.add_argument("--list", action="store_true", help="list resolver items")
    parser.add_argument("--dry-run", action="store_true", help="re-validate only; change nothing")
    parser.add_argument("run_date", nargs="?")
    parser.add_argument("item_id", nargs="?")
    args = parser.parse_args(argv)
    if args.list:
        return list_items(run_dir_for(args.run_date or datetime.now().strftime("%Y-%m-%d")))
    if not args.run_date or not args.item_id:
        parser.error("RUN-DATE and ITEM-ID are required (or use --list)")
    try:
        row = resolver.approve(run_dir_for(args.run_date), args.item_id, dry_run=args.dry_run)
    except resolver.ApprovalRefused as exc:
        print(f"steward-approve: refused: {exc}", file=sys.stderr)
        return 1
    print(row.get("summary") or row.get("status"))
    if row.get("undo"):
        print(f"undo: {row['undo']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
