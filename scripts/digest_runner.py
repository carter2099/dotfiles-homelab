#!/usr/bin/env python3
"""Stable executable wrapper for the modular Daily News workflow.

The service and systemd shell entry keep invoking this path.  All pipeline
implementation belongs to ``daily_news`` owners; this file only handles CLI
argument parsing and process-level configuration.
"""
from __future__ import annotations

import argparse

from daily_news.catalog import TOPICS
from daily_news.runtime import configure_test_mode
from daily_news import runtime
from daily_news.workflow import run_digest, validate_runtime_contract


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deterministic multi-phase digest runner")
    parser.add_argument("topic", nargs="?", choices=list(TOPICS) + ["all"], help="Topic to run (or 'all' for every topic)")
    parser.add_argument("--preflight", action="store_true", help="Validate load-bearing runtime contracts and exit")
    parser.add_argument("--dry-run", action="store_true", help="Run without updating the top-level daily HTML archive")
    parser.add_argument("--test", action="store_true", help="Isolate output in ~/digests/test/ and suppress production archives")
    parser.add_argument("--model", type=str, default=None, help="Override the LLM model")
    parser.add_argument("--test-label", type=str, default=None, help="Label for test run directory")
    args = parser.parse_args(argv)

    if args.preflight:
        validate_runtime_contract()
        print("Daily News preflight passed")
        return 0
    if args.topic is None:
        parser.error("topic is required unless --preflight is used")

    if args.test:
        configure_test_mode()
    if args.model:
        runtime.MODEL_OVERRIDE = args.model
    if args.test_label:
        runtime.TEST_LABEL = args.test_label
    elif args.model and args.test:
        runtime.TEST_LABEL = args.model

    if args.topic == "all":
        for category in TOPICS:
            run_digest(category, dry_run=args.dry_run)
    else:
        run_digest(args.topic, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
