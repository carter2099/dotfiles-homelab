#!/usr/bin/env python3
"""Executable entrypoint for the bounded homelab steward package."""
from __future__ import annotations

import sys


if __name__ == "__main__":
    from steward import code_pickup
    from steward.workflow import _setup_args, main

    # Parse first: --help, invalid combinations and --resume never reach the
    # startup merge/pickup, and abbreviations (--dry) resolve exactly as in the
    # workflow.  A fresh run then merges due steward-code PRs and fast-forwards
    # the live tree before the workflow fingerprints its source; a changed tree
    # is loaded by re-executing this entrypoint, an unverified one aborts.
    packet = code_pickup.startup(_setup_args(sys.argv[1:]))
    code_pickup.abort_if_unsafe(packet)
    code_pickup.reexec_if_changed(packet, __file__)
    raise SystemExit(main())
