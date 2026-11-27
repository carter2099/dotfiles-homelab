#!/usr/bin/env python3
"""Refresh (--write) or compare (--check) ~/system-config/external/** snapshots."""
from __future__ import annotations

if __name__ == "__main__":
    from steward.external_settings import main

    raise SystemExit(main())
