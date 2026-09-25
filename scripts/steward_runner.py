#!/usr/bin/env python3
"""Executable entrypoint for the bounded homelab steward package."""
from __future__ import annotations

from steward.workflow import main


if __name__ == "__main__":
    raise SystemExit(main())
