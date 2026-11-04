#!/usr/bin/env python3
"""Entry point for the security-watch timer and CLI (see security_watch/runner.py)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from security_watch import runner  # noqa: E402

if __name__ == "__main__":
    sys.exit(runner.main())
