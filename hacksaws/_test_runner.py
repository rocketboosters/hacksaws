"""Shared full-suite coverage entry point for local development."""

from __future__ import annotations

import subprocess
import sys

PYTEST_ARGUMENTS = [
    "--cov=hacksaws",
    "--cov-report=term-missing",
    "--cov-report=xml",
    "--cov-fail-under=95",
]


def main() -> int:
    """Run the full test suite and preserve pytest's process result."""
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", *PYTEST_ARGUMENTS], check=False
    )
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
