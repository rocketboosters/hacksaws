"""Shared full-suite coverage entry point for local development."""

from __future__ import annotations

import subprocess
import sys
from importlib.util import find_spec
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

PYTEST_ARGUMENTS = [
    "--cov=hacksaws",
    "--cov-report=term-missing",
    "--cov-report=xml",
    "--cov-fail-under=95",
]


def main(arguments: Sequence[str] | None = None) -> int:
    """Run the full test suite, forwarding arguments and preserving its result."""
    if find_spec("pytest") is None:
        sys.stderr.write(
            "The 'test' command requires development dependencies. "
            "Run `uv sync --group dev`, then `uv run test`.\n"
        )
        return 2
    forwarded = sys.argv[1:] if arguments is None else arguments
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", *PYTEST_ARGUMENTS, *forwarded], check=False
    )
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
