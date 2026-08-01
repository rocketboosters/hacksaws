"""Run Prettier on Git-visible files without traversing ignored directories."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable
    from collections.abc import Sequence

MAX_COMMAND_LENGTH = 24_000
MIN_ARGUMENTS = 2


def _candidates(paths: Sequence[str]) -> tuple[int, list[str]]:
    """Return Git-tracked and nonignored untracked files under ``paths``."""
    git = shutil.which("git")
    if git is None:
        sys.stderr.write("Unable to find git on PATH.\n")
        return 127, []
    completed = subprocess.run(
        [
            git,
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            *paths,
        ],
        check=False,
        stdout=subprocess.PIPE,
    )
    if completed.returncode:
        return completed.returncode, []
    candidates = [os.fsdecode(item) for item in completed.stdout.split(b"\0") if item]
    return 0, candidates


def _batches(files: Sequence[str]) -> Iterable[list[str]]:
    """Split file arguments below a conservative cross-platform command length."""
    batch: list[str] = []
    length = 0
    for file in files:
        file_length = len(file) + 3
        if batch and length + file_length > MAX_COMMAND_LENGTH:
            yield batch
            batch = []
            length = 0
        batch.append(file)
        length += file_length
    if batch:
        yield batch


def main(arguments: Sequence[str] | None = None) -> int:
    """Run Prettier in check or write mode over caller-selected paths."""
    arguments = sys.argv[1:] if arguments is None else arguments
    if len(arguments) < MIN_ARGUMENTS or arguments[0] not in {"check", "write"}:
        sys.stderr.write("usage: prettier.py {check|write} PATH [PATH ...]\n")
        return 2

    mode, *paths = arguments
    returncode, files = _candidates(paths)
    if returncode:
        return returncode
    if not files:
        return 0
    npx = shutil.which("npx")
    if npx is None:
        sys.stderr.write("Unable to find npx on PATH. Run `npm install` first.\n")
        return 127
    for batch in _batches(files):
        completed = subprocess.run(
            [npx, "prettier", f"--{mode}", "--ignore-unknown", "--", *batch],
            check=False,
        )
        if completed.returncode:
            return completed.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
