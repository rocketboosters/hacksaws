"""Hacksaws command-line package."""

from __future__ import annotations

import tomllib as _tomllib
from importlib import metadata as _metadata
from pathlib import Path as _Path
from typing import cast as _cast

from hacksaws._cli import console_main as console_main

try:
    __version__ = _metadata.version("hacksaws")
except _metadata.PackageNotFoundError:
    with _Path(__file__).parent.parent.joinpath("pyproject.toml").open("rb") as _stream:
        __version__ = _cast("str", _tomllib.load(_stream)["project"]["version"])


def main() -> int:
    """Run the Hacksaws CLI and return its process exit status."""
    return console_main().exit_code
