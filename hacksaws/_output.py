"""Terminal and machine-output primitives for the Hacksaws command line."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING
from typing import Literal

from rich.console import Console
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from collections.abc import Iterable

ColorMode = Literal["auto", "always", "never"]
SCHEMA_VERSION = 1


@dataclass(frozen=True)
class OutputOptions:
    """Invocation-level output controls, independent of business logic."""

    color: ColorMode = "auto"
    json: bool = False


def color_enabled(
    options: OutputOptions,
    *,
    stream: object | None = None,
    environ: dict[str, str] | None = None,
) -> bool:
    """Return whether terminal decoration is safe and requested."""
    if options.json or options.color == "never":
        return False
    if options.color == "always":
        return True
    values = os.environ if environ is None else environ
    target = sys.stdout if stream is None else stream
    return (
        not values.get("NO_COLOR")
        and values.get("TERM") != "dumb"
        and bool(getattr(target, "isatty", lambda: False)())
    )


def console_for(options: OutputOptions, *, stream: object) -> Console:
    """Construct a Rich console with deterministic color behavior."""
    enabled = color_enabled(options, stream=stream)
    return Console(
        file=stream,  # type: ignore[arg-type]
        force_terminal=enabled,
        color_system="auto" if enabled else None,
        no_color=not enabled,
        highlight=False,
    )


def print_message(
    message: str,
    *,
    stream: object,
    options: OutputOptions,
    kind: str = "info",
) -> None:
    """Print a single semantic message while retaining plain-text compatibility."""
    styles = {"success": "green", "warning": "yellow", "error": "bold red"}
    console_for(options, stream=stream).print(Text(message, style=styles.get(kind, "")))


def compact_table(
    columns: Iterable[str],
    rows: Iterable[Iterable[object]],
    *,
    title: str | None = None,
) -> Table:
    """Create the compact table style used by human-oriented list commands."""
    table = Table(title=title, box=None, pad_edge=False, show_header=True)
    for column in columns:
        table.add_column(column, no_wrap=True)
    for row in rows:
        table.add_row(*(str(value) for value in row))
    return table


def legend(items: Iterable[tuple[str, str]]) -> Text:
    """Return a compact, presentation-independent legend primitive."""
    return Text("  ".join(f"{label}: {meaning}" for label, meaning in items))


def confirm(
    prompt: str,
    *,
    assume_yes: bool = False,
    stdin: object | None = None,
    interactive: bool = True,
) -> bool:
    """Ask a safe default-no confirmation without allowing noninteractive hangs."""
    if assume_yes:
        return True
    if not interactive:
        return False
    source = sys.stdin if stdin is None else stdin
    if not bool(getattr(source, "isatty", lambda: False)()):
        return False
    return input(f"{prompt} [y/N] ").strip().casefold() in {"y", "yes"}
