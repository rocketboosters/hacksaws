"""Terminal and machine-output primitives for the Hacksaws command line."""

from __future__ import annotations

import os
import re
import sys
import threading
import time
import unicodedata
from dataclasses import dataclass
from typing import TYPE_CHECKING
from typing import Literal
from typing import Self
from typing import TextIO

from rich.console import Console
from rich.status import Status
from rich.table import Table
from rich.text import Text

from hacksaws import _audit

if TYPE_CHECKING:
    from collections.abc import Iterable

ColorMode = Literal["auto", "always", "never"]
ProgressMode = Literal["auto", "always", "never"]
SCHEMA_VERSION = 1

_TERMINAL_STRING_CONTROL = re.compile(
    r"(?:\x1b\]|\x9d).*?(?:\x07|\x1b\\|\x9c|$)|"
    r"(?:\x1b[P_^X]|[\x90\x98\x9e\x9f]).*?(?:\x1b\\|\x9c|$)",
    re.DOTALL,
)


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


def safe_terminal_text(value: object) -> str:
    """Return printable single-line text with terminal controls removed."""
    decoded = Text.from_ansi(_TERMINAL_STRING_CONTROL.sub("", str(value))).plain
    safe = []
    for character in decoded:
        if character in "\r\n\t":
            safe.append(" ")
        elif unicodedata.category(character) not in {"Cc", "Cf", "Cs"}:
            safe.append(character)
    return "".join(safe)


class ProgressReporter:
    """Render delayed human progress without contaminating command stdout."""

    def __init__(
        self,
        options: OutputOptions,
        *,
        mode: ProgressMode = "auto",
        stream: TextIO | None = None,
        delay: float = 0.4,
    ) -> None:
        self.options = options
        self.mode = mode
        self.stream = sys.stderr if stream is None else stream
        self.delay = delay
        self._tty = bool(getattr(self.stream, "isatty", lambda: False)())
        self._enabled = (
            not options.json and mode != "never" and (mode == "always" or self._tty)
        )
        self._rich = (
            self._enabled and self._tty and color_enabled(options, stream=self.stream)
        )
        self._message = "Working…"
        self._last_plain_message: str | None = None
        self._started_at = 0.0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._status: Status | None = None
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        """Return whether this invocation may emit progress."""
        return self._enabled

    @property
    def message(self) -> str:
        """Return the latest sanitized phase for cancellation diagnostics."""
        with self._lock:
            return self._message

    def start(self, message: object) -> ProgressReporter:
        """Start delayed progress rendering and retain the latest semantic phase."""
        self._message = safe_terminal_text(message)
        if not self._enabled or self._thread is not None:
            return self
        self._started_at = time.monotonic()
        self._thread = threading.Thread(
            target=self._run,
            name="hacksaws-progress",
            daemon=True,
        )
        self._thread.start()
        return self

    def update(self, message: object) -> None:
        """Replace the current semantic phase and emit one plain milestone."""
        rendered = safe_terminal_text(message)
        with self._lock:
            self._message = rendered
            visible = self._stop.wait(0) is False and (
                time.monotonic() - self._started_at >= self.delay
            )
            status = self._status
        if not self._enabled or not visible:
            return
        if self._rich and status is not None:
            status.update(self._rich_message())
        elif not self._rich:
            self._print_plain(rendered)

    def _rich_message(self) -> Text:
        with self._lock:
            message = self._message
        elapsed = max(0.0, time.monotonic() - self._started_at)
        return Text(f"{message}  {elapsed:.0f}s", style="cyan")

    def _print_plain(self, message: str) -> None:
        with self._lock:
            if message == self._last_plain_message:
                return
            self._last_plain_message = message
        print(message, file=self.stream, flush=True)

    def _run(self) -> None:
        if self._stop.wait(self.delay):
            return
        if self._rich:
            status = Status(
                self._rich_message(),
                console=console_for(self.options, stream=self.stream),
                spinner="dots",
            )
            with self._lock:
                self._status = status
            status.start()
            try:
                while not self._stop.wait(0.5):
                    status.update(self._rich_message())
            finally:
                status.stop()
                with self._lock:
                    self._status = None
            return
        with self._lock:
            message = self._message
        self._print_plain(message)
        self._stop.wait()

    def close(self) -> None:
        """Stop rendering and clear any live terminal status."""
        self._stop.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(1.0, self.delay + 0.1))

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_error: object) -> None:
        self.close()


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
        _audit.note_confirmation("yes-flag", "bypassed")
        return True
    if not interactive:
        _audit.note_confirmation("yes-no", "unavailable")
        return False
    source = sys.stdin if stdin is None else stdin
    if not bool(getattr(source, "isatty", lambda: False)()):
        _audit.note_confirmation("yes-no", "unavailable")
        return False
    accepted = input(f"{prompt} [y/N] ").strip().casefold() in {"y", "yes"}
    _audit.note_confirmation("yes-no", "accepted" if accepted else "declined")
    return accepted
