"""Dependency-free semantic audit context shared by CLI confirmation helpers."""

from __future__ import annotations

from contextvars import ContextVar
from typing import Literal

ConfirmationMechanism = Literal["exact-yes", "yes-no", "resource-name", "yes-flag"]
ConfirmationOutcome = Literal["accepted", "declined", "bypassed", "unavailable"]

_confirmation: ContextVar[str] = ContextVar(
    "hacksaws_audit_confirmation", default="not-requested"
)


def reset_confirmation() -> None:
    """Reset confirmation state at the start or end of an invocation."""
    _confirmation.set("not-requested")


def note_confirmation(
    mechanism: ConfirmationMechanism, outcome: ConfirmationOutcome
) -> None:
    """Retain only a semantic confirmation classification, never entered text."""
    _confirmation.set(f"{mechanism}:{outcome}")


def confirmation() -> str:
    """Return the current invocation's semantic confirmation state."""
    return _confirmation.get()
