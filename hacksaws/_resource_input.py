"""Deterministic NAME/file disambiguation shared by IAM mutation commands."""

# ruff: noqa: C901, PLR0913, PLR2004, TRY003

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from hacksaws._configs import OperationalError

if TYPE_CHECKING:
    from collections.abc import Sequence

_PATHLIKE = re.compile(r"^(?:[A-Za-z]:[\\/]|[.~][\\/]|[\\/])")
_DOCUMENT_EXTENSIONS = {".json", ".yaml", ".yml", ".toml"}


@dataclass(frozen=True, slots=True)
class NameFileInput:
    """One resolved resource name and local document input."""

    name: str | None
    file: Path | None


@dataclass(frozen=True, slots=True)
class ReferenceFileInput:
    """Exactly one remote reference or local document input."""

    reference: str | None
    file: Path | None


def looks_like_file(value: str) -> bool:
    """Return whether syntax or local state identifies a document path."""
    expanded = Path(value).expanduser()
    return (
        value == "-"
        or bool(_PATHLIKE.match(value))
        or "/" in value
        or "\\" in value
        or expanded.suffix.casefold() in _DOCUMENT_EXTENSIONS
        or expanded.is_file()
    )


def resolve_name_file(
    positional: Sequence[str],
    *,
    explicit_name: str | None = None,
    explicit_file: str | Path | None = None,
    require_name: bool = True,
    require_file: bool = True,
    name_label: str = "NAME",
    file_label: str = "FILE",
    name_option: str = "--name",
    file_option: str = "--file",
) -> NameFileInput:
    """Resolve up to two order-independent positional values before AWS access."""
    values = list(positional)
    if len(values) > 2:
        raise OperationalError(
            f"Expected at most {name_label} and {file_label}; use {name_option} "
            f"and {file_option} to make the intended values explicit."
        )
    name = explicit_name
    file = Path(explicit_file).expanduser() if explicit_file is not None else None
    if name is not None and file is not None and values:
        raise OperationalError(
            f"{name_label} and {file_label} were already supplied by flags; remove "
            "the extra positional value."
        )
    if len(values) == 2:
        if name is not None or file is not None:
            raise OperationalError(
                f"Two positional values cannot be combined with {name_option} or "
                f"{file_option}."
            )
        first_file = looks_like_file(values[0])
        second_file = looks_like_file(values[1])
        if first_file == second_file:
            raise OperationalError(
                f"Unable to distinguish {name_label} from {file_label}; use "
                f"{name_option} {name_label} {file_option} {file_label}."
            )
        name = values[1] if first_file else values[0]
        file = Path(values[0] if first_file else values[1]).expanduser()
    elif values:
        value = values[0]
        if name is not None:
            file = Path(value).expanduser()
        elif file is not None:
            name = value
        elif looks_like_file(value):
            file = Path(value).expanduser()
        else:
            name = value
    if require_name and name is None:
        raise OperationalError(
            f"Missing {name_label}; provide it positionally or with {name_option}."
        )
    if require_file and file is None:
        raise OperationalError(
            f"Missing {file_label}; provide a path positionally or with {file_option}."
        )
    return NameFileInput(name=name, file=file)


def resolve_reference_or_file(
    positional: Sequence[str],
    *,
    explicit_reference: str | None = None,
    explicit_file: str | Path | None = None,
    reference_label: str = "POLICY",
    reference_option: str = "--policy",
    file_option: str = "--file",
) -> ReferenceFileInput:
    """Resolve one remote reference or local file with explicit conflict checks."""
    values = list(positional)
    supplied = (
        len(values)
        + int(explicit_reference is not None)
        + int(explicit_file is not None)
    )
    if supplied != 1:
        raise OperationalError(
            f"Specify exactly one {reference_label} reference or policy file; use "
            f"{reference_option} {reference_label} or {file_option} FILE to "
            "disambiguate."
        )
    if explicit_reference is not None:
        return ReferenceFileInput(reference=explicit_reference, file=None)
    if explicit_file is not None:
        return ReferenceFileInput(reference=None, file=Path(explicit_file).expanduser())
    value = values[0]
    if looks_like_file(value):
        return ReferenceFileInput(reference=None, file=Path(value).expanduser())
    return ReferenceFileInput(reference=value, file=None)
