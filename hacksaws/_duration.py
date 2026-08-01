"""Exact duration parsing shared by sessions and the policy cache."""

from __future__ import annotations

import re
from decimal import ROUND_HALF_UP
from decimal import Decimal
from decimal import InvalidOperation

from hacksaws._configs import OperationalError

_DURATION = re.compile(r"^((?:[0-9]+(?:\.[0-9]+)?)|(?:\.[0-9]+))\s*([A-Za-z]+)$")
_UNITS = {
    "s": 1,
    "sec": 1,
    "second": 1,
    "seconds": 1,
    "m": 60,
    "min": 60,
    "minute": 60,
    "minutes": 60,
    "h": 3600,
    "hr": 3600,
    "hour": 3600,
    "hours": 3600,
}


def parse_duration(value: str, *, allow_zero: bool = False) -> int:
    """Parse one decimal duration and return conventional whole seconds."""
    match = _DURATION.fullmatch(value.strip())
    if not match:
        raise OperationalError(
            "Duration must be one positive decimal followed by a second, minute, "
            "or hour unit (for example 90m or 1.5hours)."
        )
    unit = match.group(2).lower()
    if unit not in _UNITS:
        raise OperationalError(f"Unsupported duration unit {match.group(2)!r}.")
    try:
        seconds = (Decimal(match.group(1)) * _UNITS[unit]).quantize(
            Decimal(1), rounding=ROUND_HALF_UP
        )
    except InvalidOperation as error:
        raise OperationalError(f"Invalid duration {value!r}.") from error
    result = int(seconds)
    if result < 0 or (result == 0 and not allow_zero):
        qualifier = "non-negative" if allow_zero else "positive"
        raise OperationalError(f"Duration must round to a {qualifier} whole second.")
    return result


def parse_count(value: str, multiplier: int) -> int:
    """Convert a decimal count for --htl/--mtl/--stl to seconds."""
    try:
        number = Decimal(value)
    except InvalidOperation as error:
        raise OperationalError(f"Invalid duration count {value!r}.") from error
    if not number.is_finite() or number <= 0:
        raise OperationalError("Duration count must be a positive decimal.")
    result = int((number * multiplier).quantize(Decimal(1), rounding=ROUND_HALF_UP))
    if result <= 0:
        raise OperationalError("Duration must round to a positive whole second.")
    return result


def session_duration(
    *,
    duration: str | None = None,
    htl: str | None = None,
    mtl: str | None = None,
    stl: str | None = None,
    default: int = 3600,
) -> int:
    """Resolve mutually-exclusive CLI duration forms."""
    values = [value is not None for value in (duration, htl, mtl, stl)]
    if sum(values) > 1:
        raise OperationalError(
            "Only one of --duration/--ttl, --htl, --mtl, and --stl may be used."
        )
    if duration is not None:
        return parse_duration(duration)
    if htl is not None:
        return parse_count(htl, 3600)
    if mtl is not None:
        return parse_count(mtl, 60)
    if stl is not None:
        return parse_count(stl, 1)
    return default
