"""Pure normalization helpers for AWS environment values."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping


def normalize_aws_value(name: str, value: str | None) -> str | None:
    """Treat blank AWS values as absent while preserving every other value."""
    if name.startswith("AWS_") and (value is None or not value.strip()):
        return None
    return value


def aws_environment_value(
    name: str, environ: Mapping[str, str] | None = None
) -> str | None:
    """Read one environment value through the AWS blank-value contract."""
    values = os.environ if environ is None else environ
    return normalize_aws_value(name, values.get(name))


def normalized_aws_environment(environ: Mapping[str, str]) -> dict[str, str]:
    """Copy an environment, omitting only blank AWS-prefixed entries."""
    return {
        name: value
        for name, value in environ.items()
        if normalize_aws_value(name, value) is not None
    }


def blank_aws_environment_keys(environ: Mapping[str, str]) -> tuple[str, ...]:
    """Return blank AWS-prefixed keys without changing the supplied mapping."""
    return tuple(
        name
        for name, value in environ.items()
        if name.startswith("AWS_") and normalize_aws_value(name, value) is None
    )
