"""Container-engine authentication operations for Amazon ECR."""

from __future__ import annotations

import base64
import binascii
import subprocess
import sys
from datetime import UTC
from datetime import datetime
from typing import TYPE_CHECKING
from typing import Any
from typing import cast

import boto3
from botocore.exceptions import BotoCoreError
from botocore.exceptions import ClientError

from hacksaws import _configs
from hacksaws import _regions
from hacksaws import _state

if TYPE_CHECKING:
    from collections.abc import Callable


def _configured_region_aliases() -> dict[str, object]:
    """Return user region aliases without exposing unrelated configuration."""
    data = _state.load_config()
    aws = data.get("aws")
    if not isinstance(aws, dict):
        return {}
    aliases = aws.get("region_aliases")
    return cast("dict[str, object]", aliases) if isinstance(aliases, dict) else {}


def _ecr_regions(
    context: _configs.Context,
    aws_account: _configs.AwsAccount,
) -> tuple[str, ...]:
    """Canonicalize, partition-check, service-check, and dedupe ECR regions."""
    args = getattr(context, "args", None)
    allow_unknown = getattr(args, "allow_unknown_region", False) is True
    preference = getattr(args, "_region_preference", None)
    preferred = (
        preference.canonical
        if isinstance(preference, _regions.RegionPreference)
        else None
    )
    effective = getattr(args, "_effective_region", None)
    explicit = getattr(args, "region", None)
    primary = next(
        (
            value
            for value in (preferred, effective, explicit, aws_account.region_name)
            if isinstance(value, str) and value
        ),
        aws_account.region_name,
    )
    resolutions = _regions.canonicalize_regions(
        (primary, *aws_account.ecr_additional_regions),
        custom_aliases=_configured_region_aliases(),
        partition=aws_account.partition,
        allow_unknown=allow_unknown,
        service="ecr",
    )
    for resolution in resolutions:
        if resolution.warning:
            print(f"Warning: {resolution.warning}", file=sys.stderr)  # noqa: T201
    return tuple(item.canonical for item in resolutions)


def _run_container_engine(
    engine: _configs.ContainerEngine,
    command: list[str],
    *,
    password: bytes | None = None,
    check: bool = True,
) -> None:
    """Run a container-engine command and normalize expected execution failures."""
    executable_name = engine.title()
    try:
        subprocess.run(command, input=password, check=check)  # noqa: S603
    except FileNotFoundError as error:
        message = f"{executable_name} is not installed or is not available on PATH."
        raise _configs.OperationalError(message) from error
    except OSError as error:
        message = f"Unable to run {executable_name}: {error}"
        raise _configs.OperationalError(message) from error
    except subprocess.CalledProcessError as error:
        message = f"{executable_name} command failed with exit code {error.returncode}."
        raise _configs.OperationalError(message) from error


def _do_login(
    context: _configs.Context,
    *,
    account_id: str,
    region_name: str,
    dns_suffix: str = "amazonaws.com",
    session: Any | None = None,
) -> str:
    """Log the selected container engine into one region-specific ECR registry."""
    registry = f"{account_id}.dkr.ecr.{region_name}.{dns_suffix}"
    print(f"[STARTED]: Logging into {registry}", flush=True)  # noqa: T201
    try:
        aws_session = session or boto3.Session(
            profile_name=context.profile,
            region_name=region_name,
        )
        client = (
            aws_session.client("ecr", region_name=region_name)
            if session is not None
            else aws_session.client("ecr")
        )
        response = client.get_authorization_token(
            registryIds=[account_id],
        )
        authorization_data = response["authorizationData"][0]
        decoded_token = base64.b64decode(
            authorization_data["authorizationToken"],
            validate=True,
        ).decode()
        user, password = decoded_token.split(":", maxsplit=1)
        expires_at = cast("datetime", authorization_data["expiresAt"])
    except (BotoCoreError, ClientError) as error:
        message = f"Unable to get an ECR token for {region_name}: {error}"
        raise _configs.OperationalError(message) from error
    except (
        binascii.Error,
        IndexError,
        KeyError,
        UnicodeDecodeError,
        ValueError,
    ) as error:
        message = f"AWS returned an invalid ECR token for {region_name}."
        raise _configs.OperationalError(message) from error

    engine = context.container_engine
    _run_container_engine(
        engine,
        [
            engine,
            "login",
            f"--username={user}",
            "--password-stdin",
            registry,
        ],
        password=password.encode(),
    )

    expires_at_utc = expires_at.astimezone(UTC)
    hours = round((expires_at_utc - datetime.now(UTC)).total_seconds() / 3600)
    print(  # noqa: T201
        f"[SUCCESS]: Login session will expire in {hours} hours",
        flush=True,
    )
    return registry


def login(context: _configs.Context, aws_account: _configs.AwsAccount) -> list[str]:
    """Log the selected container engine into every configured ECR region."""
    return [
        _do_login(
            context,
            account_id=aws_account.id,
            region_name=region_name,
            dns_suffix=aws_account.dns_suffix,
        )
        for region_name in _ecr_regions(context, aws_account)
    ]


def login_with_session(
    context: _configs.Context,
    aws_account: _configs.AwsAccount,
    session: Any,
    *,
    on_success: Callable[[str], None] | None = None,
) -> list[str]:
    """Install ECR tokens using broad intermediate credentials."""
    completed: list[str] = []
    for region_name in _ecr_regions(context, aws_account):
        registry = _do_login(
            context,
            account_id=aws_account.id,
            region_name=region_name,
            dns_suffix=aws_account.dns_suffix,
            session=session,
        )
        completed.append(registry)
        if on_success:
            on_success(registry)
    return completed


def logout(
    context: _configs.Context,
    aws_account: _configs.AwsAccount,
    *,
    check: bool = True,
) -> None:
    """Log the selected container engine out of every configured ECR registry."""
    engine = context.container_engine
    for region_name in _ecr_regions(context, aws_account):
        registry = f"{aws_account.id}.dkr.ecr.{region_name}.{aws_account.dns_suffix}"
        _run_container_engine(
            engine,
            [engine, "logout", registry],
            check=check,
        )
