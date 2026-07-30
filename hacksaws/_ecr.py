"""Container-engine authentication operations for Amazon ECR."""

from __future__ import annotations

import base64
import binascii
import subprocess
from datetime import UTC
from datetime import datetime
from typing import cast

import boto3
from botocore.exceptions import BotoCoreError
from botocore.exceptions import ClientError

from hacksaws import _configs


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
) -> None:
    """Log the selected container engine into one region-specific ECR registry."""
    registry = f"{account_id}.dkr.ecr.{region_name}.amazonaws.com"
    print(f"[STARTED]: Logging into {registry}", flush=True)  # noqa: T201
    try:
        session = boto3.Session(
            profile_name=context.profile,
            region_name=region_name,
        )
        response = session.client("ecr").get_authorization_token(
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


def login(context: _configs.Context, aws_account: _configs.AwsAccount) -> None:
    """Log the selected container engine into every configured ECR region."""
    for region_name in aws_account.ecr_regions:
        _do_login(
            context,
            account_id=aws_account.id,
            region_name=region_name,
        )


def logout(
    context: _configs.Context,
    aws_account: _configs.AwsAccount,
    *,
    check: bool = True,
) -> None:
    """Log the selected container engine out of every configured ECR registry."""
    engine = context.container_engine
    for registry in aws_account.ecr_registries:
        _run_container_engine(
            engine,
            [engine, "logout", registry],
            check=check,
        )
