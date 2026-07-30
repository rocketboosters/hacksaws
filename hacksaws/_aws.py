"""AWS credential login and logout operations."""

from __future__ import annotations

import configparser
from typing import TYPE_CHECKING
from typing import cast

import boto3
from botocore.exceptions import BotoCoreError
from botocore.exceptions import ClientError

from hacksaws import _configs

if TYPE_CHECKING:
    from pathlib import Path


def _read_config(path: Path, *, description: str) -> configparser.ConfigParser:
    """Read an INI file or raise a concise operational error."""
    parser = configparser.ConfigParser()
    try:
        loaded = parser.read(path)
    except (configparser.Error, OSError) as error:
        message = f"Unable to parse {description} file {path}: {error}"
        raise _configs.OperationalError(message) from error
    if not loaded:
        message = f"{description} file does not exist: {path}"
        raise _configs.OperationalError(message)
    return parser


def _write_config(
    path: Path,
    parser: configparser.ConfigParser,
    *,
    description: str,
) -> None:
    """Write an INI file or raise a concise operational error."""
    try:
        with path.open("w", encoding="utf-8") as stream:
            parser.write(stream)
    except OSError as error:
        message = f"Unable to write {description} file {path}: {error}"
        raise _configs.OperationalError(message) from error


def _profile_section(
    parser: configparser.ConfigParser,
    profile: str,
    *,
    description: str,
) -> configparser.SectionProxy:
    """Return a required profile section."""
    if profile not in parser:
        message = f"Profile {profile!r} is missing from the {description} file."
        raise _configs.OperationalError(message)
    return parser[profile]


def logout(context: _configs.Context) -> None:
    """Restore static credentials when a temporary login is active."""
    if not context.storage_path.exists():
        return

    credentials = _read_config(
        context.credentials_path,
        description="credentials",
    )
    storage = _read_config(context.storage_path, description="credential backup")
    credentials[context.profile] = _profile_section(
        storage,
        context.profile,
        description="credential backup",
    )
    _write_config(
        context.credentials_path,
        credentials,
        description="credentials",
    )
    try:
        context.storage_path.unlink()
    except OSError as error:
        message = f"Unable to remove credential backup {context.storage_path}: {error}"
        raise _configs.OperationalError(message) from error


def login(context: _configs.Context) -> None:
    """Exchange static credentials for an MFA-authenticated session."""
    configs = _read_config(context.config_path, description="AWS config")
    profile_configs = _profile_section(
        configs,
        f"profile {context.profile}",
        description="AWS config",
    )
    if "mfa_serial" not in profile_configs:
        message = f"Profile {context.profile!r} does not define mfa_serial."
        raise _configs.OperationalError(message)

    try:
        session = boto3.Session(profile_name=context.profile)
        response = session.client("sts").get_session_token(
            DurationSeconds=cast("int", context.args.lifespan),
            SerialNumber=profile_configs["mfa_serial"],
            TokenCode=cast("str", context.args.mfa_code),
        )
    except (BotoCoreError, ClientError) as error:
        message = f"Unable to start MFA session for {context.profile!r}: {error}"
        raise _configs.OperationalError(message) from error

    credentials = _read_config(
        context.credentials_path,
        description="credentials",
    )
    static_credentials = _profile_section(
        credentials,
        context.profile,
        description="credentials",
    )
    storage = configparser.ConfigParser()
    storage[context.profile] = static_credentials
    _write_config(
        context.storage_path,
        storage,
        description="credential backup",
    )

    temporary_credentials = response["Credentials"]
    credentials[context.profile] = {
        "aws_access_key_id": temporary_credentials["AccessKeyId"],
        "aws_secret_access_key": temporary_credentials["SecretAccessKey"],
        "aws_session_token": temporary_credentials["SessionToken"],
    }
    _write_config(
        context.credentials_path,
        credentials,
        description="credentials",
    )
