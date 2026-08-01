"""Configuration and result models used by the Hacksaws CLI."""

from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING
from typing import Literal
from typing import cast

import boto3
from botocore.exceptions import BotoCoreError
from botocore.exceptions import ClientError

from hacksaws import _output

if TYPE_CHECKING:
    import argparse
    from collections.abc import Mapping

ContainerEngine = Literal["docker", "podman"]
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_POLICY = 3
EXIT_CANCELLED = 4
EXIT_INTERRUPTED = 130

_output_options = [_output.OutputOptions()]


def configure_output(
    *, color: _output.ColorMode = "auto", json_output: bool = False
) -> None:
    """Set invocation output behavior after global CLI options are normalized."""
    _output_options[0] = _output.OutputOptions(color=color, json=json_output)


class OperationalError(Exception):
    """An expected operational failure that is safe to show without a traceback."""

    def __init__(
        self,
        message: str,
        *,
        data: object | None = None,
        details: object | None = None,
        repairs: object | None = None,
    ) -> None:
        super().__init__(message)
        self.data = data
        self.details = details
        self.repairs = repairs


@dataclasses.dataclass(frozen=True)
class Context:
    """Inputs and derived file locations for a CLI invocation."""

    args: argparse.Namespace

    @property
    def profile(self) -> str:
        """Return the AWS profile name for this invocation."""
        value = cast("str | None", getattr(self.args, "profile", None))
        return "default" if value in {None, ".", "default"} else value

    @property
    def container_engine(self) -> ContainerEngine:
        """Return the container engine selected for ECR authentication."""
        return (
            "podman" if cast("bool", getattr(self.args, "podman", False)) else "docker"
        )

    @property
    def aws_directory(self) -> Path:
        """Return the directory containing AWS configuration and credentials."""
        account_name = cast("str | None", getattr(self.args, "aws_account_name", None))
        configured_directory = cast("str", getattr(self.args, "directory", "~/.aws"))
        value = (
            "~/.aws"
            if account_name in {".", "default"}
            else f"~/.aws-{account_name}"
            if account_name
            else configured_directory
        )
        return Path(value).expanduser().absolute()

    @property
    def credentials_path(self) -> Path:
        """Return the AWS shared credentials file path."""
        return self.aws_directory / "credentials"

    @property
    def config_path(self) -> Path:
        """Return the AWS config file path."""
        return self.aws_directory / "config"

    @property
    def storage_path(self) -> Path:
        """Return the backup path used while temporary credentials are active."""
        return self.aws_directory / f"{self.profile}.store.credentials"


@dataclasses.dataclass(frozen=True)
class CredentialSelector:
    """Resolved local credential source; resolution never performs a login."""

    profile: str = "default"
    location: str = "default"
    directory: Path | None = None
    target: str | None = None


def resolve_credential_selector(args: argparse.Namespace) -> CredentialSelector:
    """Normalize credential selection without AWS side effects."""
    profile = cast("str", getattr(args, "profile", None) or "default")
    location = cast("str", getattr(args, "location", None) or "default")
    directory_value = cast("str | None", getattr(args, "directory", None))
    return CredentialSelector(
        profile=profile,
        location=location,
        directory=(
            Path(directory_value).expanduser().absolute() if directory_value else None
        ),
        target=cast("str | None", getattr(args, "target", None)),
    )


@dataclasses.dataclass(frozen=True)
class AwsAccount:
    """AWS account identity and ECR region configuration."""

    identity_response: Mapping[str, object]
    region_name: str
    ecr_additional_regions: tuple[str, ...]

    @property
    def id(self) -> str:
        """Return the AWS account ID."""
        account_id = self.identity_response.get("Account")
        if not isinstance(account_id, str) or not account_id:
            message = "AWS did not return an account ID."
            raise OperationalError(message)
        return account_id

    @property
    def user_arn(self) -> str | None:
        """Return the current AWS principal ARN, when supplied."""
        value = self.identity_response.get("Arn")
        return value if isinstance(value, str) else None

    @property
    def user_id(self) -> str | None:
        """Return the current AWS principal ID, when supplied."""
        value = self.identity_response.get("UserId")
        return value if isinstance(value, str) else None

    @property
    def partition(self) -> str:
        """Return the caller partition, defaulting to commercial for legacy data."""
        arn = self.user_arn
        if arn:
            try:
                partition = arn.split(":", 2)[1]
            except IndexError:
                partition = ""
            if partition in {"aws", "aws-us-gov", "aws-cn"}:
                return partition
        return "aws"

    @property
    def dns_suffix(self) -> str:
        """Return the AWS DNS suffix for this partition."""
        return "amazonaws.com.cn" if self.partition == "aws-cn" else "amazonaws.com"

    @property
    def ecr_regions(self) -> tuple[str, ...]:
        """Return ECR regions in stable, primary-first order without duplicates."""
        return tuple(
            dict.fromkeys((self.region_name, *self.ecr_additional_regions)),
        )

    @property
    def ecr_registries(self) -> list[str]:
        """Return registry hostnames for all configured ECR regions."""
        return [
            f"{self.id}.dkr.ecr.{region}.{self.dns_suffix}"
            for region in self.ecr_regions
        ]

    @classmethod
    def from_context(cls, context: Context) -> AwsAccount:
        """Load account identity and region data from an AWS profile."""
        try:
            session = boto3.Session(profile_name=context.profile)
            identity = session.client("sts").get_caller_identity()
        except (BotoCoreError, ClientError) as error:
            message = f"Unable to load AWS profile {context.profile!r}: {error}"
            raise OperationalError(message) from error

        additional_regions = cast("list[str] | None", context.args.ecr_region)
        return cls(
            identity_response=identity,
            region_name=session.region_name or "us-east-1",
            ecr_additional_regions=tuple(additional_regions or ()),
        )


@dataclasses.dataclass(frozen=True)
class Result:
    """Outcome of a command execution."""

    code: str
    message: str
    exit_code: int = 0
    stream: Literal["stdout", "stderr"] = "stdout"
    data: object | None = None
    details: object | None = None
    repairs: object | None = None
    kind: Literal["info", "success", "warning", "error"] | None = None

    def echo(self) -> Result:
        """Write the result message to its intended output stream."""
        output = sys.stderr if self.stream == "stderr" else sys.stdout
        if _output_options[0].json:
            envelope: dict[str, object] = {
                "schemaVersion": _output.SCHEMA_VERSION,
                "ok": self.exit_code == EXIT_OK,
                "code": self.code,
            }
            if self.exit_code == EXIT_OK:
                envelope["data"] = (
                    self.data if self.data is not None else {"message": self.message}
                )
            else:
                envelope["error"] = {
                    "message": self.message,
                    "exitCode": self.exit_code,
                    "data": self.data if self.data is not None else {},
                    "details": self.details if self.details is not None else [],
                    "repairs": self.repairs if self.repairs is not None else [],
                }
            print(json.dumps(envelope, indent=2, default=str), file=output)
        elif self.message:
            kind = self.kind or ("error" if self.stream == "stderr" else "success")
            _output.print_message(
                self.message, stream=output, options=_output_options[0], kind=kind
            )
        return self


def json_output_enabled() -> bool:
    """Return whether the current invocation requires one machine envelope."""
    return _output_options[0].json
