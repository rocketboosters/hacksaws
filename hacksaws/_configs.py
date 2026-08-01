"""Configuration and result models used by the Hacksaws CLI."""

from __future__ import annotations

import dataclasses
import sys
from pathlib import Path
from typing import TYPE_CHECKING
from typing import Literal
from typing import cast

import boto3
from botocore.exceptions import BotoCoreError
from botocore.exceptions import ClientError

if TYPE_CHECKING:
    import argparse
    from collections.abc import Mapping

ContainerEngine = Literal["docker", "podman"]


class OperationalError(Exception):
    """An expected operational failure that is safe to show without a traceback."""


@dataclasses.dataclass(frozen=True)
class Context:
    """Inputs and derived file locations for a CLI invocation."""

    args: argparse.Namespace

    @property
    def profile(self) -> str:
        """Return the AWS profile name for this invocation."""
        return cast("str", getattr(self.args, "profile", None) or "default")

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
        value = f"~/.aws-{account_name}" if account_name else configured_directory
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

    def echo(self) -> Result:
        """Write the result message to its intended output stream."""
        if self.message:
            output = sys.stderr if self.stream == "stderr" else sys.stdout
            print(self.message, file=output)
        return self
