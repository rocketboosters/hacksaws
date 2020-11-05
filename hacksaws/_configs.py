import argparse
import dataclasses
import pathlib
import typing

import boto3


@dataclasses.dataclass(frozen=True)
class Context:
    """Data structure for cli executions."""

    #: Parsed command line arguments for the invocation.
    args: argparse.Namespace

    @property
    def profile(self) -> str:
        """AWS profile name associated with this command execution."""
        return self.get("profile")

    @property
    def aws_directory(self) -> pathlib.Path:
        """
        AWS credentials directory where the credentials and config file
        reside.
        """
        if name := self.get("aws_account_name"):
            value = f"~/.aws-{name}"
        else:
            value = self.get("directory") or "~/.aws"
        return pathlib.Path(value).expanduser().absolute()

    @property
    def credentials_path(self) -> pathlib.Path:
        """Path to the AWS credentials file."""
        return self.aws_directory.joinpath("credentials")

    @property
    def config_path(self) -> pathlib.Path:
        """Path to the AWS config file."""
        return self.aws_directory.joinpath("config")

    @property
    def storage_path(self) -> pathlib.Path:
        """Path where static credentials will be saved while logged in."""
        return self.aws_directory.joinpath(f"{self.profile}.store.credentials")

    def get(self, key: str, default_value: typing.Any = None) -> typing.Any:
        """Retrieves the value from the args object."""
        return getattr(self.args, key, default_value)


@dataclasses.dataclass(frozen=True)
class AwsAccount:
    """Data structure representing basic account ID information."""

    #: Response object returned from an sts.get_caller_identity request.
    identity_response: dict
    region_name: str

    @property
    def id(self) -> str:
        return self.identity_response.get("Account")

    @property
    def user_arn(self) -> str:
        return self.identity_response.get("Arn")

    @property
    def user_id(self) -> str:
        return self.identity_response.get("UserId")

    @property
    def ecr_registry(self) -> str:
        return f"{self.id}.dkr.ecr.{self.region_name}.amazonaws.com"

    @classmethod
    def from_context(cls, context: "Context") -> "AwsAccount":
        session = boto3.Session(profile_name=context.profile)
        return cls(
            identity_response=session.client("sts").get_caller_identity(),
            region_name=session.region_name or "us-east-1",
        )


@dataclasses.dataclass(frozen=True)
class Result:
    """Data structure containing the result of a command execution."""

    code: str
    message: str

    def echo(self) -> "Result":
        print(f"\n{self.message}\n")
        return self
