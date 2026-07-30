"""Command-line parsing and orchestration."""

from __future__ import annotations

import argparse
import os
from typing import TYPE_CHECKING
from typing import cast

from hacksaws import _aws
from hacksaws import _configs
from hacksaws import _ecr

if TYPE_CHECKING:
    from collections.abc import Sequence


def _create_parser() -> argparse.ArgumentParser:
    """Create the Hacksaws argument parser."""
    parser = argparse.ArgumentParser(
        prog="hacksaws",
        description="CLI for dynamic credential login management in AWS.",
        allow_abbrev=False,
    )
    type_subparsers = parser.add_subparsers(dest="access_type")

    mfa_type_parser = type_subparsers.add_parser("mfa")
    subparsers = mfa_type_parser.add_subparsers(dest="action")

    login_parser = subparsers.add_parser("login", aliases=["in"])
    login_parser.add_argument("profile")
    login_parser.add_argument("mfa_code")
    login_parser.add_argument("-l", "--lifespan", type=int, default=43200)

    logout_parser = subparsers.add_parser("logout", aliases=["out"])
    logout_parser.add_argument("profile")

    for action_parser in (login_parser, logout_parser):
        action_parser.add_argument("--ecr", action="store_true")
        action_parser.add_argument("--ecr-region", action="append")
        action_parser.add_argument(
            "-d",
            "--dir",
            "--directory",
            dest="directory",
            default="~/.aws",
        )
        action_parser.add_argument(
            "-n",
            "--name",
            "--account-name",
            dest="aws_account_name",
        )

    return parser


def _print_help(command: Sequence[str] = ()) -> None:
    """Print command help without exiting the program."""
    try:
        _create_parser().parse_args([*command, "--help"])
    except SystemExit:
        return


def _run_mfa(context: _configs.Context) -> _configs.Result:
    """Execute an MFA login or logout action."""
    action = cast("str | None", context.args.action)
    if not action:
        _print_help(("mfa",))
        return _configs.Result(
            code="MFA_HELP",
            message="Not enough arguments specified for the mfa command.",
            exit_code=2,
            stream="stderr",
        )

    os.environ["AWS_SHARED_CREDENTIALS_FILE"] = str(context.credentials_path)
    os.environ["AWS_CONFIG_FILE"] = str(context.config_path)

    _aws.logout(context)
    aws_account = _configs.AwsAccount.from_context(context)

    if cast("bool", context.args.ecr):
        _ecr.logout(aws_account)

    if action in {"login", "in"}:
        _aws.login(context)
        if cast("bool", context.args.ecr):
            _ecr.login(context, aws_account)
        return _configs.Result(
            code="MFA_LOGIN",
            message=f"Logged into profile {context.profile}",
        )

    return _configs.Result(
        code="MFA_LOGOUT",
        message=f"Logged out of profile {context.profile}",
    )


def console_main(arguments: Sequence[str] | None = None) -> _configs.Result:
    """Run a command-line invocation and return its structured result."""
    parser = _create_parser()
    try:
        namespace = parser.parse_args(arguments)
    except SystemExit as error:
        exit_code = cast("int", error.code)
        code = "HELP" if exit_code == 0 else "ARGUMENT_ERROR"
        return _configs.Result(code=code, message="", exit_code=exit_code)

    if not namespace.access_type:
        _print_help()
        return _configs.Result(
            code="ACCESS_TYPE_HELP",
            message="Not enough arguments.",
            exit_code=2,
            stream="stderr",
        ).echo()

    try:
        result = _run_mfa(_configs.Context(args=namespace))
    except _configs.OperationalError as error:
        return _configs.Result(
            code="OPERATIONAL_ERROR",
            message=f"Error: {error}",
            exit_code=1,
            stream="stderr",
        ).echo()
    return result.echo()
