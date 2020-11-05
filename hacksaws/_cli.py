import argparse
import os
import typing

from hacksaws import _aws
from hacksaws import _configs
from hacksaws import _ecr


def _create_parser() -> argparse.ArgumentParser:
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

    for p in [login_parser, logout_parser]:
        p.add_argument("--ecr", action="store_true")
        p.add_argument(
            "-d",
            "--dir",
            "--directory",
            dest="directory",
            default=os.path.expanduser("~/.aws"),
        )
        p.add_argument(
            "-n",
            "--name",
            "--account-name",
            dest="aws_account_name",
        )

    return parser


def _print_help(command: typing.List[str] = None):
    """Prints command help without exiting the program."""
    try:
        _create_parser().parse_args((command or []) + ["--help"])
    except SystemExit:
        pass


def _run_mfa(context: _configs.Context) -> _configs.Result:
    """Executes an action for an mfa access type."""
    action = context.args.action
    if not action:
        _print_help(["mfa"])
        return _configs.Result(
            code="MFA_HELP",
            message="Not enough arguments specified for the mfa command.",
        )

    # Configure the session credential file locations based on CLI input.
    os.environ["AWS_SHARED_CREDENTIALS_FILE"] = str(context.credentials_path)
    os.environ["AWS_CONFIG_FILE"] = str(context.config_path)

    # Log out first no matter what action is taking place.
    _aws.logout(context)

    # Get account data
    aws_account = _configs.AwsAccount.from_context(context)

    if context.args.ecr:
        _ecr.logout(aws_account)

    if action in ("login", "in"):
        _aws.login(context)
        if context.args.ecr:
            _ecr.login(context, aws_account)

        return _configs.Result(
            code="MFA_LOGIN",
            message=f"Logged into profile {context.profile}",
        )

    if action in ("logout", "out"):
        return _configs.Result(
            code="MFA_LOGOUT",
            message=f"Logged out of profile {context.profile}",
        )


def console_main(arguments: typing.List[str] = None) -> _configs.Result:
    """Entrypoint for command line invocations."""
    try:
        parser = _create_parser()
        context = _configs.Context(args=parser.parse_args(arguments))
    except SystemExit:
        return _configs.Result("HELP", "Displayed command help.")

    access_type = context.args.access_type
    if not access_type:
        _print_help()
        result = _configs.Result(
            code="ACCESS_TYPE_HELP",
            message="Not enough arguments.",
        )
    else:
        result = _run_mfa(context)

    return result.echo()


# if __name__ == '__main__':
#     console_main(['mfa', 'login', '--name=scout', 'billing-ro', '123456'])
