"""Hacksaws command-line parsing and orchestration."""

from __future__ import annotations

import argparse
import contextlib
import fnmatch
import io
import json
import os
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING
from typing import Any
from typing import cast

import boto3
from botocore.exceptions import BotoCoreError
from botocore.exceptions import ClientError

from hacksaws import _aws
from hacksaws import _configs
from hacksaws import _duration
from hacksaws import _ecr
from hacksaws import _iam_cli
from hacksaws import _output
from hacksaws import _policies
from hacksaws import _sessions
from hacksaws import _state

if TYPE_CHECKING:
    from collections.abc import Iterator
    from collections.abc import Sequence


class _HacksawsArgumentParser(argparse.ArgumentParser):
    """Propagate strict, non-abbreviating parsing through every command level."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:  # noqa: ANN401
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)


def _duration_arguments(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--duration", "--ttl", help="Boundary duration such as 15m, 1h, or 600s."
    )
    group.add_argument("--htl", help="Boundary duration as floating-point hours.")
    group.add_argument("--mtl", help="Boundary duration as floating-point minutes.")
    group.add_argument("--stl", help="Boundary duration as floating-point seconds.")


def _ecr_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--ecr",
        action="store_true",
        help="Also update tracked ECR registry login state.",
    )
    parser.add_argument(
        "--podman",
        action="store_true",
        help="Use Podman instead of Docker for ECR login/logout.",
    )
    parser.add_argument(
        "--ecr-region",
        action="append",
        help="ECR region; repeat for multiple registries.",
    )


def _login_arguments(parser: argparse.ArgumentParser, *, browser: bool = False) -> None:
    parser.add_argument(
        "profile",
        nargs="?",
        help=(
            "Source/destination AWS profile. A leading non-alphanumeric character "
            "selects a saved target; +TARGET is the documented form."
        ),
    )
    if not browser:
        parser.add_argument(
            "mfa_code", nargs="?", help="Current six-digit MFA token code."
        )
        parser.add_argument(
            "-l",
            "--lifespan",
            type=int,
            default=43200,
            help="Requested MFA session lifespan in seconds (default: 43200).",
        )
    parser.add_argument(
        "--target",
        help="Saved target supplying source, destination, and optional boundary.",
    )
    parser.add_argument(
        "-d",
        "--dir",
        "--directory",
        dest="directory",
        default="~/.aws",
        help="Source AWS directory (default: ~/.aws).",
    )
    parser.add_argument(
        "-n",
        "--name",
        "--account-name",
        dest="aws_account_name",
        help="Source location name, selecting ~/.aws-NAME.",
    )
    parser.add_argument(
        "--to",
        metavar="LOCATION:PROFILE",
        help="Write final credentials to this logical destination.",
    )
    parser.add_argument(
        "--to-directory",
        metavar="PATH",
        help="Explicit destination directory; requires --to-profile.",
    )
    parser.add_argument(
        "--to-profile",
        metavar="PROFILE",
        help="Destination profile used with --to-directory.",
    )
    parser.add_argument(
        "--boundary",
        "--as",
        dest="boundary",
        help="Saved role/session-policy boundary.",
    )
    parser.add_argument(
        "--role", help="Role name or ARN to assume after authentication."
    )
    parser.add_argument(
        "--policy",
        help="Session policy name, ARN, stored name, or local file; requires a role.",
    )
    parser.add_argument("--external-id", help="External ID supplied to AssumeRole.")
    parser.add_argument("--account", help="Configured account name or ID assertion.")
    parser.add_argument(
        "--session-name", help="Assumed-role session name shown in AWS audit records."
    )
    parser.add_argument(
        "--region", help="AWS region used for login and regional operations."
    )
    _duration_arguments(parser)
    _ecr_arguments(parser)
    if browser:
        parser.add_argument(
            "--remote",
            action="store_true",
            help="Use the AWS CLI remote-device browser flow.",
        )


def _logout_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "profile", nargs="?", default="default", help="AWS profile to clear."
    )
    parser.add_argument("--target", help="Use a saved target's destination.")
    parser.add_argument(
        "-d", "--dir", "--directory", dest="directory", default="~/.aws"
    )
    parser.add_argument("-n", "--name", "--account-name", dest="aws_account_name")
    parser.add_argument(
        "--all", action="store_true", help="Log out every managed session."
    )
    parser.add_argument(
        "--except",
        dest="except_profiles",
        action="append",
        default=[],
        metavar="PROFILE|LOCATION:PROFILE",
        help="Exclude a profile from --all; repeat as needed.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Restore a changed managed section after explicit review.",
    )
    parser.add_argument(
        "--keep-ecr",
        action="store_true",
        help="Leave Hacksaws-tracked container registry authorization installed.",
    )
    _ecr_arguments(parser)


def _credential_selector(parser: argparse.ArgumentParser) -> None:
    selector = parser.add_mutually_exclusive_group()
    selector.add_argument(
        "--profile",
        "--name",
        dest="profile",
        default="default",
        help="AWS profile used for account-scoped verification (default: default).",
    )
    selector.add_argument(
        "--target",
        help="Saved target whose source profile and AWS folder provide credentials.",
    )
    folder = parser.add_mutually_exclusive_group()
    folder.add_argument(
        "--location",
        default="default",
        help="Logical AWS folder location (default: default, meaning ~/.aws).",
    )
    folder.add_argument(
        "-d", "--directory", help="Explicit directory containing AWS config files."
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Save without contacting AWS; only available where documented.",
    )


@contextlib.contextmanager
def _selected_credential_session(args: argparse.Namespace) -> Iterator[Any]:
    """Create a Boto3 session bound to one explicit profile and AWS folder."""
    selector = _configs.resolve_credential_selector(args)
    if selector.target:
        data = _state.load_config()
        _, target = _state.get_resource(data, "target", selector.target.lstrip("+"))
        profile = str(target.get("source_profile", "default"))
        directory = (
            Path(str(target["source_directory"])).expanduser().absolute()
            if target.get("source_directory")
            else _state.aws_directory(target.get("source_location")).absolute()
        )
    else:
        profile = selector.profile
        directory = (
            selector.directory or _state.aws_directory(selector.location).absolute()
        )
    with _iam_cli.credential_environment(
        directory / "config", directory / "credentials"
    ):
        yield boto3.Session(profile_name=profile)


def _resource_parser(parent: argparse._SubParsersAction[Any], kind: str) -> None:
    purposes = {
        "account": "Manage named AWS accounts used to scope remote validation.",
        "boundary": "Manage saved role and optional session-policy boundaries.",
        "target": "Manage saved login source, destination, and boundary presets.",
    }
    parser = parent.add_parser(kind, help=purposes[kind], description=purposes[kind])
    actions = parser.add_subparsers(dest="resource_action")
    add = actions.add_parser("add")
    add.add_argument("resource_name")
    add.add_argument("--description")
    update = actions.add_parser("update")
    update.add_argument("resource_name")
    update.add_argument("--description")
    update.add_argument("--clear-description", action="store_true")
    for action in ("get", "remove"):
        item = actions.add_parser(action)
        item.add_argument("resource_name")
        item.add_argument("--json", action="store_true")
        if action == "remove":
            item.add_argument("--cascade", action="store_true")
            item.add_argument("--yes", action="store_true")
    listing = actions.add_parser("list")
    listing.add_argument("--json", action="store_true")
    rename = actions.add_parser("rename")
    rename.add_argument("resource_name")
    rename.add_argument("new_name")

    if kind == "account":
        add.add_argument("account_id")
        add.add_argument("--partition", choices=sorted(_state.PARTITIONS))
        _credential_selector(add)
        _credential_selector(update)
    elif kind == "boundary":
        add.add_argument("role")
        add.add_argument("--account", required=True)
        add.add_argument("--policy")
        add.add_argument("--external-id")
        add.add_argument("--duration")
        _credential_selector(add)
        update.add_argument("--role")
        update.add_argument("--account")
        update.add_argument("--policy")
        update.add_argument("--external-id")
        update.add_argument("--duration")
        update.add_argument("--clear-policy", action="store_true")
        update.add_argument("--clear-external-id", action="store_true")
        update.add_argument("--clear-duration", action="store_true")
        _credential_selector(update)
    elif kind == "target":
        add.add_argument("--source-account", required=True)
        add.add_argument("--source-profile", default="default")
        source = add.add_mutually_exclusive_group()
        source.add_argument("--source-location", default="default")
        source.add_argument("--source-directory")
        add.add_argument("--to")
        add.add_argument("--to-directory")
        add.add_argument("--to-profile")
        add.add_argument("--boundary")
        update.add_argument("--boundary")
        update.add_argument("--clear-boundary", action="store_true")
        update.add_argument("--source-account")
        update.add_argument("--source-profile")
        update_source = update.add_mutually_exclusive_group()
        update_source.add_argument("--source-location")
        update_source.add_argument("--source-directory")
        update.add_argument("--to")
        update.add_argument("--to-directory")
        update.add_argument("--to-profile")
        update.add_argument("--clear-destination", action="store_true")


def _create_parser() -> argparse.ArgumentParser:
    """Create the complete, non-abbreviating Hacksaws parser."""
    parser = _HacksawsArgumentParser(
        prog="hacksaws",
        description=(
            "Log in to AWS safely, constrain agent credentials, and manage the "
            "IAM resources that support those workflows."
        ),
        epilog=(
            "Global output options may appear anywhere before '--':\n"
            "  --json                 Emit one stable JSON result envelope.\n"
            "  --color MODE           Color mode: auto, always, or never.\n"
            "  --no-color             Alias for --color never.\n\n"
            "Start with 'hacksaws status', or run 'hacksaws COMMAND --help' for "
            "examples and safety details."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    types = parser.add_subparsers(dest="access_type")

    mfa = types.add_parser(
        "mfa", help="Authenticate a source profile with an MFA code."
    )
    mfa_actions = mfa.add_subparsers(dest="action")
    mfa_login = mfa_actions.add_parser("login", aliases=["in"])
    _login_arguments(mfa_login)
    mfa_logout = mfa_actions.add_parser("logout", aliases=["out"])
    _logout_arguments(mfa_logout)

    for auth_name in ("pk", "web"):
        auth = types.add_parser(
            auth_name,
            help="Authenticate through the AWS browser login provider.",
        )
        actions = auth.add_subparsers(dest="action")
        login = actions.add_parser("login", aliases=["in"])
        _login_arguments(login, browser=True)
        logout = actions.add_parser("logout", aliases=["out"])
        _logout_arguments(logout)

    logout = types.add_parser("logout", help="Remove local Hacksaws login state.")
    _logout_arguments(logout)
    status = types.add_parser("status", help="Show Hacksaws-managed login sessions.")
    status.add_argument("--profile", help="Filter by destination profile.")
    status_location = status.add_mutually_exclusive_group()
    status_location.add_argument("--location", help="Filter by logical AWS location.")
    status_location.add_argument("-d", "--directory", help="Filter by AWS directory.")
    status.add_argument(
        "--verify",
        action="store_true",
        help="Opt in to STS verification for each eligible session.",
    )
    status.add_argument("--json", action="store_true")

    profile = types.add_parser("profile", help="Inspect local AWS profiles safely.")
    profile_actions = profile.add_subparsers(dest="profile_action")
    profile_list = profile_actions.add_parser(
        "list", help="List profile names without displaying credential values."
    )
    profile_list.add_argument(
        "patterns",
        nargs="*",
        help="Case-insensitive fnmatch patterns for profile or location names.",
    )
    profile_list.add_argument(
        "--verify",
        action="store_true",
        help="Verify eligible managed sessions with STS (may contact AWS).",
    )
    profile_list.add_argument(
        "--wide",
        action="store_true",
        help="Include full AWS-directory paths in the human table.",
    )
    profile_list.add_argument("--json", action="store_true")

    for kind in ("account", "boundary", "target"):
        _resource_parser(types, kind)

    policy = types.add_parser(
        "policy", help="Manage reusable policy documents stored on this computer."
    )
    policy_actions = policy.add_subparsers(dest="resource_action")
    for action in ("add", "update"):
        item = policy_actions.add_parser(action)
        item.add_argument("resource_name")
        item.add_argument("file")
        item.add_argument("--format", choices=("json", "yaml", "yml", "toml"))
        item.add_argument("--description")
    for action in ("get", "remove"):
        item = policy_actions.add_parser(action)
        item.add_argument("resource_name")
        item.add_argument("--json", action="store_true")
    policy_actions.add_parser("list").add_argument("--json", action="store_true")
    rename = policy_actions.add_parser("rename")
    rename.add_argument("resource_name")
    rename.add_argument("new_name")

    cache = types.add_parser("cache", help="Inspect the Hacksaws session-policy cache.")
    cache_actions = cache.add_subparsers(dest="cache_action")
    cache_get = cache_actions.add_parser("get", help="Read policy-cache settings.")
    cache_get.add_argument("setting", nargs="?", choices=("max-age",))
    cache_get.add_argument("--json", action="store_true")
    cache_set = cache_actions.add_parser("set", help="Update a policy-cache setting.")
    cache_set.add_argument("setting", choices=("max-age",))
    cache_set.add_argument("value")
    cache_actions.add_parser(
        "status", help="Summarize fresh, stale, and invalid entries."
    ).add_argument("--json", action="store_true")
    cache_list = cache_actions.add_parser(
        "list", help="List cache metadata, never documents."
    )
    cache_list.add_argument(
        "patterns",
        nargs="*",
        help="Case-insensitive fnmatch patterns for cache entry identities.",
    )
    cache_filter = cache_list.add_mutually_exclusive_group()
    cache_filter.add_argument("--fresh", action="store_true")
    cache_filter.add_argument("--stale", action="store_true")
    cache_filter.add_argument("--invalid", action="store_true")
    cache_list.add_argument("--origin")
    cache_list.add_argument("--json", action="store_true")
    cache_show = cache_actions.add_parser(
        "show", help="Show one explicitly selected cache entry."
    )
    cache_show.add_argument("entry")
    cache_show.add_argument("--json", action="store_true")
    cache_clear = cache_actions.add_parser("clear", help="Remove policy-cache entries.")
    cache_clear.add_argument("entries", nargs="*")
    clear_scope = cache_clear.add_mutually_exclusive_group()
    clear_scope.add_argument("--stale", action="store_true")
    clear_scope.add_argument("--all", action="store_true")
    cache_clear.add_argument("--yes", action="store_true")

    config = types.add_parser(
        "config", help="Inspect, validate, import, and export Hacksaws configuration."
    )
    config_actions = config.add_subparsers(dest="config_action")
    show = config_actions.add_parser("show")
    show.add_argument("--account")
    show.add_argument("--json", action="store_true")
    explain = config_actions.add_parser("explain")
    explain.add_argument("target")
    explain.add_argument("--json", action="store_true")
    check = config_actions.add_parser("check")
    check.add_argument(
        "--remote", action="store_true", help="Validate account-scoped AWS resources."
    )
    check.add_argument(
        "--probe",
        action="store_true",
        help="Also probe saved boundaries with a deny-all AssumeRole request.",
    )
    check.add_argument("--account", help="Check only this configured AWS account.")
    check.add_argument("--json", action="store_true")
    _credential_selector(check)
    fix = config_actions.add_parser("fix")
    fix.add_argument("--account", help="Repair only this configured AWS account.")
    fix.add_argument(
        "--remote",
        action="store_true",
        help="Include account-scoped AWS resource issues in the repair review.",
    )
    fix.add_argument(
        "--probe",
        action="store_true",
        help="Also probe saved boundaries with a deny-all AssumeRole request.",
    )
    fix.add_argument(
        "--yes",
        action="store_true",
        help="Run non-interactively; unresolved issues remain and return nonzero.",
    )
    _credential_selector(fix)
    export = config_actions.add_parser("export")
    export.add_argument("zip", nargs="?")
    imported = config_actions.add_parser("import")
    imported.add_argument("zip")
    imported.add_argument("--replace", action="store_true")
    imported.add_argument("--yes", action="store_true")
    options = config_actions.add_parser("options")
    options.add_argument("--json", action="store_true")
    for action in ("get", "reset"):
        item = config_actions.add_parser(action)
        item.add_argument("key")
        item.add_argument("--json", action="store_true")
    direct_set = config_actions.add_parser("set")
    direct_set.add_argument("key")
    direct_set.add_argument("value")
    direct_set.add_argument("--json", action="store_true")
    option = config_actions.add_parser("option", aliases=["opt"])
    option_actions = option.add_subparsers(dest="option_action")
    option_actions.add_parser("list", aliases=["ls"]).add_argument(
        "--json", action="store_true"
    )
    for action in ("get", "explain", "reset"):
        item = option_actions.add_parser(action)
        item.add_argument("key")
        item.add_argument("--json", action="store_true")
    option_set = option_actions.add_parser("set")
    option_set.add_argument("key")
    option_set.add_argument("value")
    option_set.add_argument("--json", action="store_true")
    _register_extension_commands(types)
    return parser


def _register_extension_commands(
    parent: argparse._SubParsersAction[Any],
) -> None:
    """Reserve integration hooks for IAM and remote command providers.

    Domain modules register their command trees here once their implementation is
    available; keeping the hook local prevents output/config plumbing from owning
    IAM behavior.
    """
    _iam_cli.register_root_cleanup_parser(parent)
    _iam_cli.register_parser(parent)


def _extract_global_options(
    arguments: Sequence[str],
) -> tuple[list[str], str | None, bool]:
    """Consume output switches anywhere before ``--`` without changing command syntax."""
    remaining: list[str] = []
    color: str | None = None
    use_json = False
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            remaining.extend(arguments[index:])
            break
        if argument == "--json":
            use_json = True
        elif argument == "--no-color":
            if color and color != "never":
                raise _configs.OperationalError("--no-color conflicts with --color.")
            color = "never"
        elif argument == "--color":
            index += 1
            if index == len(arguments) or arguments[index] not in {
                "auto",
                "always",
                "never",
            }:
                raise _configs.OperationalError(
                    "--color requires auto, always, or never."
                )
            if color and color != arguments[index]:
                raise _configs.OperationalError("--color was specified more than once.")
            color = arguments[index]
        elif argument.startswith("--color="):
            value = argument.partition("=")[2]
            if value not in {"auto", "always", "never"}:
                raise _configs.OperationalError(
                    "--color requires auto, always, or never."
                )
            if color and color != value:
                raise _configs.OperationalError("--color was specified more than once.")
            color = value
        else:
            remaining.append(argument)
        index += 1
    return remaining, color, use_json


def _json_requested(arguments: Sequence[str]) -> bool:
    """Detect machine mode before validating any other global option."""
    for argument in arguments:
        if argument == "--":
            return False
        if argument == "--json":
            return True
    return False


@contextlib.contextmanager
def _redirect_stdin(stream: object) -> Iterator[None]:
    """Temporarily provide a non-TTY input stream for strict machine mode."""
    previous = sys.stdin
    sys.stdin = cast("Any", stream)
    try:
        yield
    finally:
        sys.stdin = previous


class _NonInteractiveStdin:
    """EOF-safe input used to make accidental prompts decline in JSON mode."""

    def isatty(self) -> bool:
        return False

    def readline(self, size: int = -1, /) -> str:
        return "" if size == 0 else "\n"


def _print_help(command: Sequence[str] = ()) -> None:
    try:
        _create_parser().parse_args([*command, "--help"])
    except SystemExit:
        return


def _validate_login(namespace: argparse.Namespace) -> None:
    profile = getattr(namespace, "profile", None)
    if profile in {".", "default"}:
        namespace.profile = "default"
        profile = "default"
    if profile and not profile[0].isalnum():
        if getattr(namespace, "target", None):
            raise _configs.OperationalError("Specify a target only once.")
        if len(profile) == 1:
            raise _configs.OperationalError("A target shorthand requires a name.")
        namespace.target = "+" + profile[1:]
        namespace.profile = None
    if getattr(namespace, "policy", None) and not (
        getattr(namespace, "role", None)
        or getattr(namespace, "boundary", None)
        or getattr(namespace, "target", None)
    ):
        raise _configs.OperationalError("--policy requires --role or --boundary.")
    if (
        getattr(namespace, "external_id", None)
        or getattr(namespace, "session_name", None)
    ) and not (
        getattr(namespace, "role", None)
        or getattr(namespace, "boundary", None)
        or getattr(namespace, "target", None)
    ):
        raise _configs.OperationalError(
            "Role-only options require --role or --boundary."
        )
    if getattr(namespace, "to", None) and (
        getattr(namespace, "to_directory", None)
        or getattr(namespace, "to_profile", None)
    ):
        raise _configs.OperationalError(
            "--to is mutually exclusive with --to-directory/--to-profile."
        )
    if getattr(namespace, "to_directory", None) and not getattr(
        namespace, "to_profile", None
    ):
        raise _configs.OperationalError("--to-directory requires --to-profile.")
    if getattr(namespace, "target", None) and not namespace.target.startswith("+"):
        namespace.target = "+" + namespace.target
    if getattr(namespace, "role", None) and getattr(namespace, "boundary", None):
        raise _configs.OperationalError(
            "--role and --boundary/--as are mutually exclusive."
        )
    if getattr(namespace, "target", None):
        data = _state.load_config()
        _, target = _state.get_resource(data, "target", namespace.target.lstrip("+"))
        direct_boundary = getattr(namespace, "boundary", None)
        if direct_boundary and target.get("boundary"):
            raise _configs.OperationalError(
                "A target with a saved boundary cannot accept --boundary/--as."
            )
        overrides = [
            getattr(namespace, "profile", None),
            getattr(namespace, "aws_account_name", None),
            getattr(namespace, "to", None),
            getattr(namespace, "to_directory", None),
            getattr(namespace, "to_profile", None),
            getattr(namespace, "role", None),
            getattr(namespace, "policy", None),
            getattr(namespace, "account", None),
            getattr(namespace, "external_id", None),
            getattr(namespace, "session_name", None),
        ]
        if (
            any(value is not None for value in overrides)
            or getattr(namespace, "directory", "~/.aws") != "~/.aws"
        ):
            raise _configs.OperationalError(
                "A saved target is a secure preset; source, destination, role, and policy cannot be overridden."
            )


def _run_mfa(context: _configs.Context) -> _configs.Result:
    """Execute MFA while preserving the legacy direct-profile behavior."""
    action = cast("str | None", context.args.action)
    if not action:
        _print_help(("mfa",))
        return _configs.Result(
            "MFA_HELP",
            "Not enough arguments specified for the mfa command.",
            2,
            "stderr",
        )
    if action in {"logout", "out"}:
        return _run_logout(context)
    _validate_login(context.args)
    if context.args.profile is None and not context.args.target:
        raise _configs.OperationalError(
            "MFA login requires a source profile unless a saved target supplies it."
        )
    if context.args.mfa_code is None:
        raise _configs.OperationalError("MFA login requires a token code.")
    if _sessions.is_expanded_login(context.args):
        return _sessions.mfa_login(context)

    os.environ["AWS_SHARED_CREDENTIALS_FILE"] = str(context.credentials_path)
    os.environ["AWS_CONFIG_FILE"] = str(context.config_path)
    _aws.logout(context)
    aws_account = _configs.AwsAccount.from_context(context)
    if cast("bool", context.args.ecr):
        _ecr.logout(context, aws_account, check=False)
    _aws.login(context)
    if cast("bool", context.args.ecr):
        _ecr.login(context, aws_account)
    return _configs.Result("MFA_LOGIN", f"Logged into profile {context.profile}")


def _run_logout(context: _configs.Context) -> _configs.Result:
    if getattr(context.args, "except_profiles", None) and not bool(
        getattr(context.args, "all", False)
    ):
        raise _configs.OperationalError("--except requires --all.")
    if bool(getattr(context.args, "all", False)):
        report = _sessions.logout_all(context.args)
        excluded = set(getattr(context.args, "except_profiles", []) or [])
        for item in _sessions.profile_inventory()["profiles"]:
            if item.get("auth_method") != "legacy-mfa":
                continue
            if _sessions.matches_logout_exclusion(
                destination=item["directory"],
                profile=item["profile"],
                location=item.get("location"),
                excluded=excluded,
            ):
                report["outcomes"].append(
                    {
                        "profile": item["profile"],
                        "destination": item["directory"],
                        "state": "excluded",
                        "changed": False,
                    }
                )
                continue
            legacy_args = argparse.Namespace(
                **{
                    **vars(context.args),
                    "all": False,
                    "target": None,
                    "directory": item["directory"],
                    "aws_account_name": None,
                    "profile": item["profile"],
                }
            )
            legacy_context = _configs.Context(args=legacy_args)
            try:
                _aws.logout(legacy_context)
                report["outcomes"].append(
                    {
                        "profile": item["profile"],
                        "destination": item["directory"],
                        "state": "logged-out",
                        "changed": True,
                    }
                )
            except _configs.OperationalError as error:
                report["errors"].append(
                    {
                        "key": f"{item['directory']}::{item['profile']}",
                        "message": str(error),
                    }
                )
        message = _logout_report_text(report)
        return _configs.Result(
            "LOGOUT_ALL",
            message,
            1 if report["errors"] else 0,
            "stderr" if report["errors"] else "stdout",
            report,
            kind="info",
        )
    profile = context.args.profile
    if profile in {".", "default"}:
        context.args.profile = "default"
    elif profile and not profile[0].isalnum() and not context.args.target:
        if len(profile) == 1:
            raise _configs.OperationalError("A target shorthand requires a name.")
        context.args.target = "+" + profile[1:]
        context.args.profile = "default"
    _sessions.recover_journal()
    if _sessions.logout(context):
        return _configs.Result(
            "LOGOUT",
            f"Logged out of profile {context.profile}",
            data={"profile": context.profile, "changed": True},
        )
    os.environ["AWS_SHARED_CREDENTIALS_FILE"] = str(context.credentials_path)
    os.environ["AWS_CONFIG_FILE"] = str(context.config_path)
    legacy_active = context.storage_path.exists()
    _aws.logout(context)
    changed = legacy_active
    return _configs.Result(
        "MFA_LOGOUT" if changed else "LOGOUT_NO_STATE",
        (
            f"Logged out of profile {context.profile}"
            if changed
            else f"No Hacksaws-managed login state found for profile {context.profile}."
        ),
        data={"profile": context.profile, "changed": changed},
        kind="info" if not changed else "success",
    )


def _run_browser(context: _configs.Context) -> _configs.Result:
    if not context.args.action:
        _print_help((context.args.access_type,))
        return _configs.Result(
            "BROWSER_HELP",
            "Not enough arguments specified for browser authentication.",
            2,
            "stderr",
        )
    if context.args.action in {"logout", "out"}:
        return _run_logout(context)
    _validate_login(context.args)
    return _sessions.browser_login(context)


def _json_or_text(value: object, use_json: bool) -> str:
    if use_json:
        return json.dumps(value, indent=2, default=str)
    if isinstance(value, dict):
        return "\n".join(f"{key}: {item}" for key, item in value.items())
    if isinstance(value, list):
        return "\n".join(json.dumps(item, default=str) for item in value) or "(none)"
    return str(value)


def _text_table(columns: list[str], rows: list[list[object]]) -> str:
    if not rows:
        return "(none)"
    rendered = [
        [str(value) if value is not None else "-" for value in row] for row in rows
    ]
    widths = [
        max(len(column), *(len(row[index]) for row in rendered))
        for index, column in enumerate(columns)
    ]
    header = "  ".join(
        column.ljust(widths[index]) for index, column in enumerate(columns)
    )
    divider = "  ".join("-" * width for width in widths)
    body = [
        "  ".join(value.ljust(widths[index]) for index, value in enumerate(row))
        for row in rendered
    ]
    return "\n".join([header, divider, *body])


def _status_text(report: dict[str, Any]) -> str:
    rows = [
        [
            item.get("location") or item.get("destination"),
            item.get("profile", "default"),
            item.get("state"),
            item.get("auth_method"),
            item.get("target_account") or item.get("source_account"),
            item.get("boundary") or item.get("role"),
            item.get("remaining_seconds"),
            (item.get("verification") or {}).get("status"),
        ]
        for item in report["sessions"]
    ]
    return _text_table(
        [
            "LOCATION",
            "PROFILE",
            "STATE",
            "AUTH",
            "ACCOUNT",
            "SCOPE",
            "REMAINING",
            "VERIFY",
        ],
        rows,
    )


def _profile_list_text(report: dict[str, Any], *, wide: bool = False) -> str:
    columns = ["LOCATION", "PROFILE", "STATE", "AUTH", "VERIFY"]
    if wide:
        columns.append("DIRECTORY")
    return _text_table(
        columns,
        [
            [
                item.get("location"),
                item["profile"],
                item["state"],
                item.get("auth_method"),
                (item.get("verification") or {}).get("status"),
                *([item["directory"]] if wide else []),
            ]
            for item in report["profiles"]
        ],
    )


def _config_text(data: dict[str, Any], *, account: str | None = None) -> str:
    """Render configuration as compact domain tables instead of Python reprs."""
    accounts = data.get("accounts", {})
    selected_accounts = {
        name: value
        for name, value in accounts.items()
        if account is None or name.casefold() == account.casefold()
    }
    if account and not selected_accounts:
        raise _configs.OperationalError(f"Unknown configured account {account!r}.")
    account_names = set(selected_accounts)
    boundaries = {
        name: value
        for name, value in data.get("boundaries", {}).items()
        if account is None or value.get("account") in account_names
    }
    boundary_names = set(boundaries)
    targets = {
        name: value
        for name, value in data.get("targets", {}).items()
        if account is None
        or value.get("source_account") in account_names
        or value.get("boundary") in boundary_names
    }
    policies = data.get("policies", {})
    if account is not None:
        used_policies = {
            str(value["policy"]) for value in boundaries.values() if value.get("policy")
        }
        policies = {
            name: value for name, value in policies.items() if name in used_policies
        }
    sections = [
        "Accounts\n"
        + _text_table(
            ["NAME", "ID", "PARTITION", "VERIFIED", "DESCRIPTION"],
            [
                [
                    name,
                    value.get("id"),
                    value.get("partition"),
                    "no" if value.get("unverified") else "yes",
                    value.get("description"),
                ]
                for name, value in sorted(selected_accounts.items())
            ],
        ),
        "Boundaries\n"
        + _text_table(
            ["NAME", "ACCOUNT", "ROLE", "POLICY", "DURATION"],
            [
                [
                    name,
                    value.get("account"),
                    value.get("role_arn"),
                    value.get("policy"),
                    value.get("duration"),
                ]
                for name, value in sorted(boundaries.items())
            ],
        ),
        "Targets\n"
        + _text_table(
            ["NAME", "ACCOUNT", "SOURCE", "DESTINATION", "BOUNDARY"],
            [
                [
                    name,
                    value.get("source_account"),
                    (
                        f"{value.get('source_location', value.get('source_directory', 'default'))}:"
                        f"{value.get('source_profile', 'default')}"
                    ),
                    (
                        f"{value.get('destination_location', value.get('destination_directory', '-'))}:"
                        f"{value.get('destination_profile', '-')}"
                    ),
                    value.get("boundary"),
                ]
                for name, value in sorted(targets.items())
            ],
        ),
        "Stored policies\n"
        + _text_table(
            ["NAME", "FILE", "DESCRIPTION"],
            [
                [name, value.get("file"), value.get("description")]
                for name, value in sorted(policies.items())
            ],
        ),
    ]
    if account is None:
        sections.append(
            "Settings\n"
            + _text_table(
                ["AREA", "VALUE"],
                [
                    ["cache.max-age", data.get("cache", {}).get("max_age")],
                    ["output.color", data.get("output", {}).get("color")],
                ],
            )
        )
    return "\n\n".join(sections)


def _logout_report_text(report: dict[str, Any]) -> str:
    rows = [
        [item.get("profile"), item.get("destination"), item["state"]]
        for item in report["outcomes"]
    ]
    rows.extend(
        [["-", item["key"], f"error: {item['message']}"] for item in report["errors"]]
    )
    return _text_table(["PROFILE", "DESTINATION", "RESULT"], rows)


def _cache_list_text(entries: list[dict[str, Any]]) -> str:
    return _text_table(
        ["ENTRY", "STATE", "ORIGIN", "SOURCE", "AGE", "BYTES"],
        [
            [
                item["identity"],
                item["state"],
                item.get("origin"),
                item.get("source_identity"),
                item.get("age_seconds"),
                item["size"],
            ]
            for item in entries
        ],
    )


def _cache_status_text(report: dict[str, Any]) -> str:
    counts = report["counts"]
    return "\n".join(
        (
            f"Policy cache: {report['root']}",
            f"Max age: {report['max_age']} seconds",
            (
                f"Entries: {sum(counts.values())} "
                f"({counts['fresh']} fresh, {counts['stale']} stale, "
                f"{counts['invalid']} invalid)"
            ),
            f"Size: {report['total_bytes']} bytes",
        )
    )


def _cascade_plan(data: dict[str, Any], kind: str, name: str) -> dict[str, set[str]]:
    """Compute whole-resource dependent deletion without weakening boundaries."""
    key, _ = _state.get_resource(data, kind, name)
    plan: dict[str, set[str]] = {
        "accounts": set(),
        "boundaries": set(),
        "targets": set(),
        "policies": set(),
    }
    plan[_state.collection_name(kind)].add(key)
    changed = True
    while changed:
        changed = False
        for target_name, target in data["targets"].items():
            if target_name in plan["targets"]:
                continue
            if any(
                str(target.get("source_account", "")).casefold() == account.casefold()
                for account in plan["accounts"]
            ) or any(
                str(target.get("boundary", "")).casefold() == boundary.casefold()
                for boundary in plan["boundaries"]
            ):
                plan["targets"].add(target_name)
                changed = True
        for boundary_name, boundary in data["boundaries"].items():
            if boundary_name in plan["boundaries"]:
                continue
            if any(
                str(boundary.get("account", "")).casefold() == account.casefold()
                for account in plan["accounts"]
            ) or any(
                str(boundary.get("policy", "")).casefold() == policy.casefold()
                for policy in plan["policies"]
            ):
                plan["boundaries"].add(boundary_name)
                changed = True
    return plan


def _cascade_remove(data: dict[str, Any], kind: str, name: str, *, yes: bool) -> str:
    plan = _cascade_plan(data, kind, name)
    planned = [
        f"{collection[:-1]}:{item}"
        for collection, names in plan.items()
        for item in sorted(names)
    ]
    active = [
        reference
        for planned_kind in ("account", "boundary", "target", "policy")
        for planned_name in plan[_state.collection_name(planned_kind)]
        for reference in _state.references(data, planned_kind, planned_name)
        if reference.startswith("session:")
    ]
    if active:
        raise _configs.OperationalError(
            f"Cascade cannot remove active session references: {', '.join(active)}. "
            "Log out first."
        )
    preview = f"Cascade preview: {', '.join(planned)}."
    if not yes:
        if not sys.stdin.isatty():
            raise _configs.OperationalError(
                f"{preview} Noninteractive cascade requires --yes."
            )
        if input(
            f"{preview} Delete all listed resources? [y/N] "
        ).strip().casefold() not in {
            "y",
            "yes",
        }:
            raise _configs.OperationalError("Cascade cancelled; no files changed.")
    policy_paths = [
        _policies.stored_directory() / f"{policy}.yaml" for policy in plan["policies"]
    ]
    journal = _sessions._begin([_state.root() / "config.json", *policy_paths])
    try:
        for collection, names in plan.items():
            for item in names:
                del data[collection][item]
        _state.save_config(data)
        for path in policy_paths:
            path.unlink(missing_ok=True)
        _sessions._commit()
    except Exception:
        _sessions._rollback(journal)
        raise
    return preview


def _run_resource(args: argparse.Namespace) -> _configs.Result:
    kind = args.access_type
    action = args.resource_action
    if not action:
        _print_help((kind,))
        return _configs.Result(
            "RESOURCE_HELP", f"Choose an action for {kind}.", 2, "stderr"
        )
    data = _state.load_config()
    if action == "list":
        values = [
            {"name": name, **item}
            for name, item in data[_state.collection_name(kind)].items()
        ]
        return _configs.Result("RESOURCE_LIST", _json_or_text(values, args.json))
    if action == "get":
        name, item = _state.get_resource(data, kind, args.resource_name)
        return _configs.Result(
            "RESOURCE_GET", _json_or_text({"name": name, **item}, args.json)
        )
    if action == "rename":
        journal = _sessions._begin(
            [_state.root() / "config.json", _state.sessions_path()]
        )
        try:
            _state.rename_resource(data, kind, args.resource_name, args.new_name)
            _state.save_config(data)
            _sessions._commit()
        except Exception:
            _sessions._rollback(journal)
            raise
        return _configs.Result(
            "RESOURCE_RENAME",
            f"Renamed {kind} {args.resource_name} to {args.new_name}.",
        )
    if action == "remove":
        if args.cascade:
            preview = _cascade_remove(data, kind, args.resource_name, yes=args.yes)
            return _configs.Result("RESOURCE_REMOVE", f"{preview} Removed.")
        _state.remove_resource(data, kind, args.resource_name)
        _state.save_config(data)
        return _configs.Result(
            "RESOURCE_REMOVE", f"Removed {kind} {args.resource_name}."
        )
    if action == "add":
        if kind == "account":
            partition = args.partition
            unverified = bool(args.no_verify)
            if args.no_verify:
                if partition is None:
                    raise _configs.OperationalError(
                        "--no-verify account saves require an explicit --partition."
                    )
            else:
                try:
                    with _selected_credential_session(args) as selected_session:
                        caller_id, caller_partition, _ = _sessions._identity(
                            selected_session,
                            label="account configuration",
                        )
                except _configs.OperationalError:
                    raise
                if caller_id != args.account_id:
                    raise _configs.OperationalError(
                        f"Configured account id {args.account_id} does not match caller {caller_id}."
                    )
                if partition and partition != caller_partition:
                    raise _configs.OperationalError(
                        f"Configured partition {partition} does not match caller {caller_partition}."
                    )
                partition = caller_partition
            value = {
                "id": args.account_id,
                "partition": partition,
                **({"unverified": True} if unverified else {}),
            }
        elif kind == "boundary":
            _, account = _state.get_resource(data, "account", args.account)
            role = args.role
            if not role.startswith("arn:"):
                role = f"arn:{account['partition']}:iam::{account['id']}:role/{role}"
            if not args.no_verify:
                role_name = role.split("role/", 1)[-1]
                try:
                    with _selected_credential_session(args) as selected_session:
                        response = selected_session.client("iam").get_role(
                            RoleName=role_name
                        )
                    role = response["Role"]["Arn"]
                except (BotoCoreError, ClientError, KeyError) as error:
                    raise _configs.OperationalError(
                        f"Unable to verify role {role_name!r}; retry with working "
                        f"credentials or explicitly use --no-verify: {error}"
                    ) from error
            match = re.fullmatch(
                r"arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role/.+", role
            )
            if not match or (
                match.group(1) != account["partition"]
                or match.group(2) != account["id"]
            ):
                raise _configs.OperationalError(
                    "Boundary role account/partition conflicts with --account."
                )
            value = {
                "role_arn": role,
                "account": args.account,
                "verified": not args.no_verify,
            }
            if args.policy:
                value["policy"] = args.policy
            if args.external_id:
                value["external_id"] = args.external_id
            if args.duration:
                value["duration"] = _duration.parse_duration(args.duration)
        else:
            value = {
                "source_account": args.source_account,
                "source_profile": args.source_profile,
            }
            if args.source_directory:
                value["source_directory"] = str(
                    Path(args.source_directory).expanduser().absolute()
                )
            else:
                value["source_location"] = _state.normalize_location(
                    args.source_location
                )
            if args.to:
                location, separator, profile = args.to.partition(":")
                if not separator or not profile:
                    raise _configs.OperationalError("--to must be LOCATION:PROFILE.")
                value.update(
                    destination_location=_state.normalize_location(location),
                    destination_profile=profile,
                )
            elif args.to_directory:
                if not args.to_profile:
                    raise _configs.OperationalError(
                        "--to-directory requires --to-profile."
                    )
                value.update(
                    destination_directory=str(
                        Path(args.to_directory).expanduser().absolute()
                    ),
                    destination_profile=args.to_profile,
                )
            if args.boundary:
                value["boundary"] = args.boundary
        if args.description:
            value["description"] = args.description
        _state.add_resource(data, kind, args.resource_name, value)
    else:
        patch: dict[str, Any] = {}
        if args.description is not None:
            patch["description"] = args.description
        if args.clear_description:
            _, item = _state.get_resource(data, kind, args.resource_name)
            item.pop("description", None)
        if kind == "boundary":
            _, existing_boundary = _state.get_resource(data, kind, args.resource_name)
            selected_account = args.account or existing_boundary["account"]
            if args.account:
                _state.get_resource(data, "account", args.account)
                patch["account"] = args.account
            if args.role:
                _, account_record = _state.get_resource(
                    data, "account", selected_account
                )
                role = args.role
                if not role.startswith("arn:"):
                    role = (
                        f"arn:{account_record['partition']}:iam::"
                        f"{account_record['id']}:role/{role}"
                    )
                if not args.no_verify:
                    role_name = role.split("role/", 1)[-1]
                    try:
                        with _selected_credential_session(args) as selected_session:
                            role = selected_session.client("iam").get_role(
                                RoleName=role_name
                            )["Role"]["Arn"]
                    except (BotoCoreError, ClientError, KeyError) as error:
                        raise _configs.OperationalError(
                            f"Unable to verify role update {role_name!r}: {error}"
                        ) from error
                patch["role_arn"] = role
                patch["verified"] = not args.no_verify
            for field in ("policy", "external_id"):
                supplied = getattr(args, field)
                if supplied is not None:
                    patch[field] = supplied
                if getattr(args, f"clear_{field}"):
                    _, item = _state.get_resource(data, kind, args.resource_name)
                    item.pop(field, None)
            if args.duration:
                patch["duration"] = _duration.parse_duration(args.duration)
            if args.clear_duration:
                _, item = _state.get_resource(data, kind, args.resource_name)
                item.pop("duration", None)
        if kind == "target":
            _, item = _state.get_resource(data, kind, args.resource_name)
            if args.source_account:
                _state.get_resource(data, "account", args.source_account)
                patch["source_account"] = args.source_account
            if args.source_profile:
                patch["source_profile"] = args.source_profile
            if args.source_location:
                item.pop("source_directory", None)
                patch["source_location"] = _state.normalize_location(
                    args.source_location
                )
            if args.source_directory:
                item.pop("source_location", None)
                patch["source_directory"] = str(
                    Path(args.source_directory).expanduser().absolute()
                )
            if args.boundary:
                patch["boundary"] = args.boundary
            if args.clear_boundary:
                _, item = _state.get_resource(data, kind, args.resource_name)
                item.pop("boundary", None)
            if args.clear_destination:
                for field in (
                    "destination_location",
                    "destination_directory",
                    "destination_profile",
                ):
                    item.pop(field, None)
            if args.to and (args.to_directory or args.to_profile):
                raise _configs.OperationalError(
                    "--to is mutually exclusive with --to-directory/--to-profile."
                )
            if args.to:
                location, separator, profile = args.to.partition(":")
                if not separator or not profile:
                    raise _configs.OperationalError("--to must be LOCATION:PROFILE.")
                item.pop("destination_directory", None)
                patch.update(
                    destination_location=_state.normalize_location(location),
                    destination_profile=profile,
                )
            if args.to_directory:
                if not args.to_profile:
                    raise _configs.OperationalError(
                        "--to-directory requires --to-profile."
                    )
                item.pop("destination_location", None)
                patch.update(
                    destination_directory=str(
                        Path(args.to_directory).expanduser().absolute()
                    ),
                    destination_profile=args.to_profile,
                )
        _state.update_resource(data, kind, args.resource_name, patch)
    _state.save_config(data)
    return _configs.Result("RESOURCE_SAVED", f"Saved {kind} {args.resource_name}.")


def _stdin_policy(args: argparse.Namespace) -> Path:
    if args.file != "-":
        return Path(args.file).expanduser()
    if not args.format:
        raise _configs.OperationalError("Policy FILE '-' requires --format.")
    temporary = _state.root() / f".stdin-policy.{args.format}"
    _state.atomic_write(temporary, sys.stdin.buffer.read())
    return temporary


def _run_policy(args: argparse.Namespace) -> _configs.Result:
    action = args.resource_action
    if not action:
        _print_help(("policy",))
        return _configs.Result("POLICY_HELP", "Choose a policy action.", 2, "stderr")
    if action in {"add", "update"}:
        path = _stdin_policy(args)
        try:
            operation = (
                _policies.add_stored if action == "add" else _policies.update_stored
            )
            operation(args.resource_name, path, args.description)
        finally:
            if args.file == "-":
                path.unlink(missing_ok=True)
        return _configs.Result("POLICY_SAVED", f"Saved policy {args.resource_name}.")
    if action == "remove":
        _policies.remove_stored(args.resource_name)
        return _configs.Result("POLICY_REMOVE", f"Removed policy {args.resource_name}.")
    if action == "rename":
        _policies.rename_stored(args.resource_name, args.new_name)
        return _configs.Result(
            "POLICY_RENAME", f"Renamed policy {args.resource_name} to {args.new_name}."
        )
    data = _state.load_config()
    if action == "list":
        values = [{"name": name, **item} for name, item in data["policies"].items()]
        return _configs.Result("POLICY_LIST", _json_or_text(values, args.json))
    key, metadata = _state.get_resource(data, "policy", args.resource_name)
    document, _ = _policies.parse_policy(_policies.stored_directory() / f"{key}.yaml")
    return _configs.Result(
        "POLICY_GET",
        _json_or_text({"name": key, **metadata, "document": document}, args.json),
    )


def _run_cache(args: argparse.Namespace) -> _configs.Result:
    data = _state.load_config()
    if args.cache_action == "set":
        data["cache"]["max_age"] = _duration.parse_duration(args.value, allow_zero=True)
        _state.save_config(data)
        return _configs.Result(
            "CACHE_SET",
            f"Policy cache max-age set to {data['cache']['max_age']} seconds.",
        )
    if args.cache_action == "get":
        value: object = (
            {"setting": "max-age", "value": data["cache"]["max_age"]}
            if args.setting == "max-age"
            else {"max_age": data["cache"]["max_age"]}
        )
        return _configs.Result(
            "CACHE_GET",
            _json_or_text(value, use_json=args.json),
            data=value,
            kind="info",
        )
    if args.cache_action in {"status", "list"}:
        report = _policies.cache_inventory()
        if args.cache_action == "status":
            summary = {key: value for key, value in report.items() if key != "entries"}
            return _configs.Result(
                "CACHE_STATUS",
                _cache_status_text(report),
                data=summary,
                kind="info",
            )
        state = (
            "fresh"
            if args.fresh
            else "stale"
            if args.stale
            else "invalid"
            if args.invalid
            else None
        )
        entries = [
            item
            for item in report["entries"]
            if (state is None or item["state"] == state)
            and (args.origin is None or item.get("origin") == args.origin)
            and (
                not args.patterns
                or any(
                    fnmatch.fnmatchcase(
                        str(item["identity"]).casefold(), pattern.casefold()
                    )
                    for pattern in args.patterns
                )
            )
        ]
        result = {"entries": entries, "count": len(entries), "counts": report["counts"]}
        return _configs.Result(
            "CACHE_LIST", _cache_list_text(entries), data=result, kind="info"
        )
    if args.cache_action == "show":
        value = _policies.cache_show(args.entry)
        return _configs.Result(
            "CACHE_SHOW",
            json.dumps(value, indent=2, default=str),
            data=value,
            kind="info",
        )
    if args.cache_action == "clear":
        if args.entries and (args.stale or args.all):
            raise _configs.OperationalError(
                "Cache entry names cannot be combined with --stale or --all."
            )
        inventory = _policies.cache_inventory()
        if args.entries:
            candidates = [
                item
                for item in inventory["entries"]
                if any(
                    fnmatch.fnmatchcase(
                        str(item["identity"]).casefold(), pattern.casefold()
                    )
                    for pattern in args.entries
                )
            ]
        elif args.stale:
            candidates = [
                item
                for item in inventory["entries"]
                if item["state"] in {"stale", "invalid"}
            ]
        else:
            candidates = list(inventory["entries"])
        if candidates and not args.yes:
            interactive = not _configs.json_output_enabled() and bool(
                getattr(sys.stdin, "isatty", lambda: False)()
            )
            if not _output.confirm(
                f"Remove {len(candidates)} policy-cache entr{'y' if len(candidates) == 1 else 'ies'}?",
                stdin=sys.stdin,
                interactive=interactive,
            ):
                return _configs.Result(
                    "CACHE_CLEAR_CANCELLED",
                    "Policy cache clear cancelled; no entries were removed.",
                    _configs.EXIT_CANCELLED,
                    "stderr",
                    {"removed": []},
                )
        removed = _policies.clear_cache_entries(
            args.entries or None, stale_only=bool(args.stale)
        )
        result = {"removed": removed, "count": len(removed)}
        return _configs.Result(
            "CACHE_CLEAR",
            f"Removed {len(removed)} policy-cache entr{'y' if len(removed) == 1 else 'ies'}.",
            data=result,
        )
    _print_help(("cache",))
    return _configs.Result("CACHE_HELP", "Choose a cache action.", 2, "stderr")


def _run_profile(args: argparse.Namespace) -> _configs.Result:
    if args.profile_action != "list":
        _print_help(("profile",))
        return _configs.Result("PROFILE_HELP", "Choose a profile action.", 2, "stderr")
    report = _sessions.profile_inventory(args.patterns, verify=args.verify)
    return _configs.Result(
        "PROFILE_LIST",
        _profile_list_text(report, wide=args.wide),
        data=report,
        kind="info",
    )


def _run_config(args: argparse.Namespace) -> _configs.Result:
    action = args.config_action
    if action == "options":
        options = _state.config_option_patterns()
        return _configs.Result(
            "CONFIG_OPTIONS",
            _json_or_text(options, args.json),
            data=options,
        )
    if action in {"option", "opt"}:
        option_action = args.option_action
        if option_action in {"list", "ls"}:
            options = _state.config_option_patterns()
            return _configs.Result(
                "CONFIG_OPTION_LIST", _json_or_text(options, args.json), data=options
            )
        data = _state.load_config()
        if option_action == "get":
            nested_option_value = _state.get_config_option(data, args.key)
            return _configs.Result(
                "CONFIG_OPTION_GET",
                _json_or_text(nested_option_value, args.json),
                data={"key": args.key, "value": nested_option_value},
            )
        if option_action == "explain":
            descriptions = _state.config_option_patterns()
            matching = {
                pattern: detail
                for pattern, detail in descriptions.items()
                if args.key == pattern or args.key in pattern
            }
            if not matching:
                raise _configs.OperationalError(
                    f"Unknown config option {args.key!r}; run 'config options'."
                )
            return _configs.Result(
                "CONFIG_OPTION_EXPLAIN",
                _json_or_text(matching, args.json),
                data=matching,
            )
        if option_action == "set":
            try:
                nested_set_value: object = json.loads(args.value)
            except json.JSONDecodeError:
                nested_set_value = args.value
            _state.set_config_option(data, args.key, nested_set_value)
            _state.save_config(data)
            return _configs.Result(
                "CONFIG_OPTION_SET",
                f"Set config option {args.key}.",
                data={
                    "key": args.key,
                    "value": _state.get_config_option(data, args.key),
                },
            )
        if option_action == "reset":
            _state.reset_config_option(data, args.key)
            _state.save_config(data)
            return _configs.Result(
                "CONFIG_OPTION_RESET",
                f"Reset config option {args.key}.",
                data={"key": args.key, "reset": True},
            )
        _print_help(("config", "option"))
        return _configs.Result(
            "CONFIG_OPTION_HELP", "Choose a config option action.", 2, "stderr"
        )
    if action in {"get", "set", "reset"}:
        data = _state.load_config()
        if action == "get":
            direct_option_value = _state.get_config_option(data, args.key)
            return _configs.Result(
                "CONFIG_OPTION_GET",
                _json_or_text(direct_option_value, args.json),
                data={"key": args.key, "value": direct_option_value},
            )
        if action == "set":
            try:
                direct_option_value = json.loads(args.value)
            except json.JSONDecodeError:
                direct_option_value = args.value
            _state.set_config_option(data, args.key, direct_option_value)
            _state.save_config(data)
            return _configs.Result(
                "CONFIG_OPTION_SET",
                f"Set config option {args.key}.",
                data={
                    "key": args.key,
                    "value": _state.get_config_option(data, args.key),
                },
            )
        _state.reset_config_option(data, args.key)
        _state.save_config(data)
        return _configs.Result(
            "CONFIG_OPTION_RESET",
            f"Reset config option {args.key}.",
            data={"key": args.key, "reset": True},
        )
    if action == "show":
        data = _state.load_config()
        display_data: dict[str, Any] = data
        account_name: str | None = None
        if args.account:
            account_name, account = _state.get_resource(data, "account", args.account)
            boundaries = {
                name: value
                for name, value in data["boundaries"].items()
                if str(value["account"]).casefold() == account_name.casefold()
            }
            boundary_names = {name.casefold() for name in boundaries}
            display_data = {
                "account": {"name": account_name, **account},
                "boundaries": boundaries,
                "targets": {
                    name: value
                    for name, value in data["targets"].items()
                    if str(value.get("source_account", "")).casefold()
                    == account_name.casefold()
                    or str(value.get("boundary", "")).casefold() in boundary_names
                },
            }
        text = (
            json.dumps(display_data, indent=2, default=str)
            if args.json
            else _config_text(data, account=account_name)
        )
        return _configs.Result("CONFIG_SHOW", text, data=display_data)
    if action == "explain":
        value = _sessions.explain_target(args.target)
        return _configs.Result("CONFIG_EXPLAIN", _json_or_text(value, args.json))
    if action == "check":
        report = _sessions.check_config(args)
        return _configs.Result(
            "CONFIG_CHECK",
            _json_or_text(report, args.json),
            0 if not report["errors"] else 1,
        )
    if action == "fix":
        return _sessions.fix_config(args)
    if action == "export":
        path = _sessions.export_config(args.zip)
        return _configs.Result(
            "CONFIG_EXPORT", f"Exported portable configuration to {path}."
        )
    if action == "import":
        summary = _sessions.import_config(
            Path(args.zip), replace=args.replace, yes=args.yes
        )
        return _configs.Result("CONFIG_IMPORT", summary)
    _print_help(("config",))
    return _configs.Result("CONFIG_HELP", "Choose a config action.", 2, "stderr")


def _console_main_invocation(arguments: Sequence[str] | None = None) -> _configs.Result:
    raw_arguments = list(sys.argv[1:] if arguments is None else arguments)
    preselected_json = _json_requested(raw_arguments)
    _configs.configure_output(color="auto", json_output=preselected_json)
    try:
        normalized_arguments, requested_color, use_json = _extract_global_options(
            raw_arguments
        )
        _iam_cli.validate_selector_arguments(normalized_arguments)
    except _configs.OperationalError as error:
        return _configs.Result(
            "ARGUMENT_ERROR", f"Error: {error}", _configs.EXIT_USAGE, "stderr"
        ).echo()
    _configs.configure_output(
        color=cast("Any", requested_color or "auto"), json_output=use_json
    )
    parser = _create_parser()
    parse_stderr = io.StringIO()
    parse_stdout = io.StringIO()
    try:
        with (
            contextlib.redirect_stderr(parse_stderr)
            if use_json
            else contextlib.nullcontext(),
            contextlib.redirect_stdout(parse_stdout)
            if use_json
            else contextlib.nullcontext(),
        ):
            namespace = parser.parse_args(normalized_arguments)
    except SystemExit as error:
        result = _configs.Result(
            "HELP" if error.code == 0 else "ARGUMENT_ERROR",
            "" if error.code == 0 else parse_stderr.getvalue().strip(),
            cast("int", error.code),
            "stderr",
            {"help": parse_stdout.getvalue().strip()} if error.code == 0 else None,
        )
        return result.echo() if use_json else result
    namespace.json = use_json or bool(getattr(namespace, "json", False))
    if requested_color is None and namespace.access_type:
        try:
            configured_color = _state.load_config()["output"]["color"]
        except _configs.OperationalError:
            configured_color = "auto"
        _configs.configure_output(
            color=cast("Any", configured_color), json_output=use_json
        )
    if not namespace.access_type:
        if use_json:
            return _configs.Result(
                "ACCESS_TYPE_HELP",
                "Not enough arguments.",
                2,
                "stderr",
                {"help": parser.format_help().strip()},
            ).echo()
        _print_help()
        return _configs.Result(
            "ACCESS_TYPE_HELP", "Not enough arguments.", 2, "stderr"
        ).echo()
    if namespace.access_type == "mfa" and namespace.action in {"login", "in"}:
        if namespace.target and namespace.profile and namespace.mfa_code is None:
            namespace.mfa_code = namespace.profile
            namespace.profile = None
        if namespace.mfa_code is None:
            usage = parser.format_usage().strip()
            if not use_json:
                parser.print_usage(sys.stderr)
            return _configs.Result(
                "ARGUMENT_ERROR",
                "the following arguments are required: PROFILE CODE or +TARGET CODE.",
                2,
                "stderr",
                {"usage": usage} if use_json else None,
            ).echo()
    captured_stdout = io.StringIO()
    captured_stderr = io.StringIO()
    machine_stdin = _NonInteractiveStdin()
    try:
        with (
            contextlib.redirect_stdout(captured_stdout)
            if use_json
            else contextlib.nullcontext(),
            contextlib.redirect_stderr(captured_stderr)
            if use_json
            else contextlib.nullcontext(),
            _redirect_stdin(machine_stdin) if use_json else contextlib.nullcontext(),
        ):
            is_iam_recovery = namespace.access_type in {"iam", "remote"} and getattr(
                namespace, "iam_action", None
            ) in {"recovery", "recover"}
            is_remote_dry_run = namespace.access_type in {
                "iam",
                "remote",
                "cleanup",
            } and bool(getattr(namespace, "dry_run", False))
            if not (is_iam_recovery or is_remote_dry_run):
                _sessions.recover_journal()
            if namespace.access_type == "mfa":
                result = _run_mfa(_configs.Context(args=namespace))
            elif namespace.access_type in {"pk", "web"}:
                result = _run_browser(_configs.Context(args=namespace))
            elif namespace.access_type in {"iam", "remote"}:
                result = _iam_cli.dispatch(namespace)
            elif namespace.access_type == "cleanup":
                result = _iam_cli.dispatch_root_cleanup(namespace)
            elif namespace.access_type == "logout":
                result = _run_logout(_configs.Context(args=namespace))
            elif namespace.access_type == "status":
                status_report = _sessions.status_report(
                    profile=namespace.profile,
                    location=namespace.location,
                    directory=Path(namespace.directory)
                    if namespace.directory
                    else None,
                    verify=namespace.verify,
                )
                result = _configs.Result(
                    "STATUS",
                    _status_text(status_report),
                    data=status_report,
                    kind="info",
                )
            elif namespace.access_type == "profile":
                result = _run_profile(namespace)
            elif namespace.access_type in {"account", "boundary", "target"}:
                result = _run_resource(namespace)
            elif namespace.access_type == "policy":
                result = _run_policy(namespace)
            elif namespace.access_type == "cache":
                result = _run_cache(namespace)
            else:
                result = _run_config(namespace)
    except _configs.OperationalError as error:
        result = _configs.Result(
            "OPERATIONAL_ERROR",
            f"Error: {error}",
            1,
            "stderr",
            error.data,
            error.details,
            error.repairs,
        )
    return result.echo()


def console_main(arguments: Sequence[str] | None = None) -> _configs.Result:
    """Run one isolated CLI invocation without leaking output mode to callers."""
    _configs.configure_output()
    try:
        return _console_main_invocation(arguments)
    finally:
        _configs.configure_output()
