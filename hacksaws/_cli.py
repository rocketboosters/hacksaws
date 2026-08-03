"""Hacksaws command-line parsing and orchestration."""

from __future__ import annotations

import argparse
import contextlib
import fnmatch
import getpass
import io
import json
import os
import re
import sys
import unicodedata
from decimal import ROUND_HALF_UP
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING
from typing import Any
from typing import cast

import boto3
from botocore.exceptions import BotoCoreError
from botocore.exceptions import ClientError
from rich.text import Text

from hacksaws import _aws
from hacksaws import _configs
from hacksaws import _duration
from hacksaws import _history
from hacksaws import _iam_cli
from hacksaws import _output
from hacksaws import _policies
from hacksaws import _regions
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


def _history_filter_arguments(parser: argparse.ArgumentParser) -> None:
    """Add structured, secret-free history filters to one leaf command."""
    parser.add_argument(
        "--since",
        help=(
            "Include records at or after an ISO timestamp or duration ago using "
            "seconds, minutes, hours, days, or weeks (for example 24h or 2weeks)."
        ),
    )
    parser.add_argument(
        "--until",
        help=(
            "Include records at or before an ISO timestamp or duration ago using "
            "seconds, minutes, hours, days, or weeks."
        ),
    )
    parser.add_argument(
        "--command",
        help="Include this canonical command family, such as iam.policy.",
    )
    parser.add_argument(
        "--outcome",
        choices=(
            "success",
            "usage-error",
            "policy-refusal",
            "cancelled",
            "operational-error",
            "interrupted",
            "crashed",
        ),
        help="Include only this command outcome.",
    )
    parser.add_argument("--account", help="Include only this recorded AWS account.")
    parser.add_argument(
        "--resource", help="Match a recorded resource name or ARN fragment."
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum records to return (default: 50; maximum: 10000).",
    )
    parser.add_argument(
        "--include-running",
        action="store_true",
        help="Also include commands whose final outcome has not been recorded.",
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
            "mfa_code",
            nargs="?",
            help=(
                "Current six-digit MFA token; omit for a hidden interactive prompt, "
                "or use --mfa-code-stdin for noninteractive input."
            ),
        )
        parser.add_argument(
            "--mfa-code-stdin",
            action="store_true",
            help="Read the MFA token code from standard input instead of the command line.",
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
    parser.add_argument(
        "--allow-unknown-region",
        action="store_true",
        help="Accept a new canonical AWS region absent from bundled Botocore data.",
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


def _assume_arguments(parser: argparse.ArgumentParser) -> None:
    """Register the explicit role-assumption workflow without login-only flags."""
    parser.add_argument(
        "profile",
        nargs="?",
        metavar="SOURCE",
        help=(
            "Source AWS profile. A leading non-alphanumeric character selects a "
            "saved target; +TARGET is the documented form."
        ),
    )
    parser.add_argument(
        "destination",
        nargs="?",
        metavar="DEST",
        help="Destination profile in the source AWS location (equivalent to --to-profile).",
    )
    parser.add_argument(
        "-n",
        "--name",
        "--account-name",
        dest="aws_account_name",
        help="Source location name, selecting ~/.aws-NAME (default: ~/.aws).",
    )
    parser.add_argument(
        "--target",
        help="Saved target supplying source and destination endpoints.",
    )
    destination = parser.add_mutually_exclusive_group()
    destination.add_argument(
        "--self",
        dest="self_destination",
        action="store_true",
        help="Explicitly replace the source endpoint with assumed-role credentials.",
    )
    destination.add_argument(
        "--to",
        metavar="LOCATION:PROFILE",
        help="Write assumed credentials to this logical location and profile.",
    )
    parser.add_argument(
        "--to-directory",
        metavar="PATH",
        help="Write to an explicit AWS directory; requires --to-profile.",
    )
    parser.add_argument(
        "--to-profile",
        metavar="PROFILE",
        help="Write to PROFILE in the source AWS location.",
    )
    role = parser.add_mutually_exclusive_group()
    role.add_argument("--role", help="Concrete IAM role name or ARN to assume.")
    role.add_argument(
        "--boundary",
        "--as",
        dest="boundary",
        help="Saved boundary supplying the concrete role and optional policy.",
    )
    parser.add_argument(
        "--policy",
        help="Optional session policy name, ARN, stored name, or local file.",
    )
    parser.add_argument("--external-id", help="External ID supplied to AssumeRole.")
    parser.add_argument(
        "--account", help="Configured account name or ID asserted for the role target."
    )
    parser.add_argument(
        "--session-name", help="Assumed-role session name shown in AWS audit records."
    )
    parser.add_argument(
        "--region", help="AWS region used for credential resolution and console links."
    )
    parser.add_argument(
        "--allow-unknown-region",
        action="store_true",
        help="Accept a new canonical AWS region absent from bundled Botocore data.",
    )
    _duration_arguments(parser)
    parser.add_argument(
        "--keep-source",
        action="store_true",
        help="Leave live source credentials in place after writing the destination.",
    )
    parser.add_argument(
        "--keep-ecr",
        action="store_true",
        help="Preserve Hacksaws-tracked ECR authorization while clearing the source.",
    )
    parser.add_argument(
        "--replace",
        action="store_true",
        help="Allow replacement of a destination that already contains credentials.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Approve the displayed assumption plan without prompting.",
    )
    parser.set_defaults(
        action="assume",
        directory="~/.aws",
        force=False,
        ecr=False,
        podman=False,
        ecr_region=[],
        remote=False,
        mfa_code=None,
        mfa_code_stdin=False,
    )


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
        add.add_argument(
            "--region",
            metavar="REGION_OR_ALIAS",
            help="Preferred region for this account; stored canonically.",
        )
        add.add_argument(
            "--allow-unknown-region",
            action="store_true",
            help="Accept a canonical-shaped region absent from bundled metadata.",
        )
        account_region = update.add_mutually_exclusive_group()
        account_region.add_argument(
            "--region",
            metavar="REGION_OR_ALIAS",
            help="Replace this account's preferred region.",
        )
        account_region.add_argument(
            "--clear-region",
            action="store_true",
            help="Remove this account's preferred region.",
        )
        update.add_argument(
            "--allow-unknown-region",
            action="store_true",
            help="Accept a canonical-shaped region absent from bundled metadata.",
        )
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
        add.add_argument(
            "--region",
            metavar="REGION_OR_ALIAS",
            help="Saved target region, ahead of profile/account/global defaults.",
        )
        add.add_argument(
            "--allow-unknown-region",
            action="store_true",
            help="Accept a canonical-shaped region absent from bundled metadata.",
        )
        update.add_argument("--boundary")
        update.add_argument("--clear-boundary", action="store_true")
        target_region = update.add_mutually_exclusive_group()
        target_region.add_argument(
            "--region",
            metavar="REGION_OR_ALIAS",
            help="Replace this target's saved region.",
        )
        target_region.add_argument(
            "--clear-region",
            action="store_true",
            help="Remove this target's saved region.",
        )
        update.add_argument(
            "--allow-unknown-region",
            action="store_true",
            help="Accept a canonical-shaped region absent from bundled metadata.",
        )
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
    assume = types.add_parser(
        "assume",
        help="Assume a role from existing temporary credentials.",
        description=(
            "Assume a concrete IAM role from an existing AWS profile, write the "
            "result to an explicit destination, and optionally clear the source."
        ),
        epilog=(
            "Examples:\n"
            "  hacksaws assume admin --name horizon --role AgentSession --to agent:default\n"
            "  hacksaws assume admin --role AgentSession --to-directory ./agent-aws --to-profile debug\n"
            "  hacksaws assume admin --boundary logs-read --to-profile agent\n"
            "  hacksaws assume +prod-agent\n"
            "  hacksaws assume debug --role AgentSession --self\n\n"
            "Use --self only for deliberate in-place replacement. Writing the same "
            "endpoint with --to is supported but emits an additional warning.\n"
            "Saved targets own their source and destination and therefore reject "
            "--self and other endpoint overrides. An unbounded target may add only "
            "one saved --boundary/--as plus duration and lifecycle controls."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _assume_arguments(assume)
    status = types.add_parser(
        "status",
        help="Show Hacksaws-managed login sessions.",
        description="Show a compact, secret-free view of managed login sessions.",
        epilog=(
            "AUTH values:\n"
            "  web        AWS browser/passkey login\n"
            "  web→role   browser/passkey login followed by an assumed role\n"
            "  mfa        MFA-authenticated session\n"
            "  mfa→role   MFA authentication followed by an assumed role\n"
            "  role       direct assumed-role handoff\n"
            "  legacy     legacy MFA tracking\n"
            "  unknown    unclassified login metadata\n\n"
            "SCOPE examples:\n"
            "  AgentSession                         IAM role\n"
            "  AgentSession (@Guardrail)            role plus Hacksaws boundary preset\n"
            "  AgentSession (@Guardrail) → ReadLogs role restricted by a session policy\n\n"
            "Examples:\n"
            "  hacksaws status\n"
            "  hacksaws status --verify\n"
            "  hacksaws status --profile agent --json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    status.add_argument("--profile", help="Filter by destination profile.")
    status_location = status.add_mutually_exclusive_group()
    status_location.add_argument("--location", help="Filter by logical AWS location.")
    status_location.add_argument("-d", "--directory", help="Filter by AWS directory.")
    status.add_argument(
        "--verify",
        action="store_true",
        help="Opt in to STS verification for each eligible session.",
    )
    status.add_argument(
        "--json", action="store_true", help="Emit stable raw lifecycle JSON."
    )

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
    profile_region = profile_actions.add_parser(
        "region", help="Inspect or change the region stored on one AWS profile."
    )
    profile_region_actions = profile_region.add_subparsers(dest="profile_region_action")
    profile_region_get = profile_region_actions.add_parser(
        "get", help="Show the profile's currently stored region."
    )
    _credential_selector(profile_region_get)
    profile_region_get.add_argument(
        "--json", action="store_true", help="Emit stable JSON."
    )
    profile_region_set = profile_region_actions.add_parser(
        "set", help="Store a canonical region on the profile."
    )
    profile_region_set.add_argument(
        "region",
        metavar="REGION_OR_ALIAS",
        help="Canonical region or compact, geography, or custom alias.",
    )
    profile_region_set.add_argument(
        "--allow-unknown-region",
        action="store_true",
        help="Accept a canonical-shaped region absent from bundled metadata.",
    )
    _credential_selector(profile_region_set)
    profile_region_set.add_argument(
        "--json", action="store_true", help="Emit stable JSON."
    )
    profile_region_clear = profile_region_actions.add_parser(
        "clear", help="Remove the region stored on the profile."
    )
    _credential_selector(profile_region_clear)
    profile_region_clear.add_argument(
        "--json", action="store_true", help="Emit stable JSON."
    )

    for kind in ("account", "boundary", "target"):
        _resource_parser(types, kind)

    region = types.add_parser(
        "region",
        help="Discover canonical AWS regions and manage input-only aliases.",
        description=(
            "Resolve canonical regions, compact aliases such as usw2, geography "
            "aliases such as oregon, and portable custom aliases. Hacksaws always "
            "stores the canonical AWS region."
        ),
        epilog=(
            "Examples:\n"
            "  hacksaws region list '*west*'\n"
            "  hacksaws region explain oregon\n"
            "  hacksaws region alias add pacific us-west-2\n"
            "  hacksaws region list --account production\n\n"
            "Operational AWS, China, and GovCloud regions are shown by default. "
            "Use --all-partitions for discovery only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    region_actions = region.add_subparsers(dest="region_action")
    for action in ("list", "explain"):
        item = region_actions.add_parser(action)
        if action == "list":
            item.add_argument(
                "patterns",
                nargs="*",
                help="Case-insensitive fnmatch patterns ORed across names and aliases.",
            )
        else:
            item.add_argument(
                "region",
                metavar="REGION_OR_ALIAS",
                help="Canonical region or compact, geography, or custom alias.",
            )
            item.add_argument(
                "--allow-unknown-region",
                action="store_true",
                help="Accept a canonical-shaped region absent from bundled metadata.",
            )
        scope = item.add_mutually_exclusive_group()
        scope.add_argument("--partition", help="Limit discovery to one AWS partition.")
        scope.add_argument(
            "--account", help="Use a configured account's partition as the scope."
        )
        item.add_argument(
            "--all-partitions",
            action="store_true",
            help="Include discovery-only partitions Hacksaws cannot operate in.",
        )
        item.add_argument("--json", action="store_true", help="Emit stable JSON.")
    alias = region_actions.add_parser(
        "alias", help="Manage portable global custom region aliases."
    )
    alias_actions = alias.add_subparsers(dest="region_alias_action")
    alias_add = alias_actions.add_parser("add", help="Create a portable input alias.")
    alias_add.add_argument("alias", help="New lower-kebab-case alias name.")
    alias_add.add_argument(
        "region",
        metavar="REGION_OR_ALIAS",
        help="Known region or built-in alias to store canonically.",
    )
    alias_add.add_argument("--description", help="Optional purpose or geography note.")
    alias_update = alias_actions.add_parser(
        "update", help="Change an alias target or description."
    )
    alias_update.add_argument("alias", help="Existing custom alias name.")
    alias_update.add_argument(
        "--region",
        metavar="REGION_OR_ALIAS",
        help="Replacement known region or built-in alias.",
    )
    alias_update.add_argument("--description", help="Replacement description.")
    alias_update.add_argument(
        "--clear-description", action="store_true", help="Remove its description."
    )
    for action in ("get", "remove"):
        item = alias_actions.add_parser(action)
        item.add_argument("alias", help="Existing custom alias name.")
        item.add_argument("--json", action="store_true", help="Emit stable JSON.")
    alias_list = alias_actions.add_parser("list", help="List custom aliases.")
    alias_list.add_argument(
        "patterns",
        nargs="*",
        help="Case-insensitive fnmatch patterns ORed across alias fields.",
    )
    alias_list.add_argument("--json", action="store_true", help="Emit stable JSON.")
    alias_rename = alias_actions.add_parser("rename", help="Rename an input alias.")
    alias_rename.add_argument("alias", help="Existing custom alias name.")
    alias_rename.add_argument("new_alias", help="New lower-kebab-case alias name.")

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
    direct_set.add_argument("--allow-unknown-region", action="store_true")
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
    option_set.add_argument("--allow-unknown-region", action="store_true")

    history = types.add_parser(
        "history",
        help="Inspect redacted local command outcomes without exposing credentials.",
        description=(
            "Inspect the credential-free local audit trail. Hacksaws records command "
            "families, validated identifiers, outcomes, and timings; it never records "
            "raw arguments, command output, prompt input, credential values, or paths."
        ),
    )
    history_actions = history.add_subparsers(dest="history_action")
    history_list = history_actions.add_parser(
        "list", help="List recent completed command outcomes in a compact table."
    )
    history_list.add_argument(
        "patterns",
        nargs="*",
        help="Case-insensitive fnmatch patterns matched across safe record fields.",
    )
    history_list.add_argument(
        "--wide",
        action="store_true",
        help="Show account, resource, and result details.",
    )
    _history_filter_arguments(history_list)
    history_search = history_actions.add_parser(
        "search", help="Search safe history fields using one or more ORed patterns."
    )
    history_search.add_argument(
        "patterns",
        nargs="+",
        help="Case-insensitive fnmatch patterns; plain text is treated as *TEXT*.",
    )
    history_search.add_argument(
        "--wide",
        action="store_true",
        help="Show account, resource, and result details.",
    )
    _history_filter_arguments(history_search)
    history_show = history_actions.add_parser(
        "show", help="Show one safe record by full or unique-prefix history ID."
    )
    history_show.add_argument("history_id", help="Full or unique ID prefix (4+ hex).")
    history_report = history_actions.add_parser(
        "report", help="Summarize outcomes and command families for a time window."
    )
    _history_filter_arguments(history_report)
    history_export = history_actions.add_parser(
        "export", help="Export selected safe records as deterministic JSONL or JSON."
    )
    history_export.add_argument(
        "patterns",
        nargs="*",
        help="Optional case-insensitive fnmatch patterns for safe record fields.",
    )
    _history_filter_arguments(history_export)
    history_export.add_argument(
        "--format",
        choices=("jsonl", "json"),
        default="jsonl",
        help="Export encoding (default: jsonl).",
    )
    history_export.add_argument(
        "--output",
        "-o",
        help="Write to this file instead of standard output.",
    )
    history_actions.add_parser(
        "status", help="Show database health, size, and retention settings."
    )
    history_actions.add_parser(
        "check", help="Validate the history schema, database, and safe payloads."
    )
    history_clear = history_actions.add_parser(
        "clear",
        help="Remove resolved history while preserving active recovery records.",
    )
    history_clear_scope = history_clear.add_mutually_exclusive_group(required=True)
    history_clear_scope.add_argument(
        "--before",
        help=(
            "Remove records before an ISO timestamp or duration ago, such as 30d "
            "or 2weeks."
        ),
    )
    history_clear_scope.add_argument(
        "--all", action="store_true", help="Remove every eligible resolved record."
    )
    history_clear.add_argument(
        "--dry-run",
        action="store_true",
        help="Plan the clear without changing history.",
    )
    history_clear.add_argument(
        "--yes",
        action="store_true",
        help="Apply without prompting; intended for deliberate automation.",
    )
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


def _validate_assume(namespace: argparse.Namespace) -> None:
    """Validate assume-only grammar before AWS discovery or confirmation."""
    positional_destination = getattr(namespace, "destination", None)
    if positional_destination:
        if (
            namespace.target
            or namespace.self_destination
            or namespace.to
            or namespace.to_directory
            or namespace.to_profile
        ):
            raise _configs.OperationalError(
                "Positional DEST is mutually exclusive with saved targets, --self, "
                "--to, --to-directory, and --to-profile."
            )
        namespace.to_profile = (
            "default"
            if positional_destination in {".", "default"}
            else positional_destination
        )
    profile = getattr(namespace, "profile", None)
    if profile in {".", "default"}:
        namespace.profile = "default"
        profile = "default"
    if profile and not profile[0].isalnum():
        if namespace.target:
            raise _configs.OperationalError("Specify a saved target only once.")
        if len(profile) == 1:
            raise _configs.OperationalError("A target shorthand requires a name.")
        namespace.target = "+" + profile[1:]
        namespace.profile = None
        profile = None
    if namespace.target and not namespace.target.startswith("+"):
        namespace.target = "+" + namespace.target
    if not (profile or namespace.target):
        raise _configs.OperationalError(
            "Assume requires a source profile or saved target."
        )
    if namespace.self_destination and namespace.keep_source:
        raise _configs.OperationalError("--self cannot be combined with --keep-source.")
    if namespace.self_destination and (namespace.to_directory or namespace.to_profile):
        raise _configs.OperationalError(
            "--self is mutually exclusive with --to-directory/--to-profile."
        )
    if namespace.to and (namespace.to_directory or namespace.to_profile):
        raise _configs.OperationalError(
            "--to is mutually exclusive with --to-directory/--to-profile."
        )
    if namespace.to_directory and not namespace.to_profile:
        raise _configs.OperationalError("--to-directory requires --to-profile.")
    if namespace.to:
        location, separator, destination_profile = namespace.to.partition(":")
        if not separator or not location or not destination_profile:
            raise _configs.OperationalError("--to must be LOCATION:PROFILE.")
    data = _state.load_config()
    target: dict[str, Any] | None = None
    if namespace.target:
        _, target = _state.get_resource(data, "target", namespace.target.lstrip("+"))
        if namespace.self_destination:
            raise _configs.OperationalError(
                "A saved target owns its destination and cannot be combined with --self."
            )
        if namespace.aws_account_name:
            raise _configs.OperationalError(
                "A saved target supplies its source location; omit --name."
            )
        if namespace.to or namespace.to_directory or namespace.to_profile:
            raise _configs.OperationalError(
                "A saved target supplies its destination; use --self for an explicit "
                "in-place assumption."
            )
        saved_boundary = target.get("boundary")
        if saved_boundary:
            overrides = [
                option
                for option, value in (
                    ("--role", namespace.role),
                    ("--boundary/--as", namespace.boundary),
                    ("--policy", namespace.policy),
                    ("--account", namespace.account),
                    ("--external-id", namespace.external_id),
                    ("--session-name", namespace.session_name),
                )
                if value
            ]
            if overrides:
                raise _configs.OperationalError(
                    "A bounded target supplies its role contract and cannot be "
                    "combined with " + ", ".join(overrides) + "."
                )
        else:
            overrides = [
                option
                for option, value in (
                    ("--role", namespace.role),
                    ("--policy", namespace.policy),
                    ("--account", namespace.account),
                    ("--external-id", namespace.external_id),
                    ("--session-name", namespace.session_name),
                    ("--region", namespace.region),
                )
                if value
            ]
            if overrides:
                raise _configs.OperationalError(
                    "An unbounded target may add one saved --boundary/--as, not "
                    + ", ".join(overrides)
                    + "."
                )
        if not (
            target.get("destination_location")
            or target.get("destination_directory")
            or target.get("destination_profile")
        ):
            raise _configs.OperationalError(
                "Saved target has no destination; update it or use --self."
            )
    elif not (
        namespace.self_destination
        or namespace.to
        or namespace.to_directory
        or namespace.to_profile
    ):
        raise _configs.OperationalError(
            "Assume requires --self, --to LOCATION:PROFILE, --to-profile PROFILE, "
            "or a saved target destination."
        )
    concrete_boundary = namespace.boundary or (target or {}).get("boundary")
    if not (namespace.role or concrete_boundary):
        raise _configs.OperationalError(
            "Assume requires a concrete --role, saved --boundary/--as, or bounded "
            "target."
        )
    if namespace.boundary:
        _state.get_resource(data, "boundary", namespace.boundary)


def _assume_preview_text(preview: dict[str, Any]) -> str:
    """Render a secret-free assume plan in a stable, reviewable layout."""
    preferred = (
        ("source", "Source"),
        ("destination", "Destination"),
        ("role", "Role"),
        ("policy", "Session policy"),
        ("duration", "Duration"),
        ("durationSeconds", "Duration (seconds)"),
        ("account", "Account"),
        ("partition", "Partition"),
        ("keepSource", "Keep source"),
        ("keepEcr", "Keep ECR"),
        ("replace", "Replace destination"),
    )
    lines = ["Assume role plan:"]
    rendered: set[str] = set()
    for key, label in preferred:
        if key not in preview:
            continue
        value = preview[key]
        text = (
            json.dumps(value, sort_keys=True)
            if isinstance(value, (dict, list))
            else str(value)
        )
        lines.append(f"  {label}: {text}")
        rendered.add(key)
    for key, value in preview.items():
        if key in rendered or key == "warnings":
            continue
        text = (
            json.dumps(value, sort_keys=True)
            if isinstance(value, (dict, list))
            else str(value)
        )
        lines.append(f"  {key}: {text}")
    warnings = preview.get("warnings", [])
    if isinstance(warnings, list):
        lines.extend(f"WARNING: {warning}" for warning in warnings)
    return "\n".join(lines)


def _run_assume(context: _configs.Context) -> _configs.Result:
    """Preview, confirm, then execute one source-to-destination assumption."""
    _validate_assume(context.args)
    plan = _sessions.prepare_assume_role(context)
    preview = _sessions.assume_role_preview(plan)
    rendered = _assume_preview_text(preview)
    if not bool(context.args.yes):
        if _configs.json_output_enabled() or not sys.stdin.isatty():
            return _configs.Result(
                "ASSUME_CONFIRMATION_REQUIRED",
                "Assume role requires --yes in non-interactive or JSON mode.",
                _configs.EXIT_CANCELLED,
                "stderr",
                data={"preview": preview},
                kind="warning",
            )
        prompt = f"{rendered}\nType exactly 'yes' to apply this plan:\n> "
        if input(prompt).strip() != "yes":
            return _configs.Result(
                "ASSUME_CANCELLED",
                "Assume role cancelled; no credentials were changed.",
                _configs.EXIT_CANCELLED,
                "stderr",
                data={"preview": preview},
                kind="warning",
            )
        context.args.yes = True
    result = _sessions.assume_role(context, plan)
    data = dict(result.data) if isinstance(result.data, dict) else {}
    data.setdefault("preview", preview)
    return _configs.Result(
        result.code,
        result.message,
        result.exit_code,
        result.stream,
        data=data,
        details=result.details,
        repairs=result.repairs,
        kind=result.kind,
    )


def _run_mfa(context: _configs.Context) -> _configs.Result:
    """Execute MFA through the transactional session lifecycle."""
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
    if context.args.mfa_code is not None and bool(
        getattr(context.args, "mfa_code_stdin", False)
    ):
        raise _configs.OperationalError(
            "Specify the MFA token either positionally or with --mfa-code-stdin, not both."
        )
    if bool(getattr(context.args, "mfa_code_stdin", False)):
        context.args.mfa_code = sys.stdin.readline().strip()
        context.args.mfa_code_source = "stdin"
    elif context.args.mfa_code is None:
        if bool(getattr(context.args, "json", False)) or not sys.stdin.isatty():
            raise _configs.OperationalError(
                "MFA login requires a token code; provide it positionally or use "
                "--mfa-code-stdin."
            )
        context.args.mfa_code = getpass.getpass("MFA token code: ").strip()
        context.args.mfa_code_source = "prompt"
    else:
        context.args.mfa_code_source = "argument"
    if not context.args.mfa_code:
        raise _configs.OperationalError("MFA token code cannot be empty.")
    _history.note_mfa_code(source=context.args.mfa_code_source)
    return _sessions.mfa_login(context)


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


_TERMINAL_STRING_CONTROL = re.compile(
    r"(?:\x1b\]|\x9d).*?(?:\x07|\x1b\\|\x9c|$)|"
    r"(?:\x1b[P_^X]|[\x90\x98\x9e\x9f]).*?(?:\x1b\\|\x9c|$)",
    re.DOTALL,
)


def _safe_terminal_text(value: object) -> str:
    """Return single-line printable text with terminal controls removed."""
    decoded = Text.from_ansi(_TERMINAL_STRING_CONTROL.sub("", str(value))).plain
    safe = []
    for character in decoded:
        if character in "\r\n\t":
            safe.append(" ")
        elif unicodedata.category(character) not in {"Cc", "Cf", "Cs"}:
            safe.append(character)
    return "".join(safe)


def _text_table(columns: Sequence[str], rows: Sequence[Sequence[object]]) -> str:
    if not rows:
        return "(none)"
    rendered_columns = [_safe_terminal_text(column) for column in columns]
    rendered = [
        [_safe_terminal_text(value) if value is not None else "-" for value in row]
        for row in rows
    ]

    def display_width(value: str) -> int:
        return Text(value).cell_len

    widths = [
        max(display_width(column), *(display_width(row[index]) for row in rendered))
        for index, column in enumerate(rendered_columns)
    ]

    def pad(value: str, width: int) -> str:
        return value + " " * (width - display_width(value))

    header = "  ".join(
        pad(column, widths[index]) for index, column in enumerate(rendered_columns)
    ).rstrip()
    divider = "  ".join("-" * width for width in widths)
    body = [
        "  ".join(pad(value, widths[index]) for index, value in enumerate(row)).rstrip()
        for row in rendered
    ]
    return "\n".join([header, divider, *body])


_STATUS_STATES = {
    "active": ("🟢", "active"),
    "expiring": ("🟡", "expiring"),
    "expired": ("🔴", "expired"),
    "drifted": ("⚠️", "drifted/legacy-unverified"),
    "legacy-unverified": ("⚠️", "drifted/legacy-unverified"),
    "missing": ("❌", "missing/invalid"),
    "invalid": ("❌", "missing/invalid"),
    "logout-residue": ("🧹", "logout/ECR residue"),
    "ecr-only": ("🧹", "logout/ECR residue"),
}
_UNKNOWN_STATUS_STATE = ("❔", "unknown/inconclusive")
_STATUS_AUTH = {
    "browser-native": ("web", "AWS browser/passkey login"),
    "browser-boundary": ("web→role", "browser/passkey login, then role"),
    "assume-role": ("role", "assumed-role handoff"),
    "legacy-mfa": ("legacy", "legacy MFA tracking"),
    "browser-cache-residue": ("web", "AWS browser/passkey login"),
}
_UNKNOWN_STATUS_AUTH = ("unknown", "unclassified login")
_STATUS_VERIFICATIONS = {
    "verified": "verified",
    "mismatch": "mismatch",
    "error": "error",
}
_IAM_SCOPE_ARN = re.compile(r"arn:[^:\s]+:iam::(?:aws|\d{12}):(?:role|policy)/([^\s]+)")
_SECONDS_PER_MINUTE = 60
_SECONDS_PER_HOUR = 60 * _SECONDS_PER_MINUTE


def _status_state(item: dict[str, Any]) -> tuple[str, str]:
    return _STATUS_STATES.get(str(item.get("state")), _UNKNOWN_STATUS_STATE)


def _status_auth(item: dict[str, Any]) -> tuple[str, str]:
    method = str(item.get("auth_method") or "")
    if method == "mfa":
        return (
            ("mfa→role", "MFA login, then role")
            if item.get("role")
            else ("mfa", "MFA login")
        )
    return _STATUS_AUTH.get(method, _UNKNOWN_STATUS_AUTH)


def _short_scope(value: object) -> str:
    if not value:
        return ""
    return _IAM_SCOPE_ARN.sub(lambda match: match.group(1), str(value))


def _status_scope(item: dict[str, Any]) -> str:
    effective = item.get("effective_scope")
    if isinstance(effective, dict):
        kind = str(effective.get("kind") or "unknown")
        role = effective.get("role_label")
        boundary = effective.get("boundary_label")
        policy = effective.get("policy_label")
        if kind != "role-session":
            return {
                "ecr-only": "ECR only",
                "logout-residue": "logout residue",
                "account-login": "account login",
                "mfa-session": "MFA session",
                "legacy-unknown": "unknown (legacy)",
                "unknown": "unknown session",
            }.get(kind, "unknown session")
        if not role:
            role = "role session"
        if boundary:
            role = f"{role} (@{boundary})"
    else:
        role = item.get("role")
        boundary = item.get("boundary")
        if boundary:
            role = f"{_short_scope(role) or 'role session'} (@{_short_scope(boundary)})"
        policy = item.get("policy")
    label = _short_scope(role)
    restriction = _short_scope(policy)
    if label and restriction:
        return f"{label} → {restriction}"
    return label or restriction


def _status_ttl(item: dict[str, Any]) -> str:
    state = str(item.get("state") or "")
    if state not in {"active", "expiring"}:
        return ""
    raw = item.get("remaining_seconds")
    if raw is None:
        return ""
    try:
        seconds = Decimal(str(raw))
    except ArithmeticError:
        return ""
    if seconds <= 0:
        return ""
    if seconds < _SECONDS_PER_MINUTE:
        return "<1m"
    if seconds < 2 * _SECONDS_PER_HOUR:
        minutes = (seconds / _SECONDS_PER_MINUTE).quantize(
            Decimal(1), rounding=ROUND_HALF_UP
        )
        return f"{minutes}m"
    hours = (seconds / _SECONDS_PER_HOUR).quantize(Decimal(1), rounding=ROUND_HALF_UP)
    return f"{hours}h"


def _status_verification(item: dict[str, Any]) -> str:
    verification = item.get("verification")
    if not isinstance(verification, dict):
        return ""
    status = verification.get("status")
    rendered = _STATUS_VERIFICATIONS.get(str(status), "")
    if rendered != "mismatch":
        return rendered
    if verification.get("expected_role") is not None:
        return f"mismatch (role {verification.get('actual_role') or 'unknown'})"
    return f"mismatch ({verification.get('actual_account') or 'unknown'})"


_STATUS_SUMMARY_ORDER = [
    ("active", "🟢", "active"),
    ("expiring", "🟡", "expiring"),
    ("expired", "🔴", "expired"),
    ("drifted", "⚠️", "drifted"),
    ("legacy-unverified", "⚠️", "legacy-unverified"),
    ("missing", "❌", "missing"),
    ("invalid", "❌", "invalid"),
    ("logout-residue", "🧹", "logout-residue"),
    ("ecr-only", "🧹", "ECR-only"),
]


def _status_summary(sessions: Sequence[dict[str, Any]]) -> str:
    counts: dict[str, int] = {}
    unknown = 0
    known = {state for state, _symbol, _label in _STATUS_SUMMARY_ORDER}
    for item in sessions:
        state = str(item.get("state") or "")
        if state in known:
            counts[state] = counts.get(state, 0) + 1
        else:
            unknown += 1
    entries = [
        f"{counts[state]} {symbol}{label}"
        for state, symbol, label in _STATUS_SUMMARY_ORDER
        if counts.get(state)
    ]
    if unknown:
        entries.append(f"{unknown} ❔unknown/inconclusive")
    return _safe_terminal_text(f"State: {' | '.join(entries)}")


def _status_text(report: dict[str, Any]) -> str:
    sessions = report["sessions"]
    if not sessions:
        return "(none)"
    show_location = not all(item.get("location") == "default" for item in sessions)
    ttls = [_status_ttl(item) for item in sessions]
    show_ttl = any(ttls)
    verifications = [_status_verification(item) for item in sessions]
    show_verification = any(verifications)
    states = [_status_state(item) for item in sessions]
    auth = [_status_auth(item) for item in sessions]

    columns = ["PROFILE", "REGION", "STATE", "AUTH", "ACCOUNT", "SCOPE"]
    if show_location:
        columns.insert(0, "LOCATION")
    if show_ttl:
        columns.append("TTL")
    if show_verification:
        columns.append("VERIFY")

    rows = []
    for index, item in enumerate(sessions):
        row = [
            str(item.get("profile") or "default"),
            str(item.get("profile_region") or item.get("region") or ""),
            states[index][0],
            auth[index][0],
            str(item.get("target_account") or item.get("source_account") or ""),
            _status_scope(item),
        ]
        if show_location:
            row.insert(0, str(item.get("location") or item.get("destination") or ""))
        if show_ttl:
            row.append(ttls[index])
        if show_verification:
            row.append(verifications[index])
        rows.append(row)

    return f"{_text_table(columns, rows)}\n\n{_status_summary(sessions)}"


def _profile_list_text(report: dict[str, Any], *, wide: bool = False) -> str:
    columns = ["LOCATION", "PROFILE", "REGION", "STATE", "AUTH", "VERIFY"]
    if wide:
        columns.append("DIRECTORY")
    return _text_table(
        columns,
        [
            [
                item.get("location"),
                item["profile"],
                item.get("region"),
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
            ["NAME", "ID", "PARTITION", "REGION", "VERIFIED", "DESCRIPTION"],
            [
                [
                    name,
                    value.get("id"),
                    value.get("partition"),
                    value.get("region"),
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
            ["NAME", "ACCOUNT", "REGION", "SOURCE", "DESTINATION", "BOUNDARY"],
            [
                [
                    name,
                    value.get("source_account"),
                    value.get("region"),
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
                    ["aws.region", data.get("aws", {}).get("region")],
                    [
                        "aws.region-aliases",
                        len(data.get("aws", {}).get("region_aliases", {})),
                    ],
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
            if args.region:
                value["region"] = _regions.resolve_region(
                    args.region,
                    custom_aliases=data["aws"]["region_aliases"],
                    partition=partition,
                    allow_unknown=args.allow_unknown_region,
                ).canonical
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
            if args.region:
                _, source_account = _state.get_resource(
                    data, "account", args.source_account
                )
                value["region"] = _regions.resolve_region(
                    args.region,
                    custom_aliases=data["aws"]["region_aliases"],
                    partition=source_account["partition"],
                    allow_unknown=args.allow_unknown_region,
                ).canonical
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
        if kind == "account":
            _, item = _state.get_resource(data, kind, args.resource_name)
            if args.region:
                patch["region"] = _regions.resolve_region(
                    args.region,
                    custom_aliases=data["aws"]["region_aliases"],
                    partition=item["partition"],
                    allow_unknown=args.allow_unknown_region,
                ).canonical
            if args.clear_region:
                item.pop("region", None)
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
            if args.region:
                source_account_name = args.source_account or item["source_account"]
                _, source_account = _state.get_resource(
                    data, "account", source_account_name
                )
                patch["region"] = _regions.resolve_region(
                    args.region,
                    custom_aliases=data["aws"]["region_aliases"],
                    partition=source_account["partition"],
                    allow_unknown=args.allow_unknown_region,
                ).canonical
            if args.clear_region:
                item.pop("region", None)
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
    if args.profile_action == "region":
        action = args.profile_region_action
        if action == "get":
            value = _sessions.profile_region_get(args)
            message = (
                json.dumps(value, indent=2)
                if args.json
                else (
                    f"{value['location']}:{value['profile']} uses {value['region']}."
                    if value["region"]
                    else f"{value['location']}:{value['profile']} has no stored region."
                )
            )
            return _configs.Result(
                "PROFILE_REGION_GET", message, data=value, kind="info"
            )
        if action in {"set", "clear"}:
            value = _sessions.profile_region_change(args, clear=action == "clear")
            if args.json:
                message = json.dumps(value, indent=2)
            elif value["changed"]:
                verb = "Cleared" if action == "clear" else f"Set {value['region']} on"
                message = f"{verb} {value['location']}:{value['profile']}."
                if value["warnings"]:
                    message += "\nWarning: " + " ".join(value["warnings"])
            else:
                message = f"{value['location']}:{value['profile']} already " + (
                    "has no stored region."
                    if value["region"] is None
                    else f"uses {value['region']}."
                )
            return _configs.Result(
                f"PROFILE_REGION_{action.upper()}", message, data=value
            )
        _print_help(("profile", "region"))
        return _configs.Result(
            "PROFILE_REGION_HELP", "Choose a profile region action.", 2, "stderr"
        )
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


def _region_scope(
    data: dict[str, Any], args: argparse.Namespace
) -> tuple[str | None, str | None]:
    """Resolve optional partition/account filters for region discovery."""
    if getattr(args, "account", None):
        account_name, account = _state.get_resource(data, "account", args.account)
        return str(account["partition"]), account_name
    partition = getattr(args, "partition", None)
    known_partitions = {
        item.partition for item in _regions.region_registry(all_partitions=True)
    }
    if partition and partition not in known_partitions:
        raise _regions.RegionError(
            "REGION_PARTITION_UNKNOWN",
            f"Unknown AWS partition {partition!r}.",
            candidates=sorted(known_partitions),
        )
    return partition, None


def _region_record(
    info: _regions.RegionInfo,
    custom: dict[str, tuple[str, str | None]],
) -> dict[str, Any]:
    return {
        "region": info.name,
        "name": info.description,
        "partition": info.partition,
        "operational": info.operational,
        "compact": info.compact_alias,
        "geography": list(info.geography_aliases),
        "custom": sorted(
            alias for alias, (region, _) in custom.items() if region == info.name
        ),
    }


def _region_list_text(values: list[dict[str, Any]]) -> str:
    return _text_table(
        ["REGION", "NAME", "PARTITION", "COMPACT", "GEOGRAPHY", "CUSTOM"],
        [
            [
                item["region"],
                item["name"],
                item["partition"],
                item["compact"],
                ", ".join(item["geography"]),
                ", ".join(item["custom"]),
            ]
            for item in values
        ],
    )


def _alias_items(data: dict[str, Any]) -> dict[str, dict[str, str]]:
    return cast("dict[str, dict[str, str]]", data["aws"]["region_aliases"])


def _alias_key(aliases: dict[str, Any], name: str) -> str:
    normalized = _regions.normalize_alias(name)
    match = next((key for key in aliases if key.casefold() == normalized), None)
    if match is None:
        raise _regions.RegionError(
            "REGION_ALIAS_NOT_FOUND", f"Unknown custom region alias {name!r}."
        )
    return match


def _alias_list_text(values: list[dict[str, Any]]) -> str:
    return _text_table(
        ["ALIAS", "REGION", "NAME", "DESCRIPTION"],
        [
            [item["alias"], item["region"], item["name"], item.get("description")]
            for item in values
        ],
    )


def _run_region_alias(
    args: argparse.Namespace, data: dict[str, Any]
) -> _configs.Result:
    """Run custom alias CRUD while persisting canonical targets only."""
    action = args.region_alias_action
    if not action:
        _print_help(("region", "alias"))
        return _configs.Result(
            "REGION_ALIAS_HELP", "Choose a region alias action.", 2, "stderr"
        )
    aliases = _alias_items(data)
    custom = data["aws"]["region_aliases"]
    if action == "list":
        values = []
        for alias, item in sorted(aliases.items()):
            resolution = _regions.resolve_region(item["region"])
            record = {
                "alias": alias,
                "region": resolution.canonical,
                "name": resolution.description,
                **(
                    {"description": item["description"]}
                    if item.get("description")
                    else {}
                ),
            }
            if not args.patterns or any(
                fnmatch.fnmatchcase(candidate.casefold(), pattern.casefold())
                for pattern in args.patterns
                for candidate in (
                    alias,
                    resolution.canonical,
                    resolution.description,
                    item.get("description", ""),
                )
            ):
                values.append(record)
        return _configs.Result(
            "REGION_ALIAS_LIST",
            json.dumps(values, indent=2) if args.json else _alias_list_text(values),
            data=values,
        )
    if action == "get":
        key = _alias_key(aliases, args.alias)
        item = aliases[key]
        resolution = _regions.resolve_region(item["region"])
        value = {
            "alias": key,
            "region": resolution.canonical,
            "name": resolution.description,
            **({"description": item["description"]} if item.get("description") else {}),
        }
        return _configs.Result(
            "REGION_ALIAS_GET",
            json.dumps(value, indent=2) if args.json else _alias_list_text([value]),
            data=value,
        )
    if action == "remove":
        key = _alias_key(aliases, args.alias)
        del aliases[key]
        _state.save_config(data)
        return _configs.Result(
            "REGION_ALIAS_REMOVE",
            f"Removed region alias {key}; canonical stored regions are unchanged.",
            data={"alias": key, "consumersChanged": False},
        )
    if action == "rename":
        key = _alias_key(aliases, args.alias)
        new_name = _regions.normalize_alias(args.new_alias)
        if new_name != args.new_alias:
            raise _regions.RegionError(
                "REGION_ALIAS_INVALID",
                f"Custom aliases use lower kebab case; try {new_name!r}.",
            )
        if any(existing.casefold() == new_name for existing in aliases):
            raise _regions.RegionError(
                "REGION_ALIAS_CONFLICT", f"Region alias {new_name!r} already exists."
            )
        aliases[new_name] = aliases.pop(key)
        _state.save_config(data)
        return _configs.Result(
            "REGION_ALIAS_RENAME",
            f"Renamed region alias {key} to {new_name}; canonical consumers are unchanged.",
        )
    name = _regions.normalize_alias(args.alias)
    if name != args.alias:
        raise _regions.RegionError(
            "REGION_ALIAS_INVALID",
            f"Custom aliases use lower kebab case; try {name!r}.",
        )
    if action == "add" and any(key.casefold() == name for key in aliases):
        raise _regions.RegionError(
            "REGION_ALIAS_CONFLICT", f"Region alias {name!r} already exists."
        )
    key = name if action == "add" else _alias_key(aliases, name)
    existing = aliases.get(key, {})
    region_input = args.region if action == "add" else args.region or existing["region"]
    resolution = _regions.resolve_region(region_input, custom_aliases=custom)
    value = {"region": resolution.canonical}
    description = getattr(args, "description", None)
    if description is not None:
        value["description"] = description
    elif existing.get("description") and not getattr(args, "clear_description", False):
        value["description"] = existing["description"]
    aliases[key] = value
    _state.save_config(data)
    return _configs.Result(
        "REGION_ALIAS_SAVED",
        f"Saved region alias {key} as {resolution.canonical} ({resolution.description}).",
        data={"alias": key, **value, "name": resolution.description},
    )


def _run_region(args: argparse.Namespace) -> _configs.Result:
    """Discover canonical regions or manage global custom aliases."""
    data = _state.load_config()
    if args.region_action == "alias":
        return _run_region_alias(args, data)
    if args.region_action not in {"list", "explain"}:
        _print_help(("region",))
        return _configs.Result("REGION_HELP", "Choose a region action.", 2, "stderr")
    partition, account_name = _region_scope(data, args)
    aliases = data["aws"]["region_aliases"]
    if args.region_action == "explain":
        resolution = _regions.resolve_region(
            args.region,
            custom_aliases=aliases,
            partition=partition,
            allow_unknown=args.allow_unknown_region,
            allow_non_operational=args.all_partitions,
        )
        value = {
            "input": resolution.input,
            "region": resolution.canonical,
            "name": resolution.description,
            "partition": resolution.partition,
            "operational": resolution.operational,
            "known": resolution.known,
            "matchedBy": resolution.source,
            "matchedAlias": resolution.matched_alias,
            "account": account_name,
            "storedAs": resolution.canonical,
            "warning": resolution.warning,
        }
        text = "\n".join(
            f"{label}: {value[key] or '-'}"
            for key, label in (
                ("input", "Input"),
                ("region", "Canonical region"),
                ("name", "Name"),
                ("partition", "Partition"),
                ("matchedBy", "Matched by"),
                ("storedAs", "Configuration stores"),
                ("warning", "Warning"),
            )
        )
        return _configs.Result(
            "REGION_EXPLAIN",
            json.dumps(value, indent=2) if args.json else text,
            data=value,
        )
    custom = _regions.custom_alias_map(aliases)
    values = []
    for info in _regions.region_registry(all_partitions=args.all_partitions):
        if partition and info.partition != partition:
            continue
        item = _region_record(info, custom)
        candidates = (
            item["region"],
            item["name"],
            item["partition"],
            item["compact"] or "",
            *item["geography"],
            *item["custom"],
        )
        if args.patterns and not any(
            fnmatch.fnmatchcase(str(candidate).casefold(), pattern.casefold())
            for pattern in args.patterns
            for candidate in candidates
        ):
            continue
        values.append(item)
    return _configs.Result(
        "REGION_LIST",
        json.dumps(values, indent=2) if args.json else _region_list_text(values),
        data=values,
    )


def _canonical_config_region(
    data: dict[str, Any], key: str, value: object, *, allow_unknown: bool
) -> object:
    """Resolve region-bearing config values before schema persistence."""
    if type(value) is not str:
        return value
    parts = key.split(".")
    option_shape = tuple(parts)
    partition = None
    if option_shape[:1] == ("accounts",) and option_shape[2:] == ("region",):
        _, account = _state.get_resource(data, "account", parts[1])
        partition = account["partition"]
    elif option_shape[:1] == ("targets",) and option_shape[2:] == ("region",):
        _, target = _state.get_resource(data, "target", parts[1])
        _, account = _state.get_resource(data, "account", target["source_account"])
        partition = account["partition"]
    is_region = key == "aws.region" or (
        option_shape[:1] in {("accounts",), ("targets",)}
        and option_shape[2:] == ("region",)
    )
    is_alias_region = option_shape[:2] == ("aws", "region_aliases") and option_shape[
        3:
    ] == ("region",)
    if not (is_region or is_alias_region):
        return value
    return _regions.resolve_region(
        value,
        custom_aliases=data["aws"]["region_aliases"],
        partition=partition,
        allow_unknown=allow_unknown and not is_alias_region,
    ).canonical


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
            nested_set_value = _canonical_config_region(
                data,
                args.key,
                nested_set_value,
                allow_unknown=args.allow_unknown_region,
            )
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
            direct_option_value = _canonical_config_region(
                data,
                args.key,
                direct_option_value,
                allow_unknown=args.allow_unknown_region,
            )
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


_HISTORY_OUTCOMES = {
    "success": ("✓", "success"),
    "usage-error": ("?", "usage error"),
    "policy-refusal": ("⊘", "policy refusal"),
    "cancelled": ("○", "cancelled"),
    "operational-error": ("!", "operational error"),
    "interrupted": ("↯", "interrupted"),
    "crashed": ("X", "crashed/abandoned"),
}


def _history_records(args: argparse.Namespace) -> list[dict[str, object]]:
    return _history.list_records(
        patterns=tuple(getattr(args, "patterns", ()) or ()),
        since=_history.parse_time(args.since) if getattr(args, "since", None) else None,
        until=(
            _history.parse_time(args.until) if getattr(args, "until", None) else None
        ),
        command=getattr(args, "command", None),
        outcome=getattr(args, "outcome", None),
        account=getattr(args, "account", None),
        resource=getattr(args, "resource", None),
        limit=getattr(args, "limit", 50),
        include_running=bool(getattr(args, "include_running", False)),
    )


def _history_list_text(records: list[dict[str, object]], *, wide: bool = False) -> str:
    columns = ["ID", "STARTED", "S", "COMMAND", "PROFILE"]
    if wide:
        columns.extend(("ACCOUNT", "RESOURCE", "RESULT", "MS"))
    rows: list[list[object]] = []
    used_symbols: set[str] = set()
    for record in records:
        outcome = str(record.get("outcome") or "")
        symbol = _HISTORY_OUTCOMES.get(outcome, ("…", "running/unknown"))[0]
        used_symbols.add(symbol)
        row: list[object] = [
            str(record["id"])[:8],
            str(record.get("startedAt") or "-").replace("T", " ")[:19],
            symbol,
            record.get("command"),
            record.get("profile"),
        ]
        if wide:
            row.extend(
                (
                    record.get("accountId"),
                    record.get("resourceName") or record.get("resourceArn"),
                    record.get("resultCode"),
                    record.get("durationMs"),
                )
            )
        rows.append(row)
    table = _text_table(columns, rows)
    if not rows:
        return table
    meanings = [
        (symbol, meaning)
        for outcome, (symbol, meaning) in _HISTORY_OUTCOMES.items()
        if symbol in used_symbols and outcome
    ]
    if "…" in used_symbols:
        meanings.append(("…", "running/unknown"))
    return f"{table}\n\nKey: " + "  ".join(
        f"{symbol} {meaning}" for symbol, meaning in meanings
    )


def _history_show_text(record: dict[str, object]) -> str:
    lines = [
        f"History ID: {record['id']}",
        f"Command: {record['command']}",
        f"Safe template: {_history.command_template(record)}",
        f"Outcome: {record.get('outcome') or record.get('state')}",
        f"Result: {record.get('resultCode') or '-'} (exit {record.get('exitCode')})",
        f"Started: {record.get('startedAt')}",
        f"Ended: {record.get('endedAt') or '-'}",
        f"Duration: {record.get('durationMs') or 0} ms",
        f"Confirmation: {record.get('confirmation')}",
    ]
    context = [
        f"{label}={record.get(key)}"
        for key, label in (
            ("accountId", "account"),
            ("location", "location"),
            ("profile", "profile"),
            ("target", "target"),
            ("resourceName", "resource"),
            ("resourceArn", "arn"),
        )
        if record.get(key)
    ]
    if context:
        lines.append("Context: " + ", ".join(context))
    safe = record.get("safe")
    if isinstance(safe, dict):
        input_kinds = safe.get("inputKinds")
        if isinstance(input_kinds, list) and input_kinds:
            lines.append(
                "Inputs: "
                + ", ".join(
                    f"{item.get('role')} ({item.get('format')})"
                    for item in input_kinds
                    if isinstance(item, dict)
                )
            )
        secret_presence = safe.get("secretPresence")
        if isinstance(secret_presence, dict) and any(secret_presence.values()):
            present = [
                name
                for key, name in (
                    ("mfaCode", "MFA code"),
                    ("externalId", "external ID"),
                )
                if secret_presence.get(key) is True
            ]
            lines.append(
                "Secret inputs supplied (values never stored): " + ", ".join(present)
            )
    if record.get("recoveryUnresolved") is True:
        lines.append("Recovery: unresolved; retention and clear preserve this record.")
    return "\n".join(lines)


def _history_report(records: list[dict[str, object]]) -> dict[str, object]:
    outcomes: dict[str, int] = {}
    commands: dict[str, int] = {}
    duration = 0
    for record in records:
        outcome = str(record.get("outcome") or record.get("state") or "unknown")
        command = str(record.get("command") or "unknown")
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
        commands[command] = commands.get(command, 0) + 1
        value = record.get("durationMs")
        if type(value) is int:
            duration += value
    return {
        "count": len(records),
        "durationMs": duration,
        "outcomes": dict(sorted(outcomes.items())),
        "commands": dict(sorted(commands.items())),
    }


def _history_report_text(report: dict[str, object]) -> str:
    outcomes = cast("dict[str, int]", report["outcomes"])
    commands = cast("dict[str, int]", report["commands"])
    return "\n\n".join(
        (
            f"Commands: {report['count']}  Total duration: {report['durationMs']} ms",
            "Outcomes\n" + _text_table(("OUTCOME", "COUNT"), list(outcomes.items())),
            "Command families\n"
            + _text_table(("COMMAND", "COUNT"), list(commands.items())),
        )
    )


def _history_status_text(report: dict[str, object]) -> str:
    retention = cast("dict[str, object]", report["retention"])
    return "\n".join(
        (
            f"History database: {report['database']}",
            f"Health: {report['integrity']}",
            f"Records: {report['count']} ({report['running']} running)",
            f"Logical size: {report['logicalBytes']} bytes",
            f"Range: {report['oldest'] or '-'} to {report['newest'] or '-'}",
            (
                "Retention: "
                f"{retention['max_age']}s, {retention['max_entries']} entries, "
                f"{retention['max_bytes']} bytes; "
                f"recording {'enabled' if retention['enabled'] else 'disabled'}"
            ),
        )
    )


def _run_history(args: argparse.Namespace) -> _configs.Result:
    action = args.history_action
    if action in {"list", "search"}:
        records = _history_records(args)
        return _configs.Result(
            "HISTORY_LIST" if action == "list" else "HISTORY_SEARCH",
            _history_list_text(records, wide=args.wide),
            data={"count": len(records), "records": records},
            kind="info",
        )
    if action == "show":
        record = _history.get_record(args.history_id)
        return _configs.Result(
            "HISTORY_SHOW", _history_show_text(record), data=record, kind="info"
        )
    if action == "report":
        report = _history_report(_history_records(args))
        return _configs.Result(
            "HISTORY_REPORT", _history_report_text(report), data=report, kind="info"
        )
    if action == "export":
        records = _history_records(args)
        encoded = _history.export_records(records, format_name=args.format)
        if args.output:
            destination = Path(args.output).expanduser().absolute()
            _state.atomic_write(destination, encoded.encode("utf-8"))
            return _configs.Result(
                "HISTORY_EXPORT",
                f"Exported {len(records)} safe history records to {destination}.",
                data={
                    "count": len(records),
                    "format": args.format,
                    "output": str(destination),
                },
            )
        return _configs.Result(
            "HISTORY_EXPORT",
            encoded.rstrip("\n"),
            data={"count": len(records), "format": args.format, "records": records},
            kind="info",
        )
    if action == "status":
        report = _history.status()
        return _configs.Result(
            "HISTORY_STATUS", _history_status_text(report), data=report, kind="info"
        )
    if action == "check":
        report = _history.check()
        return _configs.Result(
            "HISTORY_CHECK_OK" if report["ok"] else "HISTORY_CHECK_FAILED",
            (
                "History database and safe records are valid."
                if report["ok"]
                else f"History check found {report['corruptRecords']} corrupt records."
            ),
            0 if report["ok"] else 1,
            data=report,
            kind="success" if report["ok"] else "error",
        )
    if action == "clear":
        before = _history.parse_time(args.before) if args.before else None
        plan = _history.clear(before=before, all_records=args.all, apply=False)
        if args.dry_run or plan["count"] == 0:
            return _configs.Result(
                "HISTORY_CLEAR_PLAN",
                f"Would remove {plan['count']} eligible safe history records; no changes made.",
                data=plan,
                kind="info",
            )
        if args.yes:
            _history.note_confirmation("yes-flag", "bypassed")
        elif bool(getattr(args, "json", False)) or not sys.stdin.isatty():
            _history.note_confirmation("exact-yes", "unavailable")
            return _configs.Result(
                "CONFIRMATION_REQUIRED",
                "History clear requires an interactive exact 'yes' or --yes.",
                _configs.EXIT_CANCELLED,
                "stderr",
                data=plan,
            )
        else:
            answer = input(
                f"History clear plan: remove {plan['count']} eligible records "
                f"({plan['logicalBytes']} logical bytes).\n"
                "Running commands and unresolved recovery records are preserved.\n"
                "Type 'yes' exactly to continue: "
            )
            accepted = answer.strip() == "yes"
            _history.note_confirmation(
                "exact-yes", "accepted" if accepted else "declined"
            )
            if not accepted:
                return _configs.Result(
                    "HISTORY_CLEAR_CANCELLED",
                    "History clear cancelled; no records were removed.",
                    _configs.EXIT_CANCELLED,
                    "stderr",
                    data=plan,
                )
        applied = _history.clear(before=before, all_records=args.all, apply=True)
        return _configs.Result(
            "HISTORY_CLEAR",
            f"Removed {applied['count']} eligible safe history records.",
            data=applied,
        )
    _print_help(("history",))
    return _configs.Result(
        "HISTORY_HELP", "Choose a history action.", _configs.EXIT_USAGE, "stderr"
    )


def _console_main_invocation(
    arguments: Sequence[str] | None = None,
    *,
    history_handle: _history.HistoryHandle | None = None,
) -> _configs.Result:
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
    if (
        namespace.access_type == "mfa"
        and namespace.action in {"login", "in"}
        and namespace.target
        and namespace.profile
        and namespace.mfa_code is None
    ):
        namespace.mfa_code = namespace.profile
        namespace.profile = None
    if namespace.access_type == "mfa" and namespace.action in {"login", "in"}:
        missing_code = namespace.mfa_code is None and not bool(
            getattr(namespace, "mfa_code_stdin", False)
        )
        missing_source = namespace.profile is None and not namespace.target
        if missing_source or (missing_code and (use_json or not sys.stdin.isatty())):
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
    if history_handle is not None:
        _history.enrich(history_handle, namespace)
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
            elif namespace.access_type == "assume":
                result = _run_assume(_configs.Context(args=namespace))
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
            elif namespace.access_type == "region":
                result = _run_region(namespace)
            elif namespace.access_type == "policy":
                result = _run_policy(namespace)
            elif namespace.access_type == "cache":
                result = _run_cache(namespace)
            elif namespace.access_type == "history":
                result = _run_history(namespace)
            else:
                result = _run_config(namespace)
    except _configs.OperationalError as error:
        result = _configs.Result(
            getattr(error, "code", "OPERATIONAL_ERROR"),
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
    raw_arguments = list(sys.argv[1:] if arguments is None else arguments)
    history_handle = _history.begin(
        json_mode=_json_requested(raw_arguments), interactive=sys.stdin.isatty()
    )
    _configs.configure_output()
    try:
        result = _console_main_invocation(raw_arguments, history_handle=history_handle)
    except BaseException as error:
        _history.fail(history_handle, error)
        raise
    else:
        _history.finish(history_handle, result)
        return result
    finally:
        _configs.configure_output()
