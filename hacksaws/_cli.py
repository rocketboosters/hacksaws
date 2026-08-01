"""Hacksaws command-line parsing and orchestration."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
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
from hacksaws import _policies
from hacksaws import _sessions
from hacksaws import _state

if TYPE_CHECKING:
    from collections.abc import Sequence


def _duration_arguments(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--duration", "--ttl")
    group.add_argument("--htl")
    group.add_argument("--mtl")
    group.add_argument("--stl")


def _ecr_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--ecr", action="store_true")
    parser.add_argument("--podman", action="store_true")
    parser.add_argument("--ecr-region", action="append")


def _login_arguments(parser: argparse.ArgumentParser, *, browser: bool = False) -> None:
    parser.add_argument("profile", nargs="?")
    if not browser:
        parser.add_argument("mfa_code", nargs="?")
        parser.add_argument("-l", "--lifespan", type=int, default=43200)
    parser.add_argument("--target")
    parser.add_argument(
        "-d", "--dir", "--directory", dest="directory", default="~/.aws"
    )
    parser.add_argument("-n", "--name", "--account-name", dest="aws_account_name")
    parser.add_argument("--to")
    parser.add_argument("--to-directory")
    parser.add_argument("--to-profile")
    parser.add_argument("--boundary", "--as", dest="boundary")
    parser.add_argument("--role")
    parser.add_argument("--policy")
    parser.add_argument("--external-id")
    parser.add_argument("--account")
    parser.add_argument("--session-name")
    parser.add_argument("--region")
    _duration_arguments(parser)
    _ecr_arguments(parser)
    if browser:
        parser.add_argument("--remote", action="store_true")


def _logout_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("profile", nargs="?", default="default")
    parser.add_argument("--target")
    parser.add_argument(
        "-d", "--dir", "--directory", dest="directory", default="~/.aws"
    )
    parser.add_argument("-n", "--name", "--account-name", dest="aws_account_name")
    _ecr_arguments(parser)


def _credential_selector(parser: argparse.ArgumentParser) -> None:
    selector = parser.add_mutually_exclusive_group()
    selector.add_argument("--profile", "--name", dest="profile", default="default")
    selector.add_argument("--target")
    parser.add_argument("--no-verify", action="store_true")


def _resource_parser(
    parent: argparse._SubParsersAction[argparse.ArgumentParser], kind: str
) -> None:
    parser = parent.add_parser(kind)
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
        update.add_argument("--profile", "--name", dest="profile", default="default")
        update.add_argument("--no-verify", action="store_true")
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
    parser = argparse.ArgumentParser(
        prog="hacksaws",
        description="Secure AWS login and boundary manager.",
        allow_abbrev=False,
    )
    types = parser.add_subparsers(dest="access_type")

    mfa = types.add_parser("mfa")
    mfa_actions = mfa.add_subparsers(dest="action")
    mfa_login = mfa_actions.add_parser("login", aliases=["in"])
    _login_arguments(mfa_login)
    mfa_logout = mfa_actions.add_parser("logout", aliases=["out"])
    _logout_arguments(mfa_logout)

    for auth_name in ("pk", "web"):
        auth = types.add_parser(auth_name)
        actions = auth.add_subparsers(dest="action")
        login = actions.add_parser("login", aliases=["in"])
        _login_arguments(login, browser=True)
        logout = actions.add_parser("logout", aliases=["out"])
        _logout_arguments(logout)

    logout = types.add_parser("logout")
    _logout_arguments(logout)
    status = types.add_parser("status")
    status.add_argument("--json", action="store_true")

    for kind in ("account", "boundary", "target"):
        _resource_parser(types, kind)

    policy = types.add_parser("policy")
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

    cache = types.add_parser("cache")
    cache_actions = cache.add_subparsers(dest="cache_action")
    cache_get = cache_actions.add_parser("get")
    cache_get.add_argument("setting", nargs="?", choices=("max-age",))
    cache_get.add_argument("--json", action="store_true")
    cache_set = cache_actions.add_parser("set")
    cache_set.add_argument("setting", choices=("max-age",))
    cache_set.add_argument("value")
    cache_clear = cache_actions.add_parser("clear")
    cache_clear.add_argument("--yes", action="store_true")

    config = types.add_parser("config")
    config_actions = config.add_subparsers(dest="config_action")
    show = config_actions.add_parser("show")
    show.add_argument("--account")
    show.add_argument("--json", action="store_true")
    explain = config_actions.add_parser("explain")
    explain.add_argument("target")
    explain.add_argument("--json", action="store_true")
    check = config_actions.add_parser("check")
    check.add_argument("--remote", action="store_true")
    check.add_argument("--probe", action="store_true")
    check.add_argument("--account")
    check.add_argument("--json", action="store_true")
    _credential_selector(check)
    fix = config_actions.add_parser("fix")
    fix.add_argument("--account")
    fix.add_argument("--yes", action="store_true")
    export = config_actions.add_parser("export")
    export.add_argument("zip", nargs="?")
    imported = config_actions.add_parser("import")
    imported.add_argument("zip")
    imported.add_argument("--replace", action="store_true")
    imported.add_argument("--yes", action="store_true")
    return parser


def _print_help(command: Sequence[str] = ()) -> None:
    try:
        _create_parser().parse_args([*command, "--help"])
    except SystemExit:
        return


def _validate_login(namespace: argparse.Namespace) -> None:
    if getattr(namespace, "profile", None) and namespace.profile.startswith("+"):
        if getattr(namespace, "target", None):
            raise _configs.OperationalError("Specify a target only once.")
        namespace.target = namespace.profile
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
    if context.args.profile.startswith("+") and not context.args.target:
        context.args.target = context.args.profile
        context.args.profile = "default"
    _sessions.recover_journal()
    if _sessions.logout(context):
        return _configs.Result("LOGOUT", f"Logged out of profile {context.profile}")
    os.environ["AWS_SHARED_CREDENTIALS_FILE"] = str(context.credentials_path)
    os.environ["AWS_CONFIG_FILE"] = str(context.config_path)
    _aws.logout(context)
    return _configs.Result("MFA_LOGOUT", f"Logged out of profile {context.profile}")


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
                    caller_id, caller_partition, _ = _sessions._identity(
                        boto3.Session(profile_name=args.profile),
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
                    response = (
                        boto3.Session(profile_name=args.profile)
                        .client("iam")
                        .get_role(RoleName=role_name)
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
                        role = (
                            boto3.Session(profile_name=args.profile)
                            .client("iam")
                            .get_role(RoleName=role_name)["Role"]["Arn"]
                        )
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
    if args.cache_action == "clear":
        shutil.rmtree(_policies.cache_root(), ignore_errors=True)
        return _configs.Result("CACHE_CLEAR", "Policy cache cleared.")
    if args.cache_action == "get":
        entries = (
            list(_policies.cache_root().glob("*.json"))
            if _policies.cache_root().exists()
            else []
        )
        value = {"max_age": data["cache"]["max_age"], "entries": len(entries)}
        return _configs.Result("CACHE_GET", _json_or_text(value, args.json))
    _print_help(("cache",))
    return _configs.Result("CACHE_HELP", "Choose a cache action.", 2, "stderr")


def _run_config(args: argparse.Namespace) -> _configs.Result:
    action = args.config_action
    if action == "show":
        data = _state.load_config()
        if args.account:
            key, account = _state.get_resource(data, "account", args.account)
            data = {
                "account": {"name": key, **account},
                "boundaries": {
                    k: v
                    for k, v in data["boundaries"].items()
                    if str(v["account"]).casefold() == key.casefold()
                },
                "targets": data["targets"],
            }
        return _configs.Result("CONFIG_SHOW", _json_or_text(data, args.json))
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


def console_main(arguments: Sequence[str] | None = None) -> _configs.Result:
    parser = _create_parser()
    try:
        namespace = parser.parse_args(arguments)
    except SystemExit as error:
        return _configs.Result(
            "HELP" if error.code == 0 else "ARGUMENT_ERROR", "", cast("int", error.code)
        )
    if not namespace.access_type:
        _print_help()
        return _configs.Result(
            "ACCESS_TYPE_HELP", "Not enough arguments.", 2, "stderr"
        ).echo()
    if namespace.access_type == "mfa" and namespace.action in {"login", "in"}:
        if namespace.target and namespace.profile and namespace.mfa_code is None:
            namespace.mfa_code = namespace.profile
            namespace.profile = None
        if namespace.mfa_code is None:
            parser.print_usage(sys.stderr)
            return _configs.Result(
                "ARGUMENT_ERROR",
                "the following arguments are required: PROFILE CODE or +TARGET CODE.",
                2,
                "stderr",
            ).echo()
    try:
        _sessions.recover_journal()
        if namespace.access_type == "mfa":
            result = _run_mfa(_configs.Context(args=namespace))
        elif namespace.access_type in {"pk", "web"}:
            result = _run_browser(_configs.Context(args=namespace))
        elif namespace.access_type == "logout":
            result = _run_logout(_configs.Context(args=namespace))
        elif namespace.access_type == "status":
            result = _configs.Result(
                "STATUS", _json_or_text(_sessions.status(), namespace.json)
            )
        elif namespace.access_type in {"account", "boundary", "target"}:
            result = _run_resource(namespace)
        elif namespace.access_type == "policy":
            result = _run_policy(namespace)
        elif namespace.access_type == "cache":
            result = _run_cache(namespace)
        else:
            result = _run_config(namespace)
    except _configs.OperationalError as error:
        return _configs.Result(
            "OPERATIONAL_ERROR", f"Error: {error}", 1, "stderr"
        ).echo()
    return result.echo()
