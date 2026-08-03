"""Shared IAM CLI parser, credential context, and leaf-adapter contract."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from typing import Any
from typing import Protocol
from typing import cast

import boto3
from botocore.exceptions import BotoCoreError
from botocore.exceptions import ClientError

from hacksaws import _configs
from hacksaws import _iam_cleanup
from hacksaws import _iam_policy_cli
from hacksaws import _iam_recovery
from hacksaws import _iam_role_cli
from hacksaws import _output
from hacksaws import _regions
from hacksaws import _state

if TYPE_CHECKING:
    from collections.abc import Callable
    from collections.abc import Iterator
    from collections.abc import Mapping


class IamAdapter(Protocol):
    """A leaf module that contributes a parser and dispatch implementation."""

    name: str

    def register(self, parser: argparse.ArgumentParser) -> None:
        """Register leaf subcommands below the supplied IAM command parser."""

    def dispatch(
        self, args: argparse.Namespace, context: IamCommandContext
    ) -> _configs.Result | None:
        """Handle a parsed leaf, returning ``None`` when it does not own it."""


_adapters: list[IamAdapter] = []
_CREDENTIAL_ENVIRONMENT_KEYS = (
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_ROLE_ARN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "AWS_EC2_METADATA_DISABLED",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_ENDPOINT_URL",
    "AWS_ENDPOINT_URL_STS",
    "AWS_ENDPOINT_URL_IAM",
    "AWS_ENDPOINT_URL_ACCESSANALYZER",
    "AWS_ENDPOINT_URL_ACCESS_ANALYZER",
)


def _ensure_builtin_adapters() -> None:
    """Register bundled parser adapters exactly once at parser construction time."""
    for adapter in (_iam_policy_cli, _iam_role_cli):
        if not any(existing.name == adapter.name for existing in _adapters):
            register_adapter(adapter)


def register_adapter(adapter: IamAdapter) -> None:
    """Register one policy/role adapter exactly once for parser and dispatch wiring."""
    if any(existing.name == adapter.name for existing in _adapters):
        raise ValueError(adapter.name)
    _adapters.append(adapter)


def clear_adapters() -> None:
    """Clear adapters for isolated tests; production integrations register once."""
    _adapters.clear()


def add_selector_arguments(
    parser: argparse.ArgumentParser,
    *,
    root: bool = False,
    mutation: bool = False,
) -> None:
    """Add common IAM selectors without child defaults clobbering parent options."""
    fallback: object = None if root else argparse.SUPPRESS
    credentials = parser.add_argument_group("credential selection")
    credentials.add_argument(
        "--profile",
        default="default" if root else argparse.SUPPRESS,
        metavar="PROFILE",
        help="AWS profile to use (default: default).",
    )
    credentials.add_argument(
        "--location",
        default="default" if root else argparse.SUPPRESS,
        metavar="NAME",
        help="Named AWS directory such as horizon (default: default).",
    )
    credentials.add_argument(
        "-d",
        "--directory",
        default=fallback,
        metavar="PATH",
        help="Explicit AWS config directory; cannot be combined with --location.",
    )
    credentials.add_argument(
        "--target",
        default=fallback,
        metavar="NAME",
        help=(
            "Saved target supplying credentials; cannot be overridden by source "
            "selectors."
        ),
    )
    credentials.add_argument(
        "--account",
        default=fallback,
        metavar="NAME_OR_ID",
        help="Require the selected credentials to identify this configured account.",
    )
    credentials.add_argument(
        "--region",
        default=fallback,
        metavar="REGION",
        help="AWS region used for regional clients and console links.",
    )
    credentials.add_argument(
        "--allow-unknown-region",
        action="store_true",
        default=False if root else argparse.SUPPRESS,
        help=(
            "Allow an exact canonical region absent from bundled Botocore metadata; "
            "aliases never bypass validation."
        ),
    )
    if mutation:
        safety = parser.add_argument_group("safety")
        safety.add_argument(
            "--dry-run",
            action="store_true",
            default=False if root else argparse.SUPPRESS,
            help=(
                "Resolve, validate, and show the plan without changing AWS or "
                "local state."
            ),
        )
        safety.add_argument(
            "--yes",
            action="store_true",
            default=False if root else argparse.SUPPRESS,
            help="Approve the displayed plan without an interactive prompt.",
        )


def _selector_arguments(parser: argparse.ArgumentParser, *, root: bool = False) -> None:
    """Backward-compatible internal spelling for common selectors."""
    add_selector_arguments(parser, root=root)


_SELECTOR_SPELLINGS = {
    "profile": ("--profile",),
    "location": ("--location",),
    "directory": ("-d", "--directory"),
    "target": ("--target",),
    "account": ("--account",),
    "region": ("--region",),
    "allow_unknown_region": ("--allow-unknown-region",),
    "yes": ("--yes",),
    "dry_run": ("--dry-run",),
}


def validate_selector_arguments(arguments: list[str]) -> None:
    """Reject duplicated and contradictory IAM selectors before argparse merges them."""
    if not arguments or arguments[0] not in {
        "iam",
        "remote",
        "cleanup",
        "account",
        "boundary",
        "config",
    }:
        return
    found: dict[str, str] = {}
    for token in arguments[1:]:
        option = token.partition("=")[0]
        for logical, spellings in _SELECTOR_SPELLINGS.items():
            if option not in spellings:
                continue
            if logical in found:
                raise _configs.OperationalError(
                    f"{option} duplicates {found[logical]}; specify "
                    f"{logical.replace('_', '-')} only once."
                )
            found[logical] = option
            break
    if "location" in found and "directory" in found:
        raise _configs.OperationalError(
            "--location and --directory select the same AWS folder; specify only one."
        )
    if "target" in found:
        conflicts = [
            found[key] for key in ("profile", "location", "directory") if key in found
        ]
        if conflicts:
            raise _configs.OperationalError(
                "--target supplies its own credential source and cannot be combined "
                "with "
                + ", ".join(conflicts)
                + ". --account may be combined with --target as an identity assertion."
            )


def register_parser(
    parent: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register canonical ``iam`` and exact ``remote`` alias command trees."""
    _ensure_builtin_adapters()
    iam = parent.add_parser(
        "iam", aliases=["remote"], help="Manage remote IAM resources."
    )
    _selector_arguments(iam, root=True)
    actions = iam.add_subparsers(dest="iam_action")
    for name, aliases, help_text in (
        ("policy", ["policies"], "Managed-policy operations."),
        ("role", ["roles"], "IAM role operations."),
    ):
        command = actions.add_parser(name, aliases=aliases, help=help_text)
        _selector_arguments(command)
        for adapter in _adapters:
            if adapter.name == name:
                adapter.register(command)
    inventory = actions.add_parser(
        "list",
        help="List Hacksaws-owned IAM roles, policies, and group grants.",
        description=(
            "Inventory live-tag-verified IAM resources in one verified AWS account. "
            "The default fast scan uses canonical /hacksaws/ paths; use "
            "--all-account for a comprehensive supported-resource scan."
        ),
    )
    _selector_arguments(inventory)
    _inventory_arguments(inventory)
    cleanup = actions.add_parser(
        "cleanup",
        help="Plan or remove selected Hacksaws-owned IAM resources.",
        description=(
            "Perform account-scoped, dependency-ordered Leave No Trace cleanup."
        ),
    )
    add_selector_arguments(cleanup, mutation=True)
    _cleanup_arguments(cleanup)
    recovery = actions.add_parser(
        "recovery",
        aliases=["recover"],
        help="Inspect or recover an interrupted transaction.",
    )
    _selector_arguments(recovery)
    recovery.add_argument(
        "recovery_action", choices=("list", "get", "continue", "rollback")
    )
    recovery.add_argument("journal_id", nargs="?")


def register_root_cleanup_parser(
    parent: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register the canonical top-level cleanup command."""
    parser = parent.add_parser(
        "cleanup",
        help="Remove selected Hacksaws-owned IAM resources from one AWS account.",
        description=(
            "Plan and execute dependency-ordered Leave No Trace cleanup. A pattern, "
            "--all, --smoke, or --smoke-run is required."
        ),
    )
    parser.set_defaults(iam_action="cleanup")
    add_selector_arguments(parser, root=True, mutation=True)
    _cleanup_arguments(parser)


def _resource_filters(parser: argparse.ArgumentParser) -> None:
    resources = parser.add_argument_group("resource selection")
    resources.add_argument(
        "patterns",
        nargs="*",
        metavar="PATTERN",
        help=(
            "Case-insensitive fnmatch pattern matched against names and ARNs; "
            "multiple patterns are ORed."
        ),
    )
    resources.add_argument("--roles", action="store_true", help="Include IAM roles.")
    resources.add_argument(
        "--policies", action="store_true", help="Include customer-managed policies."
    )
    resources.add_argument(
        "--group-grants",
        action="store_true",
        help="Include Hacksaws-managed group assume-role grants.",
    )
    resources.add_argument(
        "--created", action="store_true", help="Include resources created by Hacksaws."
    )
    resources.add_argument(
        "--adopted",
        action="store_true",
        help="Include resources explicitly adopted by Hacksaws.",
    )
    resources.add_argument(
        "--legacy",
        action="store_true",
        help=(
            "Include safely identified Hacksaws resources created before origin "
            "tracking. Cleanup excludes them unless this selector is explicit."
        ),
    )
    resources.add_argument(
        "--smoke",
        action="store_true",
        help="Restrict selection to tagged smoke-test resources.",
    )
    resources.add_argument(
        "--smoke-run",
        metavar="RUN_ID",
        help="Restrict selection to one tagged smoke-test run.",
    )


def _inventory_arguments(parser: argparse.ArgumentParser) -> None:
    _resource_filters(parser)
    scope = parser.add_argument_group("inventory scope")
    scope.add_argument(
        "--all-account",
        action="store_true",
        help=(
            "Expand the default canonical /hacksaws/ scan to matching roles and "
            "customer-managed policies across the whole account, including "
            "resources not managed by Hacksaws."
        ),
    )
    scope.add_argument(
        "--details",
        action="store_true",
        help=(
            "Fetch dependency details for matching resources; this performs extra "
            "IAM requests and may take longer."
        ),
    )
    output = parser.add_argument_group("output")
    width = output.add_mutually_exclusive_group()
    width.add_argument(
        "--compact",
        action="store_true",
        help="Show the smallest useful table (default).",
    )
    width.add_argument(
        "--wide",
        action="store_true",
        help="Include ARNs and paths without changing which IAM details are fetched.",
    )
    progress = output.add_mutually_exclusive_group()
    progress.add_argument(
        "--progress",
        dest="progress",
        action="store_true",
        default=None,
        help=(
            "Show progress on stderr; force plain milestones when stderr is not a "
            "terminal."
        ),
    )
    progress.add_argument(
        "--no-progress",
        dest="progress",
        action="store_false",
        help="Suppress progress messages and terminal animation.",
    )


def _cleanup_arguments(parser: argparse.ArgumentParser) -> None:
    _resource_filters(parser)
    selection = parser.add_argument_group("cleanup scope")
    selection.add_argument(
        "--all",
        action="store_true",
        help=(
            "Select every matching supported resource type; conflicts with positional "
            "patterns."
        ),
    )
    dependencies = parser.add_argument_group("dependency handling")
    dependencies.add_argument(
        "--cascade",
        action="store_true",
        help=(
            "Detach ordinary retained attachments required to delete selected "
            "resources."
        ),
    )
    dependencies.add_argument(
        "--remove-boundaries",
        action="store_true",
        help=(
            "Remove selected policies from retained user or role permissions "
            "boundaries."
        ),
    )
    dependencies.add_argument(
        "--remove-from-instance-profiles",
        action="store_true",
        help="Remove selected roles from retained instance profiles.",
    )


def _cleanup_types(args: argparse.Namespace) -> frozenset[_iam_cleanup.ResourceType]:
    values: set[_iam_cleanup.ResourceType] = set()
    if args.roles:
        values.add(_iam_cleanup.ResourceType.ROLE)
    if args.policies:
        values.add(_iam_cleanup.ResourceType.POLICY)
    if args.group_grants:
        values.add(_iam_cleanup.ResourceType.GROUP_GRANT)
    return frozenset(values)


def _cleanup_origins(
    args: argparse.Namespace, *, include_legacy_by_default: bool = False
) -> frozenset[_iam_cleanup.OwnershipOrigin]:
    values: set[_iam_cleanup.OwnershipOrigin] = set()
    if args.created:
        values.add(_iam_cleanup.OwnershipOrigin.CREATED)
    if args.adopted:
        values.add(_iam_cleanup.OwnershipOrigin.ADOPTED)
    if getattr(args, "legacy", False):
        values.add(_iam_cleanup.OwnershipOrigin.LEGACY)
    defaults = {
        _iam_cleanup.OwnershipOrigin.CREATED,
        _iam_cleanup.OwnershipOrigin.ADOPTED,
    }
    if include_legacy_by_default:
        defaults.add(_iam_cleanup.OwnershipOrigin.LEGACY)
    return frozenset(values or defaults)


def _inventory_text(
    items: list[dict[str, object]],
    *,
    wide: bool,
    query: _iam_cleanup.InventoryQuery | None = None,
    summary: _iam_cleanup.InventorySummary | None = None,
) -> str:
    details = query.details if query else False
    all_account = query.all_account if query else False
    warnings = summary.warnings if summary else ()
    if not items:
        account = (
            f"AWS account {summary.account_id} ({summary.partition})"
            if summary
            else "the selected AWS account"
        )
        if all_account:
            message = (
                f"No matching supported IAM resources were found in {account}. "
                "Scope: all-account."
            )
        else:
            message = (
                f"No matching Hacksaws-owned IAM resources were found in {account}. "
                "Scope: canonical /hacksaws/ paths with live-tag-verified ownership. "
                "This fast scan can miss adopted resources outside the canonical "
                "path, resources whose path changed, and untagged legacy resources. "
                "Use --all-account for the comprehensive account scan; untagged "
                "legacy resources cannot be classified as Hacksaws-owned."
            )
        return _inventory_warnings_text(message, warnings)
    headers: tuple[str, ...]
    rows: list[tuple[str, ...]]
    if wide:
        headers = (
            ("Type", "Name", "Origin", "Path", "Deps", "ARN")
            if details
            else ("Type", "Name", "Origin", "Path", "ARN")
        )
        rows = [
            tuple(
                _output.safe_terminal_text(value)
                for value in (
                    (
                        item["type"],
                        item["name"],
                        item["origin"],
                        item["path"],
                        _dependency_count(item),
                        item["arn"],
                    )
                    if details
                    else (
                        item["type"],
                        item["name"],
                        item["origin"],
                        item["path"],
                        item["arn"],
                    )
                )
            )
            for item in items
        ]
    else:
        headers = (
            ("Type", "Name", "Origin", "Deps", "Smoke")
            if details
            else ("Type", "Name", "Origin", "Smoke")
        )
        rows = [
            tuple(
                _output.safe_terminal_text(value)
                for value in (
                    (
                        item["type"],
                        item["name"],
                        item["origin"],
                        _dependency_count(item),
                        "🧪" if item["smoke"] else "",
                    )
                    if details
                    else (
                        item["type"],
                        item["name"],
                        item["origin"],
                        "🧪" if item["smoke"] else "",
                    )
                )
            )
            for item in items
        ]
    widths = [
        max(len(headers[index]), *(len(row[index]) for row in rows))
        for index in range(len(headers))
    ]
    table = "\n".join(
        [
            "  ".join(
                value.ljust(widths[index]) for index, value in enumerate(headers)
            ),
            "  ".join("-" * width for width in widths),
            *(
                "  ".join(value.ljust(widths[index]) for index, value in enumerate(row))
                for row in rows
            ),
        ]
    )
    return _inventory_warnings_text(table, warnings)


def _dependency_count(item: dict[str, object]) -> int:
    dependencies = cast("dict[str, list[object]]", item.get("dependencies", {}))
    return sum(len(value) for value in dependencies.values())


def _inventory_warnings_text(message: str, warnings: tuple[str, ...]) -> str:
    if not warnings:
        return message
    rendered = "\n".join(
        f"  - {_output.safe_terminal_text(warning)}" for warning in warnings
    )
    return f"{message}\n\nWarnings:\n{rendered}"


def _inventory_progress_text(event: _iam_cleanup.InventoryProgress) -> str:
    message = event.message
    if event.candidates is not None:
        noun = "candidate" if event.candidates == 1 else "candidates"
        return f"{message} {event.candidates} {noun}"
    if event.inspected is not None and event.owned is not None:
        return f"{message} {event.inspected} inspected, {event.owned} owned"
    if event.matches is not None:
        noun = "match" if event.matches == 1 else "matches"
        return f"{message} {event.matches} {noun}"
    if event.completed is not None and event.total is not None:
        message = f"{message} {event.completed}/{event.total}"
    return message


def _inventory_query(args: argparse.Namespace) -> _iam_cleanup.InventoryQuery:
    origins = (
        frozenset()
        if args.all_account
        and not (args.created or args.adopted or getattr(args, "legacy", False))
        else _cleanup_origins(args, include_legacy_by_default=True)
    )
    return _iam_cleanup.InventoryQuery(
        patterns=tuple(args.patterns),
        resource_types=_cleanup_types(args),
        origins=origins,
        owned_only=not args.all_account,
        smoke_only=args.smoke,
        smoke_run_id=args.smoke_run,
        all_account=args.all_account,
        details=args.details,
    )


def inventory_result(
    args: argparse.Namespace,
    context: IamCommandContext,
    *,
    progress: Callable[[_iam_cleanup.InventoryProgress], None] | None = None,
) -> _configs.Result:
    query = _inventory_query(args)
    summary = _iam_cleanup.CleanupService(context).inventory_summary(
        query, progress=progress
    )
    data = summary.as_dict()
    items = cast("list[dict[str, object]]", data["items"])
    return _configs.Result(
        "IAM_INVENTORY",
        _inventory_text(
            items,
            wide=args.wide,
            query=query,
            summary=summary,
        ),
        data=data,
        kind="warning" if summary.warnings else "info",
    )


def _inventory_command_result(args: argparse.Namespace) -> _configs.Result:
    selected = getattr(args, "progress", None)
    mode: _output.ProgressMode = (
        "always" if selected is True else "never" if selected is False else "auto"
    )
    with _output.ProgressReporter(_configs.output_options(), mode=mode) as reporter:
        reporter.start("Verifying AWS identity…")
        try:
            context = IamCommandContext.create(args)
            result = inventory_result(
                args,
                context,
                progress=lambda event: reporter.update(_inventory_progress_text(event)),
            )
        except KeyboardInterrupt:
            return _configs.Result(
                "IAM_INVENTORY_INTERRUPTED",
                f"IAM inventory cancelled during: {reporter.message} No AWS "
                "resources were changed.",
                _configs.EXIT_INTERRUPTED,
                "stderr",
                kind="warning",
            )
        except (
            BotoCoreError,
            ClientError,
            _iam_cleanup.policies.PolicyServiceError,
            _iam_cleanup.roles.IamRoleError,
        ) as error:
            raise _configs.OperationalError(
                "Unable to inspect IAM resources during "
                f"{reporter.message}: {_output.safe_terminal_text(error)}",
                repairs=[
                    (
                        "Verify the selected profile can list IAM roles and policies, "
                        "then retry."
                    )
                ],
            ) from error
        else:
            data = cast("dict[str, object]", result.data)
            reporter.update(f"Rendering {data['count']} resources…")
            return result


def _cleanup_plan_data(plan: _iam_cleanup.CleanupPlan) -> dict[str, object]:
    """Build a bounded cleanup review without policy/trust documents or raw params."""
    resources = [item.as_dict() for item in plan.resources]
    operations = [
        {
            "order": index,
            "id": step.id,
            "resource": step.resource_key,
            "action": step.action,
            "reversible": step.compensate_action is not None,
            "irreversible": step.irreversible,
            "prerequisites": list(step.prerequisites),
        }
        for index, step in enumerate(plan.steps, 1)
    ]
    dependency_counts = {
        key: sum(
            len(values)
            for item in plan.resources
            for name, values in item.dependencies.items()
            if name == key
        )
        for key in sorted({key for item in plan.resources for key in item.dependencies})
    }
    return {
        "classification": plan.classification.value,
        "action": "cleanup",
        "risk": "critical" if plan.resources else "none",
        "verifiedIdentity": {
            "accountId": plan.account_id,
            "partition": plan.partition,
            "callerArn": plan.caller_arn,
        },
        "selection": {
            "resources": resources,
            "count": len(resources),
            "origins": sorted({str(item["origin"]) for item in resources}),
            "types": sorted({str(item["type"]) for item in resources}),
        },
        "dependencies": dependency_counts,
        "blockers": [item.as_dict() for item in plan.blockers],
        "warnings": list(plan.warnings),
        "operations": operations,
        "journalExpected": plan.classification
        is _iam_cleanup.PlanClassification.PLANNED,
        "recovery": (
            "A credential-free journal will be written before the first AWS mutation; "
            "irreversible identity deletions retain commit-point receipts."
            if plan.resources
            else "No journal is needed because no resources matched."
        ),
        "leaveNoTrace": {
            "expectedAbsent": [item.key for item in plan.resources],
            "localRecoveryJournalRetained": True,
        },
    }


def _cleanup_plan_text(data: Mapping[str, object]) -> str:
    """Render compact cleanup review text from the credential-free plan model."""
    identity = cast("Mapping[str, object]", data["verifiedIdentity"])
    selection = cast("Mapping[str, object]", data["selection"])
    resources = cast("list[Mapping[str, object]]", selection["resources"])
    lines = [
        f"PLAN — CLEANUP ({data['risk']} risk)",
        f"Account: {identity['accountId']} ({identity['partition']})",
        f"Caller: {identity['callerArn']}",
        f"Resources selected: {selection['count']}",
    ]
    lines.extend(
        f"  - {item['type']} {item['name']} [{item['origin']}] {item['arn']}"
        for item in resources
    )
    dependencies = cast("Mapping[str, int]", data["dependencies"])
    populated = {key: count for key, count in dependencies.items() if count}
    lines.append(
        "Dependencies: "
        + (
            ", ".join(f"{key}={count}" for key, count in populated.items())
            if populated
            else "none"
        )
    )
    operations = cast("list[Mapping[str, object]]", data["operations"])
    if operations:
        lines.append("Ordered AWS operations:")
        lines.extend(
            f"  {item['order']}. {item['action']} — {item['resource']} "
            "["
            + (
                "irreversible"
                if item["irreversible"]
                else "reversible"
                if item["reversible"]
                else "one-way"
            )
            + "]"
            for item in operations
        )
    blockers = cast("list[Mapping[str, object]]", data["blockers"])
    if blockers:
        lines.append("Blockers:")
        lines.extend(f"  - {item['message']}" for item in blockers)
    warnings = cast("list[str]", data["warnings"])
    if warnings:
        lines.append("Warnings:")
        lines.extend(f"  - {item}" for item in warnings)
    lines.append(str(data["recovery"]))
    lines.append("No changes have been made.")
    return "\n".join(_output.safe_terminal_text(line) for line in lines)


def _iam_console_url(context: IamCommandContext) -> str:
    """Return the partition-appropriate IAM console home link."""
    partition = getattr(context, "partition", "aws")
    region_name = getattr(context, "region_name", "us-east-1")
    domain = {
        "aws": "console.aws.amazon.com",
        "aws-cn": "console.amazonaws.cn",
        "aws-us-gov": "console.amazonaws-us-gov.com",
    }.get(partition)
    if domain is None:
        raise _configs.OperationalError(
            f"AWS Console links are not supported for partition {partition!r}."
        )
    return f"https://{region_name}.{domain}/iam/home?region={region_name}#/home"


def cleanup_result(
    args: argparse.Namespace, context: IamCommandContext
) -> _configs.Result:
    if args.all and args.patterns:
        raise _configs.OperationalError(
            "--all conflicts with positional cleanup patterns."
        )
    if not (args.all or args.patterns or args.smoke or args.smoke_run):
        raise _configs.OperationalError(
            "Cleanup requires PATTERN, --all, --smoke, or --smoke-run so "
            "account-wide deletion is never accidental."
        )
    options = _iam_cleanup.CleanupOptions(
        patterns=tuple(args.patterns),
        all_resources=args.all,
        resource_types=_cleanup_types(args),
        origins=_cleanup_origins(args),
        smoke_only=args.smoke,
        smoke_run_id=args.smoke_run,
        cascade=args.cascade,
        remove_boundaries=args.remove_boundaries,
        remove_from_instance_profiles=args.remove_from_instance_profiles,
        dry_run=bool(args.dry_run),
    )
    service = _iam_cleanup.CleanupService(context)
    plan = service.plan(options)
    plan_data = _cleanup_plan_data(plan)
    review = _cleanup_plan_text(plan_data)
    if plan.classification is _iam_cleanup.PlanClassification.BLOCKED:
        return _configs.Result(
            "IAM_CLEANUP_BLOCKED",
            review,
            _configs.EXIT_POLICY,
            "stderr",
            {"plan": plan_data, "result": {"classification": "blocked"}},
        )
    if plan.classification is _iam_cleanup.PlanClassification.NO_MATCHES:
        return _configs.Result(
            "IAM_CLEANUP_NO_MATCHES",
            "NO CHANGE — Cleanup matched no resources.\nNo changes have been made.",
            data={
                "plan": plan_data,
                "applied": {"operationsCompleted": 0, "resourcesDeleted": 0},
                "result": {
                    "classification": "no-change",
                    "journalId": None,
                    "leaveNoTrace": True,
                },
            },
        )
    if args.dry_run:
        return _configs.Result(
            "IAM_CLEANUP_DRY_RUN",
            "DRY RUN\n" + review,
            data={
                "plan": plan_data,
                "result": {
                    "classification": "dry-run",
                    "journalId": None,
                    "changed": False,
                },
            },
        )
    if not args.yes:
        if _configs.json_output_enabled() or not os.isatty(0):
            return _configs.Result(
                "IAM_CLEANUP_CONFIRMATION_REQUIRED",
                review + "\nConfirmation required: rerun with --yes.",
                _configs.EXIT_CANCELLED,
                "stderr",
                {
                    "plan": plan_data,
                    "result": {"classification": "confirmation-required"},
                },
            )
        if (
            input(review + "\n\nType exactly 'yes' to execute this plan:\n> ").strip()
            != "yes"
        ):
            return _configs.Result(
                "IAM_CLEANUP_CANCELLED",
                "CANCELLED — Cleanup declined. No changes have been made.",
                _configs.EXIT_CANCELLED,
                "stderr",
                {
                    "plan": plan_data,
                    "result": {"classification": "cancelled"},
                },
            )
    outcome = service.execute(plan)
    result_data = outcome.as_dict()
    console_url = _iam_console_url(context)
    result_data["consoleUrl"] = console_url
    applied = {
        "operationsPlanned": len(plan.steps),
        "operationsCompleted": len(outcome.completed),
        "resourcesSelected": len(plan.resources),
        "resourcesDeleted": len(plan.resources) if outcome.lnt else 0,
        "failures": list(outcome.failed),
        "residue": list(outcome.remaining),
    }
    data = {"plan": plan_data, "applied": applied, "result": result_data}
    partial = outcome.classification is not _iam_cleanup.ResultClassification.CLEANED
    message = (
        (
            f"Cleanup incomplete: {len(outcome.failed)} failed operation(s), "
            f"{len(outcome.remaining)} residue item(s)."
        )
        if partial
        else f"Deleted {len(plan.resources)} IAM resource(s)."
    )
    message += (
        f"\nApplied: {len(outcome.completed)}/{len(plan.steps)} ordered AWS "
        "operation(s) completed."
        f"\nFailures: {len(outcome.failed)}"
        f"\nResidue: {len(outcome.remaining)}"
        f"\nVerified: Leave No Trace {'succeeded' if outcome.lnt else 'not proven'}."
        + (
            f"\nJournal: {outcome.journal_id} "
            "(recovery receipt retained; use 'hacksaws iam recovery get')."
            if outcome.journal_id
            else "\nJournal: none."
        )
        + "\nAWS Console: "
        + console_url
    )
    return _configs.Result(
        "IAM_CLEANUP_PARTIAL" if partial else "IAM_CLEANUP_COMPLETE",
        _output.safe_terminal_text(message),
        2 if partial else 0,
        "stderr" if partial else "stdout",
        data,
    )


def _dispatch_cleanup(args: argparse.Namespace) -> _configs.Result:
    """Create a cleanup context while classifying identity refusal distinctly."""
    try:
        context = IamCommandContext.create(args)
    except _configs.OperationalError as error:
        message = str(error)
        if "selected account requires" in message:
            return _configs.Result(
                "IAM_CLEANUP_SAFETY_REFUSAL",
                "Cleanup refused because the selected credentials could not prove "
                f"the requested AWS account: {message}",
                _configs.EXIT_POLICY,
                "stderr",
                data={"reason": "account-mismatch"},
                repairs=[
                    "Select credentials for the requested account or correct --account."
                ],
            )
        raise
    return cleanup_result(args, context)


@contextlib.contextmanager
def credential_environment(config: Path, credentials: Path) -> Iterator[None]:
    """Temporarily bind Boto3 to exactly one selected shared-config source."""
    keys = _CREDENTIAL_ENVIRONMENT_KEYS
    previous = {key: os.environ.get(key) for key in keys}
    os.environ["AWS_CONFIG_FILE"] = str(config)
    os.environ["AWS_SHARED_CREDENTIALS_FILE"] = str(credentials)
    for key in keys[2:]:
        os.environ.pop(key, None)
    os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@dataclass(frozen=True)
class IamCommandContext:
    """Verified AWS clients and selected local credential source for one IAM command."""

    selector: _configs.CredentialSelector
    config_path: Path
    credentials_path: Path
    session: Any
    iam: Any
    sts: Any
    access_analyzer: Any
    account_id: str
    partition: str
    arn: str
    region_name: str
    region_resolution: _regions.RegionResolution

    @classmethod
    def create(
        cls,
        args: argparse.Namespace,
        *,
        session_factory: Callable[..., Any] = boto3.Session,
    ) -> IamCommandContext:
        """Resolve local selection, create clients, and verify caller identity only."""
        selector = _configs.resolve_credential_selector(args)
        directory, profile, expected_account = _selected_source(selector, args)
        region_settings = _iam_region_settings(selector, expected_account)
        env_region = os.getenv("AWS_REGION") or ""
        env_default_region = os.getenv("AWS_DEFAULT_REGION") or ""
        with credential_environment(directory / "config", directory / "credentials"):
            try:
                higher_precedence_region = any(
                    (
                        getattr(args, "region", None),
                        env_region,
                        env_default_region,
                        region_settings["target"],
                    )
                )
                profile_session = (
                    None
                    if higher_precedence_region
                    else session_factory(profile_name=profile)
                )
                profile_credentials = (
                    profile_session.get_credentials()
                    if profile_session is not None
                    else None
                )
                if profile_session is not None and profile_credentials is None:
                    raise _configs.OperationalError(
                        f"Selected AWS profile {profile!r} has no credentials."
                    )
                preference = _regions.resolve_region_preference(
                    explicit=getattr(args, "region", None),
                    env_region=env_region,
                    env_default_region=env_default_region,
                    target=region_settings["target"],
                    source=(
                        profile_session.region_name
                        if profile_session is not None
                        else None
                    ),
                    account=region_settings["account"],
                    global_region=region_settings["global"],
                    custom_aliases=region_settings["aliases"],
                    partition=(
                        str(expected_account["partition"])
                        if expected_account is not None
                        else None
                    ),
                    allow_unknown=bool(getattr(args, "allow_unknown_region", False)),
                    interactive=False,
                )
                region_resolution = _regions.validate_service_region(
                    preference.resolution,
                    "sts",
                    allow_unknown=bool(getattr(args, "allow_unknown_region", False)),
                )
                region_name = region_resolution.canonical
                selected_session = (
                    profile_session
                    if profile_session is not None
                    and profile_session.region_name == region_name
                    else session_factory(
                        profile_name=profile,
                        region_name=region_name,
                    )
                )
                credentials = (
                    profile_credentials
                    if selected_session is profile_session
                    else selected_session.get_credentials()
                )
                if credentials is None:
                    raise _configs.OperationalError(
                        f"Selected AWS profile {profile!r} has no credentials."
                    )
                frozen = credentials.get_frozen_credentials()
                session = session_factory(
                    aws_access_key_id=frozen.access_key,
                    aws_secret_access_key=frozen.secret_key,
                    aws_session_token=frozen.token,
                    region_name=region_name,
                )
                sts = session.client("sts")
                iam = session.client("iam")
                access_analyzer = session.client("accessanalyzer")
                response = sts.get_caller_identity()
                account_id = str(response["Account"])
                arn = str(response["Arn"])
                partition_match = re.fullmatch(r"arn:([^:]+):.+", arn)
                if not re.fullmatch(r"\d{12}", account_id) or partition_match is None:
                    raise KeyError("invalid caller identity")
                partition = partition_match.group(1)
            except (BotoCoreError, ClientError, KeyError) as error:
                raise _configs.OperationalError(
                    "Unable to verify selected IAM credentials with "
                    f"GetCallerIdentity: {error}"
                ) from error
        if partition not in _regions.OPERATIONAL_PARTITIONS:
            raise _configs.OperationalError(
                f"Authenticated caller partition {partition!r} is not supported."
            )
        if partition != region_resolution.partition:
            raise _configs.OperationalError(
                "Resolved AWS region partition "
                f"{region_resolution.partition!r} does not match authenticated "
                f"caller partition {partition!r}."
            )
        if expected_account and (
            account_id != expected_account["id"]
            or partition != expected_account["partition"]
        ):
            raise _configs.OperationalError(
                "Selected IAM credentials identify "
                f"{partition}:{account_id}, but the selected account requires "
                f"{expected_account['partition']}:{expected_account['id']}."
            )
        return cls(
            selector=_configs.CredentialSelector(
                profile=profile,
                location=selector.location,
                directory=directory,
                target=selector.target,
            ),
            config_path=directory / "config",
            credentials_path=directory / "credentials",
            session=session,
            iam=iam,
            sts=sts,
            access_analyzer=access_analyzer,
            account_id=account_id,
            partition=partition,
            arn=arn,
            region_name=region_name,
            region_resolution=region_resolution,
        )


def _selected_source(
    selector: _configs.CredentialSelector, args: argparse.Namespace
) -> tuple[Path, str, dict[str, Any] | None]:
    """Resolve target/location/directory precedence without triggering any login."""
    data = _state.load_config()
    expected_name = args.account
    if selector.target:
        _, target = _state.get_resource(data, "target", selector.target.lstrip("+"))
        directory = (
            Path(target["source_directory"])
            if target.get("source_directory")
            else _state.aws_directory(target.get("source_location"))
        )
        profile = str(target.get("source_profile", "default"))
        expected_name = expected_name or str(target["source_account"])
    else:
        directory = selector.directory or _state.aws_directory(selector.location)
        profile = selector.profile
    expected = None
    if expected_name:
        _, expected = _state.get_resource(data, "account", expected_name)
    return directory.expanduser().absolute(), profile, expected


def _iam_region_settings(
    selector: _configs.CredentialSelector,
    expected_account: dict[str, Any] | None,
) -> dict[str, Any]:
    """Return configured IAM-region preference layers without AWS side effects."""
    data = _state.load_config()
    aws = data.get("aws")
    aws_settings = aws if isinstance(aws, dict) else {}
    target_region: str | None = None
    if selector.target:
        _, target = _state.get_resource(data, "target", selector.target.lstrip("+"))
        value = target.get("region")
        target_region = value if isinstance(value, str) else None
    account_region: str | None = None
    if expected_account is not None:
        value = expected_account.get("region")
        account_region = value if isinstance(value, str) else None
    global_value = aws_settings.get("region")
    aliases = aws_settings.get("region_aliases")
    return {
        "target": target_region,
        "account": account_region,
        "global": global_value if isinstance(global_value, str) else None,
        "aliases": aliases if isinstance(aliases, dict) else {},
    }


def recovery_result(args: argparse.Namespace) -> _configs.Result:
    """Inspect or execute an IAM-only durable recovery journal."""
    action = args.recovery_action
    if action == "list":
        journals = _iam_recovery.list_journals()
        data = {"journals": journals, "count": len(journals)}
        return _configs.Result("IAM_RECOVERY_LIST", json.dumps(data), data=data)
    journal_id = getattr(args, "journal_id", None)
    if not journal_id:
        raise _configs.OperationalError(
            f"IAM recovery {action} requires a journal ID.",
            repairs=["Run 'hacksaws iam recovery list' to find journal IDs."],
        )
    if action == "get":
        data = _iam_recovery.get_journal(journal_id)
        return _configs.Result("IAM_RECOVERY_GET", json.dumps(data), data=data)
    journal = _iam_recovery.get_journal(journal_id)
    if journal.get("serviceType") == "policy":
        _iam_policy_cli.ensure_recovery_handlers()
    elif journal.get("serviceType") == "iam-cleanup":
        _iam_cleanup.ensure_recovery_handler()
    context = IamCommandContext.create(args)
    if action == "continue" and journal.get("serviceType") == "iam-cleanup":
        outcome = _iam_cleanup.CleanupService(context).continue_journal(journal_id)
        data = outcome.as_dict()
    elif action == "continue":
        data = _iam_recovery.continue_journal(journal_id, context)
    elif journal.get("serviceType") == "iam-cleanup":
        data = _iam_cleanup.CleanupService(context).rollback_journal(journal_id)
    else:
        data = _iam_recovery.rollback_journal(journal_id, context)
    return _configs.Result(
        "IAM_RECOVERY_CONTINUE" if action == "continue" else "IAM_RECOVERY_ROLLBACK",
        f"IAM recovery {action} completed for {journal_id}.",
        data=data,
    )


def dispatch(args: argparse.Namespace) -> _configs.Result:  # noqa: C901, PLR0911
    """Dispatch recovery locally or hand verified context to the owning leaf adapter."""
    if args.iam_action in {"recovery", "recover"}:
        return recovery_result(args)
    if args.iam_action in {"list", "cleanup"}:
        if args.iam_action == "cleanup":
            return _dispatch_cleanup(args)
        return _inventory_command_result(args)
    if args.iam_action not in {"policy", "policies", "role", "roles"}:
        return _configs.Result(
            "IAM_HELP", "Choose an IAM command.", _configs.EXIT_USAGE, "stderr"
        )
    expected = "policy" if args.iam_action in {"policy", "policies"} else "role"
    leaf = "policy_action" if expected == "policy" else "role_command"
    if not getattr(args, leaf, None):
        return _configs.Result(
            "IAM_LEAF_HELP",
            f"Choose an IAM {expected} command.",
            _configs.EXIT_USAGE,
            "stderr",
        )
    candidates = [adapter for adapter in _adapters if adapter.name == expected]
    if not candidates:
        return _configs.Result(
            "IAM_LEAF_HELP",
            f"No {expected} command adapter is installed.",
            _configs.EXIT_USAGE,
            "stderr",
        )
    for adapter in candidates:
        normalize = getattr(adapter, "normalize_arguments", None)
        if normalize is not None:
            normalize(args)
    context = IamCommandContext.create(args)
    for adapter in candidates:
        result = adapter.dispatch(args, context)
        if result is not None:
            return result
    return _configs.Result(
        "IAM_LEAF_HELP",
        f"No {args.iam_action} command adapter is installed.",
        _configs.EXIT_USAGE,
        "stderr",
    )


def dispatch_root_cleanup(args: argparse.Namespace) -> _configs.Result:
    """Dispatch the canonical root cleanup command through the shared service."""
    return _dispatch_cleanup(args)
