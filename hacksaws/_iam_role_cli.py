"""Command-line adapter for IAM role, trust, and inline-policy workflows."""

# ruff: noqa: C901, PLR0911, PLR0912, PLR0915, TRY003

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import asdict
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING
from typing import Any
from urllib.parse import quote

import yaml
from botocore.exceptions import BotoCoreError
from botocore.exceptions import ClientError

from hacksaws import _duration as duration_parser
from hacksaws import _iam_managed_policies as managed
from hacksaws import _iam_policy_cli as policy_cli
from hacksaws import _iam_policy_documents as documents
from hacksaws import _iam_recovery as recovery
from hacksaws import _iam_roles as roles
from hacksaws import _state
from hacksaws._configs import EXIT_CANCELLED
from hacksaws._configs import EXIT_USAGE
from hacksaws._configs import OperationalError
from hacksaws._configs import Result

if TYPE_CHECKING:
    from collections.abc import Iterable

    from hacksaws._iam_cli import IamCommandContext

name = "role"
_input = input
_editor_runner = subprocess.run
_ROLE_NAME = re.compile(r"^[\w+=,.@-]{1,64}$", re.ASCII)
_PATHLIKE = re.compile(r"^(?:[A-Za-z]:[\\/]|[.~][\\/]|.*[\\/])")
_POLICY_EXTENSIONS = {".json", ".yaml", ".yml", ".toml"}
_RECOVERY_SERVICE = "iam-role"
_CREATE_ROLE_HANDLER = "create-role-with-receipt"


def _console_url(context: IamCommandContext, role_name: str) -> str:
    region = (
        getattr(getattr(context, "session", None), "region_name", None) or "us-east-1"
    )
    return (
        f"https://{region}.console.aws.amazon.com/iam/home?region={region}"
        f"#/roles/details/{quote(role_name, safe='')}"
    )


class _MutationCancelledError(RuntimeError):
    """Signal a fail-closed mutation confirmation without touching AWS."""


class _DryRunCompletedError(RuntimeError):
    """Return a fully materialized role plan without creating a journal."""

    def __init__(self, plan: roles.MutationPlan) -> None:
        self.plan = plan
        super().__init__(_preview(plan))


def _add_selector_arguments(
    parser: argparse.ArgumentParser, *, mutation: bool = False
) -> None:
    group = parser.add_argument_group("credential selection")
    group.add_argument(
        "--profile",
        default=argparse.SUPPRESS,
        metavar="PROFILE",
        help="AWS profile to use.",
    )
    group.add_argument(
        "--location",
        default=argparse.SUPPRESS,
        metavar="NAME",
        help="Named AWS config directory to use.",
    )
    group.add_argument(
        "-d",
        "--directory",
        default=argparse.SUPPRESS,
        metavar="PATH",
        help="Explicit AWS config directory; conflicts with --location.",
    )
    group.add_argument(
        "--target",
        default=argparse.SUPPRESS,
        metavar="NAME",
        help="Saved target supplying the credential source.",
    )
    group.add_argument(
        "--account",
        default=argparse.SUPPRESS,
        metavar="NAME_OR_ID",
        help="Assert the selected AWS account.",
    )
    group.add_argument(
        "--region",
        default=argparse.SUPPRESS,
        metavar="REGION",
        help="Region used for AWS clients and console links.",
    )
    if mutation:
        safety = parser.add_argument_group("safety")
        safety.add_argument(
            "--dry-run",
            action="store_true",
            default=argparse.SUPPRESS,
            help="Validate and show the plan without changing AWS or local state.",
        )
        safety.add_argument(
            "--yes",
            action="store_true",
            default=argparse.SUPPRESS,
            help="Approve the displayed plan without prompting.",
        )


def _leaf(
    actions: argparse._SubParsersAction[argparse.ArgumentParser],
    command: str,
    *,
    help_text: str,
    mutation: bool = False,
) -> argparse.ArgumentParser:
    parser = actions.add_parser(command, help=help_text)
    _add_selector_arguments(parser, mutation=mutation)
    parser.set_defaults(role_command=command)
    return parser


def _duration_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--duration", "--ttl")
    parser.add_argument("--htl")
    parser.add_argument("--mtl")
    parser.add_argument("--stl")


def _metadata_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--metadata", choices=("nested", "sidecar", "none"), default="none"
    )
    parser.add_argument("--sidecar", type=Path)


def _export_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", "-o", type=Path)
    parser.add_argument("--format", choices=("yaml", "json"), default="yaml")
    _metadata_arguments(parser)


def _condition_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--condition",
        action="append",
        default=[],
        metavar="OPERATOR:KEY=VALUE",
        help="Add an exact IAM trust condition; repeat for multiple conditions.",
    )


def register(parser: argparse.ArgumentParser) -> None:
    """Register the complete role command tree below ``iam role``."""
    actions = parser.add_subparsers(dest="role_command")

    create = _leaf(
        actions, "create", help_text="Create a managed IAM role.", mutation=True
    )
    create.add_argument("role", help="IAM role name or same-account role ARN.")
    create.add_argument("--description", help="Human-readable role description.")
    create.add_argument("--path", help="IAM role path (default from configuration).")
    create.add_argument(
        "--permissions-boundary",
        help="Managed policy name or ARN used as the role permissions boundary.",
    )
    create.add_argument(
        "--tag",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Add an IAM tag; repeat for multiple tags.",
    )
    create.add_argument(
        "--trust-caller",
        action="store_true",
        help="Trust the exact selected caller identity by default.",
    )
    create.add_argument(
        "--trust-policy",
        type=Path,
        help="JSON/YAML/TOML trust-policy file instead of interactive trust setup.",
    )
    create.add_argument(
        "--case",
        choices=("Pascal", "camel", "snake", "kebab"),
        help="Override configured name casing.",
    )
    create.add_argument("--prefix", help="Override the configured role-name prefix.")
    create.add_argument("--suffix", help="Override the configured role-name suffix.")
    create.add_argument(
        "--naming-enforcement",
        choices=("off", "warn", "error"),
        help="Override naming-rule enforcement for this command.",
    )
    create.add_argument(
        "--replace",
        action="store_true",
        help="Update an existing role only after a conflict preview; never delete it.",
    )
    _metadata_arguments(create)
    _duration_arguments(create)

    get = _leaf(actions, "get", help_text="Show comprehensive IAM role state.")
    get.add_argument("role")

    listing = _leaf(actions, "list", help_text="List IAM roles.")
    listing.add_argument("patterns", nargs="*")
    scope = listing.add_mutually_exclusive_group()
    scope.add_argument("--custom", action="store_true")
    scope.add_argument("--all", action="store_true")
    scope.add_argument("--service", action="store_true")
    listing.add_argument("--wide", action="store_true")
    listing.add_argument("--probe", action="store_true")

    update = _leaf(
        actions, "update", help_text="Update mutable role fields.", mutation=True
    )
    update.add_argument("role")
    update.add_argument("--description")
    update.add_argument("--clear-description", action="store_true")
    update.add_argument("--permissions-boundary")
    update.add_argument("--clear-permissions-boundary", action="store_true")
    update.add_argument("--trust-policy", type=Path)
    _metadata_arguments(update)
    _duration_arguments(update)

    delete = _leaf(
        actions, "delete", help_text="Delete an IAM role safely.", mutation=True
    )
    delete.add_argument("role")
    delete.add_argument("--cascade", action="store_true")
    delete.add_argument("--remove-from-instance-profiles", action="store_true")
    delete.add_argument("--unmanaged", action="store_true")
    delete.add_argument("--service-role", action="store_true")

    attach = _leaf(
        actions, "attach", help_text="Attach or publish a role policy.", mutation=True
    )
    attach.add_argument("role")
    attach.add_argument("policy")
    attach.add_argument("--inline", action="store_true")
    attach.add_argument("--policy-name")
    attach.add_argument("--path")
    _metadata_arguments(attach)

    detach = _leaf(
        actions, "detach", help_text="Detach a managed role policy.", mutation=True
    )
    detach.add_argument("role")
    detach.add_argument("policy")

    adopt = _leaf(actions, "adopt", help_text="Adopt an existing role.", mutation=True)
    adopt.add_argument("role")
    adopt.add_argument("--owner")
    adopt.add_argument("--audit-id")
    release = _leaf(
        actions, "release", help_text="Release a managed role.", mutation=True
    )
    release.add_argument("role")

    tag = _leaf(actions, "tag", help_text="Manage role tags.")
    tag_actions = tag.add_subparsers(dest="role_tag_action")
    tag_list = tag_actions.add_parser("list")
    _add_selector_arguments(tag_list)
    tag_list.add_argument("role")
    tag_set = tag_actions.add_parser("set")
    _add_selector_arguments(tag_set, mutation=True)
    tag_set.add_argument("role")
    tag_set.add_argument("tags", nargs="+")
    tag_remove = tag_actions.add_parser("remove")
    _add_selector_arguments(tag_remove, mutation=True)
    tag_remove.add_argument("role")
    tag_remove.add_argument("keys", nargs="+")

    inline = _leaf(actions, "inline-policy", help_text="Manage inline role policies.")
    inline_actions = inline.add_subparsers(dest="role_inline_action")
    for action in ("list", "get"):
        item = inline_actions.add_parser(action)
        _add_selector_arguments(item)
        item.add_argument("role")
        if action == "get":
            item.add_argument("policy")
    inline_export = inline_actions.add_parser("export")
    _add_selector_arguments(inline_export)
    inline_export.add_argument("role")
    inline_export.add_argument("policy")
    _export_arguments(inline_export)
    inline_put = inline_actions.add_parser("put")
    _add_selector_arguments(inline_put, mutation=True)
    inline_put.add_argument("role")
    inline_put.add_argument("policy")
    inline_put.add_argument("file", type=Path)
    _metadata_arguments(inline_put)
    inline_edit = inline_actions.add_parser("edit")
    _add_selector_arguments(inline_edit, mutation=True)
    inline_edit.add_argument("role")
    inline_edit.add_argument("policy")
    inline_delete = inline_actions.add_parser("delete")
    _add_selector_arguments(inline_delete, mutation=True)
    inline_delete.add_argument("role")
    inline_delete.add_argument("policy")

    trust = _leaf(actions, "trust", help_text="Manage role trust policies.")
    trust_actions = trust.add_subparsers(dest="role_trust_action")
    for action in ("get", "set", "edit", "check"):
        item = trust_actions.add_parser(action)
        _add_selector_arguments(item, mutation=action in {"set", "edit"})
        item.add_argument("role")
        if action == "set":
            item.add_argument("file", type=Path)
            _metadata_arguments(item)
        if action == "check":
            item.add_argument("--probe", action="store_true")
    trust_export = trust_actions.add_parser("export")
    _add_selector_arguments(trust_export)
    trust_export.add_argument("role")
    _export_arguments(trust_export)

    for action in ("add", "remove"):
        command = trust_actions.add_parser(action)
        _add_selector_arguments(command)
        kinds = command.add_subparsers(dest="role_trust_kind")
        for kind in ("user", "role", "account", "principal"):
            item = kinds.add_parser(kind)
            _add_selector_arguments(item, mutation=True)
            item.add_argument("target_role")
            item.add_argument("principal")
            item.add_argument("--principal-account")
            if action == "add":
                item.add_argument("--sid")
                _condition_arguments(item)
        members = kinds.add_parser("group-members")
        _add_selector_arguments(members, mutation=True)
        members.add_argument("group")
        members.add_argument("members", nargs="+")

    sync = trust_actions.add_parser("sync")
    _add_selector_arguments(sync)
    sync_kinds = sync.add_subparsers(dest="role_trust_kind")
    sync_members = sync_kinds.add_parser("group-members")
    _add_selector_arguments(sync_members, mutation=True)
    sync_members.add_argument("group")
    sync_members.add_argument("members", nargs="*")

    for action in ("grant", "revoke"):
        command = trust_actions.add_parser(action)
        _add_selector_arguments(command)
        kinds = command.add_subparsers(dest="role_trust_kind")
        group = kinds.add_parser("group")
        _add_selector_arguments(group, mutation=True)
        group.add_argument("target_role")
        group.add_argument("group")


def _service(context: IamCommandContext) -> roles.IamRoleService:
    return roles.IamRoleService(context.iam)


def _error_code(error: ClientError) -> str:
    return str(error.response.get("Error", {}).get("Code", ""))


def _iam_call(
    context: IamCommandContext, action: str, payload: Mapping[str, object]
) -> None:
    params = payload.get("params")
    if not isinstance(params, Mapping):
        raise OperationalError("Role recovery step parameters are invalid.")
    try:
        getattr(context.iam, action)(**dict(params))
    except ClientError as error:
        code = _error_code(error)
        if code == "NoSuchEntity" and action.startswith(
            ("delete_", "detach_", "remove_", "untag_")
        ):
            return
        raise


def _effect_role_id(payload: Mapping[str, object]) -> str | None:
    effect = payload.get("effect")
    if effect is None:
        return None
    if not isinstance(effect, Mapping) or not isinstance(effect.get("roleId"), str):
        raise OperationalError("IAM recovery role identity receipt is invalid.")
    role_id = str(effect["roleId"])
    if not role_id:
        raise OperationalError("IAM recovery role identity receipt is empty.")
    return role_id


def _create_role_state_matches(
    current: roles.RoleSnapshot, params: Mapping[str, object]
) -> bool:
    raw_tags = params.get("Tags", [])
    raw_duration = params.get("MaxSessionDuration", 3600)
    if not isinstance(raw_tags, list) or not isinstance(raw_duration, int):
        return False
    desired_tags = {
        str(item["Key"]): str(item.get("Value", ""))
        for item in raw_tags
        if isinstance(item, Mapping) and "Key" in item
    }
    return (
        current.name == str(params.get("RoleName", ""))
        and current.path == str(params.get("Path", "/"))
        and roles.document_hash(current.trust)
        == roles.document_hash(
            roles.decode_document(params.get("AssumeRolePolicyDocument", {}))
        )
        and current.description == params.get("Description")
        and current.max_session_duration == raw_duration
        and current.permissions_boundary == params.get("PermissionsBoundary")
        and dict(current.tags) == desired_tags
        and not current.attached_policies
        and not current.inline_policies
        and not current.instance_profiles
    )


def _create_role_with_receipt(
    payload: Mapping[str, object], context: IamCommandContext
) -> Mapping[str, object]:
    params = payload.get("params")
    if not isinstance(params, Mapping):
        raise OperationalError("Role create recovery parameters are invalid.")
    receipt_role_id = _effect_role_id(payload)
    try:
        response = context.iam.create_role(**dict(params))
    except ClientError as error:
        if _error_code(error) != "EntityAlreadyExists":
            raise
        if receipt_role_id is None:
            raise OperationalError(
                "A role exists at the create target but this pending journal has no "
                "durable AWS RoleId receipt proving it created that role. Preserve "
                "the role and recover manually."
            ) from error
        current = _service(context).get_role(str(params["RoleName"]))
        if current.role_id != receipt_role_id or not _create_role_state_matches(
            current, params
        ):
            raise OperationalError(
                "The live role does not match the journal's immutable RoleId receipt "
                "and expected create state; refusing adoption."
            ) from error
        return {"roleId": receipt_role_id}
    role = response.get("Role") if isinstance(response, Mapping) else None
    role_id = role.get("RoleId") if isinstance(role, Mapping) else None
    if not isinstance(role_id, str) or not role_id:
        raise OperationalError(
            "AWS created the role but returned no immutable RoleId receipt. The "
            "result is ambiguous; preserve the role and recover manually."
        )
    return {"roleId": role_id}


def _delete_created_role_with_receipt(
    payload: Mapping[str, object], context: IamCommandContext
) -> None:
    params = payload.get("params")
    role_id = _effect_role_id(payload)
    if not isinstance(params, Mapping) or role_id is None:
        raise OperationalError(
            "Create rollback has no durable AWS RoleId receipt. Preserve any role "
            "at the target name and recover manually."
        )
    role_name = str(params.get("RoleName", ""))
    try:
        current = _service(context).get_role(role_name)
    except ClientError as error:
        if _error_code(error) == "NoSuchEntity":
            return
        raise
    if current.role_id != role_id:
        raise OperationalError(
            "The live role's immutable RoleId does not match the create receipt; "
            "preserving it and requiring manual recovery."
        )
    context.iam.delete_role(RoleName=role_name)


def _managed_service(context: IamCommandContext) -> managed.IamManagedPolicyService:
    return managed.IamManagedPolicyService(
        context.iam,
        context.sts,
        getattr(context, "access_analyzer", None),
        managed.PolicyServiceOptions(
            account_id=context.account_id,
            partition=context.partition,
            owned_path=_config_path(),
        ),
    )


def _managed_record(
    service: managed.IamManagedPolicyService, arn: str
) -> managed.ManagedPolicyRecord | None:
    try:
        return service.get_policy(
            arn, include_document=True, include_versions=True, include_tags=True
        )
    except ClientError as error:
        if _error_code(error) == "NoSuchEntity":
            return None
        raise


def _managed_tag_hash(tags: Iterable[managed.Tag]) -> str:
    return roles.document_hash({tag.key: tag.value for tag in tags})


def _require_policy_identity(
    record: managed.ManagedPolicyRecord, resource_id: str
) -> None:
    values = {tag.key.casefold(): tag.value for tag in record.tags}
    if not (
        values.get("hacksaws:managed-by") == "hacksaws"
        and values.get("hacksaws:resource-kind") == "managed-policy"
        and values.get("hacksaws:resource-id") == resource_id
    ):
        raise OperationalError(
            f"Managed policy {record.arn.value} is not the exact Hacksaws-owned "
            f"resource {resource_id!r}."
        )


def _policy_state_hash(state: Mapping[str, object]) -> str:
    """Hash durable policy semantics while ignoring AWS-assigned version IDs."""
    if state.get("exists") is not True:
        return roles.document_hash({"exists": False, "arn": str(state.get("arn", ""))})
    versions: list[dict[str, object]] = []
    raw_versions = state.get("versions", [])
    if isinstance(raw_versions, list):
        for item in raw_versions:
            if isinstance(item, Mapping) and isinstance(item.get("document"), Mapping):
                document = dict(item["document"])
                versions.append(
                    {
                        "default": item.get("default") is True,
                        "document": document,
                        "digest": managed.policy_digest(document),
                    }
                )
    versions.sort(key=lambda item: (str(item["digest"]), bool(item["default"])))
    raw_tags = state.get("tags", [])
    tags = (
        {
            str(item["Key"]): str(item.get("Value", ""))
            for item in raw_tags
            if isinstance(item, Mapping) and "Key" in item
        }
        if isinstance(raw_tags, list)
        else {}
    )
    raw_dependencies = state.get("dependencies", {})
    dependencies = (
        {
            str(key): sorted(str(value) for value in values)
            for key, values in raw_dependencies.items()
            if isinstance(values, list)
        }
        if isinstance(raw_dependencies, Mapping)
        else {}
    )
    return roles.document_hash(
        {
            "exists": True,
            "arn": str(state.get("arn", "")),
            "name": str(state.get("name", "")),
            "path": str(state.get("path", "")),
            "description": state.get("description"),
            "tags": tags,
            "versions": versions,
            "dependencies": dependencies,
        }
    )


def _policy_state(
    service: managed.IamManagedPolicyService,
    record: managed.ManagedPolicyRecord,
) -> dict[str, object]:
    return policy_cli._policy_state(  # noqa: SLF001
        record, dependencies=service.policy_dependencies(record.arn.value)
    )


def _materialize_managed_operation(
    operation: roles.Operation, context: IamCommandContext
) -> roles.Operation:
    """Convert a logical publication into complete durable reconcile states."""
    payload = operation.params
    arn = str(payload["PolicyArn"])
    resource_id = str(payload["ResourceId"])
    document = roles.decode_document(payload["PolicyDocument"])
    service = _managed_service(context)
    current = _managed_record(service, arn)
    if current is None:
        caller = managed.CallerIdentity(
            context.account_id, context.partition, context.arn, context.arn
        )
        change = service.plan_create(
            str(payload["PolicyName"]),
            document,
            options=managed.CreatePolicyOptions(
                path=str(payload["Path"]),
                resource_id=resource_id,
                caller=caller,
                include_aws_validation=False,
            ),
        )
    else:
        _require_policy_identity(current, resource_id)
        change = service.plan_publish(arn, document, include_aws_validation=False)
    forward, compensation = policy_cli._change_states(  # noqa: SLF001
        service, change
    )
    if current is not None:
        dependencies = policy_cli._dependency_payload(  # noqa: SLF001
            service.policy_dependencies(current.arn.value)
        )
        forward["dependencies"] = dependencies
        compensation["dependencies"] = dependencies
    return replace(
        operation,
        params={
            "State": forward,
            "ExpectedStateHash": _policy_state_hash(compensation),
            "ResourceId": resource_id,
        },
        compensate_params={
            "State": compensation,
            "ExpectedStateHash": _policy_state_hash(forward),
            "ResourceId": resource_id,
        },
    )


def _materialize_managed_operations(
    plan: roles.MutationPlan, context: IamCommandContext
) -> roles.MutationPlan:
    return replace(
        plan,
        operations=tuple(
            _materialize_managed_operation(operation, context)
            if operation.client == "managed_policy" and "State" not in operation.params
            else operation
            for operation in plan.operations
        ),
    )


def _publish_owned_policy(
    payload: Mapping[str, object], context: IamCommandContext
) -> None:
    raw_state = payload.get("State")
    if not isinstance(raw_state, Mapping):
        raise OperationalError("Managed-policy recovery state is invalid.")
    state = dict(raw_state)
    arn = str(state.get("arn", ""))
    resource_id = str(payload["ResourceId"])
    service = _managed_service(context)
    current = _managed_record(service, arn)
    if current is not None:
        _require_policy_identity(current, resource_id)
        live: Mapping[str, object] = _policy_state(service, current)
    else:
        live = {"exists": False, "arn": arn}
    live_hash = _policy_state_hash(live)
    desired_hash = _policy_state_hash(state)
    if live_hash == desired_hash:
        return
    if live_hash != str(payload["ExpectedStateHash"]):
        raise OperationalError(
            f"Managed policy {arn} changed after planning; no reconciliation was made."
        )
    policy_cli._reconcile_policy(state, context)  # noqa: SLF001
    updated = _managed_record(service, arn)
    if updated is not None:
        _require_policy_identity(updated, resource_id)
        observed: Mapping[str, object] = _policy_state(service, updated)
    else:
        observed = {"exists": False, "arn": arn}
    if _policy_state_hash(observed) != desired_hash:
        raise OperationalError(f"Managed policy {arn} reconciliation was incomplete.")


def _restore_owned_policy(
    payload: Mapping[str, object], context: IamCommandContext
) -> None:
    _publish_owned_policy(payload, context)


_IAM_HANDLER_PAIRS = {
    ("delete_role", None),
    ("update_role", "update_role"),
    ("update_assume_role_policy", "update_assume_role_policy"),
    ("put_role_permissions_boundary", "delete_role_permissions_boundary"),
    ("put_role_permissions_boundary", "put_role_permissions_boundary"),
    ("delete_role_permissions_boundary", "put_role_permissions_boundary"),
    ("tag_role", "tag_role"),
    ("tag_role", "untag_role"),
    ("untag_role", "tag_role"),
    ("untag_role", None),
    ("attach_role_policy", "detach_role_policy"),
    ("detach_role_policy", "attach_role_policy"),
    ("put_role_policy", "put_role_policy"),
    ("put_role_policy", "delete_role_policy"),
    ("delete_role_policy", "put_role_policy"),
    ("remove_role_from_instance_profile", "add_role_to_instance_profile"),
    ("attach_group_policy", "detach_group_policy"),
}


def _handler_name(action: str, compensation: str | None) -> str:
    return f"{action}--{compensation or 'none'}".replace("_", "-")


def ensure_role_recovery_handlers() -> None:
    """Register only fixed IAM role mutations with idempotent recovery wrappers."""
    for action, compensation in _IAM_HANDLER_PAIRS:
        name_value = _handler_name(action, compensation)

        def forward(
            payload: Mapping[str, object],
            context: object,
            *,
            selected: str = action,
        ) -> None:
            _iam_call(context, selected, payload)  # type: ignore[arg-type]

        def compensate(
            payload: Mapping[str, object],
            context: object,
            *,
            selected: str | None = compensation,
            forward_action: str = action,
        ) -> None:
            if selected is None and forward_action == "delete_role":
                params = payload.get("params")
                if not isinstance(params, Mapping):
                    raise OperationalError(
                        "Irreversible role-delete recovery state is invalid."
                    )
                role_name = str(params.get("RoleName", ""))
                expected_role_id = str(params.get("ExpectedRoleId", ""))
                try:
                    current = _service(context).get_role(role_name)  # type: ignore[arg-type]
                except ClientError as error:
                    if _error_code(error) != "NoSuchEntity":
                        raise
                else:
                    if expected_role_id and current.role_id == expected_role_id:
                        return
                raise OperationalError(
                    "Role deletion crossed an irreversible AWS principal-identity "
                    "commit point. Hacksaws will not recreate the role and claim a "
                    "complete rollback; restore it and dependent resource policies "
                    "manually."
                )
            if selected is not None:
                _iam_call(context, selected, payload)  # type: ignore[arg-type]

        try:
            recovery.register_handler(
                _RECOVERY_SERVICE,
                name_value,
                forward=forward,
                compensate=compensate,
            )
        except ValueError as error:
            if "already registered" not in str(error):
                raise
    try:
        recovery.register_handler(
            _RECOVERY_SERVICE,
            _CREATE_ROLE_HANDLER,
            forward=_create_role_with_receipt,  # type: ignore[arg-type]
            compensate=_delete_created_role_with_receipt,  # type: ignore[arg-type]
        )
    except ValueError as error:
        if "already registered" not in str(error):
            raise
    try:
        recovery.register_handler(
            _RECOVERY_SERVICE,
            "publish-owned-policy--restore-owned-policy",
            forward=_publish_owned_policy,  # type: ignore[arg-type]
            compensate=_restore_owned_policy,  # type: ignore[arg-type]
        )
    except ValueError as error:
        if "already registered" not in str(error):
            raise


def _preview(plan: roles.MutationPlan) -> str:
    lines = [f"Plan: {plan.kind}", "Resources:"]
    lines.extend(f"  - {resource}" for resource in plan.resources)
    lines.append("AWS mutations:")
    lines.extend(
        f"  - {operation.client}:{operation.action}" for operation in plan.operations
    )
    lines.extend(f"Warning: {warning}" for warning in plan.warnings)
    return "\n".join(lines)


ensure_role_recovery_handlers()


def _confirm_plan(args: argparse.Namespace, plan: roles.MutationPlan) -> bool:
    if not plan.operations or bool(getattr(args, "yes", False)):
        return True
    if bool(getattr(args, "json", False)) or not sys.stdin.isatty():
        return False
    if plan.kind == "role-delete":
        role_name = plan.resources[0].rsplit("/", maxsplit=1)[-1]
        return (
            _input(
                f"{_preview(plan)}\nType the role name {role_name!r} to confirm the "
                "irreversible delete commit: "
            ).strip()
            == role_name
        )
    return (
        _input(f"{_preview(plan)}\nType 'yes' to apply this exact plan: ").strip()
        == "yes"
    )


def _assert_preconditions(plan: roles.MutationPlan, context: IamCommandContext) -> None:
    service = _service(context)
    if "role" in plan.expected:
        current = service.get_role(_role_name(plan.resources[0], context))
        if roles.role_snapshot_hash(current) != plan.expected["role"]:
            raise OperationalError(
                "IAM role changed after planning; no mutation was made."
            )
    if "trust" in plan.expected:
        current_trust = service.get_trust(_role_name(plan.resources[0], context))
        if roles.document_hash(current_trust) != plan.expected["trust"]:
            raise OperationalError(
                "Trust policy changed after planning; no mutation was made."
            )
    if "inline" in plan.expected:
        role_name, policy_name = plan.resources[:2]
        try:
            current_inline = service.get_inline_policy(role_name, policy_name)
            digest = roles.document_hash(current_inline)
        except ClientError as error:
            if _error_code(error) != "NoSuchEntity":
                raise
            digest = "absent"
        if digest != plan.expected["inline"]:
            raise OperationalError(
                "Inline policy changed after planning; no mutation was made."
            )
    if "group" in plan.expected:
        group_name = plan.expected.get("groupName")
        if not group_name:
            raise OperationalError("Group mutation plan has no group identity.")
        current_group = _group_snapshot(group_name, context)
        digest = (
            roles.document_hash(current_group.document)
            if current_group.exists
            else "absent"
        )
        if (
            digest != plan.expected["group"]
            or current_group.policy_arn != plan.expected.get("groupPolicyArn")
            or str(current_group.attached).lower() != plan.expected.get("groupAttached")
        ):
            raise OperationalError(
                "IAM group aggregate policy or attachment changed after planning; "
                "no mutation was made."
            )


def _execute(
    plan: roles.MutationPlan,
    context: IamCommandContext,
    args: argparse.Namespace,
) -> recovery.IamJournal | None:
    plan = _materialize_managed_operations(plan, context)
    if bool(getattr(args, "dry_run", False)):
        raise _DryRunCompletedError(plan)
    if not _confirm_plan(args, plan):
        raise _MutationCancelledError(_preview(plan))
    if not plan.operations:
        return None
    _assert_preconditions(plan, context)
    ensure_role_recovery_handlers()
    prepared: list[tuple[str, dict[str, object], dict[str, object]]] = []
    for operation in plan.operations:
        if operation.client == "managed_policy":
            handler = "publish-owned-policy--restore-owned-policy"
            forward = dict(operation.params)
            compensation = dict(operation.compensate_params or {})
        elif operation.action == "create_role":
            handler = _CREATE_ROLE_HANDLER
            forward = {"params": dict(operation.params)}
            compensation = {
                "params": dict(operation.compensate_params or {}),
                "effectSourceStep": "self",
            }
        else:
            pair = (operation.action, operation.compensate_action)
            if pair not in _IAM_HANDLER_PAIRS:
                raise OperationalError(
                    f"Role mutation {pair!r} has no whitelisted recovery handler."
                )
            handler = _handler_name(*pair)
            forward = {"params": dict(operation.params)}
            compensation = {"params": dict(operation.compensate_params or {})}
        prepared.append((handler, forward, compensation))
    journal = recovery.begin_journal(
        _RECOVERY_SERVICE,
        context.account_id,
        plan.kind,
        partition=context.partition,
    )
    for handler, forward, compensation in prepared:
        journal.record_before_mutation(
            handler, forward=forward, compensation=compensation
        )
    recovery.continue_journal(journal.id, context)
    return journal


def _role_name(reference: str, context: IamCommandContext) -> str:
    if not reference.startswith("arn:"):
        if not _ROLE_NAME.fullmatch(reference):
            raise OperationalError(f"Invalid IAM role name {reference!r}.")
        return reference
    match = roles.ROLE_ARN.fullmatch(reference)
    if match is None:
        raise OperationalError(f"Invalid IAM role ARN {reference!r}.")
    if match.group(1) != context.partition or match.group(2) != context.account_id:
        raise OperationalError("Role ARN does not belong to the selected AWS account.")
    return match.group(3).rsplit("/", maxsplit=1)[-1]


def _parse_tags(values: Iterable[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        key, separator, tag_value = value.partition("=")
        if not separator or not key:
            raise OperationalError(f"Tag {value!r} must use KEY=VALUE syntax.")
        if key in result:
            raise OperationalError(f"Tag key {key!r} was supplied more than once.")
        if key.casefold().startswith("hacksaws:"):
            raise OperationalError(
                "Reserved hacksaws: tags may be changed only with adopt or release."
            )
        result[key] = tag_value
    return result


def _account_refs() -> dict[str, roles.AccountRef]:
    configured = _state.load_config().get("accounts", {})
    return {
        key.casefold(): roles.AccountRef(
            key,
            str(value["id"]),
            str(value.get("partition", "aws")),
        )
        for key, value in configured.items()
        if isinstance(value, dict) and "id" in value
    }


def _account_name(context: IamCommandContext) -> str | None:
    for account in _account_refs().values():
        if (
            account.account_id == context.account_id
            and account.partition == context.partition
        ):
            return account.name
    return None


def _config_path() -> str:
    data = _state.load_config()
    value = data.get("iam", {}).get("path", roles.DEFAULT_ROLE_PATH)
    return roles.normalize_path(str(value))


def _apply_case(value: str, style: str) -> str:
    words = [item for item in re.split(r"[^A-Za-z0-9]+", value) if item]
    if not words:
        return value
    if style == "snake":
        return "_".join(item.lower() for item in words)
    if style == "kebab":
        return "-".join(item.lower() for item in words)
    pascal = "".join(item[:1].upper() + item[1:] for item in words)
    return pascal[:1].lower() + pascal[1:] if style == "camel" else pascal


def _configured_name(
    raw: str, args: argparse.Namespace, context: IamCommandContext
) -> tuple[str, str | None]:
    explicit = {
        key: getattr(args, key)
        for key in ("case", "prefix", "suffix", "naming_enforcement")
        if getattr(args, key, None) is not None
    }
    if "naming_enforcement" in explicit:
        explicit["enforcement"] = explicit.pop("naming_enforcement")
    naming = _state.resolve_naming(
        _state.load_config(),
        resource="role",
        account=_account_name(context),
        explicit=explicit,
    )
    desired = (
        f"{naming['prefix']}{_apply_case(raw, str(naming['case']))}{naming['suffix']}"
    )
    enforcement = str(naming["enforcement"])
    if raw != desired and enforcement == "error":
        raise OperationalError(
            f"Role name {raw!r} violates naming policy; use {desired!r}."
        )
    warning = (
        f"Naming policy suggests {desired!r}."
        if raw != desired and enforcement == "warn"
        else None
    )
    return (desired if enforcement != "off" else raw), warning


def _duration(args: argparse.Namespace, default: int = 3600) -> int:
    return duration_parser.session_duration(
        duration=getattr(args, "duration", None),
        htl=getattr(args, "htl", None),
        mtl=getattr(args, "mtl", None),
        stl=getattr(args, "stl", None),
        default=default,
    )


def _load_document(path: Path, args: argparse.Namespace) -> dict[str, Any]:
    try:
        loaded = documents.load_policy_input(
            path,
            metadata_mode=documents.MetadataMode(getattr(args, "metadata", "none")),
            sidecar=getattr(args, "sidecar", None),
        )
    except (documents.PolicyInputError, OSError) as error:
        raise OperationalError(str(error)) from error
    return dict(loaded.document)


def _trust_for_create(
    args: argparse.Namespace, context: IamCommandContext
) -> dict[str, Any]:
    if args.trust_policy and args.trust_caller:
        raise OperationalError("Use only one of --trust-policy and --trust-caller.")
    if args.trust_policy:
        return _load_document(args.trust_policy, args)
    if not args.trust_caller and not sys.stdin.isatty():
        raise OperationalError(
            "Noninteractive role creation requires --trust-caller or --trust-policy."
        )
    caller = roles.resolve_principal(
        roles.PrincipalRef("caller", context.arn), {}, caller_arn=context.arn
    )
    return {
        "Version": "2012-10-17",
        "Statement": [roles.trust_statement(caller, "HacksawsExactCaller")],
    }


def _role_data(role: roles.RoleSnapshot) -> dict[str, Any]:
    return {
        "name": role.name,
        "arn": role.arn,
        "path": role.path,
        "description": role.description,
        "maxSessionDuration": role.max_session_duration,
        "permissionsBoundary": role.permissions_boundary,
        "tags": dict(sorted(role.tags.items())),
        "trust": role.trust,
        "attachedPolicies": list(role.attached_policies),
        "inlinePolicies": dict(sorted(role.inline_policy_documents.items())),
        "instanceProfiles": list(role.instance_profiles),
    }


def _mapping_text(data: Mapping[str, Any]) -> str:
    return "\n".join(
        f"{key}: {json.dumps(value, default=str)}" for key, value in data.items()
    )


def _caller_trust(role: roles.RoleSnapshot, context: IamCommandContext) -> bool | None:
    caller = roles.normalize_caller_principal(context.arn)
    account = f"arn:{context.partition}:iam::{context.account_id}:root"
    found_condition = False
    statements = role.trust.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return None
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        aws = principal.get("AWS") if isinstance(principal, dict) else None
        values = aws if isinstance(aws, list) else [aws]
        if caller in values or account in values:
            if statement.get("Condition"):
                found_condition = True
            elif statement.get("Action") == "sts:AssumeRole":
                return True
    return None if found_condition else False


def _matches(role: roles.RoleSnapshot, patterns: Iterable[str]) -> bool:
    values = tuple(patterns)
    return not values or any(
        fnmatch.fnmatchcase(role.name.casefold(), pattern.casefold())
        or fnmatch.fnmatchcase(role.arn.casefold(), pattern.casefold())
        for pattern in values
    )


def _list_result(args: argparse.Namespace, context: IamCommandContext) -> Result:
    service = _service(context)
    summaries = service.list_roles(path_prefix="/")
    hydrated = [service.get_role(item.name) for item in summaries]
    selected: list[tuple[roles.RoleSnapshot, str, str]] = []
    warnings: list[str] = []
    if args.probe:
        warnings.append(
            "Probe performs live sts:AssumeRole calls; attempts may be recorded "
            "in CloudTrail."
        )
    for role in hydrated:
        owned = role.tags.get(roles.MANAGED_TAG) == "true"
        service_role = role.path.startswith("/aws-service-role/")
        trust = _caller_trust(role, context)
        classification = roles.classify_assumability(
            trust_allows=trust, identity_allows=None
        ).classification
        if args.service:
            include = service_role
        elif args.all:
            include = True
        elif args.custom:
            include = not owned and not service_role
        else:
            include = owned and classification != "denied"
        if not include or not _matches(role, args.patterns):
            continue
        probe = ""
        if args.probe:
            try:
                roles.BotoStsProbe(context.sts).probe(role.arn, "hacksaws-role-check")
                probe = "ok"
            except ClientError as error:
                probe = (
                    "denied"
                    if _error_code(error) in {"AccessDenied", "AccessDeniedException"}
                    else "indeterminate"
                )
                warnings.append(f"{role.name}: probe failed: {error}")
            except BotoCoreError as error:
                probe = "indeterminate"
                warnings.append(f"{role.name}: probe failed: {error}")
        selected.append((role, classification, probe))
    columns = ["NAME", "PATH", "FLAGS"]
    if args.wide:
        columns += ["ARN", "DURATION", "BOUNDARY", "TAGS"]
    if args.probe:
        columns.append("PROBE")
    rows: list[list[str]] = []
    for role, classification_value, probe in selected:
        flags = "".join(
            flag
            for enabled, flag in (
                (role.tags.get(roles.MANAGED_TAG) == "true", "O"),
                (classification_value == "potentially-allowed", "A"),
                (classification_value == "indeterminate", "?"),
                (role.path.startswith("/aws-service-role/"), "S"),
            )
            if enabled
        )
        row = [role.name, role.path, flags or "-"]
        if args.wide:
            row += [
                role.arn,
                str(role.max_session_duration),
                role.permissions_boundary or "-",
                ",".join(f"{k}={v}" for k, v in sorted(role.tags.items())) or "-",
            ]
        if args.probe:
            row.append(probe)
        rows.append(row)
    widths = [
        max([len(column), *(len(row[index]) for row in rows)])
        for index, column in enumerate(columns)
    ]
    lines = [
        "  ".join(column.ljust(widths[index]) for index, column in enumerate(columns))
    ]
    lines.extend(
        "  ".join(value.ljust(widths[index]) for index, value in enumerate(row))
        for row in rows
    )
    legend: list[str] = []
    if any(role.tags.get(roles.MANAGED_TAG) == "true" for role, _, _ in selected):
        legend.append("O=Hacksaws-owned")
    if any(
        classification == "potentially-allowed" for _, classification, _ in selected
    ):
        legend.append("A=potentially assumable")
    if any(classification == "indeterminate" for _, classification, _ in selected):
        legend.append("?=assumability indeterminate")
    if any(role.path.startswith("/aws-service-role/") for role, _, _ in selected):
        legend.append("S=service-linked")
    if legend:
        lines.append("Legend: " + "; ".join(legend))
    lines.extend(f"Warning: {warning}" for warning in warnings)
    data = {
        "roles": [
            {**_role_data(role), "assumability": classification, "probe": probe or None}
            for role, classification, probe in selected
        ],
        "warnings": warnings,
    }
    return Result("IAM_ROLE_LIST", "\n".join(lines), data=data)


def _confirm_exact(action: str, expected: str, *, yes: bool) -> bool:
    if yes:
        return True
    if not sys.stdin.isatty():
        return False
    return _input(f"{action}. Type {expected!r} to confirm: ").strip() == expected


def _looks_like_file(value: str) -> bool:
    path = Path(value).expanduser()
    return (
        bool(_PATHLIKE.match(value))
        or path.suffix.casefold() in _POLICY_EXTENSIONS
        or path.is_file()
    )


def _resolve_policy_arn(reference: str, context: IamCommandContext) -> str:
    if reference.startswith("arn:"):
        return reference
    matches: list[str] = []
    paginator = context.iam.get_paginator("list_policies")
    for scope in ("Local", "AWS"):
        for page in paginator.paginate(Scope=scope):
            matches.extend(
                str(item["Arn"])
                for item in page.get("Policies", [])
                if str(item.get("PolicyName", "")).casefold() == reference.casefold()
            )
    matches = sorted(set(matches))
    if not matches:
        raise OperationalError(f"Managed policy {reference!r} was not found.")
    if len(matches) > 1:
        raise OperationalError(
            f"Managed policy {reference!r} is ambiguous; specify its ARN."
        )
    return matches[0]


def _owned_publish_attach_plan(
    role: roles.RoleSnapshot,
    policy_name: str,
    document: Mapping[str, Any],
    path: str,
    context: IamCommandContext,
) -> roles.MutationPlan:
    """Plan a rerunnable owned publication followed by an idempotent attachment."""
    selected_path = roles.normalize_path(path)
    arn = (
        f"arn:{context.partition}:iam::{context.account_id}:policy"
        f"{selected_path}{policy_name}"
    )
    service = _managed_service(context)
    current = _managed_record(service, arn)
    resource_id = f"role-attachment-{roles.document_hash(arn)[:24]}"
    if current is not None:
        _require_policy_identity(current, resource_id)
    if current is not None and current.document is None:
        raise OperationalError(f"Managed policy {arn} has no active document.")
    current_document = current.document if current is not None else None
    expected = (
        roles.document_hash(current_document)
        if current_document is not None
        else "absent"
    )
    desired_hash = roles.document_hash(document)
    publication = roles.Operation(
        "managed_policy",
        "publish_owned_policy",
        {
            "PolicyArn": arn,
            "PolicyName": policy_name,
            "Path": selected_path,
            "PolicyDocument": dict(document),
            "ExpectedDocumentHash": expected,
            **(
                {
                    "ExpectedDefaultVersionId": current.default_version_id,
                    "ExpectedTagHash": _managed_tag_hash(current.tags),
                }
                if current is not None
                else {}
            ),
            "ResourceId": resource_id,
        },
        "restore_owned_policy",
        {
            "PolicyArn": arn,
            "PolicyName": policy_name,
            "Path": selected_path,
            "PolicyDocument": (
                dict(current_document) if current_document is not None else {}
            ),
            "ExpectedDocumentHash": desired_hash,
            **(
                {"ExpectedTagHash": _managed_tag_hash(current.tags)}
                if current is not None
                else {}
            ),
            "DeleteIfCreated": current is None,
            "ResourceId": resource_id,
        },
    )
    attachment = roles.plan_attach_policy(role.name, arn, current=role)
    return roles.MutationPlan(
        "policy-publish-attach",
        (role.arn, arn),
        (publication, *attachment.operations),
        {"role": roles.role_snapshot_hash(role)},
    )


def _principal(
    kind: str, value: str, account_name: str | None, context: IamCommandContext
) -> roles.DurablePrincipal:
    accounts = _account_refs()
    if kind == "principal":
        return roles.resolve_principal(roles.PrincipalRef("principal", value), accounts)
    if kind == "account":
        if value.startswith("arn:"):
            return roles.resolve_principal(
                roles.PrincipalRef("principal", value), accounts
            )
        account = accounts.get(value.casefold())
        if account:
            return roles.DurablePrincipal(
                "account",
                f"arn:{account.partition}:iam::{account.account_id}:root",
                account.account_id,
                account.partition,
            )
        if re.fullmatch(r"\d{12}", value):
            return roles.DurablePrincipal(
                "account",
                f"arn:{context.partition}:iam::{value}:root",
                value,
                context.partition,
            )
        raise OperationalError(f"Configured account {value!r} was not found.")
    selected = account_name
    principal_name = value
    if not selected and ":" in value and not value.startswith("arn:"):
        selected, principal_name = value.split(":", maxsplit=1)
    if not selected:
        local = roles.AccountRef("selected", context.account_id, context.partition)
        accounts = {**accounts, "selected": local}
        selected = "selected"
    selected = selected.casefold()
    if kind == "user" and not value.startswith("arn:"):
        account = accounts.get(selected)
        if account and account.account_id == context.account_id:
            try:
                response = context.iam.get_user(UserName=principal_name)
                arn = str(response["User"]["Arn"])
                return roles.resolve_principal(
                    roles.PrincipalRef("principal", arn), accounts
                )
            except ClientError as error:
                raise OperationalError(
                    f"Unable to resolve IAM user {principal_name!r}: {error}"
                ) from error
    if kind == "role" and not value.startswith("arn:"):
        account = accounts.get(selected)
        if account is None:
            raise OperationalError(f"Configured account {selected!r} was not found.")
        if (
            account.account_id != context.account_id
            or account.partition != context.partition
        ):
            raise OperationalError(
                "Cross-account named roles cannot be verified; specify the exact "
                "role ARN."
            )
        try:
            response = context.iam.get_role(RoleName=principal_name)
            arn = str(response["Role"]["Arn"])
        except (ClientError, KeyError) as error:
            raise OperationalError(
                f"Unable to resolve IAM role {principal_name!r}: {error}"
            ) from error
        return roles.resolve_principal(roles.PrincipalRef("principal", arn), accounts)
    return roles.resolve_principal(
        roles.PrincipalRef(kind, principal_name, selected),  # type: ignore[arg-type]
        accounts,
    )


def _conditions(values: Iterable[str]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for value in values:
        operator_key, separator, condition_value = value.partition("=")
        operator, colon, key = operator_key.partition(":")
        if (
            not separator
            or not colon
            or not operator
            or not key
            or "*" in condition_value
        ):
            raise OperationalError(
                f"Condition {value!r} must use OPERATOR:KEY=VALUE without wildcards."
            )
        result.setdefault(operator, {})[key] = condition_value
    return result


def _trust_mutation(args: argparse.Namespace, context: IamCommandContext) -> Result:
    service = _service(context)
    role_name = _role_name(args.target_role, context)
    current = service.get_trust(role_name)
    principal = _principal(
        args.role_trust_kind,
        args.principal,
        getattr(args, "principal_account", None),
        context,
    )
    if args.role_trust_action == "remove":
        plan = roles.plan_remove_trust(role_name, current, principal)
        action = "removed"
    else:
        conditions = _conditions(args.condition)
        if conditions:
            statement = roles.trust_statement(principal, args.sid)
            statement["Condition"] = conditions
            statements = current.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            desired = {**current, "Statement": [*statements, statement]}
            plan = roles.plan_set_trust(role_name, current, desired)
        else:
            plan = roles.plan_add_trust(role_name, current, principal, sid=args.sid)
        action = "added"
    _execute(plan, context, args)
    data = {
        "role": role_name,
        "principal": asdict(principal),
        "changed": bool(plan.operations),
    }
    return Result(
        "IAM_ROLE_TRUST_MUTATED",
        f"Trust {action} for {principal.arn} on {role_name}.",
        data=data,
    )


def _policy_payload(
    document: Mapping[str, Any], metadata: str, name_value: str
) -> object:
    if metadata == "nested":
        return {"metadata": {"name": name_value}, "policy": dict(document)}
    return dict(document)


def _serialize(
    document: Mapping[str, Any], format_name: str, metadata: str, name_value: str
) -> str:
    payload = _policy_payload(document, metadata, name_value)
    if format_name == "json":
        return json.dumps(payload, indent=2, sort_keys=True) + "\n"
    return str(yaml.safe_dump(payload, sort_keys=False))


def _export(
    document: Mapping[str, Any], args: argparse.Namespace, name_value: str
) -> Result:
    text = _serialize(document, args.format, args.metadata, name_value)
    output: Path | None = args.output
    if args.metadata == "sidecar" and output is None:
        raise OperationalError("Sidecar metadata export requires --output.")
    written: list[str] = []
    if output:
        output = output.expanduser().absolute()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        written.append(str(output))
        if args.metadata == "sidecar":
            sidecar = args.sidecar or output.with_name(
                f"{output.stem}.metadata{output.suffix}"
            )
            sidecar.write_text(
                _serialize({"name": name_value}, args.format, "none", name_value),
                encoding="utf-8",
            )
            written.append(str(sidecar))
    return Result(
        "IAM_ROLE_POLICY_EXPORT",
        f"Exported {name_value} to {', '.join(written)}." if written else text.rstrip(),
        data={"document": dict(document), "files": written},
    )


def _edit_document(
    document: Mapping[str, Any], label: str, *, write_backup: bool = True
) -> dict[str, Any]:
    if write_backup:
        backup = _state.root() / "backups"
        backup.mkdir(parents=True, exist_ok=True)
        digest = roles.document_hash(document)
        backup_path = backup / f"{label}-{digest[:12]}.yaml"
        backup_path.write_text(
            yaml.safe_dump(dict(document), sort_keys=False), encoding="utf-8"
        )
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR")
    if not editor:
        raise OperationalError("Set VISUAL or EDITOR before using edit commands.")
    with tempfile.TemporaryDirectory(prefix="hacksaws-role-") as directory:
        path = Path(directory) / f"{label}.yaml"
        path.write_text(
            yaml.safe_dump(dict(document), sort_keys=False), encoding="utf-8"
        )
        command = [*shlex.split(editor, posix=os.name != "nt"), str(path)]
        result = _editor_runner(command, check=False)
        if result.returncode != 0:
            raise OperationalError(f"Editor exited with status {result.returncode}.")
        edited = documents.load_policy_input(path).document
    return dict(edited)


def _group_snapshot(
    group_name: str, context: IamCommandContext
) -> roles.GroupGrantSnapshot:
    try:
        context.iam.get_group(GroupName=group_name)
    except ClientError as error:
        raise OperationalError(
            f"Unable to resolve IAM group {group_name!r}: {error}"
        ) from error
    policy_name = f"hacksaws-{group_name}-assume-roles"
    path = _config_path()
    policy_arn = (
        f"arn:{context.partition}:iam::{context.account_id}:policy{path}{policy_name}"
    )
    attached = False
    for page in context.iam.get_paginator("list_attached_group_policies").paginate(
        GroupName=group_name
    ):
        attached = attached or any(
            item.get("PolicyArn") == policy_arn
            for item in page.get("AttachedPolicies", [])
        )
    role_arns: tuple[str, ...] = ()
    exists = False
    document: dict[str, Any] = {"Version": "2012-10-17", "Statement": []}
    default_version_id: str | None = None
    tags: dict[str, str] = {}
    owned = False
    try:
        policy = context.iam.get_policy(PolicyArn=policy_arn)["Policy"]
        default_version_id = str(policy["DefaultVersionId"])
        version = context.iam.get_policy_version(
            PolicyArn=policy_arn, VersionId=default_version_id
        )["PolicyVersion"]
        document = roles.decode_document(version["Document"])
        tag_response = context.iam.list_policy_tags(PolicyArn=policy_arn)
        tags = {
            str(item["Key"]): str(item.get("Value", ""))
            for item in tag_response.get("Tags", [])
            if isinstance(item, Mapping) and "Key" in item
        }
        owned = (
            tags.get("hacksaws:managed-by") == "hacksaws"
            and tags.get("hacksaws:resource-kind") == "managed-policy"
            and tags.get("hacksaws:resource-id") == f"group-{group_name}"
        )
        if not owned:
            raise OperationalError(
                f"Aggregate policy {policy_arn} is not verified as Hacksaws-owned."
            )
        statements = document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        resources: list[str] = []
        for statement in statements if isinstance(statements, list) else []:
            if not isinstance(statement, dict) or statement.get("Sid") != (
                "HacksawsGroupAssumeRoles"
            ):
                continue
            if (
                statement.get("Effect") != "Allow"
                or statement.get("Action") != "sts:AssumeRole"
            ):
                raise OperationalError(
                    "Aggregate group statement has unexpected semantics."
                )
            value = statement.get("Resource") if isinstance(statement, dict) else None
            resources.extend(
                value
                if isinstance(value, list)
                else [value]
                if isinstance(value, str)
                else []
            )
        role_arns = tuple(sorted(set(resources)))
        exists = True
    except ClientError as error:
        if str(error.response.get("Error", {}).get("Code")) != "NoSuchEntity":
            raise
    account = roles.AccountRef(
        _account_name(context) or context.account_id,
        context.account_id,
        context.partition,
    )
    return roles.GroupGrantSnapshot(
        group_name,
        account,
        policy_name,
        policy_arn,
        role_arns,
        exists,
        attached,
        document,
        default_version_id,
        (),
        tags,
        owned,
        path,
    )


def _member_arns(values: Iterable[str], context: IamCommandContext) -> tuple[str, ...]:
    return tuple(
        _service(context).get_role(_role_name(value, context)).arn for value in values
    )


def _remaining_group_grants(
    role_arn: str, excluding_policy_arn: str, context: IamCommandContext
) -> tuple[str, ...]:
    """Return other verified Hacksaws aggregate policies still granting this role."""
    matches: list[str] = []
    paginator = context.iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local", PathPrefix=_config_path()):
        for item in page.get("Policies", []):
            if not isinstance(item, Mapping):
                continue
            arn = str(item.get("Arn", ""))
            if not arn or arn == excluding_policy_arn:
                continue
            tags = context.iam.list_policy_tags(PolicyArn=arn).get("Tags", [])
            values = {
                str(tag["Key"]): str(tag.get("Value", ""))
                for tag in tags
                if isinstance(tag, Mapping) and "Key" in tag
            }
            if not (
                values.get("hacksaws:managed-by") == "hacksaws"
                and values.get("hacksaws:resource-kind") == "managed-policy"
                and str(values.get("hacksaws:resource-id", "")).startswith("group-")
            ):
                continue
            group_name = str(values["hacksaws:resource-id"])[len("group-") :]
            expected_name = f"hacksaws-{group_name}-assume-roles"
            expected_arn = (
                f"arn:{context.partition}:iam::{context.account_id}:policy"
                f"{_config_path()}{expected_name}"
            )
            if str(item.get("PolicyName", "")) != expected_name or arn != expected_arn:
                continue
            try:
                context.iam.get_group(GroupName=group_name)
            except ClientError as error:
                if _error_code(error) == "NoSuchEntity":
                    continue
                raise
            attached = any(
                attached_policy.get("PolicyArn") == arn
                for attached_page in context.iam.get_paginator(
                    "list_attached_group_policies"
                ).paginate(GroupName=group_name)
                for attached_policy in attached_page.get("AttachedPolicies", [])
                if isinstance(attached_policy, Mapping)
            )
            if not attached:
                continue
            policy = context.iam.get_policy(PolicyArn=arn)["Policy"]
            version = context.iam.get_policy_version(
                PolicyArn=arn, VersionId=policy["DefaultVersionId"]
            )["PolicyVersion"]
            document = roles.decode_document(version["Document"])
            statements = document.get("Statement", [])
            if isinstance(statements, Mapping):
                statements = [statements]
            for statement in statements if isinstance(statements, list) else []:
                if not isinstance(statement, Mapping) or statement.get("Sid") != (
                    "HacksawsGroupAssumeRoles"
                ):
                    continue
                resources = statement.get("Resource", [])
                selected = resources if isinstance(resources, list) else [resources]
                if role_arn in selected:
                    matches.append(arn)
                    break
    return tuple(sorted(matches))


def _group_command(args: argparse.Namespace, context: IamCommandContext) -> Result:
    group = _group_snapshot(args.group, context)
    action = args.role_trust_action
    if action in {"add", "sync", "remove"}:
        members = _member_arns(args.members, context)
        if action == "add":
            plan = roles.plan_sync_group_members(group, (*group.role_arns, *members))
        elif action == "sync":
            plan = roles.plan_sync_group_members(group, members)
        else:
            plan = roles.plan_sync_group_members(
                group, (arn for arn in group.role_arns if arn not in members)
            )
        _execute(plan, context, args)
        return Result(
            "IAM_ROLE_GROUP_MEMBERS",
            f"Updated aggregate AssumeRole grants for group {group.group_name}.",
            data={"group": group.group_name, "roles": list(plan.resources[1:])},
        )
    role = _service(context).get_role(_role_name(args.target_role, context))
    if action == "grant":
        plan = roles.plan_group_grant(role, role.trust, group)
    else:
        account = roles.DurablePrincipal(
            "account",
            f"arn:{context.partition}:iam::{context.account_id}:root",
            context.account_id,
            context.partition,
        )
        member_plan = roles.plan_remove_group_member(group, role.arn)
        remaining = _remaining_group_grants(role.arn, group.policy_arn, context)
        trust = (
            roles.MutationPlan("trust-retained", (role.arn,), ())
            if remaining
            else roles.plan_remove_owned_group_trust(role.name, role.trust, account)
        )
        plan = roles.MutationPlan(
            "group-revoke",
            (role.arn, group.group_name),
            (*trust.operations, *member_plan.operations),
            {**trust.expected, **member_plan.expected},
            (
                (
                    "Account-root trust is retained because other aggregate group "
                    "grants still reference this role."
                ),
            )
            if remaining
            else (),
        )
    _execute(plan, context, args)
    return Result(
        "IAM_ROLE_GROUP_TRUST",
        f"{action.title()}ed group {group.group_name} for role {role.name}.",
        data={"role": role.arn, "group": group.group_name, "action": action},
    )


def _inline_command(args: argparse.Namespace, context: IamCommandContext) -> Result:
    service = _service(context)
    role_name = _role_name(args.role, context)
    action = args.role_inline_action
    if action == "list":
        values = list(service.list_inline_policies(role_name))
        return Result(
            "IAM_ROLE_INLINE_LIST", "\n".join(values), data={"policies": values}
        )
    try:
        current = service.get_inline_policy(role_name, args.policy)
    except ClientError as error:
        error_code = str(error.response.get("Error", {}).get("Code"))
        if action != "put" or error_code != "NoSuchEntity":
            raise
        current = None
    if action == "put":
        desired = _load_document(args.file, args)
        plan = roles.plan_put_inline_policy(
            role_name,
            args.policy,
            desired,
            current=current,
            expected_hash=(
                roles.document_hash(current) if current is not None else None
            ),
        )
        if current is not None:
            latest = service.get_inline_policy(role_name, args.policy)
            if roles.document_hash(latest) != roles.document_hash(current):
                raise OperationalError(
                    "Inline policy changed before mutation; no update was made."
                )
        _execute(plan, context, args)
        return Result(
            "IAM_ROLE_INLINE_MUTATED",
            f"Inline policy {args.policy} put completed for {role_name}.",
            data={"role": role_name, "policy": args.policy, "action": action},
        )
    if current is None:
        raise OperationalError(f"Inline policy {args.policy!r} was not found.")
    if action == "get":
        return Result(
            "IAM_ROLE_INLINE_GET",
            yaml.safe_dump(current, sort_keys=False).rstrip(),
            data=current,
        )
    if action == "export":
        return _export(current, args, args.policy)
    if action == "edit":
        desired = _edit_document(
            current,
            f"{role_name}-{args.policy}",
            write_backup=not bool(getattr(args, "dry_run", False)),
        )
        latest = service.get_inline_policy(role_name, args.policy)
        if roles.document_hash(latest) != roles.document_hash(current):
            raise OperationalError(
                "Inline policy changed while the editor was open; no update was made."
            )
        plan = roles.plan_put_inline_policy(
            role_name,
            args.policy,
            desired,
            current=current,
            expected_hash=roles.document_hash(current),
        )
    else:
        plan = roles.plan_delete_inline_policy(
            role_name,
            args.policy,
            current=current,
            expected_hash=roles.document_hash(current),
        )
    latest = service.get_inline_policy(role_name, args.policy)
    if roles.document_hash(latest) != roles.document_hash(current):
        raise OperationalError(
            "Inline policy changed before mutation; no update was made."
        )
    _execute(plan, context, args)
    return Result(
        "IAM_ROLE_INLINE_MUTATED",
        f"Inline policy {args.policy} {action} completed for {role_name}.",
        data={"role": role_name, "policy": args.policy, "action": action},
    )


def _trust_command(args: argparse.Namespace, context: IamCommandContext) -> Result:
    action = args.role_trust_action
    trust_kind = getattr(args, "role_trust_kind", None)
    if action in {"add", "remove"} and trust_kind != "group-members":
        return _trust_mutation(args, context)
    if trust_kind in {"group", "group-members"}:
        return _group_command(args, context)
    service = _service(context)
    role_name = _role_name(args.role, context)
    current = service.get_trust(role_name)
    if action == "get":
        return Result(
            "IAM_ROLE_TRUST_GET",
            yaml.safe_dump(current, sort_keys=False).rstrip(),
            data=current,
        )
    if action == "export":
        return _export(current, args, f"{role_name}-trust")
    if action == "check":
        role = service.get_role(role_name)
        trust = _caller_trust(role, context)
        static = roles.classify_assumability(trust_allows=trust, identity_allows=None)
        data: dict[str, Any] = {
            "role": role.arn,
            "static": asdict(static),
            "probe": None,
        }
        lines = [f"Static: {static.classification}", *static.reasons]
        if args.probe:
            lines.append(
                "Warning: probe performs a live sts:AssumeRole request recorded by AWS."
            )
            try:
                data["probe"] = dict(
                    roles.BotoStsProbe(context.sts).probe(
                        role.arn, "hacksaws-role-check"
                    )
                )
                lines.append("Probe: allowed")
            except (BotoCoreError, ClientError) as error:
                data["probe"] = {"ok": False, "error": str(error)}
                lines.append("Probe: denied")
        return Result("IAM_ROLE_TRUST_CHECK", "\n".join(lines), data=data)
    if action == "set":
        desired = _load_document(args.file, args)
    else:
        desired = _edit_document(
            current,
            f"{role_name}-trust",
            write_backup=not bool(getattr(args, "dry_run", False)),
        )
    latest = service.get_trust(role_name)
    if roles.document_hash(latest) != roles.document_hash(current):
        raise OperationalError(
            "Trust policy changed during editing; no update was made."
        )
    plan = roles.plan_set_trust(
        role_name, current, desired, expected_hash=roles.document_hash(current)
    )
    _execute(plan, context, args)
    return Result(
        "IAM_ROLE_TRUST_SET",
        f"Updated trust policy for {role_name}.",
        data={"role": role_name, "trust": desired},
    )


def _dispatch(args: argparse.Namespace, context: IamCommandContext) -> Result | None:
    command = getattr(args, "role_command", None)
    service = _service(context)
    if command is None:
        return None
    if command == "list":
        return _list_result(args, context)
    if command == "get":
        role = service.get_role(_role_name(args.role, context))
        data = _role_data(role)
        return Result("IAM_ROLE_GET", _mapping_text(data), data=data)
    if command == "create":
        role_name, warning = _configured_name(args.role, args, context)
        spec = roles.RoleSpec(
            role_name,
            _trust_for_create(args, context),
            path=args.path or _config_path(),
            description=args.description,
            max_session_duration=_duration(args),
            permissions_boundary=args.permissions_boundary,
            tags=_parse_tags(args.tag),
            owner=roles.normalize_caller_principal(context.arn),
        )
        try:
            current = service.get_role(role_name)
        except ClientError as error:
            if _error_code(error) != "NoSuchEntity":
                raise
            current = None
        if current is None:
            plan = roles.plan_create_role(spec)
        else:
            plan = roles.plan_update_role(current, spec)
            if not plan.operations:
                return Result(
                    "IAM_ROLE_NO_CHANGE",
                    f"NO CHANGE — IAM role {role_name} already matches {current.arn}.",
                    data={
                        "classification": "no-change",
                        "role": role_name,
                        "arn": current.arn,
                        "roleId": current.role_id,
                    },
                )
            if not args.replace:
                return Result(
                    "IAM_ROLE_COLLISION",
                    f"CONFLICT — IAM role {role_name} already exists and differs. "
                    "Use 'iam role update' for routine changes, or repeat create "
                    "with --replace after reviewing the exact plan.",
                    EXIT_USAGE,
                    "stderr",
                    {
                        "classification": "conflict",
                        "role": role_name,
                        "arn": current.arn,
                        "operations": [item.action for item in plan.operations],
                    },
                )
        _execute(plan, context, args)
        try:
            result_role = service.get_role(role_name)
        except ClientError as error:
            if _error_code(error) != "NoSuchEntity":
                raise
            result_role = None
        message = (
            f"Updated existing IAM role {role_name}."
            if current is not None
            else f"Created IAM role {role_name}."
        )
        if warning:
            message += f" Warning: {warning}"
        console_url = _console_url(context, role_name)
        role_arn = (
            result_role.arn
            if result_role is not None
            else f"arn:{context.partition}:iam::{context.account_id}:role/{role_name}"
        )
        role_id = result_role.role_id if result_role is not None else None
        message += (
            f"\nARN: {role_arn}"
            + (f"\nRole ID: {role_id}" if role_id else "")
            + f"\nAWS Console: {console_url}"
        )
        return Result(
            "IAM_ROLE_REPLACED" if current is not None else "IAM_ROLE_CREATED",
            message,
            data={
                "role": role_name,
                "arn": role_arn,
                "roleId": role_id,
                "warning": warning,
                "consoleUrl": console_url,
            },
        )
    if command == "update":
        current = service.get_role(_role_name(args.role, context))
        if current.tags.get(roles.MANAGED_TAG) != "true":
            raise OperationalError(
                "Role is not Hacksaws-owned; adopt it before updating managed fields."
            )
        description = (
            None
            if args.clear_description
            else args.description
            if args.description is not None
            else current.description
        )
        boundary = (
            None
            if args.clear_permissions_boundary
            else args.permissions_boundary
            if args.permissions_boundary is not None
            else current.permissions_boundary
        )
        trust = (
            _load_document(args.trust_policy, args)
            if args.trust_policy
            else current.trust
        )
        desired = roles.RoleSpec(
            current.name,
            trust,
            path=current.path,
            description=description,
            max_session_duration=_duration(args, current.max_session_duration),
            permissions_boundary=boundary,
            tags={
                key: value
                for key, value in current.tags.items()
                if key not in {roles.MANAGED_TAG, roles.OWNER_TAG, roles.AUDIT_TAG}
            },
            owner=current.tags.get(roles.OWNER_TAG, "hacksaws"),
            audit_id=current.tags.get(roles.AUDIT_TAG),
            ownership_origin=current.tags.get(roles.ORIGIN_TAG, "created"),
        )
        plan = roles.plan_update_role(current, desired)
        _execute(plan, context, args)
        return Result(
            "IAM_ROLE_UPDATED",
            f"Updated IAM role {current.name}.",
            data={
                "role": current.name,
                "operations": [item.action for item in plan.operations],
            },
        )
    if command == "delete":
        current = service.get_role(_role_name(args.role, context))
        if current.path.startswith("/aws-service-role/") and not args.service_role:
            raise OperationalError(
                "Service-linked role deletion requires --service-role."
            )
        plan = roles.plan_delete_role(
            current,
            cascade=args.cascade,
            remove_from_instance_profiles=args.remove_from_instance_profiles,
            allow_unmanaged=args.unmanaged,
        )
        _execute(plan, context, args)
        return Result(
            "IAM_ROLE_DELETED",
            f"Deleted IAM role {current.name}.",
            data={"role": current.arn, "warnings": list(plan.warnings)},
        )
    if command in {"attach", "detach"}:
        role_name = _role_name(args.role, context)
        current_role = service.get_role(role_name)
        if command == "attach" and _looks_like_file(args.policy):
            path = Path(args.policy).expanduser()
            if not path.is_file():
                raise OperationalError(f"Local policy file {path} does not exist.")
            document = _load_document(path, args)
            policy_name = args.policy_name or path.stem
            if args.inline:
                try:
                    current_inline = service.get_inline_policy(role_name, policy_name)
                except ClientError as error:
                    if _error_code(error) != "NoSuchEntity":
                        raise
                    current_inline = None
                plan = roles.plan_put_inline_policy(
                    role_name,
                    policy_name,
                    document,
                    current=current_inline,
                    expected_hash=(
                        roles.document_hash(current_inline)
                        if current_inline is not None
                        else None
                    ),
                )
            else:
                plan = _owned_publish_attach_plan(
                    current_role,
                    policy_name,
                    document,
                    args.path or _config_path(),
                    context,
                )
            reference = plan.resources[-1]
        else:
            arn = _resolve_policy_arn(args.policy, context)
            plan = (
                roles.plan_attach_policy(role_name, arn, current=current_role)
                if command == "attach"
                else roles.plan_detach_policy(role_name, arn, current=current_role)
            )
            reference = arn
        _execute(plan, context, args)
        return Result(
            f"IAM_ROLE_POLICY_{command.upper()}",
            f"{command.title()}ed {reference} for {role_name}.",
            data={"role": role_name, "policy": reference},
        )
    if command == "tag":
        role_name = _role_name(args.role, context)
        action = args.role_tag_action
        current_role = service.get_role(role_name)
        if action == "list":
            values = dict(current_role.tags)
            return Result(
                "IAM_ROLE_TAG_LIST", _mapping_text(values), data={"tags": values}
            )
        if action == "set":
            plan = roles.plan_put_tags(
                role_name,
                _parse_tags(args.tags),
                current=current_role.tags,
                expected_role=current_role,
            )
        else:
            if any(key.casefold().startswith("hacksaws:") for key in args.keys):
                raise OperationalError(
                    "Reserved hacksaws: tags may be changed only with adopt or release."
                )
            plan = roles.plan_remove_tags(
                role_name,
                args.keys,
                current=current_role.tags,
                expected_role=current_role,
            )
        _execute(plan, context, args)
        return Result(
            "IAM_ROLE_TAG_MUTATED",
            f"Role tags {action} completed for {role_name}.",
            data={"role": role_name, "action": action},
        )
    if command in {"adopt", "release"}:
        current = service.get_role(_role_name(args.role, context))
        plan = (
            roles.plan_adopt_role(
                current,
                args.owner or roles.normalize_caller_principal(context.arn),
                args.audit_id,
            )
            if command == "adopt"
            else roles.plan_release_role(current)
        )
        _execute(plan, context, args)
        return Result(
            "IAM_ROLE_OWNERSHIP",
            f"{command.title()}ed IAM role {current.name}.",
            data={"role": current.arn, "action": command},
        )
    if command == "inline-policy":
        if not getattr(args, "role_inline_action", None):
            return Result(
                "IAM_ROLE_INLINE_HELP",
                "Choose an inline-policy action.",
                EXIT_USAGE,
                "stderr",
            )
        return _inline_command(args, context)
    if command == "trust":
        if not getattr(args, "role_trust_action", None):
            return Result(
                "IAM_ROLE_TRUST_HELP", "Choose a trust action.", EXIT_USAGE, "stderr"
            )
        return _trust_command(args, context)
    return None


def dispatch(args: argparse.Namespace, context: IamCommandContext) -> Result | None:
    """Dispatch a parsed role leaf and normalize expected operational failures."""
    try:
        return _dispatch(args, context)
    except _DryRunCompletedError as completed:
        plan = completed.plan
        data = {
            "dryRun": True,
            "classification": "planned" if plan.operations else "no-change",
            "kind": plan.kind,
            "resources": list(plan.resources),
            "operations": [
                {"client": item.client, "action": item.action}
                for item in plan.operations
            ],
            "warnings": list(plan.warnings),
        }
        return Result(
            "IAM_ROLE_DRY_RUN",
            f"DRY RUN — {_preview(plan)}\nNo AWS or local state was changed.",
            data=data,
        )
    except _MutationCancelledError as error:
        return Result(
            "IAM_ROLE_MUTATION_CANCELLED",
            f"Mutation cancelled; no AWS changes were made.\n{error}",
            EXIT_CANCELLED,
            "stderr",
            {"preview": str(error)},
        )
    except OperationalError:
        raise
    except (roles.IamRoleError, documents.PolicyInputError) as error:
        raise OperationalError(str(error)) from error
    except (BotoCoreError, ClientError) as error:
        raise OperationalError(f"AWS IAM role operation failed: {error}") from error
